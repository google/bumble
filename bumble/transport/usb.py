# Copyright 2021-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import asyncio
import ctypes
import logging
import platform
import threading
from collections.abc import Callable
from typing import Any

import usb1

from bumble import hci
from bumble.colors import color
from bumble.transport.common import BaseSource, Transport, TransportInitError

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def _safe_call_soon(loop: asyncio.AbstractEventLoop, callback, *args) -> None:
    """Schedule `callback` on `loop` from the libusb event thread, tolerating the
    case where the loop has already been closed during process/transport
    teardown. Without this guard, a libusb transfer callback that fires after the
    asyncio loop is closed raises 'Event loop is closed' on the C callback
    thread, which can escalate to a libusb mutex assertion and crash the process
    (SIGABRT). This makes an unclean shutdown a no-op instead of a core dump."""
    try:
        loop.call_soon_threadsafe(callback, *args)
    except RuntimeError:
        pass  # loop already closed; nothing left to schedule


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# pylint: disable=invalid-name
USB_RECIPIENT_DEVICE = 0x00
USB_RECIPIENT_INTERFACE = 0x01
USB_REQUEST_TYPE_CLASS = 0x01 << 5
USB_DEVICE_CLASS_DEVICE = 0x00
USB_DEVICE_CLASS_MISCELLANEOUS = 0xEF
USB_DEVICE_CLASS_WIRELESS_CONTROLLER = 0xE0
USB_DEVICE_SUBCLASS_RF_CONTROLLER = 0x01
USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER = 0x01
USB_ENDPOINT_TRANSFER_TYPE_ISOCHRONOUS = 0x01
USB_ENDPOINT_TRANSFER_TYPE_BULK = 0x02
USB_ENDPOINT_TRANSFER_TYPE_INTERRUPT = 0x03
USB_ENDPOINT_IN = 0x80

USB_BT_HCI_CLASS_TUPLE = (
    USB_DEVICE_CLASS_WIRELESS_CONTROLLER,
    USB_DEVICE_SUBCLASS_RF_CONTROLLER,
    USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER,
)

MAX_SCO_IN_PACKETS = 128
NUMBER_OF_SCO_IN_TRANSFERS = 2
# Each HCI SCO packet sent over the isochronous endpoint spans 3 USB (micro)frames,
# with the 3-byte HCI header at the start of the first one (Core Spec Vol 4, Part B,
# 2.1.1). For example, with alternate setting 2 (17-byte max packet size), each HCI SCO
# packet carries 3 * 17 - 3 = 48 bytes of data.
USB_FRAMES_PER_SCO_PACKET = 3
# Number of isochronous OUT transfers kept in flight, so that SCO data is sent at the
# rate of the SCO link instead of leaving gaps between transfers.
NUMBER_OF_SCO_OUT_TRANSFERS = 4
HCI_SCO_HEADER_SIZE = 3
# With alternate setting 6 (transparent 16 kHz, e.g. mSBC / LC3 SWB), each HCI SCO
# packet (3 + 60 bytes, i.e. one 7.5 ms codec frame) fits in a single USB frame (Core
# Spec Vol 4, Part B, Table 2.1). Packets are sent back to back: controllers such as
# Intel BE200 do not accept empty frames in between.
SCO_ALT6_ALTERNATE_SETTING = 6
# Alternate settings for 1, 2 and 3 SCO links with 16-bit samples on HCI. With 8-bit
# samples, the alternate setting is the number of SCO links (Core Spec Vol 4, Part B,
# Table 2.1).
SCO_16_BIT_ALTERNATE_SETTINGS = (2, 4, 5)


# -----------------------------------------------------------------------------
def load_libusb():
    '''
    Attempt to load the libusb-1.0 C library from libusb_package in site-packages.
    If the library exists, we create a DLL object and initialize the usb1 backend.
    This only needs to be done once, but before a usb1.USBContext is created.
    If the library does not exists, do nothing and usb1 will search default system paths
    when usb1.USBContext is created.
    '''
    try:
        import libusb_package
    except ImportError:
        logger.debug('libusb_package is not available')
    else:
        if libusb_path := libusb_package.get_library_path():
            logger.debug(f'loading libusb library at {libusb_path}')
            dll_loader = (
                ctypes.WinDLL if platform.system() == 'Windows' else ctypes.CDLL
            )
            libusb_dll = dll_loader(
                str(libusb_path), use_errno=True, use_last_error=True
            )
            usb1.loadLibrary(libusb_dll)


def find_endpoints(device, forced_mode, sco_alternate=None):
    '''Look for the interfaces with the right class and endpoints'''
    # pylint: disable-next=too-many-nested-blocks
    for configuration_index, configuration in enumerate(device):
        # Select the interface and endpoints for ACL
        acl_interface = None
        bulk_in = None
        bulk_out = None
        interrupt_in = None
        for interface in configuration:
            for setting in interface:
                if acl_interface is not None:
                    continue

                if (
                    not forced_mode
                    and (
                        setting.getClass(),
                        setting.getSubClass(),
                        setting.getProtocol(),
                    )
                    != USB_BT_HCI_CLASS_TUPLE
                ):
                    continue

                for endpoint in setting:
                    attributes = endpoint.getAttributes()
                    address = endpoint.getAddress()
                    if attributes & 0x03 == USB_ENDPOINT_TRANSFER_TYPE_BULK:
                        if address & USB_ENDPOINT_IN:
                            if bulk_in is None:
                                bulk_in = endpoint
                        else:
                            if bulk_out is None:
                                bulk_out = endpoint
                    elif attributes & 0x03 == USB_ENDPOINT_TRANSFER_TYPE_INTERRUPT:
                        if address & USB_ENDPOINT_IN and interrupt_in is None:
                            interrupt_in = endpoint

                # Only keep complete sets (endpoints that should be under the
                # same interface)
                if (
                    bulk_in is not None
                    and bulk_out is not None
                    and interrupt_in is not None
                ):
                    acl_interface = setting

        # Select the interface and endpoints for SCO
        sco_interface = None
        max_packet_size = (0, 0)
        isochronous_in = None
        isochronous_out = None
        sco_isochronous_in = None
        sco_isochronous_out = None

        for interface in configuration:
            if sco_interface is not None:
                continue

            if sco_alternate is None:
                continue

            for setting in interface:
                if (
                    not forced_mode
                    and (
                        setting.getClass(),
                        setting.getSubClass(),
                        setting.getProtocol(),
                    )
                    != USB_BT_HCI_CLASS_TUPLE
                ):
                    continue

                if (
                    sco_alternate != 0
                    and setting.getAlternateSetting() != sco_alternate
                ):
                    continue

                isochronous_in = None
                isochronous_out = None

                for endpoint in setting:
                    if (
                        endpoint.getAttributes() & 0x03
                        == USB_ENDPOINT_TRANSFER_TYPE_ISOCHRONOUS
                    ):
                        if endpoint.getMaxPacketSize() > 0:
                            if endpoint.getAddress() & USB_ENDPOINT_IN:
                                if (
                                    isochronous_in is None
                                    or endpoint.getMaxPacketSize()
                                    > (isochronous_in.getMaxPacketSize())
                                ):
                                    isochronous_in = endpoint
                            else:
                                if (
                                    isochronous_out is None
                                    or endpoint.getMaxPacketSize()
                                    > (isochronous_out.getMaxPacketSize())
                                ):
                                    isochronous_out = endpoint

                if isochronous_in is not None and isochronous_out is not None:
                    if (
                        sco_interface is None
                        or sco_alternate == 0
                        and (
                            isochronous_in.getMaxPacketSize(),
                            isochronous_out.getMaxPacketSize(),
                        )
                        > max_packet_size
                    ):
                        sco_interface = setting
                        sco_isochronous_in = isochronous_in
                        sco_isochronous_out = isochronous_out
                        max_packet_size = (
                            isochronous_in.getMaxPacketSize(),
                            isochronous_out.getMaxPacketSize(),
                        )

        # Return if we found at least a compatible ACL interface
        if acl_interface is not None:
            return (
                configuration_index + 1,
                acl_interface,
                sco_interface,
                interrupt_in,
                bulk_in,
                sco_isochronous_in,
                bulk_out,
                sco_isochronous_out,
            )

        logger.debug(f'skipping configuration {configuration_index + 1}')

    return None


def find_sco_settings(configuration, interface_number) -> dict[int, tuple[Any, Any]]:
    '''Returns the isochronous (in, out) endpoints of each SCO alternate setting.'''
    settings: dict[int, tuple[Any, Any]] = {}
    for interface in configuration:
        for setting in interface:
            if setting.getNumber() != interface_number:
                continue
            isochronous_in = isochronous_out = None
            for endpoint in setting:
                if (
                    endpoint.getAttributes() & 0x03
                    == USB_ENDPOINT_TRANSFER_TYPE_ISOCHRONOUS
                    and endpoint.getMaxPacketSize() > 0
                ):
                    if endpoint.getAddress() & USB_ENDPOINT_IN:
                        isochronous_in = endpoint
                    else:
                        isochronous_out = endpoint
            if isochronous_in is not None and isochronous_out is not None:
                settings[setting.getAlternateSetting()] = (
                    isochronous_in,
                    isochronous_out,
                )
    logger.debug(
        'SCO alternate settings: '
        + ', '.join(
            f'{alt}: {endpoints[1].getMaxPacketSize()}'
            for alt, endpoints in sorted(settings.items())
        )
    )
    return settings


class UsbPacketSink:
    def __init__(
        self,
        device,
        bulk_out,
        isochronous_out,
        interface_number=0,
        sco_alternate_setting=0,
    ) -> None:
        self.device = device
        self.bulk_out = bulk_out
        self.isochronous_out = isochronous_out
        self.interface_number = interface_number
        self.bulk_or_control_out_transfer = device.getTransfer()
        self.out_transfer_ready = asyncio.Semaphore(1)
        self.packets: asyncio.Queue[bytes] = (
            asyncio.Queue()
        )  # Queue of packets waiting to be sent
        self.loop = asyncio.get_running_loop()
        self.queue_task = None
        self.closed = False

        # SCO data is sent on its own path, so that it is not delayed by ACL data or
        # commands, with several isochronous transfers in flight.
        self.sco_packet_data_size = 0
        self.sco_buffers: dict[int, bytearray] = {}  # Pending SCO data, by handle
        self.sco_packets: asyncio.Queue[bytes] = asyncio.Queue()
        self.sco_queue_task = None
        self.isochronous_out_transfers: list[Any] = []
        self.free_isochronous_out_transfers: asyncio.Queue[Any] = asyncio.Queue()
        self.sco_frames_per_packet = USB_FRAMES_PER_SCO_PACKET
        self.command_hook: Callable[[bytes], None] | None = None
        self.configure_sco(isochronous_out, sco_alternate_setting)

    def configure_sco(self, isochronous_out, sco_alternate_setting) -> None:
        self.isochronous_out = isochronous_out
        self.sco_frames_per_packet = (
            1
            if sco_alternate_setting == SCO_ALT6_ALTERNATE_SETTING
            else USB_FRAMES_PER_SCO_PACKET
        )
        self.sco_packet_data_size = 0
        self.isochronous_out_transfers = []
        self.free_isochronous_out_transfers = asyncio.Queue()
        if isochronous_out is not None and isochronous_out.getMaxPacketSize() > 0:
            self.sco_packet_data_size = (
                self.sco_frames_per_packet * isochronous_out.getMaxPacketSize()
                - HCI_SCO_HEADER_SIZE
            )
            for _ in range(NUMBER_OF_SCO_OUT_TRANSFERS):
                transfer = self.device.getTransfer(
                    iso_packets=self.sco_frames_per_packet
                )
                self.isochronous_out_transfers.append(transfer)
                self.free_isochronous_out_transfers.put_nowait(transfer)
            if self.queue_task is not None and self.sco_queue_task is None:
                self.sco_queue_task = asyncio.create_task(self.process_sco_queue())
        logger.debug(
            f'SCO OUT: alternate setting {sco_alternate_setting}, '
            f'{self.sco_packet_data_size} bytes per packet'
        )

    def stop_sco(self) -> None:
        if self.sco_queue_task:
            self.sco_queue_task.cancel()
            self.sco_queue_task = None
        for transfer in self.isochronous_out_transfers:
            if transfer.isSubmitted():
                try:
                    transfer.cancel()
                except usb1.USBError:
                    pass
        self.isochronous_out_transfers = []
        self.sco_buffers.clear()
        while not self.sco_packets.empty():
            self.sco_packets.get_nowait()

    def start(self):
        self.queue_task = asyncio.create_task(self.process_queue())
        if self.isochronous_out_transfers:
            self.sco_queue_task = asyncio.create_task(self.process_sco_queue())

    def on_packet(self, packet):
        # Ignore packets if we're closed
        if self.closed:
            return

        if len(packet) == 0:
            logger.warning('packet too short')
            return

        if packet[0] == hci.HCI_SYNCHRONOUS_DATA_PACKET:
            self.on_sco_packet(packet[1:])
            return

        if self.command_hook and packet[0] == hci.HCI_COMMAND_PACKET:
            try:
                self.command_hook(packet)
            except Exception:
                logger.exception(color('!!! Exception in command hook', 'red'))

        # Queue the packet
        self.packets.put_nowait(packet)

    def on_sco_packet(self, packet: bytes) -> None:
        if not self.isochronous_out_transfers:
            logger.warning(color('isochronous packets not supported', 'red'))
            return

        if len(packet) < HCI_SCO_HEADER_SIZE:
            logger.warning('SCO packet too short')
            return

        # Re-packetize the data into HCI SCO packets that exactly fill
        # USB_FRAMES_PER_SCO_PACKET isochronous packets, keeping the remainder until
        # more data is available.
        handle = int.from_bytes(packet[:2], 'little') & 0x0FFF
        buffer = self.sco_buffers.setdefault(handle, bytearray())
        buffer.extend(packet[HCI_SCO_HEADER_SIZE:])
        while len(buffer) >= self.sco_packet_data_size:
            self.sco_packets.put_nowait(
                packet[:2]
                + bytes([self.sco_packet_data_size])
                + bytes(buffer[: self.sco_packet_data_size])
            )
            del buffer[: self.sco_packet_data_size]

    def sco_transfer_callback(self, transfer):
        _safe_call_soon(
            self.loop, self.free_isochronous_out_transfers.put_nowait, transfer
        )
        status = transfer.getStatus()
        if status != usb1.TRANSFER_COMPLETED:
            logger.warning(
                color(f'!!! SCO OUT transfer not completed: status={status}', 'red')
            )

    async def process_sco_queue(self):
        iso_max_packet_size = (self.sco_packet_data_size + HCI_SCO_HEADER_SIZE) // (
            self.sco_frames_per_packet
        )
        while not self.closed:
            packet = await self.sco_packets.get()
            transfer = await self.free_isochronous_out_transfers.get()
            try:
                transfer.setIsochronous(
                    self.isochronous_out.getAddress(),
                    packet,
                    callback=self.sco_transfer_callback,
                    iso_transfer_length_list=[iso_max_packet_size]
                    * self.sco_frames_per_packet,
                )
                transfer.submit()
            except Exception as error:
                logger.warning(f'!!! exception while submitting SCO transfer: {error}')
                self.free_isochronous_out_transfers.put_nowait(transfer)

    def transfer_callback(self, transfer):
        _safe_call_soon(self.loop, self.out_transfer_ready.release)
        status = transfer.getStatus()

        logger.debug(f"OUT CALLBACK: {status}")

        if status != usb1.TRANSFER_COMPLETED:
            logger.warning(
                color(
                    f'!!! OUT transfer not completed: status={status}',
                    'red',
                )
            )

    async def process_queue(self):
        while not self.closed:
            # Wait for a packet to transfer.
            packet = await self.packets.get()

            # Wait until we can start a transfer.
            await self.out_transfer_ready.acquire()

            # Transfer the packet.
            packet_type = packet[0]
            packet_payload = packet[1:]
            submitted = False
            try:
                if packet_type == hci.HCI_ACL_DATA_PACKET:
                    self.bulk_or_control_out_transfer.setBulk(
                        self.bulk_out.getAddress(),
                        packet_payload,
                        callback=self.transfer_callback,
                    )
                    self.bulk_or_control_out_transfer.submit()
                    submitted = True
                elif packet_type == hci.HCI_COMMAND_PACKET:
                    # A controller that isn't the first interface of a composite
                    # device must be addressed by its interface number, or the
                    # command goes to whichever function owns interface 0
                    # (Core Spec Vol 4, Part B, 2.2.2)
                    self.bulk_or_control_out_transfer.setControl(
                        (
                            USB_RECIPIENT_INTERFACE
                            if self.interface_number
                            else USB_RECIPIENT_DEVICE
                        )
                        | USB_REQUEST_TYPE_CLASS,
                        0,
                        0,
                        self.interface_number,
                        packet_payload,
                        callback=self.transfer_callback,
                    )
                    self.bulk_or_control_out_transfer.submit()
                    submitted = True
                elif packet_type == hci.HCI_ISO_DATA_PACKET:
                    if not self.isochronous_out_transfers:
                        # Workaround: Send ISO packets over Bulk Out when Isochronous endpoints are not enabled
                        self.bulk_or_control_out_transfer.setBulk(
                            self.bulk_out.getAddress(),
                            packet_payload,
                            callback=self.transfer_callback,
                        )
                        self.bulk_or_control_out_transfer.submit()
                        submitted = True
                    else:
                        logger.warning(
                            color(
                                'ISO packets over Isochronous endpoints not supported yet',
                                'red',
                            )
                        )
                        self.out_transfer_ready.release()
                        continue
                else:
                    logger.warning(
                        color(f'unsupported packet type {packet_type}', 'red')
                    )
            except Exception as error:
                logger.warning(f'!!! exception while submitting transfer: {error}')

            if not submitted:
                self.out_transfer_ready.release()

    def close(self):
        self.closed = True

    async def terminate(self):
        self.close()

        if self.queue_task:
            self.queue_task.cancel()
        if self.sco_queue_task:
            self.sco_queue_task.cancel()

        # Empty the packet queues so that we don't send any more data
        while not self.packets.empty():
            self.packets.get_nowait()
        while not self.sco_packets.empty():
            self.sco_packets.get_nowait()

        # SCO transfers in flight complete on their own within a few frames, and are
        # finalized after the libusb event thread is joined (see below).
        for transfer in self.isochronous_out_transfers:
            if transfer.isSubmitted():
                try:
                    transfer.cancel()
                except usb1.USBError as error:
                    logger.debug(f'SCO OUT transfer likely already completed ({error})')

        # If we have transfers in flight, cancel them
        for transfer in (self.bulk_or_control_out_transfer,):
            if transfer.isSubmitted():
                # Try to cancel the transfer, but that may fail because it may have
                # already completed
                try:
                    transfer.cancel()

                    logger.debug('waiting for OUT transfer cancellation to be done...')
                    await self.out_transfer_ready.acquire()
                    logger.debug('OUT transfer cancellation done')
                except usb1.USBError as error:
                    logger.debug(f'OUT transfer likely already completed ({error})')

        # Do not close the transfer objects here. The callbacks that wake this
        # coroutine run on the libusb event thread and may not have returned yet.
        # UsbTransport.close() stops and joins that thread before device.close()
        # finalizes the transfers.


READ_SIZE = 4096


class PacketSplitter:
    """Splitter than can parse a byte stream and extract packets that consist of a
    header and a body, where the header includes an n-byte 'length' field at a
    certain offset.
    Extracted packets are emitted by calling a function passed to the constructor,
    with the full packet (header + body) as argument.
    """

    def __init__(
        self, length_offset: int, length_size: int, emit: Callable[[bytes], Any]
    ) -> None:
        self.emit = emit
        self.packet = b''
        self.length_offset = length_offset
        self.length_size = length_size
        self.header_size = length_offset + length_size

    def feed(self, data: bytes) -> None:
        while data:
            # Accumulate until we have a complete header
            if (bytes_needed := self.header_size - len(self.packet)) > 0:
                self.packet += data[:bytes_needed]
                data = data[bytes_needed:]
                if len(self.packet) < self.header_size:
                    continue

            packet_length = self.header_size + int.from_bytes(
                self.packet[self.length_offset : self.length_offset + self.length_size],
                'little',
            )
            bytes_needed = packet_length - len(self.packet)
            self.packet += data[:bytes_needed]
            data = data[bytes_needed:]
            if len(self.packet) == packet_length:
                # Packet complete
                self.emit(self.packet)
                self.packet = b''


class ScoPacketSplitter(PacketSplitter):
    def __init__(self, emit: Callable[[bytes], Any]) -> None:
        # The length field is 1 byte at offset 2 in the HCI SCO packet header
        super().__init__(length_offset=2, length_size=1, emit=emit)


class EventPacketSplitter(PacketSplitter):
    def __init__(self, emit: Callable[[bytes], Any]) -> None:
        # The length field is 1 byte at offset 1 in the HCI Event packet header
        super().__init__(length_offset=1, length_size=1, emit=emit)


class AclPacketSplitter(PacketSplitter):
    def __init__(self, emit: Callable[[bytes], Any]) -> None:
        # The length field is 2 bytes at offset 2 in the HCI ACL packet header
        super().__init__(length_offset=2, length_size=2, emit=emit)


class UsbPacketSource(asyncio.Protocol, BaseSource):
    def __init__(self, device, metadata, interrupt_in, bulk_in, isochronous_in):
        super().__init__()
        self.device = device
        self.metadata = metadata
        self.interrupt_in = interrupt_in
        self.interrupt_in_transfer = None
        self.bulk_in = bulk_in
        self.bulk_in_transfer = None
        self.isochronous_in = isochronous_in
        self.isochronous_in_transfers = []
        self.loop = asyncio.get_running_loop()
        self.queue = asyncio.Queue()
        self.dequeue_task = None
        self.done = {}
        self.splitters = {
            hci.HCI_EVENT_PACKET: EventPacketSplitter(
                lambda packet: self.queue_packet(hci.HCI_EVENT_PACKET, packet)
            ),
            hci.HCI_ACL_DATA_PACKET: AclPacketSplitter(
                lambda packet: self.queue_packet(hci.HCI_ACL_DATA_PACKET, packet)
            ),
            hci.HCI_SYNCHRONOUS_DATA_PACKET: ScoPacketSplitter(
                lambda packet: self.queue_packet(
                    hci.HCI_SYNCHRONOUS_DATA_PACKET, packet
                )
            ),
        }
        self.closed = False
        self.lock = threading.Lock()
        self.event_hook: Callable[[bytes], None] | None = None

    def start_sco(self, isochronous_in) -> None:
        self.isochronous_in = isochronous_in
        for _ in range(NUMBER_OF_SCO_IN_TRANSFERS):
            transfer = self.device.getTransfer(iso_packets=MAX_SCO_IN_PACKETS)
            transfer.setIsochronous(
                isochronous_in.getAddress(),
                MAX_SCO_IN_PACKETS * isochronous_in.getMaxPacketSize(),
                callback=self.transfer_callback,
                user_data=hci.HCI_SYNCHRONOUS_DATA_PACKET,
            )
            self.isochronous_in_transfers.append(transfer)
            self.done[transfer] = asyncio.Event()
            transfer.submit()

    def stop_sco(self) -> None:
        for transfer in self.isochronous_in_transfers:
            if transfer.isSubmitted():
                try:
                    transfer.cancel()
                except usb1.USBError:
                    pass
        self.isochronous_in_transfers = []

    def start(self):
        # Set up transfer objects for input
        self.interrupt_in_transfer = self.device.getTransfer()
        self.interrupt_in_transfer.setInterrupt(
            self.interrupt_in.getAddress(),
            READ_SIZE,
            callback=self.transfer_callback,
            user_data=hci.HCI_EVENT_PACKET,
        )
        self.done[self.interrupt_in_transfer] = asyncio.Event()
        self.interrupt_in_transfer.submit()

        self.bulk_in_transfer = self.device.getTransfer()
        self.bulk_in_transfer.setBulk(
            self.bulk_in.getAddress(),
            READ_SIZE,
            callback=self.transfer_callback,
            user_data=hci.HCI_ACL_DATA_PACKET,
        )
        self.done[self.bulk_in_transfer] = asyncio.Event()
        self.bulk_in_transfer.submit()

        if self.isochronous_in is not None:
            for _ in range(NUMBER_OF_SCO_IN_TRANSFERS):
                transfer = self.device.getTransfer(iso_packets=MAX_SCO_IN_PACKETS)
                transfer.setIsochronous(
                    self.isochronous_in.getAddress(),
                    MAX_SCO_IN_PACKETS * self.isochronous_in.getMaxPacketSize(),
                    callback=self.transfer_callback,
                    user_data=hci.HCI_SYNCHRONOUS_DATA_PACKET,
                )
                self.isochronous_in_transfers.append(transfer)
                self.done[transfer] = asyncio.Event()
                transfer.submit()

        self.dequeue_task = self.loop.create_task(self.dequeue())

    def queue_packet(self, packet_type: int, packet_data: bytes) -> None:
        if (
            packet_type == hci.HCI_SYNCHRONOUS_DATA_PACKET
            and len(packet_data) >= HCI_SCO_HEADER_SIZE
            and packet_data[2] == 0
        ):
            # Empty SCO packets may be received around alternate setting changes.
            return
        _safe_call_soon(
            self.loop, self.queue.put_nowait, bytes([packet_type]) + packet_data
        )

    def transfer_callback(self, transfer):
        packet_type = transfer.getUserData()
        status = transfer.getStatus()

        # pylint: disable=no-member
        if (
            packet_type != hci.HCI_SYNCHRONOUS_DATA_PACKET
            or transfer.getActualLength()
            or status != usb1.TRANSFER_COMPLETED
        ):
            logger.debug(
                f"IN[{packet_type}] CALLBACK: status={status}, length={transfer.getActualLength()}"
            )
        if status == usb1.TRANSFER_COMPLETED:
            with self.lock:
                if self.closed:
                    logger.debug("packet source closed, discarding transfer")
                elif (splitter := self.splitters.get(packet_type)) is None:
                    logger.warning(f'no splitter for packet type {packet_type}')
                else:
                    if packet_type == hci.HCI_SYNCHRONOUS_DATA_PACKET:
                        for iso_status, iso_buffer in transfer.iterISO():
                            if not iso_buffer:
                                continue
                            if iso_status:
                                logger.warning(f"ISO packet status error: {iso_status}")
                                continue
                            logger.debug(
                                "### SCO packet: %d %s",
                                len(iso_buffer),
                                iso_buffer.hex(),
                            )
                            splitter.feed(iso_buffer)
                    else:
                        splitter.feed(
                            transfer.getBuffer()[: transfer.getActualLength()]
                        )

                    # Re-submit the transfer so we can receive more data
                    try:
                        transfer.submit()
                    except usb1.USBError as error:
                        logger.warning(f"Failed to re-submit transfer: {error}")
                        _safe_call_soon(self.loop, self.on_transport_lost)
        elif status == usb1.TRANSFER_CANCELLED:
            logger.debug(f"IN[{packet_type}] transfer canceled")
            _safe_call_soon(self.loop, self.done[transfer].set)
        else:
            logger.warning(
                color(f'!!! IN[{packet_type}] transfer not completed', 'red')
            )
            _safe_call_soon(self.loop, self.done[transfer].set)
            _safe_call_soon(self.loop, self.on_transport_lost)

    async def dequeue(self):
        while not self.closed:
            try:
                packet = await self.queue.get()
            except asyncio.CancelledError:
                return
            if self.event_hook and packet[0] == hci.HCI_EVENT_PACKET:
                try:
                    self.event_hook(packet)
                except Exception:
                    logger.exception(color('!!! Exception in event hook', 'red'))
            if self.sink:
                try:
                    self.sink.on_packet(packet)
                except Exception:
                    logger.exception(color('!!! Exception in sink.on_packet', 'red'))

    def close(self):
        with self.lock:
            self.closed = True

    async def terminate(self):
        self.close()

        if self.dequeue_task:
            self.dequeue_task.cancel()

        # Cancel the transfers
        for transfer in (
            self.interrupt_in_transfer,
            self.bulk_in_transfer,
            *self.isochronous_in_transfers,
        ):
            if transfer is None:
                continue

            if transfer.isSubmitted():
                # Try to cancel the transfer, but that may fail because it may
                # have already completed
                packet_type = transfer.getUserData()
                assert isinstance(packet_type, int)
                try:
                    transfer.cancel()
                    logger.debug(
                        f'waiting for IN[{packet_type}] transfer cancellation '
                        'to be done...'
                    )
                    await self.done[transfer].wait()
                    logger.debug(f'IN[{packet_type}] transfer cancellation done')
                except usb1.USBError as error:
                    logger.debug(
                        f'IN[{packet_type}] transfer likely already completed '
                        f'({error})'
                    )


class UsbTransport(Transport):
    def __init__(
        self,
        context,
        device,
        acl_interface,
        sco_interface,
        source: UsbPacketSource,
        sink: UsbPacketSink,
    ):
        super().__init__(source, sink)
        self.usb_source = source
        self.usb_sink = sink
        # Dynamic SCO alternate setting (see enable_dynamic_sco_alternate_setting)
        self.sco_settings: dict[int, tuple[Any, Any]] = {}
        self.sco_links: dict[int, int] = {}  # Air mode, by handle
        self.sco_16_bit_samples = True
        self.sco_alternate_setting = -1
        self.context = context
        self.device = device
        self.acl_interface = acl_interface
        self.sco_interface = sco_interface
        self.event_loop_should_exit = False
        self.lock = threading.Lock()
        self.closed = False

        # Get exclusive access
        device.claimInterface(acl_interface.getNumber())
        if sco_interface is not None:
            device.claimInterface(sco_interface.getNumber())

        # Set the alternate setting if not the default
        if acl_interface.getAlternateSetting() != 0:
            logger.debug(
                f'setting ACL interface {acl_interface.getNumber()} '
                f'altsetting {acl_interface.getAlternateSetting()}'
            )
            device.setInterfaceAltSetting(
                acl_interface.getNumber(), acl_interface.getAlternateSetting()
            )
        if sco_interface is not None and sco_interface.getAlternateSetting() != 0:
            logger.debug(
                f'setting SCO interface {sco_interface.getNumber()} '
                f'altsetting {sco_interface.getAlternateSetting()}'
            )
            device.setInterfaceAltSetting(
                sco_interface.getNumber(), sco_interface.getAlternateSetting()
            )

        # The source and sink can now start
        source.start()
        sink.start()

        # Create a thread to process events
        self.event_thread = threading.Thread(target=self.run, daemon=True)
        self.event_thread.start()

    def enable_dynamic_sco_alternate_setting(
        self, sco_settings: dict[int, tuple[Any, Any]]
    ) -> None:
        """Select the SCO alternate setting when SCO links are established.

        Like Linux btusb, keep alternate setting 0 while there is no SCO link, and
        switch according to the air mode, the sample size on HCI and the number of
        links when links are established or closed. Some controllers (e.g. Intel
        BE200) do not send or receive data with alternate setting 6 unless it is
        selected after the SCO link is established.
        """
        assert self.sco_interface is not None
        self.sco_settings = sco_settings
        self.sco_links = {}
        self.sco_16_bit_samples = True
        self.sco_alternate_setting = -1
        self.set_sco_alternate_setting(0)
        self.usb_source.event_hook = self.on_event_for_sco
        self.usb_sink.command_hook = self.on_command_for_sco

    def select_sco_alternate_setting(self) -> int:
        if not self.sco_links:
            return 0
        if hci.CodecID.TRANSPARENT in self.sco_links.values():
            candidates = [SCO_ALT6_ALTERNATE_SETTING, 1]
        else:
            link_count = min(len(self.sco_links), len(SCO_16_BIT_ALTERNATE_SETTINGS))
            candidates = [
                (
                    SCO_16_BIT_ALTERNATE_SETTINGS[link_count - 1]
                    if self.sco_16_bit_samples
                    else link_count
                )
            ]
        for alternate_setting in candidates:
            if alternate_setting in self.sco_settings:
                return alternate_setting
        return max(self.sco_settings)

    def set_sco_alternate_setting(self, alternate_setting: int) -> None:
        if alternate_setting == self.sco_alternate_setting:
            return
        logger.debug(f'switching SCO alternate setting to {alternate_setting}')
        self.usb_source.stop_sco()
        self.usb_sink.stop_sco()
        self.device.setInterfaceAltSetting(
            self.sco_interface.getNumber(), alternate_setting
        )
        self.sco_alternate_setting = alternate_setting
        if alternate_setting:
            isochronous_in, isochronous_out = self.sco_settings[alternate_setting]
            self.usb_source.start_sco(isochronous_in)
            self.usb_sink.configure_sco(isochronous_out, alternate_setting)

    def on_command_for_sco(self, packet: bytes) -> None:
        # Track the sample size of SCO data on HCI.
        op_code = int.from_bytes(packet[1:3], 'little')
        parameters = packet[4:]
        if op_code == hci.HCI_WRITE_VOICE_SETTING_COMMAND and len(parameters) >= 2:
            voice_setting = int.from_bytes(parameters[:2], 'little')
            self.sco_16_bit_samples = bool(voice_setting & 0x0020)
        elif op_code in (
            hci.HCI_ENHANCED_SETUP_SYNCHRONOUS_CONNECTION_COMMAND,
            hci.HCI_ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND,
        ):
            # Input_Coded_Data_Size, after the connection handle (2 bytes) or BD_ADDR
            # (6 bytes), bandwidths, coding formats, codec frame sizes and input /
            # output bandwidths and coding formats.
            offset = (
                2
                if op_code == hci.HCI_ENHANCED_SETUP_SYNCHRONOUS_CONNECTION_COMMAND
                else 6
            ) + 40
            if len(parameters) >= offset + 2:
                coded_data_size = int.from_bytes(
                    parameters[offset : offset + 2], 'little'
                )
                self.sco_16_bit_samples = coded_data_size != 8

    def on_event_for_sco(self, packet: bytes) -> None:
        event_code = packet[1]
        if (
            event_code == hci.HCI_SYNCHRONOUS_CONNECTION_COMPLETE_EVENT
            and packet[3] == hci.HCI_SUCCESS
        ):
            handle = int.from_bytes(packet[4:6], 'little') & 0x0FFF
            air_mode = packet[19]
            logger.debug(f'SCO link 0x{handle:04X} established, air mode {air_mode}')
            self.sco_links[handle] = air_mode
        elif (
            event_code == hci.HCI_DISCONNECTION_COMPLETE_EVENT
            and packet[3] == hci.HCI_SUCCESS
        ):
            handle = int.from_bytes(packet[4:6], 'little') & 0x0FFF
            if self.sco_links.pop(handle, None) is None:
                return
        else:
            return
        self.set_sco_alternate_setting(self.select_sco_alternate_setting())

    def run(self):
        logger.debug('starting USB event loop')
        while True:
            with self.lock:
                if self.event_loop_should_exit:
                    logger.debug("USB event loop exit requested")
                    break

            # pylint: disable=no-member
            try:
                self.context.handleEvents()
            except usb1.USBErrorInterrupted:
                pass
            except Exception as error:
                logger.warning(f'!!! Exception while handling events: {error}')

        logger.debug('ending USB event loop')

    async def close(self):
        # close() may be reached both explicitly and through Transport.__aexit__.
        # Guard the native resources from a second teardown.
        if self.closed:
            return
        self.closed = True

        self.source.close()
        self.sink.close()
        await self.source.terminate()
        await self.sink.terminate()

        # We no longer need the event loop to run
        with self.lock:
            self.event_loop_should_exit = True
        try:
            self.context.interruptEventHandler()
        except (AttributeError, usb1.USBError) as error:
            logger.warning(f"Failed to interrupt event handler: {error}")

        # handleEvents() owns libusb state until the event thread has returned.
        # In particular, transfer cancellation callbacks only schedule their
        # asyncio completion signals; those signals do not prove that the native
        # callback has returned. Wait and join before freeing transfers, the
        # device handle, or the context.
        logger.debug("waiting for USB event loop to be done...")
        await asyncio.to_thread(self.event_thread.join)
        logger.debug("USB event loop done")

        self.device.releaseInterface(self.acl_interface.getNumber())
        if self.sco_interface:
            self.device.releaseInterface(self.sco_interface.getNumber())
        self.device.close()
        self.context.close()


async def open_usb_transport(spec: str) -> Transport:
    '''
    Open a USB transport.
    The moniker string has this syntax:
    either <index> or
    <vendor>:<product> or
    <vendor>:<product>/<serial-number>] or
    <vendor>:<product>#<index>
    With <index> as the 0-based index to select amongst all the devices that appear
    to be supporting Bluetooth HCI (0 being the first one), or
    Where <vendor> and <product> are the vendor ID and product ID in hexadecimal. The
    /<serial-number> suffix or #<index> suffix max be specified when more than one
    device with the same vendor and product identifiers are present.

    Opotionally, the moniker may include a +sco=<alternate> suffix to enable SCO/eSCO
    and specify the alternate setting to use for SCO/eSCO transfers, with 0 meaning an
    automatic selection.

    In addition, if the moniker ends with the symbol "!", the device will be used in
    "forced" mode:
    the first USB interface of the device will be used, regardless of the interface
    class/subclass.
    This may be useful for some devices that use a custom class/subclass but may
    nonetheless work as-is.

    Examples:
    0 --> the first BT USB dongle
    04b4:f901 --> the BT USB dongle with vendor=04b4 and product=f901
    04b4:f901#2 --> the third USB device with vendor=04b4 and product=f901
    04b4:f901/00E04C239987 --> the BT USB dongle with vendor=04b4 and product=f901 and
    serial number 00E04C239987
    0B05:17CB! --> the BT USB dongle with vendor=0B05 and product=17CB, in "forced"
    mode.
    0+sco=0 --> the first BT USB dongle, with SCO enabled using auto-selection.
    0+sco=5 --> the first BT USB dongle, with SCO enabled using alternate setting 5.
    '''

    # Find the device according to the spec moniker
    load_libusb()
    context = usb1.USBContext()
    context.open()
    try:
        found = None
        device = None

        if spec.endswith('!'):
            spec = spec[:-1]
            forced_mode = True
        else:
            forced_mode = False

        if '+sco=' in spec:
            spec, sco_alternate_str = spec.split('+sco=')
            sco_alternate = int(sco_alternate_str)
        else:
            sco_alternate = None

        if ':' in spec:
            vendor_id, product_id = spec.split(':')
            serial_number = None
            device_index = 0
            if '/' in product_id:
                product_id, serial_number = product_id.split('/')
            elif '#' in product_id:
                product_id, device_index_str = product_id.split('#')
                device_index = int(device_index_str)

            for device in context.getDeviceIterator(skip_on_error=True):
                try:
                    device_serial_number = device.getSerialNumber()
                except usb1.USBError:
                    device_serial_number = None
                if (
                    device.getVendorID() == int(vendor_id, 16)
                    and device.getProductID() == int(product_id, 16)
                    and (serial_number is None or serial_number == device_serial_number)
                ):
                    if device_index == 0:
                        found = device
                        break
                    device_index -= 1
                device.close()
        elif '-' in spec:

            def device_path(device):
                return f'{device.getBusNumber()}-{".".join(map(str, device.getPortNumberList()))}'

            for device in context.getDeviceIterator(skip_on_error=True):
                if device_path(device) == spec:
                    found = device
                    break
                device.close()
        else:
            # Look for a compatible device by index
            def device_is_bluetooth_hci(device):
                # Check if the device class indicates a match
                if (
                    device.getDeviceClass(),
                    device.getDeviceSubClass(),
                    device.getDeviceProtocol(),
                ) == USB_BT_HCI_CLASS_TUPLE:
                    return True

                # If the device class is 'Device' or 'Miscellaneous' (composite
                # devices), look for a matching interface
                if device.getDeviceClass() in (
                    USB_DEVICE_CLASS_DEVICE,
                    USB_DEVICE_CLASS_MISCELLANEOUS,
                ):
                    for configuration in device:
                        for interface in configuration:
                            for setting in interface:
                                if (
                                    setting.getClass(),
                                    setting.getSubClass(),
                                    setting.getProtocol(),
                                ) == USB_BT_HCI_CLASS_TUPLE:
                                    return True

                return False

            device_index = int(spec)
            for device in context.getDeviceIterator(skip_on_error=True):
                if device_is_bluetooth_hci(device):
                    if device_index == 0:
                        found = device
                        break
                    device_index -= 1
                device.close()

        if found is None:
            context.close()
            raise TransportInitError('device not found')

        logger.debug(f'USB Device: {found}')

        assert device is not None
        endpoints = find_endpoints(device, forced_mode, sco_alternate)
        found_configuration = None
        if endpoints is None:
            raise TransportInitError('no compatible interface found for device')
        (
            configuration,
            acl_interface,
            sco_interface,
            interrupt_in,
            bulk_in,
            isochronous_in,
            bulk_out,
            isochronous_out,
        ) = endpoints
        acl_interface_info = (
            f'acl_interface={acl_interface.getNumber()}/'
            f'{acl_interface.getAlternateSetting()}'
        )
        sco_interface_info = (
            '<none>'
            if sco_interface is None
            else (
                f'sco_interface={sco_interface.getNumber()}/'
                f'{sco_interface.getAlternateSetting()}'
            )
        )
        logger.debug(
            f'selected endpoints: configuration={configuration}, '
            f'acl_interface={acl_interface_info}, '
            f'sco_interface={sco_interface_info}, '
            f'interrupt_in=0x{interrupt_in.getAddress():02X}, '
            f'bulk_in=0x{bulk_in.getAddress():02X}, '
            f'bulk_out=0x{bulk_out.getAddress():02X}, '
            f'isochronous_in=0x{isochronous_in.getAddress() if isochronous_in else 0:02X}, '
            f'isochronous_out=0x{isochronous_out.getAddress() if isochronous_out else 0:02X}'
        )

        for configuration_index, device_configuration in enumerate(device):
            if configuration_index + 1 == configuration:
                found_configuration = device_configuration
        device_metadata = {
            'vendor_id': found.getVendorID(),
            'product_id': found.getProductID(),
        }
        device = found.open()

        # Auto-detach the kernel driver if supported
        # pylint: disable=no-member
        if usb1.hasCapability(usb1.CAP_SUPPORTS_DETACH_KERNEL_DRIVER):
            try:
                logger.debug('auto-detaching kernel driver')
                device.setAutoDetachKernelDriver(True)
            except usb1.USBError as error:
                logger.warning(f'unable to auto-detach kernel driver: {error}')

        # Set the configuration if needed
        try:
            current_configuration = device.getConfiguration()
            logger.debug(f'current configuration = {current_configuration}')
        except usb1.USBError:
            current_configuration = 0

        if current_configuration != configuration:
            try:
                logger.debug(f'setting configuration {configuration}')
                device.setConfiguration(configuration)
            except usb1.USBError:
                logger.warning('failed to set configuration')

        if sco_alternate == 0 and sco_interface is not None:
            # The SCO endpoints are selected once a SCO link is established.
            isochronous_in = isochronous_out = None
        source = UsbPacketSource(
            device, device_metadata, interrupt_in, bulk_in, isochronous_in
        )
        sink = UsbPacketSink(
            device,
            bulk_out,
            isochronous_out,
            acl_interface.getNumber(),
            (
                sco_interface.getAlternateSetting()
                if sco_interface is not None and sco_alternate != 0
                else 0
            ),
        )
        transport = UsbTransport(
            context, device, acl_interface, sco_interface, source, sink
        )
        if sco_alternate == 0 and sco_interface is not None:
            transport.enable_dynamic_sco_alternate_setting(
                find_sco_settings(found_configuration, sco_interface.getNumber())
            )
        return transport
    except usb1.USBError as error:
        logger.warning(color(f'!!! failed to open USB device: {error}', 'red'))
        context.close()
        raise
