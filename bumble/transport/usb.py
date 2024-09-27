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
# Constants
# -----------------------------------------------------------------------------
# pylint: disable=invalid-name
USB_RECIPIENT_DEVICE = 0x00
USB_REQUEST_TYPE_CLASS = 0x01 << 5
USB_DEVICE_CLASS_DEVICE = 0x00
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
                isochronous_in,
                bulk_out,
                isochronous_out,
            )

        logger.debug(f'skipping configuration {configuration_index + 1}')

    return None


class UsbPacketSink:
    def __init__(self, device, bulk_out, isochronous_out):
        self.device = device
        self.packets = asyncio.Queue[bytes]()  # Queue of packets waiting to be sent
        self.bulk_out = bulk_out
        self.isochronous_out = isochronous_out
        self.bulk_or_control_out_transfer = device.getTransfer()
        self.isochronous_out_transfer = device.getTransfer(iso_packets=1)
        self.out_transfer_ready = asyncio.Semaphore(1)
        self.packets: asyncio.Queue[bytes] = (
            asyncio.Queue()
        )  # Queue of packets waiting to be sent
        self.loop = asyncio.get_running_loop()
        self.queue_task = None
        self.closed = False

    def start(self):
        self.queue_task = asyncio.create_task(self.process_queue())

    def on_packet(self, packet):
        # Ignore packets if we're closed
        if self.closed:
            return

        if len(packet) == 0:
            logger.warning('packet too short')
            return

        # Queue the packet
        self.packets.put_nowait(packet)

    def transfer_callback(self, transfer):
        self.loop.call_soon_threadsafe(self.out_transfer_ready.release)
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
                    self.bulk_or_control_out_transfer.setControl(
                        USB_RECIPIENT_DEVICE | USB_REQUEST_TYPE_CLASS,
                        0,
                        0,
                        0,
                        packet_payload,
                        callback=self.transfer_callback,
                    )
                    self.bulk_or_control_out_transfer.submit()
                    submitted = True
                elif packet_type == hci.HCI_SYNCHRONOUS_DATA_PACKET:
                    if self.isochronous_out is None:
                        logger.warning(
                            color('isochronous packets not supported', 'red')
                        )
                        self.out_transfer_ready.release()
                        continue

                    self.isochronous_out_transfer.setIsochronous(
                        self.isochronous_out.getAddress(),
                        packet_payload,
                        callback=self.transfer_callback,
                    )
                    self.isochronous_out_transfer.submit()
                    submitted = True
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

        # Empty the packet queue so that we don't send any more data
        while not self.packets.empty():
            self.packets.get_nowait()

        # If we have transfers in flight, cancel them
        for transfer in (
            self.bulk_or_control_out_transfer,
            self.isochronous_out_transfer,
        ):
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


READ_SIZE = 4096


class ScoAccumulator:
    def __init__(self, emit: Callable[[bytes], Any]) -> None:
        self.emit = emit
        self.packet = b''

    def feed(self, data: bytes) -> None:
        while data:
            # Accumulate until we have a complete 3-byte header
            if (bytes_needed := 3 - len(self.packet)) > 0:
                self.packet += data[:bytes_needed]
                data = data[bytes_needed:]
                continue

            packet_length = 3 + self.packet[2]
            bytes_needed = packet_length - len(self.packet)
            self.packet += data[:bytes_needed]
            data = data[bytes_needed:]
            if len(self.packet) == packet_length:
                # Packet complete
                self.emit(self.packet)
                self.packet = b''


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
        self.isochronous_in_transfer = None
        self.isochronous_accumulator = ScoAccumulator(
            lambda packet: self.queue_packet(hci.HCI_SYNCHRONOUS_DATA_PACKET, packet)
        )
        self.loop = asyncio.get_running_loop()
        self.queue = asyncio.Queue()
        self.dequeue_task = None
        self.done = {
            hci.HCI_EVENT_PACKET: asyncio.Event(),
            hci.HCI_ACL_DATA_PACKET: asyncio.Event(),
            hci.HCI_SYNCHRONOUS_DATA_PACKET: asyncio.Event(),
        }
        self.closed = False
        self.lock = threading.Lock()

    def start(self):
        # Set up transfer objects for input
        self.interrupt_in_transfer = self.device.getTransfer()
        self.interrupt_in_transfer.setInterrupt(
            self.interrupt_in.getAddress(),
            READ_SIZE,
            callback=self.transfer_callback,
            user_data=hci.HCI_EVENT_PACKET,
        )
        self.interrupt_in_transfer.submit()

        self.bulk_in_transfer = self.device.getTransfer()
        self.bulk_in_transfer.setBulk(
            self.bulk_in.getAddress(),
            READ_SIZE,
            callback=self.transfer_callback,
            user_data=hci.HCI_ACL_DATA_PACKET,
        )
        self.bulk_in_transfer.submit()

        if self.isochronous_in is not None:
            self.isochronous_in_transfer = self.device.getTransfer(iso_packets=16)
            self.isochronous_in_transfer.setIsochronous(
                self.isochronous_in.getAddress(),
                16 * self.isochronous_in.getMaxPacketSize(),
                callback=self.transfer_callback,
                user_data=hci.HCI_SYNCHRONOUS_DATA_PACKET,
            )
            self.isochronous_in_transfer.submit()

        self.dequeue_task = self.loop.create_task(self.dequeue())

    def queue_packet(self, packet_type: int, packet_data: bytes) -> None:
        self.loop.call_soon_threadsafe(
            self.queue.put_nowait, bytes([packet_type]) + packet_data
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
                            self.isochronous_accumulator.feed(iso_buffer)
                    else:
                        self.queue_packet(
                            packet_type,
                            transfer.getBuffer()[: transfer.getActualLength()],
                        )

                    # Re-submit the transfer so we can receive more data
                    try:
                        transfer.submit()
                    except usb1.USBError as error:
                        logger.warning(f"Failed to re-submit transfer: {error}")
                        self.loop.call_soon_threadsafe(self.on_transport_lost)
        elif status == usb1.TRANSFER_CANCELLED:
            logger.debug(f"IN[{packet_type}] transfer canceled")
            self.loop.call_soon_threadsafe(self.done[packet_type].set)
        else:
            logger.warning(
                color(f'!!! IN[{packet_type}] transfer not completed', 'red')
            )
            self.loop.call_soon_threadsafe(self.done[packet_type].set)
            self.loop.call_soon_threadsafe(self.on_transport_lost)

    async def dequeue(self):
        while not self.closed:
            try:
                packet = await self.queue.get()
            except asyncio.CancelledError:
                return
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
            self.isochronous_in_transfer,
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
                    await self.done[packet_type].wait()
                    logger.debug(f'IN[{packet_type}] transfer cancellation done')
                except usb1.USBError as error:
                    logger.debug(
                        f'IN[{packet_type}] transfer likely already completed '
                        f'({error})'
                    )


class UsbTransport(Transport):
    def __init__(self, context, device, acl_interface, sco_interface, source, sink):
        super().__init__(source, sink)
        self.context = context
        self.device = device
        self.acl_interface = acl_interface
        self.sco_interface = sco_interface
        self.loop = asyncio.get_running_loop()
        self.event_loop_done = self.loop.create_future()
        self.event_loop_should_exit = False
        self.lock = threading.Lock()

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
        self.event_thread = threading.Thread(target=self.run)
        self.event_thread.start()

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
        self.loop.call_soon_threadsafe(self.event_loop_done.set_result, None)

    async def close(self):
        self.source.close()
        self.sink.close()
        await self.source.terminate()
        await self.sink.terminate()

        # We no longer need the event loop to run
        with self.lock:
            self.event_loop_should_exit = True
        self.context.interruptEventHandler()

        self.device.releaseInterface(self.acl_interface.getNumber())
        if self.sco_interface:
            self.device.releaseInterface(self.sco_interface.getNumber())
        self.device.close()
        self.context.close()

        # Wait for the thread to terminate
        logger.debug("waiting for USB event loop to be done...")
        await self.event_loop_done
        logger.debug("USB event loop done")


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

                # If the device class is 'Device', look for a matching interface
                if device.getDeviceClass() == USB_DEVICE_CLASS_DEVICE:
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

        source = UsbPacketSource(
            device, device_metadata, interrupt_in, bulk_in, isochronous_in
        )
        sink = UsbPacketSink(device, bulk_out, isochronous_out)
        return UsbTransport(context, device, acl_interface, sco_interface, source, sink)
    except usb1.USBError as error:
        logger.warning(color(f'!!! failed to open USB device: {error}', 'red'))
        context.close()
        raise
