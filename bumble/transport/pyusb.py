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
import asyncio
import logging
import threading
import time

import usb.core
import usb.util

from typing import Optional
from usb.core import Device as UsbDevice
from usb.core import USBError
from usb.util import CTRL_TYPE_CLASS, CTRL_RECIPIENT_OTHER
from usb.legacy import REQ_SET_FEATURE, REQ_CLEAR_FEATURE, CLASS_HUB

from .common import Transport, ParserSource
from .. import hci
from ..colors import color


# -----------------------------------------------------------------------------
# Constant
# -----------------------------------------------------------------------------
USB_PORT_FEATURE_POWER = 8
POWER_CYCLE_DELAY = 1
RESET_DELAY = 3

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_pyusb_transport(spec: str) -> Transport:
    '''
    Open a USB transport. [Implementation based on PyUSB]
    The parameter string has this syntax:
    either <index> or <vendor>:<product>
    With <index> as the 0-based index to select amongst all the devices that appear
    to be supporting Bluetooth HCI (0 being the first one), or
    Where <vendor> and <product> are the vendor ID and product ID in hexadecimal.

    Examples:
    0 --> the first BT USB dongle
    04b4:f901 --> the BT USB dongle with vendor=04b4 and product=f901
    '''

    # pylint: disable=invalid-name
    USB_RECIPIENT_DEVICE = 0x00
    USB_REQUEST_TYPE_CLASS = 0x01 << 5
    USB_ENDPOINT_EVENTS_IN = 0x81
    USB_ENDPOINT_ACL_IN = 0x82
    USB_ENDPOINT_SCO_IN = 0x83
    USB_ENDPOINT_ACL_OUT = 0x02
    #  USB_ENDPOINT_SCO_OUT                             = 0x03
    USB_DEVICE_CLASS_WIRELESS_CONTROLLER = 0xE0
    USB_DEVICE_SUBCLASS_RF_CONTROLLER = 0x01
    USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER = 0x01

    READ_SIZE = 1024
    READ_TIMEOUT = 1000

    class UsbPacketSink:
        def __init__(self, device):
            self.device = device
            self.thread = threading.Thread(target=self.run)
            self.loop = asyncio.get_running_loop()
            self.stop_event = None

        def on_packet(self, packet):
            # TODO: don't block here, just queue for the write thread
            if len(packet) == 0:
                logger.warning('packet too short')
                return

            packet_type = packet[0]
            try:
                if packet_type == hci.HCI_ACL_DATA_PACKET:
                    self.device.write(USB_ENDPOINT_ACL_OUT, packet[1:])
                elif packet_type == hci.HCI_COMMAND_PACKET:
                    self.device.ctrl_transfer(
                        USB_RECIPIENT_DEVICE | USB_REQUEST_TYPE_CLASS,
                        0,
                        0,
                        0,
                        packet[1:],
                    )
                else:
                    logger.warning(
                        color(f'unsupported packet type {packet_type}', 'red')
                    )
            except usb.core.USBTimeoutError:
                logger.warning('USB Write Timeout')
            except usb.core.USBError as error:
                logger.warning(f'USB write error: {error}')
                time.sleep(1)  # Sleep one second to avoid busy looping

        def start(self):
            self.thread.start()

        async def stop(self):
            # Create stop events and wait for them to be signaled
            self.stop_event = asyncio.Event()
            await self.stop_event.wait()

        def run(self):
            while self.stop_event is None:
                time.sleep(1)
            self.loop.call_soon_threadsafe(self.stop_event.set)

    class UsbPacketSource(asyncio.Protocol, ParserSource):
        def __init__(self, device, metadata, sco_enabled):
            super().__init__()
            self.device = device
            self.metadata = metadata
            self.loop = asyncio.get_running_loop()
            self.queue = asyncio.Queue()
            self.dequeue_task = None
            self.event_thread = threading.Thread(
                target=self.run, args=(USB_ENDPOINT_EVENTS_IN, hci.HCI_EVENT_PACKET)
            )
            self.event_thread.stop_event = None
            self.acl_thread = threading.Thread(
                target=self.run, args=(USB_ENDPOINT_ACL_IN, hci.HCI_ACL_DATA_PACKET)
            )
            self.acl_thread.stop_event = None

            # SCO support is optional
            self.sco_enabled = sco_enabled
            if sco_enabled:
                self.sco_thread = threading.Thread(
                    target=self.run,
                    args=(USB_ENDPOINT_SCO_IN, hci.HCI_SYNCHRONOUS_DATA_PACKET),
                )
                self.sco_thread.stop_event = None

        def data_received(self, data):
            self.parser.feed_data(data)

        def enqueue(self, packet):
            self.queue.put_nowait(packet)

        async def dequeue(self):
            while True:
                try:
                    data = await self.queue.get()
                except asyncio.CancelledError:
                    return
                self.data_received(data)

        def start(self):
            self.dequeue_task = self.loop.create_task(self.dequeue())
            self.event_thread.start()
            self.acl_thread.start()
            if self.sco_enabled:
                self.sco_thread.start()

        async def stop(self):
            # Stop the dequeuing task
            self.dequeue_task.cancel()

            # Create stop events and wait for them to be signaled
            self.event_thread.stop_event = asyncio.Event()
            self.acl_thread.stop_event = asyncio.Event()
            await self.event_thread.stop_event.wait()
            await self.acl_thread.stop_event.wait()
            if self.sco_enabled:
                await self.sco_thread.stop_event.wait()

        def run(self, endpoint, packet_type):
            # Read until asked to stop
            current_thread = threading.current_thread()
            while current_thread.stop_event is None:
                try:
                    # Read, with a timeout of 1 second
                    data = self.device.read(endpoint, READ_SIZE, timeout=READ_TIMEOUT)
                    packet = bytes([packet_type]) + data.tobytes()
                    self.loop.call_soon_threadsafe(self.enqueue, packet)
                except usb.core.USBTimeoutError:
                    continue
                except usb.core.USBError:
                    # Don't log this: because pyusb doesn't really support multiple
                    # threads reading at the same time, we can get occasional
                    # USBError(errno=5) Input/Output errors reported, but they seem to
                    # be harmless.
                    # Until support for async or multi-thread support is added to pyusb,
                    # we'll just live with this as is...
                    # logger.warning(f'USB read error: {error}')
                    time.sleep(1)  # Sleep one second to avoid busy looping

            stop_event = current_thread.stop_event
            self.loop.call_soon_threadsafe(stop_event.set)

    class UsbTransport(Transport):
        def __init__(self, device, source, sink):
            super().__init__(source, sink)
            self.device = device

        async def close(self):
            await self.source.stop()
            await self.sink.stop()
            usb.util.release_interface(self.device, 0)

    usb_find = usb.core.find
    try:
        import libusb_package
    except ImportError:
        logger.debug('libusb_package is not available')
    else:
        usb_find = libusb_package.find

    # Find the device according to the spec moniker
    power_cycle = False
    if spec.startswith('!'):
        power_cycle = True
        spec = spec[1:]
    if ':' in spec:
        vendor_id, product_id = spec.split(':')
        device = usb_find(idVendor=int(vendor_id, 16), idProduct=int(product_id, 16))
    elif '-' in spec:

        def device_path(device):
            if device.port_numbers:
                return f'{device.bus}-{".".join(map(str, device.port_numbers))}'
            else:
                return str(device.bus)

        device = usb_find(custom_match=lambda device: device_path(device) == spec)
    else:
        device_index = int(spec)
        devices = list(
            usb_find(
                find_all=1,
                bDeviceClass=USB_DEVICE_CLASS_WIRELESS_CONTROLLER,
                bDeviceSubClass=USB_DEVICE_SUBCLASS_RF_CONTROLLER,
                bDeviceProtocol=USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER,
            )
        )
        if len(devices) > device_index:
            device = devices[device_index]
        else:
            device = None

    if device is None:
        raise ValueError('device not found')
    logger.debug(f'USB Device: {device}')

    # Power Cycle the device
    if power_cycle:
        try:
            device = await _power_cycle(device)  # type: ignore
        except Exception as e:
            logging.debug(e)
            logging.info(f"Unable to power cycle {hex(device.idVendor)} {hex(device.idProduct)}")  # type: ignore

    # Collect the metadata
    device_metadata = {'vendor_id': device.idVendor, 'product_id': device.idProduct}

    # Detach the kernel driver if needed
    if device.is_kernel_driver_active(0):
        logger.debug("detaching kernel driver")
        device.detach_kernel_driver(0)

    # Set configuration, if needed
    try:
        configuration = device.get_active_configuration()
    except usb.core.USBError:
        device.set_configuration()
        configuration = device.get_active_configuration()
    interface = configuration[(0, 0)]
    logger.debug(f'USB Interface: {interface}')
    usb.util.claim_interface(device, 0)

    # Select an alternate setting for SCO, if available
    sco_enabled = False
    # pylint: disable=line-too-long
    # NOTE: this is disabled for now, because SCO with alternate settings is broken,
    # see: https://github.com/libusb/libusb/issues/36
    #
    # best_packet_size = 0
    # best_interface = None
    # sco_enabled = False
    # for interface in configuration:
    #     iso_in_endpoint = None
    #     iso_out_endpoint = None
    #     for endpoint in interface:
    #         if (endpoint.bEndpointAddress == USB_ENDPOINT_SCO_IN and
    #             usb.util.endpoint_direction(endpoint.bEndpointAddress) == usb.util.ENDPOINT_IN and
    #             usb.util.endpoint_type(endpoint.bmAttributes) == usb.util.ENDPOINT_TYPE_ISO):
    #             iso_in_endpoint = endpoint
    #             continue
    #         if (endpoint.bEndpointAddress == USB_ENDPOINT_SCO_OUT and
    #             usb.util.endpoint_direction(endpoint.bEndpointAddress) == usb.util.ENDPOINT_OUT and
    #             usb.util.endpoint_type(endpoint.bmAttributes) == usb.util.ENDPOINT_TYPE_ISO):
    #             iso_out_endpoint = endpoint

    #     if iso_in_endpoint is not None and iso_out_endpoint is not None:
    #         if iso_out_endpoint.wMaxPacketSize > best_packet_size:
    #             best_packet_size = iso_out_endpoint.wMaxPacketSize
    #             best_interface = interface

    # if best_interface is not None:
    #     logger.debug(f'SCO enabled, selecting alternate setting (wMaxPacketSize={best_packet_size}): {best_interface}')
    #     sco_enabled = True
    #     try:
    #         device.set_interface_altsetting(
    #             interface = best_interface.bInterfaceNumber,
    #             alternate_setting = best_interface.bAlternateSetting
    #         )
    #     except usb.USBError:
    #         logger.warning('failed to set alternate setting')

    packet_source = UsbPacketSource(device, device_metadata, sco_enabled)
    packet_sink = UsbPacketSink(device)
    packet_source.start()
    packet_sink.start()

    return UsbTransport(device, packet_source, packet_sink)


async def _power_cycle(device: UsbDevice) -> UsbDevice:
    """
    For devices connected to compatible USB hubs: Performs a power cycle on a given USB device.
    This involves temporarily disabling its port on the hub and then re-enabling it.
    """
    device_path = f'{device.bus}-{".".join(map(str, device.port_numbers))}'  # type: ignore
    hub = _find_hub_by_device_path(device_path)

    if hub:
        try:
            device_port = device.port_numbers[-1]  # type: ignore
            _set_port_status(hub, device_port, False)
            await asyncio.sleep(POWER_CYCLE_DELAY)
            _set_port_status(hub, device_port, True)
            await asyncio.sleep(RESET_DELAY)

            # Device needs to be find again otherwise it will appear as disconnected
            return usb.core.find(idVendor=device.idVendor, idProduct=device.idProduct)  # type: ignore
        except USBError as e:
            logger.error(f"Adjustment needed: Please revise the udev rule for device {hex(device.idVendor)}:{hex(device.idProduct)} for proper recognition.")  # type: ignore
            logger.error(e)

    return device


def _set_port_status(device: UsbDevice, port: int, on: bool):
    """Sets the power status of a specific port on a USB hub."""
    device.ctrl_transfer(
        bmRequestType=CTRL_TYPE_CLASS | CTRL_RECIPIENT_OTHER,
        bRequest=REQ_SET_FEATURE if on else REQ_CLEAR_FEATURE,
        wIndex=port,
        wValue=USB_PORT_FEATURE_POWER,
    )


def _find_device_by_path(sys_path: str) -> Optional[UsbDevice]:
    """Finds a USB device based on its system path."""
    bus_num, *port_parts = sys_path.split('-')
    ports = [int(port) for port in port_parts[0].split('.')]
    devices = usb.core.find(find_all=True, bus=int(bus_num))
    if devices:
        for device in devices:
            if device.bus == int(bus_num) and list(device.port_numbers) == ports:  # type: ignore
                return device

    return None


def _find_hub_by_device_path(sys_path: str) -> Optional[UsbDevice]:
    """Finds the USB hub associated with a specific device path."""
    hub_sys_path = sys_path.rsplit('.', 1)[0]
    hub_device = _find_device_by_path(hub_sys_path)

    if hub_device is None:
        return None
    else:
        return hub_device if _is_hub(hub_device) else None


def _is_hub(device: UsbDevice) -> bool:
    """Checks if a USB device is a hub"""
    if device.bDeviceClass == CLASS_HUB:  # type: ignore
        return True
    for config in device:
        for interface in config:
            if interface.bInterfaceClass == CLASS_HUB:  # type: ignore
                return True
    return False
