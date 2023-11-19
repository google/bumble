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
import collections
import ctypes
import platform

import usb1

from bumble.transport.common import Transport, ParserSource
from bumble import hci
from bumble.colors import color
from bumble.utils import AsyncRunner


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


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
    usb:0B05:17CB! --> the BT USB dongle vendor=0B05 and product=17CB, in "forced" mode.
    '''

    # pylint: disable=invalid-name
    USB_RECIPIENT_DEVICE = 0x00
    USB_REQUEST_TYPE_CLASS = 0x01 << 5
    USB_DEVICE_CLASS_DEVICE = 0x00
    USB_DEVICE_CLASS_WIRELESS_CONTROLLER = 0xE0
    USB_DEVICE_SUBCLASS_RF_CONTROLLER = 0x01
    USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER = 0x01
    USB_ENDPOINT_TRANSFER_TYPE_BULK = 0x02
    USB_ENDPOINT_TRANSFER_TYPE_INTERRUPT = 0x03
    USB_ENDPOINT_IN = 0x80

    USB_BT_HCI_CLASS_TUPLE = (
        USB_DEVICE_CLASS_WIRELESS_CONTROLLER,
        USB_DEVICE_SUBCLASS_RF_CONTROLLER,
        USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER,
    )

    READ_SIZE = 1024

    class UsbPacketSink:
        def __init__(self, device, acl_out):
            self.device = device
            self.acl_out = acl_out
            self.acl_out_transfer = device.getTransfer()
            self.packets = collections.deque()  # Queue of packets waiting to be sent
            self.loop = asyncio.get_running_loop()
            self.cancel_done = self.loop.create_future()
            self.closed = False

        def start(self):
            pass

        def on_packet(self, packet):
            # Ignore packets if we're closed
            if self.closed:
                return

            if len(packet) == 0:
                logger.warning('packet too short')
                return

            # Queue the packet
            self.packets.append(packet)
            if len(self.packets) == 1:
                # The queue was previously empty, re-prime the pump
                self.process_queue()

        def transfer_callback(self, transfer):
            status = transfer.getStatus()

            # pylint: disable=no-member
            if status == usb1.TRANSFER_COMPLETED:
                self.loop.call_soon_threadsafe(self.on_packet_sent)
            elif status == usb1.TRANSFER_CANCELLED:
                self.loop.call_soon_threadsafe(self.cancel_done.set_result, None)
            else:
                logger.warning(
                    color(f'!!! OUT transfer not completed: status={status}', 'red')
                )

        def on_packet_sent(self):
            if self.packets:
                self.packets.popleft()
                self.process_queue()

        def process_queue(self):
            if len(self.packets) == 0:
                return  # Nothing to do

            packet = self.packets[0]
            packet_type = packet[0]
            if packet_type == hci.HCI_ACL_DATA_PACKET:
                self.acl_out_transfer.setBulk(
                    self.acl_out, packet[1:], callback=self.transfer_callback
                )
                self.acl_out_transfer.submit()
            elif packet_type == hci.HCI_COMMAND_PACKET:
                self.acl_out_transfer.setControl(
                    USB_RECIPIENT_DEVICE | USB_REQUEST_TYPE_CLASS,
                    0,
                    0,
                    0,
                    packet[1:],
                    callback=self.transfer_callback,
                )
                self.acl_out_transfer.submit()
            else:
                logger.warning(color(f'unsupported packet type {packet_type}', 'red'))

        def close(self):
            self.closed = True

        async def terminate(self):
            if not self.closed:
                self.close()

            # Empty the packet queue so that we don't send any more data
            self.packets.clear()

            # If we have a transfer in flight, cancel it
            if self.acl_out_transfer.isSubmitted():
                # Try to cancel the transfer, but that may fail because it may have
                # already completed
                try:
                    self.acl_out_transfer.cancel()

                    logger.debug('waiting for OUT transfer cancellation to be done...')
                    await self.cancel_done
                    logger.debug('OUT transfer cancellation done')
                except usb1.USBError:
                    logger.debug('OUT transfer likely already completed')

    class UsbPacketSource(asyncio.Protocol, ParserSource):
        def __init__(self, device, metadata, acl_in, events_in):
            super().__init__()
            self.device = device
            self.metadata = metadata
            self.acl_in = acl_in
            self.acl_in_transfer = None
            self.events_in = events_in
            self.events_in_transfer = None
            self.loop = asyncio.get_running_loop()
            self.queue = asyncio.Queue()
            self.dequeue_task = None
            self.cancel_done = {
                hci.HCI_EVENT_PACKET: self.loop.create_future(),
                hci.HCI_ACL_DATA_PACKET: self.loop.create_future(),
            }
            self.closed = False

        def start(self):
            # Set up transfer objects for input
            self.events_in_transfer = device.getTransfer()
            self.events_in_transfer.setInterrupt(
                self.events_in,
                READ_SIZE,
                callback=self.transfer_callback,
                user_data=hci.HCI_EVENT_PACKET,
            )
            self.events_in_transfer.submit()

            self.acl_in_transfer = device.getTransfer()
            self.acl_in_transfer.setBulk(
                self.acl_in,
                READ_SIZE,
                callback=self.transfer_callback,
                user_data=hci.HCI_ACL_DATA_PACKET,
            )
            self.acl_in_transfer.submit()

            self.dequeue_task = self.loop.create_task(self.dequeue())

        @property
        def usb_transfer_submitted(self):
            return (
                self.events_in_transfer.isSubmitted()
                or self.acl_in_transfer.isSubmitted()
            )

        def transfer_callback(self, transfer):
            packet_type = transfer.getUserData()
            status = transfer.getStatus()

            # pylint: disable=no-member
            if status == usb1.TRANSFER_COMPLETED:
                packet = (
                    bytes([packet_type])
                    + transfer.getBuffer()[: transfer.getActualLength()]
                )
                self.loop.call_soon_threadsafe(self.queue.put_nowait, packet)

                # Re-submit the transfer so we can receive more data
                transfer.submit()
            elif status == usb1.TRANSFER_CANCELLED:
                self.loop.call_soon_threadsafe(
                    self.cancel_done[packet_type].set_result, None
                )
            else:
                logger.warning(
                    color(f'!!! IN transfer not completed: status={status}', 'red')
                )
                self.loop.call_soon_threadsafe(self.on_transport_lost)

        async def dequeue(self):
            while not self.closed:
                try:
                    packet = await self.queue.get()
                except asyncio.CancelledError:
                    return
                self.parser.feed_data(packet)

        def close(self):
            self.closed = True

        async def terminate(self):
            if not self.closed:
                self.close()

            self.dequeue_task.cancel()

            # Cancel the transfers
            for transfer in (self.events_in_transfer, self.acl_in_transfer):
                if transfer.isSubmitted():
                    # Try to cancel the transfer, but that may fail because it may have
                    # already completed
                    packet_type = transfer.getUserData()
                    try:
                        transfer.cancel()
                        logger.debug(
                            f'waiting for IN[{packet_type}] transfer cancellation '
                            'to be done...'
                        )
                        await self.cancel_done[packet_type]
                        logger.debug(f'IN[{packet_type}] transfer cancellation done')
                    except usb1.USBError:
                        logger.debug(
                            f'IN[{packet_type}] transfer likely already completed'
                        )

    class UsbTransport(Transport):
        def __init__(self, context, device, interface, setting, source, sink):
            super().__init__(source, sink)
            self.context = context
            self.device = device
            self.interface = interface
            self.loop = asyncio.get_running_loop()
            self.event_loop_done = self.loop.create_future()

            # Get exclusive access
            device.claimInterface(interface)

            # Set the alternate setting if not the default
            if setting != 0:
                device.setInterfaceAltSetting(interface, setting)

            # The source and sink can now start
            source.start()
            sink.start()

            # Create a thread to process events
            self.event_thread = threading.Thread(target=self.run)
            self.event_thread.start()

        def run(self):
            logger.debug('starting USB event loop')
            while self.source.usb_transfer_submitted:
                # pylint: disable=no-member
                try:
                    self.context.handleEvents()
                except usb1.USBErrorInterrupted:
                    pass

            logger.debug('USB event loop done')
            self.loop.call_soon_threadsafe(self.event_loop_done.set_result, None)

        async def close(self):
            self.source.close()
            self.sink.close()
            await self.source.terminate()
            await self.sink.terminate()
            self.device.releaseInterface(self.interface)
            self.device.close()
            self.context.close()

            # Wait for the thread to terminate
            await self.event_loop_done

    # Find the device according to the spec moniker
    load_libusb()
    context = usb1.USBContext()
    context.open()
    try:
        found = None

        if spec.endswith('!'):
            spec = spec[:-1]
            forced_mode = True
        else:
            forced_mode = False

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
            raise ValueError('device not found')

        logger.debug(f'USB Device: {found}')

        # Look for the first interface with the right class and endpoints
        def find_endpoints(device):
            # pylint: disable-next=too-many-nested-blocks
            for (configuration_index, configuration) in enumerate(device):
                interface = None
                for interface in configuration:
                    setting = None
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

                        events_in = None
                        acl_in = None
                        acl_out = None
                        for endpoint in setting:
                            attributes = endpoint.getAttributes()
                            address = endpoint.getAddress()
                            if attributes & 0x03 == USB_ENDPOINT_TRANSFER_TYPE_BULK:
                                if address & USB_ENDPOINT_IN and acl_in is None:
                                    acl_in = address
                                elif acl_out is None:
                                    acl_out = address
                            elif (
                                attributes & 0x03
                                == USB_ENDPOINT_TRANSFER_TYPE_INTERRUPT
                            ):
                                if address & USB_ENDPOINT_IN and events_in is None:
                                    events_in = address

                        # Return if we found all 3 endpoints
                        if (
                            acl_in is not None
                            and acl_out is not None
                            and events_in is not None
                        ):
                            return (
                                configuration_index + 1,
                                setting.getNumber(),
                                setting.getAlternateSetting(),
                                acl_in,
                                acl_out,
                                events_in,
                            )

                        logger.debug(
                            f'skipping configuration {configuration_index + 1} / '
                            f'interface {setting.getNumber()}'
                        )

            return None

        endpoints = find_endpoints(found)
        if endpoints is None:
            raise ValueError('no compatible interface found for device')
        (configuration, interface, setting, acl_in, acl_out, events_in) = endpoints
        logger.debug(
            f'selected endpoints: configuration={configuration}, '
            f'interface={interface}, '
            f'setting={setting}, '
            f'acl_in=0x{acl_in:02X}, '
            f'acl_out=0x{acl_out:02X}, '
            f'events_in=0x{events_in:02X}, '
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

        source = UsbPacketSource(device, device_metadata, acl_in, events_in)
        sink = UsbPacketSink(device, acl_out)
        return UsbTransport(context, device, interface, setting, source, sink)
    except usb1.USBError as error:
        logger.warning(color(f'!!! failed to open USB device: {error}', 'red'))
        context.close()
        raise
