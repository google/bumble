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
# This tool lists all the USB devices, with details about each device.
# For each device, the different possible Bumble transport strings that can
# refer to it are listed. If the device is known to be a Bluetooth HCI device,
# its identifier is printed in reverse colors, and the transport names in cyan color.
# For other devices, regardless of their type, the transport names are printed
# in red. Whether that device is actually a Bluetooth device or not depends on
# whether it is a Bluetooth device that uses a non-standard Class, or some other
# type of device (there's no way to tell).
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import os
import logging
import click
import usb1

from bumble.colors import color
from bumble.transport.usb import load_libusb


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
USB_DEVICE_CLASS_DEVICE = 0x00
USB_DEVICE_CLASS_WIRELESS_CONTROLLER = 0xE0
USB_DEVICE_SUBCLASS_RF_CONTROLLER = 0x01
USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER = 0x01

USB_DEVICE_CLASSES = {
    0x00: 'Device',
    0x01: 'Audio',
    0x02: 'Communications and CDC Control',
    0x03: 'Human Interface Device',
    0x05: 'Physical',
    0x06: 'Still Imaging',
    0x07: 'Printer',
    0x08: 'Mass Storage',
    0x09: 'Hub',
    0x0A: 'CDC Data',
    0x0B: 'Smart Card',
    0x0D: 'Content Security',
    0x0E: 'Video',
    0x0F: 'Personal Healthcare',
    0x10: 'Audio/Video',
    0x11: 'Billboard',
    0x12: 'USB Type-C Bridge',
    0x3C: 'I3C',
    0xDC: 'Diagnostic',
    USB_DEVICE_CLASS_WIRELESS_CONTROLLER: (
        'Wireless Controller',
        {
            0x01: {
                0x01: 'Bluetooth',
                0x02: 'UWB',
                0x03: 'Remote NDIS',
                0x04: 'Bluetooth AMP',
            }
        },
    ),
    0xEF: 'Miscellaneous',
    0xFE: 'Application Specific',
    0xFF: 'Vendor Specific',
}

USB_ENDPOINT_IN = 0x80
USB_ENDPOINT_TYPES = ['CONTROL', 'ISOCHRONOUS', 'BULK', 'INTERRUPT']

USB_BT_HCI_CLASS_TUPLE = (
    USB_DEVICE_CLASS_WIRELESS_CONTROLLER,
    USB_DEVICE_SUBCLASS_RF_CONTROLLER,
    USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER,
)


# -----------------------------------------------------------------------------
def show_device_details(device):
    for configuration in device:
        print(f'  Configuration {configuration.getConfigurationValue()}')
        for interface in configuration:
            for setting in interface:
                alternate_setting = setting.getAlternateSetting()
                suffix = (
                    f'/{alternate_setting}' if interface.getNumSettings() > 1 else ''
                )
                (class_string, subclass_string) = get_class_info(
                    setting.getClass(), setting.getSubClass(), setting.getProtocol()
                )
                details = f'({class_string}, {subclass_string})'
                print(f'      Interface: {setting.getNumber()}{suffix} {details}')
                for endpoint in setting:
                    endpoint_type = USB_ENDPOINT_TYPES[endpoint.getAttributes() & 3]
                    endpoint_direction = (
                        'OUT'
                        if (endpoint.getAddress() & USB_ENDPOINT_IN == 0)
                        else 'IN'
                    )
                    print(
                        f'        Endpoint 0x{endpoint.getAddress():02X}: '
                        f'{endpoint_type} {endpoint_direction}'
                    )


# -----------------------------------------------------------------------------
def get_class_info(cls, subclass, protocol):
    class_info = USB_DEVICE_CLASSES.get(cls)
    protocol_string = ''
    if class_info is None:
        class_string = f'0x{cls:02X}'
    else:
        if isinstance(class_info, tuple):
            class_string = class_info[0]
            subclass_info = class_info[1].get(subclass)
            if subclass_info:
                protocol_string = subclass_info.get(protocol)
                if protocol_string is not None:
                    protocol_string = f' [{protocol_string}]'

        else:
            class_string = class_info

    subclass_string = f'{subclass}/{protocol}{protocol_string}'

    return (class_string, subclass_string)


# -----------------------------------------------------------------------------
def is_bluetooth_hci(device):
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


# -----------------------------------------------------------------------------
@click.command()
@click.option('--verbose', is_flag=True, default=False, help='Print more details')
def main(verbose):
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())

    load_libusb()
    with usb1.USBContext() as context:
        bluetooth_device_count = 0
        devices = {}

        for device in context.getDeviceIterator(skip_on_error=True):
            device_class = device.getDeviceClass()
            device_subclass = device.getDeviceSubClass()
            device_protocol = device.getDeviceProtocol()

            device_id = (device.getVendorID(), device.getProductID())

            (device_class_string, device_subclass_string) = get_class_info(
                device_class, device_subclass, device_protocol
            )

            try:
                device_serial_number = device.getSerialNumber()
            except usb1.USBError:
                device_serial_number = None

            try:
                device_manufacturer = device.getManufacturer()
            except usb1.USBError:
                device_manufacturer = None

            try:
                device_product = device.getProduct()
            except usb1.USBError:
                device_product = None

            device_is_bluetooth_hci = is_bluetooth_hci(device)
            if device_is_bluetooth_hci:
                bluetooth_device_count += 1
                fg_color = 'black'
                bg_color = 'yellow'
            else:
                fg_color = 'yellow'
                bg_color = 'black'

            # Compute the different ways this can be referenced as a Bumble transport
            bumble_transport_names = []
            basic_transport_name = (
                f'usb:{device.getVendorID():04X}:{device.getProductID():04X}'
            )

            if device_is_bluetooth_hci:
                bumble_transport_names.append(f'usb:{bluetooth_device_count - 1}')

            if device_id not in devices:
                bumble_transport_names.append(basic_transport_name)
            else:
                bumble_transport_names.append(
                    f'{basic_transport_name}#{len(devices[device_id])}'
                )

            if device_serial_number is not None:
                if (
                    device_id not in devices
                    or device_serial_number not in devices[device_id]
                ):
                    bumble_transport_names.append(
                        f'{basic_transport_name}/{device_serial_number}'
                    )

            # Print the results
            print(
                color(
                    f'ID {device.getVendorID():04X}:{device.getProductID():04X}',
                    fg=fg_color,
                    bg=bg_color,
                )
            )
            if bumble_transport_names:
                print(
                    color('  Bumble Transport Names:', 'blue'),
                    ' or '.join(
                        color(x, 'cyan' if device_is_bluetooth_hci else 'red')
                        for x in bumble_transport_names
                    ),
                )
            print(
                color('  Bus/Device:            ', 'green'),
                f'{device.getBusNumber():03}/{device.getDeviceAddress():03}',
            )
            print(color('  Class:                 ', 'green'), device_class_string)
            print(color('  Subclass/Protocol:     ', 'green'), device_subclass_string)
            if device_serial_number is not None:
                print(color('  Serial:                ', 'green'), device_serial_number)
            if device_manufacturer is not None:
                print(color('  Manufacturer:          ', 'green'), device_manufacturer)
            if device_product is not None:
                print(color('  Product:               ', 'green'), device_product)

            if verbose:
                show_device_details(device)

            print()

            devices.setdefault(device_id, []).append(device_serial_number)


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
