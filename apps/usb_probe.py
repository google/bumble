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
import usb1
from colors import color


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
USB_DEVICE_CLASS_WIRELESS_CONTROLLER             = 0xE0
USB_DEVICE_SUBCLASS_RF_CONTROLLER                = 0x01
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
                0x04: 'Bluetooth AMP'
            }
        }
    ),
    0xEF: 'Miscellaneous',
    0xFE: 'Application Specific',
    0xFF: 'Vendor Specific'
}


# -----------------------------------------------------------------------------
def main():
    logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())

    with usb1.USBContext() as context:
        bluetooth_device_count = 0
        devices = {}

        for device in context.getDeviceIterator(skip_on_error=True):
            device_class    = device.getDeviceClass()
            device_subclass = device.getDeviceSubClass()
            device_protocol = device.getDeviceProtocol()

            device_id = (device.getVendorID(), device.getProductID())

            device_is_bluetooth_hci = (
                device_class    == USB_DEVICE_CLASS_WIRELESS_CONTROLLER and
                device_subclass == USB_DEVICE_SUBCLASS_RF_CONTROLLER and
                device_protocol == USB_DEVICE_PROTOCOL_BLUETOOTH_PRIMARY_CONTROLLER
            )

            device_class_details = ''
            device_class_info    = USB_DEVICE_CLASSES.get(device_class)
            if device_class_info is not None:
                if type(device_class_info) is tuple:
                    device_class = device_class_info[0]
                    device_subclass_info = device_class_info[1].get(device_subclass)
                    if device_subclass_info:
                        device_class_details = f' [{device_subclass_info.get(device_protocol)}]'
                else:
                    device_class = device_class_info

            if device_is_bluetooth_hci:
                bluetooth_device_count += 1
                fg_color = 'black'
                bg_color = 'yellow'
            else:
                fg_color = 'yellow'
                bg_color = 'black'

            # Compute the different ways this can be referenced as a Bumble transport
            bumble_transport_names = []
            basic_transport_name = f'usb:{device.getVendorID():04X}:{device.getProductID():04X}'

            if device_is_bluetooth_hci:
                bumble_transport_names.append(f'usb:{bluetooth_device_count - 1}')

            serial_number_collision = False
            if device_id in devices:
                for device_serial in devices[device_id]:
                    if device_serial == device.getSerialNumber():
                        serial_number_collision = True

            if device_id not in devices:
                bumble_transport_names.append(basic_transport_name)
            else:
                bumble_transport_names.append(f'{basic_transport_name}#{len(devices[device_id])}')

            if device.getSerialNumber() and not serial_number_collision:
                bumble_transport_names.append(f'{basic_transport_name}/{device.getSerialNumber()}')

            print(color(f'ID {device.getVendorID():04X}:{device.getProductID():04X}', fg=fg_color, bg=bg_color))
            if bumble_transport_names:
                print(color('  Bumble Transport Names:', 'blue'), ' or '.join(color(x, 'cyan' if device_is_bluetooth_hci else 'red') for x in bumble_transport_names))
            print(color('  Bus/Device:            ', 'green'), f'{device.getBusNumber():03}/{device.getDeviceAddress():03}')
            if device.getSerialNumber():
                print(color('  Serial:                ', 'green'), device.getSerialNumber())
            print(color('  Class:                 ', 'green'), device_class)
            print(color('  Subclass/Protocol:     ', 'green'), f'{device_subclass}/{device_protocol}{device_class_details}')
            print(color('  Manufacturer:          ', 'green'), device.getManufacturer())
            print(color('  Product:               ', 'green'), device.getProduct())
            print()

            devices.setdefault(device_id, []).append(device.getSerialNumber())


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
