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
import sys
import os
import logging
import struct
import json
import websockets
from bumble.colors import color

from bumble.core import AdvertisingData
from bumble.device import Device, Connection, Peer
from bumble.utils import AsyncRunner
from bumble.transport import open_transport_or_link
from bumble.gatt import (
    Descriptor,
    Service,
    Characteristic,
    CharacteristicValue,
    GATT_DEVICE_INFORMATION_SERVICE,
    GATT_HUMAN_INTERFACE_DEVICE_SERVICE,
    GATT_BATTERY_SERVICE,
    GATT_BATTERY_LEVEL_CHARACTERISTIC,
    GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
    GATT_REPORT_CHARACTERISTIC,
    GATT_REPORT_MAP_CHARACTERISTIC,
    GATT_PROTOCOL_MODE_CHARACTERISTIC,
    GATT_HID_INFORMATION_CHARACTERISTIC,
    GATT_HID_CONTROL_POINT_CHARACTERISTIC,
    GATT_REPORT_REFERENCE_DESCRIPTOR,
)

# -----------------------------------------------------------------------------

# Protocol Modes
HID_BOOT_PROTOCOL = 0x00
HID_REPORT_PROTOCOL = 0x01

# Report Types
HID_INPUT_REPORT = 0x01
HID_OUTPUT_REPORT = 0x02
HID_FEATURE_REPORT = 0x03

# Report Map
HID_KEYBOARD_REPORT_MAP = bytes(
    # pylint: disable=line-too-long
    [
        0x05,
        0x01,  # Usage Page (Generic Desktop Controls)
        0x09,
        0x06,  # Usage (Keyboard)
        0xA1,
        0x01,  # Collection (Application)
        0x85,
        0x01,  # . Report ID (1)
        0x05,
        0x07,  # . Usage Page (Keyboard/Keypad)
        0x19,
        0xE0,  # . Usage Minimum (0xE0)
        0x29,
        0xE7,  # . Usage Maximum (0xE7)
        0x15,
        0x00,  # . Logical Minimum (0)
        0x25,
        0x01,  # . Logical Maximum (1)
        0x75,
        0x01,  # . Report Size (1)
        0x95,
        0x08,  # . Report Count (8)
        0x81,
        0x02,  # . Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
        0x95,
        0x01,  # . Report Count (1)
        0x75,
        0x08,  # . Report Size (8)
        0x81,
        0x01,  # . Input (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
        0x95,
        0x06,  # . Report Count (6)
        0x75,
        0x08,  # . Report Size (8)
        0x15,
        0x00,  # . Logical Minimum (0x00)
        0x25,
        0x94,  # . Logical Maximum (0x94)
        0x05,
        0x07,  # . Usage Page (Keyboard/Keypad)
        0x19,
        0x00,  # . Usage Minimum (0x00)
        0x29,
        0x94,  # . Usage Maximum (0x94)
        0x81,
        0x00,  # . Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
        0x95,
        0x05,  # . Report Count (5)
        0x75,
        0x01,  # . Report Size (1)
        0x05,
        0x08,  # . Usage Page (LEDs)
        0x19,
        0x01,  # . Usage Minimum (Num Lock)
        0x29,
        0x05,  # . Usage Maximum (Kana)
        0x91,
        0x02,  # . Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
        0x95,
        0x01,  # . Report Count (1)
        0x75,
        0x03,  # . Report Size (3)
        0x91,
        0x01,  # . Output (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
        0xC0,  # End Collection
    ]
)


# -----------------------------------------------------------------------------
# pylint: disable=invalid-overridden-method
class ServerListener(Device.Listener, Connection.Listener):
    def __init__(self, device):
        self.device = device

    @AsyncRunner.run_in_task()
    async def on_connection(self, connection):
        print(f'=== Connected to {connection}')
        connection.listener = self

    @AsyncRunner.run_in_task()
    async def on_disconnection(self, reason):
        print(f'### Disconnected, reason={reason}')


# -----------------------------------------------------------------------------
def on_hid_control_point_write(_connection, value):
    print(f'Control Point Write: {value}')


# -----------------------------------------------------------------------------
def on_report(characteristic, value):
    print(color('Report:', 'cyan'), value.hex(), 'from', characteristic)


# -----------------------------------------------------------------------------
async def keyboard_host(device, peer_address):
    await device.power_on()
    connection = await device.connect(peer_address)
    await connection.pair()
    peer = Peer(connection)
    await peer.discover_service(GATT_HUMAN_INTERFACE_DEVICE_SERVICE)
    hid_services = peer.get_services_by_uuid(GATT_HUMAN_INTERFACE_DEVICE_SERVICE)
    if not hid_services:
        print(color('!!! No HID service', 'red'))
        return
    await peer.discover_characteristics()

    protocol_mode_characteristics = peer.get_characteristics_by_uuid(
        GATT_PROTOCOL_MODE_CHARACTERISTIC
    )
    if not protocol_mode_characteristics:
        print(color('!!! No Protocol Mode characteristic', 'red'))
        return
    protocol_mode_characteristic = protocol_mode_characteristics[0]

    hid_information_characteristics = peer.get_characteristics_by_uuid(
        GATT_HID_INFORMATION_CHARACTERISTIC
    )
    if not hid_information_characteristics:
        print(color('!!! No HID Information characteristic', 'red'))
        return
    hid_information_characteristic = hid_information_characteristics[0]

    report_map_characteristics = peer.get_characteristics_by_uuid(
        GATT_REPORT_MAP_CHARACTERISTIC
    )
    if not report_map_characteristics:
        print(color('!!! No Report Map characteristic', 'red'))
        return
    report_map_characteristic = report_map_characteristics[0]

    control_point_characteristics = peer.get_characteristics_by_uuid(
        GATT_HID_CONTROL_POINT_CHARACTERISTIC
    )
    if not control_point_characteristics:
        print(color('!!! No Control Point characteristic', 'red'))
        return
    # control_point_characteristic = control_point_characteristics[0]

    report_characteristics = peer.get_characteristics_by_uuid(
        GATT_REPORT_CHARACTERISTIC
    )
    if not report_characteristics:
        print(color('!!! No Report characteristic', 'red'))
        return
    for i, characteristic in enumerate(report_characteristics):
        print(color('REPORT:', 'yellow'), characteristic)
        if characteristic.properties & Characteristic.Properties.NOTIFY:
            await peer.discover_descriptors(characteristic)
            report_reference_descriptor = characteristic.get_descriptor(
                GATT_REPORT_REFERENCE_DESCRIPTOR
            )
            if report_reference_descriptor:
                report_reference = await peer.read_value(report_reference_descriptor)
                print(color('  Report Reference:', 'blue'), report_reference.hex())
            else:
                report_reference = bytes([0, 0])
            await peer.subscribe(
                characteristic,
                lambda value, param=f'[{i}] {report_reference.hex()}': on_report(
                    param, value
                ),
            )

    protocol_mode = await peer.read_value(protocol_mode_characteristic)
    print(f'Protocol Mode: {protocol_mode.hex()}')
    hid_information = await peer.read_value(hid_information_characteristic)
    print(f'HID Information: {hid_information.hex()}')
    report_map = await peer.read_value(report_map_characteristic)
    print(f'Report Map: {report_map.hex()}')

    await asyncio.get_running_loop().create_future()


# -----------------------------------------------------------------------------
async def keyboard_device(device, command):
    # Create an 'input report' characteristic to send keyboard reports to the host
    input_report_characteristic = Characteristic(
        GATT_REPORT_CHARACTERISTIC,
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE
        | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([0, 0, 0, 0, 0, 0, 0, 0]),
        [
            Descriptor(
                GATT_REPORT_REFERENCE_DESCRIPTOR,
                Descriptor.READABLE,
                bytes([0x01, HID_INPUT_REPORT]),
            )
        ],
    )

    # Create an 'output report' characteristic to receive keyboard reports from the host
    output_report_characteristic = Characteristic(
        GATT_REPORT_CHARACTERISTIC,
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE
        | Characteristic.WRITE_WITHOUT_RESPONSE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([0]),
        [
            Descriptor(
                GATT_REPORT_REFERENCE_DESCRIPTOR,
                Descriptor.READABLE,
                bytes([0x01, HID_OUTPUT_REPORT]),
            )
        ],
    )

    # Add the services to the GATT sever
    device.add_services(
        [
            Service(
                GATT_DEVICE_INFORMATION_SERVICE,
                [
                    Characteristic(
                        GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
                        Characteristic.Properties.READ,
                        Characteristic.READABLE,
                        'Bumble',
                    )
                ],
            ),
            Service(
                GATT_HUMAN_INTERFACE_DEVICE_SERVICE,
                [
                    Characteristic(
                        GATT_PROTOCOL_MODE_CHARACTERISTIC,
                        Characteristic.Properties.READ,
                        Characteristic.READABLE,
                        bytes([HID_REPORT_PROTOCOL]),
                    ),
                    Characteristic(
                        GATT_HID_INFORMATION_CHARACTERISTIC,
                        Characteristic.Properties.READ,
                        Characteristic.READABLE,
                        # bcdHID=1.1, bCountryCode=0x00,
                        # Flags=RemoteWake|NormallyConnectable
                        bytes([0x11, 0x01, 0x00, 0x03]),
                    ),
                    Characteristic(
                        GATT_HID_CONTROL_POINT_CHARACTERISTIC,
                        Characteristic.WRITE_WITHOUT_RESPONSE,
                        Characteristic.WRITEABLE,
                        CharacteristicValue(write=on_hid_control_point_write),
                    ),
                    Characteristic(
                        GATT_REPORT_MAP_CHARACTERISTIC,
                        Characteristic.Properties.READ,
                        Characteristic.READABLE,
                        HID_KEYBOARD_REPORT_MAP,
                    ),
                    input_report_characteristic,
                    output_report_characteristic,
                ],
            ),
            Service(
                GATT_BATTERY_SERVICE,
                [
                    Characteristic(
                        GATT_BATTERY_LEVEL_CHARACTERISTIC,
                        Characteristic.Properties.READ,
                        Characteristic.READABLE,
                        bytes([100]),
                    )
                ],
            ),
        ]
    )

    # Debug print
    for attribute in device.gatt_server.attributes:
        print(attribute)

    # Set the advertising data
    device.advertising_data = bytes(
        AdvertisingData(
            [
                (
                    AdvertisingData.COMPLETE_LOCAL_NAME,
                    bytes('Bumble Keyboard', 'utf-8'),
                ),
                (
                    AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                    bytes(GATT_HUMAN_INTERFACE_DEVICE_SERVICE),
                ),
                (AdvertisingData.APPEARANCE, struct.pack('<H', 0x03C1)),
                (AdvertisingData.FLAGS, bytes([0x05])),
            ]
        )
    )

    # Attach a listener
    device.listener = ServerListener(device)

    # Go!
    await device.power_on()
    await device.start_advertising(auto_restart=True)

    if command == 'web':
        # Start a Websocket server to receive events from a web page
        async def serve(websocket, _path):
            while True:
                try:
                    message = await websocket.recv()
                    print('Received: ', str(message))

                    parsed = json.loads(message)
                    message_type = parsed['type']
                    if message_type == 'keydown':
                        # Only deal with keys a to z for now
                        key = parsed['key']
                        if len(key) == 1:
                            code = ord(key)
                            if ord('a') <= code <= ord('z'):
                                hid_code = 0x04 + code - ord('a')
                                input_report_characteristic.value = bytes(
                                    [0, 0, hid_code, 0, 0, 0, 0, 0]
                                )
                                await device.notify_subscribers(
                                    input_report_characteristic
                                )
                    elif message_type == 'keyup':
                        input_report_characteristic.value = bytes.fromhex(
                            '0000000000000000'
                        )
                        await device.notify_subscribers(input_report_characteristic)

                except websockets.exceptions.ConnectionClosedOK:
                    pass

        # pylint: disable-next=no-member
        await websockets.serve(serve, 'localhost', 8989)
        await asyncio.get_event_loop().create_future()
    else:
        message = bytes('hello', 'ascii')
        while True:
            for letter in message:
                await asyncio.sleep(3.0)

                # Keypress for the letter
                keycode = 0x04 + letter - 0x61
                input_report_characteristic.value = bytes(
                    [0, 0, keycode, 0, 0, 0, 0, 0]
                )
                await device.notify_subscribers(input_report_characteristic)

                # Key release
                input_report_characteristic.value = bytes.fromhex('0000000000000000')
                await device.notify_subscribers(input_report_characteristic)


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 4:
        print(
            'Usage: python keyboard.py <device-config> <transport-spec> <command>'
            '  where <command> is one of:\n'
            '  connect <address> (run a keyboard host, connecting to a keyboard)\n'
            '  web (run a keyboard with keypress input from a web page, '
            'see keyboard.html\n'
        )
        print(
            '  sim (run a keyboard simulation, emitting a canned sequence of keystrokes'
        )
        print('example: python keyboard.py keyboard.json usb:0 sim')
        print(
            'example: python keyboard.py keyboard.json usb:0 connect A0:A1:A2:A3:A4:A5'
        )
        return

    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        # Create a device to manage the host
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)

        command = sys.argv[3]
        if command == 'connect':
            # Run as a Keyboard host
            await keyboard_host(device, sys.argv[4])
        elif command in ('sim', 'web'):
            # Run as a keyboard device
            await keyboard_device(device, command)


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
