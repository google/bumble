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
import random
import logging

from bumble.device import Device, Connection
from bumble.transport import open_transport_or_link
from bumble.gatt import Service, Characteristic


# -----------------------------------------------------------------------------
class Listener(Device.Listener, Connection.Listener):
    def __init__(self, device):
        self.device = device

    def on_connection(self, connection):
        print(f'=== Connected to {connection}')
        connection.listener = self

    def on_disconnection(self, reason):
        print(f'### Disconnected, reason={reason}')

    def on_characteristic_subscription(
        self, connection, characteristic, notify_enabled, indicate_enabled
    ):
        print(
            f'$$$ Characteristic subscription for handle {characteristic.handle} '
            f'from {connection}: '
            f'notify {"enabled" if notify_enabled else "disabled"}, '
            f'indicate {"enabled" if indicate_enabled else "disabled"}'
        )


# -----------------------------------------------------------------------------
# Alternative way to listen for subscriptions
# -----------------------------------------------------------------------------
def on_my_characteristic_subscription(peer, enabled):
    print(f'### My characteristic from {peer}: {"enabled" if enabled else "disabled"}')


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print('Usage: run_notifier.py <device-config> <transport-spec>')
        print('example: run_notifier.py device1.json usb:0')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device to manage the host
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.listener = Listener(device)

        # Add a few entries to the device's GATT server
        characteristic1 = Characteristic(
            '486F64C6-4B5F-4B3B-8AFF-EDE134A8446A',
            Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
            Characteristic.READABLE,
            bytes([0x40]),
        )
        characteristic2 = Characteristic(
            '8EBDEBAE-0017-418E-8D3B-3A3809492165',
            Characteristic.Properties.READ | Characteristic.Properties.INDICATE,
            Characteristic.READABLE,
            bytes([0x41]),
        )
        characteristic3 = Characteristic(
            '8EBDEBAE-0017-418E-8D3B-3A3809492165',
            Characteristic.Properties.READ
            | Characteristic.Properties.NOTIFY
            | Characteristic.Properties.INDICATE,
            Characteristic.READABLE,
            bytes([0x42]),
        )
        characteristic3.on('subscription', on_my_characteristic_subscription)
        custom_service = Service(
            '50DB505C-8AC4-4738-8448-3B1D9CC09CC5',
            [characteristic1, characteristic2, characteristic3],
        )
        device.add_services([custom_service])

        # Debug print
        for attribute in device.gatt_server.attributes:
            print(attribute)

        # Get things going
        await device.power_on()

        # Connect to a peer
        if len(sys.argv) > 3:
            target_address = sys.argv[3]
            print(f'=== Connecting to {target_address}...')
            await device.connect(target_address)
        else:
            await device.start_advertising(auto_restart=True)

        while True:
            await asyncio.sleep(3.0)
            characteristic1.value = bytes([random.randint(0, 255)])
            await device.notify_subscribers(characteristic1)
            characteristic2.value = bytes([random.randint(0, 255)])
            await device.indicate_subscribers(characteristic2)
            characteristic3.value = bytes([random.randint(0, 255)])
            await device.notify_subscribers(characteristic3)
            await device.indicate_subscribers(characteristic3)


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
