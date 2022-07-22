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
from colors import color
from bumble.device import Device, Peer
from bumble.transport import open_transport
from bumble.profiles.battery_service import BatteryServiceProxy


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 3:
        print('Usage: battery_client.py <transport-spec> <bluetooth-address>')
        print('example: battery_client.py usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[1]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create and start a device
        device = Device.with_hci('Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
        await device.power_on()

        # Connect to the peer
        target_address = sys.argv[2]
        print(f'=== Connecting to {target_address}...')
        connection = await device.connect(target_address)
        print(f'=== Connected to {connection}')

        # Discover the Battery Service
        peer = Peer(connection)
        print('=== Discovering Battery Service')
        battery_service = await peer.discover_and_create_service_proxy(BatteryServiceProxy)

        # Check that the service was found
        if not battery_service:
            print('!!! Service not found')
            return

        # Subscribe to and read the battery level
        if battery_service.battery_level:
            await battery_service.battery_level.subscribe(
                lambda value: print(f'{color("Battery Level Update:", "green")} {value}')
            )
            value = await battery_service.battery_level.read_value()
            print(f'{color("Initial Battery Level:", "green")} {value}')

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
