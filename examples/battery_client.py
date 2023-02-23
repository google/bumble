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
from bumble.colors import color
from bumble.device import Device
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
        async with device.connect_as_gatt(target_address) as peer:
            print(f'=== Connected to {peer}')
            battery_service = peer.create_service_proxy(BatteryServiceProxy)

            # Check that the service was found
            if not battery_service:
                print('!!! Service not found')
                return

            # Subscribe to and read the battery level
            if battery_service.battery_level:
                await battery_service.battery_level.subscribe(
                    lambda value: print(
                        f'{color("Battery Level Update:", "green")} {value}'
                    )
                )
                value = await battery_service.battery_level.read_value()
                print(f'{color("Initial Battery Level:", "green")} {value}')

            await peer.sustain()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
