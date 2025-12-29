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
import random
import sys

import bumble.logging
from bumble import data_types
from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.profiles.battery_service import BatteryService
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) != 3:
        print('Usage: python battery_server.py <device-config> <transport-spec>')
        print('example: python battery_server.py device1.json usb:0')
        return

    async with await open_transport(sys.argv[2]) as hci_transport:
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )

        # Add a Battery Service to the GATT sever
        battery_service = BatteryService(lambda _: random.randint(0, 100))
        device.add_service(battery_service)

        # Set the advertising data
        device.advertising_data = bytes(
            AdvertisingData(
                [
                    data_types.CompleteLocalName('Bumble Battery'),
                    data_types.IncompleteListOf16BitServiceUUIDs(
                        [battery_service.uuid]
                    ),
                    data_types.Appearance(
                        data_types.Appearance.Category.WEARABLE_AUDIO_DEVICE,
                        data_types.Appearance.WearableAudioDeviceSubcategory.EARBUD,
                    ),
                ]
            )
        )

        # Go!
        await device.power_on()
        await device.start_advertising(auto_restart=True)

        # Notify every 3 seconds
        while True:
            await asyncio.sleep(3.0)
            await device.notify_subscribers(
                battery_service.battery_level_characteristic
            )


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
