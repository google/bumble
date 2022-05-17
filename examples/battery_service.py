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
import random
import struct

from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.gatt import (
    Service,
    Characteristic,
    CharacteristicValue,
    GATT_DEVICE_BATTERY_SERVICE,
    GATT_BATTERY_LEVEL_CHARACTERISTIC
)


# -----------------------------------------------------------------------------
def read_battery_level(connection):
    return bytes([random.randint(0, 100)])


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 3:
        print('Usage: python battery_service.py <device-config> <transport-spec>')
        print('example: python battery_service.py device1.json usb:0')
        return

    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        # Create a device to manage the host
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)

        # Add a Battery Service to the GATT sever
        device.add_services([
            Service(
                GATT_DEVICE_BATTERY_SERVICE,
                [
                    Characteristic(
                        GATT_BATTERY_LEVEL_CHARACTERISTIC,
                        Characteristic.READ,
                        Characteristic.READABLE,
                        CharacteristicValue(read=read_battery_level)
                    )
                ]
            )
        ])

        # Set the advertising data
        device.advertising_data = bytes(
            AdvertisingData([
                (AdvertisingData.COMPLETE_LOCAL_NAME, bytes('Bumble Battery', 'utf-8')),
                (AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, struct.pack('<H', 0x180F)),
                (AdvertisingData.APPEARANCE, struct.pack('<H', 0x0340))
            ])
        )

        # Go!
        await device.power_on()
        await device.start_advertising()
        await hci_source.wait_for_termination()

# -----------------------------------------------------------------------------
logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
