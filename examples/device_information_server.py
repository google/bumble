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

from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.profiles.device_information_service import DeviceInformationService


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 3:
        print('Usage: python device_info_server.py <device-config> <transport-spec>')
        print('example: python device_info_server.py device1.json usb:0')
        return

    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)

        # Add a Device Information Service to the GATT sever
        device_information_service = DeviceInformationService(
            manufacturer_name='ACME',
            model_number='AB-102',
            serial_number='7654321',
            hardware_revision='1.1.3',
            software_revision='2.5.6',
            system_id=(0x123456, 0x8877665544),
        )
        device.add_service(device_information_service)

        # Set the advertising data
        device.advertising_data = bytes(
            AdvertisingData(
                [
                    (
                        AdvertisingData.COMPLETE_LOCAL_NAME,
                        bytes('Bumble Device', 'utf-8'),
                    ),
                    (AdvertisingData.APPEARANCE, struct.pack('<H', 0x0340)),
                ]
            )
        )

        # Go!
        await device.power_on()
        await device.start_advertising(auto_restart=True)
        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
