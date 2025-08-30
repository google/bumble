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
import struct
import sys

import bumble.logging
from bumble import data_types
from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.profiles.device_information_service import DeviceInformationService
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) != 3:
        print('Usage: python device_info_server.py <device-config> <transport-spec>')
        print('example: python device_info_server.py device1.json usb:0')
        return

    async with await open_transport(sys.argv[2]) as hci_transport:
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )

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
                    data_types.CompleteLocalName('Bumble Device'),
                    data_types.Appearance(
                        data_types.Appearance.Category.HEART_RATE_SENSOR,
                        data_types.Appearance.HeartRateSensorSubcategory.GENERIC_HEART_RATE_SENSOR,
                    ),
                ]
            )
        )

        # Go!
        await device.power_on()
        await device.start_advertising(auto_restart=True)
        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
