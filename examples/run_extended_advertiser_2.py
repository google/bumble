# Copyright 2021-2024 Google LLC
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
import logging
import sys
import os
from bumble.device import AdvertisingParameters, AdvertisingEventProperties, Device
from bumble.hci import Address
from bumble.core import AdvertisingData
from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: run_extended_advertiser_2.py <config-file> <transport-spec>')
        print('example: run_extended_advertiser_2.py device1.json usb:0')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        await device.power_on()

        if not device.supports_le_extended_advertising:
            print("Device does not support extended advertising")
            return

        print("Max advertising sets:", device.host.number_of_supported_advertising_sets)
        print(
            "Max advertising data length:", device.host.maximum_advertising_data_length
        )

        if device.host.number_of_supported_advertising_sets >= 1:
            advertising_data1 = AdvertisingData(
                [(AdvertisingData.COMPLETE_LOCAL_NAME, "Bumble 1".encode("utf-8"))]
            )

            set1 = await device.create_advertising_set(
                advertising_data=bytes(advertising_data1),
            )
            print("Selected TX power 1:", set1.selected_tx_power)

            advertising_data2 = AdvertisingData(
                [(AdvertisingData.COMPLETE_LOCAL_NAME, "Bumble 2".encode("utf-8"))]
            )

        if device.host.number_of_supported_advertising_sets >= 2:
            set2 = await device.create_advertising_set(
                random_address=Address("F0:F0:F0:F0:F0:F1"),
                advertising_parameters=AdvertisingParameters(),
                advertising_data=bytes(advertising_data2),
                auto_start=False,
                auto_restart=True,
            )
            print("Selected TX power 2:", set2.selected_tx_power)
            await set2.start()

        if device.host.number_of_supported_advertising_sets >= 3:
            scan_response_data3 = AdvertisingData(
                [(AdvertisingData.COMPLETE_LOCAL_NAME, "Bumble 3".encode("utf-8"))]
            )

            set3 = await device.create_advertising_set(
                random_address=Address("F0:F0:F0:F0:F0:F2"),
                advertising_parameters=AdvertisingParameters(
                    advertising_event_properties=AdvertisingEventProperties(
                        is_connectable=False, is_scannable=True
                    )
                ),
                scan_response_data=bytes(scan_response_data3),
            )
            print("Selected TX power 3:", set2.selected_tx_power)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
