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
from bumble.device import Device, Peer
from bumble.profiles.device_information_service import DeviceInformationServiceProxy
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 3:
        print(
            'Usage: device_information_client.py <transport-spec> <bluetooth-address>'
        )
        print('example: device_information_client.py usb:0 E1:CA:72:48:C4:E8')
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

        # Discover the Device Information service
        peer = Peer(connection)
        print('=== Discovering Device Information Service')
        device_information_service = await peer.discover_service_and_create_proxy(
            DeviceInformationServiceProxy
        )

        # Check that the service was found
        if device_information_service is None:
            print('!!! Service not found')
            return

        # Read and print the fields
        if device_information_service.manufacturer_name is not None:
            print(
                color('Manufacturer Name:       ', 'green'),
                await device_information_service.manufacturer_name.read_value(),
            )
        if device_information_service.model_number is not None:
            print(
                color('Model Number:            ', 'green'),
                await device_information_service.model_number.read_value(),
            )
        if device_information_service.serial_number is not None:
            print(
                color('Serial Number:           ', 'green'),
                await device_information_service.serial_number.read_value(),
            )
        if device_information_service.hardware_revision is not None:
            print(
                color('Hardware Revision:       ', 'green'),
                await device_information_service.hardware_revision.read_value(),
            )
        if device_information_service.firmware_revision is not None:
            print(
                color('Firmware Revision:       ', 'green'),
                await device_information_service.firmware_revision.read_value(),
            )
        if device_information_service.software_revision is not None:
            print(
                color('Software Revision:       ', 'green'),
                await device_information_service.software_revision.read_value(),
            )
        if device_information_service.system_id is not None:
            print(
                color('System ID:               ', 'green'),
                await device_information_service.system_id.read_value(),
            )
        if (
            device_information_service.ieee_regulatory_certification_data_list
            is not None
        ):
            print(
                color('Regulatory Certification:', 'green'),
                (
                    # pylint: disable-next=line-too-long
                    await device_information_service.ieee_regulatory_certification_data_list.read_value()
                ).hex(),
            )


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
