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
from bumble.host import Host
from bumble.profiles.device_information_service import DeviceInformationServiceProxy
from bumble.transport import open_transport
from bumble import gatt


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 3:
        print('Usage: device_info_client.py <transport-spec> <bluetooth-address>')
        print('example: device_info_client.py usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[1]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create and start a device
        host = Host(controller_source=hci_source, controller_sink=hci_sink)
        device = Device('Bumble', address = 'F0:F1:F2:F3:F4:F5', host = host)
        await device.power_on()

        # Connect to the peer
        target_address = sys.argv[2]
        print(f'=== Connecting to {target_address}...')
        connection = await device.connect(target_address)
        print(f'=== Connected to {connection}')

        # Discover the Device Information service
        peer = Peer(connection)
        print('=== Discovering Device Information Service')
        await peer.discover_services([gatt.GATT_DEVICE_INFORMATION_SERVICE])

        # Check that the service was found
        device_info_services = peer.get_services_by_uuid(gatt.GATT_DEVICE_INFORMATION_SERVICE)
        if not device_info_services:
            print('!!! Service not found')
            return
        device_info_service = device_info_services[0]
        await device_info_service.discover_characteristics()

        # Create a service-specific proxy to read and decode the values
        device_info = DeviceInformationServiceProxy(device_info_service)

        # Read and print the fields
        if device_info.manufacturer_name is not None:
            print(color('Manufacturer Name:       ', 'green'), await device_info.manufacturer_name.read_value())
        if device_info.model_number is not None:
            print(color('Model Number:            ', 'green'), await device_info.model_number.read_value())
        if device_info.serial_number is not None:
            print(color('Serial Number:           ', 'green'), await device_info.serial_number.read_value())
        if device_info.hardware_revision is not None:
            print(color('Hardware Revision:       ', 'green'), await device_info.hardware_revision.read_value())
        if device_info.firmware_revision is not None:
            print(color('Firmware Revision:       ', 'green'), await device_info.firmware_revision.read_value())
        if device_info.software_revision is not None:
            print(color('Software Revision:       ', 'green'), await device_info.software_revision.read_value())
        if device_info.system_id is not None:
            print(color('System ID:               ', 'green'), await device_info.system_id.read_value())
        if device_info.ieee_regulatory_certification_data_list is not None:
            print(color('Regulatory Certification:', 'green'), (await device_info.ieee_regulatory_certification_data_list.read_value()).hex())


# -----------------------------------------------------------------------------
logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
