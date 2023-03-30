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
import logging
import asyncio
import sys
import os

from bumble.gatt import (
    GATT_CHARACTERISTIC_USER_DESCRIPTION_DESCRIPTOR,
    GATT_DEVICE_INFORMATION_SERVICE,
    GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
    Characteristic,
    Descriptor,
    Service,
)
from bumble.device import Device
from bumble.host import Host
from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 4:
        print(
            'Usage: run_controller.py <controller-address> <device-config> '
            '<transport-spec>'
        )
        print(
            'example: run_controller.py F2:F3:F4:F5:F6:F7 device1.json '
            'udp:0.0.0.0:22333,172.16.104.161:22333'
        )
        return

    print('>>> connecting to HCI...')
    async with await open_transport_or_link(sys.argv[3]) as (hci_source, hci_sink):
        print('>>> connected')

        # Create a local link
        link = LocalLink()

        # Create a first controller using the packet source/sink as its host interface
        controller1 = Controller(
            'C1', host_source=hci_source, host_sink=hci_sink, link=link
        )
        controller1.random_address = sys.argv[1]

        # Create a second controller using the same link
        controller2 = Controller('C2', link=link)

        # Create a host for the second controller
        host = Host()
        host.controller = controller2

        # Create a device to manage the host
        device = Device.from_config_file(sys.argv[2])
        device.host = host

        # Add some basic services to the device's GATT server
        descriptor = Descriptor(
            GATT_CHARACTERISTIC_USER_DESCRIPTION_DESCRIPTOR,
            Descriptor.READABLE,
            'My Description',
        )
        manufacturer_name_characteristic = Characteristic(
            GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            "Fitbit",
            [descriptor],
        )
        device_info_service = Service(
            GATT_DEVICE_INFORMATION_SERVICE, [manufacturer_name_characteristic]
        )
        device.add_service(device_info_service)

        # Debug print
        for attribute in device.gatt_server.attributes:
            print(attribute)

        await device.power_on()
        await device.start_advertising()
        await device.start_scanning()

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
