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

from bumble.core import ProtocolError
from bumble.device import Device, Peer
from bumble.gatt import show_services
from bumble.transport import open_transport_or_link
from bumble.utils import AsyncRunner


# -----------------------------------------------------------------------------
class Listener(Device.Listener):
    def __init__(self, device):
        self.device = device

    @AsyncRunner.run_in_task()
    # pylint: disable=invalid-overridden-method
    async def on_connection(self, connection):
        print(f'=== Connected to {connection}')

        # Discover all services
        print('=== Discovering services')
        peer = Peer(connection)
        await peer.discover_services()
        for service in peer.services:
            await service.discover_characteristics()
            for characteristic in service.characteristics:
                await characteristic.discover_descriptors()

        print('=== Services discovered')
        show_services(peer.services)

        # Discover all attributes
        print('=== Discovering attributes')
        attributes = await peer.discover_attributes()
        for attribute in attributes:
            print(attribute)
        print('=== Attributes discovered')

        # Read all attributes
        for attribute in attributes:
            try:
                value = await peer.read_value(attribute)
                print(color(f'0x{attribute.handle:04X} = {value.hex()}', 'green'))
            except ProtocolError as error:
                print(color(f'cannot read {attribute.handle:04X}:', 'red'), error)
            except TimeoutError:
                print(color('read timeout'))


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print(
            'Usage: run_gatt_client.py <device-config> <transport-spec> '
            '[<bluetooth-address>]'
        )
        print('example: run_gatt_client.py device1.json usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device to manage the host, with a custom listener
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.listener = Listener(device)
        await device.power_on()

        # Connect to a peer
        if len(sys.argv) > 3:
            target_address = sys.argv[3]
            print(f'=== Connecting to {target_address}...')
            await device.connect(target_address)
        else:
            await device.start_advertising()

        await asyncio.get_running_loop().create_future()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
