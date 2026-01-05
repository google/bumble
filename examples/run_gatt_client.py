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

import bumble.logging
from bumble import gatt_client
from bumble.colors import color
from bumble.core import ProtocolError
from bumble.device import Connection, Device
from bumble.transport import open_transport
from bumble.utils import AsyncRunner


# -----------------------------------------------------------------------------
class Listener(Device.Listener):
    def __init__(self, device):
        self.device = device

    @AsyncRunner.run_in_task()
    # pylint: disable=invalid-overridden-method
    async def on_connection(self, connection: Connection):
        print(f'=== Connected to {connection}')

        # Discover all services
        print('=== Discovering services')
        if connection.device.config.eatt_enabled:
            client = await gatt_client.Client.connect_eatt(connection)
        else:
            client = connection.gatt_client
        await client.discover_services()
        for service in client.services:
            await service.discover_characteristics()
            for characteristic in service.characteristics:
                await characteristic.discover_descriptors()

        print('=== Services discovered')
        gatt_client.show_services(client.services)

        # Discover all attributes
        print('=== Discovering attributes')
        attributes = await client.discover_attributes()
        for attribute in attributes:
            print(attribute)
        print('=== Attributes discovered')

        # Read all attributes
        for attribute in attributes:
            try:
                value = await client.read_value(attribute)
                print(color(f'0x{attribute.handle:04X} = {value.hex()}', 'green'))
            except ProtocolError as error:
                print(color(f'cannot read {attribute.handle:04X}:', 'red'), error)
            except TimeoutError:
                print(color('read timeout'))


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_gatt_client.py <device-config> <transport-spec> '
            '[<bluetooth-address>]'
        )
        print('example: run_gatt_client.py device1.json usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device to manage the host, with a custom listener
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
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
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
