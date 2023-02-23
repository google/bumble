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
import os
import logging
import click

import bumble.core
from bumble.colors import color
from bumble.device import Device, Peer
from bumble.gatt import show_services
from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def dump_gatt_db(peer, done):
    # Discover all services
    print(color('### Discovering Services and Characteristics', 'magenta'))
    await peer.discover_services()
    for service in peer.services:
        await service.discover_characteristics()
        for characteristic in service.characteristics:
            await characteristic.discover_descriptors()

    print(color('=== Services ===', 'yellow'))
    show_services(peer.services)
    print()

    # Discover all attributes
    print(color('=== All Attributes ===', 'yellow'))
    attributes = await peer.discover_attributes()
    for attribute in attributes:
        print(attribute)
        try:
            value = await attribute.read_value()
            print(color(f'{value.hex()}', 'green'))
        except bumble.core.ProtocolError as error:
            print(color(error, 'red'))
        except bumble.core.TimeoutError:
            print(color('read timeout', 'red'))

    if done is not None:
        done.set_result(None)


# -----------------------------------------------------------------------------
async def async_main(device_config, encrypt, transport, address_or_name):
    async with await open_transport_or_link(transport) as (hci_source, hci_sink):

        # Create a device
        if device_config:
            device = Device.from_config_file_with_hci(
                device_config, hci_source, hci_sink
            )
        else:
            device = Device.with_hci(
                'Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink
            )
        await device.power_on()

        if address_or_name:
            # Connect to the target peer
            connection = await device.connect(address_or_name)

            # Encrypt the connection if required
            if encrypt:
                await connection.encrypt()

            await dump_gatt_db(Peer(connection), None)
        else:
            # Wait for a connection
            done = asyncio.get_running_loop().create_future()
            device.on(
                'connection',
                lambda connection: asyncio.create_task(
                    dump_gatt_db(Peer(connection), done)
                ),
            )
            await device.start_advertising(auto_restart=True)

            print(color('### Waiting for connection...', 'blue'))
            await done


# -----------------------------------------------------------------------------
@click.command()
@click.option('--device-config', help='Device configuration', type=click.Path())
@click.option('--encrypt', help='Encrypt the connection', is_flag=True, default=False)
@click.argument('transport')
@click.argument('address-or-name', required=False)
def main(device_config, encrypt, transport, address_or_name):
    """
    Dump the GATT database on a remote device. If ADDRESS_OR_NAME is not specified,
    wait for an incoming connection.
    """
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(async_main(device_config, encrypt, transport, address_or_name))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
