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
from bumble.colors import color

from bumble.core import ProtocolError
from bumble.controller import Controller
from bumble.device import Device, Peer
from bumble.host import Host
from bumble.link import LocalLink
from bumble.gatt import (
    Service,
    Characteristic,
    Descriptor,
    show_services,
    GATT_CHARACTERISTIC_USER_DESCRIPTION_DESCRIPTOR,
    GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
    GATT_DEVICE_INFORMATION_SERVICE,
)


# -----------------------------------------------------------------------------
class ServerListener(Device.Listener):
    def on_connection(self, connection):
        print(f'### Server:  connected to {connection}')


# -----------------------------------------------------------------------------
async def main():
    # Create a local link
    link = LocalLink()

    # Setup a stack for the client
    client_controller = Controller("client controller", link=link)
    client_host = Host()
    client_host.controller = client_controller
    client_device = Device("client", address='F0:F1:F2:F3:F4:F5', host=client_host)
    await client_device.power_on()

    # Setup a stack for the server
    server_controller = Controller("server controller", link=link)
    server_host = Host()
    server_host.controller = server_controller
    server_device = Device("server", address='F6:F7:F8:F9:FA:FB', host=server_host)
    server_device.listener = ServerListener()
    await server_device.power_on()

    # Add a few entries to the device's GATT server
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
    server_device.add_service(device_info_service)

    # Connect the client to the server
    connection = await client_device.connect(server_device.random_address)
    print(f'=== Client: connected to {connection}')

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
            value = await attribute.read_value()
            print(color(f'0x{attribute.handle:04X} = {value.hex()}', 'green'))
        except ProtocolError as error:
            print(color(f'cannot read {attribute.handle:04X}:', 'red'), error)

    await asyncio.get_running_loop().create_future()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
