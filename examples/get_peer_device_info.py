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
from bumble.transport import open_transport
from bumble.utils import AsyncRunner
from bumble import gatt


# -----------------------------------------------------------------------------
class Listener(Device.Listener):
    def __init__(self, device):
        self.device = device
        self.done = asyncio.get_running_loop().create_future()

    @AsyncRunner.run_in_task()
    async def on_connection(self, connection):
        print(f'=== Connected to {connection}')

        # Discover the Device Info service
        peer = Peer(connection)
        print('=== Discovering Device Info')
        await peer.discover_services([gatt.GATT_DEVICE_INFORMATION_SERVICE])

        # Check that the service was found
        device_info_services = peer.get_services_by_uuid(gatt.GATT_DEVICE_INFORMATION_SERVICE)
        if not device_info_services:
            print('!!! Service not found')
            return

        # Get the characteristics we want from the (first) device info service
        service = device_info_services[0]
        await peer.discover_characteristics([
            gatt.GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC
        ], service)

        # Read the manufacturer name
        manufacturer_name = peer.get_characteristics_by_uuid(gatt.GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC, service)
        if manufacturer_name:
            value = await peer.read_value(manufacturer_name[0])
            print(color('Manufacturer Name:', 'green'), value.decode('utf-8'))
        else:
            print('>>> No manufacturer name')

        self.done.set_result(None)


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 3:
        print('Usage: get_peer_device_info.py <transport-spec> <bluetooth-address>')
        print('example: get_peer_device_info.py usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    packet_source, packet_sink = await open_transport(sys.argv[1])
    print('<<< connected')

    # Create a host using the packet source and sink as controller
    host = Host(controller_source=packet_source, controller_sink=packet_sink)

    # Create a device to manage the host, with a custom listener
    device = Device('Bumble', address = 'F0:F1:F2:F3:F4:F5', host = host)
    device.listener = Listener(device)
    await device.power_on()

    # Connect to a peer
    target_address = sys.argv[2]
    print(f'=== Connecting to {target_address}...')
    await device.connect(target_address)
    await device.listener.done


# -----------------------------------------------------------------------------
logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
