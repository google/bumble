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
from colors import color

from bumble.device import Device, Peer
from bumble.core import AdvertisingData
from bumble.gatt import Service, Characteristic
from bumble.utils import AsyncRunner
from bumble.transport import open_transport_or_link
from bumble.hci import HCI_Constant


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
GG_GATTLINK_SERVICE_UUID                          = 'ABBAFF00-E56A-484C-B832-8B17CF6CBFE8'
GG_GATTLINK_RX_CHARACTERISTIC_UUID                = 'ABBAFF01-E56A-484C-B832-8B17CF6CBFE8'
GG_GATTLINK_TX_CHARACTERISTIC_UUID                = 'ABBAFF02-E56A-484C-B832-8B17CF6CBFE8'
GG_GATTLINK_L2CAP_CHANNEL_PSM_CHARACTERISTIC_UUID = 'ABBAFF03-E56A-484C-B832-8B17CF6CBFE8'

GG_PREFERRED_MTU = 256


# -----------------------------------------------------------------------------
class GattlinkHubBridge(Device.Listener):
    def __init__(self):
        self.peer              = None
        self.rx_socket         = None
        self.tx_socket         = None
        self.rx_characteristic = None
        self.tx_characteristic = None

    @AsyncRunner.run_in_task()
    async def on_connection(self, connection):
        print(f'=== Connected to {connection}')
        self.peer = Peer(connection)

        # Request a larger MTU than the default
        server_mtu = await self.peer.request_mtu(GG_PREFERRED_MTU)
        print(f'### Server MTU = {server_mtu}')

        # Discover all services
        print(color('=== Discovering services', 'yellow'))
        await self.peer.discover_service(GG_GATTLINK_SERVICE_UUID)
        print(color('=== Services discovered', 'yellow'), self.peer.services)
        for service in self.peer.services:
            print(service)
        services = self.peer.get_services_by_uuid(GG_GATTLINK_SERVICE_UUID)
        if not services:
            print(color('!!! Gattlink service not found', 'red'))
            return

        # Use the first Gattlink (there should only be one anyway)
        gattlink_service = services[0]

        # Discover all the characteristics for the service
        characteristics = await gattlink_service.discover_characteristics()
        print(color('=== Characteristics discovered', 'yellow'))
        for characteristic in characteristics:
            if characteristic.uuid == GG_GATTLINK_RX_CHARACTERISTIC_UUID:
                self.rx_characteristic = characteristic
            elif characteristic.uuid == GG_GATTLINK_TX_CHARACTERISTIC_UUID:
                self.tx_characteristic = characteristic
        print('RX:', self.rx_characteristic)
        print('TX:', self.tx_characteristic)

        # Subscribe to TX
        if self.tx_characteristic:
            await self.peer.subscribe(self.tx_characteristic, self.on_tx_received)
            print(color('=== Subscribed to Gattlink TX', 'yellow'))
        else:
            print(color('!!! Gattlink TX not found', 'red'))

    def on_connection_failure(self, error):
        print(color(f'!!! Connection failed: {error}'))

    def on_disconnection(self, reason):
        print(color(f'!!! Disconnected from {self.peer}, reason={HCI_Constant.error_name(reason)}', 'red'))
        self.tx_characteristic = None
        self.rx_characteristic = None
        self.peer = None

    # Called by the GATT client when a notification is received
    def on_tx_received(self, value):
        print(color('>>> TX:', 'magenta'), value.hex())
        if self.tx_socket:
            self.tx_socket.sendto(value)

    # Called by asyncio when the UDP socket is created
    def connection_made(self, transport):
        pass

    # Called by asyncio when a UDP datagram is received
    def datagram_received(self, data, address):
        print(color('<<< RX:', 'magenta'), data.hex())

        # TODO: use a queue instead of creating a task everytime
        if self.peer and self.rx_characteristic:
            asyncio.create_task(self.peer.write_value(self.rx_characteristic, data))


# -----------------------------------------------------------------------------
class GattlinkNodeBridge(Device.Listener):
    def __init__(self):
        self.peer      = None
        self.rx_socket = None
        self.tx_socket = None

    # Called by asyncio when the UDP socket is created
    def connection_made(self, transport):
        pass

    # Called by asyncio when a UDP datagram is received
    def datagram_received(self, data, address):
        print(color('<<< RX:', 'magenta'), data.hex())

        # TODO: use a queue instead of creating a task everytime
        if self.peer and self.rx_characteristic:
            asyncio.create_task(self.peer.write_value(self.rx_characteristic, data))


# -----------------------------------------------------------------------------
async def run(hci_transport, device_address, send_host, send_port, receive_host, receive_port):
    print('<<< connecting to HCI...')
    async with await open_transport_or_link(hci_transport) as (hci_source, hci_sink):
        print('<<< connected')

        # Instantiate a bridge object
        bridge = GattlinkNodeBridge()

        # Create a UDP to RX bridge (receive from UDP, send to RX)
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(
            lambda: bridge,
            local_addr=(receive_host, receive_port)
        )

        # Create a UDP to TX bridge (receive from TX, send to UDP)
        bridge.tx_socket, _ = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(send_host, send_port)
        )

        # Create a device to manage the host, with a custom listener
        device = Device.with_hci('Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
        device.listener = bridge
        await device.power_on()

        # Connect to the peer
        # print(f'=== Connecting to {device_address}...')
        # await device.connect(device_address)

        # TODO move to class
        gattlink_service = Service(
            GG_GATTLINK_SERVICE_UUID,
            [
                Characteristic(
                    GG_GATTLINK_L2CAP_CHANNEL_PSM_CHARACTERISTIC_UUID,
                    Characteristic.READ,
                    Characteristic.READABLE,
                    bytes([193, 0])
                )
            ]
        )
        device.add_services([gattlink_service])
        device.advertising_data = bytes(
            AdvertisingData([
                (AdvertisingData.COMPLETE_LOCAL_NAME, bytes('Bumble GG', 'utf-8')),
                (AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS, bytes(reversed(bytes.fromhex('ABBAFF00E56A484CB8328B17CF6CBFE8'))))
            ])
        )
        await device.start_advertising()

        # Wait until the source terminates
        await hci_source.wait_for_termination()


@click.command()
@click.argument('hci_transport')
@click.argument('device_address')
@click.option('-sh', '--send-host', type=str, default='127.0.0.1', help='UDP host to send to')
@click.option('-sp', '--send-port', type=int, default=9001, help='UDP port to send to')
@click.option('-rh', '--receive-host', type=str, default='127.0.0.1', help='UDP host to receive on')
@click.option('-rp', '--receive-port', type=int, default=9000, help='UDP port to receive on')
def main(hci_transport, device_address, send_host, send_port, receive_host, receive_port):
    logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run(hci_transport, device_address, send_host, send_port, receive_host, receive_port))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
