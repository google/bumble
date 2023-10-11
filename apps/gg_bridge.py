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
import struct
import logging
import click

from bumble import l2cap
from bumble.colors import color
from bumble.device import Device, Peer
from bumble.core import AdvertisingData
from bumble.gatt import Service, Characteristic, CharacteristicValue
from bumble.utils import AsyncRunner
from bumble.transport import open_transport_or_link
from bumble.hci import HCI_Constant


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
GG_GATTLINK_SERVICE_UUID = 'ABBAFF00-E56A-484C-B832-8B17CF6CBFE8'
GG_GATTLINK_RX_CHARACTERISTIC_UUID = 'ABBAFF01-E56A-484C-B832-8B17CF6CBFE8'
GG_GATTLINK_TX_CHARACTERISTIC_UUID = 'ABBAFF02-E56A-484C-B832-8B17CF6CBFE8'
GG_GATTLINK_L2CAP_CHANNEL_PSM_CHARACTERISTIC_UUID = (
    'ABBAFF03-E56A-484C-B832-8B17CF6CBFE8'
)

GG_PREFERRED_MTU = 256


# -----------------------------------------------------------------------------
class GattlinkL2capEndpoint:
    def __init__(self):
        self.l2cap_channel = None
        self.l2cap_packet = b''
        self.l2cap_packet_size = 0

    # Called when an L2CAP SDU has been received
    def on_coc_sdu(self, sdu):
        print(color(f'<<< [L2CAP SDU]: {len(sdu)} bytes', 'cyan'))
        while len(sdu):
            if self.l2cap_packet_size == 0:
                # Expect a new packet
                self.l2cap_packet_size = sdu[0] + 1
                sdu = sdu[1:]
            else:
                bytes_needed = self.l2cap_packet_size - len(self.l2cap_packet)
                chunk = min(bytes_needed, len(sdu))
                self.l2cap_packet += sdu[:chunk]
                sdu = sdu[chunk:]
                if len(self.l2cap_packet) == self.l2cap_packet_size:
                    self.on_l2cap_packet(self.l2cap_packet)
                    self.l2cap_packet = b''
                    self.l2cap_packet_size = 0


# -----------------------------------------------------------------------------
class GattlinkHubBridge(GattlinkL2capEndpoint, Device.Listener):
    def __init__(self, device, peer_address):
        super().__init__()
        self.device = device
        self.peer_address = peer_address
        self.peer = None
        self.tx_socket = None
        self.rx_characteristic = None
        self.tx_characteristic = None
        self.l2cap_psm_characteristic = None

        device.listener = self

    async def start(self):
        # Connect to the peer
        print(f'=== Connecting to {self.peer_address}...')
        await self.device.connect(self.peer_address)

    async def connect_l2cap(self, psm):
        print(color(f'### Connecting with L2CAP on PSM = {psm}', 'yellow'))
        try:
            self.l2cap_channel = await self.peer.connection.open_l2cap_channel(psm)
            print(color('*** Connected', 'yellow'), self.l2cap_channel)
            self.l2cap_channel.sink = self.on_coc_sdu

        except Exception as error:
            print(color(f'!!! Connection failed: {error}', 'red'))

    @AsyncRunner.run_in_task()
    # pylint: disable=invalid-overridden-method
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
            elif (
                characteristic.uuid == GG_GATTLINK_L2CAP_CHANNEL_PSM_CHARACTERISTIC_UUID
            ):
                self.l2cap_psm_characteristic = characteristic
        print('RX:', self.rx_characteristic)
        print('TX:', self.tx_characteristic)
        print('PSM:', self.l2cap_psm_characteristic)

        if self.l2cap_psm_characteristic:
            # Subscribe to and then read the PSM value
            await self.peer.subscribe(
                self.l2cap_psm_characteristic, self.on_l2cap_psm_received
            )
            psm_bytes = await self.peer.read_value(self.l2cap_psm_characteristic)
            psm = struct.unpack('<H', psm_bytes)[0]
            await self.connect_l2cap(psm)
        elif self.tx_characteristic:
            # Subscribe to TX
            await self.peer.subscribe(self.tx_characteristic, self.on_tx_received)
            print(color('=== Subscribed to Gattlink TX', 'yellow'))
        else:
            print(color('!!! No Gattlink TX or PSM found', 'red'))

    def on_connection_failure(self, error):
        print(color(f'!!! Connection failed: {error}'))

    def on_disconnection(self, reason):
        print(
            color(
                f'!!! Disconnected from {self.peer}, '
                f'reason={HCI_Constant.error_name(reason)}',
                'red',
            )
        )
        self.tx_characteristic = None
        self.rx_characteristic = None
        self.peer = None

    # Called when an L2CAP packet has been received
    def on_l2cap_packet(self, packet):
        print(color(f'<<< [L2CAP PACKET]: {len(packet)} bytes', 'cyan'))
        print(color('>>> [UDP]', 'magenta'))
        self.tx_socket.sendto(packet)

    # Called by the GATT client when a notification is received
    def on_tx_received(self, value):
        print(color(f'<<< [GATT TX]: {len(value)} bytes', 'cyan'))
        if self.tx_socket:
            print(color('>>> [UDP]', 'magenta'))
            self.tx_socket.sendto(value)

    # Called by asyncio when the UDP socket is created
    def on_l2cap_psm_received(self, value):
        psm = struct.unpack('<H', value)[0]
        asyncio.create_task(self.connect_l2cap(psm))

    # Called by asyncio when the UDP socket is created
    def connection_made(self, transport):
        pass

    # Called by asyncio when a UDP datagram is received
    def datagram_received(self, data, _address):
        print(color(f'<<< [UDP]: {len(data)} bytes', 'green'))

        if self.l2cap_channel:
            print(color('>>> [L2CAP]', 'yellow'))
            self.l2cap_channel.write(bytes([len(data) - 1]) + data)
        elif self.peer and self.rx_characteristic:
            print(color('>>> [GATT RX]', 'yellow'))
            asyncio.create_task(self.peer.write_value(self.rx_characteristic, data))


# -----------------------------------------------------------------------------
class GattlinkNodeBridge(GattlinkL2capEndpoint, Device.Listener):
    def __init__(self, device: Device):
        super().__init__()
        self.device = device
        self.peer = None
        self.tx_socket = None
        self.tx_subscriber = None
        self.rx_characteristic = None
        self.transport = None

        # Register as a listener
        device.listener = self

        # Listen for incoming L2CAP CoC connections
        psm = 0xFB
        device.create_l2cap_server(
            spec=l2cap.LeCreditBasedChannelSpec(
                psm=0xFB,
            ),
            handler=self.on_coc,
        )
        print(f'### Listening for CoC connection on PSM {psm}')

        # Setup the Gattlink service
        self.rx_characteristic = Characteristic(
            GG_GATTLINK_RX_CHARACTERISTIC_UUID,
            Characteristic.WRITE_WITHOUT_RESPONSE,
            Characteristic.WRITEABLE,
            CharacteristicValue(write=self.on_rx_write),
        )
        self.tx_characteristic = Characteristic(
            GG_GATTLINK_TX_CHARACTERISTIC_UUID,
            Characteristic.Properties.NOTIFY,
            Characteristic.READABLE,
        )
        self.tx_characteristic.on('subscription', self.on_tx_subscription)
        self.psm_characteristic = Characteristic(
            GG_GATTLINK_L2CAP_CHANNEL_PSM_CHARACTERISTIC_UUID,
            Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
            Characteristic.READABLE,
            bytes([psm, 0]),
        )
        gattlink_service = Service(
            GG_GATTLINK_SERVICE_UUID,
            [self.rx_characteristic, self.tx_characteristic, self.psm_characteristic],
        )
        device.add_services([gattlink_service])
        device.advertising_data = bytes(
            AdvertisingData(
                [
                    (AdvertisingData.COMPLETE_LOCAL_NAME, bytes('Bumble GG', 'utf-8')),
                    (
                        AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
                        bytes(
                            reversed(bytes.fromhex('ABBAFF00E56A484CB8328B17CF6CBFE8'))
                        ),
                    ),
                ]
            )
        )

    async def start(self):
        await self.device.start_advertising()

    # Called by asyncio when the UDP socket is created
    def connection_made(self, transport):
        self.transport = transport

    # Called by asyncio when a UDP datagram is received
    def datagram_received(self, data, _address):
        print(color(f'<<< [UDP]: {len(data)} bytes', 'green'))

        if self.l2cap_channel:
            print(color('>>> [L2CAP]', 'yellow'))
            self.l2cap_channel.write(bytes([len(data) - 1]) + data)
        elif self.tx_subscriber:
            print(color('>>> [GATT TX]', 'yellow'))
            self.tx_characteristic.value = data
            asyncio.create_task(self.device.notify_subscribers(self.tx_characteristic))

    # Called when a write to the RX characteristic has been received
    def on_rx_write(self, _connection, data):
        print(color(f'<<< [GATT RX]: {len(data)} bytes', 'cyan'))
        print(color('>>> [UDP]', 'magenta'))
        self.tx_socket.sendto(data)

    # Called when the subscription to the TX characteristic has changed
    def on_tx_subscription(self, peer, enabled):
        print(
            f'### [GATT TX] subscription from {peer}: '
            f'{"enabled" if enabled else "disabled"}'
        )
        if enabled:
            self.tx_subscriber = peer
        else:
            self.tx_subscriber = None

    # Called when an L2CAP packet is received
    def on_l2cap_packet(self, packet):
        print(color(f'<<< [L2CAP PACKET]: {len(packet)} bytes', 'cyan'))
        print(color('>>> [UDP]', 'magenta'))
        self.tx_socket.sendto(packet)

    # Called when a new connection is established
    def on_coc(self, channel):
        print('*** CoC Connection', channel)
        self.l2cap_channel = channel
        channel.sink = self.on_coc_sdu


# -----------------------------------------------------------------------------
async def run(
    hci_transport,
    device_address,
    role_or_peer_address,
    send_host,
    send_port,
    receive_host,
    receive_port,
):
    print('<<< connecting to HCI...')
    async with await open_transport_or_link(hci_transport) as (hci_source, hci_sink):
        print('<<< connected')

        # Instantiate a bridge object
        device = Device.with_hci('Bumble GG', device_address, hci_source, hci_sink)

        # Instantiate a bridge object
        if role_or_peer_address == 'node':
            bridge = GattlinkNodeBridge(device)
        else:
            bridge = GattlinkHubBridge(device, role_or_peer_address)

        # Create a UDP to RX bridge (receive from UDP, send to RX)
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(
            lambda: bridge, local_addr=(receive_host, receive_port)
        )

        # Create a UDP to TX bridge (receive from TX, send to UDP)
        bridge.tx_socket, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=(send_host, send_port),
        )

        await device.power_on()
        await bridge.start()

        # Wait until the source terminates
        await hci_source.wait_for_termination()


@click.command()
@click.argument('hci_transport')
@click.argument('device_address')
@click.argument('role_or_peer_address')
@click.option(
    '-sh', '--send-host', type=str, default='127.0.0.1', help='UDP host to send to'
)
@click.option('-sp', '--send-port', type=int, default=9001, help='UDP port to send to')
@click.option(
    '-rh',
    '--receive-host',
    type=str,
    default='127.0.0.1',
    help='UDP host to receive on',
)
@click.option(
    '-rp', '--receive-port', type=int, default=9000, help='UDP port to receive on'
)
def main(
    hci_transport,
    device_address,
    role_or_peer_address,
    send_host,
    send_port,
    receive_host,
    receive_port,
):
    asyncio.run(
        run(
            hci_transport,
            device_address,
            role_or_peer_address,
            send_host,
            send_port,
            receive_host,
            receive_port,
        )
    )


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())
if __name__ == '__main__':
    main()
