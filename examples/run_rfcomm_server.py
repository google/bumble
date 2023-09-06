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

from bumble.core import UUID
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.rfcomm import Server
from bumble.utils import AsyncRunner
from bumble.rfcomm import make_service_sdp_records


# -----------------------------------------------------------------------------
def sdp_records(channel, uuid):
    service_record_handle = 0x00010001
    return {
        service_record_handle: make_service_sdp_records(
            service_record_handle, channel, UUID(uuid)
        )
    }


# -----------------------------------------------------------------------------
def on_rfcomm_session(rfcomm_session, tcp_server):
    print('*** RFComm session connected', rfcomm_session)
    tcp_server.attach_session(rfcomm_session)


# -----------------------------------------------------------------------------
class TcpServerProtocol(asyncio.Protocol):
    def __init__(self, server):
        self.server = server

    def connection_made(self, transport):
        peer_name = transport.get_extra_info('peer_name')
        print(f'<<< TCP Server: connection from {peer_name}')
        if self.server:
            self.server.tcp_transport = transport
        else:
            transport.close()

    def connection_lost(self, exc):
        print('<<< TCP Server: connection lost')
        if self.server:
            self.server.tcp_transport = None

    def data_received(self, data):
        print(f'<<< TCP Server: data received: {len(data)} bytes - {data.hex()}')
        if self.server:
            self.server.tcp_data_received(data)


# -----------------------------------------------------------------------------
class TcpServer:
    def __init__(self, port):
        self.rfcomm_session = None
        self.tcp_transport = None
        AsyncRunner.spawn(self.run(port))

    def attach_session(self, rfcomm_session):
        if self.rfcomm_session:
            self.rfcomm_session.sink = None

        self.rfcomm_session = rfcomm_session
        rfcomm_session.sink = self.rfcomm_data_received

    def rfcomm_data_received(self, data):
        print(f'<<< RFCOMM Data: {data.hex()}')
        if self.tcp_transport:
            self.tcp_transport.write(data)
        else:
            print('!!! no TCP connection, dropping data')

    def tcp_data_received(self, data):
        if self.rfcomm_session:
            self.rfcomm_session.write(data)
        else:
            print('!!! no RFComm session, dropping data')

    async def run(self, port):
        print(f'$$$ Starting TCP server on port {port}')

        server = await asyncio.get_running_loop().create_server(
            lambda: TcpServerProtocol(self), '127.0.0.1', port
        )

        async with server:
            await server.serve_forever()


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 4:
        print(
            'Usage: run_rfcomm_server.py <device-config> <transport-spec> '
            '<tcp-port> [<uuid>]'
        )
        print('example: run_rfcomm_server.py classic2.json usb:0 8888')
        return

    tcp_port = int(sys.argv[3])

    if len(sys.argv) >= 5:
        uuid = sys.argv[4]
    else:
        uuid = 'E6D55659-C8B4-4B85-96BB-B1143AF6D3AE'

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True

        # Create a TCP server
        tcp_server = TcpServer(tcp_port)

        # Create and register an RFComm server
        rfcomm_server = Server(device)

        # Listen for incoming DLC connections
        channel_number = rfcomm_server.listen(
            lambda session: on_rfcomm_session(session, tcp_server)
        )
        print(f'### Listening for RFComm connections on channel {channel_number}')

        # Setup the SDP to advertise this channel
        device.sdp_service_records = sdp_records(channel_number, uuid)

        # Start the controller
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
