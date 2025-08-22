# Copyright 2021-2024 Google LLC
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
import logging

from bumble.transport.common import StreamPacketSink, StreamPacketSource, Transport

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_unix_client_transport(spec: str) -> Transport:
    '''Open a UNIX socket client transport.

    The parameter is the path of unix socket. For abstract socket, the first character
    needs to be '@'.

    Example:
        * /tmp/hci.socket
        * @hci_socket
    '''

    class UnixPacketSource(StreamPacketSource):
        def connection_lost(self, exc):
            logger.debug(f'connection lost: {exc}')
            self.on_transport_lost()

    # For abstract socket, the first character should be null character.
    if spec.startswith('@'):
        spec = '\0' + spec[1:]

    (
        unix_transport,
        packet_source,
    ) = await asyncio.get_running_loop().create_unix_connection(UnixPacketSource, spec)
    packet_sink = StreamPacketSink(unix_transport)

    return Transport(packet_source, packet_sink)


# -----------------------------------------------------------------------------
async def open_unix_server_transport(spec: str) -> Transport:
    '''Open a UNIX socket server transport.

    The parameter is the path of unix socket. For abstract socket, the first character
    needs to be '@'.

    Example:
        * /tmp/hci.socket
        * @hci_socket
    '''
    # For abstract socket, the first character should be null character.
    if spec.startswith('@'):
        spec = '\0' + spec[1:]

    class UnixServerTransport(Transport):
        def __init__(self, source, sink, server):
            self.server = server
            super().__init__(source, sink)

        async def close(self):
            await super().close()

    class UnixServerProtocol(asyncio.BaseProtocol):
        def __init__(self, packet_source, packet_sink):
            self.packet_source = packet_source
            self.packet_sink = packet_sink

        # Called when a new connection is established
        def connection_made(self, transport):
            peer_name = transport.get_extra_info('peer_name')
            logger.debug('connection from %s', peer_name)
            self.packet_sink.transport = transport

        # Called when the client is disconnected
        def connection_lost(self, error):
            logger.debug('connection lost: %s', error)
            self.packet_sink.transport = None

        def eof_received(self):
            logger.debug('connection end')
            self.packet_sink.transport = None

        # Called when data is received on the socket
        def data_received(self, data):
            self.packet_source.data_received(data)

    class UnixServerPacketSink:
        def __init__(self):
            self.transport = None

        def on_packet(self, packet):
            if self.transport:
                self.transport.write(packet)
            else:
                logger.debug('no client, dropping packet')

    packet_source = StreamPacketSource()
    packet_sink = UnixServerPacketSink()
    server = await asyncio.get_running_loop().create_unix_server(
        lambda: UnixServerProtocol(packet_source, packet_sink), spec
    )

    return UnixServerTransport(packet_source, packet_sink, server)
