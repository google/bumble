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
from __future__ import annotations
import asyncio
import logging
import socket

from .common import Transport, StreamPacketSource

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------

# A pass-through function to ease mock testing.
async def _create_server(*args, **kw_args):
    await asyncio.get_running_loop().create_server(*args, **kw_args)


async def open_tcp_server_transport(spec: str) -> Transport:
    '''
    Open a TCP server transport.
    The parameter string has this syntax:
    <local-host>:<local-port>
    Where <local-host> may be the address of a local network interface, or '_'
    to accept connections on all local network interfaces.

    Example: _:9001
    '''
    local_host, local_port = spec.split(':')
    return await _open_tcp_server_transport_impl(
        host=local_host if local_host != '_' else None, port=int(local_port)
    )


async def open_tcp_server_transport_with_socket(sock: socket.socket) -> Transport:
    '''
    Open a TCP server transport with an existing socket.

    One reason to use this variant is to let python pick an unused port.
    '''
    return await _open_tcp_server_transport_impl(sock=sock)


async def _open_tcp_server_transport_impl(**kwargs) -> Transport:
    class TcpServerTransport(Transport):
        async def close(self):
            await super().close()

    class TcpServerProtocol(asyncio.BaseProtocol):
        def __init__(self, packet_source, packet_sink):
            self.packet_source = packet_source
            self.packet_sink = packet_sink

        # Called when a new connection is established
        def connection_made(self, transport):
            peer_name = transport.get_extra_info('peer_name')
            logger.debug(f'connection from {peer_name}')
            self.packet_sink.transport = transport

        # Called when the client is disconnected
        def connection_lost(self, error):
            logger.debug(f'connection lost: {error}')
            self.packet_sink.transport = None

        def eof_received(self):
            logger.debug('connection end')
            self.packet_sink.transport = None

        # Called when data is received on the socket
        def data_received(self, data):
            self.packet_source.data_received(data)

    class TcpServerPacketSink:
        def __init__(self):
            self.transport = None

        def on_packet(self, packet):
            if self.transport:
                self.transport.write(packet)
            else:
                logger.debug('no client, dropping packet')

    packet_source = StreamPacketSource()
    packet_sink = TcpServerPacketSink()
    await _create_server(
        lambda: TcpServerProtocol(packet_source, packet_sink), **kwargs
    )

    return TcpServerTransport(packet_source, packet_sink)
