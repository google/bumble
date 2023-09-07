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
import logging
import websockets

from .common import Transport, ParserSource, PumpedPacketSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_ws_server_transport(spec: str) -> Transport:
    '''
    Open a WebSocket server transport.
    The parameter string has this syntax:
    <local-host>:<local-port>
    Where <local-host> may be the address of a local network interface, or '_'
    to accept connections on all local network interfaces.

    Example: _:9001
    '''

    class WsServerTransport(Transport):
        def __init__(self):
            source = ParserSource()
            sink = PumpedPacketSink(self.send_packet)
            self.connection = None
            self.server = None

            super().__init__(source, sink)

        async def serve(self, local_host, local_port):
            self.sink.start()
            # pylint: disable-next=no-member
            self.server = await websockets.serve(
                ws_handler=self.on_connection,
                host=local_host if local_host != '_' else None,
                port=int(local_port),
            )
            logger.debug(f'websocket server ready on port {local_port}')

        async def on_connection(self, connection):
            logger.debug(
                f'new connection on {connection.local_address} '
                f'from {connection.remote_address}'
            )
            self.connection = connection
            # pylint: disable=no-member
            try:
                async for packet in connection:
                    if isinstance(packet, bytes):
                        self.source.parser.feed_data(packet)
                    else:
                        logger.warning('discarding packet: not a BINARY frame')
            except websockets.WebSocketException as error:
                logger.debug(f'exception while receiving packet: {error}')

            # We're now disconnected
            self.connection = None

        async def send_packet(self, packet):
            if self.connection is None:
                logger.debug('no connection, dropping packet')
                return
            return await self.connection.send(packet)

    local_host, local_port = spec.split(':')
    transport = WsServerTransport()
    await transport.serve(local_host, local_port)
    return transport
