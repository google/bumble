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
import logging

from .common import Transport, StreamPacketSource, StreamPacketSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_tcp_client_transport(spec: str) -> Transport:
    '''
    Open a TCP client transport.
    The parameter string has this syntax:
    <remote-host>:<remote-port>

    Example: 127.0.0.1:9001
    '''

    class TcpPacketSource(StreamPacketSource):
        def connection_lost(self, exc):
            logger.debug(f'connection lost: {exc}')
            self.on_transport_lost()

    remote_host, remote_port = spec.split(':')
    tcp_transport, packet_source = await asyncio.get_running_loop().create_connection(
        TcpPacketSource,
        host=remote_host,
        port=int(remote_port),
    )
    packet_sink = StreamPacketSink(tcp_transport)

    return Transport(packet_source, packet_sink)
