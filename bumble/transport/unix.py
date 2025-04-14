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

from bumble.transport.common import Transport, StreamPacketSource, StreamPacketSink

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
