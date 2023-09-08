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

from .common import Transport, ParserSource

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_udp_transport(spec: str) -> Transport:
    '''
    Open a UDP transport.
    The parameter string has this syntax:
    <local-host>:<local-port>,<remote-host>:<remote-port>

    Example: 0.0.0.0:9000,127.0.0.1:9001
    '''

    class UdpPacketSource(asyncio.DatagramProtocol, ParserSource):
        def datagram_received(self, data, addr):
            self.parser.feed_data(data)

    class UdpPacketSink:
        def __init__(self, transport):
            self.transport = transport

        def on_packet(self, packet):
            self.transport.sendto(packet)

        def close(self):
            self.transport.close()

    local, remote = spec.split(',')
    local_host, local_port = local.split(':')
    remote_host, remote_port = remote.split(':')
    (
        udp_transport,
        packet_source,
    ) = await asyncio.get_running_loop().create_datagram_endpoint(
        UdpPacketSource,
        local_addr=(local_host, int(local_port)),
        remote_addr=(remote_host, int(remote_port)),
    )
    packet_sink = UdpPacketSink(udp_transport)

    return Transport(packet_source, packet_sink)
