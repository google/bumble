# Copyright 2024 Google LLC
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
import os
import time
from typing import Optional
from bumble.colors import color
from bumble.hci import (
    HCI_READ_LOOPBACK_MODE_COMMAND,
    HCI_Read_Loopback_Mode_Command,
    HCI_WRITE_LOOPBACK_MODE_COMMAND,
    HCI_Write_Loopback_Mode_Command,
    LoopbackMode,
)
from bumble.host import Host
from bumble.transport import open_transport_or_link
import click


class Loopback:
    """Send and receive ACL data packets in local loopback mode"""

    def __init__(self, packet_size: int, packet_count: int, transport: str):
        self.transport = transport
        self.packet_size = packet_size
        self.packet_count = packet_count
        self.connection_handle: Optional[int] = None
        self.connection_event = asyncio.Event()
        self.done = asyncio.Event()
        self.expected_cid = 0
        self.bytes_received = 0
        self.start_timestamp = 0.0
        self.last_timestamp = 0.0

    def on_connection(self, connection_handle: int, *args):
        """Retrieve connection handle from new connection event"""
        if not self.connection_event.is_set():
            # save first connection handle for ACL
            # subsequent connections are SCO
            self.connection_handle = connection_handle
            self.connection_event.set()

    def on_l2cap_pdu(self, connection_handle: int, cid: int, pdu: bytes):
        """Calculate packet receive speed"""
        now = time.time()
        print(f'<<< Received packet {cid}: {len(pdu)} bytes')
        assert connection_handle == self.connection_handle
        assert cid == self.expected_cid
        self.expected_cid += 1
        if cid == 0:
            self.start_timestamp = now
        else:
            elapsed_since_start = now - self.start_timestamp
            elapsed_since_last = now - self.last_timestamp
            self.bytes_received += len(pdu)
            instant_rx_speed = len(pdu) / elapsed_since_last
            average_rx_speed = self.bytes_received / elapsed_since_start
            print(
                color(
                    f'@@@ RX speed: instant={instant_rx_speed:.4f},'
                    f' average={average_rx_speed:.4f}',
                    'cyan',
                )
            )

        self.last_timestamp = now

        if self.expected_cid == self.packet_count:
            print(color('@@@ Received last packet', 'green'))
            self.done.set()

    async def run(self):
        """Run a loopback throughput test"""
        print(color('>>> Connecting to HCI...', 'green'))
        async with await open_transport_or_link(self.transport) as (
            hci_source,
            hci_sink,
        ):
            print(color('>>> Connected', 'green'))

            host = Host(hci_source, hci_sink)
            await host.reset()

            # make sure data can fit in one l2cap pdu
            l2cap_header_size = 4

            max_packet_size = (
                host.acl_packet_queue
                if host.acl_packet_queue
                else host.le_acl_packet_queue
            ).max_packet_size - l2cap_header_size
            if self.packet_size > max_packet_size:
                print(
                    color(
                        f'!!! Packet size ({self.packet_size}) larger than max supported'
                        f' size ({max_packet_size})',
                        'red',
                    )
                )
                return

            if not host.supports_command(
                HCI_WRITE_LOOPBACK_MODE_COMMAND
            ) or not host.supports_command(HCI_READ_LOOPBACK_MODE_COMMAND):
                print(color('!!! Loopback mode not supported', 'red'))
                return

            # set event callbacks
            host.on('connection', self.on_connection)
            host.on('l2cap_pdu', self.on_l2cap_pdu)

            loopback_mode = LoopbackMode.LOCAL

            print(color('### Setting loopback mode', 'blue'))
            await host.send_command(
                HCI_Write_Loopback_Mode_Command(loopback_mode=LoopbackMode.LOCAL),
                check_result=True,
            )

            print(color('### Checking loopback mode', 'blue'))
            response = await host.send_command(
                HCI_Read_Loopback_Mode_Command(), check_result=True
            )
            if response.return_parameters.loopback_mode != loopback_mode:
                print(color('!!! Loopback mode mismatch', 'red'))
                return

            await self.connection_event.wait()
            print(color('### Connected', 'cyan'))

            print(color('=== Start sending', 'magenta'))
            start_time = time.time()
            bytes_sent = 0
            for cid in range(0, self.packet_count):
                # using the cid as an incremental index
                host.send_l2cap_pdu(
                    self.connection_handle, cid, bytes(self.packet_size)
                )
                print(
                    color(
                        f'>>> Sending packet {cid}: {self.packet_size} bytes', 'yellow'
                    )
                )
                bytes_sent += self.packet_size  # don't count L2CAP or HCI header sizes
                await asyncio.sleep(0)  # yield to allow packet receive

            await self.done.wait()
            print(color('=== Done!', 'magenta'))

            elapsed = time.time() - start_time
            average_tx_speed = bytes_sent / elapsed
            print(
                color(
                    f'@@@ TX speed: average={average_tx_speed:.4f} ({bytes_sent} bytes'
                    f' in {elapsed:.2f} seconds)',
                    'green',
                )
            )


# -----------------------------------------------------------------------------
@click.command()
@click.option(
    '--packet-size',
    '-s',
    metavar='SIZE',
    type=click.IntRange(8, 4096),
    default=500,
    help='Packet size',
)
@click.option(
    '--packet-count',
    '-c',
    metavar='COUNT',
    type=click.IntRange(1, 65535),
    default=10,
    help='Packet count',
)
@click.argument('transport')
def main(packet_size, packet_count, transport):
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())

    loopback = Loopback(packet_size, packet_count, transport)
    asyncio.run(loopback.run())


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
