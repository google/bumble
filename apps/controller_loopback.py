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
import statistics
import struct
import time

import click

import bumble.logging
from bumble.colors import color
from bumble.hci import (
    HCI_READ_LOOPBACK_MODE_COMMAND,
    HCI_WRITE_LOOPBACK_MODE_COMMAND,
    Address,
    HCI_Read_Loopback_Mode_Command,
    HCI_SynchronousDataPacket,
    HCI_Write_Loopback_Mode_Command,
    LoopbackMode,
)
from bumble.host import Host
from bumble.transport import open_transport


class Loopback:
    """Send and receive ACL data packets in local loopback mode"""

    def __init__(
        self,
        packet_size: int,
        packet_count: int,
        connection_type: str,
        mode: str,
        interval: int,
        transport: str,
    ):
        self.transport = transport
        self.packet_size = packet_size
        self.packet_count = packet_count
        self.connection_handle: int | None = None
        self.connection_type = connection_type
        self.connection_event = asyncio.Event()
        self.mode = mode
        self.interval = interval
        self.done = asyncio.Event()
        self.expected_counter = 0
        self.bytes_received = 0
        self.start_timestamp = 0.0
        self.last_timestamp = 0.0
        self.send_timestamps: list[float] = []
        self.rtts: list[float] = []

    def on_connection(self, connection_handle: int, *args):
        """Retrieve connection handle from new connection event"""
        if not self.connection_event.is_set():
            # The first connection handle is of type ACL,
            # subsequent connections are of type SCO
            if self.connection_type == "sco" and self.connection_handle is None:
                self.connection_handle = connection_handle
                return

            self.connection_handle = connection_handle
            self.connection_event.set()

    def on_sco_connection(
        self, address: Address, connection_handle: int, link_type: int
    ):
        self.on_connection(connection_handle)

    def on_l2cap_pdu(self, connection_handle: int, cid: int, pdu: bytes):
        """Calculate packet receive speed"""
        now = time.time()
        (counter,) = struct.unpack_from("H", pdu, 0)
        rtt = now - self.send_timestamps[counter]
        self.rtts.append(rtt)
        print(f'<<< Received packet {counter}: {len(pdu)} bytes, RTT={rtt:.4f}')
        assert connection_handle == self.connection_handle
        assert counter == self.expected_counter
        self.expected_counter += 1
        if counter == 0:
            self.start_timestamp = now
        else:
            elapsed_since_start = now - self.start_timestamp
            elapsed_since_last = now - self.last_timestamp
            self.bytes_received += len(pdu)
            instant_rx_speed = len(pdu) / elapsed_since_last
            average_rx_speed = self.bytes_received / elapsed_since_start
            if self.mode == 'throughput':
                print(
                    color(
                        f'@@@ RX speed: instant={instant_rx_speed:.4f},'
                        f' average={average_rx_speed:.4f},',
                        'cyan',
                    )
                )

        self.last_timestamp = now

        if self.expected_counter == self.packet_count:
            print(color('@@@ Received last packet', 'green'))
            self.done.set()

    def on_sco_packet(self, connection_handle: int, packet) -> None:
        print("---", connection_handle, packet)

    async def send_acl_packet(self, host: Host, packet: bytes) -> None:
        assert self.connection_handle
        host.send_l2cap_pdu(self.connection_handle, 0, packet)

    async def send_sco_packet(self, host: Host, packet: bytes) -> None:
        assert self.connection_handle
        host.send_hci_packet(
            HCI_SynchronousDataPacket(
                connection_handle=self.connection_handle,
                packet_status=HCI_SynchronousDataPacket.Status.CORRECTLY_RECEIVED_DATA,
                data_total_length=len(packet),
                data=packet,
            )
        )

    async def send_loop(self, host: Host, sender) -> None:
        for counter in range(0, self.packet_count):
            print(
                color(
                    f'>>> Sending {self.connection_type.upper()} '
                    f'packet {counter}: {self.packet_size} bytes',
                    'yellow',
                )
            )
            self.send_timestamps.append(time.time())
            await sender(host, struct.pack("H", counter) + bytes(self.packet_size - 2))
            await asyncio.sleep(self.interval / 1000 if self.mode == "rtt" else 0)

    async def run(self) -> None:
        """Run a loopback throughput test"""
        print(color('>>> Connecting to HCI...', 'green'))
        async with await open_transport(self.transport) as (
            hci_source,
            hci_sink,
        ):
            print(color('>>> Connected', 'green'))

            host = Host(hci_source, hci_sink)
            await host.reset()

            # make sure data can fit in one l2cap pdu
            l2cap_header_size = 4

            packet_queue = (
                host.acl_packet_queue
                if host.acl_packet_queue
                else host.le_acl_packet_queue
            )
            if packet_queue is None:
                print(color('!!! No packet queue', 'red'))
                return
            max_packet_size = packet_queue.max_packet_size - l2cap_header_size
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
            host.on('classic_connection', self.on_connection)
            host.on('le_connection', self.on_connection)
            host.on('sco_connection', self.on_sco_connection)
            host.on('l2cap_pdu', self.on_l2cap_pdu)
            host.on('sco_packet', self.on_sco_packet)

            loopback_mode = LoopbackMode.LOCAL

            print(color('### Setting loopback mode', 'blue'))
            await host.send_sync_command(
                HCI_Write_Loopback_Mode_Command(loopback_mode=LoopbackMode.LOCAL),
            )

            print(color('### Checking loopback mode', 'blue'))
            response = await host.send_sync_command(HCI_Read_Loopback_Mode_Command())
            if response.loopback_mode != loopback_mode:
                print(color('!!! Loopback mode mismatch', 'red'))
                return

            await self.connection_event.wait()
            assert self.connection_handle is not None
            print(color('### Connected', 'cyan'))

            print(color('=== Start sending', 'magenta'))
            start_time = time.time()
            if self.connection_type == "acl":
                sender = self.send_acl_packet
            elif self.connection_type == "sco":
                sender = self.send_sco_packet
            else:
                raise ValueError(f'Unknown connection type: {self.connection_type}')
            await self.send_loop(host, sender)

            await self.done.wait()
            print(color('=== Done!', 'magenta'))

            bytes_sent = self.packet_size * self.packet_count
            elapsed = time.time() - start_time
            average_tx_speed = bytes_sent / elapsed
            if self.mode == 'throughput':
                print(
                    color(
                        f'@@@ TX speed: average={average_tx_speed:.4f} '
                        f'({bytes_sent} bytes in {elapsed:.2f} seconds)',
                        'green',
                    )
                )
            if self.mode == 'rtt':
                print(
                    color(
                        f'RTTs: min={min(self.rtts):.4f}, '
                        f'max={max(self.rtts):.4f}, '
                        f'avg={statistics.mean(self.rtts):.4f}',
                        'blue',
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
@click.option(
    '--connection-type',
    '-t',
    metavar='TYPE',
    type=click.Choice(['acl', 'sco']),
    default='acl',
    help='Connection type',
)
@click.option(
    '--mode',
    '-m',
    metavar='MODE',
    type=click.Choice(['throughput', 'rtt']),
    default='throughput',
    help='Test mode',
)
@click.option(
    '--interval',
    type=int,
    default=100,
    help='Inter-packet interval (ms) [RTT mode only]',
)
@click.argument('transport')
def main(packet_size, packet_count, connection_type, mode, interval, transport):
    bumble.logging.setup_basic_logging()

    if connection_type == "sco" and packet_size > 255:
        print("ERROR: the maximum packet size for SCO is 255")
        return

    async def run():
        loopback = Loopback(
            packet_size, packet_count, connection_type, mode, interval, transport
        )
        await loopback.run()

    asyncio.run(run())


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
