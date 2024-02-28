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
import datetime
import logging
import os
import struct

import click

from bumble.colors import color
from bumble import hci
from bumble.transport.common import PacketReader
from bumble.helpers import PacketTracer


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class SnoopPacketReader:
    '''
    Reader that reads HCI packets from a "snoop" file (based on RFC 1761, but not
    exactly the same...)
    '''

    DATALINK_H1 = 1001
    DATALINK_H4 = 1002
    DATALINK_BSCP = 1003
    DATALINK_H5 = 1004

    IDENTIFICATION_PATTERN = b'btsnoop\0'
    TIMESTAMP_ANCHOR = datetime.datetime(2000, 1, 1)
    TIMESTAMP_DELTA = 0x00E03AB44A676000
    ONE_MICROSECOND = datetime.timedelta(microseconds=1)

    def __init__(self, source):
        self.source = source
        self.at_end = False

        # Read the header
        identification_pattern = source.read(8)
        if identification_pattern != self.IDENTIFICATION_PATTERN:
            raise ValueError(
                'not a valid snoop file, unexpected identification pattern'
            )
        (self.version_number, self.data_link_type) = struct.unpack(
            '>II', source.read(8)
        )
        if self.data_link_type not in (self.DATALINK_H4, self.DATALINK_H1):
            raise ValueError(f'datalink type {self.data_link_type} not supported')

    def next_packet(self):
        # Read the record header
        header = self.source.read(24)
        if len(header) < 24:
            self.at_end = True
            return (None, 0, None)

        # Parse the header
        (
            original_length,
            included_length,
            packet_flags,
            _cumulative_drops,
            timestamp,
        ) = struct.unpack('>IIIIQ', header)

        # Skip truncated packets
        if original_length != included_length:
            print(
                color(
                    f"!!! truncated packet ({included_length}/{original_length})", "red"
                )
            )
            self.source.read(included_length)
            return (None, 0, None)

        # Convert the timestamp to a datetime object.
        ts_dt = self.TIMESTAMP_ANCHOR + datetime.timedelta(
            microseconds=timestamp - self.TIMESTAMP_DELTA
        )

        if self.data_link_type == self.DATALINK_H1:
            # The packet is un-encapsulated, look at the flags to figure out its type
            if packet_flags & 1:
                # Controller -> Host
                if packet_flags & 2:
                    packet_type = hci.HCI_EVENT_PACKET
                else:
                    packet_type = hci.HCI_ACL_DATA_PACKET
            else:
                # Host -> Controller
                if packet_flags & 2:
                    packet_type = hci.HCI_COMMAND_PACKET
                else:
                    packet_type = hci.HCI_ACL_DATA_PACKET

            return (
                packet_flags & 1,
                bytes([packet_type]) + self.source.read(included_length),
            )

        return (ts_dt, packet_flags & 1, self.source.read(included_length))


# -----------------------------------------------------------------------------
class Printer:
    def __init__(self):
        self.index = 0

    def print(self, message: str) -> None:
        self.index += 1
        print(f"[{self.index:8}]{message}")


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
@click.command()
@click.option(
    '--format',
    type=click.Choice(['h4', 'snoop']),
    default='h4',
    help='Format of the input file',
)
@click.option(
    '--vendors',
    type=click.Choice(['android', 'zephyr']),
    multiple=True,
    help='Support vendor-specific commands (list one or more)',
)
@click.argument('filename')
# pylint: disable=redefined-builtin
def main(format, vendors, filename):
    for vendor in vendors:
        if vendor == 'android':
            import bumble.vendor.android.hci
        elif vendor == 'zephyr':
            import bumble.vendor.zephyr.hci

    input = open(filename, 'rb')
    if format == 'h4':
        packet_reader = PacketReader(input)

        def read_next_packet():
            return (None, 0, packet_reader.next_packet())

    else:
        packet_reader = SnoopPacketReader(input)
        read_next_packet = packet_reader.next_packet

    printer = Printer()
    tracer = PacketTracer(emit_message=printer.print)

    while not packet_reader.at_end:
        try:
            (timestamp, direction, packet) = read_next_packet()
            if packet:
                tracer.trace(hci.HCI_Packet.from_bytes(packet), direction, timestamp)
            else:
                printer.print(color("[TRUNCATED]", "red"))
        except Exception as error:
            logger.exception()
            print(color(f'!!! {error}', 'red'))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())
    main()  # pylint: disable=no-value-for-parameter
