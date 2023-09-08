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
import struct
import click

from bumble.colors import color
from bumble import hci
from bumble.transport.common import PacketReader
from bumble.helpers import PacketTracer


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

    def __init__(self, source):
        self.source = source

        # Read the header
        identification_pattern = source.read(8)
        if identification_pattern.hex().lower() != '6274736e6f6f7000':
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
            return (0, None)
        (
            original_length,
            included_length,
            packet_flags,
            _cumulative_drops,
            _timestamp_seconds,
            _timestamp_microsecond,
        ) = struct.unpack('>IIIIII', header)

        # Abort on truncated packets
        if original_length != included_length:
            return (0, None)

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

        return (packet_flags & 1, self.source.read(included_length))


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
            return (0, packet_reader.next_packet())

    else:
        packet_reader = SnoopPacketReader(input)
        read_next_packet = packet_reader.next_packet

    tracer = PacketTracer(emit_message=print)

    while True:
        try:
            (direction, packet) = read_next_packet()
            if packet is None:
                break
            tracer.trace(hci.HCI_Packet.from_bytes(packet), direction)
        except Exception as error:
            print(color(f'!!! {error}', 'red'))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()  # pylint: disable=no-value-for-parameter
