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
import random
import os
from bumble.transport.common import PacketParser


# -----------------------------------------------------------------------------
class Sink:
    def __init__(self):
        self.packets = []

    def on_packet(self, packet):
        self.packets.append(packet)


# -----------------------------------------------------------------------------
def test_parser():
    sink1 = Sink()
    parser1 = PacketParser(sink1)
    sink2 = Sink()
    parser2 = PacketParser(sink2)

    for parser in [parser1, parser2]:
        with open(
            os.path.join(os.path.dirname(__file__), 'hci_data_001.bin'), 'rb'
        ) as input:
            while True:
                n = random.randint(1, 9)
                data = input.read(n)
                if not data:
                    break
                parser.feed_data(data)

    assert sink1.packets == sink2.packets


# -----------------------------------------------------------------------------
def test_parser_extensions():
    sink = Sink()
    parser = PacketParser(sink)

    # Check that an exception is thrown for an unknown type
    try:
        parser.feed_data(bytes([0x77, 0x00, 0x02, 0x01, 0x02]))
        exception_thrown = False
    except ValueError:
        exception_thrown = True

    assert exception_thrown

    # Now add a custom info
    parser.extended_packet_info[0x77] = (1, 1, 'B')
    parser.reset()
    parser.feed_data(bytes([0x77, 0x00, 0x02, 0x01, 0x02]))
    assert len(sink.packets) == 1


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_parser()
    test_parser_extensions()
