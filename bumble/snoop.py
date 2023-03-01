# Copyright 2021-2023 Google LLC
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

import datetime
import struct

from hci import HCI_Packet, HCI_EVENT_PACKET, HCI_COMMAND_PACKET

SNOOP_TIMEDELTA_SINCE_2000AD_MICROSEC = 0x00E03AB44A676000


class Snoop:
    def __init__(self, path: str) -> None:
        self.logger = open(path, 'wb')
        self.logger.write(
            struct.pack(
                '>8sLL',
                b'btsnoop\0',  # Identification pattern
                1,  # Version number: 1
                1002,  # Datalink type: 1002(H4)
            )
        )

    def write(self, packet: HCI_Packet, outgoing: bool) -> None:
        if self.logger is None:
            return
        packet_bytes: bytes = packet.to_bytes()
        packet_flags = 0x00 if outgoing else 0x01
        if packet.hci_packet_type in (HCI_EVENT_PACKET, HCI_COMMAND_PACKET):
            packet_flags = packet_flags | 0x10
        # Timestamp: microseconds since 0000/01/01
        timestamp = (
            int(
                (datetime.datetime.utcnow() - datetime.datetime(2000, 1, 1))
                / datetime.timedelta(microseconds=1)
            )
            + SNOOP_TIMEDELTA_SINCE_2000AD_MICROSEC
        )
        packet_header = struct.pack(
            '>LLLLQ',
            len(packet_bytes),  # Original length
            len(packet_bytes),  # Included length
            packet_flags,  # Flags
            0,  # Cumulative drops
            timestamp,  # Timestamp
        )
        self.logger.write(packet_header)
        # Packet data
        self.logger.write(packet_bytes)

    def close(self) -> None:
        self.logger.close()
