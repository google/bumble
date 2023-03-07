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

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from enum import IntEnum
import struct
import datetime
from typing import BinaryIO

from bumble.hci import HCI_Packet, HCI_COMMAND_PACKET, HCI_EVENT_PACKET


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class Snooper:
    """
    Base class for snooper implementations.

    A snooper is an object that will be provided with HCI packets as they are
    exchanged between a host and a controller.
    """

    class Direction(IntEnum):
        HOST_TO_CONTROLLER = 0
        CONTROLLER_TO_HOST = 1

    class DataLinkType(IntEnum):
        H1 = 1001
        H4 = 1002
        HCI_BSCP = 1003
        H5 = 1004

    def snoop(self, hci_packet: HCI_Packet, direction: Direction) -> None:
        """Snoop on an HCI packet."""


# -----------------------------------------------------------------------------
class BtSnooper(Snooper):
    """
    Snooper that saves HCI packets using the BTSnoop format, based on RFC 1761.
    """

    IDENTIFICATION_PATTERN = b'btsnoop\0'
    TIMESTAMP_ANCHOR = datetime.datetime(2000, 1, 1)
    TIMESTAMP_DELTA = 0x00E03AB44A676000
    ONE_MS = datetime.timedelta(microseconds=1)

    def __init__(self, output: BinaryIO):
        self.output = output

        # Write the header
        self.output.write(
            self.IDENTIFICATION_PATTERN + struct.pack('>LL', 1, self.DataLinkType.H4)
        )

    def snoop(self, hci_packet: HCI_Packet, direction: Snooper.Direction) -> None:
        flags = int(direction)
        if hci_packet.hci_packet_type in (HCI_EVENT_PACKET, HCI_COMMAND_PACKET):
            flags |= 0x10

        # Compute the current timestamp
        timestamp = (
            int((datetime.datetime.utcnow() - self.TIMESTAMP_ANCHOR) / self.ONE_MS)
            + self.TIMESTAMP_DELTA
        )

        # Emit the record
        packet_data = bytes(hci_packet)
        self.output.write(
            struct.pack(
                '>IIIIQ',
                len(packet_data),  # Original Length
                len(packet_data),  # Included Length
                flags,  # Packet Flags
                0,  # Cumulative Drops
                timestamp,  # Timestamp
            )
            + packet_data
        )
