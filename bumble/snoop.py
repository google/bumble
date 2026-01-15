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
import logging
import os
import struct
from collections.abc import Generator

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from contextlib import contextmanager
from enum import IntEnum
from typing import BinaryIO

from bumble import core
from bumble.hci import HCI_COMMAND_PACKET, HCI_EVENT_PACKET

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


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

    def snoop(self, hci_packet: bytes, direction: Direction) -> None:
        """Snoop on an HCI packet."""


# -----------------------------------------------------------------------------
class BtSnooper(Snooper):
    """
    Snooper that saves HCI packets using the BTSnoop format, based on RFC 1761.
    """

    IDENTIFICATION_PATTERN = b'btsnoop\0'
    TIMESTAMP_ANCHOR = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    TIMESTAMP_DELTA = 0x00E03AB44A676000
    ONE_MS = datetime.timedelta(microseconds=1)

    def __init__(self, output: BinaryIO):
        self.output = output

        # Write the header
        self.output.write(
            self.IDENTIFICATION_PATTERN + struct.pack('>LL', 1, self.DataLinkType.H4)
        )

    def snoop(self, hci_packet: bytes, direction: Snooper.Direction) -> None:
        flags = int(direction)
        packet_type = hci_packet[0]
        if packet_type in (HCI_EVENT_PACKET, HCI_COMMAND_PACKET):
            flags |= 0x10

        # Compute the current timestamp
        timestamp = (
            int(
                (
                    datetime.datetime.now(tz=datetime.timezone.utc)
                    - self.TIMESTAMP_ANCHOR
                )
                / self.ONE_MS
            )
            + self.TIMESTAMP_DELTA
        )

        # Emit the record
        self.output.write(
            struct.pack(
                '>IIIIQ',
                len(hci_packet),  # Original Length
                len(hci_packet),  # Included Length
                flags,  # Packet Flags
                0,  # Cumulative Drops
                timestamp,  # Timestamp
            )
            + hci_packet
        )


# -----------------------------------------------------------------------------
class PcapSnooper(Snooper):
    """
    Snooper that saves or streames HCI packets using the PCAP format.
    """

    PCAP_MAGIC = 0xA1B2C3D4
    DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201

    def __init__(self, fifo):
        self.output = fifo

        # Write the header
        self.output.write(
            struct.pack(
                "<IHHIIII",
                self.PCAP_MAGIC,
                2,
                4,  # Major and Minor PCAP Version
                0,
                0,  # Reserved 1 and 2
                65535,  # SnapLen
                # FCS and f are set to 0 implicitly by the next line
                self.DLT_BLUETOOTH_HCI_H4_WITH_PHDR,  # The DLT in this PCAP
            )
        )

    def snoop(self, hci_packet: bytes, direction: Snooper.Direction):
        now = datetime.datetime.now(datetime.timezone.utc)
        sec = int(now.timestamp())
        usec = now.microsecond

        # Emit the record
        self.output.write(
            struct.pack(
                "<IIII",
                sec,  # Timestamp (Seconds)
                usec,  # Timestamp (Microseconds)
                len(hci_packet) + 4,
                len(hci_packet) + 4,  # +4 because of the addtional direction info...
            )
            + struct.pack(">I", int(direction))  # ...thats being added here
            + hci_packet
        )
        self.output.flush()  # flush after every packet for live logging


# -----------------------------------------------------------------------------
_SNOOPER_INSTANCE_COUNT = 0


@contextmanager
def create_snooper(spec: str) -> Generator[Snooper, None, None]:
    """
    Create a snooper given a specification string.

    The general syntax for the specification string is:
      <snooper-type>:<type-specific-arguments>

    Supported snooper types are:

      btsnoop
        The syntax for the type-specific arguments for this type is:
        <io-type>:<io-type-specific-arguments>

        Supported I/O types are:

        file
          The type-specific arguments for this I/O type is a string that is converted
          to a file path using the python `str.format()` string formatting. The log
          records will be written to that file if it can be opened/created.
          The keyword args that may be referenced by the string pattern are:
            now: the value of `datetime.now()`
            utcnow: the value of `datetime.now(tz=datetime.timezone.utc)`
            pid: the current process ID.
            instance: the instance ID in the current process.

      pcapsnoop
        The syntax for the type-specific arguments for this type is:
        <io-type>:<io-type-specific-arguments>

        Supported I/O types are:

        file
          The type-specific arguments for this I/O type is a string that is converted
          to a file path using the python `str.format()` string formatting. The log
          records will be written to that file if it can be opened/created.
          The keyword args that may be referenced by the string pattern are:
            now: the value of `datetime.now()`
            utcnow: the value of `datetime.now(tz=datetime.timezone.utc)`
            pid: the current process ID.
            instance: the instance ID in the current process.

        pipe
          The type-specific arguments for this I/O type is a string that is converted
          to a path using the python `str.format()` string formatting. The log
          records will be written to the named pipe referenced by this path
          if it can be opened. The keyword args that may be referenced by the
          string pattern are:
            now: the value of `datetime.now()`
            utcnow: the value of `datetime.now(tz=datetime.timezone.utc)`
            pid: the current process ID.
            instance: the instance ID in the current process.

    Examples:
      btsnoop:file:my_btsnoop.log
      btsnoop:file:/tmp/bumble_{now:%Y-%m-%d-%H:%M:%S}_{pid}.log
      pcapsnoop:pipe:/tmp/bumble-extcap


    """
    if ':' not in spec:
        raise core.InvalidArgumentError('snooper type prefix missing')

    snooper_type, snooper_args = spec.split(':', maxsplit=1)

    if snooper_type == 'btsnoop':
        if ':' not in snooper_args:
            raise core.InvalidArgumentError('I/O type for btsnoop snooper type missing')

        io_type, io_name = snooper_args.split(':', maxsplit=1)
        if io_type == 'file':
            # Process the file name string pattern.
            global _SNOOPER_INSTANCE_COUNT
            file_path = io_name.format(
                now=datetime.datetime.now(),
                utcnow=datetime.datetime.now(tz=datetime.timezone.utc),
                pid=os.getpid(),
                instance=_SNOOPER_INSTANCE_COUNT,
            )

            # Open the file
            logger.debug(f'Snoop file: {file_path}')
            with open(file_path, 'wb') as snoop_file:
                _SNOOPER_INSTANCE_COUNT += 1
                yield BtSnooper(snoop_file)
                _SNOOPER_INSTANCE_COUNT -= 1
                return

    elif snooper_type == 'pcapsnoop':
        if ':' not in snooper_args:
            raise core.InvalidArgumentError(
                'I/O type for pcapsnoop snooper type missing'
            )

        io_type, io_name = snooper_args.split(':', maxsplit=1)
        if io_type in {'pipe', 'file'}:
            # Process the file name string pattern.
            file_path = io_name.format(
                now=datetime.datetime.now(),
                utcnow=datetime.datetime.now(tz=datetime.timezone.utc),
                pid=os.getpid(),
                instance=_SNOOPER_INSTANCE_COUNT,
            )

            # Pipes we have to open with unbuffered binary I/O
            kwargs = {}
            if io_type == 'pipe':
                kwargs["buffering"] = 0

            # Open a file or pipe
            logger.debug(f'PCAP file: {file_path}')
            # Pass ``buffering`` for pipes but not for files
            with open(file_path, 'wb', **kwargs) as snoop_file:
                _SNOOPER_INSTANCE_COUNT += 1
                yield PcapSnooper(snoop_file)
                _SNOOPER_INSTANCE_COUNT -= 1
                return

        raise core.InvalidArgumentError(f'I/O type {io_type} not supported')

    raise core.InvalidArgumentError(f'snooper type {snooper_type} not found')
