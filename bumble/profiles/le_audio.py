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
from __future__ import annotations
import dataclasses
import struct
from typing import List, Type
from typing_extensions import Self

from bumble import utils


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class Metadata:
    '''Bluetooth Assigned Numbers, Section 6.12.6 - Metadata LTV structures.

    As Metadata fields may extend, and Spec doesn't forbid duplication, we don't parse
    Metadata into a key-value style dataclass here. Rather, we encourage users to parse
    again outside the lib.
    '''

    class Tag(utils.OpenIntEnum):
        # fmt: off
        PREFERRED_AUDIO_CONTEXTS                 = 0x01
        STREAMING_AUDIO_CONTEXTS                 = 0x02
        PROGRAM_INFO                             = 0x03
        LANGUAGE                                 = 0x04
        CCID_LIST                                = 0x05
        PARENTAL_RATING                          = 0x06
        PROGRAM_INFO_URI                         = 0x07
        AUDIO_ACTIVE_STATE                       = 0x08
        BROADCAST_AUDIO_IMMEDIATE_RENDERING_FLAG = 0x09
        ASSISTED_LISTENING_STREAM                = 0x0A
        BROADCAST_NAME                           = 0x0B
        EXTENDED_METADATA                        = 0xFE
        VENDOR_SPECIFIC                          = 0xFF

    @dataclasses.dataclass
    class Entry:
        tag: Metadata.Tag
        data: bytes

        @classmethod
        def from_bytes(cls: Type[Self], data: bytes) -> Self:
            return cls(tag=Metadata.Tag(data[0]), data=data[1:])

        def __bytes__(self) -> bytes:
            return bytes([len(self.data) + 1, self.tag]) + self.data

    entries: List[Entry] = dataclasses.field(default_factory=list)

    @classmethod
    def from_bytes(cls: Type[Self], data: bytes) -> Self:
        entries = []
        offset = 0
        length = len(data)
        while offset < length:
            entry_length = data[offset]
            offset += 1
            entries.append(cls.Entry.from_bytes(data[offset : offset + entry_length]))
            offset += entry_length

        return cls(entries)

    def __bytes__(self) -> bytes:
        return b''.join([bytes(entry) for entry in self.entries])
