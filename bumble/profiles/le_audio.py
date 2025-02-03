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
import enum
import struct
from typing import Any, List, Type
from typing_extensions import Self

from bumble.profiles import bap
from bumble import utils


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class AudioActiveState(utils.OpenIntEnum):
    NO_AUDIO_DATA_TRANSMITTED = 0x00
    AUDIO_DATA_TRANSMITTED = 0x01


class AssistedListeningStream(utils.OpenIntEnum):
    UNSPECIFIED_AUDIO_ENHANCEMENT = 0x00


@dataclasses.dataclass
class Metadata:
    '''Bluetooth Assigned Numbers, Section 6.12.6 - Metadata LTV structures.

    As Metadata fields may extend, and the spec may not guarantee the uniqueness of
    tags, we don't automatically parse the Metadata data into specific classes.
    Users of this class may decode the data by themselves, or use the Entry.decode
    method.
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

        def decode(self) -> Any:
            """
            Decode the data into an object, if possible.

            If no specific object class exists to represent the data, the raw data
            bytes are returned.
            """

            if self.tag in (
                Metadata.Tag.PREFERRED_AUDIO_CONTEXTS,
                Metadata.Tag.STREAMING_AUDIO_CONTEXTS,
            ):
                return bap.ContextType(struct.unpack("<H", self.data)[0])

            if self.tag in (
                Metadata.Tag.PROGRAM_INFO,
                Metadata.Tag.PROGRAM_INFO_URI,
                Metadata.Tag.BROADCAST_NAME,
            ):
                return self.data.decode("utf-8")

            if self.tag == Metadata.Tag.LANGUAGE:
                return self.data.decode("ascii")

            if self.tag == Metadata.Tag.CCID_LIST:
                return list(self.data)

            if self.tag == Metadata.Tag.PARENTAL_RATING:
                return self.data[0]

            if self.tag == Metadata.Tag.AUDIO_ACTIVE_STATE:
                return AudioActiveState(self.data[0])

            if self.tag == Metadata.Tag.ASSISTED_LISTENING_STREAM:
                return AssistedListeningStream(self.data[0])

            return self.data

        @classmethod
        def from_bytes(cls: Type[Self], data: bytes) -> Self:
            return cls(tag=Metadata.Tag(data[0]), data=data[1:])

        def __bytes__(self) -> bytes:
            return bytes([len(self.data) + 1, self.tag]) + self.data

    entries: List[Entry] = dataclasses.field(default_factory=list)

    def pretty_print(self, indent: str) -> str:
        """Convenience method to generate a string with one key-value pair per line."""

        max_key_length = 0
        keys = []
        values = []
        for entry in self.entries:
            key = entry.tag.name
            max_key_length = max(max_key_length, len(key))
            keys.append(key)
            decoded = entry.decode()
            if isinstance(decoded, enum.Enum):
                values.append(decoded.name)
            elif isinstance(decoded, bytes):
                values.append(decoded.hex())
            else:
                values.append(str(decoded))

        return '\n'.join(
            f'{indent}{key}: {" " * (max_key_length-len(key))}{value}'
            for key, value in zip(keys, values)
        )

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

    def __str__(self) -> str:
        entries_str = []
        for entry in self.entries:
            decoded = entry.decode()
            entries_str.append(
                f'{entry.tag.name}: '
                f'{decoded.hex() if isinstance(decoded, bytes) else decoded!r}'
            )
        return f'Metadata(entries={", ".join(entry_str for entry_str in entries_str)})'
