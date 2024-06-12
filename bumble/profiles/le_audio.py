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
from typing import List
from typing_extensions import Self


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class Metadata:
    @dataclasses.dataclass
    class Entry:
        tag: int
        data: bytes

    entries: List[Entry]

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        entries = []
        offset = 0
        length = len(data)
        while length >= 2:
            entry_length = data[offset]
            entry_tag = data[offset + 1]
            entry_data = data[offset + 2 : offset + 2 + entry_length - 1]
            entries.append(cls.Entry(entry_tag, entry_data))
            length -= entry_length
            offset += entry_length

        return cls(entries)
