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
from typing_extensions import Self

from bumble.profiles import le_audio


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class PublicBroadcastAnnouncement:
    class Features(enum.IntFlag):
        ENCRYPTED = 1 << 0
        STANDARD_QUALITY_CONFIGURATION = 1 << 1
        HIGH_QUALITY_CONFIGURATION = 1 << 2

    features: Features
    metadata: le_audio.Metadata

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        features = cls.Features(data[0])
        metadata_length = data[1]
        metadata_ltv = data[2 : 2 + metadata_length]
        return cls(
            features=features, metadata=le_audio.Metadata.from_bytes(metadata_ltv)
        )
