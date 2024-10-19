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
import struct
from typing import List


# -----------------------------------------------------------------------------
class MediaPacket:
    @staticmethod
    def from_bytes(data: bytes) -> MediaPacket:
        version = (data[0] >> 6) & 0x03
        padding = (data[0] >> 5) & 0x01
        extension = (data[0] >> 4) & 0x01
        csrc_count = data[0] & 0x0F
        marker = (data[1] >> 7) & 0x01
        payload_type = data[1] & 0x7F
        sequence_number = struct.unpack_from('>H', data, 2)[0]
        timestamp = struct.unpack_from('>I', data, 4)[0]
        ssrc = struct.unpack_from('>I', data, 8)[0]
        csrc_list = [
            struct.unpack_from('>I', data, 12 + i)[0] for i in range(csrc_count)
        ]
        payload = data[12 + csrc_count * 4 :]

        return MediaPacket(
            version,
            padding,
            extension,
            marker,
            sequence_number,
            timestamp,
            ssrc,
            csrc_list,
            payload_type,
            payload,
        )

    def __init__(
        self,
        version: int,
        padding: int,
        extension: int,
        marker: int,
        sequence_number: int,
        timestamp: int,
        ssrc: int,
        csrc_list: List[int],
        payload_type: int,
        payload: bytes,
    ) -> None:
        self.version = version
        self.padding = padding
        self.extension = extension
        self.marker = marker
        self.sequence_number = sequence_number & 0xFFFF
        self.timestamp = timestamp & 0xFFFFFFFF
        self.timestamp_seconds = 0.0
        self.ssrc = ssrc
        self.csrc_list = csrc_list
        self.payload_type = payload_type
        self.payload = payload

    def __bytes__(self) -> bytes:
        header = bytes(
            [
                self.version << 6
                | self.padding << 5
                | self.extension << 4
                | len(self.csrc_list),
                self.marker << 7 | self.payload_type,
            ]
        ) + struct.pack(
            '>HII',
            self.sequence_number,
            self.timestamp,
            self.ssrc,
        )
        for csrc in self.csrc_list:
            header += struct.pack('>I', csrc)
        return header + self.payload

    def __str__(self) -> str:
        return (
            f'RTP(v={self.version},'
            f'p={self.padding},'
            f'x={self.extension},'
            f'm={self.marker},'
            f'pt={self.payload_type},'
            f'sn={self.sequence_number},'
            f'ts={self.timestamp},'
            f'ssrc={self.ssrc},'
            f'csrcs={self.csrc_list},'
            f'payload_size={len(self.payload)})'
        )
