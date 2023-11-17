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
from __future__ import annotations

import dataclasses
import struct
import logging
from collections.abc import AsyncGenerator
from typing import List, Callable, Awaitable

from .company_ids import COMPANY_IDENTIFIERS
from .sdp import (
    DataElement,
    ServiceAttribute,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
)
from .core import (
    BT_L2CAP_PROTOCOL_ID,
    BT_AUDIO_SOURCE_SERVICE,
    BT_AUDIO_SINK_SERVICE,
    BT_AVDTP_PROTOCOL_ID,
    BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE,
    name_or_number,
)


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off

A2DP_SBC_CODEC_TYPE            = 0x00
A2DP_MPEG_1_2_AUDIO_CODEC_TYPE = 0x01
A2DP_MPEG_2_4_AAC_CODEC_TYPE   = 0x02
A2DP_ATRAC_FAMILY_CODEC_TYPE   = 0x03
A2DP_NON_A2DP_CODEC_TYPE       = 0xFF

A2DP_CODEC_TYPE_NAMES = {
    A2DP_SBC_CODEC_TYPE:            'A2DP_SBC_CODEC_TYPE',
    A2DP_MPEG_1_2_AUDIO_CODEC_TYPE: 'A2DP_MPEG_1_2_AUDIO_CODEC_TYPE',
    A2DP_MPEG_2_4_AAC_CODEC_TYPE:   'A2DP_MPEG_2_4_AAC_CODEC_TYPE',
    A2DP_ATRAC_FAMILY_CODEC_TYPE:   'A2DP_ATRAC_FAMILY_CODEC_TYPE',
    A2DP_NON_A2DP_CODEC_TYPE:       'A2DP_NON_A2DP_CODEC_TYPE'
}


SBC_SYNC_WORD = 0x9C

SBC_SAMPLING_FREQUENCIES = [
    16000,
    22050,
    44100,
    48000
]

SBC_MONO_CHANNEL_MODE         = 0x00
SBC_DUAL_CHANNEL_MODE         = 0x01
SBC_STEREO_CHANNEL_MODE       = 0x02
SBC_JOINT_STEREO_CHANNEL_MODE = 0x03

SBC_CHANNEL_MODE_NAMES = {
    SBC_MONO_CHANNEL_MODE:         'SBC_MONO_CHANNEL_MODE',
    SBC_DUAL_CHANNEL_MODE:         'SBC_DUAL_CHANNEL_MODE',
    SBC_STEREO_CHANNEL_MODE:       'SBC_STEREO_CHANNEL_MODE',
    SBC_JOINT_STEREO_CHANNEL_MODE: 'SBC_JOINT_STEREO_CHANNEL_MODE'
}

SBC_BLOCK_LENGTHS = [4, 8, 12, 16]

SBC_SUBBANDS = [4, 8]

SBC_SNR_ALLOCATION_METHOD      = 0x00
SBC_LOUDNESS_ALLOCATION_METHOD = 0x01

SBC_ALLOCATION_METHOD_NAMES = {
    SBC_SNR_ALLOCATION_METHOD:      'SBC_SNR_ALLOCATION_METHOD',
    SBC_LOUDNESS_ALLOCATION_METHOD: 'SBC_LOUDNESS_ALLOCATION_METHOD'
}

MPEG_2_4_AAC_SAMPLING_FREQUENCIES = [
    8000,
    11025,
    12000,
    16000,
    22050,
    24000,
    32000,
    44100,
    48000,
    64000,
    88200,
    96000
]

MPEG_2_AAC_LC_OBJECT_TYPE       = 0x00
MPEG_4_AAC_LC_OBJECT_TYPE       = 0x01
MPEG_4_AAC_LTP_OBJECT_TYPE      = 0x02
MPEG_4_AAC_SCALABLE_OBJECT_TYPE = 0x03

MPEG_2_4_OBJECT_TYPE_NAMES = {
    MPEG_2_AAC_LC_OBJECT_TYPE:       'MPEG_2_AAC_LC_OBJECT_TYPE',
    MPEG_4_AAC_LC_OBJECT_TYPE:       'MPEG_4_AAC_LC_OBJECT_TYPE',
    MPEG_4_AAC_LTP_OBJECT_TYPE:      'MPEG_4_AAC_LTP_OBJECT_TYPE',
    MPEG_4_AAC_SCALABLE_OBJECT_TYPE: 'MPEG_4_AAC_SCALABLE_OBJECT_TYPE'
}

# fmt: on


# -----------------------------------------------------------------------------
def flags_to_list(flags, values):
    result = []
    for i, value in enumerate(values):
        if flags & (1 << (len(values) - i - 1)):
            result.append(value)
    return result


# -----------------------------------------------------------------------------
def make_audio_source_service_sdp_records(service_record_handle, version=(1, 3)):
    # pylint: disable=import-outside-toplevel
    from .avdtp import AVDTP_PSM

    version_int = version[0] << 8 | version[1]
    return [
        ServiceAttribute(
            SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            DataElement.unsigned_integer_32(service_record_handle),
        ),
        ServiceAttribute(
            SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
        ),
        ServiceAttribute(
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(BT_AUDIO_SOURCE_SERVICE)]),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_L2CAP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(AVDTP_PSM),
                        ]
                    ),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AVDTP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(version_int),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.uuid(BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE),
                    DataElement.unsigned_integer_16(version_int),
                ]
            ),
        ),
    ]


# -----------------------------------------------------------------------------
def make_audio_sink_service_sdp_records(service_record_handle, version=(1, 3)):
    # pylint: disable=import-outside-toplevel
    from .avdtp import AVDTP_PSM

    version_int = version[0] << 8 | version[1]
    return [
        ServiceAttribute(
            SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            DataElement.unsigned_integer_32(service_record_handle),
        ),
        ServiceAttribute(
            SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
        ),
        ServiceAttribute(
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(BT_AUDIO_SINK_SERVICE)]),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_L2CAP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(AVDTP_PSM),
                        ]
                    ),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AVDTP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(version_int),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.uuid(BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE),
                    DataElement.unsigned_integer_16(version_int),
                ]
            ),
        ),
    ]


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class SbcMediaCodecInformation:
    '''
    A2DP spec - 4.3.2 Codec Specific Information Elements
    '''

    sampling_frequency: int
    channel_mode: int
    block_length: int
    subbands: int
    allocation_method: int
    minimum_bitpool_value: int
    maximum_bitpool_value: int

    SAMPLING_FREQUENCY_BITS = {16000: 1 << 3, 32000: 1 << 2, 44100: 1 << 1, 48000: 1}
    CHANNEL_MODE_BITS = {
        SBC_MONO_CHANNEL_MODE: 1 << 3,
        SBC_DUAL_CHANNEL_MODE: 1 << 2,
        SBC_STEREO_CHANNEL_MODE: 1 << 1,
        SBC_JOINT_STEREO_CHANNEL_MODE: 1,
    }
    BLOCK_LENGTH_BITS = {4: 1 << 3, 8: 1 << 2, 12: 1 << 1, 16: 1}
    SUBBANDS_BITS = {4: 1 << 1, 8: 1}
    ALLOCATION_METHOD_BITS = {
        SBC_SNR_ALLOCATION_METHOD: 1 << 1,
        SBC_LOUDNESS_ALLOCATION_METHOD: 1,
    }

    @staticmethod
    def from_bytes(data: bytes) -> SbcMediaCodecInformation:
        sampling_frequency = (data[0] >> 4) & 0x0F
        channel_mode = (data[0] >> 0) & 0x0F
        block_length = (data[1] >> 4) & 0x0F
        subbands = (data[1] >> 2) & 0x03
        allocation_method = (data[1] >> 0) & 0x03
        minimum_bitpool_value = (data[2] >> 0) & 0xFF
        maximum_bitpool_value = (data[3] >> 0) & 0xFF
        return SbcMediaCodecInformation(
            sampling_frequency,
            channel_mode,
            block_length,
            subbands,
            allocation_method,
            minimum_bitpool_value,
            maximum_bitpool_value,
        )

    @classmethod
    def from_discrete_values(
        cls,
        sampling_frequency: int,
        channel_mode: int,
        block_length: int,
        subbands: int,
        allocation_method: int,
        minimum_bitpool_value: int,
        maximum_bitpool_value: int,
    ) -> SbcMediaCodecInformation:
        return SbcMediaCodecInformation(
            sampling_frequency=cls.SAMPLING_FREQUENCY_BITS[sampling_frequency],
            channel_mode=cls.CHANNEL_MODE_BITS[channel_mode],
            block_length=cls.BLOCK_LENGTH_BITS[block_length],
            subbands=cls.SUBBANDS_BITS[subbands],
            allocation_method=cls.ALLOCATION_METHOD_BITS[allocation_method],
            minimum_bitpool_value=minimum_bitpool_value,
            maximum_bitpool_value=maximum_bitpool_value,
        )

    @classmethod
    def from_lists(
        cls,
        sampling_frequencies: List[int],
        channel_modes: List[int],
        block_lengths: List[int],
        subbands: List[int],
        allocation_methods: List[int],
        minimum_bitpool_value: int,
        maximum_bitpool_value: int,
    ) -> SbcMediaCodecInformation:
        return SbcMediaCodecInformation(
            sampling_frequency=sum(
                cls.SAMPLING_FREQUENCY_BITS[x] for x in sampling_frequencies
            ),
            channel_mode=sum(cls.CHANNEL_MODE_BITS[x] for x in channel_modes),
            block_length=sum(cls.BLOCK_LENGTH_BITS[x] for x in block_lengths),
            subbands=sum(cls.SUBBANDS_BITS[x] for x in subbands),
            allocation_method=sum(
                cls.ALLOCATION_METHOD_BITS[x] for x in allocation_methods
            ),
            minimum_bitpool_value=minimum_bitpool_value,
            maximum_bitpool_value=maximum_bitpool_value,
        )

    def __bytes__(self) -> bytes:
        return bytes(
            [
                (self.sampling_frequency << 4) | self.channel_mode,
                (self.block_length << 4)
                | (self.subbands << 2)
                | self.allocation_method,
                self.minimum_bitpool_value,
                self.maximum_bitpool_value,
            ]
        )

    def __str__(self) -> str:
        channel_modes = ['MONO', 'DUAL_CHANNEL', 'STEREO', 'JOINT_STEREO']
        allocation_methods = ['SNR', 'Loudness']
        return '\n'.join(
            # pylint: disable=line-too-long
            [
                'SbcMediaCodecInformation(',
                f'  sampling_frequency:    {",".join([str(x) for x in flags_to_list(self.sampling_frequency, SBC_SAMPLING_FREQUENCIES)])}',
                f'  channel_mode:          {",".join([str(x) for x in flags_to_list(self.channel_mode, channel_modes)])}',
                f'  block_length:          {",".join([str(x) for x in flags_to_list(self.block_length, SBC_BLOCK_LENGTHS)])}',
                f'  subbands:              {",".join([str(x) for x in flags_to_list(self.subbands, SBC_SUBBANDS)])}',
                f'  allocation_method:     {",".join([str(x) for x in flags_to_list(self.allocation_method, allocation_methods)])}',
                f'  minimum_bitpool_value: {self.minimum_bitpool_value}',
                f'  maximum_bitpool_value: {self.maximum_bitpool_value}' ')',
            ]
        )


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class AacMediaCodecInformation:
    '''
    A2DP spec - 4.5.2 Codec Specific Information Elements
    '''

    object_type: int
    sampling_frequency: int
    channels: int
    rfa: int
    vbr: int
    bitrate: int

    OBJECT_TYPE_BITS = {
        MPEG_2_AAC_LC_OBJECT_TYPE: 1 << 7,
        MPEG_4_AAC_LC_OBJECT_TYPE: 1 << 6,
        MPEG_4_AAC_LTP_OBJECT_TYPE: 1 << 5,
        MPEG_4_AAC_SCALABLE_OBJECT_TYPE: 1 << 4,
    }
    SAMPLING_FREQUENCY_BITS = {
        8000: 1 << 11,
        11025: 1 << 10,
        12000: 1 << 9,
        16000: 1 << 8,
        22050: 1 << 7,
        24000: 1 << 6,
        32000: 1 << 5,
        44100: 1 << 4,
        48000: 1 << 3,
        64000: 1 << 2,
        88200: 1 << 1,
        96000: 1,
    }
    CHANNELS_BITS = {1: 1 << 1, 2: 1}

    @staticmethod
    def from_bytes(data: bytes) -> AacMediaCodecInformation:
        object_type = data[0]
        sampling_frequency = (data[1] << 4) | ((data[2] >> 4) & 0x0F)
        channels = (data[2] >> 2) & 0x03
        rfa = 0
        vbr = (data[3] >> 7) & 0x01
        bitrate = ((data[3] & 0x7F) << 16) | (data[4] << 8) | data[5]
        return AacMediaCodecInformation(
            object_type, sampling_frequency, channels, rfa, vbr, bitrate
        )

    @classmethod
    def from_discrete_values(
        cls,
        object_type: int,
        sampling_frequency: int,
        channels: int,
        vbr: int,
        bitrate: int,
    ) -> AacMediaCodecInformation:
        return AacMediaCodecInformation(
            object_type=cls.OBJECT_TYPE_BITS[object_type],
            sampling_frequency=cls.SAMPLING_FREQUENCY_BITS[sampling_frequency],
            channels=cls.CHANNELS_BITS[channels],
            rfa=0,
            vbr=vbr,
            bitrate=bitrate,
        )

    @classmethod
    def from_lists(
        cls,
        object_types: List[int],
        sampling_frequencies: List[int],
        channels: List[int],
        vbr: int,
        bitrate: int,
    ) -> AacMediaCodecInformation:
        return AacMediaCodecInformation(
            object_type=sum(cls.OBJECT_TYPE_BITS[x] for x in object_types),
            sampling_frequency=sum(
                cls.SAMPLING_FREQUENCY_BITS[x] for x in sampling_frequencies
            ),
            channels=sum(cls.CHANNELS_BITS[x] for x in channels),
            rfa=0,
            vbr=vbr,
            bitrate=bitrate,
        )

    def __bytes__(self) -> bytes:
        return bytes(
            [
                self.object_type & 0xFF,
                (self.sampling_frequency >> 4) & 0xFF,
                (((self.sampling_frequency & 0x0F) << 4) | (self.channels << 2)) & 0xFF,
                ((self.vbr << 7) | ((self.bitrate >> 16) & 0x7F)) & 0xFF,
                ((self.bitrate >> 8) & 0xFF) & 0xFF,
                self.bitrate & 0xFF,
            ]
        )

    def __str__(self) -> str:
        object_types = [
            'MPEG_2_AAC_LC',
            'MPEG_4_AAC_LC',
            'MPEG_4_AAC_LTP',
            'MPEG_4_AAC_SCALABLE',
            '[4]',
            '[5]',
            '[6]',
            '[7]',
        ]
        channels = [1, 2]
        # pylint: disable=line-too-long
        return '\n'.join(
            [
                'AacMediaCodecInformation(',
                f'  object_type:        {",".join([str(x) for x in flags_to_list(self.object_type, object_types)])}',
                f'  sampling_frequency: {",".join([str(x) for x in flags_to_list(self.sampling_frequency, MPEG_2_4_AAC_SAMPLING_FREQUENCIES)])}',
                f'  channels:           {",".join([str(x) for x in flags_to_list(self.channels, channels)])}',
                f'  vbr:                {self.vbr}',
                f'  bitrate:            {self.bitrate}' ')',
            ]
        )


@dataclasses.dataclass
# -----------------------------------------------------------------------------
class VendorSpecificMediaCodecInformation:
    '''
    A2DP spec - 4.7.2 Codec Specific Information Elements
    '''

    vendor_id: int
    codec_id: int
    value: bytes

    @staticmethod
    def from_bytes(data: bytes) -> VendorSpecificMediaCodecInformation:
        (vendor_id, codec_id) = struct.unpack_from('<IH', data, 0)
        return VendorSpecificMediaCodecInformation(vendor_id, codec_id, data[6:])

    def __bytes__(self) -> bytes:
        return struct.pack('<IH', self.vendor_id, self.codec_id, self.value)

    def __str__(self) -> str:
        # pylint: disable=line-too-long
        return '\n'.join(
            [
                'VendorSpecificMediaCodecInformation(',
                f'  vendor_id: {self.vendor_id:08X} ({name_or_number(COMPANY_IDENTIFIERS, self.vendor_id & 0xFFFF)})',
                f'  codec_id:  {self.codec_id:04X}',
                f'  value:     {self.value.hex()}' ')',
            ]
        )


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class SbcFrame:
    sampling_frequency: int
    block_count: int
    channel_mode: int
    subband_count: int
    payload: bytes

    @property
    def sample_count(self) -> int:
        return self.subband_count * self.block_count

    @property
    def bitrate(self) -> int:
        return 8 * ((len(self.payload) * self.sampling_frequency) // self.sample_count)

    @property
    def duration(self) -> float:
        return self.sample_count / self.sampling_frequency

    def __str__(self) -> str:
        return (
            f'SBC(sf={self.sampling_frequency},'
            f'cm={self.channel_mode},'
            f'br={self.bitrate},'
            f'sc={self.sample_count},'
            f'size={len(self.payload)})'
        )


# -----------------------------------------------------------------------------
class SbcParser:
    def __init__(self, read: Callable[[int], Awaitable[bytes]]) -> None:
        self.read = read

    @property
    def frames(self) -> AsyncGenerator[SbcFrame, None]:
        async def generate_frames() -> AsyncGenerator[SbcFrame, None]:
            while True:
                # Read 4 bytes of header
                header = await self.read(4)
                if len(header) != 4:
                    return

                # Check the sync word
                if header[0] != SBC_SYNC_WORD:
                    logger.debug('invalid sync word')
                    return

                # Extract some of the header fields
                sampling_frequency = SBC_SAMPLING_FREQUENCIES[(header[1] >> 6) & 3]
                blocks = 4 * (1 + ((header[1] >> 4) & 3))
                channel_mode = (header[1] >> 2) & 3
                channels = 1 if channel_mode == SBC_MONO_CHANNEL_MODE else 2
                subbands = 8 if ((header[1]) & 1) else 4
                bitpool = header[2]

                # Compute the frame length
                frame_length = 4 + (4 * subbands * channels) // 8
                if channel_mode in (SBC_MONO_CHANNEL_MODE, SBC_DUAL_CHANNEL_MODE):
                    frame_length += (blocks * channels * bitpool) // 8
                else:
                    frame_length += (
                        (1 if channel_mode == SBC_JOINT_STEREO_CHANNEL_MODE else 0)
                        * subbands
                        + blocks * bitpool
                    ) // 8

                # Read the rest of the frame
                payload = header + await self.read(frame_length - 4)

                # Emit the next frame
                yield SbcFrame(
                    sampling_frequency, blocks, channel_mode, subbands, payload
                )

        return generate_frames()


# -----------------------------------------------------------------------------
class SbcPacketSource:
    def __init__(
        self, read: Callable[[int], Awaitable[bytes]], mtu: int, codec_capabilities
    ) -> None:
        self.read = read
        self.mtu = mtu
        self.codec_capabilities = codec_capabilities

    @property
    def packets(self):
        async def generate_packets():
            # pylint: disable=import-outside-toplevel
            from .avdtp import MediaPacket  # Import here to avoid a circular reference

            sequence_number = 0
            timestamp = 0
            frames = []
            frames_size = 0
            max_rtp_payload = self.mtu - 12 - 1

            # NOTE: this doesn't support frame fragments
            sbc_parser = SbcParser(self.read)
            async for frame in sbc_parser.frames:
                print(frame)

                if (
                    frames_size + len(frame.payload) > max_rtp_payload
                    or len(frames) == 16
                ):
                    # Need to flush what has been accumulated so far

                    # Emit a packet
                    sbc_payload = bytes([len(frames)]) + b''.join(
                        [frame.payload for frame in frames]
                    )
                    packet = MediaPacket(
                        2, 0, 0, 0, sequence_number, timestamp, 0, [], 96, sbc_payload
                    )
                    packet.timestamp_seconds = timestamp / frame.sampling_frequency
                    yield packet

                    # Prepare for next packets
                    sequence_number += 1
                    timestamp += sum((frame.sample_count for frame in frames))
                    frames = [frame]
                    frames_size = len(frame.payload)
                else:
                    # Accumulate
                    frames.append(frame)
                    frames_size += len(frame.payload)

        return generate_packets()
