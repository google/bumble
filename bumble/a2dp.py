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

from collections.abc import AsyncGenerator
import dataclasses
import enum
import logging
import struct
from typing import Awaitable, Callable
from typing_extensions import ClassVar, Self


from bumble.codecs import AacAudioRtpPacket
from bumble.company_ids import COMPANY_IDENTIFIERS
from bumble.sdp import (
    DataElement,
    ServiceAttribute,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
)
from bumble.core import (
    BT_L2CAP_PROTOCOL_ID,
    BT_AUDIO_SOURCE_SERVICE,
    BT_AUDIO_SINK_SERVICE,
    BT_AVDTP_PROTOCOL_ID,
    BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE,
    name_or_number,
)
from bumble.rtp import MediaPacket


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

SBC_MAX_FRAMES_IN_RTP_PAYLOAD = 15

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


OPUS_MAX_FRAMES_IN_RTP_PAYLOAD = 15

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
    from bumble.avdtp import AVDTP_PSM

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
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE),
                            DataElement.unsigned_integer_16(version_int),
                        ]
                    )
                ]
            ),
        ),
    ]


# -----------------------------------------------------------------------------
def make_audio_sink_service_sdp_records(service_record_handle, version=(1, 3)):
    # pylint: disable=import-outside-toplevel
    from bumble.avdtp import AVDTP_PSM

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
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE),
                            DataElement.unsigned_integer_16(version_int),
                        ]
                    )
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

    sampling_frequency: SamplingFrequency
    channel_mode: ChannelMode
    block_length: BlockLength
    subbands: Subbands
    allocation_method: AllocationMethod
    minimum_bitpool_value: int
    maximum_bitpool_value: int

    class SamplingFrequency(enum.IntFlag):
        SF_16000 = 1 << 3
        SF_32000 = 1 << 2
        SF_44100 = 1 << 1
        SF_48000 = 1 << 0

        @classmethod
        def from_int(cls, sampling_frequency: int) -> Self:
            sampling_frequencies = [
                16000,
                32000,
                44100,
                48000,
            ]
            index = sampling_frequencies.index(sampling_frequency)
            return cls(1 << (len(sampling_frequencies) - index - 1))

    class ChannelMode(enum.IntFlag):
        MONO = 1 << 3
        DUAL_CHANNEL = 1 << 2
        STEREO = 1 << 1
        JOINT_STEREO = 1 << 0

    class BlockLength(enum.IntFlag):
        BL_4 = 1 << 3
        BL_8 = 1 << 2
        BL_12 = 1 << 1
        BL_16 = 1 << 0

    class Subbands(enum.IntFlag):
        S_4 = 1 << 1
        S_8 = 1 << 0

    class AllocationMethod(enum.IntFlag):
        SNR = 1 << 1
        LOUDNESS = 1 << 0

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        sampling_frequency = cls.SamplingFrequency((data[0] >> 4) & 0x0F)
        channel_mode = cls.ChannelMode((data[0] >> 0) & 0x0F)
        block_length = cls.BlockLength((data[1] >> 4) & 0x0F)
        subbands = cls.Subbands((data[1] >> 2) & 0x03)
        allocation_method = cls.AllocationMethod((data[1] >> 0) & 0x03)
        minimum_bitpool_value = (data[2] >> 0) & 0xFF
        maximum_bitpool_value = (data[3] >> 0) & 0xFF
        return cls(
            sampling_frequency,
            channel_mode,
            block_length,
            subbands,
            allocation_method,
            minimum_bitpool_value,
            maximum_bitpool_value,
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


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class AacMediaCodecInformation:
    '''
    A2DP spec - 4.5.2 Codec Specific Information Elements
    '''

    object_type: ObjectType
    sampling_frequency: SamplingFrequency
    channels: Channels
    vbr: int
    bitrate: int

    class ObjectType(enum.IntFlag):
        MPEG_2_AAC_LC = 1 << 7
        MPEG_4_AAC_LC = 1 << 6
        MPEG_4_AAC_LTP = 1 << 5
        MPEG_4_AAC_SCALABLE = 1 << 4

    class SamplingFrequency(enum.IntFlag):
        SF_8000 = 1 << 11
        SF_11025 = 1 << 10
        SF_12000 = 1 << 9
        SF_16000 = 1 << 8
        SF_22050 = 1 << 7
        SF_24000 = 1 << 6
        SF_32000 = 1 << 5
        SF_44100 = 1 << 4
        SF_48000 = 1 << 3
        SF_64000 = 1 << 2
        SF_88200 = 1 << 1
        SF_96000 = 1 << 0

        @classmethod
        def from_int(cls, sampling_frequency: int) -> Self:
            sampling_frequencies = [
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
                96000,
            ]
            index = sampling_frequencies.index(sampling_frequency)
            return cls(1 << (len(sampling_frequencies) - index - 1))

    class Channels(enum.IntFlag):
        MONO = 1 << 1
        STEREO = 1 << 0

    @classmethod
    def from_bytes(cls, data: bytes) -> AacMediaCodecInformation:
        object_type = cls.ObjectType(data[0])
        sampling_frequency = cls.SamplingFrequency(
            (data[1] << 4) | ((data[2] >> 4) & 0x0F)
        )
        channels = cls.Channels((data[2] >> 2) & 0x03)
        vbr = (data[3] >> 7) & 0x01
        bitrate = ((data[3] & 0x7F) << 16) | (data[4] << 8) | data[5]
        return AacMediaCodecInformation(
            object_type, sampling_frequency, channels, vbr, bitrate
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
        return struct.pack('<IH', self.vendor_id, self.codec_id) + self.value

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
class OpusMediaCodecInformation(VendorSpecificMediaCodecInformation):
    vendor_id: int = dataclasses.field(init=False, repr=False)
    codec_id: int = dataclasses.field(init=False, repr=False)
    value: bytes = dataclasses.field(init=False, repr=False)
    channel_mode: ChannelMode
    frame_size: FrameSize
    sampling_frequency: SamplingFrequency

    class ChannelMode(enum.IntFlag):
        MONO = 1 << 0
        STEREO = 1 << 1
        DUAL_MONO = 1 << 2

    class FrameSize(enum.IntFlag):
        FS_10MS = 1 << 0
        FS_20MS = 1 << 1

    class SamplingFrequency(enum.IntFlag):
        SF_48000 = 1 << 0

    VENDOR_ID: ClassVar[int] = 0x000000E0
    CODEC_ID: ClassVar[int] = 0x0001

    def __post_init__(self) -> None:
        self.vendor_id = self.VENDOR_ID
        self.codec_id = self.CODEC_ID
        self.value = bytes(
            [
                self.channel_mode
                | (self.frame_size << 3)
                | (self.sampling_frequency << 7)
            ]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Create a new instance from the `value` part of the data, not including
        the vendor id and codec id"""
        channel_mode = cls.ChannelMode(data[0] & 0x07)
        frame_size = cls.FrameSize((data[0] >> 3) & 0x03)
        sampling_frequency = cls.SamplingFrequency((data[0] >> 7) & 0x01)

        return cls(
            channel_mode,
            frame_size,
            sampling_frequency,
        )

    def __str__(self) -> str:
        return repr(self)


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class SbcFrame:
    sampling_frequency: int
    block_count: int
    channel_mode: int
    allocation_method: int
    subband_count: int
    bitpool: int
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
            f'am={self.allocation_method},'
            f'br={self.bitrate},'
            f'sc={self.sample_count},'
            f'bp={self.bitpool},'
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
                allocation_method = (header[1] >> 1) & 1
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
                    sampling_frequency,
                    blocks,
                    channel_mode,
                    allocation_method,
                    subbands,
                    bitpool,
                    payload,
                )

        return generate_frames()


# -----------------------------------------------------------------------------
class SbcPacketSource:
    def __init__(self, read: Callable[[int], Awaitable[bytes]], mtu: int) -> None:
        self.read = read
        self.mtu = mtu

    @property
    def packets(self):
        async def generate_packets():
            sequence_number = 0
            sample_count = 0
            frames = []
            frames_size = 0
            max_rtp_payload = self.mtu - 12 - 1

            # NOTE: this doesn't support frame fragments
            sbc_parser = SbcParser(self.read)
            async for frame in sbc_parser.frames:
                if (
                    frames_size + len(frame.payload) > max_rtp_payload
                    or len(frames) == SBC_MAX_FRAMES_IN_RTP_PAYLOAD
                ):
                    # Need to flush what has been accumulated so far
                    logger.debug(f"yielding {len(frames)} frames")

                    # Emit a packet
                    sbc_payload = bytes([len(frames) & 0x0F]) + b''.join(
                        [frame.payload for frame in frames]
                    )
                    timestamp_seconds = sample_count / frame.sampling_frequency
                    timestamp = int(1000 * timestamp_seconds)
                    packet = MediaPacket(
                        2, 0, 0, 0, sequence_number, timestamp, 0, [], 96, sbc_payload
                    )
                    packet.timestamp_seconds = timestamp_seconds
                    yield packet

                    # Prepare for next packets
                    sequence_number += 1
                    sequence_number &= 0xFFFF
                    sample_count += sum((frame.sample_count for frame in frames))
                    frames = [frame]
                    frames_size = len(frame.payload)
                else:
                    # Accumulate
                    frames.append(frame)
                    frames_size += len(frame.payload)

        return generate_packets()


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class AacFrame:
    class Profile(enum.IntEnum):
        MAIN = 0
        LC = 1
        SSR = 2
        LTP = 3

    profile: Profile
    sampling_frequency: int
    channel_configuration: int
    payload: bytes

    @property
    def sample_count(self) -> int:
        return 1024

    @property
    def duration(self) -> float:
        return self.sample_count / self.sampling_frequency

    def __str__(self) -> str:
        return (
            f'AAC(sf={self.sampling_frequency},'
            f'ch={self.channel_configuration},'
            f'size={len(self.payload)})'
        )


# -----------------------------------------------------------------------------
ADTS_AAC_SAMPLING_FREQUENCIES = [
    96000,
    88200,
    64000,
    48000,
    44100,
    32000,
    24000,
    22050,
    16000,
    12000,
    11025,
    8000,
    7350,
    0,
    0,
    0,
]


# -----------------------------------------------------------------------------
class AacParser:
    """Parser for AAC frames in an ADTS stream"""

    def __init__(self, read: Callable[[int], Awaitable[bytes]]) -> None:
        self.read = read

    @property
    def frames(self) -> AsyncGenerator[AacFrame, None]:
        async def generate_frames() -> AsyncGenerator[AacFrame, None]:
            while True:
                header = await self.read(7)
                if not header:
                    return

                sync_word = (header[0] << 4) | (header[1] >> 4)
                if sync_word != 0b111111111111:
                    raise ValueError(f"invalid sync word ({sync_word:06x})")
                layer = (header[1] >> 1) & 0b11
                profile = AacFrame.Profile((header[2] >> 6) & 0b11)
                sampling_frequency = ADTS_AAC_SAMPLING_FREQUENCIES[
                    (header[2] >> 2) & 0b1111
                ]
                channel_configuration = ((header[2] & 0b1) << 2) | (header[3] >> 6)
                frame_length = (
                    ((header[3] & 0b11) << 11) | (header[4] << 3) | (header[5] >> 5)
                )

                if layer != 0:
                    raise ValueError("layer must be 0")

                payload = await self.read(frame_length - 7)
                if payload:
                    yield AacFrame(
                        profile, sampling_frequency, channel_configuration, payload
                    )

        return generate_frames()


# -----------------------------------------------------------------------------
class AacPacketSource:
    def __init__(self, read: Callable[[int], Awaitable[bytes]], mtu: int) -> None:
        self.read = read
        self.mtu = mtu

    @property
    def packets(self):
        async def generate_packets():
            sequence_number = 0
            sample_count = 0

            aac_parser = AacParser(self.read)
            async for frame in aac_parser.frames:
                logger.debug("yielding one AAC frame")

                # Emit a packet
                aac_payload = bytes(
                    AacAudioRtpPacket.for_simple_aac(
                        frame.sampling_frequency,
                        frame.channel_configuration,
                        frame.payload,
                    )
                )
                timestamp_seconds = sample_count / frame.sampling_frequency
                timestamp = int(1000 * timestamp_seconds)
                packet = MediaPacket(
                    2, 0, 0, 0, sequence_number, timestamp, 0, [], 96, aac_payload
                )
                packet.timestamp_seconds = timestamp_seconds
                yield packet

                # Prepare for next packets
                sequence_number += 1
                sequence_number &= 0xFFFF
                sample_count += frame.sample_count

        return generate_packets()


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class OpusPacket:
    class ChannelMode(enum.IntEnum):
        MONO = 0
        STEREO = 1
        DUAL_MONO = 2

    channel_mode: ChannelMode
    duration: int  # Duration in ms.
    sampling_frequency: int
    payload: bytes

    def __str__(self) -> str:
        return (
            f'Opus(ch={self.channel_mode.name}, '
            f'd={self.duration}ms, '
            f'size={len(self.payload)})'
        )


# -----------------------------------------------------------------------------
class OpusParser:
    """
    Parser for Opus packets in an Ogg stream

    See RFC 3533

    NOTE: this parser only supports bitstreams with a single logical stream.
    """

    CAPTURE_PATTERN = b'OggS'

    class HeaderType(enum.IntFlag):
        CONTINUED = 0x01
        FIRST = 0x02
        LAST = 0x04

    def __init__(self, read: Callable[[int], Awaitable[bytes]]) -> None:
        self.read = read

    @property
    def packets(self) -> AsyncGenerator[OpusPacket, None]:
        async def generate_frames() -> AsyncGenerator[OpusPacket, None]:
            packet = b''
            packet_count = 0
            expected_bitstream_serial_number = None
            expected_page_sequence_number = 0
            channel_mode = OpusPacket.ChannelMode.STEREO

            while True:
                # Parse the page header
                header = await self.read(27)
                if len(header) != 27:
                    logger.debug("end of stream")
                    break

                capture_pattern = header[:4]
                if capture_pattern != self.CAPTURE_PATTERN:
                    print(capture_pattern.hex())
                    raise ValueError("invalid capture pattern at start of page")

                version = header[4]
                if version != 0:
                    raise ValueError(f"version {version} not supported")

                header_type = self.HeaderType(header[5])
                (
                    granule_position,
                    bitstream_serial_number,
                    page_sequence_number,
                    crc_checksum,
                    page_segments,
                ) = struct.unpack_from("<QIIIB", header, 6)
                segment_table = await self.read(page_segments)

                if header_type & self.HeaderType.FIRST:
                    if expected_bitstream_serial_number is None:
                        # We will only accept pages for the first encountered stream
                        logger.debug("BOS")
                        expected_bitstream_serial_number = bitstream_serial_number
                        expected_page_sequence_number = page_sequence_number

                if (
                    expected_bitstream_serial_number is None
                    or expected_bitstream_serial_number != bitstream_serial_number
                ):
                    logger.debug("skipping page (not the first logical bitstream)")
                    for lacing_value in segment_table:
                        if lacing_value:
                            await self.read(lacing_value)
                    continue

                if expected_page_sequence_number != page_sequence_number:
                    raise ValueError(
                        f"expected page sequence number {expected_page_sequence_number}"
                        f" but got {page_sequence_number}"
                    )
                expected_page_sequence_number = page_sequence_number + 1

                # Assemble the page
                if not header_type & self.HeaderType.CONTINUED:
                    packet = b''
                for lacing_value in segment_table:
                    if lacing_value:
                        packet += await self.read(lacing_value)
                    if lacing_value < 255:
                        # End of packet
                        packet_count += 1

                        if packet_count == 1:
                            # The first packet contains the identification header
                            logger.debug("first packet (header)")
                            if packet[:8] != b"OpusHead":
                                raise ValueError("first packet is not OpusHead")
                            packet_count = (
                                OpusPacket.ChannelMode.MONO
                                if packet[9] == 1
                                else OpusPacket.ChannelMode.STEREO
                            )

                        elif packet_count == 2:
                            # The second packet contains the comment header
                            logger.debug("second packet (tags)")
                            if packet[:8] != b"OpusTags":
                                logger.warning("second packet is not OpusTags")
                        else:
                            yield OpusPacket(channel_mode, 20, 48000, packet)

                        packet = b''

                if header_type & self.HeaderType.LAST:
                    logger.debug("EOS")

        return generate_frames()


# -----------------------------------------------------------------------------
class OpusPacketSource:
    def __init__(self, read: Callable[[int], Awaitable[bytes]], mtu: int) -> None:
        self.read = read
        self.mtu = mtu

    @property
    def packets(self):
        async def generate_packets():
            sequence_number = 0
            elapsed_ms = 0

            opus_parser = OpusParser(self.read)
            async for opus_packet in opus_parser.packets:
                # We only support sending one Opus frame per RTP packet
                # TODO: check the spec for the first byte value here
                opus_payload = bytes([1]) + opus_packet.payload
                elapsed_s = elapsed_ms / 1000
                timestamp = int(elapsed_s * opus_packet.sampling_frequency)
                rtp_packet = MediaPacket(
                    2, 0, 0, 0, sequence_number, timestamp, 0, [], 96, opus_payload
                )
                rtp_packet.timestamp_seconds = elapsed_s
                yield rtp_packet

                # Prepare for next packets
                sequence_number += 1
                sequence_number &= 0xFFFF
                elapsed_ms += opus_packet.duration

        return generate_packets()


# -----------------------------------------------------------------------------
# This map should be left at the end of the file so it can refer to the classes
# above
# -----------------------------------------------------------------------------
A2DP_VENDOR_MEDIA_CODEC_INFORMATION_CLASSES = {
    OpusMediaCodecInformation.VENDOR_ID: {
        OpusMediaCodecInformation.CODEC_ID: OpusMediaCodecInformation
    }
}
