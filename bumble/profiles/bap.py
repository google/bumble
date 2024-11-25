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
from __future__ import annotations

from collections.abc import Sequence
import dataclasses
import enum
import struct
import functools
import logging
from typing import List
from typing_extensions import Self

from bumble import core
from bumble import hci
from bumble import gatt
from bumble import utils
from bumble.profiles import le_audio


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------


class AudioLocation(enum.IntFlag):
    '''Bluetooth Assigned Numbers, Section 6.12.1 - Audio Location'''

    # fmt: off
    NOT_ALLOWED             = 0x00000000
    FRONT_LEFT              = 0x00000001
    FRONT_RIGHT             = 0x00000002
    FRONT_CENTER            = 0x00000004
    LOW_FREQUENCY_EFFECTS_1 = 0x00000008
    BACK_LEFT               = 0x00000010
    BACK_RIGHT              = 0x00000020
    FRONT_LEFT_OF_CENTER    = 0x00000040
    FRONT_RIGHT_OF_CENTER   = 0x00000080
    BACK_CENTER             = 0x00000100
    LOW_FREQUENCY_EFFECTS_2 = 0x00000200
    SIDE_LEFT               = 0x00000400
    SIDE_RIGHT              = 0x00000800
    TOP_FRONT_LEFT          = 0x00001000
    TOP_FRONT_RIGHT         = 0x00002000
    TOP_FRONT_CENTER        = 0x00004000
    TOP_CENTER              = 0x00008000
    TOP_BACK_LEFT           = 0x00010000
    TOP_BACK_RIGHT          = 0x00020000
    TOP_SIDE_LEFT           = 0x00040000
    TOP_SIDE_RIGHT          = 0x00080000
    TOP_BACK_CENTER         = 0x00100000
    BOTTOM_FRONT_CENTER     = 0x00200000
    BOTTOM_FRONT_LEFT       = 0x00400000
    BOTTOM_FRONT_RIGHT      = 0x00800000
    FRONT_LEFT_WIDE         = 0x01000000
    FRONT_RIGHT_WIDE        = 0x02000000
    LEFT_SURROUND           = 0x04000000
    RIGHT_SURROUND          = 0x08000000

    @property
    def channel_count(self) -> int:
        return bin(self.value).count('1')


class AudioInputType(enum.IntEnum):
    '''Bluetooth Assigned Numbers, Section 6.12.2 - Audio Input Type'''

    # fmt: off
    UNSPECIFIED = 0x00
    BLUETOOTH   = 0x01
    MICROPHONE  = 0x02
    ANALOG      = 0x03
    DIGITAL     = 0x04
    RADIO       = 0x05
    STREAMING   = 0x06
    AMBIENT     = 0x07


class ContextType(enum.IntFlag):
    '''Bluetooth Assigned Numbers, Section 6.12.3 - Context Type'''

    # fmt: off
    PROHIBITED       = 0x0000
    UNSPECIFIED      = 0x0001
    CONVERSATIONAL   = 0x0002
    MEDIA            = 0x0004
    GAME             = 0x0008
    INSTRUCTIONAL    = 0x0010
    VOICE_ASSISTANTS = 0x0020
    LIVE             = 0x0040
    SOUND_EFFECTS    = 0x0080
    NOTIFICATIONS    = 0x0100
    RINGTONE         = 0x0200
    ALERTS           = 0x0400
    EMERGENCY_ALARM  = 0x0800


class SamplingFrequency(utils.OpenIntEnum):
    '''Bluetooth Assigned Numbers, Section 6.12.5.1 - Sampling Frequency'''

    # fmt: off
    FREQ_8000    = 0x01
    FREQ_11025   = 0x02
    FREQ_16000   = 0x03
    FREQ_22050   = 0x04
    FREQ_24000   = 0x05
    FREQ_32000   = 0x06
    FREQ_44100   = 0x07
    FREQ_48000   = 0x08
    FREQ_88200   = 0x09
    FREQ_96000   = 0x0A
    FREQ_176400  = 0x0B
    FREQ_192000  = 0x0C
    FREQ_384000  = 0x0D
    # fmt: on

    @classmethod
    def from_hz(cls, frequency: int) -> SamplingFrequency:
        return {
            8000: SamplingFrequency.FREQ_8000,
            11025: SamplingFrequency.FREQ_11025,
            16000: SamplingFrequency.FREQ_16000,
            22050: SamplingFrequency.FREQ_22050,
            24000: SamplingFrequency.FREQ_24000,
            32000: SamplingFrequency.FREQ_32000,
            44100: SamplingFrequency.FREQ_44100,
            48000: SamplingFrequency.FREQ_48000,
            88200: SamplingFrequency.FREQ_88200,
            96000: SamplingFrequency.FREQ_96000,
            176400: SamplingFrequency.FREQ_176400,
            192000: SamplingFrequency.FREQ_192000,
            384000: SamplingFrequency.FREQ_384000,
        }[frequency]

    @property
    def hz(self) -> int:
        return {
            SamplingFrequency.FREQ_8000: 8000,
            SamplingFrequency.FREQ_11025: 11025,
            SamplingFrequency.FREQ_16000: 16000,
            SamplingFrequency.FREQ_22050: 22050,
            SamplingFrequency.FREQ_24000: 24000,
            SamplingFrequency.FREQ_32000: 32000,
            SamplingFrequency.FREQ_44100: 44100,
            SamplingFrequency.FREQ_48000: 48000,
            SamplingFrequency.FREQ_88200: 88200,
            SamplingFrequency.FREQ_96000: 96000,
            SamplingFrequency.FREQ_176400: 176400,
            SamplingFrequency.FREQ_192000: 192000,
            SamplingFrequency.FREQ_384000: 384000,
        }[self]


class SupportedSamplingFrequency(enum.IntFlag):
    '''Bluetooth Assigned Numbers, Section 6.12.4.1 - Sample Frequency'''

    # fmt: off
    FREQ_8000    = 1 << (SamplingFrequency.FREQ_8000 - 1)
    FREQ_11025   = 1 << (SamplingFrequency.FREQ_11025 - 1)
    FREQ_16000   = 1 << (SamplingFrequency.FREQ_16000 - 1)
    FREQ_22050   = 1 << (SamplingFrequency.FREQ_22050 - 1)
    FREQ_24000   = 1 << (SamplingFrequency.FREQ_24000 - 1)
    FREQ_32000   = 1 << (SamplingFrequency.FREQ_32000 - 1)
    FREQ_44100   = 1 << (SamplingFrequency.FREQ_44100 - 1)
    FREQ_48000   = 1 << (SamplingFrequency.FREQ_48000 - 1)
    FREQ_88200   = 1 << (SamplingFrequency.FREQ_88200 - 1)
    FREQ_96000   = 1 << (SamplingFrequency.FREQ_96000 - 1)
    FREQ_176400  = 1 << (SamplingFrequency.FREQ_176400 - 1)
    FREQ_192000  = 1 << (SamplingFrequency.FREQ_192000 - 1)
    FREQ_384000  = 1 << (SamplingFrequency.FREQ_384000 - 1)
    # fmt: on

    @classmethod
    def from_hz(cls, frequencies: Sequence[int]) -> SupportedSamplingFrequency:
        MAPPING = {
            8000: SupportedSamplingFrequency.FREQ_8000,
            11025: SupportedSamplingFrequency.FREQ_11025,
            16000: SupportedSamplingFrequency.FREQ_16000,
            22050: SupportedSamplingFrequency.FREQ_22050,
            24000: SupportedSamplingFrequency.FREQ_24000,
            32000: SupportedSamplingFrequency.FREQ_32000,
            44100: SupportedSamplingFrequency.FREQ_44100,
            48000: SupportedSamplingFrequency.FREQ_48000,
            88200: SupportedSamplingFrequency.FREQ_88200,
            96000: SupportedSamplingFrequency.FREQ_96000,
            176400: SupportedSamplingFrequency.FREQ_176400,
            192000: SupportedSamplingFrequency.FREQ_192000,
            384000: SupportedSamplingFrequency.FREQ_384000,
        }

        return functools.reduce(
            lambda x, y: x | MAPPING[y],
            frequencies,
            cls(0),
        )


class FrameDuration(enum.IntEnum):
    '''Bluetooth Assigned Numbers, Section 6.12.5.2 - Frame Duration'''

    # fmt: off
    DURATION_7500_US  = 0x00
    DURATION_10000_US = 0x01

    @property
    def us(self) -> int:
        return {
            FrameDuration.DURATION_7500_US: 7500,
            FrameDuration.DURATION_10000_US: 10000,
        }[self]


class SupportedFrameDuration(enum.IntFlag):
    '''Bluetooth Assigned Numbers, Section 6.12.4.2 - Frame Duration'''

    # fmt: off
    DURATION_7500_US_SUPPORTED  = 0b0001
    DURATION_10000_US_SUPPORTED = 0b0010
    DURATION_7500_US_PREFERRED  = 0b0001
    DURATION_10000_US_PREFERRED = 0b0010


class AnnouncementType(utils.OpenIntEnum):
    '''Basic Audio Profile, 3.5.3. Additional Audio Stream Control Service requirements'''

    # fmt: off
    GENERAL  = 0x00
    TARGETED = 0x01


@dataclasses.dataclass
class UnicastServerAdvertisingData:
    """Advertising Data for ASCS."""

    announcement_type: AnnouncementType = AnnouncementType.TARGETED
    available_audio_contexts: ContextType = ContextType.MEDIA
    metadata: bytes = b''

    def __bytes__(self) -> bytes:
        return bytes(
            core.AdvertisingData(
                [
                    (
                        core.AdvertisingData.SERVICE_DATA_16_BIT_UUID,
                        struct.pack(
                            '<2sBIB',
                            bytes(gatt.GATT_AUDIO_STREAM_CONTROL_SERVICE),
                            self.announcement_type,
                            self.available_audio_contexts,
                            len(self.metadata),
                        )
                        + self.metadata,
                    )
                ]
            )
        )


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------


def bits_to_channel_counts(data: int) -> List[int]:
    pos = 0
    counts = []
    while data != 0:
        # Bit 0 = count 1
        # Bit 1 = count 2, and so on
        pos += 1
        if data & 1:
            counts.append(pos)
        data >>= 1
    return counts


def channel_counts_to_bits(counts: Sequence[int]) -> int:
    return sum(set([1 << (count - 1) for count in counts]))


# -----------------------------------------------------------------------------
# Structures
# -----------------------------------------------------------------------------


@dataclasses.dataclass
class CodecSpecificCapabilities:
    '''See:
    * Bluetooth Assigned Numbers, 6.12.4 - Codec Specific Capabilities LTV Structures
    * Basic Audio Profile, 4.3.1 - Codec_Specific_Capabilities LTV requirements
    '''

    class Type(enum.IntEnum):
        # fmt: off
        SAMPLING_FREQUENCY   = 0x01
        FRAME_DURATION       = 0x02
        AUDIO_CHANNEL_COUNT  = 0x03
        OCTETS_PER_FRAME     = 0x04
        CODEC_FRAMES_PER_SDU = 0x05

    supported_sampling_frequencies: SupportedSamplingFrequency
    supported_frame_durations: SupportedFrameDuration
    supported_audio_channel_count: Sequence[int]
    min_octets_per_codec_frame: int
    max_octets_per_codec_frame: int
    supported_max_codec_frames_per_sdu: int

    @classmethod
    def from_bytes(cls, data: bytes) -> CodecSpecificCapabilities:
        offset = 0
        # Allowed default values.
        supported_audio_channel_count = [1]
        supported_max_codec_frames_per_sdu = 1
        while offset < len(data):
            length, type = struct.unpack_from('BB', data, offset)
            offset += 2
            value = int.from_bytes(data[offset : offset + length - 1], 'little')
            offset += length - 1

            if type == CodecSpecificCapabilities.Type.SAMPLING_FREQUENCY:
                supported_sampling_frequencies = SupportedSamplingFrequency(value)
            elif type == CodecSpecificCapabilities.Type.FRAME_DURATION:
                supported_frame_durations = SupportedFrameDuration(value)
            elif type == CodecSpecificCapabilities.Type.AUDIO_CHANNEL_COUNT:
                supported_audio_channel_count = bits_to_channel_counts(value)
            elif type == CodecSpecificCapabilities.Type.OCTETS_PER_FRAME:
                min_octets_per_sample = value & 0xFFFF
                max_octets_per_sample = value >> 16
            elif type == CodecSpecificCapabilities.Type.CODEC_FRAMES_PER_SDU:
                supported_max_codec_frames_per_sdu = value

        # It is expected here that if some fields are missing, an error should be raised.
        # pylint: disable=possibly-used-before-assignment,used-before-assignment
        return CodecSpecificCapabilities(
            supported_sampling_frequencies=supported_sampling_frequencies,
            supported_frame_durations=supported_frame_durations,
            supported_audio_channel_count=supported_audio_channel_count,
            min_octets_per_codec_frame=min_octets_per_sample,
            max_octets_per_codec_frame=max_octets_per_sample,
            supported_max_codec_frames_per_sdu=supported_max_codec_frames_per_sdu,
        )

    def __bytes__(self) -> bytes:
        return struct.pack(
            '<BBHBBBBBBBBHHBBB',
            3,
            CodecSpecificCapabilities.Type.SAMPLING_FREQUENCY,
            self.supported_sampling_frequencies,
            2,
            CodecSpecificCapabilities.Type.FRAME_DURATION,
            self.supported_frame_durations,
            2,
            CodecSpecificCapabilities.Type.AUDIO_CHANNEL_COUNT,
            channel_counts_to_bits(self.supported_audio_channel_count),
            5,
            CodecSpecificCapabilities.Type.OCTETS_PER_FRAME,
            self.min_octets_per_codec_frame,
            self.max_octets_per_codec_frame,
            2,
            CodecSpecificCapabilities.Type.CODEC_FRAMES_PER_SDU,
            self.supported_max_codec_frames_per_sdu,
        )


@dataclasses.dataclass
class CodecSpecificConfiguration:
    '''See:
    * Bluetooth Assigned Numbers, 6.12.5 - Codec Specific Configuration LTV Structures
    * Basic Audio Profile, 4.3.2 - Codec_Specific_Capabilities LTV requirements
    '''

    class Type(utils.OpenIntEnum):
        # fmt: off
        SAMPLING_FREQUENCY       = 0x01
        FRAME_DURATION           = 0x02
        AUDIO_CHANNEL_ALLOCATION = 0x03
        OCTETS_PER_FRAME         = 0x04
        CODEC_FRAMES_PER_SDU     = 0x05

    sampling_frequency: SamplingFrequency | None = None
    frame_duration: FrameDuration | None = None
    audio_channel_allocation: AudioLocation | None = None
    octets_per_codec_frame: int | None = None
    codec_frames_per_sdu: int | None = None

    @classmethod
    def from_bytes(cls, data: bytes) -> CodecSpecificConfiguration:
        offset = 0
        sampling_frequency: SamplingFrequency | None = None
        frame_duration: FrameDuration | None = None
        audio_channel_allocation: AudioLocation | None = None
        octets_per_codec_frame: int | None = None
        codec_frames_per_sdu: int | None = None

        while offset < len(data):
            length, type = struct.unpack_from('BB', data, offset)
            offset += 2
            value = int.from_bytes(data[offset : offset + length - 1], 'little')
            offset += length - 1

            if type == CodecSpecificConfiguration.Type.SAMPLING_FREQUENCY:
                sampling_frequency = SamplingFrequency(value)
            elif type == CodecSpecificConfiguration.Type.FRAME_DURATION:
                frame_duration = FrameDuration(value)
            elif type == CodecSpecificConfiguration.Type.AUDIO_CHANNEL_ALLOCATION:
                audio_channel_allocation = AudioLocation(value)
            elif type == CodecSpecificConfiguration.Type.OCTETS_PER_FRAME:
                octets_per_codec_frame = value
            elif type == CodecSpecificConfiguration.Type.CODEC_FRAMES_PER_SDU:
                codec_frames_per_sdu = value

        return CodecSpecificConfiguration(
            sampling_frequency=sampling_frequency,
            frame_duration=frame_duration,
            audio_channel_allocation=audio_channel_allocation,
            octets_per_codec_frame=octets_per_codec_frame,
            codec_frames_per_sdu=codec_frames_per_sdu,
        )

    def __bytes__(self) -> bytes:
        return b''.join(
            [
                struct.pack(fmt, length, tag, value)
                for fmt, length, tag, value in [
                    (
                        '<BBB',
                        2,
                        CodecSpecificConfiguration.Type.SAMPLING_FREQUENCY,
                        self.sampling_frequency,
                    ),
                    (
                        '<BBB',
                        2,
                        CodecSpecificConfiguration.Type.FRAME_DURATION,
                        self.frame_duration,
                    ),
                    (
                        '<BBI',
                        5,
                        CodecSpecificConfiguration.Type.AUDIO_CHANNEL_ALLOCATION,
                        self.audio_channel_allocation,
                    ),
                    (
                        '<BBH',
                        3,
                        CodecSpecificConfiguration.Type.OCTETS_PER_FRAME,
                        self.octets_per_codec_frame,
                    ),
                    (
                        '<BBB',
                        2,
                        CodecSpecificConfiguration.Type.CODEC_FRAMES_PER_SDU,
                        self.codec_frames_per_sdu,
                    ),
                ]
                if value is not None
            ]
        )


@dataclasses.dataclass
class BroadcastAudioAnnouncement:
    broadcast_id: int

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls(int.from_bytes(data[:3], 'little'))

    def __bytes__(self) -> bytes:
        return self.broadcast_id.to_bytes(3, 'little')

    def get_advertising_data(self) -> bytes:
        return bytes(
            core.AdvertisingData(
                [
                    (
                        core.AdvertisingData.SERVICE_DATA_16_BIT_UUID,
                        (
                            bytes(gatt.GATT_BROADCAST_AUDIO_ANNOUNCEMENT_SERVICE)
                            + bytes(self)
                        ),
                    )
                ]
            )
        )


@dataclasses.dataclass
class BasicAudioAnnouncement:
    @dataclasses.dataclass
    class BIS:
        index: int
        codec_specific_configuration: CodecSpecificConfiguration

        def __bytes__(self) -> bytes:
            codec_specific_configuration_bytes = bytes(
                self.codec_specific_configuration
            )
            return (
                bytes([self.index, len(codec_specific_configuration_bytes)])
                + codec_specific_configuration_bytes
            )

    @dataclasses.dataclass
    class Subgroup:
        codec_id: hci.CodingFormat
        codec_specific_configuration: CodecSpecificConfiguration
        metadata: le_audio.Metadata
        bis: List[BasicAudioAnnouncement.BIS]

        def __bytes__(self) -> bytes:
            metadata_bytes = bytes(self.metadata)
            codec_specific_configuration_bytes = bytes(
                self.codec_specific_configuration
            )
            return (
                bytes([len(self.bis)])
                + bytes(self.codec_id)
                + bytes([len(codec_specific_configuration_bytes)])
                + codec_specific_configuration_bytes
                + bytes([len(metadata_bytes)])
                + metadata_bytes
                + b''.join(map(bytes, self.bis))
            )

    presentation_delay: int
    subgroups: List[BasicAudioAnnouncement.Subgroup]

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        presentation_delay = int.from_bytes(data[:3], 'little')
        subgroups = []
        offset = 4
        for _ in range(data[3]):
            num_bis = data[offset]
            offset += 1
            codec_id = hci.CodingFormat.from_bytes(data[offset : offset + 5])
            offset += 5
            codec_specific_configuration_length = data[offset]
            offset += 1
            codec_specific_configuration = data[
                offset : offset + codec_specific_configuration_length
            ]
            offset += codec_specific_configuration_length
            metadata_length = data[offset]
            offset += 1
            metadata = le_audio.Metadata.from_bytes(
                data[offset : offset + metadata_length]
            )
            offset += metadata_length

            bis = []
            for _ in range(num_bis):
                bis_index = data[offset]
                offset += 1
                bis_codec_specific_configuration_length = data[offset]
                offset += 1
                bis_codec_specific_configuration = data[
                    offset : offset + bis_codec_specific_configuration_length
                ]
                offset += bis_codec_specific_configuration_length
                bis.append(
                    cls.BIS(
                        bis_index,
                        CodecSpecificConfiguration.from_bytes(
                            bis_codec_specific_configuration
                        ),
                    )
                )

            subgroups.append(
                cls.Subgroup(
                    codec_id,
                    CodecSpecificConfiguration.from_bytes(codec_specific_configuration),
                    metadata,
                    bis,
                )
            )

        return cls(presentation_delay, subgroups)

    def __bytes__(self) -> bytes:
        return (
            self.presentation_delay.to_bytes(3, 'little')
            + bytes([len(self.subgroups)])
            + b''.join(map(bytes, self.subgroups))
        )

    def get_advertising_data(self) -> bytes:
        return bytes(
            core.AdvertisingData(
                [
                    (
                        core.AdvertisingData.SERVICE_DATA_16_BIT_UUID,
                        (
                            bytes(gatt.GATT_BASIC_AUDIO_ANNOUNCEMENT_SERVICE)
                            + bytes(self)
                        ),
                    )
                ]
            )
        )
