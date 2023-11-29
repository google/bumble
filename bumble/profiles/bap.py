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
from typing import Optional, List, Union

from bumble import hci
from bumble import gatt
from bumble import gatt_client


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


class SamplingFrequency(enum.IntEnum):
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


class SupportedFrameDuration(enum.IntFlag):
    '''Bluetooth Assigned Numbers, Section 6.12.4.2 - Frame Duration'''

    # fmt: off
    DURATION_7500_US_SUPPORTED  = 0b0001
    DURATION_10000_US_SUPPORTED = 0b0010
    DURATION_7500_US_PREFERRED  = 0b0001
    DURATION_10000_US_PREFERRED = 0b0010


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
    supported_audio_channel_counts: Sequence[int]
    min_octets_per_codec_frame: int
    max_octets_per_codec_frame: int
    supported_max_codec_frames_per_sdu: int

    @classmethod
    def from_bytes(cls, data: bytes) -> CodecSpecificCapabilities:
        offset = 0
        # Allowed default values.
        supported_audio_channel_counts = [1]
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
                supported_audio_channel_counts = bits_to_channel_counts(value)
            elif type == CodecSpecificCapabilities.Type.OCTETS_PER_FRAME:
                min_octets_per_sample = value & 0xFFFF
                max_octets_per_sample = value >> 16
            elif type == CodecSpecificCapabilities.Type.CODEC_FRAMES_PER_SDU:
                supported_max_codec_frames_per_sdu = value

        # It is expected here that if some fields are missing, an error should be raised.
        return CodecSpecificCapabilities(
            supported_sampling_frequencies=supported_sampling_frequencies,
            supported_frame_durations=supported_frame_durations,
            supported_audio_channel_counts=supported_audio_channel_counts,
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
            channel_counts_to_bits(self.supported_audio_channel_counts),
            5,
            CodecSpecificCapabilities.Type.OCTETS_PER_FRAME,
            self.min_octets_per_codec_frame,
            self.max_octets_per_codec_frame,
            2,
            CodecSpecificCapabilities.Type.CODEC_FRAMES_PER_SDU,
            self.supported_max_codec_frames_per_sdu,
        )


@dataclasses.dataclass
class PacRecord:
    coding_format: hci.CodingFormat
    codec_specific_capabilities: Union[CodecSpecificCapabilities, bytes]
    # TODO: Parse Metadata
    metadata: bytes = b''

    @classmethod
    def from_bytes(cls, data: bytes) -> PacRecord:
        offset, coding_format = hci.CodingFormat.parse_from_bytes(data, 0)
        codec_specific_capabilities_size = data[offset]

        offset += 1
        codec_specific_capabilities_bytes = data[
            offset : offset + codec_specific_capabilities_size
        ]
        offset += codec_specific_capabilities_size
        metadata_size = data[offset]
        metadata = data[offset : offset + metadata_size]

        codec_specific_capabilities: Union[CodecSpecificCapabilities, bytes]
        if coding_format.codec_id == hci.CodecID.VENDOR_SPECIFIC:
            codec_specific_capabilities = codec_specific_capabilities_bytes
        else:
            codec_specific_capabilities = CodecSpecificCapabilities.from_bytes(
                codec_specific_capabilities_bytes
            )

        return PacRecord(
            coding_format=coding_format,
            codec_specific_capabilities=codec_specific_capabilities,
            metadata=metadata,
        )

    def __bytes__(self) -> bytes:
        capabilities_bytes = bytes(self.codec_specific_capabilities)
        return (
            bytes(self.coding_format)
            + bytes([len(capabilities_bytes)])
            + capabilities_bytes
            + bytes([len(self.metadata)])
            + self.metadata
        )


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class PublishedAudioCapabilitiesService(gatt.TemplateService):
    UUID = gatt.GATT_PUBLISHED_AUDIO_CAPABILITIES_SERVICE

    sink_pac: Optional[gatt.Characteristic]
    sink_audio_locations: Optional[gatt.Characteristic]
    source_pac: Optional[gatt.Characteristic]
    source_audio_locations: Optional[gatt.Characteristic]
    available_audio_contexts: gatt.Characteristic
    supported_audio_contexts: gatt.Characteristic

    def __init__(
        self,
        supported_source_context: ContextType,
        supported_sink_context: ContextType,
        available_source_context: ContextType,
        available_sink_context: ContextType,
        sink_pac: Sequence[PacRecord] = [],
        sink_audio_locations: Optional[AudioLocation] = None,
        source_pac: Sequence[PacRecord] = [],
        source_audio_locations: Optional[AudioLocation] = None,
    ) -> None:
        characteristics = []

        self.supported_audio_contexts = gatt.Characteristic(
            uuid=gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=struct.pack('<HH', supported_sink_context, supported_source_context),
        )
        characteristics.append(self.supported_audio_contexts)

        self.available_audio_contexts = gatt.Characteristic(
            uuid=gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=struct.pack('<HH', available_sink_context, available_source_context),
        )
        characteristics.append(self.available_audio_contexts)

        if sink_pac:
            self.sink_pac = gatt.Characteristic(
                uuid=gatt.GATT_SINK_PAC_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=bytes([len(sink_pac)]) + b''.join(map(bytes, sink_pac)),
            )
            characteristics.append(self.sink_pac)

        if sink_audio_locations is not None:
            self.sink_audio_locations = gatt.Characteristic(
                uuid=gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('<I', sink_audio_locations),
            )
            characteristics.append(self.sink_audio_locations)

        if source_pac:
            self.source_pac = gatt.Characteristic(
                uuid=gatt.GATT_SOURCE_PAC_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=bytes([len(source_pac)]) + b''.join(map(bytes, source_pac)),
            )
            characteristics.append(self.source_pac)

        if source_audio_locations is not None:
            self.source_audio_locations = gatt.Characteristic(
                uuid=gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('<I', source_audio_locations),
            )
            characteristics.append(self.source_audio_locations)

        super().__init__(characteristics)


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class PublishedAudioCapabilitiesServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = PublishedAudioCapabilitiesService

    sink_pac: Optional[gatt_client.CharacteristicProxy] = None
    sink_audio_locations: Optional[gatt_client.CharacteristicProxy] = None
    source_pac: Optional[gatt_client.CharacteristicProxy] = None
    source_audio_locations: Optional[gatt_client.CharacteristicProxy] = None
    available_audio_contexts: gatt_client.CharacteristicProxy
    supported_audio_contexts: gatt_client.CharacteristicProxy

    def __init__(self, service_proxy: gatt_client.ServiceProxy):
        self.service_proxy = service_proxy

        self.available_audio_contexts = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC
        )[0]
        self.supported_audio_contexts = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC
        )[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SINK_PAC_CHARACTERISTIC
        ):
            self.sink_pac = characteristics[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SOURCE_PAC_CHARACTERISTIC
        ):
            self.source_pac = characteristics[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC
        ):
            self.sink_audio_locations = characteristics[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC
        ):
            self.source_audio_locations = characteristics[0]
