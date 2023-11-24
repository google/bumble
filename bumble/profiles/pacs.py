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
import functools
import struct
from typing import Optional

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


class SampleFrequency(enum.IntEnum):
    '''Bluetooth Assigned Numbers, Section 6.12.5.1 - Sample Frequency'''

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
    def from_hz(cls, frequency: int) -> SampleFrequency:
        return {
            8000: SampleFrequency.FREQ_8000,
            11025: SampleFrequency.FREQ_11025,
            16000: SampleFrequency.FREQ_16000,
            22050: SampleFrequency.FREQ_22050,
            24000: SampleFrequency.FREQ_24000,
            32000: SampleFrequency.FREQ_32000,
            44100: SampleFrequency.FREQ_44100,
            48000: SampleFrequency.FREQ_48000,
            88200: SampleFrequency.FREQ_88200,
            96000: SampleFrequency.FREQ_96000,
            176400: SampleFrequency.FREQ_176400,
            192000: SampleFrequency.FREQ_192000,
            384000: SampleFrequency.FREQ_384000,
        }[frequency]

    @property
    def hz(self) -> int:
        return {
            SampleFrequency.FREQ_8000: 8000,
            SampleFrequency.FREQ_11025: 11025,
            SampleFrequency.FREQ_16000: 16000,
            SampleFrequency.FREQ_22050: 22050,
            SampleFrequency.FREQ_24000: 24000,
            SampleFrequency.FREQ_32000: 32000,
            SampleFrequency.FREQ_44100: 44100,
            SampleFrequency.FREQ_48000: 48000,
            SampleFrequency.FREQ_88200: 88200,
            SampleFrequency.FREQ_96000: 96000,
            SampleFrequency.FREQ_176400: 176400,
            SampleFrequency.FREQ_192000: 192000,
            SampleFrequency.FREQ_384000: 384000,
        }[self]


class SupportedSampleFrequency(enum.IntFlag):
    '''Bluetooth Assigned Numbers, Section 6.12.4.1 - Sample Frequency'''

    # fmt: off
    FREQ_8000    = 1 << (SampleFrequency.FREQ_8000 - 1)
    FREQ_11025   = 1 << (SampleFrequency.FREQ_11025 - 1)
    FREQ_16000   = 1 << (SampleFrequency.FREQ_16000 - 1)
    FREQ_22050   = 1 << (SampleFrequency.FREQ_22050 - 1)
    FREQ_24000   = 1 << (SampleFrequency.FREQ_24000 - 1)
    FREQ_32000   = 1 << (SampleFrequency.FREQ_32000 - 1)
    FREQ_44100   = 1 << (SampleFrequency.FREQ_44100 - 1)
    FREQ_48000   = 1 << (SampleFrequency.FREQ_48000 - 1)
    FREQ_88200   = 1 << (SampleFrequency.FREQ_88200 - 1)
    FREQ_96000   = 1 << (SampleFrequency.FREQ_96000 - 1)
    FREQ_176400  = 1 << (SampleFrequency.FREQ_176400 - 1)
    FREQ_192000  = 1 << (SampleFrequency.FREQ_192000 - 1)
    FREQ_384000  = 1 << (SampleFrequency.FREQ_384000 - 1)
    # fmt: on

    @classmethod
    def from_hz(cls, frequencies: Sequence[int]) -> SupportedSampleFrequency:
        MAPPING = {
            8000: SupportedSampleFrequency.FREQ_8000,
            11025: SupportedSampleFrequency.FREQ_11025,
            16000: SupportedSampleFrequency.FREQ_16000,
            22050: SupportedSampleFrequency.FREQ_22050,
            24000: SupportedSampleFrequency.FREQ_24000,
            32000: SupportedSampleFrequency.FREQ_32000,
            44100: SupportedSampleFrequency.FREQ_44100,
            48000: SupportedSampleFrequency.FREQ_48000,
            88200: SupportedSampleFrequency.FREQ_88200,
            96000: SupportedSampleFrequency.FREQ_96000,
            176400: SupportedSampleFrequency.FREQ_176400,
            192000: SupportedSampleFrequency.FREQ_192000,
            384000: SupportedSampleFrequency.FREQ_384000,
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


def bits_to_channel_counts(data: int) -> Sequence[int]:
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
    '''Bluetooth Assigned Numbers, Section 6.12.5 - Codec Specific Capabilities LTV Structures.'''

    class Type(enum.IntEnum):
        # fmt: off
        SAMPLE_FREQUENCY     = 0x01
        FRAME_DURATION       = 0x02
        AUDIO_CHANNEL_COUNT  = 0x03
        OCTETS_PER_SAMPLE    = 0x04
        CODEC_FRAMES_PER_SDU = 0x05

    supported_sample_frequencies: SupportedSampleFrequency
    supported_frame_durations: SupportedFrameDuration
    supported_audio_channel_counts: Sequence[int]
    min_octets_per_sample: int
    max_octets_per_sample: int
    supported_max_codec_frames_per_sdu: int

    @classmethod
    def from_bytes(cls, data: bytes) -> CodecSpecificCapabilities:
        pos = 0
        while pos < len(data):
            length, type = struct.unpack_from('BB', data, pos)
            pos += 2
            value = int.from_bytes(data[pos : pos + length - 1], 'little')
            pos += length - 1

            if type == CodecSpecificCapabilities.Type.SAMPLE_FREQUENCY:
                supported_sample_frequencies = SupportedSampleFrequency(value)
            elif type == CodecSpecificCapabilities.Type.FRAME_DURATION:
                supported_frame_durations = SupportedFrameDuration(value)
            elif type == CodecSpecificCapabilities.Type.AUDIO_CHANNEL_COUNT:
                supported_audio_channel_counts = bits_to_channel_counts(value)
            elif type == CodecSpecificCapabilities.Type.OCTETS_PER_SAMPLE:
                min_octets_per_sample = value & 0xFFFF
                max_octets_per_sample = value >> 16
            elif type == CodecSpecificCapabilities.Type.CODEC_FRAMES_PER_SDU:
                supported_max_codec_frames_per_sdu = value

        # It is expected here that if some fields are missing, an error should be raised.
        return CodecSpecificCapabilities(
            supported_sample_frequencies=supported_sample_frequencies,
            supported_frame_durations=supported_frame_durations,
            supported_audio_channel_counts=supported_audio_channel_counts,
            min_octets_per_sample=min_octets_per_sample,
            max_octets_per_sample=max_octets_per_sample,
            supported_max_codec_frames_per_sdu=supported_max_codec_frames_per_sdu,
        )

    def __bytes__(self) -> bytes:
        return struct.pack(
            '<BBHBBBBBBBBHHBBB',
            3,
            CodecSpecificCapabilities.Type.SAMPLE_FREQUENCY,
            self.supported_sample_frequencies,
            2,
            CodecSpecificCapabilities.Type.FRAME_DURATION,
            self.supported_frame_durations,
            2,
            CodecSpecificCapabilities.Type.AUDIO_CHANNEL_COUNT,
            channel_counts_to_bits(self.supported_audio_channel_counts),
            5,
            CodecSpecificCapabilities.Type.OCTETS_PER_SAMPLE,
            self.min_octets_per_sample,
            self.max_octets_per_sample,
            2,
            CodecSpecificCapabilities.Type.CODEC_FRAMES_PER_SDU,
            self.supported_max_codec_frames_per_sdu,
        )


@dataclasses.dataclass
class PAC_Record:
    codec_id: bytes
    codec_specific_capabilities: CodecSpecificCapabilities
    metadata: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> PAC_Record:
        codec_id, size = struct.unpack_from('5sB', data)
        pos = 5 + 1
        codec_specific_capabilities, size = struct.unpack_from(f'{size}sB', data, pos)
        pos += len(codec_specific_capabilities) + 1
        (metadata,) = struct.unpack_from(f'{size}s', data, pos)
        return PAC_Record(
            codec_id=codec_id,
            codec_specific_capabilities=CodecSpecificCapabilities.from_bytes(
                codec_specific_capabilities
            ),
            metadata=metadata,
        )

    def __bytes__(self) -> bytes:
        capabilities_bytes = bytes(self.codec_specific_capabilities)
        return struct.pack(
            f'5sB{len(capabilities_bytes)}sB{len(self.metadata)}s',
            self.codec_id,
            len(capabilities_bytes),
            capabilities_bytes,
            len(self.metadata),
            self.metadata,
        )


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class Service(gatt.TemplateService):
    UUID = gatt.GATT_PUBLISHED_AUDIO_CAPABILITIES_SERVICE

    def __init__(
        self,
        supported_source_context: ContextType,
        supported_sink_context: ContextType,
        available_source_context: ContextType,
        available_sink_context: ContextType,
        sink_pacs: Optional[Sequence[PAC_Record]] = None,
        sink_audio_location: Optional[AudioLocation] = None,
        source_pacs: Optional[Sequence[PAC_Record]] = None,
        source_audio_location: Optional[AudioLocation] = None,
    ):
        characteristics = []
        supported_audio_context_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=struct.pack('<HH', supported_sink_context, supported_source_context),
        )
        characteristics.append(supported_audio_context_characteristic)
        available_audio_context_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=struct.pack('<HH', available_sink_context, available_source_context),
        )
        characteristics.append(available_audio_context_characteristic)
        if sink_pacs is not None:
            sink_pac_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SINK_PAC_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('<H', len(sink_pacs))
                + b''.join(map(bytes, sink_pacs)),
            )
            characteristics.append(sink_pac_characteristic)
        if sink_audio_location is not None:
            sink_audio_location_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('<I', sink_audio_location),
            )
            characteristics.append(sink_audio_location_characteristic)
        if source_pacs is not None:
            source_pac_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SOURCE_PAC_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('<H', len(source_pacs))
                + b''.join(map(bytes, source_pacs)),
            )
            characteristics.append(source_pac_characteristic)
        if source_audio_location is not None:
            source_audio_location_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('<I', source_audio_location),
            )
            characteristics.append(source_audio_location_characteristic)
        super().__init__(characteristics)


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class ServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = Service

    sink_pac: Optional[gatt_client.CharacteristicProxy] = None
    sink_audio_location: Optional[gatt_client.CharacteristicProxy] = None
    source_pac: Optional[gatt_client.CharacteristicProxy] = None
    source_audio_location: Optional[gatt_client.CharacteristicProxy] = None
    available_audio_context: gatt_client.CharacteristicProxy
    supported_audio_context: gatt_client.CharacteristicProxy

    def __init__(self, service_proxy: gatt_client.ServiceProxy):
        self.service_proxy = service_proxy

        self.available_audio_context = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC
        )[0]
        self.supported_audio_context = service_proxy.get_characteristics_by_uuid(
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
            self.sink_audio_location = characteristics[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC
        ):
            self.source_audio_location = characteristics[0]
