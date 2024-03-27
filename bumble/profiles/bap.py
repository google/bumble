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
from typing import Optional, List, Union, Type, Dict, Any, Tuple

from bumble import core
from bumble import colors
from bumble import device
from bumble import hci
from bumble import gatt
from bumble import gatt_client


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


class AnnouncementType(enum.IntEnum):
    '''Basic Audio Profile, 3.5.3. Additional Audio Stream Control Service requirements'''

    # fmt: off
    GENERAL  = 0x00
    TARGETED = 0x01


# -----------------------------------------------------------------------------
# ASE Operations
# -----------------------------------------------------------------------------


class ASE_Operation:
    '''
    See Audio Stream Control Service - 5 ASE Control operations.
    '''

    classes: Dict[int, Type[ASE_Operation]] = {}
    op_code: int
    name: str
    fields: Optional[Sequence[Any]] = None
    ase_id: List[int]

    class Opcode(enum.IntEnum):
        # fmt: off
        CONFIG_CODEC         = 0x01
        CONFIG_QOS           = 0x02
        ENABLE               = 0x03
        RECEIVER_START_READY = 0x04
        DISABLE              = 0x05
        RECEIVER_STOP_READY  = 0x06
        UPDATE_METADATA      = 0x07
        RELEASE              = 0x08

    @staticmethod
    def from_bytes(pdu: bytes) -> ASE_Operation:
        op_code = pdu[0]

        cls = ASE_Operation.classes.get(op_code)
        if cls is None:
            instance = ASE_Operation(pdu)
            instance.name = ASE_Operation.Opcode(op_code).name
            instance.op_code = op_code
            return instance
        self = cls.__new__(cls)
        ASE_Operation.__init__(self, pdu)
        if self.fields is not None:
            self.init_from_bytes(pdu, 1)
        return self

    @staticmethod
    def subclass(fields):
        def inner(cls: Type[ASE_Operation]):
            try:
                operation = ASE_Operation.Opcode[cls.__name__[4:].upper()]
                cls.name = operation.name
                cls.op_code = operation
            except:
                raise KeyError(f'PDU name {cls.name} not found in Ase_Operation.Opcode')
            cls.fields = fields

            # Register a factory for this class
            ASE_Operation.classes[cls.op_code] = cls

            return cls

        return inner

    def __init__(self, pdu: Optional[bytes] = None, **kwargs) -> None:
        if self.fields is not None and kwargs:
            hci.HCI_Object.init_from_fields(self, self.fields, kwargs)
        if pdu is None:
            pdu = bytes([self.op_code]) + hci.HCI_Object.dict_to_bytes(
                kwargs, self.fields
            )
        self.pdu = pdu

    def init_from_bytes(self, pdu: bytes, offset: int):
        return hci.HCI_Object.init_from_bytes(self, pdu, offset, self.fields)

    def __bytes__(self) -> bytes:
        return self.pdu

    def __str__(self) -> str:
        result = f'{colors.color(self.name, "yellow")} '
        if fields := getattr(self, 'fields', None):
            result += ':\n' + hci.HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if len(self.pdu) > 1:
                result += f': {self.pdu.hex()}'
        return result


@ASE_Operation.subclass(
    [
        [
            ('ase_id', 1),
            ('target_latency', 1),
            ('target_phy', 1),
            ('codec_id', hci.CodingFormat.parse_from_bytes),
            ('codec_specific_configuration', 'v'),
        ],
    ]
)
class ASE_Config_Codec(ASE_Operation):
    '''
    See Audio Stream Control Service 5.1 - Config Codec Operation
    '''

    target_latency: List[int]
    target_phy: List[int]
    codec_id: List[hci.CodingFormat]
    codec_specific_configuration: List[bytes]


@ASE_Operation.subclass(
    [
        [
            ('ase_id', 1),
            ('cig_id', 1),
            ('cis_id', 1),
            ('sdu_interval', 3),
            ('framing', 1),
            ('phy', 1),
            ('max_sdu', 2),
            ('retransmission_number', 1),
            ('max_transport_latency', 2),
            ('presentation_delay', 3),
        ],
    ]
)
class ASE_Config_QOS(ASE_Operation):
    '''
    See Audio Stream Control Service 5.2 - Config Qos Operation
    '''

    cig_id: List[int]
    cis_id: List[int]
    sdu_interval: List[int]
    framing: List[int]
    phy: List[int]
    max_sdu: List[int]
    retransmission_number: List[int]
    max_transport_latency: List[int]
    presentation_delay: List[int]


@ASE_Operation.subclass([[('ase_id', 1), ('metadata', 'v')]])
class ASE_Enable(ASE_Operation):
    '''
    See Audio Stream Control Service 5.3 - Enable Operation
    '''

    metadata: bytes


@ASE_Operation.subclass([[('ase_id', 1)]])
class ASE_Receiver_Start_Ready(ASE_Operation):
    '''
    See Audio Stream Control Service 5.4 - Receiver Start Ready Operation
    '''


@ASE_Operation.subclass([[('ase_id', 1)]])
class ASE_Disable(ASE_Operation):
    '''
    See Audio Stream Control Service 5.5 - Disable Operation
    '''


@ASE_Operation.subclass([[('ase_id', 1)]])
class ASE_Receiver_Stop_Ready(ASE_Operation):
    '''
    See Audio Stream Control Service 5.6 - Receiver Stop Ready Operation
    '''


@ASE_Operation.subclass([[('ase_id', 1), ('metadata', 'v')]])
class ASE_Update_Metadata(ASE_Operation):
    '''
    See Audio Stream Control Service 5.7 - Update Metadata Operation
    '''

    metadata: List[bytes]


@ASE_Operation.subclass([[('ase_id', 1)]])
class ASE_Release(ASE_Operation):
    '''
    See Audio Stream Control Service 5.8 - Release Operation
    '''


class AseResponseCode(enum.IntEnum):
    # fmt: off
    SUCCESS                                     = 0x00
    UNSUPPORTED_OPCODE                          = 0x01
    INVALID_LENGTH                              = 0x02
    INVALID_ASE_ID                              = 0x03
    INVALID_ASE_STATE_MACHINE_TRANSITION        = 0x04
    INVALID_ASE_DIRECTION                       = 0x05
    UNSUPPORTED_AUDIO_CAPABILITIES              = 0x06
    UNSUPPORTED_CONFIGURATION_PARAMETER_VALUE   = 0x07
    REJECTED_CONFIGURATION_PARAMETER_VALUE      = 0x08
    INVALID_CONFIGURATION_PARAMETER_VALUE       = 0x09
    UNSUPPORTED_METADATA                        = 0x0A
    REJECTED_METADATA                           = 0x0B
    INVALID_METADATA                            = 0x0C
    INSUFFICIENT_RESOURCES                      = 0x0D
    UNSPECIFIED_ERROR                           = 0x0E


class AseReasonCode(enum.IntEnum):
    # fmt: off
    NONE                            = 0x00
    CODEC_ID                        = 0x01
    CODEC_SPECIFIC_CONFIGURATION    = 0x02
    SDU_INTERVAL                    = 0x03
    FRAMING                         = 0x04
    PHY                             = 0x05
    MAXIMUM_SDU_SIZE                = 0x06
    RETRANSMISSION_NUMBER           = 0x07
    MAX_TRANSPORT_LATENCY           = 0x08
    PRESENTATION_DELAY              = 0x09
    INVALID_ASE_CIS_MAPPING         = 0x0A


class AudioRole(enum.IntEnum):
    SINK = hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.CONTROLLER_TO_HOST
    SOURCE = hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.HOST_TO_CONTROLLER


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
                            gatt.GATT_AUDIO_STREAM_CONTROL_SERVICE.to_bytes(),
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
class CodecSpecificConfiguration:
    '''See:
    * Bluetooth Assigned Numbers, 6.12.5 - Codec Specific Configuration LTV Structures
    * Basic Audio Profile, 4.3.2 - Codec_Specific_Capabilities LTV requirements
    '''

    class Type(enum.IntEnum):
        # fmt: off
        SAMPLING_FREQUENCY       = 0x01
        FRAME_DURATION           = 0x02
        AUDIO_CHANNEL_ALLOCATION = 0x03
        OCTETS_PER_FRAME         = 0x04
        CODEC_FRAMES_PER_SDU     = 0x05

    sampling_frequency: SamplingFrequency
    frame_duration: FrameDuration
    audio_channel_allocation: AudioLocation
    octets_per_codec_frame: int
    codec_frames_per_sdu: int

    @classmethod
    def from_bytes(cls, data: bytes) -> CodecSpecificConfiguration:
        offset = 0
        # Allowed default values.
        audio_channel_allocation = AudioLocation.NOT_ALLOWED
        codec_frames_per_sdu = 1
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

        # It is expected here that if some fields are missing, an error should be raised.
        return CodecSpecificConfiguration(
            sampling_frequency=sampling_frequency,
            frame_duration=frame_duration,
            audio_channel_allocation=audio_channel_allocation,
            octets_per_codec_frame=octets_per_codec_frame,
            codec_frames_per_sdu=codec_frames_per_sdu,
        )

    def __bytes__(self) -> bytes:
        return struct.pack(
            '<BBBBBBBBIBBHBBB',
            2,
            CodecSpecificConfiguration.Type.SAMPLING_FREQUENCY,
            self.sampling_frequency,
            2,
            CodecSpecificConfiguration.Type.FRAME_DURATION,
            self.frame_duration,
            5,
            CodecSpecificConfiguration.Type.AUDIO_CHANNEL_ALLOCATION,
            self.audio_channel_allocation,
            3,
            CodecSpecificConfiguration.Type.OCTETS_PER_FRAME,
            self.octets_per_codec_frame,
            2,
            CodecSpecificConfiguration.Type.CODEC_FRAMES_PER_SDU,
            self.codec_frames_per_sdu,
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


class AseStateMachine(gatt.Characteristic):
    class State(enum.IntEnum):
        # fmt: off
        IDLE             = 0x00
        CODEC_CONFIGURED = 0x01
        QOS_CONFIGURED   = 0x02
        ENABLING         = 0x03
        STREAMING        = 0x04
        DISABLING        = 0x05
        RELEASING        = 0x06

    cis_link: Optional[device.CisLink] = None

    # Additional parameters in CODEC_CONFIGURED State
    preferred_framing = 0  # Unframed PDU supported
    preferred_phy = 0
    preferred_retransmission_number = 13
    preferred_max_transport_latency = 100
    supported_presentation_delay_min = 0
    supported_presentation_delay_max = 0
    preferred_presentation_delay_min = 0
    preferred_presentation_delay_max = 0
    codec_id = hci.CodingFormat(hci.CodecID.LC3)
    codec_specific_configuration: Union[CodecSpecificConfiguration, bytes] = b''

    # Additional parameters in QOS_CONFIGURED State
    cig_id = 0
    cis_id = 0
    sdu_interval = 0
    framing = 0
    phy = 0
    max_sdu = 0
    retransmission_number = 0
    max_transport_latency = 0
    presentation_delay = 0

    # Additional parameters in ENABLING, STREAMING, DISABLING State
    # TODO: Parse this
    metadata = b''

    def __init__(
        self,
        role: AudioRole,
        ase_id: int,
        service: AudioStreamControlService,
    ) -> None:
        self.service = service
        self.ase_id = ase_id
        self._state = AseStateMachine.State.IDLE
        self.role = role

        uuid = (
            gatt.GATT_SINK_ASE_CHARACTERISTIC
            if role == AudioRole.SINK
            else gatt.GATT_SOURCE_ASE_CHARACTERISTIC
        )
        super().__init__(
            uuid=uuid,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=gatt.CharacteristicValue(read=self.on_read),
        )

        self.service.device.on('cis_request', self.on_cis_request)
        self.service.device.on('cis_establishment', self.on_cis_establishment)

    def on_cis_request(
        self,
        acl_connection: device.Connection,
        cis_handle: int,
        cig_id: int,
        cis_id: int,
    ) -> None:
        if cis_id == self.cis_id and self.state == self.State.ENABLING:
            acl_connection.abort_on(
                'flush', self.service.device.accept_cis_request(cis_handle)
            )

    def on_cis_establishment(self, cis_link: device.CisLink) -> None:
        if cis_link.cis_id == self.cis_id and self.state == self.State.ENABLING:
            self.state = self.State.STREAMING
            self.cis_link = cis_link

            async def post_cis_established():
                await self.service.device.send_command(
                    hci.HCI_LE_Setup_ISO_Data_Path_Command(
                        connection_handle=cis_link.handle,
                        data_path_direction=self.role,
                        data_path_id=0x00,  # Fixed HCI
                        codec_id=hci.CodingFormat(hci.CodecID.TRANSPARENT),
                        controller_delay=0,
                        codec_configuration=b'',
                    )
                )
                await self.service.device.notify_subscribers(self, self.value)

            cis_link.acl_connection.abort_on('flush', post_cis_established())

    def on_config_codec(
        self,
        target_latency: int,
        target_phy: int,
        codec_id: hci.CodingFormat,
        codec_specific_configuration: bytes,
    ) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state not in (
            self.State.IDLE,
            self.State.CODEC_CONFIGURED,
            self.State.QOS_CONFIGURED,
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )

        self.max_transport_latency = target_latency
        self.phy = target_phy
        self.codec_id = codec_id
        if codec_id.codec_id == hci.CodecID.VENDOR_SPECIFIC:
            self.codec_specific_configuration = codec_specific_configuration
        else:
            self.codec_specific_configuration = CodecSpecificConfiguration.from_bytes(
                codec_specific_configuration
            )

        self.state = self.State.CODEC_CONFIGURED

        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_config_qos(
        self,
        cig_id: int,
        cis_id: int,
        sdu_interval: int,
        framing: int,
        phy: int,
        max_sdu: int,
        retransmission_number: int,
        max_transport_latency: int,
        presentation_delay: int,
    ) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state not in (
            AseStateMachine.State.CODEC_CONFIGURED,
            AseStateMachine.State.QOS_CONFIGURED,
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )

        self.cig_id = cig_id
        self.cis_id = cis_id
        self.sdu_interval = sdu_interval
        self.framing = framing
        self.phy = phy
        self.max_sdu = max_sdu
        self.retransmission_number = retransmission_number
        self.max_transport_latency = max_transport_latency
        self.presentation_delay = presentation_delay

        self.state = self.State.QOS_CONFIGURED

        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_enable(self, metadata: bytes) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state != AseStateMachine.State.QOS_CONFIGURED:
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )

        self.metadata = metadata
        self.state = self.State.ENABLING

        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_receiver_start_ready(self) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state != AseStateMachine.State.ENABLING:
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.state = self.State.STREAMING
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_disable(self) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state not in (
            AseStateMachine.State.ENABLING,
            AseStateMachine.State.STREAMING,
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.state = self.State.DISABLING
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_receiver_stop_ready(self) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state != AseStateMachine.State.DISABLING:
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.state = self.State.QOS_CONFIGURED
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_update_metadata(
        self, metadata: bytes
    ) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state not in (
            AseStateMachine.State.ENABLING,
            AseStateMachine.State.STREAMING,
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.metadata = metadata
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_release(self) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state == AseStateMachine.State.IDLE:
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.state = self.State.RELEASING

        async def remove_cis_async():
            await self.service.device.send_command(
                hci.HCI_LE_Remove_ISO_Data_Path_Command(
                    connection_handle=self.cis_link.handle,
                    data_path_direction=self.role,
                )
            )
            self.state = self.State.IDLE
            await self.service.device.notify_subscribers(self, self.value)

        self.service.device.abort_on('flush', remove_cis_async())
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    @property
    def state(self) -> State:
        return self._state

    @state.setter
    def state(self, new_state: State) -> None:
        logger.debug(f'{self} state change -> {colors.color(new_state.name, "cyan")}')
        self._state = new_state

    @property
    def value(self):
        '''Returns ASE_ID, ASE_STATE, and ASE Additional Parameters.'''

        if self.state == self.State.CODEC_CONFIGURED:
            codec_specific_configuration_bytes = bytes(
                self.codec_specific_configuration
            )
            additional_parameters = (
                struct.pack(
                    '<BBBH',
                    self.preferred_framing,
                    self.preferred_phy,
                    self.preferred_retransmission_number,
                    self.preferred_max_transport_latency,
                )
                + self.supported_presentation_delay_min.to_bytes(3, 'little')
                + self.supported_presentation_delay_max.to_bytes(3, 'little')
                + self.preferred_presentation_delay_min.to_bytes(3, 'little')
                + self.preferred_presentation_delay_max.to_bytes(3, 'little')
                + bytes(self.codec_id)
                + bytes([len(codec_specific_configuration_bytes)])
                + codec_specific_configuration_bytes
            )
        elif self.state == self.State.QOS_CONFIGURED:
            additional_parameters = (
                bytes([self.cig_id, self.cis_id])
                + self.sdu_interval.to_bytes(3, 'little')
                + struct.pack(
                    '<BBHBH',
                    self.framing,
                    self.phy,
                    self.max_sdu,
                    self.retransmission_number,
                    self.max_transport_latency,
                )
                + self.presentation_delay.to_bytes(3, 'little')
            )
        elif self.state in (
            self.State.ENABLING,
            self.State.STREAMING,
            self.State.DISABLING,
        ):
            additional_parameters = (
                bytes([self.cig_id, self.cis_id, len(self.metadata)]) + self.metadata
            )
        else:
            additional_parameters = b''

        return bytes([self.ase_id, self.state]) + additional_parameters

    @value.setter
    def value(self, _new_value):
        # Readonly. Do nothing in the setter.
        pass

    def on_read(self, _: Optional[device.Connection]) -> bytes:
        return self.value

    def __str__(self) -> str:
        return (
            f'AseStateMachine(id={self.ase_id}, role={self.role.name} '
            f'state={self._state.name})'
        )


class AudioStreamControlService(gatt.TemplateService):
    UUID = gatt.GATT_AUDIO_STREAM_CONTROL_SERVICE

    ase_state_machines: Dict[int, AseStateMachine]
    ase_control_point: gatt.Characteristic

    def __init__(
        self,
        device: device.Device,
        source_ase_id: Sequence[int] = [],
        sink_ase_id: Sequence[int] = [],
    ) -> None:
        self.device = device
        self.ase_state_machines = {
            **{
                id: AseStateMachine(role=AudioRole.SINK, ase_id=id, service=self)
                for id in sink_ase_id
            },
            **{
                id: AseStateMachine(role=AudioRole.SOURCE, ase_id=id, service=self)
                for id in source_ase_id
            },
        }  # ASE state machines, by ASE ID

        self.ase_control_point = gatt.Characteristic(
            uuid=gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.WRITEABLE,
            value=gatt.CharacteristicValue(write=self.on_write_ase_control_point),
        )

        super().__init__([self.ase_control_point, *self.ase_state_machines.values()])

    def on_operation(self, opcode: ASE_Operation.Opcode, ase_id: int, args):
        if ase := self.ase_state_machines.get(ase_id):
            handler = getattr(ase, 'on_' + opcode.name.lower())
            return (ase_id, *handler(*args))
        else:
            return (ase_id, AseResponseCode.INVALID_ASE_ID, AseReasonCode.NONE)

    def on_write_ase_control_point(self, connection, data):
        operation = ASE_Operation.from_bytes(data)
        responses = []
        logger.debug(f'*** ASCS Write {operation} ***')

        if operation.op_code == ASE_Operation.Opcode.CONFIG_CODEC:
            for ase_id, *args in zip(
                operation.ase_id,
                operation.target_latency,
                operation.target_phy,
                operation.codec_id,
                operation.codec_specific_configuration,
            ):
                responses.append(self.on_operation(operation.op_code, ase_id, args))
        elif operation.op_code == ASE_Operation.Opcode.CONFIG_QOS:
            for ase_id, *args in zip(
                operation.ase_id,
                operation.cig_id,
                operation.cis_id,
                operation.sdu_interval,
                operation.framing,
                operation.phy,
                operation.max_sdu,
                operation.retransmission_number,
                operation.max_transport_latency,
                operation.presentation_delay,
            ):
                responses.append(self.on_operation(operation.op_code, ase_id, args))
        elif operation.op_code in (
            ASE_Operation.Opcode.ENABLE,
            ASE_Operation.Opcode.UPDATE_METADATA,
        ):
            for ase_id, *args in zip(
                operation.ase_id,
                operation.metadata,
            ):
                responses.append(self.on_operation(operation.op_code, ase_id, args))
        elif operation.op_code in (
            ASE_Operation.Opcode.RECEIVER_START_READY,
            ASE_Operation.Opcode.DISABLE,
            ASE_Operation.Opcode.RECEIVER_STOP_READY,
            ASE_Operation.Opcode.RELEASE,
        ):
            for ase_id in operation.ase_id:
                responses.append(self.on_operation(operation.op_code, ase_id, []))

        control_point_notification = bytes(
            [operation.op_code, len(responses)]
        ) + b''.join(map(bytes, responses))
        self.device.abort_on(
            'flush',
            self.device.notify_subscribers(
                self.ase_control_point, control_point_notification
            ),
        )

        for ase_id, *_ in responses:
            if ase := self.ase_state_machines.get(ase_id):
                self.device.abort_on(
                    'flush',
                    self.device.notify_subscribers(ase, ase.value),
                )


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


class AudioStreamControlServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = AudioStreamControlService

    sink_ase: List[gatt_client.CharacteristicProxy]
    source_ase: List[gatt_client.CharacteristicProxy]
    ase_control_point: gatt_client.CharacteristicProxy

    def __init__(self, service_proxy: gatt_client.ServiceProxy):
        self.service_proxy = service_proxy

        self.sink_ase = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SINK_ASE_CHARACTERISTIC
        )
        self.source_ase = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SOURCE_ASE_CHARACTERISTIC
        )
        self.ase_control_point = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC
        )[0]
