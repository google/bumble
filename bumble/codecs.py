# Copyright 2023 Google LLC
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
from dataclasses import dataclass
from typing_extensions import Self

from bumble import core


# -----------------------------------------------------------------------------
class BitReader:
    """Simple but not optimized bit stream reader."""

    data: bytes
    bytes_position: int
    bit_position: int
    cache: int
    bits_cached: int

    def __init__(self, data: bytes):
        self.data = data
        self.byte_position = 0
        self.bit_position = 0
        self.cache = 0
        self.bits_cached = 0

    def read(self, bits: int) -> int:
        """ "Read up to 32 bits."""

        if bits > 32:
            raise core.InvalidArgumentError('maximum read size is 32')

        if self.bits_cached >= bits:
            # We have enough bits.
            self.bits_cached -= bits
            self.bit_position += bits
            return (self.cache >> self.bits_cached) & ((1 << bits) - 1)

        # Read more cache, up to 32 bits
        feed_bytes = self.data[self.byte_position : self.byte_position + 4]
        feed_size = len(feed_bytes)
        feed_int = int.from_bytes(feed_bytes, byteorder='big')
        if 8 * feed_size + self.bits_cached < bits:
            raise core.InvalidArgumentError('trying to read past the data')
        self.byte_position += feed_size

        # Combine the new cache and the old cache
        cache = self.cache & ((1 << self.bits_cached) - 1)
        new_bits = bits - self.bits_cached
        self.bits_cached = 8 * feed_size - new_bits
        result = (feed_int >> self.bits_cached) | (cache << new_bits)
        self.cache = feed_int

        self.bit_position += bits
        return result

    def read_bytes(self, count: int):
        if self.bit_position + 8 * count > 8 * len(self.data):
            raise core.InvalidArgumentError('not enough data')

        if self.bit_position % 8:
            # Not byte aligned
            result = bytearray(count)
            for i in range(count):
                result[i] = self.read(8)
            return bytes(result)

        # Byte aligned
        self.byte_position = self.bit_position // 8
        self.bits_cached = 0
        self.cache = 0
        offset = self.bit_position // 8
        self.bit_position += 8 * count
        return self.data[offset : offset + count]

    def bits_left(self) -> int:
        return (8 * len(self.data)) - self.bit_position

    def skip(self, bits: int) -> None:
        # Slow, but simple...
        while bits:
            if bits > 32:
                self.read(32)
                bits -= 32
            else:
                self.read(bits)
                break


# -----------------------------------------------------------------------------
class BitWriter:
    """Simple but not optimized bit stream writer."""

    data: int
    bit_count: int

    def __init__(self) -> None:
        self.data = 0
        self.bit_count = 0

    def write(self, value: int, bit_count: int) -> None:
        self.data = (self.data << bit_count) | value
        self.bit_count += bit_count

    def write_bytes(self, data: bytes) -> None:
        bit_count = 8 * len(data)
        self.data = (self.data << bit_count) | int.from_bytes(data, 'big')
        self.bit_count += bit_count

    def __bytes__(self) -> bytes:
        return (self.data << ((8 - (self.bit_count % 8)) % 8)).to_bytes(
            (self.bit_count + 7) // 8, 'big'
        )


# -----------------------------------------------------------------------------
class AacAudioRtpPacket:
    """AAC payload encapsulated in an RTP packet payload"""

    audio_mux_element: AudioMuxElement

    @staticmethod
    def read_latm_value(reader: BitReader) -> int:
        bytes_for_value = reader.read(2)
        value = 0
        for _ in range(bytes_for_value + 1):
            value = value * 256 + reader.read(8)
        return value

    @staticmethod
    def read_audio_object_type(reader: BitReader):
        # GetAudioObjectType - ISO/EIC 14496-3 Table 1.16
        audio_object_type = reader.read(5)
        if audio_object_type == 31:
            audio_object_type = 32 + reader.read(6)

        return audio_object_type

    @dataclass
    class GASpecificConfig:
        audio_object_type: int
        # NOTE: other fields not supported

        @classmethod
        def from_bits(
            cls, reader: BitReader, channel_configuration: int, audio_object_type: int
        ) -> Self:
            # GASpecificConfig - ISO/EIC 14496-3 Table 4.1
            frame_length_flag = reader.read(1)
            depends_on_core_coder = reader.read(1)
            if depends_on_core_coder:
                core_coder_delay = reader.read(14)
            extension_flag = reader.read(1)
            if not channel_configuration:
                raise core.InvalidPacketError('program_config_element not supported')
            if audio_object_type in (6, 20):
                layer_nr = reader.read(3)
            if extension_flag:
                if audio_object_type == 22:
                    num_of_sub_frame = reader.read(5)
                layer_length = reader.read(11)
                if audio_object_type in (17, 19, 20, 23):
                    aac_section_data_resilience_flags = reader.read(1)
                    aac_scale_factor_data_resilience_flags = reader.read(1)
                    aac_spectral_data_resilience_flags = reader.read(1)
                extension_flag_3 = reader.read(1)
                if extension_flag_3 == 1:
                    raise core.InvalidPacketError('extensionFlag3 == 1 not supported')

            return cls(audio_object_type)

        def to_bits(self, writer: BitWriter) -> None:
            assert self.audio_object_type in (1, 2)
            writer.write(0, 1)  # frame_length_flag = 0
            writer.write(0, 1)  # depends_on_core_coder = 0
            writer.write(0, 1)  # extension_flag = 0

    @dataclass
    class AudioSpecificConfig:
        audio_object_type: int
        sampling_frequency_index: int
        sampling_frequency: int
        channel_configuration: int
        ga_specific_config: AacAudioRtpPacket.GASpecificConfig
        sbr_present_flag: int
        ps_present_flag: int
        extension_audio_object_type: int
        extension_sampling_frequency_index: int
        extension_sampling_frequency: int
        extension_channel_configuration: int

        SAMPLING_FREQUENCIES = [
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
        ]

        @classmethod
        def for_simple_aac(
            cls,
            audio_object_type: int,
            sampling_frequency: int,
            channel_configuration: int,
        ) -> Self:
            if sampling_frequency not in cls.SAMPLING_FREQUENCIES:
                raise ValueError(f'invalid sampling frequency {sampling_frequency}')

            ga_specific_config = AacAudioRtpPacket.GASpecificConfig(audio_object_type)

            return cls(
                audio_object_type=audio_object_type,
                sampling_frequency_index=cls.SAMPLING_FREQUENCIES.index(
                    sampling_frequency
                ),
                sampling_frequency=sampling_frequency,
                channel_configuration=channel_configuration,
                ga_specific_config=ga_specific_config,
                sbr_present_flag=0,
                ps_present_flag=0,
                extension_audio_object_type=0,
                extension_sampling_frequency_index=0,
                extension_sampling_frequency=0,
                extension_channel_configuration=0,
            )

        @classmethod
        def from_bits(cls, reader: BitReader) -> Self:
            # AudioSpecificConfig - ISO/EIC 14496-3 Table 1.15
            audio_object_type = AacAudioRtpPacket.read_audio_object_type(reader)
            sampling_frequency_index = reader.read(4)
            if sampling_frequency_index == 0xF:
                sampling_frequency = reader.read(24)
            else:
                sampling_frequency = cls.SAMPLING_FREQUENCIES[sampling_frequency_index]
            channel_configuration = reader.read(4)
            sbr_present_flag = 0
            ps_present_flag = 0
            extension_sampling_frequency_index = 0
            extension_sampling_frequency = 0
            extension_channel_configuration = 0
            extension_audio_object_type = 0
            if audio_object_type in (5, 29):
                extension_audio_object_type = 5
                sbr_present_flag = 1
                if audio_object_type == 29:
                    ps_present_flag = 1
                extension_sampling_frequency_index = reader.read(4)
                if extension_sampling_frequency_index == 0xF:
                    extension_sampling_frequency = reader.read(24)
                else:
                    extension_sampling_frequency = cls.SAMPLING_FREQUENCIES[
                        extension_sampling_frequency_index
                    ]
                audio_object_type = AacAudioRtpPacket.read_audio_object_type(reader)
                if audio_object_type == 22:
                    extension_channel_configuration = reader.read(4)

            if audio_object_type in (1, 2, 3, 4, 6, 7, 17, 19, 20, 21, 22, 23):
                ga_specific_config = AacAudioRtpPacket.GASpecificConfig.from_bits(
                    reader, channel_configuration, audio_object_type
                )
            else:
                raise core.InvalidPacketError(
                    f'audioObjectType {audio_object_type} not supported'
                )

            # if self.extension_audio_object_type != 5 and bits_to_decode >= 16:
            #     sync_extension_type = reader.read(11)
            #     if sync_extension_type == 0x2B7:
            #         self.extension_audio_object_type = AacAudioRtpPacket.audio_object_type(reader)
            #         if self.extension_audio_object_type == 5:
            #             self.sbr_present_flag = reader.read(1)
            #             if self.sbr_present_flag:
            #                 self.extension_sampling_frequency_index = reader.read(4)
            #                 if self.extension_sampling_frequency_index == 0xF:
            #                     self.extension_sampling_frequency = reader.read(24)
            #                 else:
            #                     self.extension_sampling_frequency = self.SAMPLING_FREQUENCIES[self.extension_sampling_frequency_index]
            #                 if bits_to_decode >= 12:
            #                     sync_extension_type = reader.read(11)
            #                     if sync_extension_type == 0x548:
            #                         self.ps_present_flag = reader.read(1)
            #         elif self.extension_audio_object_type == 22:
            #             self.sbr_present_flag = reader.read(1)
            #             if self.sbr_present_flag:
            #                 self.extension_sampling_frequency_index = reader.read(4)
            #                 if self.extension_sampling_frequency_index == 0xF:
            #                     self.extension_sampling_frequency = reader.read(24)
            #                 else:
            #                     self.extension_sampling_frequency = self.SAMPLING_FREQUENCIES[self.extension_sampling_frequency_index]
            #             self.extension_channel_configuration = reader.read(4)

            return cls(
                audio_object_type,
                sampling_frequency_index,
                sampling_frequency,
                channel_configuration,
                ga_specific_config,
                sbr_present_flag,
                ps_present_flag,
                extension_audio_object_type,
                extension_sampling_frequency_index,
                extension_sampling_frequency,
                extension_channel_configuration,
            )

        def to_bits(self, writer: BitWriter) -> None:
            if self.sampling_frequency_index >= 15:
                raise ValueError(
                    f"unsupported sampling frequency index {self.sampling_frequency_index}"
                )

            if self.audio_object_type not in (1, 2):
                raise ValueError(
                    f"unsupported audio object type {self.audio_object_type} "
                )

            writer.write(self.audio_object_type, 5)
            writer.write(self.sampling_frequency_index, 4)
            writer.write(self.channel_configuration, 4)
            self.ga_specific_config.to_bits(writer)

    @dataclass
    class StreamMuxConfig:
        other_data_present: int
        other_data_len_bits: int
        audio_specific_config: AacAudioRtpPacket.AudioSpecificConfig

        @classmethod
        def from_bits(cls, reader: BitReader) -> Self:
            # StreamMuxConfig - ISO/EIC 14496-3 Table 1.42
            audio_mux_version = reader.read(1)
            if audio_mux_version == 1:
                audio_mux_version_a = reader.read(1)
            else:
                audio_mux_version_a = 0
            if audio_mux_version_a != 0:
                raise core.InvalidPacketError('audioMuxVersionA != 0 not supported')
            if audio_mux_version == 1:
                tara_buffer_fullness = AacAudioRtpPacket.read_latm_value(reader)
            stream_cnt = 0
            all_streams_same_time_framing = reader.read(1)
            num_sub_frames = reader.read(6)
            num_program = reader.read(4)
            if num_program != 0:
                raise core.InvalidPacketError('num_program != 0 not supported')
            num_layer = reader.read(3)
            if num_layer != 0:
                raise core.InvalidPacketError('num_layer != 0 not supported')
            if audio_mux_version == 0:
                audio_specific_config = AacAudioRtpPacket.AudioSpecificConfig.from_bits(
                    reader
                )
            else:
                asc_len = AacAudioRtpPacket.read_latm_value(reader)
                marker = reader.bit_position
                audio_specific_config = AacAudioRtpPacket.AudioSpecificConfig.from_bits(
                    reader
                )
                audio_specific_config_len = reader.bit_position - marker
                if asc_len < audio_specific_config_len:
                    raise core.InvalidPacketError('audio_specific_config_len > asc_len')
                asc_len -= audio_specific_config_len
                reader.skip(asc_len)
            frame_length_type = reader.read(3)
            if frame_length_type == 0:
                latm_buffer_fullness = reader.read(8)
            elif frame_length_type == 1:
                frame_length = reader.read(9)
            else:
                raise core.InvalidPacketError(
                    f'frame_length_type {frame_length_type} not supported'
                )

            other_data_present = reader.read(1)
            other_data_len_bits = 0
            if other_data_present:
                if audio_mux_version == 1:
                    other_data_len_bits = AacAudioRtpPacket.read_latm_value(reader)
                else:
                    while True:
                        other_data_len_bits *= 256
                        other_data_len_esc = reader.read(1)
                        other_data_len_bits += reader.read(8)
                        if other_data_len_esc == 0:
                            break
            crc_check_present = reader.read(1)
            if crc_check_present:
                crc_checksum = reader.read(8)

            return cls(other_data_present, other_data_len_bits, audio_specific_config)

        def to_bits(self, writer: BitWriter) -> None:
            writer.write(0, 1)  # audioMuxVersion = 0
            writer.write(1, 1)  # allStreamsSameTimeFraming = 1
            writer.write(0, 6)  # numSubFrames = 0
            writer.write(0, 4)  # numProgram = 0
            writer.write(0, 3)  # numLayer = 0
            self.audio_specific_config.to_bits(writer)
            writer.write(0, 3)  # frameLengthType = 0
            writer.write(0, 8)  # latmBufferFullness = 0
            writer.write(0, 1)  # otherDataPresent = 0
            writer.write(0, 1)  # crcCheckPresent = 0

    @dataclass
    class AudioMuxElement:
        stream_mux_config: AacAudioRtpPacket.StreamMuxConfig
        payload: bytes

        @classmethod
        def from_bits(cls, reader: BitReader) -> Self:
            # AudioMuxElement - ISO/EIC 14496-3 Table 1.41
            # (only supports mux_config_present=1)
            use_same_stream_mux = reader.read(1)
            if use_same_stream_mux:
                raise core.InvalidPacketError('useSameStreamMux == 1 not supported')
            stream_mux_config = AacAudioRtpPacket.StreamMuxConfig.from_bits(reader)

            # We only support:
            # allStreamsSameTimeFraming == 1
            # audioMuxVersionA == 0,
            # numProgram == 0
            # numSubFrames == 0
            # numLayer == 0

            mux_slot_length_bytes = 0
            while True:
                tmp = reader.read(8)
                mux_slot_length_bytes += tmp
                if tmp != 255:
                    break

            payload = reader.read_bytes(mux_slot_length_bytes)

            if stream_mux_config.other_data_present:
                reader.skip(stream_mux_config.other_data_len_bits)

            # ByteAlign
            while reader.bit_position % 8:
                reader.read(1)

            return cls(stream_mux_config, payload)

        def to_bits(self, writer: BitWriter) -> None:
            writer.write(0, 1)  # useSameStreamMux = 0
            self.stream_mux_config.to_bits(writer)
            mux_slot_length_bytes = len(self.payload)
            while mux_slot_length_bytes > 255:
                writer.write(255, 8)
                mux_slot_length_bytes -= 255
            writer.write(mux_slot_length_bytes, 8)
            if mux_slot_length_bytes == 255:
                writer.write(0, 8)
            writer.write_bytes(self.payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        # Parse the bit stream
        reader = BitReader(data)
        return cls(cls.AudioMuxElement.from_bits(reader))

    @classmethod
    def for_simple_aac(
        cls, sampling_frequency: int, channel_configuration: int, payload: bytes
    ) -> Self:
        audio_specific_config = cls.AudioSpecificConfig.for_simple_aac(
            2, sampling_frequency, channel_configuration
        )
        stream_mux_config = cls.StreamMuxConfig(0, 0, audio_specific_config)
        audio_mux_element = cls.AudioMuxElement(stream_mux_config, payload)

        return cls(audio_mux_element)

    def to_adts(self):
        # pylint: disable=line-too-long
        sampling_frequency_index = (
            self.audio_mux_element.stream_mux_config.audio_specific_config.sampling_frequency_index
        )
        channel_configuration = (
            self.audio_mux_element.stream_mux_config.audio_specific_config.channel_configuration
        )
        frame_size = len(self.audio_mux_element.payload)
        return (
            bytes(
                [
                    0xFF,
                    0xF1,  # 0xF9 (MPEG2)
                    0x40
                    | (sampling_frequency_index << 2)
                    | (channel_configuration >> 2),
                    ((channel_configuration & 0x3) << 6) | ((frame_size + 7) >> 11),
                    ((frame_size + 7) >> 3) & 0xFF,
                    (((frame_size + 7) << 5) & 0xFF) | 0x1F,
                    0xFC,
                ]
            )
            + self.audio_mux_element.payload
        )

    def __init__(self, audio_mux_element: AudioMuxElement) -> None:
        self.audio_mux_element = audio_mux_element

    def __bytes__(self) -> bytes:
        writer = BitWriter()
        self.audio_mux_element.to_bits(writer)
        return bytes(writer)
