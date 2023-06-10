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
            raise ValueError('maximum read size is 32')

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
            raise ValueError('trying to read past the data')
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
            raise ValueError('not enough data')

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
class AacAudioRtpPacket:
    """AAC payload encapsulated in an RTP packet payload"""

    @staticmethod
    def latm_value(reader: BitReader) -> int:
        bytes_for_value = reader.read(2)
        value = 0
        for _ in range(bytes_for_value + 1):
            value = value * 256 + reader.read(8)
        return value

    @staticmethod
    def program_config_element(reader: BitReader):
        raise ValueError('program_config_element not supported')

    @dataclass
    class GASpecificConfig:
        def __init__(
            self, reader: BitReader, channel_configuration: int, audio_object_type: int
        ) -> None:
            # GASpecificConfig - ISO/EIC 14496-3 Table 4.1
            frame_length_flag = reader.read(1)
            depends_on_core_coder = reader.read(1)
            if depends_on_core_coder:
                self.core_coder_delay = reader.read(14)
            extension_flag = reader.read(1)
            if not channel_configuration:
                AacAudioRtpPacket.program_config_element(reader)
            if audio_object_type in (6, 20):
                self.layer_nr = reader.read(3)
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
                    raise ValueError('extensionFlag3 == 1 not supported')

    @staticmethod
    def audio_object_type(reader: BitReader):
        # GetAudioObjectType - ISO/EIC 14496-3 Table 1.16
        audio_object_type = reader.read(5)
        if audio_object_type == 31:
            audio_object_type = 32 + reader.read(6)

        return audio_object_type

    @dataclass
    class AudioSpecificConfig:
        audio_object_type: int
        sampling_frequency_index: int
        sampling_frequency: int
        channel_configuration: int
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

        def __init__(self, reader: BitReader) -> None:
            # AudioSpecificConfig - ISO/EIC 14496-3 Table 1.15
            self.audio_object_type = AacAudioRtpPacket.audio_object_type(reader)
            self.sampling_frequency_index = reader.read(4)
            if self.sampling_frequency_index == 0xF:
                self.sampling_frequency = reader.read(24)
            else:
                self.sampling_frequency = self.SAMPLING_FREQUENCIES[
                    self.sampling_frequency_index
                ]
            self.channel_configuration = reader.read(4)
            self.sbr_present_flag = -1
            self.ps_present_flag = -1
            if self.audio_object_type in (5, 29):
                self.extension_audio_object_type = 5
                self.sbc_present_flag = 1
                if self.audio_object_type == 29:
                    self.ps_present_flag = 1
                self.extension_sampling_frequency_index = reader.read(4)
                if self.extension_sampling_frequency_index == 0xF:
                    self.extension_sampling_frequency = reader.read(24)
                else:
                    self.extension_sampling_frequency = self.SAMPLING_FREQUENCIES[
                        self.extension_sampling_frequency_index
                    ]
                self.audio_object_type = AacAudioRtpPacket.audio_object_type(reader)
                if self.audio_object_type == 22:
                    self.extension_channel_configuration = reader.read(4)
            else:
                self.extension_audio_object_type = 0

            if self.audio_object_type in (1, 2, 3, 4, 6, 7, 17, 19, 20, 21, 22, 23):
                ga_specific_config = AacAudioRtpPacket.GASpecificConfig(
                    reader, self.channel_configuration, self.audio_object_type
                )
            else:
                raise ValueError(
                    f'audioObjectType {self.audio_object_type} not supported'
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

    @dataclass
    class StreamMuxConfig:
        other_data_present: int
        other_data_len_bits: int
        audio_specific_config: AacAudioRtpPacket.AudioSpecificConfig

        def __init__(self, reader: BitReader) -> None:
            # StreamMuxConfig - ISO/EIC 14496-3 Table 1.42
            audio_mux_version = reader.read(1)
            if audio_mux_version == 1:
                audio_mux_version_a = reader.read(1)
            else:
                audio_mux_version_a = 0
            if audio_mux_version_a != 0:
                raise ValueError('audioMuxVersionA != 0 not supported')
            if audio_mux_version == 1:
                tara_buffer_fullness = AacAudioRtpPacket.latm_value(reader)
            stream_cnt = 0
            all_streams_same_time_framing = reader.read(1)
            num_sub_frames = reader.read(6)
            num_program = reader.read(4)
            if num_program != 0:
                raise ValueError('num_program != 0 not supported')
            num_layer = reader.read(3)
            if num_layer != 0:
                raise ValueError('num_layer != 0 not supported')
            if audio_mux_version == 0:
                self.audio_specific_config = AacAudioRtpPacket.AudioSpecificConfig(
                    reader
                )
            else:
                asc_len = AacAudioRtpPacket.latm_value(reader)
                marker = reader.bit_position
                self.audio_specific_config = AacAudioRtpPacket.AudioSpecificConfig(
                    reader
                )
                audio_specific_config_len = reader.bit_position - marker
                if asc_len < audio_specific_config_len:
                    raise ValueError('audio_specific_config_len > asc_len')
                asc_len -= audio_specific_config_len
                reader.skip(asc_len)
            frame_length_type = reader.read(3)
            if frame_length_type == 0:
                latm_buffer_fullness = reader.read(8)
            elif frame_length_type == 1:
                frame_length = reader.read(9)
            else:
                raise ValueError(f'frame_length_type {frame_length_type} not supported')

            self.other_data_present = reader.read(1)
            if self.other_data_present:
                if audio_mux_version == 1:
                    self.other_data_len_bits = AacAudioRtpPacket.latm_value(reader)
                else:
                    self.other_data_len_bits = 0
                    while True:
                        self.other_data_len_bits *= 256
                        other_data_len_esc = reader.read(1)
                        self.other_data_len_bits += reader.read(8)
                        if other_data_len_esc == 0:
                            break
            crc_check_present = reader.read(1)
            if crc_check_present:
                crc_checksum = reader.read(8)

    @dataclass
    class AudioMuxElement:
        payload: bytes
        stream_mux_config: AacAudioRtpPacket.StreamMuxConfig

        def __init__(self, reader: BitReader, mux_config_present: int):
            if mux_config_present == 0:
                raise ValueError('muxConfigPresent == 0 not supported')

            # AudioMuxElement - ISO/EIC 14496-3 Table 1.41
            use_same_stream_mux = reader.read(1)
            if use_same_stream_mux:
                raise ValueError('useSameStreamMux == 1 not supported')
            self.stream_mux_config = AacAudioRtpPacket.StreamMuxConfig(reader)

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

            self.payload = reader.read_bytes(mux_slot_length_bytes)

            if self.stream_mux_config.other_data_present:
                reader.skip(self.stream_mux_config.other_data_len_bits)

            # ByteAlign
            while reader.bit_position % 8:
                reader.read(1)

    def __init__(self, data: bytes) -> None:
        # Parse the bit stream
        reader = BitReader(data)
        self.audio_mux_element = self.AudioMuxElement(reader, mux_config_present=1)

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
