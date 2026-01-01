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
import asyncio
import logging
import os
import struct
from collections.abc import Awaitable

import pytest

from bumble import a2dp, avdtp
from bumble.controller import Controller
from bumble.core import PhysicalTransport
from bumble.device import Device
from bumble.host import Host
from bumble.link import LocalLink
from bumble.rtp import MediaPacket
from bumble.transport.common import AsyncPipeSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class TwoDevices:
    def __init__(self):
        self.connections = [None, None]

        addresses = ['F0:F1:F2:F3:F4:F5', 'F5:F4:F3:F2:F1:F0']
        self.link = LocalLink()
        self.controllers = [
            Controller('C1', link=self.link, public_address=addresses[0]),
            Controller('C2', link=self.link, public_address=addresses[1]),
        ]
        self.devices = [
            Device(
                address=addresses[0],
                host=Host(self.controllers[0], AsyncPipeSink(self.controllers[0])),
            ),
            Device(
                address=addresses[1],
                host=Host(self.controllers[1], AsyncPipeSink(self.controllers[1])),
            ),
        ]

        self.paired = [None, None]

    def on_connection(self, which, connection):
        self.connections[which] = connection

    def on_paired(self, which, keys):
        self.paired[which] = keys


# -----------------------------------------------------------------------------
class Data:
    pointer: int = 0
    data: bytes

    def __init__(self, data: bytes):
        self.data = data

    async def read(self, length: int) -> Awaitable[bytes]:
        def generate_read():
            end = min(self.pointer + length, len(self.data))
            chunk = self.data[self.pointer : end]
            self.pointer = end
            return chunk

        return generate_read()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_connection():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Attach listeners
    two_devices.devices[0].on(
        'connection', lambda connection: two_devices.on_connection(0, connection)
    )
    two_devices.devices[1].on(
        'connection', lambda connection: two_devices.on_connection(1, connection)
    )

    # Enable Classic connections
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=PhysicalTransport.BR_EDR
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    # Check the post conditions
    assert two_devices.connections[0] is not None
    assert two_devices.connections[1] is not None


# -----------------------------------------------------------------------------
def source_codec_capabilities():
    return avdtp.MediaCodecCapabilities(
        media_type=avdtp.MediaType.AUDIO,
        media_codec_type=a2dp.CodecType.SBC,
        media_codec_information=a2dp.SbcMediaCodecInformation(
            sampling_frequency=a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_44100,
            channel_mode=a2dp.SbcMediaCodecInformation.ChannelMode.JOINT_STEREO,
            block_length=a2dp.SbcMediaCodecInformation.BlockLength.BL_16,
            subbands=a2dp.SbcMediaCodecInformation.Subbands.S_8,
            allocation_method=a2dp.SbcMediaCodecInformation.AllocationMethod.LOUDNESS,
            minimum_bitpool_value=2,
            maximum_bitpool_value=53,
        ),
    )


# -----------------------------------------------------------------------------
def sink_codec_capabilities():
    return avdtp.MediaCodecCapabilities(
        media_type=avdtp.MediaType.AUDIO,
        media_codec_type=a2dp.CodecType.SBC,
        media_codec_information=a2dp.SbcMediaCodecInformation(
            sampling_frequency=a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_48000
            | a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_44100
            | a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_32000
            | a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_16000,
            channel_mode=a2dp.SbcMediaCodecInformation.ChannelMode.MONO
            | a2dp.SbcMediaCodecInformation.ChannelMode.DUAL_CHANNEL
            | a2dp.SbcMediaCodecInformation.ChannelMode.STEREO
            | a2dp.SbcMediaCodecInformation.ChannelMode.JOINT_STEREO,
            block_length=a2dp.SbcMediaCodecInformation.BlockLength.BL_4
            | a2dp.SbcMediaCodecInformation.BlockLength.BL_8
            | a2dp.SbcMediaCodecInformation.BlockLength.BL_12
            | a2dp.SbcMediaCodecInformation.BlockLength.BL_16,
            subbands=a2dp.SbcMediaCodecInformation.Subbands.S_4
            | a2dp.SbcMediaCodecInformation.Subbands.S_8,
            allocation_method=a2dp.SbcMediaCodecInformation.AllocationMethod.LOUDNESS
            | a2dp.SbcMediaCodecInformation.AllocationMethod.SNR,
            minimum_bitpool_value=2,
            maximum_bitpool_value=53,
        ),
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_source_sink_1():
    two_devices = TwoDevices()
    # Enable Classic connections
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    def on_rtp_packet(packet):
        rtp_packets.append(packet)
        if len(rtp_packets) == rtp_packets_expected:
            rtp_packets_fully_received.set_result(None)

    sink = None

    def on_avdtp_connection(server):
        nonlocal sink
        sink = server.add_sink(sink_codec_capabilities())
        sink.on('rtp_packet', on_rtp_packet)

    # Create a listener to wait for AVDTP connections
    listener = avdtp.Listener.for_device(two_devices.devices[1])
    listener.on('connection', on_avdtp_connection)

    async def make_connection():
        connections = await asyncio.gather(
            two_devices.devices[0].connect(
                two_devices.devices[1].public_address, PhysicalTransport.BR_EDR
            ),
            two_devices.devices[1].accept(two_devices.devices[0].public_address),
        )
        return connections[0]

    connection = await make_connection()
    client = await avdtp.Protocol.connect(connection)
    endpoints = await client.discover_remote_endpoints()
    assert len(endpoints) == 1
    remote_sink = list(endpoints)[0]
    assert remote_sink.in_use == 0
    assert remote_sink.media_type == avdtp.MediaType.AUDIO
    assert remote_sink.tsep == avdtp.StreamEndPointType.SNK

    async def generate_packets(packet_count):
        sequence_number = 0
        timestamp = 0
        for i in range(packet_count):
            payload = bytes([sequence_number % 256])
            packet = MediaPacket(
                2, 0, 0, 0, sequence_number, timestamp, 0, [], 96, payload
            )
            packet.timestamp_seconds = timestamp / 44100
            timestamp += 10
            sequence_number += 1
            yield packet

    # Send packets using a pump object
    rtp_packets_fully_received = asyncio.get_running_loop().create_future()
    rtp_packets_expected = 3
    rtp_packets = []
    pump = avdtp.MediaPacketPump(generate_packets(3))
    source = client.add_source(source_codec_capabilities(), pump)
    stream = await client.create_stream(source, remote_sink)
    await stream.start()
    assert stream.state == avdtp.State.STREAMING
    assert stream.local_endpoint.in_use == 1
    assert stream.rtp_channel is not None
    assert sink.in_use == 1
    assert sink.stream is not None
    assert sink.stream.state == avdtp.State.STREAMING
    await rtp_packets_fully_received

    await stream.close()
    assert stream.rtp_channel is None
    assert source.in_use == 0
    assert source.stream.state == avdtp.State.IDLE
    assert sink.in_use == 0
    assert sink.stream.state == avdtp.State.IDLE

    # Send packets manually
    rtp_packets_fully_received = asyncio.get_running_loop().create_future()
    rtp_packets_expected = 3
    rtp_packets = []
    source_packets = [
        MediaPacket(2, 0, 0, 0, i, i * 10, 0, [], 96, bytes([i])) for i in range(3)
    ]
    source = client.add_source(source_codec_capabilities(), None)
    stream = await client.create_stream(source, remote_sink)
    await stream.start()
    assert stream.state == avdtp.State.STREAMING
    assert stream.local_endpoint.in_use == 1
    assert stream.rtp_channel is not None
    assert sink.in_use == 1
    assert sink.stream is not None
    assert sink.stream.state == avdtp.State.STREAMING

    stream.send_media_packet(source_packets[0])
    stream.send_media_packet(source_packets[1])
    stream.send_media_packet(source_packets[2])

    await stream.close()
    assert stream.rtp_channel is None
    assert len(rtp_packets) == 3
    assert source.in_use == 0
    assert source.stream.state == avdtp.State.IDLE
    assert sink.in_use == 0
    assert sink.stream.state == avdtp.State.IDLE


# -----------------------------------------------------------------------------
def test_sbc_codec_specific_information():
    sbc_info = a2dp.SbcMediaCodecInformation.from_bytes(bytes.fromhex("3fff0235"))
    assert (
        sbc_info.sampling_frequency
        == a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_44100
        | a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_48000
    )
    assert (
        sbc_info.channel_mode
        == a2dp.SbcMediaCodecInformation.ChannelMode.MONO
        | a2dp.SbcMediaCodecInformation.ChannelMode.DUAL_CHANNEL
        | a2dp.SbcMediaCodecInformation.ChannelMode.STEREO
        | a2dp.SbcMediaCodecInformation.ChannelMode.JOINT_STEREO
    )
    assert (
        sbc_info.block_length
        == a2dp.SbcMediaCodecInformation.BlockLength.BL_4
        | a2dp.SbcMediaCodecInformation.BlockLength.BL_8
        | a2dp.SbcMediaCodecInformation.BlockLength.BL_12
        | a2dp.SbcMediaCodecInformation.BlockLength.BL_16
    )
    assert (
        sbc_info.subbands
        == a2dp.SbcMediaCodecInformation.Subbands.S_4
        | a2dp.SbcMediaCodecInformation.Subbands.S_8
    )
    assert (
        sbc_info.allocation_method
        == a2dp.SbcMediaCodecInformation.AllocationMethod.SNR
        | a2dp.SbcMediaCodecInformation.AllocationMethod.LOUDNESS
    )
    assert sbc_info.minimum_bitpool_value == 2
    assert sbc_info.maximum_bitpool_value == 53

    sbc_info2 = a2dp.SbcMediaCodecInformation(
        a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_44100
        | a2dp.SbcMediaCodecInformation.SamplingFrequency.SF_48000,
        a2dp.SbcMediaCodecInformation.ChannelMode.MONO
        | a2dp.SbcMediaCodecInformation.ChannelMode.DUAL_CHANNEL
        | a2dp.SbcMediaCodecInformation.ChannelMode.STEREO
        | a2dp.SbcMediaCodecInformation.ChannelMode.JOINT_STEREO,
        a2dp.SbcMediaCodecInformation.BlockLength.BL_4
        | a2dp.SbcMediaCodecInformation.BlockLength.BL_8
        | a2dp.SbcMediaCodecInformation.BlockLength.BL_12
        | a2dp.SbcMediaCodecInformation.BlockLength.BL_16,
        a2dp.SbcMediaCodecInformation.Subbands.S_4
        | a2dp.SbcMediaCodecInformation.Subbands.S_8,
        a2dp.SbcMediaCodecInformation.AllocationMethod.SNR
        | a2dp.SbcMediaCodecInformation.AllocationMethod.LOUDNESS,
        2,
        53,
    )
    assert sbc_info == sbc_info2
    assert bytes(sbc_info2) == bytes.fromhex("3fff0235")


# -----------------------------------------------------------------------------
def test_aac_codec_specific_information():
    aac_info = a2dp.AacMediaCodecInformation.from_bytes(bytes.fromhex("f0018c83e800"))
    assert (
        aac_info.object_type
        == a2dp.AacMediaCodecInformation.ObjectType.MPEG_2_AAC_LC
        | a2dp.AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LC
        | a2dp.AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LTP
        | a2dp.AacMediaCodecInformation.ObjectType.MPEG_4_AAC_SCALABLE
    )
    assert (
        aac_info.sampling_frequency
        == a2dp.AacMediaCodecInformation.SamplingFrequency.SF_44100
        | a2dp.AacMediaCodecInformation.SamplingFrequency.SF_48000
    )
    assert (
        aac_info.channels
        == a2dp.AacMediaCodecInformation.Channels.MONO
        | a2dp.AacMediaCodecInformation.Channels.STEREO
    )
    assert aac_info.vbr == 1
    assert aac_info.bitrate == 256000

    aac_info2 = a2dp.AacMediaCodecInformation(
        a2dp.AacMediaCodecInformation.ObjectType.MPEG_2_AAC_LC
        | a2dp.AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LC
        | a2dp.AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LTP
        | a2dp.AacMediaCodecInformation.ObjectType.MPEG_4_AAC_SCALABLE,
        a2dp.AacMediaCodecInformation.SamplingFrequency.SF_44100
        | a2dp.AacMediaCodecInformation.SamplingFrequency.SF_48000,
        a2dp.AacMediaCodecInformation.Channels.MONO
        | a2dp.AacMediaCodecInformation.Channels.STEREO,
        1,
        256000,
    )
    assert aac_info == aac_info2
    assert bytes(aac_info2) == bytes.fromhex("f0018c83e800")


# -----------------------------------------------------------------------------
def test_opus_codec_specific_information():
    opus_info = a2dp.OpusMediaCodecInformation.from_bytes(bytes([0x92]))
    assert opus_info.vendor_id == a2dp.OpusMediaCodecInformation.VENDOR_ID
    assert opus_info.codec_id == a2dp.OpusMediaCodecInformation.CODEC_ID
    assert opus_info.frame_size == a2dp.OpusMediaCodecInformation.FrameSize.FS_20MS
    assert opus_info.channel_mode == a2dp.OpusMediaCodecInformation.ChannelMode.STEREO
    assert (
        opus_info.sampling_frequency
        == a2dp.OpusMediaCodecInformation.SamplingFrequency.SF_48000
    )

    opus_info2 = a2dp.OpusMediaCodecInformation(
        a2dp.OpusMediaCodecInformation.ChannelMode.STEREO,
        a2dp.OpusMediaCodecInformation.FrameSize.FS_20MS,
        a2dp.OpusMediaCodecInformation.SamplingFrequency.SF_48000,
    )
    assert opus_info2 == opus_info
    assert opus_info2.value == bytes([0x92])


# -----------------------------------------------------------------------------
async def test_sbc_parser():
    header = b'\x9c\x80\x08\x00'
    payload = b'\x00\x00\x00\x00\x00\x00'
    data = Data(header + payload)

    parser = a2dp.SbcParser(data.read)
    async for frame in parser.frames:
        assert frame.sampling_frequency == 44100
        assert frame.block_count == 4
        assert frame.channel_mode == 0
        assert frame.allocation_method == 0
        assert frame.subband_count == 4
        assert frame.bitpool == 8
        assert frame.payload == header + payload


# -----------------------------------------------------------------------------
async def test_sbc_packet_source():
    header = b'\x9c\x80\x08\x00'
    payload = b'\x00\x00\x00\x00\x00\x00'
    data = Data((header + payload) * 2)

    packet_source = a2dp.SbcPacketSource(data.read, 23)
    async for packet in packet_source.packets:
        assert packet.sequence_number == 0
        assert packet.timestamp == 0
        assert packet.payload == b'\x01' + header + payload


# -----------------------------------------------------------------------------
async def test_aac_parser():
    header = b'\xff\xf0\x10\x00\x01\xa0\x00'
    payload = b'\x00\x00\x00\x00\x00\x00'
    data = Data(header + payload)

    parser = a2dp.AacParser(data.read)
    async for frame in parser.frames:
        assert frame.profile == a2dp.AacFrame.Profile.MAIN
        assert frame.sampling_frequency == 44100
        assert frame.channel_configuration == 0
        assert frame.payload == payload


# -----------------------------------------------------------------------------
async def test_aac_packet_source():
    header = b'\xff\xf0\x10\x00\x01\xa0\x00'
    payload = b'\x00\x00\x00\x00\x00\x00'
    data = Data(header + payload)

    packet_source = a2dp.AacPacketSource(data.read, 0)
    async for packet in packet_source.packets:
        assert packet.sequence_number == 0
        assert packet.timestamp == 0
        assert packet.payload == b' \x00\x12\x00\x00\x000\x00\x00\x00\x00\x00\x00'


# -----------------------------------------------------------------------------
async def test_opus_parser():
    packed_header_data_revised = struct.pack(
        "<QIIIB",
        0,  # granule_position
        2,  # bitstream_serial_number
        2,  # page_sequence_number
        0,  # crc_checksum
        3,  # page_segments
    )

    first_page_header_revised = (
        b'OggS'  # Capture pattern
        + b'\x00'  # Version
        + b'\x02'  # Header type
        + packed_header_data_revised
    )

    segment_table_revised = b'\x0a\x08\x0a'

    opus_head_packet_data = b'OpusHead' + b'\x00' + b'\x00'
    opus_tags_packet_data = b'OpusTags'
    audio_data_packet = b'0123456789'

    data = Data(
        first_page_header_revised
        + segment_table_revised
        + opus_head_packet_data
        + opus_tags_packet_data
        + audio_data_packet
    )

    parser = a2dp.OpusParser(data.read)
    async for packet in parser.packets:
        assert packet.channel_mode == a2dp.OpusPacket.ChannelMode.STEREO
        assert packet.payload == audio_data_packet


# -----------------------------------------------------------------------------
async def test_opus_packet_source():
    packed_header_data_revised = struct.pack(
        "<QIIIB",
        0,  # granule_position
        2,  # bitstream_serial_number
        2,  # page_sequence_number
        0,  # crc_checksum
        3,  # page_segments
    )

    first_page_header_revised = (
        b'OggS'  # Capture pattern
        + b'\x00'  # Version
        + b'\x02'  # Header type
        + packed_header_data_revised
    )

    segment_table_revised = b'\x0a\x08\x0a'

    opus_head_packet_data = b'OpusHead' + b'\x00' + b'\x00'
    opus_tags_packet_data = b'OpusTags'
    audio_data_packet = b'0123456789'

    data = Data(
        first_page_header_revised
        + segment_table_revised
        + opus_head_packet_data
        + opus_tags_packet_data
        + audio_data_packet
    )

    parser = a2dp.OpusPacketSource(data.read, 0)
    async for packet in parser.packets:
        assert packet.sequence_number == 0
        assert packet.timestamp == 0
        assert packet.payload == b'\x01' + audio_data_packet


# -----------------------------------------------------------------------------
async def async_main():
    test_sbc_codec_specific_information()
    test_aac_codec_specific_information()
    test_opus_codec_specific_information()
    await test_self_connection()
    await test_source_sink_1()
    test_sbc_parser()
    test_sbc_packet_source()
    test_aac_parser()
    test_aac_packet_source()
    test_opus_parser()
    test_opus_packet_source()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(async_main())
