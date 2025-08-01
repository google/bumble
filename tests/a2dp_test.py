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
import pytest

from bumble.controller import Controller
from bumble.core import PhysicalTransport
from bumble.link import LocalLink
from bumble.device import Device
from bumble.host import Host
from bumble.transport.common import AsyncPipeSink
from bumble.avdtp import (
    AVDTP_IDLE_STATE,
    AVDTP_STREAMING_STATE,
    MediaPacketPump,
    Protocol,
    Listener,
    MediaCodecCapabilities,
    AVDTP_AUDIO_MEDIA_TYPE,
    AVDTP_TSEP_SNK,
    A2DP_SBC_CODEC_TYPE,
)
from bumble.a2dp import (
    AacMediaCodecInformation,
    OpusMediaCodecInformation,
    SbcMediaCodecInformation,
)
from bumble.rtp import MediaPacket

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
    return MediaCodecCapabilities(
        media_type=AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=A2DP_SBC_CODEC_TYPE,
        media_codec_information=SbcMediaCodecInformation(
            sampling_frequency=SbcMediaCodecInformation.SamplingFrequency.SF_44100,
            channel_mode=SbcMediaCodecInformation.ChannelMode.JOINT_STEREO,
            block_length=SbcMediaCodecInformation.BlockLength.BL_16,
            subbands=SbcMediaCodecInformation.Subbands.S_8,
            allocation_method=SbcMediaCodecInformation.AllocationMethod.LOUDNESS,
            minimum_bitpool_value=2,
            maximum_bitpool_value=53,
        ),
    )


# -----------------------------------------------------------------------------
def sink_codec_capabilities():
    return MediaCodecCapabilities(
        media_type=AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=A2DP_SBC_CODEC_TYPE,
        media_codec_information=SbcMediaCodecInformation(
            sampling_frequency=SbcMediaCodecInformation.SamplingFrequency.SF_48000
            | SbcMediaCodecInformation.SamplingFrequency.SF_44100
            | SbcMediaCodecInformation.SamplingFrequency.SF_32000
            | SbcMediaCodecInformation.SamplingFrequency.SF_16000,
            channel_mode=SbcMediaCodecInformation.ChannelMode.MONO
            | SbcMediaCodecInformation.ChannelMode.DUAL_CHANNEL
            | SbcMediaCodecInformation.ChannelMode.STEREO
            | SbcMediaCodecInformation.ChannelMode.JOINT_STEREO,
            block_length=SbcMediaCodecInformation.BlockLength.BL_4
            | SbcMediaCodecInformation.BlockLength.BL_8
            | SbcMediaCodecInformation.BlockLength.BL_12
            | SbcMediaCodecInformation.BlockLength.BL_16,
            subbands=SbcMediaCodecInformation.Subbands.S_4
            | SbcMediaCodecInformation.Subbands.S_8,
            allocation_method=SbcMediaCodecInformation.AllocationMethod.LOUDNESS
            | SbcMediaCodecInformation.AllocationMethod.SNR,
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
    listener = Listener.for_device(two_devices.devices[1])
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
    client = await Protocol.connect(connection)
    endpoints = await client.discover_remote_endpoints()
    assert len(endpoints) == 1
    remote_sink = list(endpoints)[0]
    assert remote_sink.in_use == 0
    assert remote_sink.media_type == AVDTP_AUDIO_MEDIA_TYPE
    assert remote_sink.tsep == AVDTP_TSEP_SNK

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
    pump = MediaPacketPump(generate_packets(3))
    source = client.add_source(source_codec_capabilities(), pump)
    stream = await client.create_stream(source, remote_sink)
    await stream.start()
    assert stream.state == AVDTP_STREAMING_STATE
    assert stream.local_endpoint.in_use == 1
    assert stream.rtp_channel is not None
    assert sink.in_use == 1
    assert sink.stream is not None
    assert sink.stream.state == AVDTP_STREAMING_STATE
    await rtp_packets_fully_received

    await stream.close()
    assert stream.rtp_channel is None
    assert source.in_use == 0
    assert source.stream.state == AVDTP_IDLE_STATE
    assert sink.in_use == 0
    assert sink.stream.state == AVDTP_IDLE_STATE

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
    assert stream.state == AVDTP_STREAMING_STATE
    assert stream.local_endpoint.in_use == 1
    assert stream.rtp_channel is not None
    assert sink.in_use == 1
    assert sink.stream is not None
    assert sink.stream.state == AVDTP_STREAMING_STATE

    stream.send_media_packet(source_packets[0])
    stream.send_media_packet(source_packets[1])
    stream.send_media_packet(source_packets[2])

    await stream.close()
    assert stream.rtp_channel is None
    assert len(rtp_packets) == 3
    assert source.in_use == 0
    assert source.stream.state == AVDTP_IDLE_STATE
    assert sink.in_use == 0
    assert sink.stream.state == AVDTP_IDLE_STATE


# -----------------------------------------------------------------------------
def test_sbc_codec_specific_information():
    sbc_info = SbcMediaCodecInformation.from_bytes(bytes.fromhex("3fff0235"))
    assert (
        sbc_info.sampling_frequency
        == SbcMediaCodecInformation.SamplingFrequency.SF_44100
        | SbcMediaCodecInformation.SamplingFrequency.SF_48000
    )
    assert (
        sbc_info.channel_mode
        == SbcMediaCodecInformation.ChannelMode.MONO
        | SbcMediaCodecInformation.ChannelMode.DUAL_CHANNEL
        | SbcMediaCodecInformation.ChannelMode.STEREO
        | SbcMediaCodecInformation.ChannelMode.JOINT_STEREO
    )
    assert (
        sbc_info.block_length
        == SbcMediaCodecInformation.BlockLength.BL_4
        | SbcMediaCodecInformation.BlockLength.BL_8
        | SbcMediaCodecInformation.BlockLength.BL_12
        | SbcMediaCodecInformation.BlockLength.BL_16
    )
    assert (
        sbc_info.subbands
        == SbcMediaCodecInformation.Subbands.S_4 | SbcMediaCodecInformation.Subbands.S_8
    )
    assert (
        sbc_info.allocation_method
        == SbcMediaCodecInformation.AllocationMethod.SNR
        | SbcMediaCodecInformation.AllocationMethod.LOUDNESS
    )
    assert sbc_info.minimum_bitpool_value == 2
    assert sbc_info.maximum_bitpool_value == 53

    sbc_info2 = SbcMediaCodecInformation(
        SbcMediaCodecInformation.SamplingFrequency.SF_44100
        | SbcMediaCodecInformation.SamplingFrequency.SF_48000,
        SbcMediaCodecInformation.ChannelMode.MONO
        | SbcMediaCodecInformation.ChannelMode.DUAL_CHANNEL
        | SbcMediaCodecInformation.ChannelMode.STEREO
        | SbcMediaCodecInformation.ChannelMode.JOINT_STEREO,
        SbcMediaCodecInformation.BlockLength.BL_4
        | SbcMediaCodecInformation.BlockLength.BL_8
        | SbcMediaCodecInformation.BlockLength.BL_12
        | SbcMediaCodecInformation.BlockLength.BL_16,
        SbcMediaCodecInformation.Subbands.S_4 | SbcMediaCodecInformation.Subbands.S_8,
        SbcMediaCodecInformation.AllocationMethod.SNR
        | SbcMediaCodecInformation.AllocationMethod.LOUDNESS,
        2,
        53,
    )
    assert sbc_info == sbc_info2
    assert bytes(sbc_info2) == bytes.fromhex("3fff0235")


# -----------------------------------------------------------------------------
def test_aac_codec_specific_information():
    aac_info = AacMediaCodecInformation.from_bytes(bytes.fromhex("f0018c83e800"))
    assert (
        aac_info.object_type
        == AacMediaCodecInformation.ObjectType.MPEG_2_AAC_LC
        | AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LC
        | AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LTP
        | AacMediaCodecInformation.ObjectType.MPEG_4_AAC_SCALABLE
    )
    assert (
        aac_info.sampling_frequency
        == AacMediaCodecInformation.SamplingFrequency.SF_44100
        | AacMediaCodecInformation.SamplingFrequency.SF_48000
    )
    assert (
        aac_info.channels
        == AacMediaCodecInformation.Channels.MONO
        | AacMediaCodecInformation.Channels.STEREO
    )
    assert aac_info.vbr == 1
    assert aac_info.bitrate == 256000

    aac_info2 = AacMediaCodecInformation(
        AacMediaCodecInformation.ObjectType.MPEG_2_AAC_LC
        | AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LC
        | AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LTP
        | AacMediaCodecInformation.ObjectType.MPEG_4_AAC_SCALABLE,
        AacMediaCodecInformation.SamplingFrequency.SF_44100
        | AacMediaCodecInformation.SamplingFrequency.SF_48000,
        AacMediaCodecInformation.Channels.MONO
        | AacMediaCodecInformation.Channels.STEREO,
        1,
        256000,
    )
    assert aac_info == aac_info2
    assert bytes(aac_info2) == bytes.fromhex("f0018c83e800")


# -----------------------------------------------------------------------------
def test_opus_codec_specific_information():
    opus_info = OpusMediaCodecInformation.from_bytes(bytes([0x92]))
    assert opus_info.vendor_id == OpusMediaCodecInformation.VENDOR_ID
    assert opus_info.codec_id == OpusMediaCodecInformation.CODEC_ID
    assert opus_info.frame_size == OpusMediaCodecInformation.FrameSize.FS_20MS
    assert opus_info.channel_mode == OpusMediaCodecInformation.ChannelMode.STEREO
    assert (
        opus_info.sampling_frequency
        == OpusMediaCodecInformation.SamplingFrequency.SF_48000
    )

    opus_info2 = OpusMediaCodecInformation(
        OpusMediaCodecInformation.ChannelMode.STEREO,
        OpusMediaCodecInformation.FrameSize.FS_20MS,
        OpusMediaCodecInformation.SamplingFrequency.SF_48000,
    )
    assert opus_info2 == opus_info
    assert opus_info2.value == bytes([0x92])


# -----------------------------------------------------------------------------
async def async_main():
    test_sbc_codec_specific_information()
    test_aac_codec_specific_information()
    test_opus_codec_specific_information()
    await test_self_connection()
    await test_source_sink_1()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(async_main())
