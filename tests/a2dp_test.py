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
from bumble.core import BT_BR_EDR_TRANSPORT
from bumble.link import LocalLink
from bumble.device import Device
from bumble.host import Host
from bumble.transport import AsyncPipeSink
from bumble.avdtp import (
    AVDTP_IDLE_STATE,
    AVDTP_STREAMING_STATE,
    MediaPacketPump,
    Protocol,
    Listener,
    MediaCodecCapabilities,
    MediaPacket,
    AVDTP_AUDIO_MEDIA_TYPE,
    AVDTP_TSEP_SNK,
    A2DP_SBC_CODEC_TYPE,
)
from bumble.a2dp import (
    SbcMediaCodecInformation,
    SBC_MONO_CHANNEL_MODE,
    SBC_DUAL_CHANNEL_MODE,
    SBC_STEREO_CHANNEL_MODE,
    SBC_JOINT_STEREO_CHANNEL_MODE,
    SBC_LOUDNESS_ALLOCATION_METHOD,
    SBC_SNR_ALLOCATION_METHOD,
)

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
            two_devices.devices[1].public_address, transport=BT_BR_EDR_TRANSPORT
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
        media_codec_information=SbcMediaCodecInformation.from_discrete_values(
            sampling_frequency=44100,
            channel_mode=SBC_JOINT_STEREO_CHANNEL_MODE,
            block_length=16,
            subbands=8,
            allocation_method=SBC_LOUDNESS_ALLOCATION_METHOD,
            minimum_bitpool_value=2,
            maximum_bitpool_value=53,
        ),
    )


# -----------------------------------------------------------------------------
def sink_codec_capabilities():
    return MediaCodecCapabilities(
        media_type=AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=A2DP_SBC_CODEC_TYPE,
        media_codec_information=SbcMediaCodecInformation.from_lists(
            sampling_frequencies=[48000, 44100, 32000, 16000],
            channel_modes=[
                SBC_MONO_CHANNEL_MODE,
                SBC_DUAL_CHANNEL_MODE,
                SBC_STEREO_CHANNEL_MODE,
                SBC_JOINT_STEREO_CHANNEL_MODE,
            ],
            block_lengths=[4, 8, 12, 16],
            subbands=[4, 8],
            allocation_methods=[
                SBC_LOUDNESS_ALLOCATION_METHOD,
                SBC_SNR_ALLOCATION_METHOD,
            ],
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
                two_devices.devices[1].public_address, BT_BR_EDR_TRANSPORT
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
async def run_test_self():
    await test_self_connection()
    await test_source_sink_1()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_test_self())
