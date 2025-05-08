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
import sys
from dataclasses import dataclass

import ffmpeg

from bumble.a2dp import (
    A2DP_MPEG_2_4_AAC_CODEC_TYPE,
    A2DP_SBC_CODEC_TYPE,
    AacMediaCodecInformation,
    AacPacketSource,
    SbcMediaCodecInformation,
    SbcPacketSource,
    make_audio_source_service_sdp_records,
)
from bumble.avdtp import (
    AVDTP_AUDIO_MEDIA_TYPE,
    Listener,
    MediaCodecCapabilities,
    MediaPacketPump,
    Protocol,
    find_avdtp_service_with_connection,
)
from bumble.colors import color
from bumble.core import PhysicalTransport
from bumble.device import Device
from bumble.transport import open_transport_or_link

from typing import Dict, Union


@dataclass
class CodecCapabilities:
    name: str
    sample_rate: str
    number_of_channels: str


# -----------------------------------------------------------------------------
def sdp_records():
    service_record_handle = 0x00010001
    return {
        service_record_handle: make_audio_source_service_sdp_records(
            service_record_handle
        )
    }


# -----------------------------------------------------------------------------
def on_avdtp_connection(
    read_function, protocol, codec_capabilities: MediaCodecCapabilities
):
    packet_source = SbcPacketSource(read_function, protocol.l2cap_channel.peer_mtu)
    packet_pump = MediaPacketPump(packet_source.packets)
    protocol.add_source(codec_capabilities, packet_pump)


# -----------------------------------------------------------------------------
async def stream_packets(
    read_function, protocol, codec_capabilities: MediaCodecCapabilities
):
    # Discover all endpoints on the remote device
    endpoints = await protocol.discover_remote_endpoints()
    for endpoint in endpoints:
        print('@@@', endpoint)

    # Select a sink
    assert codec_capabilities.media_codec_type in [
        A2DP_SBC_CODEC_TYPE,
        A2DP_MPEG_2_4_AAC_CODEC_TYPE,
    ]
    sink = protocol.find_remote_sink_by_codec(
        AVDTP_AUDIO_MEDIA_TYPE, codec_capabilities.media_codec_type
    )
    if sink is None:
        print(color('!!! no Sink found', 'red'))
        return
    print(f'### Selected sink: {sink.seid}')

    # Stream the packets
    packet_sources = {
        A2DP_SBC_CODEC_TYPE: SbcPacketSource(
            read_function, protocol.l2cap_channel.peer_mtu
        ),
        A2DP_MPEG_2_4_AAC_CODEC_TYPE: AacPacketSource(
            read_function, protocol.l2cap_channel.peer_mtu
        ),
    }
    packet_source = packet_sources[codec_capabilities.media_codec_type]
    packet_pump = MediaPacketPump(packet_source.packets)  # type: ignore
    source = protocol.add_source(codec_capabilities, packet_pump)
    stream = await protocol.create_stream(source, sink)
    await stream.start()
    await asyncio.sleep(60)
    await stream.stop()
    await stream.close()


# -----------------------------------------------------------------------------
def fetch_codec_informations(filepath) -> MediaCodecCapabilities:
    probe = ffmpeg.probe(filepath)
    assert 'streams' in probe
    streams = probe['streams']

    if not streams or len(streams) > 1:
        print(streams)
        print(color('!!! file not supported', 'red'))
        exit()
    audio_stream = streams[0]

    media_codec_type = None
    media_codec_information: Union[
        SbcMediaCodecInformation, AacMediaCodecInformation, None
    ] = None

    assert 'codec_name' in audio_stream
    codec_name: str = audio_stream['codec_name']
    if codec_name == "sbc":
        media_codec_type = A2DP_SBC_CODEC_TYPE
        sbc_sampling_frequency: Dict[
            str, SbcMediaCodecInformation.SamplingFrequency
        ] = {
            '16000': SbcMediaCodecInformation.SamplingFrequency.SF_16000,
            '32000': SbcMediaCodecInformation.SamplingFrequency.SF_32000,
            '44100': SbcMediaCodecInformation.SamplingFrequency.SF_44100,
            '48000': SbcMediaCodecInformation.SamplingFrequency.SF_48000,
        }
        sbc_channel_mode: Dict[int, SbcMediaCodecInformation.ChannelMode] = {
            1: SbcMediaCodecInformation.ChannelMode.MONO,
            2: SbcMediaCodecInformation.ChannelMode.JOINT_STEREO,
        }

        assert 'sample_rate' in audio_stream
        assert 'channels' in audio_stream
        media_codec_information = SbcMediaCodecInformation(
            sampling_frequency=sbc_sampling_frequency[audio_stream['sample_rate']],
            channel_mode=sbc_channel_mode[audio_stream['channels']],
            block_length=SbcMediaCodecInformation.BlockLength.BL_16,
            subbands=SbcMediaCodecInformation.Subbands.S_8,
            allocation_method=SbcMediaCodecInformation.AllocationMethod.LOUDNESS,
            minimum_bitpool_value=2,
            maximum_bitpool_value=53,
        )
    elif codec_name == "aac":
        media_codec_type = A2DP_MPEG_2_4_AAC_CODEC_TYPE
        object_type: Dict[str, AacMediaCodecInformation.ObjectType] = {
            'LC': AacMediaCodecInformation.ObjectType.MPEG_2_AAC_LC,
            'LTP': AacMediaCodecInformation.ObjectType.MPEG_4_AAC_LTP,
            'SSR': AacMediaCodecInformation.ObjectType.MPEG_4_AAC_SCALABLE,
        }
        aac_sampling_frequency: Dict[
            str, AacMediaCodecInformation.SamplingFrequency
        ] = {
            '44100': AacMediaCodecInformation.SamplingFrequency.SF_44100,
            '48000': AacMediaCodecInformation.SamplingFrequency.SF_48000,
        }
        aac_channel_mode: Dict[int, AacMediaCodecInformation.Channels] = {
            1: AacMediaCodecInformation.Channels.MONO,
            2: AacMediaCodecInformation.Channels.STEREO,
        }

        assert 'profile' in audio_stream
        assert 'sample_rate' in audio_stream
        assert 'channels' in audio_stream
        media_codec_information = AacMediaCodecInformation(
            object_type=object_type[audio_stream['profile']],
            sampling_frequency=aac_sampling_frequency[audio_stream['sample_rate']],
            channels=aac_channel_mode[audio_stream['channels']],
            vbr=1,
            bitrate=128000,
        )
    else:
        print(color('!!! codec not supported, only aac & sbc are supported', 'red'))
        exit()

    assert media_codec_type is not None
    assert media_codec_information is not None

    return MediaCodecCapabilities(
        media_type=AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=media_codec_type,
        media_codec_information=media_codec_information,
    )


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 4:
        print(
            'Usage: run_a2dp_source.py <device-config> <transport-spec> <audio-file> '
            '[<bluetooth-address>]'
        )
        print(
            'example: run_a2dp_source.py classic1.json usb:0 test.sbc E1:CA:72:48:C4:E8'
        )
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True

        # Setup the SDP to expose the SRC service
        device.sdp_service_records = sdp_records()

        # Start
        await device.power_on()

        with open(sys.argv[3], 'rb') as audio_file:
            # NOTE: this should be using asyncio file reading, but blocking reads are
            # good enough for testing
            async def read(byte_count):
                return audio_file.read(byte_count)

            codec_capabilities = fetch_codec_informations(sys.argv[3])

            if len(sys.argv) > 4:
                # Connect to a peer
                target_address = sys.argv[4]
                print(f'=== Connecting to {target_address}...')
                connection = await device.connect(
                    target_address, transport=PhysicalTransport.BR_EDR
                )
                print(f'=== Connected to {connection.peer_address}!')

                # Request authentication
                print('*** Authenticating...')
                await connection.authenticate()
                print('*** Authenticated')

                # Enable encryption
                print('*** Enabling encryption...')
                await connection.encrypt()
                print('*** Encryption on')

                # Look for an A2DP service
                avdtp_version = await find_avdtp_service_with_connection(connection)
                if not avdtp_version:
                    print(color('!!! no A2DP service found'))
                    return

                # Create a client to interact with the remote device
                protocol = await Protocol.connect(connection, avdtp_version)

                # Start streaming
                await stream_packets(read, protocol, codec_capabilities)
            else:
                # Create a listener to wait for AVDTP connections
                listener = Listener.for_device(device=device, version=(1, 2))
                listener.on(
                    'connection',
                    lambda protocol: on_avdtp_connection(
                        read, protocol, codec_capabilities
                    ),
                )

                # Become connectable and wait for a connection
                await device.set_discoverable(True)
                await device.set_connectable(True)

            await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
