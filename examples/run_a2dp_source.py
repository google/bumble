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
import sys

import bumble.logging
from bumble.a2dp import (
    A2DP_SBC_CODEC_TYPE,
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
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
def sdp_records():
    service_record_handle = 0x00010001
    return {
        service_record_handle: make_audio_source_service_sdp_records(
            service_record_handle
        )
    }


# -----------------------------------------------------------------------------
def codec_capabilities():
    # NOTE: this shouldn't be hardcoded, but should be inferred from the input file
    # instead
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
def on_avdtp_connection(read_function, protocol):
    packet_source = SbcPacketSource(read_function, protocol.l2cap_channel.peer_mtu)
    packet_pump = MediaPacketPump(packet_source.packets)
    protocol.add_source(codec_capabilities(), packet_pump)


# -----------------------------------------------------------------------------
async def stream_packets(read_function, protocol):
    # Discover all endpoints on the remote device
    endpoints = await protocol.discover_remote_endpoints()
    for endpoint in endpoints:
        print('@@@', endpoint)

    # Select a sink
    sink = protocol.find_remote_sink_by_codec(
        AVDTP_AUDIO_MEDIA_TYPE, A2DP_SBC_CODEC_TYPE
    )
    if sink is None:
        print(color('!!! no SBC sink found', 'red'))
        return
    print(f'### Selected sink: {sink.seid}')

    # Stream the packets
    packet_source = SbcPacketSource(read_function, protocol.l2cap_channel.peer_mtu)
    packet_pump = MediaPacketPump(packet_source.packets)
    source = protocol.add_source(codec_capabilities(), packet_pump)
    stream = await protocol.create_stream(source, sink)
    await stream.start()
    await asyncio.sleep(5)
    await stream.stop()
    await asyncio.sleep(5)
    await stream.start()
    await asyncio.sleep(5)
    await stream.stop()
    await stream.close()


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 4:
        print(
            'Usage: run_a2dp_source.py <device-config> <transport-spec> <sbc-file> '
            '[<bluetooth-address>]'
        )
        print(
            'example: run_a2dp_source.py classic1.json usb:0 test.sbc E1:CA:72:48:C4:E8'
        )
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[2]) as hci_transport:
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

        with open(sys.argv[3], 'rb') as sbc_file:
            # NOTE: this should be using asyncio file reading, but blocking reads are
            # good enough for testing
            async def read(byte_count):
                return sbc_file.read(byte_count)

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
                await stream_packets(read, protocol)
            else:
                # Create a listener to wait for AVDTP connections
                listener = Listener.for_device(device=device, version=(1, 2))
                listener.on(
                    'connection', lambda protocol: on_avdtp_connection(read, protocol)
                )

                # Become connectable and wait for a connection
                await device.set_discoverable(True)
                await device.set_connectable(True)

            await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
