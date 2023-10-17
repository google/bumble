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
import os
import logging

from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import BT_BR_EDR_TRANSPORT
from bumble.avdtp import (
    AVDTP_AUDIO_MEDIA_TYPE,
    Protocol,
    Listener,
    MediaCodecCapabilities,
)
from bumble.a2dp import (
    make_audio_sink_service_sdp_records,
    A2DP_SBC_CODEC_TYPE,
    SBC_MONO_CHANNEL_MODE,
    SBC_DUAL_CHANNEL_MODE,
    SBC_SNR_ALLOCATION_METHOD,
    SBC_LOUDNESS_ALLOCATION_METHOD,
    SBC_STEREO_CHANNEL_MODE,
    SBC_JOINT_STEREO_CHANNEL_MODE,
    SbcMediaCodecInformation,
)

Context = {'output': None}


# -----------------------------------------------------------------------------
def sdp_records():
    service_record_handle = 0x00010001
    return {
        service_record_handle: make_audio_sink_service_sdp_records(
            service_record_handle
        )
    }


# -----------------------------------------------------------------------------
def codec_capabilities():
    # NOTE: this shouldn't be hardcoded, but passed on the command line instead
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
def on_avdtp_connection(server):
    # Add a sink endpoint to the server
    sink = server.add_sink(codec_capabilities())
    sink.on('rtp_packet', on_rtp_packet)


# -----------------------------------------------------------------------------
def on_rtp_packet(packet):
    header = packet.payload[0]
    fragmented = header >> 7
    # start = (header >> 6) & 0x01
    # last = (header >> 5) & 0x01
    number_of_frames = header & 0x0F

    if fragmented:
        print(f'RTP: fragment {number_of_frames}')
    else:
        print(f'RTP: {number_of_frames} frames')

    Context['output'].write(packet.payload[1:])


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 4:
        print(
            'Usage: run_a2dp_sink.py <device-config> <transport-spec> <sbc-file> '
            '[<bt-addr>]'
        )
        print('example: run_a2dp_sink.py classic1.json usb:0 output.sbc')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        with open(sys.argv[3], 'wb') as sbc_file:
            Context['output'] = sbc_file

            # Create a device
            device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
            device.classic_enabled = True

            # Setup the SDP to expose the sink service
            device.sdp_service_records = sdp_records()

            # Start the controller
            await device.power_on()

            # Create a listener to wait for AVDTP connections
            listener = Listener.for_device(device)
            listener.on('connection', on_avdtp_connection)

            if len(sys.argv) >= 5:
                # Connect to the source
                target_address = sys.argv[4]
                print(f'=== Connecting to {target_address}...')
                connection = await device.connect(
                    target_address, transport=BT_BR_EDR_TRANSPORT
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

                server = await Protocol.connect(connection)
                listener.set_server(connection, server)
                sink = server.add_sink(codec_capabilities())
                sink.on('rtp_packet', on_rtp_packet)
            else:
                # Start being discoverable and connectable
                await device.set_discoverable(True)
                await device.set_connectable(True)

            await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
