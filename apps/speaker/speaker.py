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
import os
import logging

import click
from bumble.core import BT_BR_EDR_TRANSPORT

from bumble.device import Device, DeviceConfiguration
from bumble.transport import open_transport
from bumble.avdtp import (
    AVDTP_AUDIO_MEDIA_TYPE,
    Listener,
    MediaCodecCapabilities,
    Protocol,
)
from bumble.a2dp import (
    MPEG_2_AAC_LC_OBJECT_TYPE,
    make_audio_sink_service_sdp_records,
    A2DP_SBC_CODEC_TYPE,
    A2DP_MPEG_2_4_AAC_CODEC_TYPE,
    SBC_MONO_CHANNEL_MODE,
    SBC_DUAL_CHANNEL_MODE,
    SBC_SNR_ALLOCATION_METHOD,
    SBC_LOUDNESS_ALLOCATION_METHOD,
    SBC_STEREO_CHANNEL_MODE,
    SBC_JOINT_STEREO_CHANNEL_MODE,
    SbcMediaCodecInformation,
    AacMediaCodecInformation
)
from bumble.utils import AsyncRunner


# -----------------------------------------------------------------------------
class Speaker:
    def __init__(self, transport, discover):
        self.transport = transport
        self.discover = discover
        self.device = None
        self.listener = None
        self.output_filename = 'speaker_output.sbc'
        self.output = None

    def sdp_records(self):
        service_record_handle = 0x00010001
        return {
            service_record_handle: make_audio_sink_service_sdp_records(
                service_record_handle
            )
        }

    def codec_capabilities(self):
        return self.aac_codec_capabilities()

    def aac_codec_capabilities(self):
        return MediaCodecCapabilities(
            media_type=AVDTP_AUDIO_MEDIA_TYPE,
            media_codec_type=A2DP_MPEG_2_4_AAC_CODEC_TYPE,
            media_codec_information=AacMediaCodecInformation.from_lists(
                object_types=[MPEG_2_AAC_LC_OBJECT_TYPE],
                sampling_frequencies=[48000, 44100],
                channels=[1,2],
                vbr=1,
                bitrate=256000
            )
        )

    def sbc_codec_capabilities(self):
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

    def on_bluetooth_connection(self, connection):
        print(f"Connection: {connection}")
        connection.on('disconnection', self.on_bluetooth_disconnection)

    def on_bluetooth_disconnection(self, reason):
        print(f"Disconnection ({reason})")
        AsyncRunner.spawn(self.advertise())

    def on_avdtp_connection(self, protocol):
        print("Audio Stream Open")

        # Add a sink endpoint to the server
        sink = protocol.add_sink(self.codec_capabilities())
        sink.on('start', self.on_sink_start)
        sink.on('stop', self.on_sink_stop)
        sink.on('suspend', self.on_sink_suspend)
        sink.on('configuration', lambda: self.on_sink_configuration(sink.configuration))
        sink.on('rtp_packet', self.on_rtp_packet)
        sink.on('rtp_channel_open', self.on_rtp_channel_open)
        sink.on('rtp_channel_close', self.on_rtp_channel_close)

        # Listen for close events
        protocol.on('close', self.on_avdtp_close)

        # Discover all endpoints on the remote device is requested
        if self.discover:
            AsyncRunner.spawn(self.discover_remote_endpoints(protocol))

    def on_avdtp_close(self):
        print("Audio Stream Closed")

    def on_sink_start(self):
        print("Sink Start")

    def on_sink_stop(self):
        print("Sink Stop")

    def on_sink_suspend(self):
        print("Sink Suspend")

    def on_sink_configuration(self, config):
        print("Sink Configuration:")
        print('\n'.join(["  " + str(capability) for capability in config]))

    def on_rtp_channel_open(self):
        print("RTP Channel Open")

    def on_rtp_channel_close(self):
        print("RTP Channel Closed")

    def on_rtp_packet(self, packet):
        # header = packet.payload[0]
        # fragmented = header >> 7
        # # start = (header >> 6) & 0x01
        # # last = (header >> 5) & 0x01
        # number_of_frames = header & 0x0F

        # payload = packet.payload[1:]
        # payload_size = len(payload)
        # if fragmented:
        #     print(f'RTP: fragment {payload_size} bytes in {number_of_frames} frames')
        # else:
        #     print(f'RTP: {payload_size} bytes in {number_of_frames} frames')
        print(packet.payload.hex())

        self.output.write(packet.payload)

    async def advertise(self):
        await self.device.set_discoverable(True)
        await self.device.set_connectable(True)

    async def connect(self, address):
        # Connect to the source
        print(f'=== Connecting to {address}...')
        connection = await self.device.connect(
            address, transport=BT_BR_EDR_TRANSPORT
        )
        print(f'=== Connected to {connection.peer_address}')
        self.on_bluetooth_connection(connection)

        # Request authentication
        print('*** Authenticating...')
        await connection.authenticate()
        print('*** Authenticated')

        # Enable encryption
        print('*** Enabling encryption...')
        await connection.encrypt()
        print('*** Encryption on')

        protocol = await Protocol.connect(connection)
        self.listener.set_server(connection, protocol)
        self.on_avdtp_connection(protocol)

    async def discover_remote_endpoints(self, protocol):
        endpoints = await protocol.discover_remote_endpoints()
        print(f'@@@ Found {len(endpoints)} endpoints')
        for endpoint in endpoints:
            print('@@@', endpoint)

    async def run(self, connect_address):
        async with await open_transport(self.transport) as (hci_source, hci_sink):
            with open(self.output_filename, 'wb') as sbc_file:
                self.output = sbc_file

                # Create a device
                device_config = DeviceConfiguration()
                device_config.name = "Bumble Speaker"
                device_config.class_of_device = 2360324
                device_config.keystore = "JsonKeyStore"
                device_config.classic_enabled = True
                device_config.le_enabled = False
                self.device = Device.from_config_with_hci(
                    device_config, hci_source, hci_sink
                )

                # Setup the SDP to expose the sink service
                self.device.sdp_service_records = self.sdp_records()

                # Start the controller
                await self.device.power_on()

                # Listen for Bluetooth connections
                self.device.on('connection', self.on_bluetooth_connection);

                # Create a listener to wait for AVDTP connections
                self.listener = Listener(Listener.create_registrar(self.device))
                self.listener.on('connection', self.on_avdtp_connection)

                if connect_address:
                    # Connect to the source
                    await self.connect(connect_address)
                else:
                    # Start being discoverable and connectable
                    await self.advertise()

                await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
@click.group()
@click.option('--device-config', metavar='FILENAME', help='Device configuration file')
@click.pass_context
def speaker(ctx, device_config):
    ctx.ensure_object(dict)
    ctx.obj['device_config'] = device_config


@speaker.command()
@click.argument('transport')
@click.option(
    '--connect',
    'connect_address',
    metavar='ADDRESS_OR_NAME',
    help='Address or name to connect to',
)
@click.option('--discover', is_flag=True)
@click.pass_context
def play(ctx, transport, connect_address, discover):
    asyncio.run(Speaker(transport, discover).run(connect_address))


# -----------------------------------------------------------------------------
def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    speaker()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
