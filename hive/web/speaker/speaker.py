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
import enum
import logging
from typing import Dict, List

from bumble.core import BT_BR_EDR_TRANSPORT, CommandTimeoutError
from bumble.device import Device, DeviceConfiguration
from bumble.pairing import PairingConfig
from bumble.sdp import ServiceAttribute
from bumble.avdtp import (
    AVDTP_AUDIO_MEDIA_TYPE,
    Listener,
    MediaCodecCapabilities,
    MediaPacket,
    Protocol,
)
from bumble.a2dp import (
    make_audio_sink_service_sdp_records,
    MPEG_2_AAC_LC_OBJECT_TYPE,
    A2DP_SBC_CODEC_TYPE,
    A2DP_MPEG_2_4_AAC_CODEC_TYPE,
    SBC_MONO_CHANNEL_MODE,
    SBC_DUAL_CHANNEL_MODE,
    SBC_SNR_ALLOCATION_METHOD,
    SBC_LOUDNESS_ALLOCATION_METHOD,
    SBC_STEREO_CHANNEL_MODE,
    SBC_JOINT_STEREO_CHANNEL_MODE,
    SbcMediaCodecInformation,
    AacMediaCodecInformation,
)
from bumble.utils import AsyncRunner
from bumble.codecs import AacAudioRtpPacket
from bumble.hci import HCI_Reset_Command


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class AudioExtractor:
    @staticmethod
    def create(codec: str):
        if codec == 'aac':
            return AacAudioExtractor()
        if codec == 'sbc':
            return SbcAudioExtractor()

    def extract_audio(self, packet: MediaPacket) -> bytes:
        raise NotImplementedError()


# -----------------------------------------------------------------------------
class AacAudioExtractor:
    def extract_audio(self, packet: MediaPacket) -> bytes:
        return AacAudioRtpPacket(packet.payload).to_adts()


# -----------------------------------------------------------------------------
class SbcAudioExtractor:
    def extract_audio(self, packet: MediaPacket) -> bytes:
        # header = packet.payload[0]
        # fragmented = header >> 7
        # start = (header >> 6) & 0x01
        # last = (header >> 5) & 0x01
        # number_of_frames = header & 0x0F

        # TODO: support fragmented payloads
        return packet.payload[1:]


# -----------------------------------------------------------------------------
class Speaker:
    class StreamState(enum.Enum):
        IDLE = 0
        STOPPED = 1
        STARTED = 2
        SUSPENDED = 3

    def __init__(self, hci_source, hci_sink, codec):
        self.hci_source = hci_source
        self.hci_sink = hci_sink
        self.js_listeners = {}
        self.codec = codec
        self.device = None
        self.connection = None
        self.avdtp_listener = None
        self.packets_received = 0
        self.bytes_received = 0
        self.stream_state = Speaker.StreamState.IDLE
        self.audio_extractor = AudioExtractor.create(codec)

    def sdp_records(self) -> Dict[int, List[ServiceAttribute]]:
        service_record_handle = 0x00010001
        return {
            service_record_handle: make_audio_sink_service_sdp_records(
                service_record_handle
            )
        }

    def codec_capabilities(self) -> MediaCodecCapabilities:
        if self.codec == 'aac':
            return self.aac_codec_capabilities()

        if self.codec == 'sbc':
            return self.sbc_codec_capabilities()

        raise RuntimeError('unsupported codec')

    def aac_codec_capabilities(self) -> MediaCodecCapabilities:
        return MediaCodecCapabilities(
            media_type=AVDTP_AUDIO_MEDIA_TYPE,
            media_codec_type=A2DP_MPEG_2_4_AAC_CODEC_TYPE,
            media_codec_information=AacMediaCodecInformation.from_lists(
                object_types=[MPEG_2_AAC_LC_OBJECT_TYPE],
                sampling_frequencies=[48000, 44100],
                channels=[1, 2],
                vbr=1,
                bitrate=256000,
            ),
        )

    def sbc_codec_capabilities(self) -> MediaCodecCapabilities:
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

    def on_key_store_update(self):
        print("Key Store updated")
        self.emit('key_store_update')

    def on_bluetooth_connection(self, connection):
        print(f'Connection: {connection}')
        self.connection = connection
        connection.on('disconnection', self.on_bluetooth_disconnection)
        peer_name = '' if connection.peer_name is None else connection.peer_name
        peer_address = connection.peer_address.to_string(False)
        self.emit('connection', {'peer_name': peer_name, 'peer_address': peer_address})

    def on_bluetooth_disconnection(self, reason):
        print(f'Disconnection ({reason})')
        self.connection = None
        self.emit('disconnection', None)

    def on_avdtp_connection(self, protocol):
        print('Audio Stream Open')

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

    def on_avdtp_close(self):
        print("Audio Stream Closed")

    def on_sink_start(self):
        print("Sink Started")
        self.stream_state = self.StreamState.STARTED
        self.emit('start', None)

    def on_sink_stop(self):
        print("Sink Stopped")
        self.stream_state = self.StreamState.STOPPED
        self.emit('stop', None)

    def on_sink_suspend(self):
        print("Sink Suspended")
        self.stream_state = self.StreamState.SUSPENDED
        self.emit('suspend', None)

    def on_sink_configuration(self, config):
        print("Sink Configuration:")
        print('\n'.join(["  " + str(capability) for capability in config]))

    def on_rtp_channel_open(self):
        print("RTP Channel Open")

    def on_rtp_channel_close(self):
        print("RTP Channel Closed")
        self.stream_state = self.StreamState.IDLE

    def on_rtp_packet(self, packet):
        self.packets_received += 1
        self.bytes_received += len(packet.payload)
        self.emit("audio", self.audio_extractor.extract_audio(packet))

    async def connect(self, address):
        # Connect to the source
        print(f'=== Connecting to {address}...')
        connection = await self.device.connect(address, transport=BT_BR_EDR_TRANSPORT)
        print(f'=== Connected to {connection.peer_address}')

        # Request authentication
        print('*** Authenticating...')
        await connection.authenticate()
        print('*** Authenticated')

        # Enable encryption
        print('*** Enabling encryption...')
        await connection.encrypt()
        print('*** Encryption on')

        protocol = await Protocol.connect(connection)
        self.avdtp_listener.set_server(connection, protocol)
        self.on_avdtp_connection(protocol)

    async def discover_remote_endpoints(self, protocol):
        endpoints = await protocol.discover_remote_endpoints()
        print(f'@@@ Found {len(endpoints)} endpoints')
        for endpoint in endpoints:
            print('@@@', endpoint)

    def on(self, event_name, listener):
        self.js_listeners[event_name] = listener

    def emit(self, event_name, event=None):
        if listener := self.js_listeners.get(event_name):
            listener(event)

    async def run(self, connect_address):
        # Create a device
        device_config = DeviceConfiguration()
        device_config.name = "Bumble Speaker"
        device_config.class_of_device = 0x240414
        device_config.keystore = "JsonKeyStore:/bumble/keystore.json"
        device_config.classic_enabled = True
        device_config.le_enabled = False
        self.device = Device.from_config_with_hci(
            device_config, self.hci_source, self.hci_sink
        )

        # Setup the SDP to expose the sink service
        self.device.sdp_service_records = self.sdp_records()

        # Don't require MITM when pairing.
        self.device.pairing_config_factory = lambda connection: PairingConfig(
            mitm=False
        )

        # Start the controller
        await self.device.power_on()

        # Listen for Bluetooth connections
        self.device.on('connection', self.on_bluetooth_connection)

        # Listen for changes to the key store
        self.device.on('key_store_update', self.on_key_store_update)

        # Create a listener to wait for AVDTP connections
        self.avdtp_listener = Listener.for_device(self.device)
        self.avdtp_listener.on('connection', self.on_avdtp_connection)

        print(f'Speaker ready to play, codec={self.codec}')

        if connect_address:
            # Connect to the source
            try:
                await self.connect(connect_address)
            except CommandTimeoutError:
                print("Connection timed out")
                return
        else:
            # We'll wait for a connection
            print("Waiting for connection...")

    async def start(self):
        await self.run(None)

    async def stop(self):
        # TODO: replace this once a proper reset is implemented in the lib.
        await self.device.host.send_command(HCI_Reset_Command())
        await self.device.power_off()
        print('Speaker stopped')


# -----------------------------------------------------------------------------
def main(hci_source, hci_sink):
    return Speaker(hci_source, hci_sink, "aac")
