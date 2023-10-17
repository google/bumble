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
import asyncio
import asyncio.subprocess
from importlib import resources
import enum
import json
import os
import logging
import pathlib
import subprocess
from typing import Dict, List, Optional
import weakref

import click
import aiohttp
from aiohttp import web

import bumble
from bumble.colors import color
from bumble.core import BT_BR_EDR_TRANSPORT, CommandTimeoutError
from bumble.device import Connection, Device, DeviceConfiguration
from bumble.hci import HCI_StatusError
from bumble.pairing import PairingConfig
from bumble.sdp import ServiceAttribute
from bumble.transport import open_transport
from bumble.avdtp import (
    AVDTP_AUDIO_MEDIA_TYPE,
    Listener,
    MediaCodecCapabilities,
    MediaPacket,
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
    AacMediaCodecInformation,
)
from bumble.utils import AsyncRunner
from bumble.codecs import AacAudioRtpPacket


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_UI_PORT = 7654

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
class Output:
    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def suspend(self) -> None:
        pass

    async def on_connection(self, connection: Connection) -> None:
        pass

    async def on_disconnection(self, reason: int) -> None:
        pass

    def on_rtp_packet(self, packet: MediaPacket) -> None:
        pass


# -----------------------------------------------------------------------------
class FileOutput(Output):
    filename: str
    codec: str
    extractor: AudioExtractor

    def __init__(self, filename, codec):
        self.filename = filename
        self.codec = codec
        self.file = open(filename, 'wb')
        self.extractor = AudioExtractor.create(codec)

    def on_rtp_packet(self, packet: MediaPacket) -> None:
        self.file.write(self.extractor.extract_audio(packet))


# -----------------------------------------------------------------------------
class QueuedOutput(Output):
    MAX_QUEUE_SIZE = 32768

    packets: asyncio.Queue
    extractor: AudioExtractor
    packet_pump_task: Optional[asyncio.Task]
    started: bool

    def __init__(self, extractor):
        self.extractor = extractor
        self.packets = asyncio.Queue()
        self.packet_pump_task = None
        self.started = False

    async def start(self):
        if self.started:
            return

        self.packet_pump_task = asyncio.create_task(self.pump_packets())

    async def pump_packets(self):
        while True:
            packet = await self.packets.get()
            await self.on_audio_packet(packet)

    async def on_audio_packet(self, packet: bytes) -> None:
        pass

    def on_rtp_packet(self, packet: MediaPacket) -> None:
        if self.packets.qsize() > self.MAX_QUEUE_SIZE:
            logger.debug("queue full, dropping")
            return

        self.packets.put_nowait(self.extractor.extract_audio(packet))


# -----------------------------------------------------------------------------
class WebSocketOutput(QueuedOutput):
    def __init__(self, codec, send_audio, send_message):
        super().__init__(AudioExtractor.create(codec))
        self.send_audio = send_audio
        self.send_message = send_message

    async def on_connection(self, connection: Connection) -> None:
        try:
            await connection.request_remote_name()
        except HCI_StatusError:
            pass
        peer_name = '' if connection.peer_name is None else connection.peer_name
        peer_address = connection.peer_address.to_string(False)
        await self.send_message(
            'connection',
            peer_address=peer_address,
            peer_name=peer_name,
        )

    async def on_disconnection(self, reason) -> None:
        await self.send_message('disconnection')

    async def on_audio_packet(self, packet: bytes) -> None:
        await self.send_audio(packet)

    async def start(self):
        await super().start()
        await self.send_message('start')

    async def stop(self):
        await super().stop()
        await self.send_message('stop')

    async def suspend(self):
        await super().suspend()
        await self.send_message('suspend')


# -----------------------------------------------------------------------------
class FfplayOutput(QueuedOutput):
    MAX_QUEUE_SIZE = 32768

    subprocess: Optional[asyncio.subprocess.Process]
    ffplay_task: Optional[asyncio.Task]

    def __init__(self, codec: str) -> None:
        super().__init__(AudioExtractor.create(codec))
        self.subprocess = None
        self.ffplay_task = None
        self.codec = codec

    async def start(self):
        if self.started:
            return

        await super().start()

        self.subprocess = await asyncio.create_subprocess_shell(
            f'ffplay -f {self.codec} pipe:0',
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        self.ffplay_task = asyncio.create_task(self.monitor_ffplay())

    async def stop(self):
        # TODO
        pass

    async def suspend(self):
        # TODO
        pass

    async def monitor_ffplay(self):
        async def read_stream(name, stream):
            while True:
                data = await stream.read()
                logger.debug(f'{name}:', data)

        await asyncio.wait(
            [
                asyncio.create_task(
                    read_stream('[ffplay stdout]', self.subprocess.stdout)
                ),
                asyncio.create_task(
                    read_stream('[ffplay stderr]', self.subprocess.stderr)
                ),
                asyncio.create_task(self.subprocess.wait()),
            ]
        )
        logger.debug("FFPLAY done")

    async def on_audio_packet(self, packet):
        try:
            self.subprocess.stdin.write(packet)
        except Exception:
            logger.warning('!!!! exception while sending audio to ffplay pipe')


# -----------------------------------------------------------------------------
class UiServer:
    speaker: weakref.ReferenceType[Speaker]
    port: int

    def __init__(self, speaker: Speaker, port: int) -> None:
        self.speaker = weakref.ref(speaker)
        self.port = port
        self.channel_socket = None

    async def start_http(self) -> None:
        """Start the UI HTTP server."""

        app = web.Application()
        app.add_routes(
            [
                web.get('/', self.get_static),
                web.get('/speaker.html', self.get_static),
                web.get('/speaker.js', self.get_static),
                web.get('/speaker.css', self.get_static),
                web.get('/logo.svg', self.get_static),
                web.get('/channel', self.get_channel),
            ]
        )

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', self.port)
        print('UI HTTP server at ' + color(f'http://127.0.0.1:{self.port}', 'green'))
        await site.start()

    async def get_static(self, request):
        path = request.path
        if path == '/':
            path = '/speaker.html'
        if path.endswith('.html'):
            content_type = 'text/html'
        elif path.endswith('.js'):
            content_type = 'text/javascript'
        elif path.endswith('.css'):
            content_type = 'text/css'
        elif path.endswith('.svg'):
            content_type = 'image/svg+xml'
        else:
            content_type = 'text/plain'
        text = (
            resources.files("bumble.apps.speaker")
            .joinpath(pathlib.Path(path).relative_to('/'))
            .read_text(encoding="utf-8")
        )
        return aiohttp.web.Response(text=text, content_type=content_type)

    async def get_channel(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        # Process messages until the socket is closed.
        self.channel_socket = ws
        async for message in ws:
            if message.type == aiohttp.WSMsgType.TEXT:
                logger.debug(f'<<< received message: {message.data}')
                await self.on_message(message.data)
            elif message.type == aiohttp.WSMsgType.ERROR:
                logger.debug(
                    f'channel connection closed with exception {ws.exception()}'
                )

        self.channel_socket = None
        logger.debug('--- channel connection closed')

        return ws

    async def on_message(self, message_str: str):
        # Parse the message as JSON
        message = json.loads(message_str)

        # Dispatch the message
        message_type = message['type']
        message_params = message.get('params', {})
        handler = getattr(self, f'on_{message_type}_message')
        if handler:
            await handler(**message_params)

    async def on_hello_message(self):
        await self.send_message(
            'hello',
            bumble_version=bumble.__version__,
            codec=self.speaker().codec,
            streamState=self.speaker().stream_state.name,
        )
        if connection := self.speaker().connection:
            await self.send_message(
                'connection',
                peer_address=connection.peer_address.to_string(False),
                peer_name=connection.peer_name,
            )

    async def send_message(self, message_type: str, **kwargs) -> None:
        if self.channel_socket is None:
            return

        message = {'type': message_type, 'params': kwargs}
        await self.channel_socket.send_json(message)

    async def send_audio(self, data: bytes) -> None:
        if self.channel_socket is None:
            return

        try:
            await self.channel_socket.send_bytes(data)
        except Exception as error:
            logger.warning(f'exception while sending audio packet: {error}')


# -----------------------------------------------------------------------------
class Speaker:
    class StreamState(enum.Enum):
        IDLE = 0
        STOPPED = 1
        STARTED = 2
        SUSPENDED = 3

    def __init__(self, device_config, transport, codec, discover, outputs, ui_port):
        self.device_config = device_config
        self.transport = transport
        self.codec = codec
        self.discover = discover
        self.ui_port = ui_port
        self.device = None
        self.connection = None
        self.listener = None
        self.packets_received = 0
        self.bytes_received = 0
        self.stream_state = Speaker.StreamState.IDLE
        self.outputs = []
        for output in outputs:
            if output == '@ffplay':
                self.outputs.append(FfplayOutput(codec))
                continue

            # Default to FileOutput
            self.outputs.append(FileOutput(output, codec))

        # Create an HTTP server for the UI
        self.ui_server = UiServer(speaker=self, port=ui_port)

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

    async def dispatch_to_outputs(self, function):
        for output in self.outputs:
            await function(output)

    def on_bluetooth_connection(self, connection):
        print(f'Connection: {connection}')
        self.connection = connection
        connection.on('disconnection', self.on_bluetooth_disconnection)
        AsyncRunner.spawn(
            self.dispatch_to_outputs(lambda output: output.on_connection(connection))
        )

    def on_bluetooth_disconnection(self, reason):
        print(f'Disconnection ({reason})')
        self.connection = None
        AsyncRunner.spawn(self.advertise())
        AsyncRunner.spawn(
            self.dispatch_to_outputs(lambda output: output.on_disconnection(reason))
        )

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

        # Discover all endpoints on the remote device is requested
        if self.discover:
            AsyncRunner.spawn(self.discover_remote_endpoints(protocol))

    def on_avdtp_close(self):
        print("Audio Stream Closed")

    def on_sink_start(self):
        print("Sink Started\u001b[0K")
        self.stream_state = self.StreamState.STARTED
        AsyncRunner.spawn(self.dispatch_to_outputs(lambda output: output.start()))

    def on_sink_stop(self):
        print("Sink Stopped\u001b[0K")
        self.stream_state = self.StreamState.STOPPED
        AsyncRunner.spawn(self.dispatch_to_outputs(lambda output: output.stop()))

    def on_sink_suspend(self):
        print("Sink Suspended\u001b[0K")
        self.stream_state = self.StreamState.SUSPENDED
        AsyncRunner.spawn(self.dispatch_to_outputs(lambda output: output.suspend()))

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
        print(
            f'[{self.bytes_received} bytes in {self.packets_received} packets] {packet}',
            end='\r',
        )

        for output in self.outputs:
            output.on_rtp_packet(packet)

    async def advertise(self):
        await self.device.set_discoverable(True)
        await self.device.set_connectable(True)

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
        self.listener.set_server(connection, protocol)
        self.on_avdtp_connection(protocol)

    async def discover_remote_endpoints(self, protocol):
        endpoints = await protocol.discover_remote_endpoints()
        print(f'@@@ Found {len(endpoints)} endpoints')
        for endpoint in endpoints:
            print('@@@', endpoint)

    async def run(self, connect_address):
        await self.ui_server.start_http()
        self.outputs.append(
            WebSocketOutput(
                self.codec, self.ui_server.send_audio, self.ui_server.send_message
            )
        )

        async with await open_transport(self.transport) as (hci_source, hci_sink):
            # Create a device
            device_config = DeviceConfiguration()
            if self.device_config:
                device_config.load_from_file(self.device_config)
            else:
                device_config.name = "Bumble Speaker"
                device_config.class_of_device = 0x240414
                device_config.keystore = "JsonKeyStore"

            device_config.classic_enabled = True
            device_config.le_enabled = False
            self.device = Device.from_config_with_hci(
                device_config, hci_source, hci_sink
            )

            # Setup the SDP to expose the sink service
            self.device.sdp_service_records = self.sdp_records()

            # Don't require MITM when pairing.
            self.device.pairing_config_factory = lambda connection: PairingConfig(
                mitm=False
            )

            # Start the controller
            await self.device.power_on()

            # Print some of the config/properties
            print("Speaker Name:", color(device_config.name, 'yellow'))
            print(
                "Speaker Bluetooth Address:",
                color(
                    self.device.public_address.to_string(with_type_qualifier=False),
                    'yellow',
                ),
            )

            # Listen for Bluetooth connections
            self.device.on('connection', self.on_bluetooth_connection)

            # Create a listener to wait for AVDTP connections
            self.listener = Listener.for_device(self.device)
            self.listener.on('connection', self.on_avdtp_connection)

            print(f'Speaker ready to play, codec={color(self.codec, "cyan")}')

            if connect_address:
                # Connect to the source
                try:
                    await self.connect(connect_address)
                except CommandTimeoutError:
                    print(color("Connection timed out", "red"))
                    return
            else:
                # Start being discoverable and connectable
                print("Waiting for connection...")
                await self.advertise()

            await hci_source.wait_for_termination()

        for output in self.outputs:
            await output.stop()


# -----------------------------------------------------------------------------
@click.group()
@click.pass_context
def speaker_cli(ctx, device_config):
    ctx.ensure_object(dict)
    ctx.obj['device_config'] = device_config


@click.command()
@click.option(
    '--codec', type=click.Choice(['sbc', 'aac']), default='aac', show_default=True
)
@click.option(
    '--discover', is_flag=True, help='Discover remote endpoints once connected'
)
@click.option(
    '--output',
    multiple=True,
    metavar='NAME',
    help=(
        'Send audio to this named output '
        '(may be used more than once for multiple outputs)'
    ),
)
@click.option(
    '--ui-port',
    'ui_port',
    metavar='HTTP_PORT',
    default=DEFAULT_UI_PORT,
    show_default=True,
    help='HTTP port for the UI server',
)
@click.option(
    '--connect',
    'connect_address',
    metavar='ADDRESS_OR_NAME',
    help='Address or name to connect to',
)
@click.option('--device-config', metavar='FILENAME', help='Device configuration file')
@click.argument('transport')
def speaker(
    transport, codec, connect_address, discover, output, ui_port, device_config
):
    """Run the speaker."""

    if '@ffplay' in output:
        # Check if ffplay is installed
        try:
            subprocess.run(['ffplay', '-version'], capture_output=True, check=True)
        except FileNotFoundError:
            print(
                color('ffplay not installed, @ffplay output will be disabled', 'yellow')
            )
            output = list(filter(lambda x: x != '@ffplay', output))

    asyncio.run(
        Speaker(device_config, transport, codec, discover, output, ui_port).run(
            connect_address
        )
    )


# -----------------------------------------------------------------------------
def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())
    speaker()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
