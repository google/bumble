# Copyright 2021-2024 Google LLC
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
import datetime
import functools
from importlib import resources
import json
import os
import logging
import pathlib
import weakref
import lc3
import wave

import click
import aiohttp.web

import bumble
from bumble.core import AdvertisingData
from bumble.colors import color
from bumble.device import Device, DeviceConfiguration, AdvertisingParameters
from bumble.transport import open_transport
from bumble.profiles import ascs, bap, pacs
from bumble.hci import Address, CodecID, CodingFormat, HCI_IsoDataPacket


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_UI_PORT = 7654
DEFAULT_PCM_BYTES_PER_SAMPLE = 2


def _sink_pac_record() -> pacs.PacRecord:
    return pacs.PacRecord(
        coding_format=CodingFormat(CodecID.LC3),
        codec_specific_capabilities=bap.CodecSpecificCapabilities(
            supported_sampling_frequencies=(
                bap.SupportedSamplingFrequency.FREQ_8000
                | bap.SupportedSamplingFrequency.FREQ_16000
                | bap.SupportedSamplingFrequency.FREQ_24000
                | bap.SupportedSamplingFrequency.FREQ_32000
                | bap.SupportedSamplingFrequency.FREQ_48000
            ),
            supported_frame_durations=(
                bap.SupportedFrameDuration.DURATION_10000_US_SUPPORTED
            ),
            supported_audio_channel_count=[1, 2],
            min_octets_per_codec_frame=26,
            max_octets_per_codec_frame=240,
            supported_max_codec_frames_per_sdu=2,
        ),
    )


def _source_pac_record() -> pacs.PacRecord:
    return pacs.PacRecord(
        coding_format=CodingFormat(CodecID.LC3),
        codec_specific_capabilities=bap.CodecSpecificCapabilities(
            supported_sampling_frequencies=(
                bap.SupportedSamplingFrequency.FREQ_8000
                | bap.SupportedSamplingFrequency.FREQ_16000
                | bap.SupportedSamplingFrequency.FREQ_24000
                | bap.SupportedSamplingFrequency.FREQ_32000
                | bap.SupportedSamplingFrequency.FREQ_48000
            ),
            supported_frame_durations=(
                bap.SupportedFrameDuration.DURATION_10000_US_SUPPORTED
            ),
            supported_audio_channel_count=[1],
            min_octets_per_codec_frame=30,
            max_octets_per_codec_frame=100,
            supported_max_codec_frames_per_sdu=1,
        ),
    )


decoder: lc3.Decoder | None = None
encoder: lc3.Encoder | None = None


async def lc3_source_task(
    filename: str,
    sdu_length: int,
    frame_duration_us: int,
    device: Device,
    cis_handle: int,
) -> None:
    assert encoder
    with wave.open(filename, 'rb') as wav:
        assert (
            bits_per_sample := wav.getsampwidth()
        ) == DEFAULT_PCM_BYTES_PER_SAMPLE * 8

        frame_samples = encoder.get_frame_samples()
        packet_sequence_number = 0

        while True:
            next_round = datetime.datetime.now() + datetime.timedelta(
                microseconds=frame_duration_us
            )
            sdu = encoder.encode(
                pcm=wav.readframes(frame_samples),
                num_bytes=sdu_length,
                bit_depth=bits_per_sample,
            )

            iso_packet = HCI_IsoDataPacket(
                connection_handle=cis_handle,
                data_total_length=sdu_length + 4,
                packet_sequence_number=packet_sequence_number,
                pb_flag=0b10,
                packet_status_flag=0,
                iso_sdu_length=sdu_length,
                iso_sdu_fragment=sdu,
            )
            device.host.send_hci_packet(iso_packet)
            packet_sequence_number += 1
            sleep_time = next_round - datetime.datetime.now()
            await asyncio.sleep(sleep_time.total_seconds())


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

        app = aiohttp.web.Application()
        app.add_routes(
            [
                aiohttp.web.get('/', self.get_static),
                aiohttp.web.get('/index.html', self.get_static),
                aiohttp.web.get('/channel', self.get_channel),
            ]
        )

        runner = aiohttp.web.AppRunner(app)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, 'localhost', self.port)
        print('UI HTTP server at ' + color(f'http://127.0.0.1:{self.port}', 'green'))
        await site.start()

    async def get_static(self, request):
        path = request.path
        if path == '/':
            path = '/index.html'
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
            resources.files("bumble.apps.lea_unicast")
            .joinpath(pathlib.Path(path).relative_to('/'))
            .read_text(encoding="utf-8")
        )
        return aiohttp.web.Response(text=text, content_type=content_type)

    async def get_channel(self, request):
        ws = aiohttp.web.WebSocketResponse()
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

    def __init__(
        self,
        device_config_path: str | None,
        ui_port: int,
        transport: str,
        lc3_input_file_path: str,
    ):
        self.device_config_path = device_config_path
        self.transport = transport
        self.lc3_input_file_path = lc3_input_file_path

        # Create an HTTP server for the UI
        self.ui_server = UiServer(speaker=self, port=ui_port)

    async def run(self) -> None:
        await self.ui_server.start_http()

        async with await open_transport(self.transport) as hci_transport:
            # Create a device
            if self.device_config_path:
                device_config = DeviceConfiguration.from_file(self.device_config_path)
            else:
                device_config = DeviceConfiguration(
                    name="Bumble LE Headphone",
                    class_of_device=0x244418,
                    keystore="JsonKeyStore",
                    advertising_interval_min=25,
                    advertising_interval_max=25,
                    address=Address('F1:F2:F3:F4:F5:F6'),
                )

            device_config.le_enabled = True
            device_config.cis_enabled = True
            self.device = Device.from_config_with_hci(
                device_config, hci_transport.source, hci_transport.sink
            )

            self.device.add_service(
                pacs.PublishedAudioCapabilitiesService(
                    supported_source_context=bap.ContextType(0xFFFF),
                    available_source_context=bap.ContextType(0xFFFF),
                    supported_sink_context=bap.ContextType(0xFFFF),  # All context types
                    available_sink_context=bap.ContextType(0xFFFF),  # All context types
                    sink_audio_locations=(
                        bap.AudioLocation.FRONT_LEFT | bap.AudioLocation.FRONT_RIGHT
                    ),
                    sink_pac=[_sink_pac_record()],
                    source_audio_locations=bap.AudioLocation.FRONT_LEFT,
                    source_pac=[_source_pac_record()],
                )
            )

            ascs_service = ascs.AudioStreamControlService(
                self.device, sink_ase_id=[1], source_ase_id=[2]
            )
            self.device.add_service(ascs_service)

            advertising_data = bytes(
                AdvertisingData(
                    [
                        (
                            AdvertisingData.COMPLETE_LOCAL_NAME,
                            bytes(device_config.name, 'utf-8'),
                        ),
                        (
                            AdvertisingData.FLAGS,
                            bytes([AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG]),
                        ),
                        (
                            AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                            bytes(pacs.PublishedAudioCapabilitiesService.UUID),
                        ),
                    ]
                )
            ) + bytes(bap.UnicastServerAdvertisingData())

            def on_pdu(pdu: HCI_IsoDataPacket, ase: ascs.AseStateMachine):
                codec_config = ase.codec_specific_configuration
                if (
                    not isinstance(codec_config, bap.CodecSpecificConfiguration)
                    or codec_config.frame_duration is None
                    or codec_config.audio_channel_allocation is None
                    or decoder is None
                ):
                    return
                pcm = decoder.decode(
                    pdu.iso_sdu_fragment, bit_depth=DEFAULT_PCM_BYTES_PER_SAMPLE * 8
                )
                self.device.abort_on('disconnection', self.ui_server.send_audio(pcm))

            def on_ase_state_change(ase: ascs.AseStateMachine) -> None:
                codec_config = ase.codec_specific_configuration
                if ase.state == ascs.AseStateMachine.State.STREAMING:
                    if ase.role == ascs.AudioRole.SOURCE:
                        if (
                            not isinstance(codec_config, bap.CodecSpecificConfiguration)
                            or ase.cis_link is None
                            or codec_config.octets_per_codec_frame is None
                            or codec_config.frame_duration is None
                            or codec_config.codec_frames_per_sdu is None
                        ):
                            return
                        ase.cis_link.abort_on(
                            'disconnection',
                            lc3_source_task(
                                filename=self.lc3_input_file_path,
                                sdu_length=(
                                    codec_config.codec_frames_per_sdu
                                    * codec_config.octets_per_codec_frame
                                ),
                                frame_duration_us=codec_config.frame_duration.us,
                                device=self.device,
                                cis_handle=ase.cis_link.handle,
                            ),
                        )
                    else:
                        if not ase.cis_link:
                            return
                        ase.cis_link.sink = functools.partial(on_pdu, ase=ase)
                elif ase.state == ascs.AseStateMachine.State.CODEC_CONFIGURED:
                    if (
                        not isinstance(codec_config, bap.CodecSpecificConfiguration)
                        or codec_config.sampling_frequency is None
                        or codec_config.frame_duration is None
                        or codec_config.audio_channel_allocation is None
                    ):
                        return
                    if ase.role == ascs.AudioRole.SOURCE:
                        global encoder
                        encoder = lc3.Encoder(
                            frame_duration_us=codec_config.frame_duration.us,
                            sample_rate_hz=codec_config.sampling_frequency.hz,
                            num_channels=codec_config.audio_channel_allocation.channel_count,
                        )
                    else:
                        global decoder
                        decoder = lc3.Decoder(
                            frame_duration_us=codec_config.frame_duration.us,
                            sample_rate_hz=codec_config.sampling_frequency.hz,
                            num_channels=codec_config.audio_channel_allocation.channel_count,
                        )

            for ase in ascs_service.ase_state_machines.values():
                ase.on('state_change', functools.partial(on_ase_state_change, ase=ase))

            await self.device.power_on()
            await self.device.create_advertising_set(
                advertising_data=advertising_data,
                auto_restart=True,
                advertising_parameters=AdvertisingParameters(
                    primary_advertising_interval_min=100,
                    primary_advertising_interval_max=100,
                ),
            )

            await hci_transport.source.terminated


@click.command()
@click.option(
    '--ui-port',
    'ui_port',
    metavar='HTTP_PORT',
    default=DEFAULT_UI_PORT,
    show_default=True,
    help='HTTP port for the UI server',
)
@click.option('--device-config', metavar='FILENAME', help='Device configuration file')
@click.argument('transport')
@click.argument('lc3_file')
def speaker(ui_port: int, device_config: str, transport: str, lc3_file: str) -> None:
    """Run the speaker."""

    asyncio.run(Speaker(device_config, ui_port, transport, lc3_file).run())


# -----------------------------------------------------------------------------
def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())
    speaker()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
