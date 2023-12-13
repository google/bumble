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
import enum
import functools
from importlib import resources
import json
import os
import logging
import pathlib
from typing import Optional, List, cast
import weakref
import struct

import ctypes
import wasmtime
import wasmtime.loader
import liblc3  # type: ignore
import logging

import click
import aiohttp.web

import bumble
from bumble.core import AdvertisingData
from bumble.colors import color
from bumble.device import Device, DeviceConfiguration, AdvertisingParameters
from bumble.transport import open_transport
from bumble.profiles import bap
from bumble.hci import Address, CodecID, CodingFormat, HCI_IsoDataPacket

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_UI_PORT = 7654


def _sink_pac_record() -> bap.PacRecord:
    return bap.PacRecord(
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


def _source_pac_record() -> bap.PacRecord:
    return bap.PacRecord(
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


# -----------------------------------------------------------------------------
# WASM - liblc3
# -----------------------------------------------------------------------------
store = wasmtime.loader.store
_memory = cast(wasmtime.Memory, liblc3.memory)
STACK_POINTER = _memory.data_len(store)
_memory.grow(store, 1)
# Mapping wasmtime memory to linear address
memory = (ctypes.c_ubyte * _memory.data_len(store)).from_address(
    ctypes.addressof(_memory.data_ptr(store).contents)  # type: ignore
)


class Liblc3PcmFormat(enum.IntEnum):
    S16 = 0
    S24 = 1
    S24_3LE = 2
    FLOAT = 3


MAX_DECODER_SIZE = liblc3.lc3_decoder_size(10000, 48000)
MAX_ENCODER_SIZE = liblc3.lc3_encoder_size(10000, 48000)

DECODER_STACK_POINTER = STACK_POINTER
ENCODER_STACK_POINTER = DECODER_STACK_POINTER + MAX_DECODER_SIZE * 2
DECODE_BUFFER_STACK_POINTER = ENCODER_STACK_POINTER + MAX_ENCODER_SIZE * 2
ENCODE_BUFFER_STACK_POINTER = DECODE_BUFFER_STACK_POINTER + 8192
DEFAULT_PCM_SAMPLE_RATE = 48000
DEFAULT_PCM_FORMAT = Liblc3PcmFormat.S16
DEFAULT_PCM_BYTES_PER_SAMPLE = 2


encoders: List[int] = []
decoders: List[int] = []


def setup_encoders(
    sample_rate_hz: int, frame_duration_us: int, num_channels: int
) -> None:
    logger.info(
        f"setup_encoders {sample_rate_hz}Hz {frame_duration_us}us {num_channels}channels"
    )
    encoders[:num_channels] = [
        liblc3.lc3_setup_encoder(
            frame_duration_us,
            sample_rate_hz,
            DEFAULT_PCM_SAMPLE_RATE,  # Input sample rate
            ENCODER_STACK_POINTER + MAX_ENCODER_SIZE * i,
        )
        for i in range(num_channels)
    ]


def setup_decoders(
    sample_rate_hz: int, frame_duration_us: int, num_channels: int
) -> None:
    logger.info(
        f"setup_decoders {sample_rate_hz}Hz {frame_duration_us}us {num_channels}channels"
    )
    decoders[:num_channels] = [
        liblc3.lc3_setup_decoder(
            frame_duration_us,
            sample_rate_hz,
            DEFAULT_PCM_SAMPLE_RATE,  # Output sample rate
            DECODER_STACK_POINTER + MAX_DECODER_SIZE * i,
        )
        for i in range(num_channels)
    ]


def decode(
    frame_duration_us: int,
    num_channels: int,
    input_bytes: bytes,
) -> bytes:
    if not input_bytes:
        return b''

    input_buffer_offset = DECODE_BUFFER_STACK_POINTER
    input_buffer_size = len(input_bytes)
    input_bytes_per_frame = input_buffer_size // num_channels

    # Copy into wasm
    memory[input_buffer_offset : input_buffer_offset + input_buffer_size] = input_bytes  # type: ignore

    output_buffer_offset = input_buffer_offset + input_buffer_size
    output_buffer_size = (
        liblc3.lc3_frame_samples(frame_duration_us, DEFAULT_PCM_SAMPLE_RATE)
        * DEFAULT_PCM_BYTES_PER_SAMPLE
        * num_channels
    )

    for i in range(num_channels):
        res = liblc3.lc3_decode(
            decoders[i],
            input_buffer_offset + input_bytes_per_frame * i,
            input_bytes_per_frame,
            DEFAULT_PCM_FORMAT,
            output_buffer_offset + i * DEFAULT_PCM_BYTES_PER_SAMPLE,
            num_channels,  # Stride
        )

        if res != 0:
            logging.error(f"Parsing failed, res={res}")

    # Extract decoded data from the output buffer
    return bytes(
        memory[output_buffer_offset : output_buffer_offset + output_buffer_size]
    )


def encode(
    sdu_length: int,
    num_channels: int,
    stride: int,
    input_bytes: bytes,
) -> bytes:
    if not input_bytes:
        return b''

    input_buffer_offset = ENCODE_BUFFER_STACK_POINTER
    input_buffer_size = len(input_bytes)

    # Copy into wasm
    memory[input_buffer_offset : input_buffer_offset + input_buffer_size] = input_bytes  # type: ignore

    output_buffer_offset = input_buffer_offset + input_buffer_size
    output_buffer_size = sdu_length
    output_frame_size = output_buffer_size // num_channels

    for i in range(num_channels):
        res = liblc3.lc3_encode(
            encoders[i],
            DEFAULT_PCM_FORMAT,
            input_buffer_offset + DEFAULT_PCM_BYTES_PER_SAMPLE * i,
            stride,
            output_frame_size,
            output_buffer_offset + output_frame_size * i,
        )

        if res != 0:
            logging.error(f"Parsing failed, res={res}")

    # Extract decoded data from the output buffer
    return bytes(
        memory[output_buffer_offset : output_buffer_offset + output_buffer_size]
    )


async def lc3_source_task(
    filename: str,
    sdu_length: int,
    frame_duration_us: int,
    device: Device,
    cis_handle: int,
) -> None:
    with open(filename, 'rb') as f:
        header = f.read(44)
        assert header[8:12] == b'WAVE'

        pcm_num_channel, pcm_sample_rate, _byte_rate, _block_align, bits_per_sample = (
            struct.unpack("<HIIHH", header[22:36])
        )
        assert pcm_sample_rate == DEFAULT_PCM_SAMPLE_RATE
        assert bits_per_sample == DEFAULT_PCM_BYTES_PER_SAMPLE * 8

        frame_bytes = (
            liblc3.lc3_frame_samples(frame_duration_us, DEFAULT_PCM_SAMPLE_RATE)
            * DEFAULT_PCM_BYTES_PER_SAMPLE
        )
        packet_sequence_number = 0

        while True:
            next_round = datetime.datetime.now() + datetime.timedelta(
                microseconds=frame_duration_us
            )
            pcm_data = f.read(frame_bytes)
            sdu = encode(sdu_length, pcm_num_channel, pcm_num_channel, pcm_data)

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
        device_config_path: Optional[str],
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
                bap.PublishedAudioCapabilitiesService(
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

            ascs = bap.AudioStreamControlService(
                self.device, sink_ase_id=[1], source_ase_id=[2]
            )
            self.device.add_service(ascs)

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
                            bytes(bap.PublishedAudioCapabilitiesService.UUID),
                        ),
                    ]
                )
            ) + bytes(bap.UnicastServerAdvertisingData())

            def on_pdu(pdu: HCI_IsoDataPacket, ase: bap.AseStateMachine):
                codec_config = ase.codec_specific_configuration
                assert isinstance(codec_config, bap.CodecSpecificConfiguration)
                pcm = decode(
                    codec_config.frame_duration.us,
                    codec_config.audio_channel_allocation.channel_count,
                    pdu.iso_sdu_fragment,
                )
                self.device.abort_on('disconnection', self.ui_server.send_audio(pcm))

            def on_ase_state_change(ase: bap.AseStateMachine) -> None:
                if ase.state == bap.AseStateMachine.State.STREAMING:
                    codec_config = ase.codec_specific_configuration
                    assert isinstance(codec_config, bap.CodecSpecificConfiguration)
                    assert ase.cis_link
                    if ase.role == bap.AudioRole.SOURCE:
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
                        ase.cis_link.sink = functools.partial(on_pdu, ase=ase)
                elif ase.state == bap.AseStateMachine.State.CODEC_CONFIGURED:
                    codec_config = ase.codec_specific_configuration
                    assert isinstance(codec_config, bap.CodecSpecificConfiguration)
                    if ase.role == bap.AudioRole.SOURCE:
                        setup_encoders(
                            codec_config.sampling_frequency.hz,
                            codec_config.frame_duration.us,
                            codec_config.audio_channel_allocation.channel_count,
                        )
                    else:
                        setup_decoders(
                            codec_config.sampling_frequency.hz,
                            codec_config.frame_duration.us,
                            codec_config.audio_channel_allocation.channel_count,
                        )

            for ase in ascs.ase_state_machines.values():
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
