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
import asyncio
import logging
import sys
import os
import websockets
import json

from bumble import utils
from bumble.core import AdvertisingData
from bumble.device import (
    Device,
    AdvertisingParameters,
    AdvertisingEventProperties,
    Connection,
    Peer,
)
from bumble.hci import (
    CodecID,
    CodingFormat,
    OwnAddressType,
)
from bumble.profiles.ascs import AudioStreamControlService
from bumble.profiles.bap import (
    CodecSpecificCapabilities,
    ContextType,
    AudioLocation,
    SupportedSamplingFrequency,
    SupportedFrameDuration,
    UnicastServerAdvertisingData,
)
from bumble.profiles.mcp import (
    MediaControlServiceProxy,
    GenericMediaControlServiceProxy,
    MediaState,
    MediaControlPointOpcode,
)
from bumble.profiles.pacs import PacRecord, PublishedAudioCapabilitiesService
from bumble.transport import open_transport_or_link

from typing import Optional


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: run_mcp_client.py <config-file>' '<transport-spec-for-device>')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )

        await device.power_on()

        # Add "placeholder" services to enable Android LEA features.
        device.add_service(
            PublishedAudioCapabilitiesService(
                supported_source_context=ContextType.PROHIBITED,
                available_source_context=ContextType.PROHIBITED,
                supported_sink_context=ContextType.MEDIA,
                available_sink_context=ContextType.MEDIA,
                sink_audio_locations=(
                    AudioLocation.FRONT_LEFT | AudioLocation.FRONT_RIGHT
                ),
                sink_pac=[
                    PacRecord(
                        coding_format=CodingFormat(CodecID.LC3),
                        codec_specific_capabilities=CodecSpecificCapabilities(
                            supported_sampling_frequencies=(
                                SupportedSamplingFrequency.FREQ_16000
                                | SupportedSamplingFrequency.FREQ_32000
                                | SupportedSamplingFrequency.FREQ_48000
                            ),
                            supported_frame_durations=(
                                SupportedFrameDuration.DURATION_10000_US_SUPPORTED
                            ),
                            supported_audio_channel_count=[1, 2],
                            min_octets_per_codec_frame=0,
                            max_octets_per_codec_frame=320,
                            supported_max_codec_frames_per_sdu=2,
                        ),
                    ),
                ],
            )
        )
        device.add_service(AudioStreamControlService(device, sink_ase_id=[1]))

        ws: Optional[websockets.WebSocketServerProtocol] = None
        mcp: Optional[MediaControlServiceProxy] = None

        advertising_data = bytes(
            AdvertisingData(
                [
                    (
                        AdvertisingData.COMPLETE_LOCAL_NAME,
                        bytes('Bumble LE Audio', 'utf-8'),
                    ),
                    (
                        AdvertisingData.FLAGS,
                        bytes([AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG]),
                    ),
                    (
                        AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                        bytes(PublishedAudioCapabilitiesService.UUID),
                    ),
                ]
            )
        ) + bytes(UnicastServerAdvertisingData())

        await device.create_advertising_set(
            advertising_parameters=AdvertisingParameters(
                advertising_event_properties=AdvertisingEventProperties(),
                own_address_type=OwnAddressType.RANDOM,
                primary_advertising_interval_max=100,
                primary_advertising_interval_min=100,
            ),
            advertising_data=advertising_data,
            auto_restart=True,
        )

        def on_media_state(media_state: MediaState) -> None:
            if ws:
                asyncio.create_task(
                    ws.send(json.dumps({'media_state': media_state.name}))
                )

        def on_track_title(title: str) -> None:
            if ws:
                asyncio.create_task(ws.send(json.dumps({'title': title})))

        def on_track_duration(duration: int) -> None:
            if ws:
                asyncio.create_task(ws.send(json.dumps({'duration': duration})))

        def on_track_position(position: int) -> None:
            if ws:
                asyncio.create_task(ws.send(json.dumps({'position': position})))

        def on_connection(connection: Connection) -> None:
            async def on_connection_async():
                async with Peer(connection) as peer:
                    nonlocal mcp
                    mcp = peer.create_service_proxy(MediaControlServiceProxy)
                    if not mcp:
                        mcp = peer.create_service_proxy(GenericMediaControlServiceProxy)
                    mcp.on('media_state', on_media_state)
                    mcp.on('track_title', on_track_title)
                    mcp.on('track_duration', on_track_duration)
                    mcp.on('track_position', on_track_position)
                    await mcp.subscribe_characteristics()

            utils.cancel_on_event(connection, 'disconnection', on_connection_async())

        device.on('connection', on_connection)

        async def serve(websocket: websockets.WebSocketServerProtocol, _path):
            nonlocal ws
            ws = websocket
            async for message in websocket:
                request = json.loads(message)
                if mcp:
                    await mcp.write_control_point(
                        MediaControlPointOpcode(request['opcode'])
                    )
            ws = None

        await websockets.serve(serve, 'localhost', 8989)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
