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
import json
import secrets
import sys

import websockets.asyncio.server

import bumble.logging
from bumble import data_types
from bumble.core import AdvertisingData
from bumble.device import AdvertisingEventProperties, AdvertisingParameters, Device
from bumble.hci import CodecID, CodingFormat, OwnAddressType
from bumble.profiles.ascs import AudioStreamControlService
from bumble.profiles.bap import (
    AudioLocation,
    CodecSpecificCapabilities,
    ContextType,
    SupportedFrameDuration,
    SupportedSamplingFrequency,
    UnicastServerAdvertisingData,
)
from bumble.profiles.cap import CommonAudioServiceService
from bumble.profiles.csip import CoordinatedSetIdentificationService, SirkType
from bumble.profiles.pacs import PacRecord, PublishedAudioCapabilitiesService
from bumble.profiles.vcs import VolumeControlService
from bumble.transport import open_transport


def dumps_volume_state(volume_setting: int, muted: int, change_counter: int) -> str:
    return json.dumps(
        {
            'volume_setting': volume_setting,
            'muted': muted,
            'change_counter': change_counter,
        }
    )


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: run_vcp_renderer.py <config-file><transport-spec-for-device>')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[2]) as hci_transport:
        print('<<< connected')

        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )

        await device.power_on()

        # Add "placeholder" services to enable Android LEA features.
        csis = CoordinatedSetIdentificationService(
            set_identity_resolving_key=secrets.token_bytes(16),
            set_identity_resolving_key_type=SirkType.PLAINTEXT,
        )
        device.add_service(CommonAudioServiceService(csis))
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
                    # Codec Capability Setting 48_4
                    PacRecord(
                        coding_format=CodingFormat(CodecID.LC3),
                        codec_specific_capabilities=CodecSpecificCapabilities(
                            supported_sampling_frequencies=(
                                SupportedSamplingFrequency.FREQ_48000
                            ),
                            supported_frame_durations=(
                                SupportedFrameDuration.DURATION_10000_US_SUPPORTED
                            ),
                            supported_audio_channel_count=[1],
                            min_octets_per_codec_frame=120,
                            max_octets_per_codec_frame=120,
                            supported_max_codec_frames_per_sdu=1,
                        ),
                    ),
                ],
            )
        )
        device.add_service(AudioStreamControlService(device, sink_ase_id=[1, 2]))

        vcs = VolumeControlService()
        device.add_service(vcs)

        ws: websockets.asyncio.server.ServerConnection | None = None

        def on_volume_state_change():
            if ws:
                asyncio.create_task(
                    ws.send(
                        dumps_volume_state(
                            vcs.volume_setting, vcs.muted, vcs.change_counter
                        )
                    )
                )

        vcs.on('volume_state_change', on_volume_state_change)

        advertising_data = (
            bytes(
                AdvertisingData(
                    [
                        data_types.CompleteLocalName('Bumble LE Audio'),
                        data_types.Flags(
                            AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG
                            | AdvertisingData.BR_EDR_HOST_FLAG
                            | AdvertisingData.BR_EDR_CONTROLLER_FLAG
                        ),
                        data_types.IncompleteListOf16BitServiceUUIDs(
                            [PublishedAudioCapabilitiesService.UUID]
                        ),
                    ]
                )
            )
            + csis.get_advertising_data()
            + bytes(UnicastServerAdvertisingData())
        )

        await device.create_advertising_set(
            advertising_parameters=AdvertisingParameters(
                advertising_event_properties=AdvertisingEventProperties(),
                own_address_type=OwnAddressType.PUBLIC,
            ),
            advertising_data=advertising_data,
        )

        async def serve(websocket: websockets.asyncio.server.ServerConnection):
            nonlocal ws
            await websocket.send(
                dumps_volume_state(vcs.volume_setting, vcs.muted, vcs.change_counter)
            )
            ws = websocket
            async for message in websocket:
                volume_state = json.loads(message)
                vcs.volume_setting = volume_state['volume_setting']
                vcs.muted = volume_state['muted']
                vcs.change_counter = volume_state['change_counter']
                await device.notify_subscribers(vcs.volume_state)
            ws = None

        await websockets.asyncio.server.serve(serve, 'localhost', 8989)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
