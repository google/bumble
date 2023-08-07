# Copyright 2023 Google LLC
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
import json
import sys
import os
import logging
import websockets

from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import BT_BR_EDR_TRANSPORT
from bumble import avc
from bumble import avrcp
from bumble import avdtp
from bumble import a2dp
from bumble import utils


logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def sdp_records():
    a2dp_sink_service_record_handle = 0x00010001
    avrcp_controller_service_record_handle = 0x00010002
    avrcp_target_service_record_handle = 0x00010003
    # pylint: disable=line-too-long
    return {
        a2dp_sink_service_record_handle: a2dp.make_audio_sink_service_sdp_records(
            a2dp_sink_service_record_handle
        ),
        avrcp_controller_service_record_handle: avrcp.make_controller_service_sdp_records(
            avrcp_controller_service_record_handle
        ),
        avrcp_target_service_record_handle: avrcp.make_target_service_sdp_records(
            avrcp_controller_service_record_handle
        ),
    }


# -----------------------------------------------------------------------------
def codec_capabilities():
    return avdtp.MediaCodecCapabilities(
        media_type=avdtp.AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=a2dp.A2DP_SBC_CODEC_TYPE,
        media_codec_information=a2dp.SbcMediaCodecInformation.from_lists(
            sampling_frequencies=[48000, 44100, 32000, 16000],
            channel_modes=[
                a2dp.SBC_MONO_CHANNEL_MODE,
                a2dp.SBC_DUAL_CHANNEL_MODE,
                a2dp.SBC_STEREO_CHANNEL_MODE,
                a2dp.SBC_JOINT_STEREO_CHANNEL_MODE,
            ],
            block_lengths=[4, 8, 12, 16],
            subbands=[4, 8],
            allocation_methods=[
                a2dp.SBC_LOUDNESS_ALLOCATION_METHOD,
                a2dp.SBC_SNR_ALLOCATION_METHOD,
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
    print(f'RTP: {packet}')


# -----------------------------------------------------------------------------
def on_avrcp_start(avrcp_protocol: avrcp.Protocol, websocket_server: WebSocketServer):
    async def get_supported_events():
        events = await avrcp_protocol.get_supported_events()
        print("SUPPORTED EVENTS:", events)
        websocket_server.send_message(
            {
                "type": "supported-events",
                "params": {"events": [event.name for event in events]},
            }
        )

        if avrcp.EventId.TRACK_CHANGED in events:
            utils.AsyncRunner.spawn(monitor_track_changed())

        if avrcp.EventId.PLAYBACK_STATUS_CHANGED in events:
            utils.AsyncRunner.spawn(monitor_playback_status())

        if avrcp.EventId.PLAYBACK_POS_CHANGED in events:
            utils.AsyncRunner.spawn(monitor_playback_position())

        if avrcp.EventId.PLAYER_APPLICATION_SETTING_CHANGED in events:
            utils.AsyncRunner.spawn(monitor_player_application_settings())

        if avrcp.EventId.AVAILABLE_PLAYERS_CHANGED in events:
            utils.AsyncRunner.spawn(monitor_available_players())

        if avrcp.EventId.ADDRESSED_PLAYER_CHANGED in events:
            utils.AsyncRunner.spawn(monitor_addressed_player())

        if avrcp.EventId.UIDS_CHANGED in events:
            utils.AsyncRunner.spawn(monitor_uids())

        if avrcp.EventId.VOLUME_CHANGED in events:
            utils.AsyncRunner.spawn(monitor_volume())

    utils.AsyncRunner.spawn(get_supported_events())

    async def monitor_track_changed():
        async for identifier in avrcp_protocol.monitor_track_changed():
            print("TRACK CHANGED:", identifier.hex())
            websocket_server.send_message(
                {"type": "track-changed", "params": {"identifier": identifier.hex()}}
            )

    async def monitor_playback_status():
        async for playback_status in avrcp_protocol.monitor_playback_status():
            print("PLAYBACK STATUS CHANGED:", playback_status.name)
            websocket_server.send_message(
                {
                    "type": "playback-status-changed",
                    "params": {"status": playback_status.name},
                }
            )

    async def monitor_playback_position():
        async for playback_position in avrcp_protocol.monitor_playback_position(
            playback_interval=1
        ):
            print("PLAYBACK POSITION CHANGED:", playback_position)
            websocket_server.send_message(
                {
                    "type": "playback-position-changed",
                    "params": {"position": playback_position},
                }
            )

    async def monitor_player_application_settings():
        async for settings in avrcp_protocol.monitor_player_application_settings():
            print("PLAYER APPLICATION SETTINGS:", settings)
            settings_as_dict = [
                {"attribute": setting.attribute_id.name, "value": setting.value_id.name}
                for setting in settings
            ]
            websocket_server.send_message(
                {
                    "type": "player-settings-changed",
                    "params": {"settings": settings_as_dict},
                }
            )

    async def monitor_available_players():
        async for _ in avrcp_protocol.monitor_available_players():
            print("AVAILABLE PLAYERS CHANGED")
            websocket_server.send_message(
                {"type": "available-players-changed", "params": {}}
            )

    async def monitor_addressed_player():
        async for player in avrcp_protocol.monitor_addressed_player():
            print("ADDRESSED PLAYER CHANGED")
            websocket_server.send_message(
                {
                    "type": "addressed-player-changed",
                    "params": {
                        "player": {
                            "player_id": player.player_id,
                            "uid_counter": player.uid_counter,
                        }
                    },
                }
            )

    async def monitor_uids():
        async for uid_counter in avrcp_protocol.monitor_uids():
            print("UIDS CHANGED")
            websocket_server.send_message(
                {
                    "type": "uids-changed",
                    "params": {
                        "uid_counter": uid_counter,
                    },
                }
            )

    async def monitor_volume():
        async for volume in avrcp_protocol.monitor_volume():
            print("VOLUME CHANGED:", volume)
            websocket_server.send_message(
                {"type": "volume-changed", "params": {"volume": volume}}
            )


# -----------------------------------------------------------------------------
class WebSocketServer:
    def __init__(
        self, avrcp_protocol: avrcp.Protocol, avrcp_delegate: Delegate
    ) -> None:
        self.socket = None
        self.delegate = None
        self.avrcp_protocol = avrcp_protocol
        self.avrcp_delegate = avrcp_delegate

    async def start(self) -> None:
        # pylint: disable-next=no-member
        await websockets.serve(self.serve, 'localhost', 8989)  # type: ignore

    async def serve(self, socket, _path) -> None:
        print('### WebSocket connected')
        self.socket = socket
        while True:
            try:
                message = await socket.recv()
                print('Received: ', str(message))

                parsed = json.loads(message)
                message_type = parsed['type']
                if message_type == 'send-key-down':
                    await self.on_send_key_down(parsed)
                elif message_type == 'send-key-up':
                    await self.on_send_key_up(parsed)
                elif message_type == 'set-volume':
                    await self.on_set_volume(parsed)
                elif message_type == 'get-play-status':
                    await self.on_get_play_status()
                elif message_type == 'get-element-attributes':
                    await self.on_get_element_attributes()
            except websockets.exceptions.ConnectionClosedOK:
                self.socket = None
                break

    async def on_send_key_down(self, message: dict) -> None:
        key = avc.PassThroughFrame.OperationId[message["key"]]
        await self.avrcp_protocol.send_key_event(key, True)

    async def on_send_key_up(self, message: dict) -> None:
        key = avc.PassThroughFrame.OperationId[message["key"]]
        await self.avrcp_protocol.send_key_event(key, False)

    async def on_set_volume(self, message: dict) -> None:
        volume = message["volume"]
        self.avrcp_delegate.volume = volume
        self.avrcp_protocol.notify_volume_changed(volume)

    async def on_get_play_status(self) -> None:
        play_status = await self.avrcp_protocol.get_play_status()
        self.send_message(
            {
                "type": "get-play-status-response",
                "params": {
                    "song_length": play_status.song_length,
                    "song_position": play_status.song_position,
                    "play_status": play_status.play_status.name,
                },
            }
        )

    async def on_get_element_attributes(self) -> None:
        attributes = await self.avrcp_protocol.get_element_attributes(
            0,
            [
                avrcp.MediaAttributeId.TITLE,
                avrcp.MediaAttributeId.ARTIST_NAME,
                avrcp.MediaAttributeId.ALBUM_NAME,
                avrcp.MediaAttributeId.TRACK_NUMBER,
                avrcp.MediaAttributeId.TOTAL_NUMBER_OF_TRACKS,
                avrcp.MediaAttributeId.GENRE,
                avrcp.MediaAttributeId.PLAYING_TIME,
                avrcp.MediaAttributeId.DEFAULT_COVER_ART,
            ],
        )
        self.send_message(
            {
                "type": "get-element-attributes-response",
                "params": [
                    {
                        "attribute_id": attribute.attribute_id.name,
                        "attribute_value": attribute.attribute_value,
                    }
                    for attribute in attributes
                ],
            }
        )

    def send_message(self, message: dict) -> None:
        if self.socket is None:
            print("no socket, dropping message")
            return
        serialized = json.dumps(message)
        utils.AsyncRunner.spawn(self.socket.send(serialized))


# -----------------------------------------------------------------------------
class Delegate(avrcp.Delegate):
    def __init__(self):
        super().__init__(
            [avrcp.EventId.VOLUME_CHANGED, avrcp.EventId.PLAYBACK_STATUS_CHANGED]
        )
        self.websocket_server = None

    async def set_absolute_volume(self, volume: int) -> None:
        await super().set_absolute_volume(volume)
        if self.websocket_server is not None:
            self.websocket_server.send_message(
                {"type": "set-volume", "params": {"volume": volume}}
            )


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print(
            'Usage: run_avrcp_controller.py <device-config> <transport-spec> '
            '<sbc-file> [<bt-addr>]'
        )
        print('example: run_avrcp_controller.py classic1.json usb:0')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True

        # Setup the SDP to expose the sink service
        device.sdp_service_records = sdp_records()

        # Start the controller
        await device.power_on()

        # Create a listener to wait for AVDTP connections
        listener = avdtp.Listener(avdtp.Listener.create_registrar(device))
        listener.on('connection', on_avdtp_connection)

        avrcp_delegate = Delegate()
        avrcp_protocol = avrcp.Protocol(avrcp_delegate)
        avrcp_protocol.listen(device)

        websocket_server = WebSocketServer(avrcp_protocol, avrcp_delegate)
        avrcp_delegate.websocket_server = websocket_server
        avrcp_protocol.on(
            "start", lambda: on_avrcp_start(avrcp_protocol, websocket_server)
        )
        await websocket_server.start()

        if len(sys.argv) >= 5:
            # Connect to the peer
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

            server = await avdtp.Protocol.connect(connection)
            listener.set_server(connection, server)
            sink = server.add_sink(codec_capabilities())
            sink.on('rtp_packet', on_rtp_packet)

            await avrcp_protocol.connect(connection)

        else:
            # Start being discoverable and connectable
            await device.set_discoverable(True)
            await device.set_connectable(True)

        await asyncio.get_event_loop().create_future()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
