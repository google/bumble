# Copyright 2025 Google LLC
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
import os
import sys

from bumble.colors import color
from bumble.device import Device, Peer
from bumble.profiles.ams import (
    AmsClient,
    EntityId,
    PlayerAttributeId,
    QueueAttributeId,
    RemoteCommandId,
    TrackAttributeId,
)
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def handle_command_client(
    ams_client: AmsClient, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    while True:
        command = (await reader.readline()).decode("utf-8")
        if not command.endswith("\n"):
            print("command client terminated")
            return
        command = command.strip()

        try:
            if command.upper() in [member.name for member in RemoteCommandId]:
                await ams_client.command(RemoteCommandId[command.upper()])
                continue
        except Exception as error:
            writer.write(f"ERROR: {error}\n".encode())

        writer.write(f"unknown command {command}\n".encode())


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_ams_client.py <device-config> <transport-spec> '
            '<bluetooth-address> <mtu>'
        )
        print('example: run_ams_client.py device1.json usb:0 E1:CA:72:48:C4:E8 512')
        return
    device_config, transport_spec, bluetooth_address, mtu = sys.argv[1:]

    print('<<< connecting to HCI...')
    async with await open_transport(transport_spec) as hci_transport:
        print('<<< connected')

        # Create a device to manage the host, with a custom listener
        device = Device.from_config_file_with_hci(
            device_config, hci_transport.source, hci_transport.sink
        )
        await device.power_on()

        # Connect to the peer
        print(f'=== Connecting to {bluetooth_address}...')
        connection = await device.connect(bluetooth_address)
        print(f'=== Connected: {connection}')

        await connection.encrypt()

        peer = Peer(connection)
        mtu_int = int(mtu)
        if mtu_int:
            new_mtu = await peer.request_mtu(mtu_int)
            print(f'ATT MTU = {new_mtu}')
        ams_client = await AmsClient.for_peer(peer)
        if ams_client is None:
            print("!!! no AMS service found")
            return

        # Register event handlers

        def on_supported_commands():
            print(
                color("Supported commands:", "magenta"),
                ", ".join([command.name for command in ams_client.supported_commands]),
            )

        ams_client.on(AmsClient.EVENT_SUPPORTED_COMMANDS, on_supported_commands)

        def on_player_name():
            print(color("Player Name:", "green"), ams_client.player_name)

        ams_client.on(AmsClient.EVENT_PLAYER_NAME, on_player_name)

        def on_player_playback_info():
            print(
                color("Playback State:", "green"),
                ams_client.player_playback_info.playback_state.name,
            )
            print(
                color("Playback Rate: ", "green"),
                ams_client.player_playback_info.playback_rate,
            )
            print(
                color("Elapsed Time:  ", "green"),
                ams_client.player_playback_info.elapsed_time,
            )

        ams_client.on(AmsClient.EVENT_PLAYER_PLAYBACK_INFO, on_player_playback_info)

        def on_player_volume():
            print(color("Volume:", "green"), ams_client.player_volume)

        ams_client.on(AmsClient.EVENT_PLAYER_VOLUME, on_player_volume)

        def on_queue_count():
            print(color("Queue Count:", "yellow"), ams_client.queue_count)

        ams_client.on(AmsClient.EVENT_QUEUE_COUNT, on_queue_count)

        def on_queue_index():
            print(color("Queue Index:", "yellow"), ams_client.queue_index)

        ams_client.on(AmsClient.EVENT_QUEUE_INDEX, on_queue_index)

        def on_queue_shuffle_mode():
            print(
                color("Queue Shuffle Mode:", "yellow"),
                ams_client.queue_shuffle_mode.name,
            )

        ams_client.on(AmsClient.EVENT_QUEUE_SHUFFLE_MODE, on_queue_shuffle_mode)

        def on_queue_repeat_mode():
            print(
                color("Queue Repeat Mode:", "yellow"), ams_client.queue_repeat_mode.name
            )

        ams_client.on(AmsClient.EVENT_QUEUE_REPEAT_MODE, on_queue_repeat_mode)

        def on_track_artist():
            print(color("Track Artist:", "cyan"), ams_client.track_artist)

        ams_client.on(AmsClient.EVENT_TRACK_ARTIST, on_track_artist)

        def on_track_album():
            print(color("Track Album:", "cyan"), ams_client.track_album)

        ams_client.on(AmsClient.EVENT_TRACK_ALBUM, on_track_album)

        def on_track_title():
            print(color("Track Title:", "cyan"), ams_client.track_title)

        ams_client.on(AmsClient.EVENT_TRACK_TITLE, on_track_title)

        def on_track_duration():
            print(color("Track Duration:", "cyan"), ams_client.track_duration)

        ams_client.on(AmsClient.EVENT_TRACK_DURATION, on_track_duration)

        # Start the client
        await ams_client.start()

        # Observe the player, queue and track
        await ams_client.observe(
            EntityId.PLAYER,
            [
                PlayerAttributeId.NAME,
                PlayerAttributeId.PLAYBACK_INFO,
                PlayerAttributeId.VOLUME,
            ],
        )
        await ams_client.observe(
            EntityId.QUEUE,
            [
                QueueAttributeId.COUNT,
                QueueAttributeId.INDEX,
                QueueAttributeId.REPEAT_MODE,
                QueueAttributeId.SHUFFLE_MODE,
            ],
        )
        await ams_client.observe(
            EntityId.TRACK,
            [
                TrackAttributeId.ALBUM,
                TrackAttributeId.ARTIST,
                TrackAttributeId.DURATION,
                TrackAttributeId.TITLE,
            ],
        )

        # Accept a TCP connection to handle commands.
        tcp_server = await asyncio.start_server(
            lambda reader, writer: handle_command_client(ams_client, reader, writer),
            '127.0.0.1',
            9000,
        )
        print("Accepting command client on port 9000")
        async with tcp_server:
            await tcp_server.serve_forever()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
asyncio.run(main())
