# Copyright 2026 Google LLC
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

from __future__ import annotations

import asyncio

import pytest

from bumble import device as device_module
from bumble import gatt
from bumble.profiles import ams
from bumble.testing import test_utils

TIMEOUT = 1.0


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_for_peer_no_service() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    peer = device_module.Peer(devices.connections[1])
    client = await ams.AmsClient.for_peer(peer)
    assert client is None


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_commands_and_observe() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    service = ams.Ams()
    devices[0].add_service(service)

    remote_commands: list[bytes] = []
    observed_entities: list[bytes] = []

    service.remote_command_characteristic.value = gatt.CharacteristicValue(
        write=lambda _conn, val: remote_commands.append(val)
    )
    service.entity_update_characteristic.value = gatt.CharacteristicValue(
        write=lambda _conn, val: observed_entities.append(val)
    )

    peer = device_module.Peer(devices.connections[1])
    client = await ams.AmsClient.for_peer(peer)
    assert client is not None
    await client.start()

    # Supported commands notification
    supported_event = asyncio.Event()
    client.on(ams.AmsClient.EVENT_SUPPORTED_COMMANDS, supported_event.set)
    await devices[0].notify_subscribers(
        service.remote_command_characteristic,
        bytes([ams.RemoteCommandId.PLAY, ams.RemoteCommandId.PAUSE]),
    )
    await asyncio.wait_for(supported_event.wait(), TIMEOUT)
    assert client.supported_commands == {
        ams.RemoteCommandId.PLAY,
        ams.RemoteCommandId.PAUSE,
    }

    # Observe
    await client.observe(
        ams.EntityId.PLAYER,
        [ams.PlayerAttributeId.NAME, ams.PlayerAttributeId.VOLUME],
    )
    assert observed_entities == [
        bytes(
            [
                ams.EntityId.PLAYER,
                ams.PlayerAttributeId.NAME,
                ams.PlayerAttributeId.VOLUME,
            ]
        )
    ]

    # Remote commands
    await client.play()
    await client.pause()
    await client.toggle_play_pause()
    await client.next_track()
    await client.previous_track()
    await client.volume_up()
    await client.volume_down()
    await client.advance_repeat_mode()
    await client.advance_shuffle_mode()
    await client.skip_forward()
    await client.skip_backward()
    await client.like_track()
    await client.dislike_track()
    await client.bookmark_track()

    assert [cmd[0] for cmd in remote_commands] == [
        ams.RemoteCommandId.PLAY,
        ams.RemoteCommandId.PAUSE,
        ams.RemoteCommandId.TOGGLE_PLAY_PAUSE,
        ams.RemoteCommandId.NEXT_TRACK,
        ams.RemoteCommandId.PREVIOUS_TRACK,
        ams.RemoteCommandId.VOLUME_UP,
        ams.RemoteCommandId.VOLUME_DOWN,
        ams.RemoteCommandId.ADVANCE_REPEAT_MODE,
        ams.RemoteCommandId.ADVANCE_SHUFFLE_MODE,
        ams.RemoteCommandId.SKIP_FORWARD,
        ams.RemoteCommandId.SKIP_BACKWARD,
        ams.RemoteCommandId.LIKE_TRACK,
        ams.RemoteCommandId.DISLIKE_TRACK,
        ams.RemoteCommandId.BOOKMARK_TRACK,
    ]

    await client.stop()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_entity_update_notifications() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    service = ams.Ams()
    devices[0].add_service(service)

    selected_entity_attr = b""

    def on_entity_attr_write(_conn, val: bytes) -> None:
        nonlocal selected_entity_attr
        selected_entity_attr = val

    def on_entity_attr_read(_conn) -> bytes:
        assert selected_entity_attr == bytes(
            [ams.EntityId.TRACK, ams.TrackAttributeId.TITLE]
        )
        return b"Full Un-truncated Song Title"

    service.entity_attribute_characteristic.value = gatt.CharacteristicValue(
        read=on_entity_attr_read, write=on_entity_attr_write
    )

    peer = device_module.Peer(devices.connections[1])
    client = await ams.AmsClient.for_peer(peer)
    assert client is not None
    await client.start()

    async def send_and_wait(
        entity_id: int, attr_id: int, flags: int, value: bytes, event_name: str
    ) -> None:
        ev = asyncio.Event()
        client.once(event_name, ev.set)
        await devices[0].notify_subscribers(
            service.entity_update_characteristic,
            bytes([entity_id, attr_id, flags]) + value,
        )
        await asyncio.wait_for(ev.wait(), TIMEOUT)

    # Player attributes
    await send_and_wait(
        ams.EntityId.PLAYER,
        ams.PlayerAttributeId.NAME,
        0,
        b"MusicPlayer",
        ams.AmsClient.EVENT_PLAYER_NAME,
    )
    assert client.player_name == "MusicPlayer"

    await send_and_wait(
        ams.EntityId.PLAYER,
        ams.PlayerAttributeId.PLAYBACK_INFO,
        0,
        b"1,1.25,45.5",
        ams.AmsClient.EVENT_PLAYER_PLAYBACK_INFO,
    )
    assert client.player_playback_info == ams.PlaybackInfo(
        ams.PlaybackState.PLAYING, 1.25, 45.5
    )

    await send_and_wait(
        ams.EntityId.PLAYER,
        ams.PlayerAttributeId.VOLUME,
        0,
        b"0.75",
        ams.AmsClient.EVENT_PLAYER_VOLUME,
    )
    assert client.player_volume == 0.75

    # Queue attributes
    await send_and_wait(
        ams.EntityId.QUEUE,
        ams.QueueAttributeId.COUNT,
        0,
        b"12",
        ams.AmsClient.EVENT_QUEUE_COUNT,
    )
    assert client.queue_count == 12

    await send_and_wait(
        ams.EntityId.QUEUE,
        ams.QueueAttributeId.INDEX,
        0,
        b"3",
        ams.AmsClient.EVENT_QUEUE_INDEX,
    )
    assert client.queue_index == 3

    await send_and_wait(
        ams.EntityId.QUEUE,
        ams.QueueAttributeId.REPEAT_MODE,
        0,
        b"2",
        ams.AmsClient.EVENT_QUEUE_REPEAT_MODE,
    )
    assert client.queue_repeat_mode == ams.RepeatMode.ALL

    await send_and_wait(
        ams.EntityId.QUEUE,
        ams.QueueAttributeId.SHUFFLE_MODE,
        0,
        b"1",
        ams.AmsClient.EVENT_QUEUE_SHUFFLE_MODE,
    )
    assert client.queue_shuffle_mode == ams.ShuffleMode.ONE

    # Track attributes
    await send_and_wait(
        ams.EntityId.TRACK,
        ams.TrackAttributeId.ARTIST,
        0,
        b"The Artist",
        ams.AmsClient.EVENT_TRACK_ARTIST,
    )
    assert client.track_artist == "The Artist"

    await send_and_wait(
        ams.EntityId.TRACK,
        ams.TrackAttributeId.ALBUM,
        0,
        b"The Album",
        ams.AmsClient.EVENT_TRACK_ALBUM,
    )
    assert client.track_album == "The Album"

    # Truncated Track Title -> triggers entity_attribute write + read
    await send_and_wait(
        ams.EntityId.TRACK,
        ams.TrackAttributeId.TITLE,
        ams.EntityUpdateFlags.TRUNCATED,
        b"Trunc...",
        ams.AmsClient.EVENT_TRACK_TITLE,
    )
    assert client.track_title == "Full Un-truncated Song Title"

    await send_and_wait(
        ams.EntityId.TRACK,
        ams.TrackAttributeId.DURATION,
        0,
        b"210.5",
        ams.AmsClient.EVENT_TRACK_DURATION,
    )
    assert client.track_duration == 210.5

    # Unknown attributes / entity IDs (log warnings without raising)
    await client._on_entity_update_notification(bytes([ams.EntityId.PLAYER, 99, 0]))
    await client._on_entity_update_notification(bytes([ams.EntityId.QUEUE, 99, 0]))
    await client._on_entity_update_notification(bytes([ams.EntityId.TRACK, 99, 0]))
    await client._on_entity_update_notification(bytes([99, 0, 0]))
