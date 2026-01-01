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

"""
Apple Media Service (AMS).
"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import asyncio
import dataclasses
import enum
import logging
from collections.abc import Iterable

from bumble import utils
from bumble.device import Peer
from bumble.gatt import (
    GATT_AMS_ENTITY_ATTRIBUTE_CHARACTERISTIC,
    GATT_AMS_ENTITY_UPDATE_CHARACTERISTIC,
    GATT_AMS_REMOTE_COMMAND_CHARACTERISTIC,
    GATT_AMS_SERVICE,
    Characteristic,
    TemplateService,
)
from bumble.gatt_client import CharacteristicProxy, ProfileServiceProxy, ServiceProxy

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Protocol
# -----------------------------------------------------------------------------
class RemoteCommandId(utils.OpenIntEnum):
    PLAY = 0
    PAUSE = 1
    TOGGLE_PLAY_PAUSE = 2
    NEXT_TRACK = 3
    PREVIOUS_TRACK = 4
    VOLUME_UP = 5
    VOLUME_DOWN = 6
    ADVANCE_REPEAT_MODE = 7
    ADVANCE_SHUFFLE_MODE = 8
    SKIP_FORWARD = 9
    SKIP_BACKWARD = 10
    LIKE_TRACK = 11
    DISLIKE_TRACK = 12
    BOOKMARK_TRACK = 13


class EntityId(utils.OpenIntEnum):
    PLAYER = 0
    QUEUE = 1
    TRACK = 2


class ActionId(utils.OpenIntEnum):
    POSITIVE = 0
    NEGATIVE = 1


class EntityUpdateFlags(enum.IntFlag):
    TRUNCATED = 1


class PlayerAttributeId(utils.OpenIntEnum):
    NAME = 0
    PLAYBACK_INFO = 1
    VOLUME = 2


class QueueAttributeId(utils.OpenIntEnum):
    INDEX = 0
    COUNT = 1
    SHUFFLE_MODE = 2
    REPEAT_MODE = 3


class ShuffleMode(utils.OpenIntEnum):
    OFF = 0
    ONE = 1
    ALL = 2


class RepeatMode(utils.OpenIntEnum):
    OFF = 0
    ONE = 1
    ALL = 2


class TrackAttributeId(utils.OpenIntEnum):
    ARTIST = 0
    ALBUM = 1
    TITLE = 2
    DURATION = 3


class PlaybackState(utils.OpenIntEnum):
    PAUSED = 0
    PLAYING = 1
    REWINDING = 2
    FAST_FORWARDING = 3


@dataclasses.dataclass
class PlaybackInfo:
    playback_state: PlaybackState = PlaybackState.PAUSED
    playback_rate: float = 1.0
    elapsed_time: float = 0.0


# -----------------------------------------------------------------------------
# GATT Server-side
# -----------------------------------------------------------------------------
class Ams(TemplateService):
    UUID = GATT_AMS_SERVICE

    remote_command_characteristic: Characteristic
    entity_update_characteristic: Characteristic
    entity_attribute_characteristic: Characteristic

    def __init__(self) -> None:
        # TODO not the final implementation
        self.remote_command_characteristic = Characteristic(
            GATT_AMS_REMOTE_COMMAND_CHARACTERISTIC,
            Characteristic.Properties.NOTIFY
            | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            Characteristic.Permissions.WRITEABLE,
        )

        # TODO not the final implementation
        self.entity_update_characteristic = Characteristic(
            GATT_AMS_ENTITY_UPDATE_CHARACTERISTIC,
            Characteristic.Properties.NOTIFY | Characteristic.Properties.WRITE,
            Characteristic.Permissions.WRITEABLE,
        )

        # TODO not the final implementation
        self.entity_attribute_characteristic = Characteristic(
            GATT_AMS_ENTITY_ATTRIBUTE_CHARACTERISTIC,
            Characteristic.Properties.READ
            | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            Characteristic.Permissions.WRITEABLE | Characteristic.Permissions.READABLE,
        )

        super().__init__(
            [
                self.remote_command_characteristic,
                self.entity_update_characteristic,
                self.entity_attribute_characteristic,
            ]
        )


# -----------------------------------------------------------------------------
# GATT Client-side
# -----------------------------------------------------------------------------
class AmsProxy(ProfileServiceProxy):
    SERVICE_CLASS = Ams

    # NOTE: these don't use adapters, because the format for write and notifications
    # are different.
    remote_command: CharacteristicProxy[bytes]
    entity_update: CharacteristicProxy[bytes]
    entity_attribute: CharacteristicProxy[bytes]

    def __init__(self, service_proxy: ServiceProxy):
        self.remote_command = service_proxy.get_required_characteristic_by_uuid(
            GATT_AMS_REMOTE_COMMAND_CHARACTERISTIC
        )

        self.entity_update = service_proxy.get_required_characteristic_by_uuid(
            GATT_AMS_ENTITY_UPDATE_CHARACTERISTIC
        )

        self.entity_attribute = service_proxy.get_required_characteristic_by_uuid(
            GATT_AMS_ENTITY_ATTRIBUTE_CHARACTERISTIC
        )


class AmsClient(utils.EventEmitter):
    EVENT_SUPPORTED_COMMANDS = "supported_commands"
    EVENT_PLAYER_NAME = "player_name"
    EVENT_PLAYER_PLAYBACK_INFO = "player_playback_info"
    EVENT_PLAYER_VOLUME = "player_volume"
    EVENT_QUEUE_COUNT = "queue_count"
    EVENT_QUEUE_INDEX = "queue_index"
    EVENT_QUEUE_SHUFFLE_MODE = "queue_shuffle_mode"
    EVENT_QUEUE_REPEAT_MODE = "queue_repeat_mode"
    EVENT_TRACK_ARTIST = "track_artist"
    EVENT_TRACK_ALBUM = "track_album"
    EVENT_TRACK_TITLE = "track_title"
    EVENT_TRACK_DURATION = "track_duration"

    supported_commands: set[RemoteCommandId]
    player_name: str = ""
    player_playback_info: PlaybackInfo = PlaybackInfo(PlaybackState.PAUSED, 0.0, 0.0)
    player_volume: float = 1.0
    queue_count: int = 0
    queue_index: int = 0
    queue_shuffle_mode: ShuffleMode = ShuffleMode.OFF
    queue_repeat_mode: RepeatMode = RepeatMode.OFF
    track_artist: str = ""
    track_album: str = ""
    track_title: str = ""
    track_duration: float = 0.0

    def __init__(self, ams_proxy: AmsProxy) -> None:
        super().__init__()
        self._ams_proxy = ams_proxy
        self._started = False
        self._read_attribute_semaphore = asyncio.Semaphore()
        self.supported_commands = set()

    @classmethod
    async def for_peer(cls, peer: Peer) -> AmsClient | None:
        ams_proxy = await peer.discover_service_and_create_proxy(AmsProxy)
        if ams_proxy is None:
            return None
        return cls(ams_proxy)

    async def start(self) -> None:
        logger.debug("subscribing to remote command characteristic")
        await self._ams_proxy.remote_command.subscribe(
            self._on_remote_command_notification
        )

        logger.debug("subscribing to entity update characteristic")
        await self._ams_proxy.entity_update.subscribe(
            lambda data: utils.AsyncRunner.spawn(
                self._on_entity_update_notification(data)
            )
        )

        self._started = True

    async def stop(self) -> None:
        await self._ams_proxy.remote_command.unsubscribe(
            self._on_remote_command_notification
        )
        await self._ams_proxy.entity_update.unsubscribe(
            self._on_entity_update_notification
        )
        self._started = False

    async def observe(
        self,
        entity: EntityId,
        attributes: Iterable[PlayerAttributeId | QueueAttributeId | TrackAttributeId],
    ) -> None:
        await self._ams_proxy.entity_update.write_value(
            bytes([entity] + list(attributes)), with_response=True
        )

    async def command(self, command: RemoteCommandId) -> None:
        await self._ams_proxy.remote_command.write_value(
            bytes([command]), with_response=True
        )

    async def play(self) -> None:
        await self.command(RemoteCommandId.PLAY)

    async def pause(self) -> None:
        await self.command(RemoteCommandId.PAUSE)

    async def toggle_play_pause(self) -> None:
        await self.command(RemoteCommandId.TOGGLE_PLAY_PAUSE)

    async def next_track(self) -> None:
        await self.command(RemoteCommandId.NEXT_TRACK)

    async def previous_track(self) -> None:
        await self.command(RemoteCommandId.PREVIOUS_TRACK)

    async def volume_up(self) -> None:
        await self.command(RemoteCommandId.VOLUME_UP)

    async def volume_down(self) -> None:
        await self.command(RemoteCommandId.VOLUME_DOWN)

    async def advance_repeat_mode(self) -> None:
        await self.command(RemoteCommandId.ADVANCE_REPEAT_MODE)

    async def advance_shuffle_mode(self) -> None:
        await self.command(RemoteCommandId.ADVANCE_SHUFFLE_MODE)

    async def skip_forward(self) -> None:
        await self.command(RemoteCommandId.SKIP_FORWARD)

    async def skip_backward(self) -> None:
        await self.command(RemoteCommandId.SKIP_BACKWARD)

    async def like_track(self) -> None:
        await self.command(RemoteCommandId.LIKE_TRACK)

    async def dislike_track(self) -> None:
        await self.command(RemoteCommandId.DISLIKE_TRACK)

    async def bookmark_track(self) -> None:
        await self.command(RemoteCommandId.BOOKMARK_TRACK)

    def _on_remote_command_notification(self, data: bytes) -> None:
        supported_commands = [RemoteCommandId(command) for command in data]
        logger.debug(
            f"supported commands: {[command.name for command in supported_commands]}"
        )
        for command in supported_commands:
            self.supported_commands.add(command)

        self.emit(self.EVENT_SUPPORTED_COMMANDS)

    async def _on_entity_update_notification(self, data: bytes) -> None:
        entity = EntityId(data[0])
        flags = EntityUpdateFlags(data[2])
        value = data[3:]

        if flags & EntityUpdateFlags.TRUNCATED:
            logger.debug("truncated attribute, fetching full value")

            # Write the entity and attribute we're interested in
            # (protected by a semaphore, so that we only read one attribute at a time)
            async with self._read_attribute_semaphore:
                await self._ams_proxy.entity_attribute.write_value(
                    data[:2], with_response=True
                )
                value = await self._ams_proxy.entity_attribute.read_value()

        if entity == EntityId.PLAYER:
            player_attribute = PlayerAttributeId(data[1])
            if player_attribute == PlayerAttributeId.NAME:
                self.player_name = value.decode()
                self.emit(self.EVENT_PLAYER_NAME)
            elif player_attribute == PlayerAttributeId.PLAYBACK_INFO:
                playback_state_str, playback_rate_str, elapsed_time_str = (
                    value.decode().split(",")
                )
                self.player_playback_info = PlaybackInfo(
                    PlaybackState(int(playback_state_str)),
                    float(playback_rate_str),
                    float(elapsed_time_str),
                )
                self.emit(self.EVENT_PLAYER_PLAYBACK_INFO)
            elif player_attribute == PlayerAttributeId.VOLUME:
                self.player_volume = float(value.decode())
                self.emit(self.EVENT_PLAYER_VOLUME)
            else:
                logger.warning(f"received unknown player attribute {player_attribute}")

        elif entity == EntityId.QUEUE:
            queue_attribute = QueueAttributeId(data[1])
            if queue_attribute == QueueAttributeId.COUNT:
                self.queue_count = int(value)
                self.emit(self.EVENT_QUEUE_COUNT)
            elif queue_attribute == QueueAttributeId.INDEX:
                self.queue_index = int(value)
                self.emit(self.EVENT_QUEUE_INDEX)
            elif queue_attribute == QueueAttributeId.REPEAT_MODE:
                self.queue_repeat_mode = RepeatMode(int(value))
                self.emit(self.EVENT_QUEUE_REPEAT_MODE)
            elif queue_attribute == QueueAttributeId.SHUFFLE_MODE:
                self.queue_shuffle_mode = ShuffleMode(int(value))
                self.emit(self.EVENT_QUEUE_SHUFFLE_MODE)
            else:
                logger.warning(f"received unknown queue attribute {queue_attribute}")

        elif entity == EntityId.TRACK:
            track_attribute = TrackAttributeId(data[1])
            if track_attribute == TrackAttributeId.ARTIST:
                self.track_artist = value.decode()
                self.emit(self.EVENT_TRACK_ARTIST)
            elif track_attribute == TrackAttributeId.ALBUM:
                self.track_album = value.decode()
                self.emit(self.EVENT_TRACK_ALBUM)
            elif track_attribute == TrackAttributeId.TITLE:
                self.track_title = value.decode()
                self.emit(self.EVENT_TRACK_TITLE)
            elif track_attribute == TrackAttributeId.DURATION:
                self.track_duration = float(value.decode())
                self.emit(self.EVENT_TRACK_DURATION)
            else:
                logger.warning(f"received unknown track attribute {track_attribute}")

        else:
            logger.warning(f"received unknown attribute ID {data[1]}")
