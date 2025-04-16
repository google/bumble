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
import dataclasses
import enum
import struct

from bumble import core
from bumble import device
from bumble import gatt
from bumble import gatt_client
from bumble import utils

from typing import Type, Optional, ClassVar, Dict, TYPE_CHECKING
from typing_extensions import Self

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------


class PlayingOrder(utils.OpenIntEnum):
    '''See Media Control Service 3.15. Playing Order.'''

    SINGLE_ONCE = 0x01
    SINGLE_REPEAT = 0x02
    IN_ORDER_ONCE = 0x03
    IN_ORDER_REPEAT = 0x04
    OLDEST_ONCE = 0x05
    OLDEST_REPEAT = 0x06
    NEWEST_ONCE = 0x07
    NEWEST_REPEAT = 0x08
    SHUFFLE_ONCE = 0x09
    SHUFFLE_REPEAT = 0x0A


class PlayingOrderSupported(enum.IntFlag):
    '''See Media Control Service 3.16. Playing Orders Supported.'''

    SINGLE_ONCE = 0x0001
    SINGLE_REPEAT = 0x0002
    IN_ORDER_ONCE = 0x0004
    IN_ORDER_REPEAT = 0x0008
    OLDEST_ONCE = 0x0010
    OLDEST_REPEAT = 0x0020
    NEWEST_ONCE = 0x0040
    NEWEST_REPEAT = 0x0080
    SHUFFLE_ONCE = 0x0100
    SHUFFLE_REPEAT = 0x0200


class MediaState(utils.OpenIntEnum):
    '''See Media Control Service 3.17. Media State.'''

    INACTIVE = 0x00
    PLAYING = 0x01
    PAUSED = 0x02
    SEEKING = 0x03


class MediaControlPointOpcode(utils.OpenIntEnum):
    '''See Media Control Service 3.18. Media Control Point.'''

    PLAY = 0x01
    PAUSE = 0x02
    FAST_REWIND = 0x03
    FAST_FORWARD = 0x04
    STOP = 0x05
    MOVE_RELATIVE = 0x10
    PREVIOUS_SEGMENT = 0x20
    NEXT_SEGMENT = 0x21
    FIRST_SEGMENT = 0x22
    LAST_SEGMENT = 0x23
    GOTO_SEGMENT = 0x24
    PREVIOUS_TRACK = 0x30
    NEXT_TRACK = 0x31
    FIRST_TRACK = 0x32
    LAST_TRACK = 0x33
    GOTO_TRACK = 0x34
    PREVIOUS_GROUP = 0x40
    NEXT_GROUP = 0x41
    FIRST_GROUP = 0x42
    LAST_GROUP = 0x43
    GOTO_GROUP = 0x44


class MediaControlPointResultCode(enum.IntFlag):
    '''See Media Control Service 3.18.2. Media Control Point Notification.'''

    SUCCESS = 0x01
    OPCODE_NOT_SUPPORTED = 0x02
    MEDIA_PLAYER_INACTIVE = 0x03
    COMMAND_CANNOT_BE_COMPLETED = 0x04


class MediaControlPointOpcodeSupported(enum.IntFlag):
    '''See Media Control Service 3.19. Media Control Point Opcodes Supported.'''

    PLAY = 0x00000001
    PAUSE = 0x00000002
    FAST_REWIND = 0x00000004
    FAST_FORWARD = 0x00000008
    STOP = 0x00000010
    MOVE_RELATIVE = 0x00000020
    PREVIOUS_SEGMENT = 0x00000040
    NEXT_SEGMENT = 0x00000080
    FIRST_SEGMENT = 0x00000100
    LAST_SEGMENT = 0x00000200
    GOTO_SEGMENT = 0x00000400
    PREVIOUS_TRACK = 0x00000800
    NEXT_TRACK = 0x00001000
    FIRST_TRACK = 0x00002000
    LAST_TRACK = 0x00004000
    GOTO_TRACK = 0x00008000
    PREVIOUS_GROUP = 0x00010000
    NEXT_GROUP = 0x00020000
    FIRST_GROUP = 0x00040000
    LAST_GROUP = 0x00080000
    GOTO_GROUP = 0x00100000


class SearchControlPointItemType(utils.OpenIntEnum):
    '''See Media Control Service 3.20. Search Control Point.'''

    TRACK_NAME = 0x01
    ARTIST_NAME = 0x02
    ALBUM_NAME = 0x03
    GROUP_NAME = 0x04
    EARLIEST_YEAR = 0x05
    LATEST_YEAR = 0x06
    GENRE = 0x07
    ONLY_TRACKS = 0x08
    ONLY_GROUPS = 0x09


class ObjectType(utils.OpenIntEnum):
    '''See Media Control Service 4.4.1. Object Type field.'''

    TASK = 0
    GROUP = 1


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------


class ObjectId(int):
    '''See Media Control Service 4.4.2. Object ID field.'''

    @classmethod
    def create_from_bytes(cls: Type[Self], data: bytes) -> Self:
        return cls(int.from_bytes(data, byteorder='little', signed=False))

    def __bytes__(self) -> bytes:
        return self.to_bytes(6, 'little')


@dataclasses.dataclass
class GroupObjectType:
    '''See Media Control Service 4.4. Group Object Type.'''

    object_type: ObjectType
    object_id: ObjectId

    @classmethod
    def from_bytes(cls: Type[Self], data: bytes) -> Self:
        return cls(
            object_type=ObjectType(data[0]),
            object_id=ObjectId.create_from_bytes(data[1:]),
        )

    def __bytes__(self) -> bytes:
        return bytes([self.object_type]) + bytes(self.object_id)


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class MediaControlService(gatt.TemplateService):
    '''Media Control Service server implementation, only for testing currently.'''

    UUID = gatt.GATT_MEDIA_CONTROL_SERVICE

    def __init__(self, media_player_name: Optional[str] = None) -> None:
        self.track_position = 0

        self.media_player_name_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_MEDIA_PLAYER_NAME_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=(media_player_name or 'Bumble Player').encode(),
        )
        self.track_changed_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_TRACK_CHANGED_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.track_title_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_TRACK_TITLE_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.track_duration_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_TRACK_DURATION_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.track_position_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_TRACK_POSITION_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
            | gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.media_state_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_MEDIA_STATE_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.media_control_point_characteristic: gatt.Characteristic[bytes] = (
            gatt.Characteristic(
                uuid=gatt.GATT_MEDIA_CONTROL_POINT_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.WRITE
                | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
                | gatt.Characteristic.Properties.NOTIFY,
                permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
                | gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
                value=gatt.CharacteristicValue(write=self.on_media_control_point),
            )
        )
        self.media_control_point_opcodes_supported_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.content_control_id_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_CONTENT_CONTROL_ID_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )

        super().__init__(
            [
                self.media_player_name_characteristic,
                self.track_changed_characteristic,
                self.track_title_characteristic,
                self.track_duration_characteristic,
                self.track_position_characteristic,
                self.media_state_characteristic,
                self.media_control_point_characteristic,
                self.media_control_point_opcodes_supported_characteristic,
                self.content_control_id_characteristic,
            ]
        )

    async def on_media_control_point(
        self, connection: Optional[device.Connection], data: bytes
    ) -> None:
        if not connection:
            raise core.InvalidStateError()

        opcode = MediaControlPointOpcode(data[0])

        await connection.device.notify_subscriber(
            connection,
            self.media_control_point_characteristic,
            value=bytes([opcode, MediaControlPointResultCode.SUCCESS]),
        )


class GenericMediaControlService(MediaControlService):
    UUID = gatt.GATT_GENERIC_MEDIA_CONTROL_SERVICE


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class MediaControlServiceProxy(
    gatt_client.ProfileServiceProxy, utils.CompositeEventEmitter
):
    SERVICE_CLASS = MediaControlService

    _CHARACTERISTICS: ClassVar[Dict[str, core.UUID]] = {
        'media_player_name': gatt.GATT_MEDIA_PLAYER_NAME_CHARACTERISTIC,
        'media_player_icon_object_id': gatt.GATT_MEDIA_PLAYER_ICON_OBJECT_ID_CHARACTERISTIC,
        'media_player_icon_url': gatt.GATT_MEDIA_PLAYER_ICON_URL_CHARACTERISTIC,
        'track_changed': gatt.GATT_TRACK_CHANGED_CHARACTERISTIC,
        'track_title': gatt.GATT_TRACK_TITLE_CHARACTERISTIC,
        'track_duration': gatt.GATT_TRACK_DURATION_CHARACTERISTIC,
        'track_position': gatt.GATT_TRACK_POSITION_CHARACTERISTIC,
        'playback_speed': gatt.GATT_PLAYBACK_SPEED_CHARACTERISTIC,
        'seeking_speed': gatt.GATT_SEEKING_SPEED_CHARACTERISTIC,
        'current_track_segments_object_id': gatt.GATT_CURRENT_TRACK_SEGMENTS_OBJECT_ID_CHARACTERISTIC,
        'current_track_object_id': gatt.GATT_CURRENT_TRACK_OBJECT_ID_CHARACTERISTIC,
        'next_track_object_id': gatt.GATT_NEXT_TRACK_OBJECT_ID_CHARACTERISTIC,
        'parent_group_object_id': gatt.GATT_PARENT_GROUP_OBJECT_ID_CHARACTERISTIC,
        'current_group_object_id': gatt.GATT_CURRENT_GROUP_OBJECT_ID_CHARACTERISTIC,
        'playing_order': gatt.GATT_PLAYING_ORDER_CHARACTERISTIC,
        'playing_orders_supported': gatt.GATT_PLAYING_ORDERS_SUPPORTED_CHARACTERISTIC,
        'media_state': gatt.GATT_MEDIA_STATE_CHARACTERISTIC,
        'media_control_point': gatt.GATT_MEDIA_CONTROL_POINT_CHARACTERISTIC,
        'media_control_point_opcodes_supported': gatt.GATT_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_CHARACTERISTIC,
        'search_control_point': gatt.GATT_SEARCH_CONTROL_POINT_CHARACTERISTIC,
        'search_results_object_id': gatt.GATT_SEARCH_RESULTS_OBJECT_ID_CHARACTERISTIC,
        'content_control_id': gatt.GATT_CONTENT_CONTROL_ID_CHARACTERISTIC,
    }

    media_player_name: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    media_player_icon_object_id: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    media_player_icon_url: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    track_changed: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    track_title: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    track_duration: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    track_position: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    playback_speed: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    seeking_speed: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    current_track_segments_object_id: Optional[
        gatt_client.CharacteristicProxy[bytes]
    ] = None
    current_track_object_id: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    next_track_object_id: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    parent_group_object_id: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    current_group_object_id: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    playing_order: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    playing_orders_supported: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    media_state: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    media_control_point: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    media_control_point_opcodes_supported: Optional[
        gatt_client.CharacteristicProxy[bytes]
    ] = None
    search_control_point: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    search_results_object_id: Optional[gatt_client.CharacteristicProxy[bytes]] = None
    content_control_id: Optional[gatt_client.CharacteristicProxy[bytes]] = None

    if TYPE_CHECKING:
        media_control_point_notifications: asyncio.Queue[bytes]

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        utils.CompositeEventEmitter.__init__(self)
        self.service_proxy = service_proxy
        self.lock = asyncio.Lock()
        self.media_control_point_notifications = asyncio.Queue()

        for field, uuid in self._CHARACTERISTICS.items():
            if characteristics := service_proxy.get_characteristics_by_uuid(uuid):
                setattr(self, field, characteristics[0])

    async def subscribe_characteristics(self) -> None:
        if self.media_control_point:
            await self.media_control_point.subscribe(self._on_media_control_point)
        if self.media_state:
            await self.media_state.subscribe(self._on_media_state)
        if self.track_changed:
            await self.track_changed.subscribe(self._on_track_changed)
        if self.track_title:
            await self.track_title.subscribe(self._on_track_title)
        if self.track_duration:
            await self.track_duration.subscribe(self._on_track_duration)
        if self.track_position:
            await self.track_position.subscribe(self._on_track_position)

    async def write_control_point(
        self, opcode: MediaControlPointOpcode
    ) -> MediaControlPointResultCode:
        '''Writes a Media Control Point Opcode to peer and waits for the notification.

        The write operation will be executed when there isn't other pending commands.

        Args:
            opcode: opcode defined in `MediaControlPointOpcode`.

        Returns:
            Response code provided in `MediaControlPointResultCode`

        Raises:
            InvalidOperationError: Server does not have Media Control Point Characteristic.
            InvalidStateError: Server replies a notification with mismatched opcode.
        '''
        if not self.media_control_point:
            raise core.InvalidOperationError("Peer does not have media control point")

        async with self.lock:
            await self.media_control_point.write_value(
                bytes([opcode]),
                with_response=False,
            )

            (
                response_opcode,
                response_code,
            ) = await self.media_control_point_notifications.get()
            if response_opcode != opcode:
                raise core.InvalidStateError(
                    f"Expected {opcode} notification, but get {response_opcode}"
                )
            return MediaControlPointResultCode(response_code)

    def _on_media_control_point(self, data: bytes) -> None:
        self.media_control_point_notifications.put_nowait(data)

    def _on_media_state(self, data: bytes) -> None:
        self.emit('media_state', MediaState(data[0]))

    def _on_track_changed(self, data: bytes) -> None:
        del data
        self.emit('track_changed')

    def _on_track_title(self, data: bytes) -> None:
        self.emit('track_title', data.decode("utf-8"))

    def _on_track_duration(self, data: bytes) -> None:
        self.emit('track_duration', struct.unpack_from('<i', data)[0])

    def _on_track_position(self, data: bytes) -> None:
        self.emit('track_position', struct.unpack_from('<i', data)[0])


class GenericMediaControlServiceProxy(MediaControlServiceProxy):
    SERVICE_CLASS = GenericMediaControlService
