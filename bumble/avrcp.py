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
import enum
import functools
import logging
import struct
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Mapping,
    Sequence,
)
from dataclasses import dataclass, field
from typing import ClassVar, SupportsBytes, TypeVar

from bumble import avc, avctp, core, hci, l2cap, sdp, utils
from bumble.colors import color
from bumble.device import Connection, Device
from bumble.sdp import (
    SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
    DataElement,
    ServiceAttribute,
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
AVRCP_PID = 0x110E
AVRCP_BLUETOOTH_SIG_COMPANY_ID = 0x001958


_UINT64_BE_METADATA = hci.metadata(
    {
        'parser': lambda data, offset: (
            offset + 8,
            int.from_bytes(data[offset : offset + 8], byteorder='big'),
        ),
        'serializer': lambda x: x.to_bytes(8, byteorder='big'),
    }
)


class PduId(utils.OpenIntEnum):
    GET_CAPABILITIES = 0x10
    LIST_PLAYER_APPLICATION_SETTING_ATTRIBUTES = 0x11
    LIST_PLAYER_APPLICATION_SETTING_VALUES = 0x12
    GET_CURRENT_PLAYER_APPLICATION_SETTING_VALUE = 0x13
    SET_PLAYER_APPLICATION_SETTING_VALUE = 0x14
    GET_PLAYER_APPLICATION_SETTING_ATTRIBUTE_TEXT = 0x15
    GET_PLAYER_APPLICATION_SETTING_VALUE_TEXT = 0x16
    INFORM_DISPLAYABLE_CHARACTER_SET = 0x17
    INFORM_BATTERY_STATUS_OF_CT = 0x18
    GET_ELEMENT_ATTRIBUTES = 0x20
    GET_PLAY_STATUS = 0x30
    REGISTER_NOTIFICATION = 0x31
    REQUEST_CONTINUING_RESPONSE = 0x40
    ABORT_CONTINUING_RESPONSE = 0x41
    SET_ABSOLUTE_VOLUME = 0x50
    SET_ADDRESSED_PLAYER = 0x60
    SET_BROWSED_PLAYER = 0x70
    GET_FOLDER_ITEMS = 0x71
    CHANGE_PATH = 0x72
    GET_ITEM_ATTRIBUTES = 0x73
    PLAY_ITEM = 0x74
    GET_TOTAL_NUMBER_OF_ITEMS = 0x75
    SEARCH = 0x80
    ADD_TO_NOW_PLAYING = 0x90


class CharacterSetId(hci.SpecableEnum):
    UTF_8 = 0x6A


class MediaAttributeId(hci.SpecableEnum):
    TITLE = 0x01
    ARTIST_NAME = 0x02
    ALBUM_NAME = 0x03
    TRACK_NUMBER = 0x04
    TOTAL_NUMBER_OF_TRACKS = 0x05
    GENRE = 0x06
    PLAYING_TIME = 0x07
    DEFAULT_COVER_ART = 0x08


class PlayStatus(hci.SpecableEnum):
    STOPPED = 0x00
    PLAYING = 0x01
    PAUSED = 0x02
    FWD_SEEK = 0x03
    REV_SEEK = 0x04
    ERROR = 0xFF


class EventId(hci.SpecableEnum):
    PLAYBACK_STATUS_CHANGED = 0x01
    TRACK_CHANGED = 0x02
    TRACK_REACHED_END = 0x03
    TRACK_REACHED_START = 0x04
    PLAYBACK_POS_CHANGED = 0x05
    BATT_STATUS_CHANGED = 0x06
    SYSTEM_STATUS_CHANGED = 0x07
    PLAYER_APPLICATION_SETTING_CHANGED = 0x08
    NOW_PLAYING_CONTENT_CHANGED = 0x09
    AVAILABLE_PLAYERS_CHANGED = 0x0A
    ADDRESSED_PLAYER_CHANGED = 0x0B
    UIDS_CHANGED = 0x0C
    VOLUME_CHANGED = 0x0D

    def __bytes__(self) -> bytes:
        return bytes([int(self)])


class StatusCode(hci.SpecableEnum):
    INVALID_COMMAND = 0x00
    INVALID_PARAMETER = 0x01
    PARAMETER_CONTENT_ERROR = 0x02
    INTERNAL_ERROR = 0x03
    OPERATION_COMPLETED = 0x04
    UID_CHANGED = 0x05
    INVALID_DIRECTION = 0x07
    NOT_A_DIRECTORY = 0x08
    DOES_NOT_EXIST = 0x09
    INVALID_SCOPE = 0x0A
    RANGE_OUT_OF_BOUNDS = 0x0B
    FOLDER_ITEM_IS_NOT_PLAYABLE = 0x0C
    MEDIA_IN_USE = 0x0D
    NOW_PLAYING_LIST_FULL = 0x0E
    SEARCH_NOT_SUPPORTED = 0x0F
    SEARCH_IN_PROGRESS = 0x10
    INVALID_PLAYER_ID = 0x11
    PLAYER_NOT_BROWSABLE = 0x12
    PLAYER_NOT_ADDRESSED = 0x13
    NO_VALID_SEARCH_RESULTS = 0x14
    NO_AVAILABLE_PLAYERS = 0x15
    ADDRESSED_PLAYER_CHANGED = 0x16


class Scope(hci.SpecableEnum):
    MEDIA_PLAYER_LIST = 0x00
    MEDIA_PLAYER_VIRTUAL_FILESYSTEM = 0x01
    SEARCH = 0x02
    NOW_PLAYING = 0x03


class ControllerFeatures(enum.IntFlag):
    # fmt: off
    CATEGORY_1                                      = 1 << 0
    CATEGORY_2                                      = 1 << 1
    CATEGORY_3                                      = 1 << 2
    CATEGORY_4                                      = 1 << 3
    SUPPORTS_BROWSING                               = 1 << 6
    SUPPORTS_COVER_ART_GET_IMAGE_PROPERTIES_FEATURE = 1 << 7
    SUPPORTS_COVER_ART_GET_IMAGE_FEATURE            = 1 << 8
    SUPPORTS_COVER_ART_GET_LINKED_THUMBNAIL_FEATURE = 1 << 9


class TargetFeatures(enum.IntFlag):
    # fmt: off
    CATEGORY_1                                  = 1 << 0
    CATEGORY_2                                  = 1 << 1
    CATEGORY_3                                  = 1 << 2
    CATEGORY_4                                  = 1 << 3
    PLAYER_APPLICATION_SETTINGS                 = 1 << 4
    GROUP_NAVIGATION                            = 1 << 5
    SUPPORTS_BROWSING                           = 1 << 6
    SUPPORTS_MULTIPLE_MEDIA_PLAYER_APPLICATIONS = 1 << 7
    SUPPORTS_COVER_ART                          = 1 << 8


# -----------------------------------------------------------------------------
@dataclass
class ControllerServiceSdpRecord:
    service_record_handle: int
    avctp_version: tuple[int, int] = (1, 4)
    avrcp_version: tuple[int, int] = (1, 6)
    supported_features: int | ControllerFeatures = ControllerFeatures(1)

    def to_service_attributes(self) -> list[ServiceAttribute]:
        avctp_version_int = self.avctp_version[0] << 8 | self.avctp_version[1]
        avrcp_version_int = self.avrcp_version[0] << 8 | self.avrcp_version[1]

        attributes = [
            ServiceAttribute(
                SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                DataElement.unsigned_integer_32(self.service_record_handle),
            ),
            ServiceAttribute(
                SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
                DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
            ),
            ServiceAttribute(
                SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.uuid(core.BT_AV_REMOTE_CONTROL_SERVICE),
                        DataElement.uuid(core.BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE),
                    ]
                ),
            ),
            ServiceAttribute(
                SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence(
                            [
                                DataElement.uuid(core.BT_L2CAP_PROTOCOL_ID),
                                DataElement.unsigned_integer_16(avctp.AVCTP_PSM),
                            ]
                        ),
                        DataElement.sequence(
                            [
                                DataElement.uuid(core.BT_AVCTP_PROTOCOL_ID),
                                DataElement.unsigned_integer_16(avctp_version_int),
                            ]
                        ),
                    ]
                ),
            ),
            ServiceAttribute(
                SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence(
                            [
                                DataElement.uuid(core.BT_AV_REMOTE_CONTROL_SERVICE),
                                DataElement.unsigned_integer_16(avrcp_version_int),
                            ]
                        ),
                    ]
                ),
            ),
            ServiceAttribute(
                SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
                DataElement.unsigned_integer_16(self.supported_features),
            ),
        ]
        if self.supported_features & ControllerFeatures.SUPPORTS_BROWSING:
            attributes.append(
                ServiceAttribute(
                    SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                    DataElement.sequence(
                        [
                            DataElement.sequence(
                                [
                                    DataElement.uuid(core.BT_L2CAP_PROTOCOL_ID),
                                    DataElement.unsigned_integer_16(
                                        avctp.AVCTP_BROWSING_PSM
                                    ),
                                ]
                            ),
                            DataElement.sequence(
                                [
                                    DataElement.uuid(core.BT_AVCTP_PROTOCOL_ID),
                                    DataElement.unsigned_integer_16(avctp_version_int),
                                ]
                            ),
                        ]
                    ),
                ),
            )
        return attributes

    @classmethod
    async def find(cls, connection: Connection) -> list[ControllerServiceSdpRecord]:
        async with sdp.Client(connection) as sdp_client:
            search_result = await sdp_client.search_attributes(
                uuids=[core.BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE],
                attribute_ids=[
                    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                    SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
                ],
            )

            records: list[ControllerServiceSdpRecord] = []
            for attribute_lists in search_result:
                record = cls(0)
                for attribute in attribute_lists:
                    if attribute.id == SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID:
                        record.service_record_handle = attribute.value.value
                    elif attribute.id == SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                        # [[L2CAP, PSM], [AVCTP, version]]
                        record.avctp_version = (
                            attribute.value.value[1].value[1].value >> 8,
                            attribute.value.value[1].value[1].value & 0xFF,
                        )
                    elif (
                        attribute.id
                        == SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID
                    ):
                        # [[AV_REMOTE_CONTROL, version]]
                        record.avrcp_version = (
                            attribute.value.value[0].value[1].value >> 8,
                            attribute.value.value[0].value[1].value & 0xFF,
                        )
                    elif attribute.id == SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID:
                        record.supported_features = ControllerFeatures(
                            attribute.value.value
                        )
                records.append(record)
            return records


# -----------------------------------------------------------------------------
@dataclass
class TargetServiceSdpRecord:
    service_record_handle: int
    avctp_version: tuple[int, int] = (1, 4)
    avrcp_version: tuple[int, int] = (1, 6)
    supported_features: int | TargetFeatures = TargetFeatures(0x23)

    def to_service_attributes(self) -> list[ServiceAttribute]:
        # TODO: support a way to compute the supported features from a feature list
        avctp_version_int = self.avctp_version[0] << 8 | self.avctp_version[1]
        avrcp_version_int = self.avrcp_version[0] << 8 | self.avrcp_version[1]

        attributes = [
            ServiceAttribute(
                SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                DataElement.unsigned_integer_32(self.service_record_handle),
            ),
            ServiceAttribute(
                SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
                DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
            ),
            ServiceAttribute(
                SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.uuid(core.BT_AV_REMOTE_CONTROL_TARGET_SERVICE),
                    ]
                ),
            ),
            ServiceAttribute(
                SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence(
                            [
                                DataElement.uuid(core.BT_L2CAP_PROTOCOL_ID),
                                DataElement.unsigned_integer_16(avctp.AVCTP_PSM),
                            ]
                        ),
                        DataElement.sequence(
                            [
                                DataElement.uuid(core.BT_AVCTP_PROTOCOL_ID),
                                DataElement.unsigned_integer_16(avctp_version_int),
                            ]
                        ),
                    ]
                ),
            ),
            ServiceAttribute(
                SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence(
                            [
                                DataElement.uuid(core.BT_AV_REMOTE_CONTROL_SERVICE),
                                DataElement.unsigned_integer_16(avrcp_version_int),
                            ]
                        ),
                    ]
                ),
            ),
            ServiceAttribute(
                SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
                DataElement.unsigned_integer_16(self.supported_features),
            ),
        ]
        if self.supported_features & TargetFeatures.SUPPORTS_BROWSING:
            attributes.append(
                ServiceAttribute(
                    SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                    DataElement.sequence(
                        [
                            DataElement.sequence(
                                [
                                    DataElement.uuid(core.BT_L2CAP_PROTOCOL_ID),
                                    DataElement.unsigned_integer_16(
                                        avctp.AVCTP_BROWSING_PSM
                                    ),
                                ]
                            ),
                            DataElement.sequence(
                                [
                                    DataElement.uuid(core.BT_AVCTP_PROTOCOL_ID),
                                    DataElement.unsigned_integer_16(avctp_version_int),
                                ]
                            ),
                        ]
                    ),
                ),
            )
        return attributes

    @classmethod
    async def find(cls, connection: Connection) -> list[TargetServiceSdpRecord]:
        async with sdp.Client(connection) as sdp_client:
            search_result = await sdp_client.search_attributes(
                uuids=[core.BT_AV_REMOTE_CONTROL_TARGET_SERVICE],
                attribute_ids=[
                    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                    SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
                ],
            )

            records: list[TargetServiceSdpRecord] = []
            for attribute_lists in search_result:
                record = cls(0)
                for attribute in attribute_lists:
                    if attribute.id == SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID:
                        record.service_record_handle = attribute.value.value
                    elif attribute.id == SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                        # [[L2CAP, PSM], [AVCTP, version]]
                        record.avctp_version = (
                            attribute.value.value[1].value[1].value >> 8,
                            attribute.value.value[1].value[1].value & 0xFF,
                        )
                    elif (
                        attribute.id
                        == SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID
                    ):
                        # [[AV_REMOTE_CONTROL, version]]
                        record.avrcp_version = (
                            attribute.value.value[0].value[1].value >> 8,
                            attribute.value.value[0].value[1].value & 0xFF,
                        )
                    elif attribute.id == SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID:
                        record.supported_features = TargetFeatures(
                            attribute.value.value
                        )
                records.append(record)
            return records


# -----------------------------------------------------------------------------
def _parse_string(data: bytes, offset: int, length_size: int) -> tuple[int, str]:
    length = int.from_bytes(
        data[offset : offset + length_size], byteorder='big', signed=False
    )
    offset += length_size
    encoded = data[offset : offset + length]
    try:
        decoded = encoded.decode("utf-8")
    except UnicodeDecodeError:
        # This can decode anything.
        decoded = encoded.decode("latin1")
    return offset + length, decoded


# -----------------------------------------------------------------------------
def _serialize_string(value: str, length_size: int) -> bytes:
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(length_size, byteorder='big', signed=False) + encoded


# -----------------------------------------------------------------------------
def _string_spec(length_size: int):
    return {
        'parser': functools.partial(_parse_string, length_size=length_size),
        'serializer': functools.partial(_serialize_string, length_size=length_size),
    }


# -----------------------------------------------------------------------------
@dataclass
class MediaAttribute(hci.HCI_Dataclass_Object):
    attribute_id: MediaAttributeId = field(
        metadata=MediaAttributeId.type_metadata(4, byteorder='big')
    )
    character_set_id: CharacterSetId = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    attribute_value: str = field(metadata=hci.metadata(_string_spec(2)))


# -----------------------------------------------------------------------------
@dataclass
class SongAndPlayStatus:
    song_length: int
    song_position: int
    play_status: PlayStatus


# -----------------------------------------------------------------------------
class ApplicationSetting:
    class AttributeId(hci.SpecableEnum):
        EQUALIZER_ON_OFF = 0x01
        REPEAT_MODE = 0x02
        SHUFFLE_ON_OFF = 0x03
        SCAN_ON_OFF = 0x04

    class EqualizerOnOffStatus(hci.SpecableEnum):
        OFF = 0x01
        ON = 0x02

    class RepeatModeStatus(hci.SpecableEnum):
        OFF = 0x01
        SINGLE_TRACK_REPEAT = 0x02
        ALL_TRACK_REPEAT = 0x03
        GROUP_REPEAT = 0x04

    class ShuffleOnOffStatus(hci.SpecableEnum):
        OFF = 0x01
        ALL_TRACKS_SHUFFLE = 0x02
        GROUP_SHUFFLE = 0x03

    class ScanOnOffStatus(hci.SpecableEnum):
        OFF = 0x01
        ALL_TRACKS_SCAN = 0x02
        GROUP_SCAN = 0x03

    class GenericValue(hci.SpecableEnum):
        pass


# -----------------------------------------------------------------------------
@dataclass
class AttributeValueEntry(hci.HCI_Dataclass_Object):
    attribute_id: MediaAttributeId = field(
        metadata=MediaAttributeId.type_metadata(4, byteorder='big')
    )
    character_set_id: CharacterSetId = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    attribute_value: str = field(metadata=hci.metadata(_string_spec(2)))


# -----------------------------------------------------------------------------
class BrowseableItem:
    """6.10.2 Browseable items."""

    class Type(hci.SpecableEnum):
        MEDIA_PLAYER = 0x01
        FOLDER = 0x02
        MEDIA_ELEMENT = 0x03

    item_type: ClassVar[Type]
    _payload: bytes | None = None

    subclasses: ClassVar[dict[Type, type[BrowseableItem]]] = {}
    fields: ClassVar[hci.Fields] = ()

    @classmethod
    def parse_from_bytes(cls, data: bytes, offset: int) -> tuple[int, BrowseableItem]:
        item_type, length = struct.unpack_from('>BH', data, offset)
        subclass = cls.subclasses[BrowseableItem.Type(item_type)]
        instance = subclass(
            **hci.HCI_Object.dict_from_bytes(data, offset + 3, subclass.fields)
        )
        instance._payload = data[3:]
        return offset + length + 3, instance

    def __bytes__(self) -> bytes:
        if self._payload is None:
            self._payload = hci.HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return struct.pack('>BH', self.item_type, len(self._payload)) + self._payload

    _Item = TypeVar('_Item', bound='BrowseableItem')

    @classmethod
    def item(cls, subclass: type[_Item]) -> type[_Item]:
        cls.subclasses[subclass.item_type] = subclass
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)
        return subclass


# -----------------------------------------------------------------------------
@BrowseableItem.item
@dataclass
class MediaPlayerItem(BrowseableItem):
    item_type = BrowseableItem.Type.MEDIA_PLAYER

    class MajorPlayerType(hci.SpecableFlag):
        AUDIO = 0x01
        VIDEO = 0x02
        BROADCASTING_AUDIO = 0x04
        BROADCASTING_VIDEO = 0x08

    class PlayerSubType(hci.SpecableFlag):
        AUDIO_BOOK = 0x01
        PODCAST = 0x02

    class Features(hci.SpecableFlag):
        SELECT = 1 << 0
        UP = 1 << 1
        DOWN = 1 << 2
        LEFT = 1 << 3
        RIGHT = 1 << 4
        RIGHT_UP = 1 << 5
        RIGHT_DOWN = 1 << 6
        LEFT_UP = 1 << 7
        LEFT_DOWN = 1 << 8
        ROOT_MENU = 1 << 9
        SETUP_MENU = 1 << 10
        CONTENTS_MENU = 1 << 11
        FAVORITE_MENU = 1 << 12
        EXIT = 1 << 13
        NUM_0 = 1 << 14
        NUM_1 = 1 << 15
        NUM_2 = 1 << 16
        NUM_3 = 1 << 17
        NUM_4 = 1 << 18
        NUM_5 = 1 << 19
        NUM_6 = 1 << 20
        NUM_7 = 1 << 21
        NUM_8 = 1 << 22
        NUM_9 = 1 << 23
        DOT = 1 << 24
        ENTER = 1 << 25
        CLEAR = 1 << 26
        CHANNEL_UP = 1 << 27
        CHANNEL_DOWN = 1 << 28
        PREVIOUS_CHANNEL = 1 << 29
        SOUND_SELECT = 1 << 30
        INPUT_SELECT = 1 << 31
        DISPLAY_INFORMATION = 1 << 32
        HELP = 1 << 33
        PAGE_UP = 1 << 34
        PAGE_DOWN = 1 << 35
        POWER = 1 << 36
        VOLUME_UP = 1 << 37
        VOLUME_DOWN = 1 << 38
        MUTE = 1 << 39
        PLAY = 1 << 40
        STOP = 1 << 41
        PAUSE = 1 << 42
        RECORD = 1 << 43
        REWIND = 1 << 44
        FAST_FORWARD = 1 << 45
        EJECT = 1 << 46
        FORWARD = 1 << 47
        BACKWARD = 1 << 48
        ANGLE = 1 << 49
        SUBPICTURE = 1 << 50
        F1 = 1 << 51
        F2 = 1 << 52
        F3 = 1 << 53
        F4 = 1 << 54
        F5 = 1 << 55
        VENDOR_UNIQUE = 1 << 56
        BASIC_GROUP_NAVIGATION = 1 << 57
        ADVANCED_CONTROL_PLAYER = 1 << 58
        BROWSING = 1 << 59
        SEARCHING = 1 << 60
        ADD_TO_NOW_PLAYING = 1 << 61
        UI_DS_UNIQUE_IN_PLAYER_BROWSE_TREE = 1 << 62
        ONLY_BROWSABLE_WHEN_ADDRESSED = 1 << 63
        ONLY_SEARCHABLE_WHEN_ADDRESSED = 1 << 64
        NOW_PLAYING = 1 << 65
        UID_PERSISTENCY = 1 << 66
        NUMBER_OF_ITEMS = 1 << 67
        COVER_ART = 1 << 68

    player_id: int = field(metadata=hci.metadata('>2'))
    major_player_type: MajorPlayerType = field(
        metadata=MajorPlayerType.type_metadata(1)
    )
    player_sub_type: PlayerSubType = field(
        metadata=PlayerSubType.type_metadata(4, byteorder='little')
    )
    play_status: PlayStatus = field(metadata=PlayStatus.type_metadata(1))
    feature_bitmask: Features = field(
        metadata=Features.type_metadata(16, byteorder='little')
    )
    character_set_id: CharacterSetId = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    displayable_name: str = field(metadata=hci.metadata(_string_spec(2)))


# -----------------------------------------------------------------------------
@BrowseableItem.item
@dataclass
class FolderItem(BrowseableItem):
    item_type = BrowseableItem.Type.FOLDER

    class FolderType(hci.SpecableEnum):
        MIXED = 0x00
        TITLES = 0x01
        ALBUMS = 0x02
        ARTISTS = 0x03
        GENRES = 0x04
        PLAYLISTS = 0x05
        YEARS = 0x06

    class Playable(hci.SpecableEnum):
        NOT_PLAYABLE = 0x00
        PLAYABLE = 0x01

    folder_uid: int = field(metadata=_UINT64_BE_METADATA)
    folder_type: FolderType = field(metadata=FolderType.type_metadata(1))
    is_playable: Playable = field(metadata=Playable.type_metadata(1))
    character_set_id: CharacterSetId = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    displayable_name: str = field(metadata=hci.metadata(_string_spec(2)))


# -----------------------------------------------------------------------------
@BrowseableItem.item
@dataclass
class MediaElementItem(BrowseableItem):
    item_type = BrowseableItem.Type.MEDIA_ELEMENT

    class MediaType(hci.SpecableEnum):
        AUDIO = 0x00
        VIDEO = 0x01

    media_element_uid: int = field(metadata=_UINT64_BE_METADATA)
    media_type: MediaType = field(metadata=MediaType.type_metadata(1))
    character_set_id: CharacterSetId = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    displayable_name: str = field(metadata=hci.metadata(_string_spec(2)))
    attribute_value_entry_list: Sequence[AttributeValueEntry] = field(
        metadata=hci.metadata(
            AttributeValueEntry.parse_from_bytes, list_begin=True, list_end=True
        )
    )


# -----------------------------------------------------------------------------
class PduAssembler:
    """
    PDU Assembler to support fragmented PDUs are defined in:
    Audio/Video Remote Control / Profile Specification
    6.3.1 AVRCP specific AV//C commands
    """

    pdu_id: PduId | None
    payload: bytes

    def __init__(self, callback: Callable[[PduId, bytes], None]) -> None:
        self.callback = callback
        self.reset()

    def reset(self) -> None:
        self.pdu_id = None
        self.parameter = b''

    def on_pdu(self, pdu: bytes) -> None:
        pdu_id = PduId(pdu[0])
        packet_type = Protocol.PacketType(pdu[1] & 3)
        parameter_length = struct.unpack_from('>H', pdu, 2)[0]
        parameter = pdu[4 : 4 + parameter_length]
        if len(parameter) != parameter_length:
            logger.warning("parameter length exceeds pdu size")
            self.reset()
            return

        if packet_type in (Protocol.PacketType.SINGLE, Protocol.PacketType.START):
            if self.pdu_id is not None:
                # We are already in a PDU
                logger.warning("received START or SINGLE fragment while in pdu")
                self.reset()

        if packet_type in (Protocol.PacketType.CONTINUE, Protocol.PacketType.END):
            if pdu_id != self.pdu_id:
                logger.warning("PID does not match")
                self.reset()
                return
        else:
            self.pdu_id = pdu_id

        self.parameter += parameter

        if packet_type in (Protocol.PacketType.SINGLE, Protocol.PacketType.END):
            self.on_pdu_complete()

    def on_pdu_complete(self) -> None:
        assert self.pdu_id is not None
        try:
            self.callback(self.pdu_id, self.parameter)
        except Exception:
            logger.exception(color('!!! exception in callback', 'red'))

        self.reset()


# -----------------------------------------------------------------------------
class Command:
    pdu_id: ClassVar[PduId]
    _payload: bytes | None = None

    _Command = TypeVar('_Command', bound='Command')
    subclasses: ClassVar[dict[int, type[Command]]] = {}
    fields: ClassVar[hci.Fields] = ()

    @classmethod
    def command(cls, subclass: type[_Command]) -> type[_Command]:
        cls.subclasses[subclass.pdu_id] = subclass
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)
        return subclass

    @classmethod
    def from_bytes(cls, pdu_id: int, pdu: bytes) -> Command:
        if not (subclass := cls.subclasses.get(pdu_id)):
            raise core.InvalidPacketError(f"Unimplemented PDU {pdu_id}")
        instance = subclass(**hci.HCI_Object.dict_from_bytes(pdu, 0, subclass.fields))
        instance._payload = pdu[0:]
        return instance

    def __bytes__(self) -> bytes:
        if self._payload is None:
            self._payload = hci.HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return self._payload


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetCapabilitiesCommand(Command):
    pdu_id = PduId.GET_CAPABILITIES

    class CapabilityId(hci.SpecableEnum):
        COMPANY_ID = 0x02
        EVENTS_SUPPORTED = 0x03

    capability_id: CapabilityId = field(metadata=CapabilityId.type_metadata(1))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class ListPlayerApplicationSettingAttributesCommand(Command):
    pdu_id = PduId.LIST_PLAYER_APPLICATION_SETTING_ATTRIBUTES


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class ListPlayerApplicationSettingValuesCommand(Command):
    pdu_id = PduId.LIST_PLAYER_APPLICATION_SETTING_VALUES

    attribute: ApplicationSetting.AttributeId = field(
        metadata=ApplicationSetting.AttributeId.type_metadata(1)
    )


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetCurrentPlayerApplicationSettingValueCommand(Command):
    pdu_id = PduId.GET_CURRENT_PLAYER_APPLICATION_SETTING_VALUE

    attribute: Sequence[ApplicationSetting.AttributeId] = field(
        metadata=ApplicationSetting.AttributeId.type_metadata(
            1, list_begin=True, list_end=True
        )
    )


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class SetPlayerApplicationSettingValueCommand(Command):
    pdu_id = PduId.SET_PLAYER_APPLICATION_SETTING_VALUE

    attribute: Sequence[ApplicationSetting.AttributeId] = field(
        metadata=ApplicationSetting.AttributeId.type_metadata(1, list_begin=True)
    )
    value: Sequence[int] = field(metadata=hci.metadata(1, list_end=True))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetPlayerApplicationSettingAttributeTextCommand(Command):
    pdu_id = PduId.GET_PLAYER_APPLICATION_SETTING_ATTRIBUTE_TEXT

    attribute: Sequence[ApplicationSetting.AttributeId] = field(
        metadata=ApplicationSetting.AttributeId.type_metadata(
            1, list_begin=True, list_end=True
        )
    )


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetPlayerApplicationSettingValueTextCommand(Command):
    pdu_id = PduId.GET_PLAYER_APPLICATION_SETTING_VALUE_TEXT

    attribute: ApplicationSetting.AttributeId = field(
        metadata=ApplicationSetting.AttributeId.type_metadata(1)
    )
    value: Sequence[int] = field(
        metadata=hci.metadata(1, list_begin=True, list_end=True)
    )


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class InformDisplayableCharacterSetCommand(Command):
    pdu_id = PduId.INFORM_DISPLAYABLE_CHARACTER_SET

    character_set_id: Sequence[CharacterSetId] = field(
        metadata=CharacterSetId.type_metadata(
            2, list_begin=True, list_end=True, byteorder='big'
        )
    )


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class InformBatteryStatusOfCtCommand(Command):
    pdu_id = PduId.INFORM_BATTERY_STATUS_OF_CT

    class BatteryStatus(hci.SpecableEnum):
        NORMAL = 0x00
        WARNING = 0x01
        CRITICAL = 0x02
        EXTERNAL = 0x03
        FULL_CHARGE = 0x04

    battery_status: BatteryStatus = field(metadata=BatteryStatus.type_metadata(1))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetPlayStatusCommand(Command):
    pdu_id = PduId.GET_PLAY_STATUS


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetElementAttributesCommand(Command):
    pdu_id = PduId.GET_ELEMENT_ATTRIBUTES

    identifier: int = field(metadata=_UINT64_BE_METADATA)
    attribute_ids: Sequence[MediaAttributeId] = field(
        metadata=MediaAttributeId.type_metadata(
            4, list_begin=True, list_end=True, byteorder='big'
        )
    )


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class SetAbsoluteVolumeCommand(Command):
    pdu_id = PduId.SET_ABSOLUTE_VOLUME
    MAXIMUM_VOLUME = 0x7F

    volume: int = field(metadata=hci.metadata(1))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class RegisterNotificationCommand(Command):
    pdu_id = PduId.REGISTER_NOTIFICATION

    event_id: EventId = field(metadata=EventId.type_metadata(1))
    playback_interval: int = field(metadata=hci.metadata('>4'))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class SetAddressedPlayerCommand(Command):
    pdu_id = PduId.SET_ADDRESSED_PLAYER

    player_id: int = field(metadata=hci.metadata('>2'))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class SetBrowsedPlayerCommand(Command):
    pdu_id = PduId.SET_BROWSED_PLAYER

    player_id: int = field(metadata=hci.metadata('>2'))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetFolderItemsCommand(Command):
    pdu_id = PduId.GET_FOLDER_ITEMS

    scope: Scope = field(metadata=Scope.type_metadata(1))
    start_item: int = field(metadata=hci.metadata('>4'))
    end_item: int = field(metadata=hci.metadata('>4'))
    # When attributes is empty, all attributes will be requested.
    attributes: Sequence[MediaAttributeId] = field(
        metadata=MediaAttributeId.type_metadata(
            4, list_begin=True, list_end=True, byteorder='big'
        )
    )


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class ChangePathCommand(Command):
    pdu_id = PduId.CHANGE_PATH

    class Direction(hci.SpecableEnum):
        UP = 0
        DOWN = 1

    uid_counter: int = field(metadata=hci.metadata('>2'))
    direction: Direction = field(metadata=Direction.type_metadata(1))
    folder_uid: int = field(metadata=_UINT64_BE_METADATA)


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetItemAttributesCommand(Command):
    pdu_id = PduId.GET_ITEM_ATTRIBUTES

    scope: Scope = field(metadata=Scope.type_metadata(1))
    uid: int = field(metadata=_UINT64_BE_METADATA)
    uid_counter: int = field(metadata=hci.metadata('>2'))
    # When attributes is empty, all attributes will be requested.
    attributes: Sequence[MediaAttributeId] = field(
        metadata=MediaAttributeId.type_metadata(4, list_begin=True, list_end=True)
    )


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class GetTotalNumberOfItemsCommand(Command):
    pdu_id = PduId.GET_TOTAL_NUMBER_OF_ITEMS

    scope: Scope = field(metadata=Scope.type_metadata(1))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class SearchCommand(Command):
    pdu_id = PduId.SEARCH

    character_set_id: CharacterSetId = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    search_string: str = field(metadata=hci.metadata(_string_spec(2)))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class PlayItemCommand(Command):
    pdu_id = PduId.PLAY_ITEM

    scope: Scope = field(metadata=Scope.type_metadata(1))
    uid: int = field(metadata=_UINT64_BE_METADATA)
    uid_counter: int = field(metadata=hci.metadata('>2'))


# -----------------------------------------------------------------------------
@Command.command
@dataclass
class AddToNowPlayingCommand(Command):
    pdu_id = PduId.ADD_TO_NOW_PLAYING

    scope: Scope = field(metadata=Scope.type_metadata(1))
    uid: int = field(metadata=_UINT64_BE_METADATA)
    uid_counter: int = field(metadata=hci.metadata('>2'))


# -----------------------------------------------------------------------------
class Response:
    pdu_id: PduId
    _payload: bytes | None = None

    fields: ClassVar[hci.Fields] = ()
    subclasses: ClassVar[dict[PduId, type[Response]]] = {}

    _Response = TypeVar('_Response', bound='Response')

    @classmethod
    def response(cls, subclass: type[_Response]) -> type[_Response]:
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)
        if pdu_id := getattr(subclass, 'pdu_id', None):
            cls.subclasses[pdu_id] = subclass
        return subclass

    def __bytes__(self) -> bytes:
        if self._payload is None:
            self._payload = hci.HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return self._payload

    @classmethod
    def from_bytes(cls, pdu: bytes, pdu_id: PduId) -> Response:
        if not (subclass := cls.subclasses.get(pdu_id)):
            raise core.InvalidArgumentError(f"Unimplemented packet {pdu_id.name}")
        return subclass.from_parameters(pdu)

    @classmethod
    def from_parameters(cls, parameters: bytes) -> Response:
        instance = cls(**hci.HCI_Object.dict_from_bytes(parameters, 0, cls.fields))
        instance._payload = parameters
        return instance


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class RejectedResponse(Response):
    pdu_id: PduId
    status_code: StatusCode = field(metadata=StatusCode.type_metadata(1))

    @classmethod
    def from_bytes(cls, pdu: bytes, pdu_id: PduId) -> Response:
        return cls(pdu_id=pdu_id, status_code=StatusCode(pdu[0]))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class NotImplementedResponse(Response):
    pdu_id: PduId
    parameters: bytes = field(metadata=hci.metadata('*'))

    @classmethod
    def from_bytes(cls, pdu: bytes, pdu_id: PduId) -> Response:
        return cls(pdu_id=pdu_id, parameters=pdu)


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetCapabilitiesResponse(Response):
    pdu_id = PduId.GET_CAPABILITIES
    capability_id: GetCapabilitiesCommand.CapabilityId
    capabilities: Sequence[SupportsBytes | bytes]

    @classmethod
    def from_parameters(cls, parameters: bytes) -> Response:
        if len(parameters) < 2:
            # Possibly a reject response.
            return cls(GetCapabilitiesCommand.CapabilityId(0), [])

        # Assume that the payloads all follow the same pattern:
        #  <CapabilityID><CapabilityCount><Capability*>
        capability_id = GetCapabilitiesCommand.CapabilityId(parameters[0])
        capability_count = parameters[1]

        capabilities: list[SupportsBytes | bytes]
        if capability_id == GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED:
            capabilities = [EventId(parameters[2 + x]) for x in range(capability_count)]
        else:
            capability_size = (len(parameters) - 2) // capability_count
            capabilities = [
                parameters[x : x + capability_size]
                for x in range(2, len(parameters), capability_size)
            ]

        return cls(capability_id, capabilities)

    def __post_init__(self) -> None:
        self._payload = bytes([self.capability_id, len(self.capabilities)]) + b''.join(
            bytes(capability) for capability in self.capabilities
        )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class ListPlayerApplicationSettingAttributesResponse(Response):
    pdu_id = PduId.LIST_PLAYER_APPLICATION_SETTING_ATTRIBUTES

    attribute: Sequence[ApplicationSetting.AttributeId] = field(
        metadata=ApplicationSetting.AttributeId.type_metadata(
            1, list_begin=True, list_end=True
        )
    )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class ListPlayerApplicationSettingValuesResponse(Response):
    pdu_id = PduId.LIST_PLAYER_APPLICATION_SETTING_VALUES

    value: Sequence[int] = field(
        metadata=hci.metadata(1, list_begin=True, list_end=True)
    )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetCurrentPlayerApplicationSettingValueResponse(Response):
    pdu_id = PduId.GET_CURRENT_PLAYER_APPLICATION_SETTING_VALUE

    attribute: Sequence[ApplicationSetting.AttributeId] = field(
        metadata=ApplicationSetting.AttributeId.type_metadata(1, list_begin=True)
    )
    value: Sequence[int] = field(metadata=hci.metadata(1, list_end=True))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class SetPlayerApplicationSettingValueResponse(Response):
    pdu_id = PduId.SET_PLAYER_APPLICATION_SETTING_VALUE


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetPlayerApplicationSettingAttributeTextResponse(Response):
    pdu_id = PduId.GET_PLAYER_APPLICATION_SETTING_ATTRIBUTE_TEXT

    attribute: Sequence[ApplicationSetting.AttributeId] = field(
        metadata=ApplicationSetting.AttributeId.type_metadata(1, list_begin=True)
    )
    character_set_id: Sequence[CharacterSetId] = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    attribute_string: Sequence[str] = field(
        metadata=hci.metadata(_string_spec(1), list_end=True)
    )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetPlayerApplicationSettingValueTextResponse(Response):
    pdu_id = PduId.GET_PLAYER_APPLICATION_SETTING_VALUE_TEXT

    value: Sequence[int] = field(metadata=hci.metadata(1, list_begin=True))
    character_set_id: Sequence[CharacterSetId] = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    attribute_string: Sequence[str] = field(
        metadata=hci.metadata(_string_spec(1), list_end=True)
    )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class InformDisplayableCharacterSetResponse(Response):
    pdu_id = PduId.INFORM_DISPLAYABLE_CHARACTER_SET


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class InformBatteryStatusOfCtResponse(Response):
    pdu_id = PduId.INFORM_BATTERY_STATUS_OF_CT


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetPlayStatusResponse(Response):
    pdu_id = PduId.GET_PLAY_STATUS

    # TG doesn't support Song Length or Position.
    UNAVAILABLE = 0xFFFFFFFF

    song_length: int = field(metadata=hci.metadata(">4"))
    song_position: int = field(metadata=hci.metadata(">4"))
    play_status: PlayStatus = field(metadata=PlayStatus.type_metadata(1))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetElementAttributesResponse(Response):
    pdu_id = PduId.GET_ELEMENT_ATTRIBUTES
    attributes: Sequence[MediaAttribute] = field(
        metadata=hci.metadata(
            MediaAttribute.parse_from_bytes, list_begin=True, list_end=True
        )
    )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class SetAbsoluteVolumeResponse(Response):
    pdu_id = PduId.SET_ABSOLUTE_VOLUME
    volume: int = field(metadata=hci.metadata(1))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class RegisterNotificationResponse(Response):
    pdu_id = PduId.REGISTER_NOTIFICATION
    event: Event = field(
        metadata=hci.metadata(
            lambda data, offset: (len(data), Event.from_bytes(data[offset:]))
        )
    )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class SetAddressedPlayerResponse(Response):
    pdu_id = PduId.SET_ADDRESSED_PLAYER

    status: StatusCode = field(metadata=StatusCode.type_metadata(1))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class SetBrowsedPlayerResponse(Response):
    pdu_id = PduId.SET_BROWSED_PLAYER

    status: StatusCode = field(metadata=StatusCode.type_metadata(1))
    uid_counter: int = field(metadata=hci.metadata('>2'))
    numbers_of_items: int = field(metadata=hci.metadata('>4'))
    character_set_id: CharacterSetId = field(
        metadata=CharacterSetId.type_metadata(2, byteorder='big')
    )
    folder_names: Sequence[str] = field(
        metadata=hci.metadata(_string_spec(2), list_begin=True, list_end=True)
    )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetFolderItemsResponse(Response):
    pdu_id = PduId.GET_FOLDER_ITEMS

    status: StatusCode
    uid_counter: int
    items: Sequence[BrowseableItem]

    @classmethod
    def from_parameters(cls, parameters: bytes) -> Response:
        status, uid_counter, count = struct.unpack_from('>BHH', parameters)
        items: list[BrowseableItem] = []
        offset = 5
        for _ in range(count):
            offset, item = BrowseableItem.parse_from_bytes(parameters, offset)
            items.append(item)
        instance = cls(status=StatusCode(status), uid_counter=uid_counter, items=items)
        instance._payload = parameters
        return instance

    def __post_init__(self) -> None:
        if self._payload is None:
            self._payload = struct.pack(
                '>BHH', self.status, self.uid_counter, len(self.items)
            ) + b''.join(map(bytes, self.items))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class ChangePathResponse(Response):
    pdu_id = PduId.CHANGE_PATH

    status: StatusCode = field(metadata=StatusCode.type_metadata(1))
    number_of_items: int = field(metadata=hci.metadata('>4'))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetItemAttributesResponse(Response):
    pdu_id = PduId.GET_ITEM_ATTRIBUTES

    status: StatusCode = field(metadata=StatusCode.type_metadata(1))
    attribute_value_entry_list: Sequence[AttributeValueEntry] = field(
        metadata=hci.metadata(
            AttributeValueEntry.parse_from_bytes, list_begin=True, list_end=True
        )
    )


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class GetTotalNumberOfItemsResponse(Response):
    pdu_id = PduId.GET_TOTAL_NUMBER_OF_ITEMS

    status: StatusCode = field(metadata=StatusCode.type_metadata(1))
    uid_counter: int = field(metadata=hci.metadata('>2'))
    number_of_items: int = field(metadata=hci.metadata('>4'))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class SearchResponse(Response):
    pdu_id = PduId.SEARCH

    status: StatusCode = field(metadata=StatusCode.type_metadata(1))
    uid_counter: int = field(metadata=hci.metadata('>2'))
    number_of_items: int = field(metadata=hci.metadata('>4'))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class PlayItemResponse(Response):
    pdu_id = PduId.PLAY_ITEM

    status: StatusCode = field(metadata=StatusCode.type_metadata(1))


# -----------------------------------------------------------------------------
@Response.response
@dataclass
class AddToNowPlayingResponse(Response):
    pdu_id = PduId.ADD_TO_NOW_PLAYING

    status: StatusCode = field(metadata=StatusCode.type_metadata(1))


# -----------------------------------------------------------------------------
class Event:
    event_id: EventId
    _pdu: bytes | None = None

    _Event = TypeVar('_Event', bound='Event')
    subclasses: ClassVar[dict[int, type[Event]]] = {}
    fields: ClassVar[hci.Fields] = ()

    @classmethod
    def event(cls, subclass: type[_Event]) -> type[_Event]:
        cls.subclasses[subclass.event_id] = subclass
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)
        return subclass

    @classmethod
    def from_bytes(cls, pdu: bytes) -> Event:
        if not (subclass := cls.subclasses.get(pdu[0])):
            raise core.InvalidPacketError(f"Unimplemented Event {pdu[0]}")
        instance = subclass(**hci.HCI_Object.dict_from_bytes(pdu, 1, subclass.fields))
        instance._pdu = pdu
        return instance

    def __bytes__(self) -> bytes:
        if self._pdu is None:
            self._pdu = bytes([self.event_id]) + hci.HCI_Object.dict_to_bytes(
                self.__dict__, self.fields
            )
        return self._pdu


# -----------------------------------------------------------------------------
@dataclass
class GenericEvent(Event):
    event_id: EventId = field(metadata=EventId.type_metadata(1))
    data: bytes = field(metadata=hci.metadata('*'))


GenericEvent.fields = hci.HCI_Object.fields_from_dataclass(GenericEvent)


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class PlaybackStatusChangedEvent(Event):
    event_id = EventId.PLAYBACK_STATUS_CHANGED
    play_status: PlayStatus = field(metadata=PlayStatus.type_metadata(1))


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class PlaybackPositionChangedEvent(Event):
    event_id = EventId.PLAYBACK_POS_CHANGED
    playback_position: int = field(metadata=hci.metadata('>4'))


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class TrackChangedEvent(Event):
    event_id = EventId.TRACK_CHANGED
    NO_TRACK = 0xFFFFFFFFFFFFFFFF

    uid: int = field(metadata=_UINT64_BE_METADATA)


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class PlayerApplicationSettingChangedEvent(Event):
    event_id = EventId.PLAYER_APPLICATION_SETTING_CHANGED

    @dataclass
    class Setting(hci.HCI_Dataclass_Object):
        attribute_id: ApplicationSetting.AttributeId = field(
            metadata=ApplicationSetting.AttributeId.type_metadata(1)
        )
        value_id: (
            ApplicationSetting.EqualizerOnOffStatus
            | ApplicationSetting.RepeatModeStatus
            | ApplicationSetting.ShuffleOnOffStatus
            | ApplicationSetting.ScanOnOffStatus
            | ApplicationSetting.GenericValue
        ) = field(metadata=hci.metadata(1))

        def __post_init__(self) -> None:
            super().__post_init__()
            match self.attribute_id:
                case ApplicationSetting.AttributeId.EQUALIZER_ON_OFF:
                    self.value_id = ApplicationSetting.EqualizerOnOffStatus(
                        self.value_id
                    )
                case ApplicationSetting.AttributeId.REPEAT_MODE:
                    self.value_id = ApplicationSetting.RepeatModeStatus(self.value_id)
                case ApplicationSetting.AttributeId.SHUFFLE_ON_OFF:
                    self.value_id = ApplicationSetting.ShuffleOnOffStatus(self.value_id)
                case ApplicationSetting.AttributeId.SCAN_ON_OFF:
                    self.value_id = ApplicationSetting.ScanOnOffStatus(self.value_id)
                case _:
                    self.value_id = ApplicationSetting.GenericValue(self.value_id)

    player_application_settings: Sequence[Setting] = field(
        metadata=hci.metadata(Setting.parse_from_bytes, list_begin=True, list_end=True)
    )


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class NowPlayingContentChangedEvent(Event):
    event_id = EventId.NOW_PLAYING_CONTENT_CHANGED


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class AvailablePlayersChangedEvent(Event):
    event_id = EventId.AVAILABLE_PLAYERS_CHANGED


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class AddressedPlayerChangedEvent(Event):
    event_id = EventId.ADDRESSED_PLAYER_CHANGED

    @dataclass
    class Player(hci.HCI_Dataclass_Object):
        player_id: int = field(metadata=hci.metadata('>2'))
        uid_counter: int = field(metadata=hci.metadata('>2'))

    player: Player = field(metadata=hci.metadata(Player.parse_from_bytes))


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class UidsChangedEvent(Event):
    event_id = EventId.UIDS_CHANGED
    uid_counter: int = field(metadata=hci.metadata('>2'))


# -----------------------------------------------------------------------------
@Event.event
@dataclass
class VolumeChangedEvent(Event):
    event_id = EventId.VOLUME_CHANGED
    volume: int = field(metadata=hci.metadata(1))


# -----------------------------------------------------------------------------
class Delegate:
    """
    Base class for AVRCP delegates.

    All the methods are async, even if they don't always need to be, so that
    delegates that do need to wait for an async result may do so.
    """

    class Error(Exception):
        """The delegate method failed, with a specified status code."""

        def __init__(self, status_code: StatusCode) -> None:
            self.status_code = status_code

    class AvcError(Exception):
        """The delegate AVC method failed, with a specified status code."""

        def __init__(self, status_code: avc.ResponseFrame.ResponseCode) -> None:
            self.status_code = status_code

    supported_events: list[EventId]
    supported_company_ids: list[int]
    supported_player_app_settings: dict[ApplicationSetting.AttributeId, list[int]]
    player_app_settings: dict[ApplicationSetting.AttributeId, int]
    volume: int
    playback_status: PlayStatus

    def __init__(
        self,
        supported_events: Iterable[EventId] = (),
        supported_company_ids: Iterable[int] = (AVRCP_BLUETOOTH_SIG_COMPANY_ID,),
        supported_player_app_settings: (
            Mapping[ApplicationSetting.AttributeId, Sequence[int]] | None
        ) = None,
    ) -> None:
        self.supported_company_ids = list(supported_company_ids)
        self.supported_events = list(supported_events)
        self.volume = 0
        self.playback_status = PlayStatus.STOPPED
        self.supported_player_app_settings = (
            {key: list(value) for key, value in supported_player_app_settings.items()}
            if supported_player_app_settings
            else {}
        )
        self.player_app_settings = {}
        self.uid_counter = 0
        self.addressed_player_id = 0
        self.current_track_uid = TrackChangedEvent.NO_TRACK

    async def get_supported_events(self) -> list[EventId]:
        return self.supported_events

    async def get_supported_company_ids(self) -> list[int]:
        return self.supported_company_ids

    async def set_absolute_volume(self, volume: int) -> None:
        """
        Set the absolute volume.

        Returns: the effective volume that was set.
        """
        logger.debug(f"@@@ set_absolute_volume: volume={volume}")
        self.volume = volume

    async def get_absolute_volume(self) -> int:
        return self.volume

    async def on_key_event(
        self,
        key: avc.PassThroughFrame.OperationId,
        pressed: bool,
        data: bytes,
    ) -> None:
        logger.debug(
            "@@@ on_key_event: key=%s, pressed=%s, data=%s", key, pressed, data.hex()
        )

    async def get_playback_status(self) -> PlayStatus:
        return self.playback_status

    async def get_supported_player_app_settings(
        self,
    ) -> dict[ApplicationSetting.AttributeId, list[int]]:
        return self.supported_player_app_settings

    async def get_current_player_app_settings(
        self,
    ) -> dict[ApplicationSetting.AttributeId, int]:
        return self.player_app_settings

    async def set_player_app_settings(
        self, attribute: ApplicationSetting.AttributeId, value: int
    ) -> None:
        self.player_app_settings[attribute] = value

    async def play_item(self, scope: Scope, uid: int, uid_counter: int) -> None:
        logger.debug(
            "@@@ play_item: scope=%s, uid=%s, uid_counter=%s",
            scope,
            uid,
            uid_counter,
        )

    async def get_uid_counter(self) -> int:
        return self.uid_counter

    async def get_addressed_player_id(self) -> int:
        return self.addressed_player_id

    async def get_current_track_uid(self) -> int:
        return self.current_track_uid

    # TODO add other delegate methods


# -----------------------------------------------------------------------------
class Protocol(utils.EventEmitter):
    """AVRCP Controller and Target protocol."""

    EVENT_CONNECTION = "connection"
    EVENT_START = "start"
    EVENT_STOP = "stop"

    class PacketType(enum.IntEnum):
        SINGLE = 0b00
        START = 0b01
        CONTINUE = 0b10
        END = 0b11

    class InvalidPidError(Exception):
        """A response frame with ipid==1 was received."""

    class NotPendingError(Exception):
        """There is no pending command for a transaction label."""

    class MismatchedResponseError(Exception):
        """The response type does not corresponding to the request type."""

        def __init__(self, response: Response) -> None:
            self.response = response

    class UnexpectedResponseTypeError(Exception):
        """The response type is not the expected one."""

        def __init__(self, response: Protocol.ResponseContext) -> None:
            self.response = response

    class UnexpectedResponseCodeError(Exception):
        """The response code was not the expected one."""

        def __init__(
            self, response_code: avc.ResponseFrame.ResponseCode, response: Response
        ) -> None:
            self.response_code = response_code
            self.response = response

    class PendingCommand:
        response: asyncio.Future

        def __init__(self, transaction_label: int) -> None:
            self.transaction_label = transaction_label
            self.reset()

        def reset(self):
            self.response = asyncio.get_running_loop().create_future()

    @dataclass
    class ReceiveCommandState:
        transaction_label: int
        command_type: avc.CommandFrame.CommandType

    @dataclass
    class ReceiveResponseState:
        transaction_label: int
        response_code: avc.ResponseFrame.ResponseCode

    @dataclass
    class ResponseContext:
        transaction_label: int
        response: Response

    @dataclass
    class FinalResponse(ResponseContext):
        response_code: avc.ResponseFrame.ResponseCode

    @dataclass
    class InterimResponse(ResponseContext):
        final: Awaitable[Protocol.FinalResponse]

    @dataclass
    class NotificationListener:
        transaction_label: int
        register_notification_command: RegisterNotificationCommand

    delegate: Delegate
    send_transaction_label: int
    command_pdu_assembler: PduAssembler
    receive_command_state: ReceiveCommandState | None
    response_pdu_assembler: PduAssembler
    receive_response_state: ReceiveResponseState | None
    avctp_protocol: avctp.Protocol | None
    free_commands: asyncio.Queue
    pending_commands: dict[int, PendingCommand]  # Pending commands, by label
    notification_listeners: dict[EventId, NotificationListener]

    @staticmethod
    def _check_vendor_dependent_frame(
        frame: avc.VendorDependentCommandFrame | avc.VendorDependentResponseFrame,
    ) -> bool:
        if frame.company_id != AVRCP_BLUETOOTH_SIG_COMPANY_ID:
            logger.debug("unsupported company id, ignoring")
            return False

        if frame.subunit_type != avc.Frame.SubunitType.PANEL or frame.subunit_id != 0:
            logger.debug("unsupported subunit")
            return False

        return True

    def __init__(self, delegate: Delegate | None = None) -> None:
        super().__init__()
        self.delegate = delegate if delegate else Delegate()
        self.command_pdu_assembler = PduAssembler(self._on_command_pdu)
        self.receive_command_state = None
        self.response_pdu_assembler = PduAssembler(self._on_response_pdu)
        self.receive_response_state = None
        self.avctp_protocol = None
        self.notification_listeners = {}

        # Create an initial pool of free commands
        self.pending_commands = {}
        self.free_commands = asyncio.Queue()
        for transaction_label in range(16):
            self.free_commands.put_nowait(self.PendingCommand(transaction_label))

    def listen(self, device: Device) -> None:
        """
        Listen for incoming connections.

        A 'connection' event will be emitted when a connection is made, and a 'start'
        event will be emitted when the protocol is ready to be used on that connection.
        """
        device.create_l2cap_server(
            l2cap.ClassicChannelSpec(avctp.AVCTP_PSM), self._on_avctp_connection
        )

    async def connect(self, connection: Connection) -> None:
        """
        Connect to a peer.
        """
        avctp_channel = await connection.create_l2cap_channel(
            l2cap.ClassicChannelSpec(psm=avctp.AVCTP_PSM)
        )
        self._on_avctp_channel_open(avctp_channel)

    async def _obtain_pending_command(self) -> PendingCommand:
        pending_command = await self.free_commands.get()
        self.pending_commands[pending_command.transaction_label] = pending_command
        return pending_command

    def recycle_pending_command(self, pending_command: PendingCommand) -> None:
        pending_command.reset()
        del self.pending_commands[pending_command.transaction_label]
        self.free_commands.put_nowait(pending_command)
        logger.debug(f"recycled pending command, {self.free_commands.qsize()} free")

    _R = TypeVar('_R')

    @staticmethod
    def _check_response(
        response_context: ResponseContext, expected_type: type[_R]
    ) -> _R:
        if isinstance(response_context, Protocol.FinalResponse):
            if (
                response_context.response_code
                != avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE
            ):
                raise Protocol.UnexpectedResponseCodeError(
                    response_context.response_code, response_context.response
                )

            if not (isinstance(response_context.response, expected_type)):
                raise Protocol.MismatchedResponseError(response_context.response)

            return response_context.response

        raise Protocol.UnexpectedResponseTypeError(response_context)

    def _delegate_command(
        self, transaction_label: int, command: Command, method: Awaitable
    ) -> None:
        async def call() -> None:
            try:
                await method
            except Delegate.Error as error:
                self.send_rejected_avrcp_response(
                    transaction_label,
                    command.pdu_id,
                    error.status_code,
                )
            except Exception:
                logger.exception("delegate method raised exception")
                self.send_rejected_avrcp_response(
                    transaction_label,
                    command.pdu_id,
                    StatusCode.INTERNAL_ERROR,
                )

        utils.AsyncRunner.spawn(call())

    async def get_supported_events(self) -> list[EventId]:
        """Get the list of events supported by the connected peer."""
        response_context = await self.send_avrcp_command(
            avc.CommandFrame.CommandType.STATUS,
            GetCapabilitiesCommand(
                GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED
            ),
        )
        response = self._check_response(response_context, GetCapabilitiesResponse)
        return list(
            capability
            for capability in response.capabilities
            if isinstance(capability, EventId)
        )

    async def get_supported_company_ids(self) -> list[int]:
        """Get the list of events supported by the connected peer."""
        response_context = await self.send_avrcp_command(
            avc.CommandFrame.CommandType.STATUS,
            GetCapabilitiesCommand(GetCapabilitiesCommand.CapabilityId.COMPANY_ID),
        )
        response = self._check_response(response_context, GetCapabilitiesResponse)
        return list(
            int.from_bytes(capability, 'big')
            for capability in response.capabilities
            if isinstance(capability, bytes)
        )

    async def get_play_status(self) -> SongAndPlayStatus:
        """Get the play status of the connected peer."""
        response_context = await self.send_avrcp_command(
            avc.CommandFrame.CommandType.STATUS, GetPlayStatusCommand()
        )
        response = self._check_response(response_context, GetPlayStatusResponse)
        return SongAndPlayStatus(
            response.song_length, response.song_position, response.play_status
        )

    async def get_element_attributes(
        self, element_identifier: int, attribute_ids: Sequence[MediaAttributeId]
    ) -> list[MediaAttribute]:
        """Get element attributes from the connected peer."""
        response_context = await self.send_avrcp_command(
            avc.CommandFrame.CommandType.STATUS,
            GetElementAttributesCommand(element_identifier, attribute_ids),
        )
        response = self._check_response(response_context, GetElementAttributesResponse)
        return list(response.attributes)

    async def list_supported_player_app_settings(
        self, attribute_ids: Sequence[ApplicationSetting.AttributeId] = ()
    ) -> dict[ApplicationSetting.AttributeId, list[int]]:
        """Get element attributes from the connected peer."""
        response_context = await self.send_avrcp_command(
            avc.CommandFrame.CommandType.STATUS,
            ListPlayerApplicationSettingAttributesCommand(),
        )
        if not attribute_ids:
            list_attribute_response = self._check_response(
                response_context, ListPlayerApplicationSettingAttributesResponse
            )
            attribute_ids = list_attribute_response.attribute

        supported_settings: dict[ApplicationSetting.AttributeId, list[int]] = {}
        for attribute_id in attribute_ids:
            response_context = await self.send_avrcp_command(
                avc.CommandFrame.CommandType.STATUS,
                ListPlayerApplicationSettingValuesCommand(attribute_id),
            )
            list_value_response = self._check_response(
                response_context, ListPlayerApplicationSettingValuesResponse
            )
            supported_settings[attribute_id] = list(list_value_response.value)

        return supported_settings

    async def get_player_app_settings(
        self, attribute_ids: Sequence[ApplicationSetting.AttributeId]
    ) -> dict[ApplicationSetting.AttributeId, int]:
        """Get element attributes from the connected peer."""
        response_context = await self.send_avrcp_command(
            avc.CommandFrame.CommandType.STATUS,
            GetCurrentPlayerApplicationSettingValueCommand(attribute_ids),
        )
        response: GetCurrentPlayerApplicationSettingValueResponse = (
            self._check_response(
                response_context, GetCurrentPlayerApplicationSettingValueResponse
            )
        )
        return {
            attribute_id: value
            for attribute_id, value in zip(response.attribute, response.value)
        }

    async def monitor_events(
        self, event_id: EventId, playback_interval: int = 0
    ) -> AsyncIterator[Event]:
        """
        Monitor events emitted from a peer.

        This generator yields Event objects.
        """

        def check_response(response) -> Event:
            if not isinstance(response, RegisterNotificationResponse):
                raise self.MismatchedResponseError(response)

            return response.event

        while True:
            response = await self.send_avrcp_command(
                avc.CommandFrame.CommandType.NOTIFY,
                RegisterNotificationCommand(event_id, playback_interval),
            )

            if isinstance(response, self.InterimResponse):
                logger.debug(f"interim: {response}")
                yield check_response(response.response)

                logger.debug("waiting for final response")
                response = await response.final

            if not isinstance(response, self.FinalResponse):
                raise self.UnexpectedResponseTypeError(response)

            logger.debug(f"final: {response}")
            if response.response_code != avc.ResponseFrame.ResponseCode.CHANGED:
                raise self.UnexpectedResponseCodeError(
                    response.response_code, response.response
                )

            yield check_response(response.response)

    async def monitor_playback_status(
        self,
    ) -> AsyncIterator[PlayStatus]:
        """Monitor Playback Status changes from the connected peer."""
        async for event in self.monitor_events(EventId.PLAYBACK_STATUS_CHANGED, 0):
            if not isinstance(event, PlaybackStatusChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield event.play_status

    async def monitor_track_changed(
        self,
    ) -> AsyncIterator[int]:
        """Monitor Track changes from the connected peer."""
        async for event in self.monitor_events(EventId.TRACK_CHANGED, 0):
            if not isinstance(event, TrackChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield event.uid

    async def monitor_playback_position(
        self, playback_interval: int
    ) -> AsyncIterator[int]:
        """Monitor Playback Position changes from the connected peer."""
        async for event in self.monitor_events(
            EventId.PLAYBACK_POS_CHANGED, playback_interval
        ):
            if not isinstance(event, PlaybackPositionChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield event.playback_position

    async def monitor_player_application_settings(
        self,
    ) -> AsyncIterator[list[PlayerApplicationSettingChangedEvent.Setting]]:
        """Monitor Player Application Setting changes from the connected peer."""
        async for event in self.monitor_events(
            EventId.PLAYER_APPLICATION_SETTING_CHANGED, 0
        ):
            if not isinstance(event, PlayerApplicationSettingChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield list(event.player_application_settings)

    async def monitor_now_playing_content(self) -> AsyncIterator[None]:
        """Monitor Now Playing changes from the connected peer."""
        async for event in self.monitor_events(EventId.NOW_PLAYING_CONTENT_CHANGED, 0):
            if not isinstance(event, NowPlayingContentChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield None

    async def monitor_available_players(self) -> AsyncIterator[None]:
        """Monitor Available Players changes from the connected peer."""
        async for event in self.monitor_events(EventId.AVAILABLE_PLAYERS_CHANGED, 0):
            if not isinstance(event, AvailablePlayersChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield None

    async def monitor_addressed_player(
        self,
    ) -> AsyncIterator[AddressedPlayerChangedEvent.Player]:
        """Monitor Addressed Player changes from the connected peer."""
        async for event in self.monitor_events(EventId.ADDRESSED_PLAYER_CHANGED, 0):
            if not isinstance(event, AddressedPlayerChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield event.player

    async def monitor_uids(
        self,
    ) -> AsyncIterator[int]:
        """Monitor UID changes from the connected peer."""
        async for event in self.monitor_events(EventId.UIDS_CHANGED, 0):
            if not isinstance(event, UidsChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield event.uid_counter

    async def monitor_volume(
        self,
    ) -> AsyncIterator[int]:
        """Monitor Volume changes from the connected peer."""
        async for event in self.monitor_events(EventId.VOLUME_CHANGED, 0):
            if not isinstance(event, VolumeChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield event.volume

    def notify_event(self, event: Event):
        """Notify an event to the connected peer."""
        if (listener := self.notification_listeners.get(event.event_id)) is None:
            logger.debug(f"no listener for {event.event_id.name}")
            return

        # Emit the notification.
        notification = RegisterNotificationResponse(event)
        self.send_avrcp_response(
            listener.transaction_label,
            avc.ResponseFrame.ResponseCode.CHANGED,
            notification,
        )

        # Remove the listener (they will need to re-register).
        del self.notification_listeners[event.event_id]

    def notify_playback_status_changed(self, status: PlayStatus) -> None:
        """Notify the connected peer of a Playback Status change."""
        self.notify_event(PlaybackStatusChangedEvent(status))

    def notify_track_changed(self, uid: int) -> None:
        """Notify the connected peer of a Track change."""
        self.notify_event(TrackChangedEvent(uid))

    def notify_playback_position_changed(self, position: int) -> None:
        """Notify the connected peer of a Position change."""
        self.notify_event(PlaybackPositionChangedEvent(position))

    def notify_player_application_settings_changed(
        self, settings: Sequence[PlayerApplicationSettingChangedEvent.Setting]
    ) -> None:
        """Notify the connected peer of an Player Application Setting change."""
        self.notify_event(
            PlayerApplicationSettingChangedEvent(settings),
        )

    def notify_now_playing_content_changed(self) -> None:
        """Notify the connected peer of a Now Playing change."""
        self.notify_event(NowPlayingContentChangedEvent())

    def notify_available_players_changed(self) -> None:
        """Notify the connected peer of an Available Players change."""
        self.notify_event(AvailablePlayersChangedEvent())

    def notify_addressed_player_changed(
        self, player: AddressedPlayerChangedEvent.Player
    ) -> None:
        """Notify the connected peer of an Addressed Player change."""
        self.notify_event(AddressedPlayerChangedEvent(player))

    def notify_uids_changed(self, uid_counter: int) -> None:
        """Notify the connected peer of a UID change."""
        self.notify_event(UidsChangedEvent(uid_counter))

    def notify_volume_changed(self, volume: int) -> None:
        """Notify the connected peer of a Volume change."""
        self.notify_event(VolumeChangedEvent(volume))

    def _register_notification_listener(
        self, transaction_label: int, command: RegisterNotificationCommand
    ) -> None:
        listener = self.NotificationListener(transaction_label, command)
        self.notification_listeners[command.event_id] = listener

    def _on_avctp_connection(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug("AVCTP connection established")
        l2cap_channel.on(
            l2cap_channel.EVENT_OPEN, lambda: self._on_avctp_channel_open(l2cap_channel)
        )

        self.emit(self.EVENT_CONNECTION)

    def _on_avctp_channel_open(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug("AVCTP channel open")
        if self.avctp_protocol is not None:
            # TODO: find a better strategy instead of just closing
            logger.warning("AVCTP protocol already active, closing connection")
            utils.AsyncRunner.spawn(l2cap_channel.disconnect())
            return

        self.avctp_protocol = avctp.Protocol(l2cap_channel)
        self.avctp_protocol.register_command_handler(AVRCP_PID, self._on_avctp_command)
        self.avctp_protocol.register_response_handler(
            AVRCP_PID, self._on_avctp_response
        )
        l2cap_channel.on(l2cap_channel.EVENT_CLOSE, self._on_avctp_channel_close)

        self.emit(self.EVENT_START)

    def _on_avctp_channel_close(self) -> None:
        logger.debug("AVCTP channel closed")
        self.avctp_protocol = None

        self.emit(self.EVENT_STOP)

    def _on_avctp_command(self, transaction_label: int, payload: bytes) -> None:
        command = avc.CommandFrame.from_bytes(payload)
        if not isinstance(command, avc.CommandFrame):
            raise core.InvalidPacketError(
                f"{command} is not a valid AV/C Command Frame"
            )
        logger.debug(
            f"<<< AVCTP Command, transaction_label={transaction_label}: {command}"
        )

        # Only addressing the unit, or the PANEL subunit with subunit ID 0 is supported
        # in this profile.
        if not (
            command.subunit_type == avc.Frame.SubunitType.UNIT
            and command.subunit_id == 7
        ) and not (
            command.subunit_type == avc.Frame.SubunitType.PANEL
            and command.subunit_id == 0
        ):
            logger.debug("subunit not supported")
            self.send_not_implemented_response(transaction_label, command)
            return

        if isinstance(command, avc.VendorDependentCommandFrame):
            if not self._check_vendor_dependent_frame(command):
                return

            if self.receive_command_state is None:
                self.receive_command_state = self.ReceiveCommandState(
                    transaction_label=transaction_label, command_type=command.ctype
                )
            elif (
                self.receive_command_state.transaction_label != transaction_label
                or self.receive_command_state.command_type != command.ctype
            ):
                # We're in the middle of some other PDU
                logger.warning("received interleaved PDU, resetting state")
                self.command_pdu_assembler.reset()
                self.receive_command_state = None
                return
            else:
                self.receive_command_state.command_type = command.ctype
                self.receive_command_state.transaction_label = transaction_label

            self.command_pdu_assembler.on_pdu(command.vendor_dependent_data)
            return

        if isinstance(command, avc.PassThroughCommandFrame):

            async def dispatch_key_event() -> None:
                try:
                    await self.delegate.on_key_event(
                        command.operation_id,
                        command.state_flag == avc.PassThroughFrame.StateFlag.PRESSED,
                        command.operation_data,
                    )
                    response_code = avc.ResponseFrame.ResponseCode.ACCEPTED
                except Delegate.AvcError as error:
                    logger.exception("delegate method raised exception")
                    response_code = error.status_code
                except Exception:
                    logger.exception("delegate method raised exception")
                    response_code = avc.ResponseFrame.ResponseCode.REJECTED
                self.send_passthrough_response(
                    transaction_label=transaction_label,
                    command=command,
                    response_code=response_code,
                )

            utils.AsyncRunner.spawn(dispatch_key_event())
            return

        # TODO handle other types
        self.send_not_implemented_response(transaction_label, command)

    def _on_avctp_response(self, transaction_label: int, payload: bytes | None) -> None:
        response = avc.ResponseFrame.from_bytes(payload) if payload else None
        if not isinstance(response, avc.ResponseFrame):
            raise core.InvalidPacketError(
                f"{response} is not a valid AV/C Response Frame"
            )
        logger.debug(
            f"<<< AVCTP Response, transaction_label={transaction_label}: {response}"
        )

        # Check that we have a pending command that matches this response.
        if not (pending_command := self.pending_commands.get(transaction_label)):
            logger.warning("no pending command with this transaction label")
            return

        # A None response means an invalid PID was used in the request.
        if response is None:
            pending_command.response.set_exception(self.InvalidPidError())

        if isinstance(response, avc.VendorDependentResponseFrame):
            if not self._check_vendor_dependent_frame(response):
                return

            if self.receive_response_state is None:
                self.receive_response_state = self.ReceiveResponseState(
                    transaction_label=transaction_label, response_code=response.response
                )
            elif (
                self.receive_response_state.transaction_label != transaction_label
                or self.receive_response_state.response_code != response.response
            ):
                # We're in the middle of some other PDU
                logger.warning("received interleaved PDU, resetting state")
                self.response_pdu_assembler.reset()
                self.receive_response_state = None
                return
            else:
                self.receive_response_state.response_code = response.response
                self.receive_response_state.transaction_label = transaction_label

            self.response_pdu_assembler.on_pdu(response.vendor_dependent_data)
            return

        if isinstance(response, avc.PassThroughResponseFrame):
            pending_command.response.set_result(response)

        # TODO handle other types

        self.recycle_pending_command(pending_command)

    def _on_command_pdu(self, pdu_id: PduId, pdu: bytes) -> None:
        logger.debug(f"<<< AVRCP command PDU [pdu_id={pdu_id.name}]: {pdu.hex()}")

        assert self.receive_command_state is not None
        transaction_label = self.receive_command_state.transaction_label

        # Dispatch the command.
        # NOTE: with a small number of supported commands, a manual dispatch like this
        # is Ok, but if/when more commands are supported, a lookup dispatch mechanism
        # would be more appropriate.
        # TODO: switch on ctype
        if self.receive_command_state.command_type in (
            avc.CommandFrame.CommandType.CONTROL,
            avc.CommandFrame.CommandType.STATUS,
            avc.CommandFrame.CommandType.NOTIFY,
        ):
            # TODO: catch exceptions from delegates
            command = Command.from_bytes(pdu_id, pdu)
            match command:
                case GetCapabilitiesCommand():
                    self._on_get_capabilities_command(transaction_label, command)
                case SetAbsoluteVolumeCommand():
                    self._on_set_absolute_volume_command(transaction_label, command)
                case RegisterNotificationCommand():
                    self._on_register_notification_command(transaction_label, command)
                case GetPlayStatusCommand():
                    self._on_get_play_status_command(transaction_label, command)
                case ListPlayerApplicationSettingAttributesCommand():
                    self._on_list_player_application_setting_attributes_command(
                        transaction_label, command
                    )
                case ListPlayerApplicationSettingValuesCommand():
                    self._on_list_player_application_setting_values_command(
                        transaction_label, command
                    )
                case SetPlayerApplicationSettingValueCommand():
                    self._on_set_player_application_setting_value_command(
                        transaction_label, command
                    )
                case GetCurrentPlayerApplicationSettingValueCommand():
                    self._on_get_current_player_application_setting_value_command(
                        transaction_label, command
                    )
                case PlayItemCommand():
                    self._on_play_item_command(transaction_label, command)
                case _:
                    # Not supported.
                    # TODO: check that this is the right way to respond in this case.
                    logger.debug("unsupported PDU ID")
                    self.send_rejected_avrcp_response(
                        transaction_label, pdu_id, StatusCode.INVALID_PARAMETER
                    )
        else:
            logger.debug("unsupported command type")
            self.send_rejected_avrcp_response(
                transaction_label, pdu_id, StatusCode.INVALID_COMMAND
            )

        self.receive_command_state = None

    def _on_response_pdu(self, pdu_id: PduId, pdu: bytes) -> None:
        logger.debug(f"<<< AVRCP response PDU [pdu_id={pdu_id.name}]: {pdu.hex()}")

        assert self.receive_response_state is not None

        transaction_label = self.receive_response_state.transaction_label
        response_code = self.receive_response_state.response_code
        self.receive_response_state = None

        # Check that we have a pending command that matches this response.
        if not (pending_command := self.pending_commands.get(transaction_label)):
            logger.warning("no pending command with this transaction label")
            return

        # Convert the PDU bytes into a response object.
        # NOTE: with a small number of supported responses, a manual switch like this
        # is Ok, but if/when more responses are supported, a lookup mechanism would be
        # more appropriate.
        response: Response | None = None
        match response_code:
            case avc.ResponseFrame.ResponseCode.REJECTED:
                response = RejectedResponse(
                    pdu_id=pdu_id, status_code=StatusCode(pdu[0])
                )
            case avc.ResponseFrame.ResponseCode.NOT_IMPLEMENTED:
                response = NotImplementedResponse(pdu_id=pdu_id, parameters=pdu)
            case (
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE
                | avc.ResponseFrame.ResponseCode.INTERIM
                | avc.ResponseFrame.ResponseCode.CHANGED
                | avc.ResponseFrame.ResponseCode.ACCEPTED
            ):
                response = Response.from_bytes(pdu=pdu, pdu_id=PduId(pdu_id))
            case _:
                logger.debug("unexpected response code")
                pending_command.response.set_exception(
                    core.ProtocolError(
                        error_code=None,
                        error_namespace="avrcp",
                        details="unexpected response code",
                    )
                )

        if response is None:
            self.recycle_pending_command(pending_command)
            return

        logger.debug(f"<<< AVRCP response: {response}")

        # Make the response available to the waiter.
        if response_code == avc.ResponseFrame.ResponseCode.INTERIM:
            pending_interim_response = pending_command.response
            pending_command.reset()
            pending_interim_response.set_result(
                self.InterimResponse(
                    pending_command.transaction_label,
                    response,
                    pending_command.response,
                )
            )
        else:
            pending_command.response.set_result(
                self.FinalResponse(
                    pending_command.transaction_label,
                    response,
                    response_code,
                )
            )
            self.recycle_pending_command(pending_command)

    def send_command(self, transaction_label: int, command: avc.CommandFrame) -> None:
        logger.debug(f">>> AVRCP command: {command}")

        if self.avctp_protocol is None:
            logger.warning("trying to send command while avctp_protocol is None")
            return

        self.avctp_protocol.send_command(transaction_label, AVRCP_PID, bytes(command))

    async def send_passthrough_command(
        self, command: avc.PassThroughCommandFrame
    ) -> avc.PassThroughResponseFrame:
        # Wait for a free command slot.
        pending_command = await self._obtain_pending_command()

        # Send the command.
        self.send_command(pending_command.transaction_label, command)

        # Wait for the response.
        return await pending_command.response

    async def send_key_event(
        self, key: avc.PassThroughCommandFrame.OperationId, pressed: bool
    ) -> avc.PassThroughResponseFrame:
        """Send a key event to the connected peer."""
        return await self.send_passthrough_command(
            avc.PassThroughCommandFrame(
                avc.CommandFrame.CommandType.CONTROL,
                avc.Frame.SubunitType.PANEL,
                0,
                (
                    avc.PassThroughFrame.StateFlag.PRESSED
                    if pressed
                    else avc.PassThroughFrame.StateFlag.RELEASED
                ),
                key,
                b'',
            )
        )

    async def send_avrcp_command(
        self, command_type: avc.CommandFrame.CommandType, command: Command
    ) -> ResponseContext:
        # Wait for a free command slot.
        pending_command = await self._obtain_pending_command()

        # TODO: fragmentation
        # Send the command.
        logger.debug(f">>> AVRCP command PDU: {command}")
        payload = bytes(command)
        pdu = struct.pack(">BBH", command.pdu_id, 0, len(payload)) + payload
        command_frame = avc.VendorDependentCommandFrame(
            command_type,
            avc.Frame.SubunitType.PANEL,
            0,
            AVRCP_BLUETOOTH_SIG_COMPANY_ID,
            pdu,
        )
        self.send_command(pending_command.transaction_label, command_frame)

        # Wait for the response.
        return await pending_command.response

    def send_response(
        self, transaction_label: int, response: avc.ResponseFrame
    ) -> None:
        assert self.avctp_protocol is not None
        logger.debug(f">>> AVRCP response: {response}")
        self.avctp_protocol.send_response(transaction_label, AVRCP_PID, bytes(response))

    def send_passthrough_response(
        self,
        transaction_label: int,
        command: avc.PassThroughCommandFrame,
        response_code: avc.ResponseFrame.ResponseCode,
    ):
        response = avc.PassThroughResponseFrame(
            response_code,
            avc.Frame.SubunitType.PANEL,
            0,
            command.state_flag,
            command.operation_id,
            command.operation_data,
        )
        self.send_response(transaction_label, response)

    def send_avrcp_response(
        self,
        transaction_label: int,
        response_code: avc.ResponseFrame.ResponseCode,
        response: Response,
    ) -> None:
        # TODO: fragmentation
        logger.debug(f">>> AVRCP response PDU: {response}")
        payload = bytes(response)
        pdu = struct.pack(">BBH", response.pdu_id, 0, len(payload)) + payload
        response_frame = avc.VendorDependentResponseFrame(
            response_code,
            avc.Frame.SubunitType.PANEL,
            0,
            AVRCP_BLUETOOTH_SIG_COMPANY_ID,
            pdu,
        )
        self.send_response(transaction_label, response_frame)

    def send_not_implemented_response(
        self, transaction_label: int, command: avc.CommandFrame
    ) -> None:
        response = avc.ResponseFrame(
            avc.ResponseFrame.ResponseCode.NOT_IMPLEMENTED,
            command.subunit_type,
            command.subunit_id,
            command.opcode,
            command.operands,
        )
        self.send_response(transaction_label, response)

    def send_rejected_avrcp_response(
        self, transaction_label: int, pdu_id: PduId, status_code: StatusCode
    ) -> None:
        self.send_avrcp_response(
            transaction_label,
            avc.ResponseFrame.ResponseCode.REJECTED,
            RejectedResponse(pdu_id, status_code),
        )

    def send_not_implemented_avrcp_response(
        self, transaction_label: int, pdu_id: PduId
    ) -> None:
        self.send_avrcp_response(
            transaction_label,
            avc.ResponseFrame.ResponseCode.NOT_IMPLEMENTED,
            NotImplementedResponse(pdu_id, b''),
        )

    def _on_get_capabilities_command(
        self, transaction_label: int, command: GetCapabilitiesCommand
    ) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        async def get_supported_events() -> None:
            capabilities: Sequence[bytes | SupportsBytes]
            match command.capability_id:
                case GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED:
                    capabilities = await self.delegate.get_supported_events()
                case GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED.COMPANY_ID:
                    company_ids = await self.delegate.get_supported_company_ids()
                    capabilities = [
                        company_id.to_bytes(3, 'big') for company_id in company_ids
                    ]
                case _:
                    raise core.InvalidArgumentError(
                        f"Unsupported capability: {command.capability_id}"
                    )
            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                GetCapabilitiesResponse(command.capability_id, capabilities),
            )

        self._delegate_command(transaction_label, command, get_supported_events())

    def _on_set_absolute_volume_command(
        self, transaction_label: int, command: SetAbsoluteVolumeCommand
    ) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        async def set_absolute_volume() -> None:
            await self.delegate.set_absolute_volume(command.volume)
            effective_volume = await self.delegate.get_absolute_volume()
            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.ACCEPTED,
                SetAbsoluteVolumeResponse(effective_volume),
            )

        self._delegate_command(transaction_label, command, set_absolute_volume())

    def _on_get_play_status_command(
        self, transaction_label: int, command: GetPlayStatusCommand
    ) -> None:
        logger.debug("<<< AVRCP command PDU: %s", command)

        async def get_playback_status() -> None:
            play_status: PlayStatus = await self.delegate.get_playback_status()
            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                GetPlayStatusResponse(
                    # TODO: Delegate this.
                    song_length=GetPlayStatusResponse.UNAVAILABLE,
                    song_position=GetPlayStatusResponse.UNAVAILABLE,
                    play_status=play_status,
                ),
            )

        self._delegate_command(transaction_label, command, get_playback_status())

    def _on_list_player_application_setting_attributes_command(
        self,
        transaction_label: int,
        command: ListPlayerApplicationSettingAttributesCommand,
    ) -> None:
        logger.debug("<<< AVRCP command PDU: %s", command)

        async def get_supported_player_app_settings() -> None:
            supported_settings = await self.delegate.get_supported_player_app_settings()
            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                ListPlayerApplicationSettingAttributesResponse(
                    list(supported_settings.keys())
                ),
            )

        self._delegate_command(
            transaction_label, command, get_supported_player_app_settings()
        )

    def _on_list_player_application_setting_values_command(
        self,
        transaction_label: int,
        command: ListPlayerApplicationSettingValuesCommand,
    ) -> None:
        logger.debug("<<< AVRCP command PDU: %s", command)

        async def get_supported_player_app_settings() -> None:
            supported_settings = await self.delegate.get_supported_player_app_settings()
            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                ListPlayerApplicationSettingValuesResponse(
                    supported_settings.get(command.attribute, [])
                ),
            )

        self._delegate_command(
            transaction_label, command, get_supported_player_app_settings()
        )

    def _on_get_current_player_application_setting_value_command(
        self,
        transaction_label: int,
        command: GetCurrentPlayerApplicationSettingValueCommand,
    ) -> None:
        logger.debug("<<< AVRCP command PDU: %s", command)

        async def get_supported_player_app_settings() -> None:
            current_settings = await self.delegate.get_current_player_app_settings()

            if not all(
                attribute in current_settings for attribute in command.attribute
            ):
                self.send_not_implemented_avrcp_response(
                    transaction_label,
                    PduId.GET_CURRENT_PLAYER_APPLICATION_SETTING_VALUE,
                )
                return

            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                GetCurrentPlayerApplicationSettingValueResponse(
                    attribute=command.attribute,
                    value=[
                        current_settings[attribute] for attribute in command.attribute
                    ],
                ),
            )

        self._delegate_command(
            transaction_label, command, get_supported_player_app_settings()
        )

    def _on_set_player_application_setting_value_command(
        self,
        transaction_label: int,
        command: SetPlayerApplicationSettingValueCommand,
    ) -> None:
        logger.debug("<<< AVRCP command PDU: %s", command)

        async def set_player_app_settings() -> None:
            for attribute, value in zip(command.attribute, command.value):
                await self.delegate.set_player_app_settings(attribute, value)

            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                SetPlayerApplicationSettingValueResponse(),
            )

        self._delegate_command(transaction_label, command, set_player_app_settings())

    def _on_play_item_command(
        self,
        transaction_label: int,
        command: PlayItemCommand,
    ) -> None:
        logger.debug("<<< AVRCP command PDU: %s", command)

        async def play_item() -> None:
            await self.delegate.play_item(
                scope=command.scope, uid=command.uid, uid_counter=command.uid_counter
            )

            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                PlayItemResponse(status=StatusCode.OPERATION_COMPLETED),
            )

        self._delegate_command(transaction_label, command, play_item())

    def _on_register_notification_command(
        self, transaction_label: int, command: RegisterNotificationCommand
    ) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        async def register_notification() -> None:
            # Check if the event is supported.
            supported_events = await self.delegate.get_supported_events()
            if command.event_id not in supported_events:
                logger.debug("event not supported")
                self.send_not_implemented_avrcp_response(
                    transaction_label, PduId.REGISTER_NOTIFICATION
                )
                return

            event: Event
            match command.event_id:
                case EventId.VOLUME_CHANGED:
                    volume = await self.delegate.get_absolute_volume()
                    event = VolumeChangedEvent(volume)
                case EventId.PLAYBACK_STATUS_CHANGED:
                    playback_status = await self.delegate.get_playback_status()
                    event = PlaybackStatusChangedEvent(play_status=playback_status)
                case EventId.NOW_PLAYING_CONTENT_CHANGED:
                    event = NowPlayingContentChangedEvent()
                case EventId.PLAYER_APPLICATION_SETTING_CHANGED:
                    settings = await self.delegate.get_current_player_app_settings()
                    event = PlayerApplicationSettingChangedEvent(
                        [
                            PlayerApplicationSettingChangedEvent.Setting(
                                attribute, value  # type: ignore
                            )
                            for attribute, value in settings.items()
                        ]
                    )
                case EventId.AVAILABLE_PLAYERS_CHANGED:
                    event = AvailablePlayersChangedEvent()
                case EventId.ADDRESSED_PLAYER_CHANGED:
                    event = AddressedPlayerChangedEvent(
                        AddressedPlayerChangedEvent.Player(
                            player_id=await self.delegate.get_addressed_player_id(),
                            uid_counter=await self.delegate.get_uid_counter(),
                        )
                    )
                case EventId.UIDS_CHANGED:
                    event = UidsChangedEvent(await self.delegate.get_uid_counter())
                case EventId.TRACK_CHANGED:
                    event = TrackChangedEvent(
                        await self.delegate.get_current_track_uid()
                    )
                case _:
                    logger.warning(
                        "Event supported but not handled %s", command.event_id
                    )
                    return

            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.INTERIM,
                RegisterNotificationResponse(event),
            )
            self._register_notification_listener(transaction_label, command)

        self._delegate_command(transaction_label, command, register_notification())
