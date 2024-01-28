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
from dataclasses import dataclass
import enum
import logging
import struct
from typing import (
    AsyncIterator,
    Awaitable,
    Callable,
    cast,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    SupportsBytes,
    Tuple,
    Type,
    TypeVar,
    Union,
)

import pyee

from bumble.colors import color
from bumble.device import Device, Connection
from bumble.sdp import (
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
    DataElement,
    ServiceAttribute,
)
from bumble.utils import AsyncRunner, OpenIntEnum
from bumble.core import (
    ProtocolError,
    BT_L2CAP_PROTOCOL_ID,
    BT_AVCTP_PROTOCOL_ID,
    BT_AV_REMOTE_CONTROL_SERVICE,
    BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE,
    BT_AV_REMOTE_CONTROL_TARGET_SERVICE,
)
from bumble import l2cap
from bumble import avc
from bumble import avctp
from bumble import utils


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
AVRCP_PID = 0x110E
AVRCP_BLUETOOTH_SIG_COMPANY_ID = 0x001958


# -----------------------------------------------------------------------------
def make_controller_service_sdp_records(
    service_record_handle: int,
    avctp_version: Tuple[int, int] = (1, 4),
    avrcp_version: Tuple[int, int] = (1, 6),
    supported_features: int = 1,
) -> List[ServiceAttribute]:
    # TODO: support a way to compute the supported features from a feature list
    avctp_version_int = avctp_version[0] << 8 | avctp_version[1]
    avrcp_version_int = avrcp_version[0] << 8 | avrcp_version[1]

    return [
        ServiceAttribute(
            SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            DataElement.unsigned_integer_32(service_record_handle),
        ),
        ServiceAttribute(
            SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
        ),
        ServiceAttribute(
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.uuid(BT_AV_REMOTE_CONTROL_SERVICE),
                    DataElement.uuid(BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_L2CAP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(avctp.AVCTP_PSM),
                        ]
                    ),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AVCTP_PROTOCOL_ID),
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
                            DataElement.uuid(BT_AV_REMOTE_CONTROL_SERVICE),
                            DataElement.unsigned_integer_16(avrcp_version_int),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            DataElement.unsigned_integer_16(supported_features),
        ),
    ]


# -----------------------------------------------------------------------------
def make_target_service_sdp_records(
    service_record_handle: int,
    avctp_version: Tuple[int, int] = (1, 4),
    avrcp_version: Tuple[int, int] = (1, 6),
    supported_features: int = 0x23,
) -> List[ServiceAttribute]:
    # TODO: support a way to compute the supported features from a feature list
    avctp_version_int = avctp_version[0] << 8 | avctp_version[1]
    avrcp_version_int = avrcp_version[0] << 8 | avrcp_version[1]

    return [
        ServiceAttribute(
            SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            DataElement.unsigned_integer_32(service_record_handle),
        ),
        ServiceAttribute(
            SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
        ),
        ServiceAttribute(
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.uuid(BT_AV_REMOTE_CONTROL_TARGET_SERVICE),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_L2CAP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(avctp.AVCTP_PSM),
                        ]
                    ),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AVCTP_PROTOCOL_ID),
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
                            DataElement.uuid(BT_AV_REMOTE_CONTROL_SERVICE),
                            DataElement.unsigned_integer_16(avrcp_version_int),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            DataElement.unsigned_integer_16(supported_features),
        ),
    ]


# -----------------------------------------------------------------------------
def _decode_attribute_value(value: bytes, character_set: CharacterSetId) -> str:
    try:
        if character_set == CharacterSetId.UTF_8:
            return value.decode("utf-8")
        return value.decode("ascii")
    except UnicodeDecodeError:
        logger.warning(f"cannot decode string with bytes: {value.hex()}")
        return ""


# -----------------------------------------------------------------------------
class PduAssembler:
    """
    PDU Assembler to support fragmented PDUs are defined in:
    Audio/Video Remote Control / Profile Specification
    6.3.1 AVRCP specific AV//C commands
    """

    pdu_id: Optional[Protocol.PduId]
    payload: bytes

    def __init__(self, callback: Callable[[Protocol.PduId, bytes], None]) -> None:
        self.callback = callback
        self.reset()

    def reset(self) -> None:
        self.pdu_id = None
        self.parameter = b''

    def on_pdu(self, pdu: bytes) -> None:
        pdu_id = Protocol.PduId(pdu[0])
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
        except Exception as error:
            logger.exception(color(f'!!! exception in callback: {error}', 'red'))

        self.reset()


# -----------------------------------------------------------------------------
@dataclass
class Command:
    pdu_id: Protocol.PduId
    parameter: bytes

    def to_string(self, properties: Dict[str, str]) -> str:
        properties_str = ",".join(
            [f"{name}={value}" for name, value in properties.items()]
        )
        return f"Command[{self.pdu_id.name}]({properties_str})"

    def __str__(self) -> str:
        return self.to_string({"parameters": self.parameter.hex()})

    def __repr__(self) -> str:
        return str(self)


# -----------------------------------------------------------------------------
class GetCapabilitiesCommand(Command):
    class CapabilityId(OpenIntEnum):
        COMPANY_ID = 0x02
        EVENTS_SUPPORTED = 0x03

    capability_id: CapabilityId

    @classmethod
    def from_bytes(cls, pdu: bytes) -> GetCapabilitiesCommand:
        return cls(cls.CapabilityId(pdu[0]))

    def __init__(self, capability_id: CapabilityId) -> None:
        super().__init__(Protocol.PduId.GET_CAPABILITIES, bytes([capability_id]))
        self.capability_id = capability_id

    def __str__(self) -> str:
        return self.to_string({"capability_id": self.capability_id.name})


# -----------------------------------------------------------------------------
class GetPlayStatusCommand(Command):
    @classmethod
    def from_bytes(cls, _: bytes) -> GetPlayStatusCommand:
        return cls()

    def __init__(self) -> None:
        super().__init__(Protocol.PduId.GET_PLAY_STATUS, b'')


# -----------------------------------------------------------------------------
class GetElementAttributesCommand(Command):
    identifier: int
    attribute_ids: List[MediaAttributeId]

    @classmethod
    def from_bytes(cls, pdu: bytes) -> GetElementAttributesCommand:
        identifier = struct.unpack_from(">Q", pdu)[0]
        num_attributes = pdu[8]
        attribute_ids = [MediaAttributeId(pdu[9 + i]) for i in range(num_attributes)]
        return cls(identifier, attribute_ids)

    def __init__(
        self, identifier: int, attribute_ids: Sequence[MediaAttributeId]
    ) -> None:
        parameter = struct.pack(">QB", identifier, len(attribute_ids)) + b''.join(
            [struct.pack(">I", int(attribute_id)) for attribute_id in attribute_ids]
        )
        super().__init__(Protocol.PduId.GET_ELEMENT_ATTRIBUTES, parameter)
        self.identifier = identifier
        self.attribute_ids = list(attribute_ids)


# -----------------------------------------------------------------------------
class SetAbsoluteVolumeCommand(Command):
    MAXIMUM_VOLUME = 0x7F

    volume: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> SetAbsoluteVolumeCommand:
        return cls(pdu[0])

    def __init__(self, volume: int) -> None:
        super().__init__(Protocol.PduId.SET_ABSOLUTE_VOLUME, bytes([volume]))
        self.volume = volume

    def __str__(self) -> str:
        return self.to_string({"volume": str(self.volume)})


# -----------------------------------------------------------------------------
class RegisterNotificationCommand(Command):
    event_id: EventId
    playback_interval: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> RegisterNotificationCommand:
        event_id = EventId(pdu[0])
        playback_interval = struct.unpack_from(">I", pdu, 1)[0]
        return cls(event_id, playback_interval)

    def __init__(self, event_id: EventId, playback_interval: int) -> None:
        super().__init__(
            Protocol.PduId.REGISTER_NOTIFICATION,
            struct.pack(">BI", int(event_id), playback_interval),
        )
        self.event_id = event_id
        self.playback_interval = playback_interval

    def __str__(self) -> str:
        return self.to_string(
            {
                "event_id": self.event_id.name,
                "playback_interval": str(self.playback_interval),
            }
        )


# -----------------------------------------------------------------------------
@dataclass
class Response:
    pdu_id: Protocol.PduId
    parameter: bytes

    def to_string(self, properties: Dict[str, str]) -> str:
        properties_str = ",".join(
            [f"{name}={value}" for name, value in properties.items()]
        )
        return f"Response[{self.pdu_id.name}]({properties_str})"

    def __str__(self) -> str:
        return self.to_string({"parameter": self.parameter.hex()})

    def __repr__(self) -> str:
        return str(self)


# -----------------------------------------------------------------------------
class RejectedResponse(Response):
    status_code: Protocol.StatusCode

    @classmethod
    def from_bytes(cls, pdu_id: Protocol.PduId, pdu: bytes) -> RejectedResponse:
        return cls(pdu_id, Protocol.StatusCode(pdu[0]))

    def __init__(
        self, pdu_id: Protocol.PduId, status_code: Protocol.StatusCode
    ) -> None:
        super().__init__(pdu_id, bytes([int(status_code)]))
        self.status_code = status_code

    def __str__(self) -> str:
        return self.to_string(
            {
                "status_code": self.status_code.name,
            }
        )


# -----------------------------------------------------------------------------
class NotImplementedResponse(Response):
    @classmethod
    def from_bytes(cls, pdu_id: Protocol.PduId, pdu: bytes) -> NotImplementedResponse:
        return cls(pdu_id, pdu[1:])


# -----------------------------------------------------------------------------
class GetCapabilitiesResponse(Response):
    capability_id: GetCapabilitiesCommand.CapabilityId
    capabilities: List[Union[SupportsBytes, bytes]]

    @classmethod
    def from_bytes(cls, pdu: bytes) -> GetCapabilitiesResponse:
        if len(pdu) < 2:
            # Possibly a reject response.
            return cls(GetCapabilitiesCommand.CapabilityId(0), [])

        # Assume that the payloads all follow the same pattern:
        #  <CapabilityID><CapabilityCount><Capability*>
        capability_id = GetCapabilitiesCommand.CapabilityId(pdu[0])
        capability_count = pdu[1]

        capabilities: List[Union[SupportsBytes, bytes]]
        if capability_id == GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED:
            capabilities = [EventId(pdu[2 + x]) for x in range(capability_count)]
        else:
            capability_size = (len(pdu) - 2) // capability_count
            capabilities = [
                pdu[x : x + capability_size]
                for x in range(2, len(pdu), capability_size)
            ]

        return cls(capability_id, capabilities)

    def __init__(
        self,
        capability_id: GetCapabilitiesCommand.CapabilityId,
        capabilities: Sequence[Union[SupportsBytes, bytes]],
    ) -> None:
        super().__init__(
            Protocol.PduId.GET_CAPABILITIES,
            bytes([capability_id, len(capabilities)])
            + b''.join(bytes(capability) for capability in capabilities),
        )
        self.capability_id = capability_id
        self.capabilities = list(capabilities)

    def __str__(self) -> str:
        return self.to_string(
            {
                "capability_id": self.capability_id.name,
                "capabilities": str(self.capabilities),
            }
        )


# -----------------------------------------------------------------------------
class GetPlayStatusResponse(Response):
    song_length: int
    song_position: int
    play_status: PlayStatus

    @classmethod
    def from_bytes(cls, pdu: bytes) -> GetPlayStatusResponse:
        (song_length, song_position) = struct.unpack_from(">II", pdu, 0)
        play_status = PlayStatus(pdu[8])

        return cls(song_length, song_position, play_status)

    def __init__(
        self,
        song_length: int,
        song_position: int,
        play_status: PlayStatus,
    ) -> None:
        super().__init__(
            Protocol.PduId.GET_PLAY_STATUS,
            struct.pack(">IIB", song_length, song_position, int(play_status)),
        )
        self.song_length = song_length
        self.song_position = song_position
        self.play_status = play_status

    def __str__(self) -> str:
        return self.to_string(
            {
                "song_length": str(self.song_length),
                "song_position": str(self.song_position),
                "play_status": self.play_status.name,
            }
        )


# -----------------------------------------------------------------------------
class GetElementAttributesResponse(Response):
    attributes: List[MediaAttribute]

    @classmethod
    def from_bytes(cls, pdu: bytes) -> GetElementAttributesResponse:
        num_attributes = pdu[0]
        offset = 1
        attributes: List[MediaAttribute] = []
        for _ in range(num_attributes):
            (
                attribute_id_int,
                character_set_id_int,
                attribute_value_length,
            ) = struct.unpack_from(">IHH", pdu, offset)
            attribute_value_bytes = pdu[
                offset + 8 : offset + 8 + attribute_value_length
            ]
            attribute_id = MediaAttributeId(attribute_id_int)
            character_set_id = CharacterSetId(character_set_id_int)
            attribute_value = _decode_attribute_value(
                attribute_value_bytes, character_set_id
            )
            attributes.append(
                MediaAttribute(attribute_id, character_set_id, attribute_value)
            )
            offset += 8 + attribute_value_length

        return cls(attributes)

    def __init__(self, attributes: Sequence[MediaAttribute]) -> None:
        parameter = bytes([len(attributes)])
        for attribute in attributes:
            attribute_value_bytes = attribute.attribute_value.encode("utf-8")
            parameter += (
                struct.pack(
                    ">IHH",
                    int(attribute.attribute_id),
                    int(CharacterSetId.UTF_8),
                    len(attribute_value_bytes),
                )
                + attribute_value_bytes
            )
        super().__init__(
            Protocol.PduId.GET_ELEMENT_ATTRIBUTES,
            parameter,
        )
        self.attributes = list(attributes)

    def __str__(self) -> str:
        attribute_strs = [str(attribute) for attribute in self.attributes]
        return self.to_string(
            {
                "attributes": f"[{', '.join(attribute_strs)}]",
            }
        )


# -----------------------------------------------------------------------------
class SetAbsoluteVolumeResponse(Response):
    volume: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> SetAbsoluteVolumeResponse:
        return cls(pdu[0])

    def __init__(self, volume: int) -> None:
        super().__init__(Protocol.PduId.SET_ABSOLUTE_VOLUME, bytes([volume]))
        self.volume = volume

    def __str__(self) -> str:
        return self.to_string({"volume": str(self.volume)})


# -----------------------------------------------------------------------------
class RegisterNotificationResponse(Response):
    event: Event

    @classmethod
    def from_bytes(cls, pdu: bytes) -> RegisterNotificationResponse:
        return cls(Event.from_bytes(pdu))

    def __init__(self, event: Event) -> None:
        super().__init__(
            Protocol.PduId.REGISTER_NOTIFICATION,
            bytes(event),
        )
        self.event = event

    def __str__(self) -> str:
        return self.to_string(
            {
                "event": str(self.event),
            }
        )


# -----------------------------------------------------------------------------
class EventId(OpenIntEnum):
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


# -----------------------------------------------------------------------------
class CharacterSetId(OpenIntEnum):
    UTF_8 = 0x06


# -----------------------------------------------------------------------------
class MediaAttributeId(OpenIntEnum):
    TITLE = 0x01
    ARTIST_NAME = 0x02
    ALBUM_NAME = 0x03
    TRACK_NUMBER = 0x04
    TOTAL_NUMBER_OF_TRACKS = 0x05
    GENRE = 0x06
    PLAYING_TIME = 0x07
    DEFAULT_COVER_ART = 0x08


# -----------------------------------------------------------------------------
@dataclass
class MediaAttribute:
    attribute_id: MediaAttributeId
    character_set_id: CharacterSetId
    attribute_value: str


# -----------------------------------------------------------------------------
class PlayStatus(OpenIntEnum):
    STOPPED = 0x00
    PLAYING = 0x01
    PAUSED = 0x02
    FWD_SEEK = 0x03
    REV_SEEK = 0x04
    ERROR = 0xFF


# -----------------------------------------------------------------------------
@dataclass
class SongAndPlayStatus:
    song_length: int
    song_position: int
    play_status: PlayStatus


# -----------------------------------------------------------------------------
class ApplicationSetting:
    class AttributeId(OpenIntEnum):
        EQUALIZER_ON_OFF = 0x01
        REPEAT_MODE = 0x02
        SHUFFLE_ON_OFF = 0x03
        SCAN_ON_OFF = 0x04

    class EqualizerOnOffStatus(OpenIntEnum):
        OFF = 0x01
        ON = 0x02

    class RepeatModeStatus(OpenIntEnum):
        OFF = 0x01
        SINGLE_TRACK_REPEAT = 0x02
        ALL_TRACK_REPEAT = 0x03
        GROUP_REPEAT = 0x04

    class ShuffleOnOffStatus(OpenIntEnum):
        OFF = 0x01
        ALL_TRACKS_SHUFFLE = 0x02
        GROUP_SHUFFLE = 0x03

    class ScanOnOffStatus(OpenIntEnum):
        OFF = 0x01
        ALL_TRACKS_SCAN = 0x02
        GROUP_SCAN = 0x03

    class GenericValue(OpenIntEnum):
        pass


# -----------------------------------------------------------------------------
@dataclass
class Event:
    event_id: EventId

    @classmethod
    def from_bytes(cls, pdu: bytes) -> Event:
        event_id = EventId(pdu[0])
        subclass = EVENT_SUBCLASSES.get(event_id, GenericEvent)
        return subclass.from_bytes(pdu)

    def __bytes__(self) -> bytes:
        return bytes([self.event_id])


# -----------------------------------------------------------------------------
@dataclass
class GenericEvent(Event):
    data: bytes

    @classmethod
    def from_bytes(cls, pdu: bytes) -> GenericEvent:
        return cls(event_id=EventId(pdu[0]), data=pdu[1:])

    def __bytes__(self) -> bytes:
        return bytes([self.event_id]) + self.data


# -----------------------------------------------------------------------------
@dataclass
class PlaybackStatusChangedEvent(Event):
    play_status: PlayStatus

    @classmethod
    def from_bytes(cls, pdu: bytes) -> PlaybackStatusChangedEvent:
        return cls(play_status=PlayStatus(pdu[1]))

    def __init__(self, play_status: PlayStatus) -> None:
        super().__init__(EventId.PLAYBACK_STATUS_CHANGED)
        self.play_status = play_status

    def __bytes__(self) -> bytes:
        return bytes([self.event_id]) + bytes([self.play_status])


# -----------------------------------------------------------------------------
@dataclass
class PlaybackPositionChangedEvent(Event):
    playback_position: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> PlaybackPositionChangedEvent:
        return cls(playback_position=struct.unpack_from(">I", pdu, 1)[0])

    def __init__(self, playback_position: int) -> None:
        super().__init__(EventId.PLAYBACK_POS_CHANGED)
        self.playback_position = playback_position

    def __bytes__(self) -> bytes:
        return bytes([self.event_id]) + struct.pack(">I", self.playback_position)


# -----------------------------------------------------------------------------
@dataclass
class TrackChangedEvent(Event):
    identifier: bytes

    @classmethod
    def from_bytes(cls, pdu: bytes) -> TrackChangedEvent:
        return cls(identifier=pdu[1:])

    def __init__(self, identifier: bytes) -> None:
        super().__init__(EventId.TRACK_CHANGED)
        self.identifier = identifier

    def __bytes__(self) -> bytes:
        return bytes([self.event_id]) + self.identifier


# -----------------------------------------------------------------------------
@dataclass
class PlayerApplicationSettingChangedEvent(Event):
    @dataclass
    class Setting:
        attribute_id: ApplicationSetting.AttributeId
        value_id: OpenIntEnum

    player_application_settings: List[Setting]

    @classmethod
    def from_bytes(cls, pdu: bytes) -> PlayerApplicationSettingChangedEvent:
        def setting(attribute_id_int: int, value_id_int: int):
            attribute_id = ApplicationSetting.AttributeId(attribute_id_int)
            value_id: OpenIntEnum
            if attribute_id == ApplicationSetting.AttributeId.EQUALIZER_ON_OFF:
                value_id = ApplicationSetting.EqualizerOnOffStatus(value_id_int)
            elif attribute_id == ApplicationSetting.AttributeId.REPEAT_MODE:
                value_id = ApplicationSetting.RepeatModeStatus(value_id_int)
            elif attribute_id == ApplicationSetting.AttributeId.SHUFFLE_ON_OFF:
                value_id = ApplicationSetting.ShuffleOnOffStatus(value_id_int)
            elif attribute_id == ApplicationSetting.AttributeId.SCAN_ON_OFF:
                value_id = ApplicationSetting.ScanOnOffStatus(value_id_int)
            else:
                value_id = ApplicationSetting.GenericValue(value_id_int)

            return cls.Setting(attribute_id, value_id)

        settings = [
            setting(pdu[2 + (i * 2)], pdu[2 + (i * 2) + 1]) for i in range(pdu[1])
        ]
        return cls(player_application_settings=settings)

    def __init__(self, player_application_settings: Sequence[Setting]) -> None:
        super().__init__(EventId.PLAYER_APPLICATION_SETTING_CHANGED)
        self.player_application_settings = list(player_application_settings)

    def __bytes__(self) -> bytes:
        return (
            bytes([self.event_id])
            + bytes([len(self.player_application_settings)])
            + b''.join(
                [
                    bytes([setting.attribute_id, setting.value_id])
                    for setting in self.player_application_settings
                ]
            )
        )


# -----------------------------------------------------------------------------
@dataclass
class NowPlayingContentChangedEvent(Event):
    @classmethod
    def from_bytes(cls, pdu: bytes) -> NowPlayingContentChangedEvent:
        return cls()

    def __init__(self) -> None:
        super().__init__(EventId.NOW_PLAYING_CONTENT_CHANGED)


# -----------------------------------------------------------------------------
@dataclass
class AvailablePlayersChangedEvent(Event):
    @classmethod
    def from_bytes(cls, pdu: bytes) -> AvailablePlayersChangedEvent:
        return cls()

    def __init__(self) -> None:
        super().__init__(EventId.AVAILABLE_PLAYERS_CHANGED)


# -----------------------------------------------------------------------------
@dataclass
class AddressedPlayerChangedEvent(Event):
    @dataclass
    class Player:
        player_id: int
        uid_counter: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> AddressedPlayerChangedEvent:
        player_id, uid_counter = struct.unpack_from("<HH", pdu, 1)
        return cls(cls.Player(player_id, uid_counter))

    def __init__(self, player: Player) -> None:
        super().__init__(EventId.ADDRESSED_PLAYER_CHANGED)
        self.player = player

    def __bytes__(self) -> bytes:
        return bytes([self.event_id]) + struct.pack(
            ">HH", self.player.player_id, self.player.uid_counter
        )


# -----------------------------------------------------------------------------
@dataclass
class UidsChangedEvent(Event):
    uid_counter: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> UidsChangedEvent:
        return cls(uid_counter=struct.unpack_from(">H", pdu, 1)[0])

    def __init__(self, uid_counter: int) -> None:
        super().__init__(EventId.UIDS_CHANGED)
        self.uid_counter = uid_counter

    def __bytes__(self) -> bytes:
        return bytes([self.event_id]) + struct.pack(">H", self.uid_counter)


# -----------------------------------------------------------------------------
@dataclass
class VolumeChangedEvent(Event):
    volume: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> VolumeChangedEvent:
        return cls(volume=pdu[1])

    def __init__(self, volume: int) -> None:
        super().__init__(EventId.VOLUME_CHANGED)
        self.volume = volume

    def __bytes__(self) -> bytes:
        return bytes([self.event_id]) + bytes([self.volume])


# -----------------------------------------------------------------------------
EVENT_SUBCLASSES: Dict[EventId, Type[Event]] = {
    EventId.PLAYBACK_STATUS_CHANGED: PlaybackStatusChangedEvent,
    EventId.PLAYBACK_POS_CHANGED: PlaybackPositionChangedEvent,
    EventId.TRACK_CHANGED: TrackChangedEvent,
    EventId.PLAYER_APPLICATION_SETTING_CHANGED: PlayerApplicationSettingChangedEvent,
    EventId.NOW_PLAYING_CONTENT_CHANGED: NowPlayingContentChangedEvent,
    EventId.AVAILABLE_PLAYERS_CHANGED: AvailablePlayersChangedEvent,
    EventId.ADDRESSED_PLAYER_CHANGED: AddressedPlayerChangedEvent,
    EventId.UIDS_CHANGED: UidsChangedEvent,
    EventId.VOLUME_CHANGED: VolumeChangedEvent,
}


# -----------------------------------------------------------------------------
class Delegate:
    """
    Base class for AVRCP delegates.

    All the methods are async, even if they don't always need to be, so that
    delegates that do need to wait for an async result may do so.
    """

    class Error(Exception):
        """The delegate method failed, with a specified status code."""

        def __init__(self, status_code: Protocol.StatusCode) -> None:
            self.status_code = status_code

    supported_events: List[EventId]
    volume: int

    def __init__(self, supported_events: Iterable[EventId] = ()) -> None:
        self.supported_events = list(supported_events)
        self.volume = 0

    async def get_supported_events(self) -> List[EventId]:
        return self.supported_events

    async def set_absolute_volume(self, volume: int) -> None:
        """
        Set the absolute volume.

        Returns: the effective volume that was set.
        """
        logger.debug(f"@@@ set_absolute_volume: volume={volume}")
        self.volume = volume

    async def get_absolute_volume(self) -> int:
        return self.volume

    # TODO add other delegate methods


# -----------------------------------------------------------------------------
class Protocol(pyee.EventEmitter):
    """AVRCP Controller and Target protocol."""

    class PacketType(enum.IntEnum):
        SINGLE = 0b00
        START = 0b01
        CONTINUE = 0b10
        END = 0b11

    class PduId(OpenIntEnum):
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
        GET_TOTAL_NUMBER_OF_ITEMS = 0x75

    class StatusCode(OpenIntEnum):
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
    receive_command_state: Optional[ReceiveCommandState]
    response_pdu_assembler: PduAssembler
    receive_response_state: Optional[ReceiveResponseState]
    avctp_protocol: Optional[avctp.Protocol]
    free_commands: asyncio.Queue
    pending_commands: Dict[int, PendingCommand]  # Pending commands, by label
    notification_listeners: Dict[EventId, NotificationListener]

    @staticmethod
    def _check_vendor_dependent_frame(
        frame: Union[avc.VendorDependentCommandFrame, avc.VendorDependentResponseFrame]
    ) -> bool:
        if frame.company_id != AVRCP_BLUETOOTH_SIG_COMPANY_ID:
            logger.debug("unsupported company id, ignoring")
            return False

        if frame.subunit_type != avc.Frame.SubunitType.PANEL or frame.subunit_id != 0:
            logger.debug("unsupported subunit")
            return False

        return True

    def __init__(self, delegate: Optional[Delegate] = None) -> None:
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
        device.register_l2cap_server(avctp.AVCTP_PSM, self._on_avctp_connection)

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
        response_context: ResponseContext, expected_type: Type[_R]
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
        async def call():
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
                    Protocol.StatusCode.INTERNAL_ERROR,
                )

        utils.AsyncRunner.spawn(call())

    async def get_supported_events(self) -> List[EventId]:
        """Get the list of events supported by the connected peer."""
        response_context = await self.send_avrcp_command(
            avc.CommandFrame.CommandType.STATUS,
            GetCapabilitiesCommand(
                GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED
            ),
        )
        response = self._check_response(response_context, GetCapabilitiesResponse)
        return cast(List[EventId], response.capabilities)

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
    ) -> List[MediaAttribute]:
        """Get element attributes from the connected peer."""
        response_context = await self.send_avrcp_command(
            avc.CommandFrame.CommandType.STATUS,
            GetElementAttributesCommand(element_identifier, attribute_ids),
        )
        response = self._check_response(response_context, GetElementAttributesResponse)
        return response.attributes

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
    ) -> AsyncIterator[bytes]:
        """Monitor Track changes from the connected peer."""
        async for event in self.monitor_events(EventId.TRACK_CHANGED, 0):
            if not isinstance(event, TrackChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield event.identifier

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
    ) -> AsyncIterator[List[PlayerApplicationSettingChangedEvent.Setting]]:
        """Monitor Player Application Setting changes from the connected peer."""
        async for event in self.monitor_events(
            EventId.PLAYER_APPLICATION_SETTING_CHANGED, 0
        ):
            if not isinstance(event, PlayerApplicationSettingChangedEvent):
                logger.warning("unexpected event class")
                continue
            yield event.player_application_settings

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

    def notify_track_changed(self, identifier: bytes) -> None:
        """Notify the connected peer of a Track change."""
        if len(identifier) != 8:
            raise ValueError("identifier must be 8 bytes")
        self.notify_event(TrackChangedEvent(identifier))

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
        l2cap_channel.on("open", lambda: self._on_avctp_channel_open(l2cap_channel))

        self.emit("connection")

    def _on_avctp_channel_open(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug("AVCTP channel open")
        if self.avctp_protocol is not None:
            # TODO: find a better strategy instead of just closing
            logger.warning("AVCTP protocol already active, closing connection")
            AsyncRunner.spawn(l2cap_channel.disconnect())
            return

        self.avctp_protocol = avctp.Protocol(l2cap_channel)
        self.avctp_protocol.register_command_handler(AVRCP_PID, self._on_avctp_command)
        self.avctp_protocol.register_response_handler(
            AVRCP_PID, self._on_avctp_response
        )
        l2cap_channel.on("close", self._on_avctp_channel_close)

        self.emit("start")

    def _on_avctp_channel_close(self) -> None:
        logger.debug("AVCTP channel closed")
        self.avctp_protocol = None

        self.emit("stop")

    def _on_avctp_command(
        self, transaction_label: int, command: avc.CommandFrame
    ) -> None:
        logger.debug(
            f"<<< AVCTP Command, transaction_label={transaction_label}: " f"{command}"
        )

        # Only the PANEL subunit type with subunit ID 0 is supported in this profile.
        if (
            command.subunit_type != avc.Frame.SubunitType.PANEL
            or command.subunit_id != 0
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
            # TODO: delegate
            response = avc.PassThroughResponseFrame(
                avc.ResponseFrame.ResponseCode.ACCEPTED,
                avc.Frame.SubunitType.PANEL,
                0,
                command.state_flag,
                command.operation_id,
                command.operation_data,
            )
            self.send_response(transaction_label, response)
            return

        # TODO handle other types
        self.send_not_implemented_response(transaction_label, command)

    def _on_avctp_response(
        self, transaction_label: int, response: Optional[avc.ResponseFrame]
    ) -> None:
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
            if pdu_id == self.PduId.GET_CAPABILITIES:
                self._on_get_capabilities_command(
                    transaction_label, GetCapabilitiesCommand.from_bytes(pdu)
                )
            elif pdu_id == self.PduId.SET_ABSOLUTE_VOLUME:
                self._on_set_absolute_volume_command(
                    transaction_label, SetAbsoluteVolumeCommand.from_bytes(pdu)
                )
            elif pdu_id == self.PduId.REGISTER_NOTIFICATION:
                self._on_register_notification_command(
                    transaction_label, RegisterNotificationCommand.from_bytes(pdu)
                )
            else:
                # Not supported.
                # TODO: check that this is the right way to respond in this case.
                logger.debug("unsupported PDU ID")
                self.send_rejected_avrcp_response(
                    transaction_label, pdu_id, self.StatusCode.INVALID_PARAMETER
                )
        else:
            logger.debug("unsupported command type")
            self.send_rejected_avrcp_response(
                transaction_label, pdu_id, self.StatusCode.INVALID_COMMAND
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
        response: Optional[Response] = None
        if response_code == avc.ResponseFrame.ResponseCode.REJECTED:
            response = RejectedResponse.from_bytes(pdu_id, pdu)
        elif response_code == avc.ResponseFrame.ResponseCode.NOT_IMPLEMENTED:
            response = NotImplementedResponse.from_bytes(pdu_id, pdu)
        elif response_code in (
            avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
            avc.ResponseFrame.ResponseCode.INTERIM,
            avc.ResponseFrame.ResponseCode.CHANGED,
            avc.ResponseFrame.ResponseCode.ACCEPTED,
        ):
            if pdu_id == self.PduId.GET_CAPABILITIES:
                response = GetCapabilitiesResponse.from_bytes(pdu)
            elif pdu_id == self.PduId.GET_PLAY_STATUS:
                response = GetPlayStatusResponse.from_bytes(pdu)
            elif pdu_id == self.PduId.GET_ELEMENT_ATTRIBUTES:
                response = GetElementAttributesResponse.from_bytes(pdu)
            elif pdu_id == self.PduId.SET_ABSOLUTE_VOLUME:
                response = SetAbsoluteVolumeResponse.from_bytes(pdu)
            elif pdu_id == self.PduId.REGISTER_NOTIFICATION:
                response = RegisterNotificationResponse.from_bytes(pdu)
            else:
                logger.debug("unexpected PDU ID")
                pending_command.response.set_exception(
                    ProtocolError(
                        error_code=None,
                        error_namespace="avrcp",
                        details="unexpected PDU ID",
                    )
                )
        else:
            logger.debug("unexpected response code")
            pending_command.response.set_exception(
                ProtocolError(
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
                avc.PassThroughFrame.StateFlag.PRESSED
                if pressed
                else avc.PassThroughFrame.StateFlag.RELEASED,
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
        pdu = (
            struct.pack(">BBH", command.pdu_id, 0, len(command.parameter))
            + command.parameter
        )
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
        pdu = (
            struct.pack(">BBH", response.pdu_id, 0, len(response.parameter))
            + response.parameter
        )
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
        self, transaction_label: int, pdu_id: Protocol.PduId, status_code: StatusCode
    ) -> None:
        self.send_avrcp_response(
            transaction_label,
            avc.ResponseFrame.ResponseCode.REJECTED,
            RejectedResponse(pdu_id, status_code),
        )

    def _on_get_capabilities_command(
        self, transaction_label: int, command: GetCapabilitiesCommand
    ) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        async def get_supported_events():
            if (
                command.capability_id
                != GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED
            ):
                raise Protocol.InvalidParameterError

            supported_events = await self.delegate.get_supported_events()
            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                GetCapabilitiesResponse(command.capability_id, supported_events),
            )

        self._delegate_command(transaction_label, command, get_supported_events())

    def _on_set_absolute_volume_command(
        self, transaction_label: int, command: SetAbsoluteVolumeCommand
    ) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        async def set_absolute_volume():
            await self.delegate.set_absolute_volume(command.volume)
            effective_volume = await self.delegate.get_absolute_volume()
            self.send_avrcp_response(
                transaction_label,
                avc.ResponseFrame.ResponseCode.IMPLEMENTED_OR_STABLE,
                SetAbsoluteVolumeResponse(effective_volume),
            )

        self._delegate_command(transaction_label, command, set_absolute_volume())

    def _on_register_notification_command(
        self, transaction_label: int, command: RegisterNotificationCommand
    ) -> None:
        logger.debug(f"<<< AVRCP command PDU: {command}")

        async def register_notification():
            # Check if the event is supported.
            supported_events = await self.delegate.get_supported_events()
            if command.event_id in supported_events:
                if command.event_id == EventId.VOLUME_CHANGED:
                    volume = await self.delegate.get_absolute_volume()
                    response = RegisterNotificationResponse(VolumeChangedEvent(volume))
                    self.send_avrcp_response(
                        transaction_label,
                        avc.ResponseFrame.ResponseCode.INTERIM,
                        response,
                    )
                    self._register_notification_listener(transaction_label, command)
                    return

                if command.event_id == EventId.PLAYBACK_STATUS_CHANGED:
                    # TODO: testing only, use delegate
                    response = RegisterNotificationResponse(
                        PlaybackStatusChangedEvent(play_status=PlayStatus.PLAYING)
                    )
                    self.send_avrcp_response(
                        transaction_label,
                        avc.ResponseFrame.ResponseCode.INTERIM,
                        response,
                    )
                    self._register_notification_listener(transaction_label, command)
                    return

        self._delegate_command(transaction_label, command, register_notification())
