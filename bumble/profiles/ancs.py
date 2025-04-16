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
Apple Notification Center Service (ANCS).
"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import asyncio
import dataclasses
import datetime
import enum
import logging
import struct
from typing import Optional, Sequence, Union


from bumble.att import ATT_Error
from bumble.device import Peer
from bumble.gatt import (
    Characteristic,
    GATT_ANCS_SERVICE,
    GATT_ANCS_NOTIFICATION_SOURCE_CHARACTERISTIC,
    GATT_ANCS_CONTROL_POINT_CHARACTERISTIC,
    GATT_ANCS_DATA_SOURCE_CHARACTERISTIC,
    TemplateService,
)
from bumble.gatt_client import CharacteristicProxy, ProfileServiceProxy, ServiceProxy
from bumble.gatt_adapters import SerializableCharacteristicProxyAdapter
from bumble import utils


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
_DEFAULT_ATTRIBUTE_MAX_LENGTH = 65535


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Protocol
# -----------------------------------------------------------------------------
class ActionId(utils.OpenIntEnum):
    POSITIVE = 0
    NEGATIVE = 1


class AppAttributeId(utils.OpenIntEnum):
    DISPLAY_NAME = 0


class CategoryId(utils.OpenIntEnum):
    OTHER = 0
    INCOMING_CALL = 1
    MISSED_CALL = 2
    VOICEMAIL = 3
    SOCIAL = 4
    SCHEDULE = 5
    EMAIL = 6
    NEWS = 7
    HEALTH_AND_FITNESS = 8
    BUSINESS_AND_FINANCE = 9
    LOCATION = 10
    ENTERTAINMENT = 11


class CommandId(utils.OpenIntEnum):
    GET_NOTIFICATION_ATTRIBUTES = 0
    GET_APP_ATTRIBUTES = 1
    PERFORM_NOTIFICATION_ACTION = 2


class EventId(utils.OpenIntEnum):
    NOTIFICATION_ADDED = 0
    NOTIFICATION_MODIFIED = 1
    NOTIFICATION_REMOVED = 2


class EventFlags(enum.IntFlag):
    SILENT = 1 << 0
    IMPORTANT = 1 << 1
    PRE_EXISTING = 1 << 2
    POSITIVE_ACTION = 1 << 3
    NEGATIVE_ACTION = 1 << 4


class NotificationAttributeId(utils.OpenIntEnum):
    APP_IDENTIFIER = 0
    TITLE = 1
    SUBTITLE = 2
    MESSAGE = 3
    MESSAGE_SIZE = 4
    DATE = 5
    POSITIVE_ACTION_LABEL = 6
    NEGATIVE_ACTION_LABEL = 7


@dataclasses.dataclass
class NotificationAttribute:
    attribute_id: NotificationAttributeId
    value: Union[str, int, datetime.datetime]


@dataclasses.dataclass
class AppAttribute:
    attribute_id: AppAttributeId
    value: str


@dataclasses.dataclass
class Notification:
    event_id: EventId
    event_flags: EventFlags
    category_id: CategoryId
    category_count: int
    notification_uid: int

    @classmethod
    def from_bytes(cls, data: bytes) -> Notification:
        return cls(
            event_id=EventId(data[0]),
            event_flags=EventFlags(data[1]),
            category_id=CategoryId(data[2]),
            category_count=data[3],
            notification_uid=int.from_bytes(data[4:8], 'little'),
        )

    def __bytes__(self) -> bytes:
        return struct.pack(
            "<BBBBI",
            self.event_id,
            self.event_flags,
            self.category_id,
            self.category_count,
            self.notification_uid,
        )


class ErrorCode(utils.OpenIntEnum):
    UNKNOWN_COMMAND = 0xA0
    INVALID_COMMAND = 0xA1
    INVALID_PARAMETER = 0xA2
    ACTION_FAILED = 0xA3


class ProtocolError(Exception):
    pass


class CommandError(Exception):
    def __init__(self, error_code: ErrorCode) -> None:
        self.error_code = error_code

    def __str__(self) -> str:
        return f"CommandError(error_code={self.error_code.name})"


# -----------------------------------------------------------------------------
# GATT Server-side
# -----------------------------------------------------------------------------
class Ancs(TemplateService):
    UUID = GATT_ANCS_SERVICE

    notification_source_characteristic: Characteristic
    data_source_characteristic: Characteristic
    control_point_characteristic: Characteristic

    def __init__(self) -> None:
        # TODO not the final implementation
        self.notification_source_characteristic = Characteristic(
            GATT_ANCS_NOTIFICATION_SOURCE_CHARACTERISTIC,
            Characteristic.Properties.NOTIFY,
            Characteristic.Permissions.READABLE,
        )

        # TODO not the final implementation
        self.data_source_characteristic = Characteristic(
            GATT_ANCS_DATA_SOURCE_CHARACTERISTIC,
            Characteristic.Properties.NOTIFY,
            Characteristic.Permissions.READABLE,
        )

        # TODO not the final implementation
        self.control_point_characteristic = Characteristic(
            GATT_ANCS_CONTROL_POINT_CHARACTERISTIC,
            Characteristic.Properties.WRITE,
            Characteristic.Permissions.WRITEABLE,
        )

        super().__init__(
            [
                self.notification_source_characteristic,
                self.data_source_characteristic,
                self.control_point_characteristic,
            ]
        )


# -----------------------------------------------------------------------------
# GATT Client-side
# -----------------------------------------------------------------------------
class AncsProxy(ProfileServiceProxy):
    SERVICE_CLASS = Ancs

    notification_source: CharacteristicProxy[Notification]
    data_source: CharacteristicProxy
    control_point: CharacteristicProxy[bytes]

    def __init__(self, service_proxy: ServiceProxy):
        self.notification_source = SerializableCharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                GATT_ANCS_NOTIFICATION_SOURCE_CHARACTERISTIC
            ),
            Notification,
        )

        self.data_source = service_proxy.get_required_characteristic_by_uuid(
            GATT_ANCS_DATA_SOURCE_CHARACTERISTIC
        )

        self.control_point = service_proxy.get_required_characteristic_by_uuid(
            GATT_ANCS_CONTROL_POINT_CHARACTERISTIC
        )


class AncsClient(utils.EventEmitter):
    _expected_response_command_id: Optional[CommandId]
    _expected_response_notification_uid: Optional[int]
    _expected_response_app_identifier: Optional[str]
    _expected_app_identifier: Optional[str]
    _expected_response_tuples: int
    _response_accumulator: bytes

    def __init__(self, ancs_proxy: AncsProxy) -> None:
        super().__init__()
        self._ancs_proxy = ancs_proxy
        self._command_semaphore = asyncio.Semaphore()
        self._response: Optional[asyncio.Future] = None
        self._reset_response()
        self._started = False

    @classmethod
    async def for_peer(cls, peer: Peer) -> Optional[AncsClient]:
        ancs_proxy = await peer.discover_service_and_create_proxy(AncsProxy)
        if ancs_proxy is None:
            return None
        return cls(ancs_proxy)

    async def start(self) -> None:
        await self._ancs_proxy.notification_source.subscribe(self._on_notification)
        await self._ancs_proxy.data_source.subscribe(self._on_data)
        self._started = True

    async def stop(self) -> None:
        await self._ancs_proxy.notification_source.unsubscribe(self._on_notification)
        await self._ancs_proxy.data_source.unsubscribe(self._on_data)
        self._started = False

    def _reset_response(self) -> None:
        self._expected_response_command_id = None
        self._expected_response_notification_uid = None
        self._expected_app_identifier = None
        self._expected_response_tuples = 0
        self._response_accumulator = b""

    def _on_notification(self, notification: Notification) -> None:
        logger.debug(f"ANCS NOTIFICATION: {notification}")
        self.emit("notification", notification)

    def _on_data(self, data: bytes) -> None:
        logger.debug(f"ANCS DATA: {data.hex()}")

        if not self._response:
            logger.warning("received unexpected data, discarding")
            return

        self._response_accumulator += data

        # Try to parse the accumulated data until we have all we need.
        if not self._response_accumulator:
            logger.warning("empty data from data source")
            return

        command_id = self._response_accumulator[0]
        if command_id != self._expected_response_command_id:
            logger.warning(
                "unexpected response command id: "
                f"expected {self._expected_response_command_id} "
                f"but got {command_id}"
            )
            self._reset_response()
            if not self._response.done():
                self._response.set_exception(ProtocolError())

        if len(self._response_accumulator) < 5:
            # Not enough data yet.
            return

        attributes: list[Union[NotificationAttribute, AppAttribute]] = []

        if command_id == CommandId.GET_NOTIFICATION_ATTRIBUTES:
            (notification_uid,) = struct.unpack_from(
                "<I", self._response_accumulator, 1
            )
            if notification_uid != self._expected_response_notification_uid:
                logger.warning(
                    "unexpected response notification uid: "
                    f"expected {self._expected_response_notification_uid} "
                    f"but got {notification_uid}"
                )
                self._reset_response()
                if not self._response.done():
                    self._response.set_exception(ProtocolError())

            attribute_data = self._response_accumulator[5:]
            while len(attribute_data) >= 3:
                attribute_id, attribute_data_length = struct.unpack_from(
                    "<BH", attribute_data, 0
                )
                if len(attribute_data) < 3 + attribute_data_length:
                    return
                str_value = attribute_data[3 : 3 + attribute_data_length].decode(
                    "utf-8"
                )
                value: Union[str, int, datetime.datetime]
                if attribute_id == NotificationAttributeId.MESSAGE_SIZE:
                    value = int(str_value)
                elif attribute_id == NotificationAttributeId.DATE:
                    year = int(str_value[:4])
                    month = int(str_value[4:6])
                    day = int(str_value[6:8])
                    hour = int(str_value[9:11])
                    minute = int(str_value[11:13])
                    second = int(str_value[13:15])
                    value = datetime.datetime(year, month, day, hour, minute, second)
                else:
                    value = str_value
                attributes.append(
                    NotificationAttribute(NotificationAttributeId(attribute_id), value)
                )
                attribute_data = attribute_data[3 + attribute_data_length :]
        elif command_id == CommandId.GET_APP_ATTRIBUTES:
            if 0 not in self._response_accumulator[1:]:
                # No null-terminated string yet.
                return

            app_identifier_length = self._response_accumulator.find(0, 1) - 1
            app_identifier = self._response_accumulator[
                1 : 1 + app_identifier_length
            ].decode("utf-8")
            if app_identifier != self._expected_response_app_identifier:
                logger.warning(
                    "unexpected response app identifier: "
                    f"expected {self._expected_response_app_identifier} "
                    f"but got {app_identifier}"
                )
                self._reset_response()
                if not self._response.done():
                    self._response.set_exception(ProtocolError())

            attribute_data = self._response_accumulator[1 + app_identifier_length + 1 :]
            while len(attribute_data) >= 3:
                attribute_id, attribute_data_length = struct.unpack_from(
                    "<BH", attribute_data, 0
                )
                if len(attribute_data) < 3 + attribute_data_length:
                    return
                attributes.append(
                    AppAttribute(
                        AppAttributeId(attribute_id),
                        attribute_data[3 : 3 + attribute_data_length].decode("utf-8"),
                    )
                )
                attribute_data = attribute_data[3 + attribute_data_length :]
        else:
            logger.warning(f"unexpected response command id {command_id}")
            return

        if len(attributes) < self._expected_response_tuples:
            # We have not received all the tuples yet.
            return

        if not self._response.done():
            self._response.set_result(attributes)

    async def _send_command(self, command: bytes) -> None:
        try:
            await self._ancs_proxy.control_point.write_value(
                command, with_response=True
            )
        except ATT_Error as error:
            raise CommandError(error_code=ErrorCode(error.error_code)) from error

    async def get_notification_attributes(
        self,
        notification_uid: int,
        attributes: Sequence[
            Union[NotificationAttributeId, tuple[NotificationAttributeId, int]]
        ],
    ) -> list[NotificationAttribute]:
        if not self._started:
            raise RuntimeError("client not started")

        command = struct.pack(
            "<BI", CommandId.GET_NOTIFICATION_ATTRIBUTES, notification_uid
        )
        for attribute in attributes:
            attribute_max_length = 0
            if isinstance(attribute, tuple):
                attribute_id, attribute_max_length = attribute
                if attribute_id not in (
                    NotificationAttributeId.TITLE,
                    NotificationAttributeId.SUBTITLE,
                    NotificationAttributeId.MESSAGE,
                ):
                    raise ValueError(
                        "this attribute does not allow specifying a max length"
                    )
            else:
                attribute_id = attribute
                if attribute_id in (
                    NotificationAttributeId.TITLE,
                    NotificationAttributeId.SUBTITLE,
                    NotificationAttributeId.MESSAGE,
                ):
                    attribute_max_length = _DEFAULT_ATTRIBUTE_MAX_LENGTH

            if attribute_max_length:
                command += struct.pack("<BH", attribute_id, attribute_max_length)
            else:
                command += struct.pack("B", attribute_id)

        try:
            async with self._command_semaphore:
                self._expected_response_notification_uid = notification_uid
                self._expected_response_tuples = len(attributes)
                self._expected_response_command_id = (
                    CommandId.GET_NOTIFICATION_ATTRIBUTES
                )
                self._response = asyncio.Future()

                # Send the command.
                await self._send_command(command)

                # Wait for the response.
                return await self._response
        finally:
            self._reset_response()

    async def get_app_attributes(
        self, app_identifier: str, attributes: Sequence[AppAttributeId]
    ) -> list[AppAttribute]:
        if not self._started:
            raise RuntimeError("client not started")

        command = (
            bytes([CommandId.GET_APP_ATTRIBUTES])
            + app_identifier.encode("utf-8")
            + b"\0"
        )
        for attribute_id in attributes:
            command += struct.pack("B", attribute_id)

        try:
            async with self._command_semaphore:
                self._expected_response_app_identifier = app_identifier
                self._expected_response_tuples = len(attributes)
                self._expected_response_command_id = CommandId.GET_APP_ATTRIBUTES
                self._response = asyncio.Future()

                # Send the command.
                await self._send_command(command)

                # Wait for the response.
                return await self._response
        finally:
            self._reset_response()

    async def perform_action(self, notification_uid: int, action: ActionId) -> None:
        if not self._started:
            raise RuntimeError("client not started")

        command = struct.pack(
            "<BIB", CommandId.PERFORM_NOTIFICATION_ACTION, notification_uid, action
        )

        async with self._command_semaphore:
            await self._send_command(command)

    async def perform_positive_action(self, notification_uid: int) -> None:
        return await self.perform_action(notification_uid, ActionId.POSITIVE)

    async def perform_negative_action(self, notification_uid: int) -> None:
        return await self.perform_action(notification_uid, ActionId.NEGATIVE)
