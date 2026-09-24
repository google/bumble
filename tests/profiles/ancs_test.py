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
import datetime
import struct

import pytest

from bumble import att, gatt
from bumble import device as device_module
from bumble.profiles import ancs
from bumble.testing import test_utils

TIMEOUT = 1.0


# -----------------------------------------------------------------------------
def test_notification_serialization() -> None:
    notification = ancs.Notification(
        event_id=ancs.EventId.NOTIFICATION_ADDED,
        event_flags=ancs.EventFlags.IMPORTANT | ancs.EventFlags.POSITIVE_ACTION,
        category_id=ancs.CategoryId.SOCIAL,
        category_count=3,
        notification_uid=0x12345678,
    )
    raw = bytes(notification)
    assert raw == bytes([0, 0x0A, 4, 3, 0x78, 0x56, 0x34, 0x12])
    parsed = ancs.Notification.from_bytes(raw)
    assert parsed == notification


# -----------------------------------------------------------------------------
def test_command_error_str() -> None:
    err = ancs.CommandError(ancs.ErrorCode.INVALID_PARAMETER)
    assert err.error_code == ancs.ErrorCode.INVALID_PARAMETER
    assert str(err) == "CommandError(error_code=INVALID_PARAMETER)"


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_for_peer_no_service() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    peer = device_module.Peer(devices.connections[1])
    client = await ancs.AncsClient.for_peer(peer)
    assert client is None


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_client_not_started() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    service = ancs.Ancs()
    devices[0].add_service(service)

    peer = device_module.Peer(devices.connections[1])
    client = await ancs.AncsClient.for_peer(peer)
    assert client is not None

    with pytest.raises(RuntimeError, match="client not started"):
        await client.get_notification_attributes(
            1, [ancs.NotificationAttributeId.APP_IDENTIFIER]
        )

    with pytest.raises(RuntimeError, match="client not started"):
        await client.get_app_attributes(
            "com.example.app", [ancs.AppAttributeId.DISPLAY_NAME]
        )

    with pytest.raises(RuntimeError, match="client not started"):
        await client.perform_action(1, ancs.ActionId.POSITIVE)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_notification_source() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    service = ancs.Ancs()
    devices[0].add_service(service)

    peer = device_module.Peer(devices.connections[1])
    client = await ancs.AncsClient.for_peer(peer)
    assert client is not None

    await client.start()
    notifications = asyncio.Queue[ancs.Notification]()
    client.on(ancs.AncsClient.EVENT_NOTIFICATION, notifications.put_nowait)

    expected = ancs.Notification(
        event_id=ancs.EventId.NOTIFICATION_MODIFIED,
        event_flags=ancs.EventFlags.SILENT,
        category_id=ancs.CategoryId.EMAIL,
        category_count=1,
        notification_uid=42,
    )
    await devices[0].notify_subscribers(
        service.notification_source_characteristic, bytes(expected)
    )

    received = await asyncio.wait_for(notifications.get(), TIMEOUT)
    assert received == expected

    await client.stop()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_notification_attributes() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    service = ancs.Ancs()
    devices[0].add_service(service)

    def on_control_point_write(_connection, value: bytes) -> None:
        assert value[0] == ancs.CommandId.GET_NOTIFICATION_ATTRIBUTES
        (uid,) = struct.unpack_from("<I", value, 1)
        assert uid == 99

        def make_attr(attr_id: int, text: str) -> bytes:
            encoded = text.encode("utf-8")
            return struct.pack("<BH", attr_id, len(encoded)) + encoded

        response = (
            struct.pack("<BI", ancs.CommandId.GET_NOTIFICATION_ATTRIBUTES, uid)
            + make_attr(ancs.NotificationAttributeId.APP_IDENTIFIER, "com.test.mail")
            + make_attr(ancs.NotificationAttributeId.TITLE, "Hello")
            + make_attr(ancs.NotificationAttributeId.SUBTITLE, "World")
            + make_attr(ancs.NotificationAttributeId.MESSAGE_SIZE, "128")
            + make_attr(ancs.NotificationAttributeId.DATE, "20260924T123805")
        )

        async def send_chunks() -> None:
            # Fragment into small chunks (<= 20 bytes ATT MTU payload) to exercise accumulator boundaries
            await devices[0].notify_subscribers(
                service.data_source_characteristic, response[:3]
            )
            await devices[0].notify_subscribers(
                service.data_source_characteristic, response[3:7]
            )
            for offset in range(7, len(response), 15):
                await devices[0].notify_subscribers(
                    service.data_source_characteristic,
                    response[offset : offset + 15],
                )

        asyncio.create_task(send_chunks())

    service.control_point_characteristic.value = gatt.CharacteristicValue(
        write=on_control_point_write
    )

    peer = device_module.Peer(devices.connections[1])
    client = await ancs.AncsClient.for_peer(peer)
    assert client is not None
    await client.start()

    with pytest.raises(
        ValueError, match="this attribute does not allow specifying a max length"
    ):
        await client.get_notification_attributes(
            99, [(ancs.NotificationAttributeId.APP_IDENTIFIER, 10)]
        )

    attrs = await asyncio.wait_for(
        client.get_notification_attributes(
            99,
            [
                ancs.NotificationAttributeId.APP_IDENTIFIER,
                ancs.NotificationAttributeId.TITLE,
                (ancs.NotificationAttributeId.SUBTITLE, 32),
                ancs.NotificationAttributeId.MESSAGE_SIZE,
                ancs.NotificationAttributeId.DATE,
            ],
        ),
        TIMEOUT,
    )

    assert attrs == [
        ancs.NotificationAttribute(
            ancs.NotificationAttributeId.APP_IDENTIFIER, "com.test.mail"
        ),
        ancs.NotificationAttribute(ancs.NotificationAttributeId.TITLE, "Hello"),
        ancs.NotificationAttribute(ancs.NotificationAttributeId.SUBTITLE, "World"),
        ancs.NotificationAttribute(ancs.NotificationAttributeId.MESSAGE_SIZE, 128),
        ancs.NotificationAttribute(
            ancs.NotificationAttributeId.DATE,
            datetime.datetime(2026, 9, 24, 12, 38, 5),
        ),
    ]


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_app_attributes() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    service = ancs.Ancs()
    devices[0].add_service(service)

    def on_control_point_write(_connection, value: bytes) -> None:
        assert value == (
            bytes([ancs.CommandId.GET_APP_ATTRIBUTES])
            + b"com.test.mail\0"
            + bytes([ancs.AppAttributeId.DISPLAY_NAME])
        )
        display_name = b"Test Mail"
        response = (
            bytes([ancs.CommandId.GET_APP_ATTRIBUTES])
            + b"com.test.mail\0"
            + struct.pack("<BH", ancs.AppAttributeId.DISPLAY_NAME, len(display_name))
            + display_name
        )

        async def send_chunks() -> None:
            # First chunk without null terminator, then partial attribute, then rest
            await devices[0].notify_subscribers(
                service.data_source_characteristic, response[:6]
            )
            await devices[0].notify_subscribers(
                service.data_source_characteristic, response[6:18]
            )
            await devices[0].notify_subscribers(
                service.data_source_characteristic, response[18:]
            )

        asyncio.create_task(send_chunks())

    service.control_point_characteristic.value = gatt.CharacteristicValue(
        write=on_control_point_write
    )

    peer = device_module.Peer(devices.connections[1])
    client = await ancs.AncsClient.for_peer(peer)
    assert client is not None
    await client.start()

    attrs = await asyncio.wait_for(
        client.get_app_attributes("com.test.mail", [ancs.AppAttributeId.DISPLAY_NAME]),
        TIMEOUT,
    )
    assert attrs == [ancs.AppAttribute(ancs.AppAttributeId.DISPLAY_NAME, "Test Mail")]


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_perform_actions_and_command_error() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    service = ancs.Ancs()
    devices[0].add_service(service)

    written_commands: list[bytes] = []
    should_fail = False

    def on_control_point_write(_connection, value: bytes) -> None:
        if should_fail:
            raise att.ATT_Error(ancs.ErrorCode.ACTION_FAILED)
        written_commands.append(value)

    service.control_point_characteristic.value = gatt.CharacteristicValue(
        write=on_control_point_write
    )

    peer = device_module.Peer(devices.connections[1])
    client = await ancs.AncsClient.for_peer(peer)
    assert client is not None
    await client.start()

    await client.perform_positive_action(10)
    await client.perform_negative_action(20)
    assert written_commands == [
        struct.pack(
            "<BIB",
            ancs.CommandId.PERFORM_NOTIFICATION_ACTION,
            10,
            ancs.ActionId.POSITIVE,
        ),
        struct.pack(
            "<BIB",
            ancs.CommandId.PERFORM_NOTIFICATION_ACTION,
            20,
            ancs.ActionId.NEGATIVE,
        ),
    ]

    should_fail = True
    with pytest.raises(ancs.CommandError) as exc_info:
        await client.perform_positive_action(10)
    assert exc_info.value.error_code == ancs.ErrorCode.ACTION_FAILED


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_protocol_errors_and_edge_cases() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    service = ancs.Ancs()
    devices[0].add_service(service)

    peer = device_module.Peer(devices.connections[1])
    client = await ancs.AncsClient.for_peer(peer)
    assert client is not None
    await client.start()

    # 1. Unexpected data when no response is pending -> discarded
    client._on_data(b"\x00\x01\x02\x03\x04")

    # 2. Empty data when response is pending -> ignored
    client._response = asyncio.get_running_loop().create_future()
    client._on_data(b"")
    client._reset_response()
    client._response = None

    # 3. Wrong command ID in response -> ProtocolError
    def write_wrong_command_id(_connection, _value: bytes) -> None:
        asyncio.create_task(
            devices[0].notify_subscribers(
                service.data_source_characteristic,
                struct.pack("<BI", ancs.CommandId.GET_APP_ATTRIBUTES, 1),
            )
        )

    service.control_point_characteristic.value = gatt.CharacteristicValue(
        write=write_wrong_command_id
    )
    with pytest.raises(ancs.ProtocolError):
        await client.get_notification_attributes(
            1, [ancs.NotificationAttributeId.TITLE]
        )

    # 4. Wrong notification UID in response -> ProtocolError
    def write_wrong_uid(_connection, _value: bytes) -> None:
        asyncio.create_task(
            devices[0].notify_subscribers(
                service.data_source_characteristic,
                struct.pack("<BI", ancs.CommandId.GET_NOTIFICATION_ATTRIBUTES, 999),
            )
        )

    service.control_point_characteristic.value = gatt.CharacteristicValue(
        write=write_wrong_uid
    )
    with pytest.raises(ancs.ProtocolError):
        await client.get_notification_attributes(
            1, [ancs.NotificationAttributeId.TITLE]
        )

    # 5. Wrong app identifier in response -> ProtocolError
    def write_wrong_app_id(_connection, _value: bytes) -> None:
        asyncio.create_task(
            devices[0].notify_subscribers(
                service.data_source_characteristic,
                bytes([ancs.CommandId.GET_APP_ATTRIBUTES]) + b"wrong.app\0",
            )
        )

    service.control_point_characteristic.value = gatt.CharacteristicValue(
        write=write_wrong_app_id
    )
    with pytest.raises(ancs.ProtocolError):
        await client.get_app_attributes(
            "expected.app", [ancs.AppAttributeId.DISPLAY_NAME]
        )

    # 6. Unknown command_id matching _expected_response_command_id
    client._response = asyncio.get_running_loop().create_future()
    client._expected_response_command_id = ancs.CommandId.PERFORM_NOTIFICATION_ACTION
    client._on_data(struct.pack("<BI", ancs.CommandId.PERFORM_NOTIFICATION_ACTION, 0))
    assert not client._response.done()
