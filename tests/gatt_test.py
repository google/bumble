# Copyright 2021-2022 Google LLC
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
import logging
import os
import struct
from typing import Any
from unittest.mock import ANY, AsyncMock, Mock

import pytest
from typing_extensions import Self

from bumble import gatt_client, l2cap
from bumble.att import (
    ATT_ATTRIBUTE_NOT_FOUND_ERROR,
    ATT_PDU,
    ATT_Error,
    ATT_Error_Response,
    ATT_Read_By_Group_Type_Request,
    Attribute,
    ErrorCode,
    Opcode,
)
from bumble.core import UUID
from bumble.device import Device, Peer
from bumble.gatt import (
    GATT_BATTERY_LEVEL_CHARACTERISTIC,
    GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
    Characteristic,
    CharacteristicValue,
    Descriptor,
    Service,
)
from bumble.gatt_adapters import (
    CharacteristicProxyAdapter,
    DelegatedCharacteristicAdapter,
    DelegatedCharacteristicProxyAdapter,
    EnumCharacteristicAdapter,
    EnumCharacteristicProxyAdapter,
    MappedCharacteristicAdapter,
    MappedCharacteristicProxyAdapter,
    PackedCharacteristicAdapter,
    PackedCharacteristicProxyAdapter,
    SerializableCharacteristicAdapter,
    SerializableCharacteristicProxyAdapter,
    UTF8CharacteristicAdapter,
    UTF8CharacteristicProxyAdapter,
)

from .test_utils import Devices, TwoDevices, async_barrier


# -----------------------------------------------------------------------------
def basic_check(x):
    pdu = bytes(x)
    parsed = ATT_PDU.from_bytes(pdu)
    x_str = str(x)
    parsed_str = str(parsed)
    assert x_str == parsed_str


# -----------------------------------------------------------------------------
def test_UUID():
    u = UUID.from_16_bits(0x7788)
    assert str(u) == 'UUID-16:7788'
    u = UUID.from_32_bits(0x11223344)
    assert str(u) == 'UUID-32:11223344'
    u = UUID('61A3512C-09BE-4DDC-A6A6-0B03667AAFC6')
    assert str(u) == '61A3512C-09BE-4DDC-A6A6-0B03667AAFC6'
    v = UUID(str(u))
    assert str(v) == '61A3512C-09BE-4DDC-A6A6-0B03667AAFC6'
    w = UUID.from_bytes(bytes(v))
    assert str(w) == '61A3512C-09BE-4DDC-A6A6-0B03667AAFC6'

    u1 = UUID.from_16_bits(0x1234)
    b1 = u1.to_bytes(force_128=True)
    u2 = UUID.from_bytes(b1)
    assert u1 == u2

    u3 = UUID.from_16_bits(0x180A)
    assert str(u3) == 'UUID-16:180A (Device Information)'


# -----------------------------------------------------------------------------
def test_ATT_Error_Response():
    pdu = ATT_Error_Response(
        request_opcode_in_error=Opcode.ATT_EXCHANGE_MTU_REQUEST,
        attribute_handle_in_error=0x0000,
        error_code=ATT_ATTRIBUTE_NOT_FOUND_ERROR,
    )
    basic_check(pdu)


# -----------------------------------------------------------------------------
def test_ATT_Read_By_Group_Type_Request():
    pdu = ATT_Read_By_Group_Type_Request(
        starting_handle=0x0001,
        ending_handle=0xFFFF,
        attribute_group_type=UUID.from_16_bits(0x2800),
    )
    basic_check(pdu)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_characteristic_encoding():
    class Foo(Characteristic):
        def encode_value(self, value):
            return bytes([value])

        def decode_value(self, value_bytes):
            return value_bytes[0]

    c = Foo(
        GATT_BATTERY_LEVEL_CHARACTERISTIC,
        Characteristic.Properties.READ,
        Characteristic.READABLE,
        123,
    )
    x = await c.read_value(Mock())
    assert x == bytes([123])
    await c.write_value(Mock(), bytes([122]))
    assert c.value == 122

    class FooProxy(gatt_client.CharacteristicProxy):
        def __init__(self, characteristic):
            super().__init__(
                characteristic.client,
                characteristic.handle,
                characteristic.end_group_handle,
                characteristic.uuid,
                characteristic.properties,
            )

        def encode_value(self, value):
            return bytes([value])

        def decode_value(self, value_bytes):
            return value_bytes[0]

    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    characteristic = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE
        | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([123]),
    )

    async def async_read(connection):
        return 0x05060708

    async_characteristic = PackedCharacteristicAdapter(
        Characteristic(
            '2AB7E91B-43E8-4F73-AC3B-80C1683B47F9',
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            CharacteristicValue(read=async_read),
        ),
        '>I',
    )

    service = Service(
        '3A657F47-D34F-46B3-B1EC-698E29B6B829', [characteristic, async_characteristic]
    )
    server.add_service(service)

    connection = devices.connections[0]
    peer = Peer(connection)

    await peer.discover_services()
    await peer.discover_characteristics()
    c = peer.get_characteristics_by_uuid(characteristic.uuid)
    assert len(c) == 1
    c = c[0]
    cp = FooProxy(c)

    v = await cp.read_value()
    assert v == 123
    await cp.write_value(124)
    await async_barrier()
    assert characteristic.value == bytes([124])

    v = await cp.read_value()
    assert v == 124
    await cp.write_value(125, with_response=True)
    await async_barrier()
    assert characteristic.value == bytes([125])

    cd = DelegatedCharacteristicProxyAdapter(c, encode=lambda x: bytes([x // 2]))
    await cd.write_value(100, with_response=True)
    await async_barrier()
    assert characteristic.value == bytes([50])

    c2 = peer.get_characteristics_by_uuid(async_characteristic.uuid)
    assert len(c2) == 1
    c2 = c2[0]
    cd2 = PackedCharacteristicProxyAdapter(c2, ">I")
    cd2v = await cd2.read_value()
    assert cd2v == 0x05060708

    last_change = None

    def on_change(value):
        nonlocal last_change
        last_change = value

    await c.subscribe(on_change)
    await server.notify_subscribers(characteristic)
    await async_barrier()
    assert last_change == characteristic.value
    last_change = None

    await server.notify_subscribers(characteristic, value=bytes([125]))
    await async_barrier()
    assert last_change == bytes([125])
    last_change = None

    await c.unsubscribe(on_change)
    await server.notify_subscribers(characteristic)
    await async_barrier()
    assert last_change is None

    await cp.subscribe(on_change)
    await server.notify_subscribers(characteristic)
    await async_barrier()
    assert last_change == characteristic.value[0]
    last_change = None

    await server.notify_subscribers(characteristic, value=bytes([126]))
    await async_barrier()
    assert last_change == 126
    last_change = None

    await cp.unsubscribe(on_change)
    await server.notify_subscribers(characteristic)
    await async_barrier()
    assert last_change is None

    cd = DelegatedCharacteristicProxyAdapter(c, decode=lambda x: x[0])
    await cd.subscribe(on_change)
    await server.notify_subscribers(characteristic)
    await async_barrier()
    assert last_change == characteristic.value[0]
    last_change = None

    await cd.unsubscribe(on_change)
    await server.notify_subscribers(characteristic)
    await async_barrier()
    assert last_change is None


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_attribute_getters():
    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    characteristic_uuid = UUID('FDB159DB-036C-49E3-B3DB-6325AC750806')
    characteristic = Characteristic(
        characteristic_uuid,
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE
        | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([123]),
    )

    service_uuid = UUID('3A657F47-D34F-46B3-B1EC-698E29B6B829')
    service = Service(service_uuid, [characteristic])
    server.add_service(service)

    service_attr = server.gatt_server.get_service_attribute(service_uuid)
    assert service_attr

    (
        char_decl_attr,
        char_value_attr,
    ) = server.gatt_server.get_characteristic_attributes(
        service_uuid, characteristic_uuid
    )
    assert char_decl_attr and char_value_attr

    desc_attr = server.gatt_server.get_descriptor_attribute(
        service_uuid,
        characteristic_uuid,
        GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
    )
    assert desc_attr

    # assert all handles are in expected order
    assert (
        service_attr.handle
        < char_decl_attr.handle
        < char_value_attr.handle
        < desc_attr.handle
        == service_attr.end_group_handle
    )
    # assert characteristic declarations attribute is followed by characteristic value attribute
    assert char_decl_attr.handle + 1 == char_value_attr.handle


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_CharacteristicAdapter() -> None:
    v = bytes([1, 2, 3])
    c: Characteristic[Any] = Characteristic(
        GATT_BATTERY_LEVEL_CHARACTERISTIC,
        Characteristic.Properties.READ,
        Characteristic.READABLE,
        v,
    )

    v = bytes([3, 4, 5])
    await c.write_value(Mock(), v)
    assert c.value == v

    # Simple delegated adapter
    delegated = DelegatedCharacteristicAdapter(
        c, lambda x: bytes(reversed(x)), lambda x: bytes(reversed(x))
    )

    delegated_value = await delegated.read_value(Mock())
    assert delegated_value == bytes(reversed(v))

    delegated_value2 = bytes([3, 4, 5])
    await delegated.write_value(Mock(), delegated_value2)
    assert delegated.value == bytes(reversed(delegated_value2))

    # Packed adapter with single element format
    packed_value_ref = 1234
    packed_value_bytes = struct.pack('>H', packed_value_ref)
    c.value = packed_value_ref
    packed = PackedCharacteristicAdapter(c, '>H')

    packed_value_read = await packed.read_value(Mock())
    assert packed_value_read == packed_value_bytes
    c.value = b''
    await packed.write_value(Mock(), packed_value_bytes)
    assert packed.value == packed_value_ref

    # Packed adapter with multi-element format
    v1 = 1234
    v2 = 5678
    packed_multi_value_bytes = struct.pack('>HH', v1, v2)
    c.value = (v1, v2)
    packed_multi = PackedCharacteristicAdapter(c, '>HH')

    packed_multi_read_value = await packed_multi.read_value(Mock())
    assert packed_multi_read_value == packed_multi_value_bytes
    packed_multi.value = b''
    await packed_multi.write_value(Mock(), packed_multi_value_bytes)
    assert packed_multi.value == (v1, v2)

    # Mapped adapter
    v1 = 1234
    v2 = 5678
    packed_mapped_value_bytes = struct.pack('>HH', v1, v2)
    mapped = {'v1': v1, 'v2': v2}
    c.value = mapped
    packed_mapped = MappedCharacteristicAdapter(c, '>HH', ('v1', 'v2'))

    packed_mapped_read_value = await packed_mapped.read_value(Mock())
    assert packed_mapped_read_value == packed_mapped_value_bytes
    c.value = b''
    await packed_mapped.write_value(Mock(), packed_mapped_value_bytes)
    assert packed_mapped.value == mapped

    # UTF-8 adapter
    string_value = 'Hello π'
    string_value_bytes = string_value.encode('utf-8')
    c.value = string_value
    string_c = UTF8CharacteristicAdapter(c)

    string_read_value = await string_c.read_value(Mock())
    assert string_read_value == string_value_bytes
    c.value = b''
    await string_c.write_value(Mock(), string_value_bytes)
    assert string_c.value == string_value

    # Class adapter
    class BlaBla:
        def __init__(self, a: int, b: int) -> None:
            self.a = a
            self.b = b

        @classmethod
        def from_bytes(cls, data: bytes) -> Self:
            a, b = struct.unpack(">II", data)
            return cls(a, b)

        def __bytes__(self) -> bytes:
            return struct.pack(">II", self.a, self.b)

    class_value = BlaBla(3, 4)
    class_value_bytes = struct.pack(">II", 3, 4)
    c.value = class_value
    class_c = SerializableCharacteristicAdapter(c, BlaBla)

    class_read_value = await class_c.read_value(Mock())
    assert class_read_value == class_value_bytes
    class_c.value = b''
    await class_c.write_value(Mock(), class_value_bytes)
    assert isinstance(class_c.value, BlaBla)
    assert class_c.value.a == class_value.a
    assert class_c.value.b == class_value.b

    # Enum adapter
    class MyEnum(enum.IntEnum):
        ENUM_1 = 1234
        ENUM_2 = 5678

    enum_value = MyEnum.ENUM_2
    enum_value_bytes = int(enum_value).to_bytes(3, 'big')
    c.value = enum_value
    enum_c = EnumCharacteristicAdapter(c, MyEnum, 3, 'big')
    enum_read_value = await enum_c.read_value(Mock())
    assert enum_read_value == enum_value_bytes
    enum_c.value = b''
    await enum_c.write_value(Mock(), enum_value_bytes)
    assert isinstance(enum_c.value, MyEnum)
    assert enum_c.value == enum_value


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_CharacteristicProxyAdapter() -> None:
    class Client:
        def __init__(self, value):
            self.value = value

        async def read_value(self, handle, no_long_read=False) -> bytes:
            return self.value

        async def write_value(self, handle, value, with_response=False):
            self.value = value

    class TestAttributeProxy(gatt_client.CharacteristicProxy):
        def __init__(self, value) -> None:
            super().__init__(Client(value), 0, 0, None, 0)  # type: ignore

        @property
        def value(self):
            return self.client.value

        @value.setter
        def value(self, value):
            self.client.value = value

    v = bytes([1, 2, 3])
    c = TestAttributeProxy(v)
    a: CharacteristicProxyAdapter = CharacteristicProxyAdapter(c)

    value = await a.read_value()
    assert value == v

    v = bytes([3, 4, 5])
    await a.write_value(v)
    assert c.value == v

    # Simple delegated adapter
    delegated = DelegatedCharacteristicProxyAdapter(
        c, lambda x: bytes(reversed(x)), lambda x: bytes(reversed(x))
    )

    delegated_value = await delegated.read_value()
    assert delegated_value == bytes(reversed(v))

    delegated_value2 = bytes([3, 4, 5])
    await delegated.write_value(delegated_value2)
    assert c.value == bytes(reversed(delegated_value2))

    # Packed adapter with single element format
    packed_value_ref = 1234
    packed_value_bytes = struct.pack('>H', packed_value_ref)
    c.value = packed_value_bytes
    packed = PackedCharacteristicProxyAdapter(c, '>H')

    packed_value_read = await packed.read_value()
    assert packed_value_read == packed_value_ref
    c.value = None
    await packed.write_value(packed_value_ref)
    assert c.value == packed_value_bytes

    # Packed adapter with multi-element format
    v1 = 1234
    v2 = 5678
    packed_multi_value_bytes = struct.pack('>HH', v1, v2)
    c.value = packed_multi_value_bytes
    packed_multi = PackedCharacteristicProxyAdapter(c, '>HH')

    packed_multi_read_value = await packed_multi.read_value()
    assert packed_multi_read_value == (v1, v2)
    c.value = b''
    await packed_multi.write_value((v1, v2))
    assert c.value == packed_multi_value_bytes

    # Mapped adapter
    v1 = 1234
    v2 = 5678
    packed_mapped_value_bytes = struct.pack('>HH', v1, v2)
    mapped = {'v1': v1, 'v2': v2}
    c.value = packed_mapped_value_bytes
    packed_mapped = MappedCharacteristicProxyAdapter(c, '>HH', ('v1', 'v2'))

    packed_mapped_read_value = await packed_mapped.read_value()
    assert packed_mapped_read_value == mapped
    c.value = b''
    await packed_mapped.write_value(mapped)
    assert c.value == packed_mapped_value_bytes

    # UTF-8 adapter
    string_value = 'Hello π'
    string_value_bytes = string_value.encode('utf-8')
    c.value = string_value_bytes
    string_c = UTF8CharacteristicProxyAdapter(c)

    string_read_value = await string_c.read_value()
    assert string_read_value == string_value
    c.value = b''
    await string_c.write_value(string_value)
    assert c.value == string_value_bytes

    # Class adapter
    class BlaBla:
        def __init__(self, a: int, b: int) -> None:
            self.a = a
            self.b = b

        @classmethod
        def from_bytes(cls, data: bytes) -> Self:
            a, b = struct.unpack(">II", data)
            return cls(a, b)

        def __bytes__(self) -> bytes:
            return struct.pack(">II", self.a, self.b)

    class_value = BlaBla(3, 4)
    class_value_bytes = struct.pack(">II", 3, 4)
    c.value = class_value_bytes
    class_c = SerializableCharacteristicProxyAdapter(c, BlaBla)

    class_read_value = await class_c.read_value()
    assert isinstance(class_read_value, BlaBla)
    assert class_read_value.a == class_value.a
    assert class_read_value.b == class_value.b
    c.value = b''
    await class_c.write_value(class_value)
    assert c.value == class_value_bytes

    # Enum adapter
    class MyEnum(enum.IntEnum):
        ENUM_1 = 1234
        ENUM_2 = 5678

    enum_value = MyEnum.ENUM_1
    enum_value_bytes = int(enum_value).to_bytes(3, 'little')
    c.value = enum_value_bytes
    enum_c = EnumCharacteristicProxyAdapter(c, MyEnum, 3)

    enum_read_value = await enum_c.read_value()
    assert isinstance(enum_read_value, MyEnum)
    assert enum_read_value == enum_value
    c.value = b''
    await enum_c.write_value(enum_value)
    assert c.value == enum_value_bytes


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_CharacteristicValue():
    b = bytes([1, 2, 3])

    async def read_value(connection):
        return b

    c = CharacteristicValue(read=read_value)
    x = await c.read(None)
    assert x == b

    m = Mock()
    c = CharacteristicValue(write=m)
    z = object()
    c.write(z, b)
    m.assert_called_once_with(z, b)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_CharacteristicValue_async():
    b = bytes([1, 2, 3])

    async def read_value(connection):
        return b

    c = CharacteristicValue(read=read_value)
    x = await c.read(None)
    assert x == b

    m = AsyncMock()
    c = CharacteristicValue(write=m)
    z = object()
    await c.write(z, b)
    m.assert_called_once_with(z, b)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_write():
    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ | Characteristic.Properties.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
    )

    def on_characteristic1_write(connection, value):
        characteristic1._last_value = (connection, value)

    characteristic1.on('write', on_characteristic1_write)

    def on_characteristic2_read(connection):
        return bytes(str(connection.peer_address))

    def on_characteristic2_write(connection, value):
        characteristic2._last_value = (connection, value)

    characteristic2 = Characteristic(
        '66DE9057-C848-4ACA-B993-D675644EBB85',
        Characteristic.Properties.READ | Characteristic.Properties.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        CharacteristicValue(
            read=on_characteristic2_read, write=on_characteristic2_write
        ),
    )

    service1 = Service(
        '3A657F47-D34F-46B3-B1EC-698E29B6B829', [characteristic1, characteristic2]
    )
    server.add_services([service1])

    connection = devices.connections[0]
    peer = Peer(connection)

    await peer.discover_services()
    await peer.discover_characteristics()
    c = peer.get_characteristics_by_uuid(characteristic1.uuid)
    assert len(c) == 1
    c1 = c[0]
    c = peer.get_characteristics_by_uuid(characteristic2.uuid)
    assert len(c) == 1
    c2 = c[0]

    v1 = await peer.read_value(c1)
    assert v1 == b''
    b = bytes([1, 2, 3])
    await peer.write_value(c1, b)
    await async_barrier()
    assert characteristic1.value == b
    v1 = await peer.read_value(c1)
    assert v1 == b
    assert type(characteristic1._last_value is tuple)
    assert len(characteristic1._last_value) == 2
    assert str(characteristic1._last_value[0].peer_address) == str(
        client.random_address
    )
    assert characteristic1._last_value[1] == b
    bb = bytes([3, 4, 5, 6])
    characteristic1.value = bb
    v1 = await peer.read_value(c1)
    assert v1 == bb

    await peer.write_value(c2, b)
    await async_barrier()
    assert type(characteristic2._last_value is tuple)
    assert len(characteristic2._last_value) == 2
    assert str(characteristic2._last_value[0].peer_address) == str(
        client.random_address
    )
    assert characteristic2._last_value[1] == b


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_write2():
    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    v = bytes([0x11, 0x22, 0x33, 0x44])
    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ | Characteristic.Properties.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        value=v,
    )

    service1 = Service('3A657F47-D34F-46B3-B1EC-698E29B6B829', [characteristic1])
    server.add_services([service1])

    connection = devices.connections[0]
    peer = Peer(connection)

    await peer.discover_services()
    c = peer.get_services_by_uuid(service1.uuid)
    assert len(c) == 1
    s = c[0]
    await s.discover_characteristics()
    c = s.get_characteristics_by_uuid(characteristic1.uuid)
    assert len(c) == 1
    c1 = c[0]

    v1 = await c1.read_value()
    assert v1 == v

    a1 = PackedCharacteristicProxyAdapter(c1, '>I')
    v1 = await a1.read_value()
    assert v1 == struct.unpack('>I', v)[0]

    b = bytes([0x55, 0x66, 0x77, 0x88])
    await a1.write_value(struct.unpack('>I', b)[0])
    await async_barrier()
    assert characteristic1.value == b
    v1 = await a1.read_value()
    assert v1 == struct.unpack('>I', b)[0]


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_subscribe_notify():
    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE,
        bytes([1, 2, 3]),
    )

    def on_characteristic1_subscription(connection, notify_enabled, indicate_enabled):
        characteristic1._last_subscription = (
            connection,
            notify_enabled,
            indicate_enabled,
        )

    characteristic1.on('subscription', on_characteristic1_subscription)

    characteristic2 = Characteristic(
        '66DE9057-C848-4ACA-B993-D675644EBB85',
        Characteristic.Properties.READ | Characteristic.Properties.INDICATE,
        Characteristic.READABLE,
        bytes([4, 5, 6]),
    )

    def on_characteristic2_subscription(connection, notify_enabled, indicate_enabled):
        characteristic2._last_subscription = (
            connection,
            notify_enabled,
            indicate_enabled,
        )

    characteristic2.on('subscription', on_characteristic2_subscription)

    characteristic3 = Characteristic(
        'AB5E639C-40C1-4238-B9CB-AF41F8B806E4',
        Characteristic.Properties.READ
        | Characteristic.Properties.NOTIFY
        | Characteristic.Properties.INDICATE,
        Characteristic.READABLE,
        bytes([7, 8, 9]),
    )

    def on_characteristic3_subscription(connection, notify_enabled, indicate_enabled):
        characteristic3._last_subscription = (
            connection,
            notify_enabled,
            indicate_enabled,
        )

    characteristic3.on('subscription', on_characteristic3_subscription)

    service1 = Service(
        '3A657F47-D34F-46B3-B1EC-698E29B6B829',
        [characteristic1, characteristic2, characteristic3],
    )
    server.add_services([service1])

    def on_characteristic_subscription(
        connection, characteristic, notify_enabled, indicate_enabled
    ):
        server._last_subscription = (
            connection,
            characteristic,
            notify_enabled,
            indicate_enabled,
        )

    server.on('characteristic_subscription', on_characteristic_subscription)

    connection = devices.connections[0]
    peer = Peer(connection)

    await peer.discover_services()
    await peer.discover_characteristics()
    c = peer.get_characteristics_by_uuid(characteristic1.uuid)
    assert len(c) == 1
    c1 = c[0]
    c = peer.get_characteristics_by_uuid(characteristic2.uuid)
    assert len(c) == 1
    c2 = c[0]
    c = peer.get_characteristics_by_uuid(characteristic3.uuid)
    assert len(c) == 1
    c3 = c[0]

    c1._called = False
    c1._last_update = None

    def on_c1_update(value):
        c1._called = True
        c1._last_update = value

    c1.on('update', on_c1_update)
    await peer.subscribe(c1)
    await async_barrier()
    assert server._last_subscription[1] == characteristic1
    assert server._last_subscription[2]
    assert not server._last_subscription[3]
    assert characteristic1._last_subscription[1]
    assert not characteristic1._last_subscription[2]
    await server.indicate_subscribers(characteristic1)
    await async_barrier()
    assert not c1._called
    await server.notify_subscribers(characteristic1)
    await async_barrier()
    assert c1._called
    assert c1._last_update == characteristic1.value

    c1._called = False
    c1._last_update = None
    c1_value = characteristic1.value
    await server.notify_subscribers(characteristic1, bytes([0, 1, 2]))
    await async_barrier()
    assert c1._called
    assert c1._last_update == bytes([0, 1, 2])
    assert characteristic1.value == c1_value

    c1._called = False
    await peer.unsubscribe(c1)
    await server.notify_subscribers(characteristic1)
    assert not c1._called

    c2._called = False
    c2._last_update = None

    def on_c2_update(value):
        c2._called = True
        c2._last_update = value

    await peer.subscribe(c2, on_c2_update)
    await async_barrier()
    await server.notify_subscriber(
        characteristic2._last_subscription[0], characteristic2
    )
    await async_barrier()
    assert not c2._called
    await server.indicate_subscriber(
        characteristic2._last_subscription[0], characteristic2
    )
    await async_barrier()
    assert c2._called
    assert c2._last_update == characteristic2.value

    c2._called = False
    await peer.unsubscribe(c2, on_c2_update)
    await server.indicate_subscriber(
        characteristic2._last_subscription[0], characteristic2
    )
    await async_barrier()
    assert not c2._called

    c3._called = False
    c3._called_2 = False
    c3._called_3 = False
    c3._last_update = None
    c3._last_update_2 = None
    c3._last_update_3 = None

    def on_c3_update(value):
        c3._called = True
        c3._last_update = value

    def on_c3_update_2(value):  # for notify
        c3._called_2 = True
        c3._last_update_2 = value

    def on_c3_update_3(value):  # for indicate
        c3._called_3 = True
        c3._last_update_3 = value

    c3.on('update', on_c3_update)
    await peer.subscribe(c3, on_c3_update_2)
    await async_barrier()
    await server.notify_subscriber(
        characteristic3._last_subscription[0], characteristic3
    )
    await async_barrier()
    assert c3._called
    assert c3._last_update == characteristic3.value
    assert c3._called_2
    assert c3._last_update_2 == characteristic3.value
    assert not c3._called_3

    c3._called = False
    c3._called_2 = False
    c3._called_3 = False
    await peer.unsubscribe(c3)
    await peer.subscribe(c3, on_c3_update_3, prefer_notify=False)
    await async_barrier()
    characteristic3.value = bytes([1, 2, 3])
    await server.indicate_subscriber(
        characteristic3._last_subscription[0], characteristic3
    )
    await async_barrier()
    assert c3._called
    assert c3._last_update == characteristic3.value
    assert not c3._called_2
    assert c3._called_3
    assert c3._last_update_3 == characteristic3.value

    c3._called = False
    c3._called_2 = False
    c3._called_3 = False
    await peer.unsubscribe(c3)
    await server.notify_subscriber(
        characteristic3._last_subscription[0], characteristic3
    )
    await server.indicate_subscriber(
        characteristic3._last_subscription[0], characteristic3
    )
    await async_barrier()
    assert not c3._called
    assert not c3._called_2
    assert not c3._called_3


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unsubscribe():
    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE,
        bytes([1, 2, 3]),
    )
    characteristic2 = Characteristic(
        '3234C4F4-3F34-4616-8935-45A50EE05DEB',
        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE,
        bytes([1, 2, 3]),
    )

    service1 = Service(
        '3A657F47-D34F-46B3-B1EC-698E29B6B829',
        [characteristic1, characteristic2],
    )
    server.add_services([service1])

    mock1 = Mock()
    characteristic1.on('subscription', mock1)
    mock2 = Mock()
    characteristic2.on('subscription', mock2)

    connection = devices.connections[0]
    peer = Peer(connection)

    await peer.discover_services()
    await peer.discover_characteristics()
    c = peer.get_characteristics_by_uuid(characteristic1.uuid)
    assert len(c) == 1
    c1 = c[0]
    c = peer.get_characteristics_by_uuid(characteristic2.uuid)
    assert len(c) == 1
    c2 = c[0]

    await c1.subscribe()
    await async_barrier()
    mock1.assert_called_once_with(ANY, True, False)

    assert len(server.gatt_server.subscribers) == 1

    def callback(_):
        pass

    await c2.subscribe(callback)
    await async_barrier()
    mock2.assert_called_once_with(ANY, True, False)

    mock1.reset_mock()
    await c1.unsubscribe()
    await async_barrier()
    mock1.assert_called_once_with(ANY, False, False)

    mock2.reset_mock()
    await c2.unsubscribe(callback)
    await async_barrier()
    mock2.assert_called_once_with(ANY, False, False)

    # All CCCDs should be zeros now
    assert list(server.gatt_server.subscribers.values())[0] == {
        c1.handle: bytes([0, 0]),
        c2.handle: bytes([0, 0]),
    }

    mock1.reset_mock()
    await c1.unsubscribe()
    await async_barrier()
    mock1.assert_not_called()

    mock2.reset_mock()
    await c2.unsubscribe()
    await async_barrier()
    mock2.assert_not_called()

    mock1.reset_mock()
    await c1.unsubscribe(force=True)
    await async_barrier()
    mock1.assert_called_once_with(ANY, False, False)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_discover_all():
    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE,
        bytes([1, 2, 3]),
    )

    descriptor1 = Descriptor('2902', 'READABLE,WRITEABLE')
    descriptor2 = Descriptor('AAAA', 'READABLE,WRITEABLE')
    characteristic2 = Characteristic(
        '3234C4F4-3F34-4616-8935-45A50EE05DEB',
        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE,
        bytes([1, 2, 3]),
        descriptors=[descriptor1, descriptor2],
    )

    service1 = Service(
        '3A657F47-D34F-46B3-B1EC-698E29B6B829',
        [characteristic1, characteristic2],
    )
    service2 = Service('1111', [])
    server.add_services([service1, service2])

    connection = devices.connections[0]
    peer = Peer(connection)

    await peer.discover_all()
    assert len(peer.gatt_client.services) == 4
    # service 1800 and 1801 get added automatically
    assert peer.gatt_client.services[0].uuid == UUID('1800')
    assert peer.gatt_client.services[1].uuid == UUID('1801')
    assert peer.gatt_client.services[2].uuid == service1.uuid
    assert peer.gatt_client.services[3].uuid == service2.uuid
    s = peer.get_services_by_uuid(service1.uuid)
    assert len(s) == 1
    assert len(s[0].characteristics) == 2
    c = peer.get_characteristics_by_uuid(uuid=characteristic2.uuid, service=s[0])
    assert len(c) == 1
    assert len(c[0].descriptors) == 2
    s = peer.get_services_by_uuid(service2.uuid)
    assert len(s) == 1
    assert len(s[0].characteristics) == 0


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_mtu_exchange():
    devices = Devices(3)
    for dev in devices:
        await dev.power_on()
    [d1, d2, d3] = devices

    d3.gatt_server.max_mtu = 100

    d3_connections = []

    @d3.on('connection')
    def on_d3_connection(connection):
        d3_connections.append(connection)

    await d1.power_on()
    await d2.power_on()
    await d3.power_on()

    await d3.start_advertising(advertising_interval_min=1.0)
    d1_connection = await d1.connect(d3.random_address)
    await async_barrier()
    assert len(d3_connections) == 1
    assert d3_connections[0] is not None

    await d3.start_advertising(advertising_interval_min=1.0)
    d2_connection = await d2.connect(d3.random_address)
    await async_barrier()
    assert len(d3_connections) == 2
    assert d3_connections[1] is not None

    d1_peer = Peer(d1_connection)
    d2_peer = Peer(d2_connection)

    d1_client_mtu = await d1_peer.request_mtu(220)
    assert d1_client_mtu == 100
    assert d1_connection.att_mtu == 100

    d2_client_mtu = await d2_peer.request_mtu(50)
    assert d2_client_mtu == 50
    assert d2_connection.att_mtu == 50


# -----------------------------------------------------------------------------
def test_char_property_to_string():
    # single
    assert str(Characteristic.Properties(0x01)) == "BROADCAST"
    assert str(Characteristic.Properties.BROADCAST) == "BROADCAST"

    # double
    assert str(Characteristic.Properties(0x03)) == "BROADCAST|READ"
    assert (
        str(Characteristic.Properties.BROADCAST | Characteristic.Properties.READ)
        == "BROADCAST|READ"
    )


# -----------------------------------------------------------------------------
def test_characteristic_property_from_string():
    # single
    assert (
        Characteristic.Properties.from_string("BROADCAST")
        == Characteristic.Properties.BROADCAST
    )

    # double
    assert (
        Characteristic.Properties.from_string("BROADCAST,READ")
        == Characteristic.Properties.BROADCAST | Characteristic.Properties.READ
    )
    assert (
        Characteristic.Properties.from_string("READ,BROADCAST")
        == Characteristic.Properties.BROADCAST | Characteristic.Properties.READ
    )
    assert (
        Characteristic.Properties.from_string("BROADCAST|READ")
        == Characteristic.Properties.BROADCAST | Characteristic.Properties.READ
    )


# -----------------------------------------------------------------------------
def test_characteristic_property_from_string_assert():
    with pytest.raises(TypeError) as e_info:
        Characteristic.Properties.from_string("BROADCAST,HELLO")

    assert (
        str(e_info.value)
        == """Characteristic.Properties::from_string() error:
Expected a string containing any of the keys, separated by , or |: BROADCAST,READ,WRITE_WITHOUT_RESPONSE,WRITE,NOTIFY,INDICATE,AUTHENTICATED_SIGNED_WRITES,EXTENDED_PROPERTIES
Got: BROADCAST,HELLO"""
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_server_string():
    devices = await TwoDevices.create_with_connection()
    [_, server] = devices

    characteristic = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE
        | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([123]),
    )

    service = Service('3A657F47-D34F-46B3-B1EC-698E29B6B829', [characteristic])
    server.add_service(service)

    assert (
        str(server.gatt_server)
        == """Service(handle=0x0001, end=0x0005, uuid=UUID-16:1800 (Generic Access))
CharacteristicDeclaration(handle=0x0002, value_handle=0x0003, uuid=UUID-16:2A00 (Device Name), READ)
Characteristic(handle=0x0003, end=0x0003, uuid=UUID-16:2A00 (Device Name), READ)
CharacteristicDeclaration(handle=0x0004, value_handle=0x0005, uuid=UUID-16:2A01 (Appearance), READ)
Characteristic(handle=0x0005, end=0x0005, uuid=UUID-16:2A01 (Appearance), READ)
Service(handle=0x0006, end=0x000D, uuid=UUID-16:1801 (Generic Attribute))
CharacteristicDeclaration(handle=0x0007, value_handle=0x0008, uuid=UUID-16:2A05 (Service Changed), INDICATE)
Characteristic(handle=0x0008, end=0x0009, uuid=UUID-16:2A05 (Service Changed), INDICATE)
Descriptor(handle=0x0009, type=UUID-16:2902 (Client Characteristic Configuration), value=<dynamic>)
CharacteristicDeclaration(handle=0x000A, value_handle=0x000B, uuid=UUID-16:2B29 (Client Supported Features), READ|WRITE)
Characteristic(handle=0x000B, end=0x000B, uuid=UUID-16:2B29 (Client Supported Features), READ|WRITE)
CharacteristicDeclaration(handle=0x000C, value_handle=0x000D, uuid=UUID-16:2B2A (Database Hash), READ)
Characteristic(handle=0x000D, end=0x000D, uuid=UUID-16:2B2A (Database Hash), READ)
Service(handle=0x000E, end=0x0011, uuid=3A657F47-D34F-46B3-B1EC-698E29B6B829)
CharacteristicDeclaration(handle=0x000F, value_handle=0x0010, uuid=FDB159DB-036C-49E3-B3DB-6325AC750806, READ|WRITE|NOTIFY)
Characteristic(handle=0x0010, end=0x0011, uuid=FDB159DB-036C-49E3-B3DB-6325AC750806, READ|WRITE|NOTIFY)
Descriptor(handle=0x0011, type=UUID-16:2902 (Client Characteristic Configuration), value=<dynamic>)"""
    )


# -----------------------------------------------------------------------------
async def async_main():
    test_UUID()
    test_ATT_Error_Response()
    test_ATT_Read_By_Group_Type_Request()
    await test_read_write()
    await test_read_write2()
    await test_subscribe_notify()
    await test_unsubscribe()
    await test_characteristic_encoding()
    await test_mtu_exchange()
    await test_CharacteristicValue()
    await test_CharacteristicValue_async()
    await test_CharacteristicAdapter()
    await test_CharacteristicProxyAdapter()


# -----------------------------------------------------------------------------
def test_permissions_from_string():
    assert Attribute.Permissions.from_string('READABLE') == 1
    assert Attribute.Permissions.from_string('WRITEABLE') == 2
    assert Attribute.Permissions.from_string('READABLE,WRITEABLE') == 3


# -----------------------------------------------------------------------------
def test_characteristic_permissions():
    characteristic = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE
        | Characteristic.Properties.NOTIFY,
        'READABLE,WRITEABLE',
    )
    assert characteristic.permissions == 3


# -----------------------------------------------------------------------------
def test_characteristic_has_properties():
    characteristic = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE
        | Characteristic.Properties.NOTIFY,
        'READABLE,WRITEABLE',
    )
    assert characteristic.has_properties(Characteristic.Properties.READ)
    assert characteristic.has_properties(
        Characteristic.Properties.READ | Characteristic.Properties.WRITE
    )
    assert not characteristic.has_properties(
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE
        | Characteristic.Properties.INDICATE
    )
    assert not characteristic.has_properties(Characteristic.Properties.INDICATE)


# -----------------------------------------------------------------------------
def test_descriptor_permissions():
    descriptor = Descriptor('2902', 'READABLE,WRITEABLE')
    assert descriptor.permissions == 3


# -----------------------------------------------------------------------------
def test_get_attribute_group():
    device = Device()

    # add some services / characteristics to the gatt server
    characteristic1 = Characteristic(
        '1111',
        Characteristic.READ | Characteristic.WRITE | Characteristic.NOTIFY,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([123]),
    )
    characteristic2 = Characteristic(
        '2222',
        Characteristic.READ | Characteristic.WRITE | Characteristic.NOTIFY,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([123]),
    )
    services = [Service('1212', [characteristic1]), Service('3233', [characteristic2])]
    device.gatt_server.add_services(services)

    # get the handles from gatt server
    characteristic_attributes1 = device.gatt_server.get_characteristic_attributes(
        UUID('1212'), UUID('1111')
    )
    assert characteristic_attributes1 is not None
    characteristic_attributes2 = device.gatt_server.get_characteristic_attributes(
        UUID('3233'), UUID('2222')
    )
    assert characteristic_attributes2 is not None
    descriptor1 = device.gatt_server.get_descriptor_attribute(
        UUID('1212'), UUID('1111'), UUID('2902')
    )
    assert descriptor1 is not None
    descriptor2 = device.gatt_server.get_descriptor_attribute(
        UUID('3233'), UUID('2222'), UUID('2902')
    )
    assert descriptor2 is not None

    # confirm the handles map back to the service
    assert (
        UUID('1212')
        == device.gatt_server.get_attribute_group(
            characteristic_attributes1[0].handle, Service
        ).uuid
    )
    assert (
        UUID('1212')
        == device.gatt_server.get_attribute_group(
            characteristic_attributes1[1].handle, Service
        ).uuid
    )
    assert (
        UUID('1212')
        == device.gatt_server.get_attribute_group(descriptor1.handle, Service).uuid
    )
    assert (
        UUID('3233')
        == device.gatt_server.get_attribute_group(
            characteristic_attributes2[0].handle, Service
        ).uuid
    )
    assert (
        UUID('3233')
        == device.gatt_server.get_attribute_group(
            characteristic_attributes2[1].handle, Service
        ).uuid
    )
    assert (
        UUID('3233')
        == device.gatt_server.get_attribute_group(descriptor2.handle, Service).uuid
    )

    # confirm the handles map back to the characteristic
    assert (
        UUID('1111')
        == device.gatt_server.get_attribute_group(
            descriptor1.handle, Characteristic
        ).uuid
    )
    assert (
        UUID('2222')
        == device.gatt_server.get_attribute_group(
            descriptor2.handle, Characteristic
        ).uuid
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_characteristics_by_uuid():
    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    characteristic1 = Characteristic(
        '1234',
        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE,
        bytes([1, 2, 3]),
    )
    characteristic2 = Characteristic(
        '5678',
        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
        Characteristic.READABLE,
        bytes([1, 2, 3]),
    )
    service1 = Service(
        'ABCD',
        [characteristic1, characteristic2],
    )
    service2 = Service(
        'FFFF',
        [characteristic1],
    )

    server.add_services([service1, service2])

    connection = devices.connections[0]
    peer = Peer(connection)

    await peer.discover_services()
    await peer.discover_characteristics()
    c = peer.get_characteristics_by_uuid(uuid=UUID('1234'))
    assert len(c) == 2
    assert isinstance(c[0], gatt_client.CharacteristicProxy)
    c = peer.get_characteristics_by_uuid(uuid=UUID('1234'), service=UUID('ABCD'))
    assert len(c) == 1
    assert isinstance(c[0], gatt_client.CharacteristicProxy)
    c = peer.get_characteristics_by_uuid(uuid=UUID('1234'), service=UUID('AAAA'))
    assert len(c) == 0

    s = peer.get_services_by_uuid(uuid=UUID('ABCD'))
    assert len(s) == 1
    c = peer.get_characteristics_by_uuid(uuid=UUID('1234'), service=s[0])
    assert len(s) == 1


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_write_return_error():
    devices = await TwoDevices.create_with_connection()
    [client, server] = devices

    on_write = Mock(side_effect=ATT_Error(error_code=ErrorCode.VALUE_NOT_ALLOWED))
    characteristic = Characteristic(
        '1234',
        Characteristic.Properties.WRITE,
        Characteristic.Permissions.WRITEABLE,
        CharacteristicValue(write=on_write),
    )
    service = Service('ABCD', [characteristic])
    server.add_service(service)

    connection = devices.connections[0]

    async with Peer(connection) as peer:
        c = peer.get_characteristics_by_uuid(uuid=UUID('1234'))[0]
        with pytest.raises(ATT_Error) as e:
            await c.write_value(b'', with_response=True)
        assert e.value.error_code == ErrorCode.VALUE_NOT_ALLOWED


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_eatt_read():
    devices = await TwoDevices.create_with_connection()
    devices[1].gatt_server.register_eatt()

    characteristic = Characteristic(
        '1234',
        Characteristic.Properties.READ,
        Characteristic.Permissions.READABLE,
        b'9999',
    )
    service = Service('ABCD', [characteristic])
    devices[1].add_service(service)

    client = await gatt_client.Client.connect_eatt(devices.connections[0])
    await client.discover_services()
    service_proxy = client.get_services_by_uuid(service.uuid)[0]
    await service_proxy.discover_characteristics()
    characteristic_proxy = service_proxy.get_characteristics_by_uuid(
        characteristic.uuid
    )[0]
    assert await characteristic_proxy.read_value() == b'9999'


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_eatt_write():
    devices = await TwoDevices.create_with_connection()
    devices[1].gatt_server.register_eatt()

    write_queue = asyncio.Queue()
    characteristic = Characteristic(
        '1234',
        Characteristic.Properties.WRITE,
        Characteristic.Permissions.WRITEABLE,
        CharacteristicValue(write=lambda *args: write_queue.put_nowait(args)),
    )
    service = Service('ABCD', [characteristic])
    devices[1].add_service(service)

    client = await gatt_client.Client.connect_eatt(devices.connections[0])
    await client.discover_services()
    service_proxy = client.get_services_by_uuid(service.uuid)[0]
    await service_proxy.discover_characteristics()
    characteristic_proxy = service_proxy.get_characteristics_by_uuid(
        characteristic.uuid
    )[0]
    await characteristic_proxy.write_value(b'9999')
    assert await write_queue.get() == (devices.connections[1], b'9999')


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_eatt_notify():
    devices = await TwoDevices.create_with_connection()
    devices[1].gatt_server.register_eatt()

    characteristic = Characteristic(
        '1234',
        Characteristic.Properties.NOTIFY,
        Characteristic.Permissions.WRITEABLE,
    )
    service = Service('ABCD', [characteristic])
    devices[1].add_service(service)

    clients = [
        (
            devices.connections[0].gatt_client,
            asyncio.Queue[bytes](),
        ),
        (
            await gatt_client.Client.connect_eatt(devices.connections[0]),
            asyncio.Queue[bytes](),
        ),
        (
            await gatt_client.Client.connect_eatt(devices.connections[0]),
            asyncio.Queue[bytes](),
        ),
    ]
    for client, queue in clients:
        await client.discover_services()
        service_proxy = client.get_services_by_uuid(service.uuid)[0]
        await service_proxy.discover_characteristics()
        characteristic_proxy = service_proxy.get_characteristics_by_uuid(
            characteristic.uuid
        )[0]

    for client, queue in clients[:2]:
        characteristic_proxy = service_proxy.get_characteristics_by_uuid(
            characteristic.uuid
        )[0]
        await characteristic_proxy.subscribe(queue.put_nowait, prefer_notify=True)

    await devices[1].gatt_server.notify_subscribers(characteristic, b'1234')
    for _, queue in clients[:2]:
        assert await queue.get() == b'1234'
        assert queue.empty()
    assert clients[2][1].empty()

    await devices[1].gatt_server.notify_subscriber(
        devices.connections[1], characteristic, b'5678'
    )
    for _, queue in clients[:2]:
        assert await queue.get() == b'5678'
        assert queue.empty()
    assert clients[2][1].empty()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_eatt_indicate():
    devices = await TwoDevices.create_with_connection()
    devices[1].gatt_server.register_eatt()

    characteristic = Characteristic(
        '1234',
        Characteristic.Properties.INDICATE,
        Characteristic.Permissions.WRITEABLE,
    )
    service = Service('ABCD', [characteristic])
    devices[1].add_service(service)

    clients = [
        (
            devices.connections[0].gatt_client,
            asyncio.Queue[bytes](),
        ),
        (
            await gatt_client.Client.connect_eatt(devices.connections[0]),
            asyncio.Queue[bytes](),
        ),
        (
            await gatt_client.Client.connect_eatt(devices.connections[0]),
            asyncio.Queue[bytes](),
        ),
    ]
    for client, queue in clients:
        await client.discover_services()
        service_proxy = client.get_services_by_uuid(service.uuid)[0]
        await service_proxy.discover_characteristics()
        characteristic_proxy = service_proxy.get_characteristics_by_uuid(
            characteristic.uuid
        )[0]

    for client, queue in clients[:2]:
        characteristic_proxy = service_proxy.get_characteristics_by_uuid(
            characteristic.uuid
        )[0]
        await characteristic_proxy.subscribe(queue.put_nowait, prefer_notify=False)

    await devices[1].gatt_server.indicate_subscribers(characteristic, b'1234')
    for _, queue in clients[:2]:
        assert await queue.get() == b'1234'
        assert queue.empty()
    assert clients[2][1].empty()

    await devices[1].gatt_server.indicate_subscriber(
        devices.connections[1], characteristic, b'5678'
    )
    for _, queue in clients[:2]:
        assert await queue.get() == b'5678'
        assert queue.empty()
    assert clients[2][1].empty()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_eatt_connection_failure():
    devices = await TwoDevices.create_with_connection()

    with pytest.raises(l2cap.L2capError):
        await gatt_client.Client.connect_eatt(devices.connections[0])


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(async_main())
