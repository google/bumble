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
import asyncio
import logging
import os
import struct
import pytest
from unittest.mock import Mock, ANY

from bumble.controller import Controller
from bumble.gatt_client import CharacteristicProxy
from bumble.gatt_server import Server
from bumble.link import LocalLink
from bumble.device import Device, Peer
from bumble.host import Host
from bumble.gatt import (
    GATT_BATTERY_LEVEL_CHARACTERISTIC,
    GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
    CharacteristicAdapter,
    DelegatedCharacteristicAdapter,
    PackedCharacteristicAdapter,
    MappedCharacteristicAdapter,
    UTF8CharacteristicAdapter,
    Service,
    Characteristic,
    CharacteristicValue,
    Descriptor,
)
from bumble.transport import AsyncPipeSink
from bumble.core import UUID
from bumble.att import (
    Attribute,
    ATT_EXCHANGE_MTU_REQUEST,
    ATT_ATTRIBUTE_NOT_FOUND_ERROR,
    ATT_PDU,
    ATT_Error_Response,
    ATT_Read_By_Group_Type_Request,
)


# -----------------------------------------------------------------------------
def basic_check(x):
    pdu = x.to_bytes()
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
    w = UUID.from_bytes(v.to_bytes())
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
        request_opcode_in_error=ATT_EXCHANGE_MTU_REQUEST,
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
    x = c.read_value(None)
    assert x == bytes([123])
    c.write_value(None, bytes([122]))
    assert c.value == 122

    class FooProxy(CharacteristicProxy):
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

    [client, server] = LinkedDevices().devices[:2]

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

    await client.power_on()
    await server.power_on()
    connection = await client.connect(server.random_address)
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

    cd = DelegatedCharacteristicAdapter(c, encode=lambda x: bytes([x // 2]))
    await cd.write_value(100, with_response=True)
    await async_barrier()
    assert characteristic.value == bytes([50])

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

    cd = DelegatedCharacteristicAdapter(c, decode=lambda x: x[0])
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
    [client, server] = LinkedDevices().devices[:2]

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
def test_CharacteristicAdapter():
    # Check that the CharacteristicAdapter base class is transparent
    v = bytes([1, 2, 3])
    c = Characteristic(
        GATT_BATTERY_LEVEL_CHARACTERISTIC,
        Characteristic.Properties.READ,
        Characteristic.READABLE,
        v,
    )
    a = CharacteristicAdapter(c)

    value = a.read_value(None)
    assert value == v

    v = bytes([3, 4, 5])
    a.write_value(None, v)
    assert c.value == v

    # Simple delegated adapter
    a = DelegatedCharacteristicAdapter(
        c, lambda x: bytes(reversed(x)), lambda x: bytes(reversed(x))
    )

    value = a.read_value(None)
    assert value == bytes(reversed(v))

    v = bytes([3, 4, 5])
    a.write_value(None, v)
    assert a.value == bytes(reversed(v))

    # Packed adapter with single element format
    v = 1234
    pv = struct.pack('>H', v)
    c.value = v
    a = PackedCharacteristicAdapter(c, '>H')

    value = a.read_value(None)
    assert value == pv
    c.value = None
    a.write_value(None, pv)
    assert a.value == v

    # Packed adapter with multi-element format
    v1 = 1234
    v2 = 5678
    pv = struct.pack('>HH', v1, v2)
    c.value = (v1, v2)
    a = PackedCharacteristicAdapter(c, '>HH')

    value = a.read_value(None)
    assert value == pv
    c.value = None
    a.write_value(None, pv)
    assert a.value == (v1, v2)

    # Mapped adapter
    v1 = 1234
    v2 = 5678
    pv = struct.pack('>HH', v1, v2)
    mapped = {'v1': v1, 'v2': v2}
    c.value = mapped
    a = MappedCharacteristicAdapter(c, '>HH', ('v1', 'v2'))

    value = a.read_value(None)
    assert value == pv
    c.value = None
    a.write_value(None, pv)
    assert a.value == mapped

    # UTF-8 adapter
    v = 'Hello π'
    ev = v.encode('utf-8')
    c.value = v
    a = UTF8CharacteristicAdapter(c)

    value = a.read_value(None)
    assert value == ev
    c.value = None
    a.write_value(None, ev)
    assert a.value == v


# -----------------------------------------------------------------------------
def test_CharacteristicValue():
    b = bytes([1, 2, 3])
    c = CharacteristicValue(read=lambda _: b)
    x = c.read(None)
    assert x == b

    result = []
    c = CharacteristicValue(
        write=lambda connection, value: result.append((connection, value))
    )
    z = object()
    c.write(z, b)
    assert result == [(z, b)]


# -----------------------------------------------------------------------------
class LinkedDevices:
    def __init__(self):
        self.connections = [None, None, None]

        self.link = LocalLink()
        self.controllers = [
            Controller('C1', link=self.link),
            Controller('C2', link=self.link),
            Controller('C3', link=self.link),
        ]
        self.devices = [
            Device(
                address='F0:F1:F2:F3:F4:F5',
                host=Host(self.controllers[0], AsyncPipeSink(self.controllers[0])),
            ),
            Device(
                address='F1:F2:F3:F4:F5:F6',
                host=Host(self.controllers[1], AsyncPipeSink(self.controllers[1])),
            ),
            Device(
                address='F2:F3:F4:F5:F6:F7',
                host=Host(self.controllers[2], AsyncPipeSink(self.controllers[2])),
            ),
        ]

        self.paired = [None, None, None]


# -----------------------------------------------------------------------------
async def async_barrier():
    ready = asyncio.get_running_loop().create_future()
    asyncio.get_running_loop().call_soon(ready.set_result, None)
    await ready


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_write():
    [client, server] = LinkedDevices().devices[:2]

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

    await client.power_on()
    await server.power_on()
    connection = await client.connect(server.random_address)
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
    [client, server] = LinkedDevices().devices[:2]

    v = bytes([0x11, 0x22, 0x33, 0x44])
    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.Properties.READ | Characteristic.Properties.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        value=v,
    )

    service1 = Service('3A657F47-D34F-46B3-B1EC-698E29B6B829', [characteristic1])
    server.add_services([service1])

    await client.power_on()
    await server.power_on()
    connection = await client.connect(server.random_address)
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

    a1 = PackedCharacteristicAdapter(c1, '>I')
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
    [client, server] = LinkedDevices().devices[:2]

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

    await client.power_on()
    await server.power_on()
    connection = await client.connect(server.random_address)
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
    [client, server] = LinkedDevices().devices[:2]

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

    await client.power_on()
    await server.power_on()
    connection = await client.connect(server.random_address)
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

    await c2.subscribe()
    await async_barrier()
    mock2.assert_called_once_with(ANY, True, False)

    mock1.reset_mock()
    await c1.unsubscribe()
    await async_barrier()
    mock1.assert_called_once_with(ANY, False, False)

    mock2.reset_mock()
    await c2.unsubscribe()
    await async_barrier()
    mock2.assert_called_once_with(ANY, False, False)

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
async def test_mtu_exchange():
    [d1, d2, d3] = LinkedDevices().devices[:3]

    d3.gatt_server.max_mtu = 100

    d3_connections = []

    @d3.on('connection')
    def on_d3_connection(connection):
        d3_connections.append(connection)

    await d1.power_on()
    await d2.power_on()
    await d3.power_on()

    d1_connection = await d1.connect(d3.random_address)
    assert len(d3_connections) == 1
    assert d3_connections[0] is not None

    d2_connection = await d2.connect(d3.random_address)
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
    [_, server] = LinkedDevices().devices[:2]

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
Service(handle=0x0006, end=0x0009, uuid=3A657F47-D34F-46B3-B1EC-698E29B6B829)
CharacteristicDeclaration(handle=0x0007, value_handle=0x0008, uuid=FDB159DB-036C-49E3-B3DB-6325AC750806, READ|WRITE|NOTIFY)
Characteristic(handle=0x0008, end=0x0009, uuid=FDB159DB-036C-49E3-B3DB-6325AC750806, READ|WRITE|NOTIFY)
Descriptor(handle=0x0009, type=UUID-16:2902 (Client Characteristic Configuration), value=0000)"""
    )


# -----------------------------------------------------------------------------
async def async_main():
    await test_read_write()
    await test_read_write2()
    await test_subscribe_notify()
    await test_unsubscribe()
    await test_characteristic_encoding()
    await test_mtu_exchange()


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
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    test_UUID()
    test_ATT_Error_Response()
    test_ATT_Read_By_Group_Type_Request()
    test_CharacteristicValue()
    test_CharacteristicAdapter()
    asyncio.run(async_main())
