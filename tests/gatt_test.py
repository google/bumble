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

from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.device import Device, Peer
from bumble.host import Host
from bumble.gatt import (
    GATT_BATTERY_LEVEL_CHARACTERISTIC,
    CharacteristicAdapter,
    DelegatedCharacteristicAdapter,
    PackedCharacteristicAdapter,
    MappedCharacteristicAdapter,
    UTF8CharacteristicAdapter,
    Service,
    Characteristic,
    CharacteristicValue
)
from bumble.transport import AsyncPipeSink
from bumble.core import UUID
from bumble.att import (
    ATT_EXCHANGE_MTU_REQUEST,
    ATT_ATTRIBUTE_NOT_FOUND_ERROR,
    ATT_PDU,
    ATT_Error_Response,
    ATT_Read_By_Group_Type_Request
)


# -----------------------------------------------------------------------------
def basic_check(x):
    pdu = x.to_bytes()
    parsed = ATT_PDU.from_bytes(pdu)
    x_str = str(x)
    parsed_str = str(parsed)
    assert(x_str == parsed_str)


# -----------------------------------------------------------------------------
def test_UUID():
    u = UUID.from_16_bits(0x7788)
    assert(str(u) == 'UUID-16:7788')
    u = UUID.from_32_bits(0x11223344)
    assert(str(u) == 'UUID-32:11223344')
    u = UUID('61A3512C-09BE-4DDC-A6A6-0B03667AAFC6')
    assert(str(u) == '61A3512C-09BE-4DDC-A6A6-0B03667AAFC6')
    v = UUID(str(u))
    assert(str(v) == '61A3512C-09BE-4DDC-A6A6-0B03667AAFC6')
    w = UUID.from_bytes(v.to_bytes())
    assert(str(w) == '61A3512C-09BE-4DDC-A6A6-0B03667AAFC6')

    u1 = UUID.from_16_bits(0x1234)
    b1 = u1.to_bytes(force_128 = True)
    u2 = UUID.from_bytes(b1)
    assert(u1 == u2)

    u3 = UUID.from_16_bits(0x180a)
    assert(str(u3) == 'UUID-16:180A (Device Information)')


# -----------------------------------------------------------------------------
def test_ATT_Error_Response():
    pdu = ATT_Error_Response(
        request_opcode_in_error = ATT_EXCHANGE_MTU_REQUEST,
        attribute_handle_in_error = 0x0000,
        error_code = ATT_ATTRIBUTE_NOT_FOUND_ERROR
    )
    basic_check(pdu)


# -----------------------------------------------------------------------------
def test_ATT_Read_By_Group_Type_Request():
    pdu = ATT_Read_By_Group_Type_Request(
        starting_handle      = 0x0001,
        ending_handle        = 0xFFFF,
        attribute_group_type = UUID.from_16_bits(0x2800)
    )
    basic_check(pdu)


# -----------------------------------------------------------------------------
def test_CharacteristicAdapter():
    # Check that the CharacteristicAdapter base class is transparent
    v = bytes([1, 2, 3])
    c = Characteristic(GATT_BATTERY_LEVEL_CHARACTERISTIC, Characteristic.READ, Characteristic.READABLE, v)
    a = CharacteristicAdapter(c)

    value = a.read_value(None)
    assert(value == v)

    v = bytes([3, 4, 5])
    a.write_value(None, v)
    assert(c.value == v)

    # Simple delegated adapter
    a = DelegatedCharacteristicAdapter(c, lambda x: bytes(reversed(x)), lambda x: bytes(reversed(x)))

    value = a.read_value(None)
    assert(value == bytes(reversed(v)))

    v = bytes([3, 4, 5])
    a.write_value(None, v)
    assert(a.value == bytes(reversed(v)))

    # Packed adapter with single element format
    v = 1234
    pv = struct.pack('>H', v)
    c.value = v
    a = PackedCharacteristicAdapter(c, '>H')

    value = a.read_value(None)
    assert(value == pv)
    c.value = None
    a.write_value(None, pv)
    assert(a.value == v)

    # Packed adapter with multi-element format
    v1 = 1234
    v2 = 5678
    pv = struct.pack('>HH', v1, v2)
    c.value = (v1, v2)
    a = PackedCharacteristicAdapter(c, '>HH')

    value = a.read_value(None)
    assert(value == pv)
    c.value = None
    a.write_value(None, pv)
    assert(a.value == (v1, v2))

    # Mapped adapter
    v1 = 1234
    v2 = 5678
    pv = struct.pack('>HH', v1, v2)
    mapped = {'v1': v1, 'v2': v2}
    c.value = mapped
    a = MappedCharacteristicAdapter(c, '>HH', ('v1', 'v2'))

    value = a.read_value(None)
    assert(value == pv)
    c.value = None
    a.write_value(None, pv)
    assert(a.value == mapped)

    # UTF-8 adapter
    v = 'Hello π'
    ev = v.encode('utf-8')
    c.value = v
    a = UTF8CharacteristicAdapter(c)

    value = a.read_value(None)
    assert(value == ev)
    c.value = None
    a.write_value(None, ev)
    assert(a.value == v)


# -----------------------------------------------------------------------------
def test_CharacteristicValue():
    b = bytes([1, 2, 3])
    c = CharacteristicValue(read=lambda _: b)
    x = c.read(None)
    assert(x == b)

    result = []
    c = CharacteristicValue(write=lambda connection, value: result.append((connection, value)))
    z = object()
    c.write(z, b)
    assert(result == [(z, b)])


# -----------------------------------------------------------------------------
class TwoDevices:
    def __init__(self):
        self.connections = [None, None]

        self.link = LocalLink()
        self.controllers = [
            Controller('C1', link = self.link),
            Controller('C2', link = self.link)
        ]
        self.devices = [
            Device(
                address = 'F0:F1:F2:F3:F4:F5',
                host    = Host(self.controllers[0], AsyncPipeSink(self.controllers[0]))
            ),
            Device(
                address = 'F5:F4:F3:F2:F1:F0',
                host    = Host(self.controllers[1], AsyncPipeSink(self.controllers[1]))
            )
        ]

        self.paired = [None, None]


# -----------------------------------------------------------------------------
async def async_barrier():
    ready = asyncio.get_running_loop().create_future()
    asyncio.get_running_loop().call_soon(ready.set_result, None)
    await ready


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_write():
    [client, server] = TwoDevices().devices

    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.READ | Characteristic.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE
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
        Characteristic.READ | Characteristic.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        CharacteristicValue(read=on_characteristic2_read, write=on_characteristic2_write)
    )

    service1 = Service(
        '3A657F47-D34F-46B3-B1EC-698E29B6B829',
        [
            characteristic1,
            characteristic2
        ]
    )
    server.add_services([service1])

    await client.power_on()
    await server.power_on()
    connection = await client.connect(server.random_address)
    peer = Peer(connection)

    await peer.discover_services()
    await peer.discover_characteristics()
    c = peer.get_characteristics_by_uuid(characteristic1.uuid)
    assert(len(c) == 1)
    c1 = c[0]
    c = peer.get_characteristics_by_uuid(characteristic2.uuid)
    assert(len(c) == 1)
    c2 = c[0]

    v1 = await peer.read_value(c1)
    assert(v1 == b'')
    b = bytes([1, 2, 3])
    await peer.write_value(c1, b)
    await async_barrier()
    assert(characteristic1.value == b)
    v1 = await peer.read_value(c1)
    assert(v1 == b)
    assert(type(characteristic1._last_value) is tuple)
    assert(len(characteristic1._last_value) == 2)
    assert(str(characteristic1._last_value[0].peer_address) == str(client.random_address))
    assert(characteristic1._last_value[1] == b)
    bb = bytes([3, 4, 5, 6])
    characteristic1.value = bb
    v1 = await peer.read_value(c1)
    assert(v1 == bb)

    await peer.write_value(c2, b)
    await async_barrier()
    assert(type(characteristic2._last_value) is tuple)
    assert(len(characteristic2._last_value) == 2)
    assert(str(characteristic2._last_value[0].peer_address) == str(client.random_address))
    assert(characteristic2._last_value[1] == b)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_write2():
    [client, server] = TwoDevices().devices

    v = bytes([0x11, 0x22, 0x33, 0x44])
    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.READ | Characteristic.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        value=v
    )

    service1 = Service(
        '3A657F47-D34F-46B3-B1EC-698E29B6B829',
        [
            characteristic1
        ]
    )
    server.add_services([service1])

    await client.power_on()
    await server.power_on()
    connection = await client.connect(server.random_address)
    peer = Peer(connection)

    await peer.discover_services()
    c = peer.get_services_by_uuid(service1.uuid)
    assert(len(c) == 1)
    s = c[0]
    await s.discover_characteristics()
    c = s.get_characteristics_by_uuid(characteristic1.uuid)
    assert(len(c) == 1)
    c1 = c[0]

    v1 = await c1.read_value()
    assert(v1 == v)

    a1 = PackedCharacteristicAdapter(c1, '>I')
    v1 = await a1.read_value()
    assert(v1 == struct.unpack('>I', v)[0])

    b = bytes([0x55, 0x66, 0x77, 0x88])
    await a1.write_value(struct.unpack('>I', b)[0])
    await async_barrier()
    assert(characteristic1.value == b)
    v1 = await a1.read_value()
    assert(v1 == struct.unpack('>I', b)[0])


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_subscribe_notify():
    [client, server] = TwoDevices().devices

    characteristic1 = Characteristic(
        'FDB159DB-036C-49E3-B3DB-6325AC750806',
        Characteristic.READ | Characteristic.NOTIFY,
        Characteristic.READABLE,
        bytes([1, 2, 3])
    )

    def on_characteristic1_subscription(connection, notify_enabled, indicate_enabled):
        characteristic1._last_subscription = (connection, notify_enabled, indicate_enabled)

    characteristic1.on('subscription', on_characteristic1_subscription)

    characteristic2 = Characteristic(
        '66DE9057-C848-4ACA-B993-D675644EBB85',
        Characteristic.READ | Characteristic.INDICATE,
        Characteristic.READABLE,
        bytes([4, 5, 6])
    )

    def on_characteristic2_subscription(connection, notify_enabled, indicate_enabled):
        characteristic2._last_subscription = (connection, notify_enabled, indicate_enabled)

    characteristic2.on('subscription', on_characteristic2_subscription)

    characteristic3 = Characteristic(
        'AB5E639C-40C1-4238-B9CB-AF41F8B806E4',
        Characteristic.READ | Characteristic.NOTIFY | Characteristic.INDICATE,
        Characteristic.READABLE,
        bytes([7, 8, 9])
    )

    def on_characteristic3_subscription(connection, notify_enabled, indicate_enabled):
        characteristic3._last_subscription = (connection, notify_enabled, indicate_enabled)

    characteristic3.on('subscription', on_characteristic3_subscription)

    service1 = Service(
        '3A657F47-D34F-46B3-B1EC-698E29B6B829',
        [
            characteristic1,
            characteristic2,
            characteristic3
        ]
    )
    server.add_services([service1])

    def on_characteristic_subscription(connection, characteristic, notify_enabled, indicate_enabled):
        server._last_subscription = (connection, characteristic, notify_enabled, indicate_enabled)

    server.on('characteristic_subscription', on_characteristic_subscription)

    await client.power_on()
    await server.power_on()
    connection = await client.connect(server.random_address)
    peer = Peer(connection)

    await peer.discover_services()
    await peer.discover_characteristics()
    c = peer.get_characteristics_by_uuid(characteristic1.uuid)
    assert(len(c) == 1)
    c1 = c[0]
    c = peer.get_characteristics_by_uuid(characteristic2.uuid)
    assert(len(c) == 1)
    c2 = c[0]
    c = peer.get_characteristics_by_uuid(characteristic3.uuid)
    assert(len(c) == 1)
    c3 = c[0]

    c1._last_update = None

    def on_c1_update(connection, value):
        c1._last_update = (connection, value)

    c1.on('update', on_c1_update)
    await peer.subscribe(c1)
    await async_barrier()
    assert(server._last_subscription[1] == characteristic1)
    assert(server._last_subscription[2])
    assert(not server._last_subscription[3])
    assert(characteristic1._last_subscription[1])
    assert(not characteristic1._last_subscription[2])
    await server.indicate_subscribers(characteristic1)
    await async_barrier()
    assert(c1._last_update is None)
    await server.notify_subscribers(characteristic1)
    await async_barrier()
    assert(c1._last_update is not None)
    assert(c1._last_update[1] == characteristic1.value)

    assert(peer.gatt_client.notification_subscribers[c1.handle])
    await peer.unsubscribe(c1)
    assert(c1.handle not in peer.gatt_client.notification_subscribers)

    c2._last_update = None

    def on_c2_update(value):
        c2._last_update = (connection, value)

    await peer.subscribe(c2, on_c2_update)
    await async_barrier()
    await server.notify_subscriber(characteristic2._last_subscription[0], characteristic2)
    await async_barrier()
    assert(c2._last_update is None)
    await server.indicate_subscriber(characteristic2._last_subscription[0], characteristic2)
    await async_barrier()
    assert(c2._last_update is not None)
    assert(c2._last_update[1] == characteristic2.value)

    assert(on_c2_update in peer.gatt_client.indication_subscribers[c2.handle])
    await peer.unsubscribe(c2, on_c2_update)
    assert(on_c2_update not in peer.gatt_client.indication_subscribers[c2.handle])

    c3._last_update = None

    def on_c3_update(connection, value):
        c3._last_update = (connection, value)

    c3.on('update', on_c3_update)
    await peer.subscribe(c3)
    await async_barrier()
    await server.notify_subscriber(characteristic3._last_subscription[0], characteristic3)
    await async_barrier()
    assert(c3._last_update is not None)
    assert(c3._last_update[1] == characteristic3.value)
    characteristic3.value = bytes([1, 2, 3])
    await server.indicate_subscriber(characteristic3._last_subscription[0], characteristic3)
    await async_barrier()
    assert(c3._last_update is not None)
    assert(c3._last_update[1] == characteristic3.value)

    assert(peer.gatt_client.notification_subscribers[c3.handle])
    assert(peer.gatt_client.indication_subscribers[c3.handle])
    await peer.unsubscribe(c3)
    assert(c3.handle not in peer.gatt_client.notification_subscribers)
    assert(c3.handle not in peer.gatt_client.indication_subscribers)


# -----------------------------------------------------------------------------
async def async_main():
    await test_read_write()
    await test_read_write2()
    await test_subscribe_notify()

# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    test_UUID()
    test_ATT_Error_Response()
    test_ATT_Read_By_Group_Type_Request()
    test_CharacteristicValue()
    test_CharacteristicAdapter()
    asyncio.run(async_main())
