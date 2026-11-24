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

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import asyncio
from unittest.mock import MagicMock

import pytest

from bumble import core, device, hci, ll, lmp
from bumble.controller import Controller
from bumble.host import Host
from bumble.link import LocalLink
from bumble.testing.test_utils import async_barrier


# -----------------------------------------------------------------------------
def _make_device(
    name: str,
    link: LocalLink,
    public_address: hci.Address,
    random_address: hci.Address,
) -> tuple[Controller, device.Device]:
    controller = Controller(
        name,
        link=link,
        public_address=public_address,
    )
    controller.random_address = random_address
    dev = device.Device(
        name=name,
        address=random_address,
        host=Host(controller_source=controller, controller_sink=controller),
    )
    return controller, dev


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_acl_with_public_own_address():
    link = LocalLink()
    c1, d1 = _make_device(
        'central',
        link,
        hci.Address('00:11:22:33:44:01', hci.Address.PUBLIC_DEVICE_ADDRESS),
        hci.Address('C0:11:22:33:44:01', hci.Address.RANDOM_DEVICE_ADDRESS),
    )
    c2, d2 = _make_device(
        'peripheral',
        link,
        hci.Address('00:11:22:33:44:02', hci.Address.PUBLIC_DEVICE_ADDRESS),
        hci.Address('C0:11:22:33:44:02', hci.Address.RANDOM_DEVICE_ADDRESS),
    )

    await d1.power_on()
    await d2.power_on()

    await d2.start_advertising(own_address_type=hci.OwnAddressType.RANDOM)

    peripheral_connection_future: asyncio.Future[device.Connection] = (
        asyncio.get_running_loop().create_future()
    )
    d2.on('connection', peripheral_connection_future.set_result)

    central_conn = await d1.connect(
        d2.random_address,
        own_address_type=hci.OwnAddressType.PUBLIC,
    )
    peripheral_conn = await peripheral_connection_future

    assert central_conn.self_address == c1.public_address
    assert peripheral_conn.peer_address == c1.public_address

    # Exchange ACL data in both directions (ATT/L2CAP via GATT MTU exchange / raw ACL).
    received_on_p = asyncio.get_running_loop().create_future()
    received_on_c = asyncio.get_running_loop().create_future()
    c2.send_hci_packet_orig = c2.send_hci_packet
    c1.send_hci_packet_orig = c1.send_hci_packet

    def spy_c2(packet):
        if isinstance(packet, hci.HCI_AclDataPacket) and not received_on_p.done():
            received_on_p.set_result(packet.data)
        c2.send_hci_packet_orig(packet)

    def spy_c1(packet):
        if isinstance(packet, hci.HCI_AclDataPacket) and not received_on_c.done():
            received_on_c.set_result(packet.data)
        c1.send_hci_packet_orig(packet)

    c2.send_hci_packet = spy_c2
    c1.send_hci_packet = spy_c1

    c1_conn = c1.find_le_connection_by_handle(central_conn.handle)
    c2_conn = c2.find_le_connection_by_handle(peripheral_conn.handle)
    assert c1_conn is not None
    assert c2_conn is not None

    c1_conn.on_acl_pdu(b'\x01\x02\x03\x04')
    c2_conn.on_acl_pdu(b'\x05\x06\x07\x08')

    assert await received_on_p == b'\x01\x02\x03\x04'
    assert await received_on_c == b'\x05\x06\x07\x08'

    await central_conn.disconnect()
    await async_barrier()
    assert not c1.le_connections
    assert not c2.le_connections


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_extended_advertising_set_routing():
    link = LocalLink()
    c1, d1 = _make_device(
        'central',
        link,
        hci.Address('00:11:22:33:55:01', hci.Address.PUBLIC_DEVICE_ADDRESS),
        hci.Address('C0:11:22:33:55:01', hci.Address.RANDOM_DEVICE_ADDRESS),
    )
    c2, d2 = _make_device(
        'peripheral',
        link,
        hci.Address('00:11:22:33:55:02', hci.Address.PUBLIC_DEVICE_ADDRESS),
        hci.Address('C0:11:22:33:55:02', hci.Address.RANDOM_DEVICE_ADDRESS),
    )

    await d1.power_on()
    await d2.power_on()

    # Dedicated per-set random address distinct from controller.random_address.
    adv_set_address = hci.Address(
        'D0:AA:BB:CC:DD:EE', hci.Address.RANDOM_DEVICE_ADDRESS
    )
    adv_set = await d2.create_advertising_set(
        advertising_parameters=device.AdvertisingParameters(
            own_address_type=hci.OwnAddressType.RANDOM,
        ),
        random_address=adv_set_address,
        auto_start=True,
    )
    assert adv_set.random_address == adv_set_address

    peripheral_connection_future: asyncio.Future[device.Connection] = (
        asyncio.get_running_loop().create_future()
    )
    d2.on('connection', peripheral_connection_future.set_result)

    central_conn = await d1.connect(
        adv_set_address,
        own_address_type=hci.OwnAddressType.RANDOM,
    )
    peripheral_conn = await peripheral_connection_future

    assert peripheral_conn.self_address == adv_set_address
    assert central_conn.peer_address == adv_set_address

    # Verify LL control PDU (remote feature exchange) and ACL work over adv_set_address.
    features = await central_conn.get_remote_le_features()
    assert features is not None

    received_on_c = asyncio.get_running_loop().create_future()
    orig_send = c1.send_hci_packet

    def spy_c1(packet):
        if isinstance(packet, hci.HCI_AclDataPacket) and not received_on_c.done():
            received_on_c.set_result(packet.data)
        orig_send(packet)

    c1.send_hci_packet = spy_c1
    c2_conn = c2.find_le_connection_by_handle(peripheral_conn.handle)
    assert c2_conn is not None
    c2_conn.on_acl_pdu(b'\xaa\xbb\xcc')
    assert await received_on_c == b'\xaa\xbb\xcc'

    await central_conn.disconnect()
    await async_barrier()
    assert not c1.le_connections
    assert not c2.le_connections


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_duplicate_connection_rejected_and_self_address_checked():
    link = LocalLink()
    c1, d1 = _make_device(
        'central',
        link,
        hci.Address('00:11:22:33:66:01', hci.Address.PUBLIC_DEVICE_ADDRESS),
        hci.Address('C0:11:22:33:66:01', hci.Address.RANDOM_DEVICE_ADDRESS),
    )
    c2, d2 = _make_device(
        'peripheral',
        link,
        hci.Address('00:11:22:33:66:02', hci.Address.PUBLIC_DEVICE_ADDRESS),
        hci.Address('C0:11:22:33:66:02', hci.Address.RANDOM_DEVICE_ADDRESS),
    )

    await d1.power_on()
    await d2.power_on()
    await d2.start_advertising(own_address_type=hci.OwnAddressType.RANDOM)

    central_conn = await d1.connect(
        d2.random_address,
        own_address_type=hci.OwnAddressType.PUBLIC,
    )

    # Attempting a second LE connection to the same peer address (even with a
    # different own_address_type) must fail with CONNECTION_ALREADY_EXISTS_ERROR.
    with pytest.raises(hci.HCI_Error) as exc_info:
        await d1.connect(
            d2.random_address,
            own_address_type=hci.OwnAddressType.RANDOM,
        )
    assert (
        exc_info.value.error_code == hci.HCI_ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR
    )

    # Incoming ACL with a mismatched receiver_address (not connection.self_address)
    # must be ignored.
    received_acl: list[bytes] = []
    orig_send = c1.send_hci_packet

    def spy_c1(packet):
        if isinstance(packet, hci.HCI_AclDataPacket):
            received_acl.append(packet.data)
        orig_send(packet)

    c1.send_hci_packet = spy_c1
    link.send_acl_data(
        c2,
        sender_address=d2.random_address,
        receiver_address=c1.random_address,  # wrong: connection used c1.public_address
        transport=core.PhysicalTransport.LE,
        data=b'wrong-dest',
    )
    await async_barrier()
    assert not received_acl

    await central_conn.disconnect()
    await async_barrier()
    assert not c1.le_connections
    assert not c2.le_connections


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unrelated_controller_ignores_directed_packets_and_missing_peer_dropped():
    link = LocalLink()
    c1 = Controller(
        'c1',
        link=link,
        public_address=hci.Address('00:11:22:33:77:01'),
    )
    c2 = Controller(
        'c2',
        link=link,
        public_address=hci.Address('00:11:22:33:77:02'),
    )
    c3 = Controller(
        'c3',
        link=link,
        public_address=hci.Address('00:11:22:33:77:03'),
    )
    c3_sink = MagicMock()
    c3.set_packet_sink(c3_sink)

    unknown_addr = hci.Address('FF:EE:DD:CC:BB:AA', hci.Address.RANDOM_DEVICE_ADDRESS)

    # Missing peer for LL control PDU, ACL, and LMP should not raise.
    link.send_ll_control_pdu(
        sender_controller=c1,
        sender_address=c1.random_address,
        receiver_address=unknown_addr,
        packet=ll.TerminateInd(
            hci.HCI_ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR
        ),
    )
    link.send_acl_data(
        sender_controller=c1,
        sender_address=c1.random_address,
        receiver_address=unknown_addr,
        transport=core.PhysicalTransport.LE,
        data=b'hello',
    )
    link.send_lmp_packet(
        sender_controller=c1,
        sender_address=c1.public_address,
        receiver_address=hci.Address('00:11:22:33:77:99'),
        packet=lmp.LmpDetach(hci.HCI_ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR),
    )

    # Directed LMP packet to c2 should be ignored by c3.
    c2_sink = MagicMock()
    c2.set_packet_sink(c2_sink)
    link.send_lmp_packet(
        sender_controller=c1,
        sender_address=c1.public_address,
        receiver_address=c2.public_address,
        packet=lmp.LmpHostConnectionReq(),
    )
    await async_barrier()

    assert c2_sink.on_packet.called
    assert not c3_sink.on_packet.called


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_send_acl_data_invalid_transport():
    link = LocalLink()
    c1 = Controller('c1', link=link)
    with pytest.raises(ValueError, match='unsupported transport type'):
        link.send_acl_data(
            sender_controller=c1,
            sender_address=c1.public_address,
            receiver_address=c1.public_address,
            transport=99,  # type: ignore[arg-type]
            data=b'',
        )
