# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Radio arbitration, live wire identities and connectionless context lifetimes."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bumble import hci
from bumble.controller import Controller
from bumble.ll import (
    LL_CONN_INTERVAL_UNIT_US,
    LL_EVENT_COUNTER_MASK,
    LL_HOP_INCREMENT_MAX,
    LL_HOP_INCREMENT_MIN,
    LL_IFS_US,
    LL_PERIODIC_INTERVAL_UNIT_US,
    LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS,
    PDU_CRC_SIZE,
)
from bumble.radio_controller.controller_backend import RadioBackend
from bumble.radio_controller.radio import (
    PHY_OCTET_BITS,
    RADIO_RESPONSE_START_TOLERANCE_US,
    Phy,
)
from bumble.radio_controller.radio_advertising import SyncInfo
from bumble.radio_controller.radio_discovery import Advertising, PeriodicSync
from tests.radio_controller.unit.helpers import (
    add_connection,
    bind_candidate,
    check_access_address,
    extended_parameters,
)

ErrorCode = hci.HCI_ErrorCode


@pytest.mark.asyncio
@pytest.mark.parametrize('phy', list(Phy))
@pytest.mark.parametrize('deadline_us', [None, 1150])
async def test_response_window_waits_for_phy_sync_not_whole_packet(
    connection, monkeypatch, phy, deadline_us
):
    calls = []

    async def receive(channel, until_us, **parameters):
        calls.append((channel, until_us, parameters))

    monkeypatch.setattr(connection.radio, 'receive', receive)
    await connection.link.receive_response(37, 1000, phy, deadline_us=deadline_us)
    expected = 1000 + LL_IFS_US + phy.address_us + RADIO_RESPONSE_START_TOLERANCE_US
    assert calls == [
        (
            37,
            min(expected, deadline_us) if deadline_us else expected,
            {
                'start_us': 1000 + LL_IFS_US - RADIO_RESPONSE_START_TOLERANCE_US,
                'phy': phy,
            },
        )
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize('high_duty', [False, True])
@pytest.mark.parametrize('scheduled', [False, True])
async def test_advertising_duration_expiry_reports_timeout(
    connection, monkeypatch, high_duty, scheduled
):
    link = connection.link
    link.connections.clear()
    item = Advertising(
        link.listener.controller.public_address,
        enabled=True,
        high_duty=high_duty,
        deadline_us=10,
        next_us=20,
    )
    link.advertisers[0] = item
    ended = []
    monkeypatch.setattr(
        link.listener,
        'on_advertising_ended',
        lambda advertiser, reason: ended.append((advertiser, reason)),
    )
    link.radio.now_us = item.deadline_us
    if scheduled:
        await link._expire_advertiser(item)
    else:
        await link.advance_to_us(20)
    assert not item.enabled
    assert ended == [(item, ErrorCode.ADVERTISING_TIMEOUT_ERROR)]


@pytest.mark.asyncio
async def test_advertising_event_limit_is_not_a_duration_timeout(
    connection, monkeypatch
):
    link = connection.link
    link.connections.clear()
    item = Advertising(
        link.listener.controller.public_address,
        enabled=True,
        max_events=1,
        events=1,
        deadline_us=100,
        next_us=20,
    )
    link.advertisers[0] = item
    ended = []
    monkeypatch.setattr(
        link.listener,
        'on_advertising_ended',
        lambda advertiser, reason: ended.append((advertiser, reason)),
    )
    await link.advance_to_us(20)
    assert not item.enabled
    assert ended == [(item, ErrorCode.LIMIT_REACHED_ERROR)]


@pytest.mark.asyncio
async def test_search_without_syncinfo_has_no_established_sync_timeout(connection):
    link = connection.link
    link.connections.clear()
    sync = PeriodicSync(connection.peer, 3, 100_000, 0)
    link.sync = sync
    await link.advance_to_us(500_000)
    assert link.sync is sync and sync.info is None
    assert sync.deadline_us == 0
    assert not link.listener.controller.events


@pytest.mark.asyncio
@pytest.mark.parametrize('skip', [0, 3, hci.HCI_LE_PERIODIC_SYNC_SKIP_MAX])
async def test_six_missed_acquisition_events_expire_once_without_counter_wrap_errors(
    connection, monkeypatch, skip
):
    sync, info, _ = await bind_candidate(connection, skip=skip)
    receive = connection.radio.receive
    attempts = []

    async def record(channel, until_us, **parameters):
        if parameters.get('access_address') == info.access_address:
            attempts.append((sync.counter, channel))
        return await receive(channel, until_us, **parameters)

    monkeypatch.setattr(connection.radio, 'receive', record)
    await connection.link.advance_to_us(sync.deadline_us + 1)
    assert len(attempts) == LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS
    assert [counter for counter, _ in attempts] == [
        (info.event_counter + index) & LL_EVENT_COUNTER_MASK
        for index in range(LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS)
    ]
    assert connection.link.sync is None and not connection.link.syncs
    events = [
        event
        for event in connection.link.listener.controller.events
        if isinstance(event, hci.HCI_LE_Periodic_Advertising_Sync_Established_Event)
    ]
    assert len(events) == 1
    assert (
        events[0].status == hci.HCI_ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR
    )


def test_new_connection_window_avoids_existing_acl_and_uses_distinct_identity(
    connection,
):
    connection.established = True
    parameters = connection.link.connection_parameters(
        connection.parameters, 0, connection.anchor_us
    )
    assert parameters is not None and parameters.window_offset > 0
    assert parameters.access_address != connection.parameters.access_address
    assert parameters.interval == connection.parameters.interval


def test_connection_wire_parameters_are_seeded_and_within_bounds(connection):
    link = connection.link
    random_state = link.random.getstate()
    values = [
        link.connection_parameters(connection.parameters, 0, connection.anchor_us)
        for _ in range(100)
    ]
    for parameters in values:
        assert parameters is not None
        check_access_address(parameters.access_address)
        assert parameters.access_address != connection.parameters.access_address
        assert 0 <= parameters.crc_init < 1 << (PDU_CRC_SIZE * PHY_OCTET_BITS)
        assert LL_HOP_INCREMENT_MIN <= parameters.hop <= LL_HOP_INCREMENT_MAX
    assert len({parameters.crc_init for parameters in values}) > 1
    assert len({parameters.hop for parameters in values}) > 1
    link.random.setstate(random_state)
    assert values == [
        link.connection_parameters(connection.parameters, 0, connection.anchor_us)
        for _ in values
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize('offset,transmits', [(200, False), (2000, True)])
async def test_earlier_periodic_tx_protects_a_later_connection_window(
    connection, offset, transmits
):
    connection.role = hci.Role.CENTRAL
    connection.established = True
    connection.anchor_us = 10_000 + offset
    connection.radio.now_us = 9999
    item = Advertising(
        connection.link.listener.controller.public_address,
        periodic_enabled=True,
        periodic_next_us=10_000,
        periodic_interval=160,
        periodic_counter=LL_EVENT_COUNTER_MASK,
        periodic_aa=connection.parameters.access_address ^ 1,
        periodic_data=bytes(100),
    )
    connection.link.advertisers[0] = item
    await connection.link.advance_to_us(connection.anchor_us + 1500)
    periodic_packets = [
        packet
        for packet in connection.radio.sent
        if packet[3]['access_address'] == item.periodic_aa
    ]
    assert bool(periodic_packets) is transmits
    assert any(
        packet[3]['access_address'] == connection.parameters.access_address
        for packet in connection.radio.sent
    )
    assert item.periodic_next_us == 10_000 + 160 * LL_PERIODIC_INTERVAL_UNIT_US
    assert item.periodic_counter == 0


@pytest.mark.asyncio
async def test_colliding_acl_anchors_share_the_radio_without_starvation(connection):
    connection.role = hci.Role.CENTRAL
    connection.established = True
    second = add_connection(connection, 1)
    second.established = True
    assert second.anchor_us == connection.anchor_us
    await connection.link.advance_to_us(
        connection.anchor_us
        + 5 * connection.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    )
    by_address = {
        value.parameters.access_address: sum(
            parameters['access_address'] == value.parameters.access_address
            for _, _, _, parameters in connection.radio.sent
        )
        for value in (connection, second)
    }
    assert min(by_address.values()) >= 2
    assert max(by_address.values()) - min(by_address.values()) <= 1
    assert not connection.closed and not second.closed


async def test_periodic_wire_identity_is_allocated_on_enable_and_replayed_on_reset(
    hci_dut,
):
    tester = hci_dut
    values = []
    for _ in range(2):
        link = tester.input.backend.link
        random_state = link.random.getstate()
        await tester.command(extended_parameters())
        await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(0, 32, 32, 0)
        )
        item = link.advertisers[0]
        assert (item.periodic_aa, item.periodic_crc) == (0, 0)
        assert link.random.getstate() == random_state
        await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0))
        check_access_address(item.periodic_aa)
        assert 0 <= item.periodic_crc < 1 << (PDU_CRC_SIZE * PHY_OCTET_BITS)
        values.append((item.periodic_aa, item.periodic_crc))
        await tester.command(hci.HCI_Reset_Command())
    assert values[0] == values[1]


async def test_periodic_train_addresses_are_unique_and_reuse_only_free_slots(hci_dut):
    tester = hci_dut
    handles = [20, 40, 60, 80, 100, 120, 140, 160]
    for handle in handles:
        await tester.command(extended_parameters(advertising_handle=handle))
        await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(handle, 32, 32, 0)
        )
        await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, handle)
        )
    link = tester.input.backend.link
    addresses = {item.periodic_aa for item in link.advertisers.values()}
    assert len(addresses) == len(handles)
    for address in addresses:
        check_access_address(address)
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(0, handles[0])
    )
    await tester.command(hci.HCI_LE_Remove_Advertising_Set_Command(handles[0]))
    await tester.command(extended_parameters(advertising_handle=200))
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(200, 32, 32, 0)
    )
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 200))
    assert len({item.periodic_aa for item in link.advertisers.values()}) == len(handles)


def test_advertising_delay_seed_is_per_controller_and_reset_is_repeatable():
    async def create():
        return [
            Controller(
                'radio',
                public_address=address,
                backend=RadioBackend(SimpleNamespace(now_us=0)),
            )
            for address in ('F0:F1:F2:F3:F4:01', 'F0:F1:F2:F3:F4:02')
        ]

    controllers = asyncio.run(create())
    sequences = []
    for controller in controllers:
        link = controller.backend.link
        sequence = [link.random.randint(0, 10_000) for _ in range(10)]
        link.reset()
        assert [link.random.randint(0, 10_000) for _ in range(10)] == sequence
        sequences.append(sequence)
    assert sequences[0] != sequences[1]


def test_wire_identity_allocation_excludes_only_live_owners(connection, monkeypatch):
    link = connection.link
    periodic = Advertising(
        connection.peer, periodic_enabled=True, periodic_aa=0x456789AB
    )
    link.advertisers[0] = periodic
    candidates = iter(
        [connection.parameters.access_address, periodic.periodic_aa, 0x12345678]
    )
    monkeypatch.setattr(link.random, 'getrandbits', lambda width: next(candidates))
    assert link.new_access_address() == 0x12345678
    periodic.periodic_enabled = False
    candidates = iter([periodic.periodic_aa])
    assert link.new_access_address() == periodic.periodic_aa


@pytest.mark.asyncio
async def test_expired_sync_removes_only_its_own_handle(controller):
    link = controller.backend.link
    info = SyncInfo(9000, 80, (1 << 37) - 1, 0x456789AB, 0x123456, 0)
    peer = hci.Address('C0:11:22:33:44:55')
    expired = PeriodicSync(
        peer, 1, 100_000, 123, info=info, next_us=10_000, established=True, handle=1
    )
    active = replace(expired, handle=2, sid=2, deadline_us=500_000)
    link.syncs = {1: expired, 2: active}
    link.radio.now_us = 123
    await link.advance_to_us(124)
    assert link.syncs == {2: active}
    assert active.deadline_us == 500_000 and active.counter == 0
    assert len(controller.events) == 1
    assert isinstance(
        controller.events[0], hci.HCI_LE_Periodic_Advertising_Sync_Lost_Event
    )
    assert controller.events[0].sync_handle == 1
