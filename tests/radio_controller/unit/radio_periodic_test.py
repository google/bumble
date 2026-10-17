# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Acquisition counters, Host skip policy and report lifetime ownership."""

from dataclasses import replace

import pytest

from bumble import hci
from bumble.ll import (
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    LL_PERIODIC_INTERVAL_UNIT_US,
    LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS,
)
from bumble.radio_controller.radio_advertising import ExtendedPdu, SyncInfo
from bumble.radio_controller.radio_discovery import Advertising, PeriodicSync
from tests.radio_controller.unit.helpers import bind_candidate, received_packet

ErrorCode = hci.HCI_ErrorCode

Report = hci.HCI_LE_Extended_Advertising_Report_Event


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'power,action',
    [
        (-20, 'report'),
        (0, 'report'),
        (None, 'report'),
        (-20, 'terminate'),
        (-20, 'disable'),
        (-20, 'replace'),
    ],
)
async def test_periodic_chain_establishes_before_collection_and_preserves_identity(
    connection, monkeypatch, power, action
):
    link = connection.link
    link.connections.clear()
    sync = PeriodicSync(
        connection.peer,
        3,
        100_000,
        100_000,
        info=SyncInfo(600, 80, (1 << 37) - 1, 0x9A328370, 0x123456, 0),
        next_us=10_000,
    )
    link.sync = sync
    packet = received_packet(ExtendedPdu(tx_power=power, data=b'head'), 10_000)
    connection.radio.incoming.append(packet)
    controller = link.listener.controller

    async def collect(received, fields, **parameters):
        assert received is packet
        assert sync.established and link.sync is None
        assert link.syncs[sync.handle] is sync
        assert len(controller.events) == 1
        assert isinstance(
            controller.events[0], hci.HCI_LE_Periodic_Advertising_Sync_Established_Event
        )
        assert sync.last_rx_us == packet.start_us
        assert sync.deadline_us == packet.end_us + sync.timeout_us
        if action == 'terminate':
            result = (
                link.listener.on_hci_le_periodic_advertising_terminate_sync_command(
                    hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(sync.handle)
                )
            )
            assert result.status == ErrorCode.SUCCESS
        elif action == 'disable':
            sync.reports_enabled = False
        elif action == 'replace':
            link.syncs[sync.handle] = replace(sync)
        # Tail power deliberately differs from the periodic event's first PDU.
        return (
            b'headtail',
            Report.DATA_COMPLETE,
            10,
        )

    monkeypatch.setattr(link.extended, 'collect', collect)
    await link._periodic_receive(sync)
    reports = [
        event
        for event in controller.events
        if isinstance(event, hci.HCI_LE_Periodic_Advertising_Report_Event)
    ]
    assert len(reports) == int(action == 'report')
    if reports:
        assert reports[0].tx_power == (
            power if power is not None else Report.TX_POWER_INFORMATION_NOT_AVAILABLE
        )
        assert reports[0].data == b'headtail'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'skip,timeout_us',
    [(0, 100_000), (3, 100_000), (hci.HCI_LE_PERIODIC_SYNC_SKIP_MAX, 1_000_000)],
)
async def test_candidate_deadline_and_listening_step_ignore_host_skip_and_timeout(
    connection, skip, timeout_us
):
    sync, info, packet = await bind_candidate(
        connection, skip=skip, timeout_us=timeout_us
    )
    interval_us = info.interval * LL_PERIODIC_INTERVAL_UNIT_US
    assert sync.next_us == packet.start_us + info.offset_us
    assert (
        sync.deadline_us
        == sync.next_us + LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS * interval_us
    )
    assert sync.event_step == 1
    assert connection.link.reservations()[0].interval_us == interval_us
    before = sync.next_us
    await connection.link._periodic_receive(sync)
    assert sync.next_us == before + interval_us
    assert sync.counter == LL_EVENT_COUNTER_MASK
    assert not sync.established


@pytest.mark.asyncio
@pytest.mark.parametrize('skip', [0, 3, hci.HCI_LE_PERIODIC_SYNC_SKIP_MAX])
async def test_first_periodic_packet_switches_to_host_timeout_and_skip(
    connection, skip
):
    sync, info, _ = await bind_candidate(connection, skip=skip)
    first = sync.next_us
    packet = received_packet(ExtendedPdu(data=b'data'), first)
    connection.radio.incoming.append(packet)
    await connection.link._periodic_receive(sync)
    assert sync.established and connection.link.sync is None
    assert connection.link.syncs[sync.handle] is sync
    assert sync.deadline_us == packet.end_us + sync.timeout_us
    assert sync.event_step == skip + 1
    assert (
        sync.next_us
        == first + (skip + 1) * info.interval * LL_PERIODIC_INTERVAL_UNIT_US
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('winner', ['connection', 'periodic_tx'])
async def test_periodic_rx_yields_without_refreshing_its_loss_timeout(
    connection, winner
):
    link = connection.link
    connection.anchor_us = 10_100
    connection.radio.now_us = 9999
    sync = PeriodicSync(
        connection.peer,
        1,
        100_000,
        100_000,
        skip=2,
        info=SyncInfo(0, 40, LL_DATA_CHANNEL_MAP_ALL, 0x12345678, 0x123456, 0),
        next_us=10_000,
        counter=LL_EVENT_COUNTER_MASK - 1,
        established=True,
    )
    link.syncs[sync.handle] = sync
    if winner == 'periodic_tx':
        link.connections.clear()
        link.advertisers[0] = Advertising(
            connection.peer,
            periodic_enabled=True,
            periodic_next_us=10_100,
            periodic_interval=40,
        )
    await link._periodic_receive(sync)
    assert connection.radio.now_us == 9999  # No RX request was admitted.
    assert sync.next_us == 10_000 + 3 * 40 * LL_PERIODIC_INTERVAL_UNIT_US
    assert sync.counter == 1
    assert sync.last_rx_us == 0 and sync.deadline_us == 100_000
    assert link.syncs[sync.handle] is sync
