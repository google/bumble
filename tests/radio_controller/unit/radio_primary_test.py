# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Legacy request admission and complete primary-channel exchange reservations."""

from itertools import pairwise

import pytest

from bumble.ll import (
    LL_IFS_US,
    PDU_ADV_LEGACY_DATA_SIZE_MAX,
    PDU_ADV_SCAN_REQ_PAYLOAD_SIZE,
    PDU_ADV_TXADD_MASK,
    PDU_HEADER_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import (
    RADIO_RESPONSE_START_TOLERANCE_US,
    RADIO_SWITCH_TIME_US,
    Phy,
    Received,
)
from bumble.radio_controller.radio_discovery import Advertising
from bumble.radio_controller.radio_scheduler import RadioReservation
from tests.radio_controller.unit.helpers import PARAMETERS


@pytest.mark.asyncio
async def test_legacy_advertising_without_requests_leaves_short_detection_gap(
    connection,
):
    link = connection.link
    link.connections.clear()
    item = Advertising(
        link.listener.controller.public_address, pdu_type=AdvertisingPduType.ADV_IND
    )
    await link._advertise(item)
    assert [channel for _, channel, _, _ in link.radio.sent] == [37, 38, 39]
    for previous, current in pairwise(link.radio.sent):
        end_us = previous[0] + Phy.LE_1M.airtime_us(len(previous[2]))
        assert current[0] - end_us == (
            LL_IFS_US
            + Phy.LE_1M.address_us
            + RADIO_RESPONSE_START_TOLERANCE_US
            + RADIO_SWITCH_TIME_US
            + 1
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'pdu_type', [AdvertisingPduType.ADV_IND, AdvertisingPduType.ADV_SCAN_IND]
)
async def test_legacy_reservation_covers_complete_scan_exchanges(
    connection, monkeypatch, pdu_type
):
    link = connection.link
    link.connections.clear()
    item = Advertising(
        link.listener.controller.public_address,
        pdu_type=pdu_type,
        scan_response=bytes(PDU_ADV_LEGACY_DATA_SIZE_MAX),
    )
    monkeypatch.setattr(
        link, 'reservations', lambda: [RadioReservation(1_000_000, 1000, 2_000_000)]
    )
    durations = []

    def reserve(reservations, start, duration, latest):
        durations.append(duration)
        return start

    monkeypatch.setattr('bumble.radio_controller.radio_link.first_radio_gap', reserve)
    request = (
        bytes(
            [
                AdvertisingPduType.SCAN_REQ
                | (PDU_ADV_TXADD_MASK if connection.peer.is_random else 0),
                PDU_ADV_SCAN_REQ_PAYLOAD_SIZE,
            ]
        )
        + bytes(connection.peer)
        + bytes(item.address)
    )
    start_us = 1
    for _ in range(3):
        request_start = (
            start_us
            + Phy.LE_1M.airtime_us(PDU_HEADER_SIZE + len(bytes(item.address)))
            + LL_IFS_US
            + RADIO_RESPONSE_START_TOLERANCE_US
        )
        request_end = request_start + Phy.LE_1M.airtime_us(len(request))
        link.radio.incoming.append(
            Received(request, -40, request_start, request_end, True)
        )
        start_us = (
            request_end
            + LL_IFS_US
            + Phy.LE_1M.airtime_us(
                PDU_HEADER_SIZE + len(bytes(item.address)) + len(item.scan_response)
            )
            + RADIO_SWITCH_TIME_US
        )
    await link._advertise(item)
    assert len(link.radio.sent) == 6
    assert durations == [
        link.radio.now_us + 1 - link.radio.sent[0][0] + RADIO_SWITCH_TIME_US
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize('extended', [False, True])
async def test_duplicate_connect_request_cannot_replace_the_reserved_acl(
    connection, extended
):
    link = connection.link
    address = link.listener.controller.public_address
    item = Advertising(
        address,
        enabled=True,
        extended=extended,
        mode=AdvertisingMode.CONNECTABLE,
        pdu_type=AdvertisingPduType.ADV_IND,
    )
    link.advertisers[0] = item
    peer = connection.peer
    data = bytes(peer) + bytes(address) + PARAMETERS.encode()
    pdu = (
        bytes(
            [
                AdvertisingPduType.CONNECT_IND
                | (PDU_ADV_TXADD_MASK if peer.is_random else 0),
                len(data),
            ]
        )
        + data
    )
    assert pdu[1] == len(pdu) - PDU_HEADER_SIZE
    packet = Received(pdu, -40, 100, 500, True)
    accepted = await (
        link.extended.request(item, 0, packet)
        if extended
        else link._advertising_request(item, 37, packet)
    )
    assert not accepted
    assert link.connections == {connection.handle: connection} and item.enabled
    assert not link.listener.controller.events and not link.radio.sent
