# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Auxiliary chain budgets, identity inheritance and bounded reassembly."""

from dataclasses import replace
from itertools import pairwise

import pytest

from bumble import hci
from bumble.hci import HCI_LE_ADV_DATA_SIZE_MAX
from bumble.ll import (
    LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
    LL_MAFS_US,
    PDU_ADV_ADDRESS_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import RADIO_SWITCH_TIME_US, Phy
from bumble.radio_controller.radio_advertising import AuxPtr, ExtendedPdu
from bumble.radio_controller.radio_discovery import Advertising, Scanning
from bumble.radio_controller.radio_extended import advertising_time_us, fragments
from tests.radio_controller.unit.helpers import bind_candidate, received_packet

Report = hci.HCI_LE_Extended_Advertising_Report_Event


@pytest.mark.parametrize(
    'phy,size',
    [
        (Phy.LE_1M, 0),
        (Phy.LE_1M, 245),
        (Phy.LE_1M, 246),
        (Phy.LE_1M, HCI_LE_ADV_DATA_SIZE_MAX),
        (Phy.LE_2M, 246),
        (Phy.LE_CODED, 246),
        (Phy.LE_CODED, HCI_LE_ADV_DATA_SIZE_MAX),
    ],
)
def test_fragment_bytes_and_auxiliary_spacing(phy, size):
    data = bytes(index % 251 for index in range(size))
    packets = fragments(
        ExtendedPdu(address=bytes(PDU_ADV_ADDRESS_SIZE), adi=0x1234), data, 12, phy
    )
    assert b''.join(packet.data for packet in packets) == data
    for index, packet in enumerate(packets):
        assert len(packet.encode()) <= 257
        assert packet.adi == 0x1234
        assert packet.address == (bytes(PDU_ADV_ADDRESS_SIZE) if index == 0 else None)
        assert packet.mode == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
        if packet.aux_ptr:
            assert packet.aux_ptr.phy == phy and packet.aux_ptr.channel == 12
            assert packet.aux_ptr.offset_us % 30 == 0
            assert (
                packet.aux_ptr.offset_us
                >= phy.airtime_us(len(packet.encode())) + LL_MAFS_US
            )
        else:
            assert index == len(packets) - 1


def test_connectable_data_is_not_chained():
    (packet,) = fragments(
        ExtendedPdu(
            mode=AdvertisingMode.CONNECTABLE, address=bytes(PDU_ADV_ADDRESS_SIZE), adi=3
        ),
        bytes(200),
        12,
        Phy.LE_1M,
    )
    assert len(packet.data) == 200 and packet.aux_ptr is None
    assert packet.mode == AdvertisingMode.CONNECTABLE


def test_data_limit_is_bounded():
    with pytest.raises(ValueError):
        fragments(ExtendedPdu(), bytes(HCI_LE_ADV_DATA_SIZE_MAX + 1), 12, Phy.LE_1M)


@pytest.mark.parametrize(
    'first,capacity',
    [
        (ExtendedPdu(), 254),
        (ExtendedPdu(address=bytes(PDU_ADV_ADDRESS_SIZE), adi=1), 245),
        (
            ExtendedPdu(
                mode=AdvertisingMode.CONNECTABLE,
                address=bytes(PDU_ADV_ADDRESS_SIZE),
                target=bytes(PDU_ADV_ADDRESS_SIZE),
                adi=1,
                tx_power=0,
            ),
            238,
        ),
    ],
)
def test_capacity_uses_actual_extended_header(first, capacity):
    assert first.data_capacity() == capacity
    packets = fragments(first, bytes(capacity), 12, Phy.LE_1M)
    assert len(packets) == 1 and packets[0].encode()[1] == 255
    if first.mode:
        with pytest.raises(ValueError):
            fragments(first, bytes(capacity + 1), 12, Phy.LE_1M)
    else:
        packets = fragments(first, bytes(capacity + 1), 12, Phy.LE_1M)
        assert len(packets) == 2 and packets[0].encode()[1] == 255


@pytest.mark.parametrize('phy', list(Phy))
def test_advertising_budget_includes_all_primary_packets_and_auxiliary_chain(phy):
    item = Advertising(
        hci.Address('F0:F1:F2:F3:F4:01'),
        extended=True,
        primary_phy=phy if phy != Phy.LE_2M else Phy.LE_1M,
        secondary_phy=phy,
        data=bytes(HCI_LE_ADV_DATA_SIZE_MAX),
    )
    full = advertising_time_us(item)
    item.channel_map = 1
    assert full >= advertising_time_us(item)
    item.data = b''
    assert full > advertising_time_us(item)


@pytest.mark.asyncio
@pytest.mark.parametrize('primary_phy', [Phy.LE_1M, Phy.LE_CODED])
@pytest.mark.parametrize('channel_map', [1, 5, LL_ADV_PRIMARY_CHANNEL_MAP_ALL])
async def test_primary_switching_gap_and_auxptr_budget(
    connection, primary_phy, channel_map
):
    link = connection.link
    item = Advertising(
        link.listener.controller.public_address,
        extended=True,
        primary_phy=primary_phy,
        secondary_phy=Phy.LE_2M,
        channel_map=channel_map,
    )
    await link.extended.advertise(item)
    primary = link.radio.sent[:-1]
    auxiliary_start = link.radio.sent[-1][0]
    assert len(primary) == channel_map.bit_count()
    for previous, current in pairwise(primary):
        assert (
            current[0] - (previous[0] + primary_phy.airtime_us(len(previous[2])))
            == RADIO_SWITCH_TIME_US
        )
    for start, _, pdu, _ in primary:
        pointer = ExtendedPdu.decode(pdu).aux_ptr
        assert pointer is not None
        assert (
            start + pointer.offset_us
            <= auxiliary_start
            < start + pointer.offset_us + pointer.unit_us
        )
        assert (
            auxiliary_start - (start + primary_phy.airtime_us(len(pdu))) >= LL_MAFS_US
        )
    assert link.radio.now_us + 1 - primary[0][0] == advertising_time_us(item)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'address_type', [hci.AddressType.PUBLIC_DEVICE, hci.AddressType.RANDOM_DEVICE]
)
@pytest.mark.parametrize('location', ['primary', 'auxiliary', 'both'])
async def test_auxiliary_address_preserves_event_identity(
    connection, monkeypatch, address_type, location
):
    link = connection.link
    peer = hci.Address(bytes(connection.peer), address_type)
    primary = ExtendedPdu(
        address=bytes(peer) if location != 'auxiliary' else None,
        random_address=peer.is_random if location != 'auxiliary' else False,
        adi=1,
        aux_ptr=AuxPtr(0, 3000, Phy.LE_1M),
    )
    auxiliary = ExtendedPdu(
        address=(
            bytes(hci.Address('12:34:56:78:9A:BC'))
            if location == 'both'
            else bytes(peer) if location == 'auxiliary' else None
        ),
        random_address=not peer.is_random if location == 'both' else peer.is_random,
        adi=1,
        data=b'payload',
    )
    packet = received_packet(primary, 100)
    following = received_packet(auxiliary, 3100)
    connection.radio.now_us = packet.end_us - 1
    connection.radio.incoming.append(following)
    link.scan = Scanning(link.listener.controller.public_address, 10_000, 10_000)
    reports = []
    monkeypatch.setattr(
        link.listener, 'on_advertisement', lambda *args, **kwargs: reports.append(args)
    )
    await link.extended.scan(packet)
    assert len(reports) == 1
    assert reports[0][0] == peer
    assert reports[0][0].address_type == address_type
    assert reports[0][1] == b'payload'
    assert following.pdu == auxiliary.encode()


@pytest.mark.asyncio
@pytest.mark.parametrize('random_target', [False, True])
@pytest.mark.parametrize('repeated_target', [False, True])
async def test_auxiliary_target_cannot_override_superior_target(
    connection, monkeypatch, random_target, repeated_target
):
    link = connection.link
    target = hci.Address(
        bytes(link.listener.controller.public_address),
        (
            hci.AddressType.RANDOM_DEVICE
            if random_target
            else hci.AddressType.PUBLIC_DEVICE
        ),
    )
    primary = ExtendedPdu(
        target=bytes(target),
        random_target=random_target,
        adi=1,
        aux_ptr=AuxPtr(0, 3000, Phy.LE_1M),
    )
    auxiliary = ExtendedPdu(
        address=bytes(connection.peer),
        target=bytes(connection.peer) if repeated_target else None,
        random_target=not random_target,
        adi=1,
        data=b'payload',
    )
    packet = received_packet(primary, 100)
    connection.radio.now_us = packet.end_us - 1
    connection.radio.incoming.append(received_packet(auxiliary, 3100))
    link.scan = Scanning(target, 10_000, 10_000)
    reports = []
    monkeypatch.setattr(
        link.listener,
        'on_advertisement',
        lambda *args, **kwargs: reports.append((args, kwargs)),
    )
    await link.extended.scan(packet)
    assert len(reports) == 1
    args, kwargs = reports[0]
    assert args[1] == b'payload'
    assert args[3] == Report.EventType.DIRECTED_ADVERTISING
    assert kwargs['target'] == target
    assert kwargs['target'].address_type == target.address_type


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'mode,phy',
    [
        (AdvertisingMode.CONNECTABLE, Phy.LE_1M),
        (AdvertisingMode.SCANNABLE, Phy.LE_1M),
        (AdvertisingMode.NONCONNECTABLE_NONSCANNABLE, Phy.LE_CODED),
    ],
)
async def test_reserved_primary_addresses_do_not_replace_auxiliary_identity(
    connection, monkeypatch, mode, phy
):
    link = connection.link
    target = link.listener.controller.public_address
    primary = ExtendedPdu(
        mode=mode,
        address=bytes(hci.Address('12:34:56:78:9A:BC')),
        target=bytes(connection.peer),
        adi=1,
        aux_ptr=AuxPtr(0, 3000, phy),
    )
    auxiliary = ExtendedPdu(
        mode=mode,
        address=bytes(connection.peer),
        random_address=connection.peer.is_random,
        target=bytes(target),
        adi=1,
    )
    packet = received_packet(primary, 100, phy)
    connection.radio.now_us = packet.end_us - 1
    connection.radio.incoming.append(received_packet(auxiliary, 3100, phy))
    link.scan = Scanning(target, 10_000, 10_000)
    reports = []
    monkeypatch.setattr(
        link.listener,
        'on_advertisement',
        lambda *args, **kwargs: reports.append((args, kwargs)),
    )
    await link.extended.scan(packet)
    assert len(reports) == 1
    args, kwargs = reports[0]
    assert args[0] == connection.peer
    assert kwargs['target'] == target
    assert args[3] == mode | Report.EventType.DIRECTED_ADVERTISING


@pytest.mark.asyncio
@pytest.mark.parametrize('phy', list(Phy))
@pytest.mark.parametrize('last_power', [-10, 0, None])
@pytest.mark.parametrize('streamed', [False, True])
async def test_auxiliary_collection_reassembles_data_on_each_phy(
    connection, phy, last_power, streamed
):
    first = ExtendedPdu(
        adi=1, data=b'first', tx_power=-20, aux_ptr=AuxPtr(0, 3000, phy)
    )
    packet = received_packet(first, 100, phy)
    following = received_packet(
        ExtendedPdu(adi=1, data=b'second', tx_power=last_power), 3100, phy
    )
    connection.radio.now_us = packet.end_us - 1
    connection.radio.incoming.append(following)
    reports = []

    def report(data, status, received):
        # The first fragment is delivered before receiving the continuation.
        assert connection.radio.incoming
        reports.append((data, status, received))

    assert await connection.link.extended.collect(
        packet, first, on_fragment=report if streamed else None
    ) == (
        b'second' if streamed else b'firstsecond',
        Report.DATA_COMPLETE,
        (
            last_power
            if last_power is not None
            else Report.TX_POWER_INFORMATION_NOT_AVAILABLE
        ),
    )
    assert reports == (
        [
            (
                b'first',
                Report.DATA_INCOMPLETE_MORE_TO_COME,
                packet,
            )
        ]
        if streamed
        else []
    )
    assert not connection.radio.incoming


@pytest.mark.asyncio
@pytest.mark.parametrize('streamed', [False, True])
@pytest.mark.parametrize(
    'fault',
    [
        'missing',
        'malformed',
        'mode',
        'adi',
        'empty_continuation',
        'phy',
    ],
)
async def test_auxiliary_collection_never_marks_a_broken_chain_complete(
    connection, fault, streamed
):
    first = ExtendedPdu(
        adi=1, data=b'prefix', tx_power=0, aux_ptr=AuxPtr(0, 3000, Phy.LE_1M)
    )
    packet = received_packet(first, 100)
    next_pdu = ExtendedPdu(adi=1, data=b'not accepted', tx_power=-20)
    if fault == 'mode':
        next_pdu = replace(next_pdu, mode=AdvertisingMode.CONNECTABLE)
    elif fault == 'adi':
        next_pdu = replace(next_pdu, adi=2)
    elif fault == 'empty_continuation':
        next_pdu = replace(next_pdu, data=b'', aux_ptr=AuxPtr(0, 3000, Phy.LE_1M))
    elif fault == 'phy':
        first = replace(first, aux_ptr=AuxPtr(0, 3000, Phy.LE_2M))
        packet = received_packet(first, 100)
    connection.radio.now_us = packet.end_us - 1
    if fault not in ('missing', 'phy'):
        wire = (
            bytes([AdvertisingPduType.ADV_EXT_IND, 1])
            if fault == 'malformed'
            else next_pdu
        )
        connection.radio.incoming.append(received_packet(wire, 3100))
    reports = []
    data, status, tx_power = await connection.link.extended.collect(
        packet,
        first,
        on_fragment=(
            (lambda data, status, received: reports.append(data)) if streamed else None
        ),
    )
    assert b''.join(reports) + data == b'prefix'
    assert data == (b'' if streamed and fault != 'phy' else b'prefix')
    assert tx_power == 0
    assert status == Report.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME


@pytest.mark.asyncio
@pytest.mark.parametrize('streamed', [False, True])
async def test_auxiliary_collection_bounds_an_oversized_peer_chain(
    connection, streamed
):
    data = bytes(range(256)) * 7
    chunks = [data[offset : offset + 200] for offset in range(0, len(data), 200)]
    packets = [
        ExtendedPdu(
            adi=1,
            data=chunk,
            tx_power=index,
            aux_ptr=AuxPtr(0, 3000, Phy.LE_1M) if index < len(chunks) - 1 else None,
        )
        for index, chunk in enumerate(chunks)
    ]
    received = [
        received_packet(pdu, 100 + index * 3000) for index, pdu in enumerate(packets)
    ]
    connection.radio.now_us = received[0].end_us - 1
    connection.radio.incoming.extend(received[1:])
    reports = []
    payload, status, tx_power = await connection.link.extended.collect(
        received[0],
        packets[0],
        on_fragment=(
            (lambda data, status, received: reports.append(data)) if streamed else None
        ),
    )
    payload = b''.join(reports) + payload
    # Discard the whole overflowing PDU, not an arbitrary prefix of its data.
    assert (
        payload == data[: HCI_LE_ADV_DATA_SIZE_MAX // len(chunks[0]) * len(chunks[0])]
    )
    assert tx_power == len(payload) // len(chunks[0])
    assert status == Report.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME


@pytest.mark.asyncio
async def test_repeated_syncinfo_cannot_rebase_an_acquired_candidate(connection):
    sync, info, packet = await bind_candidate(connection)
    before = (sync.info, sync.next_us, sync.counter, sync.deadline_us, sync.last_rx_us)
    repeated = received_packet(
        ExtendedPdu(
            address=bytes(connection.peer),
            random_address=connection.peer.is_random,
            adi=0x3001,
            sync_info=replace(info, event_counter=7, offset_us=30_000),
        ),
        packet.end_us + 1000,
    )
    connection.radio.now_us = repeated.end_us - 1
    await connection.link.extended.scan(repeated)
    assert (
        sync.info,
        sync.next_us,
        sync.counter,
        sync.deadline_us,
        sync.last_rx_us,
    ) == before
