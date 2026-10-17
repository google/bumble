# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Directional limits, prospective PHY budgets and acknowledged fragment credits."""

import asyncio
import struct
from dataclasses import replace

import pytest

from bumble import hci
from bumble.ll import (
    LL_RESPONSE_TIMEOUT_US,
    PDU_DATA_LLID_MASK,
    PDU_DATA_PAYLOAD_SIZE_MAX,
    PDU_DATA_PAYLOAD_SIZE_MIN,
    PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    PDU_DATA_PAYLOAD_TIME_MIN_US,
    PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US,
    PDU_HEADER_SIZE,
    ControlPdu,
)
from bumble.radio_controller.radio import Phy, Received
from bumble.radio_controller.radio_control import InstantUpdate
from bumble.radio_controller.radio_data_length import (
    DataLengthProcedure,
    DataLengths,
    valid_data_length,
)

Opcode = ControlPdu.Opcode

ErrorCode = hci.HCI_ErrorCode


def negotiate(
    connection,
    *,
    rx=PDU_DATA_PAYLOAD_SIZE_MAX,
    rx_time=PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    tx=PDU_DATA_PAYLOAD_SIZE_MAX,
    tx_time=PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
):
    connection.establish()
    lengths = connection.controls.data_length
    lengths.request(PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US)
    connection.queue.clear()
    connection.control(
        bytes([Opcode.LL_LENGTH_RSP]) + struct.pack('<HHHH', rx, rx_time, tx, tx_time)
    )
    return lengths


def test_initial_lengths_and_asymmetric_negotiation(connection):
    lengths = connection.controls.data_length
    assert lengths.effective() == DataLengths(
        PDU_DATA_PAYLOAD_SIZE_MIN,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
        PDU_DATA_PAYLOAD_SIZE_MIN,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
    )
    lengths = negotiate(connection, rx=100, rx_time=1000, tx=200, tx_time=1500)
    assert lengths.effective() == DataLengths(200, 1500, 100, 1000)
    event = connection.link.listener.controller.events[-1]
    assert isinstance(event, hci.HCI_LE_Data_Length_Change_Event)
    assert (event.max_tx_octets, event.max_rx_octets) == (100, 200)
    lengths.refresh()
    assert connection.link.listener.controller.events[-1] is event


@pytest.mark.parametrize('phy,expected', [(Phy.LE_1M, 31), (Phy.LE_2M, 71)])
def test_time_limit_can_be_more_restrictive_than_octet_limit(connection, phy, expected):
    lengths = negotiate(connection, rx_time=PDU_DATA_PAYLOAD_TIME_MIN_US)
    connection.tx_phy = phy
    assert lengths.tx_payload_limit() == expected
    assert (
        phy.airtime_us(expected + PDU_HEADER_SIZE)
        <= PDU_DATA_PAYLOAD_TIME_MIN_US
        < phy.airtime_us(expected + PDU_HEADER_SIZE + 1)
    )


def test_coded_limits_follow_connection_interval_and_pending_update(connection):
    lengths = negotiate(connection)
    connection.tx_phy = connection.rx_phy = Phy.LE_CODED
    assert lengths.effective().tx_time == 12660
    connection.parameters = replace(connection.parameters, interval=48)
    assert lengths.effective().tx_time == PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
    connection.controls.pending = InstantUpdate(
        6, parameters=replace(connection.parameters, interval=24)
    )
    assert lengths.tx_payload_limit() == 186
    connection.controls.pending = InstantUpdate(6, peripheral_tx_phy=Phy.LE_1M)
    connection.tx_phy = Phy.LE_2M
    lengths.remote = replace(lengths.remote, rx_time=PDU_DATA_PAYLOAD_TIME_MIN_US)
    assert lengths.tx_payload_limit() == 31  # Both current 2M and upcoming 1M.


def test_central_prospective_phy_limit_starts_when_indication_is_prepared(connection):
    connection.role = hci.Role.CENTRAL
    lengths = negotiate(connection, rx=32, rx_time=PDU_DATA_PAYLOAD_TIME_MIN_US)
    connection.tx_phy = connection.rx_phy = Phy.LE_2M
    mask = int(hci.PhyBit.LE_1M)
    connection.controls.pending = InstantUpdate(6, central_tx_phy=Phy.LE_1M, local=True)
    assert lengths.tx_payload_limit() == 32
    connection.controls.prepare(bytes([Opcode.LL_PHY_UPDATE_IND, mask, mask, 6, 0]))
    assert lengths.tx_payload_limit() == 31


@pytest.mark.parametrize('local', [False, True])
def test_peripheral_prospective_limit_tracks_request_response_transmission(
    connection, local
):
    lengths = negotiate(connection, rx=32, rx_time=PDU_DATA_PAYLOAD_TIME_MIN_US)
    connection.tx_phy = connection.rx_phy = Phy.LE_2M
    mask = int(hci.PhyBit.LE_1M)
    if local:
        connection.controls.request_phy(mask, mask)
        opcode = Opcode.LL_PHY_REQ
    else:
        connection.control(bytes([Opcode.LL_PHY_REQ, mask, mask]))
        opcode = Opcode.LL_PHY_RSP
    assert lengths.tx_payload_limit() == 32
    connection.controls.prepare(bytes([opcode, mask, mask]))
    assert lengths.tx_payload_limit() == 31
    connection.control(bytes([Opcode.LL_PHY_UPDATE_IND, 0, 0, 0, 0]))
    assert lengths.tx_payload_limit() == 32


@pytest.mark.parametrize('peer_coded', [False, True])
def test_request_times_respect_known_peer_phy_features(connection, peer_coded):
    connection.peer_features = int(hci.LeFeatureMask.LE_CODED_PHY) if peer_coded else 0
    connection.controls.data_length.request(
        PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
    )
    packet = connection.queue[0].payload
    assert packet[0] == Opcode.LL_LENGTH_REQ
    expected_time = (
        PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
        if peer_coded
        else PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US
    )
    assert struct.unpack('<HHHH', packet[1:]) == (
        PDU_DATA_PAYLOAD_SIZE_MAX,
        expected_time,
        PDU_DATA_PAYLOAD_SIZE_MAX,
        expected_time,
    )


def test_simultaneous_requests_preserve_pending_local_procedure(connection):
    lengths = connection.controls.data_length
    lengths.request(PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US)
    connection.control(
        b'\x14'
        + struct.pack(
            '<HHHH',
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
        )
    )
    assert lengths.pending and connection.queue[0].payload[0] == Opcode.LL_LENGTH_RSP
    connection.control(
        b'\x15'
        + struct.pack(
            '<HHHH',
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
        )
    )
    assert not lengths.pending and lengths.deadline_us == 0


def test_invalid_length_parameter_values_are_rejected(connection):
    before = connection.controls.data_length.remote
    connection.control(bytes([Opcode.LL_LENGTH_REQ]) + bytes(8))
    assert connection.queue[-1].payload == bytes(
        [
            Opcode.LL_REJECT_EXT_IND,
            Opcode.LL_LENGTH_REQ,
            ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR,
        ]
    )
    assert connection.controls.data_length.remote == before


@pytest.mark.parametrize('opcode', [Opcode.LL_LENGTH_REQ, Opcode.LL_LENGTH_RSP])
@pytest.mark.parametrize('pending', [False, True])
@pytest.mark.parametrize('size', [0, 9])
def test_wrong_length_preserves_the_data_length_procedure(
    connection, opcode, pending, size
):
    lengths = connection.controls.data_length
    if pending:
        lengths.request(PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US)
        connection.queue.clear()
    before = (
        lengths.local,
        lengths.remote,
        lengths.reported,
        lengths.pending,
        lengths.deadline_us,
    )
    connection.control(bytes([opcode]) + bytes(size))
    assert [packet.payload for packet in connection.queue] == [
        bytes([Opcode.LL_UNKNOWN_RSP, opcode])
    ]
    assert (
        lengths.local,
        lengths.remote,
        lengths.reported,
        lengths.pending,
        lengths.deadline_us,
    ) == before
    assert not connection.link.listener.controller.events


@pytest.mark.parametrize('response', [b'\x07\x14', b'\x11\x14\x1a'])
def test_unsupported_peer_and_response_timeout(connection, response):
    connection.establish()
    lengths = connection.controls.data_length
    lengths.request(PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US)
    connection.control(response)
    assert not lengths.pending and lengths.effective() == DataLengths(
        PDU_DATA_PAYLOAD_SIZE_MIN,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
        PDU_DATA_PAYLOAD_SIZE_MIN,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
    )
    lengths.request(PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US)
    connection.radio.now_us = LL_RESPONSE_TIMEOUT_US
    assert lengths.check_timeout() and connection.closed
    assert (
        connection.link.listener.controller.events[-1].reason
        == ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR
    )


def test_unsolicited_response_does_not_change_parameters(connection):
    connection.control(
        b'\x15'
        + struct.pack(
            '<HHHH',
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
        )
    )
    assert connection.controls.data_length.effective() == DataLengths(
        PDU_DATA_PAYLOAD_SIZE_MIN,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
        PDU_DATA_PAYLOAD_SIZE_MIN,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
    )


def test_acl_fragments_preserve_boundaries_and_complete_only_after_final_ack(
    connection,
):
    negotiate(connection, rx=100)
    data = bytes(range(PDU_DATA_PAYLOAD_SIZE_MAX))
    connection.enqueue_acl(False, data)
    fragments = []
    for index in range(3):
        asyncio.run(connection.send(7, connection.radio.now_us + 1))
        fragments.append(connection.radio.sent[-1][2])
        assert not any(
            isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
            for event in connection.link.listener.controller.events
        )
        connection.accept(
            bytes([1 | (connection.tx_sn ^ 1) << 2 | connection.rx_nesn << 3, 0]), True
        )
    assert [len(pdu) - PDU_HEADER_SIZE for pdu in fragments] == [100, 100, 51]
    assert [pdu[0] & PDU_DATA_LLID_MASK for pdu in fragments] == [2, 1, 1]
    assert b''.join(pdu[PDU_HEADER_SIZE:] for pdu in fragments) == data
    credits = connection.link.listener.controller.events[-1]
    assert isinstance(credits, hci.HCI_Number_Of_Completed_Packets_Event)
    assert credits.num_completed_packets == [1]


def test_retransmission_is_not_resized_after_length_reduction(connection):
    lengths = negotiate(connection)
    connection.enqueue_acl(False, bytes(PDU_DATA_PAYLOAD_SIZE_MAX))
    asyncio.run(connection.send(7, 1))
    original = connection.radio.sent[-1][2]
    lengths.request(PDU_DATA_PAYLOAD_SIZE_MIN, PDU_DATA_PAYLOAD_TIME_MIN_US)
    asyncio.run(
        connection.send(
            14, connection.radio.earliest_start_us(14, connection.tx_phy, transmit=True)
        )
    )
    assert connection.radio.sent[-1][2][2:] == original[PDU_HEADER_SIZE:]
    assert (
        connection.pending.host_packet
        and len(connection.pending.payload) == PDU_DATA_PAYLOAD_SIZE_MAX
    )


def test_suggested_defaults_are_captured_only_at_connection_creation(connection):
    connection.link.default_tx_octets = PDU_DATA_PAYLOAD_SIZE_MAX
    connection.link.default_tx_time = PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
    assert connection.controls.data_length.local.tx_octets == PDU_DATA_PAYLOAD_SIZE_MIN
    fresh = DataLengthProcedure(connection)
    assert (fresh.local.tx_octets, fresh.local.tx_time) == (
        PDU_DATA_PAYLOAD_SIZE_MAX,
        PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    )


def test_nondefault_initial_preference_starts_a_wire_procedure(connection):
    lengths = connection.controls.data_length
    lengths.local = DataLengths(
        PDU_DATA_PAYLOAD_SIZE_MIN,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
        PDU_DATA_PAYLOAD_SIZE_MAX,
        PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    )
    connection.establish()
    assert lengths.pending and lengths.deadline_us == LL_RESPONSE_TIMEOUT_US
    assert connection.queue[0].payload == bytes([Opcode.LL_LENGTH_REQ]) + struct.pack(
        '<HHHH',
        PDU_DATA_PAYLOAD_SIZE_MAX,
        PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
        PDU_DATA_PAYLOAD_SIZE_MAX,
        PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    )


def test_receive_time_limit_does_not_accept_oversized_packet(connection):
    connection.controls.data_length.local = DataLengths(
        PDU_DATA_PAYLOAD_SIZE_MAX,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
        PDU_DATA_PAYLOAD_SIZE_MIN,
        PDU_DATA_PAYLOAD_TIME_MIN_US,
    )
    packet = Received(b'\x02\x20' + bytes(32), -45, 1, 337, True)
    connection.radio.incoming.append(packet)
    asyncio.run(connection.receive(7, 1000))
    assert connection.established and connection.rx_nesn == 0
    assert not any(
        isinstance(event, hci.HCI_AclDataPacket)
        for event in connection.link.listener.controller.events
    )


@pytest.mark.parametrize(
    'octets,time_us,valid',
    [
        (27, 328, True),
        (251, 17040, True),
        (26, 328, False),
        (252, 328, False),
        (27, 327, False),
        (27, 17041, False),
    ],
)
def test_data_length_bounds_do_not_trade_octets_for_time(octets, time_us, valid):
    assert valid_data_length(octets, time_us) is valid
