# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""ARQ ownership, Host boundaries, missed events and independent deadlines."""

import asyncio
from dataclasses import replace

import pytest

from bumble import hci
from bumble.ll import (
    LL_CONN_INTERVAL_UNIT_US,
    LL_DATA_CHANNEL_COUNT,
    LL_SUPERVISION_TIMEOUT_UNIT_US,
    PDU_DATA_MD_MASK,
    PDU_DATA_NESN_MASK,
    PDU_DATA_PAYLOAD_SIZE_MAX,
    PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US,
    ControlPdu,
    LlId,
)
from bumble.radio_controller.radio import (
    PHY_CODED_S2_FACTOR,
    PHY_CODED_S8_FACTOR,
    RADIO_HCI_ACL_BUFFER_SIZE,
    Phy,
    Received,
    window_widening,
)
from bumble.radio_controller.radio_connection import (
    LL_CONTROL_PDU_SENDER_ROLES,
    Outbound,
)
from bumble.radio_controller.radio_control import InstantUpdate
from bumble.radio_controller.radio_data_length import DataLengths
from tests.radio_controller.unit.helpers import PARAMETERS

ErrorCode = hci.HCI_ErrorCode


@pytest.mark.parametrize(
    'phy,coding,expected',
    [
        (Phy.LE_1M, PHY_CODED_S8_FACTOR, 892),
        (Phy.LE_2M, PHY_CODED_S8_FACTOR, 604),
        (Phy.LE_CODED, PHY_CODED_S8_FACTOR, 5196),
        (Phy.LE_CODED, PHY_CODED_S2_FACTOR, 3642),
    ],
)
def test_connection_event_reserves_complete_phy_exchange(
    connection, phy, coding, expected
):
    connection.tx_phy = connection.rx_phy = Phy(phy)
    connection.tx_coding = coding
    connection.enqueue_acl(False, bytes(27))
    assert connection.next_exchange_us() == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'channel_map,expected',
    [
        ((1 << LL_DATA_CHANNEL_COUNT) - 1, [7, 14, 21, 28, 35, 5]),
        ((1 << 2) | (1 << 8), [8, 2, 8, 2, 8, 8]),
    ],
)
async def test_csa1_uses_live_connection_channel_state(
    connection, channel_map, expected
):
    connection.role = hci.Role.CENTRAL
    connection.parameters = replace(connection.parameters, channel_map=channel_map)
    for _ in expected:
        await connection.advance_to_us(connection.anchor_us)
    assert [packet[1] for packet in connection.radio.sent] == expected


def test_receive_duplicate_and_bad_crc_do_not_redeliver(connection):
    packet = b"\x02\x03abc"
    connection.accept(packet, False)
    assert not connection.established and not connection.link.listener.controller.events
    connection.accept(packet, True)
    assert connection.established and connection.rx_nesn == 1
    acl = [
        event
        for event in connection.link.listener.controller.events
        if isinstance(event, hci.HCI_AclDataPacket)
    ]
    assert len(acl) == 1 and acl[0].data == b"abc"
    connection.accept(packet, True)
    assert connection.rx_nesn == 1
    assert (
        sum(
            isinstance(event, hci.HCI_AclDataPacket)
            for event in connection.link.listener.controller.events
        )
        == 1
    )


@pytest.mark.parametrize("pdu", [b"", b"\x01", b"\x02\x02x", b"\x02\x1c" + bytes(28)])
def test_invalid_data_pdu(connection, pdu):
    connection.accept(pdu, True)
    assert not connection.established and not connection.link.listener.controller.events


def test_reserved_llid_updates_arq_without_dispatch(connection):
    connection.establish()
    connection.pending = Outbound(
        LlId.CONTROL, bytes([ControlPdu.Opcode.LL_FEATURE_REQ])
    )
    connection.sent_pending = True
    payload = bytes(
        [ControlPdu.Opcode.LL_TERMINATE_IND, ErrorCode.AUTHENTICATION_FAILURE_ERROR]
    )
    connection.accept(
        bytes([LlId.RESERVED | PDU_DATA_NESN_MASK, len(payload)]) + payload, True
    )
    assert connection.pending is None
    assert (connection.tx_sn, connection.rx_nesn) == (1, 1)
    assert connection.remote_termination is None and not connection.queue
    assert not any(
        isinstance(event, hci.HCI_AclDataPacket)
        for event in connection.link.listener.controller.events
    )


def test_retransmit_keeps_sn_and_payload_until_ack(connection):
    connection.queue.append(Outbound(LlId.START, b"payload", True))
    asyncio.run(connection.send(7, 1))
    asyncio.run(connection.send(14, 1000))
    assert (
        connection.radio.sent[0][2] == connection.radio.sent[1][2] == b"\x02\x07payload"
    )
    assert connection.retries == 1 and connection.tx_sn == 0
    connection.accept(b"\x01\x00", True)  # NESN=0: not acknowledged.
    assert connection.pending is not None and connection.tx_sn == 0
    connection.accept(b"\x0d\x00", True)  # NESN=1, new SN=1.
    assert connection.pending is None and connection.tx_sn == 1
    completed = [
        event
        for event in connection.link.listener.controller.events
        if isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
    ]
    assert len(completed) == 1 and completed[0].num_completed_packets == [1]


def test_crc_error_cannot_acknowledge_outstanding_packet(connection):
    connection.queue.append(Outbound(LlId.START, b"test", True))
    asyncio.run(connection.send(7, 1))
    connection.accept(b"\x05\x00", False)
    assert connection.pending is not None and connection.tx_sn == 0


@pytest.mark.parametrize(
    "pb,llid", [(0, LlId.START), (1, LlId.CONTINUATION), (2, LlId.START)]
)
def test_acl_packet_boundaries(connection, pb, llid):
    connection.enqueue_acl(pb == 1, b"abc")
    assert connection.queue.pop() == Outbound(llid, b"abc", True)


@pytest.mark.parametrize('continuation', [False, True])
def test_empty_host_fragment_preserves_only_a_pending_start_boundary(
    connection, continuation
):
    connection.enqueue_acl(continuation, b'')
    assert not connection.queue
    assert connection.tx_start_pending == (not continuation)
    completed = connection.link.listener.controller.events[-1]
    assert isinstance(completed, hci.HCI_Number_Of_Completed_Packets_Event)
    assert completed.connection_handles == [connection.handle]
    assert completed.num_completed_packets == [1]
    connection.enqueue_acl(True, b'first bytes')
    assert connection.queue.pop() == Outbound(
        LlId.CONTINUATION if continuation else LlId.START, b'first bytes', True
    )
    assert not connection.tx_start_pending
    connection.enqueue_acl(True, b'next bytes')
    assert connection.queue.pop().llid == LlId.CONTINUATION


def test_empty_host_start_cannot_relabel_already_queued_or_control_data(connection):
    connection.enqueue_acl(False, b'older frame')
    connection.enqueue_acl(False, b'')
    connection.enqueue_control(bytes([ControlPdu.Opcode.LL_PING_REQ]))
    connection.enqueue_acl(True, b'new frame')
    assert [(item.llid, item.payload) for item in connection.queue] == [
        (LlId.START, b'older frame'),
        (LlId.CONTROL, bytes([ControlPdu.Opcode.LL_PING_REQ])),
        (LlId.START, b'new frame'),
    ]


def test_invalid_host_acl(connection):
    with pytest.raises(ValueError):
        connection.enqueue_acl(False, bytes(RADIO_HCI_ACL_BUFFER_SIZE + 1))


def test_local_termination_waits_for_ack(connection):
    connection.establish()
    connection.terminate(ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR)
    asyncio.run(connection.send(7, 1))
    connection.accept(b"\x01\x00", True)
    assert not connection.closed
    connection.accept(b"\x0d\x00", True)
    assert (
        connection.closed
        and connection.link.listener.controller.events[-1].reason
        == ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR
    )


def test_termination_deadline_is_not_restarted_by_valid_rx(connection):
    connection.establish()
    connection.radio.now_us = 100
    connection.terminate(ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR)
    deadline = 100 + PARAMETERS.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
    assert connection.termination_deadline_us == deadline
    connection.radio.now_us = 200
    connection.terminate(ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR)
    connection.accept(bytes([LlId.CONTINUATION, 0]), True)
    assert connection.last_rx_us == 200
    assert connection.termination_deadline_us == deadline
    connection.anchor_us = deadline + LL_CONN_INTERVAL_UNIT_US
    assert connection.next_operation_us == deadline
    connection.radio.now_us = deadline
    assert connection.check_timeout()
    assert (
        connection.link.listener.controller.events[-1].reason
        == ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR
    )


def test_earlier_software_timer_does_not_expire_termination(connection):
    connection.establish()
    connection.terminate(ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR)
    deadline = connection.termination_deadline_us
    connection.anchor_us = deadline + LL_CONN_INTERVAL_UNIT_US
    advance = connection.radio.advance_to_us

    async def timer_boundary(target):
        return await advance(min(target, 1000))

    connection.radio.advance_to_us = timer_boundary
    assert asyncio.run(connection.advance_to_us(deadline)) == 1000
    assert not connection.closed
    connection.radio.advance_to_us = advance
    assert asyncio.run(connection.advance_to_us(deadline)) == deadline
    assert connection.closed


def test_widened_rx_search_stops_at_supervision_deadline(connection):
    connection.establish()
    deadline = connection.supervision_deadline_us
    connection.anchor_us = deadline - 80
    asyncio.run(connection.advance_to_us(connection.anchor_us))
    assert connection.radio.now_us == deadline
    assert connection.closed


def test_supervision_timeout_uses_last_valid_rx(connection):
    connection.establish()
    connection.last_rx_us = 80
    connection.anchor_us = 1_100_000
    assert asyncio.run(connection.advance_to_us(1_000_080)) == 1_000_080
    assert (
        connection.closed
        and connection.link.listener.controller.events[-1].reason
        == ErrorCode.CONNECTION_TIMEOUT_ERROR
    )


@pytest.mark.asyncio
async def test_update_receive_window_survives_missed_events(connection, monkeypatch):
    connection.establish()
    connection.update_window = True
    original_rx = connection.last_rx_us
    windows = []

    async def miss(channel, until_us, **parameters):
        windows.append((connection.anchor_us, until_us, parameters['start_us']))
        connection.radio.now_us = until_us

    monkeypatch.setattr(connection, 'receive', miss)
    for _ in range(2):
        await connection.advance_to_us(connection.anchor_us)
        assert connection.update_window
        assert connection.last_rx_us == original_rx

    for anchor, until, start in windows:
        widening = window_widening(anchor - original_rx, connection.parameters.sca)
        assert start == anchor - widening
        assert until == (
            anchor
            + connection.parameters.window_size * LL_CONN_INTERVAL_UNIT_US
            + widening
            + connection.rx_phy.address_us
            - 1
        )


@pytest.mark.parametrize('established', [False, True])
def test_earlier_software_timer_does_not_expire_connection(connection, established):
    if established:
        connection.establish()
    deadline = 1_000_000 if established else 180_000
    connection.anchor_us = deadline + LL_CONN_INTERVAL_UNIT_US
    advance = connection.radio.advance_to_us

    async def timer_boundary(target):
        return await advance(min(target, 1000))

    connection.radio.advance_to_us = timer_boundary
    assert asyncio.run(connection.advance_to_us(deadline)) == 1000
    assert not connection.closed
    assert connection.link.connections[connection.handle] is connection
    connection.radio.advance_to_us = advance
    assert asyncio.run(connection.advance_to_us(deadline)) == deadline
    assert connection.closed


def test_first_connection_failure_is_not_a_disconnection(connection):
    connection.anchor_us = 200_000
    assert asyncio.run(connection.advance_to_us(180_000)) == 180_000
    event = connection.link.listener.controller.events[-1]
    assert isinstance(event, hci.HCI_LE_Enhanced_Connection_Complete_Event)
    assert event.status == ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR


def test_created_connection_is_reported_once_before_physical_establishment(connection):
    listener = connection.link.listener
    connection.report_created()
    assert not connection.established
    assert listener._connection(connection.handle) is connection
    connection.report_created()
    connection.establish()
    events = listener.controller.events
    assert (
        sum(
            isinstance(event, hci.HCI_LE_Enhanced_Connection_Complete_Event)
            for event in events
        )
        == 1
    )
    assert not any(
        isinstance(event, hci.HCI_LE_Channel_Selection_Algorithm_Event)
        for event in events
    )


def test_created_connection_failure_reports_disconnection(connection):
    connection.report_created()
    connection.anchor_us = 200_000
    asyncio.run(connection.advance_to_us(180_000))
    event = connection.link.listener.controller.events[-1]
    assert isinstance(event, hci.HCI_Disconnection_Complete_Event)
    assert event.status == ErrorCode.SUCCESS
    assert event.reason == ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR


def test_unknown_control_dispatch_never_echoes_its_own_response(connection):
    unknown_opcode = 0xFF  # Reserved opcode, not a supported control procedure.
    connection.control(bytes([unknown_opcode]))
    response = connection.queue.popleft()
    assert response == Outbound(
        LlId.CONTROL, bytes([ControlPdu.Opcode.LL_UNKNOWN_RSP, unknown_opcode])
    )
    connection.control(response.payload)
    assert not connection.queue and not connection.closed


@pytest.mark.parametrize('opcode,sender_role', LL_CONTROL_PDU_SENDER_ROLES.items())
@pytest.mark.parametrize('legal_sender', [False, True])
def test_control_role_dispatch_precedes_procedure_state(
    connection, monkeypatch, opcode, sender_role, legal_sender
):
    connection.role = hci.Role(1 - sender_role) if legal_sender else sender_role
    dispatched = []

    def encryption(payload):
        dispatched.append(payload)
        return True

    monkeypatch.setattr(connection.encryption, 'control', encryption)
    # Even a short payload must not reach encryption/procedure state in the wrong role.
    payload = bytes([opcode])
    connection.control(payload)
    if legal_sender:
        assert dispatched == [payload] and not connection.queue
    else:
        assert not dispatched
        assert list(connection.queue) == [
            Outbound(LlId.CONTROL, bytes([ControlPdu.Opcode.LL_UNKNOWN_RSP, opcode]))
        ]
    assert not connection.closed


def test_bad_crc_physical_reception_establishes_without_accepting_payload(connection):
    connection.report_created()
    connection.radio.incoming.append(
        Received(bytes([LlId.START, 3]) + b'abc', -45, 1300, 1404, False)
    )
    asyncio.run(connection.receive(7, 2000))
    assert connection.established and connection.rx_nesn == 0
    assert not any(
        isinstance(event, hci.HCI_AclDataPacket)
        for event in connection.link.listener.controller.events
    )


@pytest.mark.parametrize('more', [False, True])
def test_central_termination_ack_respects_md_event_boundary(connection, more):
    connection.role = hci.Role.CENTRAL
    connection.report_created()
    packet = bytes(
        [
            LlId.CONTROL | (PDU_DATA_MD_MASK if more else 0),
            2,
            ControlPdu.Opcode.LL_TERMINATE_IND,
            ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR,
        ]
    )
    connection.radio.incoming.append(Received(packet, -45, 1480, 1592, True))
    asyncio.run(connection.advance_to_us(LL_CONN_INTERVAL_UNIT_US))
    assert connection.closed == more
    assert len(connection.radio.sent) == (2 if more else 1)
    if not more:
        anchor = connection.anchor_us
        asyncio.run(connection.advance_to_us(anchor))
        assert connection.closed
        assert connection.radio.sent[-1][0] == anchor
    assert connection.radio.sent[-1][2][0] & PDU_DATA_NESN_MASK


def test_skipped_events_apply_the_instant_and_advance_csa1(connection):
    connection.role = hci.Role.CENTRAL
    connection.controls.accept_instant(
        InstantUpdate(1, channel_map=(1 << 2) | (1 << 8))
    )
    connection.radio.now_us = (
        connection.anchor_us
        + 2 * connection.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        + 1
    )
    connection.skip_missed_events()
    assert connection.event_counter == 3
    assert (
        connection.unmapped_channel
        == 3 * connection.parameters.hop % LL_DATA_CHANNEL_COUNT
    )
    assert connection.parameters.channel_map == (1 << 2) | (1 << 8)
    assert connection.controls.pending is None and not connection.radio.sent


@pytest.mark.asyncio
async def test_radio_conflict_skips_without_consuming_pending_acl(connection):
    connection.role = hci.Role.CENTRAL
    connection.enqueue_acl(False, b'keep until acknowledged')
    await connection.advance_to_us(
        connection.anchor_us + 100, radio_until_us=connection.anchor_us + 100
    )
    assert not connection.radio.sent and connection.event_counter == 1
    assert connection.queue[-1].payload == b'keep until acknowledged'


@pytest.mark.parametrize(
    'role,offset',
    [(hci.Role.CENTRAL, 4), (hci.Role.PERIPHERAL, 4), (hci.Role.PERIPHERAL, 1)],
)
def test_update_instant_rechecks_the_new_window_before_skipping(
    connection, role, offset
):
    connection.role = role
    connection.established = True
    old_anchor = connection.anchor_us
    parameters = replace(connection.parameters, window_size=3, window_offset=offset)
    connection.controls.accept_instant(InstantUpdate(1, parameters=parameters))
    connection.event_counter = 1
    connection.radio.now_us = old_anchor + 2 * LL_CONN_INTERVAL_UNIT_US
    connection.skip_missed_events()
    assert connection.controls.pending is None
    assert connection.event_counter == 1
    assert connection.anchor_us == old_anchor + offset * LL_CONN_INTERVAL_UNIT_US
    assert connection.update_window and not connection.radio.sent


@pytest.mark.parametrize('encrypted', [False, True])
def test_initial_exchange_does_not_reserve_a_maximum_size_ack(connection, encrypted):
    minimal_exchange = connection.next_exchange_us(max_rx=False)
    lengths = connection.controls.data_length
    lengths.local = lengths.remote = DataLengths(
        PDU_DATA_PAYLOAD_SIZE_MAX,
        PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US,
        PDU_DATA_PAYLOAD_SIZE_MAX,
        PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US,
    )
    connection.encryption.rx_enabled = encrypted
    assert connection.next_exchange_us(max_rx=False) == minimal_exchange
    assert connection.next_exchange_us() > minimal_exchange
