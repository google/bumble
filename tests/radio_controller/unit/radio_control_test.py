# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Deferred LL negotiations, collision ownership and wrapping instants."""

import struct
from dataclasses import replace

import pytest

from bumble import hci
from bumble.ll import (
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    LL_INSTANT_MIN_LISTENING_EVENTS,
    LL_RESPONSE_TIMEOUT_US,
    PDU_CONTROL_CONN_PARAM_OFFSET_COUNT,
    PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED,
    PDU_CONTROL_FEATURE_SET_SIZE,
    PDU_CONTROL_INSTANT_SIZE,
    ControlPdu,
)
from bumble.radio_controller.radio import (
    RADIO_INSTANT_PAST_THRESHOLD,
    RADIO_SUPPORTED_PHY_MASK,
    Phy,
)
from bumble.radio_controller.radio_control import (
    InstantUpdate,
    anchor_offset,
    preferred_interval,
    preferred_periodicity,
    valid_minimum_channels,
)

Opcode = ControlPdu.Opcode

ErrorCode = hci.HCI_ErrorCode

PROCEDURE_COLLISION = (
    ErrorCode.LMP_ERROR_TRANSACTION_COLLISION_OR_LL_PROCEDURE_COLLISION_ERROR
)


@pytest.fixture
def minimum_channel_connection(connection):
    connection.role = hci.Role.CENTRAL
    connection.parameters = replace(connection.parameters, channel_map=0x03)
    connection.controls.host_channel_map = connection.parameters.channel_map
    return connection


def connection_parameter_request(interval=24):
    return bytes([Opcode.LL_CONNECTION_PARAM_REQ]) + struct.pack(
        '<HHHHBH6H',
        interval,
        interval,
        0,
        100,
        0,
        0,
        *(
            [PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED]
            * PDU_CONTROL_CONN_PARAM_OFFSET_COUNT
        ),
    )


@pytest.mark.parametrize(
    'minimum,maximum,periodicity,selected',
    [
        (13, 19, 6, 18),
        (12, 18, 6, 12),
        (13, 17, 6, 13),
        (13, 19, 0, 13),
    ],
)
def test_preferred_interval_respects_accepted_bounds(
    minimum, maximum, periodicity, selected
):
    assert preferred_interval(minimum, maximum, periodicity) == selected


@pytest.mark.parametrize(
    'reference,instant,old_interval,interval,expected',
    [
        ((1, 1), 7, 24, 24, 1),
        ((1, 23), 7, 24, 24, 23),
        ((1, 1), 8, 24, 18, 13),
        ((LL_EVENT_COUNTER_MASK - 2, 1), 3, 24, 18, 1),
    ],
)
def test_preferred_anchor_uses_reference_counter_and_wrap(
    reference, instant, old_interval, interval, expected
):
    assert anchor_offset(reference, instant, old_interval, interval) == expected


def test_delayed_parameter_indication_recomputes_anchor_at_actual_instant(connection):
    connection.role = hci.Role.CENTRAL
    controls = connection.controls
    controls.request_update(18, 0, 300, reference=(connection.event_counter, 1))
    payload = connection.queue[-1].payload
    connection.event_counter += 1
    rewritten = controls.prepare(payload)
    _, offset, interval, _, _, instant = struct.unpack('<BHHHHH', rewritten[1:])
    assert interval == 18
    assert offset == (1 - instant * connection.parameters.interval) % interval
    assert controls.pending.parameters.window_offset == offset
    assert controls.pending.instant == instant


@pytest.mark.parametrize(
    'rx_phy,phys',
    [
        (Phy.LE_1M, hci.PhyBit.LE_1M),
        (Phy.LE_1M, hci.PhyBit.LE_2M),
        (Phy.LE_2M, hci.PhyBit.LE_2M),
        (Phy.LE_2M, hci.PhyBit.LE_CODED),
        (Phy.LE_CODED, hci.PhyBit.LE_CODED),
        (Phy.LE_CODED, hci.PhyBit.LE_1M),
        (Phy.LE_1M, RADIO_SUPPORTED_PHY_MASK),
    ],
)
def test_minimum_channels_apply_to_peripheral_transmit_phy(
    minimum_channel_connection, rx_phy, phys
):
    connection = minimum_channel_connection
    connection.rx_phy = rx_phy
    connection.tx_phy = Phy.LE_2M if rx_phy == Phy.LE_1M else Phy.LE_1M
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, phys, 4]))
    controls = connection.controls
    applies = bool(phys & (1 << (rx_phy - 1)))
    assert controls.peer_minimum_channel_phys == phys
    assert controls.peer_minimum_used_channels == 4
    assert controls.selected_channel_map() == (0x0F if applies else 0x03)
    assert bool(controls.pending) == applies
    if applies:
        assert controls.pending.channel_map == 0x0F
    else:
        assert not connection.queue
    assert connection.parameters.channel_map == 0x03
    assert not controls.deadline_us


@pytest.mark.parametrize('phys,minimum', [(0, 2), (8, 2), (1, 1), (1, 38)])
def test_invalid_minimum_channel_indication_preserves_state(
    minimum_channel_connection, phys, minimum
):
    connection = minimum_channel_connection
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, phys, minimum]))
    assert connection.queue[-1].payload == bytes(
        [Opcode.LL_UNKNOWN_RSP, Opcode.LL_MIN_USED_CHANNELS_IND]
    )
    assert not connection.controls.peer_minimum_channel_phys
    assert connection.controls.pending is None


def test_minimum_channel_rfu_bits_do_not_override_valid_phy(minimum_channel_connection):
    connection = minimum_channel_connection
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, 0x81, 4]))
    assert connection.controls.peer_minimum_channel_phys == hci.PhyBit.LE_1M
    assert connection.controls.pending.channel_map == 0x0F


def test_minimum_channel_policy_preserves_host_channels(minimum_channel_connection):
    controls = minimum_channel_connection.controls
    controls.host_channel_map = (1 << 5) | (1 << 8)
    controls.peer_minimum_channel_phys = hci.PhyBit.LE_1M
    controls.peer_minimum_used_channels = 4
    assert controls.selected_channel_map() == controls.host_channel_map | 0x03
    controls.peer_minimum_used_channels = LL_DATA_CHANNEL_COUNT
    assert controls.selected_channel_map() == LL_DATA_CHANNEL_MAP_ALL


def test_host_classification_respects_retained_minimum(minimum_channel_connection):
    connection = minimum_channel_connection
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_1M, 2]))
    connection.controls.peer_minimum_used_channels = 4
    classification = (1 << 5) | (1 << 8)
    connection.controls.request_channel_map(classification)
    assert connection.controls.host_channel_map == classification
    assert connection.controls.pending.channel_map == classification | 0x03
    assert connection.parameters.channel_map == 0x03


def test_minimum_channel_requirements_are_connection_local(minimum_channel_connection):
    from bumble.radio_controller.radio_connection import Connection

    first = minimum_channel_connection
    second = Connection(first.link, first.parameters, first.peer, hci.Role.CENTRAL, 0)
    first.link.connections[second.handle] = second
    first.control(
        bytes(
            [Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_1M, LL_DATA_CHANNEL_COUNT]
        )
    )
    assert first.controls.pending.channel_map == LL_DATA_CHANNEL_MAP_ALL
    assert not second.controls.peer_minimum_channel_phys
    assert second.controls.selected_channel_map() == 0x03
    assert second.controls.pending is None and not second.queue


def test_minimum_channels_wait_for_existing_instant(minimum_channel_connection):
    connection = minimum_channel_connection
    controls = connection.controls
    controls.request_update(40, 0, 100)
    payload = controls.prepare(connection.queue.popleft().payload)
    original = controls.pending
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_1M, 4]))
    assert controls.pending is original and not connection.queue
    controls.acknowledge(payload)
    connection.event_counter = original.instant
    controls.apply()
    assert connection.parameters.interval == 40
    assert connection.parameters.channel_map == 0x03
    assert controls.pending.channel_map == 0x0F
    assert controls.pending.instant != original.instant
    payload = controls.prepare(connection.queue.popleft().payload)
    controls.acknowledge(payload)
    connection.event_counter = controls.pending.instant
    controls.apply()
    assert connection.parameters.channel_map == 0x0F
    assert controls.pending is None and not connection.closed


def test_phy_update_rechecks_minimum_channels(minimum_channel_connection):
    connection = minimum_channel_connection
    controls = connection.controls
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_2M, 4]))
    assert controls.pending is None
    controls.pending = InstantUpdate(6, peripheral_tx_phy=Phy.LE_2M)
    connection.event_counter = 6
    controls.apply()
    assert connection.rx_phy == Phy.LE_2M
    assert controls.pending.channel_map == 0x0F
    assert connection.parameters.channel_map == 0x03


def test_latest_minimum_channel_indication_replaces_previous_requirement(
    minimum_channel_connection,
):
    connection = minimum_channel_connection
    controls = connection.controls
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_2M, 4]))
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_CODED, 5]))
    assert controls.peer_minimum_channel_phys == hci.PhyBit.LE_CODED
    assert controls.peer_minimum_used_channels == 5
    connection.rx_phy = Phy.LE_2M
    assert controls.selected_channel_map() == 0x03
    connection.rx_phy = Phy.LE_CODED
    assert controls.selected_channel_map() == 0x1F


@pytest.mark.parametrize('supported', [False, True])
def test_peripheral_minimum_channel_request_requires_peer_support(
    connection, supported
):
    connection.peer_features = (
        int(hci.LeFeatureMask.MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE)
        if supported
        else None
    )
    if supported:
        connection.controls.request_minimum_channels(
            hci.PhyBit.LE_1M, LL_DATA_CHANNEL_COUNT
        )
        assert connection.queue[-1].payload == bytes(
            [Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_1M, LL_DATA_CHANNEL_COUNT]
        )
        assert not connection.controls.deadline_us
    else:
        with pytest.raises(ValueError, match='negotiated peer support'):
            connection.controls.request_minimum_channels(
                hci.PhyBit.LE_1M, LL_DATA_CHANNEL_COUNT
            )
        assert not connection.queue


def test_minimum_channel_indication_is_peripheral_only(connection):
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_1M, 2]))
    assert connection.queue[-1].payload == bytes(
        [Opcode.LL_UNKNOWN_RSP, Opcode.LL_MIN_USED_CHANNELS_IND]
    )
    connection.role = hci.Role.CENTRAL
    with pytest.raises(ValueError, match='live Peripheral'):
        connection.controls.request_minimum_channels(hci.PhyBit.LE_1M, 2)


def test_minimum_channel_request_validates_local_capability_and_connection(connection):
    feature = hci.LeFeatureMask.MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE
    connection.peer_features = int(feature)
    for phys, minimum in ((0, 2), (1, 1), (1, 38), (8, 2)):
        with pytest.raises(ValueError, match='invalid PHY mask'):
            connection.controls.request_minimum_channels(phys, minimum)
    connection.link.features &= ~int(feature)
    with pytest.raises(ValueError, match='negotiated peer support'):
        connection.controls.request_minimum_channels(hci.PhyBit.LE_1M, 2)
    connection.role = hci.Role.CENTRAL
    connection.control(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, hci.PhyBit.LE_1M, 2]))
    assert connection.queue[-1].payload == bytes(
        [Opcode.LL_UNKNOWN_RSP, Opcode.LL_MIN_USED_CHANNELS_IND]
    )
    connection.queue.clear()
    connection.role = hci.Role.PERIPHERAL
    connection.closed = True
    with pytest.raises(ValueError, match='live Peripheral'):
        connection.controls.request_minimum_channels(hci.PhyBit.LE_1M, 2)
    assert not connection.queue


@pytest.mark.parametrize(
    'counter',
    [
        0,
        LL_EVENT_COUNTER_MASK - LL_INSTANT_MIN_LISTENING_EVENTS + 1,
        LL_EVENT_COUNTER_MASK,
    ],
)
def test_instant_wrap_and_no_early_map_application(connection, counter):
    connection.event_counter = counter
    instant = (counter + LL_INSTANT_MIN_LISTENING_EVENTS) & LL_EVENT_COUNTER_MASK
    connection.controls.accept_instant(InstantUpdate(instant, channel_map=3))
    for _ in range(LL_INSTANT_MIN_LISTENING_EVENTS):
        connection.controls.apply()
        assert connection.parameters.channel_map != 3
        connection.event_counter = (
            connection.event_counter + 1
        ) & LL_EVENT_COUNTER_MASK
    connection.controls.apply()
    assert connection.parameters.channel_map == 3
    assert connection.controls.pending is None


@pytest.mark.parametrize(
    'counter,instant',
    [
        (0, LL_EVENT_COUNTER_MASK),
        (1, 0),
        (LL_EVENT_COUNTER_MASK, LL_EVENT_COUNTER_MASK - 1),
        (0, RADIO_INSTANT_PAST_THRESHOLD),
    ],
)
def test_past_instant_disconnects(connection, counter, instant):
    connection.event_counter = counter
    connection.controls.accept_instant(InstantUpdate(instant, channel_map=3))
    assert connection.closed


def test_parameter_update_resets_supervision_at_new_window(connection):
    connection.establish()
    connection.anchor_us = 40_000
    parameters = replace(
        connection.parameters, interval=40, window_offset=2, timeout=200
    )
    connection.controls.accept_instant(InstantUpdate(1, parameters=parameters))
    connection.event_counter = 1
    connection.controls.apply()
    assert connection.anchor_us == connection.supervision_restart_us == 42_500
    assert (
        connection.last_rx_us == 0
    ), 'window widening still refers to the last real reception'
    assert connection.supervision_deadline_us == 42_500 + 200 * 10_000
    assert connection.parameters == parameters and connection.update_window
    assert connection.link.listener.controller.events[-1].connection_interval == 40


@pytest.mark.parametrize('role', [hci.Role.CENTRAL, hci.Role.PERIPHERAL])
def test_asymmetric_phy_direction(connection, role):
    connection.role = role
    connection.controls.accept_instant(
        InstantUpdate(0, central_tx_phy=Phy.LE_2M, peripheral_tx_phy=Phy.LE_CODED)
    )
    connection.controls.apply()
    assert (connection.tx_phy, connection.rx_phy) == (
        (2, 3) if role == hci.Role.CENTRAL else (3, 2)
    )


@pytest.mark.parametrize('local', [False, True])
def test_no_change_phy_has_no_instant(connection, local):
    if local:
        connection.controls.request_phy(1, 1)
    connection.controls.control(b'\x18\x00\x00\x00\x00')
    assert connection.controls.pending is None
    events = connection.link.listener.controller.events
    if local:
        assert events[-1].tx_phy == Phy.LE_1M
    else:
        assert events == []


@pytest.mark.parametrize('local', [False, True])
def test_coded_phy_update_uses_single_wire_bit_not_hci_enum(connection, local):
    connection.role = hci.Role.CENTRAL
    mask = int(hci.PhyBit.LE_CODED)
    if local:
        connection.controls.request_phy(mask, mask)
        opcode = Opcode.LL_PHY_RSP
    else:
        opcode = Opcode.LL_PHY_REQ
    connection.controls.control(bytes([opcode, mask, mask]))
    update = connection.queue[-1].payload
    assert update[0:3] == bytes([Opcode.LL_PHY_UPDATE_IND, mask, mask])
    pending = connection.controls.pending
    assert pending.central_tx_phy == pending.peripheral_tx_phy == Phy.LE_CODED


@pytest.mark.parametrize('local', [False, True])
def test_central_no_change_phy_completion_depends_on_host_request(connection, local):
    connection.role = hci.Role.CENTRAL
    mask = int(hci.PhyBit.LE_1M)
    if local:
        connection.controls.request_phy(mask, mask)
        opcode = Opcode.LL_PHY_RSP
    else:
        opcode = Opcode.LL_PHY_REQ
    connection.controls.control(bytes([opcode, mask, mask]))
    assert connection.queue[-1].payload == bytes([Opcode.LL_PHY_UPDATE_IND, 0, 0, 0, 0])
    events = connection.link.listener.controller.events
    assert not events and connection.controls.busy
    connection.controls.sent(connection.queue[-1].payload)
    assert bool(events) == local
    assert not connection.controls.phy_request_local and not connection.controls.busy


@pytest.mark.parametrize(
    'tx,rx,peer_tx,peer_rx,selected',
    [
        (
            hci.PhyBit.LE_1M,
            hci.PhyBit.LE_2M,
            hci.PhyBit.LE_2M,
            hci.PhyBit.LE_2M,
            (0, 0),
        ),
        # RFU bits do not turn a valid symmetric-only preference into asymmetry.
        (hci.PhyBit.LE_1M, hci.PhyBit.LE_2M, 0x82, 0x82, (0, 0)),
        (
            hci.PhyBit.LE_1M,
            hci.PhyBit.LE_2M,
            hci.PhyBit.LE_2M,
            hci.PhyBit.LE_1M | hci.PhyBit.LE_2M,
            (0, hci.PhyBit.LE_2M),
        ),
        (
            hci.PhyBit.LE_1M | hci.PhyBit.LE_2M,
            hci.PhyBit.LE_1M | hci.PhyBit.LE_2M,
            hci.PhyBit.LE_2M,
            hci.PhyBit.LE_2M,
            (hci.PhyBit.LE_2M, hci.PhyBit.LE_2M),
        ),
        (
            hci.PhyBit.LE_1M | hci.PhyBit.LE_CODED,
            hci.PhyBit.LE_1M | hci.PhyBit.LE_CODED,
            hci.PhyBit.LE_CODED,
            hci.PhyBit.LE_CODED,
            (hci.PhyBit.LE_CODED, hci.PhyBit.LE_CODED),
        ),
    ],
)
def test_symmetric_phy_selection_uses_both_directional_intersections(
    connection, tx, rx, peer_tx, peer_rx, selected
):
    connection.role = hci.Role.CENTRAL
    connection.controls.request_phy(int(tx), int(rx))
    connection.control(bytes([Opcode.LL_PHY_RSP, peer_tx, peer_rx]))
    assert connection.queue[-1].payload[1:3] == bytes(selected)


@pytest.mark.parametrize('central', [False, True])
def test_phy_response_timer_stops_at_indication_before_instant(connection, central):
    mask = int(hci.PhyBit.LE_2M)
    if central:
        connection.role = hci.Role.CENTRAL
        connection.controls.request_phy(mask, mask)
        connection.control(bytes([Opcode.LL_PHY_RSP, mask, mask]))
        assert connection.controls.deadline_us
        update = connection.controls.prepare(connection.queue[-1].payload)
        connection.controls.sent(update)
    else:
        connection.control(bytes([Opcode.LL_PHY_REQ, mask, mask]))
        assert connection.controls.deadline_us
        connection.control(bytes([Opcode.LL_PHY_UPDATE_IND, mask, mask, 10, 0]))
    assert connection.controls.deadline_us == 0
    assert connection.controls.pending is not None
    assert not connection.link.listener.controller.events
    connection.radio.now_us = LL_RESPONSE_TIMEOUT_US
    assert not connection.controls.check_timeout()


@pytest.mark.asyncio
async def test_zero_update_retransmission_cannot_finish_a_new_phy_request(connection):
    connection.role = hci.Role.CENTRAL
    mask = int(hci.PhyBit.LE_1M)
    connection.controls.request_phy(mask, mask)
    connection.control(bytes([Opcode.LL_PHY_RSP, mask, mask]))
    # Isolate the transmission callback from the already tested LL handshake.
    update = connection.queue.pop()
    connection.queue.clear()
    connection.queue.append(update)
    assert not connection.link.listener.controller.events
    await connection.send(7, 1)
    assert len(connection.link.listener.controller.events) == 1
    connection.controls.request_phy(int(hci.PhyBit.LE_2M), int(hci.PhyBit.LE_2M))
    await connection.send(
        7, connection.radio.earliest_start_us(7, connection.tx_phy, transmit=True)
    )
    assert connection.controls.phy_request and connection.controls.phy_request_local
    assert connection.controls.deadline_us
    assert len(connection.link.listener.controller.events) == 1


@pytest.mark.parametrize('role', [hci.Role.CENTRAL, hci.Role.PERIPHERAL])
def test_phy_preference_rfu_bits_do_not_reject_supported_request(connection, role):
    connection.role = role
    connection.controls.control(bytes([Opcode.LL_PHY_REQ, 0xFF, 0xFF]))
    if role == hci.Role.CENTRAL:
        # Core Vol 6, Part B, 5.1.10: the Central sends UPDATE_IND, never PHY_RSP.
        expected = bytes([Opcode.LL_PHY_UPDATE_IND, 0, 0, 0, 0])
    else:
        supported = int(hci.PhyBit.LE_1M | hci.PhyBit.LE_2M | hci.PhyBit.LE_CODED)
        expected = bytes([Opcode.LL_PHY_RSP, supported, supported])
    assert [item.payload for item in connection.queue] == [expected]


def test_received_coded_wire_bit_becomes_directional_hci_enum(connection):
    connection.controls.control(
        bytes(
            [
                Opcode.LL_PHY_UPDATE_IND,
                int(hci.PhyBit.LE_CODED),
                int(hci.PhyBit.LE_2M),
                0,
                0,
            ]
        )
    )
    assert (connection.tx_phy, connection.rx_phy) == (Phy.LE_2M, Phy.LE_CODED)


@pytest.mark.parametrize(
    'opcode,payload',
    [
        (
            Opcode.LL_CONNECTION_UPDATE_IND,
            struct.pack('<BHHHHH', 1, 0, 5, 0, 100, 6),
        ),
        (Opcode.LL_CHANNEL_MAP_IND, bytes(5) + b'\x06\x00'),
    ],
)
def test_invalid_instant_payload_disconnects(connection, opcode, payload):
    connection.controls.control(bytes([opcode]) + payload)
    assert connection.closed


def test_busy_phy_request_is_rejected_without_overwriting_instant(connection):
    connection.role = hci.Role.CENTRAL
    update = InstantUpdate(6, channel_map=3)
    connection.controls.pending = update
    mask = int(hci.PhyBit.LE_2M)
    connection.controls.control(bytes([Opcode.LL_PHY_REQ, mask, mask]))
    assert connection.controls.pending == update
    assert connection.queue[-1].payload == bytes(
        [
            Opcode.LL_REJECT_EXT_IND,
            Opcode.LL_PHY_REQ,
            ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR,
        ]
    )


def test_deferred_phy_request_retains_local_timeout_and_original_stimulus(connection):
    controls = connection.controls
    mask = int(hci.PhyBit.LE_2M)
    request = bytes([Opcode.LL_PHY_REQ, mask, mask])
    controls.request_phy(mask, mask)
    deadline = controls.deadline_us
    controls.control(request)
    assert controls.remote_phy_request == request
    assert controls.deadline_us == deadline
    controls.control(bytes([Opcode.LL_PHY_REQ, int(hci.PhyBit.LE_CODED), mask]))
    assert controls.remote_phy_request == request
    assert controls.deadline_us == deadline
    controls.control(
        bytes(
            [
                Opcode.LL_REJECT_EXT_IND,
                Opcode.LL_CONNECTION_PARAM_REQ,
                ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR,
            ]
        )
    )
    assert controls.remote_phy_request == request and controls.phy_request_local
    connection.radio.now_us = deadline
    assert controls.check_timeout() and connection.closed


def test_rejected_phy_restarts_deferred_remote_response_timer(connection):
    controls = connection.controls
    mask = int(hci.PhyBit.LE_2M)
    controls.request_phy(mask, mask)
    controls.control(bytes([Opcode.LL_PHY_REQ, mask, mask]))
    connection.radio.now_us = 1000
    controls.control(
        bytes(
            [
                Opcode.LL_REJECT_EXT_IND,
                Opcode.LL_PHY_REQ,
                PROCEDURE_COLLISION,
            ]
        )
    )
    assert controls.remote_phy_request is None
    assert controls.phy_request and not controls.phy_request_local
    assert controls.deadline_us == connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
    connection.radio.now_us = controls.deadline_us
    assert controls.check_timeout() and connection.closed


@pytest.mark.parametrize('host_replied', [False, True])
def test_phy_rejection_keeps_remote_parameter_response_timer(connection, host_replied):
    controls = connection.controls
    mask = int(hci.PhyBit.LE_2M)
    controls.request_phy(mask, mask)
    controls.control(connection_parameter_request(30))
    connection.radio.now_us = 1000
    if host_replied:
        controls.reply_parameters(30, 30, 0, 100)
    deadline = controls.deadline_us
    controls.control(
        bytes(
            [
                Opcode.LL_REJECT_EXT_IND,
                Opcode.LL_PHY_REQ,
                ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR,
            ]
        )
    )
    assert controls.deadline_us == deadline
    connection.radio.now_us = deadline
    assert controls.check_timeout() and connection.closed


def test_ll_response_timeout_uses_simulated_time(connection):
    connection.controls.request_parameters(24, 24, 0, 100)
    connection.radio.now_us = LL_RESPONSE_TIMEOUT_US - 1
    connection.controls.apply()
    assert not connection.closed
    connection.radio.now_us = LL_RESPONSE_TIMEOUT_US
    connection.controls.apply()
    assert connection.closed


@pytest.mark.parametrize(
    'mask,current,expected', [(2, 1, 2), (4, 1, 3), (7, 1, 1), (0, 2, 2), (3, 3, 2)]
)
def test_phy_selection_prefers_current_then_2m(mask, current, expected):
    from bumble.radio_controller.radio_control import ControlProcedures

    assert ControlProcedures.choose_phy(mask, current) == expected


def test_buffered_control_assigns_instant_at_first_transmission(connection):
    connection.role = hci.Role.CENTRAL
    connection.controls.request_channel_map(3)
    payload = connection.queue.popleft().payload
    connection.event_counter = 40
    actual = connection.controls.prepare(payload)
    assert (
        int.from_bytes(actual[-PDU_CONTROL_INSTANT_SIZE:], 'little')
        == connection.event_counter + LL_INSTANT_MIN_LISTENING_EVENTS
    )
    connection.event_counter = 41
    assert connection.controls.prepare(actual) == actual


def test_local_update_without_ack_does_not_switch_channel_map(connection):
    connection.controls.request_channel_map(3)
    payload = connection.controls.prepare(connection.queue.popleft().payload)
    connection.event_counter = int.from_bytes(
        payload[-PDU_CONTROL_INSTANT_SIZE:], 'little'
    )
    connection.controls.apply()
    assert connection.closed and connection.parameters.channel_map != 3


def test_local_update_with_ack_switches_at_instant(connection):
    connection.controls.request_channel_map(3)
    payload = connection.controls.prepare(connection.queue.popleft().payload)
    connection.controls.acknowledge(payload)
    connection.event_counter = int.from_bytes(
        payload[-PDU_CONTROL_INSTANT_SIZE:], 'little'
    )
    connection.controls.apply()
    assert not connection.closed and connection.parameters.channel_map == 3


def test_current_instant_does_not_apply_old_transmit_window_offset(connection):
    parameters = replace(connection.parameters, interval=40, window_offset=2)
    old_anchor = connection.anchor_us
    connection.controls.accept_instant(
        InstantUpdate(connection.event_counter, parameters=parameters)
    )
    assert connection.parameters == parameters
    assert connection.anchor_us == old_anchor and not connection.update_window


@pytest.mark.parametrize('opcode', [Opcode.LL_CONNECTION_PARAM_REQ, Opcode.LL_PHY_REQ])
def test_remote_reject_finishes_local_request(connection, opcode):
    if opcode == Opcode.LL_CONNECTION_PARAM_REQ:
        connection.controls.request_parameters(24, 24, 0, 100)
    else:
        connection.controls.request_phy(2, 2)
    connection.controls.control(bytes([0x11, opcode, 0x3B]))
    assert not connection.controls.busy and connection.controls.deadline_us == 0
    assert (
        connection.link.listener.controller.events[-1].status
        == hci.HCI_ErrorCode.UNACCEPTABLE_CONNECTION_PARAMETERS_ERROR
    )


@pytest.mark.parametrize('role', [hci.Role.CENTRAL, hci.Role.PERIPHERAL])
def test_parameter_request_collides_with_map_without_overwriting_it(connection, role):
    connection.role = role
    update = InstantUpdate(6, channel_map=3)
    connection.controls.pending = update
    connection.controls.control(connection_parameter_request())
    assert connection.controls.pending is update
    assert connection.queue[-1].payload == bytes(
        [
            Opcode.LL_REJECT_EXT_IND,
            Opcode.LL_CONNECTION_PARAM_REQ,
            hci.HCI_ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR,
        ]
    )
    assert connection.controls.remote_parameters is None


def test_central_rejects_same_procedure_collision(connection):
    connection.role = hci.Role.CENTRAL
    connection.controls.request_parameters(24, 24, 0, 100)
    connection.controls.control(connection_parameter_request(30))
    assert connection.controls.parameter_request
    assert connection.controls.remote_parameters is None
    assert connection.queue[-1].payload == bytes(
        [
            Opcode.LL_REJECT_EXT_IND,
            Opcode.LL_CONNECTION_PARAM_REQ,
            PROCEDURE_COLLISION,
        ]
    )


@pytest.mark.parametrize('masked', [False, True])
def test_peripheral_preserves_central_request_until_local_rejection(connection, masked):
    controls = connection.controls
    controller = connection.link.listener.controller
    if masked:
        controller.le_event_mask &= ~(
            1 << (hci.HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_EVENT - 1)
        )
    controls.request_parameters(24, 24, 0, 100)
    request = connection_parameter_request(30)
    controls.control(request)
    assert controls.remote_parameters == request[1:]
    assert len(connection.queue) == 1
    assert controller.events == []
    connection.radio.now_us = 1000
    controls.control(
        bytes(
            [
                Opcode.LL_REJECT_EXT_IND,
                Opcode.LL_CONNECTION_PARAM_REQ,
                PROCEDURE_COLLISION,
            ]
        )
    )
    assert not controls.parameter_request
    failure = controller.events[0]
    assert isinstance(failure, hci.HCI_LE_Connection_Update_Complete_Event)
    assert failure.status == PROCEDURE_COLLISION
    if masked:
        assert len(controller.events) == 1
        assert controls.remote_parameters is None and controls.deadline_us == 0
        assert connection.queue[-1].payload == bytes(
            [
                Opcode.LL_REJECT_EXT_IND,
                Opcode.LL_CONNECTION_PARAM_REQ,
                hci.HCI_ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR,
            ]
        )
    else:
        event = controller.events[1]
        assert isinstance(event, hci.HCI_LE_Remote_Connection_Parameter_Request_Event)
        assert (
            event.connection_handle,
            event.interval_min,
            event.interval_max,
            event.max_latency,
            event.timeout,
        ) == (connection.handle, 30, 30, 0, 100)
        assert controls.remote_parameters == request[1:]
        assert controls.deadline_us == connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
        controls.reply_parameters(30, 30, 0, 100)
        assert controls.remote_parameters is None
        assert connection.queue[-1].payload[0] == Opcode.LL_CONNECTION_PARAM_RSP


def test_second_central_request_does_not_replace_deferred_request(connection):
    controls = connection.controls
    controls.request_parameters(24, 24, 0, 100)
    request = connection_parameter_request(30)
    controls.control(request)
    controls.control(connection_parameter_request(40))
    assert controls.remote_parameters == request[1:]
    assert connection.queue[-1].payload == bytes(
        [
            Opcode.LL_REJECT_EXT_IND,
            Opcode.LL_CONNECTION_PARAM_REQ,
            PROCEDURE_COLLISION,
        ]
    )


def test_unrelated_rejection_keeps_parameter_response_deadline(connection):
    controls = connection.controls
    controls.request_parameters(24, 24, 0, 100)
    deadline = controls.deadline_us
    controls.control(
        bytes(
            [
                Opcode.LL_REJECT_EXT_IND,
                Opcode.LL_PHY_REQ,
                hci.HCI_ErrorCode.UNACCEPTABLE_CONNECTION_PARAMETERS_ERROR,
            ]
        )
    )
    assert controls.parameter_request and controls.deadline_us == deadline


def test_parameter_rejection_preserves_pending_channel_map(connection):
    controls = connection.controls
    controls.request_parameters(24, 24, 0, 100)
    update = InstantUpdate(6, channel_map=3)
    controls.accept_instant(update)
    controls.control(
        bytes(
            [
                Opcode.LL_REJECT_EXT_IND,
                Opcode.LL_CONNECTION_PARAM_REQ,
                hci.HCI_ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR,
            ]
        )
    )
    assert controls.pending is update and not controls.parameter_request
    connection.event_counter = update.instant
    controls.apply()
    assert connection.parameters.channel_map == 3 and not connection.closed


def test_deferred_central_request_does_not_cancel_local_timeout(connection):
    controls = connection.controls
    controls.request_parameters(24, 24, 0, 100)
    deadline = controls.deadline_us
    controls.control(connection_parameter_request(30))
    assert controls.deadline_us == deadline
    connection.radio.now_us = deadline
    assert controls.check_timeout() and connection.closed


@pytest.mark.parametrize(
    'role,opcode',
    [
        (hci.Role.CENTRAL, Opcode.LL_FEATURE_REQ),
        (hci.Role.PERIPHERAL, Opcode.LL_PERIPHERAL_FEATURE_REQ),
    ],
)
def test_feature_query_uses_wire_response_and_then_cache(connection, role, opcode):
    connection.role = role
    connection.report_created()
    listener = connection.link.listener
    command = hci.HCI_LE_Read_Remote_Features_Command(connection.handle)
    listener.on_hci_le_read_remote_features_command(command)
    assert connection.queue.pop().payload == bytes(
        [opcode]
    ) + connection.link.features.to_bytes(PDU_CONTROL_FEATURE_SET_SIZE, 'little')
    listener.on_hci_le_read_remote_features_command(command)
    assert listener.controller.events[-1].status == ErrorCode.COMMAND_DISALLOWED_ERROR
    features = int(
        hci.LeFeatureMask.LE_2M_PHY
        | hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE
    )
    connection.control(
        bytes([Opcode.LL_FEATURE_RSP])
        + features.to_bytes(PDU_CONTROL_FEATURE_SET_SIZE, 'little')
    )
    event = listener.controller.events[-1]
    assert isinstance(event, hci.HCI_LE_Read_Remote_Features_Complete_Event)
    assert (
        event.status == ErrorCode.SUCCESS
        and int.from_bytes(event.le_features, 'little') == features
    )
    assert (
        not connection.controls.feature_request
        and not connection.controls.feature_deadline_us
    )
    listener.on_hci_le_read_remote_features_command(command)
    assert not connection.queue
    assert isinstance(
        listener.controller.events[-1], hci.HCI_LE_Read_Remote_Features_Complete_Event
    )


@pytest.mark.parametrize('disconnect', [False, True])
def test_feature_query_failure_completes_once(connection, disconnect):
    connection.report_created()
    connection.controls.request_features()
    if disconnect:
        connection.complete(ErrorCode.CONNECTION_TIMEOUT_ERROR)
    else:
        connection.radio.now_us = LL_RESPONSE_TIMEOUT_US
        assert connection.controls.check_timeout()
    events = [
        event
        for event in connection.link.listener.controller.events
        if isinstance(event, hci.HCI_LE_Read_Remote_Features_Complete_Event)
    ]
    assert len(events) == 1
    assert events[0].status == (
        ErrorCode.CONNECTION_TIMEOUT_ERROR
        if disconnect
        else ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR
    )


@pytest.mark.parametrize(
    'role,opcode',
    [
        (hci.Role.CENTRAL, Opcode.LL_FEATURE_REQ),
        (hci.Role.PERIPHERAL, Opcode.LL_PERIPHERAL_FEATURE_REQ),
    ],
)
def test_unknown_feature_request_reports_failure_without_answering_unknown_rsp(
    connection, role, opcode
):
    connection.role = role
    connection.report_created()
    connection.controls.request_features()
    connection.queue.clear()
    connection.control(bytes([Opcode.LL_UNKNOWN_RSP, opcode]))
    event = connection.link.listener.controller.events[-1]
    assert isinstance(event, hci.HCI_LE_Read_Remote_Features_Complete_Event)
    assert event.status == ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
    assert not connection.queue and not connection.controls.feature_request


@pytest.mark.parametrize('role', [hci.Role.CENTRAL, hci.Role.PERIPHERAL])
def test_version_query_owns_one_indication_and_caches_first_peer_tuple(
    connection, role
):
    connection.role = role
    connection.report_created()
    controls = connection.controls
    listener = connection.link.listener
    controller = listener.controller
    controller.lmp_version = hci.HCI_VERSION_BLUETOOTH_CORE_5_4
    controller.manufacturer_company_identifier = 0x0059
    controller.lmp_subversion = 0x1234
    command = hci.HCI_Read_Remote_Version_Information_Command(connection.handle)
    listener.on_hci_read_remote_version_information_command(command)
    assert connection.queue[0].payload == bytes([Opcode.LL_VERSION_IND]) + struct.pack(
        '<BHH', *listener.local_version
    )
    assert controls.version_deadline_us == LL_RESPONSE_TIMEOUT_US
    listener.on_hci_read_remote_version_information_command(command)
    assert controller.events[-1].status == ErrorCode.COMMAND_DISALLOWED_ERROR
    assert len(connection.queue) == 1
    peer = (hci.HCI_VERSION_BLUETOOTH_CORE_5_0, 0x1234, 0x5678)
    connection.control(bytes([Opcode.LL_VERSION_IND]) + struct.pack('<BHH', *peer))
    event = controller.events[-1]
    assert isinstance(event, hci.HCI_Read_Remote_Version_Information_Complete_Event)
    assert (event.version, event.manufacturer_name, event.subversion) == peer
    assert not controls.version_request and not controls.version_deadline_us
    assert len(connection.queue) == 1, 'peer collision queued a second local version'
    controller.events.clear()
    connection.queue.clear()
    connection.control(bytes([Opcode.LL_VERSION_IND]) + struct.pack('<BHH', 0, 0, 0))
    assert (
        controls.peer_version == peer and not connection.queue and not controller.events
    )
    listener.on_hci_read_remote_version_information_command(command)
    assert not connection.queue
    assert isinstance(
        controller.events[-1], hci.HCI_Read_Remote_Version_Information_Complete_Event
    )


@pytest.mark.parametrize('disconnect', [False, True])
def test_version_timeout_and_disconnect_have_distinct_completion_semantics(
    connection, disconnect
):
    connection.report_created()
    connection.controls.request_version()
    if disconnect:
        connection.complete(ErrorCode.CONNECTION_TIMEOUT_ERROR)
    else:
        connection.radio.now_us = LL_RESPONSE_TIMEOUT_US
        assert connection.controls.check_timeout()
    events = connection.link.listener.controller.events
    versions = [
        event
        for event in events
        if isinstance(event, hci.HCI_Read_Remote_Version_Information_Complete_Event)
    ]
    assert len(versions) == (0 if disconnect else 1)
    if versions:
        assert versions[0].status == ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR
        assert events.index(versions[0]) < len(events) - 1
    assert isinstance(events[-1], hci.HCI_Disconnection_Complete_Event)
    assert (
        not connection.controls.version_request
        and not connection.controls.version_deadline_us
    )
    assert not connection.controls.check_timeout()


def test_version_timer_does_not_replace_other_procedure_deadlines(connection):
    controls = connection.controls
    controls.request_features()
    first = controls.feature_deadline_us
    connection.radio.now_us = 1000
    controls.request_version()
    assert controls.version_deadline_us == first + 1000
    assert controls.next_deadline_us == first
    controls.finish_features(ErrorCode.SUCCESS)
    assert controls.next_deadline_us == first + 1000


@pytest.mark.parametrize('legacy', [False, True])
def test_central_parameter_rejection_falls_back_only_for_unsupported_peer(
    connection, legacy
):
    connection.role = hci.Role.CENTRAL
    connection.establish()
    controls = connection.controls
    controls.request_parameters(6, 6, 0, 300)
    connection.queue.clear()
    reason = (
        ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
        if legacy
        else ErrorCode.UNACCEPTABLE_CONNECTION_PARAMETERS_ERROR
    )
    controls.control(
        bytes([Opcode.LL_REJECT_EXT_IND, Opcode.LL_CONNECTION_PARAM_REQ, reason])
    )
    assert not controls.parameter_request
    if legacy:
        assert controls.pending is not None
        assert connection.queue[-1].payload[0] == Opcode.LL_CONNECTION_UPDATE_IND
        assert not any(
            isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
            for event in connection.link.listener.controller.events
        )
    else:
        assert controls.pending is None and not connection.queue
        assert connection.link.listener.controller.events[-1].status == reason


@pytest.mark.parametrize('known', [False, True])
@pytest.mark.parametrize('unsupported', [False, True])
def test_parameter_rejection_retains_only_learned_procedure_knowledge(
    connection, known, unsupported
):
    controls = connection.controls
    features = int(
        hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE
        | hci.LeFeatureMask.LE_2M_PHY
    )
    connection.peer_features = features if known else None
    assert controls.supports_parameter_request
    controls.request_parameters(24, 24, 0, 100)
    controls.reject_parameters(
        ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
        if unsupported
        else ErrorCode.UNACCEPTABLE_CONNECTION_PARAMETERS_ERROR
    )
    assert controls.supports_parameter_request is (not unsupported)
    assert not controls.parameter_request and controls.deadline_us == 0
    # Do not invent a zero peer feature set from a single UNKNOWN_RSP.
    assert connection.peer_features == (
        features & ~int(hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE)
        if known and unsupported
        else features if known else None
    )


@pytest.mark.parametrize(
    'minimum,maximum,preference,expected',
    [
        (18, 18, 6, 0),
        (13, 19, 0, 1),
        (13, 19, 6, 6),
        (13, 19, 20, 1),
    ],
)
def test_periodicity_prefers_peer_value_only_for_a_range(
    minimum, maximum, preference, expected
):
    assert preferred_periodicity(minimum, maximum, preference) == expected


@pytest.mark.parametrize(
    'phys,minimum,expected',
    [
        (1, 2, True),
        (7, 37, True),
        (0, 2, False),
        (8, 2, False),
        (9, 2, False),
        (1, 1, False),
        (1, 38, False),
    ],
)
def test_minimum_channel_argument_boundaries(phys, minimum, expected):
    assert valid_minimum_channels(phys, minimum) is expected
