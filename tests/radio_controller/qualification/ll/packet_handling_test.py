# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL.TS.p28, Section 4.7."""

import random
import struct

import pytest

from bumble import hci
from bumble.ll import (
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_DATA_CHANNEL_COUNT,
    LL_EVENT_COUNTER_MASK,
    LL_INSTANT_MIN_LISTENING_EVENTS,
    LL_RESPONSE_TIMEOUT_US,
    PDU_CONTROL_CONN_PARAM_OFFSET_COUNT,
    PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED,
    PDU_CONTROL_ENC_REQ_SIZE,
    PDU_CONTROL_ENC_RSP_SIZE,
    PDU_CONTROL_FEATURE_SET_SIZE,
    PDU_CONTROL_INSTANT_SIZE,
    PDU_CONTROL_OPCODE_SIZE,
    PDU_CONTROL_PAYLOAD_SIZE_INITIAL_MAX,
    PDU_CONTROL_REJECT_EXT_SIZE,
    PDU_CONTROL_REJECT_SIZE,
    PDU_CONTROL_UNKNOWN_RSP_SIZE,
    PDU_DATA_LLID_MASK,
    PDU_DATA_PAYLOAD_SIZE_MAX,
    PDU_DATA_PAYLOAD_SIZE_MIN,
    PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    PDU_DATA_PAYLOAD_TIME_MIN_US,
    PDU_HEADER_SIZE,
    LlId,
)
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.link import ErrorCode, Opcode
from tests.radio_controller.qualification.ll import connection_test as connection
from tests.radio_controller.qualification.ll import security_test as security
from tests.radio_controller.qualification.peer import establish, exchange_features
from tests.radio_controller.qualification.tester import (
    LOWER_CENTRAL_PUBLIC_ADDRESS,
    LOWER_DATA_ACCESS_ADDRESS,
    LOWER_PERIPHERAL_PUBLIC_ADDRESS,
    LinkParameters,
)

# Supported optional procedures exercised by the independent peer role matrix.
PEER_FEATURES = (
    hci.LeFeatureMask.LE_ENCRYPTION
    | hci.LeFeatureMask.LE_PING
    | hci.LeFeatureMask.LE_EXTENDED_ADVERTISING
    | hci.LeFeatureMask.LE_PERIODIC_ADVERTISING
    | hci.LeFeatureMask.CHANNEL_SELECTION_ALGORITHM_2
    | hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE
    | hci.LeFeatureMask.EXTENDED_REJECT_INDICATION
    | hci.LeFeatureMask.LE_2M_PHY
    | hci.LeFeatureMask.LE_CODED_PHY
    | hci.LeFeatureMask.LE_DATA_PACKET_LENGTH_EXTENSION
    | hci.LeFeatureMask.PERIPHERAL_INITIATED_FEATURE_EXCHANGE
    | hci.LeFeatureMask.MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE
)
# Source Correction: use a legal two-channel map instead of the common single bit.
COMMON_CHANNEL_MAP = 0x03

# Independent DUT declaration: the LE procedures implemented through Core 5.0.
SUPPORTED_CONTROLS = frozenset(
    {
        Opcode.LL_CONNECTION_UPDATE_IND,
        Opcode.LL_CHANNEL_MAP_IND,
        Opcode.LL_TERMINATE_IND,
        Opcode.LL_ENC_REQ,
        Opcode.LL_ENC_RSP,
        Opcode.LL_START_ENC_REQ,
        Opcode.LL_START_ENC_RSP,
        Opcode.LL_UNKNOWN_RSP,
        Opcode.LL_FEATURE_REQ,
        Opcode.LL_FEATURE_RSP,
        Opcode.LL_PAUSE_ENC_REQ,
        Opcode.LL_PAUSE_ENC_RSP,
        Opcode.LL_VERSION_IND,
        Opcode.LL_REJECT_IND,
        Opcode.LL_PERIPHERAL_FEATURE_REQ,
        Opcode.LL_CONNECTION_PARAM_REQ,
        Opcode.LL_CONNECTION_PARAM_RSP,
        Opcode.LL_REJECT_EXT_IND,
        Opcode.LL_PING_REQ,
        Opcode.LL_PING_RSP,
        Opcode.LL_LENGTH_REQ,
        Opcode.LL_LENGTH_RSP,
        Opcode.LL_PHY_REQ,
        Opcode.LL_PHY_RSP,
        Opcode.LL_PHY_UPDATE_IND,
        Opcode.LL_MIN_USED_CHANNELS_IND,
    }
)
# Core 6.3, Vol 6 Part B, 2.4.2.25-58: defined CtrData, capped at 26 octets
# by LL.TS.p28 4.7.3.1. Select the latest capability PDU format and 26-byte UTP.
UNSUPPORTED_CONTROL_DATA_LENGTHS = {
    Opcode.LL_CTE_REQ: 1,
    Opcode.LL_CTE_RSP: 0,
    Opcode.LL_PERIODIC_SYNC_IND: 26,
    Opcode.LL_CLOCK_ACCURACY_REQ: 1,
    Opcode.LL_CLOCK_ACCURACY_RSP: 1,
    Opcode.LL_CIS_REQ: 26,
    Opcode.LL_CIS_RSP: 8,
    Opcode.LL_CIS_IND: 15,
    Opcode.LL_CIS_TERMINATE_IND: 3,
    Opcode.LL_POWER_CONTROL_REQ: 3,
    Opcode.LL_POWER_CONTROL_RSP: 4,
    Opcode.LL_POWER_CHANGE_IND: 4,
    Opcode.LL_SUBRATE_REQ: 10,
    Opcode.LL_SUBRATE_IND: 10,
    Opcode.LL_CHANNEL_REPORTING_IND: 3,
    Opcode.LL_CHANNEL_STATUS_IND: 10,
    Opcode.LL_PERIODIC_SYNC_WR_IND: 26,
    Opcode.LL_FEATURE_EXT_REQ: 26,
    Opcode.LL_FEATURE_EXT_RSP: 26,
    Opcode.LL_CS_SEC_RSP: 20,
    Opcode.LL_CS_CAPABILITIES_REQ: 26,
    Opcode.LL_CS_CAPABILITIES_RSP: 26,
    Opcode.LL_CS_CONFIG_REQ: 26,
    Opcode.LL_CS_CONFIG_RSP: 1,
    Opcode.LL_CS_REQ: 26,
    Opcode.LL_CS_RSP: 21,
    Opcode.LL_CS_IND: 18,
    Opcode.LL_CS_TERMINATE_REQ: 4,
    Opcode.LL_CS_FAE_REQ: 0,
    Opcode.LL_CS_FAE_RSP: 26,
    Opcode.LL_CS_CHANNEL_MAP_IND: 12,
    Opcode.LL_CS_SEC_REQ: 20,
    Opcode.LL_CS_TERMINATE_RSP: 4,
    Opcode.LL_FRAME_SPACE_REQ: 7,
    Opcode.LL_FRAME_SPACE_RSP: 5,
    Opcode.LL_OTA_UTP_IND: 26,
    Opcode.LL_CONNECTION_RATE_REQ: 26,
    Opcode.LL_CONNECTION_RATE_IND: 14,
}

# LL.TS.p28 Table 4.7-4: valid CtrData size and permitted Step 6 alternatives.
# The Opcode octet is not part of CtrData; a=Unknown, b=Reject, c=normal, d=silent.
INVALID_LENGTH_CASES = {
    Opcode.LL_CONNECTION_UPDATE_IND: (struct.calcsize('<BHHHHH'), 'ad'),
    Opcode.LL_CHANNEL_MAP_IND: (LL_CHANNEL_MAP_SIZE + PDU_CONTROL_INSTANT_SIZE, 'ad'),
    Opcode.LL_TERMINATE_IND: (1, 'ad'),
    Opcode.LL_ENC_REQ: (PDU_CONTROL_ENC_REQ_SIZE - PDU_CONTROL_OPCODE_SIZE, 'abc'),
    Opcode.LL_ENC_RSP: (PDU_CONTROL_ENC_RSP_SIZE - PDU_CONTROL_OPCODE_SIZE, 'abd'),
    Opcode.LL_START_ENC_REQ: (0, 'abc'),
    Opcode.LL_START_ENC_RSP: (0, 'abd'),
    Opcode.LL_UNKNOWN_RSP: (1, 'ad'),
    Opcode.LL_FEATURE_REQ: (PDU_CONTROL_FEATURE_SET_SIZE, 'ac'),
    Opcode.LL_FEATURE_RSP: (PDU_CONTROL_FEATURE_SET_SIZE, 'ad'),
    Opcode.LL_PAUSE_ENC_REQ: (0, 'ac'),
    Opcode.LL_PAUSE_ENC_RSP: (0, 'ad'),
    Opcode.LL_VERSION_IND: (struct.calcsize('<BHH'), 'acd'),
    Opcode.LL_REJECT_IND: (1, 'ad'),
    Opcode.LL_PERIPHERAL_FEATURE_REQ: (PDU_CONTROL_FEATURE_SET_SIZE, 'ac'),
    Opcode.LL_CONNECTION_PARAM_REQ: (struct.calcsize('<HHHHBH6H'), 'ac'),
    Opcode.LL_CONNECTION_PARAM_RSP: (struct.calcsize('<HHHHBH6H'), 'abd'),
    Opcode.LL_REJECT_EXT_IND: (2, 'ad'),
    Opcode.LL_PING_REQ: (0, 'ac'),
    Opcode.LL_PING_RSP: (0, 'ad'),
    Opcode.LL_LENGTH_REQ: (struct.calcsize('<4H'), 'ac'),
    Opcode.LL_LENGTH_RSP: (struct.calcsize('<4H'), 'ad'),
    Opcode.LL_PHY_REQ: (2, 'abc'),
    Opcode.LL_PHY_RSP: (2, 'ad'),
    Opcode.LL_PHY_UPDATE_IND: (2 + PDU_CONTROL_INSTANT_SIZE, 'ad'),
    Opcode.LL_MIN_USED_CHANNELS_IND: (2, 'ad'),
}
# Section 4.7.3.3 requires six distinct invalid lengths per supported opcode.
INVALID_LENGTH_ROUNDS = 6
# Step 6d observes half of the 40-second LL procedure response timeout.
CONTROL_SILENCE_US = LL_RESPONSE_TIMEOUT_US // 2


def _invalid_lengths(valid, generator):
    maximum = PDU_CONTROL_PAYLOAD_SIZE_INITIAL_MAX - PDU_CONTROL_OPCODE_SIZE
    assert 0 <= valid <= maximum
    required = ([0, valid - 1] if valid else []) + (
        [valid + 1, maximum] if valid < maximum else []
    )
    lengths = list(dict.fromkeys(required))
    remaining = [
        size for size in range(maximum + 1) if size != valid and size not in lengths
    ]
    return lengths + generator.sample(remaining, INVALID_LENGTH_ROUNDS - len(lengths))


def _normal_opcodes(opcode, central):
    if opcode == Opcode.LL_CONNECTION_PARAM_REQ:
        return (
            (
                Opcode.LL_CONNECTION_UPDATE_IND
                if central
                else Opcode.LL_CONNECTION_PARAM_RSP
            ),
        )
    if opcode == Opcode.LL_PHY_REQ:
        return (Opcode.LL_PHY_UPDATE_IND if central else Opcode.LL_PHY_RSP,)
    return {
        Opcode.LL_ENC_REQ: (Opcode.LL_ENC_RSP,),
        Opcode.LL_START_ENC_REQ: (Opcode.LL_START_ENC_RSP,),
        Opcode.LL_FEATURE_REQ: (Opcode.LL_FEATURE_RSP,),
        Opcode.LL_PAUSE_ENC_REQ: (Opcode.LL_PAUSE_ENC_RSP,),
        Opcode.LL_VERSION_IND: (Opcode.LL_VERSION_IND,),
        Opcode.LL_PERIPHERAL_FEATURE_REQ: (Opcode.LL_FEATURE_RSP,),
        Opcode.LL_PING_REQ: (Opcode.LL_PING_RSP,),
        Opcode.LL_LENGTH_REQ: (Opcode.LL_LENGTH_RSP,),
    }.get(opcode, ())


def _invalid_length_result(opcode, payload, central):
    assert payload, 'empty LL Control response'
    options = INVALID_LENGTH_CASES[opcode][1]
    if payload[0] == Opcode.LL_UNKNOWN_RSP:
        _check_unknown_response(payload, opcode)
        return 'a'
    if payload[0] in (Opcode.LL_REJECT_IND, Opcode.LL_REJECT_EXT_IND):
        assert 'b' in options, 'Reject not permitted by Table 4.7-4 for this opcode'
        _check_role_rejection(payload, opcode)
        return 'b'
    assert 'c' in options, 'normal response not permitted by Table 4.7-4'
    assert payload[0] in _normal_opcodes(opcode, central), 'unrelated normal response'
    forbidden = {
        Opcode.LL_ENC_REQ: central,
        Opcode.LL_START_ENC_REQ: not central,
        Opcode.LL_FEATURE_REQ: central,
        Opcode.LL_PAUSE_ENC_REQ: central,
        Opcode.LL_PERIPHERAL_FEATURE_REQ: not central,
    }
    assert not forbidden.get(opcode, False), 'normal response in the wrong role'
    assert len(payload) == 1 + INVALID_LENGTH_CASES[Opcode(payload[0])][0]
    return 'c'


def _control_payload(packet):
    if packet is None:
        return None
    assert packet.valid_crc
    assert len(packet.pdu) >= PDU_HEADER_SIZE
    assert packet.pdu[1] == len(packet.pdu) - PDU_HEADER_SIZE
    if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
        assert packet.pdu[PDU_HEADER_SIZE:], 'empty LL Control PDU'
        return packet.pdu[PDU_HEADER_SIZE:]
    return None


def _disconnected(tester, handle):
    event = tester.take(
        lambda item: isinstance(item, hci.HCI_Disconnection_Complete_Event)
    )
    if event is not None:
        assert event.status == ErrorCode.SUCCESS and event.connection_handle == handle
    return event


async def _parameter_request(tester, link):
    event = tester.take(
        lambda item: isinstance(
            item, hci.HCI_LE_Remote_Connection_Parameter_Request_Event
        )
    )
    if event is None:
        return None
    assert event.connection_handle == link.handle
    fields = (event.interval_min, event.interval_max, event.max_latency, event.timeout)
    # Validate the Upper Tester's proposed reply with the independent LL checker.
    connection._check_parameter_pdu(
        bytes([Opcode.LL_CONNECTION_PARAM_RSP])
        + struct.pack(
            '<HHHHBH6H',
            *fields,
            0,
            0,
            *(
                [PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED]
                * PDU_CONTROL_CONN_PARAM_OFFSET_COUNT
            ),
        )
    )
    result = await tester.command(
        hci.HCI_LE_Remote_Connection_Parameter_Request_Reply_Command(
            link.handle, *fields, 0, 0
        )
    )
    assert result.connection_handle == link.handle
    return fields


async def _invalid_observation(tester, link, opcode, payload):
    previous = link.last_sent_end_us
    packet = await link.exchange(payload, llid=LlId.CONTROL, required=False)
    assert link.last_sent_end_us != previous, 'no RF rendezvous for the stimulus'
    duration = (
        CONTROL_SILENCE_US
        if 'd' in INVALID_LENGTH_CASES[opcode][1]
        else LL_RESPONSE_TIMEOUT_US
    )
    deadline = link.last_sent_end_us + duration
    accepted = None
    while True:
        if (control := _control_payload(packet)) is not None:
            return control, accepted, None
        disconnected = _disconnected(tester, link.handle)
        if disconnected is not None and opcode == Opcode.LL_TERMINATE_IND:
            return None, accepted, disconnected
        if disconnected is not None:
            # Preserve evidence until the full silence period and Ping check.
            tester.events.append(disconnected)
        if tester.radio.now_us >= deadline:
            assert (
                'd' in INVALID_LENGTH_CASES[opcode][1]
            ), 'required control response absent'
            return None, accepted, None
        if opcode == Opcode.LL_CONNECTION_PARAM_REQ:
            if (parameters := await _parameter_request(tester, link)) is not None:
                assert accepted is None, 'duplicate Host parameter request'
                accepted = parameters
        packet = await link.exchange(required=False)


async def _ping_after_silence(tester, link, opcode):
    ping = bytes([Opcode.LL_PING_REQ])
    deadline = tester.radio.now_us + LL_RESPONSE_TIMEOUT_US
    packet = await link.exchange(ping, llid=LlId.CONTROL, required=False)
    if link.central:
        # This Central packet preceded the Lower Tester's Ping on the wire.
        if (late := _control_payload(packet)) is not None:
            outcome = _invalid_length_result(opcode, late, link.central)
            if outcome == 'c':
                assert opcode == Opcode.LL_VERSION_IND
                await _check_version(tester, late)
        packet = await link.exchange(required=False)
    received_data = packet is not None
    while tester.radio.now_us < deadline:
        if (payload := _control_payload(packet)) is not None:
            assert payload == bytes([Opcode.LL_PING_RSP]) or payload == bytes(
                [Opcode.LL_UNKNOWN_RSP, Opcode.LL_PING_REQ]
            ), 'invalid response to the Step 8 Ping'
            await link.exchange(required=False)
            return
        if (event := _disconnected(tester, link.handle)) is not None:
            pytest.skip(
                f'Inconclusive: Step 8 connection breakdown, reason {event.reason:#x}'
            )
        packet = await link.exchange(required=False)
        received_data |= packet is not None
    if not received_data:
        pytest.skip(
            'Inconclusive: Step 8 Ping cannot maintain the original RF connection'
        )
    raise AssertionError(
        'Step 8 Ping response absent while the RF connection remains active'
    )


async def _check_version(tester, response):
    local = await tester.command(hci.HCI_Read_Local_Version_Information_Command())
    assert response == bytes([Opcode.LL_VERSION_IND]) + struct.pack(
        '<BHH', local.lmp_version, local.company_identifier, local.lmp_subversion
    )


async def _complete_phy_response(tester, link, response):
    mask = int(hci.PhyBit.LE_1M | hci.PhyBit.LE_2M | hci.PhyBit.LE_CODED)
    if link.central:
        update = response
        allowed = (mask, mask)
        if any(update[1:3]):
            _check_future_instant(link, update)
    else:
        tx, rx = response[1:]
        assert tx and rx and not (tx | rx) & ~mask
        central = 0 if rx & (1 << (link.tx_phy - 1)) else rx & -rx
        peripheral = 0 if tx & (1 << (link.rx_phy - 1)) else tx & -tx
        update = connection._update_pdu(link, central, peripheral)
        allowed = (rx, tx)
        await link.exchange(update, llid=LlId.CONTROL)
    await connection._finish_update(
        tester, link, update, event_required=False, allowed=allowed
    )


async def _complete_parameter_response(tester, link, response, accepted):
    if link.central:
        update = response
        interval, timeout = connection._check_parameter_choice(update, accepted)
        _check_future_instant(link, update)
    else:
        fields = connection._check_parameter_pdu(response)
        interval = connection._select_peer_interval(*fields[:2], fields[4])
        timeout = fields[3]
        update = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + struct.pack(
            '<BHHHHH',
            LL_CONN_WINDOW_SIZE_MIN,
            0,
            interval,
            fields[2],
            timeout,
            (link.counter + LL_INSTANT_MIN_LISTENING_EVENTS) & LL_EVENT_COUNTER_MASK,
        )
        await link.exchange(update, llid=LlId.CONTROL)
    await connection._check_parameter_update(tester, link, update, interval, timeout)


def _check_future_instant(link, payload):
    instant = int.from_bytes(payload[-PDU_CONTROL_INSTANT_SIZE:], 'little')
    # exchange() has already advanced the counter beyond the received event.
    distance = (instant - (link.counter - 1)) & LL_EVENT_COUNTER_MASK
    assert LL_INSTANT_MIN_LISTENING_EVENTS <= distance <= LL_EVENT_COUNTER_MASK // 2


async def _complete_encryption_response(tester, link, stimulus, response):
    if stimulus[0] == Opcode.LL_START_ENC_REQ:
        raise AssertionError('START_ENC_RSP without a pending encryption procedure')
    if stimulus[0] == Opcode.LL_PAUSE_ENC_REQ:
        assert not link.central and getattr(
            link, 'tx_enabled', False
        ), 'Pause Encryption response without an encrypted connection'
        # Acknowledge the encrypted pause reply before switching to plaintext.
        await link.exchange()
        link.tx_enabled = link.rx_enabled = False
        await link.exchange(bytes([Opcode.LL_PAUSE_ENC_RSP]), llid=LlId.CONTROL)
        await security._begin(tester, link, refresh=True)
        await security._finish(tester, link, refresh=True)
        return link
    assert not link.central
    assert not getattr(link, 'tx_enabled', False), 'ENC_REQ before encryption pause'
    if len(stimulus) < PDU_CONTROL_ENC_REQ_SIZE:
        pytest.skip(
            'Source ambiguity: IUT interpreted a truncated ENC_REQ; Core 2.4.2 '
            'does not define the repaired SKD/IV, so the Lower Tester cannot '
            'derive the negotiated session without assuming a padding rule'
        )
    event = await tester.event(hci.HCI_LE_Long_Term_Key_Request_Event)
    assert event.connection_handle == link.handle
    assert event.random_number == stimulus[1:9]
    assert event.encryption_diversifier == int.from_bytes(stimulus[9:11], 'little')
    link = security._SecurityPeer(link)
    link.rand = stimulus[1:9]
    link.ediv = int.from_bytes(stimulus[9:11], 'little')
    link.install(stimulus[11:19] + response[1:9], stimulus[19:23] + response[9:13])
    await security._finish(tester, link)
    return link


async def _complete_normal_control(tester, link, stimulus, response, accepted):
    opcode = Opcode(stimulus[0])
    if opcode in (Opcode.LL_ENC_REQ, Opcode.LL_START_ENC_REQ, Opcode.LL_PAUSE_ENC_REQ):
        return await _complete_encryption_response(tester, link, stimulus, response)
    if opcode in (Opcode.LL_FEATURE_REQ, Opcode.LL_PERIPHERAL_FEATURE_REQ):
        assert not int.from_bytes(response[1:], 'little') & ~int(PEER_FEATURES)
    elif opcode == Opcode.LL_VERSION_IND:
        await _check_version(tester, response)
    elif opcode == Opcode.LL_LENGTH_REQ:
        rx, rx_time, tx, tx_time = struct.unpack('<4H', response[1:])
        assert all(
            PDU_DATA_PAYLOAD_SIZE_MIN <= size <= PDU_DATA_PAYLOAD_SIZE_MAX
            for size in (rx, tx)
        )
        assert all(
            PDU_DATA_PAYLOAD_TIME_MIN_US <= time <= PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
            for time in (rx_time, tx_time)
        )
        while (
            event := tester.take(
                lambda item: isinstance(item, hci.HCI_LE_Data_Length_Change_Event)
            )
        ) is not None:
            assert event.connection_handle == link.handle
            assert all(
                PDU_DATA_PAYLOAD_SIZE_MIN <= value <= PDU_DATA_PAYLOAD_SIZE_MAX
                for value in (event.max_tx_octets, event.max_rx_octets)
            )
            assert all(
                PDU_DATA_PAYLOAD_TIME_MIN_US
                <= value
                <= PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
                for value in (event.max_tx_time, event.max_rx_time)
            )
    elif opcode == Opcode.LL_PHY_REQ:
        await _complete_phy_response(tester, link, response)
        return link
    elif opcode == Opcode.LL_CONNECTION_PARAM_REQ:
        await _complete_parameter_response(tester, link, response, accepted)
        return link
    else:
        assert opcode == Opcode.LL_PING_REQ
    await link.exchange()
    return link


async def control_pdus_with_invalid_length(tester, *, central):
    """Control PDUs with Invalid Length.

    Initial Condition:
        Connected Central or Peripheral as specified in Table 4.7-3, arbitrary
        advertising parameters and supported own address, common connection
        interval, zero latency, timeout, channel map and any SCA. Select public
        addresses, 10-ms interval, 300-ms timeout and the corrected two-channel
        common map. Complete the optional-feature exchange preamble.

    Test Steps:
        1. Execute Steps 2-9 for each independently declared supported opcode.
        2. If its valid CtrData length exceeds zero, test zero and valid-minus-one.
        3. If its valid CtrData length is below 26, test valid-plus-one and 26.
        4. Add reproducibly randomized, unique invalid CtrData lengths until
           exactly six different lengths have been tested for that opcode.
           Overlapping boundary selections count only once.
        5. Send the control PDU with that opcode and random CtrData octets of
           the selected invalid length. Preserve correct outer DATA framing.
        6. Enforce that opcode's alternatives from Table 4.7-4:
           a. LL_UNKNOWN_RSP with UnknownType equal to the injected opcode.
           b. LL_REJECT_IND, or LL_REJECT_EXT_IND naming the injected opcode,
              with a defined non-success error; only when the table permits b.
           c. A normal response with the correct opcode, length, valid fields
              and role/state, only when the table permits c.
           d. No LL Control PDU for at least twenty seconds, only when the
              table permits d; maintain DATA and acknowledgement traffic.
        7. On c, complete the actual procedure. Acknowledge stateless replies;
           complete PHY/parameter instants and their HCI results. Supply the
           LTK and complete encryption when ENC_RSP is returned; complete
           pause/restart when an encrypted connection accepts PAUSE_ENC_REQ.
        8. On d, send LL_PING_REQ and require LL_PING_RSP or LL_UNKNOWN_RSP
           naming Ping. A subsequent breakdown of the original RF connection
           can make the result Inconclusive, not Pass.
        9. If the malformed LL_TERMINATE_IND caused the IUT to exit connection
           state, check the HCI disconnection and re-establish the connection
           before the next invalid-length trial.

    Expected Outcome:
        Pass verdict:
            Every opcode/length pair follows its Table 4.7-4 alternatives.
            Normal responses have valid parameters and finish their procedures;
            unknown/extended-reject responses name the correct injected opcode.
            Twenty-second silence is not accepted as a response for other rows.
            A valid Ping response is required after the silence alternative.
        Inconclusive verdict:
            Step 8 cannot maintain the connection, including incompatible RF
            channel map, interval or PHY after interpreting the malformed input.

    Coverage Note:
        Current DUT size checks do not repair malformed control data, so its
        normal connected state needs no invented encryption preamble to force c.
        If an IUT does interpret a truncated ENC_REQ, Core does not define its
        repaired SKD/IV. Without those values a session cannot be reconstructed;
        report this source ambiguity explicitly rather than assuming padding.
        Observe silence through actual connection events, not a fixed RF poll.
        A Central packet received before the Lower Tester transmits Ping is not
        evidence of a response to that Ping. All 26 supported opcodes receive
        six distinct stimuli per role; unit vectors are not additional cases.

    Observation Limits:
        Use the source's twenty-second window for d. Where d is not permitted,
        and for the subsequent Ping, bound response observation by the normal
        LL procedure response timeout. Missing Ping responses on an otherwise
        active RF connection fail rather than being hidden as Inconclusive.

    Reference:
        LL.TS.p28.pdf, Section 4.7.3.3, LL/PAC/CEN/BI-01-C and LL/PAC/PER/BI-01-C;
        Tables 4.7-3/4, Figure 4.7-3, Steps 1-9 and pass/inconclusive verdicts;
        PDF 1173-1176, printed 4.7-5..8. Source [3] 2.4.2/2.4.2.8.
        Core Vol 6 Part B 2.4.2 permits implementation-specific interpretation,
        but does not specify repaired values for missing input fields.
    """
    assert set(INVALID_LENGTH_CASES) == SUPPORTED_CONTROLS
    generator = random.Random(0)
    link = await _packet_connection(tester, central)
    for opcode in sorted(SUPPORTED_CONTROLS):
        for size in _invalid_lengths(INVALID_LENGTH_CASES[opcode][0], generator):
            payload = bytes([opcode]) + generator.randbytes(size)
            tester.output.write(f'INVALID_LENGTH {opcode.name} CtrData={size}\n')
            response, accepted, disconnected = await _invalid_observation(
                tester, link, opcode, payload
            )
            if disconnected is not None:
                tester.output.write('OUTCOME 9 reconnect after malformed TERMINATE\n')
                link = await _packet_connection(tester, central)
                continue
            if response is None:
                tester.output.write('OUTCOME 6d: twenty-second control silence\n')
                await _ping_after_silence(tester, link, opcode)
            else:
                outcome = _invalid_length_result(opcode, response, central)
                tester.output.write(f'OUTCOME 6{outcome}: {response.hex()}\n')
                if outcome == 'c':
                    link = await _complete_normal_control(
                        tester, link, payload, response, accepted
                    )
                else:
                    await link.exchange()
    await link.disconnect(local=False)


def _check_unknown_response(payload, rejected_opcode):
    assert len(payload) == PDU_CONTROL_UNKNOWN_RSP_SIZE
    assert payload == bytes([Opcode.LL_UNKNOWN_RSP, rejected_opcode])


async def _packet_connection(tester, central):
    if central:
        await tester.command(
            hci.HCI_LE_Set_Host_Channel_Classification_Command(
                COMMON_CHANNEL_MAP.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
            )
        )
    link = await establish(
        tester,
        central=central,
        interval=8,
        timeout=30,
        connection_parameters=LinkParameters(
            access_address=LOWER_DATA_ACCESS_ADDRESS,
            interval=8,
            timeout=30,
            channel_map=COMMON_CHANNEL_MAP,
        ),
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    assert link.parameters.channel_map == COMMON_CHANNEL_MAP
    await exchange_features(link, PEER_FEATURES)
    await link.exchange()
    return link


async def unknown_control_pdus(tester, *, central):
    """Unknown Control PDUs.

    Initial Condition:
        Connected Central or Peripheral as selected by Table 4.7-1. Use public
        addresses, arbitrary advertising parameters, the common 10-ms interval,
        zero latency, 300-ms timeout and corrected common two-channel map.
        SUPPORTED_CONTROLS independently declares the DUT's implemented opcodes;
        it is not obtained from Controller dispatch code.

    Test Steps:
        1. Repeat Steps 2-3 for every opcode outside SUPPORTED_CONTROLS.
           Known unsupported PDUs carry their Core 6.3 CtrData length, truncated
           to 26 octets if longer. Reserved opcodes have no defined CtrData.
        2. Receive an IUT DATA PDU and send the current unknown control PDU.
        3. Require LL_UNKNOWN_RSP with UnknownType equal to that opcode.
        4. The Lower Tester sends LL_TERMINATE_IND and disconnects the IUT.

    Expected Outcome:
        Pass verdict:
            Each unsupported or unused opcode produces exactly the unknown
            response with matching UnknownType; the maintained connection
            acknowledges the exchanges and is terminated by the Lower Tester.

    Source Correction:
        Step 3's non-success error code is not a field in LL_UNKNOWN_RSP.
        Follow its pass verdict and Core Vol 6 Part B 2.4.2.8: the only CtrData
        field is UnknownType. Do not accept an arbitrary reject response.

    Coverage Note:
        Enumerate all 256 opcode values, excluding the independent supported
        set. Select the latest defined format for versioned unsupported PDUs;
        raw lower-tester fields are zero-filled because unsupported opcodes
        must not be interpreted. Receive a response within a selected sixteen
        connection-event observation budget, then acknowledge it before the
        next stimulus. This budget is not a normative response-time limit.

    Reference:
        LL.TS.p28.pdf, 4.7.3.1, LL/PAC/CEN/BV-01-C and LL/PAC/PER/BV-01-C,
        Table 4.7-1, Figure 4.7-1, Steps 1-4; PDF 1170-1171,
        printed 4.7-2..3. Source [3] 2.4.2/2.4.2.8.
        Core 6.3 Vol 6 Part B Table 2.22 and 2.4.2.25-58 define the
        known-but-unsupported formats independently of this DUT.
    """
    link = await _packet_connection(tester, central)
    for opcode in range(1 << (8 * PDU_CONTROL_OPCODE_SIZE)):
        if opcode in SUPPORTED_CONTROLS:
            continue
        payload = bytes([opcode]) + bytes(
            UNSUPPORTED_CONTROL_DATA_LENGTHS.get(opcode, 0)
        )
        tester.output.write(f'UNKNOWN OPCODE 0x{opcode:02x} DATA {len(payload)-1}\n')
        packet = await link.exchange(payload, llid=LlId.CONTROL, check_ack=True)
        for _ in range(16):
            if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
                _check_unknown_response(packet.pdu[PDU_HEADER_SIZE:], opcode)
                break
            packet = await link.exchange()
        else:
            raise AssertionError(f'no LL_UNKNOWN_RSP for opcode 0x{opcode:02x}')
        await link.exchange()
    await link.disconnect(local=False)


def _check_role_rejection(payload, rejected_opcode):
    """Check the three permitted rejection forms, not merely any LL response."""
    assert payload, 'empty LL Control response'
    if payload[0] == Opcode.LL_UNKNOWN_RSP:
        assert len(payload) == PDU_CONTROL_UNKNOWN_RSP_SIZE
        assert payload[1] == rejected_opcode
        return
    if payload[0] == Opcode.LL_REJECT_EXT_IND:
        assert len(payload) == PDU_CONTROL_REJECT_EXT_SIZE
        assert payload[1] == rejected_opcode
    else:
        assert payload[0] == Opcode.LL_REJECT_IND
        assert len(payload) == PDU_CONTROL_REJECT_SIZE
    assert payload[-1] in tuple(ErrorCode) and payload[-1] not in (
        ErrorCode.SUCCESS,
        ErrorCode.RESERVED_FOR_FUTURE_USE,
    )


def _forbidden_controls(link):
    """Independent role matrix for the DUT's implemented control-PDU features."""
    if not link.central:
        return (
            (
                Opcode.LL_ENC_RSP,
                bytes(PDU_CONTROL_ENC_RSP_SIZE - PDU_CONTROL_OPCODE_SIZE),
            ),
            (Opcode.LL_START_ENC_REQ, b''),
            (Opcode.LL_PERIPHERAL_FEATURE_REQ, bytes(PDU_CONTROL_FEATURE_SET_SIZE)),
            (Opcode.LL_PHY_RSP, bytes([hci.PhyBit.LE_1M, hci.PhyBit.LE_1M])),
            (
                Opcode.LL_MIN_USED_CHANNELS_IND,
                bytes([hci.PhyBit.LE_1M, LL_DATA_CHANNEL_COUNT]),
            ),
        )
    parameters = link.parameters
    instant = link.counter + LL_INSTANT_MIN_LISTENING_EVENTS & LL_EVENT_COUNTER_MASK
    return (
        (
            Opcode.LL_CONNECTION_UPDATE_IND,
            struct.pack(
                '<BHHHHH',
                LL_CONN_WINDOW_SIZE_MIN,
                0,
                parameters.interval,
                0,
                parameters.timeout,
                instant,
            ),
        ),
        (
            Opcode.LL_CHANNEL_MAP_IND,
            parameters.channel_map.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
            + instant.to_bytes(PDU_CONTROL_INSTANT_SIZE, 'little'),
        ),
        (Opcode.LL_ENC_REQ, bytes(PDU_CONTROL_ENC_REQ_SIZE - PDU_CONTROL_OPCODE_SIZE)),
        (Opcode.LL_FEATURE_REQ, bytes(PDU_CONTROL_FEATURE_SET_SIZE)),
        (Opcode.LL_PAUSE_ENC_REQ, b''),
        (
            Opcode.LL_PHY_UPDATE_IND,
            struct.pack('<BBH', hci.PhyBit.LE_1M, hci.PhyBit.LE_1M, instant),
        ),
    )


async def control_pdus_not_permitted_in_the_current_role(tester, *, central):
    """Control PDUs not permitted in the current role.

    Initial Condition:
        IUT: connected Central or Peripheral as selected by Table 4.7-2, any
        advertising interval and advertising channel map, supported own-address
        type, common connection interval, zero latency, common timeout and
        channel map, any SCA. Select public addresses, 10-ms interval, 300-ms
        timeout and a legal two-channel map. Before the procedure, complete
        Feature Exchange for the optional features under test (Section 4.1.6).
        Keep the connection unencrypted while testing forbidden encryption PDUs.

    Test Steps:
        1. Repeat Steps 2-3 for every supported opcode forbidden in the current
           role according to the role mapping. If its CtrData exceeds 26 octets,
           truncate CtrData alone to 26 octets; do not count the Opcode octet.
           Central IUT: CONNECTION_UPDATE_IND, CHANNEL_MAP_IND, ENC_REQ,
           FEATURE_REQ, PAUSE_ENC_REQ and PHY_UPDATE_IND.
           Peripheral IUT: ENC_RSP, START_ENC_REQ, PERIPHERAL_FEATURE_REQ and
           PHY_RSP and MIN_USED_CHANNELS_IND. Optional features outside this
           Controller's supported set are not part of this opcode list.
        2. Receive DATA from the IUT (possibly empty), then send the selected
           supported but sender-role-forbidden control PDU. Maintain the DATA
           acknowledgement scheme while observing the response.
        3. Receive LL_UNKNOWN_RSP, LL_REJECT_EXT_IND or LL_REJECT_IND.
           UnknownType or RejectOpcode, where present, must equal the injected
           opcode. Reject PDUs must contain a defined non-success ErrorCode.
           Acknowledge each response before the next opcode iteration.
        4. Send LL_TERMINATE_IND from the Lower Tester to disconnect the IUT;
           check the matching HCI Disconnection Complete event.

    Expected Outcome:
        Pass verdict:
            Every injected opcode elicits an unknown or reject response.
            LL_UNKNOWN_RSP.UnknownType and LL_REJECT_EXT_IND.RejectOpcode must
            identify the opcode sent in Step 2. LL_REJECT_IND has no opcode field.
            Neither an unrelated response nor disconnection satisfies Step 3.
            The same ACL remains established throughout the opcode iterations.

    Source Correction:
        Step 3's non-success error wording applies only to the two reject PDUs:
        LL_UNKNOWN_RSP has no ErrorCode field; its only data is UnknownType.
        The source's own verdict and Core Vol 6 Part B Section 2.4.2.8 agree.
        Amber confirms this local reading; it is not adopted SIG errata.
        The common one-bit map is replaced by legal map 0x03, consistent with
        the existing Section 4.3 common-map correction.

    Reference:
        LL.TS.p28, Section 4.7.3.2, LL/PAC/CEN/BV-02-C and LL/PAC/PER/BV-02-C;
        PDF 1171-1173, printed 4.7-3..5; Table 4.7-2, Figure 4.7-2.
        Core reference [3], Vol 6 Part B Sections 2.4.2 and 2.4.2.8;
        sender-role applicability: LL.ICS.p24 Table 4.1.
    """
    link = await _packet_connection(tester, central)
    for opcode, data in _forbidden_controls(link):
        tester.output.write(f'FORBIDDEN {opcode.name}\n')
        payload = (
            bytes([opcode])
            + data[: PDU_CONTROL_PAYLOAD_SIZE_INITIAL_MAX - PDU_CONTROL_OPCODE_SIZE]
        )
        packet = await link.exchange(payload, llid=LlId.CONTROL)
        for _ in range(16):
            if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
                _check_role_rejection(packet.pdu[PDU_HEADER_SIZE:], opcode)
                break
            packet = await link.exchange()
        else:
            raise AssertionError(f'forbidden {opcode.name} was not rejected')
        await link.exchange()
    await link.disconnect(local=False)


PROCEDURES: ProcedureMap = {}

# Verify the opcode-specific handling of invalid LL Control CtrData lengths and the
# ability to continue the relevant Link Layer procedure.
PROCEDURES |= procedure_cases(
    control_pdus_with_invalid_length,
    {
        'LL/PAC/CEN/BI-01-C': (
            'Control PDUs with Invalid Length, Central',
            {'central': True},
        ),
        'LL/PAC/PER/BI-01-C': (
            'Control PDUs with Invalid Length, Peripheral',
            {'central': False},
        ),
    },
)

# Verify LL_UNKNOWN_RSP for every unsupported or unused control opcode, with UnknownType
# equal to the injected opcode in either connected role.
PROCEDURES |= procedure_cases(
    unknown_control_pdus,
    {
        'LL/PAC/CEN/BV-01-C': (
            'Unknown Control PDUs, Central',
            {'central': True},
        ),
        'LL/PAC/PER/BV-01-C': (
            'Unknown Control PDUs, Peripheral',
            {'central': False},
        ),
    },
)

# Verify rejection of every supported control opcode forbidden in the IUT's current
# role. The Lower Tester acts in the peer role, injects each opcode and observes the
# corresponding unknown or reject response.
PROCEDURES |= procedure_cases(
    control_pdus_not_permitted_in_the_current_role,
    {
        'LL/PAC/CEN/BV-02-C': (
            'Control PDUs not permitted in the current role, Central',
            {'central': True},
        ),
        'LL/PAC/PER/BV-02-C': (
            'Control PDUs not permitted in the current role, Peripheral',
            {'central': False},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_packet_handling(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
