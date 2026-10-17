# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL.TS.p28, Section 4.6."""

from dataclasses import replace

import pytest

from bumble import hci
from bumble.ll import (
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_INTERVAL_UNIT_US,
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_COUNT_MIN,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    LL_HOP_INCREMENT_MAX,
    LL_HOP_INCREMENT_MIN,
    PDU_CONTROL_INSTANT_SIZE,
    PDU_CONTROL_OPCODE_SIZE,
    PDU_DATA_LLID_MASK,
    PDU_HEADER_SIZE,
    ControlPdu,
    LlId,
)
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.link import check_advertising_stopped
from tests.radio_controller.qualification.peer import establish, exchange_features
from tests.radio_controller.qualification.tester import (
    LOWER_CENTRAL_PUBLIC_ADDRESS,
    LOWER_DATA_ACCESS_ADDRESS,
    LOWER_PERIPHERAL_PUBLIC_ADDRESS,
    LinkParameters,
)

Opcode = ControlPdu.Opcode
# Section 4.6 stops channel coverage after fifteen unsuccessful channel uses.
CHANNEL_OBSERVATION_LIMIT = 15
# Include the indication event N in the N..N+99 statistical window.
STATISTICAL_UPDATE_EVENTS = 100
OLD_MAP_MINIMUM_RESPONSES = 90
# Section 4.6.4.1: nominal and fewer-than-six-event update distances.
UPDATE_DISTANCES = (STATISTICAL_UPDATE_EVENTS, 3)
# Local observation budget, not a Core or test-suite response deadline.
CONTROL_OBSERVATION_EVENTS = 16
# Common connection parameters: 10-ms interval, zero latency, 300-ms timeout.
COMMON_INTERVAL = 8
COMMON_TIMEOUT = 30
# Even-numbered channels are classified as usable in the first update round.
EVEN_CHANNELS = sum(1 << channel for channel in range(0, LL_DATA_CHANNEL_COUNT, 2))


async def _empty_event(link):
    """Advance one event even without a response; validate any received empty PDU."""
    packet = await link.exchange(check_ack=True, required=False)
    if packet is not None:
        assert packet.valid_crc
        assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
        assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
    return packet


async def _observe_channels(link, *, count_all_uses=False):
    """Exercise the source's per-channel limit, not an arbitrary event-count loop."""
    remaining = {
        channel
        for channel in range(LL_DATA_CHANNEL_COUNT)
        if link.parameters.channel_map & 1 << channel
    }
    uses = dict.fromkeys(remaining, 0)
    while remaining:
        channel = link.channel
        uses[channel] += 1
        if await _empty_event(link) is not None:
            remaining.discard(channel)
        if not remaining:
            return
        if uses[channel] == CHANNEL_OBSERVATION_LIMIT and (
            count_all_uses or channel in remaining
        ):
            raise AssertionError(
                f'no response on enabled channels {sorted(remaining)} '
                f'before channel {channel} reached fifteen uses'
            )


async def _read_map(link, expected):
    result = await link.tester.command(hci.HCI_LE_Read_Channel_Map_Command(link.handle))
    assert result.connection_handle == link.handle
    assert int.from_bytes(result.channel_map, 'little') == expected


async def _switch_map(link, value, instant):
    """Keep old-map events strictly before Instant; observe Instant with the new map."""
    responses = events = 0
    distance = (instant - link.counter) & LL_EVENT_COUNTER_MASK
    assert distance <= LL_EVENT_COUNTER_MASK // 2, 'update instant is already past'
    for _ in range(distance):
        responses += await _empty_event(link) is not None
        events += 1
    await _read_map(link, link.parameters.channel_map)
    link.parameters = replace(link.parameters, channel_map=value)
    # Coverage includes Instant; no new-map event is consumed in advance.
    await _observe_channels(link, count_all_uses=not link.central)
    await _read_map(link, value)
    return events, responses


async def accepting_connections_with_hop_lengths(tester):
    """Accepting Connections with Hop Lengths.

    Initial Condition:
        IUT: undirected advertising, selected advertising intervals and one IXIT
        primary channel, a supported own-address type and the common device name.
        Select public addresses and primary channel 37. Use all 37 data channels,
        CSA #1 and the default data Access Address from Section 4.1.4.1.

    Test Steps:
        1. Configure the Lower Tester to initiate a connection.
        2. Enable IUT advertising on the single IXIT advertising channel.
        3. Receive ADV_IND and send CONNECT_IND at T_IFS after its end, with the
           maximum hop increment, 16.
        4. Receive successful HCI LE Connection Complete containing the requested
           connection parameters.
        5. Send empty DATA at every connection interval on the independently
           calculated data channel.
        6. Receive empty DATA on that channel at T_IFS; continue with the
           acknowledgement scheme.
        7. Repeat Steps 5-6 until every enabled channel has responded, or a channel
           has been used fifteen times without a response on that channel.
        8. Terminate the unencrypted Peripheral connection using its handle and
           connection parameters; check HCI Disconnection Complete.
        9. Repeat Steps 1-2.
        10. Receive ADV_IND and send CONNECT_IND at T_IFS using the minimum hop
            increment, 5.
        11. Repeat Steps 4-8.

    Expected Outcome:
        Pass verdict:
            Both hop increments execute successfully. The IUT maintains each
            connection and responds on every enabled data channel at least once.
            PHY output contains no ADV_IND between connection acceptance and
            termination. Received DATA has valid CRC, empty payload and correct
            timing and acknowledgement.

    Reference:
        LL.TS.p28, Section 4.6.3, LL/FRH/ADV/BV-01-C; PDF 1154-1156, printed
        4.6-2..4; Figure 4.6-1. Core reference [3], Vol 6 Part B Section 4.5.8.
    """
    for hop in (LL_HOP_INCREMENT_MAX, LL_HOP_INCREMENT_MIN):
        await tester.command(
            hci.HCI_LE_Set_Advertising_Data_Command(advertising_data=b'\x04\x09IUT')
        )
        link = await establish(
            tester,
            peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
            connection_parameters=LinkParameters(
                access_address=LOWER_DATA_ACCESS_ADDRESS,
                interval=COMMON_INTERVAL,
                timeout=COMMON_TIMEOUT,
                hop_sca=hop,
            ),
        )
        assert not link.csa2
        # establish() has consumed event zero after the initial transmit window.
        connection_end = link.anchor - LL_CONN_INTERVAL_UNIT_US * (
            1 + link.parameters.window_offset + link.parameters.interval
        )
        await _observe_channels(link)
        check_advertising_stopped(tester, connection_end, tester.radio.now_us)
        await link.disconnect()


async def accepting_channel_map_update(tester, *, csa2):
    """Accepting Channel Map Update.

    Initial Condition:
        IUT: connected Peripheral, public addresses, any advertising interval and
        advertising channel map, common 10-ms connection interval, zero latency,
        300-ms timeout, all 37 data channels and any SCA. Table 4.6-1 selects
        CSA #1 for BV-01 and CSA #2 for BV-02. The Lower Tester is Central.
        Complete Feature Exchange for the optional CSA #2 feature before Step 1,
        as required by Section 4.1.6.

    Test Steps:
        1. Send LL_CHANNEL_MAP_IND selecting every second channel and Instant
           100 events ahead. Receive the IUT's acknowledgement.
        2. Send empty DATA each interval using the old map and acknowledgement
           scheme until the event counter reaches Instant. Include the Step 1
           indication event N in the response statistics: N..N+99 are the 100
           old-map events for Instant N+100 (see Source Correction).
        3. At Instant, switch the independently calculated CSA to the new map.
        4. Send empty DATA each interval. Receive responses at T_IFS on the same
           channel using the acknowledgement scheme. Continue until every enabled
           channel has responded or any channel has been used fifteen times.
        5. Repeat Steps 1-4 with all channels enabled in ChM.
        6. Repeat Steps 1-5 with Instant fewer than six intervals ahead; select
           three intervals here. Check acknowledgement, exact switchover and
           connection/channel coverage without a separate 90/100 threshold.

    Expected Outcome:
        Pass verdict:
            Accept each update and maintain the connection with the selected CSA.
            Transmit and receive on indices calculated from the selected map.
            For each Instant N+100 round, respond in at least 90 of the 100
            old-map events, including the acknowledged indication at N.
            An absent response still counts as an event but earns no success.
            Instant uses the new map and never contributes to that statistic.

    Source Correction:
        The test owner confirmed that the 100-event response window includes
        N, the Step 1 indication event, followed by N+1..N+99. Retain Instant
        N+100 and apply the 90/100 threshold independently to each such round.
        The owner also confirmed that the short-Instant repetition checks
        acknowledgement, exact map adoption and connection maintenance only;
        do not invent a 100-event window or a scaled statistical threshold
        for its three old-map events. These are confirmed local interpretations,
        not adopted SIG errata.

    Reference:
        LL.TS.p28, Section 4.6.4.1, LL/FRH/PER/BV-01-C and LL/FRH/PER/BV-02-C;
        PDF 1156-1158, printed 4.6-4..6; Table 4.6-1, Figure 4.6-2.
        Core reference [10], Vol 6 Part B Sections 4.5.8 and 5.1.2.
    """
    link = await establish(
        tester,
        csa2=csa2,
        peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
        connection_parameters=LinkParameters(
            access_address=LOWER_DATA_ACCESS_ADDRESS,
            interval=COMMON_INTERVAL,
            timeout=COMMON_TIMEOUT,
        ),
    )
    if csa2:
        await exchange_features(link, hci.LeFeatureMask.CHANNEL_SELECTION_ALGORITHM_2)
    for distance in UPDATE_DISTANCES:
        for value in (EVEN_CHANNELS, LL_DATA_CHANNEL_MAP_ALL):
            instant = (link.counter + distance) & LL_EVENT_COUNTER_MASK
            indication = (
                bytes([Opcode.LL_CHANNEL_MAP_IND])
                + value.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
                + instant.to_bytes(PDU_CONTROL_INSTANT_SIZE, 'little')
            )
            acknowledged = await link.exchange(
                indication, llid=LlId.CONTROL, check_ack=True
            )
            assert acknowledged is not None, 'channel-map indication not acknowledged'
            events, responses = await _switch_map(link, value, instant)
            # Step 1's acknowledged indication is the first old-map event.
            events += 1
            responses += 1
            assert events == distance
            tester.output.write(
                f'OLD MAP distance={distance} events={events} '
                f'responses={responses}\n'
            )
            if distance == STATISTICAL_UPDATE_EVENTS:
                assert (
                    responses >= OLD_MAP_MINIMUM_RESPONSES
                ), f'only {responses}/{events} old-map responses'
    await link.disconnect()


async def requesting_channel_map_update(tester, *, csa2):
    """Requesting Channel Map Update.

    Initial Condition:
        IUT: connected Central, any scan interval/window, public peer address,
        supported own-address type, selected connection interval, common zero
        latency and 300-ms timeout. Select public own address and 10-ms interval.
        Table 4.6-3 selects CSA #1 for BV-01 and CSA #2 for BV-02.
        Complete Feature Exchange for CSA #2 before Step 1 (Section 4.1.6).

    Test Steps:
        1. Select alternative 1A for BV-01 or 1B for BV-02:
           1A.1. Send HCI LE Set Host Channel Classification with supported even
                 channels; receive successful HCI Command Complete.
           1B.1. Send that command with supported even-channel bits set to 1
                 (unknown) and the other bits 0; receive Command Complete.
        2. Receive LL_CHANNEL_MAP_IND with a changed map, not necessarily equal
           to the classification, and acknowledge it with empty DATA on the same
           channel. If no indication is received, skip Steps 3-5.
        3. Maintain the connection with empty DATA until its counter reaches the
           received Instant, using the original map.
        4. Select the matching alternative:
           4A.1. At Instant, adopt the new parameters using CSA #1.
           4B.1. At Instant, switch CSA #2 to the new map.
        5. Receive empty DATA and send empty DATA every interval with the
           acknowledgement scheme until all enabled channels have responded.
           Fail if any channel has been used fifteen times without a response
           on that channel.
        6. Repeat Steps 1-5 with the matching alternative:
           6A.1. Classify all supported channels as used.
           6B.1. Mark all supported-channel bits unknown (1).

    Expected Outcome:
        Pass verdict:
            Maintain the connection with the original map before Instant and the
            updated map from Instant onward, using the selected CSA. Send and
            receive DATA on its calculated channels. At least one iteration must
            produce and successfully exercise a changed map.
        Inconclusive verdict:
            Both iterations either omit LL_CHANNEL_MAP_IND or supply the current
            map. Represent this verdict as a skip, never as PASS or failure.

    Observation Limit:
        The source gives no deadline for the indication. Observe sixteen events
        per iteration as a local budget, not a normative deadline. If both
        observations are absent/unchanged, skip. A delayed indication cannot be
        classified as a protocol violation merely because this budget expired.

    Source Correction:
        The final generic pass-verdict sentence mentions CSA #2 without limiting
        it to alternative B. Apply that sentence to BV-02 only: Table 4.6-3 and
        alternatives 1A/4A/6A explicitly select CSA #1 for BV-01. Amber supports
        this interpretation; this is a local correction, not adopted SIG errata.

    Reference:
        LL.TS.p28, Section 4.6.5.1, LL/FRH/CEN/BV-01-C and LL/FRH/CEN/BV-02-C;
        PDF 1162-1164, printed 4.6-10..12; Table 4.6-3, Figure 4.6-6.
        Core reference [3], Vol 6 Part B Sections 4.5.8 and 5.1.2.
    """
    link = await establish(
        tester,
        central=True,
        csa2=csa2,
        peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
        interval=COMMON_INTERVAL,
        timeout=COMMON_TIMEOUT,
    )
    if csa2:
        await exchange_features(link, hci.LeFeatureMask.CHANNEL_SELECTION_ALGORITHM_2)
    changed = 0
    for classification in (EVEN_CHANNELS, LL_DATA_CHANNEL_MAP_ALL):
        await tester.command(
            hci.HCI_LE_Set_Host_Channel_Classification_Command(
                classification.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
            )
        )
        update = None
        for _ in range(CONTROL_OBSERVATION_EVENTS):
            packet = await link.exchange(required=False)
            if packet is not None:
                assert packet.valid_crc
                assert len(packet.pdu) >= PDU_HEADER_SIZE
                assert packet.pdu[1] == len(packet.pdu) - PDU_HEADER_SIZE
                if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
                    payload = packet.pdu[PDU_HEADER_SIZE:]
                    if payload and payload[0] == Opcode.LL_CHANNEL_MAP_IND:
                        update = payload
                        break
        if update is None:
            continue
        assert len(update) == (
            PDU_CONTROL_OPCODE_SIZE + LL_CHANNEL_MAP_SIZE + PDU_CONTROL_INSTANT_SIZE
        )
        value = int.from_bytes(update[1:-PDU_CONTROL_INSTANT_SIZE], 'little')
        assert value & ~LL_DATA_CHANNEL_MAP_ALL == 0
        assert value.bit_count() >= LL_DATA_CHANNEL_COUNT_MIN
        instant = int.from_bytes(update[-PDU_CONTROL_INSTANT_SIZE:], 'little')
        before = link.parameters.channel_map
        await _switch_map(link, value, instant)
        changed += value != before
    await link.disconnect()
    if not changed:
        pytest.skip('Inconclusive: both classification rounds have no changed map')


async def accepting_minimum_number_of_used_channels(tester):
    """Accepting Minimum Number of Used Channels.

    Initial Condition:
        Connected Central with any scan interval/window, public peer address,
        Lower Tester address, supported own-address type, selected connection
        interval, common Peripheral latency and timeout. Select public addresses,
        the common 10-ms interval, zero latency, 300-ms timeout and all 37 data
        channels. Complete Feature Exchange before Step 1 (Section 4.1.6).

    Test Steps:
        1. The Lower Tester sends LL_MIN_USED_CHANNELS_IND. Set PHYS to include
           every PHY supported by the IUT and MinUsedChannels=0x25 (37 channels).
           Require its Link Layer acknowledgement.
        2. Receive LL DATA from the IUT each connection interval and send a
           response using the acknowledgement scheme. Repeat ten times.

    Expected Outcome:
        Pass verdict: accept the indication and maintain the connection through
        all ten acknowledged DATA exchanges. Reject LL_UNKNOWN_RSP, any other
        unexpected control response, bad CRC or an absent DATA packet.

    Additional Checks and Postamble:
        Read the feature mask through HCI and require procedure support. Derive
        the PHYS bits from the advertised PHY features, not DUT internals.
        The initial map already contains all 37 channels, so this source case
        does not require a new channel-map indication. Map selection, PHY
        applicability and deferred-update behavior have separate unit coverage.
        Disconnect after Step 2.

    Reference:
        LL.TS.p28.pdf, standalone LL/FRH/CEN/BV-03-C; PDF 1164-1165,
        printed 4.6-12..13, Figure 4.6-7, Steps 1-2 and pass verdict.
        Source reference [10] 5.1.11; Core Vol 6 Part B 2.4.2.24 and 4.6.15.
    """
    features = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    mask = int.from_bytes(features.le_features, 'little')
    feature = hci.LeFeatureMask.MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE
    assert mask & feature
    phys = hci.PhyBit.LE_1M
    for supported, phy in (
        (hci.LeFeatureMask.LE_2M_PHY, hci.PhyBit.LE_2M),
        (hci.LeFeatureMask.LE_CODED_PHY, hci.PhyBit.LE_CODED),
    ):
        if mask & supported:
            phys |= phy
    link = await establish(
        tester,
        central=True,
        peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
        interval=COMMON_INTERVAL,
        timeout=COMMON_TIMEOUT,
    )
    await exchange_features(link, feature)
    await link.exchange()
    await link.exchange(
        bytes([Opcode.LL_MIN_USED_CHANNELS_IND, phys, LL_DATA_CHANNEL_COUNT]),
        llid=LlId.CONTROL,
        check_ack=True,
    )
    for _ in range(10):
        assert await _empty_event(link) is not None
    await link.disconnect()


PROCEDURES: ProcedureMap = {}

# Verify that an advertiser accepts CONNECT_IND, stops advertising and maintains a
# Peripheral connection using the correct data-channel sequence. The Lower Tester
# initiates and then acts as Central.
PROCEDURES |= procedure_cases(
    accepting_connections_with_hop_lengths,
    {
        'LL/FRH/ADV/BV-01-C': (
            'Accepting Connections With Hop Lengths',
            {},
        ),
    },
)

# Verify that a Peripheral accepts a Central's channel-map update, adopts the map at
# Instant and maintains the connection with the selected CSA.
PROCEDURES |= procedure_cases(
    accepting_channel_map_update,
    {
        'LL/FRH/PER/BV-01-C': (
            'Accepting Channel Map Update',
            {'csa2': False},
        ),
        'LL/FRH/PER/BV-02-C': (
            'Accepting Channel Map Update, Channel Selection Algorithm #2',
            {'csa2': True},
        ),
    },
)

# Verify that a Central requests a channel-map update and maintains the connection
# before and after Instant. The Lower Tester acts as Peripheral, requests the update
# through HCI and adopts the received on-air map.
PROCEDURES |= procedure_cases(
    requesting_channel_map_update,
    {
        'LL/FRH/CEN/BV-01-C': (
            'Requesting Channel Map Update',
            {'csa2': False},
        ),
        'LL/FRH/CEN/BV-02-C': (
            'Requesting Channel Map Update, Channel Selection Algorithm #2',
            {'csa2': True},
        ),
    },
)

# Verify that a Central accepts the Peripheral's Minimum Number of Used Channels
# procedure and maintains the connection and acknowledgement scheme.
PROCEDURES |= procedure_cases(
    accepting_minimum_number_of_used_channels,
    {
        'LL/FRH/CEN/BV-03-C': (
            'Accepting Minimum Number Of Used Channels',
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_frequency_hopping(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
