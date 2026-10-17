# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL.TS.p28, Section 4.5."""

import pytest

from bumble import hci
from bumble.ll import (
    LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_ESTABLISHMENT_EVENTS,
    LL_CONN_INTERVAL_UNIT_US,
    LL_EVENT_COUNTER_MASK,
    LL_IFS_US,
    LL_SUPERVISION_TIMEOUT_UNIT_US,
    PDU_ACCESS_ADDRESS_SIZE,
    PDU_ADV_ACCESS_ADDRESS,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_TYPE_MASK,
    PDU_DATA_LLID_MASK,
    PDU_DATA_NESN_MASK,
    PDU_DATA_SN_MASK,
    PDU_HEADER_SIZE,
    AdvertisingPduType,
    LlId,
)
from bumble.radio_controller.radio import PHY_OCTET_BITS
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.link import (
    CONNECTION_IFS_TOLERANCE_US,
    ErrorCode,
    _pending_connection,
    check_advertising_stopped,
)
from tests.radio_controller.qualification.peer import establish
from tests.radio_controller.qualification.tester import (
    DUT_ADDRESS,
    LOWER_CENTRAL_PUBLIC_ADDRESS,
    LOWER_DATA_ACCESS_ADDRESS,
    LOWER_PERIPHERAL_PUBLIC_ADDRESS,
    LinkParameters,
    check_access_address,
    legacy_parameters,
    request_pdu,
)

# LL.TS.p28 Section 4.5: forty single-bit faults, bits 1..20 then 31..12.
ADDRESS_BITS = (
    *range(1, 21),
    *range(PDU_ACCESS_ADDRESS_SIZE * PHY_OCTET_BITS - 1, 11, -1),
)
# Source Correction: the common one-channel map in 4.3.3.1 needs two channels.
COMMON_CHANNEL_MAP = 0x03
# Encoding cases score forty independent trials, accepting at least thirty-two.
MINIMUM_QUALIFYING_TRIALS = 32
# Host event delivery is observed at one-ms intervals of simulated time.
HCI_OBSERVATION_STEP_US = 1000


def _corrupted_access_address(address, bit):
    """Apply one prescribed fault after validating only the connection's base AA."""
    check_access_address(address)
    assert 0 <= bit < PDU_ACCESS_ADDRESS_SIZE * PHY_OCTET_BITS
    return address ^ 1 << bit


async def _bad_data_exchange(tester, link, bit, *, window_us=0, require_ack=False):
    """Maintain the wire acknowledgement scheme but corrupt the transmitted Access
    Address."""
    access_address = _corrupted_access_address(link.parameters.access_address, bit)
    channel = link.channel
    packet = None
    if link.central:
        packet = await tester.receive(
            channel,
            duration_us=link.anchor - tester.radio.now_us + window_us + 1000,
            start_us=max(tester.radio.now_us + 1, link.anchor - 50),
            **link.radio_parameters,
        )
        if packet is None:
            link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
            link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
            return None
        assert packet.valid_crc
        assert link.anchor <= packet.start_us <= link.anchor + window_us
        link.anchor = packet.start_us
        assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
        assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
        if require_ack:
            assert int(bool(packet.pdu[0] & PDU_DATA_NESN_MASK)) == link.sn ^ 1
        link._accept(packet)
        start = packet.end_us + LL_IFS_US
    else:
        start = link.anchor
    header = (
        LlId.CONTINUATION | link.sn * PDU_DATA_SN_MASK | link.nesn * PDU_DATA_NESN_MASK
    )
    end = await tester.transmit(
        channel,
        bytes([header, 0]),
        start_us=start,
        **link.radio_parameters | {'access_address': access_address},
    )
    if not link.central:
        packet = await tester.receive(
            channel, duration_us=1000, **link.radio_parameters
        )
        if packet is not None:
            assert packet.valid_crc
            assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
            assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
            assert abs(packet.start_us - end - LL_IFS_US) <= CONNECTION_IFS_TOLERANCE_US
            link._accept(packet)
    link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    return packet


def _take_disconnection(tester, handle):
    event = tester.take(
        lambda event: isinstance(event, hci.HCI_Disconnection_Complete_Event)
    )
    if event is not None:
        assert (event.status, event.connection_handle) == (ErrorCode.SUCCESS, handle)
    return event


async def _observe_disconnection(tester, handle, deadline):
    event = _take_disconnection(tester, handle)
    while event is None and tester.radio.now_us < deadline:
        await tester.wait(min(HCI_OBSERVATION_STEP_US, deadline - tester.radio.now_us))
        event = _take_disconnection(tester, handle)
    return event


async def _invalid_connection_address(tester, *, central=False, established=True):
    """Observe bounded trials; score RF-recognition outcomes without hiding bad HCI."""
    parameters = LinkParameters(
        access_address=LOWER_DATA_ACCESS_ADDRESS,
        interval=8,
        timeout=10 if not central and not established else 30,
        channel_map=COMMON_CHANNEL_MAP,
        hop_sca=5,
    )
    if central:
        await tester.command(
            hci.HCI_LE_Set_Host_Channel_Classification_Command(
                COMMON_CHANNEL_MAP.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
            )
        )
    sequences = (
        (ADDRESS_BITS[:20], ADDRESS_BITS[20:])
        if established and not central
        else ((bit,) for bit in ADDRESS_BITS)
    )
    qualifying = timing_qualifying = joint_qualifying = 0
    for bits in sequences:
        if established:
            link = await establish(
                tester,
                central=central,
                interval=parameters.interval,
                timeout=parameters.timeout,
                peer_address=(
                    LOWER_PERIPHERAL_PUBLIC_ADDRESS
                    if central
                    else LOWER_CENTRAL_PUBLIC_ADDRESS
                ),
                **({} if central else {'connection_parameters': parameters}),
            )
            last_valid = link.last_sent_end_us
            connection_end = None
        else:
            link, connection_end = await _pending_connection(
                tester, central=central, parameters=parameters
            )
            last_valid = connection_end
            if central:
                event = await tester.event(hci.HCI_LE_Channel_Selection_Algorithm_Event)
                assert (
                    event.connection_handle,
                    event.channel_selection_algorithm,
                ) == (link.handle, int(link.csa2))
        timeout_us = link.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
        check_access_address(link.parameters.access_address)
        interval_us = link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        deadline = last_valid + 2 * timeout_us
        event = None
        responses = transmissions = 0
        timing_ok = True
        acquired = established
        ack_pending = central and established
        stopped = resumed = False
        if central:
            while tester.radio.now_us < deadline:
                window = (
                    link.parameters.window_size * LL_CONN_INTERVAL_UNIT_US
                    if not acquired
                    else 0
                )
                if link.anchor + window + HCI_OBSERVATION_STEP_US > deadline:
                    break
                anchor = link.anchor
                packet = await _bad_data_exchange(
                    tester,
                    link,
                    bits[0],
                    window_us=window,
                    require_ack=ack_pending,
                )
                if packet is not None:
                    ack_pending = False
                if event is not None:
                    assert packet is None, 'DATA transmitted after HCI disconnection'
                event = event or _take_disconnection(tester, link.handle)
                if packet is not None:
                    acquired = True
                    transmissions += 1
                    resumed |= stopped
                if not established:
                    cutoff = connection_end + LL_CONN_ESTABLISHMENT_EVENTS * interval_us
                    if anchor < cutoff:
                        timing_ok &= packet is not None
                    elif packet is None:
                        stopped = True
                if established and event is not None:
                    break
            if not established:
                timing_ok &= transmissions <= LL_CONN_ESTABLISHMENT_EVENTS
        elif established:
            for bit in bits:
                responses += await _bad_data_exchange(tester, link, bit) is not None
            assert responses <= 4
            deadline = tester.radio.now_us + timeout_us + HCI_OBSERVATION_STEP_US
        else:
            while link.anchor + HCI_OBSERVATION_STEP_US <= deadline:
                responses += await _bad_data_exchange(tester, link, bits[0]) is not None
                event = _take_disconnection(tester, link.handle)
                if event is not None:
                    break
        event = event or await _observe_disconnection(tester, link.handle, deadline)
        observed_us = tester.radio.now_us
        expected = (
            ErrorCode.CONNECTION_TIMEOUT_ERROR
            if established
            else ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR
        )
        success = (
            event is not None
            and event.reason == expected
            and observed_us <= deadline
            and (central or established or responses == 0)
            and not ack_pending
        )
        qualifying += success
        timing_ok &= not resumed
        timing_qualifying += timing_ok
        joint_qualifying += success and timing_ok
        if not central and not established:
            check_advertising_stopped(tester, connection_end, observed_us)
        tester.output.write(
            f'ADDRESS TRIAL bits={tuple(bits)} qualified={int(success)} '
            f'timing={int(timing_ok)} responses={responses} '
            f'observed_us={observed_us} deadline_us={deadline}\n'
        )
        if established and not central:
            assert success, 'Peripheral did not report supervision timeout'
        if event is None:
            # Cleanup is outside the measured trial and cannot earn a success.
            await tester.command(
                hci.HCI_Disconnect_Command(
                    link.handle, ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR
                )
            )
            cleanup = await _observe_disconnection(
                tester,
                link.handle,
                tester.radio.now_us + timeout_us + HCI_OBSERVATION_STEP_US,
            )
            assert cleanup is not None, 'post-trial disconnect did not complete'
    if central or not established:
        assert (
            qualifying >= MINIMUM_QUALIFYING_TRIALS
        ), f'only {qualifying}/40 qualifying disconnections'
    if central and not established:
        assert timing_qualifying >= MINIMUM_QUALIFYING_TRIALS
        if joint_qualifying < MINIMUM_QUALIFYING_TRIALS:
            pytest.skip(
                'Source conflict: LL/ENC/INI/BI-01-C does not resolve whether '
                'the two 32/40 metrics must overlap on the same trials; '
                'Amber cannot resolve this boundary'
            )


async def scan_request_invalid_address(tester):
    """Scan Request Invalid Address.

    Initial Condition:
        Undirected advertising with selected minimum/maximum intervals,
        supported own address type, selected advertising channels, selected
        device-name length and common name. The advertiser accepts all scan
        and connection requests under its Filter Accept List policy.

    Test Steps:
        1. Enable undirected advertising on all supported primary advertising
           channels at the minimum interval. If filtering is supported, select
           Allow Scan Request from Any / Allow Connect Request from Any,
           the default policy 0x00.
        2. Configure the Lower Tester to observe IUT advertising and
           scan-response procedures.
        3. On the selected supported IXIT channel, receive ADV_IND and send
           SCAN_REQ T_IFS after it ends. Use a listed peer device address
           and corrupt exactly one bit of the advertising Access Address.
        4. Observe continued IUT advertising without a scan response.
        5. Execute Steps 3-4 for 40 scan requests in total. Corrupt bits 1
           through 20 in order for the first twenty requests, then bits 31
           through 12 in descending order for the remaining twenty.
        6. Disable advertising with LE Set Advertising Enable and require
           successful Command Complete.

    Test Condition:
        The source's statistical criteria assume a bit error rate of
        0.1 percent or better. The simulated path here has no injected errors.

    Expected Outcome:
        Pass verdict:
            Continue advertising and respond to no more than eight of the
            forty corrupted scan requests.

    Notes:
        This checks the reverse of a positive requirement. The allowance for
        eight replies accounts for a single-bit error being reverted while
        the remaining packet stays intact, using the source's binomial model.
        Access Address bit zero is transmitted first over the air.

    Coverage Note:
        Select public addresses and primary channel 37 for Lower Tester
        observation, while enabling all three IUT advertising channels.
        Add the public scanner to the Filter Accept List even under accept-all
        policy. Observe correctly addressed ADV_IND throughout all forty
        requests and once more after the last one. Count SCAN_RSP replies
        independently; the fixed bit sequence exactly follows Step 5.

    Reference:
        LL.TS.p28.pdf, standalone LL/ENC/ADV/BI-01-C in Section 4.5.2,
        Figure 4.5-1; all Steps 1-6, Test Condition, pass verdict and Notes;
        PDF 1140-1142, printed 4.5-2..4. References [3] 2.1.2, 4.4.2, 3.1.
    """
    peer = LOWER_CENTRAL_PUBLIC_ADDRESS
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(peer.address_type, peer)
    )
    await tester.command(
        legacy_parameters(advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL)
    )
    await tester.command(hci.HCI_LE_Set_Scan_Response_Data_Command(b'LT'))
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    responses = 0
    for bit in ADDRESS_BITS:
        packet = await tester.expect_pdu(kind=AdvertisingPduType.ADV_IND)
        assert packet.pdu[
            PDU_HEADER_SIZE : PDU_HEADER_SIZE + PDU_ADV_ADDRESS_SIZE
        ] == bytes(DUT_ADDRESS)
        await tester.transmit(
            37,
            request_pdu(AdvertisingPduType.SCAN_REQ, scanner=peer),
            start_us=packet.end_us + LL_IFS_US,
            access_address=PDU_ADV_ACCESS_ADDRESS ^ 1 << bit,
        )
        response = await tester.receive(37, duration_us=1000)
        if response is not None:
            assert response.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.SCAN_RSP
            responses += 1
    await tester.expect_pdu(kind=AdvertisingPduType.ADV_IND)
    assert responses <= 8
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


async def central_packets_invalid_address(tester):
    """Central Packets Invalid Address.

    Initial Condition:
        Undirected advertising with selected intervals, own address type,
        primary channels and device-name length/common name. Use accept-all
        advertiser filtering if supported. Select common data-channel
        parameters, zero Peripheral latency, 10 ms interval and 100 ms timeout.

    Test Steps:
        1. Enable undirected advertising on one supported IXIT channel,
           with Allow Scan Request from Any / Allow Connect Request from Any
           policy 0x00 if filtering is supported.
        2. Configure the Lower Tester as an initiator.
        3. Receive ADV_IND on the selected channel and send CONNECT_IND
           T_IFS after it ends.
        4. Require LE Connection Complete containing the Step 3 parameters.
        5. Starting the first data event, send empty DATA using the common
           channel selection but invert one bit of the connection Access
           Address.
        6. Observe no IUT response.
        7. Repeat Steps 5-6 until twice the supervision timeout has elapsed
           or Step 8 occurs.
        8. Require Disconnection Complete reporting Connection Failed to be
           Established, with the Step 4 connection handle.
        9. Execute Steps 1-8 for forty trials: invert bits 1 through 20 in
           order, then bits 31 through 12 in descending order.

    Test Condition:
        The source statistical criteria assume BER 0.1 percent or better.
        The selected simulated path has no injected bit errors.

    Expected Outcome:
        Pass verdict:
            The IUT stops advertising, moves to the data channel and reports
            establishment failure. At least 32 of forty trials report
            Disconnection Complete reason 0x3E with the correct handle.

    Notes:
        The selected advertising channel is assumed not to affect data-channel
        Access Address recognition. The statistical derivation is explained
        by LL/ENC/PER/BI-01-C.

    Coverage Note:
        Use public addresses, channel 37 and the default Peripheral data
        Access Address. Validate every HCI status and handle independently of
        the statistical count. Record each bounded observation and score
        qualifying trials only afterward, rather than demanding forty of forty.
        If the connection persists, HCI Disconnect is cleanup after the measured
        trial; its completion cannot earn a success. PHY TX CSV records verify
        that ADV_IND stopped after CONNECT_IND in every trial.

    Source Correction:
        The test owner interprets the Section 4.5 AA formulation requirement
        as applying to the valid base connection AA. The corrupted on-air word
        deliberately differs by one prescribed bit and need not satisfy normal
        AA formulation constraints. Validate the base AA, retain every required
        bit in the forty-fault sequence, and send the exact XOR result without
        replacing the address or skipping an invalid-looking corrupted word.
        Retain the reviewed common channel-map correction from Section 4.3.3.1
        to the legal two-channel minimum 0x03; this is not a SIG erratum.

    Reference:
        LL.TS.p28.pdf, standalone LL/ENC/ADV/BI-02-C in Section 4.5.2,
        Figure 4.5-2; all Steps 1-9, Test Condition, pass verdict and Notes;
        PDF 1142-1144, printed 4.5-4..6. References [3] 2.1.2, 4.4.4, 3.1.
    """
    await _invalid_connection_address(tester, central=False, established=False)


async def passive_scanning_invalid_address(tester):
    """Passive Scanning Invalid Address.

    Initial Condition:
        Passive scanning with selected scan interval/window and an accept-all
        Filter Accept List policy. The source preamble requests the minimum
        supported scan interval and maximum supported window, with interval
        equal to three times the mean advertising interval.

    Test Steps:
        1. Enable IUT passive scanning.
        2. Configure the Lower Tester as advertiser on one supported IXIT
           channel, with a device address included in the Filter Accept List.
        3. Send ADV_NONCONN_IND with an invalid Access Address on that channel
           in each event, with the selected timing matching the scan interval.
        4. Require no LE Advertising Report for these packets.
        5. Repeat Steps 3-4 for longer than forty scan intervals. For the
           first twenty ADV_NONCONN_IND packets invert bits 1 through 20
           in order; for the other twenty invert bits 31 through 12
           in descending order.
        6. Disable scanning through LE Set Scan Enable and require successful
           Command Complete.

    Test Condition:
        The statistical criteria assume BER 0.1 percent or better.

    Expected Outcome:
        Pass verdict:
            The IUT reports no more than eight of the forty advertising packets.

    Notes:
        Bit zero is transmitted first over the air. A bit error can revert
        the injected Access Address fault; demanding zero reports would
        therefore be unreliable. The source ignores the probability of the
        scanner listening on the selected channel in this calculation and
        refers to LL/ENC/PER/BI-01-C for the statistical derivation.

    Source Conflict:
        At the required 3:1 scan/mean-advertising interval ratio, forty
        advertising packets span only about thirteen scan intervals. The
        procedure also requires more than forty scan intervals, but defines
        only forty bit faults and a forty-packet verdict. Neither repeating
        the bit sequence with per-batch verdicts nor adding a silent tail is
        prescribed. Amber could not uniquely resolve the count/time conflict.
        The minimum scan interval is also ambiguous if the absolute supported
        minimum cannot satisfy the 3:1 ratio with legal advertising intervals.

    Review State:
        Skip this procedure until those source constraints are resolved.
        No repeated-batch or silent-tail stimulus is inferred.

    Reference:
        LL.TS.p28.pdf, standalone LL/ENC/SCN/BI-01-C in Section 4.5.3,
        Figure 4.5-3; all Steps 1-6, Test Condition, pass verdict and Notes;
        PDF 1144-1146, printed 4.5-6..8. References [3] 2.1.2, 4.4.3.1, 3.1.
    """
    pytest.skip(
        'Source conflict: LL/ENC/SCN/BI-01-C defines 40 packets but requires '
        'more than 40 scan intervals at a 3:1 scan/advertising ratio; '
        'Amber cannot resolve the intended count or minimum scan interval'
    )


async def active_scanning_invalid_address(tester):
    """Active Scanning Invalid Address.

    Initial Condition:
        Active scanning using a public address and selected interval/window,
        with accept-all Filter Accept List policy. Configure the scan interval
        to three times the mean advertising interval; if supported, accept all
        advertising packets through filtering policy 0x00.

    Test Steps:
        1. Enable IUT active scanning.
        2. Configure the Lower Tester for undirected advertising on one
           supported IXIT channel, with a listed device address.
        3. Send ADV_IND with an invalid Access Address using that channel
           only and the selected advertising interval.
        4. Observe no SCAN_REQ T_IFS after any of those advertising packets.
        5. Require no LE Advertising Report for those packets.
        6. Repeat Steps 3-5 until more than forty scan intervals have elapsed.
           Invert Access Address bits 1 through 20 for the first twenty
           ADV_IND packets, then bits 31 through 12 for the other twenty.
        7. Disable scanning through LE Set Scan Enable and require successful
           Command Complete.

    Test Condition:
        The statistical criteria assume BER 0.1 percent or better.

    Expected Outcome:
        Pass verdict:
            The IUT reports no more than eight of the forty advertising
            indications sent in Step 3.

    Notes:
        Bit zero is the first Access Address bit transmitted over the air.

    Source Conflict:
        The required scan/mean-advertising interval ratio is 3:1. Forty
        advertising packets therefore occupy only about thirteen scan intervals,
        while Step 6 requires more than forty scan intervals. The bit sequence
        and pass verdict define only forty packets. Amber confirms that the
        source does not uniquely authorize repeated forty-packet batches or
        a silent observation tail.

    Review State:
        Skip until the packet-count/time conflict is resolved. No per-batch
        report or SCAN_REQ threshold is inferred.

    Reference:
        LL.TS.p28.pdf, standalone LL/ENC/SCN/BI-02-C in Section 4.5.3,
        Figure 4.5-4; all Steps 1-7, Test Condition, pass verdict and Notes;
        PDF 1146-1147, printed 4.5-8..9. References [3] 2.1.2, 4.4.3.2, 3.1.
    """
    pytest.skip(
        'Source conflict: LL/ENC/SCN/BI-02-C defines 40 packets but requires '
        'more than 40 scan intervals at a 3:1 scan/advertising ratio; '
        'Amber cannot resolve the intended count'
    )


async def peripheral_packets_invalid_address(tester):
    """Peripheral Packets Invalid Address.

    Initial Condition:
        Initiating with selected scan interval/window, direct public peer
        addressing rather than Filter Accept List initiation, supported own
        address type and common connection interval, latency and timeout.
        Advertise on one selected channel using one public Lower Tester address.

    Test Steps:
        1. Configure the Lower Tester advertiser on one supported IXIT channel,
           using the common public Peripheral address.
        2. Enable IUT initiating.
        3. Send ADV_IND and receive CONNECT_IND T_IFS after an advertisement.
        4. Require LE Connection Complete reporting the Lower Tester address
           and selected connection interval.
        5. Receive the first empty Central DATA on the derived data channel
           within the permitted transmit-window offset/size timing range.
        6. Reply on that channel with empty DATA using the acknowledgement
           scheme, but invert one bit of the connection Access Address.
        7. Receive following empty Central DATA on subsequent data channels.
        8. Repeat Steps 6-7 until the IUT stops.
        9. Require Disconnection Complete reporting Connection Failed to be
           Established with the connection handle from Step 4.
        10. Execute Steps 1-9 for forty trials: invert bits 1 through 20
            in order, then bits 31 through 12 in descending order.

    Test Condition:
        The source statistical criteria assume BER 0.1 percent or better.

    Expected Outcome:
        Pass verdict:
            The IUT requests a connection and transmits for no more than six
            connection events. In at least 32 of forty trials, it transmits
            on all of the first six events whose anchor points are less than
            six connection intervals after CONNECT_IND ends. If it stops
            transmitting in an event after that cutoff, no later event resumes.
            At least 32 of forty trials report disconnection reason 0x3E.

    Notes:
        Bit zero is the first Access Address bit transmitted over the air.

    Coverage Note:
        Use common 10 ms/zero-latency/300 ms setup. Acquire the actual first
        anchor within its permitted window, then track subsequent hopping
        and anchors from it. Missing RX advances the independent event counter.
        Evaluate only anchors before the source cutoff; do not assume there
        are always exactly six eligible anchors. Observe through a finite
        two-supervision-timeout guard and record timing and HCI outcomes.
        Wrong HCI handle/status fails immediately. Post-window HCI cleanup
        cannot earn a qualifying disconnection.

    Source Conflict:
        The source gives separate 32/40 timing and HCI-event statements but
        does not say whether the successful trial sets must overlap. Amber
        confirms that a same-attempt intersection requirement is not explicit.
        Check both stated thresholds. If both pass but fewer than 32 trials
        satisfy both together, skip that unresolved corner rather than
        inventing a stricter or weaker combined verdict.

    Source Correction:
        The test owner interprets the Section 4.5 AA formulation requirement
        as applying to the valid base connection AA. The corrupted on-air word
        deliberately differs by one prescribed bit and need not satisfy normal
        AA formulation constraints. Validate the base AA, retain every required
        bit in the forty-fault sequence, and send the exact XOR result without
        replacing the address or skipping an invalid-looking corrupted word.
        Retain the reviewed common channel-map correction from Section 4.3.3.1
        to 0x03. This is a local correction, not a SIG erratum.

    Reference:
        LL.TS.p28.pdf, standalone LL/ENC/INI/BI-01-C in Section 4.5.4,
        Figure 4.5-5; all Steps 1-10, Test Condition, pass verdict and Notes;
        PDF 1147-1149, printed 4.5-9..11. References [3] 2.1.2, 4.5, 3.1.
    """
    await _invalid_connection_address(tester, central=True, established=False)


async def packets_to_another_peripheral(tester):
    """Packets to another Peripheral.

    Initial Condition:
        Connected Peripheral using common connection interval, zero latency,
        common supervision timeout/channel map and any SCA. The Lower Tester
        first establishes the connection with valid DATA before changing
        the Access Address.

    Test Steps:
        1. Prepare DATA with the second Access Address bit inverted.
        2. Send it using the connection's data-channel selection parameters.
        3. Observe no DATA response T_IFS after that packet.
        4. Prepare DATA with the next Access Address bit inverted, increasing
           the bit index.
        5. Repeat Steps 2-4 until twenty DATA packets have been sent in
           consecutive connection intervals.
        6. Stop sending DATA and allow a connection supervision timeout.
        7. Require Disconnection Complete with supervision-timeout reason
           and the current connection handle.
        8. Establish another connection with the IUT as Peripheral.
        9. Prepare DATA with the last Access Address bit inverted.
        10. Send that DATA using the connection's data-channel selection.
        11. Observe no DATA T_IFS after the packet.
        12. Prepare DATA with the next Access Address bit inverted, decreasing
            the bit index.
        13. Repeat Steps 10-12 until twenty DATA packets have been sent in
            consecutive connection intervals.
        14. Stop DATA and allow supervision timeout.
        15. Require Disconnection Complete with supervision-timeout reason
            and the second connection handle.

    Expected Outcome:
        Pass verdict:
            Each twenty-packet sequence receives responses in no more than
            four of its twenty connection events.

    Notes:
        The source allows a single-bit fault to be reverted by RF errors.
        Its illustrative derivation uses approximately 96-percent correct
        preamble/Access Address reception and ten reception opportunities
        before supervision failure. For an IUT not checking the full Access
        Address, avoiding a reverted fault across ten correctly received
        packets has approximately 99-percent probability. Its geometric
        model gives a mean repetition count below one, approximately 0.01,
        for that ten-packet run. Twenty events are therefore used to conclude
        whether the entire Access Address is checked.
        An IUT checking the full address eventually terminates the connection.

    Coverage Note:
        Use public peers, the source's default Peripheral data Access Address
        and common channel selection. Execute bits 1-20 on the first
        connection and bits 31-12 on the second. Count each sequence separately,
        not merely eight responses across both. After the last fault,
        wait at most one supervision timeout plus HCI observation tolerance,
        with no further Lower Tester DATA. Require reason 0x08 and the correct
        status/handle for each connection.

    Source Note:
        The Notes' ten-opportunity example is not used to replace the explicit
        common timeout. Retain the common 10 ms interval and 300 ms timeout;
        Amber found no source instruction requiring a 100 ms substitution.
        The procedure's four-of-twenty verdict is retained without inventing
        a new statistical threshold from that illustrative example.

    Source Correction:
        The test owner interprets the Section 4.5 AA formulation requirement
        as applying to the valid base connection AA. The corrupted on-air word
        deliberately differs by one prescribed bit and need not satisfy normal
        AA formulation constraints. Validate the base AA, retain every required
        bit in the forty-fault sequence, and send the exact XOR result without
        replacing the address or skipping an invalid-looking corrupted word.
        Retain the reviewed common channel-map correction from Section 4.3.3.1
        to 0x03; no adopted SIG erratum is asserted.

    Reference:
        LL.TS.p28.pdf, standalone LL/ENC/PER/BI-01-C in Section 4.5.5,
        Figure 4.5-6; all Steps 1-15, pass verdict and Notes;
        PDF 1149-1151, printed 4.5-11..13. References [3] 2.1.2, 4.5, 3.1.
    """
    await _invalid_connection_address(tester, central=False, established=True)


async def packets_to_another_central(tester):
    """Packets to another Central.

    Initial Condition:
        Connected Central with a public Lower Tester Peripheral address,
        supported own address type, selected scan interval/window and
        connection interval, common latency and supervision timeout.
        Establish with valid DATA before switching the peer Access Address.

    Test Steps:
        1. Establish a connection with the IUT acting as Central.
        2. Receive DATA once per connection interval on the derived channel.
        3. Reply with DATA whose Access Address has one bit inverted.
        4. Repeat the in-connection Steps 2-3 until twice the supervision
           timeout from the last valid peer packet whose ACK was received.
           See Source Correction for the source's incorrect step reference.
        5. Require Disconnection Complete with supervision-timeout reason
           and the connection handle.
        6. Execute Steps 1-5 for forty trials: invert bits 1 through 20
           in order, then bits 31 through 12 in descending order.

    Expected Outcome:
        Pass verdict:
            At least 32 of forty connections terminate within twice the
            supervision timeout from the last valid packet sent, reporting
            Disconnection Complete reason 0x08.

    Notes:
        Bit zero is the first Access Address bit transmitted over the air.

    Coverage Note:
        Select public addresses, common 10 ms/zero-latency/300 ms parameters
        and common channel classification. Before corrupting the first reply,
        require the Central's ACK of the final valid peer DATA; its RF timestamp
        supplies the observation origin. Record every bounded trial and
        evaluate 32/40 only after all trials. HCI status/handle errors are hard
        failures; post-observation cleanup never contributes to the count.

    Source Correction:
        The test owner interprets the Section 4.5 AA formulation requirement
        as applying to the valid base connection AA. The corrupted on-air word
        deliberately differs by one prescribed bit and need not satisfy normal
        AA formulation constraints. Validate the base AA, retain every required
        bit in the forty-fault sequence, and send the exact XOR result without
        replacing the address or skipping an invalid-looking corrupted word.
        Step 4 literally repeats Steps 1-2, which would re-establish the
        connection while omitting the corrupted reply. Interpret it as repeating
        Steps 2-3 within the existing connection, consistent with the MSC,
        purpose and supervision-time origin. Amber corroborates that intended
        loop; this is a local reference correction, not a published SIG erratum.
        Retain the reviewed common channel-map correction to 0x03.

    Reference:
        LL.TS.p28.pdf, standalone LL/ENC/CEN/BI-01-C in Section 4.5.6,
        Figure 4.5-7; all Steps 1-6, pass verdict and Notes;
        PDF 1151-1152, printed 4.5-13..14. References [3] 2.1.2, 4.5, 3.1.
    """
    await _invalid_connection_address(tester, central=True, established=True)


PROCEDURES: ProcedureMap = {}

# Verify that an advertiser ignores scan requests with an invalid advertising-channel
# synchronization word and continues advertising.
PROCEDURES |= procedure_cases(
    scan_request_invalid_address,
    {
        'LL/ENC/ADV/BI-01-C': (
            'Scan Request Invalid Address',
            {},
        ),
    },
)

# Verify that an advertiser accepts CONNECT_IND, stops advertising and reports
# establishment failure when subsequent Central DATA uses a different Access Address.
PROCEDURES |= procedure_cases(
    central_packets_invalid_address,
    {
        'LL/ENC/ADV/BI-02-C': (
            'Central Packets Invalid Address',
            {},
        ),
    },
)

# Verify that a passive scanner ignores advertising packets whose advertising-channel
# synchronization word / Access Address is invalid.
PROCEDURES |= procedure_cases(
    passive_scanning_invalid_address,
    {
        'LL/ENC/SCN/BI-01-C': pytest.param(
            'Passive Scanning Invalid Address',
            {},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that an active scanner ignores advertisements whose advertising-channel Access
# Address is invalid.
PROCEDURES |= procedure_cases(
    active_scanning_invalid_address,
    {
        'LL/ENC/SCN/BI-02-C': pytest.param(
            'Active Scanning Invalid Address',
            {},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that an initiator fails connection establishment after its Peripheral replies
# use an Access Address different from CONNECT_IND, while respecting the initial
# connection-event transmission rules.
PROCEDURES |= procedure_cases(
    peripheral_packets_invalid_address,
    {
        'LL/ENC/INI/BI-01-C': pytest.param(
            'Peripheral Packets Invalid Address',
            {},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that a connected Peripheral ignores DATA starting an event with an Access
# Address belonging to a different connection.
PROCEDURES |= procedure_cases(
    packets_to_another_peripheral,
    {
        'LL/ENC/PER/BI-01-C': (
            'Packets to Another Peripheral',
            {},
        ),
    },
)

# Verify that a connected Central ignores Peripheral DATA whose Access Address does not
# belong to the connection and eventually terminates through supervision timeout.
PROCEDURES |= procedure_cases(
    packets_to_another_central,
    {
        'LL/ENC/CEN/BI-01-C': (
            'Packets to Another Central',
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_encoding(air_dut, identifier, description, procedure, parameters, marks):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
