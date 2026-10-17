# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL.TS.p28, Section 4.4."""

import random
import struct

import pytest

from bumble import hci
from bumble.ll import (
    LL_ADV_DELAY_MAX_US,
    LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
    LL_ADV_PRIMARY_CHANNELS,
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_INTERVAL_UNIT_US,
    LL_CONN_WINDOW_SIZE_MAX,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_EVENT_COUNTER_MASK,
    LL_IFS_US,
    LL_INSTANT_MIN_LISTENING_EVENTS,
    LL_MAFS_US,
    LL_SCA_50_PPM,
    LL_SCA_500_PPM,
    LL_SCA_PPM,
    LL_SUPERVISION_TIMEOUT_MAX,
    PDU_ADV_ADDRESS_OFFSET,
    PDU_ADV_ADI_DID_BITS,
    PDU_ADV_CONNECT_SCA_SHIFT,
    PDU_ADV_EXT_HEADER_LENGTH_BITS,
    PDU_ADV_OFFSET_UNIT_30_US,
    PDU_ADV_SECOND_ADDRESS_OFFSET,
    PDU_ADV_TYPE_MASK,
    PDU_DATA_LLID_MASK,
    PDU_DATA_MD_MASK,
    PDU_DATA_NESN_MASK,
    PDU_DATA_SN_MASK,
    PDU_HEADER_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
    LlId,
)
from bumble.radio_controller.radio import (
    PHY_TIME_UNITS_PER_SECOND,
    RADIO_CLOCK_JITTER_US,
    RADIO_LOCAL_SCA_PPM,
    Phy,
)
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.link import (
    ADVERTISING_SID,
    AUXILIARY_CHANNEL,
    AUXILIARY_OFFSET_US,
    REPORT_DELIVERY_US,
    SCAN_RESPONSE_IFS_TOLERANCE_US,
    SCANNING_ADVERTISING_INTERVAL_US,
    SCANNING_SCAN_INTERVAL,
    Opcode,
    _check_parameter_update,
    _data_pdu,
    _pending_connection,
    _scanning_check_reports,
    _scanning_Flags,
    _ScanRound,
    _wire_event,
)
from tests.radio_controller.qualification.peer import establish
from tests.radio_controller.qualification.tester import (
    DUT_ADDRESS,
    LOWER_CENTRAL_PUBLIC_ADDRESS,
    LOWER_DATA_ACCESS_ADDRESS,
    LOWER_PERIPHERAL_PUBLIC_ADDRESS,
    PEER_ADDRESS,
    LinkParameters,
    aux_pointer,
    decode_extended,
    ext_pdu,
    extended_enable,
    extended_parameters,
    follow_auxiliary,
    legacy_parameters,
    request_pdu,
    scan_parameters,
    set_extended_data,
)

PEER_PUBLIC = hci.Address(bytes(PEER_ADDRESS), hci.AddressType.PUBLIC_DEVICE)
# Source Correction: the common one-channel map in 4.3.3.1 needs two channels.
COMMON_CHANNEL_MAP = 0x03
Properties = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties
)


def _accept_empty_response(link, packet):
    """Check the expected sequence and ACK before changing the lower tester state."""
    assert packet.valid_crc
    assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
    header = packet.pdu[0]
    assert header & PDU_DATA_LLID_MASK == LlId.CONTINUATION
    assert int(bool(header & PDU_DATA_SN_MASK)) == link.nesn
    assert int(bool(header & PDU_DATA_NESN_MASK)) == link.sn ^ 1
    link._accept(packet)


async def _scan_request_timing(tester, *, phy, offset, legacy=False):
    """Shared integer-us stimulus; section-specific callers document its limitation."""
    primary_phy = Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M
    if legacy:
        await tester.command(
            legacy_parameters(advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL)
        )
        await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(b'\x04\tIUT'))
        await tester.command(hci.HCI_LE_Set_Scan_Response_Data_Command(b'\xaa'))
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    else:
        await tester.command(
            extended_parameters(
                advertising_event_properties=Properties.SCANNABLE_ADVERTISING,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
                primary_advertising_phy=primary_phy,
                secondary_advertising_phy=phy,
            )
        )
        await set_extended_data(tester, b'\xaa', response=True)
        await tester.command(extended_enable())
    responses = 0
    for _ in range(100):
        if legacy:
            channel = LL_ADV_PRIMARY_CHANNELS[0]
            packet = await tester.expect_pdu(channel, kind=AdvertisingPduType.ADV_IND)
            assert packet.pdu[PDU_ADV_SECOND_ADDRESS_OFFSET:] == b'\x04\tIUT'
        else:
            primary = await tester.expect_pdu(
                kind=AdvertisingPduType.ADV_EXT_IND, duration_us=200000, phy=primary_phy
            )
            assert (
                primary.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
                == AdvertisingMode.SCANNABLE
            )
            primary_fields = decode_extended(primary.pdu)
            assert 'target' not in primary_fields
            channel, packet, fields = await follow_auxiliary(
                tester, primary, primary_fields
            )
            assert packet.phy == phy
            assert fields['adi'] == primary_fields['adi']
            assert 'target' not in fields
            assert (
                packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
                == AdvertisingMode.SCANNABLE
            )
            assert fields['address'] == bytes(DUT_ADDRESS)
        await tester.transmit(
            channel,
            request_pdu(AdvertisingPduType.SCAN_REQ, scanner=PEER_PUBLIC),
            start_us=packet.end_us + LL_IFS_US + offset,
            phy=phy,
        )
        end = tester.radio.now_us + 1
        response = await tester.receive(channel, duration_us=1000, phy=phy)
        if response:
            assert response.valid_crc
            assert len(response.pdu) >= PDU_HEADER_SIZE
            assert response.pdu[1] == len(response.pdu) - PDU_HEADER_SIZE
            assert response.phy == phy
            assert (
                abs(response.start_us - end - LL_IFS_US)
                <= SCAN_RESPONSE_IFS_TOLERANCE_US
            )
            if legacy:
                assert (
                    response.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.SCAN_RSP
                )
                assert response.pdu[
                    PDU_ADV_ADDRESS_OFFSET:PDU_ADV_SECOND_ADDRESS_OFFSET
                ] == bytes(DUT_ADDRESS)
                assert response.pdu[PDU_ADV_SECOND_ADDRESS_OFFSET:] == b'\xaa'
            else:
                assert (
                    response.pdu[0] & PDU_ADV_TYPE_MASK
                    == AdvertisingPduType.ADV_EXT_IND
                )
                fields = decode_extended(response.pdu)
                assert fields['address'] == bytes(DUT_ADDRESS)
                assert (
                    response.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
                    == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
                )
                assert fields['data'] == b'\xaa'
            responses += 1
    assert responses >= 95
    await tester.command(
        hci.HCI_LE_Set_Advertising_Enable_Command(0) if legacy else extended_enable(0)
    )


def _coded_response_offset_us(range_m):
    """Apply the source half-us range floor, then approximate late spacing in us."""
    assert range_m >= 0
    range_half_us = 8 * range_m // 500
    return (3 + range_half_us + 1) // 2


async def _auxiliary_scan_timing(tester, *, phy, latest=False):
    """Receive one hundred responses at integer-us subsets of scanner timing edges."""
    primary_phy = Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M
    await tester.command(
        scan_parameters(
            extended=True,
            scanning_phys=1 << primary_phy - 1,
            scan_types=[1],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    generator = random.Random(0)
    received = 0
    round_ = _ScanRound(1)
    response_offset = (
        _coded_response_offset_us(tester.scan_max_coded_range_m) if latest else -2
    )
    for attempt in range(2000):
        adi = ADVERTISING_SID << PDU_ADV_ADI_DID_BITS | attempt
        primary = ext_pdu(
            adi=adi,
            mode=AdvertisingMode.SCANNABLE,
            aux=aux_pointer(AUXILIARY_CHANNEL, AUXILIARY_OFFSET_US, phy),
        )
        distance = (
            (
                primary_phy.airtime_us(len(primary))
                + LL_MAFS_US
                + PDU_ADV_OFFSET_UNIT_30_US
                - 1
            )
            // PDU_ADV_OFFSET_UNIT_30_US
            * PDU_ADV_OFFSET_UNIT_30_US
        )
        primary = ext_pdu(
            adi=adi,
            mode=AdvertisingMode.SCANNABLE,
            aux=aux_pointer(AUXILIARY_CHANNEL, distance, phy),
        )
        start = tester.radio.now_us + REPORT_DELIVERY_US
        await tester.transmit(39, primary, start_us=start, phy=primary_phy)
        end = await tester.transmit(
            AUXILIARY_CHANNEL,
            ext_pdu(
                address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                adi=adi,
                mode=AdvertisingMode.SCANNABLE,
            ),
            start_us=start
            + distance
            + (PDU_ADV_OFFSET_UNIT_30_US - 1 if latest else 0),
            phy=phy,
        )
        request = await tester.receive(
            AUXILIARY_CHANNEL, duration_us=LL_IFS_US + phy.address_us + 2, phy=phy
        )
        if request:
            assert request.valid_crc and request.pdu == request_pdu(
                AdvertisingPduType.SCAN_REQ,
                LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                scanner=DUT_ADDRESS,
            )
            assert abs(request.start_us - end - LL_IFS_US) <= 2
            await tester.transmit(
                AUXILIARY_CHANNEL,
                ext_pdu(address=LOWER_PERIPHERAL_PUBLIC_ADDRESS, adi=adi, data=b'\xaa'),
                start_us=request.end_us + LL_IFS_US + response_offset,
                phy=phy,
            )
            await tester.wait(REPORT_DELIVERY_US)
            assert _scanning_check_reports(
                tester,
                round_,
                b'\xaa',
                adi,
                primary_phy,
                phy,
                (),
                properties=_scanning_Flags.SCANNABLE_ADVERTISING
                | _scanning_Flags.SCAN_RESPONSE,
                report_filter=lambda report: (
                    report.event_type & _scanning_Flags.SCAN_RESPONSE
                ),
            ) == (True, True)
            received += 1
            if received == 100:
                break
        await tester.wait(
            max(
                0,
                start
                + SCANNING_ADVERTISING_INTERVAL_US
                + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
                - tester.radio.now_us,
            )
        )
    assert received == 100
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def earliest_latest_transmission_to_advertiser(tester, *, offset):
    """Earliest/Latest Transmission to Advertiser.

    Initial Condition:
        Undirected advertising with selected Adv_Interval_Min/Max, supported
        own-address type, selected channels, common device name and selected
        name length. Select public addressing, all supported primary channels,
        minimum advertising interval, name data and one scan-response octet.

    Test Steps:
        1. Configure the Lower Tester for active scanning.
        2. Enable undirected IUT advertising on all supported advertising channels.
        3. Select Alternative 3A or 3B according to Table 4.4-1:
           3A.1. BV-01: receive ADV_IND and send SCAN_REQ at T_IFS - 1.5 us
                 after the advertisement ends.
           3B.1. BV-02: receive ADV_IND and send SCAN_REQ at T_IFS + 1.5 us
                 after the advertisement ends.
        4. Receive SCAN_RSP from the IUT at T_IFS after SCAN_REQ.
        5. Repeat Steps 3-4 one hundred times.

    Expected Outcome:
        Pass verdict:
            At least 95 percent of Step 3 requests receive SCAN_RSP.
            Check received response CRC, PDU format, advertiser address,
            exact scan-response data and T_IFS spacing.

    Source Note and Implementation Limit:
        Table 4.4-1 names +/-2 us, but Step 3 and the source Note explicitly
        use +/-1.5 us to allow for tester timing resolution. The integer-us
        PHY API cannot encode that required stimulus. Run one hundred +/-2-us
        stress vectors and require at least 95 valid responses, then disable
        advertising and complete the approximate verdict. This stress check does not
        satisfy the source timing boundary and is not a Source Correction.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.2.1, LL/TIM/ADV/BV-01-C and
        LL/TIM/ADV/BV-02-C;
        PDF 1028-1030, printed 4.4-2..4, Table 4.4-1, Figure 4.4-1,
        Steps 1-5, pass verdict and Note; source reference [3] 4.2, 4.4.2.3.
    """
    await _scan_request_timing(tester, phy=Phy.LE_1M, offset=offset, legacy=True)


async def extended_advertising_secondary_channel_earliest_transmission_to_advertiser(
    tester, *, phy
):
    """Extended Advertising, Secondary Channel, Earliest Transmission to Advertiser.

    Initial Condition:
        Scannable undirected advertising. The source also lists any scan
        interval/window, public peer/Lower Tester address, supported own-address
        type, connection interval, common Peripheral latency and common timeout;
        no connection is established in this procedure. Select public IUT and
        tester addresses and the PHY pair from Table 4.4-2: BV-03 uses 1M/1M,
        BV-05 uses 1M/2M, and BV-06 uses Coded/Coded.

    Test Steps:
        1. Send HCI LE Set Extended Advertising Parameters using all supported
           advertising channels and minimum interval. Set only Scannable bit 1
           in Advertising_Properties, Own_Address_Type=0x00, and primary and
           secondary PHYs from Table 4.4-2. Require successful Command Complete.
        2. Set at least one scan-response octet with HCI LE Set Extended Scan
           Response Data; require successful Command Complete.
        3. Enable extended advertising with Duration[0]=0x0000 (no duration).
        4. Receive ADV_EXT_IND and follow AuxPtr to valid AUX_ADV_IND on the
           indicated secondary channel, at least T_MAFS after the primary PDU.
           Send AUX_SCAN_REQ at T_IFS - 1.5 us after AUX_ADV_IND ends.
        5. Receive AUX_SCAN_RSP at T_IFS +/-2 us after AUX_SCAN_REQ.
        6. Repeat Steps 4-5 one hundred times.
        7. Disable extended advertising; receive HCI Command Complete.

    Expected Outcome:
        Pass verdict:
            At least 95 percent of AUX_SCAN_REQ receive AUX_SCAN_RSP at
            T_IFS +/-2 us. Every followed AuxPtr respects T_MAFS. Check CRC,
            PDU format, advertiser address, selected PHYs, SID and response data.

    Source Note and Implementation Limit:
        Step 4 and the source Note use -1.5 us, not -2 us, to allow for tester
        timing resolution. The integer-us PHY API cannot encode -1.5 us.
        One hundred -2-us stress vectors check response ratio and all remaining
        fields/timing, then complete Step 7 without a precision-only skip. This is
        not a substitute for the specified stimulus or a Source Correction.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.2.2, LL/TIM/ADV/BV-03-C,
        LL/TIM/ADV/BV-05-C and LL/TIM/ADV/BV-06-C;
        PDF 1030-1032, printed 4.4-4..6, Table 4.4-2, Figure 4.4-2,
        Steps 1-7, pass verdict and Note; source reference [10] 4.4.2.5.4.
    """
    await _scan_request_timing(tester, phy=phy, offset=-2)


async def extended_advertising_secondary_channel_latest_transmission_to_advertiser(
    tester, *, phy
):
    """Extended Advertising, Secondary Channel, Latest Transmission to Advertiser.

    Initial Condition:
        Scannable undirected advertising. The source additionally lists any
        scan interval/window, public peer/Lower Tester address, supported
        own-address type, connection interval, common Peripheral latency and
        common timeout; the procedure does not establish a connection. Select
        public addresses and Table 4.4-3 PHYs: BV-04 uses 1M/1M, BV-07 uses
        1M/2M, and BV-08 uses Coded/Coded.

    Test Steps:
        1. Send HCI LE Set Extended Advertising Parameters using all supported
           advertising channels and minimum interval. Set only Scannable bit 1,
           Own_Address_Type=0x00, and the Table 4.4-3 primary/secondary PHYs.
           Require successful Command Complete.
        2. Set at least one scan-response octet using HCI LE Set Extended Scan
           Response Data; require successful Command Complete.
        3. Enable extended advertising with Duration[0]=0x0000 (no duration).
        4. Receive ADV_EXT_IND and follow AuxPtr to valid AUX_ADV_IND on the
           indicated secondary channel, at least T_MAFS after the primary PDU.
           Send AUX_SCAN_REQ at T_IFS + 1.5 us after AUX_ADV_IND ends.
        5. Receive AUX_SCAN_RSP at T_IFS after AUX_SCAN_REQ.
        6. Repeat Steps 4-5 one hundred times.
        7. Disable extended advertising; receive HCI Command Complete.

    Expected Outcome:
        Pass verdict:
            At least 95 percent of Step 4 requests receive AUX_SCAN_RSP.
            Every followed AuxPtr respects T_MAFS. Check response spacing
            with the Core's +/-2-us tolerance, CRC, PDU format, advertiser
            address, selected PHYs, SID and exact response data.

    Source Note and Implementation Limit:
        The source Note explains the +1.5-us stimulus as a margin for tester
        timing resolution, despite the purpose's +2 us. The integer-us PHY API
        cannot encode +1.5 us. Run one hundred +2-us stress vectors and check
        response ratio and remaining timing/fields, then finish without skipping.
        No exact fractional-time pass or source correction is claimed.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.2.3, LL/TIM/ADV/BV-04-C,
        LL/TIM/ADV/BV-07-C and LL/TIM/ADV/BV-08-C;
        PDF 1032-1034, printed 4.4-6..8, Table 4.4-3, Figure 4.4-3,
        Steps 1-7, pass verdict and Note; source reference [10] 4.4.2.5.4.
    """
    await _scan_request_timing(tester, phy=phy, offset=2)


async def adjusting_anchor_point(tester):
    """Adjusting Anchor Point.

    Initial Condition:
        Connected as Peripheral with a public Central peer, common connection
        interval and channel selection, zero latency and 200 ms supervision
        timeout. Any advertising interval, advertising channel map and SCA
        value are permitted. Keep interval, latency and timeout unchanged.

    Test Steps:
        1. Send LL_CONNECTION_UPDATE_IND with maximum legal transmit-window
           size and minimum window offset. Require its acknowledgement.
        2. Send empty DATA and receive a response in every event before the
           connection-update Instant.
        3. Starting the new event, send empty DATA using the common channel
           selection and connection interval. Receive an empty response on the
           same channel T_IFS after the transmission. Repeat up to 15 times.
        4. Interleaved with Step 3, require no LE Connection Update Complete
           event at the Upper Tester.
        5. Send LL_CONNECTION_UPDATE_IND with maximum legal window size and
           maximum window offset. Require its acknowledgement.
        6. Repeat Step 2 until this update's Instant.
        7. Repeat Steps 3-4 using the newly adopted anchor.

    Test Condition:
        Source parameters assume a bit error rate of 0.1 percent or better.
        This test uses the ideal simulated RF path without error injection.

    Expected Outcome:
        Pass verdict:
            Both updates move the anchor while the connection is maintained.
            No HCI event reports a connection-parameter update.

    Coverage Note:
        Select the common 10 ms interval and retain the required 200 ms timeout.
        Maximum legal WinSize is min(8, Interval - 1), hence 7 units here;
        WinOffset ranges from zero through Interval inclusive. These Core
        bounds were cross-checked with Amber; the source's word maximum does
        not require an out-of-range value for the selected interval.
        Use an Instant at least six events ahead, check timing through the
        Instant, and execute all 15 post-update events for each offset. The
        shared helper also checks the no-notification boundary around the
        Instant. Disconnect through HCI after the source verdict.

    Source Correction:
        The common channel map in Section 4.3.3.1 enables only one channel.
        Retain the previously reviewed local correction to channels 0 and 1
        (0x03), the legal two-channel minimum; this is not a SIG erratum.

    Reference:
        LL.TS.p28.pdf, standalone LL/TIM/PER/BV-01-C in Section 4.4,
        Figure 4.4-4; all Steps 1-7, Test Condition, pass verdict and Notes;
        PDF 1034-1036, printed 4.4-8..10. Source reference [3] 5.1.1;
        Core v6.3, Vol 6, Part B, 4.5.3/5.1.1 and Vol 4, Part E, 7.7.65.3.
    """
    link = await establish(
        tester,
        central=False,
        peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
        connection_parameters=LinkParameters(
            interval=8, timeout=20, channel_map=COMMON_CHANNEL_MAP, hop_sca=5
        ),
    )
    for offset in (0, link.parameters.interval):
        update = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + struct.pack(
            '<BHHHHH',
            min(LL_CONN_WINDOW_SIZE_MAX, link.parameters.interval - 1),
            offset,
            link.parameters.interval,
            0,
            link.parameters.timeout,
            link.counter + LL_INSTANT_MIN_LISTENING_EVENTS & LL_EVENT_COUNTER_MASK,
        )
        await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
        await _check_parameter_update(
            tester,
            link,
            update,
            link.parameters.interval,
            link.parameters.timeout,
            notify=False,
        )
        for _ in range(15):
            await link.exchange()
            assert not any(
                isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
                for event in tester.events
            )
    await link.disconnect()


async def earliest_latest_transmission_start_to_peripheral(tester, *, latest):
    """Earliest/Latest Transmission Start to Peripheral.

    Initial Condition:
        Undirected advertising with selected minimum/maximum intervals,
        supported own address type, selected advertising channels and the
        common device name/length. The implementation selects a public IUT
        address and the Lower Tester's public Central address.

    Test Case Configuration:
        LL/TIM/PER/BV-02-C: earliest; 10 s supervision timeout, minimum 1.25 ms
        transmit window and zero offset for the initial connection.
        LL/TIM/PER/BV-03-C: latest; 690 ms timeout, maximum legal transmit
        window and maximum offset for the initial connection.
        Both use a 100 ms connection interval, zero latency, common data
        channel selection and Central SCA 500 ppm.

    Test Steps:
        1. Receive ADV_IND on the selected channel. Send CONNECT_IND T_IFS
           after the advertising PDU with the selected connection parameters.
        2. Require LE Connection Complete with the parameters from Step 1.
        3. Use the alternative selected by Table 4.4-4:
           3A.1. Earliest: send empty DATA at the leading edge of the first
                 event's receive window, including window widening.
           3B.1. Latest: send empty DATA at the trailing edge of that window,
                 including window widening.
        4. Terminate the Peripheral connection.
        5. Repeat Steps 1-4 with maximum transmit-window size and offset
           in the Step 1 CONNECT_IND.
        6. Execute the selected alternative:
           6A.1. Earliest: repeat Steps 1-5, with maximum transmit-window
                 size and offset already applied in Step 1.
           6A.2. Earliest: repeat Steps 1-5, but send no PDU for the first
                 four connection events in Step 3. Send at the widened
                 leading edge of the fifth event.
           6B.1. Latest: repeat Steps 1-5, but send no PDU for the first
                 four connection events in Step 3. Send at the widened
                 leading edge of the fifth event.

    Test Condition:
        Source parameters assume a bit error rate of 0.1 percent or better.

    Expected Outcome:
        Pass verdict:
            Every required connection run completes with the IUT starting
            Peripheral DATA transmissions and maintaining the connection.

    Coverage Note:
        Each Steps 1-5 block contains two connections because Step 5 repeats
        Steps 1-4. Literal expansion therefore executes six connections for
        the earliest case and four for the latest, not three for both.
        Amber corroborated this finite expansion; no source erratum is assumed.
        The missed-event blocks retain their initial window choice until
        Step 5 and use the leading edge even in the latest test.
        Observe three additional DATA events before each HCI disconnect.

    Review Limitation:
        The integer-us lower tester rounds the widening budget upward, then
        transmits one us inside its calculated leading/trailing boundary.
        The source does not specify this guard as equivalent to the exact
        edge stimulus, and Amber could not establish that equivalence.
        This remains a window-acquisition diagnostic, not full edge coverage.

    Source Correction:
        Retain the previously reviewed correction of the common one-channel
        map in Section 4.3.3.1 to the legal two-channel minimum 0x03.
        This is a local correction, not a SIG erratum.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.3.1; Table 4.4-4, Figure 4.4-5,
        Steps 1-6 including 3A/3B and 6A.1/6A.2/6B.1, Test Condition
        and pass verdict; PDF 1036-1038, printed 4.4-10..12.
        Source reference [3] 4.5.5.
    """
    blocks = [(latest, 0)]
    if not latest:
        blocks.append((True, 0))
    blocks.append((latest, 4))
    for initial_maximum, missed in blocks:
        # Step 5 is another connection within every repeated Steps 1-5 block.
        for maximum in (initial_maximum, True):
            parameters = LinkParameters(
                access_address=LOWER_DATA_ACCESS_ADDRESS,
                interval=80,
                timeout=69 if latest else 1000,
                window_size=(
                    LL_CONN_WINDOW_SIZE_MAX if maximum else LL_CONN_WINDOW_SIZE_MIN
                ),
                window_offset=80 if maximum else 0,
                channel_map=COMMON_CHANNEL_MAP,
                hop_sca=5 | LL_SCA_500_PPM << PDU_ADV_CONNECT_SCA_SHIFT,
            )
            link, end = await _pending_connection(
                tester, central=False, parameters=parameters
            )
            link.anchor += missed * parameters.interval * LL_CONN_INTERVAL_UNIT_US
            link.counter = missed
            elapsed = link.anchor - end
            widening = (
                RADIO_CLOCK_JITTER_US
                + (
                    elapsed * (LL_SCA_PPM[LL_SCA_500_PPM] + RADIO_LOCAL_SCA_PPM)
                    + PHY_TIME_UNITS_PER_SECOND
                    - 1
                )
                // PHY_TIME_UNITS_PER_SECOND
            )
            link.anchor += (
                parameters.window_size * LL_CONN_INTERVAL_UNIT_US + widening - 1
                if latest and (not missed)
                else -widening + 1
            )
            await link.exchange()
            for _ in range(3):
                await link.exchange()
            await link.disconnect()


async def shortest_longest_connection_interval(tester, *, offset):
    """Shortest/Longest Connection Interval.

    Initial Condition:
        Connected Peripheral with public addresses, selected connection
        interval, zero latency, selected timeout, common channel selection
        and the signed Lower Tester clock accuracy from Table 4.4-5.
        Use the required nominal 10 ms interval and 32 s supervision timeout.

    Test Case Configuration:
        LL/TIM/PER/BV-04-C: nominal interval minus 15.5 us; -20 ppm.
        LL/TIM/PER/BV-05-C: nominal interval plus 15.5 us; +20 ppm.

    Test Steps:
        1. Execute the selected alternative:
           1A.1. Shortest: send DATA once per event with interval equal to
                 nominal ConnInterval minus 15.5 us. Receive empty DATA
                 T_IFS afterward, with SN equal to current NESN and NESN
                 equal to the next SN. Repeat up to ten times. If a response
                 is absent, send the next packet at nominal ConnInterval
                 and restart the sequence as shown in Figure 4.4-7.
           1B.1. Longest: use nominal ConnInterval plus 15.5 us instead.
                 Require the same response, sequence and acknowledgement
                 checks for up to ten packets. After an absent response,
                 use nominal ConnInterval according to Figure 4.4-8.
        2. Repeat Step 1 five times.
        3. Terminate the unencrypted Peripheral connection with the setup
           interval, latency, timeout, channel map and connection handle.

    Expected Outcome:
        Pass verdict:
            The connection is maintained and all ten packets receive responses
            in at least three of the five repetitions.

    Notes:
        The source uses 15.5 us instead of its nominal 16 us boundary to avoid
        synchronization loss due to tester timing resolution. It assumes a
        bit error rate of 0.1 percent or better.

    Review Limitation:
        This lower tester injects integer-us offsets of -16 or +16 us and does
        not apply the signed 20 ppm clock rate. A declared 50-ppm SCA category
        does not implement that physical rate error. These diagnostic inputs
        are not equivalent to the source stimulus, as Amber confirmed.

    Source Conflict:
        The prose and Figures 4.4-7/8 do not uniquely specify whether the
        nominal-interval restart belongs to the same repetition or consumes a
        new repetition. Amber favors a fresh repetition but confirms the
        ambiguity. Skip the path immediately upon a missing response rather
        than inventing the repetition count or a pass/fail verdict. Fully
        responding runs still exercise all five ten-packet repetitions.

    Source Correction:
        Retain the previously reviewed common channel-map correction from
        Section 4.3.3.1 to 0x03; this is not a SIG erratum.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.3.2; Table 4.4-5, Figures 4.4-6..8,
        all Steps 1-3 including 1A.1/1B.1, pass verdict and Notes;
        PDF 1038-1040, printed 4.4-12..14. Source reference [3] 4.2.
    """
    link = await establish(
        tester,
        central=False,
        peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
        connection_parameters=LinkParameters(
            access_address=LOWER_DATA_ACCESS_ADDRESS,
            interval=8,
            timeout=LL_SUPERVISION_TIMEOUT_MAX,
            channel_map=COMMON_CHANNEL_MAP,
            hop_sca=5 | LL_SCA_50_PPM << PDU_ADV_CONNECT_SCA_SHIFT,
        ),
    )
    completed = 0
    for _ in range(5):
        good = 0
        for _ in range(10):
            link.anchor += offset
            packet, _ = await _wire_event(
                link, lambda _: _data_pdu(link.sn, link.nesn), required=False
            )
            if packet is None:
                pytest.skip(
                    'Source conflict: the restart repetition boundary after a miss '
                    'is not explicit in LL.TS.p28 4.4.3.2; Amber cannot resolve it'
                )
            _accept_empty_response(link, packet)
            good += 1
        completed += good == 10
    assert completed >= 3
    await link.disconnect()


async def earliest_latest_transmissions_to_peripheral(tester, *, offset):
    """Earliest/Latest Transmissions to Peripheral.

    Initial Condition:
        Connected Peripheral with public addresses, selected connection
        interval, zero latency, selected supervision timeout, common channel
        selection and any SCA. Use the required 10 ms interval and 32 s
        timeout in CONNECT_IND; retain the unencrypted connection handle.

    Test Case Configuration:
        LL/TIM/PER/BV-06-C: earliest, Table 4.4-6 nominal T_IFS minus 2 us;
        the actual Step 2A.1 lower-tester stimulus is T_IFS minus 1.5 us.
        LL/TIM/PER/BV-07-C: latest, nominal T_IFS plus 2 us;
        the actual Step 2B.1 stimulus is T_IFS plus 1.5 us.

    Test Steps:
        1. At the start of a connection event, send DATA with MD set to one.
           Receive empty DATA from the IUT T_IFS afterward.
        2. Execute the selected alternative in that same event:
           2A.1. Earliest: send a second DATA with MD zero at T_IFS minus
                 1.5 us after the IUT response. Receive empty DATA T_IFS
                 after that second transmission.
           2B.1. Latest: send the second DATA with MD zero at T_IFS plus
                 1.5 us instead. Receive empty DATA T_IFS afterward.
        3. Repeat for up to ten connection events.
        4. Terminate the unencrypted Peripheral connection using the setup
           interval, latency, timeout, channel map and connection handle.

    Expected Outcome:
        Pass verdict:
            Maintain the connection and receive responses to at least
            95 percent of the packets sent in Step 2.

    Notes:
        The source uses 1.5 us instead of 2 us to avoid synchronization loss
        due to lower-tester timing resolution. With ten attempts, the
        95-percent threshold requires all ten second-packet responses.

    Coverage Note:
        Validate empty DATA, CRC, SN and NESN before updating peer ARQ state.
        Use the common channel selection and exact HCI disconnect handle.

    Review Limitation:
        The integer-us PHY interface currently injects T_IFS minus or plus
        2 us, not the source's 1.5 us stimulus. Passing these diagnostics
        does not prove the exact fractional-time receive boundary.

    Source Correction:
        Retain the previously reviewed common channel-map correction from
        Section 4.3.3.1 to 0x03; this is not a SIG erratum.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.3.3; Table 4.4-6, Figure 4.4-9,
        all Steps 1-4 including 2A.1/2B.1, pass verdict and Notes;
        PDF 1041-1043, printed 4.4-15..17. Source reference [3] 4.2.
    """
    link = await establish(
        tester,
        central=False,
        peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
        connection_parameters=LinkParameters(
            access_address=LOWER_DATA_ACCESS_ADDRESS,
            interval=8,
            timeout=LL_SUPERVISION_TIMEOUT_MAX,
            channel_map=COMMON_CHANNEL_MAP,
            hop_sca=5,
        ),
    )
    count = 0
    for _ in range(10):
        channel = link.channel
        await tester.transmit(
            channel,
            bytes([_data_pdu(link.sn, link.nesn)[0] | PDU_DATA_MD_MASK, 0]),
            start_us=link.anchor,
            **link.radio_parameters,
        )
        end = tester.radio.now_us + 1
        response = await tester.expect_pdu(
            channel, duration_us=1000, **link.radio_parameters
        )
        assert response.start_us == end + LL_IFS_US
        _accept_empty_response(link, response)
        await tester.transmit(
            channel,
            _data_pdu(link.sn, link.nesn),
            start_us=response.end_us + LL_IFS_US + offset,
            **link.radio_parameters,
        )
        end = tester.radio.now_us + 1
        response = await tester.receive(
            channel, duration_us=1000, **link.radio_parameters
        )
        if response:
            assert response.start_us == end + LL_IFS_US
            _accept_empty_response(link, response)
            count += 1
        link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    assert count * 100 >= 95 * 10
    await link.disconnect()


async def earliest_latest_transmissions_to_central(tester, *, offset):
    """Earliest/Latest Transmissions to Central.

    Initial Condition:
        Connected Central using a public Lower Tester Peripheral address,
        supported own address type, common connection interval, latency,
        timeout and channel map, without encryption. Any scan interval
        and scan window are permitted. Select the common 10 ms interval,
        zero latency and 300 ms supervision timeout.

    Test Case Configuration:
        LL/TIM/CEN/BV-01-C: minimum inter-frame spacing, maximum negative
        jitter; Step 2A.1 specifies T_IFS 150 - 1.5 us and -50 ppm drift.
        LL/TIM/CEN/BV-02-C: maximum spacing, peak jitter; Step 2B.1 specifies
        T_IFS 150 + 1.5 us and +50 ppm drift.

    Test Steps:
        1. Receive empty DATA from the Central once per connection interval
           on the data channel derived from the common selection parameters.
        2. Execute the alternative selected in Table 4.4-16:
           2A.1. In events requiring a Peripheral response under its latency,
                 send DATA at T_IFS 150 - 1.5 us after the IUT packet,
                 applying packet timing drift -50 ppm.
           2B.1. In required events, send DATA at T_IFS 150 + 1.5 us
                 instead, applying packet timing drift +50 ppm.
        3. Repeat Steps 1-2 fifteen times.
        4. Terminate the unencrypted Central connection using the setup
           interval, latency, timeout, channel map and connection handle.

    Expected Outcome:
        Pass verdict:
            The procedure completes and the IUT maintains the connection.

    Notes:
        The source uses 1.5 us rather than 2 us to avoid synchronization loss
        due to lower-tester timing resolution.

    Coverage Note:
        With zero selected Peripheral latency, reply in every observed event.
        Verify the anchor, empty DATA, CRC, SN and NESN before advancing ARQ,
        and check the final peer packet's ACK at the next connection event.
        Require no disconnection before the explicit HCI termination.

    Review Limitation:
        The current lower tester uses integer-us spacing of 148 or 152 us.
        It does not synthesize the source's fractional-us jitter or the
        signed 50 ppm on-air packet timing drift. These diagnostics cannot
        establish full coverage of either timing case.

    Source Correction:
        Retain the previously reviewed common channel-map correction from
        Section 4.3.3.1 to 0x03; this is not a SIG erratum.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.4.1; Table 4.4-16, Figure 4.4-26,
        all Steps 1-4 including 2A.1/2B.1, pass verdict and Notes;
        PDF 1080-1081, printed 4.4-54..55. Source reference [3] 4.2.
    """
    await tester.command(
        hci.HCI_LE_Set_Host_Channel_Classification_Command(
            COMMON_CHANNEL_MAP.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
        )
    )
    link = await establish(
        tester,
        central=True,
        peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
        interval=8,
        timeout=30,
    )
    for _ in range(15):
        packet = await tester.expect_pdu(
            link.channel,
            start_us=max(tester.radio.now_us + 1, link.anchor - 50),
            duration_us=link.anchor - tester.radio.now_us + 1000,
            **link.radio_parameters,
        )
        assert packet.start_us == link.anchor and packet.pdu[1] == 0
        _accept_empty_response(link, packet)
        await tester.transmit(
            link.channel,
            _data_pdu(link.sn, link.nesn),
            start_us=packet.end_us + LL_IFS_US + offset,
            **link.radio_parameters,
        )
        link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
        link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    sent_sn = link.sn
    packet = await link.exchange()
    assert int(bool(packet.pdu[0] & PDU_DATA_NESN_MASK)) == sent_sn ^ 1
    assert not any(
        isinstance(event, hci.HCI_Disconnection_Complete_Event)
        for event in tester.events
    )
    await link.disconnect()


async def extended_scanning_secondary_channel_earliest_transmission_to_scanner(
    tester, *, phy
):
    """Extended Scanning, Secondary Channel, Earliest Transmission to Scanner.

    Initial Condition:
        The Lower Tester is a scannable undirected advertiser using a public
        address; the IUT starts with scanning disabled. Select scan interval,
        window and supported own address type. See Source Correction for the
        source's initial-state wording.

    Test Case Configuration:
        LL/TIM/SCN/BV-05-C: LE 1M primary and secondary PHYs, Core 5.1 case.
        LL/TIM/SCN/BV-06-C: LE 1M primary and LE 2M secondary, Core 5.1 case.
        The report SID comes from AUX_SCAN_RSP if its ADI is present,
        otherwise from AUX_ADV_IND. This implementation includes response ADI.

    Test Steps:
        1. Configure the Lower Tester for scannable advertising on the selected
           primary/secondary PHYs. Use only primary channel 39.
        2. Enable IUT active scanning with the PHY selection in Table 4.4-35.
        3. Send ADV_EXT_IND with AuxPtr to a valid AUX_ADV_IND. Select the
           smallest representable offset at least equal to primary packet
           duration plus T_MAFS, then transmit at the represented time,
           300-329 us after the primary ends. Change ADI DID each event.
        4. Receive AUX_SCAN_REQ and send AUX_SCAN_RSP T_IFS minus 1.5 us
           after the request ends.
        5. Require one or more Extended Advertising Reports with periodic
           interval zero, the Lower Tester address/type and Scan Response
           event-type bit set.
        6. Repeat Steps 3-5 until 100 AUX_SCAN_REQ packets have been received.
        7. Disable extended scanning and require successful Command Complete.
           See Source Correction for the command name in the source.

    Expected Outcome:
        Pass verdict:
            Every scan request answered by the Lower Tester produces the
            required scan-response report, with the SID from Table 4.4-35.

    Coverage Note:
        Select continuous scanning with interval/window 0x0010, duplicate
        filtering disabled, SID 3 and fixed response data. Verify exact
        address/type, report flags, PHYs, periodic interval, SID and data.
        No separate preliminary advertising report is required. Advertising
        reports may be absent or delivered together with scan-response reports.
        A finite 2000-advertisement guard bounds this diagnostic's execution.

    Review Limitation:
        The integer-us response stimulus is T_IFS minus 2 us, not the required
        minus 1.5 us. Correct rounded AuxPtr placement and successful report
        delivery do not establish the fractional response timing boundary.

    Source Correction:
        The source's Scannable Undirected Advertising initial state describes
        the Lower Tester, not the IUT scanner. Its Step 7 legacy Scan Enable
        command is replaced with LE Set Extended Scan Enable, Enable zero.
        Amber corroborates both local corrections against Core v6.3,
        Vol 6, Part B, 4.4.2.5.2 and Vol 4, Part E, 7.8.11/7.8.65.
        These are not claimed as adopted SIG errata.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.6.1; Table 4.4-35, Figure 4.4-52,
        all Steps 1-7 and pass verdict; PDF 1132-1134,
        printed 4.4-106..108. Source reference [10] 4.4.2.5.4.
    """
    await _auxiliary_scan_timing(tester, latest=False, phy=phy)


async def coded_secondary_scanning_earliest_transmission(
    tester,
):
    """Extended Scanning, Secondary Channel, Earliest Transmission to Scanner, LE Coded
    PHY.

    Initial Condition:
        The Lower Tester is a public-address scannable undirected advertiser.
        The IUT is initially scan-disabled, with selected scan interval,
        window and supported own address type. See Source Correction.

    Test Case Configuration:
        LL/TIM/SCN/BV-07-C: Core 5.1 SID reporting. Both primary and secondary
        use LE Coded; the report SID is from AUX_SCAN_RSP if ADI is present,
        otherwise from AUX_ADV_IND. Response ADI is present in this stimulus.

    Test Steps:
        1. Configure scannable advertising on LE Coded primary and secondary
           PHYs. Use primary channel 39 only.
        2. Enable IUT active scanning with Scanning_PHYs 0x04, LE Coded.
        3. Send ADV_EXT_IND referring through AuxPtr to valid AUX_ADV_IND.
           Use the smallest representable offset at least equal to primary
           packet duration plus T_MAFS. Transmit at the represented offset,
           300-329 us after the primary ends, and change ADI DID each event.
        4. Receive AUX_SCAN_REQ and send AUX_SCAN_RSP T_IFS minus 1.5 us
           after the request ends.
        5. Require Extended Advertising Reports with periodic interval zero,
           the Lower Tester address/type and the Scan Response bit.
        6. Repeat Steps 3-5 until 100 AUX_SCAN_REQ packets have been received.
        7. Disable extended scanning and require successful Command Complete.

    Expected Outcome:
        Pass verdict:
            Each answered request produces the required scan-response report
            with the SID prescribed by Table 4.4-36.

    Notes:
        The source uses a 1.5 us margin instead of its nominal 2 us boundary
        to avoid synchronization loss due to lower-tester timing resolution.

    Coverage Note:
        Use continuous interval/window 0x0010 and duplicate filtering zero.
        Verify exact public addresses, report flags, Coded PHYs, periodic
        interval, response SID and complete data. An independent preliminary
        advertising report is not required. Bound execution at 2000 adverts.

    Review Limitation:
        The current integer-us response stimulus is T_IFS minus 2 us, not
        minus 1.5 us. This diagnostic does not prove the fractional boundary.

    Source Correction:
        Interpret the advertising initial state as the Lower Tester state,
        with IUT scanning enabled only in Step 2. Disable the selected extended
        scanning family through LE Set Extended Scan Enable in Step 7,
        rather than the source's legacy Scan Enable command. Amber confirmed
        these readings against Core v6.3, Vol 6, Part B, 4.4.2.5.2 and
        Vol 4, Part E, 7.8.11/7.8.65; no adopted SIG erratum is asserted.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.6.2; Table 4.4-36, Figure 4.4-53,
        all Steps 1-7, pass verdict and Notes; PDF 1134-1136,
        printed 4.4-108..110. Source reference [10] 4.4.2.5.4.
    """
    await _auxiliary_scan_timing(tester, phy=Phy.LE_CODED, latest=False)


async def coded_secondary_scanning_latest_transmission(
    tester,
):
    """Extended Scanning, Secondary Channel, Latest Transmission to Scanner, LE Coded
    PHY.

    Initial Condition:
        The Lower Tester is a public-address scannable undirected advertiser.
        The IUT is initially scan-disabled, with selected scan interval,
        window and supported own address type. See Source Correction.

    Test Case Configuration:
        LL/TIM/SCN/BV-08-C: Core 5.1 SID reporting. Use LE Coded on primary
        and secondary PHYs. The report SID is from AUX_SCAN_RSP if ADI is
        present, otherwise from AUX_ADV_IND. This stimulus includes ADI.

    Test Steps:
        1. Configure scannable advertising on LE Coded primary and secondary
           PHYs. Use primary channel 39 only.
        2. Enable IUT active scanning with Scanning_PHYs 0x04, LE Coded.
        3. Send ADV_EXT_IND with AuxPtr to a valid AUX_ADV_IND transmitted
           at Aux Offset plus Offset Unit minus 0.5 us from the primary start.
           Change ADI DID in every advertising event.
        4. Receive AUX_SCAN_REQ and send AUX_SCAN_RSP T_IFS plus 1.5 us
           plus simulated range delay after the request ends. For the declared
           R = TSPX_scan_max_coded_range, compute:
           range_delay = floor((2 * R * 4 ns) / 0.5 us) * 0.5 us.
        5. Require Extended Advertising Reports with periodic interval zero,
           the Lower Tester address/type and the Scan Response bit.
        6. Repeat Steps 3-5 until 100 AUX_SCAN_REQ packets have been received.
        7. Disable extended scanning and require successful Command Complete.

    Expected Outcome:
        Pass verdict:
            Each answered request produces the required scan-response report
            with the SID prescribed by Table 4.4-37.

    Notes:
        The source uses T_IFS plus 1.5 us instead of plus 2 us, and Offset
        Unit minus 0.5 us instead of a full Offset Unit, to avoid tester
        timing-resolution synchronization errors.

    Coverage Note:
        Select continuous interval/window 0x0010 and duplicate filtering zero.
        Verify exact public addresses, report flags, Coded PHYs, periodic
        interval, response SID and data. No independent preliminary advertising
        report is required. A 2000-advertisement guard bounds execution.

    Review Limitation:
        The integer-us auxiliary delay is Offset Unit minus 1 us, not minus
        0.5 us; the response is T_IFS plus 2 us, not plus 1.5 us. The diagnostic
        uses the declared simulated range, applies the source half-us range floor,
        and rounds the combined response delay to whole us. This does not
        establish the source's exact fractional edge.

    Source Correction:
        Treat the advertising initial state as the Lower Tester's state,
        with the IUT enabled for scanning in Step 2. Use LE Set Extended Scan
        Enable, Enable zero, in Step 7 rather than legacy Scan Enable.
        Amber corroborates these local corrections against Core v6.3,
        Vol 6, Part B, 4.4.2.5.2 and Vol 4, Part E, 7.8.11/7.8.65.
        No adopted SIG erratum is claimed.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.4.6.3; Table 4.4-37, Figure 4.4-54,
        all Steps 1-7, pass verdict and Notes; PDF 1136-1138,
        printed 4.4-110..112. Source references [10] 4.2.3/4.4.2.5.4.
    """
    await _auxiliary_scan_timing(tester, phy=Phy.LE_CODED, latest=True)


PROCEDURES: ProcedureMap = {}

# Verify that an advertiser responds to scan requests at the specified minimum/maximum
# inter-packet timing. The Lower Tester requests information from the IUT and receives a
# scan response.
PROCEDURES |= procedure_cases(
    earliest_latest_transmission_to_advertiser,
    {
        'LL/TIM/ADV/BV-01-C': pytest.param(
            'Earliest transmission to Advertiser',
            {'offset': -2},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/ADV/BV-02-C': pytest.param(
            'Latest transmission to Advertiser',
            {'offset': 2},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify scannable undirected ADV_EXT_IND with a valid AuxPtr to AUX_ADV_IND, and
# response to a secondary-channel scan request sent at the minimum transmission time
# after the auxiliary advertisement.
PROCEDURES |= procedure_cases(
    extended_advertising_secondary_channel_earliest_transmission_to_advertiser,
    {
        'LL/TIM/ADV/BV-03-C': pytest.param(
            (
                'Extended Advertising, Secondary Channel, Earliest '
                'Transmission to Advertiser – LE 1M PHY'
            ),
            {'phy': Phy.LE_1M},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/ADV/BV-05-C': pytest.param(
            (
                'Extended Advertising, Secondary Channel, Earliest '
                'Transmission to Advertiser – LE 2M PHY'
            ),
            {'phy': Phy.LE_2M},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/ADV/BV-06-C': pytest.param(
            (
                'Extended Advertising, Secondary Channel, Earliest '
                'Transmission to Advertiser – LE Coded PHY'
            ),
            {'phy': Phy.LE_CODED},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify scannable undirected ADV_EXT_IND with a valid AuxPtr to AUX_ADV_IND, and
# response to a secondary-channel scan request at the maximum transmission time. The
# purpose names T_IFS + 2 us; Step 4 and the source Note prescribe a +1.5-us tester
# stimulus.
PROCEDURES |= procedure_cases(
    extended_advertising_secondary_channel_latest_transmission_to_advertiser,
    {
        'LL/TIM/ADV/BV-04-C': pytest.param(
            (
                'Extended Advertising, Secondary Channel, Latest '
                'Transmission to Advertiser – LE 1M PHY'
            ),
            {'phy': Phy.LE_1M},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/ADV/BV-07-C': pytest.param(
            (
                'Extended Advertising, Secondary Channel, Latest '
                'Transmission to Advertiser – LE 2M PHY'
            ),
            {'phy': Phy.LE_2M},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/ADV/BV-08-C': pytest.param(
            (
                'Extended Advertising, Secondary Channel, Latest '
                'Transmission to Advertiser – LE Coded PHY'
            ),
            {'phy': Phy.LE_CODED},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify that a Peripheral adopts the new anchor point after a peer connection update
# while preserving the unchanged connection parameters. Exercise minimum and maximum
# transmit-window offsets and observe continued data-channel responses without a Host
# update event.
PROCEDURES |= procedure_cases(
    adjusting_anchor_point,
    {
        'LL/TIM/PER/BV-01-C': (
            'Adjusting Anchor Point',
            {},
        ),
    },
)

# Verify that an advertising IUT establishes and maintains a Peripheral connection when
# the Central's first DATA uses the selected leading or trailing edge of the widened
# receive window.
PROCEDURES |= procedure_cases(
    earliest_latest_transmission_start_to_peripheral,
    {
        'LL/TIM/PER/BV-02-C': pytest.param(
            'Earliest Transmission Start to Peripheral',
            {'latest': False},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/PER/BV-03-C': pytest.param(
            'Latest Transmission Start to Peripheral',
            {'latest': True},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify that a Peripheral maintains the connection and responds correctly when its
# Central uses the shortest or longest specified inter-event transmission timing.
PROCEDURES |= procedure_cases(
    shortest_longest_connection_interval,
    {
        'LL/TIM/PER/BV-04-C': pytest.param(
            'Shortest Connection Interval',
            {'offset': -16},
            marks=[
                pytest.mark.limited,
                pytest.mark.source_conflict,
            ],
        ),
        'LL/TIM/PER/BV-05-C': pytest.param(
            'Longest Connection Interval',
            {'offset': 16},
            marks=[
                pytest.mark.limited,
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that a Peripheral maintains the connection and responds when its Central uses
# the specified minimum or maximum same-event spacing.
PROCEDURES |= procedure_cases(
    earliest_latest_transmissions_to_peripheral,
    {
        'LL/TIM/PER/BV-06-C': pytest.param(
            'Earliest Transmissions to Peripheral',
            {'offset': -2},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/PER/BV-07-C': pytest.param(
            'Latest Transmissions to Peripheral',
            {'offset': 2},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify that a Central maintains an unencrypted connection when its Peripheral responds
# with the specified minimum or maximum spacing, jitter and active-mode packet clock
# drift.
PROCEDURES |= procedure_cases(
    earliest_latest_transmissions_to_central,
    {
        'LL/TIM/CEN/BV-01-C': pytest.param(
            'Earliest Transmissions to Central',
            {'offset': -2},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/CEN/BV-02-C': pytest.param(
            'Latest Transmissions to Central',
            {'offset': 2},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify that a scanner receives and processes AUX_ADV_IND at the minimum permitted
# secondary-channel separation from ADV_EXT_IND.
PROCEDURES |= procedure_cases(
    extended_scanning_secondary_channel_earliest_transmission_to_scanner,
    {
        'LL/TIM/SCN/BV-05-C': pytest.param(
            (
                'Extended Scanning, Secondary Channel, Earliest '
                'Transmission to Scanner – LE 1M PHY, Core 5.1'
            ),
            {'phy': Phy.LE_1M},
            marks=[
                pytest.mark.limited,
            ],
        ),
        'LL/TIM/SCN/BV-06-C': pytest.param(
            (
                'Extended Scanning, Secondary Channel, Earliest '
                'Transmission to Scanner – LE 2M PHY, Core 5.1'
            ),
            {'phy': Phy.LE_2M},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify that a scanner processes LE Coded auxiliary advertising at its earliest
# permitted offset and the corresponding earliest scan response.
PROCEDURES |= procedure_cases(
    coded_secondary_scanning_earliest_transmission,
    {
        'LL/TIM/SCN/BV-07-C': pytest.param(
            (
                'Extended Scanning, Secondary Channel, Earliest '
                'Transmission to Scanner, LE Coded PHY, Core 5.1'
            ),
            {},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify that a scanner processes LE Coded auxiliary advertising at the latest permitted
# offset and a scan response with maximum spacing, including the simulated range delay.
PROCEDURES |= procedure_cases(
    coded_secondary_scanning_latest_transmission,
    {
        'LL/TIM/SCN/BV-08-C': pytest.param(
            (
                'Extended Scanning, Secondary Channel, Latest Transmission '
                'to Scanner, LE Coded PHY, Core 5.1'
            ),
            {},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_timing(air_dut, identifier, description, procedure, parameters, marks):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
