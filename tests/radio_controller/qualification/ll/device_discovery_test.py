# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL.TS.p28, Section 4.2: Device Discovery."""

import csv
import random
from bisect import bisect_right
from itertools import pairwise
from types import SimpleNamespace

import pytest

from bumble import hci
from bumble.core import AdvertisingData
from bumble.ll import (
    LL_ADV_DELAY_MAX_US,
    LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
    LL_ADV_PRIMARY_CHANNELS,
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_ESTABLISHMENT_EVENTS,
    LL_CONN_INTERVAL_UNIT_US,
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    LL_HOP_INCREMENT_MAX,
    LL_HOP_INCREMENT_MIN,
    LL_IFS_US,
    LL_MAFS_US,
    LL_PERIODIC_INTERVAL_MIN,
    LL_PERIODIC_INTERVAL_UNIT_US,
    LL_SCA_500_PPM,
    LL_SCA_PPM,
    PDU_ADV_ADDRESS_OFFSET,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_ADI_DID_BITS,
    PDU_ADV_ADI_DID_MASK,
    PDU_ADV_ADI_SID_MAX,
    PDU_ADV_AUX_CA_MASK,
    PDU_ADV_AUX_OFFSET_PHY_SIZE,
    PDU_ADV_AUX_OFFSET_UNITS_MASK,
    PDU_ADV_CHSEL_MASK,
    PDU_ADV_CONNECT_HOP_MASK,
    PDU_ADV_DECISION_RESOLVABLE_TAG_MASK,
    PDU_ADV_EXT_AUX_PTR_MASK,
    PDU_ADV_EXT_FLAGS_RESERVED_MASK,
    PDU_ADV_EXT_HEADER_LENGTH_BITS,
    PDU_ADV_EXT_HEADER_OFFSET,
    PDU_ADV_EXT_PAYLOAD_SIZE_MAX,
    PDU_ADV_LEGACY_DATA_SIZE_MAX,
    PDU_ADV_OFFSET_BITS,
    PDU_ADV_OFFSET_UNIT_30_US,
    PDU_ADV_OFFSET_UNIT_300_US,
    PDU_ADV_OFFSET_VALUE_MASK,
    PDU_ADV_RESERVED_MASK,
    PDU_ADV_RXADD_MASK,
    PDU_ADV_SCAN_REQ_SIZE,
    PDU_ADV_SECOND_ADDRESS_OFFSET,
    PDU_ADV_SYNC_INFO_SIZE,
    PDU_ADV_SYNC_OFFSET_RESERVED_MASK,
    PDU_ADV_TXADD_MASK,
    PDU_ADV_TYPE_MASK,
    PDU_HEADER_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
    LlId,
)
from bumble.radio_controller.radio import (
    PHY_CODED_S2_FACTOR,
    PHY_CODED_S8_FACTOR,
    PHY_OCTET_BITS,
    PHY_TIME_UNITS_PER_SECOND,
    RADIO_CLOCK_JITTER_US,
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
    SCAN_ADV_INTERVAL_US,
    SCAN_INTERVAL_US,
    SCAN_RESPONSE_IFS_TOLERANCE_US,
    SCANNING_ADVERTISING_INTERVAL_US,
    SCANNING_SCAN_INTERVAL,
    _corrupt_advertisements,
    _encoding_take_reports,
    _scanning_check_reports,
    _scanning_Flags,
    _ScanRound,
    _start_scanning,
)
from tests.radio_controller.qualification.peer import PeerLink
from tests.radio_controller.qualification.periodic import (
    PeriodicAdvertiser,
    PeriodicTrain,
    subevent_channels,
)
from tests.radio_controller.qualification.tester import (
    DUT_ADDRESS,
    LOWER_CENTRAL_PUBLIC_ADDRESS,
    LOWER_DATA_ACCESS_ADDRESS,
    LOWER_PERIPHERAL_PUBLIC_ADDRESS,
    PEER_ADDRESS,
    LinkParameters,
    adv_pdu,
    aux_pointer,
    chain,
    check_access_address,
    create_sync,
    csa2_channel,
    decode_aux,
    decode_extended,
    ext_pdu,
    extended_enable,
    extended_parameters,
    follow_auxiliary,
    legacy_parameters,
    receive_extended,
    request_pdu,
    scan_parameters,
    set_extended_data,
)

ErrorCode = hci.HCI_ErrorCode
AdvType = hci.HCI_LE_Set_Advertising_Parameters_Command.AdvertisingType
Properties = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties
)
SyncOptions = hci.HCI_LE_Periodic_Advertising_Create_Sync_Command.Options
LegacyEventType = hci.HCI_LE_Advertising_Report_Event.EventType
PERIODIC_RESPONSE_TIMING_INFORMATION = (
    AdvertisingData.Type.PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION
)
Operation = hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation
# Endpoint jitter in the common advertising timing notes, 16 us at each endpoint.
ADVERTISING_INTERVAL_JITTER_US = 32
# The LL test suite permits a deviation of 2 us from the response T_IFS.
RESPONSE_IFS_TOLERANCE_US = 2
# Selected IXIT: minimum advertising interval, public AdvA, all three channels
# supported.
ADVERTISING_INTERVAL_US = hci.HCI_LE_ADV_INTERVAL_MIN * hci.HCI_LE_ADV_INTERVAL_UNIT_US
# Maximum-length payload prescribed by Tables 4.2-9 and 4.2-11.
LEGACY_MAXIMUM_DATA = b'\xf8' + bytes(PDU_ADV_LEGACY_DATA_SIZE_MAX - 1)
# Device name prescribed by the common discovery preconditions, Section 4.1.6.
IUT_NAME_DATA = bytes([4, AdvertisingData.COMPLETE_LOCAL_NAME]) + b'IUT'


def advertising_interval_limits(interval_us):
    """Apply the source's 500-ppm drift and two-endpoint jitter bounds."""
    ppm = LL_SCA_PPM[LL_SCA_500_PPM]
    maximum = interval_us + LL_ADV_DELAY_MAX_US

    def drift(value):
        return (
            value * ppm + PHY_TIME_UNITS_PER_SECOND - 1
        ) // PHY_TIME_UNITS_PER_SECOND

    return (
        interval_us - drift(interval_us) - ADVERTISING_INTERVAL_JITTER_US,
        maximum + drift(maximum) + ADVERTISING_INTERVAL_JITTER_US,
    )


def public_peer_addresses():
    """Default public address and the three XOR vectors from Section 4.1.5.2."""
    iut = int.from_bytes(bytes(DUT_ADDRESS), 'little')
    return (LOWER_CENTRAL_PUBLIC_ADDRESS,) + tuple(
        hci.Address((iut ^ mask).to_bytes(6, 'little'), hci.AddressType.PUBLIC_DEVICE)
        for mask in (181419418583040, 90, 98956046500005)
    )


def _check_advertisement(packet, data):
    assert packet.phy == Phy.LE_1M
    assert not packet.pdu[0] & PDU_ADV_TXADD_MASK
    assert packet.pdu[PDU_ADV_ADDRESS_OFFSET:] == bytes(DUT_ADDRESS) + data


def _nonconnectable_extended_packet(packet, phy):
    """Validate the RF envelope for the configured public-address advertising set."""
    assert packet.valid_crc and packet.phy == phy
    assert packet.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
    fields = decode_extended(packet.pdu)
    assert (
        packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
        == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
    )
    if 'address' in fields:
        assert not packet.pdu[0] & PDU_ADV_TXADD_MASK
    if 'target' in fields:
        assert not packet.pdu[0] & PDU_ADV_RXADD_MASK
    return fields


def _check_advertising_update(previous, observed, did, expected):
    """Apply BV-27's RF-to-RF DID rule before accepting a new payload."""
    if previous is not None and observed != previous[0]:
        assert did != previous[1], 'Advertising data changed without a new DID'
    if previous is None or did != previous[1]:
        assert observed == expected, 'New DID does not carry the submitted data'
    return observed, did


def _overlapping_advertisement(packet, mode):
    """Decode one primary packet's RF identity and quantized auxiliary window."""
    assert packet.valid_crc and packet.phy == Phy.LE_1M
    assert packet.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
    assert packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS == mode
    fields = decode_extended(packet.pdu)
    assert 'aux' in fields and 'adi' in fields
    value = int.from_bytes(fields['aux'], 'little')
    assert value >> (PHY_OCTET_BITS + PDU_ADV_OFFSET_BITS) == Phy.LE_1M - 1
    channel, offset = decode_aux(fields['aux'])
    unit = (
        PDU_ADV_OFFSET_UNIT_300_US
        if value & PDU_ADV_AUX_OFFSET_UNITS_MASK
        else PDU_ADV_OFFSET_UNIT_30_US
    )
    target = packet.start_us + offset
    return fields, channel, target, target + unit


async def _observe_intervals(tester, channel, kind, data, count, *, chsel=None):
    minimum, maximum = advertising_interval_limits(ADVERTISING_INTERVAL_US)
    previous = None
    short_intervals = 0
    for _ in range(count + 1):
        packet = await tester.expect_pdu(channel, kind=kind)
        _check_advertisement(packet, data)
        if kind in (
            AdvertisingPduType.ADV_NONCONN_IND,
            AdvertisingPduType.ADV_SCAN_IND,
        ):
            assert not packet.pdu[0] & PDU_ADV_CHSEL_MASK
        if kind == AdvertisingPduType.ADV_DIRECT_IND:
            assert not packet.pdu[0] & PDU_ADV_RXADD_MASK
        if chsel is not None:
            assert bool(packet.pdu[0] & PDU_ADV_CHSEL_MASK) == chsel
        if previous is not None:
            interval = packet.start_us - previous
            assert minimum <= interval <= maximum, (interval, minimum, maximum)
            short_intervals += (
                interval <= ADVERTISING_INTERVAL_US + LL_ADV_DELAY_MAX_US // 2
            )
        previous = packet.start_us
    return short_intervals


async def _data_rounds(tester, kind):
    types = {
        AdvertisingPduType.ADV_IND: AdvType.ADV_IND,
        AdvertisingPduType.ADV_NONCONN_IND: AdvType.ADV_NONCONN_IND,
        AdvertisingPduType.ADV_SCAN_IND: AdvType.ADV_SCAN_IND,
    }
    await tester.command(legacy_parameters(advertising_type=types[kind]))
    for length in (1, 0, PDU_ADV_LEGACY_DATA_SIZE_MAX, 0):
        data = bytes([length]) + bytes(length - 1) if length else b''
        await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(data))
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
        await _observe_intervals(tester, 37, kind, data, 50)
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


async def _scan_response(tester, channel, kind, scanner, data):
    advertisement = await tester.expect_pdu(channel, kind=kind)
    _check_advertisement(advertisement, IUT_NAME_DATA)
    end = await tester.transmit(
        channel,
        request_pdu(AdvertisingPduType.SCAN_REQ, scanner=scanner),
        start_us=advertisement.end_us + LL_IFS_US,
    )
    response = await tester.receive(channel, duration_us=1000)
    if response is not None:
        assert response.valid_crc
        assert response.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.SCAN_RSP
        assert response.pdu[1] == len(response.pdu) - PDU_HEADER_SIZE
        assert abs(response.start_us - end - LL_IFS_US) <= RESPONSE_IFS_TOLERANCE_US
        _check_advertisement(response, data)
    return response


async def _scan_response_rounds(tester, *, scannable):
    kind = AdvertisingPduType.ADV_SCAN_IND if scannable else AdvertisingPduType.ADV_IND
    await tester.command(
        legacy_parameters(
            advertising_type=AdvType.ADV_SCAN_IND if scannable else AdvType.ADV_IND,
            advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
        )
    )
    await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(IUT_NAME_DATA))
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    peers = public_peer_addresses()
    for channel in LL_ADV_PRIMARY_CHANNELS:
        for scanner in (peers[0], peers[1], peers[3]):
            for data in (
                b'',
                bytes(
                    [
                        PDU_ADV_LEGACY_DATA_SIZE_MAX - 1,
                        AdvertisingData.COMPLETE_LOCAL_NAME,
                    ]
                )
                + bytes(PDU_ADV_LEGACY_DATA_SIZE_MAX - 2),
            ):
                await tester.command(hci.HCI_LE_Set_Scan_Response_Data_Command(data))
                replies = 0
                for _ in range(30):
                    response = await _scan_response(
                        tester, channel, kind, scanner, data
                    )
                    replies += response is not None
                    if not scannable and replies:
                        break
                assert replies == (30 if scannable else 1)
                advertisement = await tester.expect_pdu(channel, kind=kind)
                _check_advertisement(advertisement, IUT_NAME_DATA)
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


async def _accept_connection(tester, channel, peer, advertisement, silent_intervals):
    parameters = LinkParameters(access_address=LOWER_DATA_ACCESS_ADDRESS)
    end = await tester.transmit(
        channel,
        request_pdu(
            AdvertisingPduType.CONNECT_IND, scanner=peer, data=parameters.encode()
        ),
        start_us=advertisement.end_us + LL_IFS_US,
    )
    link = PeerLink(tester, parameters, end)
    await link.exchange()
    deadline = tester.radio.now_us + silent_intervals * ADVERTISING_INTERVAL_US
    while tester.radio.now_us < deadline:
        until = min(deadline, link.anchor - 1)
        assert until >= tester.radio.now_us
        assert (
            await tester.receive(channel, duration_us=until - tester.radio.now_us)
            is None
        )
        if link.anchor <= deadline:
            await link.exchange()
    event = await tester.event(hci.HCI_LE_Connection_Complete_Event)
    assert type(event) is hci.HCI_LE_Connection_Complete_Event
    assert event.status == ErrorCode.SUCCESS and event.role == hci.Role.PERIPHERAL
    assert event.peer_address == peer and event.peer_address_type == peer.address_type
    assert event.connection_interval == parameters.interval
    assert event.peripheral_latency == parameters.latency
    assert event.supervision_timeout == parameters.timeout
    link.handle = event.connection_handle
    await link.disconnect()


async def _invalid_crc_round(tester, channel, kind, request):
    for _ in range(30):
        advertisement = await tester.expect_pdu(channel, kind=kind)
        _check_advertisement(advertisement, IUT_NAME_DATA)
        await tester.transmit(
            channel, request, start_us=advertisement.end_us + LL_IFS_US, bad_crc=True
        )
        assert await tester.receive(channel, duration_us=1000) is None
    advertisement = await tester.expect_pdu(channel, kind=kind)
    _check_advertisement(advertisement, IUT_NAME_DATA)
    assert not any(
        isinstance(
            event,
            (
                hci.HCI_LE_Connection_Complete_Event,
                hci.HCI_LE_Enhanced_Connection_Complete_Event,
            ),
        )
        for event in tester.events
    )


async def advertising_events(tester, *, nonconnectable):
    """Non-Connectable or Undirected Advertising Events.

    Initial Condition:
        Table 4.2-1 selects non-connectable or undirected advertising. Use a
        public own address and the minimum advertising interval as the IXIT.

    Test Steps:
        1. Configure the Lower Tester to monitor IUT advertising packets.
        2. Enable the Table 4.2-1 advertising type on a selected channel, using
           an advertising interval within the supported minimum/maximum.
        3. Receive the selected advertising PDU on the selected channel.
        4. Measure the next event from the first packet's start; count intervals
           no longer than advInterval + 5 ms.
        5. Repeat steps 3-4 until 100 advertising intervals have been detected.
        6. Send LE Set Advertising Enable to disable advertising and receive
           Command Complete.

    Test Case Configuration:
        BV-01 selects ADV_NONCONN_IND and repeats the complete procedure on
        channels 37/38/39. BV-02 selects ADV_IND on the selected channel 37.
        Select public AdvA, the minimum IXIT interval and the common IUT name.
        Receive 101 packets to measure 100 complete intervals, not 100 packets.

    Expected Outcome:
        Pass verdict: all 100 intervals lie within the common 500-ppm drift and
        32-us endpoint-jitter bounds around advInterval through advInterval+10 ms.
        Between 35 and 65 intervals have delay no greater than 5 ms on every
        required channel, and all received packets contain the configured AdvA.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.2.1, LL/DDI/ADV/BV-01-C and LL/DDI/ADV/BV-02-C;
        PDF pages 97-99, printed pages 4.2-4 through 4.2-6, Table 4.2-1.
        Source reference [4], Sections 4.4.2.6, 4.4.2.2 and 4.4.2.3;
        Figure 4.2-1 and the timing Notes on PDF page 99.
    """
    kind = (
        AdvertisingPduType.ADV_NONCONN_IND
        if nonconnectable
        else AdvertisingPduType.ADV_IND
    )
    for channel in LL_ADV_PRIMARY_CHANNELS if nonconnectable else (37,):
        await tester.command(
            legacy_parameters(
                advertising_type=(
                    AdvType.ADV_NONCONN_IND if nonconnectable else AdvType.ADV_IND
                ),
                advertising_channel_map=1 << channel - LL_ADV_PRIMARY_CHANNELS[0],
            )
        )
        await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(IUT_NAME_DATA))
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
        short = await _observe_intervals(tester, channel, kind, IUT_NAME_DATA, 100)
        assert 35 <= short <= 65, short
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


async def advertising_data(tester, *, nonconnectable):
    """Advertising Data: Non-Connectable or Undirected.

    Initial Condition:
        Table 4.2-2 selects ADV_NONCONN_IND or ADV_IND. Configure public AdvA,
        channel 37 and the selected minimum advertising interval.

    Test Steps:
        1. Configure the Lower Tester to monitor IUT advertising packets.
        2. Configure the Table 4.2-2 type, selected channel and an interval within
           the supported minimum/maximum.
        3. Send LE Set Advertising Data with one octet containing its data length;
           receive Command Complete.
        4. Enable advertising with LE Set Advertising Enable; receive Command
           Complete.
        5. Receive the selected PDU containing the step-3 data, beginning an event
           on the selected channel.
        6. Check the next event's start relative to the first packet's start.
        7. Repeat steps 5-6 until 50 advertising intervals have been detected.
        8. Disable advertising; receive Command Complete.
        9. Set empty advertising data; receive Command Complete.
        10. Enable advertising; receive Command Complete.
        11. Receive the selected PDU without advertising data, beginning an event
            on the selected channel.
        12. Check the next event's start relative to the first packet's start.
        13. Repeat steps 11-12 until 50 advertising intervals have been detected.
        14. Disable advertising; receive Command Complete.
        15. Set maximum-length data: 31 octets by default, or the smaller IXIT
            maximum if declared. The first octet encodes the length unsigned,
            least-significant bit first; all remaining octets are zero. Receive
            Command Complete. This DUT selects the default 31-octet maximum.
        16. Repeat steps 4-14 with the maximum-length data followed by empty data.

    Test Case Configuration:
        Table 4.2-2 selects ADV_NONCONN_IND for BV-03 and ADV_IND for BV-04.
        Use the selected channel 37 and minimum IXIT interval; the four data
        rounds are 1, 0, 31 and 0 octets, each measuring 50 complete intervals.

    Expected Outcome:
        Pass verdict: all four rounds transmit the selected PDU with the exact
        data, AdvA and address type; all 200 intervals satisfy the common timing
        bounds. Every setup, data, enable and disable command succeeds.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.2.2, LL/DDI/ADV/BV-03-C and LL/DDI/ADV/BV-04-C;
        PDF pages 99-102, printed pages 4.2-6 through 4.2-9, Table 4.2-2.
        Source reference [3], Section 4.4.2.6; Figure 4.2-2, steps 1-16.
    """
    await _data_rounds(
        tester,
        (
            AdvertisingPduType.ADV_NONCONN_IND
            if nonconnectable
            else AdvertisingPduType.ADV_IND
        ),
    )


async def scan_request_connectable(tester):
    """Scan Request: Undirected Connectable.

    Initial Condition:
        ADV_IND uses public AdvA, all supported channels and unrestricted filtering.
        The Lower Tester uses the three public scanner identities of Section 4.1.5.2.

    Test Steps:
        1. Configure undirected advertising on all supported primary channels
           using an interval in the supported minimum/maximum range.
        2. Configure the Lower Tester to monitor advertising/scan responses and
           send SCAN_REQ on an IXIT channel using its common public address.
        3. Configure empty scan-response data (source device-name length zero).
        4. Receive ADV_IND and send SCAN_REQ on that channel T_IFS after its end.
        5. Receive SCAN_RSP from the IUT T_IFS after the request's end.
        6. Repeat steps 4-5 up to 30 times or until SCAN_RSP is received.
        7. Configure maximum-length scan-response data (source length 31),
           applying the total-data-length correction below.
        8. Repeat steps 4-6.
        9. Select the public scanner address differing from the IUT in its most
           significant octet.
        10. Configure empty scan-response data.
        11. Repeat steps 4-6.
        12. Configure maximum-length scan-response data.
        13. Repeat steps 4-6.
        14. Select the public scanner address differing in both most/least
            significant octets.
        15. Repeat steps 4-6, first restoring empty response data as specified
            by the local source correction below.
        16. Configure maximum-length scan-response data.
        17. Repeat steps 4-6.

    Observation Setup:
        Run the procedure on each supported primary channel. Keep advertising
        enabled across response-data and scanner changes; check that unchanged
        ADV_IND advertising resumes after every response round. Disable only in
        a separate postamble after all rounds.

    Expected Outcome:
        Pass verdict: every required identity, data length and channel receives
        a valid response within 30 attempts. Response timing is T_IFS +/- 2 us;
        advertising continues after the scan response.

    Source Correction:
        The source's 31-byte device-name wording exceeds legacy AD capacity.
        Use 31 total ScanRspData octets: Length = 30, Complete Local Name type
        and 29 name octets, consistent with Core Vol 6, Part B, Section 2.3.2.2
        and Vol 3, Part C, Section 11. Before step 15, restore empty response
        data: the source omits that configuration after changing to the third
        scanner, unlike the symmetric BV-17 procedure. Amber supports both local
        interpretations; neither is claimed as adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-05-C;
        PDF pages 102-104, printed pages 4.2-9 through 4.2-11, Figure 4.2-3.
        Source reference [3], Sections 4.4.2.3 and 4.3.2, steps 1-17;
        the common timing Notes in Section 4.2.3.2.1 apply.
    """
    await _scan_response_rounds(tester, scannable=False)


async def connection_request(tester):
    """Connection Request.

    Initial Condition:
        Public undirected advertising uses all primary channels and accepts any
        initiator. The Lower Tester uses the four public addresses of Section 4.1.5.2.

    Test Steps:
        1. Enable undirected advertising on all supported primary channels with
           an interval in the supported minimum/maximum range.
        2. Configure the Lower Tester to monitor advertising/connection and send
           CONNECT_IND on the first supported advertising channel.
        3. Select the common public Lower Tester address for CONNECT_IND.
        4. Receive ADV_IND and send CONNECT_IND T_IFS after its end.
        5. Observe no more ADV_IND after the advertising interval; wait four
           advertising intervals and check that no ADV_IND is received.
        6. Receive LE Connection Complete containing the parameters from step 4.
        7. Send HCI Disconnect with that handle; require successful Command Status.
        8. Receive Disconnection Complete.
        9. Select the public address differing from the IUT in its most significant
           octet.
        10. Repeat steps 4-8.
        11. Select the public address differing in its least significant octet.
        12. Repeat steps 4-8.
        13. Select the public address differing in both most/least significant octets.
        14. Repeat steps 4-8.
        15. Select the second supported advertising channel.
        16. Repeat steps 3-14.
        17. Select the third supported advertising channel.
        18. Repeat steps 3-14.

    Observation Setup:
        Enable the legacy connection-complete event required by step 6 before
        the procedure. Re-enable advertising for every repeated request. During
        the four-interval silence observation, maintain the established ACL
        without skipping data anchors, then verify the queued HCI notification.

    Expected Outcome:
        Pass verdict: all twelve rounds establish the requested connection,
        stop advertising for the required observation period and disconnect.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-06-C;
        PDF pages 104-106, printed pages 4.2-11 through 4.2-13, Figure 4.2-4.
        Source reference [3], Sections 4.4.2.3 and 4.3.2, steps 1-18.
    """
    await tester.masks(le=1 << (hci.HCI_LE_CONNECTION_COMPLETE_EVENT - 1))
    await tester.command(
        legacy_parameters(advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL)
    )
    await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(IUT_NAME_DATA))
    for channel in LL_ADV_PRIMARY_CHANNELS:
        for peer in public_peer_addresses():
            await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
            advertisement = await tester.expect_pdu(
                channel, kind=AdvertisingPduType.ADV_IND
            )
            _check_advertisement(advertisement, IUT_NAME_DATA)
            await _accept_connection(tester, channel, peer, advertisement, 4)


async def scan_then_connection_request(tester):
    """Scan Request Connection Request.

    Initial Condition:
        Public undirected advertising uses all primary channels and unrestricted
        filtering; select channel 37 and the common public Lower Tester address.

    Test Steps:
        1. Enable undirected advertising on all supported channels, using a
           supported interval and accept-all scan/connection policy (0x00).
        2. Set Scan Response Data to the literal "IUT"; receive Command Complete.
        3. Configure the Lower Tester to monitor advertising, scan response and
           connection procedures, sending SCAN_REQ/CONNECT_IND on an IXIT channel.
        4. Receive ADV_IND and send SCAN_REQ on that channel T_IFS after its end.
        5. Receive SCAN_RSP from the IUT T_IFS after the request's end.
        6. Repeat steps 4-5 up to 30 times or until SCAN_RSP is received.
        7. Receive the next ADV_IND and send CONNECT_IND T_IFS after its end.
        8. Receive no further ADV_IND after the advertising interval, confirming
           that the IUT stopped advertising following the connection request.
        9. Receive LE Connection Complete with the requested connection parameters.
        10. Perform Peripheral Connection Terminated with the selected interval,
            latency, timeout, channel map, unencrypted state and step-9 handle.

    Observation Setup:
        Select channel 37 and the common public Lower Tester address. Enable
        legacy connection completion before step 1, check exact response data,
        identity, CRC and T_IFS, and maintain the ACL during silence observation.

    Expected Outcome:
        Pass verdict: the scan response is valid and the subsequent connection
        succeeds with the requested parameters; advertising stops and termination
        produces a successful HCI Disconnection Complete event.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-07-C;
        PDF pages 106-108, printed pages 4.2-13 through 4.2-15, Figure 4.2-5.
        Source reference [3], Section 4.4.2.3, steps 1-10.
    """
    await tester.masks(le=1 << (hci.HCI_LE_CONNECTION_COMPLETE_EVENT - 1))
    await tester.command(
        legacy_parameters(advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL)
    )
    await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(IUT_NAME_DATA))
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    await tester.command(hci.HCI_LE_Set_Scan_Response_Data_Command(b'IUT'))
    for _ in range(30):
        response = await _scan_response(
            tester, 37, AdvertisingPduType.ADV_IND, LOWER_CENTRAL_PUBLIC_ADDRESS, b'IUT'
        )
        if response is not None:
            break
    else:
        raise AssertionError('no SCAN_RSP in 30 permitted attempts')
    advertisement = await tester.expect_pdu(37, kind=AdvertisingPduType.ADV_IND)
    _check_advertisement(advertisement, IUT_NAME_DATA)
    await _accept_connection(tester, 37, LOWER_CENTRAL_PUBLIC_ADDRESS, advertisement, 1)


async def discoverable_advertising_data(tester):
    """Advertising Data: Discoverable.

    Initial Condition:
        Configure discoverable advertising on channel 37 with public AdvA and
        the minimum selected interval, with advertising initially disabled.

    Test Steps:
        Configure the Lower Tester to monitor advertising (unnumbered preamble).
        1. Configure discoverable undirected advertising on the selected channel
           with a supported interval; apply the step-1 correction below.
        2. Set one advertising data octet indicating its length; receive Command
           Complete.
        3. Enable advertising; receive Command Complete.
        4. Receive ADV_SCAN_IND containing the step-2 data, beginning an event
           on the selected channel.
        5. Measure the next event relative to the first packet's start.
        6. Repeat steps 4-5 until 50 intervals are detected (corrected reference).
        7. Disable advertising; receive Command Complete.
        8. Set empty advertising data; receive Command Complete.
        9. Enable advertising; receive Command Complete.
        10. Receive ADV_SCAN_IND without advertising data on the selected channel.
        11. Measure the next event relative to the first packet's start.
        12. Repeat steps 10-11 until 50 intervals are detected (corrected reference).
        13. Disable advertising; receive Command Complete.
        14. Set 31 octets, the first encoding the data length unsigned,
            least-significant bit first, with the rest zero; receive Command
            Complete.
        15. Repeat steps 3-13 once with maximum-length data followed by empty
            data, applying the source's corrected repeat bounds below.

    Expected Outcome:
        Pass verdict: the four data rounds transmit ADV_SCAN_IND containing
        exactly the submitted bytes and public AdvA on LE 1M, with valid intervals.

    Source Correction:
        Step 1 says "enables", but Figure 4.2-10 sends Set Advertising Parameters
        there and only enables through HCI in step 3. Step 4's data reference
        means step 2, not step 3. Steps 6 and 12 self-reference; their intended
        packet/interval loops are 4-5 and 10-11. Step 15's 4-14 skips re-enable
        and includes another data setup; use 3-13, matching the MSC's two outer
        rounds and the intact BV-03/BV-04 procedure. These are local annotations,
        not adopted SIG errata. Amber supports this reconstruction after checking
        the MSC's complete four-phase repetition rather than only the prose.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-16-C;
        PDF pages 119-121, printed pages 4.2-26 through 4.2-28, Figure 4.2-10.
        Source reference [3], Section 4.4.2.5; all steps 1-15.
    """
    await _data_rounds(tester, AdvertisingPduType.ADV_SCAN_IND)


async def scan_request_discoverable(tester):
    """Scan Request: Discoverable.

    Initial Condition:
        Public ADV_SCAN_IND uses all primary channels and unrestricted filtering.
        Use the common public scanner, MSB-XOR and both-XOR addresses.

    Test Steps:
        1. Enable discoverable undirected advertising on all supported primary
           channels using a selected supported interval.
        2. Configure the Lower Tester to monitor advertising/scan responses and
           send SCAN_REQ on an IXIT channel using its common public address.
        3. Configure empty scan-response data (source device-name length zero).
        4. Receive ADV_SCAN_IND and send SCAN_REQ on that channel T_IFS after
           the advertisement's end.
        5. Receive SCAN_RSP from the IUT T_IFS after the request's end.
        6. Repeat steps 4-5 thirty times.
        7. Configure maximum-length scan-response data (source length 31).
        8. Repeat steps 4-6.
        9. Select the public scanner address differing from the IUT in its most
           significant octet.
        10. Configure empty scan-response data.
        11. Repeat steps 4-6.
        12. Configure maximum-length scan-response data.
        13. Repeat steps 4-6.
        14. Select the public scanner address differing in both most/least
            significant octets.
        15. Configure empty scan-response data.
        16. Repeat steps 4-6.
        17. Configure maximum-length scan-response data.
        18. Repeat steps 4-6.

    Observation Setup:
        Run all identities/data lengths on each supported primary channel;
        keep advertising enabled across those changes. Verify CRC, exact
        AdvA/data, LE 1M, T_IFS and continued advertising after each round.
        Disable advertising only after all rounds, as a separate postamble.

    Expected Outcome:
        Pass verdict: thirty valid replies occur in every identity/data/channel
        round with T_IFS +/- 2 us and no loss of discoverable advertising.

    Source Correction:
        Interpret device-name length 31 as 31 significant ScanRspData octets,
        including the AD Length/type octets, leaving 29 name octets. A literal
        31-octet name would exceed the legacy payload limit. Amber supports
        this Core-consistent interpretation; no adopted SIG erratum is claimed.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-17-C;
        PDF pages 121-123, printed pages 4.2-28 through 4.2-30, Figure 4.2-11.
        Source reference [3], Sections 4.4.2.5 and 4.4.3.2, steps 1-18;
        the common timing Notes in Section 4.2.3.2.1 apply.
    """
    await _scan_response_rounds(tester, scannable=True)


async def scan_request_invalid_crc(tester, *, scannable):
    """Scan Request Invalid CRC.

    Initial Condition:
        Table 4.2-7 selects ADV_IND or ADV_SCAN_IND, using public AdvA, the
        minimum interval, all primary channels and unrestricted filtering.

    Test Steps:
        1. Configure the Lower Tester for active scanning with invalid-CRC
           SCAN_REQ packets.
        2. Enable the Table 4.2-7 advertising type on all supported channels.
        3. Receive the selected advertising PDU and send an invalid-CRC SCAN_REQ
           on a randomly selected channel T_IFS after the advertisement's end.
        4. Verify continued advertising without a scan response.
        5. Repeat steps 3-4 thirty times.
        6. Disable advertising with LE Set Advertising Enable; receive Command
           Complete.

    Test Condition:
        The Lower Tester listens only on the selected advertising channel.
        Use the supported minimum interval and accept-all filtering policy.
        A seeded random choice selects the channel; invert all CRC bits as
        required by Section 4.1.5.1. Configure a nonempty scan response first
        so the absence of data cannot mask incorrect request acceptance.

    Expected Outcome:
        Pass verdict: all thirty corrupted requests are ignored; advertising
        continues on the selected channel and no connection is reported.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.2.3, LL/DDI/ADV/BI-01-C and LL/DDI/ADV/BI-10-C;
        PDF pages 127-129, printed pages 4.2-34 through 4.2-36, Table 4.2-7.
        CRC corruption follows the all-bit inversion in Section 4.1.5.1.
        Source reference [3], Sections 3.1 and 4.4.2.3; Figure 4.2-13,
        all steps 1-6 and the common timing Notes in Section 4.2.3.2.1.
    """
    await tester.command(
        legacy_parameters(
            advertising_type=AdvType.ADV_SCAN_IND if scannable else AdvType.ADV_IND,
            advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
        )
    )
    await tester.command(hci.HCI_LE_Set_Scan_Response_Data_Command(b'IUT'))
    await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(IUT_NAME_DATA))
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    channel = random.Random(0).choice(LL_ADV_PRIMARY_CHANNELS)
    await _invalid_crc_round(
        tester,
        channel,
        AdvertisingPduType.ADV_SCAN_IND if scannable else AdvertisingPduType.ADV_IND,
        request_pdu(AdvertisingPduType.SCAN_REQ, scanner=LOWER_CENTRAL_PUBLIC_ADDRESS),
    )
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


async def connection_request_invalid_crc(tester):
    """Connection Request Invalid CRC.

    Initial Condition:
        Public ADV_IND uses all primary channels, the minimum interval and no
        filtering. The connection request contains otherwise valid parameters.

    Test Steps:
        1. Configure the Lower Tester to initiate using invalid-CRC CONNECT_IND.
        2. Enable undirected advertising on all supported channels.
        3. Receive ADV_IND and send invalid-CRC CONNECT_IND on a randomly
           selected channel T_IFS after the advertisement's end.
        4. Verify that the IUT continues advertising.
        5. Repeat steps 3-4 thirty times.
        6. Disable advertising with LE Set Advertising Enable; receive Command
           Complete.

    Test Condition:
        Listen only on the selected channel in each repetition of the procedure.
        Randomize channel order with a fixed seed and cover all three supported
        primary channels to satisfy the all-channel pass verdict. Use accept-all
        filtering, otherwise-valid common connection parameters, and invert all
        CRC bits. Also reject any HCI connection event or RF response.

    Expected Outcome:
        Pass verdict: the corrupted request is ignored in all ninety rounds;
        advertising continues on every supported channel and no ACL is reported.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BI-02-C;
        PDF pages 129-130, printed pages 4.2-36 through 4.2-37, Figure 4.2-14.
        Repeat across channels to satisfy the all-supported-channel Pass verdict.
        Source reference [3], Sections 3.1 and 4.4.2.3; steps 1-6 and the
        common timing Notes in Section 4.2.3.2.1.
    """
    await tester.command(
        legacy_parameters(advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL)
    )
    await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(IUT_NAME_DATA))
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    request = request_pdu(
        AdvertisingPduType.CONNECT_IND,
        scanner=LOWER_CENTRAL_PUBLIC_ADDRESS,
        data=LinkParameters(access_address=LOWER_DATA_ACCESS_ADDRESS).encode(),
    )
    for channel in random.Random(0).sample(
        LL_ADV_PRIMARY_CHANNELS, len(LL_ADV_PRIMARY_CHANNELS)
    ):
        await _invalid_crc_round(tester, channel, AdvertisingPduType.ADV_IND, request)
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


async def low_duty_directed_advertising(tester):
    """Low Duty Cycle Directed Advertising Events.

    Initial Condition:
        Configure public AdvA and the common public initiator as TargetA, using
        low-duty directed advertising on channel 37 at the minimum interval.

    Test Steps:
        1. Configure the Lower Tester to scan and monitor IUT advertising.
        2. Enable low-duty directed advertising on the selected channel with
           a supported advertising interval.
        3. Receive ADV_DIRECT_IND starting an event on the selected channel.
        4. Measure the next event relative to the first packet's start.
        5. Repeat steps 3-4 until 100 complete advertising intervals are detected.
        6. Configure the Lower Tester to initiate a connection.
        7. Receive ADV_DIRECT_IND and send CONNECT_IND T_IFS after its end;
           do not send any LL data packets to the IUT.
        8. Receive no further ADV_DIRECT_IND after the advertising interval.
        9. Repeat steps 7-8 until advertising stops. In the ideal RF path,
           the first valid request is accepted and this loop exits immediately.
        10. Receive LE Connection Complete with the parameters sent in step 7.
        11. Receive Disconnection Complete after the Establishment Timeout.

    Test Condition:
        The Lower Tester listens only on the selected channel 37. Select the
        minimum supported interval and public AdvA/TargetA. Enable legacy
        connection completion, verify all PDU address bits/contents and interval
        bounds, and observe silence beyond the six-event establishment window.

    Expected Outcome:
        Pass verdict: all directed intervals satisfy the common timing bounds;
        advertising stops after connection acceptance. Success is reported for
        creation, followed by establishment-failure disconnection of that handle.
        A failed creation event cannot substitute for the two required events.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-19-C;
        PDF pages 131-132, printed pages 4.2-38 through 4.2-39, Figure 4.2-15.
        Source reference [3], Section 4.4.2.4, all steps 1-11 and the common
        timing Notes in Section 4.2.3.2.1.
    """
    peer = LOWER_CENTRAL_PUBLIC_ADDRESS
    await tester.masks(le=1 << (hci.HCI_LE_CONNECTION_COMPLETE_EVENT - 1))
    await tester.command(
        legacy_parameters(
            advertising_type=AdvType.ADV_DIRECT_IND_LOW_DUTY,
            peer_address_type=peer.address_type,
            peer_address=peer,
        )
    )
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    await _observe_intervals(
        tester, 37, AdvertisingPduType.ADV_DIRECT_IND, bytes(peer), 100
    )
    advertisement = await tester.expect_pdu(37, kind=AdvertisingPduType.ADV_DIRECT_IND)
    _check_advertisement(advertisement, bytes(peer))
    parameters = LinkParameters(access_address=LOWER_DATA_ACCESS_ADDRESS)
    await tester.transmit(
        37,
        request_pdu(
            AdvertisingPduType.CONNECT_IND, scanner=peer, data=parameters.encode()
        ),
        start_us=advertisement.end_us + LL_IFS_US,
    )
    assert await tester.receive(37, duration_us=ADVERTISING_INTERVAL_US) is None
    complete = await tester.event(hci.HCI_LE_Connection_Complete_Event)
    assert type(complete) is hci.HCI_LE_Connection_Complete_Event
    assert (
        complete.status,
        complete.role,
        complete.peer_address,
        complete.peer_address_type,
        complete.connection_interval,
        complete.peripheral_latency,
        complete.supervision_timeout,
    ) == (
        ErrorCode.SUCCESS,
        hci.Role.PERIPHERAL,
        peer,
        peer.address_type,
        parameters.interval,
        parameters.latency,
        parameters.timeout,
    )
    assert (
        await tester.receive(
            37,
            duration_us=(LL_CONN_ESTABLISHMENT_EVENTS + 1)
            * parameters.interval
            * LL_CONN_INTERVAL_UNIT_US,
        )
        is None
    )
    disconnected = await tester.event(hci.HCI_Disconnection_Complete_Event)
    assert (
        disconnected.status,
        disconnected.connection_handle,
        disconnected.reason,
    ) == (
        ErrorCode.SUCCESS,
        complete.connection_handle,
        ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR,
    )


async def advertising_always_le_1m(tester, *, nonconnectable):
    """Advertising Always Using the LE 1M PHY.

    Initial Condition:
        Table 4.2-8 selects ADV_IND or ADV_NONCONN_IND with public AdvA, all
        supported channels and the minimum advertising interval.

    Test Steps:
        1. Configure the Lower Tester to accept only LE 1M advertising packets;
           scan each supported primary channel for at least thirty intervals.
        2. Send LE Set Default PHY with ALL_PHYS = 0 and TX_PHYS / RX_PHYS
           both preferring LE 2M.
        3. Enable the Table 4.2-8 advertising type on all supported channels
           using the minimum advertising interval.
        4. Receive the selected advertising PDU starting an event on an
           applicable channel using LE 1M. Repeat until at least ninety packets
           are detected, with at least thirty per channel.
        5. Disable advertising with LE Set Advertising Enable; receive Command
           Complete.

    Observation Setup:
        Observe thirty complete intervals (31 packets) per channel, satisfying
        both step 1's interval count and step 4's packet-count minimum. Check
        PDU type, public AdvA, common name data, PHY and timing for every packet.

    Expected Outcome:
        Pass verdict: every advertising packet is received correctly on LE 1M,
        regardless of the LE 2M default preference; all channels are observed.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.2.4, LL/DDI/ADV/BV-20-C and LL/DDI/ADV/BV-111-C;
        PDF pages 132-134, printed pages 4.2-39 through 4.2-41, Table 4.2-8.
        Source reference [10], Section 2.3; Figure 4.2-16, steps 1-5.
    """
    await tester.command(
        hci.HCI_LE_Set_Default_PHY_Command(0, hci.PhyBit.LE_2M, hci.PhyBit.LE_2M)
    )
    await tester.command(
        legacy_parameters(
            advertising_type=(
                AdvType.ADV_NONCONN_IND if nonconnectable else AdvType.ADV_IND
            ),
            advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
        )
    )
    await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(IUT_NAME_DATA))
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    kind = (
        AdvertisingPduType.ADV_NONCONN_IND
        if nonconnectable
        else AdvertisingPduType.ADV_IND
    )
    for channel in LL_ADV_PRIMARY_CHANNELS:
        await _observe_intervals(tester, channel, kind, IUT_NAME_DATA, 30)
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


async def extended_legacy_nonconnectable(tester):
    """Extended Advertising, Legacy PDUs, Non-Connectable.

    Initial Condition:
        Configure a public extended advertising set using legacy non-connectable
        properties, channel 37 and the minimum interval.

    Test Steps:
        1. Configure the Lower Tester to monitor IUT advertising packets.
        2. Send LE Set Extended Advertising Parameters on the selected primary
           channel with the minimum interval and Properties = 0b00010000
           (legacy ADV_NONCONN_IND).
        Repeat steps 3-8 for every Table 4.2-9 round:
        3. Send LE Set Extended Advertising Data with the round's data; receive
           Command Complete.
        4. Enable with LE Set Extended Advertising Enable; receive Command Complete.
        5. Receive ADV_NONCONN_IND carrying the step-3 data, starting an event
           on the selected primary channel.
        6. Measure the next event relative to the first packet's start.
        7. Repeat steps 5-6 until fifty complete intervals have been detected.
        8. Disable with LE Set Extended Advertising Enable; receive Command Complete.

    Test Case Configuration:
        Table 4.2-9 selects one octet 0x01, no data, then 31 octets consisting of
        0xF8 followed by thirty zeroes. Use public AdvA and selected channel 37;
        verify PDU type, PHY, address and exact data in every packet.

    Expected Outcome:
        Pass verdict: all three rounds use ADV_NONCONN_IND on LE 1M, carry the
        exact submitted data and satisfy the advertising interval bounds.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-21-C;
        PDF pages 134-136, printed pages 4.2-41 through 4.2-43, Table 4.2-9.
        Source reference [10], Section 4.4.2.6; Figure 4.2-17, steps 1-8.
    """
    await tester.command(
        extended_parameters(
            advertising_event_properties=Properties.USE_LEGACY_ADVERTISING_PDUS
        )
    )
    for data in (b'\x01', b'', LEGACY_MAXIMUM_DATA):
        await set_extended_data(tester, data)
        await tester.command(extended_enable())
        await _observe_intervals(
            tester, 37, AdvertisingPduType.ADV_NONCONN_IND, data, 50
        )
        await tester.command(extended_enable(0))


async def extended_legacy_undirected(tester, *, extended=False, connectable=False):
    """Extended Advertising, Legacy PDUs, Undirected.

    Initial Condition:
        Table 4.2-10 selects legacy-HCI ADV_IND with CSA #2, legacy-HCI
        ADV_NONCONN_IND, or extended-HCI legacy ADV_NONCONN_IND. All channels
        are enabled with public AdvA and the minimum advertising interval.

    Test Steps:
        1. Configure the Lower Tester to monitor IUT advertising packets.
        2. Send the Table 4.2-10 Set Parameters command with its type/properties,
           all supported primary channels and the minimum advertising interval.
        Repeat steps 3-7 for every Table 4.2-11 round:
        3. Send the Table 4.2-10 Set Data command with that round's payload;
           receive Command Complete.
        4. Send the Table 4.2-10 Enable command; receive Command Complete.
           For Extended Advertising Enable, set Duration[0] = 0x0000.
        5. Listen only on the round's Table 4.2-11 channel; receive the selected
           PDU with Table 4.2-10 ChSel and the step-3 data, beginning an event.
        6. Repeat step 5 until fifty complete intervals have been detected.
        7. Disable advertising with the selected Enable command; receive
           Command Complete.

    Test Case Configuration:
        BV-22 uses legacy HCI, ADV_IND and ChSel = 1; BV-112 uses legacy HCI,
        ADV_NONCONN_IND and ChSel = 0; BV-113 uses extended HCI, legacy
        ADV_NONCONN_IND properties 0x10 and ChSel = 0. The three payload/channel
        rounds are 0x01 on 37, empty on 38, then 0xF8 plus thirty zeroes on 39.
        Enable all supported channels throughout; only the observation channel
        changes per round. Check LE 1M, public AdvA, exact data and timing.

    Expected Outcome:
        Pass verdict: each round carries the exact Table 4.2-11 data on its
        specified observation channel, using ADV_IND with ChSel 1 for BV-22,
        or ADV_NONCONN_IND with ChSel 0 for BV-112 and BV-113.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.3, LL/DDI/ADV/BV-22-C,
        LL/DDI/ADV/BV-112-C and LL/DDI/ADV/BV-113-C; PDF pages 136-139,
        printed pages 4.2-43 through 4.2-46, Tables 4.2-10 and 4.2-11.
        Source reference [10], Section 4.4.2.3; Figure 4.2-18, steps 1-7.
    """
    kind = (
        AdvertisingPduType.ADV_IND
        if connectable
        else AdvertisingPduType.ADV_NONCONN_IND
    )
    if extended:
        await tester.command(
            extended_parameters(
                advertising_event_properties=Properties.USE_LEGACY_ADVERTISING_PDUS,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
            )
        )
    else:
        await tester.command(
            legacy_parameters(
                advertising_type=(
                    AdvType.ADV_IND if connectable else AdvType.ADV_NONCONN_IND
                ),
                advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
            )
        )
    for channel, data in zip(
        LL_ADV_PRIMARY_CHANNELS, (b'\x01', b'', LEGACY_MAXIMUM_DATA)
    ):
        if extended:
            await set_extended_data(tester, data)
        else:
            await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(data))
        await tester.command(
            extended_enable()
            if extended
            else hci.HCI_LE_Set_Advertising_Enable_Command(1)
        )
        await _observe_intervals(tester, channel, kind, data, 50, chsel=connectable)
        await tester.command(
            extended_enable(0)
            if extended
            else hci.HCI_LE_Set_Advertising_Enable_Command(0)
        )


async def extended_nonconnectable(tester, *, phy):
    """Extended Advertising, Non-Connectable.

    Initial Condition:
        Advertising parameters are selected within the supported interval range,
        with a supported own-address type and all supported primary channels.
        This implementation selects a public own address and a 200-ms interval.
        Tables 4.2-12/13 select primary/secondary PHYs 1M/1M (BV-47), Coded/Coded
        (BV-48), or 1M/2M (BV-49). All three selected cases have no additional
        Host feature initial condition and both coding options are zero.

    Test Steps:
        1. Read the maximum advertising-data capacity and require 31..1650 octets.
           Store the returned capacity for the subsequent rounds.
        Repeat Steps 2-13 for each of the fourteen Table 4.2-14 rows:
        2. Continue to Step 3 if the row's data length fits the capacity;
           otherwise skip this row and continue with the next row.
        3. Set the row's properties, all primary channels, selected interval and
           the case's primary/secondary PHYs and coding options. Directed rows
           use the Lower Tester's public peer address. Both options are zero, so
           v1 parameters are permitted; nonzero options would require v2.
        4. Submit the row's data and fragmentation preference, using seeded random
           octets 1..254. Lengths above 251 use FIRST, zero or more INTERMEDIATE,
           and LAST fragments. Round 2 uses FIRST with one octet, 29 one-octet
           INTERMEDIATE fragments, and LAST with one octet. Otherwise use COMPLETE.
        5. Enable advertising with the row's Duration and Max_Extended_Advertising_
           Events values, receiving successful Command Complete responses.
        6. Receive ADV_EXT_IND with AdvMode 00 and no SuppInfo, SyncInfo, TxPower,
           ACAD or AdvData. Nonempty data requires AuxPtr; empty data permits it.
           With AuxPtr, require ADI and the configured SID; without it, forbid ADI.
           Check the configured primary PHY. These cases allow either Coded coding;
           options 3/4 in unselected cases would require the specified coding.
        7. If AuxPtr is absent, continue at Step 10.
        8. Follow AuxPtr to AUX_ADV_IND, checking pointer timing, AdvMode 00,
           matching ADI, the selected secondary PHY and no SuppInfo, SyncInfo or
           TxPower. Incomplete data requires another AuxPtr. The same coding-option
           rule as Step 6 applies to the secondary PHY.
        9. Follow each further AuxPtr to AUX_CHAIN_IND until no pointer remains
           and all data is received. Check AdvMode 00, matching ADI, secondary PHY,
           additional submitted data, and no AdvA, TargetA, SuppInfo, TxPower or
           SyncInfo. Apply the secondary coding rule to every chain PDU.
        10. If Max_Extended_Advertising_Events is nonzero, repeat Steps 6-9 until
            advertising stops. Require at least one event and no more than the
            requested count, then Advertising Set Terminated with status 0x43.
            Continue at Step 13.
        11. Otherwise, if Duration is nonzero, repeat Steps 6-9 through the duration,
            then verify no additional events start and receive Advertising Set
            Terminated with status 0x3C. Continue at Step 13.
        12. Otherwise, repeat Steps 6-9 until ten complete intervals are observed
            (eleven primary packets on one monitored primary channel).
        13. Disable using LE Set Extended Advertising Enable before the next row.

    Test Case Configuration:
        Table 4.2-14 rows 1-6: undirected data lengths 0, 31, 474, 711, 948,
        capacity; row 7: capacity with fragmentation preference 1. Rows 8-10:
        directed lengths 0, 251, capacity. Rows 11/12: undirected/directed, no
        data, Duration 500 (5 s). Rows 13/14: undirected/directed, no data,
        Max_Extended_Advertising_Events 50. Unspecified preferences, durations
        and event counts are zero.

    Expected Outcome:
        Pass verdict: the capacity is in range and every executed row produces
        ADV_EXT_IND with the prescribed fields and PHY. Nonempty data has AuxPtr;
        all referenced PDUs meet T_MAFS, contain the same SID/DID, and deliver
        exactly all submitted data without prohibited fields. Directed TargetA
        matches the configured public peer and appears in exactly one of the
        primary or first auxiliary PDU; for Coded primary plus AuxPtr it appears
        in the auxiliary PDU. Address type bits agree with present public fields.
        Every chain PDU uses the configured secondary PHY. Duration-limited rows
        stop within the source timing envelope with status 0x3C; count-limited
        rows do not exceed the requested count and terminate with status 0x43.
        Completed-event counts match independently observed primary events,
        and no further advertising is received after termination.

    Timing Measurements:
        For D = Duration * 10 ms, the source Notes permit minimum duration
        D * (1 - 500 ppm) - 16 us and maximum (D + 10 ms) * (1 + 500 ppm) + 16 us.
        Bracket enable by its command submission/completion times. The latest
        primary start uses the upper enable bracket plus the maximum duration.
        The last primary start must be no earlier than the lower enable bracket
        plus the minimum duration minus one maximum allowed advertising interval.
        This last-start lower bound is a conservative RF observation, not a
        specified HCI delivery deadline; final packet completion is not equated
        to the advertising event's start. Interval limits include 500-ppm drift
        and 32-us two-endpoint jitter.

    Source Correction:
        Step 2 refers to Step 14, but the procedure ends at Step 13. Interpret
        the capacity-exceeded branch as skipping the current table row, not as
        sending commands for an unsupported length. Amber confirms this reading;
        this is a local correction, not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.4, LL/DDI/ADV/BV-47-C,
        LL/DDI/ADV/BV-48-C and LL/DDI/ADV/BV-49-C; PDF pages 139-146,
        printed pages 4.2-46 through 4.2-53, Tables 4.2-12 through 4.2-14.
    """
    capacity = (
        await tester.command(hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command())
    ).max_advertising_data_length
    assert PDU_ADV_LEGACY_DATA_SIZE_MAX <= capacity <= hci.HCI_LE_ADV_DATA_SIZE_MAX
    rounds = [(0, length, 0, 0, 0) for length in (0, 31, 474, 711, 948, capacity)]
    rounds += [(0, capacity, 1, 0, 0)]
    rounds += [
        (Properties.DIRECTED_ADVERTISING, length, 0, 0, 0)
        for length in (0, 251, capacity)
    ]
    rounds += [
        (properties, 0, 0, duration, maximum)
        for duration, maximum in ((500, 0), (0, 50))
        for properties in (0, Properties.DIRECTED_ADVERTISING)
    ]
    generator = random.Random(0)
    interval_us = 320 * hci.HCI_LE_ADV_INTERVAL_UNIT_US
    primary_phy = Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M
    forbidden = ('address', 'target', 'sync', 'power', 'acad', 'cte')
    for round_number, (properties, length, preference, duration, maximum) in enumerate(
        rounds, 1
    ):
        if length > capacity:
            continue
        await tester.command(
            extended_parameters(
                advertising_event_properties=properties,
                peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
                peer_address_type=hci.AddressType.PUBLIC_DEVICE,
                primary_advertising_phy=primary_phy,
                secondary_advertising_phy=phy,
                primary_advertising_interval_min=320,
                primary_advertising_interval_max=320,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
            )
        )
        data = bytes(generator.randint(1, 254) for _ in range(length))
        if round_number == 2:
            for index, octet in enumerate(data):
                operation = (
                    Operation.FIRST_FRAGMENT
                    if index == 0
                    else (
                        Operation.LAST_FRAGMENT
                        if index == len(data) - 1
                        else Operation.INTERMEDIATE_FRAGMENT
                    )
                )
                await tester.command(
                    hci.HCI_LE_Set_Extended_Advertising_Data_Command(
                        0, operation, preference, bytes([octet])
                    )
                )
        else:
            await set_extended_data(tester, data, preference=preference)
        before_enable = tester.radio.now_us
        await tester.command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
                1, [0], [duration], [maximum]
            )
        )
        duration_us = duration * hci.HCI_LE_DURATION_UNIT_US
        tolerance = (
            duration_us * LL_SCA_PPM[LL_SCA_500_PPM] // PHY_TIME_UNITS_PER_SECOND
            + ADVERTISING_INTERVAL_JITTER_US // 2
        )
        maximum_duration = duration_us + LL_ADV_DELAY_MAX_US
        maximum_duration += (
            maximum_duration * LL_SCA_PPM[LL_SCA_500_PPM] // PHY_TIME_UNITS_PER_SECOND
            + ADVERTISING_INTERVAL_JITTER_US // 2
        )
        deadline = tester.radio.now_us + maximum_duration if duration else None
        previous_start = None
        count = 0
        while True:
            primary = await tester.receive(
                37, duration_us=2 * interval_us, phy=primary_phy
            )
            if primary is None:
                assert duration or maximum
                break
            first = _nonconnectable_extended_packet(primary, primary_phy)
            assert first['data'] == b'' and all(
                field not in first for field in forbidden[2:]
            )
            if previous_start is not None:
                minimum_interval, maximum_interval = advertising_interval_limits(
                    interval_us
                )
                assert (
                    minimum_interval
                    <= primary.start_us - previous_start
                    <= maximum_interval
                )
            previous_start = primary.start_us
            if deadline is not None:
                assert primary.start_us <= deadline
            if 'aux' in first:
                assert 'adi' in first
                _, packet, fields = await follow_auxiliary(tester, primary, first)
                assert _nonconnectable_extended_packet(packet, phy) == fields
                assert fields['adi'] == first['adi']
                assert all(field not in fields for field in ('cte', 'sync', 'power'))
                assert (
                    int.from_bytes(fields['adi'], 'little') >> PDU_ADV_ADI_DID_BITS == 3
                )
                assert sum('address' in item for item in (first, fields)) == 1
                assert next(
                    item['address'] for item in (first, fields) if 'address' in item
                ) == bytes(DUT_ADDRESS)
                assert sum('target' in item for item in (first, fields)) == int(
                    bool(properties)
                )
                if properties:
                    assert fields.get('target', first.get('target')) == bytes(
                        LOWER_CENTRAL_PUBLIC_ADDRESS
                    )
                if primary_phy == Phy.LE_CODED:
                    assert 'address' not in first and 'target' not in first
                assert (
                    await chain(
                        tester, packet, fields, forbidden=forbidden, expected_phy=phy
                    )
                    == data
                )
            else:
                assert not data and 'adi' not in first
                assert first['address'] == bytes(DUT_ADDRESS)
                assert first.get('target') == (
                    bytes(LOWER_CENTRAL_PUBLIC_ADDRESS) if properties else None
                )
            count += 1
            assert not maximum or count <= maximum
            if not duration and (not maximum) and (count == 11):
                break
        if duration or maximum:
            assert count > 0, 'No ADV_EXT_IND received in an executed round'
            event = await tester.event(hci.HCI_LE_Advertising_Set_Terminated_Event)
            assert event.advertising_handle == 0
            assert event.status == (
                ErrorCode.LIMIT_REACHED_ERROR
                if maximum
                else ErrorCode.ADVERTISING_TIMEOUT_ERROR
            )
            assert event.num_completed_extended_advertising_events == count
            if duration:
                assert (
                    previous_start is not None
                    and previous_start
                    >= before_enable
                    + duration_us
                    - advertising_interval_limits(interval_us)[1]
                    - tolerance
                )
            assert (
                await tester.receive(37, duration_us=2 * interval_us, phy=primary_phy)
                is None
            )
        await tester.command(extended_enable(0))


async def extended_scan_response(tester, *, phy):
    """Extended Advertising, Scannable.

    Initial Condition:
        Scannable advertising has selected supported intervals, own-address type,
        primary channels and name/data. This implementation uses public addresses
        and all primary channels. Table 4.2-15 selects primary/secondary PHYs
        1M/1M (BV-45), 1M/2M (BV-52), or Coded/Coded (BV-54). For these selected
        cases, AUX_SCAN_RSP ADI may be absent or match AUX_ADV_IND ADI. The selected
        interval is 100 ms on uncoded PHYs and 150 ms on Coded to fit the data chain.

    Test Steps:
        1. Read maximum advertising-data capacity and require 31..1650 octets.
           Store the capacity for subsequent rows.
        Repeat Steps 2-13 for every Table 4.2-16 row:
        2. If the row's data length fits, continue at Step 3; otherwise proceed
           to Step 13 to disable the set, then continue with the next row.
        3. Set all primary channels and selected intervals, the row's advertising
           properties and Scan_Request_Notification_Enable, and the PHYs from
           Table 4.2-15. Directed rows select the Lower Tester's public peer address.
        4. Submit seeded random response octets 1..254 and the row's fragmentation
           preference. Lengths above 251 use FIRST, zero or more INTERMEDIATE,
           then LAST. Round 2 uses FIRST with one octet, 29 one-octet INTERMEDIATE
           commands and LAST with one octet. Otherwise use COMPLETE.
        5. Enable extended advertising with Duration 0 and receive Command Complete.
        6. Receive ADV_EXT_IND with AdvMode 10, AuxPtr, and ADI with the configured
           SID. Forbid SuppInfo, SyncInfo, TxPower and ACAD; check primary PHY.
        7. Follow AuxPtr to AUX_ADV_IND on the secondary PHY with AdvMode 10,
           matching ADI, and no SuppInfo, AuxPtr, SyncInfo, TxPower or AdvData.
        8. Send AUX_SCAN_REQ on that secondary channel at T_IFS after AUX_ADV_IND,
           with public ScanA equal to the Lower Tester and the row's AdvA.
        9. For wrong AdvA, require no AUX_SCAN_RSP and continue at Step 12.
        10. Otherwise receive AUX_SCAN_RSP at T_IFS after AUX_SCAN_REQ, within
            +/-2 us, with AdvMode 00, IUT AdvA, no TargetA or SuppInfo, and ADI as
            permitted by the selected case. Incomplete response data requires AuxPtr.
        11. Follow every AuxPtr to AUX_CHAIN_IND with AdvMode 00 and the remaining
            data until the final pointer is absent and all data is received.
            Check the secondary PHY and prohibit AdvA, TargetA, SuppInfo, TxPower
            and SyncInfo. If AUX_SCAN_RSP has ADI, every chain PDU must carry
            the same ADI; otherwise every chain PDU must omit ADI.
        12. If notifications are enabled, receive Scan Request Received with the
            selected handle and the request's public scanner address/type.
        13. Disable extended advertising before the next row. Before disabling,
            observe another primary/auxiliary event to confirm continued advertising.

    Test Case Configuration:
        Table 4.2-16 rows 1-6: undirected scannable lengths 1, 31, 474, 711, 948,
        capacity. Row 7: capacity, notification enabled, fragmentation preference 1.
        Row 8: 31 octets, wrong AdvA. Rows 9-11: directed scannable lengths 1,
        251, capacity. Row 12: directed, 31 octets, wrong AdvA. All other rows
        disable notifications and use fragmentation preference 0.

    Expected Outcome:
        Pass verdict: capacity is in range and every executed row produces the
        prescribed primary/auxiliary PDUs, PHYs, SID and consistent advertising ADI.
        Every AuxPtr meets T_MAFS and its encoded channel/time. Correct requests
        receive the prescribed response at T_IFS +/-2 us with exactly all submitted
        data and no extra data; wrong AdvA receives no response. Response and chain
        fields obey Steps 10/11, including conditional response-chain ADI inheritance.
        Enabled notifications identify the handle and public scanner. Advertising
        continues after the response; unexpected notifications fail the test.
        The +/-2-us response tolerance and referenced 1-us interval measurement
        accuracy require no sub-microsecond stimulus or measurement.

    Source Correction:
        Step 3 points to Table 4.2-16 for PHYs; the PHYs are in Table 4.2-15,
        while 4.2-16 supplies per-round parameters. Step 6 and the pass verdict
        list TxPower twice; enforce the prohibition once. The PDF 151 verdict's
        unconditional chain-ADI prohibition is a confirmed test-text error.
        Apply Core 6.3 Vol 6 Part B Section 2.3.1.8, Table 2.7 C.1: chain ADI
        is mandatory and matches the superior PDU when that PDU includes ADI;
        otherwise it is absent. AUX_SCAN_RSP ADI remains optional per Table 4.2-15.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.5, LL/DDI/ADV/BV-45-C,
        LL/DDI/ADV/BV-52-C and LL/DDI/ADV/BV-54-C; PDF pages 146-151,
        printed pages 4.2-53 through 4.2-58, Tables 4.2-15 and 4.2-16.
    """
    primary_phy = Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M
    capacity = (
        await tester.command(hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command())
    ).max_advertising_data_length
    assert PDU_ADV_LEGACY_DATA_SIZE_MAX <= capacity <= hci.HCI_LE_ADV_DATA_SIZE_MAX
    rounds = [
        (False, length, False, 0, DUT_ADDRESS)
        for length in (1, 31, 474, 711, 948, capacity)
    ]
    rounds += [
        (False, capacity, True, 1, DUT_ADDRESS),
        (False, 31, False, 0, LOWER_CENTRAL_PUBLIC_ADDRESS),
    ]
    rounds += [(True, length, False, 0, DUT_ADDRESS) for length in (1, 251, capacity)]
    rounds += [(True, 31, False, 0, LOWER_CENTRAL_PUBLIC_ADDRESS)]
    generator = random.Random(0)
    for index, (directed, length, notify, preference, target) in enumerate(rounds):
        if length > capacity:
            await tester.command(extended_enable(0))
            continue
        await tester.command(
            extended_parameters(
                advertising_event_properties=Properties.SCANNABLE_ADVERTISING
                | (Properties.DIRECTED_ADVERTISING if directed else 0),
                peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
                peer_address_type=LOWER_CENTRAL_PUBLIC_ADDRESS.address_type,
                scan_request_notification_enable=int(notify),
                primary_advertising_phy=primary_phy,
                secondary_advertising_phy=phy,
                primary_advertising_interval_min=240 if phy == Phy.LE_CODED else 160,
                primary_advertising_interval_max=240 if phy == Phy.LE_CODED else 160,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
            )
        )
        data = bytes(generator.randint(1, 254) for _ in range(length))
        if index == 1:
            for offset, octet in enumerate(data):
                await tester.command(
                    hci.HCI_LE_Set_Extended_Scan_Response_Data_Command(
                        0,
                        (
                            Operation.FIRST_FRAGMENT
                            if offset == 0
                            else (
                                Operation.LAST_FRAGMENT
                                if offset == len(data) - 1
                                else Operation.INTERMEDIATE_FRAGMENT
                            )
                        ),
                        preference,
                        bytes([octet]),
                    )
                )
        else:
            await set_extended_data(tester, data, response=True, preference=preference)
        await tester.command(extended_enable())
        primary = await tester.expect_pdu(
            kind=AdvertisingPduType.ADV_EXT_IND, duration_us=200000, phy=primary_phy
        )
        assert primary.phy == primary_phy
        primary_fields = decode_extended(primary.pdu)
        assert (
            primary.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
            == AdvertisingMode.SCANNABLE
        )
        assert set(primary_fields) == {'adi', 'aux', 'data'} and (
            not primary_fields['data']
        )
        channel, advertisement, fields = await follow_auxiliary(
            tester, primary, primary_fields, phy=phy
        )
        assert advertisement.phy == phy
        assert (
            advertisement.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
        )
        assert (
            advertisement.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
            == AdvertisingMode.SCANNABLE
        )
        assert set(fields) == {'address', 'adi', 'data'} | (
            {'target'} if directed else set()
        )
        assert fields['address'] == bytes(DUT_ADDRESS) and (not fields['data'])
        assert not advertisement.pdu[0] & PDU_ADV_TXADD_MASK
        assert fields['adi'] == primary_fields['adi']
        assert int.from_bytes(fields['adi'], 'little') >> PDU_ADV_ADI_DID_BITS == 3
        if directed:
            assert fields['target'] == bytes(LOWER_CENTRAL_PUBLIC_ADDRESS)
            assert not advertisement.pdu[0] & PDU_ADV_RXADD_MASK
        await tester.transmit(
            channel,
            request_pdu(
                AdvertisingPduType.SCAN_REQ,
                advertiser=target,
                scanner=LOWER_CENTRAL_PUBLIC_ADDRESS,
            ),
            start_us=advertisement.end_us + LL_IFS_US,
            phy=phy,
        )
        end = tester.radio.now_us + 1
        if target != DUT_ADDRESS:
            assert await tester.receive(channel, duration_us=10000, phy=phy) is None
        else:
            response = await tester.expect_pdu(
                channel, kind=AdvertisingPduType.ADV_EXT_IND, duration_us=1000, phy=phy
            )
            assert response.phy == phy
            assert abs(response.start_us - end - LL_IFS_US) <= RESPONSE_IFS_TOLERANCE_US
            response_fields = decode_extended(response.pdu)
            assert (
                response.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
                == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
            )
            assert response_fields['address'] == bytes(DUT_ADDRESS)
            assert not response.pdu[0] & PDU_ADV_TXADD_MASK
            assert response_fields.get('adi', fields['adi']) == fields['adi']
            assert all(key not in response_fields for key in ('target', 'cte', 'sync'))
            assert (
                await chain(
                    tester,
                    response,
                    response_fields,
                    expected_phy=phy,
                    forbidden=(
                        'address',
                        'target',
                        'cte',
                        'sync',
                        'power',
                        'acad',
                    ),
                )
                == data
            )
            if notify:
                event = await tester.event(hci.HCI_LE_Scan_Request_Received_Event)
                assert (
                    event.advertising_handle == 0
                    and event.scanner_address == LOWER_CENTRAL_PUBLIC_ADDRESS
                    and (
                        event.scanner_address_type
                        == LOWER_CENTRAL_PUBLIC_ADDRESS.address_type
                    )
                )
        await receive_extended(tester, phy=phy, primary_phy=primary_phy)
        assert not any(
            isinstance(event, hci.HCI_LE_Scan_Request_Received_Event)
            for event in tester.events
        ), 'unexpected scan notification'
        await tester.command(extended_enable(0))


async def periodic_advertising(tester, *, phy=Phy.LE_1M):
    """Extended Advertising, Periodic Advertising.

    Initial Condition:
        Advertising parameters select supported intervals, advertising event
        type, own-address type and primary channels. This implementation uses
        public, non-connectable/non-scannable advertising on all primary channels,
        a 100-ms extended interval, and a 500-ms periodic interval that fits the
        largest Coded chain. Table 4.2-17 selects primary/secondary PHYs 1M/1M
        (BV-26), 1M/2M (BV-55), or Coded/Coded (BV-56).

    Test Steps:
        1. Read maximum data capacity, receive successful Command Complete,
           require 31..1650 octets and retain the capacity.
        Repeat Steps 2-16 for each Table 4.2-18 row:
        2. If the row's length fits the capacity, proceed to Step 3; otherwise
           skip the row and continue with the next row (see Source Correction).
        3. Set extended advertising parameters with properties zero, all primary
           channels, a supported selected interval and the Table 4.2-17 PHYs.
           Receive successful Command Complete.
        4. Set periodic advertising parameters with a supported selected interval
           and properties zero; receive successful Command Complete.
        5. Set the row's periodic data using seeded random octets 1..254. Lengths
           above 252 use FIRST, zero or more INTERMEDIATE fragments, then LAST.
           Round 7 uses FIRST with one octet, 29 one-octet INTERMEDIATE commands,
           and LAST with one octet. Otherwise use COMPLETE. Receive successful
           Command Complete for every fragment.
        6. Enable periodic advertising with Enable 1 and receive Command Complete.
        7. Enable extended advertising with Duration 0 and receive Command Complete.
        8. Receive ADV_EXT_IND with AdvMode 00 and AuxPtr on the primary PHY.
        9. Follow AuxPtr to AUX_ADV_IND on the secondary PHY, with AdvMode 00
           and SyncInfo. Check the AuxPtr timing and minimum T_MAFS spacing.
        10. Decode SyncInfo, compute the secondary channel independently using
            CSA #2, and receive AUX_SYNC_IND within its SyncInfo time range.
            Require AdvMode 00 and no ADI; incomplete data requires AuxPtr.
        11. Follow every AuxPtr to AUX_CHAIN_IND with AdvMode 00 and further data,
            until no pointer remains and all submitted data has been received.
        12. Repeat Steps 8-11 one hundred times.
        13. Disable only extended advertising and receive Command Complete,
            keeping periodic advertising enabled.
        14. Repeat Steps 10-11 one hundred times to confirm periodic advertising
            continues, advancing the decoded event counter/channel/anchor.
        15. Disable periodic advertising and receive successful Command Complete.
        16. Clear advertising sets and receive successful Command Complete.

    Test Case Configuration:
        Table 4.2-18 lengths are 0, 252, 474, 711, 948, the returned capacity,
        and 31 octets. The last row exercises one-octet HCI fragmentation.

    Expected Outcome:
        Pass verdict: capacity is in range and every executed row produces
        ADV_EXT_IND with AuxPtr to AUX_ADV_IND containing SyncInfo. Every AuxPtr
        meets T_MAFS and its encoded channel/time. AUX_SYNC_IND uses the independently
        computed CSA #2 channel, the configured secondary PHY, AdvMode 00 and no
        ADI. The periodic PDU and its chain contain exactly the submitted data,
        with no additional data (including the empty row), and every chain uses
        the same PHY and AdvMode. Both hundred-observation phases succeed,
        including the phase with extended advertising disabled.

    Source Correction:
        Step 2 refers to Step 17, but the procedure ends at Step 16. Skip an
        oversized row entirely and continue at the next row. This preserves
        the table's capacity guard without inventing an additional source step.
        Amber confirms this interpretation of the supplied source excerpt;
        it is a local correction, not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.6, LL/DDI/ADV/BV-26-C,
        LL/DDI/ADV/BV-55-C and LL/DDI/ADV/BV-56-C; PDF pages 151-156,
        printed pages 4.2-58 through 4.2-63, Tables 4.2-17 and 4.2-18.
    """
    capacity = (
        await tester.command(hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command())
    ).max_advertising_data_length
    assert hci.HCI_LE_ADV_DATA_SIZE_MAX >= capacity >= 31
    primary_phy = Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M
    generator = random.Random(0)
    for round_number, size in enumerate((0, 252, 474, 711, 948, capacity, 31), 1):
        if size > capacity:
            continue
        await tester.command(
            extended_parameters(
                primary_advertising_phy=primary_phy,
                secondary_advertising_phy=phy,
                primary_advertising_interval_min=160,
                primary_advertising_interval_max=160,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
            )
        )
        await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(0, 400, 400, 0)
        )
        data = bytes(generator.randint(1, 254) for _ in range(size))
        limit = 1 if round_number == 7 else 252
        if size <= limit:
            await tester.command(
                hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
                    0, Operation.COMPLETE_DATA, data
                )
            )
        else:
            for offset in range(0, size, limit):
                operation = (
                    Operation.FIRST_FRAGMENT
                    if not offset
                    else (
                        Operation.LAST_FRAGMENT
                        if offset + limit >= size
                        else Operation.INTERMEDIATE_FRAGMENT
                    )
                )
                await tester.command(
                    hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
                        0, operation, data[offset : offset + limit]
                    )
                )
        await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0))
        await tester.command(extended_enable())
        for _ in range(100):
            primary = await tester.expect_pdu(
                kind=AdvertisingPduType.ADV_EXT_IND,
                duration_us=200_000,
                phy=primary_phy,
            )
            first = _nonconnectable_extended_packet(primary, primary_phy)
            assert 'aux' in first
            _, packet, fields = await follow_auxiliary(tester, primary, first)
            assert _nonconnectable_extended_packet(packet, phy) == fields
            assert fields['adi'] == first['adi']
            assert 'sync' in fields
            train = PeriodicTrain.from_advertisement(packet, fields)
            assert train.interval == 400
            assert await train.receive(tester) == data
        await tester.command(extended_enable(0))
        for _ in range(100):
            assert await train.receive(tester) == data
        await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(0, 0))
        await tester.command(hci.HCI_LE_Clear_Advertising_Sets_Command())


async def extended_data_update(tester):
    """Extended Advertising, Host Modifying Data and ADI.

    Initial Condition:
        Advertising parameters have selected supported intervals, event type,
        own-address type and primary channels. This implementation uses public
        non-connectable/non-scannable undirected advertising on all primary
        channels, LE 1M on both PHYs and a selected interval of 100 ms.

    Test Steps:
        1. Read capacity, require 31..1650 octets and store the result.
        2. Configure all primary channels, a supported selected interval,
           properties zero and LE 1M on both PHYs; this also selects the SID.
        Repeat Steps 3-9 for each Table 4.2-19 row:
        3. If the row length fits the capacity, proceed to Step 4; otherwise
           proceed to Step 10 to disable advertising.
        4. Submit the row's data using seeded random octets 1..254. Lengths above
           251 use FIRST, zero or more INTERMEDIATE fragments, then LAST;
           other lengths use COMPLETE.
        5. Enable extended advertising with Duration 0 only in round 1; later
           rounds update the still-enabled set without disabling it.
        Repeat Steps 6-9 ten times per executed row:
        6. Receive ADV_EXT_IND with AdvMode 00, AuxPtr and ADI containing the SID
           selected in Step 2 and an Advertising DID.
        7. Follow AuxPtr to LE 1M AUX_ADV_IND with AdvMode 00 and matching ADI.
           If it does not contain all the data, it must include another AuxPtr.
        8. Follow every AuxPtr to AUX_CHAIN_IND with AdvMode 00 and further data
           until no pointer remains and all data has been received.
        9. Except for the very first advertisement, compare concatenated RF data
           with the preceding advertisement, ignoring PDU boundaries. Changed
           data with unchanged DID fails. A new DID must carry exactly the current
           submission; a previous DID may retain the previous payload. Require
           the submitted data to appear during the ten observations.
        10. Disable extended advertising after all executed rows or the capacity
            branch from Step 3.

    Test Case Configuration:
        Table 4.2-19 submits the reported capacity, one octet, and 251 octets.

    Expected Outcome:
        Pass verdict: capacity is in range. ADV_EXT_IND has the configured SID
        and AuxPtr referring to AUX_ADV_IND with matching ADI. Every AuxPtr meets
        T_MAFS and its encoded channel/time; every secondary PDU uses LE 1M.
        Data read under a new DID contains exactly the current submission and no
        further data, including all chain fragments. Every changed RF payload
        changes DID, and each executed row is actually observed. Do not impose
        an additional HCI-to-air update deadline absent from the source.

    Source Correction:
        Step 6 names Step 3 as the SID configuration step; Step 3 only checks
        capacity, while Step 2 sets advertising parameters. Use the Step 2 SID,
        consistent with the source pass verdict. Amber supports this local
        cross-reference correction; no adopted SIG erratum is claimed.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-27-C;
        PDF pages 156-159, printed pages 4.2-63 through 4.2-66,
        Table 4.2-19 and Figure 4.2-23.
    """
    capacity = (
        await tester.command(hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command())
    ).max_advertising_data_length
    assert PDU_ADV_LEGACY_DATA_SIZE_MAX <= capacity <= hci.HCI_LE_ADV_DATA_SIZE_MAX
    await tester.command(
        extended_parameters(
            primary_advertising_interval_min=160,
            primary_advertising_interval_max=160,
            primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
        )
    )
    previous = None
    generator = random.Random(0)
    for index, length in enumerate(
        (capacity, 1, hci.HCI_LE_EXT_ADV_DATA_FRAGMENT_SIZE_MAX)
    ):
        if length > capacity:
            break
        data = bytes(generator.randint(1, 254) for _ in range(length))
        await set_extended_data(tester, data)
        if index == 0:
            await tester.command(extended_enable())
        observed_current = False
        for _ in range(10):
            primary = await tester.expect_pdu(
                kind=AdvertisingPduType.ADV_EXT_IND, duration_us=200000
            )
            first_fields = _nonconnectable_extended_packet(primary, Phy.LE_1M)
            assert 'aux' in first_fields and 'adi' in first_fields
            _, packet, fields = await follow_auxiliary(tester, primary, first_fields)
            assert _nonconnectable_extended_packet(packet, Phy.LE_1M) == fields
            assert fields['adi'] == first_fields['adi']
            assert sum('address' in item for item in (first_fields, fields)) == 1
            assert next(
                item['address'] for item in (first_fields, fields) if 'address' in item
            ) == bytes(DUT_ADDRESS)
            assert all(
                'target' not in item and 'sync' not in item
                for item in (first_fields, fields)
            )
            assert int.from_bytes(fields['adi'], 'little') >> PDU_ADV_ADI_DID_BITS == 3
            observed = await chain(tester, packet, fields, expected_phy=Phy.LE_1M)
            did = int.from_bytes(fields['adi'], 'little') & PDU_ADV_ADI_DID_MASK
            previous = _check_advertising_update(previous, observed, did, data)
            observed_current |= observed == data
        assert observed_current, 'Submitted data never appeared in this round'
    await tester.command(extended_enable(0))


async def overlapping_events(tester, *, rounds=(1, 2, 3)):
    """Extended Advertising, Overlapping Extended Advertising Events.

    Initial Condition:
        Advertising parameters select supported intervals, an advertising event
        type, own-address type and primary channel map. This implementation uses
        public addresses, all primary channels and LE 1M on both PHYs. Table
        4.2-20 selects rounds 1-3 for BV-28, round 4 for BV-115, round 5 for
        BV-116 and round 6 for BV-117.

    Test Steps:
        Repeat Steps 1-9 for each selected Table 4.2-21 row:
        1. Set extended advertising parameters using all primary channels and a
           supported selected interval, the row's properties and Max_Skip, and
           LE 1M on both PHYs. Directed rows target the public Lower Tester.
        2. Set one advertising-data octet using a seeded random value 1..254.
        3. Enable extended advertising with Duration 0.
        Repeat Steps 4-8 using the row's repeat count:
        4. Receive primary ADV_EXT_IND with AuxPtr and AdvMode matching the row's
           properties; validate the RF envelope and required ADI.
        5. Decode Aux Offset and Offset Units to compute the target time range
           for the referred AUX_ADV_IND and retain its RF channel.
        6. Receive further primary events until that target is reached, repeating
           Steps 4-5 and recalculating the common time range. Require the same
           auxiliary channel/PHY, matching ADI, and overlapping pointer ranges
           within their Offset Units.
        7. Follow AuxPtr to LE 1M AUX_ADV_IND with the expected AdvMode. Verify
           the actual start is in every retained pointer range, meets T_MAFS,
           and follows the preceding auxiliary event without overlap.
        8. Record the number of primary events that skipped an auxiliary PDU.
           Require at most Max_Skip skips and hence at most Max_Skip+1
           overlapping extended events. Check the configured addresses and data.
        9. Disable extended advertising before the next selected row.

    Test Case Configuration:
        Table 4.2-21 rows (properties, Max_Skip, repeat count):
        1: (0, 1, 100); 2: (0, 15, 50); 3: (0, 255, 10);
        4: (connectable, 8, 50); 5: (directed, 8, 50);
        6: (connectable directed, 8, 50).

    Expected Outcome:
        Pass verdict: every ADV_EXT_IND AuxPtr refers to a valid AUX_ADV_IND
        meeting T_MAFS. Pointers from overlapping events identify a common time
        within one Offset Unit and the same secondary channel/PHY. Skipped events
        do not exceed Max_Skip and no more than Max_Skip+1 events overlap.
        Received modes, ADI, addresses and the one submitted data octet match
        the configured row.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.7, LL/DDI/ADV/BV-28-C,
        LL/DDI/ADV/BV-115-C, LL/DDI/ADV/BV-116-C and LL/DDI/ADV/BV-117-C;
        PDF pages 159-161, printed pages 4.2-66 through 4.2-68,
        Tables 4.2-20 and 4.2-21.
    """
    configurations = (
        (0, 1, 100),
        (0, 15, 50),
        (0, 255, 10),
        (Properties.CONNECTABLE_ADVERTISING, 8, 50),
        (Properties.DIRECTED_ADVERTISING, 8, 50),
        (Properties.CONNECTABLE_ADVERTISING | Properties.DIRECTED_ADVERTISING, 8, 50),
    )
    generator = random.Random(0)
    for round_number in rounds:
        properties, skip, count = configurations[round_number - 1]
        await tester.command(
            extended_parameters(
                advertising_event_properties=properties,
                peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
                peer_address_type=hci.AddressType.PUBLIC_DEVICE,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
                secondary_advertising_max_skip=skip,
            )
        )
        data = bytes([generator.randint(1, 254)])
        await set_extended_data(tester, data)
        await tester.command(extended_enable())
        previous_end = 0
        mode = (
            AdvertisingMode.CONNECTABLE
            if properties & Properties.CONNECTABLE_ADVERTISING
            else AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
        )
        for _ in range(count):
            primary = await tester.expect_pdu()
            fields, channel, target_min, target_max = _overlapping_advertisement(
                primary, mode
            )
            unit = target_max - target_min
            skipped = 0
            while tester.radio.now_us + 1 < target_min - unit:
                following = await tester.receive(
                    37, duration_us=target_min - unit - tester.radio.now_us - 1
                )
                if following is None:
                    break
                next_fields, next_channel, next_min, next_max = (
                    _overlapping_advertisement(following, mode)
                )
                assert next_channel == channel
                target_min = max(target_min, next_min)
                target_max = min(target_max, next_max)
                assert target_min < target_max
                assert next_fields['adi'] == fields['adi']
                primary, fields, unit = (following, next_fields, next_max - next_min)
                skipped += 1
                assert skipped <= skip
            first_fields = fields
            _, packet, fields = await follow_auxiliary(tester, primary, fields)
            assert packet.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
            assert packet.start_us > previous_end
            assert target_min <= packet.start_us < target_max
            assert packet.phy == Phy.LE_1M
            assert packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS == mode
            assert fields['adi'] == first_fields['adi']
            assert sum('address' in item for item in (first_fields, fields)) == 1
            assert next(
                item['address'] for item in (first_fields, fields) if 'address' in item
            ) == bytes(DUT_ADDRESS)
            for item in (first_fields, fields):
                if 'target' in item:
                    assert item['target'] == bytes(LOWER_CENTRAL_PUBLIC_ADDRESS)
            assert sum('target' in item for item in (first_fields, fields)) == int(
                bool(properties & Properties.DIRECTED_ADVERTISING)
            )
            assert fields['data'] == data and 'aux' not in fields
            previous_end = packet.end_us
        await tester.command(extended_enable(0))


MULTI_EXTENDED_ROUNDS = (
    (0, 1, 0, 0),
    (1, 0, 0, 191),
    (0, 5, 191, 0),
    (0, 0, 191, 191),
    (0, 4, 251, 251),
    (0, 1, 253, 0),
    (0, 0, 474, 0),
)
MULTI_LEGACY_ROUNDS = (
    (0, 16, 0, 0),
    (19, 0, 0, 191),
    (0, 19, 191, 31),
    (19, 16, 31, 31),
    (21, 4, 0, 251),
    (0, 29, 253, 0),
    (0, 18, 474, 0),
)
MULTI_PERIODIC_ROUNDS = (
    (1, (Phy.LE_1M, Phy.LE_1M)),
    (2, (Phy.LE_2M, Phy.LE_2M)),
    (3, (Phy.LE_CODED, Phy.LE_CODED)),
    (10, (Phy.LE_1M, Phy.LE_2M, Phy.LE_CODED)),
    (11, (Phy.LE_2M, Phy.LE_CODED, Phy.LE_1M)),
    (12, (Phy.LE_CODED, Phy.LE_1M, Phy.LE_2M)),
)


async def _configure_advertising_sets(
    tester, properties, phys, lengths, *, intervals=(160, 160), skip_empty=False
):
    generator = random.Random(104)
    payloads = []
    for handle, (flags, phy, interval) in enumerate(zip(properties, phys, intervals)):
        await tester.command(
            extended_parameters(
                advertising_handle=handle,
                advertising_sid=handle,
                advertising_event_properties=flags,
                peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
                peer_address_type=LOWER_CENTRAL_PUBLIC_ADDRESS.address_type,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
                primary_advertising_interval_min=interval,
                primary_advertising_interval_max=interval,
                primary_advertising_phy=phy,
                secondary_advertising_phy=phy,
            )
        )
    for handle, length in enumerate(lengths):
        payload = bytes(generator.randrange(1, 255) for _ in range(length))
        payloads.append(payload)
        if length or not skip_empty:
            await set_extended_data(tester, payload, handle=handle)
    return payloads


def _extended_advertising_set(packet, fields, properties, phys, payloads):
    """Identify a configured set without requiring an optional auxiliary PDU."""
    mode = packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
    assert not fields['data']
    if 'aux' in fields:
        assert 'adi' in fields
        handle = int.from_bytes(fields['adi'], 'little') >> PDU_ADV_ADI_DID_BITS
        assert handle in range(len(properties))
    else:
        assert 'adi' not in fields
        assert mode == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
        matches = [
            index
            for index, flags in enumerate(properties)
            if not (
                flags
                & (
                    Properties.USE_LEGACY_ADVERTISING_PDUS
                    | Properties.CONNECTABLE_ADVERTISING
                )
            )
            and packet.phy == phys[index]
            and not payloads[index]
            and bool(flags & Properties.DIRECTED_ADVERTISING) == ('target' in fields)
        ]
        assert len(matches) == 1, 'Primary-only event does not identify a unique set'
        handle = matches[0]
    flags = properties[handle]
    assert not flags & Properties.USE_LEGACY_ADVERTISING_PDUS
    assert packet.phy == phys[handle]
    assert mode == (
        AdvertisingMode.CONNECTABLE
        if flags & Properties.CONNECTABLE_ADVERTISING
        else AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
    )
    if flags & Properties.CONNECTABLE_ADVERTISING or (
        packet.phy == Phy.LE_CODED and 'aux' in fields
    ):
        assert 'address' not in fields and 'target' not in fields
    return handle


def _advertising_set_addresses(packets, directed):
    """Check public identity once across the primary and first auxiliary PDU."""
    for name, expected, mask, count in (
        ('address', DUT_ADDRESS, PDU_ADV_TXADD_MASK, 1),
        ('target', LOWER_CENTRAL_PUBLIC_ADDRESS, PDU_ADV_RXADD_MASK, int(directed)),
    ):
        present = [
            (packet, fields[name]) for packet, fields in packets if name in fields
        ]
        assert len(present) == count
        for packet, address in present:
            assert address == bytes(expected) and not packet.pdu[0] & mask


async def _observe_advertising_sets(
    tester, properties, phys, payloads, *, repetitions=10
):
    """Observe every primary channel; check each set and complete auxiliary chain."""
    legacy_types = {
        16: AdvertisingPduType.ADV_NONCONN_IND,
        19: AdvertisingPduType.ADV_IND,
        21: AdvertisingPduType.ADV_DIRECT_IND,
        29: AdvertisingPduType.ADV_DIRECT_IND,
        18: AdvertisingPduType.ADV_SCAN_IND,
    }
    counts = [0, 0]
    channels = [set(), set()]
    # Single-observation callers still need a sample on every primary channel.
    per_channel, extra = divmod(repetitions, len(LL_ADV_PRIMARY_CHANNELS))
    for position, channel in enumerate(LL_ADV_PRIMARY_CHANNELS):
        target = [count + max(1, per_channel + (position < extra)) for count in counts]
        for attempt in range(repetitions * 200):
            phy = phys[attempt % len(phys)]
            packet = await tester.receive(channel, duration_us=200000, phy=phy)
            if packet is None:
                continue
            assert packet.valid_crc and packet.phy == phy
            kind = packet.pdu[0] & PDU_ADV_TYPE_MASK
            assert packet.pdu[1] == len(packet.pdu) - PDU_HEADER_SIZE
            if kind == AdvertisingPduType.ADV_EXT_IND:
                fields = decode_extended(packet.pdu)
                handle = _extended_advertising_set(
                    packet, fields, properties, phys, payloads
                )
                flags = properties[handle]
                addresses = [(packet, fields)]
                expected_mode = (
                    AdvertisingMode.CONNECTABLE
                    if flags & Properties.CONNECTABLE_ADVERTISING
                    else AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
                )
                if 'aux' in fields:
                    adi = fields['adi']
                    _, packet, fields = await follow_auxiliary(tester, packet, fields)
                    assert fields['adi'] == adi
                    assert packet.phy == phys[handle]
                    assert (
                        packet.pdu[0] & PDU_ADV_TYPE_MASK
                        == AdvertisingPduType.ADV_EXT_IND
                    )
                    assert (
                        packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
                        == expected_mode
                    )
                    addresses.append((packet, fields))
                _advertising_set_addresses(
                    addresses, bool(flags & Properties.DIRECTED_ADVERTISING)
                )
                assert (
                    await chain(tester, packet, fields, expected_phy=phys[handle])
                    == payloads[handle]
                )
            else:
                matches = [
                    handle
                    for handle, flags in enumerate(properties)
                    if legacy_types.get(flags) == kind
                ]
                matches = [
                    handle
                    for handle in matches
                    if packet.pdu[PDU_HEADER_SIZE + PDU_ADV_ADDRESS_SIZE :]
                    == (
                        bytes(LOWER_CENTRAL_PUBLIC_ADDRESS)
                        if properties[handle] & Properties.DIRECTED_ADVERTISING
                        else payloads[handle]
                    )
                ]
                assert len(matches) == 1, (kind, packet.pdu.hex(), matches)
                handle = matches[0]
                assert phy == phys[handle]
                assert not packet.pdu[0] & PDU_ADV_TXADD_MASK
                if properties[handle] & Properties.DIRECTED_ADVERTISING:
                    assert not packet.pdu[0] & PDU_ADV_RXADD_MASK
                assert packet.pdu[
                    PDU_HEADER_SIZE : PDU_HEADER_SIZE + PDU_ADV_ADDRESS_SIZE
                ] == bytes(DUT_ADDRESS)
            counts[handle] += 1
            channels[handle].add(channel)
            if all((count >= goal for count, goal in zip(counts, target))):
                break
        assert all((count >= goal for count, goal in zip(counts, target))), (
            channel,
            counts,
        )
    assert min(counts) >= repetitions and all(len(seen) == 3 for seen in channels)


async def _set_phase(tester, phys, trains, enabled):
    advertisements = dict.fromkeys(enabled, 0)
    periodic = dict.fromkeys(range(len(phys)), 0)
    primaries = [Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M for phy in phys]
    for attempt in range(100 * len(phys) * 30):
        if enabled:
            primary_phy = primaries[attempt % len(primaries)]
            primary = await tester.receive(37, duration_us=100000, phy=primary_phy)
            if primary is None:
                continue
            fields = _nonconnectable_extended_packet(primary, primary_phy)
            assert 'aux' in fields and 'adi' in fields
            sid = int.from_bytes(fields['adi'], 'little') >> PDU_ADV_ADI_DID_BITS
            assert sid in enabled, 'Advertising received from a disabled or unknown set'
            assert primary.phy == primaries[sid]
            adi = fields['adi']
            _, packet, fields = await follow_auxiliary(tester, primary, fields)
            assert fields['adi'] == adi
            assert _nonconnectable_extended_packet(packet, phys[sid]) == fields
            assert 'sync' in fields
            assert await chain(tester, packet, fields, expected_phy=phys[sid]) == b''
            train = PeriodicTrain.from_advertisement(packet, fields)
            assert train.interval == (12, 16, 18)[sid]
            if sid in trains:
                assert (
                    train.access_address == trains[sid].access_address
                    and train.crc_init == trains[sid].crc_init
                )
            trains[sid] = train
            advertisements[sid] += 1
        if len(trains) != len(phys):
            continue
        assert len({train.access_address for train in trains.values()}) == len(phys)
        for train in trains.values():
            while train.anchor <= tester.radio.now_us:
                train.next_event()
        sid = min(trains, key=lambda key: (periodic[key], trains[key].anchor))
        data = await trains[sid].receive(tester, required=False)
        if data is not None:
            assert data == b''
            periodic[sid] += 1
        if min(periodic.values()) >= 100 and all(
            count >= 100 for count in advertisements.values()
        ):
            break
    assert min(periodic.values()) >= 100 and all(
        count >= 100 for count in advertisements.values()
    ), (advertisements, periodic)


async def _advertising_rounds(tester, table, rounds, phys, *, skip_empty=False):
    capacity = (
        await tester.command(hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command())
    ).max_advertising_data_length
    assert PDU_ADV_LEGACY_DATA_SIZE_MAX <= capacity <= hci.HCI_LE_ADV_DATA_SIZE_MAX
    for number in rounds:
        first, second, size0, size1 = table[number - 1]
        if max(size0, size1) > capacity:
            tester.output.write(
                f'ROUND {number} INAPPLICABLE: reported data capacity\n'
            )
            continue
        properties = (first, second)
        payloads = await _configure_advertising_sets(
            tester, properties, phys, (size0, size1), skip_empty=skip_empty
        )
        durations = [
            (
                128
                if flags & Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
                else 0
            )
            for flags in properties
        ]
        await tester.command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
                1, [0, 1], durations, [0, 0]
            )
        )
        await _observe_advertising_sets(tester, properties, phys, payloads)
        await tester.command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
                0, [0, 1], [0, 0], [0, 0]
            )
        )
        await tester.command(hci.HCI_LE_Clear_Advertising_Sets_Command())


async def multiple_sets_1m(tester, *, rounds):
    """Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY.

    Initial Condition:
        Advertising parameters select supported intervals, event properties,
        own-address type and primary channels. This implementation uses public
        sets 0/1, distinct SIDs 0/1, all primary channels and 100-ms intervals.
        Both primary and secondary PHYs are LE 1M. Table 4.2-22 selects which
        Table 4.2-23 rows are executed; directed sets use the public Lower Tester.

    Test Steps:
        1. Read maximum advertising-data length, require 31..1650 octets and
           store the capacity.
        Repeat Steps 2-11 for the case's Table 4.2-23 rows:
        2. If both data lengths fit the capacity, proceed to Step 3; otherwise
           skip the entire row and continue with the next row.
        3. Configure the first set using all primary channels, a supported selected
           interval, its row properties, and LE 1M on both PHYs.
        4. Configure the second set with its row properties, all primary channels,
           a supported selected interval, public Own_Address_Type and both PHYs 1M.
        5. For each set submit seeded random octets 1..254 at the row's length.
           Above 251 octets use FIRST, zero or more INTERMEDIATE, then LAST;
           otherwise use COMPLETE, including zero-length data.
        6. Enable both sets with one extended enable command and both Durations 0.
        Repeat Steps 7-9 ten times per set, monitoring channels 37/38/39:
        7. Receive interlaced ADV_EXT_IND events with each set's expected AdvMode.
           Identify an auxiliary-bearing set by SID; a primary-only empty set
           is identified by its unique configured mode, PHY and directedness.
        8. If AuxPtr is present, follow it to LE 1M AUX_ADV_IND with the same
           AdvMode and matching ADI. Incomplete data requires a further AuxPtr.
           Check encoded channel/time and at least T_MAFS after the superior PDU.
        9. Follow every further pointer to AUX_CHAIN_IND with AdvMode 00 and the
           remaining data until no pointer remains and all data is received.
           Require every chain PHY to remain LE 1M and the ADI to match.
        10. Disable both sets in one extended advertising enable command.
        11. Clear both sets using LE Clear Advertising Sets.

    Test Case Configuration:
        Table 4.2-23 rows (first properties, second properties, first length,
        second length): (0,1,0,0), (1,0,0,191), (0,5,191,0), (0,0,191,191),
        (0,4,251,251), (0,1,253,0), (0,0,474,0). Properties 0/1/4/5 mean
        non-connectable undirected/connectable undirected/non-connectable
        directed/connectable directed. BV-29 selects rows 4/7; BV-118 selects
        1/2/6; BV-119 selects 5; BV-120 selects 3. All HCI commands require success.

    Expected Outcome:
        Pass verdict: capacity is in range and both configured sets produce
        interlaced primary events with their expected modes and identities.
        AuxPtr is optional for an empty non-connectable set; when present it
        refers to a valid LE 1M auxiliary PDU and each pointer meets T_MAFS.
        Reassembled data is exactly the submission for that set, with no extra
        data, including empty rows. Every required set is observed ten times
        across the supported primary channels with its correct public addresses.

    Source Correction:
        Step 2 refers to Step 12, but the procedure ends at Step 11. Interpret
        the capacity-exceeded branch as skipping the entire row, as confirmed
        by Amber from the supplied source. This is not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.8, LL/DDI/ADV/BV-29-C,
        LL/DDI/ADV/BV-118-C, LL/DDI/ADV/BV-119-C and LL/DDI/ADV/BV-120-C;
        PDF pages 162-166, printed pages 4.2-69 through 4.2-73,
        Tables 4.2-22 and 4.2-23.
    """
    await _advertising_rounds(
        tester, MULTI_EXTENDED_ROUNDS, rounds, (Phy.LE_1M, Phy.LE_1M)
    )


async def multiple_sets_phys(tester, *, phys):
    """Extended Advertising, Multiple Sets.

    Initial Condition:
        Advertising parameters select supported intervals, event properties,
        own-address type and primary channels. This implementation uses public
        sets 0/1 with SIDs 0/1, all primary channels and 100-ms intervals. Both
        primary and secondary PHYs of a set use its Table 4.2-24 PHY: Coded/Coded
        across the two sets for BV-30, and 1M/Coded for BV-31. Directed sets
        target the public Lower Tester.

    Test Steps:
        1. Read maximum advertising-data length, require 31..1650 octets and
           retain the capacity.
        Repeat Steps 2-11 for all seven Table 4.2-25 rows:
        2. Proceed if both data lengths fit the capacity; otherwise skip the row.
        3. Configure the first set's row properties, all primary channels and a
           supported selected interval, using its assigned PHY on both channels.
        4. Configure the second set likewise with its own row properties and
           assigned PHY, explicitly selecting a public Own_Address_Type.
        5. For each set submit the specified length of seeded octets 1..254.
           Above 251 octets use FIRST, zero or more INTERMEDIATE, then LAST;
           otherwise use COMPLETE, including zero-length data.
        6. Enable both sets in one extended enable command, both Durations 0.
        Repeat Steps 7-9 ten times per set, monitoring all primary channels:
        7. Receive interlaced ADV_EXT_IND with each set's mode and assigned PHY.
           Use SID when AuxPtr is present; otherwise identify the unique empty
           primary-only set without requiring ADI or an auxiliary packet.
        8. Follow an AuxPtr, when present, to AUX_ADV_IND with the set's assigned
           PHY and expected AdvMode. Check ADI, channel, encoded timing and T_MAFS.
           If data is incomplete, require a further pointer.
        9. Follow every further pointer to AUX_CHAIN_IND with AdvMode 00 and
           additional data until the final pointer is absent and all data is
           received, retaining that set's secondary PHY and matching ADI.
        10. Disable both sets in one extended advertising enable command.
        11. Clear the advertising sets with one LE Clear Advertising Sets command.

    Test Case Configuration:
        Table 4.2-25 rows (first properties, second properties, first length,
        second length): (0,1,0,0), (1,0,0,191), (0,5,191,0), (0,0,191,191),
        (0,4,251,251), (0,1,253,0), (0,0,474,0). The properties mean
        non-connectable undirected (0), connectable undirected (1),
        non-connectable directed (4), or connectable directed (5).
        Both cases execute every applicable row. All commands require success.

    Expected Outcome:
        Pass verdict: capacity is in range; both sets produce interlaced primary
        events on their configured PHYs. Optional AuxPtrs refer to valid auxiliary
        packets with the same set's PHY and at least T_MAFS spacing. Each complete
        data chain equals that set's submission, without additional data; empty
        sets contain none. Both sets are observed ten times across primary channels,
        with the prescribed modes, public identities and matching ADI when present.

    Source Correction:
        Step 2 names nonexistent Step 12; skip the entire oversized row after
        checking both lengths. The last pass bullet's generic Coded wording
        does not override Table 4.2-24 or Steps 7/8: BV-31 uses LE 1M for its
        first set and Coded for its second. Amber supports both readings from
        the supplied source; these are local corrections, not adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.9, LL/DDI/ADV/BV-30-C and LL/DDI/ADV/BV-31-C;
        PDF pages 166-170, printed pages 4.2-73 through 4.2-77,
        Tables 4.2-24 and 4.2-25.
    """
    await _advertising_rounds(tester, MULTI_EXTENDED_ROUNDS, range(1, 8), phys)


async def multiple_legacy_extended_sets(tester, *, rounds):
    """Extended Advertising, Multiple Sets, Legacy and Extended.

    Initial Condition:
        Advertising parameters select supported intervals, event properties,
        own-address type and primary channels. Both sets use public addresses,
        all primary channels and LE 1M. This implementation selects 100-ms
        intervals for non-high-duty sets, handles/SIDs 0/1, and the public Lower
        Tester for directed advertising. Table 4.2-26 selects the rows per case.

    Test Steps:
        1. Read maximum advertising-data length, require 31..1650 octets and
           store the capacity.
        Repeat Steps 2-11 for the case's Table 4.2-27 rows:
        2. If both row lengths fit the capacity, proceed to Step 3; otherwise
           skip the entire row and proceed to the next row.
        3. Set the first advertising set's row properties using all primary
           channels, a supported interval and LE 1M primary/secondary PHYs.
        4. Set the second set's row properties with the same channel/PHY choices,
           a supported interval and a public Own_Address_Type.
        5. For each nonempty set, submit seeded octets 1..254. Above 251 use
           FIRST, zero or more INTERMEDIATE, then LAST; otherwise use COMPLETE.
           For a zero-length set, send no data command.
        6. Enable both sets in one command. Duration is 0x0080 (1280 ms) only
           for properties 0x001D; otherwise it is zero.
        Repeat Steps 7-9 ten times per set, monitoring every primary channel:
        7. Receive interlaced legacy or ADV_EXT_IND events according to each
           set's properties. Check the exact legacy kind or extended AdvMode.
        8. If AuxPtr is present, follow it to LE 1M AUX_ADV_IND with the expected
           mode and matching ADI, encoded channel/time and T_MAFS spacing.
           Incomplete data requires a further AuxPtr. Empty non-connectable
           primary-only sets do not require an auxiliary packet or ADI.
        9. Follow further pointers to AUX_CHAIN_IND with AdvMode 00 and additional
           data until all data is received and no pointer remains. Require LE 1M
           on every secondary PDU, and exact set-specific reassembled data.
        10. Disable both sets using one extended advertising enable command.
        11. Clear the advertising sets using one LE Clear Advertising Sets command.

    Test Case Configuration:
        Table 4.2-27 rows (first properties, second properties, first length,
        second length): (0x00,0x10,0,0), (0x13,0x00,0,191), (0x00,0x13,191,31),
        (0x13,0x10,31,31), (0x15,0x04,0,251), (0x00,0x1D,253,0),
        (0x00,0x12,474,0). BV-32 selects row 1; BV-121 selects 2-4;
        BV-122 selects 5; BV-123 selects 6; BV-124 selects 7.
        Require successful HCI responses throughout.

    Expected Outcome:
        Pass verdict: capacity is in range and both sets interlace the expected
        legacy or extended primary PDUs. Any AuxPtr refers to a valid LE 1M
        auxiliary packet with T_MAFS spacing. Each set's complete legacy data or
        extended chain equals the submitted data without additional bytes; empty
        rows contain no data. Both sets are observed ten times across the primary
        channels, with the configured public AdvA/TargetA and correct mode/type.

    Source Correction:
        Step 2 refers to Step 12, but the source ends at Step 11. Skip the
        entire row if either requested data length exceeds the capacity.
        Amber supports this reading from the supplied source; no adopted
        SIG erratum is claimed.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.10, LL/DDI/ADV/BV-32-C,
        LL/DDI/ADV/BV-121-C through LL/DDI/ADV/BV-124-C;
        PDF pages 170-174, printed pages 4.2-77 through 4.2-81,
        Tables 4.2-26 and 4.2-27.
    """
    await _advertising_rounds(
        tester, MULTI_LEGACY_ROUNDS, rounds, (Phy.LE_1M, Phy.LE_1M), skip_empty=True
    )


async def _require_periodic_capacity(tester, command):
    result = await tester.command(
        command, (ErrorCode.SUCCESS, ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR)
    )
    if result.status == ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR:
        pytest.skip(
            'Inconclusive: insufficient resources for the source periodic-set '
            'configuration'
        )


async def multiple_periodic_sets(tester):
    """Extended Advertising, Periodic Advertising, Multiple Sets, Multiple PHYs (All
    Supported PHYs).

    Initial Condition:
        Advertising parameters select supported intervals, event type,
        own-address type and channel map. Supported Simultaneous Advertising
        Sets is an IXIT declaration. This DUT declares both optional PHYs and
        at least three concurrent sets, verified by Read Number of Supported
        Advertising Sets during preparation. Table 4.2-28 therefore selects
        rows 1, 2, 3, 10, 11 and 12. Use public AdvA, distinct handles/SIDs
        and all primary channels. Round 1 always applies; optional-PHY rounds
        apply according to the declaration, not by silently omitting a set.

    Test Steps:
        Repeat Steps 1-12 for every selected Table 4.2-28 row:
        1. Configure all specified extended advertising sets, using 50-ms intervals,
           properties zero, all primary channels and the row's primary/secondary
           PHYs. Require successful Command Complete for each parameter command.
        2. Configure all periodic sets with properties zero and intervals 15 ms,
           20 ms and, when present, 22.5 ms for the first, second and third set.
           Require successful Command Complete for every parameter command.
        3. Enable periodic advertising for each set with Enable 1, only after
           all sets have completed Steps 1/2.
        4. Enable the associated extended sets with one command, all Durations 0.
        5. Monitor the supported primary PHYs. Receive each enabled set's
           interlaced ADV_EXT_IND with AdvMode 00 and AuxPtr on its assigned PHY.
        6. Follow each AuxPtr to the assigned secondary PHY's AUX_ADV_IND with
           AdvMode 00 and SyncInfo. Check pointer timing, T_MAFS and matching ADI.
        7. Repeat Steps 5-6 one hundred times per enabled set while using each
           SyncInfo to synchronize to its periodic train. Receive AUX_SYNC_IND
           with AdvMode 00 on the independently computed CSA #2 channels and
           configured PHYs. This receiver also samples at least 100 periodic
           PDUs per train during this phase.
        8. Disable extended advertising for the first set while retaining
           synchronization with every periodic train.
        9. Repeat Steps 5-7 for the remaining associated advertisers and all
           periodic trains. Continue sampling every configured primary PHY and
           reject primary PDUs from disabled or unknown sets; do not stop
           watching Coded solely because the disabled first set used that PHY.
        10. Disable extended advertising for the remaining set(s), maintaining
            synchronization with every periodic train.
        11. For every configured train, receive at least 100 AUX_SYNC_IND PDUs
            on its assigned secondary PHY with correct timing and CSA #2 channels.
        12. Disable periodic advertising on all configured sets.

    Test Case Configuration:
        Table 4.2-28 rows 1/2/3 use two sets on 1M/1M, 2M/2M, or Coded/Coded
        secondary PHYs respectively; uncoded primary PHYs are 1M. Rows 10/11/12
        use three secondary PHYs ordered (1M,2M,Coded), (2M,Coded,1M), and
        (Coded,1M,2M), with matching Coded primary or otherwise 1M primary.
        The IXIT selects these six rows. Clear advertising sets after Step 12
        as the postamble before the next row.

    Expected Outcome:
        Pass verdict: every configured set sends ADV_EXT_IND with AuxPtr to an
        AUX_ADV_IND containing valid SyncInfo on its assigned secondary PHY.
        Periodic PDUs use correct timing, PHY, AdvMode and independently calculated
        CSA #2 channel indices. All trains continue through both associated-disable
        phases, including at least 100 periodic PDUs per train in Step 11.
        Configured intervals and per-train Access Address/CRCInit remain consistent.
        Inconclusive verdict: Memory Capacity Exceeded while setting extended or
        periodic advertising parameters skips the test rather than passing it.
        Any other unexpected HCI status or RF mismatch fails.

    Source Correction:
        Step 11 says "both sets", but Table 4.2-28 rows 10-12 configure three.
        Apply the observation to all configured sets, consistent with the earlier
        per-set steps and pass verdict. Amber supports this interpretation of the
        supplied source; no officially adopted SIG erratum is claimed.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-33-C;
        PDF pages 174-178, printed pages 4.2-81 through 4.2-85,
        Table 4.2-28, both optional PHYs and maximum sets >=3 column.
    """
    result = await tester.command(
        hci.HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command()
    )
    assert result.num_supported_advertising_sets >= 3
    for number, phys in MULTI_PERIODIC_ROUNDS:
        tester.output.write(f'PERIODIC ROUND {number}\n')
        handles = list(range(len(phys)))
        for handle, phy in enumerate(phys):
            primary = Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M
            await _require_periodic_capacity(
                tester,
                extended_parameters(
                    advertising_handle=handle,
                    advertising_sid=handle,
                    primary_advertising_interval_min=80,
                    primary_advertising_interval_max=80,
                    primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
                    primary_advertising_phy=primary,
                    secondary_advertising_phy=phy,
                ),
            )
        for handle in handles:
            interval = (12, 16, 18)[handle]
            await _require_periodic_capacity(
                tester,
                hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(
                    handle, interval, interval, 0
                ),
            )
        for handle in handles:
            await tester.command(
                hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, handle)
            )
        await tester.command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
                1, handles, [0] * len(handles), [0] * len(handles)
            )
        )
        trains = {}
        await _set_phase(tester, phys, trains, handles)
        await tester.command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(0, [0], [0], [0])
        )
        await _set_phase(tester, phys, trains, handles[1:])
        await tester.command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
                0, handles[1:], [0] * (len(handles) - 1), [0] * (len(handles) - 1)
            )
        )
        await _set_phase(tester, phys, trains, [])
        for handle in handles:
            await tester.command(
                hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(0, handle)
            )
        await tester.command(hci.HCI_LE_Clear_Advertising_Sets_Command())


async def maximum_sets(tester):
    """Extended Advertising, Multiple Sets, Maximum Supported Sets.

    Initial Condition:
        Advertising parameters select supported intervals, event properties,
        own-address type and channel map. TSPX_adv_sets_max is supplied during
        preparation by Read Number of Supported Advertising Sets (eight for this
        DUT). Select public non-connectable/non-scannable undirected advertising,
        all primary channels, LE 1M on both PHYs and 100-ms intervals. Choose each
        SID in 0..15; uniqueness is not a source requirement. Independently seeded
        31-octet datasets distinguish sets that share a SID.

    Test Steps:
        1. Configure TSPX_adv_sets_max handles with all primary channels, a supported
           selected interval, properties zero, both PHYs 1M and a seeded random
           SID in 0..15 for each set. Complete all parameter commands first.
        2. Submit 31 seeded advertising-data octets, each 1..254, for every set.
        3. Enable each set using its own extended advertising enable command
           with Duration 0.
        4. Receive interlaced ADV_EXT_IND events with AuxPtr for every set.
        5. Follow AuxPtr to LE 1M AUX_ADV_IND; if all submitted data is not yet
           present, require a further AuxPtr. Check its encoded channel/time,
           minimum T_MAFS spacing and matching ADI.
        6. Follow every further pointer to AUX_CHAIN_IND containing additional
           data until no pointer remains and all data for the set is received.
           Every secondary PDU retains the configured PHY and chain ADI.
        7. Repeat Steps 4-6 ten times per configured set. Identify each complete
           observation by SID plus exact concatenated payload, not SID alone.
        8. Disable each set using its own extended advertising enable command.

    Expected Outcome:
        Pass verdict: the declared number of sets produce interlaced ADV_EXT_IND
        with AuxPtr to valid LE 1M AUX_ADV_IND. Each pointer meets T_MAFS and
        its encoded channel/time. Each set's complete data equals its submitted
        31 octets, without additional bytes, including any chain fragments.
        All sets are independently observed ten times, with correct public AdvA,
        AdvMode and matching ADI, even when some sets share a SID.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-35-C; PDF pages 180-182, printed pages
        4.2-87 through 4.2-89, Figure 4.2-34.
    """
    result = await tester.command(
        hci.HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command()
    )
    count = result.num_supported_advertising_sets
    assert count > 0
    generator = random.Random(0)
    datasets = {
        handle: (
            generator.randrange(PDU_ADV_ADI_SID_MAX + 1),
            bytes(generator.randint(1, 254) for _ in range(31)),
        )
        for handle in range(count)
    }
    for handle, (sid, _) in datasets.items():
        await tester.command(
            extended_parameters(
                advertising_handle=handle,
                advertising_sid=sid,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
            )
        )
    for handle, (_, data) in datasets.items():
        await set_extended_data(tester, data, handle=handle)
    for handle in range(count):
        await tester.command(extended_enable(1, handle))
    received = dict.fromkeys(datasets, 0)
    for _ in range(20 * count):
        primary = await tester.expect_pdu(kind=AdvertisingPduType.ADV_EXT_IND)
        first = _nonconnectable_extended_packet(primary, Phy.LE_1M)
        assert 'aux' in first and 'adi' in first
        _, packet, fields = await follow_auxiliary(tester, primary, first)
        assert _nonconnectable_extended_packet(packet, Phy.LE_1M) == fields
        assert fields['adi'] == first['adi']
        _advertising_set_addresses(((primary, first), (packet, fields)), False)
        sid = int.from_bytes(fields['adi'], 'little') >> PDU_ADV_ADI_DID_BITS
        data = await chain(tester, packet, fields, expected_phy=Phy.LE_1M)
        matches = [
            handle for handle, expected in datasets.items() if expected == (sid, data)
        ]
        assert len(matches) == 1, 'Unknown or ambiguous advertising-set data'
        received[matches[0]] += 1
        if min(received.values()) >= 10:
            break
    assert min(received.values()) >= 10
    for handle in range(count):
        await tester.command(extended_enable(0, handle))


async def stable_sync_info(tester):
    """Periodic Advertising validating SyncInfo fields.

    Initial Condition:
        Advertising parameters select a supported own-address type and channel
        map. This implementation uses public AdvA, all primary channels, LE 1M
        on both PHYs and the minimum periodic interval.

    Test Steps:
        1. Set extended advertising parameters: properties zero, public
           Own_Address_Type, all primary channels, and LE 1M on both PHYs.
        2. Set periodic advertising parameters using the minimum interval and
           properties zero.
        3. Set one periodic data octet with value 0x00.
        4. Enable periodic advertising with Enable 1.
        5. Enable extended advertising with Duration 0.
        6. Receive ADV_EXT_IND with AdvMode 00 and AuxPtr.
        7. Follow the pointer to AUX_ADV_IND with AdvMode 00 and SyncInfo.
           Independently decode its Access Address and CRCInit and compare them
           with the first observation. AUX_SYNC_IND transmission may occur in
           the background; this procedure checks the SyncInfo announcements.
        8. Repeat Steps 6-7 ten times.

    Postamble:
        Disable extended and periodic advertising after the observations.

    Expected Outcome:
        Pass verdict: all observed AUX_ADV_IND SyncInfo fields describing this
        periodic train contain identical Access Address and CRCInit. Every
        observation has the required primary/auxiliary types, modes and PHYs,
        a valid AuxPtr timing/channel and at least T_MAFS spacing.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-43-C; PDF pages 194-195, printed pages
        4.2-101 through 4.2-102, Figure 4.2-41.
    """
    await tester.command(
        extended_parameters(
            primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL
        )
    )
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(
            0, LL_PERIODIC_INTERVAL_MIN, LL_PERIODIC_INTERVAL_MIN, 0
        )
    )
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
            0, Operation.COMPLETE_DATA, b'\x00'
        )
    )
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0))
    await tester.command(extended_enable())
    reference = None
    for _ in range(10):
        primary = await tester.expect_pdu(kind=AdvertisingPduType.ADV_EXT_IND)
        first = _nonconnectable_extended_packet(primary, Phy.LE_1M)
        assert 'aux' in first
        _, packet, fields = await follow_auxiliary(tester, primary, first)
        assert _nonconnectable_extended_packet(packet, Phy.LE_1M) == fields
        assert fields['adi'] == first['adi'] and 'sync' in fields
        train = PeriodicTrain.from_advertisement(packet, fields)
        pair = (train.access_address, train.crc_init)
        if reference is None:
            reference = pair
        assert pair == reference
    await tester.command(extended_enable(0))
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(0, 0))


async def invalid_legacy_size(tester, *, scannable=False):
    """Disallow Extended Advertising.

    Initial Condition:
        Advertising parameters select supported intervals, event properties,
        own-address type and primary channels. Table 4.2-34 selects legacy
        non-connectable (BI-05) or legacy scannable (BI-06) PDUs through extended
        HCI commands. This implementation uses a public advertising set.

    Test Steps:
        1. Send LE Set Extended Advertising Parameters with the Table 4.2-34
           properties: Use Legacy PDUs or Use Scannable Legacy PDUs.
        2. Send LE Set Extended Advertising Data with length 31; require Command
           Complete with status 0x00.
        3. Enable the same set with LE Set Extended Advertising Enable; require
           Command Complete with status 0x00.
        4. Send LE Set Extended Advertising Data with length 32; require Command
           Complete with status 0x12.

    Postamble:
        Disable the advertising set after the rejected command.

    Expected Outcome:
        Pass verdict: Step 4 returns Invalid HCI Command Parameters (0x12) in
        Command Complete for LE Set Extended Advertising Data. The preceding
        31-octet submission and enable succeed. Responses match their command
        opcodes and preserve valid command credit.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.13, LL/DDI/ADV/BI-05-C and LL/DDI/ADV/BI-06-C; PDF
        pages 195-196, printed pages 4.2-102 through 4.2-103, Table 4.2-34.
    """
    properties = Properties.USE_LEGACY_ADVERTISING_PDUS
    if scannable:
        properties |= Properties.SCANNABLE_ADVERTISING
    await tester.command(
        extended_parameters(
            advertising_event_properties=properties,
            primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
        )
    )
    await set_extended_data(tester, bytes(PDU_ADV_LEGACY_DATA_SIZE_MAX))
    await tester.command(extended_enable())
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Data_Command(
            0, Operation.COMPLETE_DATA, 0, bytes(PDU_ADV_LEGACY_DATA_SIZE_MAX + 1)
        ),
        ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
    )
    await tester.command(extended_enable(0))


async def invalid_hop_increment(tester):
    """Connection Request Invalid Hop Increment.

    Initial Condition:
        Prepare undirected advertising with supported selected intervals, address
        type, channel and device-name/data length. Select a public AdvA, minimum
        supported interval, channel 37 and empty advertising data. No device name
        is transmitted; Section 4.1.6 requires the name IUT when one is sent.
        Allow requests from all devices. Use otherwise valid Common PDU Contents
        from Section 4.3.2 and ChSel 0 so the invalid hop is not bypassed by CSA #2.
        This DUT rejects invalid hop increments in connection-parameter decoding,
        so the executable path is the source's ignore alternative.

    Test Steps:
        1. Set legacy advertising parameters: ADV_IND (type 0), channel map 001,
           filter policy 0; require successful Command Complete.
        2. Repeat Steps 3-23 for hopIncrement 0..4 and 17..31.
        3. Prepare CONNECT_IND with that hop and otherwise valid common fields.
        4. Enable undirected advertising using the Step 1 channel map.
        5. Receive ADV_IND and send the prepared CONNECT_IND on the selected
           channel at T_IFS after the advertisement's end.
        6. The IUT either ignores the request or establishes the connection.
        7. For an ignored request, execute Steps 9-14 and omit Steps 15-23.
        8. For an accepted request, omit Steps 9-14 and execute Steps 15-23.
        9. Observe that advertising continues.
        10. Receive ADV_IND and send another CONNECT_IND with the same invalid
            hop on the selected channel at T_IFS.
        11. Send six data packets at the connection anchors/interval encoded in
            Step 10, hopping by that requested increment on the full channel map.
        12. Require no IUT response to any of those six data packets.
        13. Repeat Steps 9-12 five times.
        14. Disable advertising and receive successful Command Complete.
        Accepted-connection alternative (not taken by this DUT):
        15. Receive HCI LE Connection Complete.
        16. Execute Step 17 in parallel with Steps 18-20.
        17. After one advertising interval, require no further ADV_IND and observe
            for four advertising intervals to confirm advertising has stopped.
        18. Send data at each connection event on the channel obtained by adding
            the requested hop increment to the preceding unmapped channel.
        19. Require an acknowledgement for each data packet.
        20. Repeat Steps 18-19 for ten connection events.
        21. Send HCI Disconnect and receive successful Command Status.
        22. Receive LL_TERMINATE_IND.
        23. Receive HCI Disconnection Complete.

    Expected Outcome:
        Pass verdict: use a supported interval and the explicitly configured
        channel. For the ignore alternative, advertising continues and no data
        probe receives a response. For the accept alternative, the IUT reports
        connection completion, stops advertising and acknowledges the requested
        connection events. These are alternative outcomes, not cumulative duties.
        This DUT must satisfy the ignore outcome for all twenty hop values,
        with five six-packet probe groups per value and no connection-complete
        notification. Every observed advertisement has the configured public
        address, LE 1M PHY and empty data.

    Source Correction:
        References to Step 24 mean the actual procedure tail through Step 23;
        no Step 24 exists. Step 4 and the generic all-channel pass wording must
        retain Step 1's explicit map 001: Advertising Enable cannot change that
        map. Step 23 names a Disconnection Complete command, but it is an event.
        Amber supports the channel/numbering corrections and the alternative
        behavior reading from the supplied source. These are local corrections,
        not officially adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BI-07-C; PDF pages 207-210, printed pages
        4.2-114 through 4.2-117, Steps 1-23 and Figures 4.2-48/49.
        Section 4.1.6 defines common initial conditions; Section 4.3.2 defines
        otherwise valid connection-request contents.
    """
    await tester.command(legacy_parameters())
    for hop in (
        *range(LL_HOP_INCREMENT_MIN),
        *range(LL_HOP_INCREMENT_MAX + 1, PDU_ADV_CONNECT_HOP_MASK + 1),
    ):
        parameters = LinkParameters(
            access_address=LOWER_DATA_ACCESS_ADDRESS, hop_sca=hop
        )
        request = request_pdu(
            AdvertisingPduType.CONNECT_IND,
            scanner=LOWER_CENTRAL_PUBLIC_ADDRESS,
            data=parameters.encode(),
        )
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
        advertisement = await tester.expect_pdu(kind=AdvertisingPduType.ADV_IND)
        _check_advertisement(advertisement, b'')
        await tester.transmit(37, request, start_us=advertisement.end_us + LL_IFS_US)
        for _ in range(5):
            advertisement = await tester.expect_pdu(kind=AdvertisingPduType.ADV_IND)
            _check_advertisement(advertisement, b'')
            end = await tester.transmit(
                37, request, start_us=advertisement.end_us + LL_IFS_US
            )
            anchor = end + (1 + parameters.window_offset) * LL_CONN_INTERVAL_UNIT_US
            for counter in range(LL_CONN_ESTABLISHMENT_EVENTS):
                channel = (counter + 1) * hop % LL_DATA_CHANNEL_COUNT
                await tester.transmit(
                    channel,
                    bytes([LlId.CONTINUATION, 0]),
                    start_us=anchor
                    + counter * parameters.interval * LL_CONN_INTERVAL_UNIT_US,
                    access_address=parameters.access_address,
                    crc_init=parameters.crc_init,
                )
                assert (
                    await tester.receive(
                        channel,
                        duration_us=1000,
                        access_address=parameters.access_address,
                        crc_init=parameters.crc_init,
                    )
                    is None
                )
        advertisement = await tester.expect_pdu(kind=AdvertisingPduType.ADV_IND)
        _check_advertisement(advertisement, b'')
        assert not any(
            isinstance(
                event,
                (
                    hci.HCI_LE_Connection_Complete_Event,
                    hci.HCI_LE_Enhanced_Connection_Complete_Event,
                ),
            )
            for event in tester.events
        )
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


def _check_high_duty_timeout_events(events, handle):
    connections = [
        event
        for event in events
        if isinstance(
            event,
            (
                hci.HCI_LE_Connection_Complete_Event,
                hci.HCI_LE_Enhanced_Connection_Complete_Event,
            ),
        )
    ]
    terminated = [
        event
        for event in events
        if isinstance(event, hci.HCI_LE_Advertising_Set_Terminated_Event)
    ]
    assert connections or terminated, 'missing advertising timeout outcome'
    assert len(connections) <= 1, 'duplicate connection timeout outcomes'
    assert len(terminated) <= 1, 'duplicate advertising termination outcomes'
    for event in connections + terminated:
        assert event.status == ErrorCode.ADVERTISING_TIMEOUT_ERROR
    for event in terminated:
        assert event.advertising_handle == handle


async def high_duty_without_connection(tester):
    """High Duty Cycle Connectable Directed Advertising, No Connection.

    Initial Condition:
        Advertising parameters use a supported interval, event type, own address
        and channel map. TSPX_supported_advertising_channels declares used/unused
        channels. Select public own/peer addresses, the minimum interval and all
        three supported primary channels. The Lower Tester only receives packets.

    Test Steps:
        1. Configure the Lower Tester for passive scanning; send no scan or
           connection request during the procedure.
        2. Send LE Set Extended Advertising Parameters with properties 0x001D,
           all supported channels, a supported interval and Peer_Address equal
           to the Lower Tester. Require successful Command Complete.
        3. Send LE Set Extended Advertising Enable with Enable 1, Num_Sets 1,
           the Step 2 handle and Duration 0x000C. Require successful Command
           Complete. Preserve this literal; its correct duration is 120 ms.
        4. Receive ADV_DIRECT_IND from the IUT. Check the configured public
           AdvA/TargetA and LE 1M PHY on each supported primary channel.
        5. Do not attempt a connection for five seconds.
        6. Evaluate one of the following IUT-response alternatives:
           6A.1. Receive one LE Connection Complete or Enhanced Connection
                 Complete with Advertising Timeout (0x3C).
           6B.1. Receive one LE Advertising Set Terminated.
           6C.1. Execute 6C.2 and 6C.3 in either order.
           6C.2. Receive one LE Connection Complete or Enhanced Connection
                 Complete with Advertising Timeout (0x3C).
           6C.3. Receive one LE Advertising Set Terminated.

    Expected Outcome:
        Pass verdict: after Step 5, no connection completes and one of 6A, 6B or
        6C occurs. Legacy and enhanced connection-complete events are alternatives,
        not two required notifications. Reject duplicate outcomes. When duration
        expiry produces Advertising Set Terminated, additionally require status
        0x3C and the configured handle, as specified by Core 7.7.65.18; the test
        source's 6B.1/6C.3 does not itself spell out that status.

    Postamble:
        Confirm that advertising has stopped on all three primary channels, then
        disable the advertising set successfully.

    Source Correction:
        Step 3's parenthetical 1.2 seconds is inconsistent with Duration 0x000C.
        Core Vol 4, Part E, 7.8.56 defines 10-ms units, so retain the literal and
        interpret it as 120 ms. Amber confirms this arithmetic correction; do not
        invent a different literal to infer the author's intended duration. This
        is a local correction, not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-80-C; PDF pages 232-234, printed pages
        4.2-139 through 4.2-141, Figure 4.2-60, all Steps 1-6 and alternatives
        6A.1/6B.1/6C.1-6C.3. This is a standalone case, not Section 4.2.3.17.
        Core Specification 6.3, Vol 4, Part E, 7.8.56 and 7.7.65.18 define the
        duration units and timeout-event behavior.
    """
    await tester.command(
        extended_parameters(
            advertising_event_properties=Properties.USE_LEGACY_ADVERTISING_PDUS
            | Properties.CONNECTABLE_ADVERTISING
            | Properties.DIRECTED_ADVERTISING
            | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING,
            primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
            peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
            peer_address_type=hci.AddressType.PUBLIC_DEVICE,
        )
    )
    before_enable = tester.radio.now_us
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Enable_Command(1, [0], [0x000C], [0])
    )
    for channel in LL_ADV_PRIMARY_CHANNELS:
        packet = await tester.expect_pdu(
            channel, kind=AdvertisingPduType.ADV_DIRECT_IND
        )
        assert packet.phy == Phy.LE_1M
        assert packet.pdu[PDU_HEADER_SIZE:] == bytes(DUT_ADDRESS) + bytes(
            LOWER_CENTRAL_PUBLIC_ADDRESS
        )
        assert not packet.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
    await tester.wait(
        before_enable + 5 * PHY_TIME_UNITS_PER_SECOND - tester.radio.now_us
    )
    _check_high_duty_timeout_events(tester.events, 0)
    for channel in LL_ADV_PRIMARY_CHANNELS:
        assert await tester.receive(channel) is None
    await tester.command(extended_enable(0))


async def _observe_selected_advertising_channel(tester, channel, enabled):
    # Observe fifty worst-case event intervals, not merely fifty received packets.
    _, maximum_interval = advertising_interval_limits(ADVERTISING_INTERVAL_US)
    deadline = tester.radio.now_us + 50 * maximum_interval
    count = 0
    while tester.radio.now_us < deadline:
        packet = await tester.receive(
            channel, duration_us=deadline - tester.radio.now_us
        )
        if packet is None:
            break
        assert packet.valid_crc
        assert packet.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_IND
        assert packet.pdu[1] == len(packet.pdu) - PDU_HEADER_SIZE
        _check_advertisement(packet, b'')
        count += 1
    assert count >= 45 if enabled else count == 0


async def selected_channels(tester):
    """Advertising on Selected Channels.

    Initial Condition:
        Undirected advertising uses a supported interval, own-address type,
        advertising channels and common device-name/data length. Select public
        ADV_IND at the minimum supported interval and no name/data. Repeat the
        complete procedure for the seven Table 4.2-48 maps 0x01 through 0x07.

    Test Steps:
        1. Send LE Set Advertising Parameters with Advertising_Type 0x00 and
           the current round's channel map; require successful Command Complete.
        2. Send LE Set Advertising Data with Advertising_Data_Length zero;
           require successful Command Complete.
        3. Send LE Set Advertising Enable with Enable 1; require successful
           Command Complete.
        4. The IUT sends ADV_IND on selected channels until Step 5 finishes.
        5. Monitor each of channels 37, 38 and 39 in turn, in any order, for at
           least fifty advertising events per channel. Observe for fifty maximum
           event intervals, including AdvDelay and common drift/jitter allowance.
           Check received PDUs' type, CRC, length, public AdvA, data and LE 1M PHY.
        6. Send LE Set Advertising Enable with Enable 0; require successful
           Command Complete before beginning the next channel-map round.

    Expected Outcome:
        Pass verdict: in Step 5, receive at least 45 ADV_IND PDUs on each selected
        channel, and no ADV_IND on each unselected channel. The fifty-event
        observation requirement is not a fifty-received-packet pass threshold.

    Reference:
        LL.TS.p28.pdf, Section 4.2, LL/DDI/ADV/BV-106-C; PDF pages 264-266, printed
        pages 4.2-171 through 4.2-173, Table 4.2-48, Figure 4.2-75, Steps 1-6
        and the per-channel pass verdict. This is a standalone case, not
        Section 4.2.3.19. Section 4.1.6 defines common selected initial conditions.
    """
    for channel_map in range(1, LL_ADV_PRIMARY_CHANNEL_MAP_ALL + 1):
        await tester.command(legacy_parameters(advertising_channel_map=channel_map))
        await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(b''))
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
        for bit, channel in enumerate(LL_ADV_PRIMARY_CHANNELS):
            await _observe_selected_advertising_channel(
                tester, channel, bool(channel_map & 1 << bit)
            )
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))


LOWER_ADDRESS_LSB_XOR = 90
LOWER_ADDRESS_MSB_XOR = 165
# LL.TS.p28 Section 4.1.5.2 defines the public scanner and address perturbations.
LOWER_TESTER_PUBLIC_ADDRESS = hci.Address(
    '12:34:56:78:9A:BC', hci.AddressType.PUBLIC_DEVICE
)
SCAN_RESPONSE_DATA = b'\x03\tLT'


def _check_scan_reports(tester, peer, kind, sent, accepted):
    report_type = hci.HCI_LE_Advertising_Report_Event.EventType
    expected = {
        AdvertisingPduType.ADV_IND: report_type.ADV_IND,
        AdvertisingPduType.ADV_NONCONN_IND: report_type.ADV_NONCONN_IND,
        AdvertisingPduType.ADV_SCAN_IND: report_type.ADV_SCAN_IND,
        AdvertisingPduType.ADV_DIRECT_IND: report_type.ADV_DIRECT_IND,
    }[kind]
    advertisements = responses = 0
    for event in list(tester.events):
        if not isinstance(event, hci.HCI_LE_Advertising_Report_Event):
            continue
        for report in event.reports:
            assert accepted, 'filtered advertiser was reported'
            assert report.address == peer and report.address_type == peer.address_type
            if report.event_type == report_type.SCAN_RSP:
                assert report.data == SCAN_RESPONSE_DATA
                responses += 1
            else:
                assert report.event_type == expected
                assert (
                    report.data == b''
                    if kind == AdvertisingPduType.ADV_DIRECT_IND
                    else report.data in sent
                )
                advertisements += 1
        tester.events.remove(event)
    return (advertisements, responses)


def _advertising_public_peer_addresses():
    """Common public peer followed by the MSB, LSB and both-byte variants of AdvA."""
    variants = [LOWER_TESTER_PUBLIC_ADDRESS]
    for msb, lsb in (
        (LOWER_ADDRESS_MSB_XOR, 0),
        (0, LOWER_ADDRESS_LSB_XOR),
        (LOWER_ADDRESS_LSB_XOR, LOWER_ADDRESS_MSB_XOR),
    ):
        address = bytearray(bytes(DUT_ADDRESS))
        address[-1] ^= msb
        address[0] ^= lsb
        variants.append(hci.Address(bytes(address), hci.AddressType.PUBLIC_DEVICE))
    return tuple(variants)


async def _scan_phase(
    tester, channel, peer, kind, *, active, accepted, intervals=20, full_duration=False
):
    deadline = tester.radio.now_us + intervals * SCAN_INTERVAL_US
    start = tester.radio.now_us + 100
    seen_adv = seen_response = requests = 0
    sent = set()
    generator = random.Random(0)
    delays = []
    for _ in range(3 * intervals // 2):
        value = generator.randrange(LL_ADV_DELAY_MAX_US + 1)
        delays.extend((value, LL_ADV_DELAY_MAX_US - value))
    generator.shuffle(delays)
    scannable = kind in (AdvertisingPduType.ADV_IND, AdvertisingPduType.ADV_SCAN_IND)
    for sequence, delay in enumerate(delays):
        data = sequence.to_bytes(2, 'little')
        sent.add(data)
        pdu = (
            request_pdu(kind, advertiser=DUT_ADDRESS, scanner=peer)
            if kind == AdvertisingPduType.ADV_DIRECT_IND
            else adv_pdu(kind, address=peer, data=data)
        )
        end = await tester.transmit(channel, pdu, start_us=start)
        request = await tester.receive(channel, duration_us=1000)
        if request is not None:
            assert active and scannable and accepted, 'unexpected scan request'
            assert request.valid_crc and request.phy == Phy.LE_1M
            assert len(request.pdu) == PDU_ADV_SCAN_REQ_SIZE
            assert request.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.SCAN_REQ
            assert request.pdu[
                PDU_ADV_ADDRESS_OFFSET:PDU_ADV_SECOND_ADDRESS_OFFSET
            ] == bytes(DUT_ADDRESS)
            assert request.pdu[PDU_ADV_SECOND_ADDRESS_OFFSET:] == bytes(peer)
            assert not request.pdu[0] & PDU_ADV_TXADD_MASK
            assert bool(request.pdu[0] & PDU_ADV_RXADD_MASK) == peer.is_random
            assert (
                abs(request.start_us - end - LL_IFS_US)
                <= SCAN_RESPONSE_IFS_TOLERANCE_US
            )
            await tester.transmit(
                channel,
                adv_pdu(
                    AdvertisingPduType.SCAN_RSP, address=peer, data=SCAN_RESPONSE_DATA
                ),
                start_us=request.end_us + LL_IFS_US,
            )
            requests += 1
        await tester.wait(1000)
        adv_count, response_count = _check_scan_reports(
            tester, peer, kind, sent, accepted
        )
        seen_adv += adv_count
        seen_response += response_count
        if (
            not full_duration
            and accepted
            and seen_adv
            and (not active or not scannable or (requests and seen_response))
        ):
            break
        start += SCAN_ADV_INTERVAL_US + delay
    else:
        await tester.wait(max(0, deadline - tester.radio.now_us))
        adv_count, response_count = _check_scan_reports(
            tester, peer, kind, sent, accepted
        )
        seen_adv += adv_count
        seen_response += response_count
    assert seen_adv > 0 if accepted else seen_adv == 0
    if accepted and active and scannable:
        assert requests and seen_response
    else:
        assert not requests and (not seen_response)


async def _scan_reports(
    tester, *, kind=AdvertisingPduType.ADV_NONCONN_IND, active=False, filtered=False
):
    """Exercise the selected scan/address/filter phases for the prescribed interval
    duration."""
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    common = _advertising_public_peer_addresses()[0]
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(common.address_type, common)
    )
    interval = SCAN_INTERVAL_US // hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    previous_channel = None
    for channel, peer in _scan_variants(kind, active, filtered):
        if channel != previous_channel or not filtered:
            if previous_channel is not None:
                await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))
            await tester.command(
                scan_parameters(
                    le_scan_type=int(active),
                    scanning_filter_policy=int(filtered),
                    le_scan_interval=interval,
                    le_scan_window=interval,
                )
            )
            await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))
            previous_channel = channel
        accepted = not filtered or peer == common
        await _scan_phase(
            tester,
            channel,
            peer,
            kind,
            active=active,
            accepted=accepted,
            full_duration=not active
            and (not filtered or kind == AdvertisingPduType.ADV_DIRECT_IND),
        )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))
    _check_scan_reports(tester, peer, kind, set(), accepted)


def _scan_variants(kind, active, filtered):
    common, msb, lsb, both = _advertising_public_peer_addresses()
    if kind == AdvertisingPduType.ADV_DIRECT_IND:
        return (
            (37, common),
            (38, lsb),
            (39, hci.Address(bytes(common), hci.AddressType.RANDOM_DEVICE)),
        )
    if filtered:
        peers = (
            (common, lsb, both)
            if active
            else (
                common,
                hci.Address(bytes(common), hci.AddressType.RANDOM_DEVICE),
                lsb,
                hci.Address(bytes(both), hci.AddressType.RANDOM_DEVICE),
            )
        )
        channels = LL_ADV_PRIMARY_CHANNELS if active else (37,)
        return tuple((channel, peer) for channel in channels for peer in peers)
    if active:
        return tuple(
            (channel, peer)
            for channel in LL_ADV_PRIMARY_CHANNELS
            for peer in (common, msb, lsb, both)
        )
    return (
        (37, common),
        (38, lsb),
        (39, hci.Address(bytes(msb), hci.AddressType.RANDOM_DEVICE)),
    )


ReportType = hci.HCI_LE_Advertising_Report_Event.EventType


async def _invalid_scanning_crc(tester, *, active=False):
    """Reject bad advertising CRCs and, when scanning actively, scan-response CRCs."""
    if not active:
        await _start_scanning(tester, False)
    for channel in LL_ADV_PRIMARY_CHANNELS:
        if active:
            await _start_scanning(tester, True)
        requests, reports = await _corrupt_advertisements(
            tester, channel, active=active
        )
        assert not requests and (not reports)
        if active:
            peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
            data = b'valid advertising'
            deadline = tester.radio.now_us + 20 * SCAN_INTERVAL_US
            generator = random.Random(0)
            start = tester.radio.now_us + 100
            while tester.radio.now_us < deadline:
                end = await tester.transmit(
                    channel, adv_pdu(address=peer, data=data), start_us=start
                )
                request = await tester.receive(channel, duration_us=1000)
                if request is not None:
                    assert request.valid_crc
                    assert request.pdu == request_pdu(
                        AdvertisingPduType.SCAN_REQ,
                        advertiser=peer,
                        scanner=DUT_ADDRESS,
                    )
                    assert (
                        abs(request.start_us - end - LL_IFS_US)
                        <= SCAN_RESPONSE_IFS_TOLERANCE_US
                    )
                    await tester.transmit(
                        channel,
                        adv_pdu(
                            AdvertisingPduType.SCAN_RSP,
                            address=peer,
                            data=b'bad response',
                        ),
                        start_us=request.end_us + LL_IFS_US,
                        bad_crc=True,
                    )
                    await tester.wait(1000)
                    break
                start = (
                    start
                    + SCAN_ADV_INTERVAL_US
                    + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
                )
            else:
                raise AssertionError(
                    'no active scan request within twenty scan intervals'
                )
            reports = _encoding_take_reports(tester)
            assert reports and all(
                report.event_type == ReportType.ADV_IND
                and report.address == peer
                and report.address_type == hci.AddressType.PUBLIC_DEVICE
                and (report.data == data)
                for report in reports
            )
        if active:
            await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))
        assert not _encoding_take_reports(tester)
    if not active:
        await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))
        assert not _encoding_take_reports(tester)


# Core 6.3 Vol 6 Part B 4.4.2.4.3: maximum high-duty same-channel interval.
HIGH_DUTY_INTERVAL_MAX_US = 3750
# Section 4.2.3.15 Step 9: ten data generations, including the initial writes.
PRIMARY_DATA_ROUNDS = 10
# Core 4.4.2: consecutive primary advertising PDUs in an event are <=10 ms apart.
PRIMARY_EVENT_PDU_GAP_US = 10000
# Table 4.2-36: legacy properties, event kind, and enable duration (10 ms units).
PRIMARY_ROUNDS = {
    64: (Properties.USE_LEGACY_ADVERTISING_PDUS, AdvertisingPduType.ADV_NONCONN_IND, 0),
    65: (
        Properties.USE_LEGACY_ADVERTISING_PDUS
        | Properties.CONNECTABLE_ADVERTISING
        | Properties.SCANNABLE_ADVERTISING,
        AdvertisingPduType.ADV_IND,
        0,
    ),
    66: (
        Properties.USE_LEGACY_ADVERTISING_PDUS
        | Properties.CONNECTABLE_ADVERTISING
        | Properties.DIRECTED_ADVERTISING
        | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING,
        AdvertisingPduType.ADV_DIRECT_IND,
        0x007D,
    ),
    67: (
        Properties.USE_LEGACY_ADVERTISING_PDUS
        | Properties.CONNECTABLE_ADVERTISING
        | Properties.DIRECTED_ADVERTISING,
        AdvertisingPduType.ADV_DIRECT_IND,
        0,
    ),
    68: (
        Properties.USE_LEGACY_ADVERTISING_PDUS | Properties.SCANNABLE_ADVERTISING,
        AdvertisingPduType.ADV_SCAN_IND,
        0,
    ),
}


async def _primary_intervals(tester, legacy_kind, *, high_duty=False):
    """Measure consecutive same-channel starts, without following auxiliary PDUs."""
    for channel in (37, 38, 39):
        starts = [[], []]
        deadline = tester.radio.now_us + 300000
        while min(map(len, starts)) < 4 and tester.radio.now_us < deadline:
            packet = await tester.expect_pdu(channel, duration_us=70000)
            kind = packet.pdu[0] & PDU_ADV_TYPE_MASK
            assert kind in (AdvertisingPduType.ADV_EXT_IND, legacy_kind)
            handle = int(kind != AdvertisingPduType.ADV_EXT_IND)
            if len(starts[handle]) < 4:
                starts[handle].append(packet.start_us)
        assert min(map(len, starts)) == 4, (channel, starts)
        for handle, times in enumerate(starts):
            for first, second in pairwise(times):
                interval = second - first
                if high_duty and handle == 1:
                    assert 0 < interval <= HIGH_DUTY_INTERVAL_MAX_US, interval
                else:
                    base = (20000, 50000)[handle]
                    minimum, maximum = advertising_interval_limits(base)
                    assert minimum <= interval <= maximum, (channel, handle, interval)
                tester.output.write(
                    f'INTERVAL channel={channel} set={handle} us={interval}\n'
                )


async def _primary_set_events(tester, legacy_kind, payloads):
    """Check complete primary events; allow other events before an auxiliary PDU."""
    directed = legacy_kind == AdvertisingPduType.ADV_DIRECT_IND
    properties = (0, Properties.USE_LEGACY_ADVERTISING_PDUS)
    maximum_gap = (
        PRIMARY_EVENT_PDU_GAP_US
        + (
            PRIMARY_EVENT_PDU_GAP_US * LL_SCA_PPM[LL_SCA_500_PPM]
            + PHY_TIME_UNITS_PER_SECOND
            - 1
        )
        // PHY_TIME_UNITS_PER_SECOND
        + ADVERTISING_INTERVAL_JITTER_US
    )
    seen = set()
    for _ in range(100):
        primaries = []
        for channel in LL_ADV_PRIMARY_CHANNELS:
            packet = await tester.expect_pdu(channel, duration_us=200000)
            assert packet.phy == Phy.LE_1M
            kind = packet.pdu[0] & PDU_ADV_TYPE_MASK
            assert kind in (AdvertisingPduType.ADV_EXT_IND, legacy_kind)
            if primaries:
                assert (
                    primaries[-1].end_us
                    <= packet.start_us
                    <= (primaries[-1].start_us + maximum_gap)
                ), 'Primary packets do not belong to one advertising event'
                assert kind == primaries[0].pdu[0] & PDU_ADV_TYPE_MASK, (
                    'Primary PDU type changed within an advertising event',
                    channel,
                )
            primaries.append(packet)
        if kind == AdvertisingPduType.ADV_EXT_IND:
            parents = [decode_extended(packet.pdu) for packet in primaries]
            for packet, fields in zip(primaries, parents):
                assert (
                    _extended_advertising_set(
                        packet, fields, properties, (Phy.LE_1M, Phy.LE_1M), payloads
                    )
                    == 0
                )
            assert all(('aux' in fields) == ('aux' in parents[0]) for fields in parents)
            packet, fields = primaries[-1], parents[-1]
            auxiliary = None
            if 'aux' in fields:
                auxiliary_channel, packet, fields = await follow_auxiliary(
                    tester, packet, fields
                )
                assert packet.phy == Phy.LE_1M
                assert (
                    packet.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
                )
                assert (
                    packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS == 0
                )
                auxiliary = (packet, fields)
                for parent, parent_fields in zip(primaries, parents):
                    pointer = parent_fields['aux']
                    channel, offset = decode_aux(pointer)
                    unit = (
                        PDU_ADV_OFFSET_UNIT_300_US
                        if pointer[0] & PDU_ADV_AUX_OFFSET_UNITS_MASK
                        else PDU_ADV_OFFSET_UNIT_30_US
                    )
                    assert channel == auxiliary_channel and pointer[2] >> 5 == 0
                    assert (
                        parent.start_us + offset
                        <= packet.start_us
                        < (parent.start_us + offset + unit)
                    )
                    assert packet.start_us - parent.end_us >= LL_MAFS_US
                    assert fields['adi'] == parent_fields['adi']
            for parent, parent_fields in zip(primaries, parents):
                addresses = [(parent, parent_fields)]
                if auxiliary is not None:
                    addresses.append(auxiliary)
                _advertising_set_addresses(addresses, False)
            assert (
                await chain(tester, packet, fields, expected_phy=Phy.LE_1M)
                == payloads[0]
            )
            seen.add(0)
        else:
            for packet in primaries:
                assert not packet.pdu[0] & PDU_ADV_TXADD_MASK
                assert packet.pdu[
                    PDU_HEADER_SIZE : PDU_HEADER_SIZE + PDU_ADV_ADDRESS_SIZE
                ] == bytes(DUT_ADDRESS)
                assert packet.pdu[PDU_HEADER_SIZE + PDU_ADV_ADDRESS_SIZE :] == (
                    bytes(LOWER_CENTRAL_PUBLIC_ADDRESS) if directed else payloads[1]
                )
                if directed:
                    assert not packet.pdu[0] & PDU_ADV_RXADD_MASK
            seen.add(1)
        if len(seen) == 2:
            return
    raise AssertionError('Missing complete primary event for an advertising set')


# Section4.2.4.19: ten periodic observations before and after changing DID.
ADI_REPORTS_PER_PHASE = 10
# Selected100-ms base interval plus500-us advertising delay.
PERIODIC_ADVERTISING_INTERVAL_US = 100500
CHAIN_COUNT = 2
CHAIN_DATA_LENGTH = 249
# Maximum representable AuxPtr distance, as requested by Step8.
CHAIN_OFFSET_US = PDU_ADV_OFFSET_VALUE_MASK * PDU_ADV_OFFSET_UNIT_300_US
COMPATIBILITY_ADV_INTERVAL_US = 20500
COMPATIBILITY_AUX_CHANNEL = 0
COMPATIBILITY_AUX_OFFSET_US = 600
# Section4.2.4.19: one hundred seeded random AdvData octets per periodic PDU.
COMPATIBILITY_DATA_LENGTH = 100
# Selected100-ms periodic interval and20-ms base interval plus500-us AdvDelay.
COMPATIBILITY_INTERVAL = 80
# Selected public primary channel and secondary channel; AuxPtr spacing is600us.
COMPATIBILITY_PRIMARY_CHANNEL = 37
ExtendedReport = hci.HCI_LE_Extended_Advertising_Report_Event
# Section4.2.4.8: first min(100, Scan_Max_Data/3), then two min(249, remaining/2).
FIRST_DATA_LENGTH = 100
# Selected five-second periodic interval fits two maximum-separation AuxPtr links.
PERIODIC_PERIODIC_INTERVAL = 4000
# Selected signed-dBm power in AUX_SYNC_IND; chain PDUs omit TxPower.
PERIODIC_POWER_DBM = -20
PERIODIC_SKIP = 3
PeriodicReport = hci.HCI_LE_Periodic_Advertising_Report_Event
# LL/DDI/SCN/BV-89-C: at least five periodic reports despite nonzero RFU fields.
RFU_REQUIRED_REPORTS = 5
# Valid 16-us CTEInfo used only where the field is context-reserved.
RFU_CTE_INFO = 2
# Core Vol4 PartE7.7.65.14: valid periodic synchronization handles.
SYNC_HANDLE_MAX = 3839
SyncEstablished = hci.HCI_LE_Periodic_Advertising_Sync_Established_Event


def _check_periodic_reports(records, chunks, handle):
    """Allow buffered/incremental delivery, but never future data or unknown first
    power."""
    assert len(records) > 1, 'multiple periodic advertising reports required'
    expected = b''.join(chunks)
    offset = 0
    for index, (received, report) in enumerate(records):
        assert report.sync_handle == handle
        assert -127 <= report.rssi <= 20, 'RSSI unavailable or outside the HCI range'
        assert report.cte_type == hci.HCI_LE_PERIODIC_REPORT_CTE_NONE
        assert report.tx_power in (
            (PERIODIC_POWER_DBM,)
            if index == 0
            else (PERIODIC_POWER_DBM, ExtendedReport.TX_POWER_INFORMATION_NOT_AVAILABLE)
        ), 'first report lost AUX_SYNC_IND TxPower'
        end = offset + len(report.data)
        assert end <= sum(map(len, chunks[:received])), 'report contains future data'
        assert report.data == expected[offset:end], 'periodic data lost or reordered'
        assert report.data_status == (
            ExtendedReport.DATA_COMPLETE
            if index == len(records) - 1
            else ExtendedReport.DATA_INCOMPLETE_MORE_TO_COME
        )
        offset = end
    assert offset == len(expected), 'complete report omitted periodic data'


async def _periodic_header_compatibility(tester, *, rfu=False):
    """Ignore unsupported periodic ADI or nonzero RFU bits without losing data/sync."""
    if not rfu:
        features = await tester.command(
            hci.HCI_LE_Read_Local_Supported_Features_Command()
        )
        assert (
            not int.from_bytes(features.le_features, 'little')
            & hci.LeFeatureMask.PERIODIC_ADVERTISING_ADI_SUPPORT
        ), 'this source requires a scanner without Periodic Advertising ADI Support'
    generator = random.Random(0)
    data = generator.randbytes(COMPATIBILITY_DATA_LENGTH)
    did = generator.randrange(PDU_ADV_ADI_DID_MASK + 1)
    await tester.command(
        scan_parameters(
            extended=True,
            own_address_type=hci.AddressType.PUBLIC_DEVICE,
            scanning_filter_policy=0,
            scanning_phys=hci.PhyBit.LE_1M,
            scan_types=[0],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    train = PeriodicTrain(
        tester.radio.now_us + COMPATIBILITY_INTERVAL * LL_PERIODIC_INTERVAL_UNIT_US,
        interval=COMPATIBILITY_INTERVAL,
    )
    next_advertisement = tester.radio.now_us + REPORT_DELIVERY_US
    announcements_enabled = True

    def encode(role, **fields):
        return _rfu_periodic_pdu(role, **fields) if rfu else ext_pdu(**fields)

    primary = encode(
        'primary',
        adi=ADVERTISING_SID << PDU_ADV_ADI_DID_BITS,
        aux=aux_pointer(COMPATIBILITY_AUX_CHANNEL, COMPATIBILITY_AUX_OFFSET_US),
    )
    minimum_offset = Phy.LE_1M.airtime_us(len(primary)) + LL_MAFS_US
    unit = PDU_ADV_OFFSET_UNIT_30_US
    auxiliary_offset = max(
        COMPATIBILITY_AUX_OFFSET_US,
        (minimum_offset + unit - 1) // unit * unit,
    )

    async def announce_until(target):
        nonlocal next_advertisement
        while (
            announcements_enabled
            and next_advertisement + auxiliary_offset + REPORT_DELIVERY_US < target
        ):
            start = max(next_advertisement, tester.radio.now_us + REPORT_DELIVERY_US)
            auxiliary = start + auxiliary_offset
            await tester.transmit(
                COMPATIBILITY_PRIMARY_CHANNEL,
                encode(
                    'primary',
                    adi=ADVERTISING_SID << PDU_ADV_ADI_DID_BITS,
                    aux=aux_pointer(COMPATIBILITY_AUX_CHANNEL, auxiliary_offset),
                ),
                start_us=start,
            )
            await tester.transmit(
                COMPATIBILITY_AUX_CHANNEL,
                encode(
                    'auxiliary',
                    address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                    adi=ADVERTISING_SID << PDU_ADV_ADI_DID_BITS,
                    sync=train.sync_info(auxiliary),
                    data=b'announcement',
                ),
                start_us=auxiliary,
            )
            next_advertisement = start + COMPATIBILITY_ADV_INTERVAL_US

    async def periodic_pdu():
        await announce_until(train.anchor)
        await tester.transmit(
            train.channel,
            encode(
                'periodic',
                adi=ADVERTISING_SID << PDU_ADV_ADI_DID_BITS | did,
                data=data,
            ),
            start_us=train.anchor,
            **train.parameters,
        )
        train.next_event()

    await periodic_pdu()
    announcement = tester.take(lambda event: isinstance(event, ExtendedReport))
    assert announcement is not None, 'no extended announcement despite valid RF fields'
    report = announcement.reports[0]
    assert (
        report.event_type == (Report.EventType.DIRECTED_ADVERTISING if rfu else 0)
        and report.periodic_advertising_interval == train.interval
    )
    if rfu:
        assert report.direct_address == DUT_ADDRESS
        assert report.direct_address_type == hci.AddressType.PUBLIC_DEVICE
    assert report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
    assert report.address_type == hci.AddressType.PUBLIC_DEVICE
    assert report.advertising_sid == ADVERTISING_SID
    assert report.primary_phy == report.secondary_phy == Phy.LE_1M
    assert not any(isinstance(event, PeriodicReport) for event in tester.events)
    await tester.command(
        create_sync(
            options=0,
            advertiser_address=report.address,
            advertiser_address_type=report.address_type,
            advertising_sid=report.advertising_sid,
            skip=0,
            sync_timeout=3
            * train.interval
            * LL_PERIODIC_INTERVAL_UNIT_US
            // hci.HCI_LE_PERIODIC_SYNC_TIMEOUT_UNIT_US,
        )
    )
    established = None
    phases = (RFU_REQUIRED_REPORTS,) if rfu else (ADI_REPORTS_PER_PHASE,) * 2
    for phase, count in enumerate(phases):
        if phase:
            did = did + 1 & PDU_ADV_ADI_DID_MASK
        for _ in range(count):
            await periodic_pdu()
            if established is None:
                established = await tester.event(SyncEstablished)
                assert established.status == hci.HCI_ErrorCode.SUCCESS
                assert 0 <= established.sync_handle <= SYNC_HANDLE_MAX
                assert established.advertising_sid == ADVERTISING_SID
                assert established.advertiser_address == report.address
                assert established.advertiser_address_type == report.address_type
                assert established.advertiser_phy == Phy.LE_1M
                assert established.periodic_advertising_interval == train.interval
                assert established.advertiser_clock_accuracy == 0
            reports = []
            while event := tester.take(lambda event: isinstance(event, PeriodicReport)):
                reports.append(event)
            assert len(reports) == 1, 'each periodic PDU requires one complete report'
            assert reports[0].sync_handle == established.sync_handle
            assert reports[0].data == data
            assert reports[0].data_status == ExtendedReport.DATA_COMPLETE
            assert -127 <= reports[0].rssi <= 20
            assert not any(
                isinstance(
                    event,
                    (SyncEstablished, hci.HCI_LE_Periodic_Advertising_Sync_Lost_Event),
                )
                for event in tester.events
            ), 'synchronization was lost or established twice'
    announcements_enabled = False
    await tester.command(
        hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(established.sync_handle)
    )
    if rfu:
        await periodic_pdu()
        assert not any(
            isinstance(event, (SyncEstablished, SyncLost, PeriodicReport))
            for event in tester.events
        ), 'terminated synchronization still reported periodic traffic'
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


def _rfu_periodic_pdu(role, **fields):
    """Populate RFU fields for the selected primary, auxiliary, or periodic PDU."""
    ignored_sync = PeriodicTrain(30000).sync_info(0)
    if role == 'primary':
        # Table 2.4: SyncInfo, CTEInfo, ACAD, and AdvData are RFU. TargetA is valid.
        fields.update(
            target=DUT_ADDRESS,
            cte=RFU_CTE_INFO,
            sync=ignored_sync,
            acad=b'\x02\xffZ',
            data=b'ignored-primary-data',
        )
    elif role == 'auxiliary':
        # Table 2.5 C.2: the superior PDU already supplies the meaningful TargetA.
        fields.update(target=PEER_ADDRESS, cte=RFU_CTE_INFO)
    elif role == 'periodic':
        # Table 2.6: AdvA, TargetA, and SyncInfo are RFU in AUX_SYNC_IND.
        fields.update(address=PEER_ADDRESS, target=PEER_ADDRESS, sync=ignored_sync)
    else:
        raise ValueError(f'unknown periodic RFU PDU role: {role}')
    if fields.get('sync') is not None:
        sync = bytearray(fields['sync'])
        offset = int.from_bytes(sync[:2], 'little') | PDU_ADV_SYNC_OFFSET_RESERVED_MASK
        sync[:2] = offset.to_bytes(2, 'little')
        fields['sync'] = sync
    wire = bytearray(ext_pdu(**fields))
    wire[0] |= PDU_ADV_RESERVED_MASK | PDU_ADV_CHSEL_MASK
    if role != 'auxiliary':
        wire[0] |= PDU_ADV_TXADD_MASK
    if role != 'primary':
        wire[0] |= PDU_ADV_RXADD_MASK
    assert wire[2] != 0
    wire[PDU_ADV_EXT_HEADER_OFFSET] |= PDU_ADV_EXT_FLAGS_RESERVED_MASK
    return bytes(wire)


# Leave at least100ms for announcements/acquisition, independently of the interval.
ACQUISITION_LEAD_US = 100000
# Selected20-ms base interval plus500-us advertising delay.
PERIODIC_RECEPTION_ADVERTISING_INTERVAL_US = 20500
# Integer-us representation nearest below the source's200-ms AuxOffset.
ANNOUNCEMENT_OFFSET_US = 199980
AdvertisingReport = hci.HCI_LE_Extended_Advertising_Report_Event
# Expected Outcome: complete reports and bounded differences between counters.
COMPLETE_REPORT_PERCENT = 80
COUNTER_DIFFERENCE_PERCENT = 95
# Step5: the first two AdvData octets carry the event counter.
DATA_COUNTER_SIZE = 2
# Step 3 specifies 1 s; Step 10's 5 s is an approved local editorial correction.
PERIODIC_RECEPTION_PERIODIC_INTERVAL = 800
# Two chain offsets, their offset unit, and packet airtime fit the 1-s interval.
PERIODIC_WINDOW_CHAIN_OFFSET_US = 499500
# Selected40ms on1M makes3*interval a valid Host timeout and fits1650-octet
# chains plus announcements;200ms otherwise also fits the full S8 chain.
PERIODIC_INTERVAL_1M = 32
PERIODIC_INTERVAL_OTHER = 160
# A retry bound, not a substitute for either report-count or percentage verdict.
RECEPTION_ATTEMPT_FACTOR = 2
# Steps9/12: count serialized HCI events, not reassembled periodic data sets.
REQUIRED_REPORT_EVENTS = 5
SKIP_ROUND_REPORT_EVENTS = 30
SyncLost = hci.HCI_LE_Periodic_Advertising_Sync_Lost_Event


def _check_counters(counters, skip):
    """Compare modulo16-bit counters, with the source's rounded-down95% threshold."""
    differences = [
        after - before & LL_EVENT_COUNTER_MASK for before, after in pairwise(counters)
    ]
    assert all(differences), 'duplicate periodic event reported'
    good = sum(difference <= skip + 1 for difference in differences)
    assert good >= len(differences) * COUNTER_DIFFERENCE_PERCENT // 100


def _periodic_reception_check_reports(reports, data, boundaries, handle):
    """Validate one event's ordered HCI fragments and whole-PDU truncation."""
    joined = bytearray()
    for index, report in enumerate(reports):
        assert report.sync_handle == handle
        assert report.cte_type == hci.HCI_LE_PERIODIC_REPORT_CTE_NONE
        assert report.tx_power == AdvertisingReport.TX_POWER_INFORMATION_NOT_AVAILABLE
        assert -127 <= report.rssi <= 20
        joined.extend(report.data)
        if index < len(reports) - 1:
            assert report.data_status == AdvertisingReport.DATA_INCOMPLETE_MORE_TO_COME
        else:
            assert report.data_status in (
                AdvertisingReport.DATA_COMPLETE,
                AdvertisingReport.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME,
            )
    assert bytes(joined) == data[: len(joined)]
    complete = reports[-1].data_status == AdvertisingReport.DATA_COMPLETE
    if complete:
        assert bytes(joined) == data
    else:
        assert len(joined) in boundaries, 'truncation must precede a chain PDU'
    return complete


class _PeriodicReceptionResults:
    """Reassemble logical periodic data across HCI delivery batches and phases."""

    def __init__(self, length):
        self.length = length
        self.pending = []
        self.current_counter = None
        self.counters = []
        self.reported = set()
        self.complete_counters = set()
        self.complete = 0

    def collect(self, reports, transmitted, handle):
        for report in reports:
            assert report.sync_handle == handle
            assert report.cte_type == hci.HCI_LE_PERIODIC_REPORT_CTE_NONE
            assert (
                report.tx_power == AdvertisingReport.TX_POWER_INFORMATION_NOT_AVAILABLE
            )
            assert -127 <= report.rssi <= 20
            assert report.data_status in (
                AdvertisingReport.DATA_COMPLETE,
                AdvertisingReport.DATA_INCOMPLETE_MORE_TO_COME,
                AdvertisingReport.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME,
            )
            self.pending.append(report)
            joined = b''.join(fragment.data for fragment in self.pending)
            if self.length:
                if len(joined) >= DATA_COUNTER_SIZE and self.current_counter is None:
                    self.current_counter = int.from_bytes(
                        joined[:DATA_COUNTER_SIZE], 'little'
                    )
                    assert (
                        self.current_counter not in self.reported
                    ), 'duplicate periodic data'
                    self.reported.add(self.current_counter)
                    self.counters.append(self.current_counter)
                if self.current_counter is not None:
                    assert (
                        self.current_counter in transmitted
                    ), 'untransmitted periodic data'
                    frame = transmitted[self.current_counter]
                    assert joined == frame.data[: len(joined)]
            else:
                assert not joined
            if report.data_status == AdvertisingReport.DATA_INCOMPLETE_MORE_TO_COME:
                continue
            if self.length:
                assert (
                    self.current_counter is not None
                ), 'periodic counter is incomplete'
                frame = transmitted[self.current_counter]
                data, boundaries = frame.data, frame.boundaries
            else:
                data, boundaries = b'', ()
            complete = _periodic_reception_check_reports(
                self.pending, data, boundaries, handle
            )
            if complete:
                self.complete += 1
                if self.current_counter is not None:
                    self.complete_counters.add(self.current_counter)
            self.pending.clear()
            self.current_counter = None

    def check_rate(self, prepared):
        assert prepared, 'no prepared periodic receive opportunities'
        if self.length:
            assert (
                self.complete_counters <= prepared
            ), 'report without a receive attempt'
        assert self.complete <= len(
            prepared
        ), 'more complete reports than receive attempts'
        assert self.complete * 100 >= len(prepared) * COMPLETE_REPORT_PERCENT, (
            self.complete,
            len(prepared),
        )


def _periodic_reception_opportunities(capture, frames, interval_us, access_address):
    """Count actual PHY receive attempts, once per periodic event including chains."""
    assert frames
    boundaries = [frames[0].start_us - interval_us // 2]
    boundaries += [
        (before.end_us + after.start_us) // 2 for before, after in pairwise(frames)
    ]
    boundaries.append((frames[-1].end_us + frames[-1].start_us + interval_us) // 2)
    prepared = set()
    for request in csv.DictReader(capture):
        if int(request['phy_address'], 0) != access_address:
            continue
        index = bisect_right(boundaries, int(request['start_time'])) - 1
        if 0 <= index < len(frames):
            prepared.add(frames[index].counter)
    return prepared


def _pointer(offset):
    value = aux_pointer(0, offset)
    return bytes([value[0] & ~PDU_ADV_AUX_CA_MASK]) + value[1:]


def _widening(offset):
    return (
        RADIO_CLOCK_JITTER_US
        + (offset * 500 + PHY_TIME_UNITS_PER_SECOND - 1) // PHY_TIME_UNITS_PER_SECOND
    )


# LL/DDI/SCN/BV-74-C Steps 6-9: an initial pair and ten repetitions.
EXTENDED_PAIRS = 11
# Legacy-scanner stimulus: 600-us AuxPtr, distinct from extended-scan trains.
LEGACY_AUXILIARY_OFFSET_US = 600
LegacyReport = hci.HCI_LE_Advertising_Report_Event
Report = hci.HCI_LE_Extended_Advertising_Report_Event


# LL/DDI/SCN/BV-127-C Step 10: withhold responses for ten scan intervals.
DUPLICATE_LEGACY_WAIT_INTERVALS = 10
# LL/DDI/SCN/BV-128-C Step 8: withhold responses for five advertising intervals.
DUPLICATE_EXTENDED_WAIT_INTERVALS = 5
# Both procedures continue responding for 128 scan intervals after the first report.
DUPLICATE_OBSERVATION_SCAN_INTERVALS = 128


async def _duplicate_active_scanning(tester, *, extended):
    """Duplicate filtering must not prevent scan retries after initial absent
    responses."""
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    interval = (
        SCANNING_SCAN_INTERVAL
        if extended
        else SCAN_INTERVAL_US // hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    )
    interval_us = interval * hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    if not extended:
        # Provision the initial list; source Step 3 then selects accept-all scanning.
        await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
        await tester.command(
            hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(peer.address_type, peer)
        )
    await tester.command(
        scan_parameters(
            extended=extended,
            **(
                {
                    'scan_types': [1],
                    'scan_intervals': [interval],
                    'scan_windows': [interval],
                }
                if extended
                else {
                    'le_scan_type': 1,
                    'le_scan_interval': interval,
                    'le_scan_window': interval,
                }
            ),
        )
    )
    await tester.command(
        hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 1, 0, 0)
        if extended
        else hci.HCI_LE_Set_Scan_Enable_Command(1, 1)
    )
    adi = ADVERTISING_SID << PDU_ADV_ADI_DID_BITS
    start = tester.radio.now_us + REPORT_DELIVERY_US
    first_request_us = None
    first_request_event = 0
    unanswered_requests = sent_responses = 0
    observation_end = None
    ads = responses = 0
    generator = random.Random(0)
    for event_number in range(10000):
        channel = 37
        if extended:
            await tester.transmit(
                channel,
                ext_pdu(
                    adi=adi,
                    mode=AdvertisingMode.SCANNABLE,
                    aux=aux_pointer(AUXILIARY_CHANNEL, AUXILIARY_OFFSET_US),
                ),
                start_us=start,
            )
            channel = AUXILIARY_CHANNEL
            end = await tester.transmit(
                channel,
                ext_pdu(address=peer, adi=adi, mode=AdvertisingMode.SCANNABLE),
                start_us=start + AUXILIARY_OFFSET_US,
            )
        else:
            end = await tester.transmit(
                channel,
                adv_pdu(AdvertisingPduType.ADV_IND, address=peer, data=b''),
                start_us=start,
            )
        request = await tester.receive(channel, duration_us=1000)
        if request:
            assert request.valid_crc and request.pdu == request_pdu(
                AdvertisingPduType.SCAN_REQ, peer, scanner=DUT_ADDRESS
            )
            assert abs(request.start_us - end - LL_IFS_US) <= RESPONSE_IFS_TOLERANCE_US
            if first_request_us is None:
                first_request_us = request.end_us
                first_request_event = event_number
                tester.output.write(
                    f'DUPLICATE WAIT start_us={first_request_us} '
                    f'event={event_number}\n'
                )
            response_due = (
                event_number - first_request_event >= DUPLICATE_EXTENDED_WAIT_INTERVALS
                if extended
                else request.start_us - first_request_us
                >= DUPLICATE_LEGACY_WAIT_INTERVALS * interval_us
            )
            if response_due:
                if not sent_responses:
                    tester.output.write(
                        f'DUPLICATE FIRST RESPONSE request_us={request.start_us} '
                        f'event={event_number}\n'
                    )
                await tester.transmit(
                    channel,
                    (
                        ext_pdu(address=peer, data=b'A')
                        if extended
                        else adv_pdu(
                            AdvertisingPduType.SCAN_RSP, address=peer, data=b'A'
                        )
                    ),
                    start_us=request.end_us + LL_IFS_US,
                )
                sent_responses += 1
            else:
                unanswered_requests += 1
        await tester.wait(REPORT_DELIVERY_US)
        while event := tester.take(
            lambda event: isinstance(event, Report if extended else LegacyReport)
        ):
            for report in event.reports:
                assert (
                    report.address == peer
                    and report.address_type == hci.AddressType.PUBLIC_DEVICE
                )
                scan_response = (
                    bool(report.event_type & _scan_compatibility_Flags.SCAN_RESPONSE)
                    if extended
                    else report.event_type == LegacyEventType.SCAN_RSP
                )
                assert report.event_type == (
                    _scan_compatibility_Flags.SCANNABLE_ADVERTISING
                    | (_scan_compatibility_Flags.SCAN_RESPONSE if scan_response else 0)
                    if extended
                    else (
                        LegacyEventType.SCAN_RSP
                        if scan_response
                        else LegacyEventType.ADV_IND
                    )
                )
                if extended:
                    assert report.primary_phy == report.secondary_phy == Phy.LE_1M
                    assert (
                        report.advertising_sid == ADVERTISING_SID
                        and report.periodic_advertising_interval == 0
                    )
                assert report.data == (b'A' if scan_response else b'')
                if scan_response:
                    assert ads and unanswered_requests and sent_responses
                    responses += 1
                    if observation_end is None:
                        observation_end = (
                            tester.radio.now_us
                            + DUPLICATE_OBSERVATION_SCAN_INTERVALS * interval_us
                        )
                else:
                    ads += 1
        if observation_end is not None and tester.radio.now_us >= observation_end:
            break
        start = max(
            start
            + SCANNING_ADVERTISING_INTERVAL_US
            + generator.randrange(LL_ADV_DELAY_MAX_US + 1),
            tester.radio.now_us + LL_MAFS_US,
        )
    assert (
        ads
        and responses
        and (observation_end is not None)
        and (tester.radio.now_us >= observation_end)
    )
    if ads > 1 or responses > 1:
        tester.output.write(
            f'WARNING duplicate reports:advertising={ads},scan_response={responses}\n'
        )
    await tester.command(
        hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0)
        if extended
        else hci.HCI_LE_Set_Scan_Enable_Command(0, 0)
    )


async def _enable_legacy_scan(tester, *, filtered=False):
    interval = SCAN_INTERVAL_US // hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    await tester.command(
        scan_parameters(
            le_scan_interval=interval,
            le_scan_window=interval,
            scanning_filter_policy=int(filtered),
        )
    )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))


def _rfu_fields(wire, *, header=True, extended=True, context=None):
    """Set only ignored header bits, preserving meaningful address-type fields."""
    fields = decode_extended(wire)
    if context is not None:
        ignored = {'cte': 2}
        if context in ('primary', 'chain', 'response', 'scannable', 'connectable'):
            ignored['sync'] = PeriodicTrain(30000).sync_info(0)
        if context in ('primary', 'chain', 'response'):
            ignored['acad'] = b'\x02\xffZ'
        if context == 'chain':
            ignored['address'] = hci.Address(
                '12:34:56:78:9A:BC', hci.AddressType.PUBLIC_DEVICE
            )
        if context in ('chain', 'response'):
            ignored['target'] = hci.Address(
                '12:34:56:78:9A:BC', hci.AddressType.PUBLIC_DEVICE
            )
        if context in ('scannable', 'connectable'):
            ignored['aux'] = aux_pointer(1, AUXILIARY_OFFSET_US)
        if context == 'scannable':
            ignored['data'] = b'ignored'
        values = {
            'address': (
                hci.Address(fields['address'], hci.AddressType.PUBLIC_DEVICE)
                if 'address' in fields
                else None
            ),
            'target': (
                hci.Address(fields['target'], hci.AddressType.PUBLIC_DEVICE)
                if 'target' in fields
                else None
            ),
            'adi': int.from_bytes(fields['adi'], 'little') if 'adi' in fields else None,
            'aux': fields.get('aux'),
            'sync': fields.get('sync'),
            'cte': fields['cte'][0] if 'cte' in fields else None,
            'tx_power': (
                int.from_bytes(fields['power'], 'little', signed=True)
                if 'power' in fields
                else None
            ),
            'acad': fields.get('acad', b''),
            'data': fields['data'],
            'mode': wire[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS,
        }
        wire = ext_pdu(**values | ignored)
        fields = decode_extended(wire)
    value = bytearray(wire)
    if header:
        value[0] |= PDU_ADV_RESERVED_MASK
    if extended:
        value[PDU_ADV_EXT_HEADER_OFFSET] |= PDU_ADV_EXT_FLAGS_RESERVED_MASK
    if 'address' not in fields:
        value[0] |= PDU_ADV_TXADD_MASK
    if 'target' not in fields:
        value[0] |= PDU_ADV_RXADD_MASK
    return bytes(value)


# Separate auxiliary channels by12MHz so this discovery test is not an adjacent-channel
# RF test.
AUXILIARY_CHANNEL_STRIDE = 6
# Tables4.2-62/64/65:two independent SIDs per primary/secondary pair.
PHY_PAIRS = (
    ((Phy.LE_1M, Phy.LE_1M),) * 2
    + ((Phy.LE_CODED, Phy.LE_CODED),) * 2
    + ((Phy.LE_1M, Phy.LE_2M),) * 2
)
# All supported primary scan PHYs are1M and Coded;2M is secondary-only.
SCAN_PHYS = hci.PhyBit.LE_1M | hci.PhyBit.LE_CODED


async def _enable_scan(tester, *, active):
    await tester.command(
        scan_parameters(
            extended=True,
            scanning_phys=SCAN_PHYS,
            scan_types=[int(active)] * 2,
            scan_intervals=[SCANNING_SCAN_INTERVAL * 2] * 2,
            scan_windows=[SCANNING_SCAN_INTERVAL] * 2,
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))


def _periodic_sets(tester, length):
    generator = random.Random(0)
    interval = 1600 if length > 382 else 320
    interval_us = interval * LL_PERIODIC_INTERVAL_UNIT_US
    result = []
    for index, (primary, secondary) in enumerate(PHY_PAIRS):
        while True:
            address = generator.getrandbits(32)
            try:
                check_access_address(address)
            except AssertionError:
                continue
            if address not in [item.train.access_address for item in result]:
                break
        result.append(
            PeriodicAdvertiser(
                PeriodicTrain(
                    tester.radio.now_us
                    + interval_us
                    + index * interval_us // len(PHY_PAIRS),
                    interval=interval,
                    access_address=address,
                    crc_init=LinkParameters.crc_init ^ index,
                    phy=secondary,
                ),
                tester.radio.now_us + 1000 + index * 10000,
                200000,
                sid=index + 1,
                auxiliary_offset_us=AUXILIARY_OFFSET_US,
                primary_phy=primary,
            )
        )
    return result


ACTIVE_CHAIN_COUNT = 3
# Maximum representable AuxPtr separation for the active test's widely spaced PDUs.
ACTIVE_CHAIN_OFFSET_US = PDU_ADV_OFFSET_VALUE_MASK * PDU_ADV_OFFSET_UNIT_300_US
# Section4.2.4.7: scan response plus three chain PDUs, each229 octets.
ACTIVE_DATA_LENGTH = 229
# Source T_IFS checks use the raw peer's integer-us interface.
IFS_TOLERANCE_US = 2
# Section4.2.4.6: no report may remain incomplete for two seconds; ten truncations fail.
INCOMPLETE_REPORT_TIMEOUT_US = 2000000
# Bounded channel-acquisition opportunities; these are not truncation retries.
MAX_ADVERTISING_ATTEMPTS = 60
MAX_TRUNCATIONS = 10
# Section4.2.4.6: four100-octet chain PDUs, bounded by Scan_Max_Data/4.
PASSIVE_CHAIN_COUNT = 4
# Selected first-passive-chain offset; longer Coded PDUs increase it as required.
PASSIVE_CHAIN_OFFSET_US = 3000
PASSIVE_DATA_LENGTH = 100
# Selected distinct signed-dBm values for Power1..4, not measured RF signal levels.
POWER_LEVELS = (-20, -10, 0, 10)


def _chain_packets(chunks, powers, *, active, phy, adi):
    """Return (offset, PDU, received-data-count) without DUT wire encoders."""
    values = list(zip(chunks, powers))
    if not active:
        values.insert(0, (b'', powers[0]))
    packets = []
    offset = 0
    for index, (data, power) in enumerate(values):
        first, more = (index == 0, index < len(values) - 1)
        fields = {
            'address': LOWER_PERIPHERAL_PUBLIC_ADDRESS if first else None,
            'adi': adi,
            'tx_power': power,
            'kind': (
                AdvertisingPduType.AUX_SCAN_RSP
                if first and active
                else (
                    AdvertisingPduType.AUX_ADV_IND
                    if first
                    else AdvertisingPduType.AUX_CHAIN_IND
                )
            ),
            'data': data,
        }
        distance = ACTIVE_CHAIN_OFFSET_US if active else PASSIVE_CHAIN_OFFSET_US
        if more:
            fields['aux'] = aux_pointer(AUXILIARY_CHANNEL, distance, phy)
            if not active:
                minimum = phy.airtime_us(len(ext_pdu(**fields))) + LL_MAFS_US
                distance = max(
                    distance,
                    (minimum + PDU_ADV_OFFSET_UNIT_30_US - 1)
                    // PDU_ADV_OFFSET_UNIT_30_US
                    * PDU_ADV_OFFSET_UNIT_30_US,
                )
                fields['aux'] = aux_pointer(AUXILIARY_CHANNEL, distance, phy)
        packets.append((offset, ext_pdu(**fields), index + int(active)))
        offset += distance
    return packets


def _check_power_reports(records, chunks, powers, *, active, phy):
    """Discard truncated attempts; score complete results at their RF boundaries."""
    assert records, 'no extended advertising reports'
    if not active:
        for previous, current in pairwise(records):
            if (
                previous[2].event_type >> hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT
                == Report.DATA_INCOMPLETE_MORE_TO_COME
            ):
                assert current[0] - previous[0] <= INCOMPLETE_REPORT_TIMEOUT_US
        # Section 4.2.4.6 Step 5 discards a truncated attempt before its verdict.
        if (
            records[-1][2].event_type >> hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT
            == Report.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME
        ):
            return False
    expected = b''.join(chunks)
    offset = 0
    boundaries = [sum(map(len, chunks[: index + 1])) for index in range(len(chunks))]
    first_seen = set()
    last_power_seen = False
    for index, (_, received, report) in enumerate(records):
        status = report.event_type >> hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT
        flags = (
            _scan_power_Flags.SCANNABLE_ADVERTISING | _scan_power_Flags.SCAN_RESPONSE
            if active
            else 0
        )
        assert report.event_type & ~hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_MASK == flags
        assert report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
        assert report.address_type == hci.AddressType.PUBLIC_DEVICE
        assert report.primary_phy == report.secondary_phy == phy
        assert report.advertising_sid == ADVERTISING_SID
        assert report.periodic_advertising_interval == 0
        end = offset + len(report.data)
        assert end <= sum(
            map(len, chunks[:received])
        ), 'report contains data not yet received'
        assert (
            report.data == expected[offset:end]
        ), 'advertising data lost, reordered or duplicated'
        if active:
            assert (
                received and report.tx_power == powers[received - 1]
            ), 'stale scan-response TxPower'
        else:
            assert report.tx_power in (
                powers[0],
                powers[-1],
                Report.TX_POWER_INFORMATION_NOT_AVAILABLE,
            )
            assert (
                received == len(chunks) or report.tx_power != powers[-1]
            ), 'Power2 reported before the last PDU'
            if end > boundaries[-2] or last_power_seen:
                assert (
                    report.tx_power != powers[0]
                ), 'Power1 reported after the last PDU data or Power2'
            last_power_seen |= report.tx_power == powers[-1]
            for chunk_index, boundary in enumerate(boundaries):
                start = boundaries[chunk_index - 1] if chunk_index else 0
                if (
                    offset < boundary
                    and end > start
                    and (chunk_index not in first_seen)
                ):
                    assert (
                        report.tx_power != Report.TX_POWER_INFORMATION_NOT_AVAILABLE
                    ), 'first report containing this PDU has unknown TxPower'
                    first_seen.add(chunk_index)
        if index < len(records) - 1:
            assert status == Report.DATA_INCOMPLETE_MORE_TO_COME
        else:
            assert (
                status == Report.DATA_COMPLETE
            ), 'no final report within the observation timeout'
        offset = end
    assert len(records) > 1, 'the source requires multiple HCI report fragments'
    assert offset == len(expected), 'final complete report omitted advertising data'
    return True


async def _reporting_power(tester, *, active=False, phy=Phy.LE_1M):
    """Verify power changes across every packet and serialized HCI data fragment."""
    length = (
        ACTIVE_DATA_LENGTH
        if active
        else min(PASSIVE_DATA_LENGTH, SCAN_MAX_DATA // PASSIVE_CHAIN_COUNT)
    )
    count = ACTIVE_CHAIN_COUNT + 1 if active else PASSIVE_CHAIN_COUNT
    if active and count * length > SCAN_MAX_DATA:
        pytest.skip(
            'INCONCLUSIVE: section4.2.4.7 requires916 octets, exceeding '
            'Scan_Max_Data IXIT'
        )
    generator = random.Random(0)
    chunks = [generator.randbytes(length) for _ in range(count)]
    powers = (
        POWER_LEVELS
        if active
        else (POWER_LEVELS[0],) * (PASSIVE_CHAIN_COUNT - 1) + (POWER_LEVELS[-1],)
    )
    await tester.command(
        scan_parameters(
            extended=True,
            scanning_phys=1 << phy - 1,
            scan_types=[int(active)],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    truncated = 0
    for attempt in range(MAX_ADVERTISING_ATTEMPTS):
        adi = ADVERTISING_SID << PDU_ADV_ADI_DID_BITS | attempt
        records = []
        start = tester.radio.now_us + REPORT_DELIVERY_US
        mode = (
            AdvertisingMode.SCANNABLE
            if active
            else AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
        )
        await tester.transmit(
            37,
            ext_pdu(
                adi=adi,
                mode=mode,
                aux=aux_pointer(AUXILIARY_CHANNEL, AUXILIARY_OFFSET_US, phy),
            ),
            start_us=start,
            phy=phy,
        )
        first_start = start + AUXILIARY_OFFSET_US
        if active:
            end = await tester.transmit(
                AUXILIARY_CHANNEL,
                ext_pdu(address=LOWER_PERIPHERAL_PUBLIC_ADDRESS, adi=adi, mode=mode),
                start_us=first_start,
                phy=phy,
            )
            request = await tester.receive(
                AUXILIARY_CHANNEL,
                phy=phy,
                duration_us=LL_IFS_US + phy.address_us + IFS_TOLERANCE_US,
            )
            _scan_power_take_reports(tester, records, 0)
            if request is None:
                assert not records, (
                    'active scanner reported advertising without requesting its'
                    ' scan response'
                )
                await tester.wait(
                    max(
                        0,
                        start
                        + SCANNING_ADVERTISING_INTERVAL_US
                        + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
                        - tester.radio.now_us,
                    )
                )
                continue
            assert request.valid_crc
            assert request.pdu == request_pdu(
                AdvertisingPduType.SCAN_REQ,
                LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                scanner=DUT_ADDRESS,
            )
            assert abs(request.start_us - end - LL_IFS_US) <= IFS_TOLERANCE_US
            assert len(records) == 1
            advertisement = records.pop()[2]
            assert advertisement.event_type == _scan_power_Flags.SCANNABLE_ADVERTISING
            assert advertisement.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
            assert advertisement.address_type == hci.AddressType.PUBLIC_DEVICE
            assert advertisement.primary_phy == advertisement.secondary_phy == phy
            assert advertisement.advertising_sid == ADVERTISING_SID
            assert advertisement.periodic_advertising_interval == 0
            assert not advertisement.data
            first_start = request.end_us + LL_IFS_US
        for offset, wire, received in _chain_packets(
            chunks, powers, active=active, phy=phy, adi=adi
        ):
            await tester.transmit(
                AUXILIARY_CHANNEL, wire, start_us=first_start + offset, phy=phy
            )
            _scan_power_take_reports(tester, records, received)
        if not active:
            assert (
                await tester.receive(
                    AUXILIARY_CHANNEL, phy=phy, duration_us=REPORT_DELIVERY_US
                )
                is None
            ), 'passive scanner sent a request'
        else:
            await tester.wait(REPORT_DELIVERY_US)
        _scan_power_take_reports(tester, records, count)
        if records:
            if (
                records[-1][2].event_type >> hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT
                == Report.DATA_INCOMPLETE_MORE_TO_COME
            ):
                await tester.wait(INCOMPLETE_REPORT_TIMEOUT_US)
                _scan_power_take_reports(tester, records, count)
            if _check_power_reports(records, chunks, powers, active=active, phy=phy):
                break
            truncated += 1
            assert truncated < MAX_TRUNCATIONS, 'ten truncated advertising events'
        await tester.wait(
            max(
                0,
                start
                + SCANNING_ADVERTISING_INTERVAL_US
                + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
                - tester.radio.now_us,
            )
        )
    else:
        raise AssertionError('no complete power-reporting advertising event')
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


def _scan_power_take_reports(tester, records, received):
    for event in list(tester.events):
        if isinstance(event, Report):
            records.extend(
                (tester.radio.now_us, received, report) for report in event.reports
            )
            tester.events.remove(event)


# Table4.2-52: minimum twenty advertising intervals and ten reported advertisements.
ADVERTISING_INTERVALS = 20
# Table4.2-52 round18 assigns242 octets to AUX_ADV_IND and1403 to its chain.
FIRST_AUXILIARY_DATA = 242
# Table4.2-78: reserved AUX PHY encoding, followed by an actual LE1M PDU.
INVALID_AUX_PHY = 4
# Section4.2.4.22 repeats the invalid primary/auxiliary pair five times.
INVALID_PHY_ROUNDS = 5
REMAINING_AUXILIARY_DATA = 1403
REQUIRED_REPORTS = 10
SCAN_DURATION = 500
# Scan_Max_Data IXIT for this DUT, equal to its declared1650-octet receive capacity.
SCAN_MAX_DATA = hci.HCI_LE_ADV_DATA_SIZE_MAX


def _packets(
    round_, data, adi, primary_phy, secondary_phy, coding, *, channel=AUXILIARY_CHANNEL
):
    """Pack every nonfinal auxiliary payload to255 octets, without DUT encoders."""
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    if round_.kind != AdvertisingPduType.ADV_EXT_IND:
        wire = (
            request_pdu(round_.kind, round_.target, scanner=peer)
            if round_.kind == AdvertisingPduType.ADV_DIRECT_IND
            else adv_pdu(round_.kind, address=peer, data=data)
        )
        return ([(37, primary_phy, 0, wire)], ())
    if not round_.auxiliary:
        return (
            [
                (
                    37,
                    primary_phy,
                    0,
                    ext_pdu(address=peer, target=round_.target, adi=adi),
                )
            ],
            (),
        )
    pointer = aux_pointer(channel, AUXILIARY_OFFSET_US, secondary_phy)
    # Core Table 2.4 C.1: primary AdvA with AuxPtr is RFU on LE Coded.
    # Correct LL.TS.p28 Table 4.2-52 round 17 by moving AdvA to AUX_ADV_IND.
    primary_address = round_.primary_address and primary_phy == Phy.LE_1M
    result = [
        (
            37,
            primary_phy,
            0,
            ext_pdu(address=peer if primary_address else None, adi=adi, aux=pointer),
        )
    ]
    offset, consumed = (AUXILIARY_OFFSET_US, 0)
    boundaries = []
    first = True
    while True:
        fields = {
            'address': peer if first and not primary_address else None,
            'target': round_.target if first else None,
            'adi': adi,
            'kind': (
                AdvertisingPduType.AUX_ADV_IND
                if first
                else AdvertisingPduType.AUX_CHAIN_IND
            ),
        }
        capacity = (
            PDU_ADV_EXT_PAYLOAD_SIZE_MAX - len(ext_pdu(**fields)) + PDU_HEADER_SIZE
        )
        more = len(data) - consumed > capacity
        if more:
            fields['aux'] = pointer
            capacity = (
                PDU_ADV_EXT_PAYLOAD_SIZE_MAX - len(ext_pdu(**fields)) + PDU_HEADER_SIZE
            )
        chunk = data[consumed : consumed + capacity]
        if more:
            probe = ext_pdu(**fields, data=chunk)
            distance = secondary_phy.airtime_us(len(probe), coding) + LL_MAFS_US
            distance = (
                (distance + PDU_ADV_OFFSET_UNIT_30_US - 1)
                // PDU_ADV_OFFSET_UNIT_30_US
                * PDU_ADV_OFFSET_UNIT_30_US
            )
            fields['aux'] = aux_pointer(channel, distance, secondary_phy)
        result.append((channel, secondary_phy, offset, ext_pdu(**fields, data=chunk)))
        consumed += len(chunk)
        if not more:
            return (result, tuple(boundaries))
        boundaries.append(consumed)
        offset += distance
        first = False


SYNCHRONIZATION_ADVERTISING_INTERVAL_US = 20500
# Section4.2.4.25: ten complete periodic intervals before the duplicate command.
DUPLICATE_OBSERVATION_EVENTS = 10
# Selected negative window exceeds the three-interval Sync_Timeout; the advertiser
# search must remain pending until canceled if no matching SyncInfo is available.
FILTER_OBSERVATION_EVENTS = 10
# Data fit into a single AUX_SYNC_IND; a sequence prefix detects stale reports.
PERIODIC_DATA_LENGTH = 31
# Selected100-ms periodic interval and20-ms base advertising interval +500-us delay.
SYNCHRONIZATION_PERIODIC_INTERVAL = 80


def _check_established(event, *, phy=Phy.LE_1M):
    assert event.status == ErrorCode.SUCCESS
    assert 0 <= event.sync_handle <= SYNC_HANDLE_MAX
    assert event.advertising_sid == ADVERTISING_SID
    assert event.advertiser_address_type == hci.AddressType.PUBLIC_DEVICE
    assert event.advertiser_address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
    assert event.advertiser_phy == phy
    assert event.periodic_advertising_interval == SYNCHRONIZATION_PERIODIC_INTERVAL
    assert event.advertiser_clock_accuracy == 0
    return event.sync_handle


async def _start_advertiser(tester, *, filtered=False, duplicates=False):
    await tester.command(
        scan_parameters(
            extended=True,
            scanning_filter_policy=int(filtered),
            scanning_phys=hci.PhyBit.LE_1M,
            scan_types=[0],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(
        hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, int(duplicates), 0, 0)
    )
    interval_us = SYNCHRONIZATION_PERIODIC_INTERVAL * LL_PERIODIC_INTERVAL_UNIT_US
    return PeriodicAdvertiser(
        PeriodicTrain(
            tester.radio.now_us + interval_us,
            interval=SYNCHRONIZATION_PERIODIC_INTERVAL,
        ),
        tester.radio.now_us + 1000,
        SYNCHRONIZATION_ADVERTISING_INTERVAL_US,
    )


def _sync_command(*, use_list=False):
    return create_sync(
        options=int(use_list),
        advertising_sid=ADVERTISING_SID,
        advertiser_address_type=hci.AddressType.PUBLIC_DEVICE,
        advertiser_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
        skip=0,
        sync_timeout=3
        * SYNCHRONIZATION_PERIODIC_INTERVAL
        * LL_PERIODIC_INTERVAL_UNIT_US
        // hci.HCI_LE_PERIODIC_SYNC_TIMEOUT_UNIT_US,
    )


async def _transmit_report(tester, advertiser, *, handle=None, filtered=False):
    data = advertiser.train.counter.to_bytes(2, 'little') + random.Random(
        advertiser.train.counter
    ).randbytes(PERIODIC_DATA_LENGTH - 2)
    await advertiser.transmit(tester, data)
    if handle is None:
        established = await tester.event(SyncEstablished)
        handle = _check_established(established)
    report = await tester.event(PeriodicReport)
    assert report.sync_handle == handle and report.data == data
    assert report.data_status == ExtendedReport.DATA_COMPLETE
    assert report.cte_type == hci.HCI_LE_PERIODIC_REPORT_CTE_NONE
    assert -127 <= report.rssi <= 20
    assert not any(
        isinstance(event, (SyncEstablished, SyncLost, PeriodicReport))
        for event in tester.events
    )
    if filtered:
        assert not any(
            isinstance(event, ExtendedReport) for event in tester.events
        ), 'periodic synchronization must not bypass the scan-report filter'
    return handle


# Selected15-ms phase after the twentieth announcement; the next announcement
# can encode the following five-second periodic anchor within SyncInfo's range.
FIRST_ANCHOR_US = REPORT_DELIVERY_US + 20 * PERIODIC_ADVERTISING_INTERVAL_US + 15000
# Table4.2-61: periodic data length and maximum skipped events for each round.
RECEPTION_ROUNDS = (
    (0, 0),
    (PDU_ADV_LEGACY_DATA_SIZE_MAX, 0),
    (191, 0),
    (382, 0),
    (SCAN_MAX_DATA, 0),
    (SCAN_MAX_DATA, 1),
    (SCAN_MAX_DATA, 249),
    (SCAN_MAX_DATA, 499),
    (PDU_ADV_LEGACY_DATA_SIZE_MAX, 15),
)
_scan_compatibility_Flags = Report.EventType


class _AdvertisingPeer:
    """One independent lower-tester radio; no DUT encoders or Host stack."""

    def __init__(self, radio, sid, output):
        self.radio, self.sid, self.output = (radio, sid, output)
        self.data = None
        self.active = self.busy = False

    async def run(self):
        generator = random.Random(self.sid)
        primary, secondary = PHY_PAIRS[self.sid - 1]
        channel = (self.sid - 1) * AUXILIARY_CHANNEL_STRIDE
        adi = self.sid << PDU_ADV_ADI_DID_BITS
        next_start = self.radio.now_us + LL_MAFS_US
        while True:
            if self.data is None:
                await self.radio.advance_to_us(self.radio.now_us + REPORT_DELIVERY_US)
                next_start = self.radio.now_us + LL_MAFS_US
                continue
            self.busy = True
            data = self.data
            start = max(
                self.radio.now_us + LL_MAFS_US, next_start
            ) + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
            advertisement_start = start
            train, _ = _packets(
                _ScanRound(self.sid, len(data)),
                data,
                None if self.active else adi,
                primary,
                secondary,
                PHY_CODED_S8_FACTOR,
                channel=channel,
            )
            if self.active:
                end = await self.radio.transmit(
                    37,
                    ext_pdu(
                        adi=adi,
                        mode=AdvertisingMode.SCANNABLE,
                        aux=aux_pointer(channel, AUXILIARY_OFFSET_US, secondary),
                    ),
                    start_us=start,
                    phy=primary,
                )
                end = await self.radio.transmit(
                    channel,
                    ext_pdu(
                        address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                        adi=adi,
                        mode=AdvertisingMode.SCANNABLE,
                    ),
                    start_us=start + AUXILIARY_OFFSET_US,
                    phy=secondary,
                )
                request = await self.radio.receive(
                    channel,
                    end
                    + LL_IFS_US
                    + secondary.address_us
                    + SCAN_RESPONSE_IFS_TOLERANCE_US,
                    phy=secondary,
                )
                if request:
                    assert request.valid_crc and request.phy == secondary
                    assert request.pdu == request_pdu(
                        AdvertisingPduType.SCAN_REQ,
                        LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                        scanner=DUT_ADDRESS,
                    )
                    assert (
                        abs(request.start_us - end - LL_IFS_US)
                        <= SCAN_RESPONSE_IFS_TOLERANCE_US
                    )
                    start = request.end_us + LL_IFS_US - AUXILIARY_OFFSET_US
                else:
                    train = []
            for index, (_, phy, offset, wire) in enumerate(train):
                if self.active and index == 0:
                    continue
                await self.radio.transmit(
                    37 if index == 0 else channel,
                    wire,
                    start_us=start + offset,
                    phy=phy,
                )
            self.output.write(
                f'PEER sid={self.sid} start={advertisement_start} end='
                f'{self.radio.now_us} length={len(data)}\n'
            )
            adi = self.sid << PDU_ADV_ADI_DID_BITS | adi + 1 & PDU_ADV_ADI_DID_MASK
            next_start = advertisement_start + SCANNING_ADVERTISING_INTERVAL_US
            self.busy = False


_scan_multiple_Flags = Report.EventType
_scan_power_Flags = Report.EventType
ROUNDS = (
    _ScanRound(1, kind=AdvertisingPduType.ADV_IND, auxiliary=False),
    _ScanRound(
        2, PDU_ADV_LEGACY_DATA_SIZE_MAX, AdvertisingPduType.ADV_IND, auxiliary=False
    ),
    _ScanRound(
        3, kind=AdvertisingPduType.ADV_DIRECT_IND, target=DUT_ADDRESS, auxiliary=False
    ),
    _ScanRound(
        4, kind=AdvertisingPduType.ADV_DIRECT_IND, target=PEER_ADDRESS, auxiliary=False
    ),
    _ScanRound(5, kind=AdvertisingPduType.ADV_NONCONN_IND, auxiliary=False),
    _ScanRound(
        6,
        PDU_ADV_LEGACY_DATA_SIZE_MAX,
        AdvertisingPduType.ADV_NONCONN_IND,
        auxiliary=False,
    ),
    _ScanRound(7, auxiliary=False),
    _ScanRound(8, target=DUT_ADDRESS, auxiliary=False),
    _ScanRound(9, target=PEER_ADDRESS, auxiliary=False),
    _ScanRound(10),
    _ScanRound(11, target=DUT_ADDRESS),
    _ScanRound(12, target=PEER_ADDRESS),
    _ScanRound(13, 191),
    _ScanRound(14, 382),
    _ScanRound(15, SCAN_MAX_DATA),
    _ScanRound(16, target=DUT_ADDRESS, auxiliary=False, duration=SCAN_DURATION),
    _ScanRound(17, PDU_ADV_LEGACY_DATA_SIZE_MAX, primary_address=True),
    _ScanRound(18, FIRST_AUXILIARY_DATA + REMAINING_AUXILIARY_DATA),
)


@pytest.mark.radio_peers(6, factory=_AdvertisingPeer)
async def _multiple_scanning(tester, *, active=False):
    """Receive every set in both six-set,all-PHY discovery matrix rounds."""
    generator = random.Random(0)
    for length in (191, SCAN_MAX_DATA):
        await _enable_scan(tester, active=active)
        data = [
            bytes([sid]) + bytes(generator.randint(1, 254) for _ in range(length - 1))
            for sid in range(1, 7)
        ]
        complete, fragments = (set(), {})
        for peer, payload in zip(tester.peers, data):
            peer.active, peer.data = (active, payload)

        def reports(
            *, fragments=fragments, data=data, length=length, complete=complete
        ):
            while event := tester.take(lambda event: isinstance(event, Report)):
                for report in event.reports:
                    sid = report.advertising_sid
                    assert 1 <= sid <= len(PHY_PAIRS)
                    response = bool(
                        report.event_type & _scan_multiple_Flags.SCAN_RESPONSE
                    )
                    assert active or not response
                    key = (sid, response)
                    collected = fragments.setdefault(key, [])
                    collected.append(report)
                    status = (
                        report.event_type >> hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT
                    )
                    if status == Report.DATA_INCOMPLETE_MORE_TO_COME:
                        continue
                    primary, secondary = PHY_PAIRS[sid - 1]
                    expected = data[sid - 1] if not active or response else b''
                    _, boundaries = _packets(
                        _ScanRound(sid, length),
                        expected,
                        None if response else sid << PDU_ADV_ADI_DID_BITS,
                        primary,
                        secondary,
                        PHY_CODED_S8_FACTOR,
                    )
                    _, full = _scanning_check_reports(
                        SimpleNamespace(events=[Report(reports=collected)]),
                        _ScanRound(sid, length),
                        expected,
                        sid << PDU_ADV_ADI_DID_BITS,
                        primary,
                        secondary,
                        boundaries,
                        properties=(
                            _scan_multiple_Flags.SCANNABLE_ADVERTISING
                            | (_scan_multiple_Flags.SCAN_RESPONSE if response else 0)
                            if active
                            else 0
                        ),
                    )
                    fragments.pop(key)
                    if full and (not active or response):
                        complete.add(sid)

        deadline = tester.radio.now_us + 10000000
        while len(complete) < len(PHY_PAIRS) and tester.radio.now_us < deadline:
            await tester.wait(REPORT_DELIVERY_US)
            reports()
        assert complete == set(range(1, 7)), (
            'missing advertising sets',
            length,
            complete,
        )
        for peer in tester.peers:
            peer.data = None
        while (
            any(peer.busy for peer in tester.peers) and tester.radio.now_us < deadline
        ):
            await tester.wait(REPORT_DELIVERY_US)
            reports()
        assert not any(peer.busy for peer in tester.peers)
        await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))
    if not active:
        for suffix in ('Tx.csv', 'Txv2.csv'):
            with (tester.phy_results / f'd_2G4_00.{suffix}').open() as capture:
                assert (
                    next(csv.DictReader(capture), None) is None
                ), 'passive scanner transmitted'


async def multiple_legacy_and_extended_primary_advertising_sets(tester, *, number):
    """Extended Advertising, Multiple Sets, Legacy and Extended, Primary Advertising
    PDU.

    Initial Condition:
        Advertising parameters select supported intervals, event types, address
        type and channel map. TSPX_supported_advertising_channels declares used
        and unused channels. This implementation selects all three primary
        channels and public addresses; set 0 is extended non-connectable,
        non-scannable and undirected, while set 1 uses the case's legacy properties.
        Both sets use LE 1M and distinct SIDs; directed rows target the Lower Tester.

    Test Steps:
        1. Configure set 0 with properties zero, all primary channels, both PHYs
           LE 1M and a 20-ms interval (0x20 in 625-us units).
        2. Configure set 1 with the Table 4.2-36 properties, all primary channels,
           both PHYs LE 1M, a 50-ms interval (0x50), and a different SID.
        3. For ADV_DIRECT_IND properties, omit Steps 4/5 and proceed to Step 6.
        4. Otherwise submit five seeded random data octets to set 0, identified
           by its advertising handle (see the opcode Source Correction).
        5. Submit five different seeded octets to set 1 using its handle.
        6. Enable both sets in one extended enable command with Num_Sets 2 and
           the table's Duration for each set. Send this command to the IUT.
        7. Observe interlaced events on supported primary channels. Require only
           the configured PDU types, set 0's 20-ms cadence and set 1's cadence,
           and exact set-specific data for the nondirected rows. The receiver
           samples consecutive starts using common drift/jitter tolerances.
           Receive all three primary PDUs of each sampled event and require
           one PDU type throughout that event; different sets may use different
           types. Other events may occur before an extended event's auxiliary PDU.
        8. When AuxPtr is present, follow it to LE 1M AUX_ADV_IND and verify
           pointer timing, T_MAFS, mode, ADI, addresses and complete data.
        9. For nondirected rows, repeat the data writes for a total of ten data
           generations, including the initial writes in Steps 4/5. Keep both sets
           enabled and use new, distinct five-octet payloads for each generation.
           Repeat observations 7/8 after each pair of writes. Directed rows retain
           Step 3's empty-data branch and skip the data-update loop.
        10. Disable both sets, using one extended enable command per set.
        11. Clear the advertising sets with LE Clear Advertising Sets.

    Test Case Configuration:
        Table 4.2-36 set 1 properties/PDU/Duration:
        BV-64: 0x0010 / ADV_NONCONN_IND / 0;
        BV-65: 0x0013 / ADV_IND / 0;
        BV-66: 0x001D / high-duty ADV_DIRECT_IND / 0x007D (1.25 s);
        BV-67: 0x0015 / low-duty ADV_DIRECT_IND / 0;
        BV-68: 0x0012 / ADV_SCAN_IND / 0.
        Both sets use the row's Duration. All HCI commands require success.

    Expected Outcome:
        Pass verdict: Step 7 receives only the expected primary PDU types on the
        supported channels, with set 0 at 20 ms and set 1 at 50 ms except the
        mandatory high-duty exception below. Nondirected rows deliver the exact
        submitted data for each set in all ten generations. Each sampled primary
        event retains its configured PDU type across all three primary channels.
        Each primary AuxPtr identifies the same valid LE 1M auxiliary packet.
        Timing requirements use integer microseconds; no fractional-us boundary
        stimulus is required. Complete cleanup Steps 10/11.

    Source Correction:
        Steps 4/5 name legacy Set Advertising Data but supply a handle; use
        Set Extended Advertising Data, as also drawn in Figure 4.2-50. Step 6's
        command recipient is the IUT. Enable both sets with one Num_Sets 2 command.
        The test owner confirmed that Step 9 repeats data updates, with ten total
        generations including the initial writes; the diagram's repeat box does
        not replace these writes. Preserve Step 3 for directed rows: both sets
        carry empty data and omit the updates. Correct data are received by the
        Lower Tester, rather than the IUT named in the pass paragraph.
        BV-66 high-duty directed advertising uses the Core maximum 3.75-ms
        interval, rather than the generic 50-ms outcome, and retains the table's
        1.25-s Duration for both sets.

    Reference:
        LL.TS.p28.pdf, Section 4.2.3.15, LL/DDI/ADV/BV-64-C, LL/DDI/ADV/BV-65-C,
        LL/DDI/ADV/BV-66-C, LL/DDI/ADV/BV-67-C, LL/DDI/ADV/BV-68-C; PDF pages
        210-214, printed pages 4.2-117-4.2-121, Table 4.2-36 and Figures 4.2-50/51.
    """
    flags, _, duration = PRIMARY_ROUNDS[number]
    directed = bool(flags & Properties.DIRECTED_ADVERTISING)
    properties, phys = ((0, flags), (Phy.LE_1M, Phy.LE_1M))
    payloads = await _configure_advertising_sets(
        tester,
        properties,
        phys,
        (0, 0) if directed else (5, 5),
        intervals=(32, 80),
        skip_empty=True,
    )
    assert directed or payloads[0] != payloads[1]
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
            1, [0, 1], [duration, duration], [0, 0]
        )
    )
    await _primary_intervals(tester, PRIMARY_ROUNDS[number][1], high_duty=number == 66)
    generator = random.Random(105)
    for generation in range(1 if directed else PRIMARY_DATA_ROUNDS):
        if generation:
            previous = payloads
            payloads = [
                bytes(generator.randrange(1, 255) for _ in range(5)) for _ in range(2)
            ]
            assert payloads[0] != payloads[1]
            assert all(data != old for data, old in zip(payloads, previous))
            for handle, data in enumerate(payloads):
                await set_extended_data(tester, data, handle=handle)
        tester.output.write(f'PRIMARY DATA generation={generation + 1} {payloads!r}\n')
        await _primary_set_events(tester, PRIMARY_ROUNDS[number][1], payloads)
    for handle in range(2):
        await tester.command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(0, [handle], [0], [0])
        )
    await tester.command(hci.HCI_LE_Clear_Advertising_Sets_Command())


async def passive_scanning(tester, *, kind):
    """Passive Scanning.

    Initial Condition:
        Passive scanning uses the selected interval/window and accept-all policy
        0x00. Use a 20-ms advertising base with a 5-ms mean AdvDelay, and a 75-ms
        scan interval/window: three times the mean advertising interval. Disable
        duplicate filtering. BV-01 sends ADV_NONCONN_IND; BV-10 sends ADV_IND.

    Test Steps:
        1. Configure the Lower Tester on the first supported channel (37) with
           the common public address.
        2. Enable passive scanning in the IUT with the selected timing and policy.
        3. Send the Table 4.2-49 PDU type on that channel with the event count as
           data, at the selected advertising interval, for twenty scan intervals.
        4. Require LE Advertising Report with the matching advertising event type
           and data from a transmitted packet. Also check peer address and type.
        5. Send LE Set Scan Enable to disable scanning; require Command Complete.
        6. Configure the second channel (38) with a public address differing from
           the IUT address in its least significant octet.
        7. Repeat Steps 2-5.
        8. Configure the third channel (39) with a random address differing from
           the IUT address in its most significant octet.
        9. Repeat Steps 2-5.

    Expected Outcome:
        Pass verdict: complete the procedure on every supported channel with the
        correct packet type recognized. Require a matching report in each phase
        and no SCAN_REQ or scan-response report. The source's conditional Filter
        Accept List verdict requires reports only for a matching address/type,
        rejecting wrong types and unlisted addresses; these two selected cases
        explicitly use accept-all, so that conditional path is not activated.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.2, LL/DDI/SCN/BV-01-C, LL/DDI/SCN/BV-10-C; PDF
        pages 269-271, printed pages 4.2-176-4.2-178, Table 4.2-49, Figure
        4.2-77, Steps 1-9 and the conditional pass verdict.
    """
    await _scan_reports(tester, active=False, filtered=False, kind=kind)


async def passive_scanning_device_filtering(tester):
    """Passive Scanning Device Filtering.

    Initial Condition:
        Passive scanning uses basic filtered policy 0x01 and a Filter Accept List
        containing one public address. Select channel 37, a 20-ms advertising base
        with a 5-ms mean AdvDelay, and a 75-ms scan interval/window. The interval
        is three times the mean advertising interval. Keep scanning enabled
        across all four address/type phases; disable duplicate filtering.

    Test Steps:
        1. Enable passive scanning with policy 0x01, ignoring unlisted devices.
        2. Configure the Lower Tester on the selected channel with the public
           address present in the Filter Accept List.
        3. Send ADV_NONCONN_IND once per selected advertising interval until
           twenty scan intervals pass or Step 4 completes.
        4. Receive LE Advertising Report for non-connectable advertising with the
           listed public address/type and a transmitted packet's data.
        5. Stop Lower Tester advertising before changing its address.
        6. Configure the same address bytes with random address type.
        7. Send ADV_NONCONN_IND for twenty scan intervals.
        8. Stop Lower Tester advertising.
        9. Configure an unlisted public address differing from the IUT in the
           least significant octet.
        10. Repeat Steps 7-8.
        11. Configure an unlisted random address differing from the IUT in both
            the most and least significant octets.
        12. Repeat Steps 7-8.
        13. Disable LE scanning with LE Set Scan Enable; require Command Complete.

    Expected Outcome:
        Pass verdict: complete the selected-channel/timing procedure, reporting the
        listed public advertiser and its exact data. Reject identical address
        bytes with the wrong type and both unlisted addresses for the full
        twenty-interval phases. Passive scanning must not transmit SCAN_REQ.

    Source Correction:
        Step 13 names BR/EDR Write Scan Enable; use LE Set Scan Enable to stop
        LE scanning. This local command-name correction follows the Core LE
        scanning model and was confirmed with Amber, not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4, unnumbered procedure, LL/DDI/SCN/BV-02-C; PDF
        pages 271-273, printed pages 4.2-178-4.2-180, Figure 4.2-78,
        Steps 1-13 and the complete pass verdict. Core Specification 6.3,
        Vol 4, Part E, 7.8.10/7.8.11 define LE scan control.
    """
    await _scan_reports(
        tester, kind=AdvertisingPduType.ADV_NONCONN_IND, active=False, filtered=True
    )


async def active_scanning(tester):
    """Active Scanning.

    Initial Condition:
        Active scanning uses a public own address and selected interval/window.
        The source's initial prose lists basic filtering with one public address
        in the Filter Accept List, but Step 3 explicitly selects accept-all 0x00;
        retain that step value. Use a 20-ms advertising base with 5-ms mean
        AdvDelay and a 75-ms scan interval/window, three times that mean interval.
        Disable duplicate filtering; use the common LT scan-response name.

    Test Steps:
        1. Select the first supported Lower Tester advertising channel (37).
        2. Configure the common public Lower Tester address.
        3. Enable active scanning in the IUT with accept-all policy 0x00.
        4. Send ADV_IND on the selected channel with an unsigned little-endian
           event counter until twenty scan intervals pass or Step 5 executes.
        5. Receive SCAN_REQ at T_IFS after ADV_IND. Check CRC, PHY, both addresses
           and their types; return SCAN_RSP with the selected address and LT name
           at T_IFS after the request. Require request spacing within 2 us.
        6. Interleaved with Step 4, receive LE Advertising Report containing the
           transmitted ADV_IND information.
        7. Interleaved with Step 5, receive LE Advertising Report containing the
           scan-response information.
        8. Disable scanning with LE Set Scan Enable; require Command Complete.
        9. Configure a public advertiser differing from the IUT in its most
           significant address octet.
        10. Repeat Steps 3-8.
        11. Configure a public advertiser differing in its least significant octet.
        12. Repeat Steps 3-8.
        13. Configure a public advertiser differing in both endpoint octets.
        14. Repeat Steps 3-8.
        15. Select the second supported advertising channel (38).
        16. Repeat Steps 2-14.
        17. Select the third supported advertising channel (39).
        18. Repeat Steps 2-14.

    Expected Outcome:
        Pass verdict: on every supported channel the IUT sends a scan request to
        each of the four advertisers and reports both advertisement and response
        information. Check exact address/type/data and T_IFS within 2 us.

    Notes:
        Do not require a fixed report order or grouping: one HCI event may contain
        multiple queued reports. The source also permits a listed-only realization
        or accepting unknown devices; this realization uses Step 3's accept-all
        setting and an isolated PHY, so no unrelated advertisers are present.

    Source Correction:
        Retain numbered Step 3's explicit policy 0x00 rather than the conflicting
        filtered initial prose. Amber supports this local source interpretation;
        it is not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4, unnumbered procedure, LL/DDI/SCN/BV-03-C; PDF
        pages 273-275, printed pages 4.2-180-4.2-182, Figure 4.2-79,
        Steps 1-18, pass verdict and Notes. Core Specification 6.3, Vol 4,
        Part E, 7.8.10/7.8.11 define LE scan parameters and enable.
    """
    await _scan_reports(
        tester, kind=AdvertisingPduType.ADV_IND, active=True, filtered=False
    )


async def active_scanning_device_filtering(tester):
    """Active Scanning Device Filtering.

    Initial Condition:
        Active scanning uses a public own address, basic filtered policy 0x01 and
        one public entry in the Filter Accept List. Select a 20-ms advertising
        base with 5-ms mean AdvDelay, and 75-ms scan interval/window, three times
        the mean advertising interval. Keep scanning enabled while changing the
        three peer addresses on each channel; disable duplicate filtering.

    Test Steps:
        1. Enable active scanning with policy 0x01, ignoring unlisted devices.
        2. Select the first supported Lower Tester advertising channel (37).
        3. Configure the listed public advertiser and its scan-response data.
        4. Send ADV_IND on that channel until twenty scan intervals pass or the
           Step 5 scan exchange occurs.
        5. Receive SCAN_REQ at T_IFS after ADV_IND and send SCAN_RSP at T_IFS
           after the request. Validate CRC, PHY, addresses/types and 2-us spacing.
        6. Interleaved with Step 4, receive LE Advertising Report for ADV_IND.
        7. Interleaved with Step 5, receive LE Advertising Report for SCAN_RSP.
        8. Configure an unlisted public advertiser differing from the IUT in its
           least significant octet, with scan-response data available.
        9. Send ADV_IND on the selected channel for twenty scan intervals.
        10. Require no SCAN_REQ at T_IFS after any advertisement.
        11. Configure an unlisted public advertiser differing in both endpoint
            octets, with scan-response data available.
        12. Repeat the transmission/no-response exercise of Steps 9-10 using the
            Step 11 address; do not overwrite it with the Step 8 address.
        13. Disable LE scanning with LE Set Scan Enable; require Command Complete.
        14. Select the second supported advertising channel (38).
        15. Repeat the enable and Steps 3-13 on the newly selected channel.
        16. Select the third supported advertising channel (39).
        17. Repeat the enable and Steps 3-13 on the newly selected channel.

    Expected Outcome:
        Pass verdict: complete every supported channel/timing phase. The IUT
        requests and reports information from the listed advertiser. For each
        unlisted peer require no SCAN_REQ or advertising/scan-response report
        throughout the twenty-interval phase. Listed-peer reports match exact
        address/type/data; report order/grouping is not constrained.

    Source Correction:
        Step 4's self-reference means the exchange in Step 5. Steps 6/7 associate
        the reports with transmissions in Steps 4/5, not configuration/incorrect
        response references. Step 12 must preserve Step 11's third address;
        repeating Step 8 would replace it with the earlier address. Steps 15/17
        must preserve the channel selected in 14/16 and re-enable scanning after
        Step 13; repeating the original first-channel setup would erase that
        selection. Step 13 names BR/EDR Write Scan Enable; use LE Set Scan Enable.
        Amber supports these local numbering/command corrections against the
        source's explicit address, channel and LE filtering intent; they are not
        adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4, unnumbered procedure, LL/DDI/SCN/BV-04-C; PDF
        pages 275-278, printed pages 4.2-182-4.2-185, Figure 4.2-80,
        Steps 1-17 and pass verdict. Core Specification 6.3, Vol 4, Part E,
        7.8.10/7.8.11 define the LE scan commands.
    """
    await _scan_reports(
        tester, kind=AdvertisingPduType.ADV_IND, active=True, filtered=True
    )


async def scanning_for_advertiser_types(tester):
    """Scanning For Advertiser Types.

    Initial Condition:
        Active scanning uses a public own address and selected interval/window.
        Keep one public entry in the Filter Accept List, but select accept-all
        0x00 as explicitly required by the procedure intro rather than its stale
        filtered initial prose. Use a 20-ms advertising base with 5-ms mean
        AdvDelay and a 75-ms scan interval/window, three times the mean interval.
        Keep scanning enabled across the three channel/type phases.

    Test Steps:
        1. Enable active scanning in the IUT with the selected timing/policy.
        2. Configure the first supported channel (37), a public address differing
           from the IUT in its most significant octet and non-connectable events.
        3. Send ADV_NONCONN_IND until twenty scan intervals pass or Step 4 occurs.
        4. Require at least one LE Advertising Report matching the packet data.
        5. Configure the second channel (38), a public address differing in its
           least significant octet and the specified ADV_SCAN_IND event type.
        6. Send ADV_SCAN_IND until Step 7 or thirty scan intervals elapse.
        7. Receive SCAN_REQ at T_IFS after ADV_SCAN_IND, then return SCAN_RSP at
           T_IFS after the request. Check both addresses/types, CRC, LE 1M PHY and
           request spacing within 2 us; response data carries the common LT name.
        8. Interleaved with Step 6, receive LE Advertising Report for ADV_SCAN_IND.
        9. Interleaved with Step 7, receive LE Advertising Report for SCAN_RSP,
           including its advertiser address and exact response data.
        10. Configure the third channel (39), a public address differing in both
            endpoint octets and directed advertising.
        11. Send ADV_DIRECT_IND with TargetA equal to the IUT until fifteen scan
            intervals pass or the current phase's report in Step 12 arrives.
        12. Receive LE Advertising Report containing the directed packet's data.
        13. Disable scanning with LE Set Scan Enable; require Command Complete.

    Expected Outcome:
        Pass verdict: complete every selected address/type phase and report the
        actual advertising contents. Non-connectable and directed events produce
        advertising reports but no SCAN_REQ; ADV_SCAN_IND produces both advertising
        and scan-response reports after the valid exchange. Reports match exact
        type, peer address/type and data without a fixed event order/grouping.

    Notes:
        The source permits listed-only or accept-all realizations. This one follows
        the explicit accept-all intro in an isolated PHY with no unrelated devices.

    Source Correction:
        Step 11 refers to the previous phase's Step 8; use the current directed
        report in Step 12 as its stop condition. Preserve the explicitly named
        ADV_SCAN_IND in Step 6: the pass prose's generic connectable wording does
        not introduce ADV_IND into that phase. Retain the explicit accept-all
        policy over conflicting initial prose. These are local interpretations,
        not adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4, unnumbered procedure, LL/DDI/SCN/BV-05-C; PDF
        pages 278-281, printed pages 4.2-185-4.2-188, Figure 4.2-81,
        Steps 1-13, pass verdict and Notes.
    """
    interval = SCAN_INTERVAL_US // hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    common, msb, lsb, both = _advertising_public_peer_addresses()
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(common.address_type, common)
    )
    await tester.command(
        scan_parameters(
            le_scan_type=1,
            scanning_filter_policy=0,
            le_scan_interval=interval,
            le_scan_window=interval,
        )
    )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))
    for channel, peer, kind, intervals in (
        (37, msb, AdvertisingPduType.ADV_NONCONN_IND, 20),
        (38, lsb, AdvertisingPduType.ADV_SCAN_IND, 30),
        (39, both, AdvertisingPduType.ADV_DIRECT_IND, 15),
    ):
        await _scan_phase(
            tester, channel, peer, kind, active=True, accepted=True, intervals=intervals
        )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))


async def passive_scanning_directed_events(tester):
    """Passive Scanning: Directed Events.

    Initial Condition:
        The IUT has a configured own address and passive scanning parameters,
        with a specific public peer in the Filter Accept List. The common peer's
        bits also form a valid random address; its most significant octet 0x12
        has top bits 00. Select a 20-ms advertising base with 5-ms mean AdvDelay
        and a 75-ms scan interval/window, three times the mean interval. Use
        policy 0x01 and TargetA equal to the IUT; disable duplicate filtering.

    Test Steps:
        1. Configure the first supported channel (37), ADV_DIRECT_IND targeting
           the IUT and a common public AdvA in the Filter Accept List whose bits
           could also represent a valid random address.
        2. Enable passive scanning in the IUT.
        3. Send ADV_DIRECT_IND on the selected channel for twenty scan intervals.
        4. Require LE Advertising Report with the directed event type and the
           configured public advertiser identity. Directed reports have no data.
        5. Disable scanning with LE Set Scan Enable; require Command Complete.
        6. Configure the second channel (38), TargetA equal to the IUT and an
           unlisted public AdvA, selected to differ in its least significant octet.
        7. Repeat Steps 2-5, but require no report in Step 4 for the full phase.
        8. Configure the third channel (39), TargetA equal to the IUT and random
           AdvA with exactly the same 48 address bits used in Step 1.
        9. Repeat Steps 2-5, but require no report in Step 4 for the full phase.

    Expected Outcome:
        Pass verdict: complete the selected channel/timing phases, reporting only
        the peer whose address and type both match the Filter Accept List. Do not
        report an unlisted address or the listed bytes with random type. Require
        no SCAN_REQ in every passive phase; observe all twenty scan intervals.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4, unnumbered procedure, LL/DDI/SCN/BV-11-C; PDF
        pages 281-283, printed pages 4.2-188-4.2-190, Figure 4.2-82,
        Steps 1-9 and the complete pass verdict.
    """
    await _scan_reports(
        tester, kind=AdvertisingPduType.ADV_DIRECT_IND, active=False, filtered=True
    )


async def passive_scanning_discoverable_events(tester):
    """Passive Scanning: Discoverable Events.

    Initial Condition:
        Configure the IUT address, passive scan parameters and Filter Accept
        List policy. The common public Lower Tester address is the only list
        entry. Select 20-ms minimum advertising interval plus a 0-10-ms
        AdvDelay averaging 5 ms. The 75-ms scan interval/window is three
        times the mean advertising interval; disable duplicate filtering.

    Test Steps:
        1. Select the first supported advertising channel and common public
           Lower Tester address.
        2. Enable scanning with LE Set Scan Enable; require Command Complete.
        3. Send ADV_SCAN_IND with event-counter data on that channel for
           twenty scan intervals.
        4. Require an Advertising Report with the transmitted event type and
           data matching a transmitted event counter.
        5. Select the second supported channel and a public advertiser address
           differing from the IUT address in the least significant octet.
        6. Send ADV_SCAN_IND with that address and event-counter data for
           twenty scan intervals.
        7. Require no Advertising Report for the Step 6 packets.
        8. Select the third supported channel and a random advertiser address
           differing from the IUT address in the most significant octet.
        9. Send ADV_SCAN_IND with the Step 8 random address and event-counter
           data for twenty scan intervals.
        10. Require no Advertising Report for the Step 9 packets.
        11. Select a supported channel and the common address with random type.
        12. Send ADV_SCAN_IND with the Step 11 random address and event-counter
            data for twenty scan intervals.
        13. Require no Advertising Report for the Step 12 packets.
        14. Disable scanning with LE Set Scan Enable; require successful
            Command Complete.

    Expected Outcome:
        Pass verdict:
            Report the Step 3 advertiser with matching address, type, event
            type and sequence data. Complete all selected-channel phases.
        Fail verdict:
            Any Advertising Report in Steps 7, 10 or 13 for an incorrect
            advertiser address or type.

    Source Correction:
        Step 9's 'public' address uses the random type configured in Step 8.
        Step 10 refers to current Step 9, not Step 6. Step 12 uses the newly
        configured Step 11 address, not Step 8. Step 14 returns Command
        Complete, not Command Status, per Core Vol 4 Part E 7.8.11.

    Coverage Note:
        Preserve passive scanning continuously through the four phases. Each
        phase covers all twenty intervals, including the positive phase; no
        SCAN_REQ is allowed. Check reports after each injected advertisement.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BV-12-C, Figure 4.2-83,
        Steps 1-14 and pass/fail verdicts; PDF 283-285, printed 4.2-190..192.
        Source reference [3] 4.4.3.1.
    """
    common, msb, lsb, _ = _advertising_public_peer_addresses()
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(common.address_type, common)
    )
    interval = SCAN_INTERVAL_US // hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    await tester.command(
        scan_parameters(
            le_scan_type=0,
            scanning_filter_policy=1,
            le_scan_interval=interval,
            le_scan_window=interval,
        )
    )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))
    for channel, peer in (
        (37, common),
        (38, lsb),
        (39, hci.Address(bytes(msb), hci.AddressType.RANDOM_DEVICE)),
        (37, hci.Address(bytes(common), hci.AddressType.RANDOM_DEVICE)),
    ):
        await _scan_phase(
            tester,
            channel,
            peer,
            AdvertisingPduType.ADV_SCAN_IND,
            active=False,
            accepted=peer == common,
            full_duration=True,
        )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))
    _check_scan_reports(tester, peer, AdvertisingPduType.ADV_SCAN_IND, set(), False)


async def extended_scanning_passive(tester, *, primary_phy, secondary_phy):
    """Extended Scanning, Passive.

    Initial Condition:
        The IUT uses passive scanning with accept-all filtering. The Lower Tester
        uses a common public address; directed packets target either the IUT or
        a different device, as specified by the round. Scan_Max_Data is 1650
        octets for this implementation.

        The selected Table 4.2-51 cases do not enable Advertising Coding Selection
        (Host Support). Execute rounds 1-18 for the 1M/1M pair and rounds 10-18
        for the other selected primary/secondary PHY pairs. Legacy PDUs occur
        only in the 1M/1M case. Coded transmissions use S=2 in odd-numbered
        rounds and S=8 in even-numbered rounds.

    Test Steps:
        1. For each assigned Table 4.2-52 round, send LE Set Extended Scan
           Parameters with the selected primary PHY, passive scan type, public
           own address, accept-all filtering, and interval/window 0x0010.
           Require successful Command Complete.
        2. Enable extended scanning with Filter_Duplicates and Period zero.
           Duration is zero except in round 16, which uses 0x01F4 (five seconds).
           Require successful Command Complete.
        3. Transmit the round's PDUs, addresses, TargetA, and data lengths using
           the selected PHYs. On Coded PHY, odd rounds use S=2 and even rounds
           S=8. Include AuxPtr whenever an auxiliary PDU follows. Put the table's
           fields in AUX_ADV_IND when present, except the explicit round 17
           placement and its Coded correction below. Populate AdvData with
           seeded random octets; fill each nonfinal PDU to capacity and link
           AUX_CHAIN_IND through AuxPtr. Omit TxPower from extended PDUs.
           With Duration zero, advertise for at least twenty intervals; otherwise
           continue through the round. Use the minimum base plus AdvDelay,
           deferring the next event if needed to avoid overlapping a long chain.
        4. Check every received report's event properties, address/type, PHYs,
           SID, TargetA, zero periodic interval, unavailable TxPower, data order,
           and fragment status for undirected or IUT-directed advertising. Coded
           PHY is reported as 0x03 without Host coding-selection support. Reject
           reports for another TargetA and any passive-scanner RF response.
        5. Follow the branch selected by Duration:
           5A.1. With Duration zero, repeat Step 4 until ten logical results have
                 been reported for accepted advertisements. Change AdvData, if
                 any, after a reported result; extended PDUs also change DID.
                 Wrong-target rounds instead require no reports throughout the
                 Step 3 twenty-interval observation.
           5A.2. Disable scanning with LE Set Extended Scan Enable and require
                 successful Command Complete (see command Source Correction).
           5B.1. With nonzero Duration, repeat Step 4 until that time elapses,
                 then receive LE Scan Timeout. Do not impose 5A.1's ten-report
                 threshold on this branch. Require at least one accepted report.

    Test Case Configuration:
        Table 4.2-52: rounds 1/2 use ADV_IND with 0/31 data octets; 3/4 use
        ADV_DIRECT_IND targeting IUT/Not IUT; 5/6 use ADV_NONCONN_IND with 0/31
        octets; 7/8/9 use primary-only ADV_EXT_IND, undirected/IUT/Not IUT.
        Rounds 10/11/12 use primary-plus-auxiliary PDUs with no data and the same
        three target choices. Rounds 13/14/15 carry 191/382/Scan_Max_Data octets.
        Round 16 is primary-only directed at the IUT with Duration 0x01F4 (5 s).
        Round 17 places AdvA in the primary and 31 data octets in the auxiliary
        for LE 1M; use the approved Coded correction below. Round 18 has 242
        first-auxiliary octets and 1403 chained octets. Other Durations are zero.

    Expected Outcome:
        Pass verdict:
            Undirected advertisements and those directed at the IUT produce LE
            Extended Advertising Report events with the correct properties,
            public advertiser identity, PHYs, SID, and directed-address fields.
            SID matches ADI when present and is 0xFF otherwise. Without Host
            coding-selection support, Coded PHY is reported as 0x03 for both
            S=2 and S=8. Advertisements directed elsewhere produce no reports.

            Data match the transmitted bytes in order. Intermediate fragments
            have Data_Status 0b01; the final fragment is complete (0b00) or
            truncated (0b10). Truncation occurs only at an AUX_CHAIN_IND
            boundary, never inside one PDU. Each accepted round includes at
            least one complete result for data within Scan_Max_Data.

            A nonzero Duration produces LE Scan Timeout and stops scanning;
            subsequent advertisements produce no reports. The passive scanner
            sends no scan request.

    Postamble:
        For timed round 16, send three more advertisements after Scan Timeout and
        require no reports, then disable extended scanning successfully. This
        confirms the stop behavior in the source pass verdict, without adding
        source step numbers. Every accepted round must have a complete data
        result at least once when its data fit within Scan_Max_Data.

    Source Correction:
        Step 5A.2 names legacy Scan Enable after extended scanning; use Extended
        Scan Enable to preserve the command-family boundary. Step 4's generic
        extended-secondary-PHY wording must mean zero when no secondary packet
        exists (rounds 7/8/9/16). Core Vol 4, Part E, 7.8.65 and 7.7.65.13
        support these corrections. Apply the ten-report loop only to accepted
        advertisements, since the wrong-target verdict explicitly forbids reports.
        Table 4.2-51 includes round 17 for Coded primary PHY cases BV-43-C,
        BV-134-C, and BV-135-C, but Table 4.2-52 puts AdvA only in ADV_EXT_IND.
        This contradicts Core Vol 6, Part B, Section 2.3.1.5, Table 2.4 C.1:
        primary AdvA with AuxPtr is RFU on LE Coded and must be ignored.
        These variants instead put AdvA in AUX_ADV_IND and retain the
        advertiser-address and 31-octet data verdicts.
        The reviewer previously approved this local correction; it does not
        establish the test author's intended erratum. LE 1M variants retain the
        original round 17 with AdvA only in ADV_EXT_IND. Amber corroborated the
        command, report-PHY and branch corrections but did not independently
        determine round 17's authored intent. None is an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.4, Tables 4.2-51 and 4.2-52; PDF pages
        294-299, printed pages 4.2-201 through 4.2-206. Selected cases:
        LL/DDI/SCN/BV-19-C, LL/DDI/SCN/BV-42-C, LL/DDI/SCN/BV-43-C,
        LL/DDI/SCN/BV-133-C, LL/DDI/SCN/BV-134-C, and LL/DDI/SCN/BV-135-C.
        Steps 1-5, including 5A.1/5A.2/5B.1 and the complete pass verdict.
        The round 17 source row is on PDF page 298, printed page 4.2-205.
        Core Vol 6, Part B, Section 2.3.1.5, Table 2.4 C.1 defines the primary
        address restriction; Section 2.3.1.6, Table 2.5 defines auxiliary fields.
    """
    generator = random.Random(0)
    rounds = ROUNDS if primary_phy == secondary_phy == Phy.LE_1M else ROUNDS[9:]
    for round_ in rounds:
        tester.output.write(f'SCAN ROUND {round_.number}\n')
        await tester.command(
            scan_parameters(
                extended=True,
                scanning_phys=1 << primary_phy - 1,
                scan_types=[0],
                scan_intervals=[SCANNING_SCAN_INTERVAL],
                scan_windows=[SCANNING_SCAN_INTERVAL],
            )
        )
        enabled_at = tester.radio.now_us
        await tester.command(
            hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, round_.duration, 0)
        )
        deadline = enabled_at + round_.duration * hci.HCI_LE_DURATION_UNIT_US
        coding = PHY_CODED_S2_FACTOR if round_.number % 2 else PHY_CODED_S8_FACTOR
        data = generator.randbytes(round_.length)
        did = reports = complete = 0
        start = tester.radio.now_us + REPORT_DELIVERY_US
        observation_start = start
        accepted = round_.target is None or round_.target == DUT_ADDRESS
        attempts = max(
            ADVERTISING_INTERVALS * REQUIRED_REPORTS,
            round_.duration
            * hci.HCI_LE_DURATION_UNIT_US
            // SCANNING_ADVERTISING_INTERVAL_US
            + 2,
        )
        for attempt in range(attempts):
            adi = ADVERTISING_SID << PDU_ADV_ADI_DID_BITS | did
            train, boundaries = _packets(
                round_, data, adi, primary_phy, secondary_phy, coding
            )
            for channel, phy, offset, wire in train:
                await tester.transmit(
                    channel, wire, start_us=start + offset, phy=phy, coding=coding
                )
            assert (
                await tester.receive(
                    train[-1][0], phy=train[-1][1], duration_us=REPORT_DELIVERY_US
                )
                is None
            ), f'round{round_.number}: passive scanner transmitted a response'
            seen, full = _scanning_check_reports(
                tester, round_, data, adi, primary_phy, secondary_phy, boundaries
            )
            reports += seen
            complete += full
            if any(
                isinstance(event, hci.HCI_LE_Scan_Timeout_Event)
                for event in tester.events
            ):
                assert (
                    round_.duration and tester.radio.now_us >= deadline
                ), 'premature Scan Timeout'
            if seen:
                data = generator.randbytes(round_.length)
                did += 1
            if round_.duration and tester.radio.now_us >= deadline:
                break
            if (
                not round_.duration
                and attempt + 1 >= ADVERTISING_INTERVALS
                and (
                    tester.radio.now_us - observation_start
                    >= ADVERTISING_INTERVALS * SCANNING_ADVERTISING_INTERVAL_US
                )
                and (not accepted or reports >= REQUIRED_REPORTS)
            ):
                break
            start = max(
                start
                + SCANNING_ADVERTISING_INTERVAL_US
                + generator.randrange(LL_ADV_DELAY_MAX_US + 1),
                tester.radio.now_us + LL_MAFS_US,
            )
        else:
            assert not round_.duration, 'scan duration failed to elapse'
        if accepted:
            required_reports = 1 if round_.duration else REQUIRED_REPORTS
            assert reports >= required_reports, (round_.number, reports)
            assert complete, f'round{round_.number}: no complete data result'
        else:
            assert not reports
        if round_.duration:
            await tester.event(hci.HCI_LE_Scan_Timeout_Event)
            for _ in range(3):
                await tester.transmit(37, train[0][3], phy=primary_phy, coding=coding)
                await tester.wait(SCANNING_ADVERTISING_INTERVAL_US)
                assert not any(isinstance(event, Report) for event in tester.events)
        await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))
        assert not any(isinstance(event, Report) for event in tester.events)


async def extended_scanning_active(tester, *, primary_phy, secondary_phy):
    """Extended Scanning, Active.

    Initial Condition:
        Active scanning uses public own address, accept-all policy 0x00 and
        continuous selected interval/window. Scan_Max_Data is 1650 octets.
        The six selected cases are Core 5.1 variants in Table 4.2-53: BV-64
        uses LE 1M/1M and rounds 1-10; BV-65/66/139/140/141 use the assigned
        primary/secondary PHY pairs and rounds 5-8. Core 5.0 variants and
        round 11 are not selected by the workbook. For every assigned round,
        skip that round if ScanData exceeds Scan_Max_Data.

    Test Steps:
        1. Set extended scan parameters with Scanning_PHYs from Table 4.2-53,
           active Scan_Type 1, interval/window 0x0010, public own address and
           accept-all policy. Require successful Command Complete.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        3. Advertise the Table 4.2-54 type on the assigned PHYs. Include AuxPtr
           for AUX_ADV_IND and place the specified AdvA/TargetA only in the
           auxiliary PDU. Use the common public LT address and the round's IUT
           or Not-IUT target. Repeat for at least twenty advertising intervals
           or until Step 4; use the minimum base interval plus seeded AdvDelay.
        4. For undirected or IUT-directed advertising, receive SCAN_REQ for
           legacy PDUs or AUX_SCAN_REQ for extended PDUs on the appropriate
           channel. ScanA is the IUT address and AdvA the LT address. Check CRC,
           PHY, exact addresses/types and T_IFS within 2 us. Receive the matching
           LE Extended Advertising Report with scan-response bit clear, complete
           status, zero periodic interval and empty advertising data. If TargetA
           is not the IUT, require no request/report and proceed to Step 7.
        5. Select the branch for the received request:
           5A.1. After SCAN_REQ, send SCAN_RSP at T_IFS with the table's ScanData,
                 populated with seeded random octets from 1 through 254.
           5B.1. After AUX_SCAN_REQ, send AUX_SCAN_RSP at T_IFS with AdvMode 00
                 and the same ScanData rule. If needed, include AuxPtr and
                 continue with AUX_CHAIN_IND; fill every nonfinal PDU to capacity.
        6. Receive one or more LE Extended Advertising Report events for the
           response, with scan-response bit set and zero periodic interval.
           Validate exact ordered ScanData and fragment status: intermediate
           reports incomplete-more and the final report complete, subject to
           the source pass verdict's chain-boundary truncation allowance.
        7. Disable scanning with LE Set Extended Scan Enable and require
           successful Command Complete (see Source Correction).

    Test Case Configuration:
        Table 4.2-54 rounds 1/2 use ADV_IND with 0/31 response octets; 3/4 use
        ADV_SCAN_IND with 0/31 response octets. Rounds 5/6/7 use scannable
        ADV_EXT_IND plus AUX_ADV_IND, one response octet, and no TargetA/IUT/Not
        IUT respectively. Round 8 uses 191 response octets, round 9 uses 382
        and round 10 uses Scan_Max_Data. AdvData stays empty in the scannable
        advertisement; ScanData is transmitted in the response and its chain.

    Expected Outcome:
        Pass verdict: accepted undirected/IUT-directed advertisements elicit a
        valid scan request and matching response reports. Reports retain correct
        properties, public address/type, primary/secondary PHYs, directed address
        when applicable and zero periodic interval. Step 4 reports have the
        advertisement's SID from ADI or 0xFF without ADI. For the selected Core
        5.1 cases, response SID comes from AUX_SCAN_RSP's ADI, or AUX_ADV_IND
        when absent; this realization sends the same valid ADI in both.
        Wrong-target directed advertisements produce neither requests nor reports.

        Response data match in order, whether reported whole, fragmented or
        truncated. Intermediate status is incomplete-more (01); final status
        is complete (00) or truncated-no-more (10). Truncation may occur only
        at an AUX_CHAIN_IND boundary, not inside a PDU. Every accepted round
        with data within Scan_Max_Data must yield one complete result at least
        once; retry whole events if earlier results were truncated. Do not
        impose a fixed report grouping.

    Source Correction:
        Step 7 names legacy LE Set Scan Enable after extended scan configuration;
        use LE Set Extended Scan Enable. Core Vol 4, Part E, 7.8.65 defines
        extended scan disable and 7.8.11 is legacy-only. Amber corroborates this
        command-family correction. This is a local correction, not an adopted
        SIG erratum. Table ScanData describes response contents, not data to
        insert into the scannable AUX_ADV_IND.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.5, LL/DDI/SCN/BV-139-C, LL/DDI/SCN/BV-140-C,
        LL/DDI/SCN/BV-141-C, LL/DDI/SCN/BV-64-C, LL/DDI/SCN/BV-65-C,
        LL/DDI/SCN/BV-66-C; PDF pages 299-304, printed pages 4.2-206-4.2-211,
        Tables 4.2-53/54, Figure 4.2-89, Steps 1-7 including 5A.1/5B.1 and
        the complete pass verdict.
    """
    rounds = (
        _ScanRound(1, kind=AdvertisingPduType.ADV_IND, auxiliary=False),
        _ScanRound(2, 31, AdvertisingPduType.ADV_IND, auxiliary=False),
        _ScanRound(3, kind=AdvertisingPduType.ADV_SCAN_IND, auxiliary=False),
        _ScanRound(4, 31, AdvertisingPduType.ADV_SCAN_IND, auxiliary=False),
        _ScanRound(5, 1),
        _ScanRound(6, 1, target=DUT_ADDRESS),
        _ScanRound(7, 1, target=PEER_ADDRESS),
        _ScanRound(8, 191),
        _ScanRound(9, 382),
        _ScanRound(10, SCAN_MAX_DATA),
    )
    generator = random.Random(0)
    if primary_phy != Phy.LE_1M or secondary_phy != Phy.LE_1M:
        rounds = rounds[4:8]
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    for round_ in rounds:
        if round_.length > SCAN_MAX_DATA:
            continue
        tester.output.write(f'ACTIVE SCAN ROUND {round_.number}\n')
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
        accepted = round_.target is None or round_.target == DUT_ADDRESS
        data = bytes(generator.randint(1, 254) for _ in range(round_.length))
        observation_start = tester.radio.now_us
        start = observation_start + REPORT_DELIVERY_US
        complete = False
        for attempt in range(ADVERTISING_INTERVALS * REQUIRED_REPORTS):
            adi = ADVERTISING_SID << PDU_ADV_ADI_DID_BITS | attempt
            channel = LL_ADV_PRIMARY_CHANNELS[0]
            if round_.auxiliary:
                await tester.transmit(
                    channel,
                    ext_pdu(
                        adi=adi,
                        mode=AdvertisingMode.SCANNABLE,
                        aux=aux_pointer(
                            AUXILIARY_CHANNEL, AUXILIARY_OFFSET_US, secondary_phy
                        ),
                    ),
                    start_us=start,
                    phy=primary_phy,
                )
                channel = AUXILIARY_CHANNEL
                end = await tester.transmit(
                    channel,
                    ext_pdu(
                        address=peer,
                        target=round_.target,
                        adi=adi,
                        mode=AdvertisingMode.SCANNABLE,
                    ),
                    start_us=start + AUXILIARY_OFFSET_US,
                    phy=secondary_phy,
                )
            else:
                end = await tester.transmit(
                    channel,
                    adv_pdu(round_.kind, address=peer, data=b''),
                    start_us=start,
                )
            phy = secondary_phy if round_.auxiliary else primary_phy
            request = await tester.receive(
                channel,
                duration_us=LL_IFS_US + phy.address_us + SCAN_RESPONSE_IFS_TOLERANCE_US,
                phy=phy,
            )
            seen, _ = _scanning_check_reports(
                tester,
                round_,
                b'',
                adi,
                primary_phy,
                secondary_phy,
                (),
                properties=(
                    _scanning_Flags.SCANNABLE_ADVERTISING if round_.auxiliary else 0
                ),
            )
            if not accepted:
                assert request is None, 'scan request for another TargetA'
            elif request:
                assert request.valid_crc and request.phy == phy
                assert request.pdu == request_pdu(
                    AdvertisingPduType.SCAN_REQ, peer, scanner=DUT_ADDRESS
                )
                assert (
                    abs(request.start_us - end - LL_IFS_US)
                    <= SCAN_RESPONSE_IFS_TOLERANCE_US
                )
                assert seen, 'no advertising report before scan response'
                if round_.auxiliary:
                    response_round = _ScanRound(round_.number, round_.length)
                    train, boundaries = _packets(
                        response_round,
                        data,
                        adi,
                        primary_phy,
                        secondary_phy,
                        PHY_CODED_S8_FACTOR,
                    )
                    for response_channel, response_phy, offset, wire in train[1:]:
                        await tester.transmit(
                            response_channel,
                            wire,
                            start_us=request.end_us
                            + LL_IFS_US
                            + offset
                            - AUXILIARY_OFFSET_US,
                            phy=response_phy,
                        )
                else:
                    boundaries = ()
                    await tester.transmit(
                        channel,
                        adv_pdu(AdvertisingPduType.SCAN_RSP, address=peer, data=data),
                        start_us=request.end_us + LL_IFS_US,
                    )
                await tester.wait(REPORT_DELIVERY_US)
                seen, complete = _scanning_check_reports(
                    tester,
                    round_,
                    data,
                    adi,
                    primary_phy,
                    secondary_phy,
                    boundaries,
                    properties=_scanning_Flags.SCAN_RESPONSE
                    | (
                        _scanning_Flags.SCANNABLE_ADVERTISING if round_.auxiliary else 0
                    ),
                )
                assert seen, 'no scan-response report'
                if complete:
                    break
            if (
                not accepted
                and attempt + 1 >= ADVERTISING_INTERVALS
                and (
                    tester.radio.now_us - observation_start
                    >= ADVERTISING_INTERVALS * SCANNING_ADVERTISING_INTERVAL_US
                )
            ):
                break
            start = max(
                start
                + SCANNING_ADVERTISING_INTERVAL_US
                + generator.randrange(LL_ADV_DELAY_MAX_US + 1),
                tester.radio.now_us + LL_MAFS_US,
            )
        assert complete == accepted, f'round{round_.number}: missing complete response'
        await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def extended_scanning_passive_reporting_tx_power(tester, *, phy):
    """Extended Scanning, Passive, Reporting TX Power.

    Initial Condition:
        Continuous passive scanning uses accept-all filtering and valid selected
        parameters. Scan_Max_Data is 1650 octets. Table 4.2-55 selects LE 1M/1M
        for BV-75 and Coded/Coded for BV-76. Use public addresses, minimum-base
        advertising and interval/window 0x0010. Select distinct Power1=-20 dBm
        and Power2=10 dBm. Each of four data chunks is min(100, Scan_Max_Data/4).

    Test Steps:
        1. Set extended scan parameters with the assigned Scanning_PHYs, passive
           Scan_Type 0, accept-all policy and other valid selected values;
           require successful Command Complete.
        2. Enable extended scanning with Period and Duration zero; require
           successful Command Complete. This realization also disables duplicates.
        3. Send ADV_EXT_IND with AuxPtr to AUX_ADV_IND, which has no AdvData
           and an AuxPtr to the first AUX_CHAIN_IND.
        4. Send four AUX_CHAIN_IND PDUs, each containing the selected count of
           seeded random octets. AUX_ADV_IND and chains 1-3 carry Power1;
           chain 4 carries the distinct Power2.
        5. Receive multiple LE Extended Advertising Report events with periodic
           interval zero and incomplete-more status (01) except the last.
           If the final report is truncated (10), discard the entire attempt
           and return to Step 3 before power, data or grouping verdicts. Fail on
           the tenth truncated attempt. The incomplete-report timeout remains
           applicable before a final report arrives.

    Expected Outcome:
        Pass verdict: multiple reports reproduce the four chunks in order, with
        all intermediate statuses incomplete-more and final status complete (00).
        Each TX_Power is Power1, Power2 or unavailable (0x7F). Also check correct
        event properties, public address/type, PHYs and SID.

        Fail verdict: no subsequent report within two seconds of an incomplete
        report; retry limit reached; Power2 reported before chain 4 was received;
        Power1 reported with chain 4 data or after Power2; or the first report
        containing bytes from any chain has unavailable TX_Power. Reject future,
        missing, reordered or duplicated data. Buffered or incremental reports
        are permitted; do not require one report per PDU.

    Postamble:
        Disable extended scanning successfully after a complete result.

    Source Correction:
        Step 5 explicitly fails on ten truncations, while the separate fail prose
        says more than ten. Use Step 5's explicit threshold. Amber supports this
        local precedence; it is not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.6, LL/DDI/SCN/BV-75-C, LL/DDI/SCN/BV-76-C;
        PDF pages 304-306, printed pages 4.2-211-4.2-213, Table 4.2-55,
        Figure 4.2-90, Steps 1-5 and every pass/fail condition.
    """
    await _reporting_power(tester, active=False, phy=phy)


async def extended_scanning_active_reporting_tx_power(tester, *, phy):
    """Extended Scanning, Active, Reporting TX Power.

    Initial Condition:
        Continuous active scanning uses public own address, accept-all policy and
        selected parameters. Scan_Max_Data is 1650 octets. Table 4.2-56 selects
        LE 1M/1M for BV-77 and Coded/Coded for BV-78. Response data total
        4 * 229 = 916 octets; mark inconclusive if this exceeds Scan_Max_Data.
        Select four distinct powers -20, -10, 0 and 10 dBm.

    Test Steps:
        1. Set extended scan parameters with the assigned Scanning_PHYs, active
           Scan_Type 1, interval/window 0x0010, public own address and accept-all
           policy; require successful Command Complete.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        3. Send scannable undirected ADV_EXT_IND with AuxPtr to AUX_ADV_IND.
           The auxiliary advertisement contains no advertising data.
        4. Receive LE Extended Advertising Report with event type 0b0000010:
           scannable undirected advertising and complete status.
        5. Receive AUX_SCAN_REQ with LT AdvA and IUT ScanA. Also validate CRC,
           public address types and T_IFS within 2 us after AUX_ADV_IND.
        6. Send AUX_SCAN_RSP at T_IFS with LT AdvA, Power1, 229 seeded random
           octets and an AuxPtr to the chain. Space response PDUs as far apart
           as practical, using the maximum representable 2,457,300-us offset.
        7. Send three AUX_CHAIN_IND PDUs with 229 seeded random octets each and
           distinct Power2, Power3 and Power4 respectively.
        8. Receive multiple LE Extended Advertising Report events with periodic
           interval zero, low event bits 0b01010, intermediate incomplete-more
           status (01) and a final complete status (00). Each report's TX_Power
           must equal the last PDU received at that report's observation boundary.

    Expected Outcome:
        Pass verdict: Step 8 produces multiple reports with the specified event
        properties/status and latest received TxPower. Data reproduce all four
        chunks in order and contain no not-yet-received bytes. Validate public
        identity, PHYs and SID, allowing buffered or incremental report grouping.
        Inconclusive verdict: response length exceeds the Scan_Max_Data IXIT.
        The passive-power procedure's two-second incomplete-report deadline does
        not apply to this active procedure and its widely spaced response chain.

    Postamble:
        Disable extended scanning successfully after the complete response.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.7, LL/DDI/SCN/BV-77-C, LL/DDI/SCN/BV-78-C;
        PDF pages 306-308, printed pages 4.2-213-4.2-215, Table 4.2-56,
        Figure 4.2-91, Steps 1-8 and pass/inconclusive verdicts.
    """
    await _reporting_power(tester, active=True, phy=phy)


async def periodic_advertising_report_rssi_power_and_data_status(tester, *, phy):
    """Extended Scanning, Passive, Periodic Advertising Report, RSSI, TX_Power, Data
    Status.

    Initial Condition:
        Continuous passive scanning uses public own address and accept-all policy.
        Scan_Max_Data is 1650 octets; N=min(100, Scan_Max_Data/3). Table 4.2-57
        selects LE 1M/1M for BV-79 and Coded/Coded for BV-80. Choose Power1=-20 dBm.
        The selected five-second periodic interval accommodates two maximum
        AuxPtr offsets and the complete chain.

    Test Steps:
        1. Set extended scan parameters with the assigned Scanning_PHYs, passive
           Scan_Type 0, interval/window 0x0010, public own address and accept-all
           policy; require successful Command Complete.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        3. Send ADV_EXT_IND with AuxPtr to AUX_ADV_IND on the selected PHY.
           AUX_ADV_IND contains LT AdvA and SyncInfo for AUX_SYNC_IND. Continue
           extended advertising throughout the test until the postamble.
        4. Receive LE Extended Advertising Report with nonzero periodic interval,
           complete status and valid RSSI. Check public peer identity, SID and PHYs.
        5. Send LE Periodic Advertising Create Sync with Options 0, the Step 3
           SID, public LT identity, Skip 3, Sync_CTE_Type 0 and timeout equal to
           (Skip+3) times the Step 4 periodic interval. Convert interval units
           (1.25 ms) to HCI timeout units (10 ms). Require successful Command Status.
        6. Send AUX_SYNC_IND containing N seeded random octets, Power1 and AuxPtr
           to the first AUX_CHAIN_IND.
        7. Receive successful LE Periodic Advertising Sync Established with a
           valid handle and the Step 3 SID before transmitting the chain. Also
           validate peer address/type, PHY, interval and clock-accuracy fields.
        8. Send two AUX_CHAIN_IND PDUs, each with
           min(249, (Scan_Max_Data-N)/2) seeded random octets. The first points to
           the second; the second has no AuxPtr. Space them as far apart as
           practical, using maximum 2,457,300-us AuxPtr offsets. Omit chain TxPower.
        9. Receive multiple LE Periodic Advertising Report events; these may
           begin before Step 8. Every intermediate Data_Status is incomplete-more
           (01), the final status is complete (00), all RSSIs are valid and the
           first report uses Power1. Later reports may use Power1 or 0x7F.

    Expected Outcome:
        Pass verdict: Step 9 produces multiple periodic reports with the specified
        status, RSSI and TxPower. Additionally check the correct sync handle, no
        CTE, exact ordered data and no bytes from a PDU not yet received. Do not
        require fixed report grouping or one report per received PDU.

    Postamble:
        Terminate the established synchronization and disable extended scanning,
        requiring successful command completion.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.8, LL/DDI/SCN/BV-79-C, LL/DDI/SCN/BV-80-C;
        PDF pages 309-311, printed pages 4.2-216-4.2-218, Table 4.2-57,
        Figure 4.2-92, Steps 1-9 and the complete pass verdict.
    """
    generator = random.Random(0)
    first_length = min(FIRST_DATA_LENGTH, SCAN_MAX_DATA // (CHAIN_COUNT + 1))
    chain_length = min(CHAIN_DATA_LENGTH, (SCAN_MAX_DATA - first_length) // CHAIN_COUNT)
    chunks = [generator.randbytes(first_length)] + [
        generator.randbytes(chain_length) for _ in range(CHAIN_COUNT)
    ]
    await tester.command(
        scan_parameters(
            extended=True,
            own_address_type=hci.AddressType.PUBLIC_DEVICE,
            scanning_filter_policy=0,
            scanning_phys=1 << phy - 1,
            scan_types=[0],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    train = PeriodicTrain(
        tester.radio.now_us + FIRST_ANCHOR_US,
        interval=PERIODIC_PERIODIC_INTERVAL,
        phy=phy,
    )
    next_advertisement = tester.radio.now_us + REPORT_DELIVERY_US
    records = []
    received = 0

    def take_reports():
        while event := tester.take(lambda event: isinstance(event, PeriodicReport)):
            records.append((received, event))

    async def announce_until(target):
        nonlocal next_advertisement
        while next_advertisement <= tester.radio.now_us:
            next_advertisement += PERIODIC_ADVERTISING_INTERVAL_US
        announcement = ext_pdu(
            address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
            adi=ADVERTISING_SID << PDU_ADV_ADI_DID_BITS,
            sync=bytes(PDU_ADV_SYNC_INFO_SIZE),
            data=b'announcement',
        )
        budget = (
            AUXILIARY_OFFSET_US + phy.airtime_us(len(announcement)) + REPORT_DELIVERY_US
        )
        while next_advertisement + budget < target:
            await train.announce(
                tester,
                start=next_advertisement,
                primary_phy=phy,
                address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                auxiliary_offset=AUXILIARY_OFFSET_US,
            )
            take_reports()
            next_advertisement += PERIODIC_ADVERTISING_INTERVAL_US

    report = None
    while (
        report is None
        and next_advertisement < train.anchor - PERIODIC_ADVERTISING_INTERVAL_US
    ):
        await announce_until(next_advertisement + PERIODIC_ADVERTISING_INTERVAL_US)
        event = tester.take(lambda event: isinstance(event, ExtendedReport))
        if event is not None:
            report = event.reports[0]
    assert report is not None, 'no periodic advertising announcement report'
    assert report.event_type == 0
    assert report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
    assert report.address_type == hci.AddressType.PUBLIC_DEVICE
    assert report.primary_phy == report.secondary_phy == phy
    assert report.periodic_advertising_interval == train.interval
    assert report.advertising_sid == ADVERTISING_SID
    assert -127 <= report.rssi <= 20
    timeout = (
        (PERIODIC_SKIP + 3)
        * train.interval
        * LL_PERIODIC_INTERVAL_UNIT_US
        // hci.HCI_LE_PERIODIC_SYNC_TIMEOUT_UNIT_US
    )
    await tester.command(
        create_sync(
            advertising_sid=report.advertising_sid,
            advertiser_address_type=report.address_type,
            advertiser_address=report.address,
            skip=PERIODIC_SKIP,
            sync_timeout=timeout,
        )
    )
    await announce_until(train.anchor)
    anchor, channel, parameters = (train.anchor, train.channel, train.parameters)
    await tester.transmit(
        channel,
        ext_pdu(
            tx_power=PERIODIC_POWER_DBM,
            data=chunks[0],
            aux=aux_pointer(channel, CHAIN_OFFSET_US, phy),
        ),
        start_us=anchor,
        **parameters,
    )
    received = 1
    take_reports()
    established = tester.take(lambda event: isinstance(event, SyncEstablished))
    assert established is not None, 'sync establishment delayed until the chain ends'
    assert established.status == hci.HCI_ErrorCode.SUCCESS
    assert 0 <= established.sync_handle <= SYNC_HANDLE_MAX
    assert established.advertising_sid == report.advertising_sid
    assert established.advertiser_address == report.address
    assert established.advertiser_address_type == report.address_type
    assert established.advertiser_phy == phy
    assert established.periodic_advertising_interval == train.interval
    assert established.advertiser_clock_accuracy == 0
    train.next_event()
    for index, chunk in enumerate(chunks[1:], 1):
        target = anchor + index * CHAIN_OFFSET_US
        await announce_until(target)
        await tester.transmit(
            channel,
            ext_pdu(
                data=chunk,
                aux=(
                    aux_pointer(channel, CHAIN_OFFSET_US, phy)
                    if index < CHAIN_COUNT
                    else None
                ),
            ),
            start_us=target,
            **parameters,
        )
        received = index + 1
        take_reports()
    await tester.wait(REPORT_DELIVERY_US)
    take_reports()
    _check_periodic_reports(records, chunks, established.sync_handle)
    await tester.command(
        hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(established.sync_handle)
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def extended_scanning_periodic_advertising_reception(
    tester, *, primary_phy, secondary_phy
):
    """Extended Scanning, Periodic Advertising Reception.

    Initial Condition:
        Continuous passive scanning uses public own address and accept-all policy.
        Scan_Max_Data is 1650 octets. Table 4.2-60 selects primary/secondary PHYs:
        BV-21 uses LE 1M/1M and rounds 1-9; BV-46/47/142/143/144 use their
        assigned PHY pairs and rounds 1-6 and 9. Each round starts a separate
        periodic train with the counter initially zero.

    Test Steps:
        1. Set extended scan parameters with the selected primary Scanning_PHYs,
           passive Scan_Type 0, interval/window 0x0010, public own address and
           accept-all policy; require successful Command Complete.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        3. Start ADV_EXT_IND with AuxPtr to AUX_ADV_IND on the assigned PHY.
           AUX_ADV_IND contains public LT AdvA and SyncInfo for AUX_SYNC_IND.
           Continue extended advertising until Step 10.
        4. Receive LE Extended Advertising Report with a nonzero periodic
           interval; verify the advertised SID, peer identity and PHYs.
        5. Start the periodic stream on independently computed CSA #2 channels.
           When data are nonempty, the first two octets are an unsigned 16-bit
           event counter initially zero and incremented for each periodic event;
           fill the remainder with seeded random octets. Use the round's length,
           link chains through AuxPtr and fill every nonfinal PDU to capacity.
           Continue all events, including those the IUT may skip, through Step 15.
        6. Send LE Periodic Advertising Create Sync with Options 0, the observed
           SID, public LT address/type, table Skip, Sync_CTE_Type 0 and timeout
           (Skip+3) times the periodic interval, converted to 10-ms HCI units.
           Require successful Command Status.
        7. Receive successful LE Periodic Advertising Sync Established with
           valid handle and peer/SID/PHY/interval/clock accuracy matching the train.
        8. Receive one or more LE Periodic Advertising Report events containing
           the transmitted data, with the source's Unused field set to 0xFF
           (now named CTE_Type; see Source Correction). Check handle, RSSI,
           data order, fragment status and legal chain-boundary truncation.
           Keep unfinished HCI data across delivery batches and the Step 10
           boundary; only a terminal Complete with exact reassembled data counts
           as one successful periodic event. Truncated or unfinished data do not.
        9. Repeat Step 8 until thirty serialized HCI report events in round 7
           or five in every other round have arrived.
        10. Stop extended advertising only; keep periodic advertising running.
        11. Continue receiving periodic reports as in Step 8.
        12. Repeat Step 11 until another thirty HCI report events in round 7,
            or another five in every other round, have arrived.
        13. Send LE Periodic Advertising Terminate Sync for the established
            handle; require successful Command Complete.
        14. Disable scanning with LE Set Extended Scan Enable; require successful
            Command Complete (see command Source Correction).
        15. Stop the Lower Tester periodic stream.

    Test Case Configuration:
        Table 4.2-61 lengths/Skip: round 1 is empty/0; rounds 2-5 are
        31/191/382/Scan_Max_Data octets with Skip 0. Rounds 6/7/8 use
        Scan_Max_Data with Skip 1/249/499; round 9 uses 31 octets with Skip 15.
        Select 40-ms periodic intervals for LE 1M/1M and 200 ms otherwise,
        allowing the full data train and continuing extended announcements.

    Expected Outcome:
        Pass verdict: synchronize successfully using CSA #2; report exact data in
        order; maintain synchronization after Step 10; stop reception after
        termination. Intermediate fragments are incomplete-more (01); the last
        is complete (00) or truncated (10), only at an AUX_CHAIN_IND boundary.
        At least one complete data result is required in every round.
        SID in Step 4 must match the transmitted advertisement.
        For rounds with data, consecutive logical counters differ by at most
        Skip+1 in at least floor(95% of comparisons), including the phase boundary.
        Require complete data for at least 80% of prepared receive opportunities
        in every round, including nonzero Skip. Derive those opportunities from
        the DUT's PHY receive requests for this train, counting each periodic
        event once even when it has multiple chain-reception requests. Count
        prepared events without a complete report as failures; exclude events
        actually skipped. Do not infer a fixed cadence from the maximum Skip.
        Measure from the first periodic transmission after Create Sync through
        Step 12, including unsuccessful prepared acquisition opportunities.

    Postamble:
        After successful termination and before disabling scanning, continue
        periodic traffic for Skip+1 events to cover the next allowed receive
        opportunity. Require no report, synchronization loss or new establishment.

    Source Correction:
        Step 14 names legacy Scan Enable after extended scan configuration; use
        Extended Scan Enable. The pass text's Event_Type for periodic reports
        means Data_Status. Step 8's older Unused octet is CTE_Type in the current
        HCI event; 0xFF denotes no CTE. These corrections follow the HCI event/
        command definitions and were corroborated with Amber; they are local
        corrections, not adopted SIG errata. The test owner confirmed the 80%
        metric means complete received data divided by prepared receive
        opportunities, excluding actual skipped events. HCI fragments must be
        reassembled into one complete data result; incomplete results earn no
        success. Apply this interpretation to both zero and nonzero Skip, with
        actual receive requests measured independently in the BabbleSim PHY log.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.10, LL/DDI/SCN/BV-142-C, LL/DDI/SCN/BV-143-C,
        LL/DDI/SCN/BV-144-C, LL/DDI/SCN/BV-21-C, LL/DDI/SCN/BV-46-C,
        LL/DDI/SCN/BV-47-C; PDF pages 317-322, printed pages 4.2-224-4.2-229,
        Tables 4.2-60/61, Figure 4.2-95, Steps 1-15 and every pass condition.
        Core Specification 6.3, Vol 4, Part E, 7.8.67 defines Skip;
        7.7.65.15 defines periodic report fields and fragmentation.
    """
    interval = (
        PERIODIC_INTERVAL_1M
        if primary_phy == secondary_phy == Phy.LE_1M
        else PERIODIC_INTERVAL_OTHER
    )
    interval_us = interval * LL_PERIODIC_INTERVAL_UNIT_US
    for number, (length, skip) in enumerate(RECEPTION_ROUNDS, 1):
        if number in (7, 8) and (not primary_phy == secondary_phy == Phy.LE_1M):
            continue
        tester.events[:] = [
            event for event in tester.events if not isinstance(event, AdvertisingReport)
        ]
        tester.output.write(f'PERIODIC RECEPTION ROUND {number}\n')
        await tester.command(
            scan_parameters(
                extended=True,
                scanning_phys=1 << primary_phy - 1,
                scan_types=[0],
                scan_intervals=[SCANNING_SCAN_INTERVAL],
                scan_windows=[SCANNING_SCAN_INTERVAL],
            )
        )
        await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
        train = PeriodicTrain(
            tester.radio.now_us + max(interval_us, ACQUISITION_LEAD_US),
            interval=interval,
            phy=secondary_phy,
        )
        advertiser = PeriodicAdvertiser(
            train,
            tester.radio.now_us + REPORT_DELIVERY_US,
            PERIODIC_RECEPTION_ADVERTISING_INTERVAL_US,
            auxiliary_offset_us=AUXILIARY_OFFSET_US,
            primary_phy=primary_phy,
        )
        announcement = None
        while (
            advertiser.next_advertisement + PERIODIC_RECEPTION_ADVERTISING_INTERVAL_US
            < train.anchor
        ):
            await advertiser.announce_until(
                tester,
                advertiser.next_advertisement
                + PERIODIC_RECEPTION_ADVERTISING_INTERVAL_US,
            )
            await tester.wait(REPORT_DELIVERY_US)
            announcement = tester.take(
                lambda event: isinstance(event, AdvertisingReport)
            )
            if announcement is not None:
                break
        assert announcement is not None, 'no periodic advertiser announcement'
        report = announcement.reports[0]
        assert report.event_type == 0
        assert report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
        assert report.address_type == hci.AddressType.PUBLIC_DEVICE
        assert report.advertising_sid == ADVERTISING_SID
        assert (
            report.primary_phy == primary_phy and report.secondary_phy == secondary_phy
        )
        assert report.periodic_advertising_interval == interval
        await tester.command(
            create_sync(
                options=0,
                advertising_sid=report.advertising_sid,
                advertiser_address_type=report.address_type,
                advertiser_address=report.address,
                skip=skip,
                sync_timeout=(skip + 3)
                * interval_us
                // hci.HCI_LE_PERIODIC_SYNC_TIMEOUT_UNIT_US,
                sync_cte_type=0,
            )
        )
        generator = random.Random(number)
        handle = None
        transmitted = {}
        measured = []
        results = _PeriodicReceptionResults(length)
        required = SKIP_ROUND_REPORT_EVENTS if number == 7 else REQUIRED_REPORT_EVENTS
        for advertising in (True, False):
            advertiser.advertising = advertising
            report_events = 0
            for _ in range(required * (skip + 1) * RECEPTION_ATTEMPT_FACTOR):
                counter = train.counter
                data = (
                    counter.to_bytes(DATA_COUNTER_SIZE, 'little')
                    + generator.randbytes(length - DATA_COUNTER_SIZE)
                    if length
                    else b''
                )
                packets = list(train.packets(data))
                consumed = 0
                boundaries = []
                for _, wire in packets[:-1]:
                    consumed += len(decode_extended(wire)['data'])
                    boundaries.append(consumed)
                frame = SimpleNamespace(
                    counter=counter,
                    start_us=train.anchor,
                    end_us=train.anchor
                    + packets[-1][0]
                    + secondary_phy.airtime_us(len(packets[-1][1])),
                    data=data,
                    boundaries=tuple(boundaries),
                )
                assert (
                    counter not in transmitted
                ), 'periodic counter wrapped during a round'
                transmitted[counter] = frame
                measured.append(frame)
                await advertiser.transmit(tester, data)
                await tester.wait(REPORT_DELIVERY_US)
                if handle is None:
                    established = tester.take(
                        lambda event: isinstance(event, SyncEstablished)
                    )
                    if established is not None:
                        assert established.status == hci.HCI_ErrorCode.SUCCESS
                        assert 0 <= established.sync_handle <= SYNC_HANDLE_MAX
                        assert established.advertising_sid == ADVERTISING_SID
                        assert established.advertiser_address == report.address
                        assert (
                            established.advertiser_address_type == report.address_type
                        )
                        assert established.advertiser_phy == secondary_phy
                        assert established.periodic_advertising_interval == interval
                        assert established.advertiser_clock_accuracy == 0
                        handle = established.sync_handle
                records = []
                while event := tester.take(
                    lambda event: isinstance(event, PeriodicReport)
                ):
                    records.append(event)
                assert not any(
                    isinstance(event, (SyncLost, SyncEstablished))
                    for event in tester.events
                ), 'periodic reception lost or duplicated synchronization'
                if records:
                    assert (
                        handle is not None
                    ), 'periodic report preceded Sync Established'
                    results.collect(records, transmitted, handle)
                    report_events += len(records)
                if report_events >= required:
                    break
            assert report_events >= required, (number, advertising, report_events)
        assert results.complete, 'the round never reported its complete periodic data'
        if length:
            _check_counters(results.counters, skip)
        await tester.command(
            hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle)
        )
        for _ in range(skip + 1):
            data = (
                train.counter.to_bytes(DATA_COUNTER_SIZE, 'little')
                + generator.randbytes(length - DATA_COUNTER_SIZE)
                if length
                else b''
            )
            await advertiser.transmit(tester, data)
            await tester.wait(REPORT_DELIVERY_US)
            assert not any(
                isinstance(event, (PeriodicReport, SyncLost, SyncEstablished))
                for event in tester.events
            )
        await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))
        with (tester.phy_results / 'd_2G4_00.Rx.csv').open() as capture:
            prepared = _periodic_reception_opportunities(
                capture, measured, interval_us, train.access_address
            )
        results.check_rate(prepared)
        tester.output.write(
            f'PERIODIC RECEPTION round={number} skip={skip} '
            f'complete={results.complete} prepared={len(prepared)} '
            f'transmitted={len(measured)} pending_fragments={len(results.pending)}\n'
        )


@pytest.mark.radio_peers(6, factory=_AdvertisingPeer)
async def extended_scanning_multiple_sets_passive_multiple_phys_all_supported_phys(
    tester,
):
    """Extended Scanning, Multiple Sets, Passive, Multiple PHYs (All Supported PHYs).

    Initial Condition:
        Passive scanning uses public own address, accept-all policy and selected
        interval/window on all supported primary PHYs. Scan_Max_Data is 1650
        octets. This DUT supports LE 1M and Coded scanning and LE 1M/2M/Coded
        auxiliary reception, so the unsupported-PHY conditional is not activated.
        Repeat the complete procedure for both Table 4.2-62 data-length rounds:
        191 octets and Scan_Max_Data.

    Test Steps:
        1. Set extended scan parameters with all supported Scanning_PHYs. For
           each primary PHY use passive Scan_Type 0, interval 0x0010 times the
           number of scan PHYs and window 0x0010, public own address and accept-all
           policy. Require successful Command Complete. The two primary PHYs
           therefore use interval 0x0020 and window 0x0010.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        3. Start six advertising sets with distinct SIDs: sets 1/2 use 1M/1M,
           3/4 use Coded/Coded and 5/6 use 1M/2M. ADV_EXT_IND points to
           AUX_ADV_IND containing public LT AdvA and seeded random AdvData of
           the round's length. Chain remaining data through AuxPtr and fill
           each nonfinal PDU to capacity. Repeat for at least twenty advertising
           intervals or until Step 4 occurs for every supported set.
        4. For each set, receive one or more LE Extended Advertising Report
           events with matching type, SID, primary/secondary PHYs, zero periodic
           interval and exact data. Track interleaved fragments separately for
           each SID and require one complete data result from each set.
        5. Disable scanning with LE Set Extended Scan Enable and require
           successful Command Complete (see Source Correction).

    Expected Outcome:
        Pass verdict: every set using supported PHYs is reported with exact
        identity, properties, SID, PHYs and ordered data. Intermediate fragments
        are incomplete-more (01); the final fragment is complete (00), or
        truncated (10) only at an AUX_CHAIN_IND boundary. At least once per set
        and round, data within Scan_Max_Data are not truncated. A passive scanner
        sends no requests. The conditional unsupported-PHY verdict requires no
        reports/data for such advertisements; all assigned PHYs are supported here.

    Source Correction:
        Step 5 names legacy Scan Enable after extended scan configuration; use
        Extended Scan Enable, as defined by Core Vol 4, Part E, 7.8.65. Amber
        corroborated this local command correction; it is not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BV-23-C; PDF pages 322-325,
        printed pages 4.2-229-4.2-232, Table 4.2-62, Figure 4.2-96,
        Steps 1-5 and every pass condition.
    """
    await _multiple_scanning(tester, active=False)


@pytest.mark.radio_peers(6, factory=_AdvertisingPeer)
async def extended_scanning_multiple_sets_active_multiple_phys_all_supported_phys(
    tester,
):
    """Extended Scanning, Multiple Sets, Active, Multiple PHYs (All Supported PHYs).

    Initial Condition:
        Active scanning uses public own address, accept-all policy and selected
        interval/window on all supported primary PHYs. Scan_Max_Data is 1650
        octets. This DUT supports all assigned primary/secondary PHY pairs.
        Execute both Table 4.2-64 rounds, with 191 and Scan_Max_Data response
        octets. The selected BV-62 uses the Core 5.1 SID expectation in Table
        4.2-63; the Core 5.0 BV-24 variant is not selected.

    Test Steps:
        1. Set extended scan parameters for all supported primary PHYs, with
           active Scan_Type 1, interval 0x0010 times the scan-PHY count, window
           0x0010, public own address and accept-all policy. Require successful
           Command Complete. This realization uses 0x0020/0x0010 per PHY.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        3. Start six distinct-SID scannable sets: 1/2 use 1M/1M, 3/4 Coded/Coded
           and 5/6 1M/2M. ADV_EXT_IND has AuxPtr to AUX_ADV_IND; put public
           LT AdvA only in the auxiliary PDU and no advertising data. Repeat
           until twenty advertising intervals or Step 4 for the supported sets.
        4. Receive AUX_SCAN_REQ on each set's appropriate channel/PHY, with
           IUT ScanA and LT AdvA. Also validate public types, CRC and T_IFS.
        5. Respond at T_IFS with AUX_SCAN_RSP, AdvMode 00, seeded random octets
           from 1 through 254 and the set ID as the first data octet. Omit ADI
           from the response. Chain remaining data through AuxPtr, filling each
           nonfinal PDU to capacity; response chains also omit ADI.
        6. Receive LE Extended Advertising Report events for each response with
           scan-response bit set, periodic interval zero and exact ordered data.
           Reassemble interleaved fragments per SID and response/advertising type.
        7. Disable scanning with LE Set Extended Scan Enable and require
           successful Command Complete (see Source Correction).

    Expected Outcome:
        Pass verdict: each supported set elicits a correctly addressed request
        and response reports with low event bits 01010, matching set identity,
        PHYs and exact data. Intermediate fragments use incomplete-more (01);
        the final report is complete (00) or truncated (10) only at a chain
        boundary. Require a complete result at least once for every set and round.
        For BV-62 the reported SID matches the response's first octet; with no
        response ADI it is inherited from the matching advertising-set context,
        not invented as zero. Unsupported PHYs would produce neither requests
        nor reports; this conditional is not activated for the supported matrix.

    Source Correction:
        Step 7's legacy Scan Enable must be Extended Scan Enable. The pass text
        calls intermediate status incomplete-more but gives bits 0b10; use the
        HCI-defined 0b01, retaining 0b10 for truncation only. Amber corroborated
        both local corrections against Core Vol 4, Part E, 7.8.65 and 7.7.65.13;
        they are not adopted SIG errata. Table ScanData describes response data,
        not data to place in scannable AUX_ADV_IND.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.11, LL/DDI/SCN/BV-62-C; PDF pages
        325-328, printed pages 4.2-232-4.2-235, Tables 4.2-63/64,
        Figure 4.2-97, Steps 1-7 and every pass condition.
    """
    await _multiple_scanning(tester, active=True)


async def multiple_periodic_advertisers_all_supported_phys(
    tester,
):
    """Extended Scanning, Multiple Sets, Periodic Advertising Reception, Multiple PHYs
    (All Supported PHYs).

    Initial Condition:
        Continuous passive scanning uses public own address and accept-all policy.
        Scan_Max_Data is 1650 octets. This DUT supports all assigned PHY pairs
        and at least six simultaneous periodic synchronizations. Execute all five
        Table 4.2-65 data-length rounds: empty, 31, 191, 382 and Scan_Max_Data.
        Each set has a distinct SID, valid Access Address/CRC and independent
        CSA #2 train. Use seeded random data octets from 1 through 254.

    Test Steps:
        1. Set extended scan parameters for all supported primary PHYs, passive
           Scan_Type 0, interval 0x0010 times the scan-PHY count, window 0x0010,
           public own address and accept-all policy; require successful Command
           Complete. Two scan PHYs use interval/window 0x0020/0x0010.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        3. Start six extended sets with distinct SIDs: 1/2 use 1M/1M, 3/4
           Coded/Coded and 5/6 1M/2M. ADV_EXT_IND points to AUX_ADV_IND with
           public LT AdvA and SyncInfo for the corresponding AUX_SYNC_IND.
           Continue each set's extended announcements until its Step 9.
        4. Receive extended reports with SID and nonzero periodic interval for
           each supported set. On the first report for a set, start its Steps
           6-12 while continuing discovery of others. Serialize Step 6; permit
           previously established sets' Steps 7-12 to progress concurrently.
        5. Generate AUX_SYNC_IND and any needed AUX_CHAIN_IND for every train
           on its independently computed CSA #2 channels. Use the round's
           random data length and fill each nonfinal PDU to capacity. Continue
           all periodic trains until Step 14.
        6. Acquire each discovered set:
           6a. Send LE Periodic Advertising Create Sync with Options 0, the
               observed SID, public LT identity and timeout ten times the
               observed periodic interval, converted to HCI units. The source's
               Unused octet is zero; select Skip 0 and Sync_CTE_Type 0.
           6b. Receive successful Command Status.
           6c. Wait for successful Sync Established with valid distinct handle
               and matching peer/SID/PHY/interval/clock accuracy.
           6d. If Command Status or Sync Established reports a synchronization
               capacity limit, defer this acquisition until another set finishes
               Step 12, then retry. This conditional is not activated for the
               selected DUT, which accommodates all six sets; no synthetic
               resource-exhaustion behavior is substituted.
        7. Receive periodic report events containing the transmitted data, with
           the source's Unused octet 0xFF (current CTE_Type). Validate handle,
           RSSI, unavailable TxPower, fragment status and exact data order.
        8. Continue Step 7 until at least one hundred serialized HCI report
           events have arrived for that set.
        9. Stop that set's extended advertising only; continue its periodic train.
        10. Continue periodic reports on the same synchronization as in Step 7.
        11. Continue Step 10 until another one hundred HCI report events arrive.
        12. Terminate that set's synchronization and require successful Command
            Complete. Continue other sets without loss or extra establishment.
        13. After Step 12 completes for every supported set, disable extended
            scanning and require successful Command Complete.
        14. Stop periodic advertising on all sets.

    Expected Outcome:
        Pass verdict: every supported set synchronizes successfully, reports its
        correct data and remains synchronized after its own announcements stop.
        Periodic reception ends on that set's termination command. HCI fragments
        are incomplete-more (01) followed by complete (00), or a final truncated
        result (10) only at a chain boundary. Every set/round must have at least
        one complete data result within Scan_Max_Data. Unsupported PHYs would
        produce no periodic reports; all assigned PHYs are supported here.
        Extended-report SID matches the corresponding advertised SID from Step 3.
        Do not count reassembled data sets as the one hundred serialized reports.

    Source Correction:
        Step 5's ADV_SYNC_IND means AUX_SYNC_IND. The periodic-data pass text's
        Extended Advertising Report and Event_Type mean Periodic Advertising
        Report and Data_Status. Its final SID reference to Step 5 means the
        advertising/discovery context in Steps 3/4, not a SID in periodic PDUs.
        Old Unused labels correspond to current Sync_CTE_Type/CTE_Type with the
        stated values unchanged. Amber corroborated these mechanical corrections
        and the conditional capacity branch. They are local corrections, not
        adopted SIG errata; no limited-capacity receiver path is claimed.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BV-25-C; PDF pages 328-332,
        printed pages 4.2-235-4.2-239, Table 4.2-65, Figure 4.2-98,
        Steps 1-14 including 6a-6d and every pass condition.
        Core Specification 6.3, Vol 4, Part E, 7.8.67 and 7.7.65.15 define
        synchronization command parameters and periodic report fields.
    """
    for length in (0, 31, 191, 382, SCAN_MAX_DATA):
        tester.events[:] = [
            event for event in tester.events if not isinstance(event, Report)
        ]
        await _enable_scan(tester, active=False)
        advertisers = _periodic_sets(tester, length)
        payloads = []
        for index in range(6):
            generator = random.Random(index + 1)
            payloads.append(bytes(generator.randint(1, 254) for _ in range(length)))
        delays = random.Random(0)
        handles, seen, done = ({}, set(), set())
        counts = [0] * 6
        phases = [0] * 6
        complete = [False] * 6
        pending = None
        for _ in range(2000):
            index = min(range(6), key=lambda item: advertisers[item].train.anchor)
            target = advertisers[index].train.anchor
            while True:
                enabled = [item for item in range(6) if advertisers[item].advertising]
                if not enabled:
                    break
                candidate = min(
                    enabled, key=lambda item: advertisers[item].next_advertisement
                )
                advertiser = advertisers[candidate]
                start = max(advertiser.next_advertisement, tester.radio.now_us + 100)
                if start + AUXILIARY_OFFSET_US + 5000 >= target:
                    break
                await advertiser.train.announce(
                    tester,
                    sid=advertiser.sid,
                    start=start,
                    primary_phy=advertiser.primary_phy,
                    address=advertiser.address,
                    auxiliary_offset=AUXILIARY_OFFSET_US,
                )
                advertiser.next_advertisement = (
                    start
                    + advertiser.advertising_interval_us
                    + delays.randrange(LL_ADV_DELAY_MAX_US + 1)
                )
                await tester.wait(REPORT_DELIVERY_US)
                while event := tester.take(lambda event: isinstance(event, Report)):
                    for report in event.reports:
                        sid = report.advertising_sid
                        assert (
                            1 <= sid <= 6
                            and report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
                        )
                        assert report.address_type == hci.AddressType.PUBLIC_DEVICE
                        assert (report.primary_phy, report.secondary_phy) == PHY_PAIRS[
                            sid - 1
                        ]
                        assert (
                            report.periodic_advertising_interval
                            == advertisers[sid - 1].train.interval
                        )
                        assert report.event_type == 0
                        seen.add(sid - 1)
                if pending is None:
                    available = sorted(seen - handles.keys())
                    if available:
                        pending = available[0]
                        item = advertisers[pending]
                        await tester.command(
                            create_sync(
                                options=0,
                                advertising_sid=item.sid,
                                advertiser_address_type=hci.AddressType.PUBLIC_DEVICE,
                                advertiser_address=item.address,
                                skip=0,
                                sync_timeout=10
                                * item.train.interval
                                * LL_PERIODIC_INTERVAL_UNIT_US
                                // hci.HCI_LE_PERIODIC_SYNC_TIMEOUT_UNIT_US,
                                sync_cte_type=0,
                            )
                        )
            train = advertisers[index].train
            boundaries = []
            consumed = 0
            for _, wire in list(train.packets(payloads[index]))[:-1]:
                consumed += len(decode_extended(wire)['data'])
                boundaries.append(consumed)
            await train.transmit(tester, payloads[index])
            await tester.wait(REPORT_DELIVERY_US)
            if established := tester.take(
                lambda event: isinstance(event, SyncEstablished)
            ):
                assert (
                    pending == index and established.status == hci.HCI_ErrorCode.SUCCESS
                )
                assert established.advertising_sid == index + 1
                assert established.advertiser_address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
                assert (
                    established.advertiser_address_type == hci.AddressType.PUBLIC_DEVICE
                )
                assert 0 <= established.sync_handle <= SYNC_HANDLE_MAX
                assert established.advertiser_clock_accuracy == 0
                assert (
                    established.advertiser_phy == train.phy
                    and established.periodic_advertising_interval == train.interval
                )
                assert established.sync_handle not in handles.values()
                handles[index] = established.sync_handle
                pending = None
            reports = []
            while event := tester.take(lambda event: isinstance(event, PeriodicReport)):
                assert (
                    index in handles
                    and index not in done
                    and (event.sync_handle == handles[index])
                )
                reports.append(event)
            if reports:
                complete[index] |= _periodic_reception_check_reports(
                    reports, payloads[index], boundaries, handles[index]
                )
                counts[index] += len(reports)
                if counts[index] >= 100:
                    if phases[index] == 0:
                        phases[index] = 1
                        counts[index] = 0
                        advertisers[index].advertising = False
                    else:
                        assert complete[
                            index
                        ], 'no complete periodic result for this set'
                        await tester.command(
                            hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(
                                handles[index]
                            )
                        )
                        done.add(index)
            assert not any(
                isinstance(event, (SyncLost, SyncEstablished))
                for event in tester.events
            )
            if len(done) == 6:
                break
        assert len(done) == 6, (length, handles, counts, phases)
        await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def extended_scanning_periodic_advertising_reception_filter_policies(tester):
    """Extended Scanning, Periodic Advertising Reception, Filter Policies.

    Initial Condition:
        Start idle with Scan_Max_Data 1650 octets. Use public addresses, one
        LE 1M periodic train and data fitting one AUX_SYNC_IND. Select a 100-ms
        periodic interval; negative list phases are observed for ten intervals.
        That observation window is a harness choice, not a normative timeout.

    Test Steps:
        1. Add a seeded random public address different from the LT address to
           the Filter Accept List; require successful Command Complete.
        2. Set extended scan parameters: LE 1M primary PHY, passive Scan_Type 0,
           interval/window 0x0010, public own address and filter policy 0x01;
           require successful Command Complete.
        3. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        4. Begin non-connectable, non-scannable undirected ADV_EXT_IND with
           AuxPtr to AUX_ADV_IND on LE 1M. The auxiliary contains LT AdvA
           and SyncInfo. Continue extended advertisements throughout the test.
        5. Generate periodic AUX_SYNC_IND on independent CSA #2 channels with
           data fitting one PDU; continue the train throughout the test.
        6. Send Periodic Advertising Create Sync with Options bit 0 clear, the
           LT SID/public address, Skip 0, timeout three periodic intervals and
           the source's Unused octet zero (current Sync_CTE_Type). Require
           successful Command Status.
        7. Receive successful Sync Established with matching peer/SID/PHY/
           interval/clock accuracy and a valid handle.
        8. Receive periodic report data matching the transmitted packet, with
           the source's Unused octet 0xFF (current CTE_Type), complete status,
           matching handle and valid RSSI.
        9. Terminate the synchronization; require successful Command Complete.
        10. Clear the Periodic Advertiser List, then add the correct public LT
            address and SID; require successful Command Complete for both.
        11. Repeat Steps 6-9 with Options bit 0 set to Use Advertiser List.
        12. Repeat Step 10 with a different advertiser address.
        13. Repeat Step 6 with Use Advertiser List and require no synchronization
            to the LT advertisements during the selected negative window.
        14. Send Create Sync Cancel; require successful Command Complete.
        15. Repeat Step 10 with the correct LT address but a different SID.
        16. Repeat Step 6 with Use Advertiser List and require no synchronization
            during the selected negative window.
        17. Send Create Sync Cancel; require successful Command Complete.

    Expected Outcome:
        Pass verdict: first and second Create Sync executions synchronize and
        report correct periodic data; third and fourth do not synchronize.
        Fail verdict: any LE Extended Advertising Report anywhere in the test.
        The scan Filter Accept List remains unrelated to the LT, even when direct
        selection or the separate Periodic Advertiser List successfully acquires it.

    Additional Core Checks:
        Wrong-list searches remain pending across the ten-interval observation,
        which exceeds the three-interval Sync_Timeout: that parameter is not a
        discovery-search deadline before a matching candidate is found.
        Following each successful cancel Command Complete, additionally require
        Sync Established with Operation Cancelled by Host (0x44), as specified
        by Core 7.8.68. This event is additional to source Steps 14/17.

    Postamble:
        Stop announcements and disable extended scanning successfully.

    Source Correction:
        Step 5's SyncInfo reference to Step 3 means the advertising setup in
        Step 4. SID belongs to the extended advertising/discovery context, not
        the periodic data PDU. Modernize the Unused field names without changing
        their stated values. Amber corroborated these local term/reference
        corrections; none is an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BV-34-C; PDF pages 345-349,
        printed pages 4.2-252-4.2-256, Figures 4.2-102/103, Steps 1-17
        and pass/fail verdicts. Core Specification 6.3, Vol 4, Part E,
        7.8.67/7.8.68 define selection, timeout and cancellation behavior.
    """
    foreign = hci.Address(random.Random(0).randbytes(6), hci.AddressType.PUBLIC_DEVICE)
    assert foreign != LOWER_PERIPHERAL_PUBLIC_ADDRESS
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(
            foreign.address_type, foreign
        )
    )
    advertiser = await _start_advertiser(tester, filtered=True)
    await advertiser.transmit(tester, b'before-sync')
    assert not any(isinstance(event, ExtendedReport) for event in tester.events)
    for index, (address, sid) in enumerate(
        (
            (LOWER_PERIPHERAL_PUBLIC_ADDRESS, ADVERTISING_SID),
            (LOWER_PERIPHERAL_PUBLIC_ADDRESS, ADVERTISING_SID),
            (foreign, ADVERTISING_SID),
            (LOWER_PERIPHERAL_PUBLIC_ADDRESS, ADVERTISING_SID + 1),
        )
    ):
        if index:
            await tester.command(hci.HCI_LE_Clear_Periodic_Advertiser_List_Command())
            await tester.command(
                hci.HCI_LE_Add_Device_To_Periodic_Advertiser_List_Command(
                    address.address_type, address, sid
                )
            )
        await tester.command(_sync_command(use_list=bool(index)))
        if index < 2:
            handle = await _transmit_report(tester, advertiser, filtered=True)
            await tester.command(
                hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle)
            )
        else:
            for _ in range(FILTER_OBSERVATION_EVENTS):
                await advertiser.transmit(tester, b'unmatched-periodic-data')
                assert not any(
                    isinstance(
                        event,
                        (SyncEstablished, SyncLost, PeriodicReport, ExtendedReport),
                    )
                    for event in tester.events
                ), 'unmatched advertiser search must remain pending'
            await tester.command(
                hci.HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command()
            )
            canceled = await tester.event(SyncEstablished)
            assert canceled.status == ErrorCode.OPERATION_CANCELLED_BY_HOST_ERROR
        assert not any(isinstance(event, ExtendedReport) for event in tester.events)
    advertiser.advertising = False
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


# LL/DDI/SCN/BV-37-C: omit six initial events, then send the seventh onward.
FIRST_SYNC_MISSED_EVENTS = 6
# Leave a full second for the first SyncInfo to arrive before event one.
FIRST_SYNC_LEAD_US = 1000000


async def first_aux_sync_ind_never_received(tester):
    """First AUX_SYNC_IND Never Received.

    Initial Condition:
        Public-address passive scanning uses LE 1M, accept-all policy and
        selected continuous interval/window. Scan_Max_Data is 1650 octets.
        Select Skip 0, periodic interval 150 ms and extended advertising
        interval 50 ms. The first periodic anchor is initially 1 s ahead.

    Test Steps:
        1. Set extended scan parameters: LE 1M, passive Scan_Type 0, interval/
           window 0x0010, public own address and accept-all policy; require
           successful Command Complete.
        2. Before enabling scanning, send Periodic Advertising Create Sync with
           Options bit 0 clear, LT public address/type and SID, valid Skip 0,
           timeout (Skip+3) times the periodic interval (450 ms) and
           Sync_CTE_Type 0. Require successful Command Status.
        3. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        4. Begin LE 1M ADV_EXT_IND/AUX_ADV_IND with 50-ms advertising interval
           and 150-ms periodic interval. AuxPtr refers to AUX_ADV_IND, whose
           public LT AdvA and SyncInfo describe a valid CSA #2 periodic train.
           Initially transmit no AUX_SYNC_IND; continue extended announcements.
        5. Receive the first LE Extended Advertising Report with nonzero periodic
           interval, marking the synchronization attempt's start. Validate SID,
           public identity, PHYs, complete status and the configured interval.
           Check reports after each announcement and require at least one full
           periodic interval of lead before the first periodic anchor.
        6. Leave the first six periodic events after the initial SyncInfo silent,
           advancing both CSA #2 counter and anchor for every omitted event.
           Begin valid AUX_SYNC_IND at the seventh event; continue the extended
           announcements throughout (see Source Correction).
        7. Receive Sync Established with status 0x3E (Connection Failed To Be
           Established / Synchronization Timeout) after the six missed events.
           Reject premature failure and successful synchronization, including
           after valid periodic packets begin.

    Expected Outcome:
        Pass verdict: the IUT ceases the synchronization attempt and reports
        failure after six silent opportunities; the discovery report's SID
        matches the advertised SID. Fail verdict: successful synchronization
        to Step 6 periodic traffic, any periodic data report, or sync loss
        implying a synchronization that was not reported correctly.

    Postamble:
        Continue valid periodic packets for six events, covering a full new
        acquisition window. Require no further establishment or periodic reports.
        Stop announcements and disable extended scanning. Do not cancel the
        acquisition: its failure must come from the IUT itself.

    Source Correction:
        Final SID references mean the report in Step 5 and advertisement in
        Step 4, not the nonexistent report/advertisement in Steps 4/3. These
        are local reference corrections, not adopted SIG errata. The test owner
        clarified Step 6 as six omitted AUX_SYNC_IND opportunities followed by
        transmission starting at the seventh event. This resolves the local
        counting interpretation; it is not an outstanding source conflict.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BV-37-C; PDF pages 355-357,
        printed pages 4.2-262-4.2-264, Figure 4.2-106, Steps 1-7 and
        pass/fail verdicts. Core Specification 6.3, Vol 6, Part B, 4.4.5.1
        and Vol 4, Part E, 7.8.67 define the six-event acquisition window.
    """
    interval = 120
    interval_us = interval * LL_PERIODIC_INTERVAL_UNIT_US
    await tester.command(
        scan_parameters(
            extended=True,
            scan_types=[0],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(
        create_sync(
            options=0,
            advertising_sid=ADVERTISING_SID,
            advertiser_address_type=hci.AddressType.PUBLIC_DEVICE,
            advertiser_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
            skip=0,
            sync_timeout=3 * interval_us // hci.HCI_LE_PERIODIC_SYNC_TIMEOUT_UNIT_US,
            sync_cte_type=0,
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    advertiser = PeriodicAdvertiser(
        PeriodicTrain(tester.radio.now_us + FIRST_SYNC_LEAD_US, interval=interval),
        tester.radio.now_us + REPORT_DELIVERY_US + LL_MAFS_US,
        50000,
    )
    for _ in range(10):
        await advertiser.announce_until(
            tester,
            min(
                advertiser.train.anchor,
                advertiser.next_advertisement + advertiser.advertising_interval_us,
            ),
        )
        await tester.wait(REPORT_DELIVERY_US)
        if announcement := tester.take(lambda event: isinstance(event, ExtendedReport)):
            break
    else:
        raise AssertionError('no first periodic announcement report')
    report = announcement.reports[0]
    assert report.event_type == 0
    assert report.address_type == hci.AddressType.PUBLIC_DEVICE
    assert report.primary_phy == report.secondary_phy == Phy.LE_1M
    assert (
        report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
        and report.advertising_sid == ADVERTISING_SID
    )
    assert report.periodic_advertising_interval == interval
    lead = advertiser.train.anchor - tester.radio.now_us
    assert lead >= interval_us, 'first SyncInfo arrived too late for event one'
    tester.output.write(
        f'FIRST SYNC GUIDANCE anchor_us={advertiser.train.anchor} '
        f'reported_us={tester.radio.now_us} lead_us={lead}\n'
    )
    failure = None

    def check_events(missed):
        nonlocal failure
        assert not any(
            isinstance(event, (SyncLost, PeriodicReport)) for event in tester.events
        ), 'a failed acquisition must not receive periodic data or lose sync'
        while event := tester.take(lambda event: isinstance(event, SyncEstablished)):
            assert event.status == ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR
            assert (
                missed >= FIRST_SYNC_MISSED_EVENTS
            ), 'premature synchronization failure'
            assert failure is None, 'duplicate synchronization failure'
            failure = event

    check_events(0)
    for missed in range(1, FIRST_SYNC_MISSED_EVENTS + 1):
        anchor = advertiser.train.anchor
        await advertiser.announce_until(tester, anchor)
        check_events(missed - 1)
        await tester.wait(max(0, anchor + REPORT_DELIVERY_US - tester.radio.now_us))
        advertiser.train.next_event()
        tester.output.write(f'FIRST SYNC OMITTED event={missed} anchor_us={anchor}\n')
        check_events(missed)
    for index in range(FIRST_SYNC_MISSED_EVENTS):
        anchor = advertiser.train.anchor
        await advertiser.transmit(tester, b'periodic')
        await tester.wait(REPORT_DELIVERY_US)
        tester.output.write(
            f'FIRST SYNC SENT event={FIRST_SYNC_MISSED_EVENTS + index + 1} '
            f'anchor_us={anchor}\n'
        )
        check_events(FIRST_SYNC_MISSED_EVENTS)
        assert failure is not None, 'no synchronization failure after six missed events'
    advertiser.advertising = False
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))
    check_events(FIRST_SYNC_MISSED_EVENTS)


async def extended_scanning_periodic_advertising_reception_reporting_initially_disabled(
    tester, *, primary_phy, secondary_phy
):
    """Extended Scanning, Periodic Advertising Reception, Reporting Initially Disabled.

    Initial Condition:
        Public-address continuous passive scanning uses accept-all filtering.
        Table 4.2-74 assigns 1M/1M to BV-38, 1M/2M to BV-60 and Coded/Coded
        to BV-61. Use a 100-ms periodic train, Skip 0 and data fitting one PDU.
        Sequence-tagged seeded payloads distinguish stale reports from new data.

    Test Steps:
        1. Set extended scan parameters with the assigned primary Scanning_PHYs,
           passive Scan_Type 0, interval/window 0x0010, public own address and
           accept-all policy; require successful Command Complete.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           zero; require successful Command Complete.
        3. Begin ADV_EXT_IND with AuxPtr to AUX_ADV_IND on the assigned PHYs.
           The auxiliary contains public LT AdvA and SyncInfo. Continue
           announcements throughout the procedure until the postamble.
        4. Generate AUX_SYNC_IND on the specified secondary PHY with independent
           CSA #2 channels; continue periodic advertising until Step 16.
        5. Receive LE Extended Advertising Report with nonzero periodic interval.
           Validate public advertiser identity, SID and both PHYs.
        6. Send Periodic Advertising Create Sync with Use List clear and
           Reporting Initially Disabled set, the Step 5 SID, public LT identity,
           Skip 0, timeout three periodic intervals converted to HCI units and
           Sync_CTE_Type 0. Require successful Command Status.
        7. Receive successful Sync Established with matching identity/PHY/
           interval/clock accuracy and a valid handle.
        8. Receive no periodic reports for at least ten complete periodic
           intervals. The harness transmits eleven events to cover this window.
        9. Send Periodic Advertising Receive Enable for that handle with Enable
           1; require successful Command Complete.
        10. Receive periodic report events and verify handle, exact sequence/data,
            fragment statuses and no CTE. Reassemble fragments for each dataset.
        11. Repeat Step 10 until at least thirty HCI report events have arrived.
            Count the serialized fragments, not the reassembled data sets.
        12. Send Periodic Advertising Receive Enable with Enable 0; require
            successful Command Complete.
        13. Receive no periodic reports for at least ten complete intervals;
            again transmit eleven events to cover the full window.
        14. Send Periodic Advertising Terminate Sync for that handle; require
            successful Command Complete.
        15. Disable scanning with LE Set Extended Scan Enable; require successful
            Command Complete (see Source Correction).
        16. Stop the Lower Tester periodic stream.

    Expected Outcome:
        Pass verdict: synchronization succeeds using CSA #2 and the advertised
        SID. Periodic reports occur only while reporting is enabled; both
        disabled phases remain silent without losing synchronization.
        Termination ends periodic reception. The source requires thirty HCI
        reports, not thirty reassembled multireport data sets.

    Postamble:
        Between termination and scan disable, transmit one more periodic event
        and require no report, new establishment or synchronization-loss event.
        Stop extended announcements before disabling scanning.

    Source Correction:
        Step 6 names Options bit 2 as Reporting Initially Disabled; use bit 1.
        Bit 2 enables initial duplicate filtering instead. Step 4's ADV_SYNC_IND
        means AUX_SYNC_IND; the command's CTE_Type means Sync_CTE_Type.
        Step 15's legacy Scan Enable means Extended Scan Enable. These are
        local field/command corrections, not adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.18, LL/DDI/SCN/BV-38-C, LL/DDI/SCN/BV-60-C,
        LL/DDI/SCN/BV-61-C; PDF pages 357-360, printed pages 4.2-264-4.2-267,
        Table 4.2-74, Figure 4.2-107, Steps 1-16 and every pass condition.
        Core Specification 6.3, Vol 4, Part E, 7.8.67 and 7.8.65 define
        the Options field and extended scan control.
    """
    await tester.command(
        scan_parameters(
            extended=True,
            scanning_phys=1 << primary_phy - 1,
            scan_types=[0],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    interval_us = SYNCHRONIZATION_PERIODIC_INTERVAL * LL_PERIODIC_INTERVAL_UNIT_US
    advertiser = PeriodicAdvertiser(
        PeriodicTrain(
            tester.radio.now_us + interval_us,
            interval=SYNCHRONIZATION_PERIODIC_INTERVAL,
            phy=secondary_phy,
        ),
        tester.radio.now_us + REPORT_DELIVERY_US,
        SYNCHRONIZATION_ADVERTISING_INTERVAL_US,
        auxiliary_offset_us=AUXILIARY_OFFSET_US,
        primary_phy=primary_phy,
    )
    await advertiser.transmit(tester, b'before-sync')
    report = (await tester.event(ExtendedReport)).reports[0]
    assert report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
    assert report.address_type == hci.AddressType.PUBLIC_DEVICE
    assert report.advertising_sid == ADVERTISING_SID
    assert report.primary_phy == primary_phy and report.secondary_phy == secondary_phy
    assert report.periodic_advertising_interval == SYNCHRONIZATION_PERIODIC_INTERVAL
    command = _sync_command()
    command.options = SyncOptions.REPORTING_INITIALLY_DISABLED
    await tester.command(command)
    handle = None
    for _ in range(6):
        await advertiser.transmit(tester, b'acquisition')
        await tester.wait(REPORT_DELIVERY_US)
        if established := tester.take(lambda event: isinstance(event, SyncEstablished)):
            handle = _check_established(established, phy=secondary_phy)
            break
    assert handle is not None, 'periodic synchronization was not established'

    async def send(sequence, *, enabled):
        data = sequence.to_bytes(2, 'little') + random.Random(sequence).randbytes(
            PERIODIC_DATA_LENGTH - 2
        )
        await advertiser.transmit(tester, data)
        await tester.wait(REPORT_DELIVERY_US)
        if enabled:
            reports = [await tester.event(PeriodicReport)]
            while (
                reports[-1].data_status == ExtendedReport.DATA_INCOMPLETE_MORE_TO_COME
            ):
                reports.append(await tester.event(PeriodicReport))
            assert _periodic_reception_check_reports(reports, data, (), handle)
        assert not any(
            isinstance(event, (PeriodicReport, SyncLost, SyncEstablished))
            for event in tester.events
        )
        return len(reports) if enabled else 0

    for index in range(11):
        await send(index, enabled=False)
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Receive_Enable_Command(handle, 1)
    )
    report_count = 0
    sequence = 11
    while report_count < 30:
        report_count += await send(sequence, enabled=True)
        sequence += 1
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Receive_Enable_Command(handle, 0)
    )
    for _ in range(11):
        await send(sequence, enabled=False)
        sequence += 1
    await tester.command(hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle))
    await send(sequence, enabled=False)
    advertiser.advertising = False
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def active_scanning_invalid_crc(tester):
    """Active Scanning Invalid CRC.

    Initial Condition:
        Active scanning uses public own address and selected interval/window.
        The source initially specifies basic filtering with one public Filter
        Accept List entry, but its Notes permit an unfiltered realization.
        Use that alternative in the isolated PHY, retaining the common public
        entry. Select a 20-ms advertising base with mean 5-ms AdvDelay and
        a continuous 75-ms scan interval/window, three times the mean interval.

    Test Steps:
        1. Enable active scanning in the IUT with the selected parameters.
        2. Select the first supported Lower Tester advertising channel (37).
        3. Configure the common public advertiser with an invalid checksum.
        4. Send ADV_IND with the whole 24-bit CRC inverted at the selected
           advertising cadence for a duration exceeding twenty scan intervals.
        5. Require no SCAN_REQ at T_IFS after any invalid advertisement.
        6. Require no LE Advertising Report for those invalid packets.
        7. Configure a different public advertiser and a correct checksum.
        8. Send valid ADV_IND until twenty scan intervals elapse or Step 9 occurs.
        9. Receive SCAN_REQ at T_IFS; validate CRC, exact public addresses,
           packet length and request spacing within 2 us.
        10. Send SCAN_RSP with an invalid CRC at T_IFS after the request.
        11. Interleaved with Step 8, receive LE Advertising Report with the
            valid advertisement's public identity and exact data.
        12. Interleaved with Step 10, require no report for the invalid response.
        13. Disable scanning with LE Set Scan Enable; require Command Complete.
        14. Select the second supported advertising channel (38).
        15. Repeat Steps 3-13, re-enabling scanning after the previous disable.
        16. Select the third supported advertising channel (39).
        17. Repeat Steps 3-13, again re-enabling scanning.

    Expected Outcome:
        Pass verdict: complete every supported advertising channel with the
        selected timing combination, ignoring CRC-invalid advertisements and
        responses. Valid advertising must still elicit the correctly addressed
        scan request and HCI report, so invalid-response silence is not caused
        by a disabled scanner.

    Source Correction:
        Step 7's different-address reference to Step 2 means the advertiser
        address configured in Step 3, not the channel selected in Step 2.
        Repeated phases must re-enable scanning after Step 13; the source's
        repeat range omits this necessary enable. Amber corroborated these
        local reference/state corrections; they are not adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BI-01-C; PDF pages 361-363,
        printed pages 4.2-268-4.2-270, Figure 4.2-108, Steps 1-17,
        pass verdict and the unfiltered realization allowed by Notes.
    """
    await _invalid_scanning_crc(tester, active=True)


async def passive_scanning_invalid_crc(tester):
    """Passive Scanning Invalid CRC.

    Initial Condition:
        Passive scanning uses public own address and selected interval/window.
        Keep the common public address in the Filter Accept List, but select
        accept-all 0x00 as explicitly allowed by the procedure and Notes.
        Use a 20-ms advertising base with mean 5-ms AdvDelay and a 75-ms scan
        interval/window, three times the mean interval. Keep one scan session
        active throughout all three channel phases.

    Test Steps:
        1. Enable passive scanning in the IUT with the selected parameters.
        2. Select the first supported Lower Tester advertising channel (37).
        3. Configure the common public advertiser with an invalid checksum.
        4. Send ADV_NONCONN_IND with the whole 24-bit CRC inverted for a
           duration exceeding twenty scan intervals at the selected cadence.
        5. Require no LE Advertising Report for those packets.
        6. Select the second supported advertising channel (38).
        7. Configure the common public advertiser with an invalid checksum.
        8. Repeat the transmission/no-report checks of Steps 4-5 without
           restarting scanning or overwriting the selected channel.
        9. Select the third supported advertising channel (39).
        10. Configure the common public advertiser with an invalid checksum.
        11. Repeat Steps 4-5 on that channel, still in the same scan session.
        12. Disable LE scanning with LE Set Scan Enable; require Command Complete.

    Expected Outcome:
        Pass verdict: complete the procedure separately on every supported
        channel without any advertising report for a CRC-invalid packet.
        The passive scanner must not transmit SCAN_REQ. No active scan-response
        phase belongs to this source procedure.

    Source Correction:
        Steps 8/11 say repeat Steps 4-6; repeating Step 6 would reselect channel
        38. Preserve the newly selected channel and repeat the substantive
        Steps 4-5. Step 12 names BR/EDR Write Scan Enable; use LE Set Scan Enable.
        The explicit accept-all procedure/Notes alternative controls the chosen
        policy despite filtered initial prose. Amber corroborated these local
        corrections; they are not adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BI-02-C; PDF pages 363-365,
        printed pages 4.2-270-4.2-272, Figure 4.2-109, Steps 1-12,
        pass verdict and Notes. Core Vol 4, Part E, 7.8.11 defines LE scan enable.
    """
    await _invalid_scanning_crc(tester, active=False)


async def periodic_advertising_reception_channel_map_update(tester):
    """Periodic Advertising Reception, Channel Map Update.

    Initial Condition:
        Public-address passive scanning with accept-all filtering. All primary channels
        and all 37 secondary data channels are enabled in the initial channel map.

    Test Steps:
        1. Send HCI LE Set Extended Scan Parameters with Scanning_PHYs=LE 1M,
           Scan_Type[0]=0x00, Scan_Interval[0]=Scan_Window[0]=0x0010,
           Own_Address_Type=0x00 and Scanning_Filter_Policy=0x00. Receive
           successful HCI Command Complete.
        2. Enable extended scanning with Filter_Duplicates=Duration=Period=0;
           receive successful Command Complete.
        3. Begin ADV_EXT_IND and AUX_ADV_IND advertising on LE 1M. The primary
           AuxPtr points to the auxiliary PDU containing the Lower Tester AdvA
           and SyncInfo for AUX_SYNC_IND. Continue until Step 9.
        4. Generate AUX_SYNC_IND on the CSA#2 channels specified by SyncInfo.
           Every PDU, including those before synchronization, contains 31
           seeded random AdvData octets in the inclusive range 1..254.
        5. Receive HCI LE Extended Advertising Report. Verify the public Lower
           Tester address/type, SID, LE 1M primary/secondary PHY, event type
           and the periodic interval.
        6. Send HCI LE Periodic Advertising Create Sync with Options bit 0=0,
           Advertising_SID from Step 5, Advertiser_Address_Type=0x00,
           Advertiser_Address=Lower Tester, Skip=0x0000,
           Sync_Timeout=3 x Periodic_Advertising_Interval and Sync_CTE_Type=0.
           Receive successful HCI Command Status.
        7. Receive HCI LE Periodic Advertising Sync Established with Status=0
           and fields matching the Lower Tester advertisements.
        8. Receive HCI LE Periodic Advertising Report. Verify the established
           handle, exact data, complete status and absence of CTE.
        9. Cease extended advertising, continuing the periodic train.
        10. Send Channel Map Update Indication in the AUX_SYNC_IND extended
            header for at least six events before Instant. channelMapNEW
            enables only even-numbered data channels.
        11. At Instant, switch the independent CSA#2 channel calculation to
            channelMapNEW and continue periodic advertising.
        12. Continue receiving periodic reports as in Step 8. Check six reports
            before Instant and twelve after it, retaining the original handle.
            Include an event whose channel differs under the old and new maps;
            reject synchronization loss or a second establishment.

    Postamble:
        Terminate synchronization and disable extended scanning.

    Expected Outcome:
        Pass verdict: the IUT maintains synchronization and reports the correct periodic
        data after the Channel Map Update Instant, including transmissions that cannot
        be received using the old map.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BV-67-C; PDF pages 367-369,
        printed pages 4.2-274..276, Figure 4.2-111, Steps 1-12 and pass verdict.
        Source references [10] 4.4.2.13.1, 4.4.3.4 and [18] 1.20.
    """
    advertiser = await _start_advertiser(tester)
    train = advertiser.train
    assert train.channel_map == LL_DATA_CHANNEL_MAP_ALL
    generator = random.Random(0)
    data = bytes(generator.randint(1, 254) for _ in range(PERIODIC_DATA_LENGTH))
    await advertiser.transmit(tester, data)
    report = (await tester.event(ExtendedReport)).reports[0]
    assert (
        report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
        and report.address_type == hci.AddressType.PUBLIC_DEVICE
        and report.advertising_sid == ADVERTISING_SID
        and report.primary_phy == report.secondary_phy == Phy.LE_1M
        and report.periodic_advertising_interval == train.interval
        and report.event_type == 0
    )
    await tester.command(_sync_command())
    data = bytes(generator.randint(1, 254) for _ in range(PERIODIC_DATA_LENGTH))
    await advertiser.transmit(tester, data)
    handle = _check_established(await tester.event(SyncEstablished))
    event = await tester.event(PeriodicReport)
    assert event.sync_handle == handle and event.data == data
    assert event.data_status == ExtendedReport.DATA_COMPLETE
    assert event.cte_type == hci.HCI_LE_PERIODIC_REPORT_CTE_NONE
    advertiser.advertising = False
    channels = sum(1 << channel for channel in range(0, LL_DATA_CHANNEL_COUNT, 2))
    instant = train.counter + 6 & LL_EVENT_COUNTER_MASK
    acad = bytes(
        AdvertisingData(
            [
                (
                    AdvertisingData.Type.CHANNEL_MAP_UPDATE_INDICATION,
                    channels.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
                    + instant.to_bytes(2, 'little'),
                )
            ]
        )
    )
    changed_channel_events = 0
    for index in range(18):
        if index == 6:
            train.channel_map = channels
        if index >= 6 and train.channel != csa2_channel(
            train.counter, train.access_address, LL_DATA_CHANNEL_MAP_ALL
        ):
            changed_channel_events += 1
        data = bytes(generator.randint(1, 254) for _ in range(PERIODIC_DATA_LENGTH))
        await tester.transmit(
            train.channel,
            ext_pdu(acad=acad if index < 6 else b'', data=data),
            start_us=train.anchor,
            **train.parameters,
        )
        train.next_event()
        event = await tester.event(PeriodicReport)
        assert event.sync_handle == handle and event.data == data
        assert event.data_status == ExtendedReport.DATA_COMPLETE
        assert event.cte_type == hci.HCI_LE_PERIODIC_REPORT_CTE_NONE
        assert not any(
            isinstance(event, (SyncLost, SyncEstablished, PeriodicReport))
            for event in tester.events
        )
    assert changed_channel_events, 'the updated map must exercise a different channel'
    await tester.command(hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle))
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def unsupported_periodic_advertising_adi_is_ignored(tester):
    """Scanner not supporting Periodic Advertising ADI accepts Advertising PDU with ADI
    Set.

    Initial Condition:
        Public-address passive scanning with accept-all filtering. The IUT does not
        advertise Periodic Advertising ADI Support and has not received Set Default
        Periodic Advertising Sync Transfer Parameters since its last reset. This
        selected case uses AUX_SYNC_IND, the Table 4.2-75 alternative for
        LL/DDI/SCN/BV-68-C.

    Test Steps:
        1. Send HCI LE Set Extended Scan Parameters with Scanning_PHYs=0x01,
           Scan_Type[0]=0x00, Scan_Interval[0]=Scan_Window[0]=0x0010,
           Own_Address_Type=0x00 and Scanning_Filter_Policy=0x00. Receive
           successful HCI Command Complete.
        2. Enable extended scanning with Filter_Duplicates=Duration=Period=0;
           receive successful Command Complete.
        3. Begin ADV_EXT_IND and AUX_ADV_IND advertising on LE 1M. The primary
           AuxPtr points to the auxiliary PDU, which contains the Lower Tester
           AdvA and SyncInfo referring to AUX_SYNC_IND. Continue until Step 11.
           The selected Table 4.2-75 case does not use AUX_SYNC_SUBEVENT_IND;
           its PAwR Response Timing Information branch is inapplicable.
        4. Generate AUX_SYNC_IND on the CSA#2 channels specified in SyncInfo,
           with AdvData length 100, 100 seeded random octets and a random ADI DID.
        5. Receive HCI LE Extended Advertising Report with a nonzero periodic
           interval; verify the Lower Tester address/type, SID and PHYs.
        6. Send HCI LE Periodic Advertising Create Sync with Options=0x00
           (direct address, reporting enabled, duplicate filtering disabled),
           Advertising_SID from Step 5, Advertiser_Address_Type=0x00 and
           Advertiser_Address=Lower Tester. Receive successful Command Status.
        7. Receive HCI LE Periodic Advertising Sync Established with Status=0
           and fields matching the advertisements, including handle range,
           address/type, SID, PHY, interval and clock accuracy.
        8. Execute Alternative 8A for AUX_SYNC_IND:
           8A.1. Receive HCI LE Periodic Advertising Report.
           8A.2. Repeat Step 8A.1 for nine more periodic advertising intervals.
           Alternative 8B, including Set Periodic Sync Subevent and reports for
           subevents 1/4, belongs to the unselected AUX_SYNC_SUBEVENT_IND case.
        9. Send AUX_SYNC_IND with the same AdvData and SID as Step 4 but a
           different ADI DID.
        10. Execute Alternative 10A for AUX_SYNC_IND:
            10A.1. Receive HCI LE Periodic Advertising Report.
            10A.2. Repeat Step 10A.1 for nine more periodic intervals.
            Alternative 10B's two subevent reports and nine repetitions are
            inapplicable to this selected non-PAwR case.
        11. Stop extended and periodic advertising.

    Additional Checks and Postamble:
        Before Step 1, verify that Periodic Advertising ADI Support is absent.
        Every periodic report must contain the original handle, exact 100-octet
        data, complete status and valid RSSI, with no loss or re-establishment.
        Terminate synchronization and disable extended scanning after Step 11.

    Expected Outcome:
        Pass verdict: each of the ten periodic events before and ten after the DID
        change produces the expected complete periodic report. An unsupported ADI field
        does not suppress reports or disrupt synchronization.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.19, LL/DDI/SCN/BV-68-C; PDF pages 369-373,
        printed pages 4.2-276..280, Table 4.2-75, Figures 4.2-112/113,
        Steps 1-11 with Alternatives 8A/10A and pass verdict.
        Source references [19] 2.3.1.7, 4.6.34 and [23] 2.3.1.9.
    """
    await _periodic_header_compatibility(tester, rfu=False)


async def passive_scanning_invalid_or_unsupported_phy(tester):
    """Passive Scanning, Invalid or Unsupported PHY.

    Initial Condition:
        Passive scanning with all Lower Tester advertisements accepted through
        the Filter Accept List. Provision its public address before enabling
        filtered scanning. Select a continuous LE 1M scan window. Table 4.2-78
        selects AUX PHY 0b100 (RFU) for LL/DDI/SCN/BI-06-C; the actual
        AUX_ADV_IND uses LE 1M, encoded as 0b000.

    Test Steps:
        1. Send HCI LE Set Extended Scan Parameters enabling passive scanning;
           receive successful HCI Command Complete. Select public addressing,
           LE 1M, continuous interval/window 0x4000 and filter policy 0x01.
        2. Send HCI LE Set Extended Scan Enable; receive successful Command
           Complete. Filter_Duplicates, Duration and Period are zero.
        3. Send ADV_EXT_IND with the Table 4.2-78 AUX PHY value 0b100 (RFU).
        4. Send AUX_ADV_IND on the indicated secondary channel at the AuxPtr
           offset, using the table's actual PHY 0b000 (LE 1M).
        5. Require no HCI LE Extended Advertising Report.
        6. Repeat Steps 3-5 for a total of five primary/auxiliary pairs, using
           distinct data to detect any unexpected report.

    Additional Controls and Postamble:
        The Filter Accept List setup satisfies the source Initial Condition;
        it is not an additional numbered source step.
        Before Step 3, require a valid public ADV_EXT_IND/AUX_ADV_IND report.
        The long continuous window retains this acquired primary channel during
        all five pairs. After Step 6, require another valid report with matching
        address/type, data and PHYs, proving that scanning remains operational.
        Disable extended scanning after both positive and negative verdicts.

    Expected Outcome:
        Pass verdict: The IUT does not send an HCI_LE_Extended_Advertising_Report to the
        Upper Tester.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.22, LL/DDI/SCN/BI-06-C; PDF pages 386-388,
        printed pages 4.2-293..295, Table 4.2-78, Figure 4.2-120,
        Steps 1-6 and pass verdict; source reference [19] 4.4.3.
    """
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(
            hci.AddressType.PUBLIC_DEVICE, LOWER_PERIPHERAL_PUBLIC_ADDRESS
        )
    )
    await tester.command(
        scan_parameters(
            extended=True,
            scanning_filter_policy=1,
            scanning_phys=hci.PhyBit.LE_1M,
            scan_types=[0],
            scan_intervals=[hci.HCI_LE_SCAN_INTERVAL_MAX],
            scan_windows=[hci.HCI_LE_SCAN_INTERVAL_MAX],
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    valid = aux_pointer(AUXILIARY_CHANNEL, AUXILIARY_OFFSET_US)
    field = int.from_bytes(valid[1:], 'little') | INVALID_AUX_PHY << PDU_ADV_OFFSET_BITS
    invalid = valid[:1] + field.to_bytes(PDU_ADV_AUX_OFFSET_PHY_SIZE, 'little')

    async def send(pointer, data):
        start = tester.radio.now_us + REPORT_DELIVERY_US + LL_MAFS_US
        await tester.transmit(
            LL_ADV_PRIMARY_CHANNELS[0],
            ext_pdu(adi=ADVERTISING_SID << PDU_ADV_ADI_DID_BITS, aux=pointer),
            start_us=start,
        )
        await tester.transmit(
            AUXILIARY_CHANNEL,
            ext_pdu(
                address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                adi=ADVERTISING_SID << PDU_ADV_ADI_DID_BITS,
                data=data,
            ),
            start_us=start + AUXILIARY_OFFSET_US,
        )
        await tester.wait(REPORT_DELIVERY_US)

    async def positive(data):
        await send(valid, data)
        report = (await tester.event(Report)).reports[0]
        assert report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
        assert report.address_type == hci.AddressType.PUBLIC_DEVICE
        assert report.primary_phy == report.secondary_phy == Phy.LE_1M
        assert report.event_type == 0 and report.data == data
        assert not any(isinstance(event, Report) for event in tester.events)

    await positive(b'valid-before')
    for index in range(INVALID_PHY_ROUNDS):
        await send(invalid, bytes([index]))
        assert not any(
            isinstance(event, Report) for event in tester.events
        ), 'reserved AUX PHY must not produce an advertising report'
    await positive(b'valid-after')
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def legacy_scanning_ignore_extended_advertising_packets(tester):
    """Legacy Scanning Ignore Extended Advertising Packets.

    Initial Condition:
        Public-address passive scanning with accept-all filtering and duplicate
        filtering disabled. Use the minimum base advertising interval and a full scan
        window; the scan interval is three times the mean advertising interval,
        including AdvDelay.

    Test Steps:
        Use the minimum base advertising interval and maximum continuous scan
        window. The scan interval is three times the mean advertising interval,
        including AdvDelay. Repeat the procedure on channels 37, 38 and 39.
        1. Configure the Lower Tester with the selected first supported
           advertising channel and a common public address.
        2. Send HCI LE Set Scan Parameters with LE_Scan_Type=0x00 and
           Scanning_Filter_Policy=0x00. Receive successful Command Complete.
        3. Send HCI LE Set Scan Enable with Enable=0x01; receive successful
           Command Complete. Duplicate filtering is disabled.
        4. Send ADV_NONCONN_IND on only the selected channel each advertising
           event for twenty complete scan intervals, carrying the event count.
        5. Receive HCI LE Advertising Report with the Step 4 event type and
           data present in an actually transmitted advertisement. Verify the
           Lower Tester public address and address type.
        6. Send ADV_EXT_IND with AuxPtr pointing to the Step 7 auxiliary PDU.
        7. Send AUX_ADV_IND on the indicated secondary channel at that offset.
        8. Require no HCI LE Extended Advertising Report for the Lower Tester.
           Also reject these PDUs being misclassified as legacy reports.
        9. Repeat Steps 6-8 ten more times (eleven pairs in total).
        10. Without restarting scanning, send sequenced ADV_NONCONN_IND on the
            same channel for another twenty complete scan intervals.
        11. Receive HCI LE Advertising Report with the Step 10 event type and
            actually transmitted data; again verify address and address type.

    Postamble:
        Disable legacy scanning after each channel's procedure and reject any
        unexpected extended report throughout the test.

    Expected Outcome:
        Pass verdict: the pre- and post-extended-traffic phases both produce legacy
        reports with the correct event type, address, and actually transmitted sequence
        data. The intervening ADV_EXT_IND and AUX_ADV_IND produce neither extended
        reports nor misclassified legacy reports.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BV-74-C; PDF pages 388-390,
        printed pages 4.2-295..297, Figure 4.2-121, Steps 1-11 and pass verdict.
        Source references [3] 4.4.3.1 and [20] 7.8.1.
    """
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    for channel in LL_ADV_PRIMARY_CHANNELS:
        await _enable_legacy_scan(tester)
        await _scan_phase(
            tester,
            channel,
            peer,
            AdvertisingPduType.ADV_NONCONN_IND,
            active=False,
            accepted=True,
            full_duration=True,
        )
        assert not any(isinstance(event, Report) for event in tester.events)
        for sequence in range(EXTENDED_PAIRS):
            start = tester.radio.now_us + REPORT_DELIVERY_US
            adi = ADVERTISING_SID << PDU_ADV_ADI_DID_BITS | sequence
            await tester.transmit(
                channel,
                ext_pdu(
                    adi=adi,
                    aux=aux_pointer(AUXILIARY_CHANNEL, LEGACY_AUXILIARY_OFFSET_US),
                ),
                start_us=start,
            )
            await tester.transmit(
                AUXILIARY_CHANNEL,
                ext_pdu(address=peer, adi=adi, data=b'extended-only'),
                start_us=start + LEGACY_AUXILIARY_OFFSET_US,
            )
            await tester.wait(start + SCAN_ADV_INTERVAL_US - tester.radio.now_us)
            assert not any(
                isinstance(event, (LegacyReport, Report)) for event in tester.events
            ), 'legacy scanning reported an extended advertisement'
        await _scan_phase(
            tester,
            channel,
            peer,
            AdvertisingPduType.ADV_NONCONN_IND,
            active=False,
            accepted=True,
            full_duration=True,
        )
        await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))
        assert not any(isinstance(event, Report) for event in tester.events)


async def legacy_scanning_properly_ignore_rfu_fields_legacy_advertising(tester):
    """Legacy Scanning, Properly Ignore RFU Fields, Legacy Advertising.

    Initial Condition:
        Standby with the selected Scan Max Data IXIT. Execute Table 4.2-79's
        active-scanning case on LE 1M with the minimum advertising interval and
        continuous scanning.

    Test Steps:
        Repeat Steps 1-8 for all Table 4.2-80 rounds: ADV_SCAN_IND, ADV_IND,
        ADV_DIRECT_IND with TargetA=IUT, and ADV_NONCONN_IND. Table 4.2-79
        selects active scanning and Steps 5-7 only for rounds 1/2.
        1. Send HCI LE Set Scan Parameters with LE_Scan_Type=0x01,
           LE_Scan_Interval=LE_Scan_Window=0x0010, Own_Address_Type=0x00
           and Scanning_Filter_Policy=0x00. Receive successful Command Complete.
        2. Enable legacy scanning with Filter_Duplicates=0; receive successful
           Command Complete.
        3. Advertise on LE 1M with the round's PDU type and TargetA, public
           AdvA=Lower Tester and RFU Header bit=1. Require HCI LE Advertising
           Reports for received undirected events or events targeted at the IUT.
           Continue for at least twenty advertising intervals or until Step 6.
        4. In rounds 3/4, fail if the Lower Tester receives SCAN_REQ.
        5. In rounds 1/2, require SCAN_REQ with ScanA=IUT and AdvA=Lower Tester.
           Verify CRC and T_IFS timing. In rounds 3/4, skip Steps 5-7 and
           continue to Step 8.
        6. Send SCAN_RSP at T_IFS after SCAN_REQ, with AdvA=Lower Tester.
        7. Require one or more HCI LE Advertising Reports with Event_Type=4
           (scan response) and data matching the transmitted ScanData.
        8. Disable scanning with HCI LE Set Scan Enable; receive successful
           HCI Command Complete.

    Expected Outcome:
        Pass verdict: RFU fields do not prevent valid advertising or scan-response
        reports. ADV_IND and ADV_SCAN_IND receive scan requests and response reports;
        ADV_DIRECT_IND and ADV_NONCONN_IND never receive scan requests.

    Source Correction:
        The source's ADV_NONCONN_IND Fail verdict incorrectly says that not receiving
        SCAN_REQ is a failure. Table 4.2-80, Step 4, and Core Vol 6, Part B require the
        opposite: receiving SCAN_REQ is a failure for this nonscannable advertising
        type. Amber corroborated this local correction; it is not adopted SIG
        errata.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.23, LL/DDI/SCN/BV-86-C; PDF pages 390-392,
        printed pages 4.2-297..299, Tables 4.2-79/80, Figure 4.2-122,
        Steps 1-8 and pass/fail verdicts; source reference [10] 2.3, 4.4.3.2.
    """
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    generator = random.Random(0)
    for kind in (
        AdvertisingPduType.ADV_SCAN_IND,
        AdvertisingPduType.ADV_IND,
        AdvertisingPduType.ADV_DIRECT_IND,
        AdvertisingPduType.ADV_NONCONN_IND,
    ):
        await tester.command(
            scan_parameters(
                le_scan_type=1,
                le_scan_interval=SCANNING_SCAN_INTERVAL,
                le_scan_window=SCANNING_SCAN_INTERVAL,
            )
        )
        await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))
        wire = (
            request_pdu(kind, DUT_ADDRESS, scanner=peer)
            if kind == AdvertisingPduType.ADV_DIRECT_IND
            else adv_pdu(kind, address=peer, data=b'')
        )
        wire = bytes([wire[0] | PDU_ADV_RESERVED_MASK]) + wire[1:]
        scannable = kind in (
            AdvertisingPduType.ADV_SCAN_IND,
            AdvertisingPduType.ADV_IND,
        )
        seen = response_seen = 0
        start = tester.radio.now_us + REPORT_DELIVERY_US
        deadline = start + 20 * SCANNING_ADVERTISING_INTERVAL_US
        for attempt in range(200):
            end = await tester.transmit(37, wire, start_us=start)
            request = await tester.receive(37, duration_us=1000)
            if request:
                assert request.valid_crc
                assert scannable and request.pdu == request_pdu(
                    AdvertisingPduType.SCAN_REQ, peer, scanner=DUT_ADDRESS
                )
                assert abs(request.start_us - end - LL_IFS_US) <= 2
                await tester.transmit(
                    37,
                    adv_pdu(AdvertisingPduType.SCAN_RSP, address=peer, data=b'A'),
                    start_us=request.end_us + LL_IFS_US,
                )
            await tester.wait(REPORT_DELIVERY_US)
            while event := tester.take(lambda event: isinstance(event, LegacyReport)):
                for report in event.reports:
                    assert (
                        report.address == peer
                        and report.address_type == hci.AddressType.PUBLIC_DEVICE
                    )
                    if report.event_type == LegacyEventType.SCAN_RSP:
                        assert scannable and report.data == b'A'
                        response_seen += 1
                    else:
                        assert (
                            report.event_type
                            == {
                                AdvertisingPduType.ADV_IND: LegacyEventType.ADV_IND,
                                AdvertisingPduType.ADV_SCAN_IND: (
                                    LegacyEventType.ADV_SCAN_IND
                                ),
                                AdvertisingPduType.ADV_DIRECT_IND: (
                                    LegacyEventType.ADV_DIRECT_IND
                                ),
                                AdvertisingPduType.ADV_NONCONN_IND: (
                                    LegacyEventType.ADV_NONCONN_IND
                                ),
                            }[kind]
                        )
                        assert not report.data
                        seen += 1
            if seen and (
                response_seen
                if scannable
                else attempt >= 19 and tester.radio.now_us >= deadline
            ):
                break
            start = max(
                start
                + SCANNING_ADVERTISING_INTERVAL_US
                + generator.randrange(LL_ADV_DELAY_MAX_US + 1),
                tester.radio.now_us + LL_MAFS_US,
            )
        assert seen and (response_seen or not scannable)
        await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))


async def extended_scanning_properly_ignore_rfu_fields_extended_advertising(tester):
    """Extended Scanning, Properly Ignore RFU Fields, Extended Advertising.

    Initial Condition:
        Standby. Record the Scan Max Data IXIT (the maximum received scan data).
        Use the minimum advertising interval and continuous active LE 1M scanning.
        Table 4.2-81 selects Scan_Type[0]=0x01 for BV-88 and performs Steps 5-7
        and rounds 12-15. Public Lower Tester and IUT addresses are selected.

    Test Steps:
        Repeat Steps 1-8 for every round in Table 4.2-82.
        1. Send HCI LE Set Extended Scan Parameters: Scanning_PHYs=0x01,
           Scan_Type[0]=0x01, Scan_Interval[0]=Scan_Window[0]=0x0010,
           Own_Address_Type=0x00 and Scanning_Filter_Policy=0x00. Receive
           successful HCI Command Complete.
        2. Enable extended scanning with Filter_Duplicates, Duration and Period
           all zero; receive successful Command Complete.
        3. Advertise on LE 1M using the round's PDU types and RFU fields.
           Set the designated RFU fields only in the last Scan Response PDU
           when ScanData is specified; otherwise only in the last listed PDU.
           Link ADV_EXT_IND to AUX_ADV_IND and AUX_ADV_IND to AUX_CHAIN_IND
           with valid AuxPtr fields where applicable. Set AdvA to the Lower
           Tester and, for directed events, TargetA to the IUT; omit TargetA
           otherwise. The IUT reports each received undirected or IUT-targeted
           event through HCI LE Extended Advertising Report. Repeat for at
           least twenty advertising intervals or until Step 6 occurs.
        4. Fail if a scan request is received for a nonscannable event or during
           passive scanning.
        5. For nonscannable events or when this step is not applicable, go to
           Step 8. Otherwise require AUX_SCAN_REQ at T_IFS after AUX_ADV_IND
           on the appropriate channel, with ScanA=IUT and AdvA=Lower Tester.
           For directed events, verify the reported Direct Address Type and
           Direct Address. A directed event not addressed to the IUT skips
           to Step 8; undirected scannable rounds continue to Step 6.
        6. Send AUX_SCAN_RSP at T_IFS after AUX_SCAN_REQ with AdvMode=0b00.
           Populate AdvData with the round's number of random octets in 1..255.
           If it does not fit one PDU, include AuxPtr and send the remaining
           bytes in one or more AUX_CHAIN_IND PDUs.
        7. Receive one or more HCI LE Extended Advertising Reports with
           Event_Type bit 3 (Scan response) set. The received data must contain
           the ScanData included in the transmitted response packets.
        8. Disable scanning with HCI LE Set Extended Scan Enable and receive
           successful HCI Command Complete.

    Test Rounds:
        Table 4.2-82, all LE 1M; EXT/AUX/CHAIN below name ADV_EXT_IND,
        AUX_ADV_IND and AUX_CHAIN_IND. Mode applies to each listed PDU.
        1. Nonscannable, nonconnectable undirected, EXT(00), RFU Header bit=1.
        2. Same event and PDU, Extended Header Flags bit 7=1.
        3. Same event and PDU, valid data in all CEAP X fields.
        4. Nonscannable, nonconnectable undirected, EXT(00)/AUX(00), all X fields.
        5. Same event, EXT(00)/AUX(00)/CHAIN(00), all CEAP RFU fields.
        6. Nonscannable, nonconnectable directed, EXT(00), all CEAP RFU fields.
        7. Same directed event, EXT(00)/AUX(00), all CEAP RFU fields.
        8. Connectable undirected, EXT(01)/AUX(01), all CEAP RFU fields.
        9. Connectable directed, EXT(01)/AUX(01), all CEAP RFU fields.
        10. Scannable undirected, EXT(10)/AUX(10), all RFU fields, ScanData=1.
        11. Scannable directed, same PDUs/mode/RFU, ScanData=1.
        12. Scannable undirected, same PDUs/mode/RFU, ScanData=191.
        13. Scannable directed, same PDUs/mode/RFU, ScanData=191.
        14. Scannable undirected, same PDUs/mode/RFU, ScanData=382.
        15. Scannable directed, same PDUs/mode/RFU, ScanData=382.
        For rounds 10-15 the RFU fields belong only to the last response PDU,
        not the listed announcement PDUs.

    Expected Outcome:
        Pass verdict:
            Ignore RFU fields and issue one or more HCI LE Extended Advertising
            Reports. Report each received undirected event or event directed to
            the IUT in Step 3, and report the requested scan data in Step 7.
            The forbidden scan request in Step 4 is a failure.

    Source Correction:
        The final verdict names the legacy Advertising Report, inconsistent with
        Step 3 and extended scanning. Use Extended Advertising Report.
        Step 5's unconditional skip for advertisements not directed at the IUT
        would exclude undirected scannable rounds 10/12/14 despite their required
        ScanData. Scope that skip to directed events targeting another device.
        Its AUX_ADV_IND cross-reference is Step 3, not Step 4. The source
        tables, Core event semantics and Amber support the first two readings;
        the cross-reference is resolved by the explicit PDU in Step 3.
        These are local corrections, not adopted SIG errata.

    Source Conflict:
        Rounds 3/6 require valid data in all X/RFU CEAP fields while retaining a
        primary event without auxiliary packets. In the Core CEAP table, AuxPtr
        is X for that event; setting a valid AuxPtr instead defines an event
        with auxiliary packets. TargetA similarly makes an undirected event
        directed. Amber could not uniquely resolve the intended exhaustive field
        set while preserving the table's event types. No exception for these
        discriminator fields is assumed. Skip this case until clarified rather
        than count a subset of filled fields as complete RFU coverage.

    Reference:
        LL.TS.p28, Section 4.2.4.24, LL/DDI/SCN/BV-88-C; PDF 392-396,
        printed 4.2-299..303; Tables 4.2-81/82, Figure 4.2-123.
        Core reference [10], Vol 6 Part B Sections 2.3 and 4.4.3.2;
        CEAP field presence: Section 2.3.1.5, event reports: Vol 4 Part E
        Section 7.7.65.13.
    """
    pytest.skip(
        'Source conflict: LL.TS.p28 4.2.4.24 rounds 3/6 require all X/RFU '
        'CEAP fields while preserving no-auxiliary event types; a valid '
        'AuxPtr changes that event type and TargetA changes directedness. '
        'Amber cannot uniquely resolve the intended exhaustive field set'
    )


async def extended_scanning_periodic_advertising_properly_ignore_rfu_fields(tester):
    """Extended Scanning, Periodic Advertising, Properly Ignore RFU Fields.

    Initial Condition:
        Standby with the selected Scan Max Data IXIT. Use LE 1M throughout and public,
        accept-all passive scanning. Select a nonconnectable, nonscannable event
        directed to the IUT: the primary PDU supplies its meaningful TargetA, so the
        repeated auxiliary TargetA is RFU under the CEAP field-presence conditions.

    Test Steps:
        1. Send HCI LE Set Extended Scan Parameters with Scanning_PHYs=0x01,
           Scan_Type[0]=0x00, Scan_Interval[0]=Scan_Window[0]=0x0010,
           Own_Address_Type=0x00 and Scanning_Filter_Policy=0x00. Receive
           successful HCI Command Complete.
        2. Enable extended scanning with Filter_Duplicates=Duration=Period=0;
           receive successful Command Complete.
        3. Begin ADV_EXT_IND and AUX_ADV_IND advertising on LE 1M, populating
           all context-reserved fields. The primary AuxPtr points to the
           auxiliary PDU, which contains the real Lower Tester AdvA and
           SyncInfo referring to AUX_SYNC_IND. Continue until Step 10.
        4. Generate AUX_SYNC_IND on the CSA#2 channels specified by SyncInfo,
           with all RFU fields populated. Continue until Step 13.
        5. Receive HCI LE Extended Advertising Report with a nonzero periodic
           interval. Verify public advertiser identity, SID, directed-to-IUT
           identity and LE 1M primary/secondary PHYs.
        6. Send HCI LE Periodic Advertising Create Sync: direct address/list
           disabled, Advertising_SID from Step 5, Advertiser_Address_Type=0x00,
           Advertiser_Address=Lower Tester, Sync_Timeout=3 x reported periodic
           interval and the source's Unused=0. Encode Options=0,
           Sync_CTE_Type=0 and select Skip=0; receive successful Command Status.
        7. Receive HCI LE Periodic Advertising Sync Established with Status=0
           and fields matching the advertisements. Validate handle range,
           public address/type, SID, PHY, interval and clock accuracy.
        8. Receive one or more HCI LE Periodic Advertising Reports. If AdvData
           is present, verify that the report data matches the transmitted data.
        9. Repeat Step 8 until at least five reports have been received. Here
           each complete report contains 100 seeded data octets, the original
           handle and valid RSSI; reject sync loss or a second establishment.
        10. Cease extended advertising.
        11. Send HCI LE Periodic Advertising Terminate Sync; receive successful
            Command Complete.
        12. Disable scanning; receive successful Command Complete. Use HCI LE
            Set Extended Scan Enable, as explained in Source Correction.
        13. Cease periodic advertising.

    RFU Stimulus and Additional Check:
        Populate primary CTEInfo, SyncInfo, ACAD and AdvData; preserve the
        meaningful primary TargetA and fill auxiliary CTEInfo and the repeated
        TargetA with different data. AUX_SYNC_IND carries RFU AdvA, TargetA and
        SyncInfo. Set applicable RFU header bits, Extended Header Flags bit 7
        and SyncInfo offset RFU bits without changing meaningful timing fields.
        Round AuxOffset up from the enlarged primary airtime plus T_MAFS to an
        encodable offset. After Step 11 and before Step 12, send another periodic
        PDU and reject any periodic report, sync loss or new establishment.

    Expected Outcome:
        Pass verdict: RFU fields do not affect advertiser or target identity, timing,
        successful CSA#2 synchronization, or the contents of periodic reports. At
        least five periodic reports contain the transmitted data, synchronization is
        maintained, and successful termination prevents subsequent periodic reports.

    Source Correction:
        Source Step 6 uses the older Filter_Policy and Unused field names; encode
        Options 0 and Sync_CTE_Type 0 in LE Periodic Advertising Create Sync. Step 12
        names the legacy scan-disable command after extended scanning; use LE Set
        Extended Scan Enable. These local corrections preserve the test intent;
        Amber corroborated both mappings. They are not adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, standalone LL/DDI/SCN/BV-89-C; PDF pages 396-399,
        printed pages 4.2-303..306, Figure 4.2-124, Steps 1-13 and pass verdict.
        Source reference [10] 2.3, 4.4.2.13.1, 4.4.3.4. Core Vol 6 Part B
        2.3.1.5-2.3.1.7 defines CEAP field permissions and address presence;
        Vol 4 Part E 7.8.65 and 7.8.67 define scan enable and Create Sync.
    """
    await _periodic_header_compatibility(tester, rfu=True)


async def ignore_directed_advertising_address_not_in_filter_accept_list(tester):
    """Ignore Directed Advertising, Address Not In Filter Accept List.

    Initial Condition:
        The IUT has a configured public device address. The Lower Tester can
        transmit ADV_DIRECT_IND using the common public advertiser address and
        a different public address. Both phases keep TargetA equal to the IUT.
        Use passive scanning with Filter Accept List filtering and no duplicate
        filtering. The continuous scan window equals the scan interval, which
        is three times the mean minimum-base advertising interval including
        AdvDelay. Observe each phase for twenty complete scan intervals.

    Test Steps:
        1. Configure directed advertising with the common public AdvA and the
           IUT's public address as TargetA.
        2. Add the public advertiser to the Filter Accept List and require
           successful Command Complete.
        3. Configure legacy scanning with passive scan type, public own address,
           filter policy 0x01, and the continuous interval/window above.
           Require successful Command Complete.
        4. Enable scanning without duplicate filtering and require successful
           Command Complete.
        5. Send ADV_DIRECT_IND on one selected primary channel for twenty scan
           intervals, using minimum-base advertising plus seeded AdvDelay.
        6. Require at least one LE Advertising Report with directed event type,
           the listed public advertiser address/type, and no advertising data.
           Reject any scan request throughout the observation window.
        7. Disable scanning and require successful Command Complete.
        8. Change AdvA to a different public address absent from the list;
           preserve TargetA, filter policy, and scan timing.
        9. Repeat the enable, twenty-interval observation, and disable sequence.
           Require no advertising reports or scan requests. Repeat both phases
           independently on each supported primary advertising channel.

    Expected Outcome:
        Pass verdict:
            Advertisements with the listed public AdvA are reported correctly.
            Changing only AdvA to an unlisted public address prevents reports,
            despite TargetA still matching the IUT. The scanner remains passive
            in both phases and the observation covers the full required time.

    Reference:
        LL.TS.p28.pdf, LL/DDI/SCN/BV-90-C, unnumbered procedure following
        Section 4.2.4.24; PDF pages 399-401, printed pages 4.2-306 through
        4.2-308, Figure 4.2-125, Steps 1-9 and Expected Outcome.
        Source reference [3] 4.4.3.1.
    """
    common, different = (LOWER_PERIPHERAL_PUBLIC_ADDRESS, LOWER_CENTRAL_PUBLIC_ADDRESS)
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(common.address_type, common)
    )
    for channel in LL_ADV_PRIMARY_CHANNELS:
        for peer, accepted in ((common, True), (different, False)):
            await _enable_legacy_scan(tester, filtered=True)
            await _scan_phase(
                tester,
                channel,
                peer,
                AdvertisingPduType.ADV_DIRECT_IND,
                active=False,
                accepted=accepted,
                full_duration=True,
            )
            await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))
            assert not any(
                isinstance(event, (LegacyReport, Report)) for event in tester.events
            )


async def pawr_trains_with_same_identity_do_not_synchronize(tester):
    """Periodic Advertising with Responses Trains, Do Not Synchronize with Same Address,
    Address Type, Advertising SID.

    Initial Condition:
        The IUT starts in Standby or Device Address Set. Table 4.2-85 selects
        AUX_SYNC_IND for LL/DDI/SCN/BV-96-C; PAwR subevents are not used in this
        variant despite the shared source procedure's title. The Lower Tester
        uses a public address and independent CSA#2 periodic traffic on LE 1M.

    Test Steps:
        1. Set extended scan parameters to public own address, accept-all
           filtering, LE 1M, passive scan type, and interval/window 0x0010.
           Require successful Command Complete.
        2. Enable scanning with Filter_Duplicates 0x01 and zero Duration/Period.
           Require successful Command Complete.
        3. Start ADV_EXT_IND announcements whose AuxPtr refers to AUX_ADV_IND
           carrying the public AdvA, SID, and valid SyncInfo. Continue these
           announcements throughout the test. The unselected
           AUX_SYNC_SUBEVENT_IND branch additionally supplies PAwR Timing
           Information (subeventInterval=0x0C, responseSlotDelay=0x01,
           responseSlotSpacing=0x0A); it is inapplicable to BV-96-C.
        4. Transmit AUX_SYNC_IND on the independently calculated CSA#2 channels
           and event times described by SyncInfo.
        5. Require a complete extended advertising report with matching public
           advertiser identity, SID, PHYs, and nonzero periodic interval.
        6. Send LE Periodic Advertising Create Sync using that identity and
           SID, Options 0, Skip 0, Sync_CTE_Type 0, and a timeout of three
           periodic intervals. Require successful Command Status.
        7. Require successful Sync Established with matching identity, SID, PHY,
           periodic interval, and clock accuracy. Validate periodic data on
           the established handle.
        8. Continue receiving data for ten full periodic intervals, then repeat
           Create Sync with the same advertiser address, public address type,
           SID and Options=0x00 (direct address, reporting initially enabled,
           duplicate filtering disabled).
        9. Select Alternative 9A or 9B according to HCI Command Status:
           9A.1. Receive Command Status with a valid nonzero error code.
           9B.1. Receive successful Command Status.
           9B.2. Receive Sync Established with a valid nonzero error code.
           Reject RFU error codes or a second successful synchronization.

    Additional Check and Postamble:
        Verify further periodic data on the original handle without sync loss,
        then terminate synchronization and disable extended scanning.

    Expected Outcome:
        Pass verdict:
            The duplicate request fails through source alternative 9A or 9B,
            with a valid error code rather than a second successful sync.
            As an additional continuity check, the original synchronization
            continues to deliver the exact data on its original handle.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.25, Table 4.2-85,
        LL/DDI/SCN/BV-96-C; PDF pages 413-415, printed pages 4.2-320 through
        4.2-322, Figure 4.2-131. Steps 1-9, including Alternatives 9A/9B,
        and Expected Outcome; source reference [23] 4.4.5.1.2.
    """
    advertiser = await _start_advertiser(tester, duplicates=True)
    await advertiser.transmit(tester, b'before-sync')
    report = (await tester.event(ExtendedReport)).reports[0]
    assert report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
    assert report.address_type == hci.AddressType.PUBLIC_DEVICE
    assert report.advertising_sid == ADVERTISING_SID
    assert (
        report.event_type == 0
        and report.periodic_advertising_interval == SYNCHRONIZATION_PERIODIC_INTERVAL
    )
    assert report.primary_phy == report.secondary_phy == hci.Phy.LE_1M
    await tester.command(_sync_command())
    handle = await _transmit_report(tester, advertiser)
    for _ in range(DUPLICATE_OBSERVATION_EVENTS):
        await _transmit_report(tester, advertiser, handle=handle)
    valid_statuses = tuple(
        code for code in ErrorCode if code != ErrorCode.RESERVED_FOR_FUTURE_USE
    )
    result = await tester.command(_sync_command(), valid_statuses)
    if result.status == ErrorCode.SUCCESS:
        event = await tester.event(SyncEstablished)
        assert event.status in valid_statuses and event.status != ErrorCode.SUCCESS
    await _transmit_report(tester, advertiser, handle=handle)
    await tester.command(hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle))
    advertiser.advertising = False
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def ignore_a_connection_request_periodic_advertising_with_responses_not_supported(
    tester,
):
    """Ignore a Connection Request, Periodic Advertising with Responses Not Supported.

    Initial Condition:
        The IUT supports periodic synchronization but does not advertise the
        PAwR Scanner feature. Confirm this with LE Read Local Supported
        Features before applying the test.

        Use passive LE 1M scanning with a public own address and accept-all
        filtering. The independent Lower Tester uses a one-second periodic
        interval with three subevents. Its Response Timing Information ACAD
        specifies numSubevents 3, subeventInterval 0xF0 (300 ms),
        responseSlotDelay 0x0A (12.5 ms), and responseSlotSpacing 0xFE
        (31.75 ms). Extended announcements remain active throughout the test,
        using the shared advertiser's 20.5-ms interval.

    Test Steps:
        1. Send HCI LE Set Extended Scan Parameters with Scanning_PHYs=0x01,
           Scan_Type[0]=0x00, Scan_Interval[0]=Scan_Window[0]=0x0010,
           Own_Address_Type=0x00 and Scanning_Filter_Policy=0x00. Receive
           successful HCI Command Complete.
        2. Enable extended scanning with Filter_Duplicates=Duration=Period=0;
           receive successful Command Complete.
        3. Begin LE 1M ADV_EXT_IND/AUX_ADV_IND announcements. AuxPtr points to
           AUX_ADV_IND containing the public Lower Tester AdvA and SyncInfo
           for AUX_SYNC_SUBEVENT_IND. Include Response Timing Information:
           numSubevents=3, subeventInterval=0xF0 (300 ms),
           responseSlotDelay=0x0A (12.5 ms), responseSlotSpacing=0xFE (31.75 ms).
           Continue announcements throughout the procedure.
        4. Generate three AUX_SYNC_SUBEVENT_IND subevents on independently
           calculated CSA#2 channels with SyncInfo access address and CRC init.
        5. Receive HCI LE Extended Advertising Report with nonzero periodic
           interval; verify public identity, SID and PHYs.
        6. Send HCI LE Periodic Advertising Create Sync with Options=0x00,
           Advertising_SID from Step 5, Advertiser_Address_Type=0x00 and
           Advertiser_Address=Lower Tester. Receive successful Command Status.
           Select Skip=0, Sync_CTE_Type=0 and timeout=three periodic intervals.
        7. Send preceding event subevent 1 with ten 0x01 AdvData octets.
        8. Require no HCI LE Periodic Advertising Sync Established [v1].
        9. Send preceding event subevent 2 with ten 0x02 AdvData octets.
        10. Require no Sync Established [v1].
        11. Send subevent 0 with ten 0x00 AdvData octets.
        12. Receive successful Sync Established [v1] with fields matching the
            advertisements, including identity, SID, PHY, interval and accuracy.
        13. Receive HCI LE Periodic Advertising Report [v1] with ten 0x00 octets
            on the established handle.
        14. Send subevent 1 with ten 0x01 AdvData octets.
        15. Require no Periodic Advertising Report [v1].
        16. Send subevent 2 with ten 0x02 AdvData octets.
        17. Require no Periodic Advertising Report [v1].
        18. Send AUX_CONNECT_REQ in the next subevent 0, with the periodic
            access address and CRC init.
        19. Require no AUX_CONNECT_RSP in the response window.
        20. Send subevent 1 with ten 0x01 AdvData octets.
        21. Require no Periodic Advertising Report [v1].
        22. Send subevent 2 with ten 0x02 AdvData octets.
        23. Require no Periodic Advertising Report [v1].
        24. Send following event subevent 0 with ten 0x00 AdvData octets.
        25. Receive Periodic Advertising Report [v1] with ten 0x00 octets on
            the original handle.

    Additional Checks and Postamble:
        Reject premature reports in Steps 8/10, invalid handle ranges, incomplete
        data, unexpected CTE and invalid RSSI. Require no synchronization loss,
        second establishment or connection event. Terminate synchronization
        and disable extended scanning after Step 25.

    Expected Outcome:
        Pass verdict:
            Only subevent 0 establishes synchronization and produces periodic
            reports. Both source Steps 13 and 25 report exactly ten 0x00 octets;
            subevents 1 and 2 produce no reports or premature establishment.
            The connection request receives no response, and periodic reception
            resumes on the original handle without creating a connection.

    Reference:
        LL.TS.p28.pdf, LL/DDI/SCN/BV-99-C, unnumbered procedure following
        Section 4.2.4.26; PDF pages 423-426, printed pages 4.2-330 through
        4.2-333, Figures 4.2-135/136. Steps 1-25 and Expected Outcome,
        especially Steps 8/10/12/13/15/17/19/21/23/25;
        source reference [23] 4.4.2.12.2.
    """
    features = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    assert not (
        int.from_bytes(features.le_features, 'little')
        & hci.LeFeatureMask.PERIODIC_ADVERTISING_WITH_RESPONSES_SCANNER
    ), 'this procedure requires a scanner without PAwR support'
    await tester.command(
        scan_parameters(
            extended=True,
            scan_types=[0],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    train = PeriodicTrain(tester.radio.now_us + 1000000, interval=800)
    timing = bytes(
        AdvertisingData(
            [
                (
                    PERIODIC_RESPONSE_TIMING_INFORMATION,
                    bytes([3, 240, 10, 254]),
                )
            ]
        )
    )
    advertiser = PeriodicAdvertiser(
        train,
        tester.radio.now_us + REPORT_DELIVERY_US,
        SYNCHRONIZATION_ADVERTISING_INTERVAL_US,
        acad=timing,
    )
    for _ in range(20):
        await advertiser.announce_until(
            tester, advertiser.next_advertisement + advertiser.advertising_interval_us
        )
        if report := tester.take(lambda event: isinstance(event, ExtendedReport)):
            break
    else:
        raise AssertionError('no PAwR announcement')
    announcement = report.reports[0]
    assert announcement.event_type == 0
    assert announcement.periodic_advertising_interval == train.interval
    assert announcement.advertising_sid == ADVERTISING_SID
    assert announcement.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
    assert announcement.address_type == hci.AddressType.PUBLIC_DEVICE
    assert announcement.primary_phy == announcement.secondary_phy == Phy.LE_1M
    await tester.command(
        create_sync(
            options=0,
            advertising_sid=ADVERTISING_SID,
            advertiser_address_type=hci.AddressType.PUBLIC_DEVICE,
            advertiser_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
            skip=0,
            sync_timeout=300,
            sync_cte_type=0,
        )
    )
    for _ in range(10):
        await advertiser.announce_until(
            tester, advertiser.next_advertisement + advertiser.advertising_interval_us
        )
        if tester.take(lambda event: isinstance(event, ExtendedReport)):
            break
    else:
        raise AssertionError('no post-command PAwR SyncInfo')

    async def other_subevents(anchor, counter):
        channels = subevent_channels(counter, train.access_address)
        for subevent in (1, 2):
            await advertiser.announce_until(tester, anchor + subevent * 300000)
            await tester.transmit(
                channels[subevent],
                ext_pdu(data=bytes([subevent]) * 10),
                start_us=anchor + subevent * 300000,
                **train.parameters,
            )
            assert not any(
                isinstance(event, (PeriodicReport, SyncEstablished))
                for event in tester.events
            )

    await other_subevents(
        train.anchor - 1000000, train.counter - 1 & LL_EVENT_COUNTER_MASK
    )
    anchor, counter = (train.anchor, train.counter)
    await advertiser.transmit(tester, bytes(10))
    established = await tester.event(SyncEstablished)
    assert established.status == ErrorCode.SUCCESS
    handle = established.sync_handle
    assert 0 <= handle <= SYNC_HANDLE_MAX
    assert established.advertising_sid == ADVERTISING_SID
    assert established.advertiser_address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
    assert established.advertiser_address_type == hci.AddressType.PUBLIC_DEVICE
    assert established.advertiser_phy == Phy.LE_1M
    assert established.periodic_advertising_interval == train.interval
    assert established.advertiser_clock_accuracy == 0

    async def check_report():
        event = await tester.event(PeriodicReport)
        assert event.sync_handle == handle and event.data == bytes(10)
        assert event.data_status == Report.DATA_COMPLETE
        assert event.cte_type == hci.HCI_LE_PERIODIC_REPORT_CTE_NONE
        assert -127 <= event.rssi <= 20

    await check_report()
    await other_subevents(anchor, counter)
    await advertiser.announce_until(tester, train.anchor)
    await tester.transmit(
        train.channel,
        request_pdu(
            AdvertisingPduType.CONNECT_IND,
            advertiser=DUT_ADDRESS,
            scanner=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
            data=LinkParameters().encode(),
        ),
        start_us=train.anchor,
        **train.parameters,
    )
    assert (
        await tester.receive(train.channel, duration_us=1000, **train.parameters)
        is None
    )
    anchor, counter = (train.anchor, train.counter)
    train.next_event()
    await other_subevents(anchor, counter)
    await advertiser.transmit(tester, bytes(10))
    await check_report()
    assert not any(
        isinstance(
            event,
            (
                SyncLost,
                SyncEstablished,
                hci.HCI_LE_Connection_Complete_Event,
                hci.HCI_LE_Enhanced_Connection_Complete_Event,
            ),
        )
        for event in tester.events
    )
    await tester.command(hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle))
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def decision_based_advertisements_ignored_legacy_scanning(tester):
    """Decision-Based Advertisements Ignored, Legacy Scanning.

    Initial Condition:
        The IUT does not advertise Decision-Based Advertising Filtering support.
        Use public, accept-all, passive legacy scanning with interval/window
        0x0010. The independent Lower Tester can send a valid ADV_DECISION_IND
        with Decision Type Flags bit 0 set, a six-octet Resolvable Tag, and an
        AuxPtr referring to AUX_ADV_IND. No shared tag-resolution key is needed
        for this negative legacy-scanning test.

    Test Steps:
        1. Send a Decision PDU followed by its indicated AUX_ADV_IND. The first
           payload octet contains Decision Type Flags 0b000001 and AdvMode
           0b00, followed by Extended Header Flags and the three-octet AuxPtr,
           then the six-octet tag. Do not insert the ExtHdrLen used by ordinary
           ADV_EXT_IND; the Decision PDU has a different payload format.
        2. Send HCI LE Set Scan Parameters with LE_Scan_Type=0x00,
           LE_Scan_Interval=LE_Scan_Window=0x0010 and
           Scanning_Filter_Policy=0b0000; receive successful Command Complete.
        3. Send HCI LE Set Scan Enable with LE_Scan_Enable=0x01; receive
           successful Command Complete. Duplicate filtering is disabled.
        4. Continue Decision PDU/AUX_ADV_IND pairs with minimum-base intervals
           plus seeded AdvDelay for ten complete simulated seconds. Require
           no legacy or extended advertising reports and no scan requests.
           The auxiliary packet carries a valid public AdvA and ADI.

    Additional Controls and Postamble:
        After Step 3 and before the negative window, require a normal ADV_IND
        report with matching public identity/type and data. Repeat this control
        after Step 4 to prove that reception remains functional. These controls
        are outside the ten-second negative window. Finally disable scanning.

    Expected Outcome:
        Pass verdict:
            No LE Advertising Report is generated during the source Step 4
            ten-second window. Additional checks reject extended reports and
            scan requests, and require normal legacy reception before and
            after the window. Positive controls are not part of the negative
            observation period.

    Source Correction:
        Source Step 1 calls the primary PDU AUX_DECISION_IND. Core Vol 6,
        Part B, Section 2.3.1.11 defines ADV_DECISION_IND (type 0x09), whose
        auxiliary PDU is AUX_ADV_IND. Use those defined PDU types; this naming
        correction does not change the test's legacy-scanning verdict. Amber
        corroborated the defined names; this is not adopted SIG errata.

    Reference:
        LL.TS.p28.pdf, LL/DDI/SCN/BV-104-C, unnumbered procedure following
        Section 4.2.4.27; PDF pages 439-440, printed pages 4.2-346 through
        4.2-347, Figure 4.2-140, Steps 1-4 and Expected Outcome.
        Source reference [25] 4.4.3.6. Core Vol 6, Part B,
        Section 2.3.1.11, Figures 2.10-2.12 and Tables 2.10-2.11 define the
        Decision PDU, permitted extended fields, flags, and Resolvable Tag.
    """
    features = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    assert not (
        int.from_bytes(features.le_features, 'little')
        & hci.LeFeatureMask.DECISION_BASED_ADVERTISING_FILTERING
    ), 'this procedure requires a scanner without Decision-Based Advertising Filtering'
    decision = (
        bytes([PDU_ADV_DECISION_RESOLVABLE_TAG_MASK, PDU_ADV_EXT_AUX_PTR_MASK])
        + aux_pointer(AUXILIARY_CHANNEL, AUXILIARY_OFFSET_US)
        + bytes.fromhex('123456789a4b')
    )
    wire = bytes([AdvertisingPduType.ADV_DECISION_IND, len(decision)]) + decision
    auxiliary = ext_pdu(
        address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
        adi=ADVERTISING_SID << PDU_ADV_ADI_DID_BITS,
        data=b'ignored',
    )
    start = tester.radio.now_us + REPORT_DELIVERY_US
    await tester.transmit(37, wire, start_us=start)
    await tester.transmit(
        AUXILIARY_CHANNEL, auxiliary, start_us=start + AUXILIARY_OFFSET_US
    )
    await tester.command(
        scan_parameters(
            le_scan_type=0,
            le_scan_interval=SCANNING_SCAN_INTERVAL,
            le_scan_window=SCANNING_SCAN_INTERVAL,
        )
    )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))

    async def positive():
        for _ in range(30):
            await tester.transmit(
                37, adv_pdu(address=LOWER_PERIPHERAL_PUBLIC_ADDRESS, data=b'positive')
            )
            await tester.wait(SCANNING_ADVERTISING_INTERVAL_US)
            if event := tester.take(lambda event: isinstance(event, LegacyReport)):
                assert event.reports[0].event_type == LegacyEventType.ADV_IND
                assert event.reports[0].address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
                assert event.reports[0].address_type == hci.AddressType.PUBLIC_DEVICE
                assert event.reports[0].data == b'positive'
                return
        raise AssertionError('legacy scanner positive control absent')

    await positive()
    generator = random.Random(0)
    start = tester.radio.now_us + REPORT_DELIVERY_US
    deadline = start + 10000000
    while start <= deadline:
        await tester.transmit(37, wire, start_us=start)
        await tester.transmit(
            AUXILIARY_CHANNEL,
            auxiliary,
            start_us=start + AUXILIARY_OFFSET_US,
        )
        assert await tester.receive(AUXILIARY_CHANNEL, duration_us=1000) is None
        assert not any(
            isinstance(event, (LegacyReport, Report)) for event in tester.events
        )
        start = max(
            start
            + SCANNING_ADVERTISING_INTERVAL_US
            + generator.randrange(LL_ADV_DELAY_MAX_US + 1),
            tester.radio.now_us + LL_MAFS_US,
        )
    await tester.wait(max(0, deadline - tester.radio.now_us))
    assert not any(isinstance(event, (LegacyReport, Report)) for event in tester.events)
    await positive()
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))


async def active_scanning_duplicate_filtering(tester):
    """Active Scanning, Duplicate Filtering.

    Initial Condition:
        The IUT uses its public address and active legacy scanning. Populate
        the Filter Accept List with the Lower Tester's common public address,
        as required by the source precondition. Source Step 3 then explicitly
        selects accept-all filtering; the list does not filter this procedure.

        Use the first supported primary advertising channel and minimum-base
        advertising with seeded AdvDelay. The scan interval is three times the
        mean advertising interval, including AdvDelay; the scan window equals
        that interval. Keep the advertiser address, empty AdvData, and response
        data unchanged throughout the test.

    Test Steps:
        1. Configure the Lower Tester channel map to the first supported
           advertising channel.
        2. Set its common advertiser address with public address type.
        3. Send HCI LE Set Scan Parameters with LE_Scan_Type=0x01 and
           Scanning_Filter_Policy=0x00; receive successful Command Complete.
           Select public addressing and the continuous interval/window above.
        4. Enable legacy scanning with Enable=0x01 and Filter_Duplicates=0x01;
           receive successful Command Complete.
        5. Send identical ADV_IND on the selected channel each advertising event.
        6. Require at least one HCI LE Advertising Report with the Lower Tester
           address and Event_Type=0x00 (see Source Correction). Additional
           advertising reports produce a warning, not a failure.
        7. Receive SCAN_REQ in response to Step 5. Verify CRC, public IUT ScanA,
           public Lower Tester AdvA and T_IFS within the two-microsecond tolerance.
        8. Withhold SCAN_RSP.
        9. The source requires no HCI LE Advertising Report with the Lower
           Tester address after the unanswered request. This requirement is
           unresolved; see Source Conflict rather than narrow its meaning.
        10. After ten complete scan intervals from the first unanswered request,
            respond to the next SCAN_REQ at T_IFS with SCAN_RSP AdvData='A'.
        11. Require at least one Advertising Report with Event_Type=0x04,
            Address=Lower Tester, Data_Length=1 and Data='A'. Additional reports
            produce a warning, not a failure.
        12. Continue unchanged advertising for 128 scan intervals after the
            first response report. If another SCAN_REQ is sent:
            12.A. Receive SCAN_REQ in response to ADV_IND from Step 5.
            12.B. Send SCAN_RSP with the same public AdvA and AdvData='A' at T_IFS.
            12.C. Issue a warning for further reports with the Lower Tester
                  address. Validate every report's type, address and data.

    Postamble:
        Disable legacy scanning and receive successful Command Complete.

    Expected Outcome:
        Pass verdict:
            At least one LE Advertising Report identifies the Lower Tester with
            Event_Type 0x00 for ADV_IND, and at least one later report has
            Event_Type 0x04 with the single data octet 'A'. No scan-response
            report is accepted before an actual response is transmitted. The
            scanner retries after the unanswered phase despite duplicate
            filtering. Duplicate reports are recorded as warnings.
            No complete Pass verdict is awarded while Step 9 remains unresolved.

    Source Correction:
        Source Step 6 says Event_Type 0x01, but ADV_IND is reported as 0x00,
        consistent with the source Expected Outcome and HCI LE Advertising
        Report. The filtered initial condition does not override the explicit
        policy 0x00 in Step 3. Provision the initial list, then use that policy.
        Amber corroborates the ADV_IND event value and current policy semantics;
        these are local interpretations, not adopted SIG errata.

    Source Conflict:
        Step 9 forbids an Advertising Report with the Lower Tester address
        during unanswered requests, without distinguishing advertising data
        from scan-response reports. Steps 6/11/12.C only warn about duplicates.
        Core Vol 6 Part B 4.4.3.5 permits duplicate reports even when duplicate
        filtering is enabled and processes advertising/scan data separately.
        Amber could not establish an unambiguous literal verdict for Step 9.
        The driver checks response provenance, timing and duplicate warnings,
        but that does not implement the source's blanket negative requirement.
        Skip the complete verdict after these checks until the source is clarified.

    Reference:
        LL.TS.p28.pdf, LL/DDI/SCN/BV-127-C, unnumbered procedure following
        Section 4.2.4.30; PDF pages 463-465, printed pages 4.2-370 through
        4.2-372, Figure 4.2-152. Steps 1-12, including 12.A-C, and Expected
        Outcome; source reference [3] 4.4.3.2. Core Vol 4, Part E,
        Sections 7.7.65.2, 7.8.10, and 7.8.11 define legacy reports, scan
        filter policy, and duplicate filtering.
    """
    await _duplicate_active_scanning(tester, extended=False)
    pytest.skip(
        'Source conflict: LL/DDI/SCN/BV-127-C Step 9 forbids all Lower Tester '
        'reports during unanswered requests, while duplicate reports are '
        'warnings and Core 4.4.3.5 permits them; full verdict awaits clarification'
    )


async def extended_scanning_active_duplicate_filtering(tester):
    """Extended Scanning, Active, Duplicate Filtering.

    Initial Condition:
        The IUT uses its public address and active LE 1M extended scanning with
        accept-all filtering and interval/window 0x0010. Scan_Max_Data is at
        least one octet. The Lower Tester uses a fixed public AdvA and SID/DID,
        scannable nonconnectable extended advertising on one selected primary
        channel, and LE 1M auxiliary packets.

    Test Steps:
        1. Send HCI LE Set Extended Scan Parameters with Scan_Type[0]=0x01,
           Scan_Interval[0]=Scan_Window[0]=0x0010, Own_Address_Type=0x00 and
           Scanning_Filter_Policy=0x00. Select LE 1M; receive successful
           HCI Command Complete.
        2. Enable extended scanning with Filter_Duplicates=0x01; receive
           successful Command Complete. Duration and Period are zero.
        3. Begin LE 1M ADV_EXT_IND with AuxPtr referring to scannable
           AUX_ADV_IND carrying the public Lower Tester AdvA and fixed ADI.
        4. Require at least one HCI LE Extended Advertising Report with
           Event_Type=0x02 and Address=Lower Tester. Warn for additional reports;
           verify address type, LE 1M PHYs, SID and zero periodic interval.
        5. Receive AUX_SCAN_REQ for the undirected advertisements from Step 3.
           Verify CRC, exact public ScanA/AdvA and T_IFS timing.
        6. Withhold AUX_SCAN_RSP.
        7. The source requires no HCI LE Extended Advertising Report with the
           Lower Tester address after the unanswered request. Its scope is
           unresolved; see Source Conflict rather than narrow this requirement.
        8. Repeat Steps 5-7 for five actual advertising intervals after the
           first unanswered request, including AdvDelay in the interval count.
        9. Respond to the next valid AUX_SCAN_REQ at T_IFS with AUX_SCAN_RSP,
           preserving the public AdvA and setting the single AdvData octet 'A'.
        10. Require at least one Extended Advertising Report with
            Event_Type=0x0A, Address=Lower Tester, Data_Length=1 and Data='A'.
            Warn for additional reports and validate their complete identity,
            PHYs, SID and zero periodic interval.
        11. Continue unchanged advertising for 128 scan intervals after the
            first response report. If another AUX_SCAN_REQ is sent:
            11A. Receive AUX_SCAN_REQ from the IUT.
            11B. Send AUX_SCAN_RSP at T_IFS with the same AdvA and AdvData='A'.
            11C. Warn if the IUT sends further Extended Advertising Reports
                 with Address=Lower Tester. Validate all reported fields/data.

    Postamble:
        Disable extended scanning and receive successful Command Complete.

    Expected Outcome:
        Pass verdict:
            At least one correct scannable advertising report (0x02) and one
            scan-response report (0x0A) identify the same Lower Tester. Response
            data are exactly the single octet 'A'. No scan-response report is
            accepted before transmission of a real response. Duplicate
            filtering does not prevent retries after unanswered requests;
            additional duplicate reports are warnings, not automatic failures.
            No complete Pass verdict is awarded while Step 7 remains unresolved.

    Source Correction:
        The source Expected Outcome says 0x03, but Step 4 and the scannable,
        nonconnectable event require 0x02. Source Steps 9 and 11B say AdvA='A';
        preserve the six-octet advertiser address and put 'A' in AdvData, as
        required by Step 10. Amber corroborates these local corrections;
        they are not adopted SIG errata.

    Source Conflict:
        Step 7 forbids an Extended Advertising Report with the Lower Tester
        address during unanswered requests, without separating advertising
        data from scan-response reports. Steps 4/10/11C only warn for duplicate
        reports. Core Vol 6 Part B 4.4.3.5 permits duplicates and treats
        advertising/scan data separately. Amber could not uniquely resolve
        this negative requirement. The driver verifies retry timing, response
        provenance and duplicate warnings, not the blanket source prohibition;
        skip the complete verdict after those checks until clarified.

    Reference:
        LL.TS.p28.pdf, LL/DDI/SCN/BV-128-C, unnumbered procedure following
        Section 4.2.4.30; PDF pages 466-468, printed pages 4.2-373 through
        4.2-375, Figure 4.2-153. Steps 1-11, including 11A-C, and Expected
        Outcome; source reference [10] 4.4.3.2. Core Vol 4, Part E,
        Sections 7.7.65.13, 7.8.64, and 7.8.65 define extended reports and
        extended scanning; Vol 6, Part B, Section 2.3.2.3 defines AUX_SCAN_RSP.
    """
    await _duplicate_active_scanning(tester, extended=True)
    pytest.skip(
        'Source conflict: LL/DDI/SCN/BV-128-C Step 7 forbids all Lower Tester '
        'reports during unanswered requests, while duplicate reports are '
        'warnings and Core 4.4.3.5 permits them; full verdict awaits clarification'
    )


async def extended_scanning_passive_periodic_advertising_report_window_widening(tester):
    """Extended Scanning, Passive, Periodic Advertising Report, Window Widening.

    Initial Condition:
        The IUT supports passive extended scanning and periodic synchronization
        with v1 periodic reports. Use public addresses, accept-all filtering,
        and a continuous LE 1M scan window. The Lower Tester advertises a 500-ppm
        clock (CA=0, SCA=0). Scan_Max_Data is at least three octets, so source
        Steps 15 and 16 apply.

    Test Steps:
        1. Send LE Set Extended Scan Parameters: Scanning_PHYs=0x01, passive
           Scan_Type=0x00, Scan_Interval=Scan_Window=0x0010, public own address,
           and accept-all filter policy. Require successful Command Complete.
        2. Enable extended scanning with Filter_Duplicates, Duration, and Period
           all zero. Require successful Command Complete.
        3. Send ADV_EXT_IND with AuxPtr CA=0 and nominal 200-ms AuxOffset to
           AUX_ADV_IND. Include the Lower Tester's public AdvA and SyncInfo with
           SCA=0 and Interval=1 s. Continue extended advertisements until stopped.
        4. Require an Extended Advertising Report with a nonzero periodic
           interval, Complete data status, and valid RSSI. Also check the public
           advertiser address, SID, and the selected 1-s interval.
        5. After two nominal reports, send AUX_ADV_IND 0.5 us inside the early
           widened receive-window edge. Widening is 500/1000000 * AuxOffset
           + 16 us; integer-microsecond vector limitations are recorded below.
        6. Require an Extended Advertising Report for the early-edge packet,
           with a nonzero periodic interval, Complete status, and valid RSSI.
        7. After two early-edge reports, send AUX_ADV_IND 0.5 us inside the late
           widened receive-window edge, using the same widening calculation.
        8. Require an Extended Advertising Report for the late-edge packet,
           with a nonzero periodic interval, Complete status, and valid RSSI.
        9. Send LE Periodic Advertising Create Sync: Options=0, matching SID and
           public advertiser address, Skip=0, Sync_Timeout=three times the
           reported periodic interval (3 s), and Sync_CTE_Type=0. Require
           successful Command Status, correcting the source event name.
        10. Send AUX_SYNC_IND in the 1-s train with one random data octet and an
            AuxPtr to the first AUX_CHAIN_IND. Place it 0.5 us inside the early
            acquisition-window edge, one offset unit after receiveWindowStart,
            using widening 500/1000000 * SyncOffset + 16 us.
        11. Require successful Periodic Advertising Sync Established with a
            valid handle and the advertised SID. Also check advertiser identity,
            LE 1M PHY, 1-s interval, and 500-ppm clock accuracy.
        12. Terminate synchronization using the handle from Step 11 and require
            successful Command Complete.
        13. Repeat Steps 9-11, now placing AUX_SYNC_IND 0.5 us inside the late
            acquisition-window edge, before receiveWindowEnd.
        14. Skip Steps 15-16 if Scan_Max_Data is below three octets. This IUT
            supports at least three octets, so execute both steps.
        15. Send two AUX_CHAIN_IND PDUs, each with one random data octet. Place
            the first 0.5 us inside its early widened window and the second
            0.5 us inside its late window. Separate them as far as practical
            within the 1-s interval; retain extended advertisements between
            them. Use widening 500/1000000 * AuxOffset + 16 us.
        16. Require multiple v1 Periodic Advertising Reports on the same handle.
            All except the last must have Data_Status=0x01 (More); the last must
            have Data_Status=0x00 (Complete). Their concatenated data must equal
            the three transmitted octets, in order.

        Cleanup: terminate the remaining synchronization and disable scanning.

    Expected Outcome:
        Pass verdict:
            Source Steps 6 and 8 produce complete extended reports at the
            widened auxiliary edges. Step 11 establishes synchronization at
            both acquisition edges. Step 16 reports all three periodic data
            octets without truncation, with the required fragment statuses.

    Source Correction:
        Step 10's 5-s interval is treated as an editorial error: use the 1-s
        interval advertised by SyncInfo in Step 3 throughout. This interpretation
        was approved during review; it is not a published SIG erratum. Step 9
        requires Command Status, not the source's Command Complete, because
        LE Periodic Advertising Create Sync is an asynchronous HCI command.

    Review Limitation:
        The source requires 0.5-us boundary guards. The current vectors use
        rounded integer-microsecond widening and 1-us guards, with an encoded
        AuxOffset of 199980 us below the nominal 200 ms. These exercise reception
        near the boundaries but do not establish exact 0.5-us boundary coverage.
        Keep this case limited even when its executable assertions pass.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, Section 4.2.4.31, LL/DDI/SCN/BV-131-C; PDF pages 468-473,
        printed pages 4.2-375 through 4.2-380. Steps 1-16 and Expected Outcome.
        Core Vol 6, Part B, Sections 4.4.2.13.1 and 4.4.3.4 define the receive
        windows; Vol 4, Part E, Section 7.7.65.15 defines v1 periodic reports.
    """
    await tester.command(
        scan_parameters(
            extended=True,
            scan_types=[0],
            scan_intervals=[SCANNING_SCAN_INTERVAL],
            scan_windows=[SCANNING_SCAN_INTERVAL],
        )
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    train = PeriodicTrain(
        tester.radio.now_us + PHY_TIME_UNITS_PER_SECOND,
        interval=PERIODIC_RECEPTION_PERIODIC_INTERVAL,
    )
    generator = random.Random(0)
    adi = ADVERTISING_SID << PDU_ADV_ADI_DID_BITS

    async def announce(shift=0):
        start = tester.radio.now_us + 1000
        reference = start + ANNOUNCEMENT_OFFSET_US + shift
        while train.anchor <= reference:
            train.next_event()
        sync = train.sync_info(reference)
        await tester.transmit(
            37, ext_pdu(adi=adi, aux=_pointer(ANNOUNCEMENT_OFFSET_US)), start_us=start
        )
        await tester.transmit(
            0,
            ext_pdu(address=LOWER_PERIPHERAL_PUBLIC_ADDRESS, adi=adi, sync=sync),
            start_us=reference,
        )
        await tester.wait(1000)
        if event := tester.take(lambda event: isinstance(event, AdvertisingReport)):
            report = event.reports[0]
            assert (
                report.event_type == 0
                and report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
            )
            assert report.address_type == hci.AddressType.PUBLIC_DEVICE
            assert report.advertising_sid == ADVERTISING_SID
            assert (
                report.periodic_advertising_interval
                == PERIODIC_RECEPTION_PERIODIC_INTERVAL
            )
            assert -127 <= report.rssi <= 20
            return (
                reference,
                PeriodicTrain.from_advertisement(
                    SimpleNamespace(start_us=reference, phy=Phy.LE_1M), {'sync': sync}
                ),
            )
        return None

    async def continue_announcements(until):
        while tester.radio.now_us + ANNOUNCEMENT_OFFSET_US + 2000 < until:
            await announce()

    margin = _widening(ANNOUNCEMENT_OFFSET_US)
    for shift in (0, -margin + 1, margin - 1):
        for _ in range(2):
            for _ in range(20):
                train.anchor = tester.radio.now_us + PHY_TIME_UNITS_PER_SECOND
                if await announce(shift):
                    break
            else:
                raise AssertionError('no auxiliary window-edge report')
    for latest in (False, True):
        await tester.command(
            create_sync(
                options=0,
                advertising_sid=ADVERTISING_SID,
                advertiser_address_type=hci.AddressType.PUBLIC_DEVICE,
                advertiser_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
                skip=0,
                sync_timeout=3
                * PERIODIC_RECEPTION_PERIODIC_INTERVAL
                * LL_PERIODIC_INTERVAL_UNIT_US
                // hci.HCI_LE_PERIODIC_SYNC_TIMEOUT_UNIT_US,
                sync_cte_type=0,
            )
        )
        train.anchor = tester.radio.now_us + PHY_TIME_UNITS_PER_SECOND
        for _ in range(20):
            if observed := (await announce()):
                break
        else:
            raise AssertionError('no acquisition SyncInfo report')
        reference, candidate = observed
        margin = _widening(candidate.anchor - reference)
        start = (
            candidate.anchor + margin + candidate.offset_unit - 1
            if latest
            else candidate.anchor - margin + candidate.offset_unit + 1
        )
        data = bytes(generator.randint(1, 255) for _ in range(3))
        await tester.transmit(
            candidate.channel,
            ext_pdu(data=data[:1], aux=_pointer(PERIODIC_WINDOW_CHAIN_OFFSET_US)),
            start_us=start,
            **candidate.parameters,
        )
        event = await tester.event(SyncEstablished)
        assert event.status == hci.HCI_ErrorCode.SUCCESS
        assert (
            event.advertising_sid == ADVERTISING_SID
            and event.advertiser_address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
        )
        assert event.advertiser_address_type == hci.AddressType.PUBLIC_DEVICE
        assert event.advertiser_phy == Phy.LE_1M
        assert (
            event.periodic_advertising_interval == PERIODIC_RECEPTION_PERIODIC_INTERVAL
        )
        assert event.advertiser_clock_accuracy == LL_SCA_500_PPM
        handle = event.sync_handle
        if not latest:
            await tester.command(
                hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle)
            )
            tester.events[:] = [
                event
                for event in tester.events
                if not isinstance(event, PeriodicReport)
            ]
            continue
        train.anchor = (
            start + PERIODIC_RECEPTION_PERIODIC_INTERVAL * LL_PERIODIC_INTERVAL_UNIT_US
        )
        train.counter = candidate.counter + 1 & LL_EVENT_COUNTER_MASK
        first = (
            start
            + PERIODIC_WINDOW_CHAIN_OFFSET_US
            - _widening(PERIODIC_WINDOW_CHAIN_OFFSET_US)
            + 1
        )
        await continue_announcements(first)
        await tester.transmit(
            0,
            ext_pdu(data=data[1:2], aux=_pointer(PERIODIC_WINDOW_CHAIN_OFFSET_US)),
            start_us=first,
            **candidate.parameters,
        )
        second = (
            first
            + PERIODIC_WINDOW_CHAIN_OFFSET_US
            + PDU_ADV_OFFSET_UNIT_300_US
            + _widening(PERIODIC_WINDOW_CHAIN_OFFSET_US)
            - 1
        )
        last_pdu = ext_pdu(data=data[2:])
        assert second + candidate.phy.airtime_us(len(last_pdu)) < train.anchor
        await continue_announcements(second)
        await tester.transmit(0, last_pdu, start_us=second, **candidate.parameters)
        await tester.wait(1000)
        reports = []
        while report := tester.take(lambda event: isinstance(event, PeriodicReport)):
            assert report.sync_handle == handle
            reports.append(report)
        assert len(reports) > 1
        assert b''.join(report.data for report in reports) == data
        assert all(
            report.data_status == AdvertisingReport.DATA_INCOMPLETE_MORE_TO_COME
            for report in reports[:-1]
        )
        assert reports[-1].data_status == AdvertisingReport.DATA_COMPLETE
        await tester.command(
            hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle)
        )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


PROCEDURES: ProcedureMap = {}

# Verify the selected advertising PDU, contents, interval bounds and distribution of the
# random advertising delay.
PROCEDURES |= procedure_cases(
    advertising_events,
    {
        'LL/DDI/ADV/BV-01-C': (
            'Non-Connectable Advertising Events',
            {'nonconnectable': True},
        ),
        'LL/DDI/ADV/BV-02-C': (
            'Undirected Advertising Events',
            {'nonconnectable': False},
        ),
    },
)

# Verify that advertising carries each Host-provided data round exactly.
PROCEDURES |= procedure_cases(
    advertising_data,
    {
        'LL/DDI/ADV/BV-03-C': (
            'Advertising Data: Non-Connectable',
            {'nonconnectable': True},
        ),
        'LL/DDI/ADV/BV-04-C': (
            'Advertising Data: Undirected',
            {'nonconnectable': False},
        ),
    },
)

# Verify scan response timing, data and continued connectable advertising.
PROCEDURES |= procedure_cases(
    scan_request_connectable,
    {
        'LL/DDI/ADV/BV-05-C': (
            'Scan Request: Undirected Connectable',
            {},
        ),
    },
)

# Verify connection acceptance, complete Host notification and stopped advertising.
PROCEDURES |= procedure_cases(
    connection_request,
    {
        'LL/DDI/ADV/BV-06-C': (
            'Connection Request',
            {},
        ),
    },
)

# Verify that scan-response handling does not prevent a subsequent connection.
PROCEDURES |= procedure_cases(
    scan_then_connection_request,
    {
        'LL/DDI/ADV/BV-07-C': (
            'Scan Request Connection Request',
            {},
        ),
    },
)

# Verify exact Host-provided data in discoverable ADV_SCAN_IND events.
PROCEDURES |= procedure_cases(
    discoverable_advertising_data,
    {
        'LL/DDI/ADV/BV-16-C': (
            'Advertising Data: Discoverable',
            {},
        ),
    },
)

# Verify scan responses and continued discoverable advertising.
PROCEDURES |= procedure_cases(
    scan_request_discoverable,
    {
        'LL/DDI/ADV/BV-17-C': (
            'Scan Request: Discoverable',
            {},
        ),
    },
)

# Verify that invalid-CRC scan requests are ignored without stopping advertising.
PROCEDURES |= procedure_cases(
    scan_request_invalid_crc,
    {
        'LL/DDI/ADV/BI-01-C': (
            'Scan Request Invalid CRC, Connectable and Scannable Undirected',
            {'scannable': False},
        ),
        'LL/DDI/ADV/BI-10-C': (
            'Scan Request Invalid CRC, Scannable Undirected',
            {'scannable': True},
        ),
    },
)

# Verify that corrupted connection requests cannot establish an ACL or stop advertising.
PROCEDURES |= procedure_cases(
    connection_request_invalid_crc,
    {
        'LL/DDI/ADV/BI-02-C': (
            'Connection Request Invalid CRC',
            {},
        ),
    },
)

# Verify low-duty directed PDU contents/timing, connection acceptance and establishment
# timeout when the Lower Tester sends no connection data.
PROCEDURES |= procedure_cases(
    low_duty_directed_advertising,
    {
        'LL/DDI/ADV/BV-19-C': (
            'Low Duty Cycle Directed Advertising Events',
            {},
        ),
    },
)

# Verify legacy advertising remains on LE 1M despite Host preference for LE 2M.
PROCEDURES |= procedure_cases(
    advertising_always_le_1m,
    {
        'LL/DDI/ADV/BV-111-C': (
            'Advertising Always Using the LE 1M PHY, Non-connectable',
            {'nonconnectable': True},
        ),
        'LL/DDI/ADV/BV-20-C': (
            (
                'Advertising Always Using the LE 1M PHY, Connectable and '
                'Scannable Undirected'
            ),
            {'nonconnectable': False},
        ),
    },
)

# Verify extended HCI commands configure legacy non-connectable PDUs and data.
PROCEDURES |= procedure_cases(
    extended_legacy_nonconnectable,
    {
        'LL/DDI/ADV/BV-21-C': (
            'Extended Advertising, Legacy PDUs, Non-Connectable',
            {},
        ),
    },
)

# Verify the prescribed HCI family, legacy PDU, ChSel and data/channel rounds.
PROCEDURES |= procedure_cases(
    extended_legacy_undirected,
    {
        'LL/DDI/ADV/BV-112-C': (
            'Extended Advertising, Legacy PDUs, Undirected, Non-connectable',
            {},
        ),
        'LL/DDI/ADV/BV-113-C': (
            'Extended Advertising, Legacy PDUs, Undirected, CSA #1, Non-connectable',
            {'extended': True},
        ),
        'LL/DDI/ADV/BV-22-C': (
            (
                'Extended Advertising, Legacy PDUs, CSA #2, Connectable and'
                ' Scannable Undirected'
            ),
            {'connectable': True},
        ),
    },
)

# Verify non-connectable extended advertising on the primary and secondary channels:
# payload fields, AuxPtr timing, complete data chains, directed and undirected events,
# and commanded duration/event-count limits.
PROCEDURES |= procedure_cases(
    extended_nonconnectable,
    {
        'LL/DDI/ADV/BV-47-C': (
            'Extended Advertising, Non-Connectable – LE 1M PHY',
            {'phy': Phy.LE_1M},
        ),
        'LL/DDI/ADV/BV-48-C': (
            'Extended Advertising, Non-Connectable – LE Coded PHY',
            {'phy': Phy.LE_CODED},
        ),
        'LL/DDI/ADV/BV-49-C': (
            'Extended Advertising, Non-Connectable – LE 2M PHY',
            {'phy': Phy.LE_2M},
        ),
    },
)

# Verify scannable ADV_EXT_IND/AUX_ADV_IND fields, secondary-channel scan
# requests/responses, complete response data chains, directed/undirected events, request
# notifications, and continued advertising after a response.
PROCEDURES |= procedure_cases(
    extended_scan_response,
    {
        'LL/DDI/ADV/BV-45-C': (
            'Extended Advertising, Scannable – ADI allowed in scan response',
            {'phy': Phy.LE_1M},
        ),
        'LL/DDI/ADV/BV-52-C': (
            (
                'Extended Advertising, Scannable – ADI allowed in scan '
                'response – LE 2M PHY'
            ),
            {'phy': Phy.LE_2M},
        ),
        'LL/DDI/ADV/BV-54-C': (
            (
                'Extended Advertising, Scannable – ADI allowed in scan '
                'response – LE Coded PHY'
            ),
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify ADV_EXT_IND/AUX_ADV_IND announcements, SyncInfo, periodic packet timing and CSA
# #2 channels, and exact data with and without chaining. Confirm that periodic
# advertising continues after extended advertising is disabled, using each selected PHY
# and data length.
PROCEDURES |= procedure_cases(
    periodic_advertising,
    {
        'LL/DDI/ADV/BV-26-C': (
            'Extended Advertising, Periodic Advertising – LE 1M PHY',
            {'phy': Phy.LE_1M},
        ),
        'LL/DDI/ADV/BV-55-C': (
            'Extended Advertising, Periodic Advertising – LE 2M PHY',
            {'phy': Phy.LE_2M},
        ),
        'LL/DDI/ADV/BV-56-C': (
            'Extended Advertising, Periodic Advertising – LE Coded PHY',
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify non-connectable, undirected primary/auxiliary advertising and complete data
# chains while the Host changes data on an enabled set. Confirm that changed RF data
# changes DID and new-DID data exactly matches the current Host submission,
# independently of fragmentation boundaries.
PROCEDURES |= procedure_cases(
    extended_data_update,
    {
        'LL/DDI/ADV/BV-27-C': (
            'Extended Advertising, Host Modifying Data and ADI',
            {},
        ),
    },
)

# Verify that primary advertising events refer to a valid secondary PDU and correctly
# implement Secondary_Advertising_Max_Skip. Observe event timing and packet contents,
# including AuxPtrs from overlapping events.
PROCEDURES |= procedure_cases(
    overlapping_events,
    {
        'LL/DDI/ADV/BV-28-C': (
            'Extended Advertising, Overlapping Extended Advertising Events',
            {},
        ),
        'LL/DDI/ADV/BV-115-C': (
            (
                'Extended Advertising, Overlapping Extended Advertising '
                'Events, Connectable'
            ),
            {'rounds': (4,)},
        ),
        'LL/DDI/ADV/BV-116-C': (
            (
                'Extended Advertising, Overlapping Extended Advertising '
                'Events, Directed'
            ),
            {'rounds': (5,)},
        ),
        'LL/DDI/ADV/BV-117-C': (
            (
                'Extended Advertising, Overlapping Extended Advertising '
                'Events, Connectable Directed'
            ),
            {'rounds': (6,)},
        ),
    },
)

# Verify simultaneous LE 1M advertising sets with the configured payload fields, timing
# and channels, with and without data. Check interlaced primary events and exact
# independently submitted data through auxiliaries and chains when present.
PROCEDURES |= procedure_cases(
    multiple_sets_1m,
    {
        'LL/DDI/ADV/BV-29-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY',
            {'rounds': (4, 7)},
        ),
        'LL/DDI/ADV/BV-118-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY',
            {'rounds': (1, 2, 6)},
        ),
        'LL/DDI/ADV/BV-119-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY',
            {'rounds': (5,)},
        ),
        'LL/DDI/ADV/BV-120-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY',
            {'rounds': (3,)},
        ),
    },
)

# Verify simultaneous advertising sets using the assigned Coded/Coded or 1M/Coded PHY
# pair, including empty data, directed/connectable properties, interlaced primary
# events, valid auxiliary timing and complete data chains.
PROCEDURES |= procedure_cases(
    multiple_sets_phys,
    {
        'LL/DDI/ADV/BV-30-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE Coded PHY',
            {'phys': (Phy.LE_CODED, Phy.LE_CODED)},
        ),
        'LL/DDI/ADV/BV-31-C': (
            (
                'Extended Advertising, Multiple Sets, Multiple PHYs, LE 1M '
                'and LE Coded PHYs'
            ),
            {'phys': (Phy.LE_1M, Phy.LE_CODED)},
        ),
    },
)

# Verify parallel legacy and extended advertising sets, including correct payload
# fields, timing and channels, empty/nonempty data and complete auxiliary chains.
# Distinguish sets by their prescribed PDU types and data.
PROCEDURES |= procedure_cases(
    multiple_legacy_extended_sets,
    {
        'LL/DDI/ADV/BV-32-C': (
            'Extended Advertising, Multiple Sets, Legacy and Extended',
            {'rounds': (1,)},
        ),
        'LL/DDI/ADV/BV-121-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY',
            {'rounds': (2, 3, 4)},
        ),
        'LL/DDI/ADV/BV-122-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY',
            {'rounds': (5,)},
        ),
        'LL/DDI/ADV/BV-123-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY',
            {'rounds': (6,)},
        ),
        'LL/DDI/ADV/BV-124-C': (
            'Extended Advertising, Multiple Sets, Single PHY, LE 1M PHY',
            {'rounds': (7,)},
        ),
    },
)

# Verify simultaneous periodic advertising sets on the same or different supported PHYs,
# their announcement timing and packet contents, independent CSA #2 channel sequences,
# and continued synchronization when the associated extended advertising is disabled in
# stages.
PROCEDURES |= procedure_cases(
    multiple_periodic_sets,
    {
        'LL/DDI/ADV/BV-33-C': (
            (
                'Extended Advertising, Periodic Advertising, Multiple Sets,'
                ' Multiple PHYs (All Supported PHYs)'
            ),
            {},
        ),
    },
)

# Verify the declared maximum simultaneous advertising sets, including interlaced
# primary/auxiliary events, correct timing and channel use, and complete
# minimum-supported Host data in each set's auxiliary chain.
PROCEDURES |= procedure_cases(
    maximum_sets,
    {
        'LL/DDI/ADV/BV-35-C': (
            'Extended Advertising, Multiple Sets, Maximum Supported Sets',
            {},
        ),
    },
)

# Verify that every SyncInfo describing the same periodic advertising train has
# identical Access Address and CRCInit, using non-connectable and non-scannable
# advertisements.
PROCEDURES |= procedure_cases(
    stable_sync_info,
    {
        'LL/DDI/ADV/BV-43-C': (
            'Periodic Advertising validating SyncInfo fields',
            {},
        ),
    },
)

# Verify that a legacy-PDU advertising set rejects a 32-octet advertising data
# replacement while enabled, returning Invalid HCI Command Parameters.
PROCEDURES |= procedure_cases(
    invalid_legacy_size,
    {
        'LL/DDI/ADV/BI-05-C': (
            (
                'Disallow Extended Advertising PDU sizes for Legacy '
                'Advertising when advertising enabled'
            ),
            {},
        ),
        'LL/DDI/ADV/BI-06-C': (
            (
                'Disallow Extended Advertising PDU sizes for Scannable '
                'Legacy Advertising when advertising enabled'
            ),
            {'scannable': True},
        ),
    },
)

# Verify that invalid-hop connection requests either leave the advertiser advertising
# without data responses, or result in a connection with stopped advertising and
# acknowledged data. Exercise every specified invalid hop increment using the applicable
# behavior of this DUT.
PROCEDURES |= procedure_cases(
    invalid_hop_increment,
    {
        'LL/DDI/ADV/BI-07-C': (
            'Connection Request Invalid Hop Increment',
            {},
        ),
    },
)

# Verify that high-duty connectable directed advertising times out without completing a
# connection with the Lower Tester.
PROCEDURES |= procedure_cases(
    high_duty_without_connection,
    {
        'LL/DDI/ADV/BV-80-C': (
            'High Duty Cycle Connectable Directed Advertising, No Connection',
            {},
        ),
    },
)

# Verify advertising occurs on every enabled primary channel and nowhere on disabled
# primary channels.
PROCEDURES |= procedure_cases(
    selected_channels,
    {
        'LL/DDI/ADV/BV-106-C': (
            'Advertising on Selected Channels',
            {},
        ),
    },
)

# Verify that each advertising event uses only its configured primary PDU type when
# legacy and extended sets are active together. Check interlacing, configured intervals
# and the set-specific data where the procedure loads it; directed legacy rows carry no
# advertising data.
PROCEDURES |= procedure_cases(
    multiple_legacy_and_extended_primary_advertising_sets,
    {
        'LL/DDI/ADV/BV-64-C': (
            'Non-Connectable and Non-Scannable Undirected',
            {'number': 64},
        ),
        'LL/DDI/ADV/BV-65-C': (
            'Connectable and Scannable Undirected',
            {'number': 65},
        ),
        'LL/DDI/ADV/BV-66-C': (
            'Connectable Directed – High Duty Cycle',
            {'number': 66},
        ),
        'LL/DDI/ADV/BV-67-C': (
            'Connectable Directed – Low Duty Cycle',
            {'number': 67},
        ),
        'LL/DDI/ADV/BV-68-C': (
            'Scannable Undirected',
            {'number': 68},
        ),
    },
)

# Verify that a passive scanner detects and reports non-connectable or undirected
# advertising. The Lower Tester uses one primary channel at a time and an event sequence
# number as advertising data.
PROCEDURES |= procedure_cases(
    passive_scanning,
    {
        'LL/DDI/SCN/BV-01-C': (
            'Passive Scanning: Non-connectable',
            {'kind': 2},
        ),
        'LL/DDI/SCN/BV-10-C': (
            'Passive Scanning: Undirected Events',
            {'kind': 0},
        ),
    },
)

# Verify that passive scanning reports a specific advertiser through address/type
# filtering. Non-connectable advertising on one selected channel carries the packet
# sequence number as data.
PROCEDURES |= procedure_cases(
    passive_scanning_device_filtering,
    {
        'LL/DDI/SCN/BV-02-C': (
            'Passive Scanning Device Filtering',
            {},
        ),
    },
)

# Verify that an active scanner detects advertisers, requests additional information and
# reports both advertising and scan-response data. The Lower Tester emulates multiple
# public advertisers on one channel at a time and checks SCAN_REQ contents, exchange
# timing and the corresponding HCI reports.
PROCEDURES |= procedure_cases(
    active_scanning,
    {
        'LL/DDI/SCN/BV-03-C': (
            'Active Scanning',
            {},
        ),
    },
)

# Verify that active scanning requests and reports additional information only for the
# advertiser permitted by the filtering policy. The Lower Tester sends connectable
# undirected advertising with event-counter data, one selected channel at a time, and
# responds only when requested.
PROCEDURES |= procedure_cases(
    active_scanning_device_filtering,
    {
        'LL/DDI/SCN/BV-04-C': (
            'Active Scanning Device Filtering',
            {},
        ),
    },
)

# Verify that an accept-all active scanner detects different advertising types and
# addresses on multiple channels, requests data only from the scannable type and reports
# the transmitted advertising/response contents.
PROCEDURES |= procedure_cases(
    scanning_for_advertiser_types,
    {
        'LL/DDI/SCN/BV-05-C': (
            'Scanning For Advertiser Types',
            {},
        ),
    },
)

# Verify that passive scanning detects and reports directed advertising from the
# permitted advertiser. Exercise one primary channel at a time and distinguish the same
# address bytes with a different address type.
PROCEDURES |= procedure_cases(
    passive_scanning_directed_events,
    {
        'LL/DDI/SCN/BV-11-C': (
            'Passive Scanning: Directed Events',
            {},
        ),
    },
)

# Verify that a passive scanner correctly detects and reports legacy and extended
# advertising, including directed and undirected events, primary and auxiliary PDUs, and
# advertisements with or without data.
PROCEDURES |= procedure_cases(
    extended_scanning_passive,
    {
        'LL/DDI/SCN/BV-133-C': (
            'Extended Scanning, Passive – LE 1M PHY/LE Coded PHY',
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_CODED},
        ),
        'LL/DDI/SCN/BV-134-C': (
            'Extended Scanning, Passive – LE Coded PHY/LE 1M PHY',
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-135-C': (
            'Extended Scanning, Passive – LE Coded PHY/LE 2M PHY',
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_2M},
        ),
        'LL/DDI/SCN/BV-19-C': (
            'Extended Scanning, Passive – LE 1M PHY/LE 1M PHY',
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-42-C': (
            'Extended Scanning, Passive – LE 1M PHY/LE 2M PHY',
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_2M},
        ),
        'LL/DDI/SCN/BV-43-C': (
            'Extended Scanning, Passive – LE Coded PHY/LE Coded PHY',
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_CODED},
        ),
    },
)

# Verify that active scanning requests and reports information from scannable extended
# advertising on primary and secondary channels. Exercise directed and undirected
# advertisements and their HCI reports.
PROCEDURES |= procedure_cases(
    extended_scanning_active,
    {
        'LL/DDI/SCN/BV-139-C': (
            'Extended Scanning, Active – LE 1M PHY/LE Coded PHY, Core 5.1',
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_CODED},
        ),
        'LL/DDI/SCN/BV-140-C': (
            'Extended Scanning, Active – LE Coded PHY/LE 1M PHY, Core 5.1',
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-141-C': (
            'Extended Scanning, Active – LE Coded PHY/LE 2M PHY, Core 5.1',
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_2M},
        ),
        'LL/DDI/SCN/BV-64-C': (
            'Extended Scanning, Active – LE 1M PHY, Core 5.1',
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-65-C': (
            'Extended Scanning, Active – LE 2M Phy, Core 5.1',
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_2M},
        ),
        'LL/DDI/SCN/BV-66-C': (
            'Extended Scanning, Active – LE Coded PHY, Core 5.1',
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_CODED},
        ),
    },
)

# Verify that passive scanning reports TxPower from the latest received advertising PDU,
# using a non-connectable, non-scannable auxiliary train.
PROCEDURES |= procedure_cases(
    extended_scanning_passive_reporting_tx_power,
    {
        'LL/DDI/SCN/BV-75-C': (
            'Extended Scanning, Passive, Reporting TX Power – LE 1M PHY',
            {'phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-76-C': (
            'Extended Scanning, Passive, Reporting TX Power – LE Coded PHY',
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify active scanning detects scannable undirected extended advertising, requests
# additional information and reports data with the latest received PDU's TxPower.
PROCEDURES |= procedure_cases(
    extended_scanning_active_reporting_tx_power,
    {
        'LL/DDI/SCN/BV-77-C': (
            'Extended Scanning, Active, Reporting TX Power – LE 1M PHY',
            {'phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-78-C': (
            'Extended Scanning, Active, Reporting TX Power – LE Coded PHY',
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify a passive scanner reports periodic advertising RSSI, TxPower and data status
# while receiving a non-connectable, non-scannable train.
PROCEDURES |= procedure_cases(
    periodic_advertising_report_rssi_power_and_data_status,
    {
        'LL/DDI/SCN/BV-79-C': (
            (
                'Extended Scanning, Passive, Periodic Advertising Report, '
                'RSSI, TX_Power, Data Status – LE 1M PHY'
            ),
            {'phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-80-C': (
            (
                'Extended Scanning, Passive, Periodic Advertising Report, '
                'RSSI, TX_Power, Data Status – LE Coded PHY'
            ),
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify a passive scanner locates periodic advertising through extended announcements,
# synchronizes using CSA #2 and reports periodic data, including after extended
# announcements stop.
PROCEDURES |= procedure_cases(
    extended_scanning_periodic_advertising_reception,
    {
        'LL/DDI/SCN/BV-142-C': (
            (
                'Extended Scanning, Periodic Advertising Reception – LE 1M '
                'PHY/LE Coded PHY'
            ),
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_CODED},
        ),
        'LL/DDI/SCN/BV-143-C': (
            (
                'Extended Scanning, Periodic Advertising Reception – LE '
                'Coded PHY/LE 1M PHY'
            ),
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-144-C': (
            (
                'Extended Scanning, Periodic Advertising Reception – LE '
                'Coded PHY/LE 2M PHY'
            ),
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_2M},
        ),
        'LL/DDI/SCN/BV-21-C': (
            'Extended Scanning, Periodic Advertising Reception – LE 1M PHY',
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-46-C': (
            'Extended Scanning, Periodic Advertising Reception – LE 2M PHY',
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_2M},
        ),
        'LL/DDI/SCN/BV-47-C': (
            'Extended Scanning, Periodic Advertising Reception – LE Coded PHY',
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_CODED},
        ),
    },
)

# Verify passive scanning detects and reports multiple non-connectable, non-scannable
# advertising sets across every supported PHY pair.
PROCEDURES |= procedure_cases(
    extended_scanning_multiple_sets_passive_multiple_phys_all_supported_phys,
    {
        'LL/DDI/SCN/BV-23-C': (
            (
                'Extended Scanning, Multiple Sets, Passive, Multiple PHYs '
                '(All Supported PHYs)'
            ),
            {},
        ),
    },
)

# Verify active scanning requests information on the secondary channel and reports each
# of multiple scannable advertising sets across supported PHYs.
PROCEDURES |= procedure_cases(
    extended_scanning_multiple_sets_active_multiple_phys_all_supported_phys,
    {
        'LL/DDI/SCN/BV-62-C': (
            (
                'Extended Scanning, Multiple Sets, Active, Multiple PHYs '
                '(All Supported PHYs), Core 5.1'
            ),
            {},
        ),
    },
)

# Verify periodic advertising discovery, synchronization and data reporting across all
# supported PHYs while several advertising sets remain active.
PROCEDURES |= procedure_cases(
    multiple_periodic_advertisers_all_supported_phys,
    {
        'LL/DDI/SCN/BV-25-C': (
            (
                'Extended Scanning, Multiple Sets, Periodic Advertising '
                'Reception, Multiple PHYs (All Supported PHYs)'
            ),
            {},
        ),
    },
)

# Verify periodic synchronization follows either explicit peer selection or the Periodic
# Advertiser List, independently of scan-report filtering.
PROCEDURES |= procedure_cases(
    extended_scanning_periodic_advertising_reception_filter_policies,
    {
        'LL/DDI/SCN/BV-34-C': (
            'Extended Scanning, Periodic Advertising Reception, Filter Policies',
            {},
        ),
    },
)

# Verify synchronization fails after six initial periodic receive opportunities without
# AUX_SYNC_IND, even when valid periodic packets start at the seventh event.
PROCEDURES |= procedure_cases(
    first_aux_sync_ind_never_received,
    {
        'LL/DDI/SCN/BV-37-C': (
            'First AUX_SYNC_IND Never Received',
            {},
        ),
    },
)

# Verify periodic synchronization can succeed while reporting is initially disabled,
# reports start when enabled and stop when disabled again.
PROCEDURES |= procedure_cases(
    extended_scanning_periodic_advertising_reception_reporting_initially_disabled,
    {
        'LL/DDI/SCN/BV-38-C': (
            (
                'Extended Scanning, Periodic Advertising Reception, '
                'Reporting Initially Disabled – LE 1M PHY'
            ),
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_1M},
        ),
        'LL/DDI/SCN/BV-60-C': (
            (
                'Extended Scanning, Periodic Advertising Reception, '
                'Reporting Initially Disabled – LE 2M PHY'
            ),
            {'primary_phy': Phy.LE_1M, 'secondary_phy': Phy.LE_2M},
        ),
        'LL/DDI/SCN/BV-61-C': (
            (
                'Extended Scanning, Periodic Advertising Reception, '
                'Reporting Initially Disabled – LE Coded PHY'
            ),
            {'primary_phy': Phy.LE_CODED, 'secondary_phy': Phy.LE_CODED},
        ),
    },
)

# Verify active scanning ignores advertising indications with invalid CRC, sends no scan
# request for them and does not report a CRC-invalid scan response to a valid
# advertisement.
PROCEDURES |= procedure_cases(
    active_scanning_invalid_crc,
    {
        'LL/DDI/SCN/BI-01-C': (
            'Active Scanning Invalid CRC',
            {},
        ),
    },
)

# Verify passive scanning ignores and does not report advertising packets with invalid
# CRC on every supported primary advertising channel.
PROCEDURES |= procedure_cases(
    passive_scanning_invalid_crc,
    {
        'LL/DDI/SCN/BI-02-C': (
            'Passive Scanning Invalid CRC',
            {},
        ),
    },
)

# Verify that a passive scanner locates and receives periodic advertising, reports its
# data, and maintains synchronization across a Channel Map Update Indication from the
# Lower Tester.
PROCEDURES |= procedure_cases(
    periodic_advertising_reception_channel_map_update,
    {
        'LL/DDI/SCN/BV-67-C': (
            'Periodic Advertising Reception, Channel Map Update',
            {},
        ),
    },
)

# Verify that a scanner without Periodic Advertising ADI Support ignores the ADI field
# in AUX_SYNC_IND and continues reporting periodic advertising before and after the DID
# changes.
PROCEDURES |= procedure_cases(
    unsupported_periodic_advertising_adi_is_ignored,
    {
        'LL/DDI/SCN/BV-68-C': (
            (
                'Scanner not supporting Periodic Advertising ADI accepts '
                'Advertising PDU with ADI Set – AUX_SYNC_IND'
            ),
            {},
        ),
    },
)

# Verify that a scanner rejects an extended advertising AuxPtr whose AUX PHY value is
# reserved, rather than reporting its auxiliary advertisement.
PROCEDURES |= procedure_cases(
    passive_scanning_invalid_or_unsupported_phy,
    {
        'LL/DDI/SCN/BI-06-C': (
            'Passive Scanning, Invalid or Unsupported PHY, RFU Bits Specified',
            {},
        ),
    },
)

# Verify that a legacy passive scanner reports sequenced nonconnectable legacy
# advertisements, ignores intervening extended advertisements, and continues reporting
# the subsequent legacy traffic.
PROCEDURES |= procedure_cases(
    legacy_scanning_ignore_extended_advertising_packets,
    {
        'LL/DDI/SCN/BV-74-C': (
            'Legacy Scanning Ignore Extended Advertising Packets',
            {},
        ),
    },
)

# Verify that an active scanner ignores reserved fields in received legacy advertising
# PDUs, reports the advertising correctly, and requests scan responses only for
# scannable advertising types.
PROCEDURES |= procedure_cases(
    legacy_scanning_properly_ignore_rfu_fields_legacy_advertising,
    {
        'LL/DDI/SCN/BV-86-C': (
            'Legacy Scanning, Active, Properly Ignore RFU Fields',
            {},
        ),
    },
)

# Verify that a scanner ignores RFU fields in Advertising and Scanning PDUs. The Lower
# Tester sends extended events on one channel at a time, and the IUT reports the
# advertising to the Upper Tester.
PROCEDURES |= procedure_cases(
    extended_scanning_properly_ignore_rfu_fields_extended_advertising,
    {
        'LL/DDI/SCN/BV-88-C': pytest.param(
            'Extended Scanning, Active, Properly Ignore RFU Fields',
            {},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that a scanner ignores all RFU fields in extended announcements and periodic
# packets, establishes synchronization, reports the advertised data, and terminates
# periodic reception when instructed by the Host.
PROCEDURES |= procedure_cases(
    extended_scanning_periodic_advertising_properly_ignore_rfu_fields,
    {
        'LL/DDI/SCN/BV-89-C': (
            'Extended Scanning, Periodic Advertising, Properly Ignore RFU Fields',
            {},
        ),
    },
)

# Verify that a scanner ignores directed advertisements whose AdvA is not in its Filter
# Accept List, even when TargetA matches the IUT.
PROCEDURES |= procedure_cases(
    ignore_directed_advertising_address_not_in_filter_accept_list,
    {
        'LL/DDI/SCN/BV-90-C': (
            'Ignore Directed Advertising, Address Not In Filter Accept List',
            {},
        ),
    },
)

# Verify that an IUT already synchronized to a periodic advertiser rejects a second
# synchronization request with the same address, address type, and Advertising SID.
PROCEDURES |= procedure_cases(
    pawr_trains_with_same_identity_do_not_synchronize,
    {
        'LL/DDI/SCN/BV-96-C': (
            (
                'Periodic Advertising with Responses Trains, Do Not '
                'Synchronize with Same Address, Address Type, Advertising '
                'SID – AUX_SYNC_IND'
            ),
            {},
        ),
    },
)

# Verify that a scanner without Periodic Advertising with Responses (PAwR) support
# ignores an advertiser's connection request while continuing to receive the train as
# ordinary periodic advertising.
PROCEDURES |= procedure_cases(
    ignore_a_connection_request_periodic_advertising_with_responses_not_supported,
    {
        'LL/DDI/SCN/BV-99-C': (
            (
                'Ignore a Connection Request, Periodic Advertising with '
                'Responses Not Supported'
            ),
            {},
        ),
    },
)

# Verify that a legacy passive scanner without Decision-Based Advertising Filtering
# support ignores Decision PDUs rather than reporting them as legacy advertisements.
PROCEDURES |= procedure_cases(
    decision_based_advertisements_ignored_legacy_scanning,
    {
        'LL/DDI/SCN/BV-104-C': (
            'Decision-Based Advertisements Ignored, Legacy Scanning',
            {},
        ),
    },
)

# Verify that duplicate filtering suppresses repeated legacy advertising and
# scan-response reports without preventing scan-request retries after the Lower Tester
# initially withholds responses.
PROCEDURES |= procedure_cases(
    active_scanning_duplicate_filtering,
    {
        'LL/DDI/SCN/BV-127-C': pytest.param(
            'Active Scanning, Duplicate Filtering',
            {},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that duplicate filtering suppresses repeated extended advertising and
# scan-response reports without preventing retries after initial unanswered AUX_SCAN_REQ
# packets.
PROCEDURES |= procedure_cases(
    extended_scanning_active_duplicate_filtering,
    {
        'LL/DDI/SCN/BV-128-C': pytest.param(
            'Extended Scanning, Active, Duplicate Filtering',
            {},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify reception of extended and periodic advertising packets at both edges of the
# receive window widened for the Lower Tester's clock accuracy.
PROCEDURES |= procedure_cases(
    extended_scanning_passive_periodic_advertising_report_window_widening,
    {
        'LL/DDI/SCN/BV-131-C': pytest.param(
            (
                'Extended Scanning, Passive, Periodic Advertising Report, '
                'Window Widening, LE Periodic Advertising Report [v1]'
            ),
            {},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify passive discovery of undirected advertising on each selected channel, including
# rejection of an unlisted address or address type. Advertising payloads identify their
# event sequence.
PROCEDURES |= procedure_cases(
    passive_scanning_discoverable_events,
    {
        'LL/DDI/SCN/BV-12-C': (
            'Passive Scanning: Discoverable Events',
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_device_discovery(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
