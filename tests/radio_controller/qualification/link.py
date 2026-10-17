# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Shared independent lower-tester protocol algorithms."""

import csv
import random
import struct
from dataclasses import dataclass, replace

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from bumble import hci
from bumble.ll import (
    LL_ADV_DELAY_MAX_US,
    LL_CONN_INTERVAL_UNIT_US,
    LL_CONN_WINDOW_SIZE_MAX,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_EVENT_COUNTER_MASK,
    LL_IFS_US,
    PDU_ADV_ACCESS_ADDRESS,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_ADDRESSES_END,
    PDU_ADV_ADI_DID_BITS,
    PDU_ADV_CONNECT_SCA_SHIFT,
    PDU_ADV_RXADD_MASK,
    PDU_ADV_TXADD_MASK,
    PDU_ADV_TYPE_MASK,
    PDU_DATA_AUTHENTICATED_HEADER_MASK,
    PDU_DATA_LLID_MASK,
    PDU_DATA_MIC_SIZE,
    PDU_DATA_NESN_MASK,
    PDU_DATA_SN_MASK,
    PDU_HEADER_SIZE,
    AdvertisingPduType,
    ControlPdu,
    LlId,
)
from bumble.radio_controller.radio import Phy
from tests.radio_controller.qualification.peer import PeerLink
from tests.radio_controller.qualification.tester import (
    DUT_ADDRESS,
    LOWER_CENTRAL_PUBLIC_ADDRESS,
    LOWER_DATA_ACCESS_ADDRESS,
    LOWER_PERIPHERAL_PUBLIC_ADDRESS,
    LinkParameters,
    adv_pdu,
    create_connection,
    legacy_parameters,
    request_pdu,
    scan_parameters,
)

# Public test vector: the Lower Tester's four-octet initialization-vector component.
IV = bytes(range(4))
# Public, fixed tester vectors; not application credentials or private keys.
LTK = bytes(range(16))
# Public test vector: the Lower Tester's eight-octet session-key-diversifier component.
SKD = bytes(range(8))
# Selected scanner IXIT: minimum base advertising interval with 5-ms mean AdvDelay.
SCAN_ADV_INTERVAL_US = hci.HCI_LE_ADV_INTERVAL_MIN * hci.HCI_LE_ADV_INTERVAL_UNIT_US
# LL.TS.p28 scan-response verdict permits a 2-us deviation from T_IFS.
SCAN_RESPONSE_IFS_TOLERANCE_US = 2
# LL.TS.p28 connection-request timing tolerance around T_IFS.
CONNECTION_IFS_TOLERANCE_US = 2
ErrorCode = hci.HCI_ErrorCode


async def _check_parameter_update(
    tester, link, update, interval, timeout, *, optional_error=None, notify=True
):
    size, offset, selected, latency, supervision, _ = struct.unpack(
        '<BHHHHH', update[1:]
    )
    assert (selected, supervision) == (interval, timeout)
    assert LL_CONN_WINDOW_SIZE_MIN <= size <= min(LL_CONN_WINDOW_SIZE_MAX, interval - 1)
    assert 0 <= offset <= interval
    await link.apply_update(update, check_event_timing=True)
    if not notify:
        previous = link.anchor
        await link.exchange()
        assert not any(
            isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
            for event in tester.events
        )
        assert link.anchor - previous == interval * LL_CONN_INTERVAL_UNIT_US
        return
    event = await tester.event(hci.HCI_LE_Connection_Update_Complete_Event)
    while optional_error is not None and event.status != ErrorCode.SUCCESS:
        assert (event.connection_handle, event.status) == (link.handle, optional_error)
        event = await tester.event(hci.HCI_LE_Connection_Update_Complete_Event)
    assert (
        event.status,
        event.connection_handle,
        event.connection_interval,
        event.peripheral_latency,
        event.supervision_timeout,
    ) == (ErrorCode.SUCCESS, link.handle, interval, latency, timeout)
    previous = link.anchor
    await link.exchange()
    assert link.anchor - previous == interval * LL_CONN_INTERVAL_UNIT_US


async def _corrupt_advertisements(tester, channel, *, active):
    generator = random.Random(0)
    kind = AdvertisingPduType.ADV_IND if active else AdvertisingPduType.ADV_NONCONN_IND
    started = tester.radio.now_us
    deadline = started + 20 * SCAN_INTERVAL_US + 1
    requests = 0
    reports = []
    # Submit before the absolute start; PHY rejects TX at its current timestamp.
    event_start = started + 100
    while tester.radio.now_us < deadline:
        await tester.transmit(
            channel,
            adv_pdu(kind, address=LOWER_CENTRAL_PUBLIC_ADDRESS),
            start_us=event_start,
            bad_crc=True,
        )
        response = await tester.receive(channel, duration_us=1000)
        if response is not None:
            assert response.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.SCAN_REQ
            assert active
            requests += 1
        event_start = (
            event_start
            + SCAN_ADV_INTERVAL_US
            + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
        )
        received = _encoding_take_reports(tester)
        reports.extend(received)
    return (requests, reports)


async def _pending_connection(
    tester,
    *,
    central,
    parameters=None,
    advertising_data=b'test',
    advertising_filter_policy=0,
    advertising_channel_map=1,
):
    """Create through HCI/RF without receiving any valid connection DATA at the DUT."""
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
    if central:
        selected = parameters or LinkParameters()
        await tester.command(
            create_connection(
                peer_address_type=peer.address_type,
                peer_address=peer,
                connection_interval_min=selected.interval,
                connection_interval_max=selected.interval,
                max_latency=selected.latency,
                supervision_timeout=selected.timeout,
            )
        )
        end = await tester.transmit(37, adv_pdu(address=peer, data=advertising_data))
        request = await tester.expect_pdu(
            kind=AdvertisingPduType.CONNECT_IND, duration_us=1000
        )
        assert abs(request.start_us - end - LL_IFS_US) <= CONNECTION_IFS_TOLERANCE_US
        assert request.phy == Phy.LE_1M
        assert not request.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
        assert request.pdu[PDU_HEADER_SIZE:PDU_ADV_ADDRESSES_END] == bytes(
            DUT_ADDRESS
        ) + bytes(peer)
        parameters = LinkParameters.decode(request.pdu[PDU_ADV_ADDRESSES_END:])
        assert (parameters.interval, parameters.latency, parameters.timeout) == (
            selected.interval,
            selected.latency,
            selected.timeout,
        )
        end = request.end_us
    else:
        await tester.command(
            legacy_parameters(
                advertising_filter_policy=advertising_filter_policy,
                advertising_channel_map=advertising_channel_map,
            )
        )
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
        advertisement = await tester.expect_pdu(kind=AdvertisingPduType.ADV_IND)
        assert not advertisement.pdu[0] & PDU_ADV_TXADD_MASK
        assert advertisement.pdu[
            PDU_HEADER_SIZE : PDU_HEADER_SIZE + PDU_ADV_ADDRESS_SIZE
        ] == bytes(DUT_ADDRESS)
        parameters = parameters or LinkParameters(
            access_address=LOWER_DATA_ACCESS_ADDRESS, interval=8, timeout=10
        )
        end = await tester.transmit(
            37,
            request_pdu(
                AdvertisingPduType.CONNECT_IND, scanner=peer, data=parameters.encode()
            ),
            start_us=advertisement.end_us + LL_IFS_US,
        )
    link = PeerLink(tester, parameters, end, central=central)
    event = await tester.expect(
        lambda value: isinstance(
            value,
            (
                hci.HCI_LE_Connection_Complete_Event,
                hci.HCI_LE_Enhanced_Connection_Complete_Event,
                hci.HCI_LE_Channel_Selection_Algorithm_Event,
                hci.HCI_LE_Advertising_Set_Terminated_Event,
            ),
        )
    )
    assert isinstance(
        event,
        (
            hci.HCI_LE_Connection_Complete_Event,
            hci.HCI_LE_Enhanced_Connection_Complete_Event,
        ),
    ), 'connection-related event preceded Connection Complete'
    assert (event.status, event.role, event.peer_address) == (
        ErrorCode.SUCCESS,
        hci.Role.CENTRAL if central else hci.Role.PERIPHERAL,
        peer,
    )
    assert (
        event.connection_interval,
        event.peripheral_latency,
        event.supervision_timeout,
    ) == (parameters.interval, parameters.latency, parameters.timeout)
    assert event.peer_address_type == peer.address_type
    if not central:
        assert (
            event.central_clock_accuracy
            == parameters.hop_sca >> PDU_ADV_CONNECT_SCA_SHIFT
        )
    link.handle = event.connection_handle
    return (link, end)


async def _start_scanning(tester, active):
    peer = LOWER_CENTRAL_PUBLIC_ADDRESS
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(peer.address_type, peer)
    )
    interval = SCAN_INTERVAL_US // hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    await tester.command(
        scan_parameters(
            le_scan_type=int(active),
            le_scan_interval=interval,
            le_scan_window=interval,
            scanning_filter_policy=0,
        )
    )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))


def _encoding_take_reports(tester):
    reports = []
    while event := tester.take(
        lambda event: isinstance(event, hci.HCI_LE_Advertising_Report_Event)
    ):
        reports.extend(event.reports)
    return reports


Opcode = ControlPdu.Opcode


def check_advertising_stopped(tester, connection_end, observation_end):
    """Check all primary channels without interrupting the connection peer."""
    with (tester.phy_results / 'd_2G4_00.Tx.csv').open() as capture:
        for packet in csv.DictReader(capture):
            if (
                connection_end <= int(packet['start_time']) <= observation_end
                and int(packet['phy_address'], 16) == PDU_ADV_ACCESS_ADDRESS
            ):
                raw = bytes.fromhex(packet['packet'])
                assert (
                    raw[0] & PDU_ADV_TYPE_MASK != AdvertisingPduType.ADV_IND
                ), 'IUT continued advertising after accepting CONNECT_IND'


def check_connection_silent(
    tester, access_address, start_us, end_us, *, allowed_control=None
):
    """Check all channels, except any control response explicitly allowed by source."""
    assert tester.radio.now_us >= end_us, 'RF silence observation is incomplete'
    with (tester.phy_results / 'd_2G4_00.Tx.csv').open() as capture:
        for packet in csv.DictReader(capture):
            if (
                start_us <= int(packet['start_time']) <= end_us
                and int(packet['phy_address'], 16) == access_address
            ):
                raw = bytes.fromhex(packet['packet'])
                if allowed_control and len(raw) >= PDU_HEADER_SIZE:
                    payload = raw[PDU_HEADER_SIZE : PDU_HEADER_SIZE + raw[1]]
                    if (
                        raw[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
                        and payload
                        and len(payload) == raw[1] == allowed_control.get(payload[0])
                    ):
                        continue
                raise AssertionError('IUT transmitted after connection termination')


def _data_pdu(sn, nesn, payload=b'', *, llid=LlId.CONTINUATION):
    return (
        bytes([llid | sn * PDU_DATA_SN_MASK | nesn * PDU_DATA_NESN_MASK, len(payload)])
        + payload
    )


async def _wire_event(link, build, *, bad_crc=False, silent=False, required=True):
    """Exchange one connection event without automatically changing ARQ state."""
    tester = link.tester
    channel = link.channel
    packet = None
    if link.central:
        packet = await tester.receive(
            channel,
            start_us=max(tester.radio.now_us + 1, link.anchor - 50),
            duration_us=link.anchor - tester.radio.now_us + 3000,
            **link.radio_parameters | {'phy': link.rx_phy},
        )
        if packet is None:
            assert not required, 'missing Central transmission'
            return (None, None)
        assert packet.start_us == link.anchor
        start = packet.end_us + LL_IFS_US
    else:
        start = link.anchor
    sent = None if silent else build(packet)
    if sent is not None:
        await tester.transmit(
            channel, sent, start_us=start, bad_crc=bad_crc, **link.radio_parameters
        )
        link.last_sent_end_us = tester.radio.now_us + 1
    if not link.central:
        packet = await tester.receive(
            channel, duration_us=1000, **link.radio_parameters | {'phy': link.rx_phy}
        )
        assert packet is not None or not required, 'missing Peripheral response'
        if packet is not None:
            assert packet.start_us == link.last_sent_end_us + LL_IFS_US
    if packet is not None:
        assert packet.valid_crc and len(packet.pdu) >= PDU_HEADER_SIZE
        assert packet.pdu[1] == len(packet.pdu) - PDU_HEADER_SIZE
        link.last_received = packet
    link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    return (packet, sent)


# Selected minimum base interval; advertising events add a seeded0-10-ms delay.
SCANNING_ADVERTISING_INTERVAL_US = (
    hci.HCI_LE_ADV_INTERVAL_MIN * hci.HCI_LE_ADV_INTERVAL_UNIT_US
)
# The raw peer uses SID3, DID0 and auxiliary channel0 throughout each round.
ADVERTISING_SID = 3
AUXILIARY_CHANNEL = 0
# Selected primary-to-auxiliary offset, channel and advertising SID.
AUXILIARY_OFFSET_US = 6000
# Allow HCI delivery after each completed RF event; not a protocol timeout.
REPORT_DELIVERY_US = 1000
Report = hci.HCI_LE_Extended_Advertising_Report_Event
# Table4.2-51/52: continuous10-ms scanning and a five-second duration in round16.
SCANNING_SCAN_INTERVAL = 16


@dataclass(frozen=True)
class _ScanRound:
    number: int
    length: int = 0
    kind: AdvertisingPduType = AdvertisingPduType.ADV_EXT_IND
    target: hci.Address | None = None
    auxiliary: bool = True
    primary_address: bool = False
    duration: int = 0


def _scanning_check_reports(
    tester,
    round_,
    data,
    adi,
    primary_phy,
    secondary_phy,
    boundaries,
    *,
    properties=0,
    report_filter=None,
):
    """Validate one logical result, including fragment order and legal truncation
    points."""
    reports = []
    for event in list(tester.events):
        if isinstance(event, Report):
            reports.extend(
                report
                for report in event.reports
                if report_filter is None or report_filter(report)
            )
            tester.events.remove(event)
    accepted = round_.target is None or round_.target == DUT_ADDRESS
    if not accepted:
        assert (
            not reports
        ), f'round{round_.number}: advertising for another target was reported'
        return (False, False)
    if not reports:
        return (False, False)
    flags = (
        LEGACY_REPORT_FLAGS.get(
            round_.kind, _scanning_Flags.DIRECTED_ADVERTISING if round_.target else 0
        )
        | properties
    )
    joined = bytearray()
    for index, report in enumerate(reports):
        assert report.event_type & ~hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_MASK == flags
        assert report.address == LOWER_PERIPHERAL_PUBLIC_ADDRESS
        assert report.address_type == hci.AddressType.PUBLIC_DEVICE
        assert report.primary_phy == primary_phy
        assert report.secondary_phy == (secondary_phy if round_.auxiliary else 0)
        assert report.advertising_sid == (
            adi >> PDU_ADV_ADI_DID_BITS
            if round_.kind == AdvertisingPduType.ADV_EXT_IND
            else Report.NO_ADI_FIELD_PROVIDED
        )
        assert report.periodic_advertising_interval == 0
        assert report.tx_power == Report.TX_POWER_INFORMATION_NOT_AVAILABLE
        if round_.target:
            assert report.direct_address == round_.target
            assert report.direct_address_type == round_.target.address_type
        joined.extend(report.data)
        status = report.event_type >> hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT
        if index < len(reports) - 1:
            assert status == Report.DATA_INCOMPLETE_MORE_TO_COME
        else:
            assert status in (
                Report.DATA_COMPLETE,
                Report.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME,
            )
    assert bytes(joined) == data[: len(joined)]
    if status == Report.DATA_COMPLETE:
        assert bytes(joined) == data
        return (True, True)
    assert len(joined) in boundaries, 'truncation was not at an AUX_CHAIN_IND boundary'
    return (True, False)


class _EncryptedPeer(PeerLink):
    def __init__(self, link):
        self.__dict__.update(vars(link))
        self.aes = None
        self.session_key = None
        self.iv = b''
        self.tx_enabled = self.rx_enabled = False
        self.tx_counter = self.rx_counter = 0
        self.tx_sn = None
        self.tx_payload = b''
        self.ltk = LTK

    def install(self, skd, iv):
        encryptor = Cipher(algorithms.AES(self.ltk[::-1]), modes.ECB()).encryptor()
        self.session_key = encryptor.update(skd[::-1])
        self.aes = AESCCM(self.session_key, tag_length=PDU_DATA_MIC_SIZE)
        self.iv = iv
        self.tx_counter = self.rx_counter = 0
        self.tx_sn = None
        self.tx_payload = b''
        self.tx_sn = None

    def _accept(self, packet):
        previous = self.sn
        super()._accept(packet)
        if self.sn != previous:
            self.tx_sn = None

    def nonce(self, counter, central):
        return (counter | int(central) << 39).to_bytes(5, 'little') + self.iv

    def encode(self, header, data):
        if not data or not self.tx_enabled:
            return data
        if self.tx_sn != self.sn:
            self.tx_payload = self.aes.encrypt(
                self.nonce(self.tx_counter, not self.central),
                data,
                bytes([header & PDU_DATA_AUTHENTICATED_HEADER_MASK]),
            )
            self.tx_counter += 1
            self.tx_sn = self.sn
        return self.tx_payload

    def decode(self, packet):
        header = packet.pdu[0]
        data = packet.pdu[PDU_HEADER_SIZE:]
        if not data or not self.rx_enabled:
            return packet
        duplicate = bool(header & PDU_DATA_SN_MASK) != bool(self.nesn)
        data = self.aes.decrypt(
            self.nonce(self.rx_counter - int(duplicate), self.central),
            data,
            bytes([header & PDU_DATA_AUTHENTICATED_HEADER_MASK]),
        )
        self.rx_counter += int(not duplicate)
        return replace(packet, pdu=bytes([header, len(data)]) + data)


SCAN_INTERVAL_US = 3 * (SCAN_ADV_INTERVAL_US + LL_ADV_DELAY_MAX_US // 2)
_scanning_Flags = Report.EventType
# Core Vol4 PartE7.7.65.13: event properties for received legacy PDU types.
LEGACY_REPORT_FLAGS = {
    AdvertisingPduType.ADV_IND: _scanning_Flags.LEGACY_ADVERTISING_PDU_USED
    | _scanning_Flags.CONNECTABLE_ADVERTISING
    | _scanning_Flags.SCANNABLE_ADVERTISING,
    AdvertisingPduType.ADV_DIRECT_IND: _scanning_Flags.LEGACY_ADVERTISING_PDU_USED
    | _scanning_Flags.CONNECTABLE_ADVERTISING
    | _scanning_Flags.DIRECTED_ADVERTISING,
    AdvertisingPduType.ADV_NONCONN_IND: _scanning_Flags.LEGACY_ADVERTISING_PDU_USED,
    AdvertisingPduType.ADV_SCAN_IND: _scanning_Flags.LEGACY_ADVERTISING_PDU_USED
    | _scanning_Flags.SCANNABLE_ADVERTISING,
}
