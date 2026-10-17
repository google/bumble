# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL.TS.p28, Section 4.3."""

import random
import struct
from collections import deque
from dataclasses import replace
from itertools import pairwise

import pytest

from bumble import hci
from bumble.ll import (
    LL_ADV_DELAY_MAX_US,
    LL_ADV_DIRECT_HIGH_DUTY_TIMEOUT_US,
    LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
    LL_ADV_PRIMARY_CHANNELS,
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_AUX_WINDOW_DELAY_CODED_US,
    LL_CONN_AUX_WINDOW_DELAY_UNCODED_US,
    LL_CONN_ESTABLISHMENT_EVENTS,
    LL_CONN_INTERVAL_MAX,
    LL_CONN_INTERVAL_MIN,
    LL_CONN_INTERVAL_UNIT_US,
    LL_CONN_LATENCY_MAX,
    LL_CONN_WINDOW_SIZE_MAX,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_DATA_CHANNEL_COUNT,
    LL_EVENT_COUNTER_MASK,
    LL_IFS_US,
    LL_INSTANT_MIN_LISTENING_EVENTS,
    LL_MAFS_US,
    LL_RESPONSE_TIMEOUT_US,
    LL_SCA_50_PPM,
    LL_SCA_500_PPM,
    LL_SCA_PPM,
    LL_SUPERVISION_TIMEOUT_INTERVAL_FACTOR,
    LL_SUPERVISION_TIMEOUT_MAX,
    LL_SUPERVISION_TIMEOUT_MIN,
    LL_SUPERVISION_TIMEOUT_UNIT_US,
    PDU_ACCESS_ADDRESS_SIZE,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_ADDRESSES_END,
    PDU_ADV_ADI_DID_BITS,
    PDU_ADV_AUX_OFFSET_UNITS_MASK,
    PDU_ADV_CHSEL_MASK,
    PDU_ADV_CONNECT_PAYLOAD_SIZE,
    PDU_ADV_CONNECT_SCA_SHIFT,
    PDU_ADV_CONNECT_SIZE,
    PDU_ADV_EXT_HEADER_LENGTH_BITS,
    PDU_ADV_OFFSET_BITS,
    PDU_ADV_OFFSET_UNIT_30_US,
    PDU_ADV_OFFSET_UNIT_300_US,
    PDU_ADV_RXADD_MASK,
    PDU_ADV_TXADD_MASK,
    PDU_ADV_TYPE_MASK,
    PDU_CONTROL_CHANNEL_MAP_SIZE,
    PDU_CONTROL_CONN_PARAM_OFFSET_COUNT,
    PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED,
    PDU_CONTROL_FEATURE_SET_SIZE,
    PDU_CONTROL_INSTANT_SIZE,
    PDU_CONTROL_PHY_REQ_SIZE,
    PDU_CONTROL_PHY_UPDATE_SIZE,
    PDU_CONTROL_VERSION_SIZE,
    PDU_CRC_SIZE,
    PDU_DATA_EMPTY_TIME_CODED_S8_US,
    PDU_DATA_LLID_MASK,
    PDU_DATA_MD_MASK,
    PDU_DATA_NESN_MASK,
    PDU_DATA_OCTET_TIME_CODED_S8_US,
    PDU_DATA_PAYLOAD_SIZE_MAX,
    PDU_DATA_PAYLOAD_SIZE_MIN,
    PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    PDU_DATA_PAYLOAD_TIME_CODED_MIN_US,
    PDU_DATA_PAYLOAD_TIME_MIN_US,
    PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US,
    PDU_DATA_SN_MASK,
    PDU_HEADER_SIZE,
    PDU_PREAMBLE_1M_SIZE,
    PDU_PREAMBLE_2M_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
    ControlPdu,
    LlId,
)
from bumble.radio_controller.radio import (
    PHY_1M_OCTET_TIME_US,
    PHY_2M_OCTET_TIME_US,
    PHY_CODED_FEC1_TIME_US,
    PHY_CODED_S8_FACTOR,
    PHY_CODED_TERM2_SIZE_BITS,
    PHY_OCTET_BITS,
    PHY_OCTET_MASK,
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
    IV,
    LTK,
    SKD,
    _check_parameter_update,
    _data_pdu,
    _EncryptedPeer,
    _pending_connection,
    _wire_event,
)
from tests.radio_controller.qualification.peer import (
    PeerLink,
    establish,
    host_send,
    peer_send,
    received_acl,
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
    check_access_address,
    create_connection,
    decode_aux,
    decode_extended,
    ext_pdu,
    extended_enable,
    extended_parameters,
    follow_auxiliary,
    legacy_parameters,
    request_pdu,
)

EDIV = 4660
ErrorCode = hci.HCI_ErrorCode
PROCEDURE_COLLISION = (
    ErrorCode.LMP_ERROR_TRANSACTION_COLLISION_OR_LL_PROCEDURE_COLLISION_ERROR
)
Opcode = ControlPdu.Opcode
RAND = bytes(range(8))


async def _start_encryption(tester, link, *, refresh=False, parameter_request=None):
    """Perform the role-specific wire handshake, with HCI event validation."""
    if link.central:
        await tester.command(
            hci.HCI_LE_Enable_Encryption_Command(link.handle, RAND, EDIV, LTK)
        )
        if refresh:
            assert await link.control(Opcode.LL_PAUSE_ENC_REQ) == bytes(
                [Opcode.LL_PAUSE_ENC_REQ]
            )
            await link.exchange(bytes([Opcode.LL_PAUSE_ENC_RSP]), llid=LlId.CONTROL)
            link.rx_enabled = False
            assert await link.control(Opcode.LL_PAUSE_ENC_RSP) == bytes(
                [Opcode.LL_PAUSE_ENC_RSP]
            )
            link.tx_enabled = False
        request = await link.control(Opcode.LL_ENC_REQ, response=parameter_request)
        assert request[1:9] == RAND and int.from_bytes(request[9:11], 'little') == EDIV
        link.install(request[11:19] + SKD, request[19:23] + IV)
        await link.exchange(bytes([Opcode.LL_ENC_RSP]) + SKD + IV, llid=LlId.CONTROL)
        link.rx_enabled = True
        await link.exchange(bytes([Opcode.LL_START_ENC_REQ]), llid=LlId.CONTROL)
        assert await link.control(Opcode.LL_START_ENC_RSP) == bytes(
            [Opcode.LL_START_ENC_RSP]
        )
        link.tx_enabled = True
        await link.exchange(bytes([Opcode.LL_START_ENC_RSP]), llid=LlId.CONTROL)
    else:
        if refresh:
            assert await link.control(
                Opcode.LL_PAUSE_ENC_RSP, bytes([Opcode.LL_PAUSE_ENC_REQ])
            ) == bytes([Opcode.LL_PAUSE_ENC_RSP])
            link.tx_enabled = link.rx_enabled = False
            await link.exchange(bytes([Opcode.LL_PAUSE_ENC_RSP]), llid=LlId.CONTROL)
        response = await link.control(
            Opcode.LL_ENC_RSP,
            bytes([Opcode.LL_ENC_REQ]) + RAND + EDIV.to_bytes(2, 'little') + SKD + IV,
        )
        request = await tester.event(hci.HCI_LE_Long_Term_Key_Request_Event)
        assert (
            request.connection_handle == link.handle
            and request.random_number == RAND
            and (request.encryption_diversifier == EDIV)
        )
        link.install(SKD + response[1:9], IV + response[9:13])
        await tester.command(
            hci.HCI_LE_Long_Term_Key_Request_Reply_Command(link.handle, LTK)
        )
        assert await link.control(Opcode.LL_START_ENC_REQ) == bytes(
            [Opcode.LL_START_ENC_REQ]
        )
        link.tx_enabled = link.rx_enabled = True
        assert await link.control(
            Opcode.LL_START_ENC_RSP, bytes([Opcode.LL_START_ENC_RSP])
        ) == bytes([Opcode.LL_START_ENC_RSP])
    await link.exchange()
    event = await tester.event(
        hci.HCI_Encryption_Key_Refresh_Complete_Event
        if refresh
        else hci.HCI_Encryption_Change_Event
    )
    assert event.status == ErrorCode.SUCCESS and event.connection_handle == link.handle
    if not refresh:
        assert (
            event.encryption_enabled
            == hci.HCI_Encryption_Change_Event.Enabled.E0_OR_AES_CCM
        )


# The raw peer uses SID3, DID0 and auxiliary channel0 throughout each round.
ADVERTISING_SID = 3
AUXILIARY_CHANNEL = 0
# Selected primary-to-auxiliary offset, channel and advertising SID.
AUXILIARY_OFFSET_US = 6000
# Table4.3-22 selects scan interval/window0x0010 in625-us HCI units.
AUXILIARY_SCAN_INTERVAL = 16
# Selected finite RF observation budget; not an IUT protocol timer.
INITIATION_OBSERVATION_US = 1000000
Properties = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties
)


async def _connectable_advertisement(tester, link=None):
    """Follow an auxiliary packet in free RF gaps without starving an existing ACL."""
    deadline = tester.radio.now_us + ADVERTISING_OBSERVATION_US
    while tester.radio.now_us < deadline:
        until = (
            min(deadline, link.anchor - PEER_EXCHANGE_BUDGET_US) if link else deadline
        )
        if until <= tester.radio.now_us:
            await _service_peer([link])
            continue
        primary = await tester.receive(37, duration_us=until - tester.radio.now_us)
        if primary is None:
            continue
        assert primary.valid_crc
        assert primary.phy == Phy.LE_1M
        assert len(primary.pdu) >= PDU_HEADER_SIZE
        assert primary.pdu[1] == len(primary.pdu) - PDU_HEADER_SIZE
        assert primary.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
        fields = decode_extended(primary.pdu)
        assert set(fields) == {'adi', 'aux', 'data'} and (not fields['data'])
        assert (
            primary.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
            == AdvertisingMode.CONNECTABLE
        )
        channel, packet, auxiliary = await follow_auxiliary(tester, primary, fields)
        assert packet.phy == Phy.LE_1M
        assert packet.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
        assert (
            packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
            == AdvertisingMode.CONNECTABLE
        )
        assert not packet.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
        assert auxiliary == {
            'address': bytes(DUT_ADDRESS),
            'adi': fields['adi'],
            'data': b'',
        }
        return (channel, packet)
    raise AssertionError(
        'connectable extended advertising absent while maintaining ACL'
    )


async def _initiate_auxiliary(tester, *, phy, retry):
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    primary_phy = Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M
    await tester.command(
        create_connection(
            extended=True,
            peer_address=peer,
            peer_address_type=peer.address_type,
            initiating_phys=1 << primary_phy - 1,
            scan_intervals=[AUXILIARY_SCAN_INTERVAL],
            scan_windows=[AUXILIARY_SCAN_INTERVAL],
        )
    )
    adi = ADVERTISING_SID << PDU_ADV_ADI_DID_BITS
    assert AUXILIARY_OFFSET_US % PDU_ADV_OFFSET_UNIT_30_US == 0
    generator = random.Random(0)
    deadline = tester.radio.now_us + INITIATION_OBSERVATION_US
    requests = 0
    while tester.radio.now_us < deadline:
        _no_initiation_complete(tester)
        start = tester.radio.now_us + 100
        await tester.transmit(
            37,
            ext_pdu(
                adi=adi,
                mode=AdvertisingMode.CONNECTABLE,
                aux=aux_pointer(AUXILIARY_CHANNEL, AUXILIARY_OFFSET_US, phy),
            ),
            start_us=start,
            phy=primary_phy,
        )
        end = await tester.transmit(
            AUXILIARY_CHANNEL,
            ext_pdu(address=peer, adi=adi, mode=AdvertisingMode.CONNECTABLE),
            start_us=start + AUXILIARY_OFFSET_US,
            phy=phy,
        )
        request = await tester.receive(
            AUXILIARY_CHANNEL,
            duration_us=LL_IFS_US + phy.address_us + CONNECT_IFS_TOLERANCE_US,
            phy=phy,
        )
        if request is not None:
            requests += 1
            assert request.valid_crc and request.phy == phy
            assert request.pdu == request_pdu(
                AdvertisingPduType.CONNECT_IND,
                scanner=DUT_ADDRESS,
                advertiser=peer,
                data=request.pdu[PDU_ADV_ADDRESSES_END:],
            )
            assert abs(request.start_us - end - LL_IFS_US) <= CONNECT_IFS_TOLERANCE_US
            parameters = LinkParameters.decode(request.pdu[PDU_ADV_ADDRESSES_END:])
            assert (parameters.interval, parameters.latency, parameters.timeout) == (
                CONNECTION_INTERVAL,
                0,
                SUPERVISION_TIMEOUT,
            )
            check_access_address(parameters.access_address, phy=phy)
            if not retry or requests > 1:
                await tester.transmit(
                    AUXILIARY_CHANNEL,
                    ext_pdu(
                        kind=AdvertisingPduType.AUX_CONNECT_RSP,
                        address=peer,
                        target=DUT_ADDRESS,
                    ),
                    start_us=request.end_us + LL_IFS_US,
                    phy=phy,
                )
                link = PeerLink(
                    tester, parameters, request.end_us, central=True, csa2=True, phy=phy
                )
                delay = (
                    LL_CONN_AUX_WINDOW_DELAY_CODED_US
                    if phy == Phy.LE_CODED
                    else LL_CONN_AUX_WINDOW_DELAY_UNCODED_US
                )
                link.anchor = (
                    request.end_us
                    + delay
                    + parameters.window_offset * LL_CONN_INTERVAL_UNIT_US
                )
                event = await _connection_complete(tester, link, peer)
                assert isinstance(event, hci.HCI_LE_Enhanced_Connection_Complete_Event)
                assert bytes(event.local_resolvable_private_address) == bytes(
                    PDU_ADV_ADDRESS_SIZE
                )
                assert bytes(event.peer_resolvable_private_address) == bytes(
                    PDU_ADV_ADDRESS_SIZE
                )
                assert requests == (2 if retry else 1)
                return link
        next_start = (
            start + ADV_INTERVAL_US + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
        )
        await tester.wait(max(0, next_start - tester.radio.now_us))
    raise AssertionError(
        'auxiliary initiation or unanswered-request retry did not complete'
    )


def _no_initiation_complete(tester):
    assert not any(
        isinstance(
            event,
            (
                hci.HCI_LE_Connection_Complete_Event,
                hci.HCI_LE_Enhanced_Connection_Complete_Event,
                hci.HCI_LE_Channel_Selection_Algorithm_Event,
                hci.HCI_Disconnection_Complete_Event,
            ),
        )
        for event in tester.events
    ), 'unanswered auxiliary request produced a connection or failure event'


async def _accept_remote_parameters(
    tester, link, interval, timeout, *, optional_error=None
):
    event = await tester.event(hci.HCI_LE_Remote_Connection_Parameter_Request_Event)
    assert (
        event.connection_handle,
        event.interval_min,
        event.interval_max,
        event.max_latency,
        event.timeout,
    ) == (link.handle, interval, interval, 0, timeout)
    result = await tester.command(
        hci.HCI_LE_Remote_Connection_Parameter_Request_Reply_Command(
            link.handle, interval, interval, 0, timeout, 0, 0
        )
    )
    assert result.connection_handle == link.handle
    if link.central:
        update = await link.control(Opcode.LL_CONNECTION_UPDATE_IND)
    else:
        response = await link.control(Opcode.LL_CONNECTION_PARAM_RSP)
        minimum, _, latency, timeout, *_ = _check_parameter_pdu(response)
        interval = minimum
        update = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + struct.pack(
            '<BHHHHH',
            LL_CONN_WINDOW_SIZE_MIN,
            0,
            interval,
            latency,
            timeout,
            link.counter + LL_INSTANT_MIN_LISTENING_EVENTS & LL_EVENT_COUNTER_MASK,
        )
        await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
    await _check_parameter_update(
        tester, link, update, interval, timeout, optional_error=optional_error
    )


async def _change_phy(tester, link, phy, *, local):
    mask = 1 << phy - 1
    if local:
        await tester.command(hci.HCI_LE_Set_PHY_Command(link.handle, 0, mask, mask, 0))
        response = await link.control(Opcode.LL_PHY_REQ)
        assert len(response) == PDU_CONTROL_PHY_REQ_SIZE and response[1] and response[2]
        if not response[1] & response[2] & mask:
            pytest.skip(
                'Inconclusive: PHY setup request cannot select the required PHY'
            )
        if link.central:
            await link.exchange(
                bytes([Opcode.LL_PHY_RSP, mask, mask]), llid=LlId.CONTROL
            )
    else:
        response = await link.control(
            Opcode.LL_PHY_RSP, bytes([Opcode.LL_PHY_REQ, mask, mask])
        )
        assert len(response) == PDU_CONTROL_PHY_REQ_SIZE and response[1] and response[2]
        if not response[1] & response[2] & mask:
            pytest.skip(
                'Inconclusive: PHY setup response cannot select the required PHY'
            )
    if link.central:
        update = await link.control(Opcode.LL_PHY_UPDATE_IND)
        assert len(update) == PDU_CONTROL_PHY_UPDATE_SIZE
        allowed = {0, *(_bit(supported) for supported in Phy)}
        assert all(value in allowed for value in update[1:3])
        current = (link.rx_phy, link.tx_phy)
        if any(
            (Phy(value.bit_length()) if value else previous) != phy
            for value, previous in zip(update[1:3], current)
        ):
            pytest.skip('Inconclusive: PHY setup did not select the required PHY')
    else:
        update = _update_pdu(link, mask, mask)
        await link.exchange(update, llid=LlId.CONTROL)
    await _finish_update(
        tester, link, update, event_required=local, allowed=(mask, mask)
    )


def _check_feature_pdu(declared, pdu, *, opcode=Opcode.LL_FEATURE_RSP):
    """Apply Send-to-Peer rules and the zero-peer response's USED octet."""
    assert len(pdu) == 1 + PDU_CONTROL_FEATURE_SET_SIZE
    assert pdu[0] == opcode
    response = opcode == Opcode.LL_FEATURE_RSP
    if response:
        assert pdu[1] == 0, 'zero-peer FeatureSet_USED octet was not cleared'
    features = int.from_bytes(pdu[1:], 'little')
    optional = (
        hci.LeFeatureMask.LE_PING
        | hci.LeFeatureMask.LL_PRIVACY
        | hci.LeFeatureMask.EXTENDED_SCANNER_FILTER_POLICIES
        | hci.LeFeatureMask.LE_EXTENDED_ADVERTISING
        | hci.LeFeatureMask.LE_PERIODIC_ADVERTISING
        | hci.LeFeatureMask.CONNECTIONLESS_CTE_TRANSMITTER
        | hci.LeFeatureMask.CONNECTIONLESS_CTR_RECEIVER
        | hci.LeFeatureMask.ANTENNA_SWITCHING_DURING_CTE_TRANSMISSION
        | hci.LeFeatureMask.ANTENNA_SWITCHING_DURING_CTE_RECEPTION
        | hci.LeFeatureMask.PERIODIC_ADVERTISING_ADI_SUPPORT
    )
    forbidden = (
        hci.LeFeatureMask.REMOTE_PUBLIC_KEY_VALIDATION
        | hci.LeFeatureMask.DECISION_BASED_ADVERTISING_FILTERING
        | hci.LeFeatureMask.CHANNEL_SOUNDING_TONE_QUALITY_INDICATION
    )
    defined = sum(
        1 << feature
        for feature in hci.LeFeature
        if feature < PDU_CONTROL_FEATURE_SET_SIZE * 8
    )
    required = declared & ~int(optional | forbidden)
    if response:
        required &= ~((1 << 8) - 1)
    assert features & required == required, 'required local feature absent'
    assert not features & (
        int(forbidden) | ~defined | ~declared
    ), 'forbidden, RFU or undeclared feature reported to peer'


def _check_parameter_pdu(payload):
    fields = struct.unpack('<HHHHBH6H', payload[1:])
    minimum, maximum, latency, timeout = fields[:4]
    assert LL_CONN_INTERVAL_MIN <= minimum <= maximum <= LL_CONN_INTERVAL_MAX
    assert fields[4] <= maximum
    assert 0 <= latency <= LL_CONN_LATENCY_MAX
    assert LL_SUPERVISION_TIMEOUT_MIN <= timeout <= LL_SUPERVISION_TIMEOUT_MAX
    assert (
        timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
        > LL_SUPERVISION_TIMEOUT_INTERVAL_FACTOR
        * (latency + 1)
        * maximum
        * LL_CONN_INTERVAL_UNIT_US
    )
    return fields


def _check_parameter_choice(update, accepted=None):
    """Validate a connection update and, when accepted, its negotiated fields."""
    assert len(update) == 1 + struct.calcsize('<BHHHHH')
    assert update[0] == Opcode.LL_CONNECTION_UPDATE_IND
    size, offset, interval, latency, timeout, _ = struct.unpack('<BHHHHH', update[1:])
    assert LL_CONN_INTERVAL_MIN <= interval <= LL_CONN_INTERVAL_MAX
    assert LL_CONN_WINDOW_SIZE_MIN <= size <= min(LL_CONN_WINDOW_SIZE_MAX, interval - 1)
    assert 0 <= offset <= interval
    assert 0 <= latency <= LL_CONN_LATENCY_MAX
    assert LL_SUPERVISION_TIMEOUT_MIN <= timeout <= LL_SUPERVISION_TIMEOUT_MAX
    assert (
        timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
        > LL_SUPERVISION_TIMEOUT_INTERVAL_FACTOR
        * (latency + 1)
        * interval
        * LL_CONN_INTERVAL_UNIT_US
    )
    if accepted is not None:
        minimum, maximum, agreed_latency, agreed_timeout = accepted[:4]
        assert minimum <= interval <= maximum
        assert (latency, timeout) == (agreed_latency, agreed_timeout)
    return interval, timeout


def _select_peer_interval(minimum, maximum, periodicity):
    """Prefer a periodic multiple without leaving the actual peer response range."""
    return next(
        (
            interval
            for interval in range(minimum, maximum + 1)
            if not periodicity or interval % periodicity == 0
        ),
        minimum,
    )


class _HciDataStream:
    """Compare bytes and start-flag offsets, not packetization (LL.TS.p28 4.1.7)."""

    def __init__(self, tester, handle):
        self.tester, self.handle = tester, handle
        self.expected, self.received = bytearray(), bytearray()
        self.expected_starts, self.received_starts = [], []

    def sent(self, data, continuation):
        if not continuation:
            self.expected_starts.append(len(self.expected))
        self.expected.extend(data)

    def accept(self, event):
        assert event.connection_handle == self.handle
        assert event.bc_flag == 0 and event.data_total_length == len(event.data)
        assert event.pb_flag in (
            hci.HCI_ACL_PB_FIRST_FLUSHABLE,
            hci.HCI_ACL_PB_CONTINUATION,
        )
        if event.pb_flag == hci.HCI_ACL_PB_FIRST_FLUSHABLE:
            self.received_starts.append(len(self.received))
        self.received.extend(event.data)
        assert self.expected.startswith(self.received), 'HCI data bytes changed'
        assert (
            self.received_starts == self.expected_starts[: len(self.received_starts)]
        ), 'HCI start-flag locations changed'

    def poll(self):
        while event := self.tester.take(
            lambda value: isinstance(value, hci.HCI_AclDataPacket)
        ):
            self.accept(event)

    async def finish(self):
        self.poll()
        while len(self.received) < len(self.expected) or len(
            self.received_starts
        ) < len(self.expected_starts):
            self.accept(await self.tester.event(hci.HCI_AclDataPacket))
            self.poll()
        assert self.received == self.expected
        assert self.received_starts == self.expected_starts, 'missing HCI start flag'


async def _data_exchange(tester, *, central, direction):
    """Verify directional 1000-octet groups, ACL fragmentation and simultaneous data
    exchange."""
    result = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
    buffer_size = result.le_acl_data_packet_length
    assert buffer_size >= PDU_DATA_PAYLOAD_SIZE_MIN
    assert result.total_num_le_acl_data_packets > 0
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    generator = random.Random(0)
    receiver = _HciDataStream(tester, link.handle) if direction != 'tx' else None
    if direction == 'duplex':
        for index in range(100):
            data = generator.randbytes(10) if central else bytes(10)
            peer_data = generator.randbytes(10)
            continuation = central and index != 0
            receiver.sent(peer_data, continuation)
            await host_send(
                tester,
                link,
                data,
                continuation,
                peer_data=peer_data,
                peer_continuation=continuation,
                receiver=receiver,
            )
    else:
        operation = host_send if direction == 'tx' else peer_send
        for group in range(3):
            for index in range(100):
                data = bytes(10) if direction == 'tx' else generator.randbytes(10)
                continuation = group == 1 or (group == 2 and index != 0)
                if receiver is not None:
                    receiver.sent(data, continuation)
                await operation(
                    tester,
                    link,
                    data,
                    continuation,
                    receiver=receiver,
                )
        if direction == 'tx' and buffer_size > PDU_DATA_PAYLOAD_SIZE_MIN:
            sent = 0
            while sent < 1000:
                data = bytes(
                    generator.randrange(PDU_DATA_PAYLOAD_SIZE_MIN + 1, buffer_size + 1)
                )
                assert await host_send(tester, link, data) >= 2
                sent += len(data)
        elif direction == 'rx':
            for _ in range(10):
                data = generator.randbytes(3)
                receiver.sent(data, False)
                await peer_send(tester, link, data, receiver=receiver)
    if receiver is not None:
        await receiver.finish()
    await link.disconnect(local=True)


async def _feature_or_version(tester, *, central, version=False):
    """The peer initiates Feature/Version Exchange; check the LL response and finish
    the connection."""
    declared = None
    if not version:
        result = await tester.command(
            hci.HCI_LE_Read_Local_Supported_Features_Command()
        )
        declared = int.from_bytes(result.le_features, 'little')
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    if version:
        payload = bytes(
            [Opcode.LL_VERSION_IND, hci.HCI_VERSION_BLUETOOTH_CORE_5_4]
        ) + struct.pack('<HH', 4660, 0)
        response = await link.control(Opcode.LL_VERSION_IND, payload)
        assert len(response) == 6
    else:
        opcode = Opcode.LL_PERIPHERAL_FEATURE_REQ if central else Opcode.LL_FEATURE_REQ
        response = await link.control(
            Opcode.LL_FEATURE_RSP, bytes([opcode]) + bytes(PDU_CONTROL_FEATURE_SET_SIZE)
        )
        assert declared is not None
        _check_feature_pdu(declared, response)
    await link.disconnect(local=True)


async def _local_parameters(tester, *, central, reject=False):
    """Initiate a maximum-interval Central update or three Peripheral requests
    through HCI."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    if central:
        await link.control(
            Opcode.LL_FEATURE_RSP,
            bytes([Opcode.LL_PERIPHERAL_FEATURE_REQ])
            + bytes(PDU_CONTROL_FEATURE_SET_SIZE),
        )
    for interval, timeout in (
        ((LL_CONN_INTERVAL_MIN, 300),)
        if reject
        else (
            ((LL_CONN_INTERVAL_MAX, LL_SUPERVISION_TIMEOUT_MAX),)
            if central
            else (
                (LL_CONN_INTERVAL_MIN, 300),
                (LL_CONN_INTERVAL_MAX, LL_SUPERVISION_TIMEOUT_MAX),
                (LL_CONN_INTERVAL_MIN, 300),
            )
        )
    ):
        await tester.command(
            hci.HCI_LE_Connection_Update_Command(
                link.handle, interval, interval, 0, timeout, 0, 0
            )
        )
        if central:
            update = await link.control(Opcode.LL_CONNECTION_UPDATE_IND)
            assert struct.unpack('<BHHHHH', update[1:])[2:5] == (interval, 0, timeout)
        else:
            request = await link.control(Opcode.LL_CONNECTION_PARAM_REQ)
            minimum, _, latency, supervision, *_ = _check_parameter_pdu(request)
            if reject:
                await link.exchange(
                    bytes(
                        [
                            Opcode.LL_REJECT_EXT_IND,
                            Opcode.LL_CONNECTION_PARAM_REQ,
                            ErrorCode.COMMAND_DISALLOWED_ERROR,
                        ]
                    ),
                    llid=LlId.CONTROL,
                    check_ack=True,
                )
                event = await tester.event(hci.HCI_LE_Connection_Update_Complete_Event)
                assert (event.status, event.connection_handle) == (
                    ErrorCode.COMMAND_DISALLOWED_ERROR,
                    link.handle,
                )
                await link.exchange()
                assert not any(
                    isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
                    for event in tester.events
                ), 'rejected parameter request produced another completion'
                break
            interval, timeout = (minimum, supervision)
            update = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + struct.pack(
                '<BHHHHH',
                LL_CONN_WINDOW_SIZE_MIN,
                0,
                interval,
                latency,
                timeout,
                link.counter + LL_INSTANT_MIN_LISTENING_EVENTS & LL_EVENT_COUNTER_MASK,
            )
            await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
        await _check_parameter_update(tester, link, update, interval, timeout)
    await link.disconnect(local=True)


async def _parameter_collision(tester, *, central=False, channel_map=False):
    """Exercise the role-specific parameter/channel-map collision on an active ACL."""
    import pytest

    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    interval, timeout = (LL_CONN_INTERVAL_MIN, 300)
    new_map = sum(1 << channel for channel in range(0, LL_DATA_CHANNEL_COUNT, 2))
    reason = (
        ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR
        if central or channel_map
        else PROCEDURE_COLLISION
    )
    if central:
        for attempt in range(20):
            candidate = new_map if not attempt else new_map & ~(1 << 2 * (attempt - 1))
            result = await tester.command(
                hci.HCI_LE_Set_Host_Channel_Classification_Command(
                    candidate.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
                ),
                status=tuple(ErrorCode),
            )
            if result.status == ErrorCode.SUCCESS:
                break
            deadline = tester.radio.now_us + 5000000
            while tester.radio.now_us < deadline:
                await link.exchange()
        else:
            pytest.skip('Inconclusive: all twenty Host channel classifications failed')
        update = await link.control(
            Opcode.LL_CHANNEL_MAP_IND,
            response=_parameter_request(link, interval, timeout),
            required=False,
        )
        if update is None:
            pytest.skip('Inconclusive: Controller chose not to send LL_CHANNEL_MAP_IND')
        response = await link.control(Opcode.LL_REJECT_EXT_IND)
        assert response == bytes(
            [Opcode.LL_REJECT_EXT_IND, Opcode.LL_CONNECTION_PARAM_REQ, reason]
        )
    else:
        await tester.command(
            hci.HCI_LE_Connection_Update_Command(
                link.handle, interval, interval, 0, timeout, 0, 0
            )
        )
        request = await link.control(Opcode.LL_CONNECTION_PARAM_REQ)
        _check_parameter_pdu(request)
        if channel_map:
            update = (
                bytes([Opcode.LL_CHANNEL_MAP_IND])
                + new_map.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
                + (
                    link.counter + LL_INSTANT_MIN_LISTENING_EVENTS
                    & LL_EVENT_COUNTER_MASK
                ).to_bytes(PDU_CONTROL_INSTANT_SIZE, 'little')
            )
            await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
        else:
            packet = await link.exchange(
                _parameter_request(link, interval, timeout),
                llid=LlId.CONTROL,
                check_ack=True,
            )
            assert not (
                packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
                and packet.pdu[PDU_HEADER_SIZE] == Opcode.LL_REJECT_EXT_IND
            ), 'Peripheral rejected the Central request instead of preserving it'
        await link.exchange(
            bytes([Opcode.LL_REJECT_EXT_IND, Opcode.LL_CONNECTION_PARAM_REQ, reason]),
            llid=LlId.CONTROL,
            check_ack=True,
        )
        if channel_map:
            event = await tester.event(hci.HCI_LE_Connection_Update_Complete_Event)
            assert (event.connection_handle, event.status) == (link.handle, reason)
        else:
            failures = [
                event
                for event in tester.events
                if isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
            ]
            assert all(
                (event.connection_handle, event.status) == (link.handle, reason)
                for event in failures
            )
            for event in failures:
                tester.events.remove(event)
            await _accept_remote_parameters(
                tester, link, interval, timeout, optional_error=reason
            )
            assert not any(
                isinstance(event, hci.HCI_LE_Remote_Connection_Parameter_Request_Event)
                for event in tester.events
            )
            await link.disconnect(local=True)
            return
    wire_map = int.from_bytes(update[1:-PDU_CONTROL_INSTANT_SIZE], 'little')
    assert wire_map.bit_count() >= 2 and (not wire_map >> LL_DATA_CHANNEL_COUNT)
    await link.apply_update(update)
    for _ in range(3):
        await link.exchange()
    assert not any(
        isinstance(
            event,
            (
                hci.HCI_LE_Remote_Connection_Parameter_Request_Event,
                hci.HCI_LE_Connection_Update_Complete_Event,
            ),
        )
        for event in tester.events
    ), 'channel-map collision leaked a Host parameter event'
    result = await tester.command(hci.HCI_LE_Read_Channel_Map_Command(link.handle))
    assert result.connection_handle == link.handle
    assert int.from_bytes(result.channel_map, 'little') == link.parameters.channel_map
    await peer_send(tester, link, b'after-channel-map-update')
    await link.disconnect(local=True)


def _parameter_request(link, interval, timeout):
    return bytes([Opcode.LL_CONNECTION_PARAM_REQ]) + struct.pack(
        '<HHHHBH6H',
        interval,
        interval,
        0,
        timeout,
        0,
        link.counter,
        *[PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED]
        * PDU_CONTROL_CONN_PARAM_OFFSET_COUNT,
    )


async def _remote_parameters(
    tester, *, central, reject=False, masked=False, invalid=False
):
    """Request 6/3200/6 interval updates remotely; accept, reject or mask the Host
    event; verify RF instants."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    if masked:
        await tester.masks(
            le=(1 << 64) - 1
            & ~(1 << hci.HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_EVENT - 1)
        )
    for interval, timeout in (
        ((6, 300),)
        if reject or masked or invalid
        else ((6, 300), (3200, 3200), (6, 300))
    ):
        request = _parameter_request(link, interval if not invalid else 4, timeout)
        if invalid or masked:
            response = await link.control(Opcode.LL_REJECT_EXT_IND, request)
            assert response[1:] == bytes(
                [
                    Opcode.LL_CONNECTION_PARAM_REQ,
                    (
                        ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR
                        if invalid
                        else ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
                    ),
                ]
            )
            for _ in range(3):
                await link.exchange()
            assert not any(
                isinstance(
                    e,
                    (
                        hci.HCI_LE_Remote_Connection_Parameter_Request_Event,
                        hci.HCI_LE_Connection_Update_Complete_Event,
                    ),
                )
                for e in tester.events
            )
            break
        await link.exchange(request, llid=LlId.CONTROL)
        if reject:
            event = await tester.event(
                hci.HCI_LE_Remote_Connection_Parameter_Request_Event
            )
            assert (
                event.connection_handle,
                event.interval_min,
                event.interval_max,
                event.max_latency,
                event.timeout,
            ) == (link.handle, interval, interval, 0, timeout)
            reason = ErrorCode.UNACCEPTABLE_CONNECTION_PARAMETERS_ERROR
            result = await tester.command(
                hci.HCI_LE_Remote_Connection_Parameter_Request_Negative_Reply_Command(
                    link.handle, reason
                )
            )
            assert result.connection_handle == link.handle
            response = await link.control(Opcode.LL_REJECT_EXT_IND)
            assert response[1:] == bytes([Opcode.LL_CONNECTION_PARAM_REQ, reason])
            for _ in range(3):
                await link.exchange()
            assert not any(
                isinstance(e, hci.HCI_LE_Connection_Update_Complete_Event)
                for e in tester.events
            )
        else:
            await _accept_remote_parameters(tester, link, interval, timeout)
    await link.disconnect(local=True)


async def _connection_termination(tester, *, central, local):
    """Verify termination acknowledgement, HCI reasons and supervision-time RF
    silence."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
        timeout=100 if central else LL_SUPERVISION_TIMEOUT_MIN,
    )
    reason = ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR
    if local:
        await tester.command(hci.HCI_Disconnect_Command(link.handle, reason))
        response = await link.control(Opcode.LL_TERMINATE_IND)
        assert response == bytes([Opcode.LL_TERMINATE_IND, reason])
        if not central:
            await link._send(link.channel, b'', LlId.CONTINUATION, link.anchor)
            link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
            link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    else:
        sn = link.sn
        channel = link.channel
        response = await link.exchange(
            bytes([Opcode.LL_TERMINATE_IND, reason]), llid=LlId.CONTROL
        )
        assert response.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
        assert response.pdu[PDU_HEADER_SIZE:] == b''
        if central:
            assert (
                await tester.receive(
                    channel,
                    duration_us=link.anchor - tester.radio.now_us - 1,
                    **link.radio_parameters,
                )
                is None
            ), 'termination acknowledgement occurred before the following event'
            response = await tester.expect_pdu(
                link.channel, duration_us=1000, **link.radio_parameters
            )
            assert response.start_us == link.anchor
            assert response.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
            assert response.pdu[PDU_HEADER_SIZE:] == b''
            sn = link.sn
            link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
            link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
        assert int(bool(response.pdu[0] & PDU_DATA_NESN_MASK)) != sn
    deadline = (
        tester.radio.now_us + link.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
    )
    while link.anchor < deadline:
        if not central:
            await link._send(link.channel, b'', LlId.CONTINUATION, link.anchor)
        until = min(
            deadline,
            link.anchor + link.parameters.interval * LL_CONN_INTERVAL_UNIT_US - 1,
        )
        packet = await tester.receive(
            link.channel,
            duration_us=until - tester.radio.now_us,
            **link.radio_parameters,
        )
        assert packet is None, 'connection traffic continued after termination ACK'
        link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    await tester.wait(max(0, deadline - tester.radio.now_us))
    event = tester.take(
        lambda event: isinstance(event, hci.HCI_Disconnection_Complete_Event)
    )
    assert event is not None, 'missing HCI disconnection during RF observation'
    assert event.status == ErrorCode.SUCCESS
    assert event.connection_handle == link.handle
    assert event.reason == (
        ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR if local else reason
    )
    assert not any(
        isinstance(event, hci.HCI_Disconnection_Complete_Event)
        for event in tester.events
    ), 'duplicate HCI disconnection event'


# LL.TS.p28, responding Step 10 and Table 4.3-63 rows 13..15, not S=8 packet airtime.
DLE_CODED_TIME_BOUNDARY_US = 2128
# LL.TS.p28, Tables 4.3-61/63: tuples use LL wire order RX octets/time, TX octets/time.
LENGTH_FIELDS = struct.Struct('<HHHH')
MAXIMUM = (PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US) * 2
MINIMUM = (PDU_DATA_PAYLOAD_SIZE_MIN, PDU_DATA_PAYLOAD_TIME_MIN_US) * 2
PRESERVATION_REQUEST_ATTEMPTS = 2
# LL.TS.p28, responding Step 8 and initiating Step 10.
RECEIVE_PACKET_COUNT = 20
# LL.TS.p28 Section 4.3.7.34: retain an unacknowledged packet for five intervals.
RETRANSMISSION_INTERVALS = 5
# LL.TS.p28 Section 4.3.7.36: increase TxOctets by twenty, at most ten rounds.
UNCODED_REQUEST_ATTEMPTS = 10
UNCODED_REQUEST_OCTET_INCREMENT = 20
# LL.TS.p28 unsupported-peer Step 1 and preservation Steps 1..5.
UNSUPPORTED_REQUEST_ATTEMPTS = 20
# Core Vol 6, Part B, 4.5.10: old/new maxima during a DLE transition.
DLE_TRANSITION_PACKETS = 2


def _check_changed_events(tester, handle, before, after, intermediate=None):
    """Allow a local autonomous change followed by the peer's response, as the TS
    permits."""
    current = before
    count = 0
    while event := tester.take(
        lambda event: isinstance(event, hci.HCI_LE_Data_Length_Change_Event)
    ):
        count += 1
        assert count <= 2
        assert event.connection_handle == handle
        values = (
            event.max_tx_octets,
            event.max_tx_time,
            event.max_rx_octets,
            event.max_rx_time,
        )
        assert values != current, 'unchanged effective limits reported again'
        assert values == after or values == intermediate
        current = values
    assert current == after, 'effective change missing from HCI'


def _check_parameters(payload, opcode, supported):
    assert payload[0] == opcode and len(payload) == 1 + LENGTH_FIELDS.size
    values = LENGTH_FIELDS.unpack(payload[1:])
    assert all(
        (low <= value <= high for value, low, high in zip(values, MINIMUM, supported))
    )
    return values


class _LengthObserver:
    """Track wire DLE and PHY changes without discarding control PDUs during setup."""

    def __init__(self, tester, link, dut, peer, supported):
        self.tester, self.link = tester, link
        self.dut, self.peer, self.supported = dut, peer, supported
        self.current = _effective_lengths(dut, peer, link)
        self.changes = []
        self.packet_limits = {}
        self.grace = self.current
        self.grace_packets = 0

    def _change(self):
        current = _effective_lengths(self.dut, self.peer, self.link)
        if current != self.current:
            self.changes.append(current)
            self.current = current

    def receive(self, packet):
        self._change()
        payload = packet.pdu[PDU_HEADER_SIZE:]
        if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
            if payload[0] == Opcode.LL_LENGTH_REQ:
                self.grace = self.current
                self.grace_packets = DLE_TRANSITION_PACKETS
                self.dut = _check_parameters(
                    payload, Opcode.LL_LENGTH_REQ, self.supported
                )
                self._change()
                return bytes([Opcode.LL_LENGTH_RSP]) + LENGTH_FIELDS.pack(*self.peer)
        elif payload:
            limits = self.current
            if self.grace_packets:
                limits = tuple(max(new, old) for new, old in zip(limits, self.grace))
                self.grace_packets -= 1
            self.packet_limits[packet.start_us] = limits
        return None

    def check(self, *, final=False):
        events = []
        while event := self.tester.take(
            lambda event: isinstance(event, hci.HCI_LE_Data_Length_Change_Event)
        ):
            assert event.connection_handle == self.link.handle
            events.append(
                (
                    event.max_tx_octets,
                    event.max_tx_time,
                    event.max_rx_octets,
                    event.max_rx_time,
                )
            )
        assert (
            events == self.changes[: len(events)]
        ), 'incorrect effective-length changes'
        del self.changes[: len(events)]
        if final:
            assert not self.changes, 'missing effective-length changes'
            assert not self.link.control_responses, 'unanswered Data Length Request'


async def _connection_event(
    link, data=b'', *, llid=LlId.CONTINUATION, response_timeout_after_us=None
):
    """Receive every DUT PDU in one event, following MD and acknowledging each
    sequence."""
    tester, channel = (link.tester, link.channel)
    packets = []
    start = link.anchor
    if not link.central:
        await link._send(channel, data, llid, start)
        data = b''
        start = tester.radio.now_us + 1 + LL_IFS_US
    while True:
        sn = link.nesn
        packet = await tester.receive(
            channel,
            start_us=max(tester.radio.now_us + 1, start - 1),
            duration_us=max(3000, start - tester.radio.now_us + 3000),
            **link.radio_parameters | {'phy': link.rx_phy},
        )
        if packet is None:
            if (
                response_timeout_after_us is not None
                and tester.radio.now_us >= response_timeout_after_us
                and any(
                    isinstance(event, hci.HCI_Disconnection_Complete_Event)
                    and (event.status, event.connection_handle, event.reason)
                    == (
                        ErrorCode.SUCCESS,
                        link.handle,
                        ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR,
                    )
                    for event in tester.events
                )
            ):
                pytest.skip('Inconclusive: DATA total absent at procedure timeout')
            assert packets, 'missing first DATA PDU in connection event'
            break
        assert packet.valid_crc
        assert packet.start_us == start
        assert int(bool(packet.pdu[0] & PDU_DATA_SN_MASK)) == sn
        link._accept(packet)
        packets.append(packet)
        more = bool(packet.pdu[0] & PDU_DATA_MD_MASK)
        if link.central or more:
            await link._send(
                channel,
                data,
                llid if data else LlId.CONTINUATION,
                packet.end_us + LL_IFS_US,
            )
            data = b''
        if not more:
            break
        start = tester.radio.now_us + 1 + LL_IFS_US
        assert start < link.anchor + link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    return packets


async def _data_length(tester, *, central, local, phy):
    """Execute the complete responding or initiating DLE matrix on LE 1M/2M/Coded."""
    supported = await _supported_lengths(tester)
    buffer = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
    declared = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    coded = bool(
        int.from_bytes(declared.le_features, 'little') & hci.LeFeatureMask.LE_CODED_PHY
    )
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
        interval=48 if phy == Phy.LE_CODED else 24,
    )
    features = (
        hci.LeFeatureMask.LE_DATA_PACKET_LENGTH_EXTENSION
        | hci.LeFeatureMask.LE_2M_PHY
        | hci.LeFeatureMask.LE_CODED_PHY
    )
    await link.control(
        Opcode.LL_FEATURE_RSP,
        bytes([Opcode.LL_PERIPHERAL_FEATURE_REQ if central else Opcode.LL_FEATURE_REQ])
        + int(features).to_bytes(PDU_CONTROL_FEATURE_SET_SIZE, 'little'),
    )
    previous = (MINIMUM[2], MINIMUM[3], MINIMUM[0], MINIMUM[1])
    if phy != Phy.LE_1M:
        await _change_phy(tester, link, phy, local=True)
        current = _effective_lengths(MINIMUM, MINIMUM, link)
        _check_changed_events(tester, link.handle, previous, current)
        previous = current
    peer = MINIMUM
    requests = 0
    generator = random.Random(0)
    if local:
        rounds = [
            (request, response)
            for response in (MINIMUM, MAXIMUM)
            for request in _initiating_rounds(supported)
        ]
    else:
        vectors = _responding_rounds(supported)
        if coded:
            vectors += [
                tuple(
                    (
                        (
                            DLE_CODED_TIME_BOUNDARY_US
                            if index % 2 and value == PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
                            else value
                        )
                        for index, value in enumerate(row)
                    )
                )
                for row in list(vectors)
                if PDU_DATA_PAYLOAD_TIME_CODED_MAX_US in (row[1], row[3])
            ]
        rounds = [(row, None) for row in vectors]
    for index, (request, response) in enumerate(rounds, 1):
        tester.output.write(f'DLE ROUND {index} request={request} peer={response}\n')
        if local:
            result = await tester.command(
                hci.HCI_LE_Set_Data_Length_Command(link.handle, *request)
            )
            assert result.connection_handle == link.handle
            packet = await link.control(Opcode.LL_LENGTH_REQ, required=False)
            if packet is None:
                tester.output.write('DLE ROW OMITTED: no LL_LENGTH_REQ observed\n')
                continue
            requests += 1
            dut = _check_parameters(packet, Opcode.LL_LENGTH_REQ, supported)
            intermediate = _effective_lengths(dut, peer, link)
            peer = response
            await link.exchange(
                bytes([Opcode.LL_LENGTH_RSP]) + LENGTH_FIELDS.pack(*peer),
                llid=LlId.CONTROL,
            )
        else:
            peer = request
            dut = _check_parameters(
                await link.control(
                    Opcode.LL_LENGTH_RSP,
                    bytes([Opcode.LL_LENGTH_REQ]) + LENGTH_FIELDS.pack(*peer),
                ),
                Opcode.LL_LENGTH_RSP,
                supported,
            )
            intermediate = None
        current = _effective_lengths(dut, peer, link)
        await tester.wait(0)
        _check_changed_events(tester, link.handle, previous, current, intermediate)
        previous = current
        await _transfer_under_limits(
            tester,
            link,
            current,
            buffer.le_acl_data_packet_length,
            buffer.total_num_le_acl_data_packets,
            generator,
        )
        assert not any(
            isinstance(event, hci.HCI_LE_Data_Length_Change_Event)
            for event in tester.events
        ), 'unexpected data-length event during data transfer'
    await link.disconnect(local=True)
    if local and (not requests):
        pytest.skip(
            'Inconclusive: no LL_LENGTH_REQ observed during the initiating matrix'
        )


def _effective_lengths(dut, peer, link):
    rx, rt, tx, tt = dut
    peer_rx, peer_rt, peer_tx, peer_tt = peer
    tx, tt, rx, rt = (
        min(tx, peer_rx),
        min(tt, peer_rt),
        min(rx, peer_tx),
        min(rt, peer_tt),
    )
    if link.tx_phy == Phy.LE_CODED:
        rt = max(rt, PDU_DATA_PAYLOAD_TIME_CODED_MIN_US)
    if link.rx_phy == Phy.LE_CODED:
        receive_budget = min(
            rt, PDU_DATA_EMPTY_TIME_CODED_S8_US + rx * PDU_DATA_OCTET_TIME_CODED_S8_US
        )
        tt = max(
            PDU_DATA_PAYLOAD_TIME_CODED_MIN_US,
            min(
                tt,
                link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
                - receive_budget
                - 2 * LL_IFS_US,
            ),
        )
    return (tx, tt, rx, rt)


def _initiating_rounds(supported):
    """Table 4.3-63, including the distinct 2120-us and 2128-us boundary rounds."""
    _, _, tx, tt = supported
    return [
        (octets, time_us)
        for time_us in (
            tt,
            PDU_DATA_PAYLOAD_TIME_MIN_US,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
            PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US,
            DLE_CODED_TIME_BOUNDARY_US,
        )
        for octets in (tx, PDU_DATA_PAYLOAD_SIZE_MIN, PDU_DATA_PAYLOAD_SIZE_MAX)
    ]


async def _negotiate_maximum(tester, link, supported):
    """Source-prescribed maximum request, with one intermediate retry if omitted."""
    for attempt in range(PRESERVATION_REQUEST_ATTEMPTS):
        octets, time_us = supported[2:]
        if attempt:
            octets = (
                octets - PDU_DATA_PAYLOAD_SIZE_MIN
            ) // 2 + PDU_DATA_PAYLOAD_SIZE_MIN
            time_us = (
                time_us - PDU_DATA_PAYLOAD_TIME_MIN_US
            ) // 2 + PDU_DATA_PAYLOAD_TIME_MIN_US
        result = await tester.command(
            hci.HCI_LE_Set_Data_Length_Command(link.handle, octets, time_us)
        )
        assert result.connection_handle == link.handle
        if packet := (await link.control(Opcode.LL_LENGTH_REQ, required=False)):
            dut = _check_parameters(packet, Opcode.LL_LENGTH_REQ, supported)
            await link.exchange(
                bytes([Opcode.LL_LENGTH_RSP]) + LENGTH_FIELDS.pack(*MAXIMUM),
                llid=LlId.CONTROL,
            )
            await tester.wait(0)
            current = _effective_lengths(dut, MAXIMUM, link)
            _check_changed_events(
                tester, link.handle, _effective_lengths(MINIMUM, MINIMUM, link), current
            )
            return (dut, current)
    pytest.skip(
        'Inconclusive: no LL_LENGTH_REQ after maximum and intermediate HCI requests'
    )


def _payload_limit(phy, octets, time_us):
    """Unencrypted PDU budget from wire fields, not the DUT's airtime implementation."""
    if phy == Phy.LE_CODED:
        overhead = (
            PHY_CODED_FEC1_TIME_US
            + (
                (PDU_HEADER_SIZE + PDU_CRC_SIZE) * PHY_OCTET_BITS
                + PHY_CODED_TERM2_SIZE_BITS
            )
            * PHY_CODED_S8_FACTOR
        )
        return min(octets, (time_us - overhead) // PDU_DATA_OCTET_TIME_CODED_S8_US)
    unit, preamble = (
        (PHY_1M_OCTET_TIME_US, PDU_PREAMBLE_1M_SIZE)
        if phy == Phy.LE_1M
        else (PHY_2M_OCTET_TIME_US, PDU_PREAMBLE_2M_SIZE)
    )
    overhead = preamble + PDU_ACCESS_ADDRESS_SIZE + PDU_HEADER_SIZE + PDU_CRC_SIZE
    return min(octets, time_us // unit - overhead)


def _responding_rounds(supported):
    """All 16 Table 4.3-61 rounds in RX-first wire order; the tester supports
    protocol maxima."""
    rx, rt, tx, tt = supported
    low, high = (PDU_DATA_PAYLOAD_SIZE_MIN, PDU_DATA_PAYLOAD_SIZE_MAX)
    short, long = (PDU_DATA_PAYLOAD_TIME_MIN_US, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US)
    rounds = [
        MINIMUM,
        MAXIMUM,
        (tx, tt, rx, rt),
        (tx, tt, low, short),
        (low, long, low, long),
        (high, long, low, rt),
        (tx, long, high, short),
        (low, short, high, long),
        (high, short, high, rt),
        (tx, short, rx, short),
        (low, tt, rx, long),
        (high, tt, rx, rt),
    ]
    generator = random.Random(0)
    for _ in range(4):
        rounds.append(
            (
                generator.randrange(low + 1, high),
                generator.randrange(short + 1, long),
                generator.randrange(low + 1, high),
                generator.randrange(short + 1, long),
            )
        )
    return rounds


async def _supported_lengths(tester):
    maximum = await tester.command(hci.HCI_LE_Read_Maximum_Data_Length_Command())
    values = (
        maximum.supported_max_rx_octets,
        maximum.supported_max_rx_time,
        maximum.supported_max_tx_octets,
        maximum.supported_max_tx_time,
    )
    assert all(
        (low <= value <= high for value, low, high in zip(values, MINIMUM, MAXIMUM))
    )
    return values


async def _transfer_under_limits(
    tester, link, effective, buffer_size, buffer_slots, generator
):
    tx_octets, tx_time, rx_octets, rx_time = effective
    data = generator.randbytes(2 * tx_octets + 1)
    chunks = [
        data[index : index + buffer_size] for index in range(0, len(data), buffer_size)
    ]
    assert len(chunks) <= buffer_slots
    await tester.wait(0)
    for index, chunk in enumerate(chunks):
        tester.send(
            bytes(
                hci.HCI_AclDataPacket(
                    link.handle,
                    (
                        hci.HCI_ACL_PB_CONTINUATION
                        if index
                        else hci.HCI_ACL_PB_FIRST_NON_FLUSHABLE
                    ),
                    0,
                    len(chunk),
                    chunk,
                )
            )
        )
    received = b''
    for _ in range(64):
        for packet in await _connection_event(link):
            if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
                continue
            assert packet.pdu[1] <= tx_octets
            assert packet.end_us - packet.start_us <= tx_time
            if packet.pdu[1]:
                assert packet.pdu[0] & PDU_DATA_LLID_MASK == (
                    LlId.CONTINUATION if received else LlId.START
                )
                received += packet.pdu[PDU_HEADER_SIZE:]
        assert data.startswith(received)
        if received == data:
            break
    assert received == data
    for packet in await _connection_event(link):
        assert packet.pdu[0] & PDU_DATA_LLID_MASK != LlId.CONTROL
        assert packet.pdu[1] == 0
    completed = 0
    while event := tester.take(
        lambda event: isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
    ):
        assert event.connection_handles == [link.handle]
        completed += sum(event.num_completed_packets)
    assert completed == len(chunks)
    size = _payload_limit(link.tx_phy, rx_octets, rx_time)
    assert size > 0
    for _ in range(RECEIVE_PACKET_COUNT):
        packet = await peer_send(tester, link, generator.randbytes(size))
        assert packet.pdu[1] <= tx_octets
        assert packet.end_us - packet.start_us <= tx_time


async def _unsupported_peer(tester, *, central, phy):
    """Retain initial limits and bidirectional data after an unsupported LENGTH_REQ."""
    supported = await _supported_lengths(tester)
    buffer = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
        interval=48 if phy == Phy.LE_CODED else 24,
    )
    initial = _effective_lengths(MINIMUM, MINIMUM, link)
    if phy != Phy.LE_1M:
        await _change_phy(tester, link, phy, local=True)
        coded_initial = _effective_lengths(MINIMUM, MINIMUM, link)
        _check_changed_events(tester, link.handle, initial, coded_initial)
        initial = coded_initial
    generator = random.Random(0)
    for attempt in range(UNSUPPORTED_REQUEST_ATTEMPTS):
        request = (
            supported[2:]
            if attempt == 0
            else (
                (min(MINIMUM[2] + 1, supported[2]), min(MINIMUM[3] + 1, supported[3]))
                if attempt == 1
                else (
                    generator.randint(MINIMUM[2], supported[2]),
                    generator.randint(MINIMUM[3], supported[3]),
                )
            )
        )
        result = await tester.command(
            hci.HCI_LE_Set_Data_Length_Command(link.handle, *request)
        )
        assert result.connection_handle == link.handle
        if packet := (await link.control(Opcode.LL_LENGTH_REQ, required=False)):
            _check_parameters(packet, Opcode.LL_LENGTH_REQ, supported)
            await link.exchange(
                bytes([Opcode.LL_UNKNOWN_RSP, Opcode.LL_LENGTH_REQ]), llid=LlId.CONTROL
            )
            break
    else:
        pytest.skip('Inconclusive: no LL_LENGTH_REQ in twenty HCI attempts')
    await tester.wait(0)
    _check_changed_events(tester, link.handle, initial, initial)
    await _transfer_under_limits(
        tester,
        link,
        initial,
        buffer.le_acl_data_packet_length,
        buffer.total_num_le_acl_data_packets,
        generator,
    )
    assert not any(
        isinstance(event, hci.HCI_LE_Data_Length_Change_Event)
        for event in tester.events
    )
    await link.disconnect(local=True)


# Filter both scanning and initiating peers through the Filter Accept List.
ADV_FILTER_ACCEPT_LIST_ONLY = 3
ADV_INTERVAL_US = 20000
# Source Correction: LL.TS.p28 Sections 4.3.2.1/4.3.3.1
# ChM=0x01 is a source error; the reviewed local correction enables channels 0/1.
COMMON_ADVERTISER_CHANNEL_MAP = 0x03


def _advertiser_connection_parameters(**changes):
    return replace(
        LinkParameters(
            access_address=LOWER_DATA_ACCESS_ADDRESS,
            crc_init=0x198891,
            window_size=7,
            window_offset=7,
            interval=8,
            timeout=30,
            channel_map=COMMON_ADVERTISER_CHANNEL_MAP,
            hop_sca=5,
        ),
        **changes,
    )


# LL/CON/ADV/BV-03-C prescribes thirty NAKs followed by thirty ACK events.
LATENCY_EVENTS = 30
MINIMUM_NAK_RESPONSES = 9
PERIPHERAL_LATENCY = 5
# LL/CON/INI/BV-38-C requires at least ten events after replies resume.
RECOVERY_EVENTS = 10
# Selected IXIT: full 30-ms scan window and 20-ms base advertising interval.
ESTABLISHMENT_SCAN_INTERVAL = 48


def _accepting_timeout_bound(parameters):
    """Compute the source's conditional T2 lower bound from widened RX windows."""
    interval = parameters.interval * LL_CONN_INTERVAL_UNIT_US
    first = (1 + parameters.window_offset) * LL_CONN_INTERVAL_UNIT_US
    size = parameters.window_size * LL_CONN_INTERVAL_UNIT_US
    ppm = LL_SCA_PPM[parameters.hop_sca >> PDU_ADV_CONNECT_SCA_SHIFT]

    def window(index):
        anchor = first + index * interval
        widening = (
            RADIO_CLOCK_JITTER_US
            + (anchor * (ppm + RADIO_LOCAL_SCA_PPM) + PHY_TIME_UNITS_PER_SECOND - 1)
            // PHY_TIME_UNITS_PER_SECOND
        )
        return (anchor - widening, anchor + size + widening)

    deadline = LL_CONN_ESTABLISHMENT_EVENTS * interval
    index = 0
    while window(index)[0] < deadline:
        index += 1
    t2 = window(index - 1)[1]
    t1 = window(LL_CONN_ESTABLISHMENT_EVENTS - 1)[1]
    return t2 if t2 < t1 else 0


def _empty_data(packet, expected_sequence=None):
    """Validate received DATA independently of the DUT's ARQ implementation."""
    assert packet.valid_crc
    assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
    assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
    if expected_sequence is not None:
        assert _sequence_bits(packet) == expected_sequence


async def _initiating_failure(tester, *, bad_crc=False):
    """Distinguish six-event setup failure from supervision after bad-CRC reception."""
    link, end = await _pending_connection(
        tester,
        central=True,
        parameters=LinkParameters(timeout=LL_SUPERVISION_TIMEOUT_MIN),
        advertising_data=b'\xff',
    )
    _completion_events(tester, link)
    check_access_address(link.parameters.access_address)
    interval = link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    deadline = end + (
        link.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
        if bad_crc
        else LL_CONN_ESTABLISHMENT_EVENTS * interval
    )
    first_anchor = link.anchor
    starts = []

    def reply(packet):
        _empty_data(packet, (0, 0))
        link._accept(packet)
        return _data_pdu(link.sn, link.nesn)

    while link.anchor < deadline:
        channel = link.channel
        packet = await _receive_central_event(link)
        _empty_data(packet, (0, 0))
        starts.append(packet.start_us)
        if bad_crc:
            await tester.transmit(
                channel,
                reply(packet),
                start_us=packet.end_us + LL_IFS_US,
                bad_crc=True,
                **link.radio_parameters,
            )
            link.last_sent_end_us = tester.radio.now_us + 1
            extra = await tester.receive(
                channel, duration_us=1000, **link.radio_parameters
            )
            if extra is not None:
                assert (
                    abs(extra.start_us - link.last_sent_end_us - LL_IFS_US)
                    <= CONNECT_IFS_TOLERANCE_US
                )
                await tester.transmit(
                    channel,
                    reply(extra),
                    start_us=extra.end_us + LL_IFS_US,
                    bad_crc=True,
                    **link.radio_parameters,
                )
    _check_central_timing(link.parameters, first_anchor, starts)
    if not bad_crc:
        expected = min(
            LL_CONN_ESTABLISHMENT_EVENTS, (deadline - 1 - starts[0]) // interval + 1
        )
        assert len(starts) == expected
    event = await _observe_disconnection(
        tester, deadline - HCI_OBSERVATION_STEP_US, deadline + HCI_OBSERVATION_STEP_US
    )
    assert (event.status, event.connection_handle, event.reason) == (
        ErrorCode.SUCCESS,
        link.handle,
        (
            ErrorCode.CONNECTION_TIMEOUT_ERROR
            if bad_crc
            else ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR
        ),
    )
    for _ in range(LL_CONN_ESTABLISHMENT_EVENTS):
        await _check_rf_stopped(link)


ACCESS_ADDRESS_BIT_MINIMUM = 3
# BV-50 requires 36 distinct addresses, with both values at least three times per bit.
ACCESS_ADDRESS_ROUNDS = 36
# Core Vol4, PartE: connection handles0x0F00..0x0FFF are reserved.
CONNECTION_HANDLE_MAX = 3839
# Common connection IXIT values, in1.25-ms interval and10-ms supervision units.
CONNECTION_INTERVAL = 24
# LL.TS.p28 active-mode request timing tolerance.
CONNECT_IFS_TOLERANCE_US = 2
# BV-37: adjacent directed advertising packet starts are at most0.5 ms apart.
DIRECTED_PACKET_INTERVAL_MAX_US = 500
DIRECTED_TIMING_EVENTS = 1000
# BI-05 maintains the original ACL and advertising for at least five seconds.
DUPLICATE_OBSERVATION_US = 5000000
# Unsigned, least-significant-octet-first event count used as advertising data.
EVENT_COUNT_SIZE = 4
# LL.TS.p28 Section4.1.5.2: alter the DUT address's high, low or both end octets.
PEER_ADDRESS_XOR_MASKS = (181419418583040, 90, 98956046500005)
# Valid static random address used only in the prohibited address-change command.
PROHIBITED_RANDOM_ADDRESS = hci.Address('C0:12:34:56:78:9A')
# Selected IXIT: full 30-ms scan window and 20-ms undirected advertising interval.
INITIATING_SCAN_INTERVAL = 48
SUPERVISION_TIMEOUT = 100
# Tables4.3-12/25 require at least100 measured events; BV-37 requires1000 per CSA.
TIMING_EVENTS = 100


async def _advertise_connection(
    tester,
    peer,
    *,
    channel=37,
    directed=False,
    csa2=False,
    high_duty=False,
    reject=False,
):
    """Observe one complete initiation window without restarting the HCI procedure."""
    interval_us = INITIATING_SCAN_INTERVAL * hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    deadline = tester.radio.now_us + 4 * interval_us + 3 * interval_us
    generator = random.Random(0)
    index = 0
    previous = None
    channels = LL_ADV_PRIMARY_CHANNELS if high_duty or channel is None else (channel,)
    while tester.radio.now_us < deadline:
        selected_channel = channels[index % len(channels)]
        start = tester.radio.now_us + 1
        if index % len(channels) == 0:
            event_start = start
        if high_duty and previous is not None:
            assert start - previous <= DIRECTED_PACKET_INTERVAL_MAX_US
        pdu = _advertisement(
            peer, directed=directed, csa2=csa2, count=index // len(channels)
        )
        end = await tester.transmit(selected_channel, pdu, start_us=start)
        request = await tester.receive(
            selected_channel,
            duration_us=LL_IFS_US + Phy.LE_1M.address_us + CONNECT_IFS_TOLERANCE_US,
        )
        if request is not None:
            assert not reject, 'CONNECT_IND sent to an excluded advertiser'
            assert request.valid_crc
            assert request.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.CONNECT_IND
            assert (
                request.pdu[1]
                == len(request.pdu) - PDU_HEADER_SIZE
                == PDU_ADV_CONNECT_PAYLOAD_SIZE
            )
            assert not request.pdu[0] & PDU_ADV_TXADD_MASK
            assert bool(request.pdu[0] & PDU_ADV_RXADD_MASK) == peer.is_random
            assert abs(request.start_us - end - LL_IFS_US) <= CONNECT_IFS_TOLERANCE_US
            assert not csa2 or request.pdu[0] & PDU_ADV_CHSEL_MASK
            assert request.pdu[PDU_HEADER_SIZE:PDU_ADV_ADDRESSES_END] == bytes(
                DUT_ADDRESS
            ) + bytes(peer)
            parameters = LinkParameters.decode(request.pdu[PDU_ADV_ADDRESSES_END:])
            assert (parameters.interval, parameters.latency, parameters.timeout) == (
                CONNECTION_INTERVAL,
                0,
                SUPERVISION_TIMEOUT,
            )
            check_access_address(parameters.access_address)
            link = PeerLink(tester, parameters, request.end_us, central=True, csa2=csa2)
            await _connection_complete(tester, link, peer)
            return link
        index += 1
        previous = start
        if not high_duty and index % len(channels) == 0:
            next_event = (
                event_start
                + ADV_INTERVAL_US
                + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
            )
            await tester.wait(min(next_event, deadline + 1) - tester.radio.now_us)
    if reject:
        await tester.wait(max(0, deadline + 1 - tester.radio.now_us))
        assert not any(
            isinstance(
                event,
                (
                    hci.HCI_LE_Connection_Complete_Event,
                    hci.HCI_LE_Enhanced_Connection_Complete_Event,
                    hci.HCI_LE_Channel_Selection_Algorithm_Event,
                ),
            )
            for event in tester.events
        ), 'connection event reported for an excluded advertiser'
        return None
    raise AssertionError(
        'CONNECT_IND absent within four scan intervals plus three windows'
    )


def _advertisement(peer, *, directed=False, csa2=False, count=0):
    pdu = (
        request_pdu(
            AdvertisingPduType.ADV_DIRECT_IND, advertiser=DUT_ADDRESS, scanner=peer
        )
        if directed
        else adv_pdu(
            address=peer, csa2=csa2, data=count.to_bytes(EVENT_COUNT_SIZE, 'little')
        )
    )
    if directed and csa2:
        pdu = bytes([pdu[0] | PDU_ADV_CHSEL_MASK]) + pdu[1:]
    return pdu


def _check_access_address_set(addresses):
    """Apply the BV-50 population verdict, independently of the DUT allocator."""
    assert len(addresses) == ACCESS_ADDRESS_ROUNDS, 'wrong Access Address round count'
    assert len(set(addresses)) == len(addresses), 'repeated Access Address'
    for address in addresses:
        check_access_address(address)
    for bit in range(PDU_ACCESS_ADDRESS_SIZE * PHY_OCTET_BITS):
        ones = sum(address >> bit & 1 for address in addresses)
        assert (
            ACCESS_ADDRESS_BIT_MINIMUM
            <= ones
            <= len(addresses) - ACCESS_ADDRESS_BIT_MINIMUM
        ), f'Access Address bit{bit} lacks three occurrences of each value'


async def _connection_complete(
    tester, link, peer, *, legacy_only=False, extended=False
):
    """Validate role-specific completion and event eligibility without reordering."""
    complete_types = (
        hci.HCI_LE_Connection_Complete_Event,
        hci.HCI_LE_Enhanced_Connection_Complete_Event,
    )
    selection_type = hci.HCI_LE_Channel_Selection_Algorithm_Event
    event = await tester.expect(
        lambda value: isinstance(
            value,
            (
                *complete_types,
                selection_type,
                hci.HCI_LE_Advertising_Set_Terminated_Event,
            ),
        )
    )
    assert isinstance(event, complete_types), 'event preceded Connection Complete'
    if legacy_only:
        assert isinstance(
            event, hci.HCI_LE_Connection_Complete_Event
        ), 'masked Enhanced Connection Complete was emitted'
    assert (event.status, event.role, event.peer_address) == (
        ErrorCode.SUCCESS,
        hci.Role.CENTRAL if link.central else hci.Role.PERIPHERAL,
        peer,
    )
    assert event.peer_address_type == peer.address_type
    assert (
        event.connection_interval,
        event.peripheral_latency,
        event.supervision_timeout,
    ) == (link.parameters.interval, link.parameters.latency, link.parameters.timeout)
    if not link.central:
        assert (
            event.central_clock_accuracy
            == link.parameters.hop_sca >> PDU_ADV_CONNECT_SCA_SHIFT
        )
    assert 0 <= event.connection_handle <= CONNECTION_HANDLE_MAX
    link.handle = event.connection_handle
    if link.central:
        selection = await tester.expect(lambda _event: True)
        assert isinstance(selection, selection_type), 'unexpected event before CSA'
        assert (selection.connection_handle, selection.channel_selection_algorithm) == (
            link.handle,
            int(link.csa2),
        )
    if extended:
        _completion_events(tester, link, extended=True)
    else:
        assert (
            tester.take(
                lambda value: isinstance(
                    value, (selection_type, hci.HCI_LE_Advertising_Set_Terminated_Event)
                )
            )
            is None
        )
    return event


async def _initiate(
    tester, peer, *, channel=37, directed=False, csa2=False, change_address=False
):
    await tester.command(
        create_connection(
            peer_address=peer,
            peer_address_type=peer.address_type,
            le_scan_interval=INITIATING_SCAN_INTERVAL,
            le_scan_window=INITIATING_SCAN_INTERVAL,
            connection_interval_min=CONNECTION_INTERVAL,
            connection_interval_max=CONNECTION_INTERVAL,
            supervision_timeout=SUPERVISION_TIMEOUT,
        )
    )
    if change_address:
        await tester.command(
            hci.HCI_LE_Set_Random_Address_Command(PROHIBITED_RANDOM_ADDRESS),
            status=ErrorCode.COMMAND_DISALLOWED_ERROR,
        )
    return await _advertise_connection(
        tester, peer, channel=channel, directed=directed, csa2=csa2, high_duty=directed
    )


def _peer_addresses():
    value = int.from_bytes(bytes(DUT_ADDRESS), 'little')
    return (
        LOWER_PERIPHERAL_PUBLIC_ADDRESS,
        *(
            hci.Address(
                (value ^ mask).to_bytes(PDU_ADV_ADDRESS_SIZE, 'little'),
                hci.AddressType.PUBLIC_DEVICE,
            )
            for mask in PEER_ADDRESS_XOR_MASKS
        ),
    )


async def _invalid_control_invalid_llid(tester, *, central=False):
    """Acknowledge reserved LLID without interpreting its payload as an LL command."""
    declared = int.from_bytes(
        (
            await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
        ).le_features,
        'little',
    )
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    if central:
        await tester.command(hci.HCI_LE_Read_Remote_Features_Command(link.handle))
        await link.control(Opcode.LL_FEATURE_REQ)
    payload = bytes(
        [Opcode.LL_FEATURE_RSP if central else Opcode.LL_FEATURE_REQ]
    ) + bytes(PDU_CONTROL_FEATURE_SET_SIZE)

    def check_ignored(packet):
        assert not any(
            isinstance(
                event,
                (hci.HCI_AclDataPacket, hci.HCI_LE_Read_Remote_Features_Complete_Event),
            )
            for event in tester.events
        )
        assert not (
            packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
            and packet.pdu[1]
            and (packet.pdu[PDU_HEADER_SIZE] == Opcode.LL_FEATURE_RSP)
        )

    sent_sn = None if central else link.sn
    nesn = link.nesn

    def build(packet):
        nonlocal sent_sn, nesn
        if packet is not None:
            peer_sn, peer_nesn = _sequence_bits(packet)
            if sent_sn is None:
                sent_sn = peer_nesn
            nesn = peer_sn ^ 1
        return _data_pdu(sent_sn, nesn, payload, llid=LlId.RESERVED)

    until = 0
    for attempt in range(5):
        packet, sent = await _wire_event(link, build)
        if attempt == 0:
            until = (
                link.last_sent_end_us
                - link.tx_phy.airtime_us(len(sent))
                + 4 * PHY_TIME_UNITS_PER_SECOND
            )
        check_ignored(packet)
        if (not central or attempt) and bool(
            packet.pdu[0] & PDU_DATA_NESN_MASK
        ) != bool(sent_sn):
            break
        nesn = _sequence_bits(packet)[0] ^ 1
    else:
        raise AssertionError('reserved LLID not acknowledged within four retries')
    _restore_peer(link, packet, sent)
    while tester.radio.now_us < until:
        packet = await link.exchange()
        check_ignored(packet)
    if central:
        await link.exchange(payload, llid=LlId.CONTROL)
        event = await tester.event(hci.HCI_LE_Read_Remote_Features_Complete_Event)
        assert (event.status, event.connection_handle, event.le_features) == (
            ErrorCode.SUCCESS,
            link.handle,
            payload[1:],
        )
    else:
        response = await link.control(Opcode.LL_FEATURE_RSP, payload, check_ack=True)
        _check_feature_pdu(declared, response)
    await link.disconnect()


# Selected observation budget, not a Controller protocol timer.
ADVERTISING_OBSERVATION_US = 600000
AdvType = hci.HCI_LE_Set_Advertising_Parameters_Command.AdvertisingType
# BV-52 requires five advertisements after the outgoing connection completes.
CONTINUED_ADVERTISEMENTS = 5
# The common IUT device name used as advertising data in the legacy case.
DEVICE_NAME = b'IUT'
# ADV/BI-02:50-ms connection interval and5-ms duplicate transmit window.
DUPLICATE_CONN_INTERVAL = 40
DUPLICATE_WINDOW_SIZE = 4
# Select legacy completion while keeping forbidden CSA/advertising events observable.
LEGACY_CONNECTION_EVENT_MASK = (1 << 64) - 1 & ~(
    1 << hci.HCI_LE_ENHANCED_CONNECTION_COMPLETE_EVENT - 1
)
# Keep both roles alive beyond setup rather than checking HCI notifications alone.
MAINTAINED_EVENTS = 10
# BV-52's exact two-octet advertising payload.
PARALLEL_ADVERTISING_DATA = b'\x0f\x0f'
# Leave room for advertising and its response before an existing peer's anchor.
PEER_EXCHANGE_BUDGET_US = 5000


async def _incoming_connection(tester, links, packet, *, parameters=None):
    peer = LOWER_CENTRAL_PUBLIC_ADDRESS
    end = packet.end_us + LL_IFS_US + Phy.LE_1M.airtime_us(PDU_ADV_CONNECT_SIZE)
    parameters = parameters or _interleaved_parameters(end, links)
    actual_end = await tester.transmit(
        37,
        request_pdu(
            AdvertisingPduType.CONNECT_IND, scanner=peer, data=parameters.encode()
        ),
        start_us=packet.end_us + LL_IFS_US,
    )
    assert actual_end == end
    link = PeerLink(tester, parameters, actual_end)
    await _connection_complete(tester, link, peer, legacy_only=True)
    assert all(
        link.handle != other.handle for other in links
    ), 'connection handle reused'
    return link


def _interleaved_parameters(packet_end, links, parameters=None):
    """Place the new peer halfway between the existing connection's anchors."""
    parameters = parameters or LinkParameters(
        access_address=LOWER_DATA_ACCESS_ADDRESS, window_offset=CONNECTION_INTERVAL - 1
    )
    if links:
        interval_us = parameters.interval * LL_CONN_INTERVAL_UNIT_US
        desired = links[0].anchor + interval_us // 2
        offset = (
            (
                desired
                - packet_end
                - LL_CONN_INTERVAL_UNIT_US
                + LL_CONN_INTERVAL_UNIT_US // 2
            )
            // LL_CONN_INTERVAL_UNIT_US
            % parameters.interval
        )
        parameters = replace(parameters, window_offset=offset)
    return parameters


async def _maintain_until(tester, links, target):
    while links and min(link.anchor for link in links) <= target:
        await _service_peer(links)
    if tester.radio.now_us < target:
        await tester.wait(target - tester.radio.now_us)


def _no_creation_events(tester):
    assert not any(
        isinstance(
            event,
            (
                hci.HCI_LE_Connection_Complete_Event,
                hci.HCI_LE_Enhanced_Connection_Complete_Event,
                hci.HCI_LE_Channel_Selection_Algorithm_Event,
                hci.HCI_LE_Advertising_Set_Terminated_Event,
                hci.HCI_Disconnection_Complete_Event,
            ),
        )
        for event in tester.events
    ), 'unexpected connection creation, termination or legacy advertising event'


async def _outgoing_connection(tester, links):
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    interval_us = INITIATING_SCAN_INTERVAL * hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    deadline = tester.radio.now_us + 7 * interval_us
    generator = random.Random(0)
    next_start = tester.radio.now_us
    while tester.radio.now_us < deadline:
        await _maintain_until(tester, links, next_start)
        while (
            links
            and min(link.anchor for link in links) - tester.radio.now_us
            < PEER_EXCHANGE_BUDGET_US
        ):
            await _service_peer(links)
        start = tester.radio.now_us + 100
        end = await tester.transmit(37, adv_pdu(address=peer), start_us=start)
        request = await tester.receive(
            37, duration_us=LL_IFS_US + Phy.LE_1M.address_us + CONNECT_IFS_TOLERANCE_US
        )
        if (
            request is not None
            and request.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.CONNECT_IND
        ):
            assert request.valid_crc
            assert bytes([request.pdu[0] & ~PDU_ADV_CHSEL_MASK]) + request.pdu[
                1:
            ] == request_pdu(
                AdvertisingPduType.CONNECT_IND,
                scanner=DUT_ADDRESS,
                advertiser=peer,
                data=request.pdu[PDU_ADV_ADDRESSES_END:],
            )
            assert abs(request.start_us - end - LL_IFS_US) <= CONNECT_IFS_TOLERANCE_US
            parameters = LinkParameters.decode(request.pdu[PDU_ADV_ADDRESSES_END:])
            assert (parameters.interval, parameters.latency, parameters.timeout) == (
                CONNECTION_INTERVAL,
                0,
                SUPERVISION_TIMEOUT,
            )
            check_access_address(parameters.access_address)
            link = PeerLink(tester, parameters, request.end_us, central=True)
            await _connection_complete(tester, link, peer, legacy_only=True)
            assert all(
                link.handle != other.handle for other in links
            ), 'connection handle reused'
            return link
        next_start = (
            start + ADV_INTERVAL_US + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
        )
    raise AssertionError(
        'pending initiation did not complete while another role was active'
    )


async def _parallel_connections(tester, *, incoming_first=False):
    """Keep initiation and advertising independent through both completion orders."""
    await tester.masks(le=LEGACY_CONNECTION_EVENT_MASK)
    await tester.command(
        create_connection(
            peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
            peer_address_type=LOWER_PERIPHERAL_PUBLIC_ADDRESS.address_type,
        )
    )
    await tester.command(
        legacy_parameters(
            advertising_type=(
                AdvType.ADV_DIRECT_IND if incoming_first else AdvType.ADV_IND
            ),
            peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
            peer_address_type=LOWER_CENTRAL_PUBLIC_ADDRESS.address_type,
        )
    )
    if not incoming_first:
        await tester.command(
            hci.HCI_LE_Set_Advertising_Data_Command(PARALLEL_ADVERTISING_DATA)
        )
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    packet = await _observe_advertising(tester, [], directed=incoming_first)
    assert packet.pdu[0] & PDU_ADV_CHSEL_MASK
    if incoming_first:
        first = await _incoming_connection(tester, [], packet)
        second = await _outgoing_connection(tester, [first])
    else:
        first = await _outgoing_connection(tester, [])
        for _ in range(CONTINUED_ADVERTISEMENTS):
            packet = await _observe_advertising(tester, [first])
        second = await _incoming_connection(tester, [first], packet)
    links = [first, second]
    while min(link.counter for link in links) < MAINTAINED_EVENTS:
        await _service_peer(links)
        _no_creation_events(tester)


async def _service_peer(links):
    """Exchange the earliest independently scheduled peer event on the shared radio."""
    link = min(links, key=lambda value: value.anchor)
    previous_sn = link.sn
    packet = await link.exchange(check_ack=True)
    assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
    assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
    if link.central and link.counter > 1:
        assert bool(packet.pdu[0] & PDU_DATA_NESN_MASK) != bool(
            previous_sn
        ), 'existing ACL stopped acknowledging DATA'
    return link


# LL.TS.p28 Table 4.3-56, PDF pages 801-802: ALL_PHYS, TX, RX, peer RX, peer TX.
# Literal field values are specification stimuli, not implementation selections.
CENTRAL_INITIATING = (
    (0, 2, 2, 2, 2),
    (0, 1, 2, 1, 2),
    (0, 2, 1, 2, 1),
    (0, 1, 1, 1, 1),
    (0, 3, 2, 3, 2),
    (0, 3, 1, 3, 1),
    (0, 1, 3, 1, 3),
    (0, 2, 3, 2, 3),
    (0, 3, 3, 3, 3),
    (1, 0, 2, 3, 3),
    (2, 2, 0, 3, 3),
    (3, 0, 0, 3, 3),
    (0, 4, 4, 4, 4),
    (0, 1, 4, 1, 4),
    (0, 4, 1, 4, 1),
    (0, 1, 1, 1, 1),
    (0, 5, 4, 5, 4),
    (0, 5, 1, 5, 1),
    (0, 1, 5, 1, 5),
    (0, 4, 5, 4, 5),
    (0, 5, 5, 5, 5),
    (1, 0, 4, 5, 5),
    (2, 4, 0, 5, 5),
    (3, 0, 0, 5, 5),
    (0, 6, 6, 2, 2),
    (0, 6, 6, 4, 4),
    (0, 6, 6, 2, 2),
    (0, 2, 4, 2, 4),
    (0, 4, 2, 4, 2),
    (3, 0, 0, 4, 4),
    (3, 0, 0, 2, 2),
    (3, 0, 0, 1, 1),
)
# Table 4.3-41, PDF pages 641-643: ALL_PHYS, TX, RX, Central TX, Peripheral TX.
PERIPHERAL_INITIATING = (
    (0, 1, 3, 2, 0),
    (0, 2, 5, 1, 2),
    (0, 4, 2, 2, 4),
    (0, 2, 1, 0, 2),
    (0, 1, 4, 4, 0),
    (0, 6, 3, 2, 2),
    (0, 1, 1, 1, 1),
    (0, 3, 4, 0, 1),
    (0, 1, 5, 0, 0),
    (0, 2, 4, 4, 2),
    (0, 7, 3, 1, 0),
    (0, 6, 6, 2, 4),
    (0, 2, 3, 2, 2),
    (0, 6, 1, 1, 4),
    (0, 6, 5, 1, 4),
    (0, 5, 4, 4, 1),
    (0, 5, 1, 1, 0),
    (0, 3, 5, 1, 2),
    (0, 4, 6, 2, 4),
    (0, 7, 2, 0, 1),
    (0, 1, 6, 2, 0),
    (0, 2, 2, 2, 0),
    (0, 4, 3, 1, 4),
    (0, 3, 7, 4, 1),
    (0, 1, 2, 2, 1),
    (0, 3, 3, 1, 1),
    (0, 3, 2, 2, 1),
    (0, 7, 4, 0, 2),
    (0, 4, 7, 0, 0),
    (0, 1, 7, 4, 0),
    (0, 5, 6, 4, 1),
    (0, 6, 2, 0, 4),
    (0, 7, 7, 1, 1),
    (0, 6, 4, 4, 2),
    (0, 5, 2, 2, 1),
    (0, 2, 6, 4, 0),
    (0, 2, 7, 1, 0),
    (0, 6, 7, 4, 4),
    (0, 7, 6, 2, 2),
    (0, 3, 6, 0, 2),
    (0, 4, 5, 4, 4),
    (0, 5, 7, 4, 1),
    (0, 7, 1, 0, 4),
    (0, 6, 6, 2, 2),
    (0, 6, 6, 4, 4),
    (1, 0, 1, 1, 1),
    (2, 3, 0, 2, 2),
    (3, 0, 0, 1, 1),
    (2, 5, 0, 4, 4),
    (3, 0, 0, 4, 4),
    (3, 0, 0, 2, 2),
    (1, 0, 6, 4, 4),
    (1, 0, 6, 4, 2),
    (2, 7, 0, 2, 1),
    (2, 6, 0, 2, 2),
    (1, 0, 8, 2, 2),
    (1, 0, 17, 1, 0),
    (1, 0, 32, 2, 1),
    (1, 0, 65, 1, 1),
    (1, 0, 128, 1, 2),
    (1, 0, 255, 0, 1),
    (2, 8, 0, 0, 0),
    (2, 17, 0, 2, 0),
    (2, 32, 0, 0, 2),
    (2, 65, 0, 1, 1),
    (2, 128, 0, 2, 2),
    (2, 255, 0, 1, 1),
)
# Tables 4.3-59/44, PDF pages 805-807/646-647: TX, RX, ordered Central/Peripheral
# preferences.
RESPONDING = (
    (3, 1, (2,), (1,)),
    (5, 2, (1,), (2,)),
    (2, 4, (2,), (4,)),
    (1, 2, (1,), (2,)),
    (4, 1, (4,), (1,)),
    (3, 6, (2,), (2,)),
    (1, 1, (1,), (1,)),
    (4, 3, (4,), (1,)),
    (5, 1, (1,), (1,)),
    (4, 4, (4,), (4,)),
    (5, 7, (4,), (2, 4)),
    (5, 5, (4,), (1,)),
    (4, 2, (4,), (2,)),
    (3, 7, (1,), (4, 1)),
    (6, 6, (2,), (4,)),
    (3, 2, (2,), (2,)),
    (1, 6, (1,), (4,)),
    (5, 6, (1,), (4,)),
    (4, 5, (4,), (1,)),
    (1, 5, (1,), (4,)),
    (5, 3, (1,), (2,)),
    (1, 4, (1,), (4,)),
    (1, 3, (1,), (2,)),
    (3, 5, (2,), (1,)),
    (6, 4, (2,), (4,)),
    (2, 7, (2,), (1, 2)),
    (6, 1, (2,), (1,)),
    (2, 2, (2,), (2,)),
    (3, 4, (1,), (4,)),
    (7, 3, (4, 1), (1,)),
    (2, 1, (2,), (1,)),
    (3, 3, (1,), (1,)),
    (2, 3, (2,), (1,)),
    (4, 7, (4,), (2, 4)),
    (7, 4, (1, 4), (4,)),
    (7, 1, (4, 2), (1,)),
    (6, 5, (4,), (1,)),
    (2, 6, (2,), (4,)),
    (7, 7, (1, 2), (1, 4)),
    (4, 6, (4,), (2,)),
    (2, 5, (2,), (1,)),
    (6, 2, (4,), (2,)),
    (7, 2, (1, 2), (2,)),
    (7, 6, (4, 1), (4,)),
    (6, 7, (2,), (2, 1)),
    (6, 3, (2,), (2,)),
    (5, 4, (4,), (4,)),
    (7, 5, (4, 2), (1,)),
    (1, 7, (1,), (4, 2)),
)


def _bit(phy):
    return 1 << phy - 1


def _phy_request(packet):
    if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL and packet.pdu[
        PDU_HEADER_SIZE : PDU_HEADER_SIZE + 1
    ] == bytes([Opcode.LL_PHY_REQ]):
        request = packet.pdu[PDU_HEADER_SIZE:]
        assert len(request) == PDU_CONTROL_PHY_REQ_SIZE
        supported = sum(_bit(phy) for phy in Phy)
        assert request[1] and request[2] and not (request[1] | request[2]) & ~supported
        return request
    return None


async def _settle_autonomous_phy(link):
    """Answer an autonomous Central request with current-PHY-only preferences."""
    response = bytes([Opcode.LL_PHY_RSP, _bit(link.tx_phy), _bit(link.rx_phy)])
    update = await link.control(Opcode.LL_PHY_UPDATE_IND, response, check_ack=True)
    assert update == bytes([Opcode.LL_PHY_UPDATE_IND, 0, 0, 0, 0])
    assert not any(
        isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
        for event in link.tester.events
    ), 'autonomous no-change procedure notified the Host'


async def _central_response(link, request):
    """Handle Step 3 collision, but forbid later unsolicited requests."""
    while True:
        packet = await link.exchange(request, llid=LlId.CONTROL)
        if _phy_request(packet) is not None:
            rejection = await link.control(Opcode.LL_REJECT_EXT_IND)
            assert rejection == bytes(
                [Opcode.LL_REJECT_EXT_IND, Opcode.LL_PHY_REQ, PROCEDURE_COLLISION]
            )
            await _settle_autonomous_phy(link)
            continue
        for _ in range(16):
            if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
                response = packet.pdu[PDU_HEADER_SIZE:]
                assert (
                    response[0] == Opcode.LL_PHY_UPDATE_IND
                ), 'unexpected control after PHY request; Central must not send PHY_RSP'
                return response
            packet = await link.exchange()
        raise AssertionError('Central PHY update indication absent')


def _check_phy_choice(update, allowed, current, *, constrained_zero=False):
    """Validate directional choices independently of the Controller selection."""
    assert len(update) == PDU_CONTROL_PHY_UPDATE_SIZE
    assert update[0] == Opcode.LL_PHY_UPDATE_IND
    choices = update[1:3]
    for selected, common, old in zip(choices, allowed, current):
        assert selected in (0, *(_bit(phy) for phy in Phy))
        assert not selected or selected & common
        assert not selected or selected != _bit(old), 'unchanged PHY must use zero'
        if constrained_zero and any(choices) and not selected:
            assert not common or common & _bit(old), 'illegal one-direction no-change'
    return any(choices)


async def _finish_update(
    tester,
    link,
    update,
    *,
    event_required,
    allowed,
    constrained_zero=False,
    allow_autonomous=False,
):
    current = (link.rx_phy, link.tx_phy) if link.central else (link.tx_phy, link.rx_phy)
    changed = _check_phy_choice(
        update, allowed, current, constrained_zero=constrained_zero
    )
    instant = int.from_bytes(update[-PDU_CONTROL_INSTANT_SIZE:], 'little')
    pending = None
    if changed:
        assert (
            0
            <= (instant - link.counter & LL_EVENT_COUNTER_MASK)
            < LL_EVENT_COUNTER_MASK // 2
        )
        options = (
            {'forbidden_opcodes': (Opcode.LL_PHY_REQ,)} if allow_autonomous else {}
        )
        await link.apply_update(update, check_event_timing=True, **options)
        if allow_autonomous:
            pending = _phy_request(link.last_received)
    else:
        assert instant == 0
    for _ in range(2):
        packet = await link.exchange()
        if allow_autonomous:
            request = _phy_request(packet)
            if request is not None:
                assert pending is None or pending == request
                pending = request
    if event_required or changed:
        event = await tester.event(hci.HCI_LE_PHY_Update_Complete_Event)
        assert (event.status, event.connection_handle, event.tx_phy, event.rx_phy) == (
            ErrorCode.SUCCESS,
            link.handle,
            link.rx_phy,
            link.tx_phy,
        )
    assert not any(
        isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
        for event in tester.events
    ), 'unexpected or duplicate PHY completion'
    if pending is not None:
        await _settle_autonomous_phy(link)
    return changed


def _initiating_selection(request, preferences, current):
    tx, rx = request[1:]
    central = rx & preferences[0]
    peripheral = tx & preferences[1]
    if tx == rx and tx.bit_count() == 1:
        central = peripheral = tx
    return _no_change_bits(central, peripheral, current)


async def _past_phy_update_outcome(link, update):
    """Accept a failed past-Instant update or the source's immediate-PHY alternative."""
    tester = link.tester
    packet, sent = await _wire_event(
        link,
        lambda _: _data_pdu(link.sn, link.nesn, update, llid=LlId.CONTROL),
        required=False,
    )
    if packet is not None:
        _restore_peer(link, packet, sent)
    event = await tester.expect(
        lambda event: isinstance(
            event,
            (
                hci.HCI_LE_PHY_Update_Complete_Event,
                hci.HCI_Disconnection_Complete_Event,
            ),
        )
    )
    assert event.connection_handle == link.handle
    if isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event):
        if event.status == ErrorCode.SUCCESS:
            target = Phy(update[1].bit_length())
            assert (event.tx_phy, event.rx_phy) == (target, target)
            link.tx_phy = link.rx_phy = target
            for _ in range(MAINTAINED_EVENTS):
                await link.exchange(check_ack=True)
                assert _disconnected(tester) is None
                assert not any(
                    isinstance(value, hci.HCI_LE_PHY_Update_Complete_Event)
                    for value in tester.events
                ), 'duplicate past-Instant PHY completion'
            await link.disconnect(local=True)
            return
        event = await tester.event(hci.HCI_Disconnection_Complete_Event)
    assert (event.status, event.connection_handle, event.reason) == (
        ErrorCode.SUCCESS,
        link.handle,
        ErrorCode.INSTANT_PASSED_ERROR,
    )
    for value in list(tester.events):
        if isinstance(value, hci.HCI_LE_PHY_Update_Complete_Event):
            assert value.connection_handle == link.handle
            assert value.status != ErrorCode.SUCCESS
            tester.events.remove(value)
    deadline = (
        tester.radio.now_us + link.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
    )
    while link.anchor < deadline:
        await link._send(link.channel, b'', LlId.CONTINUATION, link.anchor)
        until = min(
            deadline,
            link.anchor + link.parameters.interval * LL_CONN_INTERVAL_UNIT_US - 1,
        )
        assert (
            await tester.receive(
                link.channel,
                duration_us=until - tester.radio.now_us,
                **link.radio_parameters,
            )
            is None
        )
        link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
        link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    await tester.wait(max(0, deadline - tester.radio.now_us))


async def _invalid_phy_update_outcome(link, update, declared):
    """Accept disconnection or verify Feature Exchange on the unchanged active PHY."""
    tester = link.tester
    pending = deque(
        [
            update,
            bytes([Opcode.LL_FEATURE_REQ]) + bytes(PDU_CONTROL_FEATURE_SET_SIZE),
        ]
    )
    deadline = tester.radio.now_us + LL_RESPONSE_TIMEOUT_US
    while link.anchor < deadline:
        event = _disconnected(tester)
        if event is not None:
            assert (event.status, event.connection_handle) == (
                ErrorCode.SUCCESS,
                link.handle,
            )
            for value in list(tester.events):
                if isinstance(value, hci.HCI_LE_PHY_Update_Complete_Event):
                    assert value.connection_handle == link.handle
                    assert value.status != ErrorCode.SUCCESS
                    tester.events.remove(value)
            await _check_rf_stopped(link)
            return True
        data = pending[0] if pending else b''
        sent_sn = link.sn
        packet, sent = await _wire_event(
            link,
            lambda _, data=data: _data_pdu(
                link.sn,
                link.nesn,
                data,
                llid=LlId.CONTROL if data else LlId.CONTINUATION,
            ),
            required=False,
        )
        if packet is None:
            continue
        if pending and _sequence_bits(packet)[1] != sent_sn:
            pending.popleft()
            if len(pending) == 1:
                deadline = (
                    link.anchor
                    + link.tx_phy.airtime_us(PDU_HEADER_SIZE + len(pending[0]))
                    + LL_RESPONSE_TIMEOUT_US
                )
        _restore_peer(link, packet, sent)
        if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL and packet.pdu[
            PDU_HEADER_SIZE : PDU_HEADER_SIZE + 1
        ] == bytes([Opcode.LL_FEATURE_RSP]):
            assert not pending, 'Feature Response before its request was acknowledged'
            _check_feature_pdu(declared, packet.pdu[PDU_HEADER_SIZE:])
            await link.exchange(check_ack=True)
            assert _disconnected(tester) is None
            assert not any(
                isinstance(value, hci.HCI_LE_PHY_Update_Complete_Event)
                for value in tester.events
            ), 'invalid-PHY maintenance reported a PHY completion'
            return False
    raise AssertionError(
        'invalid PHY update neither disconnected nor maintained LL traffic'
    )


async def _invalid_update(tester, *, past=False, rfu=False):
    """Inject past Instants or the source's invalid-PHY table rows."""
    link = await establish(tester, peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS)
    declared = 0
    if past:
        await _prepare_preferences(tester, link)
        rows = ((_bit(Phy.LE_2M), _bit(Phy.LE_2M)),)
    else:
        declared = int.from_bytes(
            (
                await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
            ).le_features,
            'little',
        )
        invalid = 128 if rfu else _bit(Phy.LE_1M) | _bit(Phy.LE_2M)
        rows = (
            (invalid, invalid),
            (invalid, _bit(Phy.LE_1M)),
            (_bit(Phy.LE_1M), invalid),
        )
    for central, peripheral in rows:
        mask = _bit(Phy.LE_2M) if past else 255
        response = await link.control(
            Opcode.LL_PHY_RSP, bytes([Opcode.LL_PHY_REQ, mask, mask])
        )
        assert len(response) == PDU_CONTROL_PHY_REQ_SIZE and response[1] and response[2]
        supported = _bit(Phy.LE_1M) | _bit(Phy.LE_2M) | _bit(Phy.LE_CODED)
        assert not (response[1] | response[2]) & ~supported
        if past and (not response[1] & response[2] & _bit(Phy.LE_2M)):
            pytest.skip(
                'Inconclusive: PHY response does not select a non-1M PHY in both fields'
            )
        update = _update_pdu(link, central, peripheral)
        if past:
            instant = link.counter + LL_EVENT_COUNTER_MASK // 2 & LL_EVENT_COUNTER_MASK
            update = update[:-PDU_CONTROL_INSTANT_SIZE] + instant.to_bytes(
                PDU_CONTROL_INSTANT_SIZE, 'little'
            )
            await _past_phy_update_outcome(link, update)
            return
        if await _invalid_phy_update_outcome(link, update, declared):
            link = await establish(tester, peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS)
    await link.disconnect(local=True)


def _no_change_bits(central, peripheral, current):
    return tuple(
        (
            value if value != _bit(old) else 0
            for value, old in zip((central, peripheral), current)
        )
    )


async def _no_common_phy(tester, *, asymmetric=False):
    """Complete a Central PHY request without changing either radio direction."""
    link = await establish(
        tester, central=True, peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS
    )
    one, two = (_bit(Phy.LE_1M), _bit(Phy.LE_2M))
    await tester.command(
        hci.HCI_LE_Set_PHY_Command(link.handle, 0, one if asymmetric else two, two, 0)
    )
    request = await link.control(Opcode.LL_PHY_REQ, required=False)
    if request is None or (asymmetric and request[1:] != bytes([one, two])):
        pytest.skip('Inconclusive: required LL_PHY_REQ preferences not selected')
    assert len(request) == PDU_CONTROL_PHY_REQ_SIZE and request[1] and request[2]
    if asymmetric:
        peer_tx = peer_rx = two
    else:
        peer_tx, peer_rx = tuple(
            two if mask == one else one for mask in reversed(request[1:])
        )
    await link.exchange(bytes([Opcode.LL_PHY_RSP, peer_tx, peer_rx]), llid=LlId.CONTROL)
    assert not any(
        isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
        for event in tester.events
    ), 'PHY completion before the no-change indication was sent'
    update = await link.control(Opcode.LL_PHY_UPDATE_IND)
    assert update == bytes([Opcode.LL_PHY_UPDATE_IND, 0, 0, 0, 0])
    await _finish_update(tester, link, update, event_required=True, allowed=(0, 0))
    await link.disconnect(local=True)


async def _phy_timeout(tester, *, central=False, local=True):
    """Keep supervision alive while an acknowledged PHY request cannot complete."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    before = tester.radio.now_us
    mask = _bit(Phy.LE_2M)
    if local:
        await tester.command(hci.HCI_LE_Set_PHY_Command(link.handle, 0, mask, mask, 0))
        request = await link.control(Opcode.LL_PHY_REQ, required=False)
        if request is None:
            pytest.skip('Inconclusive: IUT did not initiate LL_PHY_REQ')
    else:
        request = await link.control(
            Opcode.LL_PHY_RSP, bytes([Opcode.LL_PHY_REQ, mask, mask])
        )
    after = link.last_received.start_us
    assert len(request) == PDU_CONTROL_PHY_REQ_SIZE and request[1] and request[2]
    if not central:
        await link.exchange()
    earliest = before + LL_RESPONSE_TIMEOUT_US - HCI_OBSERVATION_STEP_US
    latest = after + LL_RESPONSE_TIMEOUT_US + HCI_OBSERVATION_STEP_US
    while link.anchor < earliest:
        assert _disconnected(tester) is None
        packet = await link.exchange()
        if packet.pdu[1]:
            assert packet.pdu[PDU_HEADER_SIZE:] == request
        assert not any(
            isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
            and event.status == ErrorCode.SUCCESS
            for event in tester.events
        )
    event = await _observe_disconnection(tester, earliest, latest)
    assert (event.status, event.connection_handle, event.reason) == (
        ErrorCode.SUCCESS,
        link.handle,
        ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR,
    )
    await _check_rf_stopped(link)
    for event in tester.events:
        if isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event):
            assert (
                event.status != ErrorCode.SUCCESS
                and event.connection_handle == link.handle
            )


async def _phy_update(tester, *, central, local):
    """Run the complete role-specific PHY matrix in ordered and seeded random rounds."""
    result = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    features = int.from_bytes(result.le_features, 'little')
    assert features & int(
        hci.LeFeatureMask.LE_2M_PHY | hci.LeFeatureMask.LE_CODED_PHY
    ) == int(
        hci.LeFeatureMask.LE_2M_PHY | hci.LeFeatureMask.LE_CODED_PHY
    ), 'reduced-feature PHY tables require a separate procedure'
    supported = _bit(Phy.LE_1M) | _bit(Phy.LE_2M) | _bit(Phy.LE_CODED)
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    if not local:
        await _prepare_preferences(tester, link)
    table = (
        CENTRAL_INITIATING
        if central and local
        else PERIPHERAL_INITIATING if local else RESPONDING
    )
    rows = list(enumerate(table, 1))
    changes = procedures = 0
    for repetition in range(2):
        for number, row in rows:
            tester.output.write(f'PHY ROUND {repetition + 1} ROW {number} {row}\n')
            current = (
                (link.tx_phy, link.rx_phy)
                if not central
                else (link.rx_phy, link.tx_phy)
            )
            if local:
                all_phys, tx, rx, peer_a, peer_b = row
                expected = (
                    ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR
                    if (tx | rx) & ~supported
                    else ErrorCode.SUCCESS
                )
                status = await tester.command(
                    hci.HCI_LE_Set_PHY_Command(link.handle, all_phys, tx, rx, 0),
                    status=expected,
                )
                request = await link.control(Opcode.LL_PHY_REQ, required=False)
                if request is None:
                    if status.status == ErrorCode.SUCCESS:
                        event = await tester.event(hci.HCI_LE_PHY_Update_Complete_Event)
                        assert (
                            event.status,
                            event.connection_handle,
                            event.tx_phy,
                            event.rx_phy,
                        ) == (ErrorCode.SUCCESS, link.handle, link.rx_phy, link.tx_phy)
                    else:
                        assert not any(
                            isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
                            for event in tester.events
                        )
                    continue
                assert len(request) == PDU_CONTROL_PHY_REQ_SIZE
                req_tx, req_rx = request[1:]
                assert req_tx and req_rx and (not (req_tx | req_rx) & ~supported)
                if central:
                    update = await link.control(
                        Opcode.LL_PHY_UPDATE_IND,
                        bytes([Opcode.LL_PHY_RSP, peer_b, peer_a]),
                    )
                    allowed = (req_tx & peer_a, req_rx & peer_b)
                else:
                    selected = _initiating_selection(request, (peer_a, peer_b), current)
                    update = _update_pdu(link, *selected)
                    await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
                    allowed = (req_rx, req_tx)
                event_required = status.status == ErrorCode.SUCCESS
            else:
                tx, rx, preferences_central, preferences_peripheral = row
                request = bytes([Opcode.LL_PHY_REQ, tx, rx])
                if central:
                    update = await _central_response(link, request)
                    allowed = (rx, tx)
                    if tx == rx and tx.bit_count() == 1:
                        assert not any(update[1:3]) or all(
                            (selected or _bit(old)) == tx
                            for selected, old in zip(update[1:3], current)
                        ), 'single-PHY request did not select symmetric effective PHYs'
                else:
                    response = await link.control(Opcode.LL_PHY_RSP, request)
                    assert len(response) == PDU_CONTROL_PHY_REQ_SIZE
                    rsp_tx, rsp_rx = response[1:]
                    assert rsp_tx and rsp_rx and (not (rsp_tx | rsp_rx) & ~supported)
                    selected = _responding_selection(
                        request,
                        response,
                        (preferences_central, preferences_peripheral),
                        current,
                    )
                    update = _update_pdu(link, *selected)
                    await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
                    allowed = (tx & rsp_rx, rx & rsp_tx)
                event_required = False
            changes += await _finish_update(
                tester,
                link,
                update,
                event_required=event_required,
                allowed=allowed,
                constrained_zero=central and local,
                allow_autonomous=central and not local,
            )
            procedures += 1
        random.Random(0).shuffle(rows)
    requires_change = central if local else not central
    if not procedures or (requires_change and not changes):
        pytest.skip('Inconclusive: no required PHY procedure/change was exercised')
    await link.disconnect(local=True)


async def _prepare_preferences(tester, link):
    await tester.command(hci.HCI_LE_Set_PHY_Command(link.handle, 3, 0, 0, 0))
    request = await link.control(Opcode.LL_PHY_REQ, required=False)
    if request is not None:
        if link.central:
            update = await link.control(
                Opcode.LL_PHY_UPDATE_IND,
                bytes([Opcode.LL_PHY_RSP, _bit(Phy.LE_1M), _bit(Phy.LE_1M)]),
            )
        else:
            update = _update_pdu(link, 0, 0)
            await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
        await _finish_update(
            tester,
            link,
            update,
            event_required=True,
            allowed=(_bit(Phy.LE_1M), _bit(Phy.LE_1M)),
            allow_autonomous=link.central,
        )
    else:
        event = await tester.event(hci.HCI_LE_PHY_Update_Complete_Event)
        assert (event.status, event.connection_handle, event.tx_phy, event.rx_phy) == (
            ErrorCode.SUCCESS,
            link.handle,
            Phy.LE_1M,
            Phy.LE_1M,
        )


def _responding_selection(request, response, preferences, current):
    req_tx, req_rx = request[1:]
    rsp_tx, rsp_rx = response[1:]
    central = _select(req_tx & rsp_rx, preferences[0])
    peripheral = _select(req_rx & rsp_tx, preferences[1])
    if rsp_tx == rsp_rx and rsp_tx.bit_count() == 1:
        central = peripheral = rsp_tx if rsp_tx & req_tx & req_rx else 0
    return _no_change_bits(central, peripheral, current)


def _select(mask, preferences):
    if mask.bit_count() <= 1:
        return mask
    return next(value for value in preferences if value & mask)


def _update_pdu(link, central, peripheral):
    instant = (
        link.counter + LL_INSTANT_MIN_LISTENING_EVENTS + 1 & LL_EVENT_COUNTER_MASK
        if central or peripheral
        else 0
    )
    return bytes([Opcode.LL_PHY_UPDATE_IND, central, peripheral]) + instant.to_bytes(
        PDU_CONTROL_INSTANT_SIZE, 'little'
    )


# Minimum interval, zero latency and intermediate 3-second supervision timeout.
PARAMETER_TIMEOUT = 300


async def _central_collision(tester, *, procedure):
    """Reject a Peripheral PHY request while retaining the Central's procedure."""
    link = await establish(
        tester, central=True, peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS
    )
    mask = _bit(Phy.LE_2M)
    request_opcode = {
        'phy': Opcode.LL_PHY_REQ,
        'map': Opcode.LL_CHANNEL_MAP_IND,
        'parameters': Opcode.LL_CONNECTION_PARAM_REQ,
    }[procedure]
    if procedure == 'phy':
        await tester.command(hci.HCI_LE_Set_PHY_Command(link.handle, 0, mask, mask, 0))
    elif procedure == 'map':
        even = sum(1 << channel for channel in range(0, LL_DATA_CHANNEL_COUNT, 2))
        for attempt in range(20):
            channel_map = even if not attempt else even & ~(1 << 2 * (attempt - 1))
            result = await tester.command(
                hci.HCI_LE_Set_Host_Channel_Classification_Command(
                    channel_map.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
                ),
                status=tuple(ErrorCode),
            )
            if result.status == ErrorCode.SUCCESS:
                break
            deadline = tester.radio.now_us + 5000000
            while tester.radio.now_us < deadline:
                await link.exchange()
        else:
            pytest.skip('Inconclusive: all twenty Host channel classifications failed')
    else:
        await link.control(
            Opcode.LL_FEATURE_RSP,
            bytes([Opcode.LL_PERIPHERAL_FEATURE_REQ])
            + int(hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE).to_bytes(
                PDU_CONTROL_FEATURE_SET_SIZE, 'little'
            ),
        )
        await tester.command(
            hci.HCI_LE_Connection_Update_Command(
                link.handle,
                LL_CONN_INTERVAL_MIN,
                LL_CONN_INTERVAL_MIN,
                0,
                PARAMETER_TIMEOUT,
                0,
                0,
            )
        )
    original = None

    def collide(packet):
        nonlocal original
        if (
            packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
            and packet.pdu[PDU_HEADER_SIZE] == request_opcode
        ):
            original = packet.pdu[PDU_HEADER_SIZE:]
            return (bytes([Opcode.LL_PHY_REQ, mask, mask]), LlId.CONTROL)
        return (b'', LlId.CONTINUATION)

    for _ in range(16):
        await link.exchange(reply=collide)
        if original is not None:
            break
    if original is None:
        if procedure == 'phy':
            pytest.skip('Inconclusive: required local LL indication/request absent')
        pytest.fail(f'Central did not initiate the {procedure} procedure')
    reason = (
        PROCEDURE_COLLISION
        if procedure == 'phy'
        else ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR
    )
    rejection = await link.control(Opcode.LL_REJECT_EXT_IND)
    assert rejection == bytes([Opcode.LL_REJECT_EXT_IND, Opcode.LL_PHY_REQ, reason])
    if procedure == 'phy':
        assert len(original) == PDU_CONTROL_PHY_REQ_SIZE and original[1] and original[2]
        supported = sum(_bit(phy) for phy in Phy)
        assert not (original[1] | original[2]) & ~supported
        update = await link.control(
            Opcode.LL_PHY_UPDATE_IND, bytes([Opcode.LL_PHY_RSP, mask, mask])
        )
        allowed = (original[1] & mask, original[2] & mask)
        if not _check_phy_choice(
            update,
            allowed,
            (link.rx_phy, link.tx_phy),
            constrained_zero=True,
        ):
            pytest.skip('Inconclusive: Central did not select a PHY change')
        await _finish_update(
            tester,
            link,
            update,
            event_required=True,
            allowed=allowed,
            constrained_zero=True,
        )
    elif procedure == 'parameters':
        _check_parameter_pdu(original)
        response = (
            bytes([Opcode.LL_CONNECTION_PARAM_RSP])
            + _parameter_request(link, LL_CONN_INTERVAL_MIN, PARAMETER_TIMEOUT)[1:]
        )
        update = await link.control(Opcode.LL_CONNECTION_UPDATE_IND, response)
        await _check_parameter_update(
            tester, link, update, LL_CONN_INTERVAL_MIN, PARAMETER_TIMEOUT
        )
    else:
        assert len(original) == PDU_CONTROL_CHANNEL_MAP_SIZE
        assert (
            int.from_bytes(original[1:-PDU_CONTROL_INSTANT_SIZE], 'little')
            == channel_map
        )
        await link.apply_update(original)
        for _ in range(3):
            await link.exchange()
        result = await tester.command(hci.HCI_LE_Read_Channel_Map_Command(link.handle))
        assert result.connection_handle == link.handle
        assert int.from_bytes(result.channel_map, 'little') == channel_map
    assert not any(
        isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
        for event in tester.events
    ), 'rejected remote request leaked an HCI PHY completion'
    await peer_send(tester, link, b'collision-complete')
    await link.disconnect(local=True)


async def _phy_collision_peripheral_collision(tester, *, procedure):
    """Yield a local PHY procedure to the Central without losing its new procedure."""
    link = await establish(tester, peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS)
    mask = _bit(Phy.LE_2M)
    await tester.command(hci.HCI_LE_Set_PHY_Command(link.handle, 0, mask, mask, 0))
    request = await link.control(Opcode.LL_PHY_REQ, required=False)
    if request is None:
        pytest.skip('Inconclusive: Peripheral did not initiate LL_PHY_REQ')
    assert len(request) == PDU_CONTROL_PHY_REQ_SIZE and request[1] and request[2]
    instant = link.counter + LL_INSTANT_MIN_LISTENING_EVENTS + 1 & LL_EVENT_COUNTER_MASK
    channel_map = sum(1 << channel for channel in range(0, LL_DATA_CHANNEL_COUNT, 2))
    if procedure == 'phy':
        incoming = bytes([Opcode.LL_PHY_REQ, mask, mask])
    elif procedure == 'map':
        incoming = (
            bytes([Opcode.LL_CHANNEL_MAP_IND])
            + channel_map.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
            + instant.to_bytes(PDU_CONTROL_INSTANT_SIZE, 'little')
        )
    elif procedure == 'parameters':
        incoming = _parameter_request(link, LL_CONN_INTERVAL_MIN, PARAMETER_TIMEOUT)
    else:
        assert procedure == 'update'
        incoming = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + struct.pack(
            '<BHHHHH',
            LL_CONN_WINDOW_SIZE_MIN,
            0,
            LL_CONN_INTERVAL_MIN,
            0,
            PARAMETER_TIMEOUT,
            instant,
        )
    packet = await link.exchange(incoming, llid=LlId.CONTROL, check_ack=True)
    assert (
        packet.pdu[0] & PDU_DATA_LLID_MASK != LlId.CONTROL
    ), 'Peripheral rejected or answered the Central before local rejection'
    reason = (
        PROCEDURE_COLLISION
        if procedure == 'phy'
        else ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR
    )
    packet = await link.exchange(
        bytes([Opcode.LL_REJECT_EXT_IND, Opcode.LL_PHY_REQ, reason]),
        llid=LlId.CONTROL,
        check_ack=True,
    )
    failures = [
        event
        for event in tester.events
        if isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
    ]
    assert failures or procedure == 'phy', 'missing HCI PHY collision failure'
    for event in failures:
        assert (event.status, event.connection_handle, event.tx_phy, event.rx_phy) == (
            reason,
            link.handle,
            Phy.LE_1M,
            Phy.LE_1M,
        )
        tester.events.remove(event)
    if procedure == 'phy':
        response = packet.pdu[PDU_HEADER_SIZE:]
        if not response or response[0] != Opcode.LL_PHY_RSP:
            response = await link.control(Opcode.LL_PHY_RSP)
        assert len(response) == PDU_CONTROL_PHY_REQ_SIZE
        supported = _bit(Phy.LE_1M) | _bit(Phy.LE_2M) | _bit(Phy.LE_CODED)
        assert (
            response[1]
            and response[2]
            and (not (response[1] | response[2]) & ~supported)
        )
        assert response[1] & response[2] & mask
        update = _update_pdu(link, mask, mask)
        await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
        await _finish_update(
            tester, link, update, event_required=True, allowed=(mask, mask)
        )
    elif procedure == 'parameters':
        await _accept_remote_parameters(
            tester, link, LL_CONN_INTERVAL_MIN, PARAMETER_TIMEOUT
        )
    elif procedure == 'update':
        await _check_parameter_update(
            tester, link, incoming, LL_CONN_INTERVAL_MIN, PARAMETER_TIMEOUT
        )
    else:
        await link.apply_update(incoming)
        for _ in range(3):
            await link.exchange()
        result = await tester.command(hci.HCI_LE_Read_Channel_Map_Command(link.handle))
        assert result.connection_handle == link.handle
        assert int.from_bytes(result.channel_map, 'little') == channel_map
    assert not any(
        isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
        for event in tester.events
    ), 'duplicate or unrelated HCI PHY completion after collision'
    await peer_send(tester, link, b'collision-complete')
    await link.disconnect(local=True)


CODED_DELAY_OCTETS = 423
# LL.TS.p28, CEN Step7/PER Step8: complete packet count for each payload size.
CODED_PACKET_COUNT = 288
CODED_PACKET_OCTETS = 141
CODED_PACKET_TIME_US = 1240
# LL.TS.p28, PDF827/676..677: eighteen rows of sixteen consecutive DATA packets.
CODING_PATTERN = tuple(
    int(value)
    for row in (
        '2828282828282828',
        '2828282828282828',
        '2222222288888888',
        '2222222282222222',
        '2888888882888888',
        '8888888888222222',
        '2222222222822222',
        '2222222222288888',
        '8888888888828888',
        '8888888888888222',
        '8882228882882228',
        '2822828888828282',
        '8222282882888822',
        '8882282828822882',
        '2222882882828882',
        '8222882282228222',
        '2228228228828228',
        '8882888222288888',
    )
    for value in row
)
# A tester observation bound, not a protocol response deadline.
CONTROL_OBSERVATION_EVENTS = 16
# All changed-PHY traffic procedures observe ten further events after Instant.
POST_INSTANT_EVENTS = 10
# LL.TS.p28, CEN Step8/PER Step9: 150 us +/-2 us for every response.
RESPONSE_TOLERANCE_US = 2
# No-change procedures delay the indication until these DATA totals are received.
UNCODED_DELAY_OCTETS = 140
# LL.TS.p28 PHY packet-time procedures: 2M->1M, or 1M->Coded.
UNCODED_PACKET_OCTETS = 32
UNCODED_PACKET_TIME_US = 328


async def _coded_reception(tester, *, central):
    """Receive every prescribed coding transition at maximum and minimum payload
    sizes."""
    supported = await _supported_lengths(tester)
    link = await establish(
        tester,
        central=central,
        interval=LL_CONN_INTERVAL_MAX,
        timeout=LL_SUPERVISION_TIMEOUT_MAX,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    coded = _bit(Phy.LE_CODED)
    if central:
        await tester.command(
            hci.HCI_LE_Set_PHY_Command(link.handle, 0, coded, coded, 0)
        )
        request = await link.control(Opcode.LL_PHY_REQ)
        assert len(request) == PDU_CONTROL_PHY_REQ_SIZE and request[1] and request[2]
        update = await link.control(
            Opcode.LL_PHY_UPDATE_IND, bytes([Opcode.LL_PHY_RSP, coded, coded])
        )
        if update[1:3] != bytes([coded, coded]):
            pytest.skip('Inconclusive: Central did not select Coded in both directions')
    else:
        await _prepare_preferences(tester, link)
        response = await link.control(
            Opcode.LL_PHY_RSP, bytes([Opcode.LL_PHY_REQ, coded, coded])
        )
        assert len(response) == PDU_CONTROL_PHY_REQ_SIZE and response[1] and response[2]
        if not response[1] & response[2] & coded:
            pytest.skip('Inconclusive: Peripheral PHY response does not support Coded')
        update = _update_pdu(link, coded, coded)
        await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
    await _finish_update(
        tester, link, update, event_required=True, allowed=(coded, coded)
    )
    before = (PDU_DATA_PAYLOAD_SIZE_MIN, PDU_DATA_PAYLOAD_TIME_CODED_MIN_US) * 2
    _check_changed_events(tester, link.handle, MINIMUM, before)
    effective = before
    if (
        supported[2] > PDU_DATA_PAYLOAD_SIZE_MIN
        or supported[3] > PDU_DATA_PAYLOAD_TIME_MIN_US
    ):
        result = await tester.command(
            hci.HCI_LE_Set_Data_Length_Command(link.handle, *supported[2:])
        )
        assert result.connection_handle == link.handle
        request = await link.control(Opcode.LL_LENGTH_REQ, required=False)
        peer = (*supported[2:], *supported[:2])
        if request is not None:
            dut = _check_parameters(request, Opcode.LL_LENGTH_REQ, supported)
            await link.exchange(
                bytes([Opcode.LL_LENGTH_RSP]) + LENGTH_FIELDS.pack(*peer),
                llid=LlId.CONTROL,
            )
        else:
            response = await link.control(
                Opcode.LL_LENGTH_RSP,
                bytes([Opcode.LL_LENGTH_REQ]) + LENGTH_FIELDS.pack(*peer),
            )
            dut = _check_parameters(response, Opcode.LL_LENGTH_RSP, supported)
        effective = _effective_lengths(dut, peer, link)
        _check_changed_events(
            tester,
            link.handle,
            before,
            effective,
            intermediate=_effective_lengths(dut, MINIMUM, link),
        )
    for size in (effective[2], PDU_DATA_PAYLOAD_SIZE_MIN):
        await _receive_coding_sequence(tester, link, size)
    await link.disconnect(local=True)


async def _complete_update(stream, update, target):
    link, tester = (stream.link, stream.tester)
    mask = _bit(target)
    supported = sum(_bit(phy) for phy in Phy)
    _check_phy_choice(
        update,
        (supported, supported),
        (link.rx_phy, link.tx_phy) if link.central else (link.tx_phy, link.rx_phy),
    )
    if update[1:3] != bytes([mask, mask]):
        pytest.skip('Inconclusive: IUT did not select the required bidirectional PHY')
    instant = int.from_bytes(update[-PDU_CONTROL_INSTANT_SIZE:], 'little')
    distance = instant - link.counter & LL_EVENT_COUNTER_MASK
    assert 0 <= distance < LL_EVENT_COUNTER_MASK // 2
    before = _effective_lengths(stream.dut, stream.peer, link)
    for _ in range(distance):
        assert not any(
            isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
            for event in tester.events
        ), 'PHY completion before Instant'
        await stream.event()
    assert not any(
        isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
        for event in tester.events
    ), 'PHY completion before Instant'
    link.tx_phy = link.rx_phy = target
    await stream.event()
    event = await tester.event(hci.HCI_LE_PHY_Update_Complete_Event)
    assert (event.status, event.connection_handle, event.tx_phy, event.rx_phy) == (
        ErrorCode.SUCCESS,
        link.handle,
        target,
        target,
    )
    after = _effective_lengths(stream.dut, stream.peer, link)
    if getattr(stream, 'lengths', None) is None:
        _check_changed_events(tester, link.handle, before, after)
    for _ in range(POST_INSTANT_EVENTS):
        await stream.event()
    if getattr(stream, 'lengths', None) is not None:
        stream.lengths.check(final=True)
    assert not any(
        isinstance(
            event,
            (hci.HCI_LE_PHY_Update_Complete_Event, hci.HCI_LE_Data_Length_Change_Event),
        )
        for event in tester.events
    ), 'duplicate change event'


async def _mandatory_coded_minimum(tester, *, central):
    """Keep 27-octet DATA flowing when Coded raises the mandatory time minimum."""
    link = await establish(
        tester,
        central=central,
        interval=48,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    buffer = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
    stream = _AclStream(
        tester,
        link,
        MINIMUM,
        MINIMUM,
        PDU_DATA_PAYLOAD_SIZE_MIN,
        buffer.total_num_le_acl_data_packets,
    )
    stream.coded_dle_inconclusive = True
    stream.require_initial_full_size = False
    await tester.command(hci.HCI_LE_Set_PHY_Command(link.handle, 3, 0, 0, 0))
    request = await stream.control(Opcode.LL_PHY_REQ, queue=False, required=False)
    if request is not None:
        assert len(request) == PDU_CONTROL_PHY_REQ_SIZE and request[1] and request[2]
        if central:
            update = await stream.control(
                Opcode.LL_PHY_UPDATE_IND,
                bytes([Opcode.LL_PHY_RSP, _bit(Phy.LE_1M), _bit(Phy.LE_1M)]),
                queue=False,
            )
            assert update == _update_pdu(link, 0, 0)
        else:
            await stream.event(_update_pdu(link, 0, 0), queue=False)
    event = await tester.event(hci.HCI_LE_PHY_Update_Complete_Event)
    assert (event.status, event.connection_handle, event.tx_phy, event.rx_phy) == (
        ErrorCode.SUCCESS,
        link.handle,
        Phy.LE_1M,
        Phy.LE_1M,
    )
    request = stream.take(Opcode.LL_LENGTH_REQ)
    if request is not None:
        supported = await _supported_lengths(tester)
        dut = _check_parameters(request, Opcode.LL_LENGTH_REQ, supported)
        await stream.event(
            bytes([Opcode.LL_LENGTH_RSP]) + LENGTH_FIELDS.pack(*MINIMUM), queue=False
        )
        _check_changed_events(
            tester, link.handle, MINIMUM, _effective_lengths(dut, MINIMUM, link)
        )
    await stream.event()
    stream.trigger = Opcode.LL_PHY_UPDATE_IND if central else Opcode.LL_PHY_REQ
    for target in (Phy.LE_CODED, Phy.LE_1M):
        update = await _start_update(stream, target, local=True, fallback=True)
        await _complete_update(stream, update, target)
    await stream.finish()
    await link.disconnect(local=True)


async def _negotiate_traffic_lengths(tester, link, octets, time_us):
    supported = await _supported_lengths(tester)
    peer = (octets, time_us) * 2
    await tester.command(
        hci.HCI_LE_Set_Data_Length_Command(link.handle, octets, time_us)
    )
    request = await link.control(Opcode.LL_LENGTH_REQ, required=False)
    if request is not None:
        dut = _check_parameters(request, Opcode.LL_LENGTH_REQ, supported)
        await link.exchange(
            bytes([Opcode.LL_LENGTH_RSP]) + LENGTH_FIELDS.pack(*peer), llid=LlId.CONTROL
        )
    else:
        response = await link.control(
            Opcode.LL_LENGTH_RSP,
            bytes([Opcode.LL_LENGTH_REQ]) + LENGTH_FIELDS.pack(*peer),
        )
        dut = _check_parameters(response, Opcode.LL_LENGTH_RSP, supported)
    if dut[2] < octets or dut[3] < time_us:
        pytest.skip('Inconclusive: IUT did not select the required DLE limits')
    await tester.wait(0)
    current = _effective_lengths(dut, peer, link)
    _check_changed_events(
        tester, link.handle, _effective_lengths(MINIMUM, MINIMUM, link), current
    )
    return (dut, peer)


async def _packet_time_restrictions(
    tester, *, central, local, coded=False, no_change=False
):
    """Observe every DATA before the procedure, before Instant and after the change."""
    link = await establish(
        tester,
        central=central,
        interval=48,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    if local or not central or coded:
        await _prepare_preferences(tester, link)
    if not coded:
        await _change_phy(tester, link, Phy.LE_2M, local=central)
    size, time_us = (
        (CODED_PACKET_OCTETS, CODED_PACKET_TIME_US)
        if coded
        else (UNCODED_PACKET_OCTETS, UNCODED_PACKET_TIME_US)
    )
    dut, peer = await _negotiate_traffic_lengths(tester, link, size, time_us)
    buffer = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
    stream = _AclStream(
        tester, link, dut, peer, size, buffer.total_num_le_acl_data_packets
    )
    stream.coded_dle_inconclusive = coded and (not central or local)
    if coded and central and not local:
        supported = await _supported_lengths(tester)
        stream.lengths = _LengthObserver(tester, link, dut, peer, supported)
        link.on_receive = stream.lengths.receive
    for _ in range(CONTROL_OBSERVATION_EVENTS):
        await stream.event()
        if stream.submitted > len(stream.expected):
            break
    else:
        raise AssertionError('no complete DATA observed before the PHY procedure')
    if central and (not local) and (not coded):
        await tester.command(hci.HCI_LE_Set_PHY_Command(link.handle, 3, 0, 0, 0))
        if await stream.control(Opcode.LL_PHY_REQ, required=False) is not None:
            mask = _bit(Phy.LE_2M)
            update = await stream.control(
                Opcode.LL_PHY_UPDATE_IND, bytes([Opcode.LL_PHY_RSP, mask, mask])
            )
            assert update == bytes([Opcode.LL_PHY_UPDATE_IND, 0, 0, 0, 0])
        event = await tester.event(hci.HCI_LE_PHY_Update_Complete_Event)
        assert (event.status, event.connection_handle, event.tx_phy, event.rx_phy) == (
            ErrorCode.SUCCESS,
            link.handle,
            Phy.LE_2M,
            Phy.LE_2M,
        )
    stream.trigger = (
        Opcode.LL_PHY_UPDATE_IND
        if central
        else Opcode.LL_PHY_REQ if local else Opcode.LL_PHY_RSP
    )
    stream.limit = size - 1
    target = Phy.LE_CODED if coded else Phy.LE_1M
    update = await _start_update(stream, target, local=local, no_change=no_change)
    assert not stream.initial, 'on-air restriction boundary was not observed'
    if no_change:
        assert update == bytes([Opcode.LL_PHY_UPDATE_IND, 0, 0, 0, 0])
        await tester.wait(0)
        if local:
            event = await tester.event(hci.HCI_LE_PHY_Update_Complete_Event)
            assert (
                event.status,
                event.connection_handle,
                event.tx_phy,
                event.rx_phy,
            ) == (ErrorCode.SUCCESS, link.handle, link.rx_phy, link.tx_phy)
        else:
            assert not any(
                isinstance(event, hci.HCI_LE_PHY_Update_Complete_Event)
                for event in tester.events
            )
    else:
        await _complete_update(stream, update, target)
    await stream.finish()
    await link.disconnect(local=True)


async def _receive_coding_sequence(tester, link, size):
    """Keep each 288-packet sequence within one maximum-interval connection event."""
    assert len(CODING_PATTERN) == CODED_PACKET_COUNT
    tester.output.write(f'CODED RX ROUND octets={size} packets={len(CODING_PATTERN)}\n')
    if link.central:
        response = await _receive_empty(link, link.anchor)
        start = response.end_us + LL_IFS_US
    else:
        start = link.anchor
    for index, coding in enumerate(CODING_PATTERN):
        data = bytes(index * size + octet & PHY_OCTET_MASK for octet in range(size))
        sn = link.sn
        pdu = _data_pdu(sn, link.nesn, data, llid=LlId.START)
        more = link.central or index + 1 < len(CODING_PATTERN)
        pdu = bytes([pdu[0] | (PDU_DATA_MD_MASK if more else 0)]) + pdu[1:]
        tester.output.write(f'CODED RX PACKET {index + 1} S={coding} octets={size}\n')
        end = await tester.transmit(
            link.channel, pdu, start_us=start, coding=coding, **link.radio_parameters
        )
        assert (
            end - start
            == PHY_CODED_FEC1_TIME_US
            + (
                (PDU_HEADER_SIZE + size + PDU_CRC_SIZE) * PHY_OCTET_BITS
                + PHY_CODED_TERM2_SIZE_BITS
            )
            * coding
        )
        response = await _receive_empty(link, end + LL_IFS_US, acknowledged_sn=sn)
        await received_acl(tester, link, data, False)
        start = response.end_us + LL_IFS_US
    if link.central:
        await link._send(link.channel, b'', LlId.CONTINUATION, start)
    assert (
        tester.radio.now_us
        < link.anchor + link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    )
    link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    assert not any(
        isinstance(event, hci.HCI_AclDataPacket) for event in tester.events
    ), 'duplicate or unexpected HCI data after the 288-packet sequence'


async def _receive_empty(link, expected_start, *, acknowledged_sn=None):
    tester = link.tester
    packet = await tester.expect_pdu(
        link.channel,
        start_us=max(tester.radio.now_us + 1, expected_start - RESPONSE_TOLERANCE_US),
        duration_us=max(3000, expected_start - tester.radio.now_us + 3000),
        **link.radio_parameters | {'phy': link.rx_phy},
    )
    assert abs(packet.start_us - expected_start) <= RESPONSE_TOLERANCE_US
    assert packet.phy == Phy.LE_CODED
    assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
    assert packet.pdu[1] == 0, 'IUT response is not an empty DATA PDU'
    sn, nesn = _sequence_bits(packet)
    assert sn == link.nesn
    if acknowledged_sn is not None:
        assert nesn == acknowledged_sn ^ 1, 'IUT did not acknowledge the DATA PDU'
    link._accept(packet)
    link.last_received = packet
    return packet


async def _start_update(stream, target, *, local, no_change=False, fallback=False):
    tester, link = (stream.tester, stream.link)
    procedure_before_us = tester.radio.now_us
    mask = _bit(target)
    if local:
        await tester.wait(0)
        stream.enqueue()
        await tester.command(hci.HCI_LE_Set_PHY_Command(link.handle, 0, mask, mask, 0))
        request = await stream.control(Opcode.LL_PHY_REQ)
        assert len(request) == PDU_CONTROL_PHY_REQ_SIZE and request[1] and request[2]
        permitted = (
            request[1] if no_change and not link.central else request[1] & request[2]
        )
        if not permitted & mask:
            if not fallback or link.central:
                pytest.skip(
                    'Inconclusive: IUT request does not permit the selected PHY'
                )
            await stream.event(_update_pdu(link, 0, 0))
            event = await tester.event(hci.HCI_LE_PHY_Update_Complete_Event)
            assert (event.status, event.tx_phy, event.rx_phy) == (
                ErrorCode.SUCCESS,
                link.rx_phy,
                link.tx_phy,
            )
            response = await stream.control(
                Opcode.LL_PHY_RSP, bytes([Opcode.LL_PHY_REQ, mask, mask])
            )
            assert (
                len(response) == PDU_CONTROL_PHY_REQ_SIZE
                and response[1]
                and response[2]
            )
            if not response[1] & response[2] & mask:
                pytest.skip(
                    'Inconclusive: remote fallback does not permit selected PHY'
                )
        if link.central:
            return await stream.control(
                Opcode.LL_PHY_UPDATE_IND, bytes([Opcode.LL_PHY_RSP, mask, mask])
            )
    else:
        preferences = mask | (_bit(link.tx_phy) if no_change else 0)
        request = bytes([Opcode.LL_PHY_REQ, preferences, preferences])
        if link.central:
            return await stream.control(Opcode.LL_PHY_UPDATE_IND, request)
        response = await stream.control(Opcode.LL_PHY_RSP, request)
        assert len(response) == PDU_CONTROL_PHY_REQ_SIZE and response[1] and response[2]
        permitted = response[1] if no_change else response[1] & response[2]
        if not permitted & mask:
            pytest.skip('Inconclusive: IUT response does not permit the selected PHY')
    if no_change:
        threshold = (
            CODED_DELAY_OCTETS if target == Phy.LE_CODED else UNCODED_DELAY_OCTETS
        )
        deadline = tester.radio.now_us + LL_RESPONSE_TIMEOUT_US
        while stream.restricted_octets < threshold:
            if tester.radio.now_us >= deadline:
                pytest.skip(
                    'Inconclusive: required DATA total absent before procedure timeout'
                )
            await stream.event(
                response_timeout_after_us=procedure_before_us
                + LL_RESPONSE_TIMEOUT_US
                - HCI_OBSERVATION_STEP_US
            )
        update = _update_pdu(link, 0, 0)
    else:
        update = _update_pdu(link, mask, mask)
    if no_change:
        # The Lower Central sends the update before DATA returned by this exchange.
        stream.restricted = False
    await stream.event(update)
    return update


ARQ_CENTRAL_TIMEOUT = 90
# The MSCs prescribe one 0xFF data octet and four for the normal Central scheme.
ARQ_PAYLOAD = b'\xff'
# LL.TS.p28 ARQ procedures repeat fifteen exchanges; Central uses 900 ms.
ARQ_ROUNDS = 15


async def _acknowledgement_scheme(tester, *, central=False):
    """Exercise fifteen normal sequence transitions with exact payload and HCI
    checks."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
        timeout=ARQ_CENTRAL_TIMEOUT if central else 100,
    )
    receiver = _HciDataStream(tester, link.handle) if central else None
    for _ in range(ARQ_ROUNDS):
        if central:
            data = ARQ_PAYLOAD * 4
            receiver.sent(data, False)
            await host_send(tester, link, data, peer_data=data, receiver=receiver)
        else:
            expected = link.nesn
            packet = await link.exchange(check_ack=True)
            assert _sequence_bits(packet)[0] == expected
            assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
            assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
    if receiver is not None:
        await receiver.finish()
    await link.disconnect()


def _restore_peer(link, packet, sent):
    """Restore normal peer sequencing after a CRC-valid, positively acknowledged
    exchange."""
    if link.central:
        link.sn = int(bool(sent[0] & PDU_DATA_SN_MASK))
        link.nesn = int(bool(sent[0] & PDU_DATA_NESN_MASK))
    else:
        sn, nesn = _sequence_bits(packet)
        link.sn, link.nesn = (nesn, sn ^ 1)


async def _retransmissions(tester, *, central=False, mode='crc', latency=False):
    """Verify the prescribed CRC, negative-ACK, repeated-ACK or lost-NAK sequence."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
        timeout=(
            LL_SUPERVISION_TIMEOUT_MAX
            if latency
            else ARQ_CENTRAL_TIMEOUT if central else 100
        ),
        latency=1 if latency else 0,
    )
    if central:
        await tester.wait(0)
        tester.send(
            bytes(
                hci.HCI_AclDataPacket(
                    link.handle, hci.HCI_ACL_PB_FIRST_NON_FLUSHABLE, 0, 1, ARQ_PAYLOAD
                )
            )
        )
    peer_sn = link.sn if not central else link.sn ^ 1
    held_sn = _sequence_bits(link.last_received)[0] if not central else None
    expected_nesn = peer_sn
    previous = None
    rounds = ARQ_ROUNDS + int(
        (mode == 'duplicate' and not central) or (mode == 'lost' and central)
    )
    for index in range(rounds):
        crc_bad = mode == 'crc' or (mode == 'lost' and index == 0)
        duplicate_sn = peer_sn
        if mode == 'lost' and index:
            duplicate_sn ^= 1

        def build(packet, sn=duplicate_sn):
            nonlocal held_sn
            if packet is not None and (held_sn is None or mode == 'duplicate'):
                held_sn = _sequence_bits(packet)[0]
            nesn = held_sn ^ 1 if mode in ('crc', 'duplicate') else held_sn
            payload = ARQ_PAYLOAD if mode in ('duplicate', 'lost') else b''
            return _data_pdu(
                sn, nesn, payload, llid=LlId.START if payload else LlId.CONTINUATION
            )

        packet, sent = await _wire_event(
            link, build, bad_crc=crc_bad, silent=latency and index % 2 == 1
        )
        sn, nesn = _sequence_bits(packet)
        if central:
            assert packet.pdu[0] & PDU_DATA_LLID_MASK == (
                LlId.START if packet.pdu[1] else LlId.CONTINUATION
            )
        if not central:
            assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
            assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
            if previous is None:
                assert sn == held_sn ^ (mode == 'duplicate')
        if previous is not None:
            expected_sn = _sequence_bits(previous)[0] ^ (mode == 'duplicate')
            assert sn == expected_sn
            if central:
                assert nesn == expected_nesn
        if central and (mode in ('crc', 'nak', 'lost') or index == 0):
            assert packet.pdu[PDU_HEADER_SIZE:] == ARQ_PAYLOAD
        if mode in ('crc', 'nak', 'lost') and previous is not None:
            assert packet.pdu[PDU_HEADER_SIZE:] == previous.pdu[PDU_HEADER_SIZE:]
        if sent is not None and (not crc_bad):
            expected_nesn = peer_sn ^ 1 if mode != 'lost' else peer_sn
            if mode == 'nak':
                peer_sn ^= 1
        if not central:
            assert nesn == expected_nesn
        if mode == 'duplicate':
            held_sn = sn
        previous = packet
    acl = [event for event in tester.events if isinstance(event, hci.HCI_AclDataPacket)]
    if mode == 'duplicate':
        assert len(acl) == 1 and acl[0].connection_handle == link.handle
        assert (
            acl[0].data == ARQ_PAYLOAD
            and acl[0].pb_flag == hci.HCI_ACL_PB_FIRST_FLUSHABLE
        )
    else:
        assert not acl
    if central and mode != 'duplicate':
        assert not any(
            isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
            for event in tester.events
        )

    def recover(packet):
        sn, nesn = _sequence_bits(packet or previous)
        return _data_pdu(nesn, sn ^ 1)

    packet, sent = await _wire_event(link, recover)
    if central:
        sn, nesn = _sequence_bits(packet)
        assert packet.pdu[0] & PDU_DATA_LLID_MASK == (
            LlId.START if packet.pdu[1] else LlId.CONTINUATION
        )
        assert sn == _sequence_bits(previous)[0] ^ (mode == 'duplicate')
        assert nesn == expected_nesn
        if mode != 'duplicate':
            assert packet.pdu[PDU_HEADER_SIZE:] == ARQ_PAYLOAD
    _restore_peer(link, packet, sent)
    await link.exchange()
    if central:
        completed = [
            event
            for event in tester.events
            if isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
        ]
        assert sum(sum(event.num_completed_packets) for event in completed) == 1
        assert all(event.connection_handles == [link.handle] for event in completed)
    await link.disconnect(local=central or mode not in ('nak', 'duplicate'))


def _sequence_bits(packet):
    return (
        int(bool(packet.pdu[0] & PDU_DATA_SN_MASK)),
        int(bool(packet.pdu[0] & PDU_DATA_NESN_MASK)),
    )


async def _central_parameters(tester, *, reject=False, collision=False, legacy=False):
    """Accept four rounds or exercise rejection, collision or legacy fallback."""
    link = await establish(
        tester, central=True, peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS
    )
    await link.control(
        Opcode.LL_FEATURE_RSP,
        bytes([Opcode.LL_PERIPHERAL_FEATURE_REQ])
        + int(hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE).to_bytes(
            PDU_CONTROL_FEATURE_SET_SIZE, 'little'
        ),
    )
    rounds = (
        ((LL_CONN_INTERVAL_MIN, 300),)
        if reject or collision or legacy
        else (
            (LL_CONN_INTERVAL_MIN, 300),
            (LL_CONN_INTERVAL_MAX, LL_SUPERVISION_TIMEOUT_MAX),
            (LL_CONN_INTERVAL_MIN, 300),
            (2400, LL_SUPERVISION_TIMEOUT_MAX),
        )
    )
    for index, (interval, timeout) in enumerate(rounds):
        latency = 0
        if index == 3:
            # Case 4: 3 s, or 2 s if already using 3 s; retain current latency.
            interval = 1600 if link.parameters.interval == 2400 else 2400
            latency = link.parameters.latency
        await tester.command(
            hci.HCI_LE_Connection_Update_Command(
                link.handle, interval, interval, latency, timeout, 0, 0
            )
        )
        request = await link.control(Opcode.LL_CONNECTION_PARAM_REQ)
        fields = _check_parameter_pdu(request)
        if collision:
            peer_request = _parameter_request(link, interval, timeout)
            rejection = await link.control(Opcode.LL_REJECT_EXT_IND, peer_request)
            assert rejection == bytes(
                [
                    Opcode.LL_REJECT_EXT_IND,
                    Opcode.LL_CONNECTION_PARAM_REQ,
                    PROCEDURE_COLLISION,
                ]
            )
        if reject or legacy:
            reason = (
                ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
                if legacy
                else ErrorCode.UNACCEPTABLE_CONNECTION_PARAMETERS_ERROR
            )
            response = bytes(
                [Opcode.LL_REJECT_EXT_IND, Opcode.LL_CONNECTION_PARAM_REQ, reason]
            )
        else:
            minimum, maximum, latency, timeout, periodicity, reference, *offsets = (
                fields
            )
            if index == 3:
                # Change the reference without retaining offsets tied to the old one.
                reference = (link.counter - 1) & LL_EVENT_COUNTER_MASK
                if reference == fields[5]:
                    reference = (reference - 1) & LL_EVENT_COUNTER_MASK
                offsets = [
                    PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED
                ] * PDU_CONTROL_CONN_PARAM_OFFSET_COUNT
            response = bytes([Opcode.LL_CONNECTION_PARAM_RSP]) + struct.pack(
                '<HHHHBH6H',
                minimum,
                maximum,
                latency,
                timeout,
                periodicity,
                reference,
                *offsets,
            )
        update = await link.control(
            Opcode.LL_CONNECTION_UPDATE_IND,
            response,
            check_ack=True,
            required=not reject,
        )
        if reject and update is None:
            event = await tester.event(hci.HCI_LE_Connection_Update_Complete_Event)
            assert (event.status, event.connection_handle) == (reason, link.handle)
            for _ in range(3):
                packet = await link.exchange()
                assert not (
                    packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
                    and packet.pdu[PDU_HEADER_SIZE] == Opcode.LL_CONNECTION_UPDATE_IND
                ), 'update followed the rejected-procedure completion'
            assert not any(
                isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
                for event in tester.events
            )
        else:
            assert not any(
                isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
                for event in tester.events
            ), 'procedure completion before the update Instant'
            interval, timeout = _check_parameter_choice(
                update, None if reject or legacy else fields
            )
            await _check_parameter_update(tester, link, update, interval, timeout)
    await link.disconnect()


async def _parameter_control(link, expected, *, without_features=False):
    """Reject a forbidden procedure immediately rather than ignoring it until
    timeout."""
    for _ in range(16):
        packet = await link.exchange()
        if packet.pdu[0] & PDU_DATA_LLID_MASK != LlId.CONTROL:
            continue
        payload = packet.pdu[PDU_HEADER_SIZE:]
        if payload[0] == expected:
            return payload
        if without_features and payload[0] in (
            Opcode.LL_FEATURE_REQ,
            Opcode.LL_PERIPHERAL_FEATURE_REQ,
        ):
            if link.central:
                pytest.skip(
                    'Inconclusive: autonomous Central feature exchange before PARAM_REQ'
                )
            await link.exchange(
                bytes([Opcode.LL_UNKNOWN_RSP, payload[0]]), llid=LlId.CONTROL
            )
        else:
            pytest.fail(
                f'expected {expected.name}, received control opcode0x{payload[0]:02x}'
            )
    pytest.fail(f'no {expected.name} within sixteen connection events')


async def _parameter_encryption_collision(tester, *, central):
    """Complete encryption and parameter negotiation in the prescribed collision
    order."""
    link = _EncryptedPeer(
        await establish(
            tester,
            central=central,
            peer_address=(
                LOWER_PERIPHERAL_PUBLIC_ADDRESS
                if central
                else LOWER_CENTRAL_PUBLIC_ADDRESS
            ),
        )
    )
    interval, timeout = (LL_CONN_INTERVAL_MIN, 300)
    if central:
        await _start_encryption(
            tester, link, parameter_request=_parameter_request(link, interval, timeout)
        )
        await _accept_remote_parameters(tester, link, interval, timeout)
    else:
        await tester.command(
            hci.HCI_LE_Connection_Update_Command(
                link.handle, interval, interval, 0, timeout, 0, 0
            )
        )
        request = await link.control(Opcode.LL_CONNECTION_PARAM_REQ)
        interval, _, latency, timeout, *_ = _check_parameter_pdu(request)
        requested_at = tester.radio.now_us
        await _start_encryption(tester, link)
        assert tester.radio.now_us - requested_at < LL_RESPONSE_TIMEOUT_US
        update = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + struct.pack(
            '<BHHHHH',
            LL_CONN_WINDOW_SIZE_MIN,
            0,
            interval,
            latency,
            timeout,
            link.counter + LL_INSTANT_MIN_LISTENING_EVENTS & LL_EVENT_COUNTER_MASK,
        )
        await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
        await _check_parameter_update(tester, link, update, interval, timeout)
    await link.exchange()
    await link.disconnect()


async def _preferred_parameters(tester, *, central, anchors_only=False, anchors=False):
    """Accept preferred anchor points and preferred interval periodicity on the air."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    rounds = (
        ((1,), (link.parameters.interval - 1,), (1, 2))
        if anchors_only
        else ((1,) if anchors else (0,) if central else (),)
    )
    for offsets in rounds:
        minimum = maximum = link.parameters.interval
        latency, timeout = (link.parameters.latency, link.parameters.timeout)
        periodicity = 0
        if not anchors_only:
            minimum, maximum, latency, timeout, periodicity = (13, 19, 0, 300, 18)
        reference = link.counter
        reference_anchor = link.anchor
        request = bytes([Opcode.LL_CONNECTION_PARAM_REQ]) + struct.pack(
            '<HHHHBH6H',
            minimum,
            maximum,
            latency,
            timeout,
            periodicity,
            reference,
            *offsets,
            *[PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED]
            * (PDU_CONTROL_CONN_PARAM_OFFSET_COUNT - len(offsets)),
        )
        reply = None
        if anchors_only:
            reply = await link.control(
                (
                    Opcode.LL_CONNECTION_UPDATE_IND
                    if central
                    else Opcode.LL_CONNECTION_PARAM_RSP
                ),
                request,
            )
            assert not any(
                isinstance(event, hci.HCI_LE_Remote_Connection_Parameter_Request_Event)
                for event in tester.events
            )
        else:
            await link.exchange(request, llid=LlId.CONTROL)
            event = await tester.event(
                hci.HCI_LE_Remote_Connection_Parameter_Request_Event
            )
            assert (
                event.connection_handle,
                event.interval_min,
                event.interval_max,
                event.max_latency,
                event.timeout,
            ) == (link.handle, minimum, maximum, latency, timeout)
            result = await tester.command(
                hci.HCI_LE_Remote_Connection_Parameter_Request_Reply_Command(
                    link.handle, minimum, maximum, latency, timeout, 0, 0
                )
            )
            assert result.connection_handle == link.handle
        if central:
            update = (
                reply
                if reply is not None
                else await link.control(Opcode.LL_CONNECTION_UPDATE_IND)
            )
            interval, timeout = _check_parameter_choice(
                update, (minimum, maximum, latency, timeout)
            )
        else:
            response = (
                reply
                if reply is not None
                else await link.control(Opcode.LL_CONNECTION_PARAM_RSP)
            )
            fields = _check_parameter_pdu(response)
            if anchors_only:
                interval = link.parameters.interval
                assert fields[0] <= interval <= fields[1]
                assert fields[2:4] == (latency, timeout)
            else:
                interval = _select_peer_interval(fields[0], fields[1], fields[4])
                latency, timeout = fields[2:4]
            instant = (
                link.counter + LL_INSTANT_MIN_LISTENING_EVENTS & LL_EVENT_COUNTER_MASK
            )
            offset = (
                (
                    offsets[0]
                    - (instant - reference & LL_EVENT_COUNTER_MASK)
                    * link.parameters.interval
                )
                % interval
                if offsets
                else 0
            )
            update = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + struct.pack(
                '<BHHHHH',
                LL_CONN_WINDOW_SIZE_MIN,
                offset,
                interval,
                latency,
                timeout,
                instant,
            )
            await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
        await _check_parameter_update(
            tester, link, update, interval, timeout, notify=not anchors_only
        )
        if central:
            phase = (link.last_received.start_us - reference_anchor) % (
                interval * LL_CONN_INTERVAL_UNIT_US
            )
            if anchors_only:
                assert phase == offsets[0] * LL_CONN_INTERVAL_UNIT_US
            tester.output.write(
                f'PARAMETERS interval={interval} preferred_periodicity={periodicity} '
                f'anchor_phase_us={phase}\n'
            )
    await link.disconnect()


async def _remote_features(tester, *, central, unsupported=False):
    """Verify the Host command, role-specific on-air request and exact completion
    features."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    declared = int.from_bytes(
        (
            await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
        ).le_features,
        'little',
    )
    await tester.command(hci.HCI_LE_Read_Remote_Features_Command(link.handle))
    opcode = Opcode.LL_FEATURE_REQ if central else Opcode.LL_PERIPHERAL_FEATURE_REQ
    initial = link.last_received.pdu[PDU_HEADER_SIZE:]
    request = (
        initial
        if link.last_received.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
        and initial[:1] == bytes([opcode])
        else await link.control(opcode)
    )
    _check_feature_pdu(declared, request, opcode=opcode)
    features = int(
        hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE
        | hci.LeFeatureMask.LE_2M_PHY
    )
    response = (
        bytes([Opcode.LL_UNKNOWN_RSP, opcode])
        if unsupported
        else bytes([Opcode.LL_FEATURE_RSP])
        + features.to_bytes(PDU_CONTROL_FEATURE_SET_SIZE, 'little')
    )
    sent_sn = link.sn
    packet = await link.exchange(response, llid=LlId.CONTROL, check_ack=True)
    if central:
        sent_sn = link.sn
        packet = await link.exchange()
    assert bool(packet.pdu[0] & PDU_DATA_NESN_MASK) != bool(sent_sn)
    event = await tester.event(hci.HCI_LE_Read_Remote_Features_Complete_Event)
    assert event.connection_handle == link.handle
    assert event.status == (
        ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR if unsupported else ErrorCode.SUCCESS
    )
    if not unsupported:
        assert event.le_features == response[1:]
    await link.disconnect()


async def _unsupported_parameters(tester, *, central, features):
    """Learn an unsupported peer procedure without retrying it on the same ACL."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    initial = (
        link.last_received.pdu[PDU_HEADER_SIZE:]
        if link.last_received.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
        else b''
    )
    if (
        not features
        and initial
        and initial[0] in (Opcode.LL_FEATURE_REQ, Opcode.LL_PERIPHERAL_FEATURE_REQ)
    ):
        if central:
            pytest.skip(
                'Inconclusive: autonomous Central feature exchange during setup'
            )
        await link.exchange(
            bytes([Opcode.LL_UNKNOWN_RSP, initial[0]]), llid=LlId.CONTROL
        )
    if features:
        peer_features = bytes(PDU_CONTROL_FEATURE_SET_SIZE)
        if central:
            autonomous = initial[:1] == bytes([Opcode.LL_FEATURE_REQ])
            if autonomous:
                request = initial
            else:
                await tester.command(
                    hci.HCI_LE_Read_Remote_Features_Command(link.handle)
                )
                request = await _parameter_control(link, Opcode.LL_FEATURE_REQ)
            assert len(request) == 1 + PDU_CONTROL_FEATURE_SET_SIZE
            await link.exchange(
                bytes([Opcode.LL_FEATURE_RSP]) + peer_features, llid=LlId.CONTROL
            )
            if autonomous:
                await link.exchange()
            else:
                event = await tester.event(
                    hci.HCI_LE_Read_Remote_Features_Complete_Event
                )
                assert (event.status, event.connection_handle, event.le_features) == (
                    ErrorCode.SUCCESS,
                    link.handle,
                    peer_features,
                )
        else:
            if initial[:1] == bytes([Opcode.LL_PERIPHERAL_FEATURE_REQ]):
                assert len(initial) == 1 + PDU_CONTROL_FEATURE_SET_SIZE
                await link.exchange(
                    bytes([Opcode.LL_FEATURE_RSP]) + peer_features, llid=LlId.CONTROL
                )
            else:
                response = await link.control(
                    Opcode.LL_FEATURE_RSP,
                    bytes([Opcode.LL_FEATURE_REQ]) + peer_features,
                )
                assert len(response) == 1 + PDU_CONTROL_FEATURE_SET_SIZE
            await link.exchange()
    commands = (
        ((LL_CONN_INTERVAL_MIN, 300), (12, 400))
        if central and (not features)
        else ((LL_CONN_INTERVAL_MIN, 300),)
    )
    for index, (interval, timeout) in enumerate(commands):
        command = hci.HCI_LE_Connection_Update_Command(
            link.handle, interval, interval, 0, timeout, 0, 0
        )
        if not central and features:
            status = await tester.command(
                command,
                status=(ErrorCode.SUCCESS, ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR),
            )
        else:
            status = await tester.command(command)
        if not features and index == 0:
            request = await _parameter_control(
                link, Opcode.LL_CONNECTION_PARAM_REQ, without_features=True
            )
            _check_parameter_pdu(request)
            await link.exchange(
                bytes([Opcode.LL_UNKNOWN_RSP, Opcode.LL_CONNECTION_PARAM_REQ]),
                llid=LlId.CONTROL,
            )
            if not central:
                failure = await tester.event(
                    hci.HCI_LE_Connection_Update_Complete_Event
                )
                assert (failure.status, failure.connection_handle) == (
                    ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR,
                    link.handle,
                )
                status = await tester.command(
                    command,
                    status=(
                        ErrorCode.SUCCESS,
                        ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR,
                    ),
                )
        if central:
            update = await _parameter_control(link, Opcode.LL_CONNECTION_UPDATE_IND)
            interval, timeout = _check_parameter_choice(update)
            await _check_parameter_update(tester, link, update, interval, timeout)
        else:
            if status.status == ErrorCode.SUCCESS:
                failure = await tester.event(
                    hci.HCI_LE_Connection_Update_Complete_Event
                )
                assert (failure.status, failure.connection_handle) == (
                    ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR,
                    link.handle,
                )
            for _ in range(16):
                packet = await link.exchange()
                assert not (
                    packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
                    and packet.pdu[PDU_HEADER_SIZE] == Opcode.LL_CONNECTION_PARAM_REQ
                ), 'known unsupported PARAM_REQ was sent again'
        assert not any(
            isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
            for event in tester.events
        ), 'unexpected or duplicate parameter completion'
    await link.disconnect()


# Extended accepting-connection procedures allow at most twenty AUX requests.
AUXILIARY_SETUP_ATTEMPTS = 20
# LL.TS.p28 CSA connection procedures measure100 maintained events.
CSA_TIMING_EVENTS = 100
# Core Vol6 PartB4.4.2.4.2: maximum high-duty directed advertising event interval.
HIGH_DUTY_INTERVAL_MAX_US = 3750
OTHER_PUBLIC = hci.Address('12:34:56:78:9A:BD', hci.AddressType.PUBLIC_DEVICE)


async def _advertising_csa(tester, *, directed=False, csa2=False, extended=False):
    """Select CSA from the connection request, independently of the HCI command path."""
    peer = LOWER_CENTRAL_PUBLIC_ADDRESS
    if extended:
        properties = (
            Properties.USE_LEGACY_ADVERTISING_PDUS | Properties.CONNECTABLE_ADVERTISING
        )
        properties |= (
            Properties.DIRECTED_ADVERTISING
            | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
            if directed
            else Properties.SCANNABLE_ADVERTISING
        )
        await tester.command(
            extended_parameters(
                advertising_event_properties=properties,
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
                peer_address_type=peer.address_type,
                peer_address=peer,
            )
        )
        duration = (
            LL_ADV_DIRECT_HIGH_DUTY_TIMEOUT_US // hci.HCI_LE_DURATION_UNIT_US
            if directed
            else 0
        )
        await tester.command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(1, [0], [duration], [0])
        )
    else:
        await tester.command(
            legacy_parameters(
                advertising_type=(
                    AdvType.ADV_DIRECT_IND if directed else AdvType.ADV_IND
                ),
                advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
                peer_address_type=peer.address_type,
                peer_address=peer,
            )
        )
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    kind = AdvertisingPduType.ADV_DIRECT_IND if directed else AdvertisingPduType.ADV_IND
    starts = {}
    for _ in range(2):
        for channel in LL_ADV_PRIMARY_CHANNELS:
            advertisement = await tester.expect_pdu(channel, kind=kind)
            assert advertisement.phy == Phy.LE_1M
            assert advertisement.pdu[0] & PDU_ADV_CHSEL_MASK
            assert not advertisement.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
            assert advertisement.pdu[PDU_HEADER_SIZE:] == bytes(DUT_ADDRESS) + (
                bytes(peer) if directed else b''
            )
            if channel in starts:
                elapsed = advertisement.start_us - starts[channel]
                if directed:
                    assert 0 < elapsed <= HIGH_DUTY_INTERVAL_MAX_US
                else:
                    minimum = (
                        hci.HCI_LE_ADV_INTERVAL_MIN * hci.HCI_LE_ADV_INTERVAL_UNIT_US
                    )
                    assert minimum <= elapsed <= minimum + LL_ADV_DELAY_MAX_US
            starts[channel] = advertisement.start_us
    parameters = _advertiser_connection_parameters()
    request = request_pdu(
        AdvertisingPduType.CONNECT_IND, scanner=peer, data=parameters.encode()
    )
    if csa2:
        request = bytes([request[0] | PDU_ADV_CHSEL_MASK]) + request[1:]
    end = await tester.transmit(
        channel, request, start_us=advertisement.end_us + LL_IFS_US
    )
    link = PeerLink(tester, parameters, end, csa2=csa2)
    await _data_events(tester, link, 1, observe_advertising=True)
    await _connection_complete(tester, link, peer, extended=extended)
    await _data_events(tester, link, CSA_TIMING_EVENTS, observe_advertising=True)
    _no_connection_events(tester)
    await link.disconnect()
    _no_connection_events(tester)


def _completion_events(tester, link, *, extended=False):
    """Check event eligibility from the command path, not feature support alone."""
    assert 0 <= link.handle <= CONNECTION_HANDLE_MAX
    selections = []
    terminations = []
    while event := tester.take(
        lambda value: isinstance(
            value,
            (
                hci.HCI_LE_Channel_Selection_Algorithm_Event,
                hci.HCI_LE_Advertising_Set_Terminated_Event,
            ),
        )
    ):
        if isinstance(event, hci.HCI_LE_Channel_Selection_Algorithm_Event):
            selections.append(event)
        else:
            terminations.append(event)
    if not link.central and (not extended):
        assert not selections and (
            not terminations
        ), 'legacy Peripheral emitted an ineligible event'
    else:
        assert len(selections) <= 1
        if link.central:
            assert len(selections) == 1
        for event in selections:
            assert event.connection_handle == link.handle
            assert event.channel_selection_algorithm == int(link.csa2)
        assert len(terminations) == int(extended and (not link.central))
        for event in terminations:
            assert event.status == ErrorCode.SUCCESS
            assert event.advertising_handle == 0
            assert event.connection_handle == link.handle


async def _data_events(
    tester, link, count, *, observe_advertising=False, advertising_phy=Phy.LE_1M
):
    """Measure every response/anchor; do not infer timing from DUT state."""
    starts = []
    for index in range(count):
        if observe_advertising:
            duration = link.anchor - tester.radio.now_us - 50
            if duration > 0:
                channel = LL_ADV_PRIMARY_CHANNELS[index % len(LL_ADV_PRIMARY_CHANNELS)]
                assert (
                    await tester.receive(
                        channel, duration_us=duration, phy=advertising_phy
                    )
                    is None
                ), 'advertising continued after connection creation'
        previous_sn = link.sn
        packet = await link.exchange(check_ack=True)
        assert packet.phy == link.rx_phy
        assert packet.pdu[0] & PDU_DATA_LLID_MASK in (
            LlId.CONTINUATION,
            LlId.START,
            LlId.CONTROL,
        )
        if link.central and starts:
            assert bool(packet.pdu[0] & PDU_DATA_NESN_MASK) != bool(previous_sn)
        starts.append(packet.start_us)
    interval = link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    sca_ppm = LL_SCA_PPM[link.parameters.hop_sca >> PDU_ADV_CONNECT_SCA_SHIFT]
    tolerance = 20 if sca_ppm == 500 else 10
    assert all(
        (abs(right - left - interval) <= tolerance for left, right in pairwise(starts))
    )
    assert (
        abs(starts[-1] - starts[0] - (count - 1) * interval)
        <= (count - 1) * interval * sca_ppm / PHY_TIME_UNITS_PER_SECOND
    )


def _central_first_window(
    parameters, anchor, *, window_delay_us=LL_CONN_INTERVAL_UNIT_US
):
    """Inclusive integer-us bounds from LL.TS.p28 Section 4.3.4's formula."""
    delay = window_delay_us + parameters.window_offset * LL_CONN_INTERVAL_UNIT_US
    size = parameters.window_size * LL_CONN_INTERVAL_UNIT_US
    ppm = (
        LL_SCA_PPM[parameters.hop_sca >> PDU_ADV_CONNECT_SCA_SHIFT]
        + RADIO_LOCAL_SCA_PPM
    )
    return (
        anchor - delay * ppm // PHY_TIME_UNITS_PER_SECOND - RADIO_CLOCK_JITTER_US,
        anchor
        + size
        + (delay + size) * ppm // PHY_TIME_UNITS_PER_SECOND
        + RADIO_CLOCK_JITTER_US,
    )


def _check_central_timing(
    parameters, anchor, starts, *, window_delay_us=LL_CONN_INTERVAL_UNIT_US
):
    """Check the first window and Table 4.3-12's individual/cumulative drift."""
    earliest, latest = _central_first_window(
        parameters, anchor, window_delay_us=window_delay_us
    )
    assert earliest <= starts[0] <= latest, 'first DATA outside transmit window'
    interval = parameters.interval * LL_CONN_INTERVAL_UNIT_US
    ppm = LL_SCA_PPM[parameters.hop_sca >> PDU_ADV_CONNECT_SCA_SHIFT]
    tolerance = 20 if ppm == 500 else 10
    assert all(
        abs(right - left - interval) <= tolerance for left, right in pairwise(starts)
    ), 'Central event interval outside the source tolerance'
    elapsed = (len(starts) - 1) * interval
    assert (
        abs(starts[-1] - starts[0] - elapsed) * PHY_TIME_UNITS_PER_SECOND
        <= elapsed * ppm
    ), 'Central cumulative clock drift exceeds its SCA'


async def _receive_central_event(link, *, window_delay_us=LL_CONN_INTERVAL_UNIT_US):
    """Receive a Central event within its allowed start window."""
    tester = link.tester
    ppm = LL_SCA_PPM[link.parameters.hop_sca >> PDU_ADV_CONNECT_SCA_SHIFT]
    tolerance = 20 if ppm == 500 else 10
    earliest, latest = (
        (link.anchor - tolerance, link.anchor + tolerance)
        if link.counter
        else _central_first_window(
            link.parameters, link.anchor, window_delay_us=window_delay_us
        )
    )
    # RX timeout ends address search, not the permitted packet-start window.
    packet = await tester.expect_pdu(
        link.channel,
        start_us=max(tester.radio.now_us + 1, earliest),
        duration_us=latest + link.rx_phy.address_us - tester.radio.now_us + 1,
        **(link.radio_parameters | {'phy': link.rx_phy}),
    )
    assert earliest <= packet.start_us <= latest
    assert packet.phy == link.rx_phy
    assert packet.pdu[0] & PDU_DATA_LLID_MASK in (
        LlId.CONTINUATION,
        LlId.START,
        LlId.CONTROL,
    )
    link.last_received = packet
    link.counter = (link.counter + 1) & LL_EVENT_COUNTER_MASK
    link.anchor = packet.start_us + link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    return packet


async def _central_timing_events(
    tester,
    link,
    count,
    *,
    silent_until_us=0,
    window_delay_us=LL_CONN_INTERVAL_UNIT_US,
):
    """Measure Central timing, optionally withholding initial Peripheral replies."""
    assert link.central and link.counter == 0 and count > 0
    first_anchor = link.anchor
    starts = []
    replies = 0
    while replies < count:
        channel = link.channel
        packet = await _receive_central_event(link, window_delay_us=window_delay_us)
        if replies:
            assert bool(packet.pdu[0] & PDU_DATA_NESN_MASK) != bool(link.sn)
        elif silent_until_us:
            _empty_data(packet, (0, 0))
        if packet.start_us >= silent_until_us:
            link._accept(packet)
            await link._send(channel, b'', LlId.CONTINUATION, packet.end_us + LL_IFS_US)
            replies += 1
        starts.append(packet.start_us)
    _check_central_timing(
        link.parameters, first_anchor, starts, window_delay_us=window_delay_us
    )


async def _extended_advertisement(tester, primary_phy, phy, directed, starts):
    """Observe full primary cycles and follow the last primary's AuxPtr."""
    for _ in range(1 if starts else 2):
        primaries = []
        for primary_channel in LL_ADV_PRIMARY_CHANNELS:
            primary = await tester.expect_pdu(
                primary_channel, kind=AdvertisingPduType.ADV_EXT_IND, phy=primary_phy
            )
            primary_fields = decode_extended(primary.pdu)
            assert set(primary_fields) == {'adi', 'aux', 'data'}
            assert not primary_fields['data']
            assert (
                primary.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
                == AdvertisingMode.CONNECTABLE
            )
            if primary_channel in starts:
                elapsed = primary.start_us - starts[primary_channel]
                assert (
                    ADV_INTERVAL_US <= elapsed <= ADV_INTERVAL_US + LL_ADV_DELAY_MAX_US
                )
            starts[primary_channel] = primary.start_us
            primaries.append((primary, primary_fields))
        channel, adv, fields = await follow_auxiliary(
            tester, primary, primary_fields, phy=phy
        )
        for parent, header in primaries:
            pointer = int.from_bytes(header['aux'], 'little')
            pointed_channel, offset = decode_aux(header['aux'])
            unit = (
                PDU_ADV_OFFSET_UNIT_300_US
                if pointer & PDU_ADV_AUX_OFFSET_UNITS_MASK
                else PDU_ADV_OFFSET_UNIT_30_US
            )
            assert pointed_channel == channel
            assert pointer >> (PHY_OCTET_BITS + PDU_ADV_OFFSET_BITS) == phy - 1
            assert (
                parent.start_us + offset
                <= adv.start_us
                < parent.start_us + offset + unit
            )
            assert adv.start_us - parent.end_us >= LL_MAFS_US
            assert header['adi'] == fields['adi']
        assert adv.phy == phy
        assert adv.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
        assert (
            adv.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
            == AdvertisingMode.CONNECTABLE
        )
        assert not adv.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
        assert fields['address'] == bytes(DUT_ADDRESS)
        assert fields['adi'] == primary_fields['adi']
        assert set(fields) == {'address', 'adi', 'data'} | (
            {'target'} if directed else set()
        )
        assert not fields['data']
        if directed:
            assert fields['target'] == bytes(LOWER_CENTRAL_PUBLIC_ADDRESS)
    return channel, adv


def _no_connection_events(tester):
    assert not any(
        isinstance(
            event,
            (
                hci.HCI_LE_Connection_Complete_Event,
                hci.HCI_LE_Enhanced_Connection_Complete_Event,
                hci.HCI_LE_Channel_Selection_Algorithm_Event,
                hci.HCI_LE_Advertising_Set_Terminated_Event,
                hci.HCI_Disconnection_Complete_Event,
            ),
        )
        for event in tester.events
    ), 'unexpected connection, disconnection, or advertising-termination event'


async def _extended_setup(tester, *, phy=Phy.LE_1M):
    """Check all extended connection address rounds and post-connection RF silence."""
    primary_phy = Phy.LE_CODED if phy == Phy.LE_CODED else Phy.LE_1M
    for directed in (False, True):
        for valid in (True, False):
            properties = Properties.CONNECTABLE_ADVERTISING
            if directed:
                properties |= Properties.DIRECTED_ADVERTISING
            await tester.command(
                extended_parameters(
                    advertising_event_properties=properties,
                    primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
                    primary_advertising_phy=primary_phy,
                    secondary_advertising_phy=phy,
                    peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
                    peer_address_type=LOWER_CENTRAL_PUBLIC_ADDRESS.address_type,
                )
            )
            await tester.command(extended_enable())
            starts = {}
            parameters = _advertiser_connection_parameters()
            attempts = AUXILIARY_SETUP_ATTEMPTS if valid else 1
            for _ in range(attempts):
                channel, adv = await _extended_advertisement(
                    tester, primary_phy, phy, directed, starts
                )
                request = request_pdu(
                    AdvertisingPduType.CONNECT_IND,
                    advertiser=DUT_ADDRESS if valid else OTHER_PUBLIC,
                    scanner=LOWER_CENTRAL_PUBLIC_ADDRESS,
                    data=parameters.encode(),
                )
                await tester.transmit(
                    channel, request, start_us=adv.end_us + LL_IFS_US, phy=phy
                )
                end = tester.radio.now_us + 1
                response = await tester.receive(channel, duration_us=1000, phy=phy)
                if not valid:
                    assert response is None
                    _no_connection_events(tester)
                    continue
                if response is None:
                    continue
                assert (
                    abs(response.start_us - end - LL_IFS_US) <= CONNECT_IFS_TOLERANCE_US
                )
                assert response.valid_crc and response.phy == phy
                assert len(response.pdu) >= PDU_HEADER_SIZE
                assert response.pdu[1] == len(response.pdu) - PDU_HEADER_SIZE
                assert not response.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
                assert (
                    response.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
                    == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
                )
                assert (
                    response.pdu[0] & PDU_ADV_TYPE_MASK
                    == AdvertisingPduType.AUX_CONNECT_RSP
                )
                fields = decode_extended(response.pdu)
                assert fields == {
                    'address': bytes(DUT_ADDRESS),
                    'target': bytes(LOWER_CENTRAL_PUBLIC_ADDRESS),
                    'data': b'',
                }
                link = PeerLink(
                    tester,
                    parameters,
                    end,
                    csa2=True,
                    phy=phy,
                )
                link.anchor = (
                    end
                    + (
                        LL_CONN_AUX_WINDOW_DELAY_CODED_US
                        if phy == Phy.LE_CODED
                        else LL_CONN_AUX_WINDOW_DELAY_UNCODED_US
                    )
                    + parameters.window_offset * LL_CONN_INTERVAL_UNIT_US
                )
                await _connection_complete(
                    tester, link, LOWER_CENTRAL_PUBLIC_ADDRESS, extended=True
                )
                await _data_events(
                    tester,
                    link,
                    100,
                    observe_advertising=True,
                    advertising_phy=primary_phy,
                )
                _no_connection_events(tester)
                await link.disconnect()
                _no_connection_events(tester)
                break
            else:
                assert not valid, 'AUX_CONNECT_RSP absent after twenty requests'
            await tester.command(extended_enable(0))
            if not valid:
                _no_connection_events(tester)


async def _legacy_setup(tester, *, directed=False):
    """Reject a wrong high-duty initiator, then maintain the selected legacy link."""
    if directed:
        await tester.command(
            legacy_parameters(
                advertising_type=AdvType.ADV_DIRECT_IND,
                advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
                peer_address_type=LOWER_CENTRAL_PUBLIC_ADDRESS.address_type,
                peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
            )
        )
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
        adv = await tester.expect_pdu(37, kind=AdvertisingPduType.ADV_DIRECT_IND)
        await tester.transmit(
            37,
            request_pdu(
                AdvertisingPduType.CONNECT_IND,
                scanner=OTHER_PUBLIC,
                data=_advertiser_connection_parameters().encode(),
            ),
            start_us=adv.end_us + LL_IFS_US,
        )
        await tester.expect_pdu(37, kind=AdvertisingPduType.ADV_DIRECT_IND)
        await tester.wait(LL_ADV_DIRECT_HIGH_DUTY_TIMEOUT_US)
        event = await tester.event(hci.HCI_LE_Connection_Complete_Event)
        assert event.status == ErrorCode.ADVERTISING_TIMEOUT_ERROR
    filtered = not directed
    if filtered:
        await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
        await tester.command(
            hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(
                LOWER_CENTRAL_PUBLIC_ADDRESS.address_type, LOWER_CENTRAL_PUBLIC_ADDRESS
            )
        )
    for channel in LL_ADV_PRIMARY_CHANNELS if not directed else (37,):
        await tester.command(
            legacy_parameters(
                advertising_type=(
                    AdvType.ADV_DIRECT_IND if directed else AdvType.ADV_IND
                ),
                advertising_channel_map=(
                    LL_ADV_PRIMARY_CHANNEL_MAP_ALL
                    if directed
                    else 1 << (channel - LL_ADV_PRIMARY_CHANNELS[0])
                ),
                peer_address_type=LOWER_CENTRAL_PUBLIC_ADDRESS.address_type,
                peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
                advertising_filter_policy=(
                    ADV_FILTER_ACCEPT_LIST_ONLY if filtered else 0
                ),
            )
        )
        await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
        kind = (
            AdvertisingPduType.ADV_DIRECT_IND
            if directed
            else AdvertisingPduType.ADV_IND
        )
        advertisement = await tester.expect_pdu(channel, kind=kind)
        if not directed:
            following = await tester.expect_pdu(channel, kind=kind)
            interval = following.start_us - advertisement.start_us
            assert ADV_INTERVAL_US <= interval <= ADV_INTERVAL_US + LL_ADV_DELAY_MAX_US
            for other in LL_ADV_PRIMARY_CHANNELS:
                if other != channel:
                    assert (
                        await tester.receive(
                            other, duration_us=ADV_INTERVAL_US + LL_ADV_DELAY_MAX_US
                        )
                        is None
                    )
            advertisement = await tester.expect_pdu(channel, kind=kind)
        assert not advertisement.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
        assert advertisement.pdu[PDU_HEADER_SIZE:] == bytes(DUT_ADDRESS) + (
            bytes(LOWER_CENTRAL_PUBLIC_ADDRESS) if directed else b''
        )
        parameters = _advertiser_connection_parameters()
        end = await tester.transmit(
            channel,
            request_pdu(
                AdvertisingPduType.CONNECT_IND,
                scanner=LOWER_CENTRAL_PUBLIC_ADDRESS,
                data=parameters.encode(),
            ),
            start_us=advertisement.end_us + LL_IFS_US,
        )
        link = PeerLink(tester, parameters, end)
        await _connection_complete(tester, link, LOWER_CENTRAL_PUBLIC_ADDRESS)
        await _legacy_timing_events(tester, link, directed=directed)
        _completion_events(tester, link)
        await link.disconnect()
        _completion_events(tester, link)


async def _legacy_timing_events(tester, link, *, directed):
    """Count actual DATA responses rather than assuming one reply per event."""
    required = 900 if directed else 100
    # BV-01 permits 900 transmitted events. BV-04 requires 900 responses.
    maximum = 10 * required if directed else 900
    responses = 0
    for index in range(maximum):
        duration = link.anchor - tester.radio.now_us - CONNECT_IFS_TOLERANCE_US
        if duration > 0:
            channel = LL_ADV_PRIMARY_CHANNELS[index % len(LL_ADV_PRIMARY_CHANNELS)]
            assert await tester.receive(channel, duration_us=duration) is None
        packet = await link.exchange(check_ack=True, required=False)
        if packet is not None:
            _empty_data(packet)
            responses += 1
            if responses == required:
                return
    raise AssertionError(f'only {responses}/{required} legacy DATA responses')


# HCI observation resolution; PHY packet assertions retain microsecond timestamps.
HCI_OBSERVATION_STEP_US = 1000


async def _check_rf_stopped(link):
    """Observe the next Central event or probe the next Peripheral receive window."""
    while link.anchor <= link.tester.radio.now_us:
        link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    packet, _ = await _wire_event(
        link, lambda _packet: _data_pdu(link.sn, link.nesn), required=False
    )
    assert packet is None, 'connection RF continued after disconnection'


async def _past_update_outcome(link, payload, *, allow_maintenance):
    """Accept only the source's disconnect or acknowledged-maintenance alternatives."""
    tester = link.tester
    sent_sn = link.sn
    packet, sent = await _wire_event(
        link,
        lambda _: _data_pdu(link.sn, link.nesn, payload, llid=LlId.CONTROL),
        required=False,
    )
    deadline = (
        link.last_sent_end_us + link.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
    )
    acknowledged = packet is not None and _sequence_bits(packet)[1] != sent_sn
    pending = b'' if acknowledged else payload
    maintained = True
    if packet is not None:
        _restore_peer(link, packet, sent)
    while True:
        event = _disconnected(tester)
        if event is not None:
            assert tester.radio.now_us < deadline, 'late past-Instant disconnection'
            assert (event.status, event.connection_handle, event.reason) == (
                ErrorCode.SUCCESS,
                link.handle,
                ErrorCode.INSTANT_PASSED_ERROR,
            )
            await _check_rf_stopped(link)
            return
        if tester.radio.now_us >= deadline:
            break
        if link.anchor + HCI_OBSERVATION_STEP_US >= deadline:
            await tester.wait(deadline - tester.radio.now_us)
            continue
        sent_sn = link.sn
        packet, sent = await _wire_event(
            link,
            lambda _, data=pending: _data_pdu(
                link.sn,
                link.nesn,
                data,
                llid=LlId.CONTROL if data else LlId.CONTINUATION,
            ),
            required=False,
        )
        maintained &= packet is not None
        if packet is not None:
            if pending and _sequence_bits(packet)[1] != sent_sn:
                acknowledged = True
                pending = b''
            _restore_peer(link, packet, sent)
    assert allow_maintenance, 'past connection update did not disconnect'
    assert acknowledged, 'maintained connection did not acknowledge the channel map'
    assert maintained, 'connection was not maintained after the invalid channel map'
    await link.disconnect(local=True)


def _disconnected(tester):
    return tester.take(
        lambda event: isinstance(event, hci.HCI_Disconnection_Complete_Event)
    )


async def _observe_disconnection(tester, earliest, latest):
    """Reject an early event, then observe the first delivery without skipping its
    deadline."""
    assert tester.radio.now_us < earliest
    while tester.radio.now_us <= latest:
        event = _disconnected(tester)
        if event is not None:
            assert (
                tester.radio.now_us >= earliest
            ), 'disconnection before the allowed expiry window'
            return event
        if tester.radio.now_us == latest:
            break
        target = min(tester.radio.now_us + HCI_OBSERVATION_STEP_US, latest)
        if tester.radio.now_us < earliest - 1:
            target = min(target, earliest - 1)
        await tester.wait(target - tester.radio.now_us)
    raise AssertionError('disconnection absent by the protocol deadline')


async def _procedure_timeout(tester, *, central=True, parameters=False):
    """Acknowledge a request without its response and check transaction expiry."""
    setup_before = tester.radio.now_us
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    if parameters:
        await link.control(
            Opcode.LL_FEATURE_RSP,
            bytes(
                [Opcode.LL_PERIPHERAL_FEATURE_REQ if central else Opcode.LL_FEATURE_REQ]
            )
            + int(hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE).to_bytes(
                PDU_CONTROL_FEATURE_SET_SIZE, 'little'
            ),
        )
    opcode = Opcode.LL_CONNECTION_PARAM_REQ if parameters else Opcode.LL_FEATURE_REQ
    initial = link.last_received
    autonomous = (
        not parameters
        and central
        and initial.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
        and initial.pdu[PDU_HEADER_SIZE : PDU_HEADER_SIZE + 1] == bytes([opcode])
    )
    before = setup_before if autonomous else tester.radio.now_us
    await tester.command(
        hci.HCI_LE_Connection_Update_Command(
            link.handle, LL_CONN_INTERVAL_MIN, LL_CONN_INTERVAL_MIN, 0, 300, 0, 0
        )
        if parameters
        else hci.HCI_LE_Read_Remote_Features_Command(link.handle)
    )
    request = (
        initial.pdu[PDU_HEADER_SIZE:] if autonomous else await link.control(opcode)
    )
    request_at = link.last_received.start_us
    if parameters:
        _check_parameter_pdu(request)
    else:
        assert len(request) == 1 + PDU_CONTROL_FEATURE_SET_SIZE
    if central:
        assert link.last_received.pdu[PDU_HEADER_SIZE:] == request
    else:
        await link.exchange()
    # Queueing occurs after the trigger and no later than the first RF request.
    latest = request_at + LL_RESPONSE_TIMEOUT_US + HCI_OBSERVATION_STEP_US
    earliest = before + LL_RESPONSE_TIMEOUT_US - HCI_OBSERVATION_STEP_US
    completion_type = (
        hci.HCI_LE_Connection_Update_Complete_Event
        if parameters
        else hci.HCI_LE_Read_Remote_Features_Complete_Event
    )
    while link.anchor + HCI_OBSERVATION_STEP_US < earliest:
        assert _disconnected(tester) is None
        assert not any(isinstance(event, completion_type) for event in tester.events)
        packet = await link.exchange()
        if packet.pdu[1]:
            assert packet.pdu[PDU_HEADER_SIZE:] == request
    completed = False
    event = None
    terminal_types = (completion_type, hci.HCI_Disconnection_Complete_Event)
    while tester.radio.now_us <= latest:
        event = tester.take(lambda event: isinstance(event, terminal_types))
        if event is not None:
            assert tester.radio.now_us >= earliest, 'premature control timeout'
            if isinstance(event, hci.HCI_Disconnection_Complete_Event):
                break
            assert not completed, 'duplicate procedure completion'
            assert (event.status, event.connection_handle) == (
                ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR,
                link.handle,
            )
            completed = True
            continue
        if tester.radio.now_us == latest:
            raise AssertionError('control timeout absent by the protocol deadline')
        target = min(tester.radio.now_us + HCI_OBSERVATION_STEP_US, latest)
        if tester.radio.now_us < earliest - 1:
            target = min(target, earliest - 1)
        await tester.wait(target - tester.radio.now_us)
    assert isinstance(event, hci.HCI_Disconnection_Complete_Event)
    assert (event.status, event.connection_handle, event.reason) == (
        ErrorCode.SUCCESS,
        link.handle,
        ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR,
    )
    await _check_rf_stopped(link)
    assert not any(
        isinstance(event, terminal_types) for event in tester.events
    ), 'procedure completion or duplicate disconnection after disconnection'


async def _supervision(tester, *, central=False):
    """Verify maximum and minimum supervision configurations without valid peer DATA."""
    for interval, timeout, resolution in (
        (LL_CONN_INTERVAL_MAX, LL_SUPERVISION_TIMEOUT_MAX, 10000),
        (LL_CONN_INTERVAL_MIN, LL_SUPERVISION_TIMEOUT_MIN, HCI_OBSERVATION_STEP_US),
    ):
        link = await establish(
            tester,
            central=central,
            interval=interval,
            timeout=timeout,
            peer_address=(
                LOWER_PERIPHERAL_PUBLIC_ADDRESS
                if central
                else LOWER_CENTRAL_PUBLIC_ADDRESS
            ),
        )
        # PHY validates the last occupied microsecond; packet end is exclusive.
        deadline = link.last_sent_end_us - 1 + timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
        event = await _observe_disconnection(
            tester,
            deadline if central else deadline - resolution,
            deadline + (HCI_OBSERVATION_STEP_US if central else resolution),
        )
        assert (event.status, event.connection_handle, event.reason) == (
            ErrorCode.SUCCESS,
            link.handle,
            ErrorCode.CONNECTION_TIMEOUT_ERROR,
        )
        if central:
            await tester.wait(max(0, link.anchor - tester.radio.now_us))
            assert (
                await tester.receive(
                    link.channel,
                    duration_us=interval * LL_CONN_INTERVAL_UNIT_US,
                    **link.radio_parameters,
                )
                is None
            )


async def _timeouts_termination(tester, *, central=False):
    """Keep peer DATA valid but withhold the termination ACK until T_Terminate
    expires."""
    parameters = _advertiser_connection_parameters() if central else LinkParameters()
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
        interval=parameters.interval,
        timeout=parameters.timeout,
    )
    reason = ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR
    before = tester.radio.now_us
    await tester.command(hci.HCI_Disconnect_Command(link.handle, reason))
    timeout_us = link.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
    held_sn = None
    peer_sn = link.sn
    first_transmission = None
    repeats = 0
    earliest = before + timeout_us - HCI_OBSERVATION_STEP_US
    while link.anchor + HCI_OBSERVATION_STEP_US < earliest:

        def build(received):
            nonlocal held_sn, peer_sn
            if received is not None:
                sn, nesn = _sequence_bits(received)
                peer_sn = nesn
                if held_sn is None:
                    held_sn = sn
            nesn = (
                held_sn
                if held_sn is not None
                else _sequence_bits(link.last_received)[0] ^ 1
            )
            return _data_pdu(peer_sn, nesn)

        packet, _sent = await _wire_event(link, build)
        if first_transmission is None:
            first_transmission = packet.start_us
        sn, nesn = _sequence_bits(packet)
        if not central:
            peer_sn = nesn
            if held_sn is None:
                held_sn = sn
        assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
        assert packet.pdu[PDU_HEADER_SIZE:] == bytes([Opcode.LL_TERMINATE_IND, reason])
        assert sn == held_sn
        assert _disconnected(tester) is None
        repeats += 1
    assert repeats > 1
    event = await _observe_disconnection(
        tester,
        earliest,
        first_transmission + timeout_us + HCI_OBSERVATION_STEP_US,
    )
    assert event.status == ErrorCode.SUCCESS and event.connection_handle == link.handle
    assert event.reason in (
        ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR,
        ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR,
    )
    await _check_rf_stopped(link)


# Independent peer version information, including nonzero manufacturer/subversion.
PEER_VERSION = (hci.HCI_VERSION_BLUETOOTH_CORE_5_4, 4660, 22136)
VERSION_COLLISION_DELAY_LIMIT = 10
# Long-interval collision setup: 3 s, strictly greater than the specified 2 s.
VERSION_COLLISION_INTERVAL = 2400
VERSION_COLLISION_REPEATS_PER_DELAY = 5
# LL.TS.p28 4.3.7.41..44 and PER/BV-146: prescribed event counts and delay search.
VERSION_DUPLICATE_DELAY_EVENTS = 50
VERSION_RESPONSE_DELAY_EVENTS = 10


def _completion(tester):
    return tester.take(
        lambda event: isinstance(
            event, hci.HCI_Read_Remote_Version_Information_Complete_Event
        )
    )


async def _exchange(tester, *, central=False, mode='requesting', duplicates=True):
    """Perform Version Exchange with the selected duplicate/delay stimuli."""
    local = await tester.command(hci.HCI_Read_Local_Version_Information_Command())
    expected = bytes([Opcode.LL_VERSION_IND]) + struct.pack(
        '<BHH', local.lmp_version, local.company_identifier, local.lmp_subversion
    )
    parameters = _advertiser_connection_parameters()
    if central:
        await tester.command(
            hci.HCI_LE_Set_Host_Channel_Classification_Command(
                parameters.channel_map.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
            )
        )
    link, _ = await _pending_connection(tester, central=central, parameters=parameters)
    autonomous = False

    def initial_reply(packet):
        nonlocal autonomous
        version = _version_payload(packet)
        if version is None:
            return b''
        assert version == expected
        if mode == 'responding':
            pytest.skip('Inconclusive: IUT sent Version Indication before the tester')
        autonomous = True
        if mode == 'requesting' and duplicates:
            initial.append(VERSION_IND)
        return b'' if mode == 'delayed' else VERSION_IND

    # Observe autonomous initiation before deciding whether to issue a Host command.
    initial = [initial_reply] if central else [b'', initial_reply]
    packets = await _same_event(
        link, initial, missing_version_inconclusive=mode == 'collision'
    )
    assert sum(_version_payload(packet) is not None for packet in packets) == int(
        autonomous
    )
    requesting = mode != 'responding' and not autonomous
    if requesting:
        await tester.command(
            hci.HCI_Read_Remote_Version_Information_Command(link.handle)
        )
    if not duplicates:
        assert mode in ('requesting', 'responding')
        if mode == 'responding':
            await _responding_version(tester, link, expected, duplicate=False)
        elif not autonomous:
            await _requested_version(tester, link, expected)
        await _quiet_events(link, 1)
        event = _completion(tester)
        if requesting:
            _check_completion(event, link.handle)
        else:
            assert event is None, 'unsolicited Host version completion'
        await link.disconnect()
        return
    if mode == 'delayed':
        if not autonomous:
            packets = await _same_event(link, [b''] if central else [b'', b''])
        assert [_version_payload(packet) for packet in packets].count(expected) == 1
        assert _completion(tester) is None
        due = (
            _last_transmission_start(link, 0)
            + VERSION_RESPONSE_DELAY_EVENTS
            * link.parameters.interval
            * LL_CONN_INTERVAL_UNIT_US
        )
        await _quiet_events(link, VERSION_RESPONSE_DELAY_EVENTS, no_completion=True)
        packet = await link.exchange(VERSION_IND, llid=LlId.CONTROL, check_ack=True)
        sent = _last_transmission_start(link, len(VERSION_IND))
        assert due <= sent < due + link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        assert _version_payload(packet) is None
    elif mode == 'responding':
        await _responding_version(tester, link, expected)
    elif not autonomous:
        payloads = [VERSION_IND]
        if mode == 'requesting':
            payloads.append(VERSION_IND)
        if not central and requesting:
            payloads.insert(0, b'')
        packets = await _same_event(
            link, payloads, missing_version_inconclusive=mode == 'collision'
        )
        versions = [_version_payload(packet) for packet in packets]
        if not requesting and central and (versions[0] is not None):
            pytest.skip('Inconclusive: IUT sent Version Indication before the tester')
        assert versions.count(expected) == 1
        assert all(payload in (None, expected) for payload in versions)
    if mode != 'delayed':
        due = (
            _last_transmission_start(link, len(VERSION_IND))
            + VERSION_DUPLICATE_DELAY_EVENTS
            * link.parameters.interval
            * LL_CONN_INTERVAL_UNIT_US
        )
    await _quiet_events(link, 1)
    event = _completion(tester)
    if requesting:
        _check_completion(event, link.handle)
    else:
        assert event is None
    if mode in ('requesting', 'responding'):
        while link.anchor < due:
            await _quiet_events(link, 1, no_completion=True)
        packet = await link.exchange(VERSION_IND, llid=LlId.CONTROL, check_ack=True)
        sent = _last_transmission_start(link, len(VERSION_IND))
        assert due <= sent < due + link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        assert _version_payload(packet) is None
    await _quiet_events(link, VERSION_RESPONSE_DELAY_EVENTS, no_completion=True)
    await link.disconnect()


async def _requested_version(tester, link, expected):
    """Receive a possibly delayed request and acknowledge it with the peer version."""
    responded = False

    def reply(packet):
        nonlocal responded
        version = _version_payload(packet)
        if version is None:
            return b''
        assert version == expected
        assert not responded, 'duplicate Version Indication'
        responded = True
        if link.central:
            payloads.append(b'')
        return VERSION_IND

    deadline = tester.radio.now_us + LL_RESPONSE_TIMEOUT_US
    while tester.radio.now_us < deadline:
        payloads = [reply] if link.central else [b'', reply]
        packets = await _same_event(
            link,
            payloads,
            followup=reply,
            keep_open=lambda: not link.central and not responded,
        )
        assert sum(_version_payload(p) is not None for p in packets) == int(responded)
        if responded:
            return
    pytest.skip('Observation limit: no requested Version Indication')


async def _responding_version(tester, link, expected, *, duplicate=True):
    """Acknowledge the response, optionally sending a same-event duplicate."""
    responded = False
    sent = False

    def reply(packet):
        nonlocal responded, sent
        version = _version_payload(packet)
        if not sent:
            if link.central and version is not None:
                pytest.skip(
                    'Inconclusive: IUT sent Version Indication before the tester'
                )
            sent = True
            return VERSION_IND
        if version is None:
            return b''
        assert version == expected, 'incorrect local version information'
        assert not responded, 'duplicate local Version Indication'
        responded = True
        if not duplicate:
            return b''
        # Receive the acknowledgement of the duplicate before leaving this event.
        payloads.append(b'')
        return VERSION_IND

    # The source imposes no response deadline. This bound limits the experiment;
    # exhausting it is not evidence of a normative response-time failure.
    deadline = tester.radio.now_us + LL_RESPONSE_TIMEOUT_US
    while tester.radio.now_us < deadline:
        payloads = [reply, reply] if not sent else [reply]
        packets = await _same_event(
            link,
            payloads,
            followup=reply,
            keep_open=lambda: not link.central and not responded,
        )
        versions = [_version_payload(packet) for packet in packets]
        assert all(version in (None, expected) for version in versions)
        assert versions.count(expected) == int(
            responded
        ), 'duplicate Version Indication'
        assert _completion(tester) is None, 'unsolicited Host version completion'
        if responded:
            return
    pytest.skip('Observation limit: no Version Indication within the tester budget')


def _last_transmission_start(link, payload_size):
    return link.last_sent_end_us - link.tx_phy.airtime_us(
        PDU_HEADER_SIZE + payload_size
    )


async def _quiet_events(link, count, *, no_completion=False):
    """Maintain ARQ while requiring no extra version PDU or unsolicited Host
    completion."""
    for _ in range(count):
        sent_sn = link.sn
        packet = await link.exchange(check_ack=True)
        if link.central:
            assert int(bool(packet.pdu[0] & PDU_DATA_NESN_MASK)) != sent_sn
        assert (
            _version_payload(packet) is None
        ), 'extra LL_VERSION_IND in one connection'
        assert _disconnected(link.tester) is None
        if no_completion:
            assert _completion(link.tester) is None


async def _same_event(
    link,
    payloads,
    *,
    followup=None,
    missing_version_inconclusive=False,
    keep_open=None,
):
    """Exchange an MD-linked sequence; payload callbacks inspect the preceding RX."""
    tester, channel = (link.tester, link.channel)
    packets = []
    anchor = start = link.anchor

    async def receive(expected_start):
        packet = await tester.receive(
            channel,
            start_us=max(tester.radio.now_us + 1, expected_start - 1),
            duration_us=max(1000, expected_start - tester.radio.now_us + 1000),
            **link.radio_parameters | {'phy': link.rx_phy},
        )
        if packet is None:
            if missing_version_inconclusive and not link.central and sent_version:
                pytest.skip('Inconclusive: Peripheral did not listen to Step 4 packet')
            raise AssertionError('missing DATA PDU in same-event exchange')
        assert packet.valid_crc
        assert len(packet.pdu) >= PDU_HEADER_SIZE
        assert packet.pdu[1] == len(packet.pdu) - PDU_HEADER_SIZE
        assert packet.start_us == expected_start
        assert int(bool(packet.pdu[0] & PDU_DATA_SN_MASK)) == link.nesn
        link._accept(packet)
        link.last_received = packet
        packets.append(packet)
        return packet

    sent_sn = link.sn
    sent_version = False
    for index, payload in enumerate(payloads):
        if link.central:
            packet = await receive(start)
            if index:
                assert int(bool(packet.pdu[0] & PDU_DATA_NESN_MASK)) != sent_sn
            start = packet.end_us + LL_IFS_US
        if callable(payload):
            payload = payload(link.last_received)
        header = (
            (LlId.CONTROL if payload else LlId.CONTINUATION)
            | link.sn * PDU_DATA_SN_MASK
            | link.nesn * PDU_DATA_NESN_MASK
            | (
                PDU_DATA_MD_MASK
                if index + 1 < len(payloads) or (keep_open is not None and keep_open())
                else 0
            )
        )
        sent_sn = link.sn
        sent_version = payload == VERSION_IND
        await tester.transmit(
            channel,
            bytes([header, len(payload)]) + payload,
            start_us=start,
            **link.radio_parameters,
        )
        link.last_sent_end_us = tester.radio.now_us + 1
        start = link.last_sent_end_us + LL_IFS_US
        if not link.central:
            packet = await receive(start)
            assert int(bool(packet.pdu[0] & PDU_DATA_NESN_MASK)) != sent_sn
            start = packet.end_us + LL_IFS_US
            if (
                followup is not None
                and index + 1 == len(payloads)
                and _version_payload(packet) is not None
            ):
                payloads.append(followup)
        assert (
            tester.radio.now_us
            < anchor + link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        )
    link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
    link.counter = link.counter + 1 & LL_EVENT_COUNTER_MASK
    return packets


async def _version_timeout(tester, *, central=False):
    """Withhold peer version information while maintaining the ACL until transaction
    expiry."""
    setup_before = tester.radio.now_us
    parameters = _advertiser_connection_parameters() if central else LinkParameters()
    link = await _version_link(
        tester,
        central=central,
        interval=parameters.interval,
        timeout=parameters.timeout,
    )
    response = _version_payload(link.last_received)
    requested = response is None
    if requested:
        before = tester.radio.now_us
        await tester.command(
            hci.HCI_Read_Remote_Version_Information_Command(link.handle)
        )
        response = await link.control(Opcode.LL_VERSION_IND)
    else:
        before = setup_before
    first_transmission = link.last_received.start_us
    assert len(response) == PDU_CONTROL_VERSION_SIZE
    if not central:
        await link.exchange()
    earliest = before + LL_RESPONSE_TIMEOUT_US - HCI_OBSERVATION_STEP_US
    latest = first_transmission + LL_RESPONSE_TIMEOUT_US + HCI_OBSERVATION_STEP_US
    while link.anchor + HCI_OBSERVATION_STEP_US < earliest:
        await _quiet_events(link, 1, no_completion=True)
    while tester.radio.now_us <= latest:
        terminal = [
            event
            for event in tester.events
            if isinstance(
                event,
                (
                    hci.HCI_Read_Remote_Version_Information_Complete_Event,
                    hci.HCI_Disconnection_Complete_Event,
                ),
            )
        ]
        if terminal:
            assert tester.radio.now_us >= earliest, 'premature version timeout'
            for event in terminal:
                if isinstance(
                    event, hci.HCI_Read_Remote_Version_Information_Complete_Event
                ):
                    assert (
                        requested
                    ), 'unsolicited Host completion for autonomous version'
                    _check_completion(
                        event,
                        link.handle,
                        status=ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR,
                    )
            if any(
                isinstance(event, hci.HCI_Disconnection_Complete_Event)
                for event in terminal
            ):
                assert len(terminal) <= 2
                event = terminal[-1]
                assert isinstance(
                    event, hci.HCI_Disconnection_Complete_Event
                ), 'version completion followed disconnection'
                assert (event.status, event.connection_handle, event.reason) == (
                    ErrorCode.SUCCESS,
                    link.handle,
                    ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR,
                )
                for event in terminal:
                    tester.events.remove(event)
                break
        if tester.radio.now_us == latest:
            raise AssertionError(
                'Version Exchange did not expire at the transaction deadline'
            )
        target = min(tester.radio.now_us + HCI_OBSERVATION_STEP_US, latest)
        if tester.radio.now_us < earliest - 1:
            target = min(target, earliest - 1)
        await tester.wait(target - tester.radio.now_us)
    else:
        raise AssertionError('Version Exchange observation began after its deadline')
    await _check_rf_stopped(link)
    assert _completion(tester) is None


async def _version_link(tester, *, central=False, **parameters):
    return await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
        **parameters,
    )


def _version_payload(packet):
    if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL and packet.pdu[
        PDU_HEADER_SIZE : PDU_HEADER_SIZE + 1
    ] == bytes([Opcode.LL_VERSION_IND]):
        assert len(packet.pdu) == PDU_HEADER_SIZE + PDU_CONTROL_VERSION_SIZE
        return packet.pdu[PDU_HEADER_SIZE:]
    return None


def _check_advertising(packet, *, directed=False, data=PARALLEL_ADVERTISING_DATA):
    assert packet.valid_crc
    expected = (
        AdvertisingPduType.ADV_DIRECT_IND if directed else AdvertisingPduType.ADV_IND
    )
    assert packet.pdu[0] & PDU_ADV_TYPE_MASK == expected
    assert not packet.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
    assert packet.pdu[1] == len(packet.pdu) - PDU_HEADER_SIZE
    assert packet.pdu[PDU_HEADER_SIZE:] == bytes(DUT_ADDRESS) + (
        bytes(LOWER_CENTRAL_PUBLIC_ADDRESS) if directed else data
    )


async def _observe_advertising(
    tester, links, *, directed=False, data=PARALLEL_ADVERTISING_DATA
):
    deadline = tester.radio.now_us + ADVERTISING_OBSERVATION_US
    while tester.radio.now_us < deadline:
        until = min(
            deadline,
            min(
                (link.anchor - PEER_EXCHANGE_BUDGET_US for link in links),
                default=deadline,
            ),
        )
        if until <= tester.radio.now_us:
            await _service_peer(links)
            continue
        packet = await tester.receive(37, duration_us=until - tester.radio.now_us)
        if packet is None:
            continue
        _check_advertising(packet, directed=directed, data=data)
        return packet
    raise AssertionError('advertising absent while maintaining the existing ACL')


class _AclStream:
    """Maintain HCI flow control and independently reassemble every observed DATA
    PDU."""

    def __init__(self, tester, link, dut, peer, size, slots):
        self.tester, self.link = (tester, link)
        self.dut, self.peer = (dut, peer)
        self.size, self.slots = (size, slots)
        self.expected = deque()
        self.partial = b''
        self.submitted = self.completed = 0
        self.controls = deque()
        self.trigger = None
        self.initial = True
        self.require_initial_full_size = True
        self.coded_dle_inconclusive = False
        self.restricted = False
        self.limit = size
        self.restricted_octets = 0
        self.lengths = None

    def enqueue(self):
        if self.submitted - self.completed >= self.slots:
            return
        data = bytes((self.submitted + index) % 256 for index in range(self.size))
        self.expected.append(data)
        self.submitted += 1
        self.tester.send(
            bytes(
                hci.HCI_AclDataPacket(
                    self.link.handle,
                    hci.HCI_ACL_PB_FIRST_NON_FLUSHABLE,
                    0,
                    len(data),
                    data,
                )
            )
        )

    async def event(self, data=b'', *, queue=True, response_timeout_after_us=None):
        await self.tester.wait(0)
        if queue:
            self.enqueue()
        for packet in await _connection_event(
            self.link,
            data,
            llid=LlId.CONTROL if data else LlId.CONTINUATION,
            response_timeout_after_us=response_timeout_after_us,
        ):
            llid = packet.pdu[0] & PDU_DATA_LLID_MASK
            payload = packet.pdu[PDU_HEADER_SIZE:]
            if llid == LlId.CONTROL:
                if (
                    payload[0] == Opcode.LL_LENGTH_REQ
                    and self.link.rx_phy == Phy.LE_CODED
                ):
                    _check_parameters(payload, Opcode.LL_LENGTH_REQ, MAXIMUM)
                    if self.coded_dle_inconclusive:
                        pytest.skip(
                            'Inconclusive: autonomous DLE after Coded PHY Instant'
                        )
                    assert self.lengths is not None, 'unhandled autonomous DLE'
                    continue
                self.controls.append(payload)
                if payload[0] == self.trigger:
                    self.restricted = True
                    self.initial = False
                continue
            if not payload:
                continue
            limits = (
                self.lengths.packet_limits.pop(packet.start_us)
                if self.lengths is not None
                else _effective_lengths(self.dut, self.peer, self.link)
            )
            assert len(payload) <= limits[0]
            assert packet.end_us - packet.start_us <= limits[1]
            if self.restricted:
                assert (
                    len(payload) <= self.limit
                ), 'DATA exceeds post-procedure packet limit'
                self.restricted_octets += len(payload)
            elif (
                self.initial
                and self.require_initial_full_size
                and (len(payload) != self.size)
            ):
                pytest.skip(
                    'Inconclusive: DATA was already fragmented before PHY procedure'
                )
            assert self.expected, 'unsolicited DATA without a queued Host packet'
            assert llid == (LlId.CONTINUATION if self.partial else LlId.START)
            self.partial += payload
            assert self.expected[0].startswith(
                self.partial
            ), 'ACL bytes/boundaries changed'
            if self.partial == self.expected[0]:
                self.expected.popleft()
                self.partial = b''
        if self.lengths is not None:
            self.dut = self.lengths.dut
            self.lengths.check()
        while event := self.tester.take(
            lambda event: isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
        ):
            assert event.connection_handles == [self.link.handle]
            self.completed += sum(event.num_completed_packets)
            assert self.completed <= self.submitted - len(self.expected)

    async def control(self, opcode, data=b'', *, queue=True, required=True):
        for index in range(CONTROL_OBSERVATION_EVENTS):
            if payload := self.take(opcode):
                return payload
            await self.event(data if index == 0 else b'', queue=queue)
        if payload := self.take(opcode):
            return payload
        if required:
            raise AssertionError(f'missing {opcode.name} during ACL stream')
        return None

    def take(self, opcode):
        for payload in self.controls:
            if payload[0] == opcode:
                self.controls.remove(payload)
                return payload
        return None

    async def finish(self):
        for _ in range(CONTROL_OBSERVATION_EVENTS):
            if self.completed == self.submitted:
                break
            await self.event(queue=False)
        assert not self.expected and (not self.partial)
        assert self.completed == self.submitted
        if self.lengths is not None:
            self.lengths.check(final=True)


VERSION_IND = bytes([Opcode.LL_VERSION_IND]) + struct.pack('<BHH', *PEER_VERSION)


def _check_completion(event, handle, *, status=ErrorCode.SUCCESS):
    assert event is not None
    assert (event.status, event.connection_handle) == (status, handle)
    if status == ErrorCode.SUCCESS:
        assert (
            event.version,
            event.manufacturer_name,
            event.subversion,
        ) == PEER_VERSION


async def accepting_connections(tester):
    """Accepting Connections.

    Initial Condition:
        Use public addresses and undirected advertising at a selected 20-ms base
        interval with an empty device name. The Filter Accept List contains only
        the Lower Tester's public Central address; scan and connection requests
        are filtered through that list. Use the common parameters from Sections
        4.3.2.1 and 4.3.3.1: interval=8 (10 ms), WinSize=WinOffset=7, latency=0,
        timeout=30 (300 ms), CRCInit=0x198891, Hop=5, and SCA category 0.
        The reviewed correction uses ChM=0x03, enabling data channels 0 and 1.

    Test Steps:
        1. Configure the Lower Tester as an initiator using the common public
           address and common connection parameters.
        2. Enable legacy undirected advertising on the first supported primary
           channel, 37, with the configured Filter Accept List policy.
        3. Receive ADV_IND on that channel. Check its public advertiser address,
           the selected interval including AdvDelay, and silence on the other
           primary channels.
        4. Receive ADV_IND and transmit CONNECT_IND at T_IFS after its end.
           Repeat up to 20 times or until advertising stops. In this ideal-link
           trial no request loss is injected: the first request is accepted and
           the procedure takes the permitted early-exit path.
        5. Transmit the first correctly formatted empty DATA PDU one connection
           interval after CONNECT_IND, using the common CSA#1 parameters.
        6. Receive correctly formatted DATA replies on the same data channel at
           T_IFS. Continue until 100 replies have been measured, allowing up to
           900 transmitted events. Count replies, not merely attempted events.
        7. Interleaved with Step 6, require Connection Complete with Peripheral
           role, the Lower Tester address/type, and the requested connection
           interval, latency, timeout, and Central clock accuracy.
        8. Terminate the Peripheral connection through HCI and require its
           matching Disconnection Complete event.
        9. Configure the Lower Tester to initiate another connection with the
           same common parameters.
        10. Enable advertising on the second supported primary channel, 38.
        11. Repeat Steps 3-8 on channel 38.
        12. Configure the Lower Tester to initiate another connection with the
            same common parameters.
        13. Enable advertising on the third supported primary channel, 39.
        14. Repeat Steps 3-8 on channel 39.

    Expected Outcome:
        Pass verdict:
            Every channel trial stops advertising, establishes the requested
            connection, and produces at least 100 valid, acknowledged CSA#1
            replies within the 900-event bound. Verify reply timing at T_IFS;
            the simulation's exact integer-us check is stricter than the source
            tolerance around T_IFS. HCI reports the requested connection.
        Fail verdict:
            Any Advertising Set Terminated or Channel Selection Algorithm event
            on this legacy Peripheral command path fails the trial.

    Source Correction:
        The common ChM bit string enables only channel 0, contrary to the Core
        minimum of two used ACL channels. Use the reviewed local correction
        ChM=0x03, not a claimed published SIG erratum. Step 8's handle reference
        to Step 4 means the handle reported by HCI in Step 7; CONNECT_IND does
        not contain an HCI connection handle.

    Review Limitation:
        The PHY uses integer-microsecond timestamps. The 0.1-us measurement
        accuracy specified in the source Notes is not independently exercised;
        passing the integer-us reply checks does not close this limitation.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28.pdf, LL/CON/ADV/BV-01-C, independently titled procedure after
        Section 4.3.3.2; PDF pages 478-480, printed pages 4.3-5 through 4.3-7.
        Steps 1-14, Expected Outcome, and Notes; common tables on PDF pages
        476-477. Core Vol 6, Part B, Section 4.5.5 defines connection events.
    """
    await _legacy_setup(tester, directed=False)


async def accepting_connections_timeout(tester):
    """Accepting Connections Timeout.

    Initial Condition:
        Use legacy undirected advertising on primary channel 37 with public
        addresses and the selected 20-ms base advertising interval. The Filter
        Accept List contains the Lower Tester's public address; only listed
        peers may send scan or connection requests. Select the common interval
        of 10 ms, WinSize=WinOffset=7, latency=0, supervision timeout=300 ms,
        CRCInit=0x198891, Hop=5, SCA category 0, and corrected ChM=0x03.

    Test Steps:
        1. Configure the Lower Tester as an initiator using the common public
           address and common connection/data-channel parameters.
        2. Enable legacy advertising with LE Set Advertising Enable on the
           selected supported primary channel, 37.
        3. Receive ADV_IND and respond with CONNECT_IND at T_IFS after its end.
           Repeat up to 20 times or until advertising stops. In this ideal-link
           trial the first request is accepted, so no retry is needed.
        4. Send no further RF packets after CONNECT_IND. Monitor primary channel
           37 for continued advertising and observe HCI until establishment
           failure, rather than maintaining the connection with DATA packets.
        5. Interleaved with Step 4, require Connection Complete with the public
           peer identity and requested interval, latency, and timeout; retain
           its connection handle.
        6. Require successful Disconnection Complete with the same handle and
           reason Connection Failed to be Established (0x3E). Independently
           derive T1 and T2 from the requested windows and clock accuracy; if
           T2 precedes T1, reject an event before T2, including a check immediately
           before that boundary.

    Expected Outcome:
        Pass verdict:
            Advertising stops and HCI reports connection establishment failure.
            When T2 is earlier than T1, Disconnection Complete is not earlier
            than T2. T1 is the end of the sixth receive window; T2 is the end of
            the receive window immediately before the first window starting at
            least six connection intervals after CONNECT_IND ends.
        Fail verdict:
            Any Advertising Set Terminated or Channel Selection Algorithm event
            on this legacy Peripheral command path fails the trial.

    Source Correction:
        The common table's one-channel ChM is treated as an editorial error;
        use the reviewed local correction 0x03, not a published SIG erratum.

    Coverage Note:
        For the source's common window parameters, T1 equals T2, so the source's
        conditional T2-before-T1 lower bound does not apply to this vector.
        The independent window-bound algorithm and its pre-expiry observation
        are covered by unit tests with a different, legal window offset.

    Reference:
        LL.TS.p28.pdf, LL/CON/ADV/BV-02-C, independently titled procedure after
        Section 4.3.3.2; PDF pages 480-481, printed pages 4.3-7 through 4.3-8.
        Steps 1-6 and Expected Outcome; common tables on PDF pages 476-477.
        Core Vol 6, Part B, Section 4.5.5 defines connection establishment.
    """
    parameters = _advertiser_connection_parameters()
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(
            LOWER_CENTRAL_PUBLIC_ADDRESS.address_type, LOWER_CENTRAL_PUBLIC_ADDRESS
        )
    )
    link, end = await _pending_connection(
        tester,
        central=False,
        parameters=parameters,
        advertising_filter_policy=ADV_FILTER_ACCEPT_LIST_ONLY,
    )
    _completion_events(tester, link)
    earliest = end + _accepting_timeout_bound(parameters)
    latest = (
        end
        + LL_CONN_ESTABLISHMENT_EVENTS * parameters.interval * LL_CONN_INTERVAL_UNIT_US
    )
    event = None
    while tester.radio.now_us <= latest + HCI_OBSERVATION_STEP_US:
        event = _disconnected(tester)
        if event is not None:
            assert tester.radio.now_us >= earliest
            break
        duration = HCI_OBSERVATION_STEP_US
        if tester.radio.now_us < earliest - 1:
            duration = min(duration, earliest - 1 - tester.radio.now_us)
        assert await tester.receive(37, duration_us=duration) is None
    assert event is not None, 'setup did not time out'
    assert (event.status, event.connection_handle, event.reason) == (
        ErrorCode.SUCCESS,
        link.handle,
        ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR,
    )
    _completion_events(tester, link)


async def central_missing_peripheral_packets(tester):
    """Central Missing Peripheral Packets.

    Initial Condition:
        Use public addresses and legacy undirected advertising on primary
        channel 37. Provision the Lower Tester's public Central address in the
        Filter Accept List, but use the accept-all advertising policy explicitly
        selected by the procedure preamble. Use the common 10-ms interval,
        WinSize=WinOffset=7, supervision timeout=300 ms, CRCInit=0x198891, Hop=5,
        SCA category 0, and corrected ChM=0x03. Override common latency with 5.

    Test Steps:
        1. Configure the Lower Tester as an initiator with the common public
           address, common connection parameters, and Peripheral latency 5.
        2. Enable legacy undirected advertising with LE Set Advertising Enable
           on the selected primary channel, 37.
        3. Receive ADV_IND on that channel and respond with CONNECT_IND at
           T_IFS after its end. The first DATA event begins one common connection
           interval after the request ends.
        4. For each of 30 events, transmit a correctly sequenced empty DATA PDU
           without acknowledging the Peripheral's initial SN=0 transmission:
           retain NESN=0 while advancing the Central's SN when acknowledged.
        5. Interleave with Step 4: receive correctly formatted DATA replies on
           the same data channel at T_IFS. Check unchanged Peripheral SN=0,
           correct NESN, and at least nine responses across the 30 events.
        6. For each of another 30 events, transmit correctly sequenced empty
           DATA PDUs that acknowledge the Peripheral's preceding transmission,
           using the common interval and CSA#1 channel selection.
        7. Interleave with Step 6: receive and validate the Peripheral's DATA
           replies at T_IFS. Permit latency-five omissions, but no more than five
           consecutive missing replies or six intervals between replies.
        8. Interleaved with Steps 4-5, require Connection Complete with the
           public peer identity, requested interval, latency five, and timeout.
        9. Terminate the Peripheral connection through HCI using its reported
           handle, and require the matching Disconnection Complete event.

    Expected Outcome:
        Pass verdict:
            Advertising stops and the Peripheral maintains a CSA#1 connection.
            Before its first transmission is acknowledged, at least nine of
            the first 30 events contain correctly timed replies. Subsequent
            acknowledgements and omissions respect Peripheral latency five.
        Fail verdict:
            Any Advertising Set Terminated or Channel Selection Algorithm event
            on this legacy Peripheral command path fails the trial.

    Source Correction:
        Use the reviewed local correction ChM=0x03 for the invalid one-channel
        common table; this is not a published SIG erratum. The preamble's phrase
        about filtering unknown peers conflicts with its explicit accept-any
        policy: follow that explicit policy while provisioning the stated list.
        Step 9's reference to a handle from nonexistent Step 10 means the HCI
        connection handle reported in Step 8.

    Reference:
        LL.TS.p28.pdf, LL/CON/ADV/BV-03-C, independently titled procedure after
        Section 4.3.3.2; PDF pages 481-483, printed pages 4.3-8 through 4.3-10.
        Steps 1-9 and Expected Outcome; common tables on PDF pages 476-477.
        Core Vol 6, Part B, Sections 4.5.5 and 4.5.9 define establishment and ARQ.
    """
    parameters = _advertiser_connection_parameters(latency=PERIPHERAL_LATENCY)
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(
            LOWER_CENTRAL_PUBLIC_ADDRESS.address_type, LOWER_CENTRAL_PUBLIC_ADDRESS
        )
    )
    link, _ = await _pending_connection(tester, central=False, parameters=parameters)
    _completion_events(tester, link)
    responses = 0
    peer_sn = 0
    acknowledgement = 0
    gap = 0
    for index in range(2 * LATENCY_EVENTS):
        duration = link.anchor - tester.radio.now_us - 50
        if duration > 0:
            assert await tester.receive(37, duration_us=duration) is None
        sent = _data_pdu(peer_sn, acknowledgement)
        packet, _ = await _wire_event(link, lambda _, value=sent: value, required=False)
        gap += 1
        if packet is not None:
            _empty_data(packet)
            sn, nesn = _sequence_bits(packet)
            assert nesn == peer_sn ^ 1
            peer_sn = nesn
            if index < LATENCY_EVENTS:
                assert sn == 0
                responses += 1
            else:
                assert gap <= PERIPHERAL_LATENCY + 1
            acknowledgement = 0 if index < LATENCY_EVENTS - 1 else sn ^ 1
            _restore_peer(link, packet, sent)
            gap = 0
        if index == LATENCY_EVENTS - 1:
            assert responses >= MINIMUM_NAK_RESPONSES
        if index >= LATENCY_EVENTS:
            assert gap <= PERIPHERAL_LATENCY
    _completion_events(tester, link)
    await link.disconnect()


async def directed_advertising_connection(tester):
    """Directed Advertising Connection.

    Initial Condition:
        Select public own and initiator addresses and high-duty directed
        advertising on all supported primary channels. The intended initiator
        is the Lower Tester's public Central address. Use the common 10-ms
        connection interval, WinSize=WinOffset=7, latency=0, supervision timeout
        of 300 ms, CRCInit=0x198891, Hop=5, SCA category 0, and corrected ChM=0x03.

    Test Steps:
        1. Configure the Lower Tester to initiate using a public InitA different
           from the directed advertising target.
        2. Enable high-duty directed advertising in the IUT through LE Set
           Advertising Enable, using all supported primary advertising channels.
        3. Receive ADV_DIRECT_IND and respond on the same channel with a
           CONNECT_IND carrying the mismatching InitA at T_IFS after its end.
        4. Require further ADV_DIRECT_IND after the rejected request, then
           observe the high-duty advertising timeout of 1.28 s without sending
           a matching request.
        5. Require Connection Complete with Directed Advertising Timeout status.
        6. Configure the Lower Tester to initiate using the matching public InitA
           and common connection/data-channel parameters.
        7. Enable high-duty directed advertising again on all supported primary
           advertising channels.
        8. Receive ADV_DIRECT_IND containing the IUT AdvA and Lower Tester
           TargetA; respond with matching CONNECT_IND at T_IFS after its end.
        9. Require Connection Complete with Peripheral role, matching public
           peer identity, and the requested interval, latency, and timeout.
        10. Transmit the first correctly formatted DATA PDU one connection
            interval after CONNECT_IND ends, using the common CSA#1 parameters.
        11. Require correctly formatted DATA replies on the same data channel
            at T_IFS and continue until 900 replies have been received. Observe
            that advertising has stopped while maintaining the connection.

        Cleanup: terminate the resulting connection through HCI.

    Expected Outcome:
        Pass verdict:
            The wrong initiator is rejected and directed advertising times out.
            The matching initiator establishes the requested Peripheral
            connection, HCI reports it, and 900 correctly timed CSA#1 replies
            demonstrate that the connection is maintained.
        Fail verdict:
            Any Advertising Set Terminated or Channel Selection Algorithm event
            on this legacy Peripheral command path fails the trial.

    Source Correction:
        Treat the one-channel common ChM as an editorial error and use the
        reviewed local correction 0x03; this is not a published SIG erratum.

    Reference:
        LL.TS.p28.pdf, LL/CON/ADV/BV-04-C, independently titled procedure after
        Section 4.3.3.2; PDF pages 483-485, printed pages 4.3-10 through 4.3-12.
        Steps 1-11 and Expected Outcome; common tables on PDF pages 476-477.
        Core Vol 6, Part B, Section 4.4.2.4 defines directed advertising.
    """
    await _legacy_setup(tester, directed=True)


async def extended_advertising_accepting_connections(tester, *, phy):
    """Extended Advertising, Accepting Connections.

    Initial Condition:
        Use public IUT and Lower Tester addresses, all primary advertising
        channels, accept-all filtering, an empty device name, and the minimum
        20-ms base advertising interval. Table 4.3-2 selects primary/secondary
        PHYs: 1M/1M for LL/CON/ADV/BV-05-C, 1M/2M for LL/CON/ADV/BV-12-C,
        and Coded/Coded for LL/CON/ADV/BV-13-C. All three use ADV_EXT_IND.
        Select the common Lower Tester parameters: interval=8 (10 ms),
        WinSize=WinOffset=7, latency=0, timeout=30 (300 ms), CRCInit=0x198891,
        Hop=5, SCA category 0, and the reviewed common-table ChM=0x03 correction.

    Test Steps:
        Execute all four ADV_EXT_IND rounds in Table 4.3-3: properties 0x0001
        with matching/wrong AdvA, then properties 0x0005 with matching/wrong
        AdvA. Each round starts with a newly enabled advertising set.

        1. Send LE Set Extended Advertising Parameters for handle 0, all primary
           channels, minimum advertising interval, the round's properties,
           public own address, the Table 4.3-2 PHYs, and filter policy 0x00.
           For directed rounds, select the Lower Tester's public target address.
           Require successful Command Complete.
        2. Send LE Set Decision Data only for ADV_DECISION_IND cases. This step
           is not applicable to the three selected ADV_EXT_IND cases.
        3. Enable advertising with Duration=0 and Max_Extended_Advertising_Events
           =0; require successful Command Complete.
        4. Receive ADV_EXT_IND with connectable AdvMode and only AuxPtr and ADI
           in its Extended Header. Observe two full primary-channel cycles to
           check the selected interval, including AdvDelay, on channels 37-39.
        5. Follow AuxPtr to AUX_ADV_IND on the selected secondary PHY. Check
           connectable AdvMode, public AdvA, matching ADI, and the Lower Tester's
           public TargetA in directed rounds. Check every observed primary
           AuxPtr against the actual auxiliary channel, PHY, offset window, and
           T_MAFS. Send AUX_CONNECT_REQ at T_IFS after AUX_ADV_IND, using the
           Lower Tester's InitA and matching or wrong AdvA for the current round.
        6. For wrong AdvA, require no AUX_CONNECT_RSP and no connection-related
           HCI event. Disable advertising successfully and proceed to Step 16
           without creating or using a connection handle.
        7. For matching AdvA, require AUX_CONNECT_RSP on the secondary PHY at
           T_IFS within the source tolerance. Check CRC, length, PDU type,
           AdvMode, public AdvA and TargetA. If no response arrives, repeat
           Steps 4-7, up to 20 requests; fail if all attempts are unanswered.
        8. During free RF gaps in the following connection events, scan all
           primary channels on the selected primary PHY. Require advertising
           to have stopped after connection establishment.
        9. Require Connection Complete with Peripheral role, the requested
           public peer identity, interval, latency, supervision timeout, and
           Central clock accuracy. Retain its valid connection handle.
        10. If Channel Selection Algorithm is reported, require algorithm #2
            and the connection handle from Step 9. Steps 10 and 11 may occur
            in either order; the algorithm event is optional.
        11. Require exactly one successful Advertising Set Terminated for
            advertising handle 0 and the connection handle from Step 9.
        12. Send a correctly formatted DATA PDU on the independently derived
            CSA#2 channel. Place the first anchor at the end of AUX_CONNECT_REQ
            plus the PHY-specific transmit-window delay plus WinOffset.
        13. Receive a correctly formatted DATA response on the same channel and
            selected PHY, with a valid acknowledgement and T_IFS spacing.
        14. Send subsequent correctly formatted DATA PDUs at the requested
            connection interval on independently calculated CSA#2 channels.
        15. Repeat the DATA exchange for exactly 100 connection events total.
            Do not repeat the one-shot HCI event in Step 11. Reject additional
            connection or advertising-termination events during the exchange.
        16. Terminate an established connection through HCI and require its
            matching completion. In rejected-address rounds there is no
            connection to disconnect; finish after disabling advertising.

    Expected Outcome:
        Pass verdict:
            In all four rounds, primary and auxiliary headers and PHYs match
            the selected configuration. Every AuxPtr identifies the observed
            auxiliary PDU with at least T_MAFS spacing. Matching AdvA produces
            AUX_CONNECT_RSP within the 2-us tolerance around T_IFS, the required
            HCI connection and advertising-termination events, and 100 valid
            CSA#2 DATA exchanges on the selected PHY without continued
            advertising. Wrong AdvA produces neither a response nor a connection.

    Source Correction:
        Step 15 refers to repeating Steps 11-14, but Step 11 is a one-shot
        Advertising Set Terminated event. Repeat the DATA exchange (Steps
        12-14) only. Step 6 skips to Step 16 even though no connection exists;
        do not issue Disconnect without a handle. These are local editorial
        interpretations supported by Core semantics, not published SIG errata.
        The common ChM=0x01 is corrected to 0x03 as approved during review.

    Reference:
        LL.TS.p28.pdf, Section 4.3.3.3, LL/CON/ADV/BV-05-C, LL/CON/ADV/BV-12-C,
        LL/CON/ADV/BV-13-C; PDF pages 485-490, printed pages 4.3-12 through
        4.3-17. Tables 4.3-2/3, Steps 1-16, and Expected Outcome. Core Vol 6,
        Part B, Sections 4.5.3-4.5.5 define the transmit window and connection
        transition; Vol 4, Part E defines the connection-related HCI events.
    """
    await _extended_setup(tester, phy=phy)


async def extended_advertising_legacy_pdus_accepting_connections(tester):
    """Extended Advertising, Legacy PDUs, Accepting Connections.

    Initial Condition:
        Select undirected connectable legacy advertising, public IUT and Lower
        Tester addresses, all primary channels, and an empty device name. Use
        the minimum 20-ms advertising interval and common connection parameters:
        interval=8 (10 ms), WinSize=WinOffset=7, latency=0, timeout=30 (300 ms),
        CRCInit=0x198891, Hop=5, SCA category 0, and corrected ChM=0x03.

    Test Steps:
        1. Send LE Set Extended Advertising Parameters with properties 0x0013
           (legacy ADV_IND), all primary channels, minimum advertising interval,
           public own address, primary LE 1M PHY, and accept-all filter policy.
           Require successful Command Complete.
        2. Enable the advertising set with Duration=0 and
           Max_Extended_Advertising_Events=0; require Command Complete success.
        3. Receive ADV_IND on a primary channel using LE 1M. Check ChSel=1,
           public AdvA, PDU length, CRC, and empty advertising data.
        4. Respond on the same channel at T_IFS with CONNECT_IND, ChSel=1,
           public Lower Tester InitA, matching IUT AdvA, and common parameters.
        5. Require Connection Complete with Peripheral role, matching public
           peer identity, requested interval, latency, timeout, and clock
           accuracy. Retain its valid handle. The source permits up to 20
           attempts of Steps 3-5; the ideal link takes the first successful one.
        6. Scan primary channels in free gaps during the DATA exchanges in
           Step 9; fail if advertising continues after connection establishment.
        7. If Channel Selection Algorithm is reported, require algorithm #2 and
           the Step 5 handle. Steps 7 and 8 may occur in either order.
        8. Require exactly one successful Advertising Set Terminated event for
           advertising handle 0 and the Step 5 connection handle.
        9. Exchange correctly formatted DATA PDUs for exactly 100 connection
           events on independently calculated CSA#2 channels at the requested
           interval. Check LE 1M, CRC, valid LLID, acknowledgements, and T_IFS.
        10. Terminate the connection through HCI and require matching completion.
        11. Repeat Steps 1-4, but set CONNECT_IND AdvA to a different public
            address. No connection-related HCI event may be produced.
        12. Continue observing ADV_IND on the same primary channel for at least
            five complete advertising intervals. Respond with wrong-AdvA
            CONNECT_IND each time, and require no DATA response or connection.

        Cleanup: disable the remaining advertising set and reject late
        connection-related HCI events.

    Expected Outcome:
        Pass verdict:
            Legacy ADV_IND uses LE 1M, ChSel=1, and the configured public AdvA.
            A matching CONNECT_IND produces the requested Peripheral connection,
            required Connection Complete and Advertising Set Terminated events,
            and an optional correctly valued Channel Selection Algorithm event.
            Advertising stops while 100 correctly timed CSA#2 DATA exchanges
            complete. Wrong AdvA leaves advertising active for at least five
            complete intervals, without a connection or DATA response.

    Source Correction:
        Step 8 references a connection handle from Step 6, but Step 5 reports
        that handle. The first Expected Outcome bullet refers to Step 4 for
        ADV_IND, which is received in Step 3. Use the reviewed local ChM=0x03
        correction for the invalid one-channel common table. These are local
        editorial corrections, not published SIG errata.

    Reference:
        LL.TS.p28.pdf, LL/CON/ADV/BV-06-C, independently titled procedure after
        Section 4.3.3.3; PDF pages 490-493, printed pages 4.3-17 through 4.3-20.
        Figures 4.3-7/8, Steps 1-12, and Expected Outcome; common tables on PDF
        pages 476-477. Core Vol 6, Part B, Sections 4.4.2.3 and 4.5.8 define
        connection acceptance and Channel Selection Algorithm #2.
    """
    parameters = _advertiser_connection_parameters()
    for valid in (True, False):
        await tester.command(
            extended_parameters(
                advertising_event_properties=(
                    Properties.CONNECTABLE_ADVERTISING
                    | Properties.SCANNABLE_ADVERTISING
                    | Properties.USE_LEGACY_ADVERTISING_PDUS
                ),
                primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
            )
        )
        await tester.command(extended_enable())
        starts = []
        # One initial request, then five complete intervals for the wrong AdvA.
        for _ in range(1 if valid else 6):
            adv = await tester.expect_pdu(37, kind=AdvertisingPduType.ADV_IND)
            assert adv.phy == Phy.LE_1M and adv.valid_crc
            assert adv.pdu == adv_pdu(address=DUT_ADDRESS, data=b'', csa2=True)
            if starts:
                assert (
                    ADV_INTERVAL_US
                    <= adv.start_us - starts[-1]
                    <= ADV_INTERVAL_US + LL_ADV_DELAY_MAX_US
                )
            starts.append(adv.start_us)
            request = request_pdu(
                AdvertisingPduType.CONNECT_IND,
                advertiser=DUT_ADDRESS if valid else OTHER_PUBLIC,
                scanner=LOWER_CENTRAL_PUBLIC_ADDRESS,
                data=parameters.encode(),
            )
            request = bytes([request[0] | PDU_ADV_CHSEL_MASK]) + request[1:]
            end = await tester.transmit(37, request, start_us=adv.end_us + LL_IFS_US)
            if valid:
                link = PeerLink(tester, parameters, end, csa2=True)
                await _connection_complete(
                    tester, link, LOWER_CENTRAL_PUBLIC_ADDRESS, extended=True
                )
                await _data_events(tester, link, 100, observe_advertising=True)
                _no_connection_events(tester)
                await link.disconnect()
            else:
                assert await tester.receive(37, duration_us=1000) is None
            _no_connection_events(tester)
        if not valid:
            assert starts[-1] - starts[0] >= 5 * ADV_INTERVAL_US
        await tester.command(extended_enable(0))
        _no_connection_events(tester)


async def accepting_connections_channel_selection_algorithm_1(tester, *, extended):
    """Accepting Connections, Channel Selection Algorithm #1.

    Initial Condition:
        Use undirected connectable advertising, public IUT and Lower Tester
        addresses, all primary channels, and an empty device name. Select the
        minimum advertising interval where applicable. Use common parameters:
        interval=8 (10 ms), WinSize=WinOffset=7, latency=0, timeout=30 (300 ms),
        CRCInit=0x198891, Hop=5, SCA category 0, and corrected ChM=0x03.
        LL/CON/ADV/BV-07-C uses legacy HCI advertising commands;
        LL/CON/ADV/BV-27-C uses extended HCI commands with legacy PDUs.

    Test Steps:
        1. Configure advertising through the command selected by Table 4.3-4,
           using all primary channels and the minimum applicable interval. Set
           advertising type 0x00, public own address, and accept-all filter
           policy. The extended command uses legacy ADV_IND properties 0x0013.
        2. Enable advertising through the Table 4.3-4 command and require
           Command Complete success. On the extended HCI path, set Duration=0
           and Max_Extended_Advertising_Events=0.
        3. Receive ADV_IND with ChSel=1, public AdvA, and LE 1M PHY.
           Check PDU length and CRC. Observe two complete primary-channel
           cycles and verify each channel's advertising interval.
        4. Respond on the same primary channel at T_IFS with CONNECT_IND,
           ChSel=0, public Lower Tester InitA, matching IUT AdvA, and the common
           connection parameters.
        5. Send correctly formatted DATA on the independently calculated CSA#1
           channel and require a valid acknowledgement and T_IFS response. The
           source allows up to 20 requests or until advertising stops; the ideal
           link takes the permitted early exit after the first successful request.
        6. Require Connection Complete with Peripheral role, the public peer
           identity, requested interval, latency, timeout, and clock accuracy.
           Retain the valid connection handle and maintain the unencrypted link.
        7. Only on the extended HCI command path, check the following substeps
           in either order:
           7A. Require one successful Advertising Set Terminated event with
               advertising handle 0 and the Step 6 connection handle.
           7B. If Channel Selection Algorithm is reported, require the Step 6
               handle and value 0 for Channel Selection Algorithm #1.
        8. Send a correctly formatted DATA PDU on the independently derived
           CSA#1 channel. Repeat Steps 8-10 for 100 additional connection events.
        9. Receive a correctly formatted DATA reply on the same channel using
           LE 1M. Check CRC, valid LLID, acknowledgement, and T_IFS spacing.
        10. Send subsequent DATA PDUs at the common connection interval on
            independently calculated CSA#1 channels. Scan all primary channels
            in free RF gaps and require advertising to have stopped.

        Cleanup: disconnect through HCI, require matching completion, and reject
        duplicate or late connection-related HCI events.

    Expected Outcome:
        Pass verdict:
            ADV_IND uses ChSel=1, the configured public addresses, and the
            permitted interval on all primary channels. CONNECT_IND ChSel=0
            establishes the requested Peripheral connection using CSA#1, not
            the algorithm advertised in ADV_IND's ChSel bit alone. Advertising
            stops, HCI reports the matching connection, and the first DATA
            exchange plus 100 subsequent events have valid channels, PHY, ARQ,
            and timing. Extended commands require Advertising Set Terminated
            and permit a correctly valued Channel Selection Algorithm event.
        Fail verdict:
            On the legacy HCI command path, either Advertising Set Terminated
            or Channel Selection Algorithm is an ineligible event and fails
            the trial, including during DATA exchange and cleanup.

    Source Correction:
        Use the reviewed local ChM=0x03 correction for the invalid one-channel
        common table; this is not a published SIG erratum. For the extended
        command path, translate the source's legacy Advertising_Type wording
        to the corresponding legacy-PDU Advertising_Event_Properties value.

    Reference:
        LL.TS.p28.pdf, Section 4.3.3.4, LL/CON/ADV/BV-07-C and
        LL/CON/ADV/BV-27-C; PDF pages 493-496, printed pages 4.3-20 through
        4.3-23. Table 4.3-4, Figure 4.3-9, Steps 1-10 including 7A/7B,
        and Expected Outcome; common tables on PDF pages 476-477. Core Vol 6,
        Part B, Sections 4.4.2 and 4.5.8 define acceptance and channel selection.
    """
    await _advertising_csa(tester, directed=False, csa2=False, extended=extended)


async def directed_advertising_connection_channel_selection_algorithm_1(
    tester, *, extended
):
    """Directed Advertising Connection, Channel Selection Algorithm #1.

    Initial Condition:
        Use high-duty directed advertising, public IUT and Lower Tester
        addresses, all primary channels, and an empty device name. Select the
        minimum advertising interval where applicable. Use common parameters:
        interval=8 (10 ms), WinSize=WinOffset=7, latency=0, timeout=30 (300 ms),
        CRCInit=0x198891, Hop=5, SCA category 0, and corrected ChM=0x03.
        LL/CON/ADV/BV-08-C uses legacy HCI advertising commands;
        LL/CON/ADV/BV-28-C uses extended HCI commands with legacy PDUs.

    Test Steps:
        1. Configure advertising through the command selected by Table 4.3-5,
           using all primary channels and the minimum applicable interval. Set
           advertising type 0x01, public own and peer addresses, the Lower
           Tester's public target address, and accept-all filter policy.
           The extended command uses legacy high-duty directed properties 0x001D.
        2. Enable advertising through the Table 4.3-5 command and require
           Command Complete success. On the extended HCI path, set Duration to
           1.28 s and Max_Extended_Advertising_Events=0.
        3. Receive ADV_DIRECT_IND with ChSel=1, public AdvA, and LE 1M PHY.
           Require TargetA to match the Lower Tester's public address.
           Check PDU length and CRC. Observe two complete primary-channel
           cycles and verify each channel's advertising interval.
        4. Respond on the same primary channel at T_IFS with CONNECT_IND,
           ChSel=0, public Lower Tester InitA, matching IUT AdvA, and the common
           connection parameters.
        5. Send correctly formatted DATA on the independently calculated CSA#1
           channel and require a valid acknowledgement and T_IFS response. The
           source allows up to 20 requests or until advertising stops; the ideal
           link takes the permitted early exit after the first successful request.
        6. Require Connection Complete with Peripheral role, the public peer
           identity, requested interval, latency, timeout, and clock accuracy.
           Retain the valid connection handle and maintain the unencrypted link.
        7. Only on the extended HCI command path, check the following substeps
           in either order:
           7A. Require one successful Advertising Set Terminated event with
               advertising handle 0 and the Step 6 connection handle.
           7B. If Channel Selection Algorithm is reported, require the Step 6
               handle and value 0 for Channel Selection Algorithm #1.
        8. Send a correctly formatted DATA PDU on the independently derived
           CSA#1 channel. Repeat Steps 8-10 for 100 additional connection events.
        9. Receive a correctly formatted DATA reply on the same channel using
           LE 1M. Check CRC, valid LLID, acknowledgement, and T_IFS spacing.
        10. Send subsequent DATA PDUs at the common connection interval on
            independently calculated CSA#1 channels. Scan all primary channels
            in free RF gaps and require advertising to have stopped.

        Cleanup: disconnect through HCI, require matching completion, and reject
        duplicate or late connection-related HCI events.

    Expected Outcome:
        Pass verdict:
            ADV_DIRECT_IND uses ChSel=1, the configured public addresses, and the
            permitted interval on all primary channels. CONNECT_IND ChSel=0
            establishes the requested Peripheral connection using CSA#1, not
            the algorithm advertised in ADV_DIRECT_IND's ChSel bit alone. Advertising
            stops, HCI reports the matching connection, and the first DATA
            exchange plus 100 subsequent events have valid channels, PHY, ARQ,
            and timing. Extended commands require Advertising Set Terminated
            and permit a correctly valued Channel Selection Algorithm event.
        Fail verdict:
            On the legacy HCI command path, either Advertising Set Terminated
            or Channel Selection Algorithm is an ineligible event and fails
            the trial, including during DATA exchange and cleanup.

    Source Correction:
        Use the reviewed local ChM=0x03 correction for the invalid one-channel
        common table; this is not a published SIG erratum. For the extended
        command path, translate the source's legacy Advertising_Type wording
        to the corresponding legacy-PDU Advertising_Event_Properties value.

    Reference:
        LL.TS.p28.pdf, Section 4.3.3.5, LL/CON/ADV/BV-08-C and
        LL/CON/ADV/BV-28-C; PDF pages 496-499, printed pages 4.3-23 through
        4.3-26. Table 4.3-5, Figure 4.3-10, Steps 1-10 including 7A/7B,
        and Expected Outcome; common tables on PDF pages 476-477. Core Vol 6,
        Part B, Sections 4.4.2 and 4.5.8 define acceptance and channel selection.
    """
    await _advertising_csa(tester, directed=True, csa2=False, extended=extended)


async def accepting_connections_channel_selection_algorithm_2(tester, *, extended):
    """Accepting Connections, Channel Selection Algorithm #2.

    Initial Condition:
        Use undirected connectable advertising, public IUT and Lower Tester
        addresses, all primary channels, and an empty device name. Select the
        minimum advertising interval where applicable. Use common parameters:
        interval=8 (10 ms), WinSize=WinOffset=7, latency=0, timeout=30 (300 ms),
        CRCInit=0x198891, Hop=5, SCA category 0, and corrected ChM=0x03.
        LL/CON/ADV/BV-09-C uses legacy HCI advertising commands;
        LL/CON/ADV/BV-29-C uses extended HCI commands with legacy PDUs.

    Test Steps:
        1. Configure advertising through the command selected by Table 4.3-6,
           using all primary channels and the minimum applicable interval. Set
           advertising type 0x00, public own address, and accept-all filter
           policy. The extended command uses legacy ADV_IND properties 0x0013.
        2. Enable advertising through the Table 4.3-6 command and require
           Command Complete success. On the extended HCI path, set Duration=0
           and Max_Extended_Advertising_Events=0.
        3. Receive ADV_IND with ChSel=1, public AdvA, and LE 1M PHY.
           Check PDU length and CRC. Observe two complete primary-channel
           cycles and verify each channel's advertising interval.
        4. Respond on the same primary channel at T_IFS with CONNECT_IND,
           ChSel=1, public Lower Tester InitA, matching IUT AdvA, and the common
           connection parameters.
        5. Send correctly formatted DATA on the independently calculated CSA#2
           channel and require a valid acknowledgement and T_IFS response. The
           source allows up to 20 requests or until advertising stops; the ideal
           link takes the permitted early exit after the first successful request.
        6. Require Connection Complete with Peripheral role, the public peer
           identity, requested interval, latency, timeout, and clock accuracy.
           Retain the valid connection handle and maintain the unencrypted link.
        7. Only on the extended HCI command path, check the following substeps
           in either order:
           7A. Require one successful Advertising Set Terminated event with
               advertising handle 0 and the Step 6 connection handle.
           7B. If Channel Selection Algorithm is reported, require the Step 6
               handle and value 1 for Channel Selection Algorithm #2.
        8. Send a correctly formatted DATA PDU on the independently derived
           CSA#2 channel. Repeat Steps 8-10 for 100 additional connection events.
        9. Receive a correctly formatted DATA reply on the same channel using
           LE 1M. Check CRC, valid LLID, acknowledgement, and T_IFS spacing.
        10. Send subsequent DATA PDUs at the common connection interval on
            independently calculated CSA#2 channels. Scan all primary channels
            in free RF gaps and require advertising to have stopped.

        Cleanup: disconnect through HCI, require matching completion, and reject
        duplicate or late connection-related HCI events.

    Expected Outcome:
        Pass verdict:
            ADV_IND uses ChSel=1, the configured public addresses, and the
            permitted interval on all primary channels. CONNECT_IND ChSel=1
            establishes the requested Peripheral connection using CSA#2.
            Advertising stops, HCI reports the matching connection, and the first DATA
            exchange plus 100 subsequent events have valid channels, PHY, ARQ,
            and timing. Extended commands require Advertising Set Terminated
            and permit a correctly valued Channel Selection Algorithm event.
        Fail verdict:
            On the legacy HCI command path, either Advertising Set Terminated
            or Channel Selection Algorithm is an ineligible event and fails
            the trial, including during DATA exchange and cleanup.

    Source Correction:
        Use the reviewed local ChM=0x03 correction for the invalid one-channel
        common table; this is not a published SIG erratum. For the extended
        command path, translate the source's legacy Advertising_Type wording
        to the corresponding legacy-PDU Advertising_Event_Properties value.

    Reference:
        LL.TS.p28.pdf, Section 4.3.3.6, LL/CON/ADV/BV-09-C and
        LL/CON/ADV/BV-29-C; PDF pages 500-502, printed pages 4.3-27 through
        4.3-29. Table 4.3-6, Figure 4.3-11, Steps 1-10 including 7A/7B,
        and Expected Outcome; common tables on PDF pages 476-477. Core Vol 6,
        Part B, Sections 4.4.2 and 4.5.8 define acceptance and channel selection.
    """
    await _advertising_csa(tester, directed=False, csa2=True, extended=extended)


async def directed_advertising_connection_channel_selection_algorithm_2(
    tester, *, extended
):
    """Directed Advertising Connection, Channel Selection Algorithm #2.

    Initial Condition:
        Use high-duty directed advertising, public IUT and Lower Tester
        addresses, all primary channels, and an empty device name. Select the
        minimum advertising interval where applicable. Use common parameters:
        interval=8 (10 ms), WinSize=WinOffset=7, latency=0, timeout=30 (300 ms),
        CRCInit=0x198891, Hop=5, SCA category 0, and corrected ChM=0x03.
        LL/CON/ADV/BV-10-C uses legacy HCI advertising commands;
        LL/CON/ADV/BV-30-C uses extended HCI commands with legacy PDUs.

    Test Steps:
        1. Configure advertising through the command selected by Table 4.3-7,
           using all primary channels and the minimum applicable interval. Set
           advertising type 0x01, public own and peer addresses, the Lower
           Tester's public target address, and accept-all filter policy.
           The extended command uses legacy high-duty directed properties 0x001D.
        2. Enable advertising through the Table 4.3-7 command and require
           Command Complete success. On the extended HCI path, set Duration to
           1.28 s and Max_Extended_Advertising_Events=0.
        3. Receive ADV_DIRECT_IND with ChSel=1, public AdvA, and LE 1M PHY.
           Require TargetA to match the Lower Tester's public address.
           Check PDU length and CRC. Observe two complete primary-channel
           cycles and verify each channel's advertising interval.
        4. Respond on the same primary channel at T_IFS with CONNECT_IND,
           ChSel=1, public Lower Tester InitA, matching IUT AdvA, and the common
           connection parameters.
        5. Send correctly formatted DATA on the independently calculated CSA#2
           channel and require a valid acknowledgement and T_IFS response. The
           source allows up to 20 requests or until advertising stops; the ideal
           link takes the permitted early exit after the first successful request.
        6. Require Connection Complete with Peripheral role, the public peer
           identity, requested interval, latency, timeout, and clock accuracy.
           Retain the valid connection handle and maintain the unencrypted link.
        7. Only on the extended HCI command path, check the following substeps
           in either order:
           7A. Require one successful Advertising Set Terminated event with
               advertising handle 0 and the Step 6 connection handle.
           7B. If Channel Selection Algorithm is reported, require the Step 6
               handle and value 1 for Channel Selection Algorithm #2.
        8. Send a correctly formatted DATA PDU on the independently derived
           CSA#2 channel. Repeat Steps 8-10 for 100 additional connection events.
        9. Receive a correctly formatted DATA reply on the same channel using
           LE 1M. Check CRC, valid LLID, acknowledgement, and T_IFS spacing.
        10. Send subsequent DATA PDUs at the common connection interval on
            independently calculated CSA#2 channels. Scan all primary channels
            in free RF gaps and require advertising to have stopped.

        Cleanup: disconnect through HCI, require matching completion, and reject
        duplicate or late connection-related HCI events.

    Expected Outcome:
        Pass verdict:
            ADV_DIRECT_IND uses ChSel=1, the configured public addresses, and the
            permitted interval on all primary channels. CONNECT_IND ChSel=1
            establishes the requested Peripheral connection using CSA#2.
            Advertising stops, HCI reports the matching connection, and the first DATA
            exchange plus 100 subsequent events have valid channels, PHY, ARQ,
            and timing. Extended commands require Advertising Set Terminated
            and permit a correctly valued Channel Selection Algorithm event.
        Fail verdict:
            On the legacy HCI command path, either Advertising Set Terminated
            or Channel Selection Algorithm is an ineligible event and fails
            the trial, including during DATA exchange and cleanup.

    Source Correction:
        Use the reviewed local ChM=0x03 correction for the invalid one-channel
        common table; this is not a published SIG erratum. For the extended
        command path, translate the source's legacy Advertising_Type wording
        to the corresponding legacy-PDU Advertising_Event_Properties value.

    Reference:
        LL.TS.p28.pdf, Section 4.3.3.7, LL/CON/ADV/BV-10-C and
        LL/CON/ADV/BV-30-C; PDF pages 502-505, printed pages 4.3-29 through
        4.3-32. Table 4.3-7, Figure 4.3-12, Steps 1-10 including 7A/7B,
        and Expected Outcome; common tables on PDF pages 476-477. Core Vol 6,
        Part B, Sections 4.4.2 and 4.5.8 define acceptance and channel selection.
    """
    await _advertising_csa(tester, directed=True, csa2=True, extended=extended)


async def connection_supervision_timeout_during_fail_connection_setup(tester):
    """Connection Supervision Timeout during Fail Connection Setup.

    Initial Condition:
        Use undirected legacy advertising, public addresses, the minimum
        advertising interval, all primary channels, and empty advertising data.
        Filter scan and connection requests through a Filter Accept List
        containing only the Lower Tester's public address. Use common parameters:
        interval=8 (10 ms), WinSize=WinOffset=7, latency=0, timeout=30 (300 ms),
        CRCInit=0x198891, Hop=5, SCA category 0, and corrected ChM=0x03.
        The Lower Tester observes primary channel 37 and independently hops
        data channels using Channel Selection Algorithm #1.

    Test Steps:
        1. Configure the Lower Tester to initiate with the common connection
           parameters and send DATA with deliberately inverted CRC bits from
           the first connection event onward. No valid DATA is sent beforehand.
        2. Enable undirected advertising on all primary channels, with public
           own address and filtering for both scan and connection requests.
        3. Receive a correctly formatted ADV_IND on the selected channel, 37,
           and validate CRC, PDU length, public AdvA, and LE 1M PHY.
        4. Send CONNECT_IND on that channel at T_IFS after ADV_IND, using public
           InitA/AdvA and the common connection parameters.
        5. Require Connection Complete with Peripheral role, public peer identity,
           the requested interval, latency, supervision timeout and clock accuracy.
           Retain its valid connection handle.
        6. Starting one common connection interval after CONNECT_IND ends, send
           correctly formatted DATA with an invalid CRC on independently derived
           CSA#1 channels. Repeat Steps 6-7 until supervision expires; never send
           CRC-valid DATA that could reset the supervision timer.
        7. Observe the IUT's correctly formatted reply on the same channel at
           T_IFS, without acknowledgement of the invalid DATA. Count all sent
           events and valid replies. Scan primary channels in free gaps to check
           that advertising has stopped.
        8. Require successful Disconnection Complete at the original 300-ms
           supervision deadline, with the Step 5 handle and Connection Timeout
           reason 0x08. Reject earlier termination or establishment failure 0x3E.

        Cleanup: probe the next receive window to verify RF has stopped, forbid
        unexpected connection-related HCI events and delivery of invalid DATA
        to the Host.

    Expected Outcome:
        Pass verdict:
            At least 95% of the invalid-CRC DATA transmissions receive valid,
            correctly timed, nonacknowledging DATA replies. Invalid DATA can
            establish the connection but cannot reset its supervision timer.
            Disconnection Complete reports Status=0x00, the correct handle and
            Reason=0x08 at the original supervision deadline, within the HCI
            observation resolution of 1 ms.

    Source Correction:
        Step 8 and the pass verdict place 0x08 in Disconnection Complete Status.
        Interpret it as the Reason field; Status is 0x00 for successful completion.
        Use the reviewed local ChM=0x03 correction for the invalid one-channel
        common table. These are local corrections, not published SIG errata.

    Reference:
        LL.TS.p28.pdf, LL/CON/ADV/BI-01-C, independently titled procedure after
        Section 4.3.3.7; PDF pages 506-507, printed pages 4.3-33 through 4.3-34.
        Figure 4.3-13, Steps 1-8 and Expected Outcome; common tables on PDF
        pages 476-477. Core Vol 6, Part B, Sections 4.5 and 4.5.2 distinguish
        establishment from supervision timer reset; Vol 4, Part E defines
        Disconnection Complete Status and Reason.
    """
    peer = LOWER_CENTRAL_PUBLIC_ADDRESS
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(peer.address_type, peer)
    )
    parameters = _advertiser_connection_parameters()
    link, end = await _pending_connection(
        tester,
        central=False,
        parameters=parameters,
        advertising_filter_policy=ADV_FILTER_ACCEPT_LIST_ONLY,
        advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
    )
    assert 0 <= link.handle <= CONNECTION_HANDLE_MAX
    _completion_events(tester, link)
    deadline = end + parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
    total = replies = 0
    while link.anchor < deadline:
        duration = link.anchor - tester.radio.now_us - CONNECT_IFS_TOLERANCE_US
        if duration > 0:
            channel = LL_ADV_PRIMARY_CHANNELS[total % len(LL_ADV_PRIMARY_CHANNELS)]
            assert await tester.receive(channel, duration_us=duration) is None
        packet, _ = await _wire_event(
            link, lambda _: _data_pdu(0, 0), bad_crc=True, required=False
        )
        total += 1
        if packet:
            assert packet.phy == Phy.LE_1M
            _empty_data(packet, (0, 0))
            replies += 1
    assert total > 0 and replies * 100 >= total * 95
    event = await _observe_disconnection(
        tester, deadline - HCI_OBSERVATION_STEP_US, deadline + HCI_OBSERVATION_STEP_US
    )
    assert (event.status, event.connection_handle, event.reason) == (
        ErrorCode.SUCCESS,
        link.handle,
        ErrorCode.CONNECTION_TIMEOUT_ERROR,
    )
    await _check_rf_stopped(link)
    _no_connection_events(tester)
    assert not any(isinstance(event, hci.HCI_AclDataPacket) for event in tester.events)


async def reject_existing_connection_request(tester):
    """Reject Existing Connection Request.

    Initial Condition:
        Use legacy undirected advertising on the first primary channel, 37,
        with public own and Lower Tester addresses, selected 20-ms base interval,
        and the common IUT name as advertising data. Filter scan and connection
        requests through a Filter Accept List containing only the public peer.
        Select a 50-ms connection interval and a 1-s supervision timeout. Enable
        legacy Connection Complete while leaving forbidden CSA and advertising
        termination events observable.

    Test Steps:
        1. Configure the Lower Tester as a public initiator for the original
           connection, using a 50-ms connection interval.
        2. Enable undirected advertising on primary channel 37 with filtering
           for both scan and connection requests.
        3. Observe ADV_IND on channel 37. Check CRC, PDU length, public AdvA,
           common IUT name, and two consecutive advertising starts separated by
           the selected interval plus the permitted AdvDelay.
        4. Send CONNECT_IND at T_IFS after ADV_IND, with the public Lower Tester
           InitA, matching AdvA and a 50-ms connection interval.
        5. Require Connection Complete with the requested Peripheral role,
           public identity, interval, latency, timeout and clock accuracy;
           retain its valid connection handle.
        6. Maintain the original ACL by transmitting empty DATA and checking
           correctly formatted, positively acknowledged empty replies at T_IFS.
        7. Re-enable undirected advertising on channel 37 while maintaining
           the original ACL.
        8. Receive correctly formatted ADV_IND with the same public address
           and IUT name while servicing the existing connection events.
        9. Send another CONNECT_IND at T_IFS, using the same public peer but a
           distinct valid Access Address. Select interval=50 ms and WinSize=5 ms.
           Choose the representable WinOffset closest to a window start 25 ms
           after an original connection anchor, in units of 1.25 ms.
        10. Require no additional Connection Complete for the duplicate request.
        11. Require continued correctly formatted ADV_IND on channel 37.
        12. Send empty DATA for both event streams, each using its own Access
            Address, CRCInit, channel sequence and independently scheduled anchor.
        13. Require correctly timed, acknowledged empty replies only on the
            original ACL; require no response on any duplicate connection event.
        14. Continue Steps 12-13 for at least five seconds after the duplicate
            CONNECT_IND. Observe advertising throughout, with no additional
            connection completion, unexpected disconnection or ineligible event.

        Cleanup: disable advertising and terminate the original connection
        through HCI. Require matching completion and no late creation events.

    Expected Outcome:
        Pass verdict:
            The duplicate CONNECT_IND produces neither another Connection Complete
            nor a DATA reply on its candidate ACL. The IUT continues advertising
            and correctly acknowledges empty DATA on the original connection for
            at least five seconds while both independent streams are exercised.
        Fail verdict:
            Any DATA reply on the duplicate connection, extra connection event,
            unexpected termination, loss of the original ACL or cessation of
            advertising fails the trial.

    Source Correction:
        The first pass-verdict bullet references DATA sent in Step 11, which
        describes advertising. Interpret this as the original-ACL DATA in Step 12,
        answered in Step 13. This is a local editorial correction, not a
        published SIG erratum.

    Reference:
        LL.TS.p28.pdf, LL/CON/ADV/BI-02-C, independently titled procedure after
        Section 4.3.3.8; PDF pages 512-514, printed pages 4.3-39 through 4.3-41.
        Figure 4.3-17, Steps 1-14 and Expected Outcome. Core Vol 6, Part B,
        Section 4.5 specifies connection handling for an already connected peer.
    """
    await tester.masks(le=LEGACY_CONNECTION_EVENT_MASK)
    peer = LOWER_CENTRAL_PUBLIC_ADDRESS
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(peer.address_type, peer)
    )
    await tester.command(
        legacy_parameters(advertising_filter_policy=ADV_FILTER_ACCEPT_LIST_ONLY)
    )
    await tester.command(hci.HCI_LE_Set_Advertising_Data_Command(DEVICE_NAME))
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    packet = await _observe_advertising(tester, [], data=DEVICE_NAME)
    previous = packet
    packet = await _observe_advertising(tester, [], data=DEVICE_NAME)
    assert (
        ADV_INTERVAL_US
        <= packet.start_us - previous.start_us
        <= ADV_INTERVAL_US + LL_ADV_DELAY_MAX_US
    )
    parameters = LinkParameters(
        access_address=LOWER_DATA_ACCESS_ADDRESS,
        interval=DUPLICATE_CONN_INTERVAL,
        window_offset=DUPLICATE_CONN_INTERVAL - 1,
    )
    link = await _incoming_connection(tester, [], packet, parameters=parameters)
    await _service_peer([link])
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    packet = await _observe_advertising(tester, [link], data=DEVICE_NAME)
    end = packet.end_us + LL_IFS_US + Phy.LE_1M.airtime_us(PDU_ADV_CONNECT_SIZE)
    parameters = _interleaved_parameters(
        end,
        [link],
        LinkParameters(
            interval=DUPLICATE_CONN_INTERVAL, window_size=DUPLICATE_WINDOW_SIZE
        ),
    )
    assert parameters.access_address != link.parameters.access_address
    check_access_address(parameters.access_address)
    await tester.transmit(
        37,
        request_pdu(
            AdvertisingPduType.CONNECT_IND, scanner=peer, data=parameters.encode()
        ),
        start_us=packet.end_us + LL_IFS_US,
    )
    duplicate = PeerLink(tester, parameters, end)
    deadline = end + DUPLICATE_OBSERVATION_US
    last_advertisement = end
    observed_advertisements = 0
    while tester.radio.now_us < deadline:
        next_peer = min((link, duplicate), key=lambda value: value.anchor)
        until = min(next_peer.anchor - PEER_EXCHANGE_BUDGET_US, deadline)
        if until > tester.radio.now_us:
            packet = await tester.receive(37, duration_us=until - tester.radio.now_us)
            if packet is not None:
                _check_advertising(packet, data=DEVICE_NAME)
                last_advertisement = packet.start_us
                observed_advertisements += 1
                continue
        if tester.radio.now_us >= deadline:
            break
        if next_peer is link:
            await _service_peer([link])
        else:
            channel = duplicate.channel
            await duplicate._send(channel, b'', LlId.CONTINUATION, duplicate.anchor)
            assert (
                await tester.receive(
                    channel,
                    duration_us=LL_IFS_US
                    + Phy.LE_1M.address_us
                    + CONNECT_IFS_TOLERANCE_US,
                    **duplicate.radio_parameters,
                )
                is None
            ), 'DUT accepted the duplicate connection'
            duplicate.anchor += parameters.interval * LL_CONN_INTERVAL_UNIT_US
            duplicate.counter = duplicate.counter + 1 & LL_EVENT_COUNTER_MASK
        _no_creation_events(tester)
        assert (
            tester.radio.now_us - last_advertisement <= ADVERTISING_OBSERVATION_US
        ), 'advertising stopped after duplicate CONNECT_IND'
    assert tester.radio.now_us - last_advertisement <= ADVERTISING_OBSERVATION_US
    assert (
        observed_advertisements
        and duplicate.counter
        >= DUPLICATE_OBSERVATION_US // (parameters.interval * LL_CONN_INTERVAL_UNIT_US)
    )
    _no_creation_events(tester)

    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))
    await link.disconnect()
    _no_creation_events(tester)


async def reject_connection_request_when_connected_to_the_peer_extended_advertising(
    tester,
):
    """Reject Connection Request when Connected to the Peer, Extended Advertising.

    Initial Condition:
        Use public IUT and Lower Tester addresses, all primary channels, LE 1M
        primary/secondary PHYs, the minimum 20-ms base advertising interval,
        empty advertising data, and accept-all filtering. Select connectable
        undirected extended advertising properties 0x0001, a 30-ms connection
        interval, zero Peripheral latency, and a 1-s supervision timeout.

    Test Steps:
        1. Configure extended advertising handle 0, properties 0x0001, public own
           address, all primary channels, minimum advertising interval and
           filter policy 0x00. Require successful Command Complete.
        2. Enable the set with Duration=0 and Max_Extended_Advertising_Events=0;
           require successful Command Complete.
        3. Receive ADV_EXT_IND with connectable AdvMode, AuxPtr, and mandatory
           ADI. The source's missing ADI is corrected as described below.
        4. Follow AuxPtr to AUX_ADV_IND. Check connectable AdvMode, public AdvA,
           matching ADI, the pointed channel/PHY/offset, and T_MAFS spacing.
           Respond with AUX_CONNECT_REQ at T_IFS using the public Lower Tester
           InitA and matching IUT AdvA. The source's directed-address condition
           does not apply to the selected undirected properties 0x0001.
        5. Require AUX_CONNECT_RSP on that secondary channel at T_IFS within
           the 2-us tolerance, with valid CRC/length, correct public addresses,
           LE 1M and nonconnectable/nonscannable AdvMode.
        6. Require Connection Complete with Peripheral role, public peer identity,
           requested interval, latency, timeout, clock accuracy and valid handle.
        7. Exchange correctly formatted, acknowledged DATA using independently
           calculated CSA#2 data channels.
        8. Require one successful Advertising Set Terminated for the enabled set
           and reported connection handle. This event can already be queued
           immediately after Connection Complete. If CSA is reported, check #2.
        9. Re-enable the same set with Duration=0 and maximum event count 0;
           require successful Command Complete while maintaining the original ACL.
        10. Receive ADV_EXT_IND and AUX_ADV_IND as in Steps 3-4, servicing the
            original connection in RF gaps.
        11. Respond with another AUX_CONNECT_REQ from the same public peer,
            using a distinct valid Access Address for the candidate connection.
        12. Require no AUX_CONNECT_RSP in its response window and no additional
            connection-related HCI events.
        13. Continue acknowledged, correctly timed DATA on the original CSA#2
            connection for ten selected observation events. Require advertising
            to continue and reject duplicate or late connection-related events.

        Cleanup: disable advertising and disconnect the original ACL through
        HCI, checking the corresponding completion and absence of extra events.

    Expected Outcome:
        Pass verdict:
            The duplicate request receives no AUX_CONNECT_RSP and creates no
            additional connection. The original ACL continues exchanging valid,
            acknowledged DATA on its original channel sequence and schedule.

    Source Correction:
        Step 3 requires only AuxPtr, but Core Vol 6, Part B, Section 2.3.1.5,
        Table 2.4 requires both ADI and AuxPtr for connectable ADV_EXT_IND.
        Retain both mandatory fields. Step 5 attributes transmission of
        AUX_CONNECT_REQ to the IUT; the Lower Tester sends it in Step 4.
        These are local editorial corrections, not published SIG errata.

    Reference:
        LL.TS.p28.pdf, LL/CON/ADV/BV-26-C, independently titled procedure after
        Section 4.3.3.9; PDF pages 517-520, printed pages 4.3-44 through 4.3-47.
        Figures 4.3-19/20, Steps 1-13 and Expected Outcome. Core Vol 6, Part B,
        Sections 2.3.1.5 and 4.4.2.7 define mandatory header fields and rejection
        of connection requests from an already connected initiator.
    """
    peer = LOWER_CENTRAL_PUBLIC_ADDRESS
    await tester.command(
        extended_parameters(
            advertising_event_properties=Properties.CONNECTABLE_ADVERTISING,
            primary_advertising_channel_map=LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
        )
    )
    await tester.command(extended_enable())
    channel, advertisement = await _connectable_advertisement(tester)
    parameters = LinkParameters(access_address=LOWER_DATA_ACCESS_ADDRESS)
    end = await tester.transmit(
        channel,
        request_pdu(
            AdvertisingPduType.CONNECT_IND, scanner=peer, data=parameters.encode()
        ),
        start_us=advertisement.end_us + LL_IFS_US,
    )
    response = await tester.expect_pdu(
        channel, kind=AdvertisingPduType.AUX_CONNECT_RSP, duration_us=1000
    )
    assert abs(response.start_us - end - LL_IFS_US) <= CONNECT_IFS_TOLERANCE_US
    assert response.phy == Phy.LE_1M
    assert not response.pdu[0] & (PDU_ADV_TXADD_MASK | PDU_ADV_RXADD_MASK)
    assert (
        response.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
        == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
    )
    assert decode_extended(response.pdu) == {
        'address': bytes(DUT_ADDRESS),
        'target': bytes(peer),
        'data': b'',
    }
    link = PeerLink(tester, parameters, end, csa2=True)
    link.anchor = end + LL_CONN_AUX_WINDOW_DELAY_UNCODED_US
    await _connection_complete(tester, link, peer, extended=True)
    await _data_events(tester, link, 1, observe_advertising=True)
    await tester.command(extended_enable())
    channel, advertisement = await _connectable_advertisement(tester, link)
    other_parameters = LinkParameters()
    assert other_parameters.access_address != parameters.access_address
    check_access_address(other_parameters.access_address)
    await tester.transmit(
        channel,
        request_pdu(
            AdvertisingPduType.CONNECT_IND, scanner=peer, data=other_parameters.encode()
        ),
        start_us=advertisement.end_us + LL_IFS_US,
    )
    assert (
        await tester.receive(
            channel,
            duration_us=LL_IFS_US + Phy.LE_1M.address_us + CONNECT_IFS_TOLERANCE_US,
        )
        is None
    )
    start_counter = link.counter
    while link.counter - start_counter < MAINTAINED_EVENTS:
        await _service_peer([link])
        _no_creation_events(tester)
    await _connectable_advertisement(tester, link)
    _no_creation_events(tester)
    await tester.command(extended_enable(0))
    await link.disconnect()

    _no_creation_events(tester)


async def connection_initiation(tester):
    """Connection Initiation.

    Initial Condition:
        Start from Standby with public own/peer addresses, no Filter Accept List
        filtering, and all required HCI events enabled. Select a 30-ms scan
        interval/window, 20-ms advertising base interval, 30-ms connection interval,
        zero Peripheral latency and 1-s supervision timeout under Section 4.1.6.
        The 30-ms connection interval matches the timing example in Table 4.3-12.
        LL/CON/INI/BV-36-C selects the CSA-event-supported row of Table 4.3-11.

    Test Steps:
        1. Configure the Lower Tester to advertise on channel 37 using the common
           public Peripheral address.
        2. Start unfiltered initiation to that public peer through HCI and require
           successful Command Status.
        3. Issue LE Set Random Address while initiation is active; require Command
           Complete with Command Disallowed status 0x0C.
        4. Send ADV_IND with ChSel=0 on the selected channel at the selected
           advertising cadence plus permitted AdvDelay. Stop on CONNECT_IND,
           or fail after 4 * scanInterval + 3 * scanWindow.
        5. Receive CONNECT_IND at T_IFS within 2 us. Check CRC, length, public
           InitA/AdvA, requested interval/latency/timeout and legal Access Address.
        6. Require successful Connection Complete with Central role, matching
           public peer identity, requested connection parameters and valid handle.
        7. Require the Table 4.3-11 CSA event with that handle and algorithm #1,
           after Connection Complete.
        8. Receive the first correctly formatted DATA within the transmit window,
           including the Section 4.3.4 clock-accuracy and jitter bounds; do not
           require a single predetermined timestamp within that legal window.
        9. Reply on the same data channel at T_IFS with correct acknowledgement.
        10. Receive subsequent DATA on independently derived CSA#1 channels at
            the requested interval and reply with correct acknowledgements.
        11. Repeat until at least 100 event starts are measured. Check each
            interval and cumulative drift against Table 4.3-12's SCA limits.
        12. Terminate the connection through HCI using the Step 6 handle; require
            matching completion and no duplicate or late connection-related event.
        13. Select channel 37 and a public peer differing from the IUT address in
            the most significant octet, using the Section 4.1.5.2 XOR mask.
        14. Repeat Steps 2-12.
        15. Select channel 37 and a public peer differing in the least significant
            octet using the specified XOR mask.
        16. Repeat Steps 2-12.
        17. Select channel 37 and a public peer differing in both end octets using
            the specified XOR mask.
        18. Repeat Steps 2-12.
        19. Select channel 38 and the common public Peripheral address.
        20. Repeat Steps 2-12.
        21. Select channel 38 and the most-significant-octet address variant.
        22. Repeat Steps 2-12.
        23. Select channel 38 and the least-significant-octet address variant.
        24. Repeat Steps 2-12.
        25. Select channel 38 and the both-end-octets address variant.
        26. Repeat Steps 2-12.
        27. Select channel 39 and the most-significant-octet address variant.
        28. Repeat Steps 2-12.
        29. Select channel 39 and the least-significant-octet address variant.
        30. Repeat Steps 2-12.
        31. Select channel 39 and the both-end-octets address variant.
        32. Repeat Steps 2-12.

    Expected Outcome:
        Pass verdict:
            Every prescribed channel/address combination produces a correctly timed
            CONNECT_IND and the requested Central connection. Set Random Address
            is rejected while initiating. HCI reports the correct connection and
            CSA#1. The first DATA lies in the legal transmit window, at least 100
            event starts are measured per round, acknowledgements are valid, and
            individual intervals and cumulative drift meet the advertised SCA.
        Fail verdict:
            A connection, HCI field/order, Access Address, acknowledgement or timing
            requirement is unmet. Table 4.3-11's forbidden-CSA branch does not apply
            to the selected BV-36-C supported-event variant.

    Coverage Note:
        The source omits the channel-39/common-public-address round from its
        numbered steps although the verdict covers each channel and address.
        Exercise that additional combination without renumbering the source steps.
        The nominal 30-ms interval and 1-s timeout are explicit selected IXIT
        values under Section 4.1.6, not a decoding of the group packet examples.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.1, LL/CON/INI/BV-36-C; PDF pages 521-524,
        printed pages 4.3-48 through 4.3-51. Tables 4.3-11/12, Figure 4.3-21,
        Steps 1-32, Expected Outcome and Notes. Section 4.1.5.2 on PDF page 52
        defines the XOR address variants; Section 4.1.6 on PDF page 53 permits
        selected IXIT timings. Section 4.3.4 on PDF page 520 defines the first
        transmit-window and interval formulas.
    """
    for channel in LL_ADV_PRIMARY_CHANNELS:
        for peer in _peer_addresses():
            link = await _initiate(tester, peer, channel=channel, change_address=True)
            await _central_timing_events(tester, link, TIMING_EVENTS)
            _no_connection_events(tester)
            await link.disconnect()
            _no_connection_events(tester)


async def connecting_to_directed_advertising(tester):
    """Connecting to Directed Advertising.

    Initial Condition:
        Start from Standby with public own and common Peripheral addresses,
        no Filter Accept List filtering, and required HCI events enabled. Select
        a 30-ms scan interval/window, 30-ms connection interval, zero Peripheral
        latency and 1-s supervision timeout under Section 4.1.6.
        BV-37-C uses the CSA-event-supported row of Table 4.3-13.

    Test Steps:
        1. Configure the Lower Tester to advertise on all primary channels with
           the common public Peripheral address and at most 500 us between
           adjacent packet starts. Target the IUT's public address.
        2. Start unfiltered initiation through HCI and require successful
           Command Status.
        3. Send correctly formatted ADV_DIRECT_IND with ChSel=0. Continue until
           CONNECT_IND arrives or 4 * scanInterval + 3 * scanWindow expires.
        4. Receive CONNECT_IND at T_IFS within 2 us on the selected channel.
           Validate CRC, length, public InitA/AdvA, requested parameters and
           legal Access Address.
        5. Require Connection Complete with Central role, matching public peer
           identity, requested interval/latency/timeout and a valid handle.
        6. Require the supported CSA event after Connection Complete, with the
           Step 5 handle and algorithm #1 (value 0x00).
        7. Receive the first correctly formatted DATA within its legal transmit
           window, including clock-accuracy and jitter bounds.
        8. Reply on that channel at T_IFS with a correct acknowledgement.
        9. Receive subsequent DATA on independently derived CSA#1 channels at
           the requested interval; reply with correct acknowledgements.
        10. Continue for at least 1000 measured connection events. Check each
            interval and cumulative clock drift against the Central's SCA.
        11. Terminate through HCI using the Step 5 handle, require matching
            completion, and reject duplicate or late connection-related events.

        Repeat Steps 1-11 with advertising ChSel=1. In Step 6 require algorithm
        #2 (value 0x01), and use independently calculated CSA#2 channels in
        Steps 7-10. Measure at least 1000 events in this second round as well.

    Expected Outcome:
        Pass verdict:
            Directed advertising produces the requested Central connection in
            both rounds. HCI reports the correct identity, parameters and CSA.
            The first event is inside its legal transmit window, Access Addresses
            are valid, and at least 1000 correctly acknowledged events per round
            follow CSA#1 then CSA#2, with valid intervals and cumulative drift.
        Fail verdict:
            A request, connection, HCI field/order, Access Address, acknowledgement
            or timing requirement fails. Table 4.3-13's forbidden-CSA branch does
            not apply to the selected BV-37-C supported-event variant.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.2, LL/CON/INI/BV-37-C; PDF pages 525-527,
        printed pages 4.3-52 through 4.3-54. Table 4.3-13, Figure 4.3-22,
        Steps 1-11, the repeated ChSel=1 round and Expected Outcome. Section
        4.1.6 on PDF page 53 permits selected IXIT timings; Section 4.3.4 on
        PDF page 520 defines first-window and interval accuracy bounds.
    """
    for csa2 in (False, True):
        link = await _initiate(
            tester, LOWER_PERIPHERAL_PUBLIC_ADDRESS, directed=True, csa2=csa2
        )
        await _central_timing_events(tester, link, DIRECTED_TIMING_EVENTS)
        _no_connection_events(tester)
        await link.disconnect()
        _no_connection_events(tester)


async def connection_initiation_missed_replies(tester):
    """Connection Initiation Missed Replies.

    Initial Condition:
        Use the common public Peripheral address on selected primary channel 37,
        public IUT own address, accept-all initiation and a 30-ms scan interval
        and window. Select a 30-ms connection interval, zero Peripheral latency,
        and 100-ms supervision timeout under Section 4.1.6. Half that timeout
        precedes the six-event setup deadline. Enable Connection Complete and the
        supported CSA event selected by Table 4.3-14 for BV-38-C.

    Test Steps:
        1. Configure the Lower Tester as an advertiser on channel 37 with the
           common public Peripheral address and selected advertising data.
        2. Enable unfiltered initiation through HCI; require successful
           Command Status and the selected connection parameters.
        3. Send ADV_IND on channel 37 at the selected cadence until CONNECT_IND
           arrives or 4 * scanInterval + 3 * scanWindow expires. The ideal link
           succeeds on the first permitted advertising attempt.
        4. Receive CONNECT_IND at T_IFS, checking CRC, length, public addresses,
           legal Access Address and requested interval/latency/timeout.
        5. Require Connection Complete with Central role, the public peer,
           selected connection parameters and a valid handle.
        6. Require the supported CSA event with the Step 5 handle and algorithm
           #1, after Connection Complete.
        7. Receive the first correctly formatted DATA on its independently
           calculated channel, inside the legal first transmit window with
           clock-accuracy and jitter allowances.
        8. Do not reply initially. Continue receiving DATA on subsequent CSA#1
           channels at the requested interval until half the 100-ms supervision
           duration has elapsed since CONNECT_IND. Check unchanged SN/NESN=0,
           interval timing and clock drift while no reply is acknowledged.
        9. At the first following event, send correctly formatted DATA with a
           valid acknowledgement at T_IFS on the same channel.
        10. Continue for at least ten replied-to events, checking acknowledgements,
            PHY, channel sequence, per-event intervals and cumulative clock drift.
        11. Terminate through HCI using the Step 5 handle and require matching
            completion. Reject unexpected disconnection or late creation events.

    Expected Outcome:
        Pass verdict:
            The IUT continues transmitting before and after valid Peripheral
            replies resume, reports the requested connection, and uses a valid
            Access Address. The first event is inside its legal window; DATA
            remains correctly formatted and timed, initially unacknowledged and
            then correctly acknowledged for at least ten recovery events.
        Fail verdict:
            A required connection, HCI field/order, Access Address, DATA or timing
            condition fails. The forbidden-CSA alternative in Table 4.3-14 does
            not apply to the selected supported-event BV-38-C variant.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.3, LL/CON/INI/BV-38-C; PDF pages 527-529,
        printed pages 4.3-54 through 4.3-56. Table 4.3-14, Figure 4.3-23,
        Steps 1-11 and Expected Outcome. Section 4.1.6 on PDF page 53 permits
        selected IXIT values; Section 4.3.4 on PDF page 520 defines first-window
        and interval accuracy bounds.
    """
    link, end = await _pending_connection(
        tester,
        central=True,
        parameters=LinkParameters(timeout=LL_SUPERVISION_TIMEOUT_MIN),
    )
    _completion_events(tester, link)
    check_access_address(link.parameters.access_address)
    until = end + link.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US // 2
    await _central_timing_events(tester, link, RECOVERY_EVENTS, silent_until_us=until)
    assert _disconnected(tester) is None
    _no_connection_events(tester)
    await link.disconnect()
    _no_connection_events(tester)


async def connection_initiation_timeout(tester):
    """Connection Initiation Timeout.

    Initial Condition:
        Use the common public Peripheral address on selected primary channel 37,
        public IUT own address and accept-all initiation. Select a 30-ms scan
        interval/window and 30-ms connection interval under Section 4.1.6.
        Set zero Peripheral latency and the prescribed 100-ms supervision
        timeout. BV-39-C selects the supported-CSA row of Table 4.3-15.

    Test Steps:
        1. Configure the Lower Tester to advertise on channel 37 using the
           common public address and a selected one-octet advertising payload.
        2. Start unfiltered initiation through HCI; require successful
           Command Status and the requested connection parameters.
        3. Send ADV_IND on that channel at the selected cadence until CONNECT_IND
           arrives or 4 * scanInterval + 3 * scanWindow expires. The ideal link
           succeeds on its first permitted advertising attempt.
        4. Receive CONNECT_IND at T_IFS. Check CRC, length, public addresses,
           legal Access Address, interval, zero latency and 100-ms timeout.
        5. Require Connection Complete with Central role, matching public peer,
           requested parameters and valid handle.
        6. Require the supported CSA event after Connection Complete, with the
           Step 5 handle and algorithm #1.
        7. Receive the first correctly formatted DATA inside its legal transmit
           window, including clock-accuracy and jitter bounds.
        8. Do not reply. Receive subsequent correctly formatted DATA on the
           independently calculated CSA#1 channels. Require SN/NESN to remain
           unchanged while nothing has been acknowledged.
        9. Repeat Step 8 until setup stops. Require every initial event whose
           anchor precedes six connection intervals after CONNECT_IND, no more
           than six events, and no later RF activity after the connection is lost.
        10. Require successful Disconnection Complete with the Step 5 handle and
            Connection Failed to be Established reason 0x3E at the setup deadline.

    Expected Outcome:
        Pass verdict:
            The IUT sends the requested CONNECT_IND, transmits every required
            initial event before the six-interval setup deadline, and sends no
            more than six events. It does not resume RF after setup is lost and
            reports the matching handle and reason 0x3E through HCI. The shorter
            configured 100-ms supervision value does not replace the unestablished
            connection's six-interval deadline.
        Fail verdict:
            A required setup event is omitted, DATA resumes after RF stops, the
            IUT exceeds the setup deadline, or a connection/HCI/packet/timing
            requirement fails. The forbidden-CSA row of Table 4.3-15 is not the
            selected BV-39-C variant.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.4, LL/CON/INI/BV-39-C; PDF pages 529-531,
        printed pages 4.3-56 through 4.3-58. Table 4.3-15, Figure 4.3-24,
        Steps 1-10 and Expected Outcome. Section 4.3.4 on PDF page 520 defines
        first-window and interval bounds. Core Vol 6, Part B, Section 4.5.2
        defines the six-event establishment deadline and supervision distinction.
    """
    await _initiating_failure(tester, bad_crc=False)

    _no_connection_events(tester)


async def initiation_device_filtering_undirected(tester, *, directed):
    """Initiation Device Filtering: Undirected.

    Initial Condition:
        Use public IUT own address and channel 37. Select the same valid static
        random byte pattern as the public/random peer address IXIT, so type alone
        can change without invalidating the address syntax. Select a 30-ms scan
        interval/window, 20-ms advertising base interval, 30-ms connection interval,
        zero latency and 1-s timeout under Section 4.1.6. Table 4.3-16 selects
        ADV_IND for BV-40-C and ADV_DIRECT_IND targeting the IUT for BV-41-C.
        Both selected variants permit and require the supported CSA notification.

    Test Steps:
        1. Clear the Filter Accept List and add the selected common peer address
           with public address type.
        2. Configure the Lower Tester to advertise those same bytes with random
           address type on channel 37.
        3. Start filtered initiation through HCI with the public peer identity
           and require successful Command Status. Keep initiation active across
           both rejection trials and the subsequent matching-address trial.
        4. Select the Table 4.3-16 alternative and advertise for strictly longer
           than 4 * scanInterval + 3 * scanWindow:
           4A.1. BV-40-C sends ADV_IND with an unsigned little-endian event count.
           4B.1. BV-41-C sends ADV_DIRECT_IND targeting the public IUT address.
        5. Require no connection-related HCI event and the selected RF outcome:
           5A.1. BV-40-C receives no CONNECT_IND after any ADV_IND.
           5B.1. BV-41-C receives no CONNECT_IND after any ADV_DIRECT_IND.
        6. Change the Lower Tester to another public address not in the list.
        7. Repeat Steps 4-5 for another complete rejection window without
           cancelling or restarting the IUT's initiation procedure.
        8. Change the Lower Tester to the listed public address and public type.
        9. Select the advertising alternative until a request arrives or
           4 * scanInterval + 3 * scanWindow expires:
           9A.1. BV-40-C sends ADV_IND with the unsigned little-endian event count.
           9B.1. BV-41-C sends ADV_DIRECT_IND targeting the IUT.
        10. Require the selected RF outcome with correct public InitA and peer
            AdvA/address-type bits, valid CRC/length and legal Access Address:
            10A.1. BV-40-C receives CONNECT_IND at T_IFS after ADV_IND.
            10B.1. BV-41-C receives CONNECT_IND at T_IFS after ADV_DIRECT_IND.
        11. Require successful Connection Complete with Central role, matching
            public peer identity, requested interval/latency/timeout and handle.
        12. Require the supported CSA event after Connection Complete, with the
            Step 11 handle and algorithm #1.
        13. Verify the first DATA/acknowledgement exchange on the independently
            derived CSA#1 channel, then terminate through HCI using the Step 11
            handle. Reject duplicate or late connection-related events.
        14. Repeat Steps 1-13 with public and random peer types exchanged:
            list the random peer, reject the same bytes as public, reject another
            random address, and finally connect to the matching random identity.
            Keep the IUT's own address public in both peer-filtering rounds.

    Expected Outcome:
        Pass verdict:
            No request or completion occurs for an incorrect address type or
            unlisted address. The matching address and type produce a correctly
            timed CONNECT_IND with a valid Access Address and the requested
            Central connection. HCI reports the matching peer and CSA#1; DATA
            and clean termination succeed in both public and random rounds.
        Fail verdict:
            Any excluded peer elicits a request or connection, the listed peer
            fails to connect, or a required HCI, packet or cleanup condition fails.
            The forbidden-CSA rows of Table 4.3-16 are not the selected variants.

    Source Correction:
        Step 9's stopping reference is Step 13, which terminates an established
        connection; stop advertising when CONNECT_IND is received in Step 10.
        Step 13's handle is reported in Step 11, not Step 4. The verdict's
        advertising-address wording refers to the advertiser, not the initiator.
        These are local editorial corrections, not published SIG errata.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.5, LL/CON/INI/BV-40-C and
        LL/CON/INI/BV-41-C; PDF pages 531-535, printed pages 4.3-58 through
        4.3-62. Table 4.3-16, Figure 4.3-25, Steps 1-14 including all A/B
        alternatives and Expected Outcome. Section 4.1.6 on PDF page 53 permits
        selected IXIT timings and peer address values.
    """
    for address_type in (hci.AddressType.PUBLIC_DEVICE, hci.AddressType.RANDOM_DEVICE):
        peer = hci.Address(bytes(PEER_ADDRESS), address_type)
        await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
        await tester.command(
            hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(address_type, peer)
        )
        await tester.command(
            create_connection(
                peer_address=peer,
                peer_address_type=address_type,
                initiator_filter_policy=1,
            )
        )
        for excluded in (
            hci.Address(bytes(peer), 1 - address_type),
            hci.Address('C0:55:66:77:88:99', address_type),
        ):
            await _advertise_connection(
                tester, excluded, directed=directed, reject=True
            )
        link = await _advertise_connection(tester, peer, directed=directed)
        await _central_timing_events(tester, link, 1)
        _no_connection_events(tester)
        await link.disconnect()
        _no_connection_events(tester)


async def extended_scanning_connection_initiation(tester, *, phy):
    """Extended Scanning, Connection Initiation.

    Initial Condition:
        Use public IUT and common Peripheral addresses without filtering.
        Select a 30-ms connection interval, zero latency, 1-s supervision timeout,
        20-ms advertising base interval plus seeded AdvDelay, and a 10-ms scan
        interval/window (HCI 0x0010) under Section 4.1.6. Table 4.3-22 selects:
        BV-13-C: initiating LE 1M, primary LE 1M, secondary LE 1M;
        BV-25-C: initiating LE 1M, primary LE 1M, secondary LE 2M;
        BV-26-C: initiating LE Coded, primary LE Coded, secondary LE Coded.
        These three selected cases all use ADV_EXT_IND, not decision PDUs.

    Test Steps:
        1. Set Decision Instructions only for Table 4.3-22 decision-PDU cases.
           This step does not apply to the three selected ADV_EXT_IND variants.
        2. Send Extended Create Connection with the selected initiating PHY bit,
           Scan_Interval[0]=Scan_Window[0]=0x0010, filter policy 0x00, public own
           address, matching public peer and selected connection parameters.
           Require successful Command Status.
        3. Advertise ADV_EXT_IND on the selected primary PHY with ADI and an
           AuxPtr pointing to connectable AUX_ADV_IND on the selected secondary
           PHY. Include public AdvA and matching ADI. Decision flags/data are
           not applicable to these selected variants.
        4. Receive AUX_CONNECT_REQ on that secondary channel and PHY at T_IFS
           within 2 us. Check CRC, length, public InitA/AdvA, requested connection
           parameters and valid Access Address, including Coded-specific rules.
        5. Send correctly addressed AUX_CONNECT_RSP on the secondary channel
           and PHY at T_IFS after AUX_CONNECT_REQ.
        6. Require Enhanced Connection Complete with Central role, public peer,
           zero local/peer RPAs, requested interval/latency/timeout and valid
           handle, immediately followed by CSA#2 for the same handle.
        7. Receive the first valid DATA on the independently calculated CSA#2
           channel inside its legal transmit window measured from AUX_CONNECT_REQ.
           Include the 2.5-ms uncoded or 3.75-ms Coded transmit-window delay,
           WinOffset, WinSize, clock-accuracy and jitter allowances.
        8. Reply on the same channel and PHY at T_IFS with a correct acknowledgement.
        9. Receive subsequent correctly formatted DATA on independently derived
           CSA#2 channels at the requested interval; reply with acknowledgements.
        10. Continue until 100 event starts have been measured. Check selected
            PHY, valid CRC/LLID, ARQ, individual intervals and cumulative drift
            against Table 4.3-23 and the Central's SCA.
        11. Terminate through HCI with the Step 6 handle, require matching
            completion and reject duplicate or late connection-related events.
        12. Repeat Steps 2-11, but do not answer the first AUX_CONNECT_REQ in
            Step 5. Continue advertising and require a second correctly timed
            request following backoff before sending AUX_CONNECT_RSP. Forbid
            premature completion or failure while the first request is unanswered.

    Expected Outcome:
        Pass verdict:
            In both rounds the IUT sends a correctly timed AUX_CONNECT_REQ with
            a valid Access Address, reports the requested Enhanced Connection
            Complete immediately followed by CSA#2, and maintains 100 correctly
            acknowledged events on the selected PHY. The first event is in its
            legal transmit window; per-event intervals and accumulated drift meet
            the SCA limits. An unanswered request is followed by a valid retry.

    Source Correction:
        Step 5 describes the Lower Tester sending AUX_CONNECT_RSP "from the IUT".
        It is the Lower Tester's response to the IUT request received in Step 4.
        This is a local editorial correction, not a published SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.11, LL/CON/INI/BV-13-C,
        LL/CON/INI/BV-25-C and LL/CON/INI/BV-26-C; PDF pages 549-552,
        printed pages 4.3-76 through 4.3-79. Tables 4.3-22/23, Figure 4.3-31,
        Steps 1-12, Expected Outcome and Notes. Section 4.3.4 on PDF page 520
        defines first-window timing; Core Vol 6, Part B, Sections 4.4.4.2 and
        4.5.3 define unanswered-request backoff and PHY-specific window delays.
    """
    for retry in (False, True):
        link = await _initiate_auxiliary(tester, phy=phy, retry=retry)
        await _central_timing_events(
            tester,
            link,
            TIMING_EVENTS,
            window_delay_us=(
                LL_CONN_AUX_WINDOW_DELAY_CODED_US
                if phy == Phy.LE_CODED
                else LL_CONN_AUX_WINDOW_DELAY_UNCODED_US
            ),
        )
        _no_connection_events(tester)
        await link.disconnect()
        _no_connection_events(tester)


async def connection_initiation_channel_selection_algorithm_1(tester, *, directed):
    """Connection Initiation, Channel Selection Algorithm #1.

    Initial Condition:
        Use public IUT and common Peripheral addresses with accept-all initiation.
        Select 30-ms scan interval/window and connection interval, zero Peripheral
        latency and 1-s supervision timeout under Section 4.1.6. Table 4.3-24
        selects ADV_IND for BV-14-C or ADV_DIRECT_IND targeting the IUT for
        BV-15-C. Use the selected advertising cadence and enable the required
        connection and Channel Selection Algorithm events.

    Test Steps:
        1. Send LE Create Connection with filter policy 0x00, matching public peer
           address/type and selected connection parameters. Require successful
           Command Status.
        2. Execute the Table 4.3-24 advertising alternative:
           2A.1. BV-14-C sends ADV_IND with ChSel=0.
           2A.2. Receive CONNECT_IND with ChSel=0 or 1 at T_IFS after ADV_IND.
           2B.1. BV-15-C sends ADV_DIRECT_IND with ChSel=0, targeting the IUT.
           2B.2. Receive CONNECT_IND with ChSel=0 or 1 at T_IFS after ADV_DIRECT_IND.
           Check request CRC, length, public InitA/AdvA and address-type bits,
           selected interval/latency/timeout and valid Access Address.
        3. Require successful Connection Complete with Central role, matching
           public peer identity, requested parameters and valid handle. Immediately
           afterward require the same handle and algorithm #1 in the CSA event.
        4. Receive the first correctly formatted DATA inside its legal transmit
           window, including WinOffset, WinSize, clock accuracy and jitter, on
           the independently derived CSA#1 channel.
        5. Send a correctly formatted reply on the same channel at T_IFS using
           the acknowledgement scheme.
        6. Receive subsequent DATA at connection intervals on independently
           calculated CSA#1 channels, and reply with correct acknowledgements.
        7. Continue until at least 100 event starts have been measured. Check PHY,
           CRC, valid LLID, ARQ, each interval and cumulative SCA drift against
           Table 4.3-25; do not prescribe one exact legal first-event timestamp.
        8. Terminate through HCI using the Step 3 handle and require matching
           completion. Reject duplicate or late connection-related HCI events.

    Expected Outcome:
        Pass verdict:
            The IUT sends CONNECT_IND at T_IFS within 2 us, uses a legal Access
            Address, and reports the requested Central connection immediately
            followed by CSA#1. At least 100 correctly acknowledged DATA events
            use CSA#1 channels, begin inside the legal first window, and satisfy
            the selected PHY, interval tolerance and cumulative clock-drift bound.

    Source Correction:
        Step 8 refers to a connection handle from Step 4, which receives DATA.
        Use the handle reported in Step 3. This is a local editorial correction,
        not a published SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.12, LL/CON/INI/BV-14-C and
        LL/CON/INI/BV-15-C; PDF pages 553-556, printed pages 4.3-80 through
        4.3-83. Tables 4.3-24/25, Figure 4.3-32, Steps 1-8 including
        alternatives 2A/2B, Expected Outcome and Notes. Section 4.3.4 on PDF
        page 520 defines first-window and interval formulas; Section 4.1.6 on
        PDF page 53 permits the selected IXIT timings.
    """
    link = await _initiate(
        tester, LOWER_PERIPHERAL_PUBLIC_ADDRESS, directed=directed, csa2=False
    )
    await _central_timing_events(tester, link, TIMING_EVENTS)
    _no_connection_events(tester)
    await link.disconnect()
    _no_connection_events(tester)


async def connection_initiation_channel_selection_algorithm_2(tester, *, directed):
    """Connection Initiation, Channel Selection Algorithm #2.

    Initial Condition:
        Use public IUT and common Peripheral addresses with accept-all initiation.
        Select 30-ms scan interval/window and connection interval, zero Peripheral
        latency and 1-s supervision timeout under Section 4.1.6. Table 4.3-26
        selects ADV_IND for BV-16-C or ADV_DIRECT_IND targeting the IUT for
        BV-17-C. Use the selected advertising cadence and enable the required
        connection and Channel Selection Algorithm events.

    Test Steps:
        1. Send LE Create Connection with filter policy 0x00, matching public peer
           address/type and selected connection parameters. Require successful
           Command Status.
        2. Execute the Table 4.3-26 advertising alternative:
           2A.1. BV-16-C sends ADV_IND with ChSel=1.
           2A.2. Receive CONNECT_IND with ChSel=1 at T_IFS after ADV_IND.
           2B.1. BV-17-C sends ADV_DIRECT_IND with ChSel=1, targeting the IUT.
           2B.2. Receive CONNECT_IND with ChSel=1 at T_IFS after ADV_DIRECT_IND.
           Check request CRC, length, public InitA/AdvA and address-type bits,
           selected interval/latency/timeout and valid Access Address.
        3. Require successful Connection Complete with Central role, matching
           public peer identity, requested parameters and valid handle. Immediately
           afterward require the same handle and algorithm #2 in the CSA event.
        4. Receive the first correctly formatted DATA inside its legal transmit
           window, including WinOffset, WinSize, clock accuracy and jitter, on
           the independently derived CSA#2 channel.
        5. Send a correctly formatted reply on the same channel at T_IFS using
           the acknowledgement scheme.
        6. Receive subsequent DATA at connection intervals on independently
           calculated CSA#2 channels, and reply with correct acknowledgements.
        7. Continue until at least 100 event starts have been measured. Check PHY,
           CRC, valid LLID, ARQ, each interval and cumulative SCA drift against
           Table 4.3-27; do not prescribe one exact legal first-event timestamp.
        8. Terminate through HCI using the Step 3 handle and require matching
           completion. Reject duplicate or late connection-related HCI events.

    Expected Outcome:
        Pass verdict:
            The IUT sends CONNECT_IND at T_IFS within 2 us, uses a legal Access
            Address, and reports the requested Central connection immediately
            followed by CSA#2. At least 100 correctly acknowledged DATA events
            use CSA#2 channels, begin inside the legal first window, and satisfy
            the selected PHY, interval tolerance and cumulative clock-drift bound.

    Source Correction:
        Step 8 refers to a connection handle from Step 4, which receives DATA.
        Use the handle reported in Step 3. This is a local editorial correction,
        not a published SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.13, LL/CON/INI/BV-16-C and
        LL/CON/INI/BV-17-C; PDF pages 556-559, printed pages 4.3-83 through
        4.3-86. Tables 4.3-26/27, Figure 4.3-33, Steps 1-8 including
        alternatives 2A/2B, Expected Outcome and Notes. Section 4.3.4 on PDF
        page 520 defines first-window and interval formulas; Section 4.1.6 on
        PDF page 53 permits the selected IXIT timings.
    """
    link = await _initiate(
        tester, LOWER_PERIPHERAL_PUBLIC_ADDRESS, directed=directed, csa2=True
    )
    await _central_timing_events(tester, link, TIMING_EVENTS)
    _no_connection_events(tester)
    await link.disconnect()
    _no_connection_events(tester)


async def connection_initiation_invalid_crc(tester):
    """Connection Initiation Invalid CRC.

    Initial Condition:
        Use public IUT and common public Peripheral addresses on selected primary
        channel 37, with no Filter Accept List filtering. Select a 30-ms scan
        interval/window and 20-ms advertising base interval plus seeded AdvDelay.
        Use valid selected connection parameters; their values are not material
        to this no-connection verdict. Corrupt each advertising CRC by inverting
        all checksum bits as specified in Section 4.1.5.1.

    Test Steps:
        1. Configure the Lower Tester to advertise the common public Peripheral
           address on channel 37 with the selected advertising data and interval.
        2. Start unfiltered initiation to that public peer through HCI and require
           successful Command Status.
        3. Send ADV_IND with an invalid CRC on channel 37 every selected
           advertising interval plus AdvDelay, continuing strictly beyond
           4 * scanInterval + 3 * scanWindow.
        4. Listen after every packet and require no CONNECT_IND at T_IFS and no
           premature Connection Complete, CSA or disconnection event.
        5. Send LE Create Connection Cancel, require successful Command Complete,
           then require the cancellation Connection Complete with Unknown
           Connection Identifier status 0x02. Reject extra connection events.

    Expected Outcome:
        Pass verdict:
            No invalid-CRC advertising packet produces a connection request or
            connection. Initiation remains pending for the full observation window
            and is stopped through the expected HCI cancellation completions.

    Reference:
        LL.TS.p28.pdf, LL/CON/INI/BI-01-C, independently titled procedure after
        Section 4.3.4.16; PDF pages 566-567, printed pages 4.3-93 through 4.3-94.
        Figure 4.3-37, Steps 1-5 and Expected Outcome. Section 4.1.5.1 on PDF
        page 52 defines invalid CRC; Core Vol 4, Part E defines Create Connection
        Cancel command completion and cancellation Connection Complete status.
    """
    await tester.command(
        create_connection(
            peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
            peer_address_type=hci.AddressType.PUBLIC_DEVICE,
            le_scan_interval=ESTABLISHMENT_SCAN_INTERVAL,
            le_scan_window=ESTABLISHMENT_SCAN_INTERVAL,
        )
    )
    interval_us = ESTABLISHMENT_SCAN_INTERVAL * hci.HCI_LE_SCAN_INTERVAL_UNIT_US
    deadline = tester.radio.now_us + 4 * interval_us + 3 * interval_us
    generator = random.Random(0)
    while True:
        advertised = tester.radio.now_us + 100
        await tester.transmit(
            37,
            adv_pdu(address=LOWER_PERIPHERAL_PUBLIC_ADDRESS),
            start_us=advertised,
            bad_crc=True,
        )
        assert await tester.receive(37, duration_us=1000) is None
        _no_initiation_complete(tester)
        if advertised > deadline:
            break
        next_event = (
            advertised + ADV_INTERVAL_US + generator.randrange(LL_ADV_DELAY_MAX_US + 1)
        )
        await tester.wait(next_event - tester.radio.now_us)
    await tester.command(hci.HCI_LE_Create_Connection_Cancel_Command())
    event = await tester.event(hci.HCI_LE_Connection_Complete_Event)
    assert event.status == ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR

    _no_initiation_complete(tester)


async def peripheral_packets_invalid_crc(tester):
    """Peripheral Packets Invalid CRC.

    Initial Condition:
        Use public IUT and common Peripheral addresses, selected primary channel
        37, accept-all initiation, and a 30-ms scan interval/window and connection
        interval. Set zero Peripheral latency and the prescribed 100-ms timeout.
        Advertise one data octet. BV-04-C selects the supported-CSA row of Table
        4.3-31. Invert all CRC bits in every Peripheral DATA reply.

    Test Steps:
        1. Configure the Lower Tester as a public advertiser on channel 37.
        2. Send LE Create Connection through HCI with the selected parameters;
           require successful Command Status.
        3. Send ADV_IND with one data octet and receive CONNECT_IND at T_IFS.
           The source allows advertising until the scan deadline or four attempts;
           the ideal link takes the first successful attempt. Check request CRC,
           length, addresses/type bits, legal Access Address and parameters.
        4. Require Connection Complete with Central role, matching public peer,
           selected interval/latency/timeout and valid connection handle.
        5. Require the supported CSA event after Connection Complete with the
           Step 4 handle and algorithm #1.
        6. Receive the first correctly formatted DATA within its legal transmit
           window, including clock-accuracy and jitter bounds.
        7. Perform the source substeps:
           a) Reply on the same channel at T_IFS with a correctly formatted,
              acknowledging DATA PDU but inverted CRC. If the IUT transmits a
              second DATA PDU in this event, reply with the same invalid-CRC fault.
           b) Receive correctly formatted DATA on the next independently derived
              CSA#1 channel at the requested interval with permitted clock drift.
           c) Send another correctly formatted acknowledging reply at T_IFS,
              again with an invalid CRC.
           d) If another DATA PDU occurs in this same event, validate its timing
              and send a correctly formatted invalid-CRC acknowledgement.
        8. First permitted alternative: repeat Steps 7b-7c until supervision
           expires. This no-second-PDU-observation alternative is not selected.
        9. OR, as the source's alternative separator states.
        10. Selected alternative: repeat Steps 7b-7d until supervision expires.
            Check unchanged IUT SN/NESN, correct DATA/PHY and interval/cumulative
            timing. Never send CRC-valid DATA that could reset supervision.
        11. Require successful Disconnection Complete with the Step 4 handle and
            Connection Timeout reason 0x08 at the original 100-ms deadline,
            within the 1-ms HCI observation resolution.

        Cleanup: probe subsequent connection windows for stopped RF and reject
        extra connection-related HCI events.

    Expected Outcome:
        Pass verdict:
            The requested connection is created with a valid Access Address. The
            Central continues correctly timed DATA without acknowledging corrupted
            replies and terminates at the original supervision deadline with the
            correct handle and Connection Timeout reason. Invalid CRC reception
            establishes the physical connection but cannot refresh supervision.
        Fail verdict:
            A request, connection, HCI field/order, DATA, acknowledgement or timing
            condition fails. The forbidden-CSA row of Table 4.3-31 is not the
            selected BV-04-C variant.

    Source Correction:
        Step 11 references a handle from Step 7; the handle is reported in
        Step 4. This is a local editorial correction, not a published SIG erratum.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.17, LL/CON/INI/BI-04-C; PDF pages 568-570,
        printed pages 4.3-95 through 4.3-97. Table 4.3-31, Figure 4.3-38,
        Steps 1-11 including substeps 7a-7d and alternatives 8-10, and Expected
        Outcome. Core Vol 6, Part B, Sections 4.5 and 4.5.2 distinguish physical
        establishment from valid-CRC supervision reset.
    """
    await _initiating_failure(tester, bad_crc=True)

    _no_connection_events(tester)


async def connection_initiation_with_valid_access_address(tester):
    """Connection Initiation with Valid Access Address.

    Initial Condition:
        Use public IUT and common Peripheral addresses with accept-all initiation
        on selected primary channel 37. Select 30-ms scan interval/window and
        connection interval, zero Peripheral latency, 1-s timeout, and 20-ms
        advertising base interval plus AdvDelay under Section 4.1.6. Keep the
        same Controller instance without resetting it between the 36 connections.
        BV-50-C selects the supported-CSA row of Table 4.3-33.

    Test Steps:
        1. Configure the Lower Tester to advertise the common public Peripheral
           address on selected primary channel 37.
        2. Enable unfiltered initiation through HCI and require successful
           Command Status with the selected connection parameters.
        3. Send ADV_IND and receive CONNECT_IND at T_IFS within 2 us. Check
           CRC, length, public addresses/type bits, connection parameters and
           every Access Address constraint; retain the generated address.
        4. Require successful Connection Complete with Central role, matching
           public peer identity, requested parameters and valid handle.
        5. Require the supported CSA event immediately after Connection Complete,
           with the Step 4 handle and algorithm #1.
        6. Send Disconnect for that connection handle through HCI and require
           successful Command Status.
        7. Require the matching successful Disconnection Complete, with no
           duplicate or late connection-related events.
        8. Repeat Steps 1-7 another 35 times. Require all 36 Access Addresses to
           be unique and each of their 32 bit positions to contain at least
           three zeros and at least three ones across the full sample.

    Expected Outcome:
        Pass verdict:
            Every CONNECT_IND contains a legal Access Address; all 36 addresses
            are distinct; and every bit position meets the three-zero/three-one
            requirement. The requested connections, matching HCI notifications,
            CSA#1 selection and clean termination succeed in each round.
        Fail verdict:
            Any address or bit-diversity condition fails, or a required HCI or
            packet condition is unmet. The forbidden-CSA row of Table 4.3-33 is
            not the selected supported-event BV-50-C variant.

    Reference:
        LL.TS.p28.pdf, Section 4.3.4.19, LL/CON/INI/BV-50-C; PDF pages 575-577,
        printed pages 4.3-102 through 4.3-104. Table 4.3-33, Figure 4.3-41,
        Steps 1-8 and Expected Outcome. Core Vol 6, Part B, Section 2.1.2
        defines Access Address constraints.
    """
    addresses = []
    for _ in range(ACCESS_ADDRESS_ROUNDS):
        link = await _initiate(tester, LOWER_PERIPHERAL_PUBLIC_ADDRESS)
        addresses.append(link.parameters.access_address)
        _no_connection_events(tester)
        await link.disconnect()
        _no_connection_events(tester)
    _check_access_address_set(addresses)


async def parallel_connection_requests_incoming_connect_indication_first(tester):
    """Parallel connection requests, incoming connect indication first.

    Initial Condition:
        The IUT is in Standby. Mask Enhanced Connection Complete while leaving
        legacy completion and CSA events enabled. Use public LT1/LT2 addresses,
        selected scan timing, and common connection/channel-selection parameters.

    Test Steps:
        1. Configure LT2 to monitor IUT advertising packets.
        2. Send LE Create Connection targeting LT1, with filter policy 0 and
           valid parameters; require successful Command Status.
        3. Set legacy advertising type 0x01 (high-duty directed), filter policy
           0, and LT2 peer address/type; require successful Command Complete.
        4. Enable advertising; require successful Command Complete.
        5. Receive ADV_DIRECT_IND targeting LT2. Require ChSel=1 for this
           CSA2-capable advertiser, applying the Source Correction below.
        6. LT2 sends CONNECT_IND with ChSel=0 at T_IFS after the advertisement.
        7. After Step 6, require successful legacy Connection Complete with LT2
           address/type, Peripheral role, and a valid connection handle.
        8. LT1 sends ADV_IND packets with ChSel=0 to the still-initiating IUT.
        9. Receive the IUT CONNECT_IND to LT1; validate addresses, parameters,
           Access Address and T_IFS, independently of the incoming connection.
        10. Require successful legacy Connection Complete identifying LT1,
            Central role, and a valid handle distinct from the Peripheral handle.
        11. For BV-51-C, require the Central completion to be immediately followed
            by a matching-handle CSA event with algorithm value 0 (CSA #1).

    Expected Outcome:
        Pass verdict:
            Steps 7 and 10 complete in the prescribed order with correct public
            peers, roles, handles, and connection parameters. The pending LT1
            initiation survives LT2 establishment and both ACLs remain usable.
        Fail verdict:
            Advertising Set Terminated is emitted for legacy advertising after
            Step 6, or a CSA event identifies the Peripheral handle from Step 7.

    Source Correction:
        PDF 578 Step 5 says advertiser ChSel=0. Core 6.3 Vol 6, Part B,
        Section 2.3.1.2 mandates ChSel=1 when the advertiser supports CSA #2;
        Amber corroborates this local correction. Preserve Step 6 ChSel=0,
        selecting CSA #1, and the source prohibition on Peripheral CSA events.
        This is a local source interpretation, not a published SIG erratum.

    Coverage Note:
        Maintain at least ten independently hopped, acknowledged empty DATA
        events per ACL and reject extra creation/termination events. The fixture
        closes both links after the normative observations.

    Reference:
        LL.TS.p28, Section 4.3.4.20, Table 4.3-34, Figure 4.3-42;
        LL/CON/INI/BV-51-C; PDF 577-579, printed 4.3-104 through 4.3-106.
    """
    await _parallel_connections(tester, incoming_first=True)


async def parallel_connection_requests_outgoing_connection_request_first(tester):
    """Parallel connection requests, outgoing connection request first.

    Initial Condition:
        The IUT is in Standby. Mask Enhanced Connection Complete, leaving legacy
        completion and CSA events enabled. Use public LT1/LT2 peers, selected scan
        timing, and common connection/channel-selection parameters.

    Test Steps:
        1. Configure LT2 to monitor IUT advertising packets.
        2. Send LE Create Connection for LT1 with filter policy 0 and valid
           parameters; require successful Command Status.
        3. Set legacy advertising type 0x00 (undirected), filter policy 0, and
           valid remaining parameters; require successful Command Complete.
        4. Set advertising data length 2 and exact bytes 0F 0F; require success.
        5. Enable advertising; require successful Command Complete.
        6. Receive IUT ADV_IND packets at LT2, checking public AdvA and data.
        7. LT1 sends ADV_IND packets with ChSel=0 to the IUT.
        8. Receive the IUT CONNECT_IND to LT1; validate addresses, Access
           Address, parameters, and T_IFS after the LT1 advertisement.
        9. Require successful legacy Connection Complete with LT1 address/type,
           Central role, and a valid connection handle.
        10. For BV-52-C, require the immediate matching-handle CSA event with
            algorithm value 0 (CSA #1).
        11. Observe continued IUT ADV_IND packets while maintaining the LT1 ACL.
        12. After LT2 receives five advertisements following outgoing completion,
            send CONNECT_IND with ChSel=0 at T_IFS after the fifth ADV_IND.
        13. Require successful legacy Connection Complete with LT2 address/type,
            Peripheral role, and a valid handle distinct from the Central handle.

    Expected Outcome:
        Pass verdict:
            Steps 9 and 13 identify the correct peers, roles and valid handles.
            Advertising continues after outgoing completion as required in
            Step 11, including the five packets before LT2 connects.
        Fail verdict:
            Advertising Set Terminated is emitted for legacy advertising after
            Step 12, or a CSA event identifies the Peripheral handle from Step 13.

    Coverage Note:
        Check full connection timing/clock fields, maintain at least ten empty
        DATA events per ACL with independent hopping and ACK state, and reject
        extra creation/termination events. The fixture then closes both links.

    Reference:
        LL.TS.p28, Section 4.3.4.21, Table 4.3-35, Figure 4.3-43;
        LL/CON/INI/BV-52-C; PDF 579-581, printed 4.3-106 through 4.3-108.
    """
    await _parallel_connections(tester, incoming_first=False)


async def duplicate_connection_request(tester):
    """Duplicate Connection Request.

    Initial Condition:
        Initiating with selected scan interval/window, no Filter Accept List,
        public Lower Tester peer, supported own address type, and common
        connection interval, Peripheral latency, timeout and channel parameters.

    Test Steps:
        1. Configure the Lower Tester for connectable undirected advertising on
           all three primary advertising channels.
        2. Send LE Create Connection for that public peer and require successful
           Command Status.
        3. Send ADV_IND at the selected advertising interval on each event.
        4. Receive CONNECT_IND at T_IFS after an ADV_IND; validate its addresses,
           Access Address and connection parameters.
        5. Require successful Connection Complete with the Lower Tester peer
           address, selected interval, Central role, and valid connection handle.
        6. For BI-05-C, require an immediate matching-handle CSA event with
           algorithm value 0 (CSA #1).
        7. Maintain the connection by answering IUT DATA with correctly sequenced
           empty DATA at T_IFS on the same data channel.
        8. Continue ADV_IND on every primary channel, listening for CONNECT_IND
           at T_IFS after each advertisement.
        9. Send a second LE Create Connection for the same peer address/type.
        10. Continue correctly timed DATA replies and Step 8 advertising for at
            least five seconds after the Step 11 response, preserving the ACL.
        11. Accept exactly one of the following response alternatives:
            11A.1. Command Status reports Connection Already Exists (0x0B).
            11B.1. Command Status reports success (0x00).
            11B.2. Connection Complete reports Connection Already Exists (0x0B).
            11C.1. Command Status reports success without Connection Complete.
            11C.2. After five seconds, send LE Create Connection Cancel.
            11C.3. Require successful Command Complete, followed by Connection
                   Complete with Unknown Connection Identifier (0x02).

    Expected Outcome:
        Pass verdict:
            The IUT follows alternative 11A, 11B or 11C with the specified status
            and event ordering while maintaining the original ACL.
        Fail verdict:
            Any CONNECT_IND is sent to the existing peer after Step 5, or the
            original connection is not maintained. Table 4.3-36 permits the
            initial CSA event for the selected BI-05-C variant; no duplicate
            connection or extra CSA/advertising-termination event is permitted.

    Source Correction:
        Step 11's introductory sentence mentions only alternatives 11A/11B,
        although the same step and pass verdict explicitly include 11C. Preserve
        all three alternatives. The purpose calls the IUT Peripheral, but it is
        the initiator/Central; the Lower Tester supplies Peripheral responses.

    Coverage Note:
        Repeat advertising with seeded 20-ms plus advertising-delay cadence
        during establishment. Maintain positive DATA ACKs during the five-second
        duplicate-request observation and disconnect the original link via HCI.

    Reference:
        LL.TS.p28, Section 4.3.4.22, Table 4.3-36, Figure 4.3-44;
        LL/CON/INI/BI-05-C; PDF 582-585, printed 4.3-109 through 4.3-112.
    """
    peer = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    link = await _initiate(tester, peer, channel=None)
    complete_types = (
        hci.HCI_LE_Connection_Complete_Event,
        hci.HCI_LE_Enhanced_Connection_Complete_Event,
    )

    async def advertising_cycle():
        for channel in LL_ADV_PRIMARY_CHANNELS:
            await tester.transmit(channel, adv_pdu(address=peer))
            assert (
                await tester.receive(
                    channel,
                    duration_us=LL_IFS_US
                    + Phy.LE_1M.address_us
                    + CONNECT_IFS_TOLERANCE_US,
                )
                is None
            ), 'second CONNECT_IND sent for an existing ACL'

    async def connection_event():
        previous_sn = link.sn
        packet = await link.exchange()
        if link.counter > 1:
            assert bool(packet.pdu[0] & PDU_DATA_NESN_MASK) != bool(
                previous_sn
            ), 'original ACL stopped acknowledging peer DATA'

    await connection_event()
    await advertising_cycle()
    status = await tester.command(
        create_connection(peer_address=peer, peer_address_type=peer.address_type),
        status=(ErrorCode.SUCCESS, ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR),
    )
    deadline = tester.radio.now_us + DUPLICATE_OBSERVATION_US
    rejected = status.status == ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR
    while tester.radio.now_us < deadline:
        await connection_event()
        await advertising_cycle()
        while completion := tester.take(
            lambda event: isinstance(event, complete_types)
        ):
            assert not rejected, 'unexpected additional connection completion'
            assert completion.status == ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR
            rejected = True
            deadline = tester.radio.now_us + DUPLICATE_OBSERVATION_US
        assert not any(
            isinstance(
                event,
                (
                    hci.HCI_Disconnection_Complete_Event,
                    hci.HCI_LE_Channel_Selection_Algorithm_Event,
                    hci.HCI_LE_Advertising_Set_Terminated_Event,
                ),
            )
            for event in tester.events
        ), 'original ACL lost or duplicate connection reported'
    if not rejected:
        await tester.wait(0)
        command = hci.HCI_LE_Create_Connection_Cancel_Command()
        tester.send(bytes(command))
        event = await tester.expect(
            lambda event: isinstance(
                event, (hci.HCI_Command_Complete_Event, *complete_types)
            )
        )
        assert isinstance(event, hci.HCI_Command_Complete_Event)
        assert event.command_opcode == command.op_code
        assert event.num_hci_command_packets == 1
        assert event.return_parameters.status == ErrorCode.SUCCESS
        event = await tester.event(hci.HCI_LE_Connection_Complete_Event)
        assert event.status == ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
    _no_creation_events(tester)
    await link.disconnect()
    _no_creation_events(tester)


async def peripheral_asymmetric_connections(tester):
    """Peripheral Asymmetric Connections.

    Initial Condition:
        An unencrypted connected Peripheral with public address, common channel
        parameters, latency 5 and supervision timeout 200 ms. Select a 7.5-ms
        common interval, satisfying timeout > 2 * (latency + 1) * interval.
        The Lower Tester acts as Central and tracks DATA SN/NESN independently.

    Test Steps:
        1. Send LE Read Buffer Size and require successful Command Complete with
           usable LE ACL packet length and packet count.
        2. Optionally send Read Buffer Size. Omit this optional command because
           Step 1 reports usable dedicated LE buffers.
        3. Repeat Steps 3-5 for thirty consecutive connection events. Send one
           DATA PDU per interval with nonempty payload, following the common
           channel selection and advancing SN/NESN only after valid ACKs.
        4. For each successfully acknowledged payload, require an HCI ACL Data
           packet with the connection handle, exact payload, and first-fragment
           PB flag; reject incorrect length or broadcast flags.
        5. Receive the empty Peripheral response at T_IFS after the sent packet.
           Require SN matching current NESN and NESN acknowledging the next SN.
           Missing RF responses do not advance the peer acknowledgement state.
        6. Execute Peripheral Connection Terminated for the established handle
           and connection parameters; require HCI termination completion.

    Expected Outcome:
        Pass verdict:
            The Peripheral responds in at least five of the thirty events, with
            correct DATA acknowledgement, packet timing and Host data delivery.

    Coverage Note:
        The source response threshold assumes BER no worse than 0.1 percent.
        This deterministic trial injects no bit errors; valid received packets
        must satisfy the packet/ACK assertions. Optional Step 2 is not selected.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-02-C procedure in
        Section 4.3.5, Figure 4.3-47; PDF 592-593, printed 4.3-119 through 4.3-120.
    """
    link = await establish(
        tester,
        central=False,
        peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
        interval=6,
        latency=5,
        timeout=20,
    )
    capacity = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
    assert capacity.le_acl_data_packet_length and capacity.total_num_le_acl_data_packets
    responses = 0
    for _ in range(30):
        sent_sn = link.sn
        expected_sn = link.nesn
        packet, _sent = await _wire_event(
            link,
            lambda _: _data_pdu(link.sn, link.nesn, ARQ_PAYLOAD, llid=LlId.START),
            required=False,
        )
        if packet:
            assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTINUATION
            assert len(packet.pdu) == PDU_HEADER_SIZE and packet.pdu[1] == 0
            assert _sequence_bits(packet) == (expected_sn, sent_sn ^ 1)
            link._accept(packet)
            responses += 1
            event = await tester.event(hci.HCI_AclDataPacket)
            assert event.connection_handle == link.handle and event.data == ARQ_PAYLOAD
            assert event.bc_flag == 0 and event.data_total_length == len(ARQ_PAYLOAD)
            assert event.pb_flag == hci.HCI_ACL_PB_FIRST_FLUSHABLE
    assert responses >= 5
    await link.disconnect()


async def peripheral_sending_data(tester):
    """Peripheral Sending Data.

    Initial Condition:
        An unencrypted connected public Peripheral, zero latency, and common
        connection interval, timeout and channel parameters. Read the LE buffer
        size preamble and retain the established handle and data_packet_length.
        The Lower Tester acts as Central and supplies correctly sequenced ACKs.

    Test Steps:
        1. Submit ten-octet zero-filled Host ACL packets with PB=0x00 until
           1000 octets are submitted; observe matching-handle Number Of Completed
           Packets events and respect the advertised HCI packet credits.
        2. Receive the corresponding DATA PDU with LLID=0x02 and exact payload.
        3. Send an empty Central DATA PDU once per connection interval using
           the common channel parameters and the DATA acknowledgement scheme.
        4. Repeat Steps 2-3 until all Step 1 data has been received and credited.
        5. Submit another 1000 zero-filled octets in ten-octet Host ACL packets,
           now all PB=0x01; observe the corresponding HCI completion credits.
        6. Receive each packet as LLID=0x01 and acknowledge with an empty Central
           DATA PDU using the same channel and sequence rules.
        7. Repeat Step 6 until every Step 5 payload has been received.
        8. Submit another 1000 octets in ten-octet packets, with PB=0x00 for the
           first packet and PB=0x01 for subsequent packets; track HCI credits.
        9. Require LLID=0x02 for the first payload and LLID=0x01 thereafter;
           acknowledge every packet with correctly sequenced empty DATA.
        10. Repeat Step 9 until all Step 8 data is received and credited.
        11. If data_packet_length <= 27, skip Steps 12-13 and proceed to Step 14.
        12. Otherwise, submit zero-filled Host packets with PB=0x00 and seeded
            random lengths from 28 through data_packet_length until at least
            1000 octets have been submitted.
        13. For each Step 12 packet, require at least two DATA fragments: first
            LLID=0x02, then LLID=0x01. Reassemble the exact Host payload and
            acknowledge fragments using the common sequence/channel parameters.
        14. Execute Peripheral Connection Terminated for the established handle
            and require successful HCI termination completion.

    Expected Outcome:
        Pass verdict:
            All submitted octets arrive unchanged, each Host packet is credited
            once, and LLID fragmentation boundaries follow Section 4.1.7.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-04-C procedure in
        Section 4.3.5, Figure 4.3-48; PDF 593-596, printed 4.3-120 through 4.3-123.
    """
    await _data_exchange(tester, central=False, direction='tx')


async def peripheral_receiving_data(tester):
    """Peripheral Receiving Data.

    Initial Condition:
        An unencrypted connected public Peripheral with common connection,
        channel and timeout parameters. Retain the preamble connection handle
        and buffer size. The Lower Tester acts as Central with independent ACK
        state and deterministic seeded random payloads.

    Test Steps:
        1. Configure 100 DATA packets, each with LLID=0x02 and ten random octets.
        2. Send one DATA packet per connection interval using the common channel
           parameters and acknowledgement scheme; receive the IUT response.
           Repeat Step 2 until all Step 1 payloads have been reported.
        3. Require HCI ACL Data with the exact Step 1 payload and PB=0x02.
        4. Configure another 100 ten-octet random DATA packets, all LLID=0x01.
        5. Send the Step 4 packets once per interval with correct sequence/channel
           parameters, repeating until every payload has been reported.
        6. Require the exact Step 5 payloads in HCI ACL Data with PB=0x01.
        7. Configure 100 further ten-octet random packets: first LLID=0x02,
           subsequent LLID=0x01.
        8. Send these packets once per interval, following the acknowledgement
           scheme, until all Step 7 payloads have been reported.
        9. Require the exact payload sequence in HCI ACL Data, first PB=0x02
           and subsequent PB=0x01, applying the Source Correction below.
        10. Configure ten three-octet random DATA packets with LLID=0x02; repeat
            their transfer until all ten have been acknowledged by the IUT.
        11. Send each Step 10 payload once per interval with LLID=0x02 and
            correct sequence/channel parameters; receive the IUT DATA response.
        12. Require one HCI ACL Data packet for each Step 11 payload, exact bytes
            and handle, with PB=0b10.

    Expected Outcome:
        Pass verdict:
            The IUT acknowledges all transmitted data and reports every payload
            unchanged, using the HCI fragmentation flags in Section 4.1.7.

    Source Correction:
        Step 9 says continuation PB=0x00; use PB=0x01 per Core 6.3 Vol 4,
        Part E, Section 5.4.2 and source Step 6. Amber confirms PB=0x00 is not
        a Controller-to-Host LE continuation flag. Step 10's reference to packets
        in Step 9 identifies HCI reports, not transmit packets; apply it to the
        ten packets configured in Step 10 and transmitted in Step 11. Step 11's
        payload reference to itself is Step 10. These are local interpretations,
        not published SIG errata.

    Coverage Note:
        Check HCI length/broadcast flags and DATA ACKs for every transfer, then
        disconnect through HCI after the normative twelve-step procedure.
        Section 4.1.7 compares the byte stream and start-flag locations;
        it does not require HCI and Link Layer packetization to coincide.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-05-C procedure in
        Section 4.3.5, Figure 4.3-49; PDF 596-598, printed 4.3-123 through 4.3-125.
    """
    await _data_exchange(tester, central=False, direction='rx')


async def peripheral_sending_and_receiving_data(tester):
    """Peripheral Sending and Receiving Data.

    Initial Condition:
        An unencrypted connected public Peripheral with common interval, latency,
        timeout and channel parameters. Read the buffer size preamble and retain
        the connection handle. Transfer at least 1000 octets per direction and
        more octets than the IUT data_packet_length.

    Test Steps:
        1. Submit ten-octet zero-filled Host ACL packets with PB=0x00 until
           1000 octets have been submitted for Peripheral transmission.
        2. Configure 100 Lower Tester DATA packets, each LLID=0x02 with ten
           deterministic seeded random payload octets.
        3. Send Step 2 packets once per connection interval using the common
           channel parameters and independent DATA acknowledgement scheme.
        4. Receive the IUT DATA response with LLID=0x02 and exact Step 1 data.
           Repeat Steps 3-4 until both directions' data is received/reported.
        5. Require HCI ACL Data reports with the exact Step 2 payload and
           PB=0x02, repeating until every Lower Tester payload is reported.

    Expected Outcome:
        Pass verdict:
            All transmitted data is acknowledged, every received payload is
            reported unchanged, and LLID/HCI boundaries preserve each message
            as specified in Section 4.1.7.

    Source Correction:
        Step 5 ends with all data sent in Step 1 being reported, but its HCI
        reports carry the Lower Tester data configured in Step 2. Apply the
        completion condition to Step 2; the two directions are checked separately.

    Coverage Note:
        Submit and verify one ten-octet message per direction in each of 100
        exchanges, checking HCI credits and ACKs before reusing a buffer. This
        exceeds the reported 251-octet HCI buffer size. Disconnect after all data.
        Compare received bytes and start-flag locations under Section 4.1.7,
        allowing different HCI packetization of the same message stream.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-06-C procedure in
        Section 4.3.5, Figure 4.3-50; PDF 599-600, printed 4.3-126 through 4.3-127.
    """
    await _data_exchange(tester, central=False, direction='duplex')


async def accepting_parameter_update(tester):
    """Accepting Parameter Update.

    Initial Condition:
        An unencrypted connected public Peripheral with common connection and
        channel parameters. The Lower Central advertises 500-ppm SCA.
        Before Step 1, update common parameters to 100-ms interval, latency 2,
        timeout 3 s with an Instant 100 events ahead, then return to common
        parameters with an Instant ten events ahead, as the procedure specifies.

    Test Steps:
        1. Send LL_CONNECTION_UPDATE_IND selecting minimum interval, offset and
           window size, no latency, intermediate timeout, and Instant one event
           after first transmission. Require acknowledgement. The Step 3 packet
           must start 0.5 us after the beginning of the widened receive window.
        2. Continue empty DATA and observe responses with unchanged old timing
           until the event counter reaches the indicated Instant.
        3. At the Instant, maintain the connection with the new parameters;
           warn if the IUT does not respond to the first updated event.
        4. Interleaved with Step 3, require Connection Update Complete with the
           correct handle, successful status and all new connection parameters.
        5. Send an update selecting maximum interval, maximum window offset and
           size, no latency, maximum timeout, and Instant 100 events ahead.
           Require the IUT to acknowledge the update.
        6. Repeat Steps 2-4 for the maximum-interval transition.
        7. Send an update selecting minimum interval, no latency, intermediate
           timeout, and Instant six events after first transmission; require ACK.
        8. Repeat Steps 2-4 for the minimum-interval transition.
        9. Send an update selecting 100-ms interval, maximum window offset/size,
           no latency, maximum timeout, and Instant six events ahead; require ACK.
        10. Repeat Steps 2-4, transmitting the Step 3 packet 0.5 us before the
            ending edge of the widened receive window.
        11. Send an update selecting 110-ms interval, maximum window offset,
            no latency, maximum timeout, and Instant six events ahead; require ACK.
        12. Repeat Steps 2-4, transmitting the Step 3 packet 0.5 us after the
            beginning edge of the widened receive window.

    Expected Outcome:
        Pass verdict:
            The IUT acknowledges updates, changes parameters at each Instant,
            responds in at least 65 of the 100 events in the short-to-long
            transition, and reports all new parameters through HCI.

    Source Correction:
        Step 12 describes the beginning edge but parenthetically says widening
        after the window end. Use widening before the window beginning, matching
        Step 1 and the receive-window definition. Step 11 leaves window size
        unspecified; select the maximum size as in the preceding edge trial.

    Review Limitation:
        The radio API represents integer microseconds. The executable trial uses
        a one-microsecond inside-edge guard, not the required 0.5-us stimulus in
        Steps 1, 10 and 12. All seven transitions and HCI/ACK/Instant assertions
        execute, but this is partial coverage, not a complete source verdict.

    Coverage Note:
        Inject no RF errors; the source threshold assumes BER <= 0.1 percent.
        Verify post-update ACL delivery after each transition and disconnect
        through HCI after the final update.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-10-C procedure in
        Section 4.3.5, Figures 4.3-51/52; PDF 600-603, printed 4.3-127 through
        4.3-130. Common initial conditions: Section 4.1.6.
    """
    link = await establish(tester, peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS)
    common = link.parameters
    rounds = (
        (80, 2, 300, 0, 1, 100, None),
        (common.interval, common.latency, common.timeout, 0, 1, 10, None),
        (LL_CONN_INTERVAL_MIN, 0, 300, 0, LL_CONN_WINDOW_SIZE_MIN, 1, 'early'),
        (
            LL_CONN_INTERVAL_MAX,
            0,
            LL_SUPERVISION_TIMEOUT_MAX,
            LL_CONN_INTERVAL_MAX,
            LL_CONN_WINDOW_SIZE_MAX,
            100,
            None,
        ),
        (LL_CONN_INTERVAL_MIN, 0, 300, 0, LL_CONN_WINDOW_SIZE_MIN, 6, None),
        (80, 0, LL_SUPERVISION_TIMEOUT_MAX, 80, LL_CONN_WINDOW_SIZE_MAX, 6, 'late'),
        (88, 0, LL_SUPERVISION_TIMEOUT_MAX, 88, LL_CONN_WINDOW_SIZE_MAX, 6, 'early'),
    )
    for interval, latency, timeout, offset, size, distance, edge in rounds:
        instant = link.counter + distance & LL_EVENT_COUNTER_MASK
        update = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + struct.pack(
            '<BHHHHH', size, offset, interval, latency, timeout, instant
        )
        await link.exchange(update, llid=LlId.CONTROL, check_ack=True)
        responses = 1
        while link.counter != instant:
            assert not any(
                isinstance(event, hci.HCI_LE_Connection_Update_Complete_Event)
                for event in tester.events
            ), 'update completed before Instant'
            response = await link.exchange(required=False)
            responses += response is not None
        if distance == 100:
            assert responses >= 65
        link.anchor += offset * LL_CONN_INTERVAL_UNIT_US
        elapsed = link.anchor - (link.last_sent_end_us - 1)
        accuracy_ppm = LL_SCA_PPM[LL_SCA_500_PPM] + LL_SCA_PPM[LL_SCA_50_PPM]
        widening = (
            RADIO_CLOCK_JITTER_US
            + (elapsed * accuracy_ppm + PHY_TIME_UNITS_PER_SECOND - 1)
            // PHY_TIME_UNITS_PER_SECOND
        )
        if edge == 'early':
            link.anchor -= widening - 1
        elif edge == 'late':
            link.anchor += size * LL_CONN_INTERVAL_UNIT_US + widening - 1
        link.parameters = replace(
            link.parameters,
            interval=interval,
            latency=latency,
            timeout=timeout,
            window_size=size,
            window_offset=offset,
        )
        if await link.exchange(required=False) is None:
            tester.output.write('WARNING: no response at connection-update Instant\n')
        event = await tester.event(hci.HCI_LE_Connection_Update_Complete_Event)
        assert (
            event.connection_handle == link.handle and event.status == ErrorCode.SUCCESS
        )
        assert (
            event.connection_interval,
            event.peripheral_latency,
            event.supervision_timeout,
        ) == (interval, latency, timeout)
        await peer_send(tester, link, b'updated')
    await link.disconnect(local=True)


async def peripheral_sending_termination(tester):
    """Peripheral Sending Termination.

    Initial Condition:
        An unencrypted connected public Peripheral with common interval/channel
        parameters, zero latency, and a 100-ms supervision timeout.
        The Lower Tester acts as Central and retains the established handle.

    Test Steps:
        1. Send HCI Disconnect for that handle and require successful Command
           Status. Select Remote User Terminated Connection as the reason.
        2. Receive LL_TERMINATE_IND in response to a Central DATA transmission,
           validate the requested reason, and acknowledge with empty Central
           DATA in the following connection event.
        3. Continue empty Central DATA transmissions for one full supervision
           timeout; require no further Peripheral DATA or termination responses.
        4. Interleaved with Step 3, require successful Disconnection Complete
           for the handle, indicating termination requested by the local Host.

    Expected Outcome:
        Pass verdict:
            The IUT transmits termination until acknowledged, stops maintaining
            the ACL after acknowledgement, and reports termination through HCI.
            It must stop retransmitting termination when T_Terminate expires.

    Coverage Note:
        This procedure acknowledges termination at the first opportunity.
        The separate timeout procedure exercises the unacknowledged path.
        Check HCI status, handle, local reason, and absence of duplicate events.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-11-C procedure in
        Section 4.3.5, Figure 4.3-53; PDF 604-605, printed 4.3-131 through 4.3-132.
    """
    await _connection_termination(tester, central=False, local=True)


async def peripheral_accepting_termination(tester):
    """Peripheral Accepting Termination.

    Initial Condition:
        An unencrypted connected public Peripheral with common interval/channel
        parameters, zero latency, and a 100-ms supervision timeout.
        The Lower Tester acts as Central and retains the established handle.

    Test Steps:
        1. Send LL_TERMINATE_IND with the selected peer reason. Require an empty
           Peripheral DATA response at T_IFS with NESN acknowledging the request.
        2. Continue empty Central DATA transmissions for one full supervision
           timeout; require no further Peripheral responses.
        3. Interleaved with Step 2, require successful Disconnection Complete
           with the established handle and the reason requested by the peer.

    Expected Outcome:
        Pass verdict:
            The IUT acknowledges termination before T_Terminate expires, stops
            maintaining the connection after that acknowledgement, and reports
            termination through HCI.

    Coverage Note:
        Select Remote User Terminated Connection as the peer reason and reject
        duplicate HCI disconnection events throughout the observation window.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-12-C procedure in
        Section 4.3.5, Figure 4.3-54; PDF 605-606, printed 4.3-132 through 4.3-133.
    """
    await _connection_termination(tester, central=False, local=False)


async def peripheral_supervision_timer(tester):
    """Peripheral Supervision Timer.

    Initial Condition:
        An unencrypted connected public Peripheral with selected interval and
        timeout, zero latency, and common channel parameters.
        The Lower Tester acts as Central; use the common connection preamble.

    Test Steps:
        1. Establish the connection using the maximum supported interval (4 s)
           and supervision timeout (32 s); verify the reported HCI parameters.
        2. Stop Central maintenance after a known valid DATA event. Measure the
           supervision deadline from the last valid peer packet, not Host setup.
        3. Require Disconnection Complete for the same handle with successful
           status and Connection Timeout reason, after the last event before
           expiry and at the selected supervision deadline.
        4. Establish a new connection using the minimum supported interval
           (7.5 ms) and supervision timeout (100 ms).
        5. Repeat Steps 2-3 using the minimum settings.

    Expected Outcome:
        Pass verdict:
            HCI reports disconnection at the selected connSupervisionTimeout
            after the final valid event for both maximum and minimum settings.

    Coverage Note:
        Use simulation time, with 10-ms measurement resolution for maximum
        timeout and 1-ms resolution for minimum timeout as specified by the
        source notes. Reject early or late events outside that resolution.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-13-C procedure in
        Section 4.3.5, Figure 4.3-55; PDF 606-607, printed 4.3-133 through 4.3-134.
    """
    await _supervision(tester, central=False)


async def feature_setup_response(tester):
    """Feature Setup Response.

    Initial Condition:
        An unencrypted connected public Peripheral with selected interval,
        latency and timeout, and common channel parameters. The Lower Tester
        acts as Central. Read the IUT local LE features for the declared ICS
        comparison and select an all-zero Lower Tester FeatureSet.

    Test Steps:
        1. Send LL_FEATURE_REQ with the Lower Tester FeatureSet and wait for
           LL_FEATURE_RSP. Check opcode, full FeatureSet length, cleared
           Masked-to-Peer bits, required local features and zero RFU bits.
        2. Execute Peripheral Connection Terminated for the established handle
           and parameters; require successful HCI termination completion.

    Expected Outcome:
        Pass verdict:
            Every Masked-to-Peer feature is clear. The response contains all
            required supported features matching the declared ICS mapping,
            and its RFU bits are zero.

    Coverage Note:
        Apply Core 6.3 Send-to-Peer feature rules to the local declaration:
        optional peer-report bits need not be set, forbidden bits must be clear,
        and no undeclared feature may appear. Validate DATA timing and ACKs
        through the independent Central peer while awaiting the response.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-14-C procedure in
        Section 4.3.5, Figure 4.3-56; PDF 607-608, printed 4.3-134 through 4.3-135.
    """
    await _feature_or_version(tester, central=False, version=False)


async def peripheral_retransmission_request(tester):
    """Peripheral Retransmission Request.

    Initial Condition:
        An unencrypted connected public Peripheral with common interval, latency,
        timeout and channel parameters. The Lower Tester acts as Central and
        retains current/next SN and NESN from the established connection.

    Test Steps:
        1. Repeat Steps 1-2 fifteen times. Send one DATA PDU per interval using
           the common channel selection, inverting all CRC bits. Advance the
           peer SN/NESN only as permitted by the preceding valid IUT ACK state.
        2. Receive the Peripheral response at T_IFS in required listening events.
           Require SN matching current peer NESN and NESN matching current peer
           SN, indicating that the corrupt packet was not accepted.
        3. Execute Peripheral Connection Terminated using the established handle
           and parameters, after restoring a valid acknowledged peer exchange.

    Expected Outcome:
        Pass verdict:
            Every corrupt packet elicits a negative acknowledgement: IUT SN/NESN
            remain unchanged and invalid DATA is not delivered to the Host.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-15-C procedure in
        Section 4.3.5, Figure 4.3-57; PDF 608-609, printed 4.3-135 through 4.3-136.
    """
    await _retransmissions(tester, central=False, mode='crc', latency=False)


async def peripheral_retransmission(tester):
    """Peripheral Retransmission.

    Initial Condition:
        An unencrypted connected public Peripheral with common interval, latency,
        timeout and channel parameters. The Lower Central retains independent
        current/next SN/NESN state; the outstanding IUT packet is empty DATA.

    Test Steps:
        1. Repeat Steps 1-2 fifteen times. Send one empty DATA PDU per interval
           on the common selected channel. Advance SN when acknowledged, but
           keep NESN equal to the IUT SN, deliberately withholding its ACK.
        2. Receive the Peripheral response at T_IFS. Require the same IUT SN
           and payload, with NESN acknowledging the newly accepted Central SN.
        3. The Lower Tester terminates the connection through LL_TERMINATE_IND
           after restoring normal peer sequence state.

    Expected Outcome:
        Pass verdict:
            The IUT retransmits identical payload and SN for each negative ACK
            while still acknowledging new valid Central packets.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-16-C procedure in
        Section 4.3.5, Figure 4.3-58; PDF 609-610, printed 4.3-136 through 4.3-137.
    """
    await _retransmissions(tester, central=False, mode='nak', latency=False)


async def peripheral_acknowledgement_repetition(tester):
    """Peripheral Acknowledgement Repetition.

    Initial Condition:
        An unencrypted connected public Peripheral with common interval, latency,
        timeout and channel parameters. The Lower Central retains current/next
        SN/NESN and uses one 0xFF payload octet as shown in the source MSC.

    Test Steps:
        1. Send DATA with the current Central SN. Ignore positive ACKs for that
           payload, but correctly acknowledge received IUT DATA by advancing NESN.
        2. Require the IUT acknowledgement with NESN equal to next Central SN.
        3. Repeat Steps 3-4 fifteen times. Resend the same Central DATA with
           unchanged SN and exact payload, pretending its ACK was not received.
        4. Require repeated positive ACK: IUT NESN remains next Central SN and
           IUT SN advances because its own previous DATA was acknowledged.
        5. The Lower Tester terminates the connection through LL_TERMINATE_IND
           after restoring normal peer sequence state.

    Expected Outcome:
        Pass verdict:
            The IUT acknowledges every duplicate, advances its own acknowledged
            sequence correctly, and delivers the duplicate payload to its Host
            exactly once.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-17-C procedure in
        Section 4.3.5, Figure 4.3-59; PDF 610-611, printed 4.3-137 through 4.3-138.
    """
    await _retransmissions(tester, central=False, mode='duplicate', latency=False)


async def peripheral_lost_negative_acknowledgement(tester):
    """Peripheral Lost Negative Acknowledgement.

    Initial Condition:
        An unencrypted connected public Peripheral with common interval, latency,
        timeout and channel parameters. The Lower Central retains independent
        current/next SN/NESN from the established connection.

    Test Steps:
        1. Repeat Steps 1-2 fifteen times. First send the next Central DATA with
           invalid CRC. After the resulting negative ACK, incorrectly advance
           Central SN and send valid-CRC DATA. Keep Central NESN equal to the
           IUT SN, negatively acknowledging the IUT's own DATA throughout.
        2. Receive the IUT response at T_IFS on the selected data channel.
           Require repeated unchanged IUT payload and SN matching current peer
           NESN; IUT NESN remains the current peer SN, rejecting the sequence jump.
        3. Execute Peripheral Connection Terminated with the established handle
           and parameters after restoring a valid acknowledged exchange.

    Expected Outcome:
        Pass verdict:
            The IUT repeats a negative ACK when the next payload is sent after
            the lost negative ACK, and does not deliver invalid/duplicate data.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-18-C procedure in
        Section 4.3.5, Figure 4.3-60; PDF 612-613, printed 4.3-139 through 4.3-140.
    """
    await _retransmissions(tester, central=False, mode='lost', latency=False)


async def peripheral_acknowledgement_scheme(tester):
    """Peripheral Acknowledgement Scheme.

    Initial Condition:
        An unencrypted connected public Peripheral with common interval, latency,
        timeout and channel parameters. The Lower Central retains independent
        current/next SN and NESN from the connection preamble.

    Test Steps:
        1. Repeat Steps 1-2 fifteen times. Send one DATA PDU per interval on the
           selected data channel. Advance SN only after its positive ACK; advance
           NESN when a correctly received IUT SN matches current peer NESN.
        2. In required listening events, receive the Peripheral DATA at T_IFS.
           Require SN matching current peer NESN and NESN matching next peer SN.
        3. Execute Peripheral Connection Terminated for the established handle
           and connection parameters.

    Expected Outcome:
        Pass verdict:
            The normal acknowledgement scheme executes correctly and the IUT
            acknowledges at least ten of the fifteen Central packets.

    Coverage Note:
        Select empty DATA and inject no RF errors. Require all fifteen correctly
        timed empty replies in this ideal channel, exceeding the source minimum.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-21-C procedure in
        Section 4.3.5, Figure 4.3-63; PDF 615-616, printed 4.3-142 through 4.3-143.
    """
    await _acknowledgement_scheme(tester, central=False)


async def initiate_feature_exchange(tester):
    """Initiate Feature Exchange.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, and selected timeout. Select public
        addresses; the Lower Tester acts as Central and retains the ACL handle.

    Test Steps:
        1. Send LE Read Local Supported Features Page 0 and require successful
           Command Complete with the local feature bitmap for ICS comparison.
        2. Send LE Read Remote Features Page 0 for the connection handle and
           require successful Command Status.
        3. If the IUT already sent LL_PERIPHERAL_FEATURE_REQ autonomously, use
           that request; otherwise receive its request after Step 2. Check opcode,
           FeatureSet length, supported required bits, Send-to-Peer masking and
           zero RFU bits. Send LL_FEATURE_RSP with a selected valid Central
           FeatureSet and require the IUT to acknowledge the response.
        4. Require successful LE Read Remote Features Page 0 Complete for the
           same handle with the exact feature bytes from LL_FEATURE_RSP.

    Expected Outcome:
        Pass verdict:
            The IUT requests Feature Exchange, acknowledges the reply and reports
            completion. Local HCI features match its declared support; the request
            contains supported peer-visible features with forbidden/RFU bits
            clear, and the HCI peer feature result matches the received response.

    Coverage Note:
        Core 6.3 Vol 6, Part B, Sections 4.6 and 5.1.4 distinguish Send-to-Peer
        masking from FeatureSet_USED in responses. The initial request retains
        required locally supported first-octet bits; it is neither all zero nor
        necessarily equal to the raw HCI local bitmap. Optional peer-report bits
        may be clear. Amber corroborated these request/response rules.
        Disconnect through HCI after the normative four-step procedure.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-22-C procedure in
        Section 4.3.5, Figure 4.3-64; PDF 616-618, printed 4.3-143 through 4.3-145.
    """
    await _remote_features(tester, central=False, unsupported=False)


async def initiate_feature_exchange_central_does_not_support(tester):
    """Initiate Feature Exchange – Central does not support.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, and selected timeout. Select public
        addresses. The Lower Central must not initiate Feature Exchange after
        establishment; retain the ACL handle and local feature declaration.

    Test Steps:
        1. For BV-23-C in Table 4.3-39, send LE Read Remote Features Page 0
           for the handle and require successful Command Status.
        2. Use an autonomous LL_PERIPHERAL_FEATURE_REQ already sent by the IUT,
           or receive the request after Step 1. Check its opcode, length and
           peer-visible supported features, applying Send-to-Peer/RFU rules.
        3. Acknowledge the request and send LL_UNKNOWN_RSP with UnknownType
           identifying LL_PERIPHERAL_FEATURE_REQ; require the IUT to ACK it.
        4. Require LE Read Remote Features Page 0 Complete with the same handle
           and Unsupported Remote Feature status (0x1A).

    Expected Outcome:
        Pass verdict:
            The selected HCI completion reports status 0x1A in response to the
            Lower Tester's LL_UNKNOWN_RSP, without a Central feature request.

    Coverage Note:
        This workbook selects BV-23-C, not the Read All Remote Features variant
        BV-165-C. Read local features for the request oracle, and disconnect
        through HCI after the normative four-step procedure.

    Reference:
        LL.TS.p28, Section 4.3.5.1, Table 4.3-39, Figure 4.3-65;
        LL/CON/PER/BV-23-C; PDF 618-619, printed 4.3-145 through 4.3-146.
    """
    await _remote_features(tester, central=False, unsupported=True)


async def initiating_connection_parameter_request_accept(tester):
    """Initiating Connection Parameter Request – Accept.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        selected timeout and SCA. Select public addresses and common channel
        parameters. The Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        Case 1:
            1. Send HCI LE Connection Update selecting minimum interval, zero
               latency and intermediate supervision timeout (3 s); require status.
            2. Receive LL_CONNECTION_PARAM_REQ and validate its actual parameters.
               Accept directly with LL_CONNECTION_UPDATE_IND selecting a valid
               interval within that request; require the IUT to acknowledge it.
            3. Continue empty DATA and ACKs on old timing until the Instant.
            4. At the Instant, maintain DATA using the accepted new parameters.
            5. Require successful Connection Update Complete with exact handle,
               interval, latency and timeout from the accepted update.
        Case 2:
            1. Send HCI LE Connection Update selecting maximum interval, zero
               latency and maximum timeout; require successful Command Status.
            2. Receive and validate LL_CONNECTION_PARAM_REQ, accept directly with
               LL_CONNECTION_UPDATE_IND, and require acknowledgement.
            3. Continue empty DATA and ACKs on old timing until the Instant.
            4. At the Instant, maintain DATA using the accepted new parameters.
            5. Require successful Connection Update Complete with all accepted
               parameters and the same handle.
        Case 3:
            1. Send HCI LE Connection Update selecting minimum interval, zero
               latency and intermediate timeout (3 s); require Command Status.
            2. Receive and validate LL_CONNECTION_PARAM_REQ, accept directly with
               LL_CONNECTION_UPDATE_IND, and require acknowledgement.
            3. Continue empty DATA and ACKs on old timing until the Instant.
            4. At the Instant, maintain DATA using the accepted new parameters.
            5. Require successful Connection Update Complete with all accepted
               parameters and the same handle.

    Expected Outcome:
        Pass verdict:
            All three cases emit a parameter request, acknowledge the update,
            adopt new parameters at the assigned event, and report those
            parameters with Connection Update Complete.

    Coverage Note:
        Choose the minimum valid interval from each actual LL request; do not
        require it to equal the Host command. No extra PARAM_RSP is inserted
        before the Central's direct UPDATE_IND. Reject early successful HCI
        completion and check subsequent DATA timing, then disconnect through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-24-C procedure in
        Section 4.3.5, Figure 4.3-66; PDF 620-623, printed 4.3-147 through 4.3-150.
    """
    await _local_parameters(tester, central=False, reject=False)


async def initiating_connection_parameter_request_reject(tester):
    """Initiating Connection Parameter Request – Reject.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        selected timeout and SCA. Select public addresses and common channel
        parameters; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        1. Send HCI LE Connection Update selecting minimum interval, zero
           latency and intermediate timeout (3 s); require Command Status.
        2. Receive LL_CONNECTION_PARAM_REQ and validate its actual parameters,
           which may differ from the Host command. Send LL_REJECT_EXT_IND naming
           the rejected opcode and selected error; require IUT acknowledgement.
        3. Require Connection Update Complete with the established handle and
           exact error code from LL_REJECT_EXT_IND.

    Expected Outcome:
        Pass verdict:
            The IUT emits the parameter request and reports the Lower Tester's
            rejection code through Connection Update Complete.

    Coverage Note:
        Select Command Disallowed (0x0C) as the rejection reason. Verify continued
        DATA on unchanged parameters, no extra update completion, and then HCI
        termination of the original ACL.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-25-C procedure in
        Section 4.3.5, Figure 4.3-67; PDF 623-624, printed 4.3-150 through 4.3-151.
    """
    await _local_parameters(tester, central=False, reject=True)


async def initiating_connection_parameter_request_same_procedure_collision(tester):
    """Initiating Connection Parameter Request – same procedure collision.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        selected timeout and SCA. Select public peers and common channel
        parameters; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        1. Send HCI LE Connection Update selecting minimum interval, zero
           latency and intermediate timeout (3 s); require Command Status.
        2. Receive and validate LL_CONNECTION_PARAM_REQ. Send a Central
           LL_CONNECTION_PARAM_REQ, then reject the IUT request with
           LL_REJECT_EXT_IND, rejected opcode PARAM_REQ and error 0x23.
        3. Require the IUT to ask its Host to accept/reject the Central parameters,
           with correct connection handle and all requested fields.
        4. At this point or later, allow an optional Connection Update Complete
           failure only with the same handle and error 0x23.
        5. Accept the Central request through HCI Remote Connection Parameter
           Request Reply; require successful completion and the same handle.
        6. Receive LL_CONNECTION_PARAM_RSP and validate its actual parameters.
        7. Send a valid LL_CONNECTION_UPDATE_IND based on that response and
           require the IUT to acknowledge it.
        8. Continue empty DATA and ACKs under old parameters until the Instant.
        9. Maintain DATA using the new parameters starting at the Instant.
        10. Require successful Connection Update Complete with the same handle
            and exact accepted interval, latency and supervision timeout.

    Expected Outcome:
        Pass verdict:
            The local PARAM_REQ is emitted; any local-failure HCI event has error
            0x23. The Central request survives the collision, receives PARAM_RSP,
            is adopted at its Instant, and completes through HCI with new values.

    Coverage Note:
        Reject an immediate Peripheral LL_REJECT_EXT_IND for the preserved
        Central request. Optional local failure may be interleaved with the
        subsequent completion; it must not replace the successful peer update.
        Check new-interval DATA and disconnect after the normative observations.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-26-C procedure in
        Section 4.3.5, Figure 4.3-68; PDF 624-626, printed 4.3-151 through 4.3-153.
    """
    await _parameter_collision(tester, central=False, channel_map=False)


async def initiating_parameter_request_channel_map_collision(
    tester,
):
    """Initiating Connection Parameter Request – different procedure collision – channel
    map update.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        selected timeout and SCA. Select public peers and common channel
        parameters; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        1. Send HCI LE Connection Update selecting minimum interval, zero
           latency and intermediate timeout (3 s); require Command Status.
        2. Receive and validate LL_CONNECTION_PARAM_REQ. Send LL_CHANNEL_MAP_IND,
           then LL_REJECT_EXT_IND identifying the local PARAM_REQ with error
           0x2A; require acknowledgements of both Central control packets.
        3. Require Connection Update Complete with the original handle and
           Different Transaction Collision status (0x2A).
        4. Continue empty DATA and ACKs on the original channel map until the
           indicated channel-map Instant; then maintain DATA on the new map.

    Expected Outcome:
        Pass verdict:
            The IUT emits the parameter request, reports collision error 0x2A,
            acknowledges the channel update, adopts it at the assigned event,
            and maintains the original connection on the new channel map.

    Coverage Note:
        Select a valid map containing even-numbered data channels. Independently
        compute old/new hopping, read the resulting map through HCI, verify
        post-update ACL delivery, and prohibit leaked Host parameter requests
        or additional update completions before HCI termination.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-27-C procedure in
        Section 4.3.5, Figure 4.3-69; PDF 626-627, printed 4.3-153 through 4.3-154.
    """
    await _parameter_collision(tester, central=False, channel_map=True)


async def initiating_parameter_request_encryption_collision(
    tester,
):
    """Initiating Connection Parameter Request – different procedure collision –
    encryption.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        selected timeout and SCA. Select public addresses and common channel
        parameters; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        1. Send HCI LE Connection Update selecting minimum interval, zero
           latency and intermediate timeout (3 s); require Command Status.
        2. Receive LL_CONNECTION_PARAM_REQ and validate the actual parameters,
           which may differ from Host values. Respond with LL_ENC_REQ.
        3. Receive LL_ENC_RSP with the Peripheral session-key-diversifier and
           initialization-vector components; derive the independent session key.
        4. Require HCI LE Long Term Key Request with the exact connection handle,
           random number and encryption diversifier from LL_ENC_REQ.
        5. Supply the matching LTK through HCI Long Term Key Request Reply and
           require successful Command Complete.
        6. Receive LL_START_ENC_REQ and acknowledge it on the ACL connection.
        7. Send encrypted LL_START_ENC_RSP and receive the matching encrypted
           LL_START_ENC_RSP from the Peripheral, validating its integrity.
        8. Require successful Encryption Change with encryption enabled and the
           same connection handle.
        9. Accept the preserved parameter request with encrypted
           LL_CONNECTION_UPDATE_IND selecting valid actual request parameters;
           require acknowledgement from the IUT.
        10. Continue empty DATA and ACKs using old parameters until the Instant.
        11. At the Instant, maintain the encrypted ACL with the new parameters.
        12. Require successful Connection Update Complete with exact handle,
            interval, latency and supervision timeout from the accepted update.

    Expected Outcome:
        Pass verdict:
            The IUT requests parameters, supplies its encryption components,
            requests the LTK, exchanges and acknowledges start-encryption PDUs,
            reports encryption enabled, and then acknowledges/adopts the parameter
            update at its Instant with correct HCI completion.

    Coverage Note:
        Use public fixed test vectors, independent AES-CCM and packet counters.
        Complete encryption before the pending parameter procedure's response
        timeout; measure that budget in simulation time. Verify encrypted DATA
        after the update and disconnect through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-28-C procedure in
        Section 4.3.5, Figure 4.3-70; PDF 628-630, printed 4.3-155 through 4.3-157.
    """
    await _parameter_encryption_collision(tester, central=False)


async def accepting_connection_parameter_request_no_preferred_periodicity(tester):
    """Accepting Connection Parameter Request – no Preferred_Periodicity.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        selected timeout and SCA. Select public peers and common channel
        parameters; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        Case 1:
            1. Send LL_CONNECTION_PARAM_REQ selecting minimum interval, zero
               latency, intermediate timeout (3 s) and Preferred_Periodicity=0.
            2. Require the IUT Host parameter approval request with exact handle
               and fields; accept it through the HCI positive reply.
            3. Receive LL_CONNECTION_PARAM_RSP, validate its actual parameters,
               and send a valid LL_CONNECTION_UPDATE_IND; require the IUT ACK.
            4. Continue empty DATA and ACKs with old parameters until the Instant.
            5. At the Instant, maintain the accepted new connection parameters.
            6. Require successful Connection Update Complete with exact handle,
               interval, latency and timeout from the Lower Tester's update.
        Case 2:
            1. Send LL_CONNECTION_PARAM_REQ selecting maximum interval, zero
               latency, maximum timeout and Preferred_Periodicity=0.
            2. Require the matching HCI Host approval request and accept it.
            3. Validate LL_CONNECTION_PARAM_RSP, send a valid update selecting
               actual response parameters, and require the IUT ACK.
            4. Continue empty DATA and ACKs with old parameters until the Instant.
            5. Maintain the new connection parameters starting at the Instant.
            6. Require successful HCI completion with the exact accepted values.
        Case 3:
            1. Send LL_CONNECTION_PARAM_REQ selecting minimum interval, zero
               latency, intermediate timeout (3 s) and Preferred_Periodicity=0.
            2. Require the matching HCI Host approval request and accept it.
            3. Validate LL_CONNECTION_PARAM_RSP, send a valid update selecting
               actual response parameters, and require the IUT ACK.
            4. Continue empty DATA and ACKs with old parameters until the Instant.
            5. Maintain the new connection parameters starting at the Instant.
            6. Require successful HCI completion with the exact accepted values.

    Expected Outcome:
        Pass verdict:
            In all three cases, the IUT accepts the request, acknowledges the
            update, adopts it at the assigned event and reports the selected
            parameters through Connection Update Complete.

    Coverage Note:
        The LL response may differ from the Host's values. Choose a valid
        interval from the actual response, reject early successful completion,
        verify subsequent DATA timing and terminate through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-29-C procedure in
        Section 4.3.5, Figure 4.3-71; PDF 630-633, printed 4.3-157 through 4.3-160.
    """
    await _remote_parameters(
        tester, central=False, reject=False, masked=False, invalid=False
    )


async def accepting_connection_parameter_request_preferred_anchor_points_only(tester):
    """Accepting Connection Parameter Request – preferred anchor points only.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        Case 1:
            1. Send LL_CONNECTION_PARAM_REQ with Offset0=1.25 ms, Offset1-5
               invalid, and unchanged interval, latency and supervision timeout.
            2. Receive LL_CONNECTION_PARAM_RSP and send LL_CONNECTION_UPDATE_IND
               shifting anchors by 1.25 ms; require acknowledgement.
            3. Continue empty DATA and ACKs on old timing until the Instant.
            4. Maintain the new anchor phase starting at the indicated event.
        Case 2:
            1. Send LL_CONNECTION_PARAM_REQ with Offset0=interval-1.25 ms,
               Offset1-5 invalid, and unchanged interval, latency and timeout.
            2. Receive LL_CONNECTION_PARAM_RSP and send an update shifting anchors
               by interval-1.25 ms; require acknowledgement.
            3. Continue empty DATA and ACKs on old timing until the Instant.
            4. Maintain the new anchor phase starting at the indicated event.
        Case 3:
            1. Send LL_CONNECTION_PARAM_REQ with Offset0=1.25 ms, Offset1=2.5 ms,
               Offset2-5 invalid, and unchanged interval, latency and timeout.
            2. Receive LL_CONNECTION_PARAM_RSP and send an update selecting the
               1.25-ms anchor shift; require acknowledgement.
            3. Continue empty DATA and ACKs on old timing until the Instant.
            4. Maintain the new anchor phase starting at the indicated event.

    Expected Outcome:
        Pass verdict:
            The IUT responds positively, acknowledges updates and adopts the
            requested anchor shifts: 1.25 ms, interval-1.25 ms, then 1.25 ms.

    Coverage Note:
        Compute the new phase relative to ReferenceConnEventCount, including
        counter wraparound. Verify unchanged interval/latency/timeout, absence
        of Host parameter approval or update-complete events for anchor-only
        changes, and continued DATA at the shifted anchors before HCI termination.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-30-C procedure in
        Section 4.3.5, Figure 4.3-72; PDF 633-635, printed 4.3-160 through 4.3-162.
    """
    await _preferred_parameters(tester, central=False, anchors_only=True, anchors=True)


async def accepting_connection_parameter_request_preferred_periodicity(
    tester, *, anchors
):
    """Accepting Connection Parameter Request – Preferred_Periodicity.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        1. Select alternative 1A or 1B according to Table 4.3-40:
            1A.1. For BV-31-C, send LL_CONNECTION_PARAM_REQ with a nonzero interval
                  range, zero latency, intermediate timeout (3 s), and a nonzero
                  periodicity having a multiple within the requested range.
            1B.1. For BV-32-C, send the same request plus ReferenceConnEventCount
                  and valid Offset0 corresponding to a 1.25-ms anchor shift;
                  mark Offset1-5 invalid.
        2. Require the Host parameter approval request with exact handle and
           requested fields, and accept it through the HCI positive reply.
        3. Receive LL_CONNECTION_PARAM_RSP and validate its actual parameters,
           which may differ from the Host values. Send LL_CONNECTION_UPDATE_IND
           choosing a valid interval within that response and require the IUT ACK.
        4. Continue empty DATA and ACKs using old parameters until the Instant.
        5. At the Instant, maintain DATA with the Lower Tester's accepted interval,
           latency, timeout and selected anchor phase.
        6. Require successful Connection Update Complete with exact accepted
           parameters and the original connection handle.

    Expected Outcome:
        Pass verdict:
            The IUT responds positively, acknowledges the update, adopts the
            parameters at the assigned event, and reports those values via HCI.

    Coverage Note:
        Select request interval range 13..19 and periodicity 18 in 1.25-ms units.
        Prefer a periodic multiple in the actual response range if one exists;
        otherwise select a valid response interval. PreferredPeriodicity is a
        preference, not a mandatory multiple constraint (Core 6.3 Vol 6, Part B,
        Section 5.1.7.2; Amber corroborated). Select within the actual response
        range even when it excludes that multiple. Compute Offset0's phase against the
        reference counter, reject early HCI completion, verify subsequent DATA,
        and disconnect after the normative six-step procedure.

    Reference:
        LL.TS.p28, Section 4.3.5.2, Table 4.3-40, Figure 4.3-73;
        LL/CON/PER/BV-31-C and LL/CON/PER/BV-32-C; PDF 635-637,
        printed 4.3-162 through 4.3-164.
    """
    await _preferred_parameters(
        tester, central=False, anchors_only=False, anchors=anchors
    )


async def accepting_connection_parameter_request_event_masked(tester):
    """Accepting Connection Parameter Request – event masked.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        1. Mask LE Remote Connection Parameter Request through HCI LE Set Event
           Mask and require successful Command Complete.
        2. Send LL_CONNECTION_PARAM_REQ selecting minimum interval, zero
           latency and intermediate supervision timeout (3 s).
        3. Require LL_REJECT_EXT_IND identifying LL_CONNECTION_PARAM_REQ and
           Unsupported Remote Feature error (0x1A).

    Expected Outcome:
        Pass verdict:
            The IUT rejects the parameter update with LL_REJECT_EXT_IND and
            the required error code 0x1A.

    Coverage Note:
        Continue three DATA exchanges on the original parameters, requiring no
        Host parameter request or update-complete event, then terminate via HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-33-C procedure in
        Section 4.3.5, Figure 4.3-74; PDF 637-638, printed 4.3-164 through 4.3-165.
    """
    await _remote_parameters(
        tester, central=False, reject=False, masked=True, invalid=False
    )


async def accepting_connection_parameter_request_host_rejects(tester):
    """Accepting Connection Parameter Request – Host rejects.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        selected timeout and SCA. Select public peers and common channel
        parameters; the Lower Tester maintains the Central role and ACL handle.

    Test Steps:
        1. Send LL_CONNECTION_PARAM_REQ selecting minimum interval, zero
           latency and intermediate supervision timeout (3 s).
        2. Require the Host parameter approval request with exact handle and
           requested fields. Reject it through HCI Remote Connection Parameter
           Request Negative Reply using Unacceptable Connection Parameters
           (0x3B); require successful Command Complete and the same handle.
        3. Require LL_REJECT_EXT_IND naming LL_CONNECTION_PARAM_REQ and carrying
           the exact error code 0x3B provided by the Host.

    Expected Outcome:
        Pass verdict:
            The IUT responds with LL_REJECT_EXT_IND and the exact Host-selected
            rejection error code.

    Coverage Note:
        Acknowledge the LL rejection, continue three DATA exchanges on unchanged
        parameters, reject a successful/duplicate update completion, and then
        terminate the original ACL through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-34-C procedure in
        Section 4.3.5, Figure 4.3-75; PDF 638-639, printed 4.3-165 through 4.3-166.
    """
    await _remote_parameters(
        tester, central=False, reject=True, masked=False, invalid=False
    )


async def initiating_phy_update_procedure(tester):
    """Initiating PHY Update Procedure.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers and initial LE 1M in both directions. The current profile
        supports LE 2M, LE Coded and asymmetric connections; read local features
        to confirm applicability of the full Table 4.3-41 matrix.

    Test Steps:
        Execute all 67 Table 4.3-41 rounds in order, then every round again in
        deterministic seeded random order, carrying the resulting PHY state.
        1. Send HCI LE Set PHY with that row's ALL_PHYS, TX_PHYS and RX_PHYS,
           and PHY_options=0x0000.
        2. Require Command Status: 0x11 if a requested bit denotes an unsupported
           PHY, otherwise success. For a symmetric-only IUT, ALL_PHYS=0 and
           different TX/RX sets also require 0x11; this profile is asymmetric.
        3. If the IUT does not initiate a PHY procedure, skip to Step 9 for an
           accepted command, or to the next row for a rejected command.
        4. Otherwise receive LL_PHY_REQ with nonzero supported TX/RX sets.
           Send LL_PHY_UPDATE_IND according to the row's Lower Tester preference:
            a. PHY_C_TO_P = row C_TO_P preference AND request RX_PHYS.
            b. PHY_P_TO_C = row P_TO_C preference AND request TX_PHYS.
            c. If request TX_PHYS/RX_PHYS contain the same single PHY, select
               that PHY in both directions or no change, overriding a/b.
            d. Replace a selected PHY equal to its current directional PHY
               with zero, indicating no change in that direction.
            e. For a nonzero change, choose Instant more than six and fewer
               than 32767 events ahead, modulo 65536; otherwise use Instant=0.
        5. Require acknowledgement of LL_PHY_UPDATE_IND from the Peripheral.
        6. Continue empty DATA with old PHYs and independent channel/ACK state
           until the event counter reaches the Instant.
        7. At the Instant, maintain DATA using each selected directional PHY;
           preserve the old PHY for any zero update field.
        8. Exchange further correctly acknowledged empty DATA using those PHYs.
        9. If the HCI command was accepted or either update PHY field was nonzero,
           require successful PHY Update Complete with the same handle and exact
           directional TX/RX values. For no change, report prior values. Otherwise
           prohibit PHY Update Complete.

    Expected Outcome:
        Pass verdict:
            Every emitted request has nonzero TX/RX fields; symmetric-only
            requests, where applicable, select one identical PHY. Updates are
            acknowledged, applied at the Instant and maintained thereafter.
            HCI notification eligibility and directional values match Step 9.
        Fail verdict:
            A command requesting an unsupported PHY bit is accepted.
        Inconclusive verdict:
            No PHY Update Procedure is initiated during the complete test.

    Coverage Note:
        The full table includes twelve RFU/unsupported-bit HCI rows. Reduced-PHY
        and symmetric-only profiles are not substituted for the selected profile.
        Validate every source table tuple, independent directional selection,
        no-change handling, no early successful HCI completion and no duplicate
        completion. Disconnect after both ordered and random passes.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-40-C procedure in
        Section 4.3.5, Table 4.3-41, Figure 4.3-76;
        PDF 639-643, printed 4.3-166 through 4.3-170.
    """
    await _phy_update(tester, central=False, local=True)


async def responding_to_phy_update_procedure(tester):
    """Responding to PHY Update Procedure.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers, initial LE 1M in both directions, and the profile supporting
        LE 2M, LE Coded and asymmetric links; use Table 4.3-44.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03, expressing no preference,
           and require successful Command Status.
        2. Require successful PHY Update Complete with the handle/current PHYs.
        3. Execute Steps 4-11 for all 49 Table 4.3-44 cases in order, then
           every case again in deterministic seeded random order (2N rounds).
        4. Send LL_PHY_REQ with the row's TX_PHYS and RX_PHYS.
        5. Receive LL_PHY_RSP with at least one supported PHY bit in each field.
        6. Send LL_PHY_UPDATE_IND using these directional selection rules:
            a. Intersect request TX_PHYS and response RX_PHYS for C_TO_P.
               Use zero/single bit directly; for several bits, choose the first
               available bit in the row's ordered C_TO_P preference list.
            b. Intersect request RX_PHYS and response TX_PHYS for P_TO_C.
               Resolve multiple bits using the ordered P_TO_C preference list.
            c. If both IUT response fields specify the same single PHY, use it
               symmetrically if permitted by the request, otherwise no change;
               this overrides a/b.
            d. Encode zero for a directional PHY equal to the current PHY.
            e. For a nonzero change, select Instant more than six and fewer
               than 32767 events ahead, modulo 65536; otherwise set Instant=0.
        7. Require acknowledgement of LL_PHY_UPDATE_IND. If both selected PHY
           fields are zero, proceed directly to Step 11.
        8. Continue correctly acknowledged empty DATA on old PHYs until Instant.
        9. At Instant, maintain the link using the selected new directional PHYs.
        10. Exchange further empty DATA and ACKs on the selected PHYs.
        11. For an actual change, require successful PHY Update Complete with
            exact handle and TX/RX PHYs, retaining old values for zero fields.
            For no change in both directions, prohibit PHY Update Complete.

    Expected Outcome:
        Pass verdict:
            Each request receives a nonzero supported response, each update is
            acknowledged and applied at its Instant, DATA continues on selected
            PHYs, and HCI events occur only for real changes with correct fields.
        Inconclusive verdict:
            No PHY change occurs during the complete test under the selection
            rules in Step 6.

    Coverage Note:
        Check all 49 source tuples, including ordered multi-bit preferences;
        reduced-feature Tables 4.3-42/43 do not apply to this profile. Complete
        any initial no-preference procedure without changing LE 1M, reject early
        or duplicate completion, and disconnect after both passes. For no change,
        perform two additional DATA exchanges solely to observe forbidden HCI
        events; these do not introduce an Instant or change either PHY.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-42-C procedure in
        Section 4.3.5, Tables 4.3-42/43/44, Figure 4.3-77;
        PDF 643-648, printed 4.3-170 through 4.3-175.
    """
    await _phy_update(tester, central=False, local=False)


async def handling_protocol_collision_same_procedure(tester):
    """Handling Protocol Collision – Same Procedure.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers, initial LE 1M in both directions, and supported LE 2M
        as the non-1M target. The Lower Tester acts as Central.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0, TX/RX preferring LE 2M and
           PHY_options=0x0000; require successful Command Status.
        2. Receive LL_PHY_REQ; if none is emitted, report Inconclusive. Send a
           Central LL_PHY_REQ preferring LE 2M in both directions, then reject
           the IUT request with LL_REJECT_EXT_IND identifying PHY_REQ/error 0x23.
        3. Allow an optional PHY Update Complete only with error 0x23 and the
           same connection handle, retaining current LE 1M directional values.
        4. Receive LL_PHY_RSP to the preserved Central request, with nonzero
           supported TX/RX fields, after the local request has been rejected.
        5. Send LL_PHY_UPDATE_IND selecting LE 2M in both directions and Instant
           more than six and fewer than 32767 events ahead; require the IUT ACK.
        6. Continue empty DATA and ACKs with old PHYs until the Instant.
        7. At the Instant, maintain the connection on the selected LE 2M PHYs.
        8. Exchange further correctly acknowledged DATA using the new PHYs.
        9. Require successful PHY Update Complete for the handle with both
           directional PHY fields equal to the LE 2M selection in Step 2.

    Expected Outcome:
        Pass verdict:
            The IUT requests the update, reports optional local rejection only
            with error 0x23, and preserves/responds to the Central request after
            LL_REJECT_EXT_IND. It acknowledges and adopts the update at Instant
            and reports the selected PHYs through HCI.
        Inconclusive verdict:
            No LL_PHY_REQ is sent by the IUT in Step 2.

    Coverage Note:
        Prohibit answering/rejecting the Central request before local rejection,
        premature successful HCI completion, and duplicate/unrelated PHY events.
        Verify post-collision ACL payload delivery and then terminate via HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-44-C procedure in
        Section 4.3.5, Figure 4.3-78; PDF 648-650, printed 4.3-175 through 4.3-177.
    """
    await _phy_collision_peripheral_collision(tester, procedure='phy')


async def protocol_timeout_for_phy_update_procedure(tester):
    """Protocol Timeout for PHY Update Procedure.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers and initial LE 1M; the Lower Tester acts as Central and
        maintains the ACL to prevent an unrelated supervision timeout.

    Test Steps:
        1. Send HCI LE Set PHY preferring supported LE 2M instead of LE 1M
           in both directions with PHY_options=0x0000; require Command Status.
        2. Receive LL_PHY_REQ with nonzero supported TX/RX fields. If no request
           is sent, report Inconclusive.
        3. Acknowledge LL_PHY_REQ but do not send LL_PHY_UPDATE_IND. Continue
           valid empty DATA and ACKs, preserving the existing LE 1M connection.
        4. Allow optional PHY Update Complete only with a nonzero status and
           the same connection handle; prohibit premature successful completion.
        5. At the procedure response timeout, require successful Disconnection
           Complete with the handle and LL Response Timeout reason (0x22),
           followed by cessation of connection RF traffic.

    Expected Outcome:
        Pass verdict:
            The IUT disconnects with reason 0x22 when the control transaction
            timer expires and stops maintaining the connection. Any optional
            PHY Update Complete has nonzero status.
        Inconclusive verdict:
            The IUT does not initiate LL_PHY_REQ in Step 2.

    Coverage Note:
        Core 6.3 Vol 6, Part B, Section 5.2 starts the response timer on procedure
        initiation and resets it for queued LL Control PDUs, not on first RF TX.
        Bracket the unobservable request-enqueue time between HCI submission and
        the observed first LL_PHY_REQ transmission, not HCI Command Status.
        Require 40-s expiry within that bracket plus 1-ms observation resolution;
        maintain DATA throughout to isolate procedure timeout from supervision.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-45-C procedure in
        Section 4.3.5, Figure 4.3-79; PDF 650-651, printed 4.3-177 through 4.3-178.
    """
    await _phy_timeout(tester, central=False, local=True)


async def handling_protocol_collision_different_procedure_channel_map(tester):
    """Handling Protocol Collision – Different Procedure – Channel Map.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers, initial LE 1M and supported LE 2M as the requested PHY.
        The Lower Tester acts as Central and maintains the ACL handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0, TX/RX preferring LE 2M and
           PHY_options=0x0000; require successful Command Status.
        2. Receive LL_PHY_REQ. If no request is sent, report Inconclusive.
        3. Send LL_CHANNEL_MAP_IND with a valid new map and future Instant,
           then LL_REJECT_EXT_IND naming PHY_REQ with error 0x2A.
           Require the IUT to acknowledge both control PDUs.
        4. Require PHY Update Complete with the same handle and status 0x2A,
           retaining the existing LE 1M values in both directions.
        5. Continue empty DATA and ACKs on the old map until Instant, then
           maintain the connection on the accepted new map without a PHY change.

    Expected Outcome:
        Pass verdict:
            The IUT sends its PHY request, reports the correct collision error
            0x2A, and correctly handles the Central's channel-map update.

    Coverage Note:
        Independently compute old/new hopping over a valid even-channel map.
        Read back the map through HCI, verify continued ACL payload transfer,
        prohibit extra PHY completion and terminate the original link via HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-46-C procedure in
        Section 4.3.5, Figure 4.3-80; PDF 651-652, printed 4.3-178 through 4.3-179.
    """
    await _phy_collision_peripheral_collision(tester, procedure='map')


async def handling_protocol_collision_different_procedure_connection_parameters(tester):
    """Handling Protocol Collision – Different Procedure – Connection Parameters.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers and initial LE 1M in both directions; the Lower Tester
        maintains the Central role and existing connection handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0, both directions preferring
           supported LE 2M and PHY_options=0x0000; require Command Status.
        2. Receive LL_PHY_REQ. If none is sent, report Inconclusive.
        3. Send a Central LL_CONNECTION_PARAM_REQ, then LL_REJECT_EXT_IND
           identifying the IUT PHY_REQ and error 0x2A; require both ACKs.
        4. Require the IUT Host approval request for the Central's connection
           parameters, checking the handle and all requested parameter fields.
        5. Require PHY Update Complete with status 0x2A, the existing handle,
           and unchanged directional LE 1M values.
        6. Accept the Central parameter request through HCI Remote Connection
           Parameter Request Reply; require success and the same handle.
        7. Receive LL_CONNECTION_PARAM_RSP and validate its actual parameters.
        8. Send a valid LL_CONNECTION_UPDATE_IND based on that response and
           require an acknowledgement from the IUT.
        9. Continue empty DATA and ACKs with old parameters until the Instant.
        10. Starting at the Instant, maintain DATA using the new parameters.
        11. Require successful Connection Update Complete with the handle and
            exact accepted interval, latency and supervision timeout.

    Expected Outcome:
        Pass verdict:
            The IUT initiates PHY update and reports its collision failure 0x2A,
            preserves/accepts the Central parameter request, acknowledges the
            update, adopts it at Instant and reports the new HCI parameters.
            The original ACL remains usable after the update.
        Inconclusive verdict:
            No LL_PHY_REQ is sent by the IUT in Step 2.

    Coverage Note:
        Select minimum interval, zero latency and 3-s timeout in the Central
        request. Require both Host notifications before approving the request,
        reject early successful update or extra PHY events, verify post-update
        ACL payload delivery and then terminate through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-47-C procedure in
        Section 4.3.5, Figure 4.3-81; PDF 653-655, printed 4.3-180 through 4.3-182.
    """
    await _phy_collision_peripheral_collision(tester, procedure='parameters')


async def handling_protocol_collision_different_procedure_connection_update(tester):
    """Handling Protocol Collision – Different Procedure – Connection Update.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers and initial LE 1M in both directions; the Lower Tester
        maintains the Central role and existing connection handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0, both directions preferring
           supported LE 2M and PHY_options=0x0000; require Command Status.
        2. Receive LL_PHY_REQ. If none is sent, report Inconclusive.
        3. Send a valid Central LL_CONNECTION_UPDATE_IND with a future Instant,
           then LL_REJECT_EXT_IND identifying PHY_REQ with error 0x2A.
           Require the IUT to acknowledge both Central control packets.
        4. Require PHY Update Complete with status 0x2A, the existing handle,
           and unchanged directional LE 1M values.
        5. Continue empty DATA and ACKs on old parameters until the Instant.
        6. Maintain DATA with the new parameters starting at the Instant.
        7. Require successful Connection Update Complete with exact accepted
           interval, latency, supervision timeout and the original handle.

    Expected Outcome:
        Pass verdict:
            The IUT sends its PHY request and reports collision error 0x2A,
            acknowledges/adopts the Central connection update at the assigned
            event, reports the new parameters through HCI and maintains the ACL.
        Inconclusive verdict:
            No LL_PHY_REQ is sent by the IUT in Step 2.

    Coverage Note:
        Select minimum interval, zero latency, 3-s supervision timeout and
        an Instant more than six events ahead. Prohibit loss/rejection of the
        Central update and early successful HCI completion, verify continued
        ACL data after the Instant, and terminate through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-48-C procedure in
        Section 4.3.5, Figure 4.3-82; PDF 655-657, printed 4.3-182 through 4.3-184.
    """
    await _phy_collision_peripheral_collision(tester, procedure='update')


async def initiating_phy_update_procedure_packet_time_restrictions(tester):
    """Initiating PHY Update Procedure – Packet Time Restrictions.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers
        and a 60-ms common interval. The Lower Tester acts as Central; initially
        both directions use LE 1M, with LE 2M and DLE supported.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03; require Command Status.
        2. Require PHY Update Complete indicating LE 1M in both directions.
        3. Send a Central LL_PHY_REQ preferring LE 2M for TX/RX.
        4. Receive LL_PHY_RSP with nonzero fields including LE 2M in both
           directions; otherwise report Inconclusive.
        5. Send LL_PHY_UPDATE_IND selecting LE 2M in both directions with Instant
           more than six and fewer than 32767 events ahead. Complete the procedure
           and require HCI completion reporting LE 2M in both directions.
        6. Send HCI LE Set Data Length with TxTime=0x0148 (328 us), TxOctets=32;
           require successful Command Complete.
        7. Answer an IUT DLE with RxTime=328 us/RxOctets=32, or initiate DLE
           with those values if the IUT does not. Report Inconclusive if the IUT
           chooses TxTime<328 us or TxOctets<32.
        8. Continuously queue 32-octet Host start packets through HCI, respecting
           buffer credits, throughout the remainder of the procedure.
        9. Observe at least one unfragmented 32-octet DATA matching the Host
           payload. Fragmentation at this stage is Inconclusive.
        10. Send HCI LE Set PHY with ALL_PHYS=0 and TX/RX preferring LE 1M.
        11. Receive LL_PHY_REQ permitting LE 1M in both directions, or report
            Inconclusive. Respond with LL_PHY_UPDATE_IND selecting LE 1M and
            Instant more than six and fewer than 32767 events ahead.
        12. From transmission of Step 11 LL_PHY_REQ, require every subsequent
            received DATA payload to be <=31 octets, before and after the update.
        13. Complete the PHY procedure while continuing 32-octet Host start
            packets, correct DATA acknowledgement, and independent reassembly.
        14. At the indicated Instant, maintain the link using LE 1M.
        15. Require PHY Update Complete with the handle and both PHYs=LE 1M.
        16. Continue queueing/receiving DATA for at least ten events after Instant,
            requiring every DATA payload <=31 octets and exact reconstructed data.

    Expected Outcome:
        Pass verdict:
            DATA before LL_PHY_REQ is unfragmented and exactly 32 octets;
            DATA after it is <=31 octets. The IUT changes to LE 1M at Instant.
            Every PDU fits effective receive-octet and receive-time limits.
            For the first two DATA packets after DLE, including retransmissions,
            allow the greater pre/post-DLE limits as described by the source.
        Inconclusive verdict:
            LE 2M or LE 1M cannot be selected at its specified step, DLE values
            are too small, or DATA was fragmented before the initiating request.

    Source Correction:
        Step 3 names ALL_PHYS on LL_PHY_REQ, but that field exists only in the
        HCI command. The wire request carries TX_PHYS/RX_PHYS for LE 2M.
        Steps 8/13 describe Host data using LLID; send HCI start PB=0x00,
        which maps to air LLID=0b10, rather than treating LLID as an HCI field.

    Coverage Note:
        Both previous DLE limits are <= the new 32-octet/328-us limits, so the
        first-two-packet grace does not enlarge the active receive bound.
        Check every PDU's airtime, LLID/SN and bytes, all Host completion credits,
        old PHY until Instant and new PHY thereafter. Drain and disconnect.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-49-C procedure in
        Section 4.3.5, Figures 4.3-83/84; PDF 657-661,
        printed 4.3-184 through 4.3-188.
    """
    await _packet_time_restrictions(
        tester, central=False, local=True, coded=False, no_change=False
    )


async def responding_to_phy_update_procedure_packet_time_restrictions(tester):
    """Responding to PHY Update Procedure – Packet Time Restrictions.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers
        and a 60-ms common interval. The Lower Tester acts as Central; initially
        both directions use LE 1M, with LE 2M and DLE supported.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03; require Command Status.
        2. Require PHY Update Complete indicating LE 1M in both directions.
        3. Send a Central LL_PHY_REQ preferring LE 2M for TX/RX.
        4. Receive LL_PHY_RSP with nonzero fields including LE 2M in both
           directions; otherwise report Inconclusive.
        5. Send LL_PHY_UPDATE_IND selecting LE 2M in both directions with Instant
           more than six and fewer than 32767 events ahead. Complete the procedure
           and require HCI completion reporting LE 2M in both directions.
        6. Send HCI LE Set Data Length with TxTime=0x0148 (328 us), TxOctets=32;
           require successful Command Complete.
        7. Answer an IUT DLE with RxTime=328 us/RxOctets=32, or initiate DLE
           with those values if the IUT does not. Report Inconclusive if the IUT
           chooses TxTime<328 us or TxOctets<32.
        8. Continuously queue 32-octet Host start packets through HCI, respecting
           buffer credits, throughout the remainder of the procedure.
        9. Observe at least one unfragmented 32-octet DATA matching the Host
           payload. Fragmentation at this stage is Inconclusive.
        10. Send LL_PHY_REQ with TX_PHYS=RX_PHYS=0x01 (LE 1M).
        11. Receive LL_PHY_RSP permitting LE 1M in both directions, or report
            Inconclusive. Respond with LL_PHY_UPDATE_IND selecting LE 1M and
            Instant more than six and fewer than 32767 events ahead.
        12. From transmission of Step 11 LL_PHY_RSP, require every subsequent
            received DATA payload to be <=31 octets, before and after the update.
        13. Complete the PHY procedure while continuing 32-octet Host start
            packets, correct DATA acknowledgement, and independent reassembly.
        14. At the indicated Instant, maintain the link using LE 1M.
        15. Require PHY Update Complete with the handle and both PHYs=LE 1M.
        16. Continue queueing/receiving DATA for at least ten events after Instant,
            requiring every DATA payload <=31 octets and exact reconstructed data.

    Expected Outcome:
        Pass verdict:
            DATA before LL_PHY_RSP is unfragmented and exactly 32 octets;
            DATA after it is <=31 octets. The IUT changes to LE 1M at Instant.
            Every PDU fits effective receive-octet and receive-time limits.
            The first two DATA packets after DLE, including retransmissions,
            may use the greater pre/post-DLE limits.
        Inconclusive verdict:
            LE 2M or LE 1M cannot be selected at its specified step, DLE values
            are too small, or DATA was fragmented before the responding PHY PDU.

    Source Correction:
        Step 3 names ALL_PHYS on LL_PHY_REQ, but its wire fields are only
        TX_PHYS/RX_PHYS. Steps 8/13's Host LLID wording maps to HCI start
        PB=0x00, which produces air LLID=0b10.

    Coverage Note:
        Previous DLE limits are <= the new 32-octet/328-us limits, so the
        first-two-packet grace adds no larger bound in this trial. Check every
        PDU's airtime, LLID/SN and bytes, all Host credits, directional PHYs at
        Instant and no duplicate HCI completion; drain and disconnect.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-50-C procedure in
        Section 4.3.5, Figures 4.3-85/86; PDF 661-665,
        printed 4.3-188 through 4.3-192.
    """
    await _packet_time_restrictions(
        tester, central=False, local=False, coded=False, no_change=False
    )


async def protocol_timeout_for_phy_update_procedure_no_update_request(tester):
    """Protocol Timeout for PHY Update Procedure – No Update Request.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common interval/channel parameters, selected timeout and SCA. Select
        public peers and initial LE 1M; the Lower Tester maintains the Central
        role and valid DATA so supervision cannot cause the disconnection.

    Test Steps:
        1. Send LL_PHY_REQ with TX_PHYS and RX_PHYS preferring supported LE 2M
           rather than LE 1M.
        2. Receive LL_PHY_RSP with at least one bit set in each field and
           acknowledge it, but do not send LL_PHY_UPDATE_IND.
        3. Allow optional PHY Update Complete only with a nonzero status and
           the same established connection handle.
        4. At the procedure response timeout, require successful Disconnection
           Complete with the handle and LL Response Timeout reason (0x22),
           followed by cessation of connection RF traffic.

    Expected Outcome:
        Pass verdict:
            The IUT responds with nonzero PHY_RSP fields, reports disconnection
            with reason 0x22 when the control transaction timer expires, and
            stops maintaining the link. Any optional PHY completion has nonzero
            status, not a successful or unrelated completion.

    Coverage Note:
        Continue empty DATA/ACKs without the missing update. Bound the internal
        response-enqueue time between Lower Tester submission and observed
        LL_PHY_RSP transmission; check 40-s expiry within that bracket plus
        1-ms observation resolution, then verify RF cessation.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-51-C procedure in
        Section 4.3.5, Figure 4.3-87; PDF 665-666, printed 4.3-192 through 4.3-193.
    """
    await _phy_timeout(tester, central=False, local=False)


async def initiating_phy_update_procedure_packet_time_restrictions_no_change(tester):
    """Initiating PHY Update Procedure – Packet Time Restrictions, No Change.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers,
        a 60-ms common interval, initial LE 1M and support for LE 2M/DLE.
        The Lower Tester acts as Central and maintains the ACL handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03; require Command Status.
        2. Require PHY Update Complete reporting LE 1M in both directions.
        3. Send Central LL_PHY_REQ preferring LE 2M in both TX/RX fields.
        4. Receive nonzero LL_PHY_RSP fields permitting LE 2M both ways,
           otherwise report Inconclusive.
        5. Send a bidirectional LE 2M update with Instant more than six and
           fewer than 32767 events ahead, complete it, and require HCI LE 2M.
        6. Send HCI LE Set Data Length with TxOctets=32 and TxTime=328 us.
        7. Answer an IUT DLE or initiate peer DLE if absent, with RxOctets=32
           and RxTime=328 us. Smaller IUT TX values are Inconclusive.
        8. Continuously queue 32-octet Host start packets through HCI, respecting
           buffer credits throughout the rest of the procedure.
        9. Receive at least one matching unfragmented 32-octet DATA packet;
           pre-procedure fragmentation is Inconclusive.
        10. Send HCI LE Set PHY with ALL_PHYS=0 and TX/RX preferring LE 1M.
        11. Receive LL_PHY_REQ whose TX_PHYS includes LE 1M; otherwise report
            Inconclusive. Delay the update until at least 140 DATA octets have
            been received; insufficient DATA before response timeout is
            Inconclusive. RX_PHYS need not contain LE 1M for this no-change case.
        12. Require every DATA payload after that LL_PHY_REQ and before the
            Lower Tester's update to contain <=31 octets; a larger packet fails.
        13. Send LL_PHY_UPDATE_IND with both PHY fields and Instant all zero,
            selecting no change in either direction.
        14. Require successful PHY Update Complete with the same handle and
            both directional PHYs still LE 2M.

    Expected Outcome:
        Pass verdict:
            DATA before LL_PHY_REQ is unfragmented/exactly 32 octets; DATA after
            it is <=31 octets until Step 13's update is transmitted. Every DATA
            fits effective receive-octet/time bounds. For the first two packets
            after DLE, including retransmissions, allow the greater old/new limits.
        Inconclusive verdict:
            Initial LE 2M selection is unavailable, DLE TX values are too small,
            pre-request DATA is fragmented, request TX_PHYS lacks LE 1M, or fewer
            than 140 DATA octets arrive before the response timeout.

    Source Correction:
        Step 3's ALL_PHYS is not a wire LL_PHY_REQ field; use TX_PHYS/RX_PHYS.
        Host start data in Step 8 uses HCI PB=0x00, mapped to air LLID=0b10.

    Coverage Note:
        Apply the 31-octet limit from observed PHY_REQ until transmitting the
        no-change update, not until its HCI notification. The greater DLE bounds
        equal the new 32/328 limits in this trial. Distinguish valid procedure
        timeout from early/wrong-handle/wrong-reason failures when classifying
        missing DATA. Check ACKs, fragment bytes and all Host credits; disconnect.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-52-C procedure in
        Section 4.3.5, Figures 4.3-88/89; PDF 666-669,
        printed 4.3-193 through 4.3-196.
    """
    await _packet_time_restrictions(
        tester, central=False, local=True, coded=False, no_change=True
    )


async def responding_to_phy_update_procedure_packet_time_restrictions_no_change(tester):
    """Responding to PHY Update Procedure – Packet Time Restrictions, No Change.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers,
        a 60-ms common interval, initial LE 1M and support for LE 2M/DLE.
        The Lower Tester acts as Central and maintains the ACL handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03; require Command Status.
        2. Require PHY Update Complete reporting LE 1M in both directions.
        3. Send Central LL_PHY_REQ preferring LE 2M in both TX/RX fields.
        4. Receive nonzero LL_PHY_RSP fields permitting LE 2M both ways,
           otherwise report Inconclusive.
        5. Send a bidirectional LE 2M update with Instant more than six and
           fewer than 32767 events ahead, complete it, and require HCI LE 2M.
        6. Send HCI LE Set Data Length with TxOctets=32/TxTime=328 us;
           require successful Command Complete.
        7. Answer an IUT DLE or initiate peer DLE if absent, with RxOctets=32
           and RxTime=328 us. Smaller IUT TX values are Inconclusive.
        8. Continuously queue 32-octet Host start packets through HCI, respecting
           buffer credits throughout the rest of the procedure.
        9. Receive at least one matching unfragmented 32-octet DATA packet;
           pre-procedure fragmentation is Inconclusive.
        10. Send LL_PHY_REQ with TX_PHYS=RX_PHYS=0x03 (LE 1M and LE 2M).
        11. Receive LL_PHY_RSP with nonzero TX/RX fields and TX_PHYS containing
            LE 1M, otherwise report Inconclusive. Delay the update until at least
            140 DATA octets have arrived; insufficient DATA before response
            timeout is Inconclusive. RX_PHYS need not include LE 1M.
        12. Require every DATA payload after that LL_PHY_RSP and before the
            Lower Tester's update to contain <=31 octets; a larger packet fails.
        13. Send LL_PHY_UPDATE_IND with both PHY fields and Instant all zero,
            selecting no change in either direction.

    Expected Outcome:
        Pass verdict:
            DATA before LL_PHY_RSP is unfragmented/exactly 32 octets; DATA after
            it is <=31 octets until Step 13. Every DATA fits effective receive
            octet/time bounds. For the first two packets after DLE, including
            retransmissions, allow the greater old/new limits.
        Inconclusive verdict:
            Initial LE 2M selection is unavailable, DLE TX values are too small,
            pre-response DATA is fragmented, response TX_PHYS lacks LE 1M, or
            fewer than 140 DATA octets arrive before the response timeout.

    Source Correction:
        Step 3's ALL_PHYS is not a wire LL_PHY_REQ field; use TX_PHYS/RX_PHYS.
        Host start data in Step 8 uses HCI PB=0x00, mapped to air LLID=0b10.

    Coverage Note:
        End the 31-octet restriction before the update exchange. No actual PHY
        change occurs and no HCI PHY Update Complete is eligible for this remote
        no-change procedure. Verify reassembly/ACK/credits and then disconnect.
        Greater DLE grace bounds equal the new 32/328 limits in this trial;
        valid response-timeout Inconclusive does not mask earlier RF failures.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-53-C procedure in
        Section 4.3.5, Figures 4.3-90/91; PDF 670-673,
        printed 4.3-197 through 4.3-200.
    """
    await _packet_time_restrictions(
        tester, central=False, local=False, coded=False, no_change=True
    )


async def peripheral_receiving_data_le_coded_ci_change(tester):
    """Peripheral Receiving Data, LE Coded, CI Change.

    Initial Condition:
        An unencrypted connected Peripheral with public address, maximum supported
        interval (4 s), common latency/channel parameters and selected SCA.
        Select zero latency and a valid 32-s supervision timeout; retain the
        preamble handle, HCI buffer information and maximum data-length values.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03 and PHY_options=0x0000;
           require successful Command Status.
        2. Require PHY Update Complete with the handle and both PHYs=LE 1M.
        3. Send Central LL_PHY_REQ preferring LE Coded in both TX/RX fields.
        4. Receive nonzero LL_PHY_RSP fields containing LE Coded in both
           directions; otherwise report Inconclusive.
        5. Send LL_PHY_UPDATE_IND selecting LE Coded both ways and Instant more
           than six and fewer than 32767 events ahead. Complete the update and
           require HCI completion with both directional PHYs=LE Coded.
        6. If supported TX maxima exceed 27 octets or 328 us, send HCI LE Set
           Data Length with those maxima and require Command Complete;
           otherwise proceed to Step 8.
        7. Answer an IUT DLE or initiate peer DLE if absent. The Lower Tester's
           TX octets/time use IUT RX maxima; its RX values use IUT TX maxima.
           Validate the negotiated fields and eligible HCI data-length changes.
        8. Configure 288 DATA packets at the effective Lower Tester TX/IUT RX
           maximum. Increment payload octets continuously from 0x00 across all
           packet boundaries, wrapping after 0xFF. Use the exact eighteen-row,
           sixteen-entry-per-row CODING_PATTERN from source Step 8.
        9. Send DATA using the common channel selection and acknowledgement
           scheme. Require one empty, positive Peripheral ACK for every packet
           at T_IFS=150 +/-2 us, for both S=2 and S=8 coding.
        10. Require HCI ACL Data for the transmitted payloads, with the correct
            handle, boundary/broadcast flags, length and continuous byte sequence.
        11. Repeat Steps 8-10's transfer/reporting until all 288 configured
            packets have been acknowledged and reported, without duplicates.
        12. Repeat the complete Steps 8-11 exchange at the minimum 27-octet
            payload, restarting the payload sequence at 0x00.

    Expected Outcome:
        Pass verdict:
            Every DATA packet is acknowledged, every payload is reported intact
            and in order through HCI, and all responses satisfy 150 +/-2 us T_IFS.

    Source Correction:
        Step 3 names ALL_PHYS on LL_PHY_REQ; that field belongs to the HCI
        command, not this wire PDU. Use TX_PHYS/RX_PHYS for LE Coded.
        Step 8's pattern numbers 2/8 denote coding factors S=2/S=8, not literal
        two-bit CI values: Core 6.3 Vol 6, Part B, Section 2.2 maps CI=01 to
        S=2 and CI=00 to S=8.

    Coverage Note:
        Compare all eighteen pattern rows to PDF 676-677. Exchange the full
        sequence within one maximum-interval event using MD, measure each ACK
        against its own packet end, and verify exact physical airtime independently
        of the IUT. Disconnect through HCI after both 288-packet exchanges.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-54-C procedure in
        Section 4.3.5, Figure 4.3-92; PDF 674-677,
        printed 4.3-201 through 4.3-204. Common initial conditions: Section 4.1.6.
    """
    await _coded_reception(tester, central=False)


async def initiating_phy_update_procedure_packet_time_restrictions_le_coded(tester):
    """Initiating PHY Update Procedure – Packet Time Restrictions, LE Coded.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers,
        initial LE 1M and a 60-ms common interval; support LE Coded and DLE.
        The Lower Tester acts as Central and maintains the ACL handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03 and PHY_options=0x0000;
           require successful Command Status.
        2. Require PHY Update Complete with the handle and both PHYs=LE 1M.
        3. Send HCI LE Set Data Length with TxTime=0x04D8 (1240 us) and
           TxOctets=141; require successful Command Complete.
        4. Answer an IUT DLE with RxTime=1240 us/RxOctets=141, or initiate
           peer DLE if the IUT does not. Smaller IUT TX values are Inconclusive.
        5. Continuously queue 141-octet Host start packets through HCI,
           respecting buffer credits throughout the remaining steps.
        6. Receive matching unfragmented 141-octet DATA; fragmentation before
           the initiating PHY request is Inconclusive.
        7. Send HCI LE Set PHY with ALL_PHYS=0, PHY_options=0 and TX/RX
           preferring LE Coded; require successful Command Status.
        8. Receive LL_PHY_REQ permitting Coded in both directions, or report
           Inconclusive. Respond with a Coded/Coded LL_PHY_UPDATE_IND and
           Instant more than six and fewer than 32767 events ahead.
        9. From the IUT's LL_PHY_REQ, require every subsequent DATA payload
           to be <=140 octets, both before and after the PHY update.
        10. Complete the PHY procedure while continuously queueing 141-octet
            Host start packets and receiving correctly acknowledged DATA.
        11. At the indicated Instant, maintain the connection using LE Coded.
        12. Require successful PHY Update Complete with the handle and both
            directional PHYs=LE Coded.
        13. Continue Host queueing and DATA for at least ten events after Instant,
            requiring <=140-octet payloads and exact reconstructed Host bytes.

    Expected Outcome:
        Pass verdict:
            Pre-PHY_REQ DATA is unfragmented/exactly 141 octets; subsequent DATA
            is <=140 octets. The IUT changes PHY at Instant. Every DATA packet
            fits the effective receive-octet/time limits. For the first two packets
            after DLE, including retransmissions, allow the greater old/new limits.
        Inconclusive verdict:
            DLE TX values are below 141/1240, pre-PHY_REQ DATA is fragmented,
            the request cannot select Coded both ways, or the IUT autonomously
            sends LL_LENGTH_REQ after the PHY Instant.

    Source Correction:
        Steps 5/10 describe Host start data as LLID=0b10. Supply HCI start
        PB=0x00, which maps to that air LLID; HCI does not carry an LLID field.

    Coverage Note:
        Require actual full-size DATA before issuing Set PHY. Apply the size
        restriction at observed PHY_REQ, not only at Instant; account for Coded
        minimum effective times and verify each physical packet's airtime, all
        fragments and Host credits. Initial DLE grace does not exceed the newly
        negotiated bounds. Drain the DATA stream and disconnect through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-55-C procedure in
        Section 4.3.5, Figures 4.3-93/94; PDF 677-681,
        printed 4.3-204 through 4.3-208.
    """
    await _packet_time_restrictions(
        tester, central=False, local=True, coded=True, no_change=False
    )


async def responding_to_phy_update_procedure_packet_time_restrictions_le_coded(tester):
    """Responding to PHY Update Procedure – Packet Time Restrictions, LE Coded.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers,
        initial LE 1M and a 60-ms common interval; support LE Coded and DLE.
        The Lower Tester acts as Central and maintains the ACL handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03 and PHY_options=0x0000;
           require successful Command Status.
        2. Require PHY Update Complete with the handle and both PHYs=LE 1M.
        3. Send HCI LE Set Data Length with TxTime=0x04D8 (1240 us) and
           TxOctets=141; require successful Command Complete.
        4. Answer an IUT DLE with RxTime=1240 us/RxOctets=141, or initiate
           peer DLE if the IUT does not. Smaller IUT TX values are Inconclusive.
        5. Continuously queue 141-octet Host start packets through HCI,
           respecting buffer credits throughout the remaining steps.
        6. Receive matching unfragmented 141-octet DATA. Apply the Source
           Correction below: pre-procedure fragmentation is Inconclusive.
        7. Send LL_PHY_REQ with TX_PHYS=RX_PHYS=0x04 (LE Coded).
        8. Receive LL_PHY_RSP permitting Coded in both directions, or report
           Inconclusive. Respond with a Coded/Coded LL_PHY_UPDATE_IND and
           Instant more than six and fewer than 32767 events ahead.
        9. From the IUT's LL_PHY_RSP, require every subsequent DATA payload
           to be <=140 octets, both before and after the PHY update.
        10. Complete the PHY procedure while continuously queueing 141-octet
            Host start packets and receiving correctly acknowledged DATA.
        11. At the indicated Instant, maintain the connection using LE Coded.
        12. Require successful PHY Update Complete with the handle and both
            directional PHYs=LE Coded.
        13. Continue Host queueing and DATA for at least ten events after Instant,
            requiring <=140-octet payloads and exact reconstructed Host bytes.

    Expected Outcome:
        Pass verdict:
            Pre-PHY_RSP DATA is unfragmented/exactly 141 octets; subsequent DATA
            is <=140 octets. The IUT changes PHY at Instant. Every DATA packet
            fits effective receive-octet/time limits, with the greater old/new
            limits for the first two packets after DLE, including retransmissions.
        Inconclusive verdict:
            DLE TX values are below 141/1240, pre-PHY_RSP DATA is fragmented,
            the response cannot select Coded both ways, or autonomous LL_LENGTH_REQ
            follows the PHY Instant.

    Source Correction:
        Step 6 says initial fragmentation is Fail, but this procedure's explicit
        Inconclusive list names that same condition. Use Inconclusive: Core
        6.3 Vol 6, Part B, Section 5.1.9 constrains maximum DATA size, not a
        mandatory full-size fragment. Already-fragmented DATA cannot exercise
        the intended 141-to-140 boundary. Amber supports this local interpretation;
        no adopted SIG erratum was found. Post-PHY_RSP oversize DATA still fails.
        Steps 5/10's Host LLID wording maps HCI start PB=0x00 to air LLID=0b10.

    Coverage Note:
        Apply the restriction at observed PHY_RSP, not Instant. Verify actual
        initial full-size DATA, per-PDU airtime, independent fragment/byte/credit
        accounting, old/new PHY boundaries and ten post-Instant events. Initial
        DLE grace adds no larger bound here; drain and disconnect through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-56-C procedure in
        Section 4.3.5, Figures 4.3-95/96; PDF 681-685,
        printed 4.3-208 through 4.3-212.
    """
    await _packet_time_restrictions(
        tester, central=False, local=False, coded=True, no_change=False
    )


async def mandatory_minimum_pdu_length_le_coded(tester):
    """Mandatory Minimum PDU Length, LE Coded.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers,
        initial LE 1M, a 60-ms interval, zero latency and minimum data lengths.
        The Lower Tester acts as Central and maintains the ACL handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03 and PHY_options=0x0000;
           require successful Command Status.
        2. If the IUT sends LL_PHY_REQ, respond with LL_PHY_UPDATE_IND selecting
           no PHY change: PHY_C_TO_P=PHY_P_TO_C=0.
        3. Require PHY Update Complete with the handle and both PHYs=LE 1M.
        4. If the IUT autonomously initiates DLE, respond with Lower Tester
           RxOctets=27 and RxTime=328 us; retain minimum values both ways.
        5. Continuously queue 27-octet Host start packets through HCI,
           respecting buffer credits throughout the remaining procedure.
        6. Send HCI LE Set PHY with TX_PHYS=RX_PHYS=0x04, ALL_PHYS=0 and
           PHY_options=0; require successful Command Status.
        7. Receive the IUT's LL_PHY_REQ while maintaining DATA exchange.
        8. Choose the source alternative according to the request's PHY masks:
           8A. If both directions permit LE Coded:
               8A.1 Send LL_PHY_UPDATE_IND selecting Coded/Coded and an Instant
                    more than six and fewer than 32767 events ahead.
           8B. Otherwise:
               8B.1 Send LL_PHY_UPDATE_IND selecting the current PHYs.
               8B.2 Send LL_PHY_REQ with TX_PHYS=RX_PHYS=0x04.
               8B.3 Receive LL_PHY_RSP; if it cannot select LE Coded in both
                    directions, report Inconclusive.
               8B.4 Send LL_PHY_UPDATE_IND selecting Coded/Coded and an Instant
                    more than six and fewer than 32767 events ahead.
        9. Require received DATA payloads to remain at most 27 octets.
        10. Complete the PHY procedure while continuing 27-octet Host start
            packets and correctly sequenced DATA exchange.
        11. At the indicated Instant, maintain the connection using LE Coded.
        12. Require successful PHY Update Complete with both PHYs=LE Coded.
            If DLE is supported, also require Data Length Change with TX/RX
            octets=27 and TX/RX times=2704 us; either HCI event order is allowed.
        13. Continue Host queueing and reception for at least ten connection
            events after Instant, checking every DATA payload is <=27 octets.
        14. Repeat Steps 6-13 for LE 1M: change the requested PHY masks to 0x01,
            select LE 1M at Instant and require effective TX/RX times=328 us.

    Expected Outcome:
        Pass verdict:
            DATA remains <=27 octets and within effective receive-time limits.
            Both PHY changes occur at their Instants and produce the correct
            PHY completion and eligible data-length events. For the first two
            packets after DLE, including retransmissions, allow the greater
            old/new limits. Payloads, fragment boundaries and credits are intact.
        Inconclusive verdict:
            Step 8B.3 cannot select the requested PHY, or the IUT autonomously
            sends LL_LENGTH_REQ after the PHY Instant in Step 8A.1 or 8B.4.

    Coverage Note:
        Preserve optional initial DLE while collecting the PHY exchange; do not
        discard it as unrelated control traffic. The selected IUT supports DLE.
        Drain all queued Host data and disconnect after Step 14.

    Source Correction:
        The outcome references LL_PHY_RSP, which occurs only on fallback 8B;
        normal 8A uses PHY_REQ. Apply the 27-octet bound throughout both paths,
        including earlier DATA. Amber supports this local interpretation under
        Core Vol 6, Part B, Sections 4.5.10, 5.1.9 and 5.1.10.1; it is not a
        claimed adopted SIG erratum. Step 5's Host LLID=0b10 is HCI start PB=0x00.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-57-C procedure in
        Section 4.3.5, Figures 4.3-97/98; PDF 685-689,
        printed 4.3-212 through 4.3-216. Steps 1-14 including 8A/8B;
        referenced Core Vol 6, Part B, Section 5.1.9.
    """
    await _mandatory_coded_minimum(tester, central=False)


async def initiating_phy_update_procedure_packet_time_restrictions_no_change_le_coded(
    tester,
):
    """Initiating PHY Update Procedure – Packet Time Restrictions, No Change, LE Coded.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers,
        initial LE 1M and a 60-ms interval; support LE Coded and DLE. The Lower
        Tester acts as Central and maintains the ACL handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03 and PHY_options=0x0000;
           require successful Command Status.
        2. Require PHY Update Complete with the handle and both PHYs=LE 1M.
        3. Send HCI LE Set Data Length with TxTime=0x04D8 (1240 us) and
           TxOctets=141; require successful Command Complete.
        4. Answer an IUT DLE with RxTime=1240 us/RxOctets=141, or initiate
           peer DLE if the IUT does not. Smaller IUT TX values are Inconclusive.
        5. Continuously queue 141-octet Host start packets through HCI,
           respecting buffer credits throughout the remaining steps.
        6. Receive matching unfragmented 141-octet DATA; initial fragmentation
           is Inconclusive because the intended size boundary cannot be tested.
        7. Send HCI LE Set PHY with ALL_PHYS=0, PHY_options=0 and TX/RX
           preferring LE Coded; require successful Command Status.
        8. Receive LL_PHY_REQ with the Coded bit in TX_PHYS; otherwise report
           Inconclusive. Continue receiving DATA and withhold UPDATE until at
           least 423 DATA payload octets have arrived after PHY_REQ.
        9. From PHY_REQ until the Lower Tester sends UPDATE, require every
           DATA payload to be <=140 octets; oversize DATA fails. Fewer than
           423 octets before procedure response timeout is Inconclusive.
        10. Send LL_PHY_UPDATE_IND selecting no change, with all fields zero.
        11. Require successful PHY Update Complete with the handle and both
            PHYs still LE 1M.

    Expected Outcome:
        Pass verdict:
            Pre-PHY_REQ DATA is unfragmented/exactly 141 octets; pending-update
            DATA is <=140 octets. Every DATA packet fits effective receive-octet
            and receive-time limits, using the greater old/new bounds for the
            first two packets after DLE, including retransmissions. The local
            no-change procedure completes successfully without changing PHY.
        Inconclusive verdict:
            DLE TX values are below 141/1240, initial DATA is fragmented,
            TX_PHYS does not permit Coded, or fewer than 423 DATA octets arrive
            before the procedure response timeout.

    Source Correction:
        Step 5's Host LLID=0b10 means HCI start PB=0x00, which maps to that air
        LLID. HCI ACL Data does not carry an LLID field.

    Coverage Note:
        Require actual full-size DATA before Set PHY. Observe the restriction
        at PHY_REQ, not a nonexistent PHY-change Instant. Count only constrained
        DATA payload octets; release the temporary cap before receiving DATA
        responding to the all-zero UPDATE. Independently reassemble Host bytes,
        check airtime and completion credits, then drain and disconnect.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-58-C procedure in
        Section 4.3.5, Figures 4.3-99/100; PDF 689-692,
        printed 4.3-216 through 4.3-219. Steps 1-11 and Expected Outcome;
        referenced Core Vol 6, Part B, Section 5.1.10.1.
    """
    await _packet_time_restrictions(
        tester, central=False, local=True, coded=True, no_change=True
    )


async def responding_to_phy_update_packet_time_limits_no_change_le_coded(
    tester,
):
    """Responding to PHY Update Procedure – Packet Time Restrictions, No Change, LE
    Coded.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters, selected timeout and SCA. Select public peers,
        initial LE 1M and a 60-ms interval; support LE Coded and DLE. The Lower
        Tester acts as Central and maintains the ACL handle.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03 and PHY_options=0x0000;
           require successful Command Status.
        2. Require PHY Update Complete with the handle and both PHYs=LE 1M.
        3. Send HCI LE Set Data Length with TxTime=0x04D8 (1240 us) and
           TxOctets=141; require successful Command Complete.
        4. Answer an IUT DLE with RxTime=1240 us/RxOctets=141, or initiate
           peer DLE if the IUT does not. Smaller IUT TX values are Inconclusive.
        5. Continuously queue 141-octet Host start packets through HCI,
           respecting buffer credits throughout the remaining steps.
        6. Receive matching unfragmented 141-octet DATA; initial fragmentation
           is Inconclusive because the intended size boundary cannot be tested.
        7. Send LL_PHY_REQ with TX_PHYS=RX_PHYS=0x05 (LE 1M and LE Coded).
        8. Receive LL_PHY_RSP with at least one bit in each PHY field and the
           Coded bit in TX_PHYS; otherwise report Inconclusive for missing Coded
           support. Continue receiving DATA and withhold UPDATE until at least
           423 DATA payload octets have arrived after PHY_RSP.
        9. From PHY_RSP until the Lower Tester sends UPDATE, require every
           DATA payload to be <=140 octets; oversize DATA fails. Fewer than
           423 octets before procedure response timeout is Inconclusive.
        10. Send LL_PHY_UPDATE_IND selecting no change, with all fields zero.

    Expected Outcome:
        Pass verdict:
            Pre-PHY_RSP DATA is unfragmented/exactly 141 octets; pending-update
            DATA is <=140 octets. Every DATA packet fits effective receive-octet
            and receive-time limits, using the greater old/new bounds for the
            first two packets after DLE, including retransmissions.
        Inconclusive verdict:
            DLE TX values are below 141/1240, initial DATA is fragmented,
            TX_PHYS does not permit Coded, or fewer than 423 DATA octets arrive
            before the procedure response timeout.

    Source Correction:
        Step 5's Host LLID=0b10 means HCI start PB=0x00, which maps to that air
        LLID. HCI ACL Data does not carry an LLID field.

    Coverage Note:
        Unlike the locally initiated procedure, no PHY Update Complete event
        is expected for this remote no-change procedure. Observe the size cap
        at PHY_RSP and count only constrained payload octets. Release the cap
        before receiving DATA responding to the all-zero UPDATE. Independently
        reassemble Host bytes, check airtime and credits, drain and disconnect.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-59-C procedure in
        Section 4.3.5, Figures 4.3-101/102; PDF 692-695,
        printed 4.3-219 through 4.3-222. Steps 1-10 and Expected Outcome;
        referenced Core Vol 6, Part B, Section 5.1.10.1.
    """
    await _packet_time_restrictions(
        tester, central=False, local=False, coded=True, no_change=True
    )


async def peripheral_responding_to_data_length_update_le_1m_phy(
    tester,
):
    """Peripheral Data Length Update – Responding to Data Length Update Procedure; LE 1M
    PHY.

    Initial Condition:
        An unencrypted connected Peripheral with public own/peer addresses and
        common channel parameters. Read declared supported RX/TX octets/times
        and HCI ACL buffer capacity; require valid Core ranges. The Lower
        Tester acts as Central. Select a 30-ms interval on LE 1M/2M and 60 ms
        on Coded to accommodate maximum-length bidirectional S=8 traffic.
        Specification octet bounds are 27..251; time bounds are 328..17040 us.
        Establish peer DLE/2M/Coded feature support before the procedure.

    Test Steps:
        1. Use alternative 1A:
           1A.1 Retain the initial LE 1M PHY and move to Step 2.
        2. For each round of Table 4.3-61, send LL_LENGTH_REQ with its four
           Lower Tester TX/RX octet/time fields, in RX-first wire order.
        3. Receive LL_LENGTH_RSP and check all four IUT fields are between
           the specification minima and the declared supported IUT maxima.
        4. Derive effective TX/RX octets/times from both PDUs. Require Data
           Length Change with the new values exactly when a limit changes;
           unchanged limits must not produce an event. The source permits
           uncertainty about the first round's previous values.
        5. Send the Host data in the minimum number of HCI ACL packets allowed
           by the HCI buffer size. If multiple packets are needed, submit all
           together after one event closes and before the next begins.
        6. Receive every DATA packet until the complete Host payload arrives.
           Check each packet's effective TX octet and airtime limits.
        7. Require received bytes to equal exactly the Host data from Step 5.
        8. Send at least twenty DATA packets, each using the lesser of the
           effective IUT RX octet limit and the payload that fits its RX time
           budget on the current PHY.
        9. Require HCI ACL Data to reproduce exactly the Step 8 bytes with the
           correct handle, boundary flags and lengths. Repeat Steps 2-9 for
           all sixteen source rows; duplicate rows may be omitted, not required.
        10. If the IUT supports LE Coded, repeat Steps 2-9 for every row with
            either Lower Tester time field at the specification maximum,
            replacing that maximum with 2128 us in each applicable field.

    Expected Outcome:
        Pass verdict:
            The prescribed request/response exchange succeeds. Effective
            changes produce exactly the appropriate HCI length events, while
            unchanged limits produce none. All RF/HCI data matches exactly
            and respects effective octet/time limits.

    Coverage Note:
        Table 4.3-61 is translated to RX-first wire fields, not copied in its
        displayed TX-first order. Seed the four independent random rows for
        reproducibility; exclude specification extrema/tester maxima. Compare
        changed events against previously observed wire-derived limits. Check
        every MD packet, SN/LLID, exact Host bytes and completed-packet credits.
        Drain the data exchanges and disconnect through HCI after completion.

    Reference:
        LL.TS.p28, LL/CON/PER/BV-77-C referral on PDF 695,
        printed 4.3-222; inherits LL/CON/CEN/BV-73-C with
        the IUT role changed to Peripheral.
        Inherited Section 4.3.6.2, Table 4.3-61, Figure 4.3-183;
        PDF 837-841, printed 4.3-364 through 4.3-368. Steps 1-10 and outcome.
    """
    await _data_length(tester, central=False, local=False, phy=Phy.LE_1M)


async def peripheral_initiating_data_length_update_le_1m_phy(
    tester,
):
    """Peripheral Data Length Update – Initiating Data Length Update Procedure; LE 1M
    PHY.

    Initial Condition:
        An unencrypted connected Peripheral with public own/peer addresses and
        common channel parameters. Read declared supported RX/TX octets/times
        and HCI ACL buffer capacity; require valid Core ranges. The Lower
        Tester acts as Central. Select a 30-ms interval on LE 1M/2M and 60 ms
        on Coded to accommodate maximum-length bidirectional S=8 traffic.
        Specification octet bounds are 27..251; time bounds are 328..17040 us.
        Establish peer DLE/2M/Coded feature support before the procedure.

    Test Steps:
        1. Use alternative 1A:
           1A.1 Retain the initial LE 1M PHY and move to Step 2.
        2. Repeat Steps 3-11 for each of the fifteen Table 4.3-63 HCI rows;
           duplicate rows may be omitted, not required.
        3. Send HCI LE Set Data Length with the row's TX octets/time and
           require successful Command Complete for the connection handle.
        4. Receive LL_LENGTH_REQ and check all four IUT fields against the
           specification minima and declared supported IUT maxima. If no
           request is sent, continue with the next row rather than failing.
        5. Send LL_LENGTH_RSP with both octet fields at the specification
           minimum and both time fields at the specification minimum.
        6. Require Data Length Change exactly when effective limits change,
           with the correct values; forbid an event for unchanged values.
           The first round may have unknown previous values. Permit the two
           events described by the source when a local autonomous change and
           the Lower Tester response each change effective values.
        7. Send the Host data in the minimum number of HCI ACL packets allowed
           by the HCI buffer size. If multiple packets are needed, submit all
           together after one event closes and before the next begins.
        8. Receive all DATA until the Host payload is complete, checking each
           packet's effective TX octet and airtime limits.
        9. Require exact equality to the Host data queued in Step 7.
        10. Send at least twenty DATA packets, each using the lesser of the
            effective IUT RX octet limit and the payload that fits its RX time
            budget on the current PHY.
        11. Require HCI ACL Data to reproduce exactly the Step 10 bytes with
            the correct handle, boundary flags and lengths.
        12. Repeat Steps 3-11 with both response octet fields at the
            specification maximum and both time fields at the specification
            maximum. Preserve the distinct 2120-us and 2128-us request rows.

    Expected Outcome:
        Pass verdict:
            The prescribed request/response exchange succeeds. Effective
            changes produce exactly the appropriate HCI length events, while
            unchanged limits produce none. All RF/HCI data matches exactly
            and respects effective octet/time limits.
        Inconclusive verdict:
            No LL_LENGTH_REQ is initiated across the complete matrix.

    Coverage Note:
        Execute both complete fifteen-row matrices. Distinguish the four IUT
        wire fields from the two HCI request fields. Check every MD packet,
        SN/LLID, exact Host bytes and completed-packet credits. Omitted requests
        skip only their row; the entire test is Inconclusive if none is sent.
        Drain the data exchanges and disconnect through HCI after completion.

    Reference:
        LL.TS.p28, LL/CON/PER/BV-78-C referral on PDF 695,
        printed 4.3-222; inherits LL/CON/CEN/BV-74-C with
        the IUT role changed to Peripheral.
        Inherited Section 4.3.6.3, Table 4.3-63, Figure 4.3-184;
        PDF 842-845, printed 4.3-369 through 4.3-372. Steps 1-12 and outcome.
    """
    await _data_length(tester, central=False, local=True, phy=Phy.LE_1M)


async def peripheral_data_length_update_central_does_not_support_le_1m_phy(tester):
    """Peripheral Data Length Update – Central does not support; LE 1M PHY.

    Initial Condition:
        An unencrypted connected Peripheral with public own/peer addresses and
        common channel parameters. Read declared supported RX/TX octets/times
        and HCI ACL buffer capacity; require valid Core ranges. The Lower
        Tester acts as Central. Select a 30-ms interval on LE 1M/2M and 60 ms
        on Coded to accommodate maximum-length bidirectional S=8 traffic.
        Specification octet bounds are 27..251; time bounds are 328..17040 us.
        Do not establish remote DLE support through Feature Exchange.

    Test Steps:
        1. Repeat Step 2 until LL_LENGTH_REQ is received, at most twenty
           attempts; no request after all attempts is Inconclusive.
        2. Send HCI LE Set Data Length for the connection handle:
           a. First use the declared maximum supported IUT TX octets/time.
           b. Then use minimum plus one, capped at each supported TX maximum.
           c. For remaining attempts choose octets/time independently and
              uniformly within the inclusive minimum-to-supported ranges.
        3. Check all four received LL_LENGTH_REQ fields against specification
           minima and declared supported IUT maxima.
        4. Send LL_UNKNOWN_RSP with UnknownType=LL_LENGTH_REQ.
        5. Send Host data in the minimum number of HCI ACL packets allowed
           by the HCI buffer size. If multiple packets are needed, submit all
           together after one event closes and before the next begins.
        6. Receive all DATA until the Host payload is complete, checking each
           packet's unchanged effective TX octet and airtime limits.
        7. Require exact equality to the Host data queued in Step 5.
        8. Send at least twenty DATA packets, each using the lesser of the
           effective IUT RX octet limit and the payload that fits its RX time
           budget on the current PHY.
        9. Require HCI ACL Data to reproduce exactly the Step 8 bytes with the
           correct handle, boundary flags and lengths.

    Expected Outcome:
        Pass verdict:
            Receive a valid LL_LENGTH_REQ and preserve the initial effective
            data limits after UNKNOWN_RSP. All RF/HCI data matches exactly
            and respects those limits.
        Fail verdict:
            Any Data Length Change caused by the unsupported DLE procedure.
        Inconclusive verdict:
            No LL_LENGTH_REQ in twenty attempts.

    Coverage Note:
        Seed independent inclusive random HCI requests for reproducibility.
        Check every MD packet, SN/LLID, exact Host bytes and completion credits.
        No Data Length Change is allowed during the rejected procedure or DATA.
        Drain the data exchanges and disconnect through HCI after completion.

    Reference:
        LL.TS.p28, LL/CON/PER/BV-79-C referral on PDF 695,
        printed 4.3-222; inherits LL/CON/CEN/BV-75-C with
        the IUT role changed to Peripheral.
        Inherited unsupported-peer procedure, Figure 4.3-185;
        PDF 846-848, printed 4.3-373 through 4.3-375. Steps 1-9 and outcome.
    """
    await _unsupported_peer(tester, central=False, phy=Phy.LE_1M)


async def peripheral_responding_to_data_length_update_le_2m_phy(
    tester,
):
    """Peripheral Data Length Update – Responding to Data Length Update Procedure; LE 2M
    PHY.

    Initial Condition:
        An unencrypted connected Peripheral with public own/peer addresses and
        common channel parameters. Read declared supported RX/TX octets/times
        and HCI ACL buffer capacity; require valid Core ranges. The Lower
        Tester acts as Central. Select a 30-ms interval on LE 1M/2M and 60 ms
        on Coded to accommodate maximum-length bidirectional S=8 traffic.
        Specification octet bounds are 27..251; time bounds are 328..17040 us.
        Establish peer DLE/2M/Coded feature support before the procedure.

    Test Steps:
        1. Use alternative 1B for LE 2M:
           1B.1 Send HCI LE Set PHY with ALL_PHYS=0 and TX/RX masks=0x02.
                 Complete the PHY procedure and require PHY Update Complete.
                 If both directions do not use LE 2M, report Inconclusive.
        2. For each round of Table 4.3-61, send LL_LENGTH_REQ with its four
           Lower Tester TX/RX octet/time fields, in RX-first wire order.
        3. Receive LL_LENGTH_RSP and check all four IUT fields are between
           the specification minima and the declared supported IUT maxima.
        4. Derive effective TX/RX octets/times from both PDUs. Require Data
           Length Change with the new values exactly when a limit changes;
           unchanged limits must not produce an event. The source permits
           uncertainty about the first round's previous values.
        5. Send the Host data in the minimum number of HCI ACL packets allowed
           by the HCI buffer size. If multiple packets are needed, submit all
           together after one event closes and before the next begins.
        6. Receive every DATA packet until the complete Host payload arrives.
           Check each packet's effective TX octet and airtime limits.
        7. Require received bytes to equal exactly the Host data from Step 5.
        8. Send at least twenty DATA packets, each using the lesser of the
           effective IUT RX octet limit and the payload that fits its RX time
           budget on the current PHY.
        9. Require HCI ACL Data to reproduce exactly the Step 8 bytes with the
           correct handle, boundary flags and lengths. Repeat Steps 2-9 for
           all sixteen source rows; duplicate rows may be omitted, not required.
        10. If the IUT supports LE Coded, repeat Steps 2-9 for every row with
            either Lower Tester time field at the specification maximum,
            replacing that maximum with 2128 us in each applicable field.

    Expected Outcome:
        Pass verdict:
            The prescribed request/response exchange succeeds. Effective
            changes produce exactly the appropriate HCI length events, while
            unchanged limits produce none. All RF/HCI data matches exactly
            and respects effective octet/time limits.
        Inconclusive verdict:
            The initial PHY update does not select the required PHY both ways.

    Coverage Note:
        Table 4.3-61 is translated to RX-first wire fields, not copied in its
        displayed TX-first order. Seed the four independent random rows for
        reproducibility; exclude specification extrema/tester maxima. Compare
        changed events against previously observed wire-derived limits. Check
        every MD packet, SN/LLID, exact Host bytes and completed-packet credits.
        Drain the data exchanges and disconnect through HCI after completion.

    Reference:
        LL.TS.p28, LL/CON/PER/BV-80-C referral on PDF 695,
        printed 4.3-222; inherits LL/CON/CEN/BV-76-C with
        the IUT role changed to Peripheral.
        Inherited Section 4.3.6.2, Table 4.3-61, Figure 4.3-183;
        PDF 837-841, printed 4.3-364 through 4.3-368. Steps 1-10 and outcome.
    """
    await _data_length(tester, central=False, local=False, phy=Phy.LE_2M)


async def peripheral_initiating_data_length_update_le_2m_phy(
    tester,
):
    """Peripheral Data Length Update – Initiating Data Length Update Procedure; LE 2M
    PHY.

    Initial Condition:
        An unencrypted connected Peripheral with public own/peer addresses and
        common channel parameters. Read declared supported RX/TX octets/times
        and HCI ACL buffer capacity; require valid Core ranges. The Lower
        Tester acts as Central. Select a 30-ms interval on LE 1M/2M and 60 ms
        on Coded to accommodate maximum-length bidirectional S=8 traffic.
        Specification octet bounds are 27..251; time bounds are 328..17040 us.
        Establish peer DLE/2M/Coded feature support before the procedure.

    Test Steps:
        1. Use alternative 1B for LE 2M:
           1B.1 Send HCI LE Set PHY with ALL_PHYS=0 and TX/RX masks=0x02.
                 Complete the PHY procedure and require PHY Update Complete.
                 If both directions do not use LE 2M, report Inconclusive.
        2. Repeat Steps 3-11 for each of the fifteen Table 4.3-63 HCI rows;
           duplicate rows may be omitted, not required.
        3. Send HCI LE Set Data Length with the row's TX octets/time and
           require successful Command Complete for the connection handle.
        4. Receive LL_LENGTH_REQ and check all four IUT fields against the
           specification minima and declared supported IUT maxima. If no
           request is sent, continue with the next row rather than failing.
        5. Send LL_LENGTH_RSP with both octet fields at the specification
           minimum and both time fields at the specification minimum.
        6. Require Data Length Change exactly when effective limits change,
           with the correct values; forbid an event for unchanged values.
           The first round may have unknown previous values. Permit the two
           events described by the source when a local autonomous change and
           the Lower Tester response each change effective values.
        7. Send the Host data in the minimum number of HCI ACL packets allowed
           by the HCI buffer size. If multiple packets are needed, submit all
           together after one event closes and before the next begins.
        8. Receive all DATA until the Host payload is complete, checking each
           packet's effective TX octet and airtime limits.
        9. Require exact equality to the Host data queued in Step 7.
        10. Send at least twenty DATA packets, each using the lesser of the
            effective IUT RX octet limit and the payload that fits its RX time
            budget on the current PHY.
        11. Require HCI ACL Data to reproduce exactly the Step 10 bytes with
            the correct handle, boundary flags and lengths.
        12. Repeat Steps 3-11 with both response octet fields at the
            specification maximum and both time fields at the specification
            maximum. Preserve the distinct 2120-us and 2128-us request rows.

    Expected Outcome:
        Pass verdict:
            The prescribed request/response exchange succeeds. Effective
            changes produce exactly the appropriate HCI length events, while
            unchanged limits produce none. All RF/HCI data matches exactly
            and respects effective octet/time limits.
        Inconclusive verdict:
            No LL_LENGTH_REQ is initiated across the complete matrix.
            The initial PHY update does not select the required PHY both ways.

    Coverage Note:
        Execute both complete fifteen-row matrices. Distinguish the four IUT
        wire fields from the two HCI request fields. Check every MD packet,
        SN/LLID, exact Host bytes and completed-packet credits. Omitted requests
        skip only their row; the entire test is Inconclusive if none is sent.
        Drain the data exchanges and disconnect through HCI after completion.

    Reference:
        LL.TS.p28, LL/CON/PER/BV-81-C referral on PDF 696,
        printed 4.3-223; inherits LL/CON/CEN/BV-77-C with
        the IUT role changed to Peripheral.
        Inherited Section 4.3.6.3, Table 4.3-63, Figure 4.3-184;
        PDF 842-845, printed 4.3-369 through 4.3-372. Steps 1-12 and outcome.
    """
    await _data_length(tester, central=False, local=True, phy=Phy.LE_2M)


async def peripheral_responding_to_data_length_update_le_coded_phy(
    tester,
):
    """Peripheral Data Length Update – Responding to Data Length Update Procedure; LE
    Coded PHY.

    Initial Condition:
        An unencrypted connected Peripheral with public own/peer addresses and
        common channel parameters. Read declared supported RX/TX octets/times
        and HCI ACL buffer capacity; require valid Core ranges. The Lower
        Tester acts as Central. Select a 30-ms interval on LE 1M/2M and 60 ms
        on Coded to accommodate maximum-length bidirectional S=8 traffic.
        Specification octet bounds are 27..251; time bounds are 328..17040 us.
        Establish peer DLE/2M/Coded feature support before the procedure.

    Test Steps:
        1. Use alternative 1C for LE Coded:
           1C.1 Send HCI LE Set PHY with ALL_PHYS=0 and TX/RX masks=0x04.
                 Complete the PHY procedure and require PHY Update Complete.
                 If both directions do not use LE Coded, report Inconclusive.
        2. For each round of Table 4.3-61, send LL_LENGTH_REQ with its four
           Lower Tester TX/RX octet/time fields, in RX-first wire order.
        3. Receive LL_LENGTH_RSP and check all four IUT fields are between
           the specification minima and the declared supported IUT maxima.
        4. Derive effective TX/RX octets/times from both PDUs. Require Data
           Length Change with the new values exactly when a limit changes;
           unchanged limits must not produce an event. The source permits
           uncertainty about the first round's previous values.
        5. Send the Host data in the minimum number of HCI ACL packets allowed
           by the HCI buffer size. If multiple packets are needed, submit all
           together after one event closes and before the next begins.
        6. Receive every DATA packet until the complete Host payload arrives.
           Check each packet's effective TX octet and airtime limits.
        7. Require received bytes to equal exactly the Host data from Step 5.
        8. Send at least twenty DATA packets, each using the lesser of the
           effective IUT RX octet limit and the payload that fits its RX time
           budget on the current PHY.
        9. Require HCI ACL Data to reproduce exactly the Step 8 bytes with the
           correct handle, boundary flags and lengths. Repeat Steps 2-9 for
           all sixteen source rows; duplicate rows may be omitted, not required.
        10. If the IUT supports LE Coded, repeat Steps 2-9 for every row with
            either Lower Tester time field at the specification maximum,
            replacing that maximum with 2128 us in each applicable field.

    Expected Outcome:
        Pass verdict:
            The prescribed request/response exchange succeeds. Effective
            changes produce exactly the appropriate HCI length events, while
            unchanged limits produce none. All RF/HCI data matches exactly
            and respects effective octet/time limits.
        Inconclusive verdict:
            The initial PHY update does not select the required PHY both ways.

    Coverage Note:
        Table 4.3-61 is translated to RX-first wire fields, not copied in its
        displayed TX-first order. Seed the four independent random rows for
        reproducibility; exclude specification extrema/tester maxima. Compare
        changed events against previously observed wire-derived limits. Check
        every MD packet, SN/LLID, exact Host bytes and completed-packet credits.
        Drain the data exchanges and disconnect through HCI after completion.

    Reference:
        LL.TS.p28, LL/CON/PER/BV-82-C referral on PDF 696,
        printed 4.3-223; inherits LL/CON/CEN/BV-78-C with
        the IUT role changed to Peripheral.
        Inherited Section 4.3.6.2, Table 4.3-61, Figure 4.3-183;
        PDF 837-841, printed 4.3-364 through 4.3-368. Steps 1-10 and outcome.
    """
    await _data_length(tester, central=False, local=False, phy=Phy.LE_CODED)


async def peripheral_initiating_data_length_update_le_coded_phy(
    tester,
):
    """Peripheral Data Length Update – Initiating Data Length Update Procedure; LE Coded
    PHY.

    Initial Condition:
        An unencrypted connected Peripheral with public own/peer addresses and
        common channel parameters. Read declared supported RX/TX octets/times
        and HCI ACL buffer capacity; require valid Core ranges. The Lower
        Tester acts as Central. Select a 30-ms interval on LE 1M/2M and 60 ms
        on Coded to accommodate maximum-length bidirectional S=8 traffic.
        Specification octet bounds are 27..251; time bounds are 328..17040 us.
        Establish peer DLE/2M/Coded feature support before the procedure.

    Test Steps:
        1. Use alternative 1C for LE Coded:
           1C.1 Send HCI LE Set PHY with ALL_PHYS=0 and TX/RX masks=0x04.
                 Complete the PHY procedure and require PHY Update Complete.
                 If both directions do not use LE Coded, report Inconclusive.
        2. Repeat Steps 3-11 for each of the fifteen Table 4.3-63 HCI rows;
           duplicate rows may be omitted, not required.
        3. Send HCI LE Set Data Length with the row's TX octets/time and
           require successful Command Complete for the connection handle.
        4. Receive LL_LENGTH_REQ and check all four IUT fields against the
           specification minima and declared supported IUT maxima. If no
           request is sent, continue with the next row rather than failing.
        5. Send LL_LENGTH_RSP with both octet fields at the specification
           minimum and both time fields at the specification minimum.
        6. Require Data Length Change exactly when effective limits change,
           with the correct values; forbid an event for unchanged values.
           The first round may have unknown previous values. Permit the two
           events described by the source when a local autonomous change and
           the Lower Tester response each change effective values.
        7. Send the Host data in the minimum number of HCI ACL packets allowed
           by the HCI buffer size. If multiple packets are needed, submit all
           together after one event closes and before the next begins.
        8. Receive all DATA until the Host payload is complete, checking each
           packet's effective TX octet and airtime limits.
        9. Require exact equality to the Host data queued in Step 7.
        10. Send at least twenty DATA packets, each using the lesser of the
            effective IUT RX octet limit and the payload that fits its RX time
            budget on the current PHY.
        11. Require HCI ACL Data to reproduce exactly the Step 10 bytes with
            the correct handle, boundary flags and lengths.
        12. Repeat Steps 3-11 with both response octet fields at the
            specification maximum and both time fields at the specification
            maximum. Preserve the distinct 2120-us and 2128-us request rows.

    Expected Outcome:
        Pass verdict:
            The prescribed request/response exchange succeeds. Effective
            changes produce exactly the appropriate HCI length events, while
            unchanged limits produce none. All RF/HCI data matches exactly
            and respects effective octet/time limits.
        Inconclusive verdict:
            No LL_LENGTH_REQ is initiated across the complete matrix.
            The initial PHY update does not select the required PHY both ways.

    Coverage Note:
        Execute both complete fifteen-row matrices. Distinguish the four IUT
        wire fields from the two HCI request fields. Check every MD packet,
        SN/LLID, exact Host bytes and completed-packet credits. Omitted requests
        skip only their row; the entire test is Inconclusive if none is sent.
        Drain the data exchanges and disconnect through HCI after completion.

    Reference:
        LL.TS.p28, LL/CON/PER/BV-83-C referral on PDF 696,
        printed 4.3-223; inherits LL/CON/CEN/BV-79-C with
        the IUT role changed to Peripheral.
        Inherited Section 4.3.6.3, Table 4.3-63, Figure 4.3-184;
        PDF 842-845, printed 4.3-369 through 4.3-372. Steps 1-12 and outcome.
    """
    await _data_length(tester, central=False, local=True, phy=Phy.LE_CODED)


async def peripheral_data_length_update_central_does_not_support_le_coded_phy(tester):
    """Peripheral Data Length Update – Central does not support; LE Coded PHY.

    Initial Condition:
        An unencrypted connected Peripheral with public own/peer addresses and
        common channel parameters. Read declared supported RX/TX octets/times
        and HCI ACL buffer capacity; require valid Core ranges. The Lower
        Tester acts as Central. Select a 30-ms interval on LE 1M/2M and 60 ms
        on Coded to accommodate maximum-length bidirectional S=8 traffic.
        Specification octet bounds are 27..251; time bounds are 328..17040 us.
        Do not establish remote DLE support through Feature Exchange.

    Test Steps:
        Before Step 1, send HCI LE Set PHY with ALL_PHYS=0 and both PHY
        masks=0x04. Complete the role-correct PHY procedure and require PHY
        Update Complete with LE Coded both ways, or report Inconclusive.

        1. Repeat Step 2 until LL_LENGTH_REQ is received, at most twenty
           attempts; no request after all attempts is Inconclusive.
        2. Send HCI LE Set Data Length for the connection handle:
           a. First use the declared maximum supported IUT TX octets/time.
           b. Then use minimum plus one, capped at each supported TX maximum.
           c. For remaining attempts choose octets/time independently and
              uniformly within the inclusive minimum-to-supported ranges.
        3. Check all four received LL_LENGTH_REQ fields against specification
           minima and declared supported IUT maxima.
        4. Send LL_UNKNOWN_RSP with UnknownType=LL_LENGTH_REQ.
        5. Send Host data in the minimum number of HCI ACL packets allowed
           by the HCI buffer size. If multiple packets are needed, submit all
           together after one event closes and before the next begins.
        6. Receive all DATA until the Host payload is complete, checking each
           packet's unchanged effective TX octet and airtime limits.
        7. Require exact equality to the Host data queued in Step 5.
        8. Send at least twenty DATA packets, each using the lesser of the
           effective IUT RX octet limit and the payload that fits its RX time
           budget on the current PHY.
        9. Require HCI ACL Data to reproduce exactly the Step 8 bytes with the
           correct handle, boundary flags and lengths.

    Expected Outcome:
        Pass verdict:
            Receive a valid LL_LENGTH_REQ and preserve the initial effective
            data limits after UNKNOWN_RSP. All RF/HCI data matches exactly
            and respects those limits.
        Fail verdict:
            Any Data Length Change caused by the unsupported DLE procedure.
        Inconclusive verdict:
            No LL_LENGTH_REQ in twenty attempts.
            The initial PHY update does not select the required PHY both ways.

    Coverage Note:
        Seed independent inclusive random HCI requests for reproducibility.
        Check every MD packet, SN/LLID, exact Host bytes and completion credits.
        No Data Length Change is allowed during the rejected procedure or DATA.
        Consume only the initial PHY-induced 27/2704 length notification before
        checking that the subsequent unsupported DLE produces no length event.
        Drain the data exchanges and disconnect through HCI after completion.

    Reference:
        LL.TS.p28, LL/CON/PER/BV-84-C referral on PDF 696,
        printed 4.3-223; inherits LL/CON/CEN/BV-80-C with
        the IUT role changed to Peripheral.
        Inherited unsupported-peer procedure, Figure 4.3-185;
        PDF 846-848, printed 4.3-373 through 4.3-375. Steps 1-9 and outcome.
        Additional Coded pre-step: CEN/BV-80, PDF 849-850,
        printed 4.3-376 through 4.3-377.
    """
    await _unsupported_peer(tester, central=False, phy=Phy.LE_CODED)


async def initiating_connection_parameter_request_unsupported_without_feature_exchange(
    tester,
):
    """Initiating Connection Parameter Request – Unsupported Without Feature Exchange.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common advertising/channel parameters, selected timeout and SCA.
        Select public peers and initial LE 1M; the Lower Tester acts as Central.
        Do not establish peer parameter-request support before Step 3.

    Test Steps:
        1. If the IUT autonomously sends LL_PERIPHERAL_FEATURE_REQ before
           Step 3, answer with LL_UNKNOWN_RSP identifying that opcode.
        2. Send HCI LE Connection Update with the minimum interval (7.5 ms),
           zero latency and intermediate supervision timeout (3 s); require
           successful Command Status.
        3. Receive LL_CONNECTION_PARAM_REQ and respond with LL_UNKNOWN_RSP
           identifying opcode 0x0F. The requested parameters may differ from
           the Host command; validate them as legal connection parameters.
        4. Require Connection Update Complete with the original handle and
           Unsupported Remote Feature (0x1A).
        5. Resend the identical HCI LE Connection Update and accept either:
           a. Command Status with Unsupported Remote Feature (0x1A).
           b. Successful Command Status followed by Connection Update Complete
              with the original handle and Unsupported Remote Feature (0x1A).
           Any new LL_CONNECTION_PARAM_REQ in this step fails the test.

    Expected Outcome:
        Pass verdict:
            The first Host request produces PARAM_REQ and its UNKNOWN_RSP
            produces the specified failure completion. The repeated Host
            request is rejected with 0x1A by one of Step 5's two HCI alternatives.
        Fail verdict:
            A repeated on-air PARAM_REQ, successful parameter update, incorrect
            handle/status, or duplicate completion.

    Coverage Note:
        Handle autonomous Feature Requests both during connection setup and
        while waiting for PARAM_REQ. Observe sixteen further old-parameter
        events after the second rejection to detect forbidden on-air retries;
        this is an observation bound, not an additional normative step.
        Disconnect through HCI after the observation.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-85-C procedure in
        Section 4.3.5, Figure 4.3-103; PDF 696-698,
        printed 4.3-223 through 4.3-225. Steps 1-5 including 5a/5b and outcome;
        referenced Core Vol 6, Part B, Section 5.1.7.
    """
    await _unsupported_parameters(tester, central=False, features=False)


async def initiating_connection_parameter_request_unsupported_with_feature_exchange(
    tester,
):
    """Initiating Connection Parameter Request – Unsupported With Feature Exchange.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common advertising/channel parameters, selected timeout and SCA.
        Select public peers and initial LE 1M; the Lower Tester acts as Central.

    Test Steps:
        1. Initiate Feature Exchange unless the IUT has already done so.
           Advertise no Connection Parameter Request support in the Lower
           Tester feature set. Answer an autonomous Peripheral Feature Request
           directly; otherwise send FEATURE_REQ and require FEATURE_RSP.
        2. Send HCI LE Connection Update with the minimum interval (7.5 ms),
           zero latency and intermediate supervision timeout (3 s). Accept:
           a. Command Status with Unsupported Remote Feature (0x1A).
           b. Successful Command Status followed by Connection Update Complete
              with the original handle and Unsupported Remote Feature (0x1A).
           Any LL_CONNECTION_PARAM_REQ in this step fails the test.

    Expected Outcome:
        Pass verdict:
            The IUT rejects the Host request with Unsupported Remote Feature
            through either specified HCI alternative, without an on-air PARAM_REQ.
        Fail verdict:
            Any on-air PARAM_REQ, successful parameter update, incorrect
            handle/status, or duplicate completion.

    Coverage Note:
        Use a zero Lower Tester feature set to clear the relevant support bit.
        Observe sixteen old-parameter connection events after rejection;
        disconnect through HCI after checking that no extra completion appears.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-86-C procedure in
        Section 4.3.5, Figure 4.3-104; PDF 698-699,
        printed 4.3-225 through 4.3-226. Steps 1-2 including 2a/2b and outcome;
        referenced Core Vol 6, Part B, Section 5.1.7.
    """
    await _unsupported_parameters(tester, central=False, features=True)


async def invalid_crc_anchor_point(tester):
    """Invalid CRC Anchor Point.

    Initial Condition:
        An unencrypted connected Peripheral with public addresses, common
        channel map, channel selection, interval and Peripheral latency, and
        selected SCA. The Lower Tester acts as Central. Select a 10-ms interval,
        zero latency and the prescribed 3000-ms supervision timeout; preserve
        current/next SN and NESN from the last valid connection exchange.

    Test Steps:
        1. Once per connection interval, send a DATA packet with an invalid
           CRC on the scheduled data channel, using the common channel
           selection and the saved sequence bits.
        2. Receive Peripheral DATA at T_IFS in events where it must listen;
           allow mismatches attributable to incorrectly received packets.
        3. Repeat Steps 1-2 for longer than the supervision timeout. Measure
           300 connection events, then continue observing through expiry.
        4. Require Disconnection Complete with the original connection handle
           and Connection Timeout (0x08).

    Expected Outcome:
        Pass verdict:
            The selected parameters are used, at least 65 of the measured
            300 connection events contain Peripheral responses, and HCI
            reports connection timeout after only invalid-CRC Central traffic.

    Coverage Note:
        The source assumes BER <=0.1%; the selected ideal RF channel has zero
        background BER. Its preamble/access-address error model follows PER
        BV-10, with the required response rate divided by latency plus one.
        Deliberately invert all CRC bits without corrupting the preamble or
        access address. Require all received replies to be CRC-valid, correctly
        timed and preserve the saved sequence acknowledgement. Invalid-CRC DATA
        must not produce Host ACL Data. HCI disconnection status must be success.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BI-01-C procedure in
        Section 4.3.5, Figure 4.3-105; PDF 699-700,
        printed 4.3-226 through 4.3-227. Steps 1-4, Test Condition, outcome
        and Notes; referenced Core Vol 6, Part B, Section 4.5.5.
    """
    link = await establish(
        tester,
        central=False,
        peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS,
        interval=8,
        timeout=300,
    )
    sn, nesn = _sequence_bits(link.last_received)
    peer_sn, peer_nesn = (link.sn, link.nesn)
    responses = 0
    started = tester.radio.now_us
    for _ in range(300):
        packet, _ = await _wire_event(
            link, lambda _: _data_pdu(peer_sn, peer_nesn), bad_crc=True, required=False
        )
        if packet:
            assert _sequence_bits(packet) == (sn, nesn)
            responses += 1
    assert responses >= 65
    await tester.wait(
        max(0, started + 3 * PHY_TIME_UNITS_PER_SECOND + 10000 - tester.radio.now_us)
    )
    event = await tester.event(hci.HCI_Disconnection_Complete_Event)
    assert (
        event.status == ErrorCode.SUCCESS
        and event.connection_handle == link.handle
        and event.reason == hci.HCI_ErrorCode.CONNECTION_TIMEOUT_ERROR
    )
    assert not any(isinstance(event, hci.HCI_AclDataPacket) for event in tester.events)


async def peripheral_t_terminate_timer(tester):
    """Peripheral T_Terminate Timer.

    Initial Condition:
        An unencrypted connected Peripheral with public addresses, common
        channel map, interval and Peripheral latency, selected timeout and SCA.
        The Lower Tester acts as Central. Retain the connection handle and
        sequence state; use zero latency and common supervision timing.

    Test Steps:
        1. Send HCI Disconnect with the preamble connection handle and require
           successful Command Status.
        2. Transmit Central DATA and receive LL_TERMINATE_IND. Do not
           acknowledge that indication or any subsequent packet, but continue
           Central transmissions.
        3. Send correctly formatted empty DATA without acknowledging any
           Peripheral response; repeat until T_Terminate expires.
        4. Require Disconnection Complete with status Success (0x00), the
           original handle and either Local Host Termination (0x16) or
           LL Response Timeout (0x22).

    Expected Outcome:
        Pass verdict:
            The IUT continues sending LL_TERMINATE_IND until T_Terminate
            expires and reports link termination through the specified HCI event.

    Coverage Note:
        Retain NESN equal to the termination SN so it remains unacknowledged;
        advance Central SN when appropriate so valid peer traffic keeps the
        ordinary supervision timer alive. Require the same termination payload
        and SN on retransmission. Bound expiry from the HCI command's enqueue
        window using the supervision timeout, and verify RF silence afterwards.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BI-02-C procedure in
        Section 4.3.5, Figure 4.3-106; PDF 701-702,
        printed 4.3-228 through 4.3-229. Steps 1-4 and outcome;
        referenced Core Vol 6, Part B, Section 5.1.6.
    """
    await _timeouts_termination(tester, central=False)


async def rejecting_connection_change(tester):
    """Rejecting Connection Change.

    Initial Condition:
        An unencrypted connected Peripheral with public addresses, common
        channel selection, interval and latency, selected timeout and SCA.
        The Lower Tester acts as Central. Use zero latency; retain the handle,
        event counter and common connection parameters for each fresh ACL.

    Test Steps:
        1. Send LL_CONNECTION_UPDATE_IND with intermediate legal connection
           parameters and an Instant at or before the current event. An
           acknowledgement from the IUT is optional.
        2. Require Disconnection Complete with the preamble handle and
           Instant Passed (0x28).
        3. Establish a fresh Peripheral connection.
        4. Send LL_CHANNEL_MAP_IND with the first selected channel map and
           an Instant at or before the current event. Accept either:
           Alternative 1: the IUT may acknowledge, then reports Disconnection
           Complete with the preamble handle and Instant Passed (0x28).
           Alternative 2: the IUT acknowledges, reports no disconnection and
           continues to maintain the connection with the Lower Tester.

    Expected Outcome:
        Pass verdict:
            The past connection update produces the specified HCI failure.
            For Step 4 Alternative 1, the IUT reports failure and stops the
            connection before one supervision timeout elapses from the invalid
            request. For Alternative 2, it maintains the acknowledged connection
            and does not report failure.

    Coverage Note:
        Use the preceding event as Instant, midpoint interval and timeout with
        zero latency for the connection request, and the selected even-channel
        map for the second trial. Anchor the observation deadline to the actual
        request's RF end, not the earlier test-command time. Keep valid Central
        traffic through one supervision period to distinguish maintenance from
        delayed failure; do not refresh the original invalid request's deadline.
        Both alternatives have verdict-boundary unit coverage. The current IUT
        takes Alternative 1 in the native PHY trial. Probe the next receive
        window after disconnection; terminate any maintained ACL through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BI-04-C procedure in
        Section 4.3.5, Figure 4.3-107; PDF 702-704,
        printed 4.3-229 through 4.3-231. Steps 1-4, both alternatives and
        Expected Outcome; referenced Core Vol 6, Part B, Sections 5.1.1/5.1.2.
    """
    for channel_map in (False, True):
        link = await establish(tester, peer_address=LOWER_CENTRAL_PUBLIC_ADDRESS)
        instant = link.counter - 1 & LL_EVENT_COUNTER_MASK
        payload = (
            bytes([Opcode.LL_CHANNEL_MAP_IND])
            + sum(
                1 << channel for channel in range(0, LL_DATA_CHANNEL_COUNT, 2)
            ).to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
            + instant.to_bytes(PDU_CONTROL_INSTANT_SIZE, 'little')
            if channel_map
            else bytes([Opcode.LL_CONNECTION_UPDATE_IND])
            + struct.pack(
                '<BHHHHH',
                LL_CONN_WINDOW_SIZE_MIN,
                0,
                (LL_CONN_INTERVAL_MIN + LL_CONN_INTERVAL_MAX) // 2,
                0,
                (LL_SUPERVISION_TIMEOUT_MIN + LL_SUPERVISION_TIMEOUT_MAX) // 2,
                instant,
            )
        )
        await _past_update_outcome(link, payload, allow_maintenance=channel_map)


async def peripheral_connection_control_timer(tester):
    """Peripheral Connection Control Timer.

    Initial Condition:
        An unencrypted connected Peripheral with public addresses, common
        channel selection, interval and latency, selected timeout and SCA.
        The Lower Tester acts as Central, retains the connection handle and
        continues valid DATA so supervision does not cause the failure.

    Test Steps:
        1. If the IUT has autonomously sent LL_VERSION_IND after connection
           setup, acknowledge it and continue Central transmissions without
           ever sending a peer VERSION_IND. Continue directly to Step 6.
        2. Otherwise, send HCI Read Remote Version Information for the saved
           handle and require successful Command Status.
        3. Receive the IUT's LL_VERSION_IND and positively acknowledge it.
        4. Continue empty Central DATA until the connection control timeout
           or the completion in Step 5; do not provide a peer version response.
        5. For the Host-requested branch, receive Read Remote Version
           Information Complete with the saved handle and LL Response Timeout
           status, unless disconnection precedes procedure completion.
        6. Require Disconnection Complete for the saved handle with LL
           Response Timeout (0x22), indicating the connection transaction timeout.

    Expected Outcome:
        Pass verdict:
            The procedure fails through its control timeout, not a supervision
            timeout. The IUT reports termination to the Host and stops responding
            to Central transmissions.

    Coverage Note:
        Preserve the autonomous path without issuing an extra Host command;
        an autonomous exchange must not produce an unsolicited Host version
        completion. Verify one acknowledged VERSION_IND, no repeats after ACK,
        and no early completion/disconnection before the 40-s response deadline.
        An optional Host failure completion must precede disconnection; no
        version completion may follow it. Probe the next RF receive window.
        Use a 1-ms HCI observation bound around the recorded timer start;
        the autonomous path brackets that start between connection setup and
        the first received RF timestamp, rather than treating TX as queue time.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BI-05-C procedure in
        Section 4.3.5, Figure 4.3-108; PDF 704-706,
        printed 4.3-231 through 4.3-233. Steps 1-6 and Expected Outcome;
        referenced Core Vol 6, Part B, Section 5.2.
    """
    await _version_timeout(tester, central=False)


async def initiating_connection_parameter_request_timeout(tester):
    """Initiating Connection Parameter Request – Timeout.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters and interval, selected timeout and SCA.
        Select public peers, zero latency and LE 1M. The Lower Tester acts as
        Central and advertises Connection Parameter Request support.

    Test Steps:
        1. Send HCI LE Connection Update with the minimum connection interval
           (7.5 ms), zero latency and intermediate supervision timeout (3 s);
           require successful Command Status.
        2. Receive and acknowledge LL_CONNECTION_PARAM_REQ without sending
           LL_CONNECTION_PARAM_RSP or an update. Its legal parameters may
           differ from the Host-requested values.
        3. Require Disconnection Complete with LL Response Timeout (0x22)
           when the connection control transaction timer expires, and require
           the IUT to stop maintaining the connection.

    Expected Outcome:
        Pass verdict:
            The IUT reports LL Response Timeout at transaction expiry and
            ceases connection RF traffic.

    Coverage Note:
        Validate every parameter field and positively acknowledge the request.
        Continue valid empty DATA on the old schedule so ordinary supervision
        cannot expire. Reject early disconnection or successful parameter
        completion. Bound the 40-s response timeout by the command enqueue
        window with 1-ms HCI observation resolution, check the HCI handle/status,
        then probe the next Peripheral receive window for RF silence.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BI-07-C procedure in
        Section 4.3.5, Figure 4.3-109; PDF 706-707,
        printed 4.3-233 through 4.3-234. Steps 1-3 and Expected Outcome;
        referenced Core Vol 6, Part B, Section 5.1.7.
    """
    await _procedure_timeout(tester, central=False, parameters=True)


async def accepting_connection_parameter_request_illegal_parameters(tester):
    """Accepting Connection Parameter Request – Illegal Parameters.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters and interval, selected timeout and SCA.
        Select public peers, zero latency and LE 1M; the Lower Tester is Central.

    Test Steps:
        1. Send LL_CONNECTION_PARAM_REQ with both minimum and maximum interval
           fields set to the invalid encoded value 4.
        2. Receive LL_REJECT_EXT_IND with ErrorCode=Invalid LL Parameters
           (0x1E), identifying LL_CONNECTION_PARAM_REQ as the rejected opcode.

    Expected Outcome:
        Pass verdict:
            The IUT rejects the invalid interval request through the specified
            extended reject opcode and reason.

    Source Correction:
        The source labels interval value 4 as 6 ms. At the specified 1.25-ms
        interval unit it means 5 ms; retain the encoded value 4 as the invalid
        test stimulus. Core Vol 6, Part B, Section 2.4.2.1 and Amber support this
        local editorial correction; no adopted SIG erratum is claimed.

    Coverage Note:
        Keep other fields legal. Acknowledge the reject and maintain three
        further old-parameter connection events. Reject any Host remote-parameter
        request or update completion resulting from the invalid request, then
        disconnect through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BI-08-C procedure in
        Section 4.3.5, Figure 4.3-110; PDF 707-708,
        printed 4.3-234 through 4.3-235. Steps 1-2 and Expected Outcome;
        referenced Core Vol 6, Part B, Section 5.1.7.
    """
    await _remote_parameters(
        tester, central=False, reject=False, masked=False, invalid=True
    )


async def responding_to_phy_update_procedure_instant_in_past(tester):
    """Responding to PHY Update Procedure – Instant In Past.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters and interval, selected timeout and SCA.
        Select public peers, zero latency and initial LE 1M. The Lower Tester
        acts as Central and selects LE 2M as the non-1M PHY for this vector.

    Test Steps:
        1. Send HCI LE Set PHY with ALL_PHYS=0x03 and require successful
           Command Status and PHY Update Complete, retaining initial LE 1M.
        2. Send LL_PHY_REQ with both TX_PHYS and RX_PHYS preferring a PHY
           other than LE 1M; select LE 2M in this implementation.
        3. Receive LL_PHY_RSP with nonzero TX/RX fields supporting the selected
           non-1M PHY in both directions. Otherwise report Inconclusive.
        4. Send LL_PHY_UPDATE_IND selecting that non-1M PHY both ways, with
           (Instant - connEventCount) modulo 65536 >=32767. Accept either:
           Alternative 1: an optional PHY Update Complete has nonzero status;
           require Disconnection Complete with Instant Passed (0x28) and
           cessation of connection maintenance.
           Alternative 2: require PHY Update Complete with both requested PHYs,
           maintain the connection on those PHYs and report no connection failure.

    Expected Outcome:
        Pass verdict:
            PHY_RSP has a nonzero selection in both fields. The nonzero PHY
            update is handled through one complete Step 4 alternative: failed
            completion if present and disconnection 0x28, or successful non-1M
            completion and a maintained connection without failure.
        Inconclusive verdict:
            Step 3 does not permit a non-1M PHY in both directions.

    Source Correction:
        The outcome's reference to an optional completion in Step 5 points to
        Step 4 Alternative 1; no Step 5 exists. Amber corroborates this local
        editorial interpretation; no adopted SIG erratum is claimed.

    Coverage Note:
        Use distance 32767, the source boundary, for the invalid Instant.
        Accept both alternatives rather than forcing the current IUT's chosen
        disconnection. Check event handles/status, reject successful completion
        on the failure path and duplicate/contradictory notifications. Probe
        the old PHY for one supervision period after disconnection. For the
        maintained path, check ten acknowledged connection events on the new
        PHY and terminate through HCI. Boundary units cover both alternatives;
        the native IUT currently exercises Alternative 1.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BI-09-C procedure in
        Section 4.3.5, Figure 4.3-111; PDF 708-710,
        printed 4.3-235 through 4.3-237. Steps 1-4, both alternatives and
        Expected Outcome; referenced Core Vol 6, Part B, Section 5.1.10.
    """
    await _invalid_update(tester, past=True, rfu=False)


async def version_exchange_iut_requesting_collision_peripheral(tester):
    """Version Exchange, IUT Requesting, Collision, Peripheral.

    Initial Condition:
        An unencrypted connected Peripheral with public addresses, common
        channel parameters and latency, selected SCA and an interval >2 s.
        Select a 3-s interval, zero latency and 32-s supervision timeout. Read
        local version/manufacturer/subversion to validate the IUT wire payload.

    Test Steps:
        1. Establish the connection. If the IUT autonomously sends its version
           in three consecutive repeats, end with Inconclusive.
        2. Send HCI Read Remote Version Information as close as possible
           after a connection event; require successful Command Status.
        3. Wait DELAY connection events, then send the Lower Tester's
           LL_VERSION_IND containing its selected version information.
        4. Require the IUT's own LL_VERSION_IND as its response in the same
           event, also acknowledging the Lower Tester's indication.
        5. Acknowledge the IUT version indication.
        6. Require Read Remote Version Information Complete with the saved
           handle and the Lower Tester version fields from Step 3.
        7. Observe at least ten consecutive further connection events without
           another IUT LL_VERSION_IND.

        Repeat complete trials, disconnecting and reconnecting with the Initial
        Condition until Steps 3/4 occur in the same event. Start DELAY=0 and
        increment it after every fifth trial. DELAY=10 is Inconclusive.

    Expected Outcome:
        Pass verdict:
            The same-event response in Step 4 is the IUT version, correctly
            acknowledges the peer, and produces the exact Host result in Step 6.
        Fail verdict:
            More than one LL_VERSION_IND in a trial, or incorrect version data.
        Inconclusive verdict:
            Three consecutive autonomous initializations, or DELAY reaches ten.

    Source Correction:
        The abbreviated outcome omits Step 1's three-consecutive qualifier.
        Follow that explicit executable condition, not immediate Inconclusive
        after one autonomous trial. Amber corroborates this local interpretation;
        no separate adopted SIG erratum is claimed.

    Coverage Note:
        Count indications during DELAY and the collision exchange, and validate
        their exact local version fields. A missing same-event response retries
        the trial; an incorrect or duplicate version is a failure, not a retry
        or Inconclusive. Observe acknowledgements and prohibit duplicates during
        the ten-event post-collision window; reject extra Host completions.
        Disconnect the successful trial after all checks.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-146-C procedure in
        Section 4.3.5, Figure 4.3-122; PDF 728-729,
        printed 4.3-255 through 4.3-256. Steps 1-7, repeat preamble and outcome;
        referenced Core Vol 6, Part B, Section 5.1.5.
    """
    local = await tester.command(hci.HCI_Read_Local_Version_Information_Command())
    expected = bytes([Opcode.LL_VERSION_IND]) + struct.pack(
        '<BHH', local.lmp_version, local.company_identifier, local.lmp_subversion
    )
    autonomous = 0
    for attempt in range(
        VERSION_COLLISION_DELAY_LIMIT * VERSION_COLLISION_REPEATS_PER_DELAY
    ):
        delay = attempt // VERSION_COLLISION_REPEATS_PER_DELAY
        link = await _version_link(
            tester,
            interval=VERSION_COLLISION_INTERVAL,
            timeout=LL_SUPERVISION_TIMEOUT_MAX,
        )
        initial = _version_payload(link.last_received)
        if initial is not None:
            assert initial == expected
            autonomous += 1
            await link.disconnect()
            if autonomous == 3:
                pytest.skip(
                    'Inconclusive: three autonomous Version Exchange initializations'
                )
            continue
        autonomous = 0
        before = tester.radio.now_us
        await tester.command(
            hci.HCI_Read_Remote_Version_Information_Command(link.handle)
        )
        assert (
            tester.radio.now_us - before
            < VERSION_COLLISION_INTERVAL * LL_CONN_INTERVAL_UNIT_US
        )
        versions = []
        for _ in range(delay):
            value = _version_payload(await link.exchange())
            if value is not None:
                versions.append(value)
        packets = await _same_event(link, [VERSION_IND])
        assert len(packets) == 1
        value = _version_payload(packets[0])
        if value is not None:
            versions.append(value)
        assert len(versions) <= 1, 'duplicate VERSION_IND in one collision trial'
        assert all(version == expected for version in versions), 'wrong IUT version'
        if value is None:
            await link.disconnect()
            _completion(tester)
            continue
        await _quiet_events(link, VERSION_RESPONSE_DELAY_EVENTS)
        _check_completion(_completion(tester), link.handle)
        assert _completion(tester) is None
        await link.disconnect()
        return
    pytest.skip(
        'Inconclusive: no same-event version collision before DELAY reached ten'
    )


async def invalid_llid(tester):
    """Invalid LLID.

    Initial Condition:
        Use the common unencrypted connected Peripheral setup with public
        peers, common channel parameters, zero latency and LE 1M. The Lower
        Tester is Central. Read the declared local LE feature set to validate
        the later legitimate response. The source gives no separate initial
        condition for this independently titled procedure.

    Test Steps:
        1. Send the LL_FEATURE_REQ payload with LLID=0b00 rather than the
           control-packet LLID; retain valid sequence bits and CRC.
        2. Require the IUT to acknowledge it with no more than four retries;
           a missing acknowledgement fails the test.
        3. For four seconds after the first invalid transmission, require
           that no LL_FEATURE_RSP is returned in response to its payload.
        4. After that four-second interval, send the same LL_FEATURE_REQ
           payload with the correct LLID=0b11.
        5. Require LL_FEATURE_RSP with valid control LLID and FeatureSet.

    Expected Outcome:
        Pass verdict:
            The invalid-LLID packet is acknowledged but not processed as a
            Feature Request. The valid packet produces a correctly encoded
            Feature Response with the permitted local features.
        Fail verdict:
            The initial packet remains unacknowledged after four retries.

    Coverage Note:
        Use at most five total transmissions: the initial packet plus four
        retries. Anchor the four-second window to the first RF transmission,
        not the final retry or acknowledgement. Continue correctly sequenced
        empty DATA while checking that the invalid payload does not leak into
        Host ACL data. Validate the legitimate response's feature masks and
        acknowledgement before disconnecting through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BI-17-C procedure in
        Section 4.3.5, Figure 4.3-123; PDF 729-730,
        printed 4.3-256 through 4.3-257. Steps 1-5 and Expected Outcome;
        referenced Core Vol 6, Part B, Section 2.4.
    """
    await _invalid_control_invalid_llid(tester, central=False)


async def phy_update_procedure_invalid_or_unsupported_phy_central_initiated(
    tester, *, rfu
):
    """PHY Update Procedure, Invalid or Unsupported PHY, Central Initiated.

    Initial Condition:
        An unencrypted connected Peripheral with supported own address type,
        common channel parameters and interval, selected timeout and SCA.
        Select public peers, zero latency and initial LE 1M; the Lower Tester
        is Central. Read the declared local feature set to validate any later
        Feature Response. The IUT supports LE 1M, LE 2M and LE Coded.

    Test Steps:
        1. Send LL_PHY_REQ with TX_PHYS=RX_PHYS=0xFF.
        2. Receive LL_PHY_RSP with nonzero TX/RX masks containing only the
           defined, supported PHY bits.
        3. Send LL_PHY_UPDATE_IND with PHY_C_TO_P/PHY_P_TO_C from the selected
           Table 4.3-49 row, using a valid future Instant. For BI-20 use
           (0x03,0x03), (0x03,0x01), (0x01,0x03); for BI-21 use
           (0x80,0x80), (0x80,0x01), (0x01,0x80).
        4. Follow the IUT's chosen outcome:
           Alternative 4A, disconnection:
               4A.1 Require HCI Disconnection Complete for the active handle.
               4A.2 Reestablish the connection between IUT and Lower Tester.
               4A.3 Require Connection Complete for the new Peripheral ACL.
           Alternative 4B, maintenance on the active PHY:
               4B.1 Require no HCI PHY Update Complete event.
               4B.2 Send LL_FEATURE_REQ on the unchanged active PHY with the
                    Lower Tester feature set; select zero features here.
               4B.3 Receive a valid LL_FEATURE_RSP on that PHY with the
                    permitted IUT feature set.
               4B.4 If PHY_C_TO_P is an unsupported defined PHY and not RFU,
                    transmit on the unsupported PHY and require no response.

        Repeat the complete procedure for all three rows of the selected case.

    Expected Outcome:
        Pass verdict:
            Complete the selected disconnect/reestablish or maintained-link
            alternative. Maintenance produces a valid Feature Response and no
            Host PHY completion. Any applicable unsupported-PHY probe receives
            no response.

    Source Correction:
        The outcome addresses the HCI PHY completion check to the Lower Tester.
        HCI events belong to the Upper Tester, as Step 4B.1 specifies. Amber
        corroborates this local destination correction; no adopted erratum is
        claimed.

    Coverage Note:
        Step 4B.4 is inapplicable to both selected cases: 0x03 is an invalid
        multi-PHY mask, not HCI PHY enumeration 3/Coded, and 0x80 is RFU.
        The unsupported-single-PHY cases BI-18/BI-19 are not selected here.
        Amber corroborates that applicability distinction. Keep each on-air
        control payload unchanged until acknowledged before advancing to the
        Feature Request, and require its acknowledgement before accepting the
        response. Reestablish after every 4A result, including the final row;
        retain a 4B connection for the next row, then disconnect through HCI.
        Boundary units cover both paths, retries and invalid notifications;
        native trials currently exercise 4A. A failed optional PHY notification
        on 4A must have the right handle and may not claim successful change.

    Reference:
        LL.TS.p28, Section 4.3.5.3, Table 4.3-49, Figure 4.3-125;
        LL/CON/PER/BI-20-C and LL/CON/PER/BI-21-C, PDF 732-734,
        printed 4.3-259 through 4.3-261. Steps 1-4, alternatives 4A.1-3/
        4B.1-4 and Expected Outcome; referenced Core Vol 6, Part B, 5.1.10.
    """
    await _invalid_update(tester, past=False, rfu=rfu)


async def listening_for_packet_with_window_widening_acl(tester):
    """Listening for Packet With Window Widening, ACL.

    Initial Condition:
        A connected Peripheral with supported own address type, selected
        channel parameters, timeout and SCA. The Lower Tester is Central and
        advertises 500-ppm sleep clock accuracy. Use public peers, initial LE 1M
        and zero latency. Repeat all steps for both Table 4.3-50 rows:
        round 1, 3-s supervision and the early receive-window extension;
        round 2, 2-s supervision and the late receive-window extension.

    Test Steps:
        1. Send HCI LE Connection Update with zero latency and the round's
           supervision timeout; require successful Command Status.
        2. Receive LL_CONNECTION_PARAM_REQ. Its legal parameters may differ
           from those provided by the Host command.
        3. Accept the request with LL_CONNECTION_UPDATE_IND, Instant fifty
           connection events ahead and WinOffset=1.
        4. Send empty DATA within the receive window, obtaining acknowledgements
           until the connection event counter reaches Instant.
        5. Require an empty IUT DATA reply for each packet received in Step 4.
        6. At the update, send no PDU for ten connection intervals.
        7. Send empty DATA 0.5 us after the beginning edge of the window
           identified by the round: before receiveWindowStart for round 1,
           after receiveWindowEnd for round 2. Compute the source widening as
           (500 / 1000000) * (receiveWindowEnd - last Step 4 DATA anchor) + 16 us.
        8. Require the IUT to receive that Step 7 packet during the widened
           interval and respond with empty DATA.

    Expected Outcome:
        Pass verdict:
            For both rounds, the IUT receives the correctly positioned Step 7
            packet and returns empty DATA within the widened-window scenario.

    Source Correction:
        The outcome says the Step 8 response answers a packet from Step 8;
        the stimulus is actually Step 7. Amber corroborates this local editorial
        reference correction; no adopted SIG erratum is claimed.

    Review Limitation:
        The 0.5-us source guard is approximated with a 1-us inside-edge guard
        once its independently unresolved late-edge interpretation is settled.
        Timestamp resolution alone does not justify skipping this case.

    Source Conflict:
        The late round's beginning-edge wording does not identify whether the
        stimulus follows receiveWindowEnd or precedes the outer trailing edge.
        Figure 4.3-127 supplies no exact timestamp formula. This separate source
        question permits the skip; it is not a timing-precision skip.

    Timing Approximation:
        Execute at 1-us timestamp resolution, retaining the limited precision
        label. Fractional guards use the documented integer-us approximation.
        Complete all executable checks without skipping for precision alone;
        only an independent source_conflict label permits a protocol-path skip.

    Reference:
        LL.TS.p28, independently titled LL/CON/PER/BV-158-C procedure in
        Section 4.3.5, Figure 4.3-127 and Table 4.3-50; PDF 736-738,
        printed 4.3-263 through 4.3-265. Steps 1-8 and Expected Outcome;
        referenced Core Vol 6, Part B, Section 4.2.4.
    """
    pytest.skip(
        'Source conflict: late-window edge wording needs clarification; '
        '1-us approximation is allowed once that protocol question is resolved '
        '(LL.TS.p28 PDF 738, Step 7/Table 4.3-50)'
    )


async def events_with_peripheral_latency(tester):
    """Events with Peripheral Latency.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common channel parameters. Use latency
        five, supervision timeout 32 s and the nearest encodable connection
        interval to the source's 32 ms, as explained below. Read HCI buffer
        capacity and honor Host flow control throughout.

    Test Steps:
        Repeat Steps 1-5 for 600 connection events.
        1. Submit four-octet Host data 0xFFFFFFFF for the established handle,
           with the HCI packet-boundary start flag, when a credit is available.
        2. Receive a Central DATA packet once per connection interval on the
           channel derived from the channel-selection parameters.
        3. Send Peripheral DATA only in events required by latency five, at
           T_IFS after the received packet. Retain the initial SN and NESN.
        4. Require the Host to receive the Step 3 data with the start flag.
           Repeated Peripheral SN must not produce duplicate Host delivery.
        5. Until the next Peripheral response, require the Central to retain
           the acknowledgement state or indicate no response, with SN/NESN
           corresponding to the peer's NESN/SN. Permit flow control to change
           SN without changing NESN; a retransmission keeps its data and LLID.
        6. Execute Central Connection Terminated using the established
           interval, latency, timeout, channel map and unencrypted handle.

    Expected Outcome:
        Pass verdict:
            The connection remains established throughout the latency sequence.
            DATA acknowledgement state obeys Step 5, including flow control.
            Per-event interval and accumulated Central drift remain within
            the advertised sleep-clock-accuracy limits.

    Source Correction:
        The prescribed 32-ms interval is not encodable in 1.25-ms units.
        Use 26 units (32.5 ms), the nearest legal value, retaining latency five,
        600 repetitions and the 32-s timeout. Amber corroborates this local
        interpretation; no adopted SIG erratum is claimed.

    Coverage Note:
        Compare HCI bytes and start-flag offsets, not a fixed fragmentation.
        Count matching-handle completion credits and reject credits for
        unsubmitted packets. The source's long timeout avoids statistically
        expected supervision failures when Peripheral latency is exercised.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-02-C procedure in
        Section 4.3.6, Figure 4.3-134; PDF 748-750, printed 4.3-275 through
        4.3-277. Steps 1-6 and Expected Outcome; DATA fragmentation in 4.1.7.
    """
    link = await establish(
        tester,
        central=True,
        peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS,
        interval=26,
        latency=5,
        timeout=LL_SUPERVISION_TIMEOUT_MAX,
    )
    capacity = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
    credits = capacity.total_num_le_acl_data_packets
    data = b'\xff' * 4
    receiver = _HciDataStream(tester, link.handle)
    receiver.sent(data, False)
    peer_sn, peer_nesn = (link.sn ^ 1, link.nesn)
    previous = None
    submitted = completed = transmitted = 0
    first_anchor = link.anchor
    starts = []
    sent = None
    for index in range(600):
        if credits:
            await tester.wait(0)
            tester.send(
                bytes(
                    hci.HCI_AclDataPacket(
                        link.handle,
                        hci.HCI_ACL_PB_FIRST_NON_FLUSHABLE,
                        0,
                        len(data),
                        data,
                    )
                )
            )
            credits -= 1
            submitted += 1
        channel = link.channel
        packet = await _receive_central_event(link)
        starts.append(packet.start_us)
        sent = None
        if index % (link.parameters.latency + 1) == link.parameters.latency:
            sent = _data_pdu(peer_sn, peer_nesn, data, llid=LlId.START)
            await tester.transmit(
                channel,
                sent,
                start_us=packet.end_us + LL_IFS_US,
                **link.radio_parameters,
            )
            link.last_sent_end_us = tester.radio.now_us + 1
        duplicate = (
            previous is not None
            and _sequence_bits(packet)[0] == _sequence_bits(previous)[0]
        )
        if duplicate:
            assert packet.pdu[PDU_HEADER_SIZE:] == previous.pdu[PDU_HEADER_SIZE:]
            assert (
                packet.pdu[0] & PDU_DATA_LLID_MASK
                == previous.pdu[0] & PDU_DATA_LLID_MASK
            )
        if packet.pdu[0] & PDU_DATA_LLID_MASK != LlId.CONTROL and packet.pdu[1]:
            offset = transmitted % len(data)
            if not duplicate:
                assert packet.pdu[0] & PDU_DATA_LLID_MASK == (
                    LlId.CONTINUATION if offset else LlId.START
                )
                assert packet.pdu[1] <= len(data) - offset
                transmitted += packet.pdu[1]
                assert transmitted <= submitted * len(data)
            assert all(octet == data[0] for octet in packet.pdu[PDU_HEADER_SIZE:])
        if index >= 6:
            assert _sequence_bits(packet)[1] == peer_sn ^ 1
        previous = packet
        while event := tester.take(
            lambda event: isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
        ):
            assert event.connection_handles == [link.handle]
            count = sum(event.num_completed_packets)
            completed += count
            assert completed <= submitted, 'completed unsubmitted Host packets'
            credits += count
            assert credits <= capacity.total_num_le_acl_data_packets
        receiver.poll()
    await receiver.finish()
    assert transmitted and sent is not None
    _check_central_timing(link.parameters, first_anchor, starts)
    _restore_peer(link, previous, sent)
    await link.exchange()
    assert not any(
        isinstance(event, hci.HCI_Disconnection_Complete_Event)
        for event in tester.events
    )
    await link.disconnect()


async def central_sending_data(tester):
    """Central Sending Data.

    Initial Condition:
        An unencrypted connected Central, public Lower Tester Peripheral,
        supported own address type and common interval, latency, timeout and
        channel parameters. Retain the preamble handle and HCI buffer length.

    Test Steps:
        1. Submit ten-octet zero-filled Host packets, all PB=0x00, until
           1000 octets have been submitted for the established handle.
        2. Receive matching-handle HCI Number Of Completed Packets credits.
        3. Receive the Step 1 data as LLID=0x02 and acknowledge on the same
           data channel with correctly sequenced empty Peripheral DATA.
        4. Repeat Steps 2-3 until all Step 1 data has been received.
        5. Submit another 1000 zero-filled octets in ten-octet Host packets,
           now all PB=0x01.
        6. Receive the corresponding HCI completion credits.
        7. Receive the Step 5 data as LLID=0x01 and acknowledge with empty
           Peripheral DATA using the same channel and acknowledgement scheme.
        8. Repeat Steps 6-7 until all Step 5 data has been received.
        9. Submit a further 1000 zero-filled octets in ten-octet packets,
           PB=0x00 for the first packet and PB=0x01 for subsequent packets.
        10. Receive the corresponding HCI completion credits.
        11. Receive Step 9 data, LLID=0x02 first and LLID=0x01 thereafter.
        12. Acknowledge with Peripheral DATA on the same data channel.
        13. Repeat Steps 10-12 until all Step 9 data has been received.
        14. If the advertised HCI buffer length exceeds 27 octets, submit
            zero-filled PB=0x00 packets with lengths from 28 through that
            buffer length until at least 1000 octets are submitted. Observe
            matching-handle completion credits; honor flow control throughout.
        15. For Step 14, receive and reconstruct every Host payload, using
            LLID=0x02 for each start and LLID=0x01 for continuations.
            Send empty Peripheral DATA once per connection interval with
            the common channel-selection parameters and acknowledgement scheme.
        16. Repeat Step 15 until all Step 14 data has been received.
        17. Execute Central Connection Terminated for the established
            unencrypted handle and connection parameters.
        Steps 14-16 are optional only when the HCI buffer length is at most 27.

    Expected Outcome:
        Pass verdict:
            All Host data arrives unchanged and in order. HCI completion
            credits match submitted packets. LLID start/continuation boundaries
            satisfy Section 4.1.7 without imposing a specific fragmentation.

    Source Correction:
        Step 15 cites Step 10, which reports credits, and requires reserved
        LLID=0x00. Apply it to the data submitted in Step 14, using LLID=0x02
        for starts and LLID=0x01 for continuations under Section 4.1.7 and
        Core Vol 6, Part B, Section 2.4.1. Amber corroborates these local
        corrections; no adopted SIG erratum is claimed.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-03-C procedure in
        Section 4.3.6, Figure 4.3-135; PDF 750-752, printed 4.3-277 through
        4.3-279. Steps 1-17 and Expected Outcome; DATA fragmentation in 4.1.7.
    """
    await _data_exchange(tester, central=True, direction='tx')


async def central_receiving_data(tester):
    """Central Receiving Data.

    Initial Condition:
        An unencrypted connected Central, public Lower Tester Peripheral,
        supported own address type and common connection/channel parameters.
        Retain the preamble handle and HCI data packet length. Use reproducible
        seeded random payloads for the Lower Tester.

    Test Steps:
        1. Configure 100 ten-octet random Peripheral packets, all LLID=0x02,
           for the first 1000-octet group, applying the correction below.
        2. Receive Central DATA and respond on the same data channel using
           the acknowledgement scheme until all 1000 octets are acknowledged.
        3. Require the Step 1 payloads at the Host, totalling 1000 octets,
           with PB=0x02 at each message start.
        4. Configure another 100 ten-octet random packets, all LLID=0x01.
        5. Repeat Step 2 for the Step 4 group.
        6. Require the Step 4 payloads at the Host, totalling 1000 octets,
           with PB=0x01, applying the source-reference correction below.
        7. Configure one ten-octet random LLID=0x02 packet followed by
           99 ten-octet random LLID=0x01 packets.
        8. Repeat Step 2 for the Step 7 group.
        9. Require all 1000 Step 7 octets at the Host, PB=0x02 first and
           PB=0x01 thereafter, applying the source-reference correction below.
        10. Configure ten three-octet random Peripheral packets, all LLID=0x02.
        11. Receive Central DATA and respond on the same channel using the
            acknowledgement scheme until every Step 10 packet is acknowledged.
        12. Require the Step 11 payloads at the Host with PB=0b10 at each
            original start boundary and exactly the Lower Tester's bytes.
        13. Execute Central Connection Terminated for the established
            unencrypted handle and connection parameters.

    Expected Outcome:
        Pass verdict:
            Every Lower Tester payload is acknowledged and reported unchanged
            and in order. HCI fragmentation preserves message starts according
            to Section 4.1.7; LL and HCI packet boundaries need not coincide.

    Source Correction:
        Steps 1/4 say 1000 ten-octet packets, while Steps 2/3/6 require a
        1000-octet group: use 100 packets. Step 7 says 990 continuation packets;
        use 99 after its one start packet for the same 1000-octet total.
        Steps 6/9 compare against Step 1 but must compare their own source
        groups in Steps 4/7. Amber corroborates these local count/reference
        corrections; no adopted SIG erratum is claimed.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-04-C procedure in
        Section 4.3.6, Figure 4.3-136; PDF 753-755, printed 4.3-280 through
        4.3-282. Steps 1-13 and Expected Outcome; DATA fragmentation in 4.1.7.
    """
    await _data_exchange(tester, central=True, direction='rx')


async def central_sending_and_receiving_data(tester):
    """Central Sending and Receiving Data.

    Initial Condition:
        An unencrypted connected Central, public Lower Tester Peripheral,
        supported own address type and common connection/channel parameters.
        Retain the preamble handle and HCI buffer length. Each direction
        transfers 1000 reproducible seeded random octets in ten-octet messages.

    Test Steps:
        1. Configure 100 ten-octet random Peripheral packets, LLID=0x02
           first and LLID=0x01 thereafter.
        2. Submit 1000 random Host octets in ten-octet packets for the
           established handle, PB=0x00 first and PB=0x01 thereafter.
        3. Receive matching-handle HCI Number Of Completed Packets credits.
        4. Receive Central DATA containing Step 2 bytes, LLID=0x02 first
           and LLID=0x01 thereafter, applying the correction below.
        5. Respond on the same data channel using the acknowledgement
           scheme and the Peripheral data configured in Step 1.
        6. Repeat Steps 4-5 until all Step 2 Host data has been received.
        7. Require Step 1 Peripheral data at the Host with PB=0x02 first
           and PB=0x01 thereafter, unchanged and in its original order.

    Expected Outcome:
        Pass verdict:
            Both directions' data is acknowledged and received unchanged.
            HCI bytes and message-start offsets obey Section 4.1.7, without
            requiring LL and HCI packetization to be identical.

    Source Correction:
        Step 4 refers to data submitted in Step 1, but Step 1 configures the
        opposite direction. Central DATA must contain Host bytes from Step 2.
        Amber corroborates this local reference correction; no adopted SIG
        erratum is claimed.

    Coverage Note:
        Respect HCI buffer credits while interleaving the two data directions.
        Disconnect through HCI after all seven source steps are complete.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-05-C procedure in
        Section 4.3.6, Figure 4.3-137; PDF 755-756, printed 4.3-282 through
        4.3-283. Steps 1-7 and Expected Outcome; DATA fragmentation in 4.1.7.
    """
    await _data_exchange(tester, central=True, direction='duplex')


async def requesting_parameter_update(tester):
    """Requesting Parameter Update.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common interval, latency, timeout and
        channel map. The optional Feature Exchange preamble declares no peer
        Connection Parameters Request support, selecting the direct update.

    Test Steps:
        1. Send HCI LE Connection Update for the maximum supported connection
           interval and require successful Command Status.
        2. Receive LL_CONNECTION_UPDATE_IND with the requested parameters.
           Acknowledge on the same channel with empty Peripheral DATA using
           the acknowledgement scheme. Continue until the following IUT
           packet is received, or up to fifteen connection events.
        3. Maintain the connection with empty DATA using the old parameters
           until the event counter reaches the update Instant.
        4. At Instant, apply the new parameters. Require the next two Central
           DATA transmissions to be separated by the new connection interval,
           allowing the applicable clock jitter.
        5. Require successful HCI LE Connection Update Complete after Instant
           with the established handle and the new interval, latency and timeout.

    Expected Outcome:
        Pass verdict:
            The Central transmits the update indication, maintains the
            connection using the new parameters, and reports those parameters
            to the Host. A successful completion before Instant fails.

    Coverage Note:
        The selected simulation uses a zero-drift clock. The independent peer
        follows the old schedule through Instant, then checks consecutive
        new-interval packets before disconnecting through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-07-C procedure in
        Section 4.3.6, Figure 4.3-138; PDF 757-758, printed 4.3-284 through
        4.3-285. Steps 1-5 and Expected Outcome. Feature Exchange preamble
        in Section 4.1.6.7.3; Core Vol 6, Part B, Section 5.1.1.
    """
    await _local_parameters(tester, central=True, reject=False)


async def central_sending_termination(tester):
    """Central Sending Termination.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common connection/channel parameters.
        Retain the preamble handle and the connection supervision timeout.

    Test Steps:
        1. Send HCI Disconnect for the established handle and require
           successful Command Status.
        2. Receive LL_TERMINATE_IND carrying the requested reason and
           acknowledge with empty Peripheral DATA in the same event.
        3. Observe no further Central transmissions for a duration equal
           to the connection supervision timeout after the acknowledgement.
        4. Interleaved with Step 3, receive successful HCI Disconnection
           Complete for the established handle, reporting local termination.

    Expected Outcome:
        Pass verdict:
            The Central sends termination until acknowledged, stops its
            connection transmissions after the acknowledgement, and reports
            successful termination through HCI.

    Coverage Note:
        Start RF observation immediately after the acknowledgement rather than
        advancing time to await HCI first. Collect HCI events during that same
        observation period, checking the handle/reason and rejecting duplicates.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-08-C procedure in
        Section 4.3.6, Figure 4.3-139; PDF 758-759, printed 4.3-285 through
        4.3-286. Steps 1-4 and Expected Outcome; Core Vol 6, Part B, 5.1.6.
    """
    await _connection_termination(tester, central=True, local=True)


async def central_accepting_termination(tester):
    """Central Accepting Termination.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common connection/channel parameters.
        Retain the preamble handle and connection supervision timeout.

    Test Steps:
        1. Receive empty Central DATA and respond with LL_TERMINATE_IND.
           Require an acknowledgement in the following connection event,
           before T_Terminate expires.
        2. Observe no further Central transmissions for a duration equal
           to the connection supervision timeout after its acknowledgement.
        3. Interleaved with Step 2, receive successful HCI Disconnection
           Complete for the established handle and the peer termination reason.

    Expected Outcome:
        Pass verdict:
            The Central acknowledges before the termination timer expires,
            stops transmitting after its acknowledgement, and reports the
            correct peer-requested termination through HCI.

    Coverage Note:
        Require an empty DATA acknowledgement with NESN acknowledging the
        termination SN, in the next event rather than the request's event.
        Observe RF and HCI concurrently over the post-acknowledgement timeout;
        missing or duplicate HCI disconnections fail.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-09-C procedure in
        Section 4.3.6, Figure 4.3-140; PDF 759-760, printed 4.3-286 through
        4.3-287. Steps 1-3 and Expected Outcome; Core Vol 6, Part B, 5.1.6.
    """
    await _connection_termination(tester, central=True, local=False)


async def central_supervision_timer(tester):
    """Central Supervision Timer.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type, zero latency and common channel parameters.
        Select the maximum and minimum supported interval/timeout pairs.

    Test Steps:
        1. Establish using the maximum supported supervision timeout and
           connection interval, with zero latency: 32 s and 4 s respectively.
        2. Stop Peripheral responses after a known valid connection event
           and remain silent until the supervision timeout expires.
        3. Require successful HCI Disconnection Complete for the established
           handle with Connection Timeout reason, no earlier than the selected
           timeout measured from the last responded event.
        4. Establish again with the minimum supported supervision timeout and
           connection interval, with zero latency: 100 ms and 7.5 ms.
        5. Repeat Steps 2-3 for the minimum settings.

    Expected Outcome:
        Pass verdict:
            For both parameter pairs, the Central reports connection timeout
            after the selected connSupervisionTimeout from the last response.

    Coverage Note:
        Use the last valid Peripheral packet as the timer reference, rather
        than Host setup. Its validation timestamp is the PHY's last occupied
        microsecond, one less than the exclusive packet-end boundary.
        Observe HCI at 1-ms resolution, including an explicit
        check immediately before the permitted boundary so a coarse sample
        cannot hide an already queued early completion. The Central procedure
        does not inherit the Peripheral procedure's 10-ms rounding note.
        Reject a missing/late event, wrong handle/status/reason, or resumed
        Central RF traffic after timeout.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-10-C procedure in
        Section 4.3.6, Figure 4.3-141; PDF 760-761, printed 4.3-287 through
        4.3-288. Steps 1-5 and Expected Outcome; Core Vol 6, Part B, 4.5.2.
    """
    await _supervision(tester, central=True)


async def feature_setup_request(tester):
    """Feature Setup Request.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and selected interval, latency, timeout and
        common channel map. Retain the established connection handle.

    Test Steps:
        1. Send HCI LE Read Local Supported Features Page 0 and require
           successful Command Complete containing the local feature set.
        2. Send HCI LE Read Remote Features Page 0 for the established handle
           and require successful Command Status.
        3. Require LL_FEATURE_REQ with the configured feature set. Accept
           an autonomous request sent before Step 2, provided it is still
           waiting for the Lower Tester's LL_FEATURE_RSP. Send that response
           with the selected valid peer feature set and require its ACK.
        4. Require successful HCI LE Read Remote Features Page 0 Complete
           for the same handle, with features matching LL_FEATURE_RSP.

    Expected Outcome:
        Pass verdict:
            The LL request contains the declared supported features under
            the Send-to-Peer rules; Masked-to-Peer and RFU bits are clear.
            The HCI local feature set matches the declared capabilities.
            The Central requests and acknowledges Feature Exchange, and its
            HCI remote-feature completion matches the Lower Tester's response.

    Coverage Note:
        The Lower Tester offers Connection Parameters Request and LE 2M PHY.
        Check the complete eight-octet feature field and HCI handle/status,
        then disconnect after the four numbered source steps.
        The pre-5.0 name "Read Remote Used Features" identifies the same
        HCI operation, not a different test procedure.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-13-C procedure in
        Section 4.3.6, Figure 4.3-142; PDF 761-763, printed 4.3-288 through
        4.3-290. Steps 1-4 and Expected Outcome; Core Vol 6, Part B, 4.6/5.1.4.
    """
    await _remote_features(tester, central=True, unsupported=False)


async def central_retransmission_request(tester):
    """Central Retransmission Request.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type, common channel-selection parameters and
        30-ms interval, zero latency and 900-ms supervision timeout.
        Retain the current/next SN and NESN variables from the connection.

    Test Steps:
        1. Submit one Host ACL data octet 0xFF for the established handle
           with the packet-boundary start flag.
        2. Receive Central DATA once per connection interval on its selected
           data channel. Respond at T_IFS with invalid-CRC DATA; repeat fifteen
           times.
        3. During Step 2, derive the next transmitted SN from the last
           correctly received NESN and acknowledge correctly received Central
           DATA using the next NESN.
        4. Require following Central packets to indicate failure to receive
           the Peripheral packet: Central SN matches the current tester NESN
           and Central NESN retains the next tester SN.
        5. Execute Central Connection Terminated for the established
           unencrypted handle and connection parameters.

    Expected Outcome:
        Pass verdict:
            The Central sends negative acknowledgements for invalid-CRC DATA.

    Coverage Note:
        Invert every CRC bit on the wire, rather than changing a receive-result
        flag. Require unchanged Central payload/sequence and no Host delivery
        from the faulty packets. Check the response after the fifteenth fault
        before recovery, and require exactly one Host completion credit after
        a valid ACK restores the independent peer's normal sequence state.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-14-C procedure in
        Section 4.3.6, Figure 4.3-143; PDF 763-764, printed 4.3-290 through
        4.3-291. Steps 1-5 and Expected Outcome; Core Vol 6, Part B, 4.5.9.
    """
    await _retransmissions(tester, central=True, mode='crc', latency=False)


async def central_retransmission(tester):
    """Central Retransmission.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type, common channel-selection parameters and
        30-ms interval, zero latency and 900-ms supervision timeout.
        Retain the connection's current/next SN and NESN variables.

    Test Steps:
        1. Submit one Host ACL data octet 0xFF for the established handle
           with the packet-boundary start flag.
        Repeat Steps 2-3 fifteen times.
        2. Receive Central DATA once per interval on the selected data channel.
           Respond at T_IFS with CRC-valid DATA, retaining the current tester
           NESN to withhold acknowledgement of the Central packet. Use a new
           tester SN when the previous Central NESN acknowledges its packet.
        3. Require Central retransmission in the following received packet,
           with SN matching current tester NESN and NESN acknowledging the
           next correctly received tester SN.
        4. Execute Central Connection Terminated for the established
           unencrypted handle and connection parameters.

    Expected Outcome:
        Pass verdict:
            Every negative acknowledgement causes retransmission of the
            same Central payload.

    Coverage Note:
        Validate the final Step 3 observation as well as intermediate replies.
        No Host completion credit may be returned before the payload is
        acknowledged. Recover with a valid ACK, require exactly one matching
        completion credit, then terminate.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-15-C procedure in
        Section 4.3.6, Figure 4.3-144; PDF 764-765, printed 4.3-291 through
        4.3-292. Steps 1-4 and Expected Outcome; Core Vol 6, Part B, 4.5.9.
    """
    await _retransmissions(tester, central=True, mode='nak', latency=False)


async def central_acknowledgement_repetition(tester):
    """Central Acknowledgement Repetition.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type, common channel-selection parameters and
        30-ms interval, zero latency and 900-ms supervision timeout.
        Retain the connection's current/next SN and NESN variables.

    Test Steps:
        1. Submit one Host ACL data octet 0xFF for the established handle
           with the packet-boundary start flag.
        Repeat Steps 2-3 fifteen times.
        2. Receive Central DATA once per interval on the selected data channel
           and respond at T_IFS. Keep the tester SN despite the Central NESN
           acknowledging it, simulating a missed acknowledgement. Positively
           acknowledge correctly received Central packets using the next NESN.
        3. Require the following Central packet to repeat its acknowledgement:
           SN matches current tester NESN and NESN retains the next tester SN.
        4. Execute Central Connection Terminated for the established
           unencrypted handle and connection parameters.

    Expected Outcome:
        Pass verdict:
            The Central repeats its acknowledgement when the tester behaves
            as though the previous acknowledgement was not received.

    Coverage Note:
        Transmit the same one-octet Peripheral payload and SN throughout;
        require exactly one Host delivery, not duplicate deliveries. Check
        the final repeated acknowledgement before restoring normal sequencing,
        and require exactly one completion credit for the submitted Host packet.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-16-C procedure in
        Section 4.3.6, Figure 4.3-145; PDF 765-767, printed 4.3-292 through
        4.3-294. Steps 1-4 and Expected Outcome; Core Vol 6, Part B, 4.5.9.
    """
    await _retransmissions(tester, central=True, mode='duplicate', latency=False)


async def central_lost_negative_acknowledgement(tester):
    """Central Lost Negative Acknowledgement.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type, common channel-selection parameters and
        30-ms interval, zero latency and 900-ms supervision timeout.
        Retain the connection's current/next SN and NESN variables.

    Test Steps:
        1. Submit one Host ACL data octet 0xFF for the established handle
           with the packet-boundary start flag.
        2. Receive Central DATA once per interval on the selected channel.
           Respond at T_IFS with one invalid-CRC DATA packet using the next
           tester SN identified by the previous Central NESN.
        Repeat Steps 3-4 fifteen times.
        3. Receive the negative acknowledgement and respond with valid-CRC
           DATA. The source text requires the same SN as the preceding tester
           packet and positive acknowledgement using the next NESN.
        4. Require following Central packets to continue the negative
           acknowledgement, with NESN matching the current tester SN.
        5. Execute Central Connection Terminated for the established
           unencrypted handle and connection parameters.

    Expected Outcome:
        Pass verdict:
            The Central repeats its negative acknowledgement when the tester
            transmits its next payload.

    Source Conflict:
        Step 3's same-SN requirement contradicts Step 4 and the purpose:
        after bad CRC, a valid packet with the still-expected SN is new DATA,
        not an out-of-sequence packet. Figure 4.3-146 instead advances the
        tester SN. The figure also retains tester NESN equal to Central SN
        (a NAK), whereas Step 3 says to use next NESN (an ACK). Amber confirms
        the sequencing contradiction but recommends the textual ACK; it does
        not reconcile that recommendation with the figure. Do not silently
        choose one stimulus or claim a resolved source correction. Skip this
        procedure until these two conflicting requirements are clarified.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-17-C procedure in
        Section 4.3.6, Figure 4.3-146; PDF 767-768, printed 4.3-294 through
        4.3-295. Steps 1-5 and Expected Outcome; Core Vol 6, Part B, 4.5.9.
    """
    pytest.skip(
        'LL.TS.p28 CEN/BV-17-C Step3 conflicts with Figure4.3-146: '
        'same/advanced tester SN and positive/negative acknowledgement'
    )


async def central_latency_retransmission_request(tester):
    """Central Latency Retransmission Request.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type, common channel-selection parameters and
        30-ms interval. Select nonzero Peripheral latency one and the maximum
        supervision timeout from TSPX_conn_timeout_max, here 32 s.
        Retain the connection's current/next SN and NESN variables.

    Test Steps:
        1. Submit one Host ACL data octet 0xFF for the established handle
           with the packet-boundary start flag.
        Repeat Steps 2-3 fifteen times.
        2. Receive Central DATA once per interval on the selected data channel.
           Respond at T_IFS with invalid-CRC DATA only in events required by
           the Peripheral latency parameter. Derive the tester SN and NESN
           from the last correctly received Central acknowledgement state.
        3. Require following Central DATA to indicate either CRC failure or
           absence of a response: SN matches current tester NESN and NESN
           retains current tester SN.
        4. Execute Central Connection Terminated for the established
           unencrypted handle and connection parameters.

    Expected Outcome:
        Pass verdict:
            The Central uses retransmissions to handle Peripheral latency.

    Coverage Note:
        With latency one, omit alternate responses while still observing
        every Central event. Require unchanged retransmitted Host payload,
        sequence state and no premature Host completion credit. Check the
        final fault's response, recover with a valid ACK and require exactly
        one matching completion credit before termination.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-18-C procedure in
        Section 4.3.6, Figure 4.3-147; PDF 768-769, printed 4.3-295 through
        4.3-296. Steps 1-4 and Expected Outcome; Core Vol 6, Part B, 4.5.9.
    """
    await _retransmissions(tester, central=True, mode='crc', latency=True)


async def connection_control_timeout(tester):
    """Connection Control Timeout.

    Initial Condition:
        The IUT is in Standby. The Lower Tester acts as a Peripheral,
        advertises with a public address on the first supported advertising
        channel, and can acknowledge DATA without answering Feature Exchange.

    Test Steps:
        1. Configure the public Lower Tester advertiser on the first supported
           advertising channel.
        2. Send HCI LE Create Connection with public Peer_Address_Type=0x00
           and the Lower Tester address; require successful Command Status.
        3. Require HCI LE Connection Complete for the established Central ACL.
        4. Send HCI LE Read Remote Features Page 0. If the IUT already sent an
           autonomous LL_FEATURE_REQ after connection, treat that packet as
           Step 5 and perform Step 4 as soon as practical; do not require
           another request or restart the existing procedure's timer.
        5. Receive LL_FEATURE_REQ from the IUT, unless already received
           through the autonomous alternative preceding Step 4.
        6. Acknowledge the request with DATA but never send LL_FEATURE_RSP.
        7. Maintain valid empty DATA to avoid supervision timeout while
           withholding LL_FEATURE_RSP until the procedure response timer expires.
        8. If HCI LE Read Remote Features Page 0 Complete is reported,
           require the established handle and status LL Response Timeout (0x22).
        9. Require successful HCI Disconnection Complete for that handle,
           with reason LL Response Timeout (0x22).

    Expected Outcome:
        Pass verdict:
            At control transaction timeout, the IUT reports disconnection
            with reason 0x22, rather than a supervision timeout.

    Source Correction:
        Step 6 describes the LL_FEATURE_REQ as received by the IUT, although
        Step 5 has the IUT transmit it. The Lower Tester acknowledges the
        request it received from the IUT. This is a local subject correction,
        not an adopted SIG erratum.

    Coverage Note:
        Core Vol 6, Part B, 5.2 starts the 40-s response timer at procedure
        initiation/LL Control PDU queueing, not at peer ACK or first RF TX.
        That internal queueing timestamp is not exposed by HCI. Bound it
        between the triggering action and the first observed request; for
        the autonomous alternative, the lower bound precedes connection
        establishment. Do not treat the Host-command timestamp as an exact
        normative timer origin. Observe with 1-ms precision, reject early
        completion, duplicate or wrong-handle/status events, and any procedure
        completion following Disconnection Complete. Require RF cessation.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-19-C procedure in
        Section 4.3.6, Figure 4.3-148; PDF 770-771, printed 4.3-297 through
        4.3-298. Steps 1-9 and the autonomous alternative before Step 4;
        Core Vol 6, Part B, 5.2.
    """
    await _procedure_timeout(tester, central=True, parameters=False)


async def central_acknowledgement_scheme(tester):
    """Central Acknowledgement Scheme.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type, common channel-selection parameters,
        30-ms interval, zero latency and 900-ms supervision timeout.
        Retain the connection handle and current/next SN and NESN variables.

    Test Steps:
        Repeat Steps 1-5 fifteen times.
        1. Submit four-octet Host data 0xFFFFFFFF for the established handle
           with the HCI packet-boundary start flag.
        2. Configure one Lower Tester DATA packet with four-octet payload
           0xFFFFFFFF.
        3. Receive Central DATA once per connection interval on its selected
           channel. Require SN matching the current tester NESN and NESN
           matching the next tester SN for correctly received packets.
        4. Respond at T_IFS using the normal acknowledgement scheme: use
           next SN when the Central NESN acknowledges the current packet,
           and next NESN to acknowledge correctly received Central DATA.
        5. Require HCI ACL Data containing the Lower Tester payload.
        6. Execute Central Connection Terminated for the established
           unencrypted handle and connection parameters.

    Expected Outcome:
        Pass verdict:
            All fifteen exchanges complete with the normal acknowledgement
            scheme, preserving payloads and packet sequence numbering.

    Coverage Note:
        Check all four Host-to-air octets and completion credits. For received
        data, compare the complete HCI byte stream and message-start offsets
        under Section 4.1.7 rather than requiring a specific HCI fragmentation.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-22-C procedure in
        Section 4.3.6, Figure 4.3-151; PDF 773-774, printed 4.3-300 through
        4.3-301. Steps 1-6 and Expected Outcome; Core Vol 6, Part B, 4.5.9.
    """
    await _acknowledgement_scheme(tester, central=True)


async def responding_to_feature_exchange(tester):
    """Responding to Feature Exchange.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common interval, latency, timeout and
        channel map. Read the declared local features for response validation.

    Test Steps:
        1. Send LL_PERIPHERAL_FEATURE_REQ with the Lower Tester's selected
           feature set and wait for LL_FEATURE_RSP.
        2. Require the Central to respond with LL_FEATURE_RSP.

    Expected Outcome:
        Pass verdict:
            The Central sends the feature response. All feature bits marked
            Masked to Peer are clear.

    Coverage Note:
        Select a zero peer FeatureSet; the response's FeatureSet_USED first
        octet must therefore be zero. Check the fixed eight-octet field,
        required local features and optional Send-to-Peer reporting rules,
        and reject forbidden, undeclared or RFU bits. Disconnect after the
        two numbered source steps.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-23-C procedure in
        Section 4.3.6, Figure 4.3-152; PDF 775, printed 4.3-302.
        Steps 1-2 and Expected Outcome; referenced Core procedure 5.1.4.2.
    """
    await _feature_or_version(tester, central=True, version=False)


async def initiating_connection_parameter_request_accept_ll_con_cen_bv_24_c(tester):
    """Initiating Connection Parameter Request – Accept.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common latency, timeout and channel map.
        Use the optional Feature Exchange preamble to declare peer support for
        Connection Parameters Request. Run all four cases on the maintained ACL.

    Test Steps:
        Case 1:
        1. Send HCI LE Connection Update requesting the minimum interval,
           zero latency and 3-s supervision; require successful Command Status.
        2. Receive valid LL_CONNECTION_PARAM_REQ, whose fields may differ from
           the Host request. Accept with LL_CONNECTION_PARAM_RSP and require
           its acknowledgement followed by LL_CONNECTION_UPDATE_IND.
        3. Maintain empty DATA using the old schedule until the update Instant.
        4. At Instant, adopt the IUT-selected parameters and continue DATA.
        5. Require successful HCI LE Connection Update Complete reporting
           the new interval, latency and timeout for the established handle.
        Case 2:
        1. Send HCI LE Connection Update requesting the maximum interval,
           zero latency and maximum supervision; require successful Status.
        2. Receive valid LL_CONNECTION_PARAM_REQ, accept it with PARAM_RSP,
           and require its acknowledgement followed by UPDATE_IND.
        3. Maintain empty DATA using the old schedule until Instant.
        4. At Instant, continue with the IUT-selected new parameters.
        5. Require successful HCI Update Complete with the selected parameters.
        Case 3:
        1. Send HCI LE Connection Update requesting the minimum interval,
           zero latency and 3-s supervision; require successful Status.
        2. Receive valid LL_CONNECTION_PARAM_REQ, accept it with PARAM_RSP,
           and require its acknowledgement followed by UPDATE_IND.
        3. Maintain empty DATA using the old schedule until Instant.
        4. At Instant, continue with the IUT-selected new parameters.
        5. Require successful HCI Update Complete with the selected parameters.
        Case 4:
        1. Request interval min=max=0x0960 (3 s), or 0x0640 (2 s) if already
           using 3 s, maximum supervision and unchanged latency; require
           successful HCI Command Status.
        2. Receive LL_CONNECTION_PARAM_REQ with a valid ReferenceConnEventCount.
           Its timing fields may differ from the Host request.
        3. Send LL_CONNECTION_PARAM_RSP with a different valid reference count.
        4. Receive LL_CONNECTION_UPDATE_IND.
        5. Maintain empty DATA using the old schedule until its Instant.
        6. At Instant, continue with the IUT-selected new parameters.
        7. Require successful HCI Update Complete with the selected parameters.

    Expected Outcome:
        Pass verdict:
            In Cases 1-3 the IUT initiates negotiation, adopts the accepted
            LL timing fields at Instant and reports them through HCI.
            In Case 4 the ACL is maintained through Instant and the new
            parameters are reported despite the changed reference count.

    Coverage Note:
        Check valid request ranges independently of Host arguments, allowing
        PreferredPeriodicity=0 with a range. For identical accepted REQ/RSP
        timing fields, the selected interval stays within the accepted range
        and latency/timeout match those fields. Reject early HCI success.
        Case 4 uses a known recent reference event different from the request;
        mark all response offsets unspecified rather than retaining offsets
        calculated against the old reference. Disconnect after all four cases.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-24-C procedure in
        Section 4.3.6, Figures 4.3-153/154; PDF 775-780, printed 4.3-302
        through 4.3-307. Cases 1-3 Steps 1-5 and Case 4 Steps 1-7;
        Core parameter negotiation procedure 5.1.7.
    """
    await _central_parameters(tester, reject=False, collision=False, legacy=False)


async def initiating_connection_parameter_request_reject_ll_con_cen_bv_25_c(tester):
    """Initiating Connection Parameter Request – Reject.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common latency, timeout and channel map.
        Declare peer Connection Parameters Request support in the optional
        Feature Exchange preamble.

    Test Steps:
        1. Send HCI LE Connection Update requesting the minimum interval,
           zero latency and 3-s supervision; require successful Command Status.
        2. Receive valid LL_CONNECTION_PARAM_REQ, whose parameters may differ
           from the Host request. Reject it with LL_REJECT_EXT_IND identifying
           that opcode and error Unacceptable Connection Parameters (0x3B).
           Require the Central to acknowledge the rejection.
        Alternative 1:
        - Require HCI LE Connection Update Complete for the established handle
          with the rejection's error code 0x3B.
        Alternative 2:
        - Receive LL_CONNECTION_UPDATE_IND; its parameters may differ from
          the Host request.
        - Maintain empty DATA using the old schedule until the update Instant.
        - At Instant, adopt the IUT-selected parameters and continue DATA.
        - Require successful HCI LE Connection Update Complete reporting
          those new parameters.

    Expected Outcome:
        Pass verdict:
            The IUT sends its parameter request and either reports error
            0x3B or completes a valid connection update with HCI notification.

    Coverage Note:
        Accept either source alternative, not only the error branch.
        Failed HCI completion fields other than status/handle are not used
        as negotiated parameters. In that branch, verify continued old RF
        timing and reject a second completion or contradictory update.
        In the update branch, validate the selected timing fields and Instant
        rather than forcing the rejected Host values. Disconnect afterwards.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-25-C procedure in
        Section 4.3.6, Figure 4.3-155; PDF 780-782, printed 4.3-307 through
        4.3-309. Steps 1-2, both alternatives and Expected Outcome;
        Core parameter negotiation procedure 5.1.7.
    """
    await _central_parameters(tester, reject=True, collision=False, legacy=False)


async def initiating_parameter_request_same_procedure_collision_cen_bv_26(
    tester,
):
    """Initiating Connection Parameter Request – same procedure collision.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common latency, timeout and channel map.
        Declare peer Connection Parameters Request support before the procedure.

    Test Steps:
        1. Send HCI LE Connection Update requesting the minimum interval,
           zero latency and 3-s supervision; require successful Command Status.
        2. Receive LL_CONNECTION_PARAM_REQ, whose fields may differ from the
           Host request, and respond with a colliding LL_CONNECTION_PARAM_REQ.
        3. Require LL_REJECT_EXT_IND rejecting the Lower Tester's request
           with reason LL Procedure Collision (0x23).
        4. Accept the original IUT request with LL_CONNECTION_PARAM_RSP and
           require LL_CONNECTION_UPDATE_IND.
        5. Maintain empty DATA using the old schedule until the update Instant.
        6. Require the IUT-selected new parameters to take effect at Instant.
        7. From the update point, maintain the connection using that new timing.
        8. Require successful HCI LE Connection Update Complete reporting
           the new parameters for the established handle.

    Expected Outcome:
        Pass verdict:
            The Central issues its own request, rejects the colliding request,
            accepts the Lower Tester's response to the original request,
            maintains the updated ACL and reports the selected parameters.

    Coverage Note:
        Validate the rejection's opcode as well as its reason. Check final
        timing against the accepted LL fields, not the raw Host request.
        Require acknowledgement of the response, no HCI success before
        Instant, and consecutive new-interval DATA before disconnecting.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-26-C procedure in
        Section 4.3.6, Figure 4.3-156; PDF 782-784, printed 4.3-309 through
        4.3-311. Steps 1-8 and Expected Outcome; Core procedure 5.1.7.
    """
    await _central_parameters(tester, reject=False, collision=True, legacy=False)


async def initiating_parameter_request_channel_map_collision_cen_bv_27(
    tester,
):
    """Initiating Connection Parameter Request – different procedure collision – channel
    map update.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common connection/channel parameters.

    Test Steps:
        1. Send HCI LE Set Host Channel Classification requesting even
           data channels only.
        2. Require Command Complete with success. If the command fails,
           retry with a different channel map, at least five seconds apart,
           up to twenty attempts or until successful.
        3. If all twenty attempts fail, return an Inconclusive verdict.
        4. Receive LL_CHANNEL_MAP_IND; its new map need not equal the map
           submitted by the Host.
        5. Send LL_CONNECTION_PARAM_REQ as the same-event acknowledgement
           of that indication, requesting the minimum interval, zero latency
           and 3-s supervision timeout.
        6. Require LL_REJECT_EXT_IND identifying that request and error
           Different Transaction Collision (0x2A).
        7. Maintain empty DATA on the old channel map until the indicated
           Instant, then maintain the connection using the new map.

    Expected Outcome:
        Pass verdict:
            The Central sends Channel Map Update, rejects the colliding
            parameter request, and maintains DATA using the updated selection
            parameters after Instant.
        Inconclusive verdict:
            All twenty Host commands fail, or the Controller chooses not to
            provide a Channel Map Update indication.

    Coverage Note:
        Send the colliding request in the packet that acknowledges the map
        indication, not in a later event. Validate at least two enabled data
        channels and no reserved map bits. Check the updated map through
        HCI Read Channel Map and transfer ACL DATA before disconnecting.
        No Host parameter-request or update-completion event is expected.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-27-C procedure in
        Section 4.3.6, Figure 4.3-157; PDF 784-785, printed 4.3-311 through
        4.3-312. Steps 1-7, Pass and Inconclusive verdicts; Core procedure 5.1.7.
    """
    await _parameter_collision(tester, central=True, channel_map=False)


async def initiating_parameter_request_encryption_collision_cen_bv_28(
    tester,
):
    """Initiating Connection Parameter Request – different procedure collision –
    encryption.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common latency, timeout and channel map.
        The Lower Tester maintains independent AES-CCM state and test key material.

    Test Steps:
        1. Send HCI LE Enable Encryption and require successful Command Status.
        2. Receive LL_ENC_REQ.
        3. As its same-event acknowledgement, send LL_CONNECTION_PARAM_REQ
           requesting the minimum interval, zero latency and 3-s supervision.
        4. Send LL_ENC_RSP with the Lower Tester's session-key and IV components.
        5. Send LL_START_ENC_REQ and require the IUT to acknowledge it.
        6. Receive LL_START_ENC_RSP and respond with LL_START_ENC_RSP.
        7. Require successful HCI Encryption Change for the established handle.
        8. At any time after Step 3, possibly interleaved with Steps 4-7,
           receive HCI LE Remote Connection Parameter Request and accept it.
        9. Require LL_CONNECTION_UPDATE_IND with the selected parameters;
           they may differ from the Host's provided values.
        10. Maintain empty DATA using the old schedule until its Instant.
        11. At Instant, maintain the connection using the selected new timing.
        12. Require successful HCI LE Connection Update Complete reporting
            those parameters for the established handle.

    Expected Outcome:
        Pass verdict:
            The IUT sends LL_ENC_REQ and LL_START_ENC_RSP, completes encryption
            with HCI notification, accepts the pending parameter negotiation,
            maintains the updated ACL and reports the selected timing through HCI.

    Coverage Note:
        Inject the parameter request in the ACK of LL_ENC_REQ, not after an
        intervening empty ACK. Derive the session key and encrypted packet
        counters independently; validate the decrypted START_ENC exchange.
        Complete encryption before the parameter procedure response timeout.
        Accept the Host parameter request after Step 7, one of the permitted
        Step 8 interleavings. Check original timing until Instant, updated DATA,
        full HCI parameters, and an encrypted exchange before disconnection.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-28-C procedure in
        Section 4.3.6, Figure 4.3-158; PDF 786-788, printed 4.3-313 through
        4.3-315. Steps 1-12, Expected Outcome and Notes; Core 5.1.7/5.1.3.1.
    """
    await _parameter_encryption_collision(tester, central=True)


async def initiating_connection_parameter_request_remote_legacy_host(tester):
    """Initiating Connection Parameter Request – remote legacy Host.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common latency, timeout and channel map.
        The peer Link Layer supports Connection Parameters Request; the Lower
        Tester models its legacy or event-masked Host by rejecting the request.

    Test Steps:
        1. Send HCI LE Connection Update requesting the minimum interval,
           zero latency and 3-s supervision; require successful Command Status.
        2. Receive valid LL_CONNECTION_PARAM_REQ, whose parameters may differ
           from the Host request. Respond with LL_REJECT_EXT_IND identifying
           that request and error Unsupported Remote Feature (0x1A).
           Require acknowledgement of the rejection.
        3. Receive LL_CONNECTION_UPDATE_IND.
        4. Maintain empty DATA using the old schedule until its Instant.
        5. At Instant, maintain the connection with the IUT-selected new timing.
        6. Require successful HCI LE Connection Update Complete reporting
           the selected parameters for the established handle.

    Expected Outcome:
        Pass verdict:
            The IUT initiates its parameter request, sends Connection Update
            after the 0x1A rejection, maintains the updated ACL and reports
            its new parameters through HCI.

    Coverage Note:
        Do not send PARAM_RSP or terminate on the rejection. Validate the
        direct update's legal timing independently of the original Host
        request, require no completion before Instant, and check consecutive
        new-interval DATA and the HCI fields before disconnecting.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-29-C procedure in
        Section 4.3.6, Figure 4.3-159; PDF 788-790, printed 4.3-315 through
        4.3-317. Steps 1-6 and Expected Outcome; Core procedure 5.1.7.
    """
    await _central_parameters(tester, reject=False, collision=False, legacy=True)


async def accepting_parameter_request_no_preferred_periodicity_cen_bv_30(
    tester,
):
    """Accepting Connection Parameter Request – no Preferred_Periodicity.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common latency, timeout and channel map.
        Maintain the same ACL through all three cases.

    Test Steps:
        Case 1:
        1. Send LL_CONNECTION_PARAM_REQ requesting the minimum interval,
           zero latency, 3-s supervision and PreferredPeriodicity=0.
        2. Require the Host parameter approval request and accept it.
        3. Receive LL_CONNECTION_UPDATE_IND and acknowledge it. The selected
           parameters may differ from those provided by the Host.
        4. Maintain empty DATA using old timing until the indicated Instant.
        5. Require the selected new parameters to take effect at Instant.
        6. From that point, maintain the connection using the new timing.
        7. Require successful HCI LE Connection Update Complete reporting
           those parameters for the established handle.
        Case 2:
        1. Send LL_CONNECTION_PARAM_REQ requesting the maximum interval,
           zero latency, maximum supervision and PreferredPeriodicity=0.
        2. Require the Host approval request and accept it.
        3. Receive and acknowledge LL_CONNECTION_UPDATE_IND carrying the
           IUT-selected parameters.
        4. Maintain empty DATA using old timing until Instant.
        5. Require the new parameters to take effect at Instant.
        6. Maintain the connection using the new timing.
        7. Require successful HCI Update Complete with the selected parameters.
        Case 3:
        1. Send LL_CONNECTION_PARAM_REQ requesting the minimum interval,
           zero latency, 3-s supervision and PreferredPeriodicity=0.
        2. Require the Host approval request and accept it.
        3. Receive and acknowledge LL_CONNECTION_UPDATE_IND carrying the
           IUT-selected parameters.
        4. Maintain empty DATA using old timing until Instant.
        5. Require the new parameters to take effect at Instant.
        6. Maintain the connection using the new timing.
        7. Require successful HCI Update Complete with the selected parameters.

    Expected Outcome:
        Pass verdict:
            All three requests are accepted, the ACL is maintained using the
            selected new parameters, and HCI reports each completed update.

    Coverage Note:
        Select supported limits 7.5 ms/4 s and 32-s maximum supervision.
        Check every Host approval field and positive-reply handle, old/new
        schedules, legal transmit-window reception and no early HCI success.
        Validate subsequent DATA and full HCI parameters before termination.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-30-C procedure in
        Section 4.3.6, Figure 4.3-160; PDF 790-793, printed 4.3-317 through
        4.3-320. Cases 1-3, each Steps 1-7, and Expected Outcome; Core 5.1.7.
    """
    await _remote_parameters(
        tester, central=True, reject=False, masked=False, invalid=False
    )


async def accepting_parameter_request_preferred_anchors_cen_bv_31(
    tester,
):
    """Accepting Connection Parameter Request – preferred anchor points only.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common interval, latency, timeout and
        channel map. Maintain the same ACL through all three cases.

    Test Steps:
        Case 1:
        1. Send LL_CONNECTION_PARAM_REQ with Offset0=1.25 ms, Offset1-5
           unspecified, and unchanged interval, latency and supervision timeout.
        2. Receive and acknowledge LL_CONNECTION_UPDATE_IND that moves
           the connection anchors by 1.25 ms.
        3. Maintain empty DATA using old timing until Instant.
        4. At Instant, maintain the connection at the new anchor phase.
        Case 2:
        1. Send LL_CONNECTION_PARAM_REQ with Offset0=interval-1.25 ms,
           Offset1-5 unspecified, and unchanged connection parameters.
        2. Receive and acknowledge LL_CONNECTION_UPDATE_IND that moves
           anchors by interval-1.25 ms.
        3. Maintain empty DATA using old timing until Instant.
        4. At Instant, maintain the connection at the new anchor phase.
        Case 3:
        1. Send LL_CONNECTION_PARAM_REQ with Offset0=1.25 ms, Offset1=2.5 ms,
           Offset2-5 unspecified, and unchanged connection parameters.
        2. Receive and acknowledge LL_CONNECTION_UPDATE_IND that selects
           the 1.25-ms anchor displacement.
        3. Maintain empty DATA using old timing until Instant.
        4. At Instant, maintain the connection at the new anchor phase.

    Expected Outcome:
        Pass verdict:
            The IUT accepts each request and maintains the ACL with actual
            anchor displacements 1.25 ms, interval-1.25 ms, and 1.25 ms.

    Coverage Note:
        These exact displacements are explicit in this procedure's verdict.
        Determine phase from received DATA, not WinOffset alone: the first
        Central packet inside the transmit window establishes the new anchor.
        Check unchanged timing parameters, old schedule through Instant and
        subsequent new-anchor DATA. An anchor-only move does not notify the
        Host of a parameter update or require Host parameter approval.
        Disconnect after all twelve numbered steps.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-31-C procedure in
        Section 4.3.6, Figure 4.3-161; PDF 793-795, printed 4.3-320 through
        4.3-322. Cases 1-3, each Steps 1-4, and Expected Outcome;
        Core 5.1.7 and anchor-point definition in 5.1.1.
    """
    await _preferred_parameters(tester, central=True, anchors_only=True, anchors=True)


async def accepting_connection_parameter_request(tester, *, anchors):
    """Accepting Connection Parameter Request.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common connection/channel parameters.
        Configure the appropriate Table 4.3-55 row:
        BV-32-C: preferred periodicity and Offset0=0.
        BV-33-C: preferred periodicity, a valid reference event and Offset0=1.25 ms;
        Offset1-5 are unspecified.

    Test Steps:
        1. Send LL_CONNECTION_PARAM_REQ with a nonzero interval range, zero
           latency, 3-s supervision and preferred periodicity having at least
           one multiple in the range. Apply the selected Table 4.3-55 offsets.
        2. Require the Host parameter approval request and accept it.
        3. Receive LL_CONNECTION_UPDATE_IND and acknowledge it.
        4. Maintain empty DATA using old timing until Instant.
        5. At Instant, maintain the connection using the selected new timing.
        6. Require successful HCI LE Connection Update Complete reporting
           the new parameters for the established handle.

    Expected Outcome:
        Pass verdict:
            The request is accepted, the ACL is maintained using the selected
            new parameters, and HCI reports the completed parameter update.

    Coverage Note:
        Use range 13..19 and PreferredPeriodicity=18 in 1.25-ms units, satisfying
        both the table's range wording and the requirement for a valid multiple.
        Check all Host approval fields and the positive-reply handle, accepted
        timing ranges, Instant, actual first-packet anchor and continued DATA.
        Core 5.1.7.2 says to try the periodic multiple and preferred offsets;
        these preferences are not mandatory verdict conditions in this procedure.
        Record selected interval and observed phase without rejecting a legal
        nonmultiple or a different legal phase. This differs from BV-31-C,
        whose verdict explicitly specifies the displacement. Disconnect afterwards.

    Reference:
        LL.TS.p28, Section 4.3.6.1, Table 4.3-55 and Figure 4.3-162;
        LL/CON/CEN/BV-32-C and LL/CON/CEN/BV-33-C; PDF 796-797,
        printed 4.3-323 through 4.3-324. Steps 1-6 and Expected Outcome.
    """
    await _preferred_parameters(
        tester, central=True, anchors_only=False, anchors=anchors
    )


async def accepting_connection_parameter_request_event_masked_ll_con_cen_bv_34_c(
    tester,
):
    """Accepting Connection Parameter Request – event masked.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common latency, timeout and channel map.

    Test Steps:
        1. Mask HCI LE Remote Connection Parameter Request on the IUT.
        2. Send LL_CONNECTION_PARAM_REQ requesting the minimum interval,
           zero latency and 3-s supervision timeout.
        3. Require LL_REJECT_EXT_IND with Unsupported Remote Feature (0x1A).

    Expected Outcome:
        Pass verdict:
            The IUT rejects the parameter request with LL_REJECT_EXT_IND
            carrying error 0x1A.

    Coverage Note:
        Check the rejected opcode as well as the reason. Require no Host
        parameter approval or update-completion event while continuing
        DATA on the unchanged connection, then disconnect through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-34-C procedure in
        Section 4.3.6, Figure 4.3-163; PDF 798, printed 4.3-325.
        Steps 1-3 and Expected Outcome; Core procedure 5.1.7.
    """
    await _remote_parameters(
        tester, central=True, reject=False, masked=True, invalid=False
    )


async def accepting_connection_parameter_request_host_rejects_ll_con_cen_bv_35_c(
    tester,
):
    """Accepting Connection Parameter Request – Host rejects.

    Initial Condition:
        An unencrypted connected Central with a public Lower Tester Peripheral,
        supported own address type and common latency, timeout and channel map.

    Test Steps:
        1. Send LL_CONNECTION_PARAM_REQ requesting the minimum interval,
           zero latency and 3-s supervision timeout.
        2. Require the Host approval request and reject it with
           Unacceptable Connection Parameters (0x3B).
        3. Require LL_REJECT_EXT_IND carrying the Host-provided error 0x3B.

    Expected Outcome:
        Pass verdict:
            The IUT responds with LL_REJECT_EXT_IND using the error code
            supplied by the Host.

    Coverage Note:
        Check every Host request field, the HCI negative-reply handle and
        the rejected LL opcode. Continue acknowledged DATA on the old
        connection and require no successful parameter update before
        disconnecting through HCI.

    Reference:
        LL.TS.p28, independently titled LL/CON/CEN/BV-35-C procedure in
        Section 4.3.6, Figure 4.3-164; PDF 798-799, printed 4.3-325 through
        4.3-326. Steps 1-3 and Expected Outcome; Core procedure 5.1.7.
    """
    await _remote_parameters(
        tester, central=True, reject=True, masked=False, invalid=False
    )


async def initiating_phy_update_procedure_ll_con_cen_bv_41_c(tester):
    """Initiating PHY Update Procedure.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The connection starts on LE 1M.
        This IUT declares both LE 2M and LE Coded support.

    Test Steps:
        Execute all 32 rounds of Table 4.3-56 in order, then execute every round
        again in seeded random order. Preserve the table's RX_PHYS/TX_PHYS column
        order when constructing the Lower Tester's response.

        1. Send HCI_LE_Set_PHY with the round's ALL_PHYS, TX_PHYS and RX_PHYS,
           and PHY_options=0x0000.
        2. Receive HCI_Command_Status. Require Unsupported Feature or Parameter
           Value (0x11) if any requested PHY bit is unsupported; otherwise require
           success (0x00).
        3. If the IUT does not initiate a PHY change, go to Step 9 for an accepted
           command, or proceed to the next round for a rejected command.
        4. Receive LL_PHY_REQ with at least one supported bit in each of TX_PHYS
           and RX_PHYS. Acknowledge the request and send LL_PHY_RSP using the
           response fields from this round of Table 4.3-56.
        5. Receive LL_PHY_UPDATE_IND. Each directional field must contain zero or
           one PHY bit; nonzero choices must be common to the corresponding
           request and response directions. If both fields are zero, go to Step 8.
        6. Maintain the connection using empty DATA packets on the old PHYs until
           the event counter reaches the indicated Instant.
        7. At the Instant, use the new PHY in each nonzero direction and retain
           the previous PHY in each zero direction. Reject an early PHY change
           or an early successful HCI PHY completion.
        8. Receive and acknowledge the IUT's empty DATA packets on the selected
           directional PHYs.
        9. If Step 2 accepted the command or either UPDATE field is nonzero,
           require LE_PHY_Update_Complete with success, the connection handle
           and the effective directional PHYs. Retain the previous PHY for a
           zero field or an absent UPDATE. Otherwise require no completion.

    Expected Outcome:
        Pass verdict:
            Every selected nonzero PHY belongs to both directional preference
            masks and differs from the previous PHY. A zero directional field
            is allowed when there is no common PHY, the current PHY is common,
            or both UPDATE fields are zero. A change uses a valid future Instant.
            DATA continues on the indicated PHYs, changing only at the Instant.
            HCI completion reports the effective PHYs, including an accepted
            command that changes neither direction. A rejected command without
            a PHY change produces no completion.
        Fail verdict:
            The IUT accepts an unsupported PHY bit or violates any required
            selection, Instant, connection-maintenance or HCI-event condition.
        Inconclusive verdict:
            The IUT initiates no PHY Update procedure or selects no actual PHY
            change over the complete test.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-41-C; Figure 4.3-165, Table 4.3-56;
        PDF pages 799-802, printed pages 4.3-326..329; source reference [10] 5.1.10.
        Core v6.3, Vol 6, Part B, 2.4.2.23: unchanged PHY fields shall be zero;
        Vol 1, Part E, 2.4.1: a sender sets the unused Instant (RFU) to zero.
    """
    await _phy_update(tester, central=True, local=True)


async def responding_to_phy_update_procedure_ll_con_cen_bv_43_c(tester):
    """Responding to PHY Update Procedure.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The connection starts on LE 1M.
        This IUT declares both LE 2M and LE Coded, selecting Table 4.3-59 rather
        than the reduced-feature Tables 4.3-57 or 4.3-58.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0x03 and require successful
           HCI_Command_Status. If the IUT sends LL_PHY_REQ, answer with
           LL_PHY_RSP specifying the current PHY in both directions and receive
           the IUT's no-change LL_PHY_UPDATE_IND. With or without this optional
           exchange, require HCI_LE_PHY_Update_Complete reporting LE 1M/LE 1M.
        2. Perform Steps 3-9 for every table case in order, then every case again
           in seeded random order: 2N iterations, where N=49 for Table 4.3-59.
        3. Send LL_PHY_REQ with this table case's TX_PHYS and RX_PHYS.
        4. Receive LL_PHY_UPDATE_IND, not the Peripheral-only LL_PHY_RSP. Each
           directional choice is zero or one bit permitted by the request.
           Require a valid future Instant if either field is nonzero.
        5. Maintain the connection using empty DATA packets on the old PHYs
           until the event counter reaches the Instant.
        6. At the Instant, use the PHYs selected by LL_PHY_UPDATE_IND; a zero
           field retains that direction's current PHY.
        7. Starting at the Instant, maintain the connection on the selected PHYs.
        8. Receive and acknowledge the IUT's empty DATA packets on those PHYs.
        9. If a PHY changed, require LE_PHY_Update_Complete with success, the
           connection handle and the selected effective PHYs. If neither PHY
           changed, require no completion.

    Test Condition:
        Before Step 3 or after the Instant, the IUT may initiate an autonomous
        LL_PHY_REQ. Answer with current-PHY-only LL_PHY_RSP and require an
        LL_PHY_UPDATE_IND with both directional fields zero.
        If the IUT sends LL_PHY_REQ simultaneously with Step 3, require its
        LL_REJECT_EXT_IND for the Lower Tester's LL_PHY_REQ with procedure
        collision (0x23). Answer the retained IUT request with current-PHY-only
        LL_PHY_RSP, require a no-change UPDATE, and repeat Step 3.
        An unsolicited IUT LL_PHY_REQ after Step 3 but before the Instant fails.
        No-change autonomous procedures must not produce Host PHY completions.

    Expected Outcome:
        Pass verdict:
            Each nonzero UPDATE field selects one requested PHY and encodes an
            actual directional change. If the request specifies the same single
            PHY in both fields, select that PHY in both effective directions
            or leave both directions unchanged; see Source Correction below.
            Nonzero fields have a valid Instant. DATA remains on the selected
            PHYs, with no change before the Instant. HCI completion reports
            effective PHYs only when a PHY changed.
        Fail verdict:
            The IUT sends an unsolicited LL_PHY_REQ after Step 3 and before the
            Instant, or violates the required selection, collision, timing,
            DATA-maintenance or HCI-event behavior.
        Inconclusive verdict:
            No PHY Update procedure is initiated over the complete test.
            The source does not require an actual PHY change for this verdict.

    Source Correction:
        The pass text literally requires identical nonzero UPDATE fields for a
        symmetric single-PHY request. Core v6.3, Vol 6, Part B, 2.4.2.23 requires
        zero for any unchanged direction; 5.1.10 requires symmetric effective
        PHY selection, not redundant nonzero encoding. From LE 1M/LE Coded,
        selecting LE Coded/LE Coded therefore uses UPDATE 0x04/0x00, not
        0x04/0x04. Compare effective PHYs while enforcing unchanged-field zero.
        Amber corroborated this interpretation against both Core clauses.
        This is a local source correction, not an adopted SIG erratum.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-43-C; Figure 4.3-166, Tables 4.3-57..59;
        PDF pages 803-808, printed pages 4.3-330..335; source reference [10] 5.1.10.
        Core v6.3, Vol 6, Part B, 2.4.2.23 and 5.1.10; Vol 1, Part E, 2.4.1:
        a sender sets the unused Instant (RFU) to zero.
    """
    await _phy_update(tester, central=True, local=False)


async def handling_protocol_collision_same_procedure_ll_con_cen_bv_45_c(tester):
    """Handling Protocol Collision – Same Procedure.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The connection starts on LE 1M.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0, TX_PHYS=RX_PHYS preferring a PHY
           other than LE 1M, and PHY_options=0x0000. Receive HCI_Command_Status.
           This procedure chooses LE 2M.
        2. Receive LL_PHY_REQ with at least one supported PHY bit in each field.
           If the IUT sends no request, end with Inconclusive.
        3. Respond with the Lower Tester's own LL_PHY_REQ, preferring a non-1M
           PHY in both directions. Inject this request in the immediate
           acknowledgement of the IUT request, before completing its procedure.
        4. Require LL_REJECT_EXT_IND rejecting the Lower Tester's LL_PHY_REQ,
           with reason code 0x23 (LL Procedure Collision).
        5. Answer the retained IUT request with LL_PHY_RSP preferring a non-1M
           PHY in both directions. Receive LL_PHY_UPDATE_IND with zero or one
           bit per field, each nonzero choice permitted by the directional
           request and response. Require a valid Instant for a nonzero choice.
           If both fields are zero, end with Inconclusive.
        6. Maintain the connection with empty DATA on the old PHYs until the
           event counter reaches the indicated Instant.
        7. At the Instant, use the PHY selected by each nonzero UPDATE field;
           retain the previous PHY for each zero field.
        8. Start maintaining the connection on those PHYs at the Instant.
        9. Receive and acknowledge the IUT's empty DATA packets on those PHYs.
        10. Require LE_PHY_Update_Complete reporting success, the active
            connection handle and the effective selected PHYs.

    Expected Outcome:
        Pass verdict:
            The original local procedure survives the collision. Each nonzero
            UPDATE field selects a common directional PHY. A zero is permitted
            if no common PHY exists, the current PHY is common, or the response
            specifies the same single PHY in both directions and both UPDATE
            fields are zero. A change uses a valid Instant; the Host receives
            the selected PHYs in LE_PHY_Update_Complete, including a no-change
            completion where applicable. No completion belongs to the rejected
            remote request.
        Inconclusive verdict:
            No LL_PHY_REQ is initiated in Step 2, or no PHY change is selected
            in Step 5. The latter ends the procedure before Steps 6-10.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-45-C; Figure 4.3-167;
        PDF pages 808-810, printed pages 4.3-335..337; source reference [10] 5.3.
    """
    await _central_collision(tester, procedure='phy')


async def protocol_timeout_for_phy_update_procedure_ll_con_cen_bv_46_c(tester):
    """Protocol Timeout for PHY Update Procedure.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The connection starts on LE 1M.

    Test Steps:
        1. Send HCI_LE_Set_PHY with TX_PHYS and RX_PHYS preferring a non-1M PHY
           and PHY_options=0x0000, and receive HCI_Command_Status. This
           procedure requests LE 2M in both directions with ALL_PHYS=0.
        2. Receive the IUT's LL_PHY_REQ with at least one supported PHY bit in
           each field. If no request is sent, end with Inconclusive.
        3. Acknowledge LL_PHY_REQ but do not send LL_PHY_RSP. Continue valid
           empty DATA on the old PHY throughout the procedure-response timer
           so that supervision timeout does not replace the intended outcome.
        4. The IUT may send HCI_LE_PHY_Update_Complete with a nonzero status.
           Reject any successful PHY completion for the incomplete procedure.
        5. Require HCI_Disconnection_Complete with success, the active handle
           and reason 0x22 (LL Response Timeout) when the transaction timer
           expires. Verify that the IUT stops maintaining the connection.

    Expected Outcome:
        Pass verdict:
            The IUT disconnects with reason 0x22 at procedure-response timeout
            and ceases RF connection maintenance. Any optional Step 4 PHY
            completion has a nonzero status and the active connection handle.
        Inconclusive verdict:
            The IUT does not initiate LL_PHY_REQ in Step 2.

    Observation Boundary:
        Bracket internal procedure initiation between the triggering HCI command
        and the first transmitted LL_PHY_REQ; do not restart the timer on its
        acknowledgement. Sample HCI delivery at 1 ms resolution around that
        bracket plus the 40 s response timeout. This is the test's observation
        policy, not a numeric timing tolerance specified by Core 5.2.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-46-C; Figure 4.3-168;
        PDF pages 810-811, printed pages 4.3-337..338; source reference [10] 5.2.
    """
    await _phy_timeout(tester, central=True, local=True)


async def handling_protocol_collision_different_procedure_channel_map_cen_bv_47(
    tester,
):
    """Handling Protocol Collision – Different Procedure – Channel Map.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The connection starts on LE 1M.

    Test Steps:
        1. Send HCI_LE_Set_Host_Channel_Classification specifying only even
           data channels.
        2. If the command succeeds, require HCI_Command_Complete with status
           0x00. Otherwise retry with different Channel_Map values, maintaining
           at least 5 seconds between attempts. After 20 failures, end with
           Inconclusive; stop retrying as soon as a command succeeds.
        3. Receive LL_CHANNEL_MAP_IND containing the accepted map from Step 1.
           Its absence after a successful command is a failure, not Inconclusive.
        4. Respond with LL_PHY_REQ preferring a PHY other than LE 1M in both
           directions. This procedure selects LE 2M and injects the request in
           the immediate acknowledgement of LL_CHANNEL_MAP_IND.
        5. Require LL_REJECT_EXT_IND rejecting LL_PHY_REQ with reason 0x2A
           (Different Transaction Collision).
        6. Maintain the connection with empty DATA until the event counter
           reaches the Channel Map Update Instant. Continue DATA using the
           updated map at and after that Instant; confirm it with HCI Read
           Channel Map.

    Expected Outcome:
        Pass verdict:
            The IUT transmits the required LL_CHANNEL_MAP_IND, rejects the
            competing PHY request, and maintains the connection with the new
            data-channel selection parameters after the assigned event.
            The rejected PHY request must not produce a PHY completion.
        Inconclusive verdict:
            HCI_LE_Set_Host_Channel_Classification fails on all 20 attempts.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-47-C; Figure 4.3-169;
        PDF pages 812-813, printed pages 4.3-339..340; source reference [10] 5.3.
    """
    await _central_collision(tester, procedure='map')


async def handling_connection_parameter_collision_cen_bv_48(
    tester,
):
    """Handling Protocol Collision – Different Procedure – Connection Parameters.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The connection starts on LE 1M.
        Declare the Lower Tester's Connection Parameters Request Procedure support
        through Feature Exchange so the IUT uses LL_CONNECTION_PARAM_REQ.

    Test Steps:
        1. Send HCI_LE_Connection_Update requesting the minimum connection
           interval (7.5 ms), zero latency and a 3 s supervision timeout.
           Receive HCI_Command_Status.
        2. Receive LL_CONNECTION_PARAM_REQ; its parameters may differ from the
           Host's requested values. Validate its fields and respond with
           LL_PHY_REQ preferring a non-1M PHY in both directions. This procedure
           chooses LE 2M and sends that request in the immediate acknowledgement
           of LL_CONNECTION_PARAM_REQ.
        3. Require LL_REJECT_EXT_IND rejecting LL_PHY_REQ with reason 0x2A
           (Different Transaction Collision).
        4. Answer the retained LL_CONNECTION_PARAM_REQ with
           LL_CONNECTION_PARAM_RSP and receive LL_CONNECTION_UPDATE_IND.
           This response proposes the minimum interval, zero latency and 3 s
           timeout; check the indication's legal parameters and transmit window.
        5. Maintain the connection with empty DATA until the event counter
           reaches the indicated connection update Instant.
        6. At that Instant, use the new parameters selected by the IUT.
        7. Start maintaining the connection with those parameters at the update,
           allowing the Central's first anchor anywhere inside the transmit window.
        8. Require HCI_LE_Connection_Update_Complete with success, the active
           handle and the new interval, latency and supervision timeout.
           Reject an early successful completion before the Instant.

    Expected Outcome:
        Pass verdict:
            The IUT sends LL_CONNECTION_PARAM_REQ, rejects the competing PHY
            request, maintains the connection with the selected new parameters
            and reports them in HCI_LE_Connection_Update_Complete.
            The rejected PHY request must not produce a PHY completion.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-48-C; Figure 4.3-170;
        PDF pages 813-815, printed pages 4.3-340..342; source reference [10] 5.3.
    """
    await _central_collision(tester, procedure='parameters')


async def initiating_phy_update_procedure_packet_time_restrictions_ll_con_cen_bv_49_c(
    tester,
):
    """Initiating PHY Update Procedure – Packet Time Restrictions.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. This procedure uses a 60 ms
        connection interval and begins on LE 1M.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0x03 and receive HCI_Command_Status.
        2. Require HCI_LE_PHY_Update_Complete reporting LE 1M in both directions.
           If LE 1M/LE 1M is not selected, end with Inconclusive.
        3. Send HCI_LE_Set_PHY with ALL_PHYS=0, TX_PHYS=RX_PHYS=0x02 and receive
           HCI_Command_Status.
        4. Receive LL_PHY_REQ and answer with LL_PHY_RSP having TX_PHYS and
           RX_PHYS both 0x02.
        5. Receive LL_PHY_UPDATE_IND selecting LE 2M in both directions.
           Otherwise end with Inconclusive. Maintain old PHYs until the Instant
           and then exchange DATA on LE 2M.
        6. Require HCI_LE_PHY_Update_Complete reporting LE 2M/LE 2M.
        7. Send HCI_LE_Set_Data_Length with TxTime=0x0148 (328 us) and
           TxOctets=32. Receive HCI_Command_Complete.
        8. If the IUT initiates Data Length Update, answer with RxTime=0x0148
           and RxOctets=32. Otherwise initiate it with those receive limits and
           receive the IUT's response. If IUT TxTime<0x0148 or TxOctets<32,
           end with Inconclusive.
        9. Begin continuously queueing 32-octet Host data packets with LLID=0b10
           (start). Keep queueing for the remainder, respecting HCI credits.
        10. Receive byte-identical, unfragmented packets matching the queued data.
            Fragmentation before the PHY restriction boundary is Inconclusive.
        11. Send HCI_LE_Set_PHY with ALL_PHYS=0 and TX_PHYS=RX_PHYS=0x01.
        12. Receive LL_PHY_REQ and answer with LL_PHY_RSP having TX_PHYS and
            RX_PHYS both 0x01.
        13. Receive LL_PHY_UPDATE_IND selecting LE 1M in both directions.
            Otherwise end with Inconclusive.
        14. Require every DATA payload received after that indication to contain
            at most 31 octets. Observe packets both before and after the PHY
            update; do not defer this restriction until the Instant.
        15. Continue the PHY Update with the Host still queueing 32-octet start
            packets and the Lower Tester receiving and reassembling DATA.
        16. At the indicated Instant, switch connection maintenance to LE 1M.
        17. Require HCI_LE_PHY_Update_Complete reporting LE 1M/LE 1M, success
            and the active connection handle, with no early completion.
        18. Continue queueing and receiving DATA of at most 31 octets for at
            least 10 connection events after the Instant.

    Expected Outcome:
        Pass verdict:
            Before Step 13's indication, DATA is 32 octets and unfragmented.
            Afterwards DATA is at most 31 octets, including before the Instant.
            The PHY changes to LE 1M at the Instant. Every received payload and
            its airtime remain within effective receive octet/time limits.
            For the first two packets after each Data Length Update, including
            retransmissions, the applicable limits are the greater of old and
            new limits. This setup increases the initial limits to 32/328, so
            the same maximum applies during and after that allowance.
            Reassembled bytes, start/continuation boundaries and HCI credits
            match the continuously submitted Host packets.
        Inconclusive verdict:
            Required LE 1M setup or LE 2M setup is not selected, the IUT's DLE
            transmit limits are too small, pre-indication DATA is fragmented,
            or the final update does not select LE 1M in both directions.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-49-C; Figures 4.3-171 and 4.3-172;
        PDF pages 815-819, printed pages 4.3-342..346; source reference [10] 5.1.10.1.
    """
    await _packet_time_restrictions(
        tester, central=True, local=True, coded=False, no_change=False
    )


async def responding_to_phy_update_packet_time_limits_cen_bv_50(
    tester,
):
    """Responding to PHY Update Procedure – Packet Time Restrictions.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. This procedure uses a 60 ms
        connection interval and begins on LE 1M.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0, TX_PHYS=RX_PHYS=0x02 and receive
           HCI_Command_Status.
        2. Receive LL_PHY_REQ and answer with LL_PHY_RSP having TX_PHYS and
           RX_PHYS both 0x02.
        3. Receive LL_PHY_UPDATE_IND selecting LE 2M in both directions.
           Otherwise end with Inconclusive. Maintain old PHYs until the Instant
           and then exchange DATA on LE 2M.
        4. Require HCI_LE_PHY_Update_Complete reporting LE 2M/LE 2M.
        5. Send HCI_LE_Set_Data_Length with TxTime=0x0148 (328 us) and
           TxOctets=32. Receive HCI_Command_Complete.
        6. If the IUT initiates Data Length Update, answer with RxTime=0x0148
           and RxOctets=32. Otherwise initiate it with those receive limits and
           receive the IUT's response. If IUT TxTime<0x0148 or TxOctets<32,
           end with Inconclusive.
        7. Begin continuously queueing 32-octet Host data packets with LLID=0b10
           (start). Keep queueing for the remainder, respecting HCI credits.
        8. Receive byte-identical, unfragmented packets matching the queued data.
           Fragmentation before the PHY restriction boundary is Inconclusive.
        9. Send HCI_LE_Set_PHY with ALL_PHYS=0x03 and receive HCI_Command_Status.
           If the IUT initiates LL_PHY_REQ, answer with LL_PHY_RSP specifying
           the current PHY in both directions and receive its no-change UPDATE.
        10. Require HCI_LE_PHY_Update_Complete reporting LE 2M/LE 2M, success
            and the active connection handle.
        11. Send LL_PHY_REQ with TX_PHYS=RX_PHYS=0x01.
        12. Receive LL_PHY_UPDATE_IND selecting LE 1M in both directions.
            Otherwise end with Inconclusive.
        13. Require every DATA payload received after that indication to contain
            at most 31 octets. Observe packets both before and after the PHY
            update; do not defer this restriction until the Instant.
        14. Continue the PHY Update with the Host still queueing 32-octet start
            packets and the Lower Tester receiving and reassembling DATA.
        15. At the indicated Instant, switch connection maintenance to LE 1M.
        16. Require HCI_LE_PHY_Update_Complete reporting LE 1M/LE 1M, success
            and the active connection handle, with no early completion.
        17. Continue queueing and receiving DATA of at most 31 octets for at
            least 10 connection events after the Instant.

    Expected Outcome:
        Pass verdict:
            Before Step 12's indication, DATA is 32 octets and unfragmented.
            Afterwards DATA is at most 31 octets, including before the Instant.
            The PHY changes to LE 1M at the Instant. Every received payload and
            its airtime remain within effective receive octet/time limits.
            For the first two packets after each Data Length Update, including
            retransmissions, the applicable limits are the greater of old and
            new limits. This setup increases the initial limits to 32/328, so
            the same maximum applies during and after that allowance.
            Reassembled bytes, start/continuation boundaries and HCI credits
            match the continuously submitted Host packets.
        Inconclusive verdict:
            LE 2M setup is not selected, the IUT's DLE transmit limits are too
            small, pre-indication DATA is fragmented, or the final update does
            not select LE 1M in both directions.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-50-C; Figures 4.3-173 and 4.3-174;
        PDF pages 819-823, printed pages 4.3-346..350; source reference [10] 5.1.10.1.
    """
    await _packet_time_restrictions(
        tester, central=True, local=False, coded=False, no_change=False
    )


async def initiating_phy_update_procedure_no_common_phy(tester):
    """Initiating PHY Update Procedure – No Common PHY.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The connection starts on LE 1M;
        the IUT also supports LE 2M.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0, TX_PHYS=RX_PHYS preferring one
           supported non-1M PHY, and PHY_options=0x0000. Receive successful
           HCI_Command_Status. This procedure selects LE 2M.
        2. Receive LL_PHY_REQ with at least one supported bit in each field.
           If the IUT sends no request, end with Inconclusive.
        3. Acknowledge LL_PHY_REQ and send LL_PHY_RSP. Select each corresponding
           directional field independently:
           a. If the request field has exactly one bit, choose a different bit
              that corresponds to a PHY supported by the IUT.
           b. If the request field has multiple bits, choose the current PHY.
           Map the IUT's TX preference to the Lower Tester's RX field and the
           IUT's RX preference to the Lower Tester's TX field.
        4. Receive LL_PHY_UPDATE_IND with PHY_C_TO_P=PHY_P_TO_C=0 and Instant=0.
           Continue DATA on the unchanged LE 1M PHYs.
        5. Require LE_PHY_Update_Complete reporting success, the active handle
           and the previous PHYs in both directions, with no duplicate completion.

    Expected Outcome:
        Pass verdict:
            Both UPDATE PHY fields and the Instant are zero. The IUT reports
            the previous PHYs in a successful no-change completion and continues
            to exchange DATA without changing the PHY.
        Inconclusive verdict:
            The IUT does not send LL_PHY_REQ in Step 2.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-51-C; Figure 4.3-175;
        PDF pages 823-824, printed pages 4.3-350..351; source reference [10] 5.1.10.
    """
    await _no_common_phy(tester, asymmetric=False)


async def central_receiving_data_le_coded_ci_change(tester):
    """Central Receiving Data, LE Coded, CI Change.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window, maximum supported connection
        interval, common Peripheral latency and supervision timeout. This
        procedure uses a 4 s interval, zero latency and a 32 s supervision timeout.
        Retain the established connection handle and negotiated data lengths.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0, TX_PHYS=RX_PHYS preferring
           LE Coded, and PHY_options=0x0000. Receive HCI_Command_Status.
        2. Receive LL_PHY_REQ and answer with LL_PHY_RSP specifying LE Coded
           in both TX_PHYS and RX_PHYS.
        3. Receive LL_PHY_UPDATE_IND selecting LE Coded for both directions.
           Otherwise end with Inconclusive. Maintain the old PHYs until the
           Instant, then maintain the connection using LE Coded.
        4. Require HCI_LE_PHY_Update_Complete reporting success, the active
           handle and LE Coded in both directions.
        5. If TSPX_TxOctets_Max>27 or TSPX_TxTime_Max>328 us, send
           HCI_LE_Set_Data_Length with those transmit maxima and receive
           HCI_Command_Complete. Otherwise go to Step 7.
        6. If the IUT initiates Data Length Update, answer with the Lower
           Tester's TxOctets=TSPX_RxOctets_Max and TxTime=TSPX_RxTime_Max.
           Otherwise initiate Data Length Update with those transmit values
           and receive the IUT's response. Validate the negotiated fields
           and effective-length HCI changes.
        7. Configure 288 DATA packets at the Lower Tester's effective maximum
           transmit size, equal to the IUT's effective receive-octet limit.
           Payload octets increment continuously across packets, starting at
           0x00 and wrapping after 0xFF. Use every CI value in the source's
           18-row, 16-value-per-row S=2/S=8 sequence, in the original order.
        8. Send the DATA packets using the acknowledgement scheme and active
           channel selection. Require an empty IUT DATA acknowledgement for
           each packet, with positive NESN transition and T_IFS=150 +/-2 us.
        9. Receive the corresponding HCI ACL data with the active handle,
           correct boundary flags and exact incrementing payload. Continue
           Steps 7-9 until all 288 packets have been acknowledged and reported.
        10. Repeat the data exchange once using 27-octet packets rather than
            the effective maximum. Repeat the entire 288-value coding sequence,
            restarting the payload at 0x00, and apply every RF/HCI check again.

    Expected Outcome:
        Pass verdict:
            Both payload-size rounds complete. Every DATA packet is acknowledged
            within 150 +/-2 us and all incrementing payload bytes reach the Host
            correctly, without duplicates. MD permits the full coding sequence
            within the connection event; acknowledgements are not deferred to
            the next 4 s event.
        Inconclusive verdict:
            The IUT does not select LE Coded in both directions in Step 3.

    Source Correction:
        Step 10 refers recursively to Steps 7-10. Repeat the data-exchange body
        (Steps 7-9) once at the minimum payload size, not the repetition
        instruction itself. The stated maximum/minimum test purpose and Amber
        corroborate this local editorial interpretation; it is not a SIG erratum.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-52-C; Figure 4.3-176 and Step 7 coding table;
        PDF pages 825-828, printed pages 4.3-352..355; source reference [10] 4.5.
    """
    await _coded_reception(tester, central=True)


async def initiating_phy_update_packet_time_limits_le_coded_cen_bv_53(
    tester,
):
    """Initiating PHY Update Procedure – Packet Time Restrictions, LE Coded.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. This procedure uses a 60 ms
        interval and starts on LE 1M.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0x03 and PHY_options=0x0000;
           receive HCI_Command_Status.
        2. Require HCI_LE_PHY_Update_Complete reporting LE 1M in both directions.
           If LE 1M/LE 1M is not selected, end with Inconclusive.
        3. Send HCI_LE_Set_Data_Length with TxTime=0x04D8 (1240 us) and
           TxOctets=141; receive HCI_Command_Complete.
        4. If the IUT initiates Data Length Update, answer with RxTime=0x04D8
           and RxOctets=141. Otherwise initiate it with those receive limits
           and receive the IUT's response. If IUT TxTime<0x04D8 or
           TxOctets<141, end with Inconclusive.
        5. Begin continuously queueing 141-octet Host packets with LLID=0b10
           (start); keep queueing for the remainder, respecting HCI credits.
        6. Receive unfragmented packets matching the queued Host data.
           Pre-indication fragmentation is Inconclusive.
        7. Send HCI_LE_Set_PHY with ALL_PHYS=0, PHY_options=0x0000 and
           TX_PHYS=RX_PHYS preferring LE Coded.
        8. Receive LL_PHY_REQ and answer with LL_PHY_RSP having TX_PHYS and
           RX_PHYS both 0x04.
        9. Receive LL_PHY_UPDATE_IND selecting LE Coded in both directions.
           Otherwise end with Inconclusive.
        10. Require every DATA payload after that indication to be at most
            140 octets. A larger payload fails, including before the Instant.
            Observe DATA both before and after PHY Update.
        11. Continue PHY Update with the Host still queueing 141-octet start
            packets and the Lower Tester receiving DATA.
        12. At the indicated Instant, switch connection maintenance to LE Coded.
        13. Require HCI_LE_PHY_Update_Complete reporting LE Coded/LE Coded,
            success and the active handle, with no early completion.
        14. Continue queueing and receiving DATA of at most 140 octets for at
            least 10 connection events after the Instant.

    Expected Outcome:
        Pass verdict:
            Before Step 9's indication, DATA is 141 octets and unfragmented;
            afterwards every DATA payload is at most 140 octets. PHYs change
            only at the Instant. Payload size and airtime obey effective
            receive-octet/time limits. For the first two packets after Data
            Length Update, including retransmissions, use the greater of old
            and new limits; the initial increase makes this the new limit.
            Reassembled Host bytes, fragment boundaries and HCI credits match.
        Inconclusive verdict:
            LE 1M setup is not selected, DLE transmit limits are too small,
            pre-indication DATA is fragmented, LE Coded is not selected in
            both directions, or the IUT autonomously sends LL_LENGTH_REQ after
            the Instant in Step 9.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-53-C; Figures 4.3-177 and 4.3-178;
        PDF pages 828-832, printed pages 4.3-355..359; source reference [10] 5.1.10.1.
    """
    await _packet_time_restrictions(
        tester, central=True, local=True, coded=True, no_change=False
    )


async def responding_to_phy_update_packet_time_limits_le_coded_cen_bv_54(
    tester,
):
    """Responding to PHY Update Procedure – Packet Time Restrictions, LE Coded.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. This procedure uses a 60 ms
        interval and starts on LE 1M.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0x03 and PHY_options=0x0000;
           receive HCI_Command_Status.
        2. Require HCI_LE_PHY_Update_Complete reporting LE 1M in both directions.
           If LE 1M/LE 1M is not selected, end with Inconclusive.
        3. Send HCI_LE_Set_Data_Length with TxTime=0x04D8 (1240 us) and
           TxOctets=141; receive HCI_Command_Complete.
        4. If the IUT initiates Data Length Update, answer with RxTime=0x04D8
           and RxOctets=141. Otherwise initiate it with those receive limits
           and receive the IUT's response. If IUT TxTime<0x04D8 or
           TxOctets<141, end with Inconclusive.
        5. Begin continuously queueing 141-octet Host packets with LLID=0b10
           (start); keep queueing for the remainder, respecting HCI credits.
        6. Receive unfragmented packets matching the Host data. Apply the
           source's explicit pre-indication fragmentation Inconclusive verdict;
           see Source Correction.
        7. Send LL_PHY_REQ with TX_PHYS and RX_PHYS both 0x04.
        8. Receive LL_PHY_UPDATE_IND selecting LE Coded in both directions.
           Otherwise end with Inconclusive.
        9. Require every DATA payload after Step 8's indication to be at most
           140 octets. A larger payload fails, including before the Instant.
           Observe DATA both before and after PHY Update.
        10. Continue PHY Update with the Host still queueing 141-octet start
            packets and the Lower Tester receiving DATA.
        11. At the indicated Instant, switch connection maintenance to LE Coded.
        12. Require HCI_LE_PHY_Update_Complete reporting LE Coded/LE Coded,
            success and the active handle, with no early completion.
        13. Continue queueing and receiving DATA of at most 140 octets for at
            least 10 connection events after the Instant.

    Expected Outcome:
        Pass verdict:
            Before Step 8's indication, DATA is 141 octets and unfragmented;
            afterwards every DATA payload is at most 140 octets. PHYs change
            only at the Instant. Payload size and airtime obey effective
            receive-octet/time limits. For the first two packets after Data
            Length Update, including retransmissions, use the greater of old
            and new limits; the initial increase makes this the new limit.
            Reassembled Host bytes, fragment boundaries and HCI credits match.
        Inconclusive verdict:
            LE 1M setup is not selected, DLE transmit limits are too small,
            pre-indication DATA is fragmented, or LE Coded is not selected
            in both directions.

    Source Correction:
        Step 6 says fragmentation is Fail, but the explicit Inconclusive list
        names the same pre-indication fragmentation. Use that explicit verdict.
        Step 9 refers to an UPDATE in Step 13, which contains post-Instant
        DATA; the actual UPDATE is in Step 8. Apply the 140-octet restriction
        immediately after Step 8. Amber corroborated these local editorial
        interpretations from the supplied source text; neither is a SIG erratum.

    Coverage Note:
        Unlike BV-53, this source does not authorize Inconclusive for an
        autonomous LL_LENGTH_REQ after the Instant. Answer such requests with
        the unchanged Lower Tester limits and independently check effective
        length events, RF payload length/airtime, reassembly and HCI credits.
        The greater old/new limits apply to the first two DATA packets after
        DLE; the separate 140-octet post-indication restriction remains active.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-54-C; Figures 4.3-179 and 4.3-180;
        PDF pages 832-835, printed pages 4.3-359..362; source reference [10] 5.1.10.1.
    """
    await _packet_time_restrictions(
        tester, central=True, local=False, coded=True, no_change=False
    )


async def mandatory_minimum_pdu_length_le_coded_ll_con_cen_bv_55_c(tester):
    """Mandatory Minimum PDU Length, LE Coded.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The source inherits the
        PER/BV-57-C procedure except for its stated Step 6 replacement.

    Test Steps:
        The following records every inherited step and the Central override.
        It is not an executable Central adaptation: see Source Conflict.

        1. Send HCI_LE_Set_PHY with ALL_PHYS=0x03, PHY_options=0x0000 and
           receive HCI_Command_Status.
        2. Inherited PER step: the IUT may send LL_PHY_REQ; the Lower Tester
           answers with LL_PHY_UPDATE_IND having both directional fields zero.
           That Lower Tester action is not valid for its stated Peripheral role.
        3. Require HCI_LE_PHY_Update_Complete reporting LE 1M/LE 1M.
        4. If the IUT initiates Data Length Update, answer with RxTime=328 us
           and RxOctets=27.
        5. Continuously queue 27-octet Host start packets for the remainder.
        6. Central override: the Lower Tester receives LL_PHY_UPDATE_IND
           selecting LE Coded in both directions; otherwise Inconclusive.
           This replaces PER Step 6's HCI Set PHY trigger without defining
           how that trigger or the later inherited request fits this step.
        7. Inherited PER step: the IUT sends LL_PHY_REQ to the Lower Tester.
        8. Inherited PER alternatives, neither resolved for a Peripheral tester:
           8A. If the request permits Coded in both directions:
               8A.1. The Lower Tester sends an UPDATE selecting Coded, with
                     modular Instant distance greater than 6 and less than 32767.
           8B. Otherwise:
               8B.1. Send an UPDATE retaining the current PHYs.
               8B.2. Send LL_PHY_REQ requesting Coded in both directions.
               8B.3. Receive LL_PHY_RSP; if Coded cannot be selected in both
                     directions, end with Inconclusive.
               8B.4. Send a Coded UPDATE with the same Instant constraints.
        9. Expect received DATA payloads of at most 27 octets.
        10. Complete PHY Update while the Host continues queueing 27-octet
            start packets and the Lower Tester receives DATA.
        11. Maintain the connection on LE Coded at the indicated Instant.
        12. Require PHY completion reporting Coded/Coded. If DLE is supported,
            require Data Length Change with both octet limits 27 and both time
            limits 2704 us; the two events may arrive in either order.
        13. Continue DATA of at most 27 octets for at least 10 further events.
        14. Repeat Steps 6-13 for LE 1M instead of Coded, changing the requested
            PHY bit from 0x04 to 0x01 and the reported time limits to 328 us.

    Expected Outcome:
        Pass verdict:
            Inherited requirements: DATA stays within 27 octets and effective
            receive-octet/time limits, the indicated PHY applies at each Instant,
            and Data Length Change reports the expected values. For the first
            two packets after DLE, including retransmissions, use the greater
            of old/new octet and time limits.
            No pass is claimed until the Central-role sequence is resolved.
        Inconclusive verdict:
            Inherited Step 8B.3 cannot select the required PHY, or an autonomous
            LL_LENGTH_REQ follows the Instant; the Central override also
            specifies Inconclusive if its Step 6 does not select Coded.

    Source Conflict:
        PDF 837 replaces inherited Step 6, but does not consistently adapt
        Steps 2, 7 or 8 to a Central IUT and Peripheral Lower Tester.
        Figure 4.3-182 also shows the IUT sending PHY_RSP and the Lower Tester
        sending UPDATE, which are Peripheral/Central actions respectively,
        despite the stated opposite roles. Purpose and inherited HCI trigger
        additionally disagree about which side initiates.
        Core PHY Update assigns PHY_RSP to the Peripheral and UPDATE to the
        Central. Amber could not resolve a unique intended Central sequence.
        Do not silently retain the previous Host-initiated interpretation;
        skip this case pending an authoritative clarification.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-55-C, Figures 4.3-181/182;
        PDF pages 836-837, printed pages 4.3-363..364.
        Inherited LL/CON/PER/BV-57-C, Figures 4.3-97/98, Steps 1-14 and verdicts;
        PDF pages 685-689, printed pages 4.3-212..216.
        Core v6.3, Vol 6, Part B, 5.1.10; Vol 6, Part D, 6.15.
    """
    pytest.skip(
        'Source conflict: CEN BV-55 Central override, inherited PER steps and '
        'Figure 4.3-182 do not define a consistent role/initiation sequence '
        '(LL.TS.p28 PDF 836-837; inherited PDF 685-689)'
    )


async def central_data_length_update_responding_to_data_length_update_procedure(
    tester, *, phy
):
    """Central Data Length Update – Responding to Data Length Update Procedure.

    Initial Condition:
        Connected Central with declared supported TX/RX octet and time maxima
        within Core Vol 6, Part B, Table 4.6. This implementation uses the IUT's
        HCI Read Maximum Data Length values as IXIT inputs and reads HCI buffer
        capacity for Host fragmentation and credits.
        The full-feature IUT supports Coded: specification minima are 27 octets
        and 328 us, maxima are 251 octets and 17040 us. The Lower Tester also
        declares these protocol maxima. Its random interior values therefore
        cannot equal its declared maxima.
        Start on LE 1M with public peer addresses; use 30 ms intervals on 1M/2M
        and 60 ms on Coded to accommodate bidirectional maximum-size packets.

    Test Case Configuration:
        LL/CON/CEN/BV-73-C: LE 1M.
        LL/CON/CEN/BV-76-C: LE 2M.
        LL/CON/CEN/BV-78-C: LE Coded.

    Test Steps:
        1. Select the alternative from Table 4.3-60:
           1A.1. LE 1M: proceed directly to Step 2.
           1B.1. LE 2M: send HCI_LE_Set_PHY with ALL_PHYS=0 and both PHY masks
                 0x02. Complete PHY Update and require PHY Update Complete.
                 If both directions are not LE 2M, end with Inconclusive.
           1C.1. LE Coded: perform the same exchange with both masks 0x04.
                 If both directions are not LE Coded, end with Inconclusive.
           Repeat Steps 2-9 for every Table 4.3-61 round. Identical-valued
           rounds may be omitted; this implementation retains all 16.
        2. Send LL_LENGTH_REQ with the current table row's payload. Preserve
           the source's TX/RX meanings when encoding the RX-first wire fields.
           Rows 1-12 use the exact minima, maxima and declared-IUT combinations.
           For rows 13-16, choose each TX/RX octet/time value independently
           inside its allowed range and unequal to the tester's declared
           maxima. If no eligible value exists, use round 1's value; the
           declared full-range tester always has eligible interior values.
        3. Receive LL_LENGTH_RSP. Require all four IUT TX/RX octet/time values
           between their specification minima and declared supported maxima.
        4. Derive the four effective TX/RX limits from the observed request,
           response and active PHYs. Require HCI_LE_Data_Length_Change with
           the new values only if an effective limit changed; otherwise
           require no event. The source allows unknown prior limits in the
           first round; this controlled setup starts with known minimum limits.
        5. Submit data in the minimum number of HCI ACL packets allowed by the
           HCI transmit buffer size. If multiple packets are needed, submit
           them together after one connection event and before the next opens.
        6. Receive DATA until all Host data is transmitted. For each packet,
           check payload length <= effective TX octets and actual airtime
           <= effective TX time.
        7. Verify that all Lower Tester data matches the Host bytes in Step 5,
           including fragment boundaries and the completed HCI packet credits.
        8. Send at least 20 DATA packets to the IUT. Each payload uses the
           smaller of effective RX octets and the largest payload fitting the
           effective RX time on the selected PHY.
        9. Receive the corresponding HCI ACL data and verify that the complete
           payload and boundaries match Step 8.
        10. If the IUT supports Coded, repeat Steps 2-9 for every maximum-time
            round, replacing the maximum time values with 2128 us.

    Expected Outcome:
        Pass verdict:
            Every exercised request receives LL_LENGTH_RSP. HCI reports exact
            changed effective limits and no event when none changed. DATA
            delivered to either tester matches the submitted data and obeys
            the directional octet/time limits.
        Inconclusive verdict:
            The Step 1B.1 or 1C.1 PHY selection cannot be established.

    Reference:
        LL.TS.p28.pdf, Section 4.3.6.2; LL/CON/CEN/BV-73-C, BV-76-C and BV-78-C;
        Table 4.3-60, Figure 4.3-183, Table 4.3-61;
        PDF pages 837-841, printed pages 4.3-364..368;
        source references [8] 5.1.9 and [10] 4.5.10.
    """
    await _data_length(tester, central=True, local=False, phy=phy)


async def central_data_length_update_initiating_data_length_update_procedure(
    tester, *, phy
):
    """Central Data Length Update – Initiating Data Length Update Procedure.

    Initial Condition:
        Connected Central with declared supported TX/RX octet and time maxima
        within Core Vol 6, Part B, Table 4.6. This implementation uses the IUT's
        HCI Read Maximum Data Length values as IXIT inputs and reads HCI buffer
        capacity for Host fragmentation and credits.
        The full-feature IUT supports Coded: specification minima are 27 octets
        and 328 us, maxima are 251 octets and 17040 us.
        Start on LE 1M with public peer addresses; use 30 ms intervals on 1M/2M
        and 60 ms on Coded to accommodate bidirectional maximum-size packets.

    Test Case Configuration:
        LL/CON/CEN/BV-74-C: LE 1M.
        LL/CON/CEN/BV-77-C: LE 2M.
        LL/CON/CEN/BV-79-C: LE Coded.

    Test Steps:
        1. Select the alternative from Table 4.3-62:
           1A.1. LE 1M: proceed directly to Step 2.
           1B.1. LE 2M: send HCI_LE_Set_PHY with ALL_PHYS=0 and both PHY masks
                 0x02. Complete PHY Update and require PHY Update Complete.
                 If both directions are not LE 2M, end with Inconclusive.
           1C.1. LE Coded: perform the same exchange with both masks 0x04.
                 If both directions are not LE Coded, end with Inconclusive.
        2. Repeat Steps 3-11 for each of the 15 Table 4.3-63 rows. Identical
           rows may be omitted; this implementation retains every row.
        3. Send HCI_LE_Set_Data_Length with the row's TxOctets and TxTime.
           The table covers supported/minimum/maximum octets at each supported,
           minimum, maximum, 2120 us and 2128 us time value.
        4. Receive LL_LENGTH_REQ. Require each IUT TX/RX octet/time value
           between its specification minimum and declared supported maximum.
           If no request is sent, proceed to the next table round.
        5. Answer with LL_LENGTH_RSP whose two octet fields are specification
           minima and whose two time fields are specification minima.
        6. Require HCI_LE_Data_Length_Change with the new effective values if
           any effective limit changed; otherwise require no event. The first
           round may have unknown prior limits; this setup starts with known
           minima. Accept the source's possible two events when an autonomous
           local change and the peer response each change effective limits.
        7. Submit data in the minimum number of HCI ACL packets allowed by the
           HCI transmit buffer size. If multiple packets are needed, submit
           them together after one connection event and before the next opens.
        8. Receive DATA until all Host data is transmitted. Check every payload
           against effective TX octets and its airtime against effective TX time.
        9. Verify exact bytes, fragment boundaries and HCI credits for all
           data received by the Lower Tester.
        10. Send at least 20 DATA packets to the IUT. Each payload uses the
            smaller of effective RX octets and the largest payload fitting the
            effective RX time on the selected PHY.
        11. Receive HCI ACL data and verify that all bytes and boundaries match
            the data sent in Step 10.
        12. Repeat Steps 3-11, answering Step 5 with specification maximum
            octets and times in both directions instead of the minima.

    Expected Outcome:
        Pass verdict:
            The IUT initiates at least one LL_LENGTH_REQ. Every exercised row
            produces the required changed-limit HCI events, with exact values
            and no unchanged-limit event. Bidirectional DATA matches the
            submitted bytes and respects effective octet/time limits.
        Inconclusive verdict:
            No LL_LENGTH_REQ is initiated during the entire matrix, or the
            Step 1B.1/1C.1 PHY selection cannot be established. An omitted
            request in one row alone is not a whole-test Inconclusive verdict.

    Reference:
        LL.TS.p28.pdf, Section 4.3.6.3; LL/CON/CEN/BV-74-C, BV-77-C and BV-79-C;
        Table 4.3-62, Figure 4.3-184, Table 4.3-63;
        PDF pages 842-845, printed pages 4.3-369..372;
        source references [8] 5.1.9 and [10] 4.5.10.
    """
    await _data_length(tester, central=True, local=True, phy=phy)


async def central_data_length_update_peripheral_does_not_support_le_1m_phy(tester):
    """Central Data Length Update – Peripheral does not support; LE 1M PHY.

    Initial Condition:
        Connected Central on LE 1M, with public peer addresses and declared
        supported TX/RX octet/time maxima within Core Table 4.6. Use the IUT's
        HCI Read Maximum Data Length values as this implementation's IXIT inputs.
        Specification minima are 27 octets and 328 us; this Coded-capable IUT
        has specification maxima 251 octets and 17040 us.
        Read HCI buffer size and credits; do not disclose unsupported DLE
        through Feature Exchange before attempting the procedure.

    Test Steps:
        1. Repeat Step 2 until LL_LENGTH_REQ is received from the IUT or
           20 attempts have completed. With no request after 20 attempts,
           end with Inconclusive.
        2. Send HCI_LE_Set_Data_Length:
           a. First attempt: supportedMaxTxOctetsIUT and supportedMaxTxTimeIUT.
           b. Second attempt: min(specification minimum octets + 1, supported
              TX octets) and min(specification minimum time + 1, supported
              TX time).
           c. Remaining attempts: independently seeded random octets and time
              between the specification minimum and IUT supported TX maximum,
              inclusive.
        3. Validate LL_LENGTH_REQ: all four IUT TX/RX octet/time fields lie
           between their specification minima and declared supported maxima.
        4. Send LL_UNKNOWN_RSP with UnknownType identifying LL_LENGTH_REQ.
        5. Submit data in the minimum number of HCI ACL packets allowed by the
           HCI transmit buffer size. If several packets are needed, send them
           together after one connection event and before the next opens.
        6. Receive DATA until the entire Host payload has arrived. Each packet
           must respect the unchanged effective TX octet and airtime limits.
        7. Check that all Lower Tester bytes and fragment boundaries match the
           Host submission in Step 5; verify all HCI packet credits.
        8. Send at least 20 DATA packets, each using the smaller of effective
           RX octets and the largest payload fitting effective RX time on 1M.
        9. Receive HCI ACL data and verify that all bytes and boundaries match
           the Lower Tester's packets in Step 8.

    Expected Outcome:
        Pass verdict:
            The IUT sends LL_LENGTH_REQ and continues bidirectional data flow
            within the pre-existing effective length limits after UNKNOWN_RSP.
            Payloads and HCI credits match the submitted data.
        Fail verdict:
            HCI_LE_Data_Length_Change is sent during the unsupported procedure
            or subsequent data transfer.
        Inconclusive verdict:
            No LL_LENGTH_REQ is initiated during all 20 HCI attempts.

    Source Correction:
        Step 1's phrase "receives an LL_LENGTH_REQ from the PDU" means receiving
        that PDU from the IUT, as Step 3 explicitly states. This is a local
        grammatical correction with no change to the procedure.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-75-C; Figure 4.3-185, Steps 1-9 and verdicts;
        PDF pages 846-848, printed pages 4.3-373..375; source reference [8] 5.1.9.
    """
    await _unsupported_peer(tester, central=True, phy=Phy.LE_1M)


async def central_data_length_update_peripheral_does_not_support_le_coded_phy(tester):
    """Central Data Length Update – Peripheral does not support; LE Coded PHY.

    Initial Condition:
        Inherit the connected-Central conditions and declared supported TX/RX
        octet/time maxima of BV-75. Use public peer addresses, HCI maximum-length
        inputs and HCI transmit buffer capacity. Specification minima are
        27 octets and 328 us; maxima are 251 octets and 17040 us.
        Use a 60 ms interval for Coded traffic. Do not disclose unsupported
        DLE through Feature Exchange before attempting the procedure.

    Preamble:
        Before inherited Step 1, send HCI_LE_Set_PHY with ALL_PHYS=0 and both
        TX_PHYS and RX_PHYS=0x04. Complete PHY Update and require
        HCI_LE_PHY_Update_Complete reporting LE Coded in both directions;
        otherwise Inconclusive. Consume any minimum-time Data Length Change
        caused by this PHY setup before checking the unsupported-DLE procedure.

    Test Steps:
        Retain the inherited BV-75 numbering after the Coded preamble.

        1. Repeat Step 2 until LL_LENGTH_REQ is received from the IUT or
           20 attempts have completed. With no request, end with Inconclusive.
        2. Send HCI_LE_Set_Data_Length:
           a. First attempt: the IUT's declared supported TX octets and time.
           b. Second attempt: the smaller of minimum octets + 1 and supported
              TX octets, and the smaller of minimum time + 1 and supported TX
              time.
           c. Remaining attempts: independently seeded random octets and time
              within specification-minimum through supported-maximum bounds,
              inclusive.
        3. Validate all four LL_LENGTH_REQ fields against specification minima
           and the IUT's declared supported TX/RX maxima.
        4. Send LL_UNKNOWN_RSP with UnknownType identifying LL_LENGTH_REQ.
        5. Submit data in the minimum number of HCI ACL packets allowed by the
           HCI transmit buffer size, together between connection events when
           multiple packets are needed.
        6. Receive all Host DATA and enforce the unchanged effective TX octet
           and airtime limits, including Coded's mandatory minimum time.
        7. Verify exact Host bytes, fragment boundaries and HCI packet credits.
        8. Send at least 20 DATA packets at the smaller of effective RX octets
           and the maximum payload fitting effective RX time on Coded.
        9. Require matching HCI ACL payloads and boundary flags for all data.

    Expected Outcome:
        Pass verdict:
            The IUT sends LL_LENGTH_REQ and continues bidirectional data flow
            within the existing effective length limits after UNKNOWN_RSP.
            Payloads and HCI credits match the submitted data.
        Fail verdict:
            HCI_LE_Data_Length_Change is sent during the unsupported-DLE
            procedure or subsequent data transfer, after the PHY preamble.
        Inconclusive verdict:
            No request is initiated during 20 attempts, or both directions
            cannot be established on LE Coded during the preamble.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-80-C; Figure 4.3-186 and Coded preamble;
        PDF pages 849-850, printed pages 4.3-376..377.
        Inherited BV-75 Steps 1-9 and verdicts, PDF 846-848, printed 4.3-373..375.
    """
    await _unsupported_peer(tester, central=True, phy=Phy.LE_CODED)


async def initiating_parameter_request_unsupported_without_feature_exchange_cen_bv_81(
    tester,
):
    """Initiating Connection Parameter Request – Unsupported Without Feature Exchange.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window, common Peripheral latency and
        supervision timeout. No Feature Exchange has disclosed peer support.

    Test Steps:
        1. If the IUT autonomously starts Feature Exchange before Step 3, end
           with Inconclusive, including a request received during setup.
        2. Send HCI_LE_Connection_Update requesting the minimum connection
           interval, zero latency and a 3 s supervision timeout. Receive
           successful HCI_Command_Status.
        3. Receive LL_CONNECTION_PARAM_REQ. Its legal parameters may differ
           from the Host request. Answer LL_UNKNOWN_RSP whose UnknownType
           identifies LL_CONNECTION_PARAM_REQ (0x0F).
        4. Receive LL_CONNECTION_UPDATE_IND. Validate its actual window,
           interval, latency and timeout; these may differ from the Host inputs.
        5. Maintain the connection with empty DATA on the old parameters until
           the event counter reaches the indication's Instant.
        6. At that Instant, maintain the connection using the newly selected
           parameters, allowing the first Central anchor within the transmit
           window.
        7. Require HCI_LE_Connection_Update_Complete with success, the active
           handle and the actual new interval, latency and supervision timeout.
           Reject a successful completion before the Instant.
        8. Repeat Steps 2 and 4-7 using Host parameters different from the first
           iteration. This implementation requests interval 15 ms and timeout
           4 s rather than 7.5 ms and 3 s. Any LL_CONNECTION_PARAM_REQ in this
           iteration fails; require the direct UPDATE_IND path and matching
           HCI completion.

    Expected Outcome:
        Pass verdict:
            The first update uses PARAM_REQ, UNKNOWN_RSP and UPDATE_IND, then
            reports the actual selected parameters. The second update omits
            PARAM_REQ and directly indicates its new parameters. Continued
            DATA and HCI agree with the selected parameters in each iteration.
        Inconclusive verdict:
            The IUT autonomously performs Feature Exchange before Step 3.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-81-C; Figure 4.3-187;
        PDF pages 850-852, printed pages 4.3-377..379; source reference [8] 5.1.7.
        Autonomous Feature Exchange: Section 4.1.6.7.4.
    """
    await _unsupported_parameters(tester, central=True, features=False)


async def initiating_parameter_request_unsupported_with_feature_exchange_cen_bv_82(
    tester,
):
    """Initiating Connection Parameter Request – Unsupported With Feature Exchange.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window, common Peripheral latency and
        supervision timeout.

    Test Steps:
        1. Initiate Feature Exchange through the Upper Tester unless the IUT
           has already initiated it. The Lower Tester reports no Connection
           Parameter Request support.
           If an autonomous FEATURE_REQ was received during setup, answer that
           request and finish its exchange rather than waiting for a second
           request. Otherwise issue HCI Read Remote Features, answer FEATURE_REQ
           with a zero peer feature set, and verify its matching HCI completion.
        2. Send HCI_LE_Connection_Update requesting the minimum connection
           interval, zero latency and a 3 s supervision timeout. Receive
           successful HCI_Command_Status.
        3. Receive LL_CONNECTION_UPDATE_IND. Its actual parameters may differ
           from the Host inputs; validate their legal ranges and transmit
           window. LL_CONNECTION_PARAM_REQ instead of UPDATE_IND fails.
        4. Maintain the connection with empty DATA on the old parameters until
           the event counter reaches the indication's Instant.
        5. At that Instant, use the newly selected parameters, allowing the
           first Central anchor within the transmit window.
        6. Require HCI_LE_Connection_Update_Complete with success, the active
           handle and the actual selected interval, latency and supervision
           timeout. Reject a successful completion before the Instant.

    Expected Outcome:
        Pass verdict:
            The IUT sends UPDATE_IND without PARAM_REQ and reports the selected
            new parameters in Connection Update Complete. Subsequent DATA uses
            the same interval and connection parameters; no duplicate completion
            is accepted.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-82-C; Figure 4.3-188;
        PDF pages 852-853, printed pages 4.3-379..380; source reference [8] 5.1.7.
    """
    await _unsupported_parameters(tester, central=True, features=True)


async def phy_update_procedure_central_requests_asymmetrical_peripheral_symmetrical(
    tester,
):
    """PHY Update Procedure – Central Requests Asymmetrical, Peripheral Symmetrical.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. All communication uses LE 1M.

    Test Steps:
        1. Send HCI_LE_Set_PHY with ALL_PHYS=0x00, TX_PHYS=0x01 and
           RX_PHYS=0x02.
        2. Receive successful HCI_Command_Status.
        3. Receive the IUT's LL_PHY_REQ with TX_PHYS=0x01 and RX_PHYS=0x02.
           If no request is sent or either field differs, end with Inconclusive.
        4. Answer LL_PHY_RSP with TX_PHYS=RX_PHYS=0x02, expressing the
           Peripheral's symmetric-only LE 2M preference.
        5. Require LL_PHY_UPDATE_IND with PHY_C_TO_P=PHY_P_TO_C=0, indicating
           no change. Require the unused Instant field to be zero.
        6. Require LE_PHY_Update_Complete reporting success, the active handle
           and unchanged LE 1M in both directions. Continue old-PHY DATA and
           reject duplicate completions.

    Expected Outcome:
        Pass verdict:
            The IUT sends the all-zero no-change UPDATE and reports unchanged
            PHYs. It must not independently change only the direction whose
            masks intersect: the Peripheral's same-single-PHY response requires
            symmetric selection or no change under Core 5.1.10.
        Inconclusive verdict:
            The IUT sends no LL_PHY_REQ or does not send TX_PHYS=0x01 and
            RX_PHYS=0x02 in Step 3.

    Source Correction:
        Step 4 writes TX_PHY twice. The second field is RX_PHYS, so both
        LL_PHY_RSP fields are 0x02. Amber corroborated the field correction.
        A follow-up retrieved Core 6.3 Vol 6 B 5.1.10's specific symmetric
        Peripheral preference rule, confirming that the generic directional
        intersection alone cannot justify a one-direction change here.
        This is a local editorial correction, not a SIG erratum.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-117-C; Figure 4.3-189, Steps 1-6 and verdicts;
        PDF pages 854-855, printed pages 4.3-381..382; source reference [10] 5.1.10.
        Core v6.3, Vol 6, Part B, 5.1.10 and 2.4.2.23.
    """
    await _no_common_phy(tester, asymmetric=True)


async def central_t_terminate_timer(tester):
    """Central T_Terminate Timer.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window, common connection timing and
        Peripheral latency. Use the common 10 ms interval, zero latency and
        300 ms supervision timeout; retain the established connection handle.

    Test Steps:
        1. Send HCI_Disconnect for the saved handle and require successful
           HCI_Command_Status.
        2. Receive LL_TERMINATE_IND. Continue valid Peripheral transmissions,
           but set NESN so that the termination PDU is not acknowledged.
        3. Require retransmissions of the same control PDU, payload and SN.
           Respond with empty DATA without acknowledging termination, continuing
           until T_Terminate expires. Follow the IUT's NESN for fresh Peripheral
           DATA so normal supervision is refreshed independently.
        4. Require HCI_Disconnection_Complete with success, the active handle
           and reason 0x16 (Connection Terminated by Local Host) or 0x22
           (LL Response Timeout). Verify that connection RF maintenance stops.

    Expected Outcome:
        Pass verdict:
            The IUT continues sending the same TERMINATE_IND until its
            termination timer expires, then reports termination through HCI.
            Valid non-acknowledging DATA does not restart T_Terminate.

    Observation Boundary:
        Core 5.1.6 starts T_Terminate when TERMINATE_IND is queued and sets it
        to connSupervisionTimeout. Bracket that internal queueing between the
        Host trigger and first observed TERMINATE_IND transmission, not peer
        acknowledgement. Check HCI around that bracket plus 300 ms at 1 ms
        sampling resolution; this is a test observation bound, not Core tolerance.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BI-02-C; Figure 4.3-190, Steps 1-4 and verdict;
        PDF pages 855-856, printed pages 4.3-382..383; source reference [3] 5.1.6.
        Common timing: Section 4.3.2.1, PDF 476, printed 4.3-3.
        Core v6.3, Vol 6, Part B, 5.1.6 and 4.5.2.
    """
    await _timeouts_termination(tester, central=True)


async def central_connection_control_timer(tester):
    """Central Connection Control Timer.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window, common connection timing and
        Peripheral latency. Use the common 10 ms interval, zero latency and
        300 ms supervision timeout; retain the established connection handle.

    Test Steps:
        1. If the IUT autonomously sent LL_VERSION_IND after connection setup,
           acknowledge that indication. Continue Peripheral DATA but never send
           the Lower Tester's VERSION_IND; proceed directly to Step 4.
        2. Otherwise send HCI_Read_Remote_Version_Information for the saved
           handle and receive successful HCI_Command_Status.
        3. Receive the IUT's LL_VERSION_IND and positively acknowledge it.
           Do not send a peer VERSION_IND.
        4. Continue empty Peripheral DATA until the connection control timeout
           or the disconnection in Step 5. Reject additional VERSION_IND after
           its acknowledgement and reject premature procedure completion.
        5. Require HCI_Disconnection_Complete for the active handle with
           success and reason 0x22 (LL Response Timeout). Verify RF maintenance
           stops. Any preceding Host-requested Version Complete must carry
           the timeout status and handle; no such event belongs to an autonomous
           exchange or may follow disconnection.

    Expected Outcome:
        Pass verdict:
            The IUT recovers from the stalled control procedure by terminating
            the connection at its 40 s procedure response timeout, not through
            supervision expiry while valid DATA is still received.

    Source Correction:
        The purpose calls the IUT a Peripheral and says its request is not
        acknowledged. The title, initial condition and Steps 1/3 instead specify
        a Central IUT and explicit acknowledgement by the Lower Tester.
        Follow those numbered steps: omit the peer's protocol response, not
        the Link Layer ACK. Core 5.1.5/5.2 and Amber corroborate this distinction.
        This is a local editorial correction, not an adopted SIG erratum.

    Observation Boundary:
        Bracket procedure initiation from the Host trigger to first VERSION_IND
        transmission. For an autonomous request, the lower bound is connection
        setup start, not its later RF timestamp. Observe HCI with a 1 ms bound,
        including a sample immediately before the earliest permitted expiry;
        never treat HCI response time or RF transmission as the exact queue time.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BI-04-C; Figure 4.3-191, Steps 1-5 and verdict;
        PDF pages 856-858, printed pages 4.3-383..385; source reference [3] 5.2.
        Common timing: Section 4.3.2.1, PDF 476, printed 4.3-3.
        Core v6.3, Vol 6, Part B, 5.1.5 and 5.2.
    """
    await _version_timeout(tester, central=True)


async def initiating_connection_parameter_request_timeout_ll_con_cen_bi_05_c(tester):
    """Initiating Connection Parameter Request – Timeout.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. The Lower Tester declares
        Connection Parameter Request support through Feature Exchange so the
        IUT uses that procedure rather than a legacy direct update.

    Test Steps:
        1. Send HCI_LE_Connection_Update requesting the minimum connection
           interval (7.5 ms), zero latency and a 3 s supervision timeout.
           Receive successful HCI_Command_Status.
        2. Receive LL_CONNECTION_PARAM_REQ. Its legal parameters may differ
           from the Host request. Acknowledge the request, but send no
           LL_CONNECTION_PARAM_RSP. Continue valid empty DATA on the old
           parameters so supervision does not replace the intended timeout.
        3. Require HCI_Disconnection_Complete with success, the active handle
           and reason 0x22 (LL Response Timeout) when the control transaction
           timer expires. Verify that connection RF maintenance stops.

    Expected Outcome:
        Pass verdict:
            The connection ends through procedure-response timeout with reason
            0x22, not an early success or supervision timeout, and the IUT stops
            maintaining the link. Any optional pending procedure completion must
            report its timeout failure before disconnection, never after it.

    Observation Boundary:
        Bracket internal procedure initiation between the triggering HCI command
        and the first observed PARAM_REQ. Observe the 40 s timer around that
        bracket at 1 ms HCI resolution; this is a test-system bound, not a
        normative extra tolerance.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BI-05-C; Figure 4.3-192, Steps 1-3 and verdict;
        PDF pages 858-859, printed pages 4.3-385..386; source reference [3] 5.1.7.
        Core v6.3, Vol 6, Part B, 5.2.
    """
    await _procedure_timeout(tester, central=True, parameters=True)


async def accepting_connection_parameter_request_illegal_parameters_ll_con_cen_bi_06_c(
    tester,
):
    """Accepting Connection Parameter Request – illegal parameters.

    Initial Condition:
        Connected Central with a public Lower Tester peer address, supported own
        address type, any scan interval/window and connection interval, common
        Peripheral latency and supervision timeout. Leave the remote-parameter
        Host event enabled so masking cannot explain the rejection.

    Test Steps:
        1. Send LL_CONNECTION_PARAM_REQ with Interval_Min=Interval_Max=4,
           below the valid minimum value 6. This encodes 5 ms.
        2. Require LL_REJECT_EXT_IND identifying LL_CONNECTION_PARAM_REQ with
           ErrorCode=0x1E (Invalid LL Parameters).

    Expected Outcome:
        Pass verdict:
            The IUT rejects the invalid request with the correct opcode and
            reason. It does not delegate the invalid request to the Host or
            report a successful update. Continue DATA on the old parameters
            before disconnecting.

    Source Correction:
        Step 1 labels the encoded interval 4 as 6 ms. Core interval units are
        1.25 ms, so the value means 5 ms; retain the prescribed wire value 4.
        Amber corroborated the unit calculation. No SIG erratum is claimed.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BI-06-C; Figure 4.3-193, Steps 1-2 and verdict;
        PDF pages 859-860, printed pages 4.3-386..387; source reference [3] 5.1.7.
        Core v6.3, Vol 6, Part B, 2.4.2.16.
    """
    await _remote_parameters(
        tester, central=True, reject=False, masked=False, invalid=True
    )


async def invalid_llid_ll_con_cen_bi_14_c(tester):
    """Invalid LLID.

    Initial Condition:
        Connected Central with a Peripheral Lower Tester, public peer address,
        supported own address type, any scan interval/window and connection
        interval, common Peripheral latency and supervision timeout.
        Use a fresh ACL without prior Feature Exchange and select
        TSPX_pdu_with_response=LL_FEATURE_REQ for this IUT.

    Test Steps:
        1. Send HCI LE Read Remote Features for the active handle and require
           successful HCI_Command_Status.
        2. Receive LL_FEATURE_REQ with valid LLID and FeatureSet.
        3. Send LL_FEATURE_RSP with reserved LLID=0b00 and a valid zero
           FeatureSet.
        4. Require acknowledgement of that packet after at most four retries;
           fail if its NESN acknowledgement is not received.
        5. For the four simulated seconds after Step 3, require no HCI LE
           Read Remote Features Complete. Continue valid empty DATA and
           ensure the invalid control payload is not delivered as Host ACL.
        6. Send the same LL_FEATURE_RSP payload with valid LLID=0b11.
        7. Require HCI LE Read Remote Features Complete with success, the
           active handle and the exact valid FeatureSet from Step 6.

    Test Condition:
        If the IUT has already exchanged features and does not generate
        FEATURE_REQ in Step 2, the source permits a different supported
        request/response PDU and its corresponding Host command/completion.
        This configuration selects the fresh-ACL Feature Exchange path; it
        does not substitute another control procedure.

    Expected Outcome:
        Pass verdict:
            No feature completion occurs in Step 5; Step 7 reports success
            and the supplied FeatureSet only after the correctly typed PDU.
        Fail verdict:
            The reserved-LLID packet is not acknowledged in Step 4, or its
            payload is processed as a control response or Host data.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BI-14-C; Figure 4.3-206, Steps 1-7,
        Test Condition and verdicts; PDF pages 885-886, printed 4.3-412..413;
        source reference [8] 2.4. The source's HCI Page 0 names use the
        equivalent existing HCI_LE_Read_Remote_Features API here.
    """
    await _invalid_control_invalid_llid(tester, central=True)


async def data_length_update_preserve_parameters_after_a_phy_change(
    tester, *, central, phy
):
    """Data Length Update – Preserve Parameters After a PHY Change.

    Initial Condition:
        Connected on LE 1M in the selected role, with supported TX octets/time
        declared within Core limits. Read HCI maximum data lengths as this IUT's
        IXIT inputs. Use public peer addresses and a 60 ms connection interval.
        The Lower Tester advertises unchanged protocol-maximum DLE values.

    Test Case Configuration:
        LL/CON/CEN/BV-126-C: Central, LE 2M.
        LL/CON/CEN/BV-127-C: Central, LE Coded.
        LL/CON/PER/BV-129-C: Peripheral, LE 2M.
        LL/CON/PER/BV-130-C: Peripheral, LE Coded.

    Test Steps:
        1. Send HCI_LE_Set_Data_Length with the supported maximum TX octets
           and time. Require successful HCI_Command_Complete.
        2. The IUT may send LL_LENGTH_REQ.
        3. If received, answer LL_LENGTH_RSP. Keep the Lower Tester's maximum
           RX/TX octet/time fields fixed throughout the test.
        4. Receive Data Length Change for the initiated update and record
           all four reported effective octet/time values.
        5. If no update was initiated, repeat Steps 1-4 once with integer
           intermediate values:
           TxTime = floor((supportedMaxTxTime - 328) / 2) + 328;
           TxOctets = floor((supportedMaxTxOctets - 27) / 2) + 27.
           If the second attempt also produces no update, end Inconclusive.
        6. Send HCI_LE_Set_PHY requesting the selected PHY in both directions
           and require successful HCI_Command_Status.
        7. Require PHY Update Complete with both directions changed to the
           selected PHY. If either direction did not change, end Inconclusive.
        8. Reject a Data Length Change unless the selected PHY is Coded and
           the only difference is an effective TX time, RX time or both rising
           to 2704 us. Octet limits must remain unchanged by the PHY change.
        9. The IUT may optionally initiate another Data Length Update:
           a. Receive its LL_LENGTH_REQ and validate all four fields.
           b. Answer LL_LENGTH_RSP with the Lower Tester's current fixed values.
           c. Require Data Length Change if and only if these fields change
              an effective octet/time limit. Retain newly negotiated values
              as the baseline for subsequent PHY-only preservation.
        10. Send HCI_LE_Set_PHY requesting LE 1M in both directions and require
            successful HCI_Command_Status.
        11. Require PHY Update Complete with both directions changed to LE 1M;
            otherwise end Inconclusive.
        12. Reject a Data Length Change unless returning from Coded removes
            its mandatory time floor, restoring the corresponding recorded
            uncoded times. See Source Correction and Source Conflict below.
        13. The IUT may optionally perform Data Length Update again:
            a. Receive LL_LENGTH_REQ.
            b. Answer LL_LENGTH_RSP with the same current Lower Tester values.
            c. Require Data Length Change exactly when effective values change.

    Expected Outcome:
        Pass verdict:
            A PHY-only transition preserves the negotiated octet/time parameters.
            The only permitted effective-length event at Step 8 is a Coded
            time-floor increase; Step 12 may undo that floor when returning
            from Coded. Optional DLE changes report correct effective values.
        Fail verdict:
            A PHY transition reports a length change outside those exceptions.
        Inconclusive verdict:
            Neither maximum nor intermediate HCI request initiates DLE, or
            the required transmit/receive PHY change cannot be established.

    Source Correction:
        Step 12 and its verdict refer to Coded in Step 10, but Step 10 always
        requests LE 1M. Interpret this as returning from the earlier Coded
        selection in Step 6. Core 4.5.10 and Amber corroborate that removing
        the Coded time floor, not resetting negotiated state, is intended.
        This is a local reference correction, not a SIG erratum.

    Source Conflict:
        Step 9 can renegotiate the underlying times. If those times fall below
        2704 us and differ from Step 4, Core preserves the new negotiation on
        returning to 1M, but Step 12 literally names the old Step 4 values.
        Amber confirms the Core behavior but cannot uniquely resolve that
        wider TS implication. Skip that specific path with an explicit source
        conflict rather than failing a Core-correct IUT or inventing a verdict.

    Coverage Note:
        Observe every received PDU throughout PHY preparation, Instant handling
        and the subsequent observation events. Answer autonomous LENGTH_REQs
        with unchanged Lower Tester limits and retain each negotiated baseline.
        Check the exact ordered HCI length changes, including PHY-only Coded
        time-floor transitions. Only the source_conflict label above remains unresolved.

    Reference:
        LL.TS.p28.pdf, Section 4.3.7.33; Table 4.3-114, Figure 4.3-242,
        Steps 1-13 and verdicts; PDF 973-976, printed 4.3-500..503.
        Core v6.3, Vol 6, Part B, 5.1.9 and 4.5.10.
    """
    supported = await _supported_lengths(tester)
    link = await establish(
        tester,
        central=central,
        interval=48,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    dut, original = await _negotiate_maximum(tester, link, supported)
    observer = _LengthObserver(tester, link, dut, MAXIMUM, supported)
    link.on_receive = observer.receive
    for target in (phy, Phy.LE_1M):
        await _change_phy(tester, link, target, local=True)
        for _ in range(CONTROL_OBSERVATION_EVENTS):
            await link.exchange()
            await tester.wait(0)
            observer.check()
        observer.check(final=True)
        preserved = (*observer.dut[2:], *observer.dut[:2])
        if target == Phy.LE_CODED and any(
            value < PDU_DATA_PAYLOAD_TIME_CODED_MIN_US and value != initial
            for value, initial in zip(preserved[1::2], original[1::2])
        ):
            pytest.skip(
                'Source conflict: Step 9 changes the uncoded time baseline, '
                'but Step 12 refers back to Step 4; Core preserves the new '
                'DLE parameters (LL.TS.p28 PDF 975)'
            )
    link.on_receive = None
    await link.disconnect(local=True)


async def data_length_update_retransmission_during_an_update(tester, *, central):
    """Data Length Update – Retransmission During an Update.

    Initial Condition:
        Connected in the selected role. The supported maximum TX octets and
        time are declared as IXIT values within Core limits. Read this IUT's
        HCI maximum data lengths as those inputs. Establish LE 1M with a public
        peer. The minimum octet and time limits used here are 27 and 328 us.

    Test Case Configuration:
        LL/CON/CEN/BV-128-C: Central.
        LL/CON/PER/BV-131-C: Peripheral.

    Test Steps:
        1. Send HCI_LE_Set_Data_Length with supportedMaxTxOctets and
           supportedMaxTxTime. Require successful HCI_Command_Complete.
        2. The IUT may send LL_LENGTH_REQ with new values.
        3. If received, answer LL_LENGTH_RSP accepting the requested values
           and record the IUT's MaxTxOctets.
        4. If the IUT initiated the update, require Data Length Change
           reporting the changed effective values.
        5. Otherwise repeat Steps 1-4 once with integer intermediate values:
           TxTime = floor((supportedMaxTxTime - 328) / 2) + 328;
           TxOctets = floor((supportedMaxTxOctets - 27) / 2) + 27.
           If neither attempt initiates DLE, end Inconclusive.
        6. Send a stream of Host ACL packets, each supportedMaxTxOctets long.
        7. Receive DATA with the negotiated IUT MaxTxOctets length.
        8. Withhold the acknowledgement of one received DATA packet.
        9. Immediately send LL_LENGTH_REQ using the minimum octet and time
           limits in all four RX/TX fields, while retaining the negative ACK.
        10. After five connection intervals, receive the retransmitted DATA.
            Require its original MaxTxOctets length and unchanged payload.

    Expected Outcome:
        Pass verdict:
            After five connection intervals, the original DATA packet is
            retransmitted without refragmentation at its original size.
        Inconclusive verdict:
            Neither HCI data-length request initiates Data Length Update.

    Coverage Note:
        Queue two Host ACL packets to supply the stream. Retain the IUT SN,
        LLID, payload and length through all five retransmission intervals,
        with no premature Host completion credit. Independently preserve the
        Lower Tester's own SN/ACK state; an unacknowledged LENGTH_REQ must not
        become an empty DATA packet under the same SN.
        Compare connection-event anchors, not Peripheral response start times:
        a longer Central request legitimately shifts the response by its extra
        airtime. After the source verdict, acknowledge the held packet, finish
        DLE, check remaining fragmentation and exact bytes under the reduced
        limits, require two Host completion credits, and disconnect via HCI.

    Reference:
        LL.TS.p28.pdf, Section 4.3.7.34; Table 4.3-115, Figure 4.3-243,
        Steps 1-10 and verdicts; PDF 976-978, printed 4.3-503..505.
        Source references [8] 5.1.9 and [10] 4.5.10.
    """
    supported = await _supported_lengths(tester)
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    _, original_limits = await _negotiate_maximum(tester, link, supported)
    payload = random.Random(0).randbytes(supported[2])
    await tester.wait(0)
    for _ in range(2):
        tester.send(
            bytes(
                hci.HCI_AclDataPacket(
                    link.handle,
                    hci.HCI_ACL_PB_FIRST_NON_FLUSHABLE,
                    0,
                    len(payload),
                    payload,
                )
            )
        )
    held_sn, peer_sn = (link.nesn, link.sn)
    request = bytes([Opcode.LL_LENGTH_REQ]) + LENGTH_FIELDS.pack(*MINIMUM)
    channel = link.channel

    def first_reply(packet):
        nonlocal peer_sn
        if central:
            peer_sn = _sequence_bits(packet)[1]
            return _data_pdu(peer_sn, held_sn, request, llid=LlId.CONTROL)
        return _data_pdu(peer_sn, held_sn)

    first, first_sent = await _wire_event(link, first_reply)
    assert first.pdu[0] & PDU_DATA_LLID_MASK == LlId.START
    assert first.pdu[1] == original_limits[0]
    assert first.pdu[PDU_HEADER_SIZE:] == payload[: original_limits[0]]
    origin = first.start_us
    if not central:
        origin -= link.tx_phy.airtime_us(len(first_sent)) + LL_IFS_US
    if not central:
        peer_sn = _sequence_bits(first)[1]
        await tester.transmit(
            channel,
            _data_pdu(peer_sn, held_sn, request, llid=LlId.CONTROL),
            start_us=first.end_us + LL_IFS_US,
            **link.radio_parameters,
        )
    for index in range(1, RETRANSMISSION_INTERVALS + 1):

        def refuse(packet, index=index):
            nonlocal peer_sn
            if central:
                assert _sequence_bits(packet)[1] == peer_sn ^ 1
                peer_sn ^= 1
            # A peer Central has not observed the immediate request's ACK yet.
            data = request if not central and index == 1 else b''
            return _data_pdu(
                peer_sn, held_sn, data, llid=LlId.CONTROL if data else LlId.CONTINUATION
            )

        packet, sent = await _wire_event(link, refuse)
        assert _sequence_bits(packet)[0] == held_sn
        if not central:
            assert _sequence_bits(packet)[1] == peer_sn ^ 1
            peer_sn ^= 1
        assert packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.START
        assert packet.pdu[1:] == first.pdu[1:]
        anchor = packet.start_us
        if not central:
            anchor -= link.tx_phy.airtime_us(len(sent)) + LL_IFS_US
        assert anchor - origin == (
            index * link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        )
        assert not any(
            isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
            for event in tester.events
        )

    def acknowledge(packet):
        nonlocal peer_sn
        if central:
            assert _sequence_bits(packet)[1] == peer_sn ^ 1
            peer_sn ^= 1
        return _data_pdu(peer_sn, held_sn ^ 1)

    packet, sent = await _wire_event(link, acknowledge)
    _restore_peer(link, packet, sent)
    if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
        response = packet.pdu[PDU_HEADER_SIZE:]
    else:
        response = await link.control(Opcode.LL_LENGTH_RSP)
    dut = _check_parameters(response, Opcode.LL_LENGTH_RSP, supported)
    first_fragment = await link.exchange()
    current = _effective_lengths(dut, MINIMUM, link)
    _check_changed_events(tester, link.handle, original_limits, current)
    remaining = payload[original_limits[0] :] + payload
    assert first_fragment.pdu[0] & PDU_DATA_LLID_MASK == (
        LlId.CONTINUATION if original_limits[0] < len(payload) else LlId.START
    )
    assert first_fragment.pdu[1] <= current[0]
    assert first_fragment.end_us - first_fragment.start_us <= current[1]
    received = first_fragment.pdu[PDU_HEADER_SIZE:]
    for _ in range(32):
        for packet in await _connection_event(link):
            assert packet.pdu[0] & PDU_DATA_LLID_MASK != LlId.CONTROL
            assert packet.pdu[1] <= current[0]
            assert packet.end_us - packet.start_us <= current[1]
            received += packet.pdu[PDU_HEADER_SIZE:]
        if received == remaining:
            break
    assert received == remaining
    await link.exchange()
    completed = [
        event
        for event in tester.events
        if isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
    ]
    assert all(event.connection_handles == [link.handle] for event in completed)
    assert sum(sum(event.num_completed_packets) for event in completed) == 2
    await link.disconnect(local=True)


async def data_length_update_peer_does_not_support_le_coded_phy(tester, *, central):
    """Data Length Update – Peer Does Not Support LE Coded PHY.

    Initial Condition:
        Connected in the selected role on LE 1M. The Lower Tester does not
        support LE Coded PHY. Use public peer addresses and supported maximum
        data lengths read through HCI as IXIT inputs. The specification minimum
        octet limit is 27; its maximum octet limit is 251. No Feature Exchange
        is initiated by the Lower Tester before the first length negotiation.

    Test Case Configuration:
        LL/CON/CEN/BV-129-C: Central.
        LL/CON/PER/BV-132-C: Peripheral.

    Test Steps:
        1. Send HCI_LE_Set_Data_Length with supportedMaxTxTime and TxOctets 27.
           Require successful HCI_Command_Complete.
        2. The IUT may issue LL_LENGTH_REQ; answer with LL_LENGTH_RSP.
        3. If the IUT initiated DLE and effective values changed, require Data
           Length Change. Otherwise require no such event.
        4. If no request was sent, repeat from Step 1 with TxOctets increased
           by 20, until the next value exceeds the specification maximum or
           ten rounds have run. If no request occurred, end Inconclusive.
        5. Send peer DATA packets at the size agreed by the length procedure.
        6. Require the IUT to forward those packets to the Upper Tester.
        7. For a Central IUT, execute Steps 9-12 and skip Steps 13-16.
        8. For a Peripheral IUT, skip Steps 9-12 and execute Steps 13-16.
        9. Send HCI LE Read Remote Features Page 0 for this connection and
           require successful Command Status.
        10. If the IUT previously sent LL_FEATURE_REQ, Steps 11-12 are optional.
        11. Receive LL_FEATURE_REQ from the Central IUT.
        12. Answer LL_FEATURE_RSP indicating no LE Coded PHY support.
        13. Send LL_FEATURE_REQ to the Peripheral IUT indicating no Coded PHY.
        14. Receive its LL_FEATURE_RSP.
        15. Send HCI LE Read Remote Features Page 0 for this connection and
            require successful Command Status.
        16. The Peripheral IUT may send LL_PERIPHERAL_FEATURE_REQ; if received,
            answer LL_FEATURE_RSP again indicating no LE Coded PHY support.
        17. Require successful Remote Features Page 0 Complete with this handle
            and no LE Coded PHY in the reported peer feature set.
        18. Send HCI_LE_Set_Data_Length with supportedMaxTxTime and TxOctets 27.
            Require successful HCI_Command_Complete.
        19. The IUT may issue LL_LENGTH_REQ. Fail if either RX or TX time exceeds
            2128 us. Answer LL_LENGTH_RSP.
        20. If the IUT initiated DLE in Step 19, require no Data Length Change;
            receipt of that event fails the test.
        21. If no request was sent, repeat from Step 18 with TxOctets increased
            by 20, stopping at the specification maximum or ten rounds. If no
            request occurred, conclude the test without Steps 22-23.
        22. Send peer DATA at the size agreed by the length procedure.
        23. Require those DATA packets at the Upper Tester.

    Expected Outcome:
        Pass verdict:
            The Step 19 RX/TX time fields are each at most 2128 us, the IUT
            reports no forbidden length change, and peer DATA reaches the Host.
            Step 21 also permits conclusion without another length request.
        Inconclusive verdict:
            No initial LL_LENGTH_REQ occurs before the Step 4 retry limit.

    Coverage Note:
        Execute the fresh connection's Central feature-request branch and both
        Peripheral paths, cached completion or optional on-air request. Use the
        existing HCI_LE_Read_Remote_Features command/event API for the source's
        Page 0 terminology. Keep peer length values fixed at 251 octets and
        2120 us per direction. Send two packets at each DATA checkpoint and
        verify exact bytes, handle and Host ACL flags, then disconnect via HCI.

    Reference:
        LL.TS.p28.pdf, Section 4.3.7.36; Table 4.3-118, Figures 4.3-245..246,
        all Steps 1-23 and verdicts; PDF 982-985, printed 4.3-509..512.
        Source references [8] 5.1.9 and [10] 4.5.10.
    """
    supported = await _supported_lengths(tester)
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    peer = (PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US) * 2
    previous = _effective_lengths(MINIMUM, MINIMUM, link)
    for feature_known in (False, True):
        packet = None
        for attempt in range(UNCODED_REQUEST_ATTEMPTS):
            octets = (
                PDU_DATA_PAYLOAD_SIZE_MIN + attempt * UNCODED_REQUEST_OCTET_INCREMENT
            )
            if octets > PDU_DATA_PAYLOAD_SIZE_MAX:
                break
            result = await tester.command(
                hci.HCI_LE_Set_Data_Length_Command(link.handle, octets, supported[3])
            )
            assert result.connection_handle == link.handle
            packet = await link.control(Opcode.LL_LENGTH_REQ, required=False)
            if packet is None:
                continue
            dut = _check_parameters(packet, Opcode.LL_LENGTH_REQ, supported)
            if feature_known:
                assert max(dut[1], dut[3]) <= DLE_CODED_TIME_BOUNDARY_US
            await link.exchange(
                bytes([Opcode.LL_LENGTH_RSP]) + LENGTH_FIELDS.pack(*peer),
                llid=LlId.CONTROL,
            )
            await tester.wait(0)
            current = _effective_lengths(dut, peer, link)
            if feature_known:
                assert current == previous
            _check_changed_events(tester, link.handle, previous, current)
            previous = current
            size = _payload_limit(link.tx_phy, current[2], current[3])
            for _ in range(2):
                await peer_send(tester, link, bytes(range(size)))
            break
        else:
            packet = None
        if packet is None and (not feature_known):
            pytest.skip('Inconclusive: no initial LL_LENGTH_REQ within ten rounds')
        if feature_known:
            break
        features = int(hci.LeFeatureMask.LE_DATA_PACKET_LENGTH_EXTENSION).to_bytes(
            PDU_CONTROL_FEATURE_SET_SIZE, 'little'
        )
        if not central:
            response = await link.control(
                Opcode.LL_FEATURE_RSP, bytes([Opcode.LL_FEATURE_REQ]) + features
            )
            assert len(response) == 1 + PDU_CONTROL_FEATURE_SET_SIZE
        await tester.command(hci.HCI_LE_Read_Remote_Features_Command(link.handle))
        if central:
            await link.control(Opcode.LL_FEATURE_REQ)
            await link.exchange(
                bytes([Opcode.LL_FEATURE_RSP]) + features, llid=LlId.CONTROL
            )
        else:
            for _ in range(16):
                if any(
                    isinstance(event, hci.HCI_LE_Read_Remote_Features_Complete_Event)
                    for event in tester.events
                ):
                    break
                packet = await link.exchange()
                if packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL:
                    payload = packet.pdu[PDU_HEADER_SIZE:]
                    assert payload[0] == Opcode.LL_PERIPHERAL_FEATURE_REQ
                    assert len(payload) == 1 + PDU_CONTROL_FEATURE_SET_SIZE
                    await link.exchange(
                        bytes([Opcode.LL_FEATURE_RSP]) + features, llid=LlId.CONTROL
                    )
        event = await tester.event(hci.HCI_LE_Read_Remote_Features_Complete_Event)
        assert (
            event.status == hci.HCI_ErrorCode.SUCCESS
            and event.connection_handle == link.handle
        )
        assert (
            not int.from_bytes(event.le_features, 'little')
            & hci.LeFeatureMask.LE_CODED_PHY
        )
    assert not any(
        isinstance(event, hci.HCI_LE_Data_Length_Change_Event)
        for event in tester.events
    )
    await link.disconnect(local=True)


async def peripheral_request_version(tester):
    """Peripheral Request Version.

    Initial Condition:
        Connected Peripheral, public address, arbitrary advertising interval,
        advertising channel map and SCA. Use the common connection interval,
        Peripheral latency, timeout and channel map.

    Test Steps:
        1. If the IUT initiates Version Exchange autonomously after connection,
           acknowledge its LL_VERSION_IND and send the Lower Tester's version.
        2. Otherwise send HCI_Read_Remote_Version_Information and require a
           successful Command Status event.
        3. Receive LL_VERSION_IND containing the IUT's version information.
        4. Acknowledge that indication and send the Lower Tester's version.
        5. For Host initiation, require Remote Version Information Complete
           containing the Lower Tester's version information.

    Expected Outcome:
        Pass verdict:
            The IUT initiates Version Exchange, reports its own version and
            acknowledges the peer's reply. When initiated by the Upper Tester,
            it reports the requested peer version in a successful HCI event.

    Coverage Note:
        Check the local version against Read Local Version Information and
        validate ACK sequence bits on the wire. The initial autonomous branch
        does not require an unsolicited Host completion. A finite observation
        budget bounds waiting for the indication; its exhaustion is diagnostic,
        not a normative response-time verdict.

    Reference:
        LL.TS.p28.pdf, LL/CON/PER/BV-19-C, Figure 4.3-61, Steps 1-5;
        PDF 613-614, printed 4.3-140..141. Source reference [3] 5.1.5.
    """
    await _exchange(tester, central=False, duplicates=False)


async def peripheral_respond_version(tester):
    """Peripheral Respond Version.

    Initial Condition:
        Connected Peripheral, public address, arbitrary advertising interval,
        advertising channel map and SCA. Use the common connection interval,
        Peripheral latency, timeout and channel map.

    Test Steps:
        1. Configure the Lower Tester to send LL_VERSION_IND.
        2. Send LL_VERSION_IND containing the Lower Tester's version.
        3. Require the IUT to acknowledge the indication and return its own
           LL_VERSION_IND containing the IUT's version information.

    Expected Outcome:
        Pass verdict:
            The IUT correctly responds to the peer's Version Exchange.
        Inconclusive verdict:
            The IUT sends LL_VERSION_IND before the Lower Tester does.

    Coverage Note:
        Check the local version against Read Local Version Information and
        validate ACK sequence bits. No Host version request or duplicate peer
        indication is injected. A finite observation budget bounds waiting for
        the response; exhaustion is diagnostic, not a timing failure.

    Reference:
        LL.TS.p28.pdf, LL/CON/PER/BV-20-C, Figure 4.3-62, Steps 1-3;
        PDF 614-615, printed 4.3-141..142. Source reference [3] 5.1.5.
    """
    await _exchange(tester, central=False, mode='responding', duplicates=False)


async def central_request_version(tester):
    """Central Request Version.

    Initial Condition:
        Connected Central, arbitrary scan interval and window, the Lower
        Tester's public peer address and a supported own address type.
        Use the common Peripheral latency and timeout with a legal connection
        interval.

    Test Steps:
        1. If the IUT initiates Version Exchange autonomously after connection,
           acknowledge its LL_VERSION_IND and send the Lower Tester's version.
        2. Otherwise send HCI_Read_Remote_Version_Information and require a
           successful Command Status event.
        3. Receive LL_VERSION_IND containing the IUT's version information.
        4. Acknowledge that indication and send the Lower Tester's version.
        5. For Host initiation, require Remote Version Information Complete
           containing the Lower Tester's version information.

    Expected Outcome:
        Pass verdict:
            The IUT initiates Version Exchange, reports its own version and
            acknowledges the peer's reply. When initiated by the Upper Tester,
            it reports the requested peer version in a successful HCI event.

    Coverage Note:
        Check the local version against Read Local Version Information and
        validate ACK sequence bits on the wire. The initial autonomous branch
        does not require an unsolicited Host completion. A finite observation
        budget bounds waiting for the indication; exhaustion is diagnostic,
        not a normative response-time verdict.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-20-C, Figure 4.3-149, Steps 1-5;
        PDF 771-772, printed 4.3-298..299. Source reference [3] 5.1.5.
    """
    await _exchange(tester, central=True, duplicates=False)


async def central_respond_version(tester):
    """Central Respond Version.

    Initial Condition:
        Connected Central, arbitrary scan interval and window, the Lower
        Tester's public peer address and a supported own address type.
        Use the common Peripheral latency and timeout with a legal connection
        interval.

    Test Steps:
        1. Configure the Lower Tester to send LL_VERSION_IND.
        2. Send LL_VERSION_IND containing the Lower Tester's version.
        3. Require the IUT to acknowledge the indication and return its own
           LL_VERSION_IND containing the IUT's version information.

    Expected Outcome:
        Pass verdict:
            The IUT correctly responds to the peer's Version Exchange.
        Inconclusive verdict:
            The IUT sends LL_VERSION_IND before the Lower Tester does.

    Coverage Note:
        Check the local version against Read Local Version Information and
        validate ACK sequence bits. No Host version request or duplicate peer
        indication is injected. A finite observation budget bounds waiting for
        the response; exhaustion is diagnostic, not a timing failure.

    Reference:
        LL.TS.p28.pdf, LL/CON/CEN/BV-21-C, Figure 4.3-150, Steps 1-3;
        PDF 772-773, printed 4.3-299..300. Source reference [3] 5.1.5.
    """
    await _exchange(tester, central=True, mode='responding', duplicates=False)


async def version_exchange_iut_requesting(tester, *, central):
    """Version Exchange, IUT Requesting.

    Initial Condition:
        Connected in the selected role using public addresses and common
        connection interval, Peripheral latency, timeout and channel map.
        Any advertising interval, advertising channel map and SCA are allowed.
        The selected common interval is 10 ms, latency zero and timeout 300 ms.

    Test Case Configuration:
        LL/CON/CEN/BI-11-C: Central.
        LL/CON/PER/BI-14-C: Peripheral.

    Test Steps:
        1. If the IUT autonomously sends LL_VERSION_IND after connection,
           containing its local version information, proceed to Step 4.
        2. Otherwise send HCI_Read_Remote_Version_Information and require
           successful HCI_Command_Status.
        3. Receive LL_VERSION_IND containing the IUT's version information.
        4. Send the Lower Tester's LL_VERSION_IND in the packet that
           acknowledges the IUT's indication.
        5. If Step 2 was performed, require Remote Version Information Complete
           containing the Lower Tester's version information.
        6. Within the same connection event, T_IFS after the preceding IUT PDU,
           send another LL_VERSION_IND. Require the IUT to ignore its content.
        7. After 50 connection intervals, send another LL_VERSION_IND.
           Require the IUT to ignore its content.

    Expected Outcome:
        Pass verdict:
            The IUT initiates Version Exchange and acknowledges the reply,
            without responding to either duplicate indication. If its Host
            initiated the procedure, exactly one successful completion reports
            the Lower Tester's version information.

    Coverage Note:
        Observe the first DATA before issuing the optional Host command.
        Read Local Version Information supplies the independent expected LMP
        version, manufacturer and LMP subversion. Use MD to keep the same-event
        sequence open, maintain ARQ and verify no extra indication or Host
        completion. The 50-interval delay begins at the same-event duplicate's
        RF timestamp; use the first legal event after that delay. Disconnect
        through HCI after ten additional quiet connection events.

    Reference:
        LL.TS.p28.pdf, Section 4.3.7.41; Table 4.3-123, Figure 4.3-253,
        Steps 1-7 and pass verdict; PDF 999-1001, printed 4.3-526..528.
        Source reference [3] 5.1.5.
    """
    await _exchange(tester, mode='requesting', central=central)


async def version_exchange_iut_responding(tester, *, central):
    """Version Exchange, IUT Responding.

    Initial Condition:
        Connected in the selected role using public addresses and common
        connection interval, Peripheral latency, timeout and channel map.
        Any advertising interval, advertising channel map and SCA are allowed.
        The selected common interval is 10 ms, latency zero and timeout 300 ms.

    Test Case Configuration:
        LL/CON/CEN/BI-12-C: Central.
        LL/CON/PER/BI-15-C: Peripheral.

    Test Steps:
        1. Send LL_VERSION_IND containing the Lower Tester's version
           information. Require the IUT to acknowledge the PDU.
        2. Receive LL_VERSION_IND containing the IUT's version information;
           the source permits this response at any later time.
        3. Within that same connection event, T_IFS after the IUT PDU, send
           another LL_VERSION_IND in its acknowledgement. Require the IUT
           to process the acknowledgement but ignore the indication content.
        4. After 50 connection intervals, send another LL_VERSION_IND and
           require the IUT to ignore its content.

    Expected Outcome:
        Pass verdict:
            The IUT correctly responds to the first indication, but sends no
            further Version Indication in response to Steps 3 or 4.
        Inconclusive verdict:
            The IUT sends LL_VERSION_IND before the Lower Tester does.

    Coverage Note:
        No Host version command is issued, so no unsolicited Host completion
        is permitted. Read Local Version Information supplies the expected
        local LMP tuple. Observe autonomous initiation during connection
        setup and immediately before the first peer indication. Use MD for
        the same-event duplicate and time the later duplicate from its RF
        timestamp. Maintain the connection while waiting across later events
        for the initial response. The duplicate still acknowledges that response
        at T_IFS within its connection event.
        Maintain ten additional quiet events and disconnect through HCI.

    Observation Limit:
        The source specifies no maximum response delay. A finite tester budget
        of LL_RESPONSE_TIMEOUT_US bounds the experiment; absence of a response
        within it yields a diagnostic skip, not a normative timing failure.

    Reference:
        LL.TS.p28.pdf, Section 4.3.7.42; Table 4.3-124, Figure 4.3-254,
        Steps 1-4 and pass/inconclusive verdicts; PDF 1001-1002,
        printed 4.3-528..529. Source reference [3] 5.1.5.
    """
    await _exchange(tester, mode='responding', central=central)


async def version_exchange_iut_requesting_collision(tester, *, central):
    """Version Exchange, IUT Requesting, Collision.

    Initial Condition:
        Connected in the selected role using public addresses and common
        connection interval, Peripheral latency, timeout and channel map.
        Any advertising interval, advertising channel map and SCA are allowed.
        The selected common interval is 10 ms, latency zero and timeout 300 ms.

    Test Case Configuration:
        LL/CON/CEN/BV-146-C: Central.
        LL/CON/PER/BV-145-C: Peripheral.

    Test Steps:
        1. If the IUT autonomously sends LL_VERSION_IND after connection,
           containing its local version information, proceed to Step 4.
        2. Otherwise send HCI_Read_Remote_Version_Information and require
           successful HCI_Command_Status.
        3. Receive LL_VERSION_IND containing the IUT's version information.
        4. Within that same connection event, T_IFS after the IUT PDU, send the
           Lower Tester's LL_VERSION_IND in the packet acknowledging it.
        5. Require the IUT to acknowledge that PDU without another
           LL_VERSION_IND.
        6. If Step 2 was performed, require successful Remote Version
           Information Complete containing the Lower Tester's version tuple.

    Expected Outcome:
        Pass verdict:
            The IUT initiates Version Exchange and acknowledges the peer's
            indication without sending another local indication. If the Host
            initiated the procedure, completion follows receipt of the peer's
            indication and reports its exact version information.
        Inconclusive verdict:
            A Peripheral IUT does not listen to the Step 4 peer packet.

    Coverage Note:
        Read Local Version Information supplies the expected local LMP tuple.
        MD preserves the collision's same-event exchange. Require exactly one
        local indication, no unsolicited Host completion for an autonomous
        initiation and no duplicates during subsequent quiet events. Disconnect
        through HCI after observation.
        If no Peripheral response is received after the Step 4 transmission,
        use the source's not-listening Inconclusive verdict. Missing responses
        before Step 4, incorrect acknowledgements, invalid CRC/length or version
        information and duplicate indications remain assertion failures.

    Reference:
        LL.TS.p28.pdf, Section 4.3.7.43; Table 4.3-125, Figure 4.3-255,
        Steps 1-6 and pass/inconclusive verdicts; PDF 1002-1004,
        printed 4.3-529..531. Source reference [3] 5.1.5.
    """
    await _exchange(tester, mode='collision', central=central)


async def version_exchange_iut_requesting_delayed_response(tester, *, central):
    """Version Exchange, IUT Requesting, Delayed Response.

    Initial Condition:
        Connected in the selected role using public addresses and common
        connection interval, Peripheral latency, timeout and channel map.
        Any advertising interval, advertising channel map and SCA are allowed.
        The selected common interval is 10 ms, latency zero and timeout 300 ms.

    Test Case Configuration:
        LL/CON/CEN/BV-147-C: Central.
        LL/CON/PER/BV-147-C: Peripheral.

    Test Steps:
        1. If the IUT autonomously sends LL_VERSION_IND after connection,
           containing its local version information, proceed to Step 4.
        2. Otherwise send HCI_Read_Remote_Version_Information and require
           successful HCI_Command_Status.
        3. Receive LL_VERSION_IND containing the IUT's version information.
        4. Acknowledge the IUT indication without sending the peer version.
        5. After ten connection events, send LL_VERSION_IND containing the
           Lower Tester's version information.
        6. Require the IUT to acknowledge it without another LL_VERSION_IND.
        7. If Step 2 was performed, require successful Remote Version
           Information Complete containing the Lower Tester's version tuple.

    Expected Outcome:
        Pass verdict:
            The IUT initiates Version Exchange and acknowledges the delayed
            reply without sending another Version Indication. If its Host
            initiated the procedure, completion occurs after the peer
            indication and reports the exact peer version tuple.
        Fail verdict:
            The IUT drops the connection during the Step 5 delay.

    Coverage Note:
        Read Local Version Information supplies the expected local LMP tuple.
        Maintain empty DATA during the ten-event delay and reject premature
        Host completion or disconnection. Time the delay from the RF packet
        acknowledging the IUT indication, then use the first legal event after
        that delay. Autonomous initiation must not cause unsolicited Host
        completion. Maintain quiet events and disconnect through HCI afterward.

    Reference:
        LL.TS.p28.pdf, Section 4.3.7.44; Table 4.3-126, Figure 4.3-256,
        Steps 1-7 and pass/fail verdicts; PDF 1004-1006,
        printed 4.3-531..533. Source reference [3] 5.1.5.
    """
    await _exchange(tester, mode='delayed', central=central)


async def reject_invalid_connection_parameter_request_parameters(tester, *, central):
    """Reject Invalid Connection Parameter Request Parameters.

    Initial Condition:
        Connected in the selected role on LE 1M, with public addresses, common
        connection interval, Peripheral latency and supervision timeout, and
        a selected channel map. Any advertising interval, advertising channel
        map and SCA value are permitted.

    Test Case Configuration:
        LL/CON/CEN/BI-13-C: Central.
        LL/CON/PER/BI-16-C: Peripheral.

    Test Steps:
        1. Send LL_CONNECTION_PARAM_REQ with Interval_Max < Interval_Min.
        2. Require LL_REJECT_EXT_IND with RejectOpcode LL_CONNECTION_PARAM_REQ
           and Invalid LMP Parameters / Invalid LL Parameters (0x1E).

    Expected Outcome:
        Pass verdict:
            The IUT rejects the offending opcode through LL_REJECT_EXT_IND
            with error code 0x1E.

    Coverage Note:
        Use a minimum one unit above the legal minimum and a maximum equal to
        the legal minimum. Keep other fields valid to isolate reversed bounds,
        rather than an independently invalid interval. Acknowledge the reject;
        observe three unchanged connection events with no Host parameter
        approval or update-completion event, then disconnect through HCI.

    Reference:
        LL.TS.p28.pdf, Section 4.3.7.45; Table 4.3-127, Figure 4.3-257,
        Steps 1-2 and pass verdict; PDF 1006-1007, printed 4.3-533..534.
        Source reference [10] 2.4.2.16.
    """
    parameters = _advertiser_connection_parameters()
    link = await establish(
        tester,
        central=central,
        interval=parameters.interval,
        timeout=parameters.timeout,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    request = _parameter_request(
        link, LL_CONN_INTERVAL_MIN + 1, link.parameters.timeout
    )
    fields = list(struct.unpack('<HHHHBH6H', request[1:]))
    fields[1] = LL_CONN_INTERVAL_MIN
    request = bytes([Opcode.LL_CONNECTION_PARAM_REQ]) + struct.pack(
        '<HHHHBH6H', *fields
    )
    response = await link.control(Opcode.LL_REJECT_EXT_IND, request, check_ack=True)
    assert response == bytes(
        [
            Opcode.LL_REJECT_EXT_IND,
            Opcode.LL_CONNECTION_PARAM_REQ,
            ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR,
        ]
    )
    for _ in range(3):
        await link.exchange()
        assert not any(
            isinstance(
                event,
                (
                    hci.HCI_LE_Remote_Connection_Parameter_Request_Event,
                    hci.HCI_LE_Connection_Update_Complete_Event,
                ),
            )
            for event in tester.events
        )
    await link.disconnect()


PROCEDURES: ProcedureMap = {}

# Verify that an undirected advertiser accepts a connection request, stops advertising,
# and maintains a correctly timed Peripheral connection using Channel Selection
# Algorithm #1 on each supported primary channel.
PROCEDURES |= procedure_cases(
    accepting_connections,
    {
        'LL/CON/ADV/BV-01-C': pytest.param(
            'Accepting Connections',
            {},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify that an advertiser accepts a connection request and stops advertising, but
# reports establishment failure when the Central sends no DATA before the connection
# establishment timer expires.
PROCEDURES |= procedure_cases(
    accepting_connections_timeout,
    {
        'LL/CON/ADV/BV-02-C': (
            'Accepting Connections Timeout',
            {},
        ),
    },
)

# Verify that a newly connected Peripheral does not use Peripheral latency before the
# Central acknowledges its initial transmission. First withhold acknowledgements, then
# verify normal acknowledgement and latency behavior.
PROCEDURES |= procedure_cases(
    central_missing_peripheral_packets,
    {
        'LL/CON/ADV/BV-03-C': (
            'Central Missing Peripheral Packets',
            {},
        ),
    },
)

# Verify that directed advertising rejects a connection request from a mismatching
# initiator, then accepts the intended public initiator and maintains a Peripheral
# connection using Channel Selection Algorithm #1.
PROCEDURES |= procedure_cases(
    directed_advertising_connection,
    {
        'LL/CON/ADV/BV-04-C': (
            'Directed Advertising Connection',
            {},
        ),
    },
)

# Verify that a connectable extended advertiser accepts a request on its secondary
# channel, stops advertising, and maintains a Peripheral connection on the selected PHY
# using Channel Selection Algorithm #2. Verify the connection-related HCI events and
# rejection of wrong AdvA.
PROCEDURES |= procedure_cases(
    extended_advertising_accepting_connections,
    {
        'LL/CON/ADV/BV-05-C': (
            'Extended Advertising, Accepting Connections – LE 1M PHY',
            {'phy': Phy.LE_1M},
        ),
        'LL/CON/ADV/BV-12-C': (
            'Extended Advertising, Accepting Connections – LE 2M PHY',
            {'phy': Phy.LE_2M},
        ),
        'LL/CON/ADV/BV-13-C': (
            'Extended Advertising, Accepting Connections – LE Coded PHY',
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify that an advertiser controlled through the extended HCI commands accepts a
# legacy CONNECT_IND, stops advertising, and maintains a Peripheral connection using
# Channel Selection Algorithm #2. Verify connection-related HCI events and rejection of
# an incorrect AdvA.
PROCEDURES |= procedure_cases(
    extended_advertising_legacy_pdus_accepting_connections,
    {
        'LL/CON/ADV/BV-06-C': (
            'Extended Advertising, Legacy PDUs, Accepting Connections',
            {},
        ),
    },
)

# Verify that an advertiser accepts a legacy CONNECT_IND with ChSel=0, stops
# advertising, and maintains a Peripheral connection using Channel Selection Algorithm
# #1. Check that connection-related HCI events match the legacy or extended command path
# selected by Table 4.3-4.
PROCEDURES |= procedure_cases(
    accepting_connections_channel_selection_algorithm_1,
    {
        'LL/CON/ADV/BV-07-C': (
            'Accepting Connections, Channel Selection Algorithm #1',
            {'extended': False},
        ),
        'LL/CON/ADV/BV-27-C': (
            (
                'Accepting Connections, Channel Selection Algorithm #1, '
                'Extended Advertising'
            ),
            {'extended': True},
        ),
    },
)

# Verify that an advertiser accepts a legacy CONNECT_IND with ChSel=0, stops
# advertising, and maintains a Peripheral connection using Channel Selection Algorithm
# #1. Check that connection-related HCI events match the legacy or extended command path
# selected by Table 4.3-5.
PROCEDURES |= procedure_cases(
    directed_advertising_connection_channel_selection_algorithm_1,
    {
        'LL/CON/ADV/BV-08-C': (
            'Directed Advertising Connection, Channel Selection Algorithm #1',
            {'extended': False},
        ),
        'LL/CON/ADV/BV-28-C': (
            (
                'Directed Advertising Connection, Channel Selection '
                'Algorithm #1, Extended Advertising'
            ),
            {'extended': True},
        ),
    },
)

# Verify that an advertiser accepts a legacy CONNECT_IND with ChSel=1, stops
# advertising, and maintains a Peripheral connection using Channel Selection Algorithm
# #2. Check that connection-related HCI events match the legacy or extended command path
# selected by Table 4.3-6.
PROCEDURES |= procedure_cases(
    accepting_connections_channel_selection_algorithm_2,
    {
        'LL/CON/ADV/BV-09-C': (
            'Accepting Connections, Channel Selection Algorithm #2',
            {'extended': False},
        ),
        'LL/CON/ADV/BV-29-C': (
            (
                'Accepting Connections, Channel Selection Algorithm #2, '
                'Extended Advertising'
            ),
            {'extended': True},
        ),
    },
)

# Verify that an advertiser accepts a legacy CONNECT_IND with ChSel=1, stops
# advertising, and maintains a Peripheral connection using Channel Selection Algorithm
# #2. Check that connection-related HCI events match the legacy or extended command path
# selected by Table 4.3-7.
PROCEDURES |= procedure_cases(
    directed_advertising_connection_channel_selection_algorithm_2,
    {
        'LL/CON/ADV/BV-10-C': (
            'Directed Advertising Connection, Channel Selection Algorithm #2',
            {'extended': False},
        ),
        'LL/CON/ADV/BV-30-C': (
            (
                'Directed Advertising Connection, Channel Selection '
                'Algorithm #2, Extended Advertising'
            ),
            {'extended': True},
        ),
    },
)

# Verify that a Peripheral establishes a connection after receiving DATA with the
# correct Access Address but an invalid CRC, does not acknowledge that invalid DATA, and
# terminates at the original supervision deadline.
PROCEDURES |= procedure_cases(
    connection_supervision_timeout_during_fail_connection_setup,
    {
        'LL/CON/ADV/BI-01-C': (
            'Connection Supervision Timeout during Fail Connection Setup',
            {},
        ),
    },
)

# Verify that a Peripheral rejects a second connection request from an already connected
# public peer, continues advertising, and maintains only the original ACL connection
# while both candidate event streams are probed.
PROCEDURES |= procedure_cases(
    reject_existing_connection_request,
    {
        'LL/CON/ADV/BI-02-C': (
            'Reject Existing Connection Request',
            {},
        ),
    },
)

# Verify that an extended advertiser rejects an AUX_CONNECT_REQ from an already
# connected peer without sending AUX_CONNECT_RSP, while the original ACL connection
# continues exchanging correctly formatted DATA.
PROCEDURES |= procedure_cases(
    reject_connection_request_when_connected_to_the_peer_extended_advertising,
    {
        'LL/CON/ADV/BV-26-C': (
            (
                'Reject Connection Request when Connected to the Peer, '
                'Extended Advertising'
            ),
            {},
        ),
    },
)

# Verify initiation with public peers on every primary advertising channel, rejection of
# Set Random Address while initiating, and a maintained CSA#1 Central connection with
# the required first-event and clock accuracy.
PROCEDURES |= procedure_cases(
    connection_initiation,
    {
        'LL/CON/INI/BV-36-C': (
            'Connection Initiation, HCI LE Channel Selection Algorithm supported',
            {},
        ),
    },
)

# Verify initiation to directed advertising and maintained Central DATA exchange, first
# using CSA#1 and then CSA#2, with correctly valued HCI events, legal first-event timing
# and clock-accuracy bounds.
PROCEDURES |= procedure_cases(
    connecting_to_directed_advertising,
    {
        'LL/CON/INI/BV-37-C': (
            (
                'Connecting to Directed Advertising, HCI LE Channel '
                'Selection Algorithm supported'
            ),
            {},
        ),
    },
)

# Verify that an initiator continues Central transmissions while initial Peripheral
# replies are omitted, then establishes and maintains the connection when valid
# acknowledgements resume before setup expires.
PROCEDURES |= procedure_cases(
    connection_initiation_missed_replies,
    {
        'LL/CON/INI/BV-38-C': (
            (
                'Connection Initiation Missed Replies, HCI LE Channel '
                'Selection Algorithm supported'
            ),
            {},
        ),
    },
)

# Verify that an initiator with no Peripheral replies stops the failed connection setup
# after the permitted initial connection events and reports Connection Failed to be
# Established through HCI.
PROCEDURES |= procedure_cases(
    connection_initiation_timeout,
    {
        'LL/CON/INI/BV-39-C': (
            (
                'Connection Initiation Timeout, HCI LE Channel Selection '
                'Algorithm supported'
            ),
            {},
        ),
    },
)

# Verify that initiation filters advertising by both peer address bytes and address
# type. Reject mismatching types and unlisted addresses, then connect to the matching
# Filter Accept List entry through the selected PDU type.
PROCEDURES |= procedure_cases(
    initiation_device_filtering_undirected,
    {
        'LL/CON/INI/BV-40-C': (
            (
                'Initiation Device Filtering: Undirected, HCI LE Channel '
                'Selection Algorithm supported'
            ),
            {'directed': False},
        ),
        'LL/CON/INI/BV-41-C': (
            (
                'Initiation Device Filtering: Directed, HCI LE Channel '
                'Selection Algorithm supported'
            ),
            {'directed': True},
        ),
    },
)

# Verify initiation on a secondary advertising channel, correct HCI completion and
# CSA#2, first-event and maintained-connection timing, and retry after an unanswered
# AUX_CONNECT_REQ on each selected PHY.
PROCEDURES |= procedure_cases(
    extended_scanning_connection_initiation,
    {
        'LL/CON/INI/BV-13-C': (
            'Extended Scanning, Connection Initiation – LE 1M PHY',
            {'phy': Phy.LE_1M},
        ),
        'LL/CON/INI/BV-25-C': (
            'Extended Scanning, Connection Initiation – LE 2M PHY',
            {'phy': Phy.LE_2M},
        ),
        'LL/CON/INI/BV-26-C': (
            'Extended Scanning, Connection Initiation – LE Coded PHY',
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify that the Central selects CSA#1 when the Lower Tester's legacy advertising ChSel
# is 0, reports the selected algorithm through HCI, and maintains correctly timed DATA
# on independently calculated channels.
PROCEDURES |= procedure_cases(
    connection_initiation_channel_selection_algorithm_1,
    {
        'LL/CON/INI/BV-14-C': (
            'Connection Initiation, Channel Selection Algorithm #1',
            {'directed': False},
        ),
        'LL/CON/INI/BV-15-C': (
            'Connecting to Directed Advertising, Channel Selection Algorithm\xa0#1',
            {'directed': True},
        ),
    },
)

# Verify that the Central selects CSA#2 when the Lower Tester's legacy advertising ChSel
# is 1, reports the selected algorithm through HCI, and maintains correctly timed DATA
# on independently calculated channels.
PROCEDURES |= procedure_cases(
    connection_initiation_channel_selection_algorithm_2,
    {
        'LL/CON/INI/BV-16-C': (
            'Connection Initiation, Channel Selection Algorithm #2',
            {'directed': False},
        ),
        'LL/CON/INI/BV-17-C': (
            'Connecting to Directed Advertising, Channel Selection Algorithm\xa0#2',
            {'directed': True},
        ),
    },
)

# Verify that invalid-CRC legacy advertising cannot trigger a connection request and
# that the still-pending initiation procedure can be cancelled successfully through HCI
# after the complete observation window.
PROCEDURES |= procedure_cases(
    connection_initiation_invalid_crc,
    {
        'LL/CON/INI/BI-01-C': (
            'Connection Initiation Invalid CRC',
            {},
        ),
    },
)

# Verify that a Central receiving only invalid-CRC Peripheral replies continues
# unacknowledged transmissions until the original supervision deadline, then reports
# Connection Timeout rather than extending the timer.
PROCEDURES |= procedure_cases(
    peripheral_packets_invalid_crc,
    {
        'LL/CON/INI/BI-04-C': (
            (
                'Peripheral Packets Invalid CRC, HCI LE Channel Selection '
                'Algorithm supported'
            ),
            {},
        ),
    },
)

# Verify that every generated connection Access Address is legal, that 36 consecutive
# connections use distinct addresses, and that each bit position contains at least three
# zeros and three ones across the set.
PROCEDURES |= procedure_cases(
    connection_initiation_with_valid_access_address,
    {
        'LL/CON/INI/BV-50-C': (
            (
                'Connection Initiation with Valid Access Address, HCI LE '
                'Channel Selection Algorithm supported'
            ),
            {},
        ),
    },
)

# Verify that starting advertising during initiation does not lose the pending outgoing
# connection when an incoming connection completes first.
PROCEDURES |= procedure_cases(
    parallel_connection_requests_incoming_connect_indication_first,
    {
        'LL/CON/INI/BV-51-C': (
            (
                'Parallel connection requests, incoming connect indication '
                'first, CSA #2'
            ),
            {},
        ),
    },
)

# Verify that an initiator can start advertising, complete its outgoing connection
# first, continue advertising, and accept an incoming connection.
PROCEDURES |= procedure_cases(
    parallel_connection_requests_outgoing_connection_request_first,
    {
        'LL/CON/INI/BV-52-C': (
            (
                'Parallel connection requests, outgoing connection request '
                'first, HCI LE Channel Selection Algorithm supported'
            ),
            {},
        ),
    },
)

# Verify that an initiator does not send another connection request to a peer with which
# it already maintains an ACL connection.
PROCEDURES |= procedure_cases(
    duplicate_connection_request,
    {
        'LL/CON/INI/BI-05-C': (
            (
                'Duplicate Connection Request, HCI LE Channel Selection '
                'Algorithm supported'
            ),
            {},
        ),
    },
)

# Verify Peripheral responses, DATA acknowledgement and Host delivery when the
# connection allows nonzero Peripheral latency.
PROCEDURES |= procedure_cases(
    peripheral_asymmetric_connections,
    {
        'LL/CON/PER/BV-02-C': (
            'Peripheral Asymmetric Connections',
            {},
        ),
    },
)

# Verify Peripheral Host-to-air DATA delivery, HCI flow control, and preservation of
# message boundaries across Link Layer fragmentation.
PROCEDURES |= procedure_cases(
    peripheral_sending_data,
    {
        'LL/CON/PER/BV-04-C': (
            'Peripheral Sending Data',
            {},
        ),
    },
)

# Verify that Peripheral DATA reception preserves payloads and upper-layer message
# boundaries when reporting HCI ACL packets to its Host.
PROCEDURES |= procedure_cases(
    peripheral_receiving_data,
    {
        'LL/CON/PER/BV-05-C': (
            'Peripheral Receiving Data',
            {},
        ),
    },
)

# Verify simultaneous Peripheral transmission and reception, preserving payloads,
# acknowledgements and HCI/LL fragmentation boundaries.
PROCEDURES |= procedure_cases(
    peripheral_sending_and_receiving_data,
    {
        'LL/CON/PER/BV-06-C': (
            'Peripheral Sending and Receiving Data',
            {},
        ),
    },
)

# Verify Peripheral acknowledgement of connection parameter updates, retention of old
# parameters before the Instant, and adoption of the new parameters at the requested
# event, including receive-window edges.
PROCEDURES |= procedure_cases(
    accepting_parameter_update,
    {
        'LL/CON/PER/BV-10-C': pytest.param(
            'Accepting Parameter Update',
            {},
            marks=[
                pytest.mark.limited,
            ],
        ),
    },
)

# Verify Peripheral-initiated connection termination, acknowledgement by the Lower
# Central, cessation of DATA, and Host termination notification.
PROCEDURES |= procedure_cases(
    peripheral_sending_termination,
    {
        'LL/CON/PER/BV-11-C': (
            'Peripheral Sending Termination',
            {},
        ),
    },
)

# Verify that a Peripheral acknowledges a Central termination request, ceases ACL
# maintenance, and reports the peer-requested disconnection.
PROCEDURES |= procedure_cases(
    peripheral_accepting_termination,
    {
        'LL/CON/PER/BV-12-C': (
            'Peripheral Accepting Termination',
            {},
        ),
    },
)

# Verify that the Peripheral terminates an unmaintained ACL on supervision timeout and
# reports the correct handle and timeout reason to its Host.
PROCEDURES |= procedure_cases(
    peripheral_supervision_timer,
    {
        'LL/CON/PER/BV-13-C': (
            'Peripheral Supervision Timer',
            {},
        ),
    },
)

# Verify that a connected Peripheral responds to Feature Exchange with the supported
# feature information and correct peer-report masking.
PROCEDURES |= procedure_cases(
    feature_setup_response,
    {
        'LL/CON/PER/BV-14-C': (
            'Feature Setup Response',
            {},
        ),
    },
)

# Verify that a Peripheral retains the DATA acknowledgement state when receiving packets
# with invalid CRC and continues to request retransmission.
PROCEDURES |= procedure_cases(
    peripheral_retransmission_request,
    {
        'LL/CON/PER/BV-15-C': (
            'Peripheral Retransmission Request',
            {},
        ),
    },
)

# Verify that a Peripheral retransmits its outstanding DATA with unchanged sequence
# number and payload when the Central withholds acknowledgement.
PROCEDURES |= procedure_cases(
    peripheral_retransmission,
    {
        'LL/CON/PER/BV-16-C': (
            'Peripheral Retransmission',
            {},
        ),
    },
)

# Verify that a Peripheral repeats a positive acknowledgement when the Central
# retransmits the same DATA payload and sequence number.
PROCEDURES |= procedure_cases(
    peripheral_acknowledgement_repetition,
    {
        'LL/CON/PER/BV-17-C': (
            'Peripheral Acknowledgement Repetition',
            {},
        ),
    },
)

# Verify that a Peripheral preserves DATA sequence state when the Central mistakes a
# negative acknowledgement for a positive one.
PROCEDURES |= procedure_cases(
    peripheral_lost_negative_acknowledgement,
    {
        'LL/CON/PER/BV-18-C': (
            'Peripheral Lost Negative Acknowledgement',
            {},
        ),
    },
)

# Verify normal DATA acknowledgement and sequence-state transitions in a maintained
# Peripheral connection.
PROCEDURES |= procedure_cases(
    peripheral_acknowledgement_scheme,
    {
        'LL/CON/PER/BV-21-C': (
            'Peripheral Acknowledgement Scheme',
            {},
        ),
    },
)

# Verify Peripheral-initiated Feature Exchange, correct peer-visible supported features,
# acknowledgement, and reporting of the peer features.
PROCEDURES |= procedure_cases(
    initiate_feature_exchange,
    {
        'LL/CON/PER/BV-22-C': (
            'Initiate Feature Exchange',
            {},
        ),
    },
)

# Verify Peripheral-initiated Feature Exchange when the Central does not support the
# procedure and answers with LL_UNKNOWN_RSP.
PROCEDURES |= procedure_cases(
    initiate_feature_exchange_central_does_not_support,
    {
        'LL/CON/PER/BV-23-C': (
            'Initiate Feature Exchange – Central does not support',
            {},
        ),
    },
)

# Verify Peripheral-initiated parameter requests accepted by the Central, including
# minimum/maximum/minimum interval transitions. The actual LL request may select
# parameters different from the Host command.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_accept,
    {
        'LL/CON/PER/BV-24-C': (
            'Initiating Connection Parameter Request – Accept',
            {},
        ),
    },
)

# Verify that a Peripheral reports rejection of its connection parameter request with
# the same error code supplied by the Central.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_reject,
    {
        'LL/CON/PER/BV-25-C': (
            'Initiating Connection Parameter Request – Reject',
            {},
        ),
    },
)

# Verify that a Peripheral preserves an overlapping Central parameter request, reports
# rejection of its local request when applicable, and completes the Central procedure
# after Host approval.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_same_procedure_collision,
    {
        'LL/CON/PER/BV-26-C': (
            'Initiating Connection Parameter Request – same procedure collision',
            {},
        ),
    },
)

# Verify that a Peripheral accepts a Central channel-map update during its own
# parameter-request procedure and reports the correct collision error.
PROCEDURES |= procedure_cases(
    initiating_parameter_request_channel_map_collision,
    {
        'LL/CON/PER/BV-27-C': (
            (
                'Initiating Connection Parameter Request – different '
                'procedure collision – channel map update'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral completes a Central encryption start procedure during its own
# pending parameter request, then completes that request.
PROCEDURES |= procedure_cases(
    initiating_parameter_request_encryption_collision,
    {
        'LL/CON/PER/BV-28-C': (
            (
                'Initiating Connection Parameter Request – different '
                'procedure collision – encryption'
            ),
            {},
        ),
    },
)

# Verify Peripheral acceptance of Central parameter requests without a preferred
# periodicity, across minimum/maximum/minimum interval changes.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_no_preferred_periodicity,
    {
        'LL/CON/PER/BV-29-C': (
            'Accepting Connection Parameter Request – no Preferred_Periodicity',
            {},
        ),
    },
)

# Verify Peripheral acceptance of anchor-only parameter requests without changing the
# connection interval, latency or supervision timeout.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_preferred_anchor_points_only,
    {
        'LL/CON/PER/BV-30-C': (
            'Accepting Connection Parameter Request – preferred anchor points only',
            {},
        ),
    },
)

# Verify Peripheral acceptance of Central parameter requests carrying a preferred
# interval periodicity, optionally with preferred anchor points.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_preferred_periodicity,
    {
        'LL/CON/PER/BV-31-C': (
            'Accepting Connection Parameter Request – Preferred_Periodicity',
            {'anchors': False},
        ),
        'LL/CON/PER/BV-32-C': (
            (
                'Accepting Connection Parameter Request – '
                'Preferred_Periodicity and preferred anchor points'
            ),
            {'anchors': True},
        ),
    },
)

# Verify that a Peripheral rejects a Central parameter request requiring Host approval
# when the Host has masked the approval-request event.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_event_masked,
    {
        'LL/CON/PER/BV-33-C': (
            'Accepting Connection Parameter Request – event masked',
            {},
        ),
    },
)

# Verify Peripheral rejection of a Central parameter request when the Peripheral Host
# supplies a negative approval reply.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_host_rejects,
    {
        'LL/CON/PER/BV-34-C': (
            'Accepting Connection Parameter Request – Host rejects',
            {},
        ),
    },
)

# Verify Peripheral-initiated PHY updates across all supported PHYs, including
# asymmetric directions, and continued DATA on the selected PHYs.
PROCEDURES |= procedure_cases(
    initiating_phy_update_procedure,
    {
        'LL/CON/PER/BV-40-C': (
            'Initiating PHY Update Procedure',
            {},
        ),
    },
)

# Verify Peripheral responses to Central PHY updates across supported directional PHY
# combinations, with HCI notification only when appropriate.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_procedure,
    {
        'LL/CON/PER/BV-42-C': (
            'Responding to PHY Update Procedure',
            {},
        ),
    },
)

# Verify that a Peripheral yields its pending PHY request to an overlapping Central PHY
# request and completes the Central procedure after rejection of its own procedure.
PROCEDURES |= procedure_cases(
    handling_protocol_collision_same_procedure,
    {
        'LL/CON/PER/BV-44-C': (
            'Handling Protocol Collision – Same Procedure',
            {},
        ),
    },
)

# Verify that a Peripheral terminates its ACL when a locally initiated PHY procedure
# receives no update before the response timer expires.
PROCEDURES |= procedure_cases(
    protocol_timeout_for_phy_update_procedure,
    {
        'LL/CON/PER/BV-45-C': (
            'Protocol Timeout for PHY Update Procedure',
            {},
        ),
    },
)

# Verify that a Peripheral preserves a Central channel-map update during its local PHY
# request and reports the correct different-procedure error.
PROCEDURES |= procedure_cases(
    handling_protocol_collision_different_procedure_channel_map,
    {
        'LL/CON/PER/BV-46-C': (
            'Handling Protocol Collision – Different Procedure – Channel Map',
            {},
        ),
    },
)

# Verify that a Peripheral preserves a Central connection parameter request while its
# own pending PHY update is rejected because of the collision.
PROCEDURES |= procedure_cases(
    handling_protocol_collision_different_procedure_connection_parameters,
    {
        'LL/CON/PER/BV-47-C': (
            (
                'Handling Protocol Collision – Different Procedure – '
                'Connection Parameters'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral preserves a Central connection update while its local PHY
# request is rejected because of a different-procedure collision.
PROCEDURES |= procedure_cases(
    handling_protocol_collision_different_procedure_connection_update,
    {
        'LL/CON/PER/BV-48-C': (
            'Handling Protocol Collision – Different Procedure – Connection Update',
            {},
        ),
    },
)

# Verify Peripheral packet-time restrictions before, during and after a locally
# initiated transition from LE 2M to LE 1M while Host DATA continues.
PROCEDURES |= procedure_cases(
    initiating_phy_update_procedure_packet_time_restrictions,
    {
        'LL/CON/PER/BV-49-C': (
            'Initiating PHY Update Procedure – Packet Time Restrictions',
            {},
        ),
    },
)

# Verify Peripheral packet-time restrictions before, during and after a
# Central-initiated transition from LE 2M to LE 1M with ongoing Host DATA.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_procedure_packet_time_restrictions,
    {
        'LL/CON/PER/BV-50-C': (
            'Responding to PHY Update Procedure – Packet Time Restrictions',
            {},
        ),
    },
)

# Verify that a Peripheral terminates the ACL when a Central-initiated PHY procedure is
# left incomplete until the response timer expires.
PROCEDURES |= procedure_cases(
    protocol_timeout_for_phy_update_procedure_no_update_request,
    {
        'LL/CON/PER/BV-51-C': (
            'Protocol Timeout for PHY Update Procedure – No Update Request',
            {},
        ),
    },
)

# Verify Peripheral packet-time restrictions during a locally initiated PHY procedure
# when the Central ultimately selects no PHY change.
PROCEDURES |= procedure_cases(
    initiating_phy_update_procedure_packet_time_restrictions_no_change,
    {
        'LL/CON/PER/BV-52-C': (
            'Initiating PHY Update Procedure – Packet Time Restrictions, No Change',
            {},
        ),
    },
)

# Verify Peripheral packet-time restrictions while responding to a Central PHY procedure
# that ultimately leaves both directional PHYs unchanged.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_procedure_packet_time_restrictions_no_change,
    {
        'LL/CON/PER/BV-53-C': (
            (
                'Responding to PHY Update Procedure – Packet Time '
                'Restrictions, No Change'
            ),
            {},
        ),
    },
)

# Verify Peripheral DATA reception while the Central alternates LE Coded S=2/S=8 rates,
# including every response's 150 +/-2 us T_IFS and exact Host delivery at the effective
# maximum and minimum payload sizes.
PROCEDURES |= procedure_cases(
    peripheral_receiving_data_le_coded_ci_change,
    {
        'LL/CON/PER/BV-54-C': (
            'Peripheral Receiving Data, LE Coded, CI Change',
            {},
        ),
    },
)

# Verify Peripheral packet-time restrictions during a locally initiated LE 1M-to-Coded
# transition, including DATA queued before the Instant that could otherwise exceed the
# post-update packet limits on retransmission.
PROCEDURES |= procedure_cases(
    initiating_phy_update_procedure_packet_time_restrictions_le_coded,
    {
        'LL/CON/PER/BV-55-C': (
            'Initiating PHY Update Procedure – Packet Time Restrictions, LE Coded',
            {},
        ),
    },
)

# Verify Peripheral packet-time restrictions during a Central-initiated LE 1M-to-Coded
# transition, including pre-Instant queued DATA whose later transmission or
# retransmission could otherwise violate the new limits.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_procedure_packet_time_restrictions_le_coded,
    {
        'LL/CON/PER/BV-56-C': (
            (
                'Responding to PHY Update Procedure – Packet Time '
                'Restrictions, LE Coded'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral continues transmitting the mandatory minimum DATA length when
# a PHY transition raises the minimum effective packet time. Maintain traffic during a
# transition to LE Coded and back to LE 1M.
PROCEDURES |= procedure_cases(
    mandatory_minimum_pdu_length_le_coded,
    {
        'LL/CON/PER/BV-57-C': (
            'Mandatory Minimum PDU Length, LE Coded',
            {},
        ),
    },
)

# Verify Peripheral packet-time restrictions when the Host requests LE Coded but the
# Central selects no PHY change. Previously queued DATA must respect the prospective
# retransmission limit while the procedure is pending, even though the connection
# remains on LE 1M.
PROCEDURES |= procedure_cases(
    initiating_phy_update_procedure_packet_time_restrictions_no_change_le_coded,
    {
        'LL/CON/PER/BV-58-C': (
            (
                'Initiating PHY Update Procedure – Packet Time '
                'Restrictions, No Change, LE Coded'
            ),
            {},
        ),
    },
)

# Verify Peripheral packet-time restrictions when a Central requests LE Coded but then
# selects no PHY change. Previously queued DATA must respect the prospective
# retransmission limit while the procedure is pending, even though the connection
# remains on LE 1M.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_packet_time_limits_no_change_le_coded,
    {
        'LL/CON/PER/BV-59-C': (
            (
                'Responding to PHY Update Procedure – Packet Time '
                'Restrictions, No Change, LE Coded'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral correctly responds to peer LL_LENGTH_REQ on LE 1M, reports
# effective changes and respects the negotiated limits during bidirectional DATA
# transfer.
PROCEDURES |= procedure_cases(
    peripheral_responding_to_data_length_update_le_1m_phy,
    {
        'LL/CON/PER/BV-77-C': (
            (
                'Peripheral Data Length Update – Responding to Data Length '
                'Update Procedure; LE 1M PHY'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral initiates Data Length Update through LL_LENGTH_REQ on LE 1M
# after HCI requests, accepts the peer response and respects effective limits during
# bidirectional DATA transfer.
PROCEDURES |= procedure_cases(
    peripheral_initiating_data_length_update_le_1m_phy,
    {
        'LL/CON/PER/BV-78-C': (
            (
                'Peripheral Data Length Update – Initiating Data Length '
                'Update Procedure; LE 1M PHY'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral maintains DATA communication on LE 1M when its Central does
# not support Data Length Update and answers LL_LENGTH_REQ with LL_UNKNOWN_RSP.
PROCEDURES |= procedure_cases(
    peripheral_data_length_update_central_does_not_support_le_1m_phy,
    {
        'LL/CON/PER/BV-79-C': (
            'Peripheral Data Length Update – Central does not support; LE 1M PHY',
            {},
        ),
    },
)

# Verify that a Peripheral correctly responds to peer LL_LENGTH_REQ on LE 2M, reports
# effective changes and respects the negotiated limits during bidirectional DATA
# transfer.
PROCEDURES |= procedure_cases(
    peripheral_responding_to_data_length_update_le_2m_phy,
    {
        'LL/CON/PER/BV-80-C': (
            (
                'Peripheral Data Length Update – Responding to Data Length '
                'Update Procedure; LE 2M PHY'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral initiates Data Length Update through LL_LENGTH_REQ on LE 2M
# after HCI requests, accepts the peer response and respects effective limits during
# bidirectional DATA transfer.
PROCEDURES |= procedure_cases(
    peripheral_initiating_data_length_update_le_2m_phy,
    {
        'LL/CON/PER/BV-81-C': (
            (
                'Peripheral Data Length Update – Initiating Data Length '
                'Update Procedure; LE 2M PHY'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral correctly responds to peer LL_LENGTH_REQ on LE Coded, reports
# effective changes and respects the negotiated limits during bidirectional DATA
# transfer.
PROCEDURES |= procedure_cases(
    peripheral_responding_to_data_length_update_le_coded_phy,
    {
        'LL/CON/PER/BV-82-C': (
            (
                'Peripheral Data Length Update – Responding to Data Length '
                'Update Procedure; LE Coded PHY'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral initiates Data Length Update through LL_LENGTH_REQ on LE
# Coded after HCI requests, accepts the peer response and respects effective limits
# during bidirectional DATA transfer.
PROCEDURES |= procedure_cases(
    peripheral_initiating_data_length_update_le_coded_phy,
    {
        'LL/CON/PER/BV-83-C': (
            (
                'Peripheral Data Length Update – Initiating Data Length '
                'Update Procedure; LE Coded PHY'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral maintains DATA communication on LE Coded when its Central
# does not support Data Length Update and answers LL_LENGTH_REQ with LL_UNKNOWN_RSP.
PROCEDURES |= procedure_cases(
    peripheral_data_length_update_central_does_not_support_le_coded_phy,
    {
        'LL/CON/PER/BV-84-C': (
            'Peripheral Data Length Update – Central does not support; LE Coded PHY',
            {},
        ),
    },
)

# Verify that a Peripheral learns that its Central does not support Connection Parameter
# Request without a completed Feature Exchange, reports the first failed request and
# rejects a repeated Host request without retransmitting the unsupported procedure.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_unsupported_without_feature_exchange,
    {
        'LL/CON/PER/BV-85-C': (
            (
                'Initiating Connection Parameter Request – Unsupported '
                'Without Feature Exchange'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral rejects a Host Connection Parameter Request after Feature
# Exchange has disclosed that its Central does not support the procedure, without
# sending an on-air parameter request.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_unsupported_with_feature_exchange,
    {
        'LL/CON/PER/BV-86-C': (
            (
                'Initiating Connection Parameter Request – Unsupported With'
                ' Feature Exchange'
            ),
            {},
        ),
    },
)

# Verify that a Peripheral uses the start of a Central packet as the event anchor
# despite an invalid CRC, responds where required, but does not treat invalid-CRC DATA
# as valid traffic for supervision refresh.
PROCEDURES |= procedure_cases(
    invalid_crc_anchor_point,
    {
        'LL/CON/PER/BI-01-C': (
            'Invalid CRC Anchor Point',
            {},
        ),
    },
)

# Verify that a Peripheral retransmits an unacknowledged termination indication until
# T_Terminate expires, then reports link termination. Valid Central traffic must not
# indefinitely restart that timer.
PROCEDURES |= procedure_cases(
    peripheral_t_terminate_timer,
    {
        'LL/CON/PER/BI-02-C': (
            'Peripheral T_Terminate Timer',
            {},
        ),
    },
)

# Verify that a Peripheral handles past Instants in connection and channel-map updates:
# report the required connection-update failure, then either disconnect or acknowledge
# and maintain the connection for the channel-map case, as permitted by the source
# alternatives.
PROCEDURES |= procedure_cases(
    rejecting_connection_change,
    {
        'LL/CON/PER/BI-04-C': (
            'Rejecting Connection Change',
            {},
        ),
    },
)

# Verify recovery from a stalled Version Exchange: keep the ACL alive without returning
# peer version information, then require the connection control timeout and cessation of
# RF maintenance. Inform the Host of its pending procedure failure unless disconnection
# takes precedence.
PROCEDURES |= procedure_cases(
    peripheral_connection_control_timer,
    {
        'LL/CON/PER/BI-05-C': (
            'Peripheral Connection Control Timer',
            {},
        ),
    },
)

# Verify that a Peripheral starts Connection Parameter Request following a Host command
# and terminates with LL Response Timeout if the Central acknowledges the request but
# never returns its procedure response.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_timeout,
    {
        'LL/CON/PER/BI-07-C': (
            'Initiating Connection Parameter Request – Timeout',
            {},
        ),
    },
)

# Verify that a Peripheral rejects a Central Connection Parameter Request whose minimum
# and maximum interval fields are outside the valid range.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_illegal_parameters,
    {
        'LL/CON/PER/BI-08-C': (
            'Accepting Connection Parameter Request – illegal parameters',
            {},
        ),
    },
)

# Verify that a Peripheral handles a Central PHY update with an Instant in the past,
# accepting either the specified failure/disconnection path or the source's alternative
# of switching PHY and maintaining the link.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_procedure_instant_in_past,
    {
        'LL/CON/PER/BI-09-C': (
            'Responding to PHY Update Procedure – Instant In Past',
            {},
        ),
    },
)

# Verify that a connected Peripheral handles simultaneous Version Exchange initiation,
# returns its version in the same connection event as the peer indication, and reports
# the peer's version to its Host.
PROCEDURES |= procedure_cases(
    version_exchange_iut_requesting_collision_peripheral,
    {
        'LL/CON/PER/BV-146-C': (
            'Version Exchange, IUT Requesting, Collision, Peripheral',
            {},
        ),
    },
)

# Verify that a Peripheral acknowledges a packet with reserved LLID=0 without
# interpreting its payload as a Feature Request, then correctly responds when the same
# feature payload uses the valid control LLID.
PROCEDURES |= procedure_cases(
    invalid_llid,
    {
        'LL/CON/PER/BI-17-C': (
            'Invalid LLID',
            {},
        ),
    },
)

# Verify that a Peripheral handles a Central PHY update containing invalid multiple-PHY
# or RFU selections, either disconnecting or keeping its active PHY without an
# inappropriate Host PHY-change notification.
PROCEDURES |= procedure_cases(
    phy_update_procedure_invalid_or_unsupported_phy_central_initiated,
    {
        'LL/CON/PER/BI-20-C': (
            (
                'PHY Update Procedure, Invalid or Unsupported PHY, Central '
                'Initiated, Multiple PHYs Specified'
            ),
            {'rfu': False},
        ),
        'LL/CON/PER/BI-21-C': (
            (
                'PHY Update Procedure, Invalid or Unsupported PHY, Central '
                'Initiated, RFU Bits Specified'
            ),
            {'rfu': True},
        ),
    },
)

# Verify that a Peripheral widens its receive window after missed events and receives a
# Central packet within the specified early or late widened region after a connection
# update.
PROCEDURES |= procedure_cases(
    listening_for_packet_with_window_widening_acl,
    {
        'LL/CON/PER/BV-158-C': pytest.param(
            'Listening for Packet With Window Widening, ACL',
            {},
            marks=[
                pytest.mark.limited,
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that a Central maintains its connection and acknowledgement state when a
# Peripheral uses latency, with acceptable Central clock drift.
PROCEDURES |= procedure_cases(
    events_with_peripheral_latency,
    {
        'LL/CON/CEN/BV-02-C': (
            'Events With Peripheral Latency',
            {},
        ),
    },
)

# Verify Central transmission of Host data to a Peripheral, including HCI completion
# credits and preservation of fragmentation boundaries.
PROCEDURES |= procedure_cases(
    central_sending_data,
    {
        'LL/CON/CEN/BV-03-C': (
            'Central Sending Data',
            {},
        ),
    },
)

# Verify that a Central acknowledges Peripheral DATA and reports its payload and
# fragmentation boundaries correctly to the Host.
PROCEDURES |= procedure_cases(
    central_receiving_data,
    {
        'LL/CON/CEN/BV-04-C': (
            'Central Receiving Data',
            {},
        ),
    },
)

# Verify simultaneous Central transmission and reception with a Peripheral, including
# acknowledgement and Host DATA delivery.
PROCEDURES |= procedure_cases(
    central_sending_and_receiving_data,
    {
        'LL/CON/CEN/BV-05-C': (
            'Central Sending and Receiving Data',
            {},
        ),
    },
)

# Verify that a Central initiates a connection parameter update, applies the new timing
# at Instant, and reports the new parameters to its Host.
PROCEDURES |= procedure_cases(
    requesting_parameter_update,
    {
        'LL/CON/CEN/BV-07-C': (
            'Requesting Parameter Update',
            {},
        ),
    },
)

# Verify that a Central sends termination, stops transmitting after the Peripheral
# acknowledges, and reports disconnection to its Host.
PROCEDURES |= procedure_cases(
    central_sending_termination,
    {
        'LL/CON/CEN/BV-08-C': (
            'Central Sending Termination',
            {},
        ),
    },
)

# Verify that a Central acknowledges Peripheral termination, stops transmitting and
# reports the peer-requested disconnection to its Host.
PROCEDURES |= procedure_cases(
    central_accepting_termination,
    {
        'LL/CON/CEN/BV-09-C': (
            'Central Accepting Termination',
            {},
        ),
    },
)

# Verify that a Central stops an unmaintained connection on supervision timeout and
# reports the timeout and established handle to its Host.
PROCEDURES |= procedure_cases(
    central_supervision_timer,
    {
        'LL/CON/CEN/BV-10-C': (
            'Central Supervision Timer',
            {},
        ),
    },
)

# Verify that a connected Central initiates Feature Exchange with its declared feature
# set and reports the Peripheral response to its Host.
PROCEDURES |= procedure_cases(
    feature_setup_request,
    {
        'LL/CON/CEN/BV-13-C': (
            'Feature Setup Request',
            {},
        ),
    },
)

# Verify that a Central maintains acknowledgement state and requests retransmission when
# the Peripheral response has an invalid CRC.
PROCEDURES |= procedure_cases(
    central_retransmission_request,
    {
        'LL/CON/CEN/BV-14-C': (
            'Central Retransmission Request',
            {},
        ),
    },
)

# Verify that a Central repeats the same DATA payload when its Peripheral negatively
# acknowledges that packet.
PROCEDURES |= procedure_cases(
    central_retransmission,
    {
        'LL/CON/CEN/BV-15-C': (
            'Central Retransmission',
            {},
        ),
    },
)

# Verify that a Central repeats its positive acknowledgement when the Peripheral
# retransmits an already received DATA packet.
PROCEDURES |= procedure_cases(
    central_acknowledgement_repetition,
    {
        'LL/CON/CEN/BV-16-C': (
            'Central Acknowledgement Repetition',
            {},
        ),
    },
)

# Verify that a Central preserves packet sequence numbering and repeats a negative
# acknowledgement when the Peripheral incorrectly advances to its next packet after a
# lost negative acknowledgement.
PROCEDURES |= procedure_cases(
    central_lost_negative_acknowledgement,
    {
        'LL/CON/CEN/BV-17-C': pytest.param(
            'Central Lost Negative Acknowledgement',
            {},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify Central acknowledgement and retransmission behavior when a Peripheral combines
# latency with invalid-CRC responses.
PROCEDURES |= procedure_cases(
    central_latency_retransmission_request,
    {
        'LL/CON/CEN/BV-18-C': (
            'Central Latency Retransmission Request',
            {},
        ),
    },
)

# Verify that a Central terminates its ACL when an initiated Link Layer control
# procedure receives no response before the transaction timeout.
PROCEDURES |= procedure_cases(
    connection_control_timeout,
    {
        'LL/CON/CEN/BV-19-C': (
            'Connection Control Timeout',
            {},
        ),
    },
)

# Verify normal Central acknowledgement and sequence-number handling while transferring
# data in both directions with a Peripheral.
PROCEDURES |= procedure_cases(
    central_acknowledgement_scheme,
    {
        'LL/CON/CEN/BV-22-C': (
            'Central Acknowledgement Scheme',
            {},
        ),
    },
)

# Verify that a connected Central responds to Peripheral-initiated Feature Exchange
# using the correct peer-visible feature set.
PROCEDURES |= procedure_cases(
    responding_to_feature_exchange,
    {
        'LL/CON/CEN/BV-23-C': (
            'Responding to Feature Exchange',
            {},
        ),
    },
)

# Verify Central-initiated parameter negotiation when the Peripheral accepts, including
# a changed reference event in the response. The IUT may select different parameters
# from the Host's request.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_accept_ll_con_cen_bv_24_c,
    {
        'LL/CON/CEN/BV-24-C': (
            'Initiating Connection Parameter Request – Accept',
            {},
        ),
    },
)

# Verify Central behavior when the Peripheral rejects its connection parameter request,
# accepting either permitted outcome of the procedure.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_reject_ll_con_cen_bv_25_c,
    {
        'LL/CON/CEN/BV-25-C': (
            'Initiating Connection Parameter Request – Reject',
            {},
        ),
    },
)

# Verify that a Central rejects a colliding Peripheral parameter request while
# preserving and completing its own parameter negotiation.
PROCEDURES |= procedure_cases(
    initiating_parameter_request_same_procedure_collision_cen_bv_26,
    {
        'LL/CON/CEN/BV-26-C': (
            'Initiating Connection Parameter Request – same procedure collision',
            {},
        ),
    },
)

# Verify that a Central completes Channel Map Update while rejecting a colliding
# Peripheral Connection Parameters Request.
PROCEDURES |= procedure_cases(
    initiating_parameter_request_channel_map_collision_cen_bv_27,
    {
        'LL/CON/CEN/BV-27-C': (
            (
                'Initiating Connection Parameter Request – different '
                'procedure collision – channel map update'
            ),
            {},
        ),
    },
)

# Verify that a Central completes Encryption Start despite a colliding Peripheral
# parameter request, then completes that deferred negotiation.
PROCEDURES |= procedure_cases(
    initiating_parameter_request_encryption_collision_cen_bv_28,
    {
        'LL/CON/CEN/BV-28-C': (
            (
                'Initiating Connection Parameter Request – different '
                'procedure collision – encryption'
            ),
            {},
        ),
    },
)

# Verify that a Central falls back to Connection Update when a remote Host does not
# support parameter requests or masks the request event.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_remote_legacy_host,
    {
        'LL/CON/CEN/BV-29-C': (
            'Initiating Connection Parameter Request – remote legacy host',
            {},
        ),
    },
)

# Verify that a Central accepts Peripheral parameter requests without a preferred
# periodicity, adopts the selected timing and informs its Host.
PROCEDURES |= procedure_cases(
    accepting_parameter_request_no_preferred_periodicity_cen_bv_30,
    {
        'LL/CON/CEN/BV-30-C': (
            'Accepting Connection Parameter Request – no Preferred_Periodicity',
            {},
        ),
    },
)

# Verify Central acceptance of anchor-only Peripheral parameter requests, retaining
# interval, latency and supervision timeout while moving anchors.
PROCEDURES |= procedure_cases(
    accepting_parameter_request_preferred_anchors_cen_bv_31,
    {
        'LL/CON/CEN/BV-31-C': (
            'Accepting Connection Parameter Request – preferred anchor points only',
            {},
        ),
    },
)

# Verify Central acceptance of Peripheral parameter requests containing preferred
# periodicity and, optionally, preferred anchor points.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request,
    {
        'LL/CON/CEN/BV-32-C': (
            'Accepting Connection Parameter Request – Preferred_Periodicity',
            {'anchors': False},
        ),
        'LL/CON/CEN/BV-33-C': (
            (
                'Accepting Connection Parameter Request – '
                'Preferred_Periodicity and preferred anchor points'
            ),
            {'anchors': True},
        ),
    },
)

# Verify that a Central rejects a Peripheral parameter request requiring Host approval
# when the Host has masked that approval-request event.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_event_masked_ll_con_cen_bv_34_c,
    {
        'LL/CON/CEN/BV-34-C': (
            'Accepting Connection Parameter Request – event masked',
            {},
        ),
    },
)

# Verify that a Central rejects a Peripheral parameter request with the error code
# supplied by its Host's negative reply.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_host_rejects_ll_con_cen_bv_35_c,
    {
        'LL/CON/CEN/BV-35-C': (
            'Accepting Connection Parameter Request – Host rejects',
            {},
        ),
    },
)

# Verify that a Central can initiate PHY Update, select supported symmetric and
# asymmetric PHYs, and maintain the connection on the selected PHYs. The Upper Tester
# issues HCI commands; the Peripheral Lower Tester observes and answers the IUT's Link
# Layer procedure.
PROCEDURES |= procedure_cases(
    initiating_phy_update_procedure_ll_con_cen_bv_41_c,
    {
        'LL/CON/CEN/BV-41-C': (
            'Initiating PHY Update Procedure',
            {},
        ),
    },
)

# Verify that a Central can respond to Peripheral-initiated PHY Update, use supported
# symmetric and asymmetric PHYs, and maintain the connection on the selected PHYs.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_procedure_ll_con_cen_bv_43_c,
    {
        'LL/CON/CEN/BV-43-C': (
            'Responding to PHY Update Procedure',
            {},
        ),
    },
)

# Verify that a Central rejects a colliding Peripheral PHY Update request and then
# completes its own PHY Update procedure. The Upper Tester starts the IUT's local
# procedure; the Lower Tester injects a competing request immediately after receiving
# the IUT request.
PROCEDURES |= procedure_cases(
    handling_protocol_collision_same_procedure_ll_con_cen_bv_45_c,
    {
        'LL/CON/CEN/BV-45-C': (
            'Handling Protocol Collision – Same Procedure',
            {},
        ),
    },
)

# Verify that a Central terminates the Link Layer connection when its PHY Update
# procedure remains incomplete until the response timer expires. The Peripheral Lower
# Tester maintains the connection but withholds the required procedure response.
PROCEDURES |= procedure_cases(
    protocol_timeout_for_phy_update_procedure_ll_con_cen_bv_46_c,
    {
        'LL/CON/CEN/BV-46-C': (
            'Protocol Timeout for PHY Update Procedure',
            {},
        ),
    },
)

# Verify that a Central rejects a Peripheral PHY Update request colliding with the
# Central's Channel Map Update, then completes the map update and maintains the
# connection using the new data-channel selection parameters.
PROCEDURES |= procedure_cases(
    handling_protocol_collision_different_procedure_channel_map_cen_bv_47,
    {
        'LL/CON/CEN/BV-47-C': (
            'Handling Protocol Collision – Different Procedure – Channel Map',
            {},
        ),
    },
)

# Verify that a Central rejects a Peripheral PHY Update request colliding with the
# Central's Connection Parameters Request, then completes its original procedure and
# reports the resulting connection parameters.
PROCEDURES |= procedure_cases(
    handling_connection_parameter_collision_cen_bv_48,
    {
        'LL/CON/CEN/BV-48-C': (
            (
                'Handling Protocol Collision – Different Procedure – '
                'Connection Parameters'
            ),
            {},
        ),
    },
)

# Verify a Central's packet-time restrictions before, during and after its locally
# initiated PHY change from LE 2M to LE 1M, while the Host continues queueing 32-octet
# start packets.
PROCEDURES |= procedure_cases(
    initiating_phy_update_procedure_packet_time_restrictions_ll_con_cen_bv_49_c,
    {
        'LL/CON/CEN/BV-49-C': (
            'Initiating PHY Update Procedure – Packet Time Restrictions',
            {},
        ),
    },
)

# Verify a Central's packet-time restrictions before, during and after a
# Peripheral-initiated change from LE 2M to LE 1M, while the Host continues queueing
# 32-octet start packets.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_packet_time_limits_cen_bv_50,
    {
        'LL/CON/CEN/BV-50-C': (
            'Responding to PHY Update Procedure – Packet Time Restrictions',
            {},
        ),
    },
)

# Verify that a Central correctly completes a locally initiated PHY Update when the
# peer's response provides no common new PHY, retaining the active PHYs and reporting a
# successful no-change completion.
PROCEDURES |= procedure_cases(
    initiating_phy_update_procedure_no_common_phy,
    {
        'LL/CON/CEN/BV-51-C': (
            'Initiating PHY Update Procedure – No Common PHY',
            {},
        ),
    },
)

# Verify that a Central receives Peripheral DATA across transitions between LE Coded S=2
# (500 kbit/s) and S=8 (125 kbit/s), acknowledges every packet within T_IFS tolerance,
# and reports the complete payload to the Host. Exercise both the maximum effective and
# minimum 27-octet payload sizes.
PROCEDURES |= procedure_cases(
    central_receiving_data_le_coded_ci_change,
    {
        'LL/CON/CEN/BV-52-C': (
            'Central Receiving Data, LE Coded, CI Change',
            {},
        ),
    },
)

# Verify a Central's transmit restrictions during a locally initiated change from LE 1M
# to LE Coded. Packets queued during PHY Update must also remain valid if awaiting
# retransmission after the Instant.
PROCEDURES |= procedure_cases(
    initiating_phy_update_packet_time_limits_le_coded_cen_bv_53,
    {
        'LL/CON/CEN/BV-53-C': (
            'Initiating PHY Update Procedure – Packet Time Restrictions, LE Coded',
            {},
        ),
    },
)

# Verify a Central's transmit restrictions during a Peripheral-initiated change from LE
# 1M to LE Coded. Packets queued during PHY Update must also remain valid if awaiting
# retransmission after the Instant.
PROCEDURES |= procedure_cases(
    responding_to_phy_update_packet_time_limits_le_coded_cen_bv_54,
    {
        'LL/CON/CEN/BV-54-C': (
            (
                'Responding to PHY Update Procedure – Packet Time '
                'Restrictions, LE Coded'
            ),
            {},
        ),
    },
)

# Verify that a Central continues transmitting DATA with the mandatory minimum 27-octet
# allowance when negotiated times would otherwise imply a shorter LE Coded packet. The
# source states that the Peripheral Lower Tester initiates PHY Update.
PROCEDURES |= procedure_cases(
    mandatory_minimum_pdu_length_le_coded_ll_con_cen_bv_55_c,
    {
        'LL/CON/CEN/BV-55-C': pytest.param(
            'Mandatory Minimum PDU Length, LE Coded',
            {},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that a Central receives LL_LENGTH_REQ, responds correctly on the selected PHY,
# reports effective-length changes through HCI, and respects the resulting limits while
# transferring data in both directions.
PROCEDURES |= procedure_cases(
    central_data_length_update_responding_to_data_length_update_procedure,
    {
        'LL/CON/CEN/BV-73-C': (
            (
                'Central Data Length Update – Responding to Data Length '
                'Update Procedure; LE 1M PHY'
            ),
            {'phy': Phy.LE_1M},
        ),
        'LL/CON/CEN/BV-76-C': (
            (
                'Central Data Length Update – Responding to Data Length '
                'Update Procedure; LE 2M PHY'
            ),
            {'phy': Phy.LE_2M},
        ),
        'LL/CON/CEN/BV-78-C': (
            (
                'Central Data Length Update – Responding to Data Length '
                'Update Procedure; LE Coded PHY'
            ),
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify that a Central initiates Data Length Update on the selected PHY. The Upper
# Tester requests new transmit limits through HCI; the Peripheral Lower Tester observes
# and answers LL_LENGTH_REQ, then verifies data flow and effective-length reporting.
PROCEDURES |= procedure_cases(
    central_data_length_update_initiating_data_length_update_procedure,
    {
        'LL/CON/CEN/BV-74-C': (
            (
                'Central Data Length Update – Initiating Data Length Update'
                ' Procedure; LE 1M PHY'
            ),
            {'phy': Phy.LE_1M},
        ),
        'LL/CON/CEN/BV-77-C': (
            (
                'Central Data Length Update – Initiating Data Length Update'
                ' Procedure; LE 2M PHY'
            ),
            {'phy': Phy.LE_2M},
        ),
        'LL/CON/CEN/BV-79-C': (
            (
                'Central Data Length Update – Initiating Data Length Update'
                ' Procedure; LE Coded PHY'
            ),
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Verify that a Central handles a Peripheral without Data Length Update support, retains
# the existing effective lengths after LL_UNKNOWN_RSP, and continues data transfer in
# both directions.
PROCEDURES |= procedure_cases(
    central_data_length_update_peripheral_does_not_support_le_1m_phy,
    {
        'LL/CON/CEN/BV-75-C': (
            'Central Data Length Update – Peripheral does not support; LE 1M PHY',
            {},
        ),
    },
)

# Verify that a Central handles a Peripheral without Data Length Update support while
# using LE Coded, retaining the existing effective lengths after LL_UNKNOWN_RSP and
# continuing bidirectional data flow.
PROCEDURES |= procedure_cases(
    central_data_length_update_peripheral_does_not_support_le_coded_phy,
    {
        'LL/CON/CEN/BV-80-C': (
            'Central Data Length Update – Peripheral does not support; LE Coded PHY',
            {},
        ),
    },
)

# Verify that a Central learns from LL_UNKNOWN_RSP that its Peripheral does not support
# Connection Parameter Request, completes the current update through the legacy
# indication, and avoids the unsupported request on the next update of the same
# connection.
PROCEDURES |= procedure_cases(
    initiating_parameter_request_unsupported_without_feature_exchange_cen_bv_81,
    {
        'LL/CON/CEN/BV-81-C': (
            (
                'Initiating Connection Parameter Request – Unsupported '
                'Without Feature Exchange'
            ),
            {},
        ),
    },
)

# Verify that a Central directly uses Connection Update Indication after Feature
# Exchange discloses that its Peripheral does not support Connection Parameter Request.
PROCEDURES |= procedure_cases(
    initiating_parameter_request_unsupported_with_feature_exchange_cen_bv_82,
    {
        'LL/CON/CEN/BV-82-C': (
            (
                'Initiating Connection Parameter Request – Unsupported With'
                ' Feature Exchange'
            ),
            {},
        ),
    },
)

# Verify that a Central keeps both PHYs unchanged when it requests an asymmetric
# connection but the Peripheral's single-PHY response only permits a symmetric
# connection.
PROCEDURES |= procedure_cases(
    phy_update_procedure_central_requests_asymmetrical_peripheral_symmetrical,
    {
        'LL/CON/CEN/BV-117-C': (
            (
                'PHY Update Procedure – Central Requests Asymmetrical, '
                'Peripheral Symmetrical'
            ),
            {},
        ),
    },
)

# Verify that a Central retransmits unacknowledged LL_TERMINATE_IND until T_Terminate
# expires, even while valid Peripheral DATA keeps the ordinary supervision timer alive.
PROCEDURES |= procedure_cases(
    central_t_terminate_timer,
    {
        'LL/CON/CEN/BI-02-C': (
            'Central T_Terminate Timer',
            {},
        ),
    },
)

# Verify that a Central recovers from a stalled Version Exchange through the procedure
# response timeout. The Peripheral Lower Tester acknowledges the IUT's VERSION_IND but
# withholds its own version response while maintaining valid DATA.
PROCEDURES |= procedure_cases(
    central_connection_control_timer,
    {
        'LL/CON/CEN/BI-04-C': (
            'Central Connection Control Timer',
            {},
        ),
    },
)

# Verify that a Central terminates the connection when its Connection Parameter Request
# is acknowledged but the Peripheral never sends the corresponding protocol response.
PROCEDURES |= procedure_cases(
    initiating_connection_parameter_request_timeout_ll_con_cen_bi_05_c,
    {
        'LL/CON/CEN/BI-05-C': (
            'Initiating Connection Parameter Request – Timeout',
            {},
        ),
    },
)

# Verify that a Central rejects a Peripheral Connection Parameter Request whose minimum
# and maximum connection intervals are outside the legal range.
PROCEDURES |= procedure_cases(
    accepting_connection_parameter_request_illegal_parameters_ll_con_cen_bi_06_c,
    {
        'LL/CON/CEN/BI-06-C': (
            'Accepting Connection Parameter Request – illegal parameters',
            {},
        ),
    },
)

# Verify that a Central acknowledges a reserved-LLID packet at the sequence level
# without interpreting its Feature Response payload, then correctly accepts the same
# response with a valid control LLID.
PROCEDURES |= procedure_cases(
    invalid_llid_ll_con_cen_bi_14_c,
    {
        'LL/CON/CEN/BI-14-C': (
            'Invalid LLID',
            {},
        ),
    },
)

# Verify that changing from LE 1M to the selected PHY and back preserves negotiated data
# lengths, except for the mandatory Coded effective-time floor. The Lower Tester never
# initiates Data Length Update.
PROCEDURES |= procedure_cases(
    data_length_update_preserve_parameters_after_a_phy_change,
    {
        'LL/CON/CEN/BV-126-C': (
            (
                'Data Length Update – Preserve Parameters After a PHY '
                'Change – LE 2M PHY'
            ),
            {'central': True, 'phy': Phy.LE_2M},
        ),
        'LL/CON/CEN/BV-127-C': pytest.param(
            (
                'Data Length Update – Preserve Parameters After a PHY '
                'Change – LE Coded PHY'
            ),
            {'central': True, 'phy': Phy.LE_CODED},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
        'LL/CON/PER/BV-129-C': (
            (
                'Data Length Update – Preserve Parameters After a PHY '
                'Change – LE 2M PHY'
            ),
            {'central': False, 'phy': Phy.LE_2M},
        ),
        'LL/CON/PER/BV-130-C': pytest.param(
            (
                'Data Length Update – Preserve Parameters After a PHY '
                'Change – LE Coded PHY'
            ),
            {'central': False, 'phy': Phy.LE_CODED},
            marks=[
                pytest.mark.source_conflict,
            ],
        ),
    },
)

# Verify that a pending retransmission is not refragmented when a Data Length Update
# reduces the permitted packet size.
PROCEDURES |= procedure_cases(
    data_length_update_retransmission_during_an_update,
    {
        'LL/CON/CEN/BV-128-C': (
            'Data Length Update – Retransmission During an Update',
            {'central': True},
        ),
        'LL/CON/PER/BV-131-C': (
            'Data Length Update – Retransmission During an Update',
            {'central': False},
        ),
    },
)

# Verify that, once an LE 1M peer is known not to support LE Coded PHY, outgoing
# length-procedure time fields do not exceed 2128 us and the IUT continues forwarding
# negotiated-size peer DATA to its Host.
PROCEDURES |= procedure_cases(
    data_length_update_peer_does_not_support_le_coded_phy,
    {
        'LL/CON/CEN/BV-129-C': (
            (
                'Data Length Update – Peer Does Not Support LE Coded PHY – '
                'supportedMaxTxTime'
            ),
            {'central': True},
        ),
        'LL/CON/PER/BV-132-C': (
            (
                'Data Length Update – Peer Does Not Support LE Coded PHY – '
                'supportedMaxTxTime'
            ),
            {'central': False},
        ),
    },
)

# Verify that a connected Peripheral initiates and completes Version Exchange with the
# Lower Tester acting as Central.
PROCEDURES |= procedure_cases(
    peripheral_request_version,
    {
        'LL/CON/PER/BV-19-C': (
            'Peripheral Request Version',
            {},
        ),
    },
)

# Verify that a connected Peripheral responds to Version Exchange initiated by the Lower
# Tester acting as Central.
PROCEDURES |= procedure_cases(
    peripheral_respond_version,
    {
        'LL/CON/PER/BV-20-C': (
            'Peripheral Respond Version',
            {},
        ),
    },
)

# Verify that a connected Central initiates and completes Version Exchange with the
# Lower Tester acting as Peripheral.
PROCEDURES |= procedure_cases(
    central_request_version,
    {
        'LL/CON/CEN/BV-20-C': (
            'Central Request Version',
            {},
        ),
    },
)

# Verify that a connected Central responds to Version Exchange initiated by the Lower
# Tester acting as Peripheral.
PROCEDURES |= procedure_cases(
    central_respond_version,
    {
        'LL/CON/CEN/BV-21-C': (
            'Central Respond Version',
            {},
        ),
    },
)

# Verify that an initiating IUT completes Version Exchange and ignores further Version
# Indications from the same peer in the same connection.
PROCEDURES |= procedure_cases(
    version_exchange_iut_requesting,
    {
        'LL/CON/CEN/BI-11-C': (
            'Version Exchange, IUT Requesting',
            {'central': True},
        ),
        'LL/CON/PER/BI-14-C': (
            'Version Exchange, IUT Requesting',
            {'central': False},
        ),
    },
)

# Verify that a responding IUT completes Version Exchange and ignores further Version
# Indications from the same peer in the same connection.
PROCEDURES |= procedure_cases(
    version_exchange_iut_responding,
    {
        'LL/CON/CEN/BI-12-C': (
            'Version Exchange, IUT Responding',
            {'central': True},
        ),
        'LL/CON/PER/BI-15-C': (
            'Version Exchange, IUT Responding',
            {'central': False},
        ),
    },
)

# Verify that an IUT handles simultaneous Version Exchange initiation without sending a
# second local Version Indication.
PROCEDURES |= procedure_cases(
    version_exchange_iut_requesting_collision,
    {
        'LL/CON/CEN/BV-146-C': (
            'Version Exchange, IUT Requesting, Collision',
            {'central': True},
        ),
        'LL/CON/PER/BV-145-C': (
            'Version Exchange, IUT Requesting, Collision',
            {'central': False},
        ),
    },
)

# Verify that an initiating IUT tolerates a delayed peer Version Indication without
# disconnecting or repeating its own indication.
PROCEDURES |= procedure_cases(
    version_exchange_iut_requesting_delayed_response,
    {
        'LL/CON/CEN/BV-147-C': (
            'Version Exchange, IUT Requesting, Delayed Response',
            {'central': True},
        ),
        'LL/CON/PER/BV-147-C': (
            'Version Exchange, IUT Requesting, Delayed Response',
            {'central': False},
        ),
    },
)

# Verify that the IUT rejects a Connection Parameters Request whose Interval_Max is
# smaller than Interval_Min.
PROCEDURES |= procedure_cases(
    reject_invalid_connection_parameter_request_parameters,
    {
        'LL/CON/CEN/BI-13-C': (
            'Reject Invalid Connection Parameter Request Parameters',
            {'central': True},
        ),
        'LL/CON/PER/BI-16-C': (
            'Reject Invalid Connection Parameter Request Parameters',
            {'central': False},
        ),
    },
)

# Verify that the IUT rejects LL_LENGTH_RSP with invalid values in its selected role/PHY
# and continues receiving Lower Tester data.
PROCEDURES |= procedure_cases(
    None,
    {
        'LL/CON/CEN/BI-07-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE 1M PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/CEN/BI-08-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE 2M PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/CEN/BI-09-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE Coded PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/CEN/BI-24-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE 1M PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/CEN/BI-25-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE 2M PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/CEN/BI-26-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE Coded PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/PER/BI-10-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE 1M PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/PER/BI-11-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE 2M PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/PER/BI-12-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE Coded PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/PER/BI-31-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE 1M PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/PER/BI-32-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE 2M PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
        'LL/CON/PER/BI-33-C': pytest.param(
            (
                'Data Length Update – Handling Invalid Data Length '
                'Responses – LE Coded PHY'
            ),
            {},
            marks=[
                pytest.mark.source_conflict,
                pytest.mark.skip(
                    reason=(
                        'Source ambiguity: LL.TS.p28 4.3.7.35, PDF 978-982. '
                        'Table 4.3-117 does not select Step 4A/4B; Table '
                        '4.3-116 ALT 5 conflicts with the event-dependent Step'
                        ' 5. The retry count and final valid-values reference '
                        'also conflict. Core and Amber do not uniquely resolve'
                        ' these branches; no source-faithful verdict is '
                        'claimed.'
                    ),
                ),
            ],
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_connection(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
