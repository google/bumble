# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI upper tester and RX-driven raw-PDU lower tester; no Host or peer Controller."""

import asyncio
import struct
from dataclasses import dataclass
from itertools import pairwise

from bumble import hci
from bumble.hci import (
    HCI_LE_ADV_INTERVAL_MIN,
    HCI_LE_EXT_ADV_DATA_FRAGMENT_SIZE_MAX,
    HCI_LE_PERIODIC_SYNC_TIMEOUT_MIN,
)
from bumble.ll import (
    LL_CHANNEL_ID_BITS,
    LL_CHANNEL_ID_MASK,
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_CSA2_MAM_MULTIPLIER,
    LL_CSA2_MAM_ROUNDS,
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_MAFS_US,
    PDU_ACCESS_ADDRESS_CODED_LSB_BITS,
    PDU_ACCESS_ADDRESS_CODED_LSB_ONES_MIN,
    PDU_ACCESS_ADDRESS_CODED_TRANSITION_BITS,
    PDU_ACCESS_ADDRESS_CODED_TRANSITIONS_MAX,
    PDU_ACCESS_ADDRESS_SIZE,
    PDU_ADV_ACCESS_ADDRESS,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_ADI_SIZE,
    PDU_ADV_AUX_CHANNEL_MASK,
    PDU_ADV_AUX_OFFSET_UNITS_MASK,
    PDU_ADV_AUX_PTR_SIZE,
    PDU_ADV_CHSEL_MASK,
    PDU_ADV_CRC_INIT,
    PDU_ADV_CTE_INFO_SIZE,
    PDU_ADV_EXT_FIELDS_OFFSET,
    PDU_ADV_EXT_FLAGS_RESERVED_MASK,
    PDU_ADV_EXT_HEADER_LENGTH_BITS,
    PDU_ADV_EXT_HEADER_OFFSET,
    PDU_ADV_EXT_HEADER_SIZE_MAX,
    PDU_ADV_EXT_TX_POWER_MASK,
    PDU_ADV_OFFSET_30_RANGE_US,
    PDU_ADV_OFFSET_BITS,
    PDU_ADV_OFFSET_UNIT_30_US,
    PDU_ADV_OFFSET_UNIT_300_US,
    PDU_ADV_OFFSET_VALUE_MASK,
    PDU_ADV_RXADD_MASK,
    PDU_ADV_SYNC_INFO_SIZE,
    PDU_ADV_TX_POWER_SIZE,
    PDU_ADV_TXADD_MASK,
    PDU_ADV_TYPE_MASK,
    PDU_CRC_SIZE,
    PDU_HEADER_SIZE,
    PDU_PREAMBLE_1M_SIZE,
    PDU_PREAMBLE_2M_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import (
    PHY_1M_OCTET_TIME_US,
    PHY_2M_OCTET_TIME_US,
    PHY_CODED_S8_FACTOR,
    PHY_OCTET_BITS,
    Phy,
)
from bumble.radio_controller.radio_babblesim import (
    HEADER,
    NEVER,
    TIME,
    TX,
    TX_END,
    TX_REQUEST,
)

AdvType = hci.HCI_LE_Set_Advertising_Parameters_Command.AdvertisingType
TX_POWER_NO_PREFERENCE = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.TX_POWER_NO_PREFERENCE
)
ErrorCode = hci.HCI_ErrorCode
DUT_ADDRESS = hci.Address('F0:F1:F2:F3:F4:01', hci.AddressType.PUBLIC_DEVICE)
PEER_ADDRESS = hci.Address('C0:11:22:33:44:55', hci.AddressType.RANDOM_DEVICE)

# LL.TS.p28, 4.1.5.2: default lower-tester addresses in the respective roles.
LOWER_CENTRAL_PUBLIC_ADDRESS = hci.Address(
    '12:34:56:78:9A:BC', hci.AddressType.PUBLIC_DEVICE
)
LOWER_PERIPHERAL_PUBLIC_ADDRESS = hci.Address(
    '45:67:89:AB:CD:EF', hci.AddressType.PUBLIC_DEVICE
)

# LL.TS.p28, 4.1.4.1: default data Access Address for an advertising/Peripheral DUT.
LOWER_DATA_ACCESS_ADDRESS = 0x456789AB


def check_access_address(value, *, phy=Phy.LE_1M):
    """Independent data Access Address constraints (Core Vol6, PartB,2.1.2)."""
    assert (value ^ PDU_ADV_ACCESS_ADDRESS).bit_count() > 1
    bits = f'{value:0{PDU_ACCESS_ADDRESS_SIZE * PHY_OCTET_BITS}b}'
    assert '0' * 7 not in bits and '1' * 7 not in bits
    assert len(set(value.to_bytes(PDU_ACCESS_ADDRESS_SIZE, 'little'))) > 1
    assert sum(left != right for left, right in pairwise(bits)) <= 24
    assert sum(left != right for left, right in pairwise(bits[:6])) >= 2
    if phy == Phy.LE_CODED:
        assert bits[-PDU_ACCESS_ADDRESS_CODED_LSB_BITS:].count('1') >= (
            PDU_ACCESS_ADDRESS_CODED_LSB_ONES_MIN
        )
        coded = bits[-PDU_ACCESS_ADDRESS_CODED_TRANSITION_BITS:]
        assert sum(left != right for left, right in pairwise(coded)) <= (
            PDU_ACCESS_ADDRESS_CODED_TRANSITIONS_MAX
        )


class HciProbe:
    def __init__(self, output=None):
        self.events = []
        self.changed = asyncio.Event()
        self.input = None
        self.advance = None
        self.output = output

    def send(self, packet):
        if self.output is not None:
            self.output.write(f'HCI TX {packet.hex()}\n')
            self.output.flush()
        self.input.on_packet(packet)

    def on_packet(self, packet):
        if self.output is not None:
            self.output.write(f'HCI RX {packet.hex()}\n')
            self.output.flush()
        self.events.append(hci.HCI_Packet.from_bytes(packet))
        self.changed.set()

    def take(self, predicate):
        for index, event in enumerate(self.events):
            if predicate(event):
                return self.events.pop(index)
        return None

    async def expect(self, predicate):
        for _ in range(100):
            event = self.take(predicate)
            if event is not None:
                return event
            if self.advance is None:
                self.changed.clear()
                await asyncio.wait_for(self.changed.wait(), 5)
            else:
                # HCI input is consumed at Controller step boundaries, not at wall time.
                await self.advance(1000)
                # Drain all HCI events from that grant, including cancellation
                # completion.
                await self.advance(0)
        raise AssertionError('HCI event absent after 100 ms of simulation')

    async def command(self, command, status=ErrorCode.SUCCESS):
        self.send(bytes(command))
        event = await self.expect(
            lambda event: (
                isinstance(
                    event,
                    (hci.HCI_Command_Complete_Event, hci.HCI_Command_Status_Event),
                )
                and event.command_opcode == command.op_code
            )
        )
        expected = (
            hci.HCI_Command_Status_Event
            if isinstance(command, hci.HCI_AsyncCommand)
            else hci.HCI_Command_Complete_Event
        )
        assert isinstance(event, expected)
        assert event.num_hci_command_packets == 1
        parameters = (
            event
            if isinstance(event, hci.HCI_Command_Status_Event)
            else event.return_parameters
        )
        actual = (
            parameters.data[0]
            if isinstance(parameters, hci.HCI_GenericReturnParameters)
            else parameters[0] if isinstance(parameters, bytes) else parameters.status
        )
        allowed = status if isinstance(status, tuple) else (status,)
        assert actual in allowed, (command.name, actual, status)
        return parameters

    async def event(self, event_type):
        if event_type == hci.HCI_LE_Connection_Complete_Event:
            event_type = (
                hci.HCI_LE_Connection_Complete_Event,
                hci.HCI_LE_Enhanced_Connection_Complete_Event,
            )
        return await self.expect(lambda event: isinstance(event, event_type))

    async def masks(self, *, general=(1 << 64) - 1, le=(1 << 64) - 1):
        await self.command(
            hci.HCI_Set_Event_Mask_Command(general.to_bytes(8, 'little'))
        )
        await self.command(hci.HCI_LE_Set_Event_Mask_Command(le.to_bytes(8, 'little')))


class AirTester(HciProbe):
    def __init__(self, radio, worker, output):
        super().__init__(output)
        self.radio = radio
        self.input = worker
        self.advance = self.wait

    async def command(self, command, status=ErrorCode.SUCCESS):
        # Inject HCI only after the other endpoint has submitted its next PHY request.
        await self.wait(0)
        return await super().command(command, status)

    async def wait(self, duration_us):
        target = self.radio.now_us + duration_us
        # Equal-time WAIT is a real PHY barrier; Radio.advance_to_us would skip it.
        self.radio.connection.wait_sync(target, 5)
        self.radio.now_us = target
        # Dispatch HCI already queued by the completed device grant before advancing
        # again.
        await asyncio.sleep(0)

    async def receive(self, channel, *, duration_us=100_000, **parameters):
        packet = await asyncio.wait_for(
            self.radio.receive(channel, self.radio.now_us + duration_us, **parameters),
            5,
        )
        await self.wait(0)
        if packet is not None:
            self.output.write(
                f'RX {channel} {packet.start_us} {packet.end_us} {packet.pdu.hex()}\n'
            )
            self.output.flush()
        return packet

    async def expect_pdu(self, channel=37, *, kind=None, **parameters):
        packet = await self.receive(channel, **parameters)
        assert packet is not None, f'no PDU on channel {channel}'
        assert (
            len(packet.pdu) >= PDU_HEADER_SIZE
            and packet.pdu[1] == len(packet.pdu) - PDU_HEADER_SIZE
        )
        assert packet.valid_crc
        if kind is not None:
            assert packet.pdu[0] & PDU_ADV_TYPE_MASK == kind
        return packet

    async def transmit(
        self,
        channel,
        pdu,
        *,
        start_us=None,
        bad_crc=False,
        access_address=PDU_ADV_ACCESS_ADDRESS,
        crc_init=PDU_ADV_CRC_INIT,
        phy=Phy.LE_1M,
        coding=PHY_CODED_S8_FACTOR,
    ):
        start_us = self.radio.now_us + 100 if start_us is None else start_us
        self.output.write(f'TX {channel} {start_us} {pdu.hex()} crc_bad={bad_crc}\n')
        self.output.flush()
        if not bad_crc:
            end = await asyncio.wait_for(
                self.radio.transmit(
                    channel,
                    pdu,
                    start_us=start_us,
                    access_address=access_address,
                    crc_init=crc_init,
                    phy=phy,
                    coding=coding,
                ),
                5,
            )
            await self.wait(0)
            return end
        # Fault injection changes the on-air CRC, not the DUT's receive result.
        from bumble.radio_controller.radio import crc24

        crc = crc24(pdu, crc_init)
        # LL.TS common invalid-CRC data inverts all 24 checksum bits.
        packet = pdu + bytes(octet ^ 0xFF for octet in crc)
        connection = self.radio.connection
        connection.begin_request()
        try:
            request = TX.pack(
                start_us,
                start_us
                + (
                    len(packet)
                    + PDU_ACCESS_ADDRESS_SIZE
                    + (
                        PDU_PREAMBLE_2M_SIZE
                        if phy == Phy.LE_2M
                        else PDU_PREAMBLE_1M_SIZE
                    )
                )
                * (PHY_2M_OCTET_TIME_US if phy == Phy.LE_2M else PHY_1M_OCTET_TIME_US)
                - 1,
                NEVER,
                NEVER,
                access_address,
                *self.radio.params(channel, phy),
                0,
                len(packet),
            )
            await connection.send(HEADER.pack(TX_REQUEST) + request + packet)
            await asyncio.wait_for(connection.response(TX_END), 5)
            self.radio.now_us = TIME.unpack(await connection.receive(TIME.size))[0]
        finally:
            connection.end_request()
        await self.wait(0)
        return self.radio.now_us + 1


class MultiAirTester(AirTester):
    """Allow independent raw peer radios to serve PHY grants on the tester loop.

    The DUT remains isolated in its own thread. Only this fixture's auxiliary
    lower testers run while the upper tester awaits its own WAIT_END.
    """

    async def wait(self, duration_us):
        target = self.radio.now_us + duration_us
        self.radio.now_us = await asyncio.wait_for(
            self.radio.connection.wait(target), 5
        )
        await asyncio.sleep(0)


def legacy_parameters(**changes):
    values = {
        'advertising_interval_min': HCI_LE_ADV_INTERVAL_MIN,
        'advertising_interval_max': HCI_LE_ADV_INTERVAL_MIN,
        'advertising_type': AdvType.ADV_IND,
        'own_address_type': hci.OwnAddressType.PUBLIC,
        'peer_address_type': hci.AddressType.PUBLIC_DEVICE,
        'peer_address': hci.Address.ANY,
        'advertising_channel_map': 1,
        'advertising_filter_policy': 0,
    }
    return hci.HCI_LE_Set_Advertising_Parameters_Command(**(values | changes))


def extended_parameters(**changes):
    values = {
        'advertising_handle': 0,
        'advertising_event_properties': 0,
        'primary_advertising_interval_min': HCI_LE_ADV_INTERVAL_MIN,
        'primary_advertising_interval_max': HCI_LE_ADV_INTERVAL_MIN,
        'primary_advertising_channel_map': 1,
        'own_address_type': hci.OwnAddressType.PUBLIC,
        'peer_address_type': hci.AddressType.PUBLIC_DEVICE,
        'peer_address': hci.Address.ANY,
        'advertising_filter_policy': 0,
        'advertising_tx_power': TX_POWER_NO_PREFERENCE,
        'primary_advertising_phy': Phy.LE_1M,
        'secondary_advertising_max_skip': 0,
        'secondary_advertising_phy': Phy.LE_1M,
        'advertising_sid': 3,
        'scan_request_notification_enable': 0,
    }
    return hci.HCI_LE_Set_Extended_Advertising_Parameters_Command(**(values | changes))


def scan_parameters(*, extended=False, **changes):
    if extended:
        values = {
            'own_address_type': hci.OwnAddressType.PUBLIC,
            'scanning_filter_policy': 0,
            'scanning_phys': hci.PhyBit.LE_1M,
            'scan_types': [0],
            'scan_intervals': [48],
            'scan_windows': [48],
        }
        return hci.HCI_LE_Set_Extended_Scan_Parameters_Command(**(values | changes))
    values = {
        'le_scan_type': 0,
        'le_scan_interval': 48,
        'le_scan_window': 48,
        'own_address_type': hci.OwnAddressType.PUBLIC,
        'scanning_filter_policy': 0,
    }
    return hci.HCI_LE_Set_Scan_Parameters_Command(**(values | changes))


def create_connection(*, extended=False, **changes):
    values = {
        'initiator_filter_policy': 0,
        'own_address_type': hci.OwnAddressType.PUBLIC,
        'peer_address_type': hci.AddressType.RANDOM_DEVICE,
        'peer_address': PEER_ADDRESS,
    }
    if extended:
        values |= {
            'initiating_phys': hci.PhyBit.LE_1M,
            'scan_intervals': [48],
            'scan_windows': [48],
            'connection_interval_mins': [24],
            'connection_interval_maxs': [24],
            'max_latencies': [0],
            'supervision_timeouts': [100],
            'min_ce_lengths': [0],
            'max_ce_lengths': [0],
        }
        return hci.HCI_LE_Extended_Create_Connection_Command(**(values | changes))
    values |= {
        'le_scan_interval': 48,
        'le_scan_window': 48,
        'connection_interval_min': 24,
        'connection_interval_max': 24,
        'max_latency': 0,
        'supervision_timeout': 100,
        'min_ce_length': 0,
        'max_ce_length': 0,
    }
    return hci.HCI_LE_Create_Connection_Command(**(values | changes))


def create_sync(**changes):
    values = {
        'options': 0,
        'advertising_sid': 3,
        'advertiser_address_type': hci.AddressType.RANDOM_DEVICE,
        'advertiser_address': PEER_ADDRESS,
        'skip': 0,
        'sync_timeout': HCI_LE_PERIODIC_SYNC_TIMEOUT_MIN,
        'sync_cte_type': 0,
    }
    return hci.HCI_LE_Periodic_Advertising_Create_Sync_Command(**(values | changes))


def extended_enable(enable=1, handle=0):
    return hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
        enable, [handle], [0], [0]
    )


def adv_pdu(
    kind=AdvertisingPduType.ADV_IND, *, address=PEER_ADDRESS, data=b'test', csa2=False
):
    payload = bytes(address) + data
    return (
        bytes(
            [
                kind
                | int(address.is_random) * PDU_ADV_TXADD_MASK
                | int(csa2) * PDU_ADV_CHSEL_MASK,
                len(payload),
            ]
        )
        + payload
    )


def request_pdu(kind, advertiser=DUT_ADDRESS, *, scanner=PEER_ADDRESS, data=b''):
    payload = bytes(scanner) + bytes(advertiser) + data
    return (
        bytes(
            [
                kind
                | int(scanner.is_random) * PDU_ADV_TXADD_MASK
                | int(advertiser.is_random) * PDU_ADV_RXADD_MASK,
                len(payload),
            ]
        )
        + payload
    )


def ext_pdu(
    *,
    address=None,
    adi=None,
    aux=None,
    sync=None,
    cte=None,
    tx_power=None,
    data=b'',
    mode=AdvertisingMode.NONCONNECTABLE_NONSCANNABLE,
    target=None,
    kind=AdvertisingPduType.ADV_EXT_IND,
    acad=b'',
):
    fields = (
        (1, bytes(address) if address is not None else None),
        (2, bytes(target) if target is not None else None),
        (4, bytes([cte]) if cte is not None else None),
        (8, struct.pack('<H', adi) if adi is not None else None),
        (16, aux),
        (32, sync),
        (
            PDU_ADV_EXT_TX_POWER_MASK,
            struct.pack('<b', tx_power) if tx_power is not None else None,
        ),
    )
    flags = sum(flag for flag, value in fields if value is not None)
    header = (
        bytes([flags])
        + b''.join(value for _, value in fields if value is not None)
        + acad
        if flags or acad
        else b''
    )
    body = bytes([len(header) | mode << PDU_ADV_EXT_HEADER_LENGTH_BITS]) + header + data
    return (
        bytes(
            [
                kind
                | (
                    int(address.is_random) * PDU_ADV_TXADD_MASK
                    if address is not None
                    else 0
                )
                | (
                    int(target.is_random) * PDU_ADV_RXADD_MASK
                    if target is not None
                    else 0
                ),
                len(body),
            ]
        )
        + body
    )


def decode_extended(pdu):
    assert (
        pdu[0] & PDU_ADV_TYPE_MASK
        in (AdvertisingPduType.ADV_EXT_IND, AdvertisingPduType.AUX_CONNECT_RSP)
        and pdu[1] == len(pdu) - PDU_HEADER_SIZE
    )
    length = pdu[PDU_HEADER_SIZE] & PDU_ADV_EXT_HEADER_SIZE_MAX
    end = PDU_ADV_EXT_HEADER_OFFSET + length
    assert end <= len(pdu)
    fields, offset = {}, PDU_ADV_EXT_FIELDS_OFFSET
    if length:
        assert not pdu[PDU_ADV_EXT_HEADER_OFFSET] & PDU_ADV_EXT_FLAGS_RESERVED_MASK
        for flag, name, size in (
            (1, 'address', PDU_ADV_ADDRESS_SIZE),
            (2, 'target', PDU_ADV_ADDRESS_SIZE),
            (4, 'cte', PDU_ADV_CTE_INFO_SIZE),
            (8, 'adi', PDU_ADV_ADI_SIZE),
            (16, 'aux', PDU_ADV_AUX_PTR_SIZE),
            (32, 'sync', PDU_ADV_SYNC_INFO_SIZE),
            (PDU_ADV_EXT_TX_POWER_MASK, 'power', PDU_ADV_TX_POWER_SIZE),
        ):
            if pdu[PDU_ADV_EXT_HEADER_OFFSET] & flag:
                assert offset + size <= end
                fields[name] = pdu[offset : offset + size]
                offset += size
        if offset < end:
            fields['acad'] = pdu[offset:end]
    fields['data'] = pdu[end:]
    return fields


def aux_pointer(channel, offset_us, phy=Phy.LE_1M):
    unit = (
        PDU_ADV_OFFSET_UNIT_30_US
        if offset_us < PDU_ADV_OFFSET_30_RANGE_US
        else PDU_ADV_OFFSET_UNIT_300_US
    )
    assert offset_us % unit == 0 and 1 <= offset_us // unit <= PDU_ADV_OFFSET_VALUE_MASK
    return (
        channel
        | (PDU_ADV_AUX_OFFSET_UNITS_MASK if unit == PDU_ADV_OFFSET_UNIT_300_US else 0)
        | (offset_us // unit) << PHY_OCTET_BITS
        | (phy - 1) << (PHY_OCTET_BITS + PDU_ADV_OFFSET_BITS)
    ).to_bytes(PDU_ADV_AUX_PTR_SIZE, 'little')


def decode_aux(data):
    value = int.from_bytes(data, 'little')
    return value & PDU_ADV_AUX_CHANNEL_MASK, (
        (value >> PHY_OCTET_BITS) & PDU_ADV_OFFSET_VALUE_MASK
    ) * (
        PDU_ADV_OFFSET_UNIT_300_US
        if value & PDU_ADV_AUX_OFFSET_UNITS_MASK
        else PDU_ADV_OFFSET_UNIT_30_US
    )


async def follow_auxiliary(tester, packet, fields, **parameters):
    value = int.from_bytes(fields['aux'], 'little')
    phy = Phy((value >> (PHY_OCTET_BITS + PDU_ADV_OFFSET_BITS)) + 1)
    channel, offset = decode_aux(fields['aux'])
    unit = (
        PDU_ADV_OFFSET_UNIT_300_US
        if value & PDU_ADV_AUX_OFFSET_UNITS_MASK
        else PDU_ADV_OFFSET_UNIT_30_US
    )
    following = await tester.expect_pdu(
        channel,
        start_us=packet.start_us + offset - unit,
        duration_us=offset + 3000,
        **(parameters | {'phy': phy}),
    )
    assert (
        packet.start_us + offset <= following.start_us < packet.start_us + offset + unit
    )
    assert following.start_us - packet.end_us >= LL_MAFS_US
    return channel, following, decode_extended(following.pdu)


async def set_extended_data(tester, data, *, response=False, preference=0, handle=0):
    command = (
        hci.HCI_LE_Set_Extended_Scan_Response_Data_Command
        if response
        else hci.HCI_LE_Set_Extended_Advertising_Data_Command
    )
    operation = hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation
    limit = HCI_LE_EXT_ADV_DATA_FRAGMENT_SIZE_MAX
    if len(data) <= limit:
        await tester.command(command(handle, operation.COMPLETE_DATA, preference, data))
        return
    for offset in range(0, len(data), limit):
        fragment = (
            operation.FIRST_FRAGMENT
            if offset == 0
            else (
                operation.LAST_FRAGMENT
                if offset + limit >= len(data)
                else operation.INTERMEDIATE_FRAGMENT
            )
        )
        await tester.command(
            command(handle, fragment, preference, data[offset : offset + limit])
        )


@dataclass
class LinkParameters:
    # Fixed lower-tester stimuli, independent of the DUT's random allocator.
    access_address: int = 0x9A328370
    crc_init: int = 0x123456
    window_size: int = LL_CONN_WINDOW_SIZE_MIN
    window_offset: int = 0
    interval: int = 24
    latency: int = 0
    timeout: int = 100
    channel_map: int = LL_DATA_CHANNEL_MAP_ALL
    hop_sca: int = 7

    def encode(self):
        return struct.pack(
            '<I3sBHHHH5sB',
            self.access_address,
            self.crc_init.to_bytes(PDU_CRC_SIZE, 'little'),
            self.window_size,
            self.window_offset,
            self.interval,
            self.latency,
            self.timeout,
            self.channel_map.to_bytes(LL_CHANNEL_MAP_SIZE, 'little'),
            self.hop_sca,
        )

    @classmethod
    def decode(cls, data):
        aa, crc, size, offset, interval, latency, timeout, channels, hop = (
            struct.unpack('<I3sBHHHH5sB', data)
        )
        return cls(
            aa,
            int.from_bytes(crc, 'little'),
            size,
            offset,
            interval,
            latency,
            timeout,
            int.from_bytes(channels, 'little'),
            hop,
        )


def csa2_mam(value, channel_id):
    value = ((value & 0xAAAA) >> 1) | ((value & 0x5555) << 1)
    value = ((value & 0xCCCC) >> 2) | ((value & 0x3333) << 2)
    value = ((value & 0xF0F0) >> 4) | ((value & 0x0F0F) << 4)
    return (LL_CSA2_MAM_MULTIPLIER * value + channel_id) & LL_CHANNEL_ID_MASK


def csa2_prn(counter, aa):
    # Independent octet permutation form of the Core channel-selection algorithm.
    channel_id = (aa >> LL_CHANNEL_ID_BITS) ^ (aa & LL_CHANNEL_ID_MASK)
    value = counter ^ channel_id
    for _ in range(LL_CSA2_MAM_ROUNDS):
        value = csa2_mam(value, channel_id)
    return channel_id, value


def csa2_channel(counter, aa, channel_map):
    channel_id, value = csa2_prn(counter, aa)
    value ^= channel_id
    channel = value % LL_DATA_CHANNEL_COUNT
    enabled = [
        index for index in range(LL_DATA_CHANNEL_COUNT) if channel_map & (1 << index)
    ]
    return (
        channel
        if channel in enabled
        else enabled[len(enabled) * value // (LL_CHANNEL_ID_MASK + 1)]
    )


async def chain(
    tester,
    packet,
    fields,
    *,
    forbidden=('address', 'target', 'sync'),
    expected_phy=None,
    **parameters,
):
    """Reassemble a raw auxiliary chain and check ADI and every AuxPtr timing bound."""
    if expected_phy is not None:
        assert packet.phy == expected_phy
    data = fields['data']
    adi = None if 'adi' in forbidden else fields.get('adi')
    while 'aux' in fields:
        _, packet, fields = await follow_auxiliary(tester, packet, fields, **parameters)
        if expected_phy is not None:
            assert packet.phy == expected_phy
        assert packet.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
        assert fields.get('adi') == adi
        assert (
            packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS
            == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
        )
        assert all(field not in fields for field in forbidden)
        data += fields['data']
    return data


async def receive_extended(tester, *, phy=Phy.LE_1M, primary_phy=Phy.LE_1M):
    primary = await tester.expect_pdu(
        kind=AdvertisingPduType.ADV_EXT_IND, duration_us=200_000, phy=primary_phy
    )
    fields = decode_extended(primary.pdu)
    channel, auxiliary, fields = await follow_auxiliary(tester, primary, fields)
    assert auxiliary.phy == phy
    assert (
        fields['adi'][:PDU_ADV_ADI_SIZE]
        == decode_extended(primary.pdu)['adi'][:PDU_ADV_ADI_SIZE]
    )
    return channel, auxiliary, fields
