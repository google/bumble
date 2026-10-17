# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Deterministic RF doubles and controller setup for implementation tests."""

from collections import deque
from dataclasses import replace
from itertools import pairwise

from bumble import hci
from bumble.hci import HCI_LE_ADV_INTERVAL_MIN, HCI_LE_PERIODIC_SYNC_TIMEOUT_MIN
from bumble.ll import (
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    PDU_ACCESS_ADDRESS_CODED_LSB_BITS,
    PDU_ACCESS_ADDRESS_CODED_LSB_ONES_MIN,
    PDU_ACCESS_ADDRESS_CODED_TRANSITION_BITS,
    PDU_ACCESS_ADDRESS_CODED_TRANSITIONS_MAX,
    PDU_ACCESS_ADDRESS_SIZE,
    PDU_ADV_ACCESS_ADDRESS,
)
from bumble.radio_controller.radio import (
    PHY_CODED_S8_FACTOR,
    PHY_OCTET_BITS,
    Phy,
    RadioSwitch,
    Received,
)
from bumble.radio_controller.radio_advertising import AuxPtr, ExtendedPdu, SyncInfo
from bumble.radio_controller.radio_connection import Connection
from bumble.radio_controller.radio_discovery import PeriodicSync
from bumble.radio_controller.radio_parameters import Parameters

PEER_ADDRESS = hci.Address('C0:11:22:33:44:55', hci.AddressType.RANDOM_DEVICE)
TX_POWER_NO_PREFERENCE = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.TX_POWER_NO_PREFERENCE
)

# Fixed wire vector for isolated implementation checks, not Controller defaults.
PARAMETERS = Parameters(
    0x9A328370,
    0x123456,
    1,
    0,
    24,
    0,
    100,
    (1 << 37) - 1,
    7,
)


class FakeRadio:
    now_us = 0

    def __init__(self):
        self.sent = []
        self.incoming = deque()
        self.switch = RadioSwitch()

    def earliest_start_us(self, channel, phy, *, transmit):
        return self.switch.earliest_start_us(
            self.now_us, channel, phy, transmit=transmit
        )

    async def advance_to_us(self, target):
        self.now_us = target
        return target

    async def transmit(self, channel, pdu, *, start_us=None, **parameters):
        phy = Phy(parameters.get('phy', Phy.LE_1M))
        ready = self.earliest_start_us(channel, phy, transmit=True)
        start_us = ready if start_us is None else start_us
        assert start_us >= ready
        self.sent.append((start_us, channel, pdu, parameters))
        self.now_us = (
            start_us
            + Phy(parameters.get('phy', Phy.LE_1M)).airtime_us(
                len(pdu), parameters.get('coding', PHY_CODED_S8_FACTOR)
            )
            - 1
        )
        self.switch.complete(channel, phy, transmit=True, end_us=self.now_us + 1)
        return self.now_us + 1

    async def receive(self, channel, until_us, **parameters):
        phy = Phy(parameters.get('phy', Phy.LE_1M))
        start = max(
            parameters.get('start_us') or self.now_us + 1,
            self.earliest_start_us(channel, phy, transmit=False),
        )
        if start >= until_us:
            await self.advance_to_us(until_us)
            return None
        if self.incoming:
            packet = self.incoming.popleft()
            self.now_us = packet.end_us - 1
            self.switch.complete(channel, phy, transmit=False, end_us=packet.end_us)
            return packet
        self.now_us = until_us
        self.switch.complete(channel, phy, transmit=False, end_us=self.now_us + 1)
        return None


def check_access_address(value):
    """Independent bit-string oracle for generated addresses, including Coded PHY."""
    assert (value ^ PDU_ADV_ACCESS_ADDRESS).bit_count() > 1
    bits = f'{value:0{PDU_ACCESS_ADDRESS_SIZE * PHY_OCTET_BITS}b}'
    assert '0' * 7 not in bits and '1' * 7 not in bits
    assert len(set(value.to_bytes(PDU_ACCESS_ADDRESS_SIZE, 'little'))) > 1
    assert sum(left != right for left, right in pairwise(bits)) <= 24
    assert sum(left != right for left, right in pairwise(bits[:6])) >= 2
    assert bits[-PDU_ACCESS_ADDRESS_CODED_LSB_BITS:].count('1') >= (
        PDU_ACCESS_ADDRESS_CODED_LSB_ONES_MIN
    )
    coded = bits[-PDU_ACCESS_ADDRESS_CODED_TRANSITION_BITS:]
    assert sum(left != right for left, right in pairwise(coded)) <= (
        PDU_ACCESS_ADDRESS_CODED_TRANSITIONS_MAX
    )


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


def add_connection(first, index, role=hci.Role.CENTRAL):
    first.report_created()
    link = first.link
    result = Connection(
        link,
        replace(
            first.parameters, access_address=first.parameters.access_address ^ index
        ),
        hci.Address(f'F0:F1:F2:F3:F4:{index + 2:02X}', hci.AddressType.PUBLIC_DEVICE),
        role,
        0,
    )
    link.connections[result.handle] = result
    result.report_created()
    return result


def received_packet(pdu, start_us, phy=Phy.LE_1M):
    wire = pdu.encode() if isinstance(pdu, ExtendedPdu) else pdu
    return Received(
        wire, -40, start_us, start_us + phy.airtime_us(len(wire)), True, phy
    )


async def bind_candidate(connection, *, skip=0, timeout_us=100_000):
    link = connection.link
    link.connections.clear()
    sync = PeriodicSync(connection.peer, 3, timeout_us, 0, skip=skip)
    link.sync = sync
    # Searching may outlive the Host's established-synchronization timeout.
    link.radio.now_us = 3 * timeout_us
    start = link.radio.now_us + 1000
    info = SyncInfo(
        9000,
        80,
        LL_DATA_CHANNEL_MAP_ALL,
        PARAMETERS.access_address,
        PARAMETERS.crc_init,
        LL_EVENT_COUNTER_MASK - 1,
    )
    primary = received_packet(ExtendedPdu(adi=0x3001, aux_ptr=AuxPtr(12, 600)), start)
    auxiliary = received_packet(
        ExtendedPdu(
            address=bytes(connection.peer),
            random_address=connection.peer.is_random,
            adi=0x3001,
            sync_info=info,
            data=b'announcement',
        ),
        start + 600,
    )
    link.radio.now_us = primary.end_us - 1
    link.radio.incoming.append(auxiliary)
    await link.extended.scan(primary)
    return sync, info, auxiliary
