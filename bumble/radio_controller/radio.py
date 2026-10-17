# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Bluetooth LE radio interface, independent of HCI and the simulator."""

from dataclasses import dataclass
from enum import IntEnum
from random import Random
from typing import Protocol

from bumble.hci import PhyBit
from bumble.ll import (
    LL_CHANNEL_ID_BITS,
    LL_CHANNEL_ID_MASK,
    LL_CSA2_MAM_MULTIPLIER,
    LL_CSA2_MAM_ROUNDS,
    LL_DATA_CHANNEL_COUNT,
    LL_EVENT_COUNTER_MASK,
    LL_SCA_PPM,
    PDU_ACCESS_ADDRESS_CODED_LSB_BITS,
    PDU_ACCESS_ADDRESS_CODED_LSB_ONES_MIN,
    PDU_ACCESS_ADDRESS_CODED_TRANSITION_BITS,
    PDU_ACCESS_ADDRESS_CODED_TRANSITIONS_MAX,
    PDU_ACCESS_ADDRESS_CONSECUTIVE_BITS_MAX,
    PDU_ACCESS_ADDRESS_MSB_TRANSITIONS_MIN,
    PDU_ACCESS_ADDRESS_MSB_WINDOW_BITS,
    PDU_ACCESS_ADDRESS_SIZE,
    PDU_ACCESS_ADDRESS_TRANSITIONS_MAX,
    PDU_ADV_ACCESS_ADDRESS,
    PDU_ADV_CRC_INIT,
    PDU_ADV_EXT_PAYLOAD_SIZE_MAX,
    PDU_CRC_POLYNOMIAL_REFLECTED,
    PDU_CRC_SIZE,
    PDU_DATA_PAYLOAD_SIZE_MAX,
    PDU_HEADER_SIZE,
    PDU_PREAMBLE_1M_SIZE,
    PDU_PREAMBLE_2M_SIZE,
)
from bumble.radio_controller.radio_parameters import valid_channel_map

# PHY airtime: Core Vol 6, Part B, 2. Bit counts are before FEC encoding.
PHY_OCTET_BITS = 8
PHY_1M_OCTET_TIME_US = 8
PHY_2M_OCTET_TIME_US = 4
# Preamble, Access Address, Coding Indicator, TERM1.
PHY_CODED_FEC1_TIME_US = 376
# TERM2 is sent with the payload's S=2/S=8 coding.
PHY_CODED_TERM2_SIZE_BITS = 3
# Preamble plus Access Address; excludes Coding Indicator on the Coded PHY.
PHY_1M_ADDRESS_TIME_US = (
    PDU_PREAMBLE_1M_SIZE + PDU_ACCESS_ADDRESS_SIZE
) * PHY_1M_OCTET_TIME_US
PHY_2M_ADDRESS_TIME_US = (
    PDU_PREAMBLE_2M_SIZE + PDU_ACCESS_ADDRESS_SIZE
) * PHY_2M_OCTET_TIME_US
PHY_CODED_ADDRESS_TIME_US = 336
# Core Vol 6, Part A, 2.1: primary advertising-channel center frequencies.
PHY_ADV_CHANNEL_FREQUENCIES_MHZ = {37: 2402, 38: 2426, 39: 2480}

# Data-channel centers skip primary advertising channel 38 at 2426 MHz.
PHY_DATA_CHANNEL_BASE_MHZ = 2404
PHY_DATA_CHANNEL_SPACING_MHZ = 2
PHY_DATA_CHANNEL_GAP_INDEX = 11
# Uncoded on-air bit rates.
PHY_1M_BITRATE_BPS = 1_000_000
PHY_2M_BITRATE_BPS = 2_000_000


# LE Coded payload coding factors, Core Vol 6, Part B, 2.2.
PHY_CODED_S2_FACTOR = 2
PHY_CODED_S8_FACTOR = 8
# Common bit-field and clock-unit conversions.
PHY_OCTET_MASK = (1 << PHY_OCTET_BITS) - 1
PHY_TIME_UNITS_PER_SECOND = 1_000_000
# Radio oscillator model; independent of the peer's advertised SCA category.
RADIO_LOCAL_SCA_PPM = 50
RADIO_CLOCK_JITTER_US = 16
# Hardware preparation when changing channel, PHY, or TX/RX direction.
# This implementation value is absorbed by existing idle time, not added to T_IFS.
RADIO_SWITCH_TIME_US = 60
# Default scan window and advertising interval, not protocol limits.
RADIO_DEFAULT_SCAN_INTERVAL_US = 30_000
RADIO_DEFAULT_ADV_INTERVAL_US = 100_000
RADIO_DIRECT_ADV_INTERVAL_US = 2500
# Response-start tolerance; detection also needs the PHY's preamble and address.
RADIO_RESPONSE_START_TOLERANCE_US = 2
# Connection-event guard and receive-window slack are scheduling policies.
RADIO_CONN_EVENT_GUARD_US = 500
RADIO_CONN_RX_WINDOW_UNCODED_US = 100
RADIO_CONN_RX_WINDOW_CODED_US = 400
# Vendor identifier for this experimental Controller.
RADIO_COMPANY_IDENTIFIER = 0xFFFF
# Past-Instant modulo-65536 distance boundary (LL.TS.p28, BI-09-C, Step 4).
RADIO_INSTANT_PAST_THRESHOLD = 0x7FFF
# Shared default maximum simulation step for Host and Controller loops.
RADIO_DEFAULT_MAX_STEP_US = 1000
# Supported transmit-power range; also used to bound reported RSSI.
RADIO_TX_POWER_MIN_DBM = -127
RADIO_TX_POWER_MAX_DBM = 20

# Advertised HCI buffer capacity, independent of each link's negotiated limits.
RADIO_HCI_ACL_BUFFER_SIZE = PDU_DATA_PAYLOAD_SIZE_MAX
RADIO_SUPPORTED_PHY_MASK = int(PhyBit.LE_1M | PhyBit.LE_2M | PhyBit.LE_CODED)

# Concurrent advertising sets and periodic receive contexts on one radio.
RADIO_ADVERTISING_SET_COUNT = 8
RADIO_PERIODIC_SYNC_COUNT = 8
# Maximum simultaneous ACL contexts, shared by both LE roles.
RADIO_CONNECTION_COUNT = 8
# Controller list capacity, independent of any simulator transport.
RADIO_PERIODIC_ADVERTISER_LIST_SIZE = 8
# Core Vol 4, Part E, 7.5.4: RSSI measurement is not yet available.
RADIO_RSSI_NOT_AVAILABLE = 0x7F
# Core Vol 4, Part E, 7.8.27: legacy single states and two-state combinations.
# Bits above 41 are reserved; this mask does not describe extended-only states.
RADIO_SUPPORTED_STATE_MASK = (1 << 42) - 1
# Primary scanning/initiating PHYs; LE 2M is valid only on secondary channels.
RADIO_PRIMARY_SCAN_PHY_MASK = int(PhyBit.LE_1M | PhyBit.LE_CODED)


class Phy(IntEnum):
    LE_1M = 1
    LE_2M = 2
    LE_CODED = 3

    @property
    def address_us(self) -> int:
        return {
            Phy.LE_1M: PHY_1M_ADDRESS_TIME_US,
            Phy.LE_2M: PHY_2M_ADDRESS_TIME_US,
            Phy.LE_CODED: PHY_CODED_ADDRESS_TIME_US,
        }[self]

    def airtime_us(self, pdu_size: int, coding: int = PHY_CODED_S8_FACTOR) -> int:
        """Preamble through CRC (and TERM2 for Coded), Core Vol 6, Part B, 2."""
        if (
            not PDU_HEADER_SIZE
            <= pdu_size
            <= PDU_HEADER_SIZE + PDU_ADV_EXT_PAYLOAD_SIZE_MAX
        ):
            raise ValueError('invalid LE PDU size')
        if self == Phy.LE_1M:
            return (
                PDU_PREAMBLE_1M_SIZE + PDU_ACCESS_ADDRESS_SIZE + pdu_size + PDU_CRC_SIZE
            ) * PHY_1M_OCTET_TIME_US
        if self == Phy.LE_2M:
            return (
                PDU_PREAMBLE_2M_SIZE + PDU_ACCESS_ADDRESS_SIZE + pdu_size + PDU_CRC_SIZE
            ) * PHY_2M_OCTET_TIME_US
        if coding not in (PHY_CODED_S2_FACTOR, PHY_CODED_S8_FACTOR):
            raise ValueError('LE Coded requires S=2 or S=8')
        return (
            PHY_CODED_FEC1_TIME_US
            + ((pdu_size + PDU_CRC_SIZE) * PHY_OCTET_BITS + PHY_CODED_TERM2_SIZE_BITS)
            * coding
        )


def crc24(pdu: bytes, crc_init: int = PDU_ADV_CRC_INIT) -> bytes:
    state = int(f'{crc_init:0{PDU_CRC_SIZE * PHY_OCTET_BITS}b}'[::-1], 2)
    for byte in pdu:
        for bit in range(PHY_OCTET_BITS):
            feedback = (state & 1) ^ ((byte >> bit) & 1)
            state >>= 1
            if feedback:
                state ^= PDU_CRC_POLYNOMIAL_REFLECTED
    return state.to_bytes(PDU_CRC_SIZE, 'little')


def channel_selection_2(counter: int, access_address: int, channel_map: int) -> int:
    """Core Vol 6, Part B, 4.5.8.3; ascending channel remapping."""
    if not valid_channel_map(channel_map):
        raise ValueError('invalid channel map')
    channel_id = (access_address >> LL_CHANNEL_ID_BITS) ^ (
        access_address & LL_CHANNEL_ID_MASK
    )
    prn = (counter & LL_EVENT_COUNTER_MASK) ^ channel_id
    for _ in range(LL_CSA2_MAM_ROUNDS):
        prn = int(
            f'{prn >> PHY_OCTET_BITS:0{PHY_OCTET_BITS}b}'[::-1], 2
        ) << PHY_OCTET_BITS | int(f'{prn & PHY_OCTET_MASK:0{PHY_OCTET_BITS}b}'[::-1], 2)
        prn = (LL_CSA2_MAM_MULTIPLIER * prn + channel_id) & LL_CHANNEL_ID_MASK
    prn ^= channel_id
    unmapped = prn % LL_DATA_CHANNEL_COUNT
    if channel_map & (1 << unmapped):
        return unmapped
    enabled = [
        index for index in range(LL_DATA_CHANNEL_COUNT) if channel_map & (1 << index)
    ]
    return enabled[(len(enabled) * prn) >> LL_CHANNEL_ID_BITS]


def window_widening(elapsed_us: int, sca: int) -> int:
    """Sleep clock uncertainty: peer SCA, local 50 ppm, instantaneous 16 us."""
    ppm = LL_SCA_PPM[sca]
    return (
        RADIO_CLOCK_JITTER_US
        + (
            max(0, elapsed_us) * (ppm + RADIO_LOCAL_SCA_PPM)
            + PHY_TIME_UNITS_PER_SECOND
            - 1
        )
        // PHY_TIME_UNITS_PER_SECOND
    )


def generate_access_address(generator: Random, used: set[int]) -> int:
    """Seeded data Access Address, valid for uncoded and Coded transmission."""
    width = PDU_ACCESS_ADDRESS_SIZE * PHY_OCTET_BITS
    while True:
        value = generator.getrandbits(width)
        if value in used or (value ^ PDU_ADV_ACCESS_ADDRESS).bit_count() <= 1:
            continue
        bits = f'{value:0{width}b}'
        run = PDU_ACCESS_ADDRESS_CONSECUTIVE_BITS_MAX + 1
        transitions = value ^ (value >> 1)
        msb = value >> (width - PDU_ACCESS_ADDRESS_MSB_WINDOW_BITS)
        if (
            '0' * run in bits
            or '1' * run in bits
            or len(set(value.to_bytes(PDU_ACCESS_ADDRESS_SIZE, 'little'))) == 1
            or (transitions & ((1 << (width - 1)) - 1)).bit_count()
            > PDU_ACCESS_ADDRESS_TRANSITIONS_MAX
            or (
                (msb ^ (msb >> 1))
                & ((1 << (PDU_ACCESS_ADDRESS_MSB_WINDOW_BITS - 1)) - 1)
            ).bit_count()
            < PDU_ACCESS_ADDRESS_MSB_TRANSITIONS_MIN
            or (value & ((1 << PDU_ACCESS_ADDRESS_CODED_LSB_BITS) - 1)).bit_count()
            < PDU_ACCESS_ADDRESS_CODED_LSB_ONES_MIN
            or (
                transitions
                & ((1 << (PDU_ACCESS_ADDRESS_CODED_TRANSITION_BITS - 1)) - 1)
            ).bit_count()
            > PDU_ACCESS_ADDRESS_CODED_TRANSITIONS_MAX
        ):
            continue
        return value


@dataclass(frozen=True)
class Received:
    """Packet bounds are half-open; now_us remains the actual PHY grant time."""

    pdu: bytes
    rssi: float
    start_us: int
    end_us: int
    valid_crc: bool
    phy: Phy = Phy.LE_1M
    coding: int = 0


class Radio(Protocol):
    @property
    def now_us(self) -> int: ...

    def earliest_start_us(self, channel: int, phy: Phy, *, transmit: bool) -> int: ...

    async def advance_to_us(self, target_us: int) -> int: ...

    async def transmit(
        self,
        channel: int,
        pdu: bytes,
        *,
        start_us: int | None = None,
        access_address: int = PDU_ADV_ACCESS_ADDRESS,
        crc_init: int = PDU_ADV_CRC_INIT,
        phy: Phy = Phy.LE_1M,
        coding: int = PHY_CODED_S8_FACTOR,
        power_dbm: int = 0,
    ) -> int: ...

    async def receive(
        self,
        channel: int,
        until_us: int,
        *,
        start_us: int | None = None,
        access_address: int = PDU_ADV_ACCESS_ADDRESS,
        crc_init: int = PDU_ADV_CRC_INIT,
        accept_bad_crc: bool = False,
        phy: Phy = Phy.LE_1M,
    ) -> Received | None: ...


@dataclass
class RadioSwitch:
    """Track the last occupied boundary; no RF operation occurs during switching."""

    switch_time_us: int = RADIO_SWITCH_TIME_US
    state: tuple[int, Phy, bool] | None = None
    end_us: int = 0

    def __post_init__(self) -> None:
        if self.switch_time_us < 0:
            raise ValueError('radio switching time must be nonnegative')

    def earliest_start_us(
        self, now_us: int, channel: int, phy: Phy, *, transmit: bool
    ) -> int:
        switching = self.state is not None and self.state != (channel, phy, transmit)
        return max(now_us + 1, self.end_us + (self.switch_time_us if switching else 0))

    def complete(self, channel: int, phy: Phy, *, transmit: bool, end_us: int) -> None:
        self.state = (channel, phy, transmit)
        self.end_us = end_us
