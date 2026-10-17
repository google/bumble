# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Connectionless LE contexts, scan windows/backoff and periodic channel maps.

The Controller configures these records; RadioLink owns and executes active
contexts. No context performs RF I/O or owns an event loop.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field, replace

from bumble.core import AdvertisingData
from bumble.hci import Address
from bumble.ll import (
    LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
    LL_CHANNEL_MAP_SIZE,
    LL_EVENT_COUNTER_MASK,
    LL_SCAN_BACKOFF_COUNT_MAX,
    LL_SCAN_BACKOFF_COUNT_MIN,
    LL_SCAN_BACKOFF_OUTCOME_COUNT,
    LL_SCAN_BACKOFF_SCALE,
    PDU_CONTROL_INSTANT_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import (
    RADIO_DEFAULT_ADV_INTERVAL_US,
    RADIO_INSTANT_PAST_THRESHOLD,
    Phy,
)
from bumble.radio_controller.radio_advertising import SyncInfo
from bumble.radio_controller.radio_parameters import Parameters, valid_channel_map


@dataclass
class Advertising:
    address: Address
    random_address: Address | None = None
    interval_us: int = RADIO_DEFAULT_ADV_INTERVAL_US
    interval_max_us: int = RADIO_DEFAULT_ADV_INTERVAL_US
    channel_map: int = LL_ADV_PRIMARY_CHANNEL_MAP_ALL
    pdu_type: int = AdvertisingPduType.ADV_NONCONN_IND
    data: bytearray = field(default_factory=bytearray)
    scan_response: bytearray = field(default_factory=bytearray)
    enabled: bool = False
    next_us: int = 0
    extended: bool = False
    sid: int = 0
    did: int = 0
    periodic_interval: int = 0
    periodic_data: bytearray = field(default_factory=bytearray)
    periodic_enabled: bool = False
    periodic_next_us: int = 0
    periodic_counter: int = 0
    # Assigned when periodic advertising is enabled, not while configuring a set.
    periodic_aa: int = 0
    periodic_crc: int = 0
    events: int = 0
    target: Address | None = None
    high_duty: bool = False
    deadline_us: int = 0
    max_events: int = 0
    primary_phy: Phy = Phy.LE_1M
    secondary_phy: Phy = Phy.LE_1M
    mode: int = AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
    notify_scan_request: bool = False
    filter_policy: int = 0
    anonymous: bool = False
    tx_power_dbm: int = 0
    include_tx_power: bool = False

    def __post_init__(self) -> None:
        # Public HCI records and RF procedures share mutable advertising buffers.
        if not isinstance(self.data, bytearray):
            self.data = bytearray(self.data)
        if not isinstance(self.scan_response, bytearray):
            self.scan_response = bytearray(self.scan_response)
        if not isinstance(self.periodic_data, bytearray):
            self.periodic_data = bytearray(self.periodic_data)


@dataclass
class ScanWindow:
    phy: Phy
    interval_us: int
    window_us: int
    active: bool = False


def scan_window_at(
    windows: tuple[ScanWindow, ...], elapsed_us: int
) -> tuple[ScanWindow | None, int, int]:
    """Phase PHY windows while preserving each PHY's own interval and channel cycle."""
    phase = 0
    active = []
    boundaries = []
    round_us = sum(window.window_us for window in windows)
    for index, window in enumerate(windows):
        if elapsed_us < phase:
            boundaries.append(phase)
        else:
            # Overcommitted scan windows share a round, without starving a PHY.
            interval = max(window.interval_us, round_us)
            cycle, offset = divmod(elapsed_us - phase, interval)
            start = phase + cycle * interval
            if offset < window.window_us:
                active.append((start, -index, window, cycle))
                boundaries.append(start + window.window_us)
            else:
                boundaries.append(start + interval)
        phase += window.window_us
    if active:
        _, _, window, cycle = max(active, key=lambda entry: entry[:2])
        return window, cycle, min(boundaries)
    return None, 0, min(boundaries)


@dataclass
class ScanBackoff:
    count: int = LL_SCAN_BACKOFF_COUNT_MIN
    upper_limit: int = LL_SCAN_BACKOFF_COUNT_MIN
    successes: int = 0
    failures: int = 0

    def permit(self) -> bool:
        self.count = max(0, self.count - 1)
        return self.count == 0

    def complete(self, success: bool, generator: random.Random) -> None:
        self.successes = self.successes + 1 if success else 0
        self.failures = self.failures + 1 if not success else 0
        if self.successes == LL_SCAN_BACKOFF_OUTCOME_COUNT:
            self.upper_limit = max(
                LL_SCAN_BACKOFF_COUNT_MIN, self.upper_limit // LL_SCAN_BACKOFF_SCALE
            )
            self.successes = 0
        elif self.failures == LL_SCAN_BACKOFF_OUTCOME_COUNT:
            self.upper_limit = min(
                LL_SCAN_BACKOFF_COUNT_MAX, self.upper_limit * LL_SCAN_BACKOFF_SCALE
            )
            self.failures = 0
        self.count = generator.randint(LL_SCAN_BACKOFF_COUNT_MIN, self.upper_limit)


@dataclass
class Scanning:
    address: Address
    interval_us: int
    window_us: int
    active: bool = False
    start_us: int = 0
    windows: tuple[ScanWindow, ...] = ()
    duration_us: int = 0
    period_us: int = 0
    deadline_us: int = 0
    filter_policy: int = 0
    backoff: ScanBackoff = field(default_factory=ScanBackoff)


@dataclass
class Initiating:
    address: Address
    peer: Address
    interval_us: int
    window_us: int
    parameters: Parameters
    start_us: int
    windows: tuple[ScanWindow, ...] = ()
    phy_parameters: dict[Phy, Parameters] | None = None
    filter_policy: int = 0


@dataclass
class PeriodicSync:
    address: Address
    sid: int
    timeout_us: int
    deadline_us: int
    skip: int = 0
    reports_enabled: bool = True
    info: SyncInfo | None = None
    next_us: int = 0
    counter: int = 0
    last_rx_us: int = 0
    established: bool = False
    phy: Phy = Phy.LE_1M
    use_list: bool = False
    handle: int = 0
    channel_map_update: tuple[int, int] | None = None

    def receive_channel_map(self, acad: bytes) -> None:
        structures = AdvertisingData.from_bytes(acad)
        if bytes(structures) != acad:
            return
        for value in structures.get_all(
            AdvertisingData.Type.CHANNEL_MAP_UPDATE_INDICATION, raw=True
        ):
            if len(value) != LL_CHANNEL_MAP_SIZE + PDU_CONTROL_INSTANT_SIZE:
                continue
            channels = int.from_bytes(value[:LL_CHANNEL_MAP_SIZE], 'little')
            instant = int.from_bytes(value[LL_CHANNEL_MAP_SIZE:], 'little')
            if not valid_channel_map(channels):
                continue
            if (
                instant - self.counter
            ) & LL_EVENT_COUNTER_MASK >= RADIO_INSTANT_PAST_THRESHOLD:
                continue
            self.channel_map_update = (instant, channels)

    def apply_channel_map(self) -> None:
        if self.channel_map_update is None:
            return
        instant, channels = self.channel_map_update
        if (
            self.counter - instant
        ) & LL_EVENT_COUNTER_MASK < RADIO_INSTANT_PAST_THRESHOLD:
            assert self.info is not None
            self.info = replace(self.info, channel_map=channels)
            self.channel_map_update = None

    @property
    def event_step(self) -> int:
        return self.skip + 1 if self.established else 1
