# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Scan-window arbitration, backoff and wrapping periodic channel maps."""

import pytest

from bumble import hci
from bumble.core import AdvertisingData
from bumble.ll import (
    LL_CHANNEL_MAP_SIZE,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
)
from bumble.radio_controller.radio import Phy
from bumble.radio_controller.radio_advertising import SyncInfo
from bumble.radio_controller.radio_discovery import (
    PeriodicSync,
    ScanBackoff,
    ScanWindow,
    scan_window_at,
)
from tests.radio_controller.unit.helpers import PARAMETERS

PEER_ADDRESS = hci.Address('C0:12:34:56:78:9A')


def test_scan_backoff_two_failures_and_two_successes():
    import random

    backoff = ScanBackoff()
    generator = random.Random(0)
    assert backoff.permit()
    backoff.complete(False, generator)
    assert backoff.upper_limit == 1
    assert backoff.permit()
    backoff.complete(False, generator)
    assert backoff.upper_limit == backoff.count == 2
    assert not backoff.permit() and backoff.permit()
    backoff.complete(True, generator)
    backoff.complete(True, generator)
    assert backoff.upper_limit == backoff.count == 1


def test_scan_backoff_limits_and_streak_reset():
    import random

    backoff = ScanBackoff()
    generator = random.Random(0)
    for _ in range(20):
        backoff.complete(False, generator)
    assert backoff.upper_limit == 256 and 1 <= backoff.count <= 256
    backoff.complete(True, generator)
    backoff.complete(False, generator)
    assert backoff.successes == 0 and backoff.failures == 1
    for _ in range(20):
        backoff.complete(True, generator)
    assert backoff.upper_limit == backoff.count == 1


@pytest.mark.parametrize(
    'elapsed,phy,cycle,end',
    [
        (0, Phy.LE_1M, 0, 10_000),
        (9999, Phy.LE_1M, 0, 10_000),
        (10_000, Phy.LE_CODED, 0, 20_000),
        (19_999, Phy.LE_CODED, 0, 20_000),
        (20_000, Phy.LE_1M, 1, 30_000),
        (30_000, Phy.LE_CODED, 1, 40_000),
        (40_000, Phy.LE_1M, 2, 50_000),
        (50_000, Phy.LE_CODED, 2, 60_000),
    ],
)
def test_dual_phy_windows_preserve_each_twenty_ms_interval(elapsed, phy, cycle, end):
    windows = (
        ScanWindow(Phy.LE_1M, 20_000, 10_000),
        ScanWindow(Phy.LE_CODED, 20_000, 10_000),
    )
    selected, actual_cycle, boundary = scan_window_at(windows, elapsed)
    assert selected.phy == phy and actual_cycle == cycle and boundary == end


@pytest.mark.parametrize(
    'elapsed,phy,cycle,end',
    [
        (0, Phy.LE_1M, 0, 20_000),
        (20_000, Phy.LE_CODED, 0, 40_000),
        (40_000, Phy.LE_1M, 1, 60_000),
        (60_000, Phy.LE_CODED, 1, 80_000),
        (80_000, Phy.LE_1M, 2, 100_000),
        (100_000, Phy.LE_CODED, 2, 120_000),
    ],
)
def test_continuous_scan_on_both_phys_shares_radio_without_starvation(
    elapsed, phy, cycle, end
):
    windows = (
        ScanWindow(Phy.LE_1M, 20_000, 20_000),
        ScanWindow(Phy.LE_CODED, 20_000, 20_000),
    )
    selected, actual_cycle, boundary = scan_window_at(windows, elapsed)
    assert selected.phy == phy and actual_cycle == cycle and boundary == end


@pytest.mark.parametrize(
    'elapsed,phy,end',
    [
        (0, Phy.LE_1M, 5000),
        (5000, Phy.LE_CODED, 10_000),
        (10_000, None, 30_000),
        (29_999, None, 30_000),
        (30_000, Phy.LE_1M, 35_000),
        (35_000, Phy.LE_CODED, 40_000),
    ],
)
def test_dual_phy_scan_gaps_do_not_spin_or_advance_a_channel_early(elapsed, phy, end):
    windows = (
        ScanWindow(Phy.LE_1M, 30_000, 5000),
        ScanWindow(Phy.LE_CODED, 30_000, 5000),
    )
    selected, _, boundary = scan_window_at(windows, elapsed)
    assert (selected.phy if selected else None) == phy
    assert boundary == end and boundary > elapsed


@pytest.mark.parametrize(
    'elapsed,phy,end',
    [
        (30_000, Phy.LE_1M, 35_000),
        (35_000, Phy.LE_1M, 40_000),
        (50_000, Phy.LE_CODED, 55_000),
    ],
)
def test_unequal_intervals_arbitrate_overlaps_without_changing_periods(
    elapsed, phy, end
):
    windows = (
        ScanWindow(Phy.LE_1M, 30_000, 10_000),
        ScanWindow(Phy.LE_CODED, 20_000, 5000),
    )
    selected, _, boundary = scan_window_at(windows, elapsed)
    assert selected.phy == phy and boundary == end


@pytest.mark.parametrize('counter', [10, LL_EVENT_COUNTER_MASK - 2])
@pytest.mark.parametrize('skip', [1, 4])
def test_periodic_map_applies_at_or_across_instant(counter, skip):
    info = SyncInfo(
        9000,
        80,
        LL_DATA_CHANNEL_MAP_ALL,
        PARAMETERS.access_address,
        PARAMETERS.crc_init,
        counter,
    )
    sync = PeriodicSync(PEER_ADDRESS, 3, 100_000, 0, info=info, counter=counter)
    instant = (counter + 3) & LL_EVENT_COUNTER_MASK
    channels = 0b10101
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
    sync.receive_channel_map(acad)
    sync.receive_channel_map(acad)
    sync.counter = (counter + 2) & LL_EVENT_COUNTER_MASK
    sync.apply_channel_map()
    assert sync.info.channel_map == LL_DATA_CHANNEL_MAP_ALL
    sync.counter = (sync.counter + skip) & LL_EVENT_COUNTER_MASK
    sync.apply_channel_map()
    assert sync.info.channel_map == channels and sync.channel_map_update is None
    sync.apply_channel_map()
    assert sync.info.channel_map == channels


@pytest.mark.parametrize(
    'channels,instant,length',
    [
        (1, 20, 7),
        (LL_DATA_CHANNEL_MAP_ALL + 1, 20, 7),
        (3, 9, 7),
        (3, 20, 6),
        (3, 20, 8),
    ],
)
def test_periodic_invalid_channel_map_acad_is_ignored(channels, instant, length):
    sync = PeriodicSync(PEER_ADDRESS, 3, 100_000, 0, counter=10)
    value = (
        channels.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
        + instant.to_bytes(2, 'little')
        + b'\x00'
    )[:length]
    sync.receive_channel_map(
        bytes(
            AdvertisingData(
                [(AdvertisingData.Type.CHANNEL_MAP_UPDATE_INDICATION, value)]
            )
        )
    )
    assert sync.channel_map_update is None
