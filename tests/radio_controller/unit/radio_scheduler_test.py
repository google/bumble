# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Half-open reservations, quantized gaps and fixed-priority admission."""

import pytest

from bumble.radio_controller.radio_scheduler import (
    RadioPriority,
    RadioReservation,
    first_radio_gap,
    higher_priority_overlap,
)


@pytest.mark.parametrize('quantum,expected', [(1, 20), (7, 21)])
def test_radio_gap_checks_full_duration_and_keeps_the_requested_grid(quantum, expected):
    reservation = RadioReservation(5, 15, 50)
    assert first_radio_gap([reservation], 0, 10, 40, quantum_us=quantum) == expected
    assert reservation.window_after(20) == (55, 70)


def test_overloaded_radio_has_no_admissible_window():
    assert first_radio_gap([RadioReservation(0, 10, 10)], 0, 1, 100) is None


@pytest.mark.parametrize(
    'start,end,priority,expected',
    [
        (0, 10, RadioPriority.PERIODIC_TX, False),
        (0, 11, RadioPriority.PERIODIC_TX, True),
        (15, 20, RadioPriority.PERIODIC_TX, True),
        (15, 15, RadioPriority.PERIODIC_TX, False),
        (20, 30, RadioPriority.PERIODIC_TX, False),
        (0, 11, RadioPriority.CONNECTION, False),
        (40, 51, RadioPriority.PERIODIC_TX, True),
    ],
)
def test_overlap_arbitration_uses_full_windows_and_fixed_priority(
    start, end, priority, expected
):
    reservation = RadioReservation(10, 10, 40)
    assert higher_priority_overlap([reservation], start, end, priority) is expected


@pytest.mark.parametrize(
    'time_us,window',
    [
        (0, (10, 15)),
        (10, (10, 15)),
        (14, (10, 15)),
        (15, (30, 35)),
        (55, (70, 75)),
    ],
)
def test_reservations_include_active_windows_and_roll_at_the_exclusive_end(
    time_us, window
):
    assert RadioReservation(10, 5, 20).window_after(time_us) == window


@pytest.mark.parametrize(
    'start,duration,latest,quantum,expected',
    [
        (3, 2, 3, 4, 3),
        (3, 3, 25, 4, 23),
        (3, 3, 22, 4, None),
        (20, 3, 25, 1, 21),
    ],
)
def test_gap_search_rechecks_other_reservations_on_the_request_grid(
    start, duration, latest, quantum, expected
):
    reservations = [RadioReservation(5, 4, 30), RadioReservation(12, 9, 30)]
    assert (
        first_radio_gap(reservations, start, duration, latest, quantum_us=quantum)
        == expected
    )


def test_unreserved_request_can_start_at_its_latest_allowed_time():
    assert first_radio_gap([], 17, 4, 17, quantum_us=5) == 17
