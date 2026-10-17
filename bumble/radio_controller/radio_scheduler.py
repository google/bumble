# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Pure radio reservations; no tasks, clocks, HCI, or simulator operations."""

from dataclasses import dataclass
from enum import IntEnum


class RadioPriority(IntEnum):
    """Fixed arbitration order for equal starts and overlapping radio windows."""

    EXPIRY = -1
    CONNECTION = 0
    PERIODIC_TX = 1
    PERIODIC_RX = 2
    ADVERTISING = 3


@dataclass(frozen=True)
class RadioReservation:
    start_us: int
    duration_us: int
    interval_us: int
    priority: RadioPriority = RadioPriority.CONNECTION

    def window_after(self, time_us: int) -> tuple[int, int]:
        """Include a window already in progress, or the next periodic occurrence."""
        cycles = max(0, (time_us - self.start_us) // self.interval_us)
        start = self.start_us + cycles * self.interval_us
        if start + self.duration_us <= time_us:
            start += self.interval_us
        return start, start + self.duration_us


def higher_priority_overlap(
    reservations: list[RadioReservation],
    start_us: int,
    end_us: int,
    priority: RadioPriority,
) -> bool:
    """Check half-open windows before admitting a nonpreemptive operation."""
    return start_us < end_us and any(
        reservation.priority < priority and start < end_us and end > start_us
        for reservation in reservations
        for start, end in [reservation.window_after(start_us)]
    )


def first_radio_gap(
    reservations: list[RadioReservation],
    start_us: int,
    duration_us: int,
    latest_us: int,
    *,
    quantum_us: int = 1,
) -> int | None:
    """Find a complete nonpreemptive slot on a grid relative to start_us."""
    candidate = start_us
    while candidate <= latest_us:
        conflicts = [
            end
            for reservation in reservations
            for start, end in [reservation.window_after(candidate)]
            if start < candidate + duration_us and end > candidate
        ]
        if not conflicts:
            return candidate
        offset = max(conflicts) - start_us
        candidate = start_us + ((offset + quantum_us - 1) // quantum_us * quantum_us)
    return None
