# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Discrete asyncio clocks and idle PHY boundaries for Hosts and Controllers."""

from __future__ import annotations

import asyncio
import math
import select
import selectors
import socket
import time
from threading import Event
from typing import Any, Protocol

from bumble.radio_controller.radio import (
    PHY_TIME_UNITS_PER_SECOND,
    RADIO_DEFAULT_MAX_STEP_US,
)


class RadioClock(Protocol):
    @property
    def now_us(self) -> int: ...

    def advance_to_us(self, target_us: int) -> int: ...


class RadioSelector(selectors.BaseSelector):
    def __init__(self, selector: selectors.BaseSelector, max_step_us: int):
        if max_step_us <= 0:
            raise ValueError('max_step_us must be positive')
        self.delegate = selector
        self.clock: RadioClock | None = None
        self.max_step_us = max_step_us

    def register(self, fileobj: Any, events: int, data: Any = None):
        return self.delegate.register(fileobj, events, data)

    def unregister(self, fileobj: Any):
        return self.delegate.unregister(fileobj)

    def modify(self, fileobj: Any, events: int, data: Any = None):
        return self.delegate.modify(fileobj, events, data)

    def get_map(self):
        return self.delegate.get_map()

    def close(self) -> None:
        self.delegate.close()

    def select(self, timeout: float | None = None):
        if self.clock is None:
            return self.delegate.select(timeout)
        ready = self.delegate.select(0)
        if ready or timeout == 0:
            return ready
        step_us = (
            self.max_step_us
            if timeout is None
            else min(
                self.max_step_us, math.ceil(max(0, timeout) * PHY_TIME_UNITS_PER_SECOND)
            )
        )
        if step_us > 0:
            before = self.clock.now_us
            if self.clock.advance_to_us(before + step_us) <= before:
                raise RuntimeError('BabbleSim clock did not advance')
        return self.delegate.select(0)


class RadioEventLoop(asyncio.SelectorEventLoop):
    """The Host waits for its own ACK; Controller threads keep their own clocks."""

    selector_type = RadioSelector

    def __init__(self, max_step_us: int = RADIO_DEFAULT_MAX_STEP_US):
        self.radio_selector = self.selector_type(
            selectors.DefaultSelector(), max_step_us
        )
        self._time_offset = 0.0
        super().__init__(selector=self.radio_selector)

    def time(self) -> float:
        clock = self.radio_selector.clock
        return self._time_offset + (
            clock.now_us / PHY_TIME_UNITS_PER_SECOND
            if clock is not None
            else time.monotonic()
        )

    def bind_clock(self, clock: RadioClock) -> None:
        if self.radio_selector.clock is not None:
            raise RuntimeError('a radio clock is already bound')
        current_time = self.time()
        self.radio_selector.clock = clock
        self._time_offset = current_time - clock.now_us / PHY_TIME_UNITS_PER_SECOND

    def unbind_clock(self) -> None:
        current_time = self.time()
        self.radio_selector.clock = None
        self._time_offset = current_time - time.monotonic()

    def run_forever(self) -> None:
        try:
            super().run_forever()
        except BaseException:
            if self.radio_selector.clock is not None:
                self.unbind_clock()
            raise


class ControllerSelector(RadioSelector):
    """Admit a PHY transaction only after all current ready work has drained."""

    def __init__(self, selector: selectors.BaseSelector, max_step_us: int):
        super().__init__(selector, max_step_us)
        self.pending: tuple[int, asyncio.Future[int | None]] | None = None

    def select(self, timeout: float | None = None):
        if self.pending is None:
            return super().select(timeout)
        ready = self.delegate.select(0)
        if ready or timeout == 0:
            return ready
        start_us, admitted = self.pending
        deadline = (
            self.clock.now_us + math.ceil(timeout * PHY_TIME_UNITS_PER_SECOND)
            if self.clock is not None and timeout is not None
            else None
        )
        if deadline is not None and deadline < start_us:
            # A software timer preceding a scheduled RF start must run first.
            return super().select(timeout)
        self.pending = None
        admitted.set_result(deadline)
        return []


class ControllerEventLoop(RadioEventLoop):
    """One Controller's discrete clock, idle request gate and interruptible PHY I/O."""

    selector_type = ControllerSelector
    radio_selector: ControllerSelector

    def __init__(self, max_step_us: int = RADIO_DEFAULT_MAX_STEP_US):
        super().__init__(max_step_us)
        self._interrupt_read, self._interrupt_write = socket.socketpair()
        self._interrupt_read.setblocking(False)
        self._interrupt_write.setblocking(False)
        self.interrupted = Event()

    async def before_phy_request(self, start_us: int = 0) -> int | None:
        if self.interrupted.is_set():
            raise asyncio.CancelledError
        if self.radio_selector.pending is not None:
            raise RuntimeError('a Controller can have only one pending PHY request')
        admitted = self.create_future()
        pending = (start_us, admitted)
        self.radio_selector.pending = pending
        try:
            return await admitted
        finally:
            if self.radio_selector.pending is pending:
                self.radio_selector.pending = None

    def wait_for_phy_io(self, fd: int, *, write: bool, deadline: float) -> None:
        if self.interrupted.is_set():
            raise asyncio.CancelledError
        readable, writable, _ = select.select(
            [self._interrupt_read] if write else [self._interrupt_read, fd],
            [fd] if write else [],
            [],
            max(0, deadline - time.monotonic()),
        )
        if self._interrupt_read in readable:
            raise asyncio.CancelledError
        if not (fd in readable or fd in writable):
            raise TimeoutError('timed out waiting for BabbleSim PHY')

    def interrupt(self) -> None:
        """Wake a blocked PHY transaction without running Controller callbacks."""
        self.interrupted.set()
        try:
            self._interrupt_write.send(b'!')
        except OSError:
            # Closing a worker can race the owner's final loop.close().
            pass

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._interrupt_read.close()
            self._interrupt_write.close()
