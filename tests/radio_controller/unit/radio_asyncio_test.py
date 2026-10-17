# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Simulation clocks, ready-work draining and PHY admission gates."""

import asyncio
import selectors
import socket
import time
from threading import Event, Thread
from unittest.mock import Mock

import pytest

from bumble.radio_controller.radio_asyncio import (
    ControllerEventLoop,
    RadioEventLoop,
    RadioSelector,
)

requires_runner = pytest.mark.skipif(
    not hasattr(asyncio, 'Runner'), reason='asyncio.Runner requires Python 3.11'
)


class Clock:
    def __init__(self):
        self.now_us = 0
        self.targets = []

    def advance_to_us(self, target_us):
        self.targets.append(target_us)
        self.now_us = target_us
        return target_us


@pytest.mark.parametrize(
    'timeout,target', [(None, 1000), (0.002, 1000), (0.0000011, 2)]
)
def test_idle_selector_advances_bounded_simulation_time(timeout, target):
    delegate = Mock(spec=selectors.BaseSelector)
    delegate.select.return_value = []
    selector = RadioSelector(delegate, 1000)
    clock = selector.clock = Clock()
    assert selector.select(timeout) == []
    assert clock.targets == [target]


def test_ready_io_and_nonblocking_polls_never_advance_time():
    delegate = Mock(spec=selectors.BaseSelector)
    delegate.select.return_value = [('ready', selectors.EVENT_READ)]
    selector = RadioSelector(delegate, 1000)
    clock = selector.clock = Clock()
    assert selector.select(1) == delegate.select.return_value
    delegate.select.return_value = []
    assert selector.select(0) == []
    assert clock.targets == []


def test_unbound_selector_keeps_wall_clock_wait():
    delegate = Mock(spec=selectors.BaseSelector)
    RadioSelector(delegate, 1000).select(0.25)
    delegate.select.assert_called_once_with(0.25)


def test_invalid_step_and_clock_must_advance():
    delegate = Mock(spec=selectors.BaseSelector)
    delegate.select.return_value = []
    with pytest.raises(ValueError, match='positive'):
        RadioSelector(delegate, 0)
    selector = RadioSelector(delegate, 1000)
    selector.clock = Mock(now_us=0, advance_to_us=Mock(return_value=0))
    with pytest.raises(RuntimeError, match='did not advance'):
        selector.select(1)


@requires_runner
def test_clock_failure_unbinds_loop_so_runner_can_finalize_tasks():
    clock = Clock()
    finalized = []
    with asyncio.Runner(loop_factory=RadioEventLoop) as runner:
        loop = runner.get_loop()

        async def exercise():
            loop.bind_clock(clock)
            clock.advance_to_us = Mock(side_effect=RuntimeError('broken PHY'))
            try:
                await asyncio.Future()
            finally:
                finalized.append(True)

        with pytest.raises(RuntimeError, match='broken PHY'):
            runner.run(exercise())
        assert loop.radio_selector.clock is None
    assert finalized == [True]


@requires_runner
@pytest.mark.parametrize('loop_factory', [RadioEventLoop, ControllerEventLoop])
def test_event_loop_sleep_timeout_and_socket_use_standard_asyncio(loop_factory):
    clock = Clock()
    with asyncio.Runner(loop_factory=loop_factory) as runner:
        loop = runner.get_loop()
        before = loop.time()
        loop.bind_clock(clock)
        assert loop.time() == pytest.approx(before, abs=0.001)
        with pytest.raises(RuntimeError, match='already bound'):
            loop.bind_clock(Clock())

        async def exercise():
            start = loop.time()
            await asyncio.sleep(0.025)
            assert loop.time() - start == pytest.approx(0.025, abs=0.000002)
            assert clock.targets[:2] == [1_000, 2_000]
            assert all(
                after - before <= 1_000
                for before, after in zip([0, *clock.targets], clock.targets)
            )
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(asyncio.Event().wait(), 0.005)
            reader, writer = socket.socketpair()
            try:
                reader.setblocking(False)
                writer.sendall(b'packet')
                now = clock.now_us
                assert await loop.sock_recv(reader, 6) == b'packet'
                assert clock.now_us == now
            finally:
                reader.close()
                writer.close()

        runner.run(exercise())
        current = loop.time()
        loop.unbind_clock()
        assert loop.time() == pytest.approx(current, abs=0.001)


@requires_runner
def test_worker_can_enqueue_hci_but_host_cannot_execute_during_wait():
    events = []
    entered, released = Event(), Event()
    clock = Clock()
    with asyncio.Runner(loop_factory=RadioEventLoop) as runner:
        loop = runner.get_loop()

        def worker():
            assert entered.wait(5)
            loop.call_soon_threadsafe(events.append, 'host')
            events.append('controller')
            released.set()

        def advance(target):
            entered.set()
            assert released.wait(5)
            assert events == ['controller']
            clock.now_us = target
            return target

        clock.advance_to_us = advance
        thread = Thread(target=worker)
        thread.start()

        async def exercise():
            loop.bind_clock(clock)
            completed = loop.create_future()
            loop.call_later(0.001, completed.set_result, None)
            await completed
            loop.unbind_clock()
            assert events == ['controller', 'host']

        try:
            runner.run(exercise())
        finally:
            released.set()
            thread.join(5)
            assert not thread.is_alive()


@requires_runner
def test_controller_gate_drains_nested_callbacks_tasks_and_ready_io():
    clock = Clock()
    events = []
    reader, writer = socket.socketpair()
    try:
        with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
            loop = runner.get_loop()
            loop.bind_clock(clock)

            async def notification():
                events.append('task')
                loop.call_soon(events.append, 'notification')

            def on_read():
                assert reader.recv(1) == b'x'
                loop.remove_reader(reader)
                loop.call_soon(loop.create_task, notification())

            def nested(depth):
                events.append(depth)
                if depth:
                    loop.call_soon(nested, depth - 1)

            async def exercise():
                loop.add_reader(reader, on_read)
                writer.sendall(b'x')
                loop.call_soon(nested, 8)
                assert await loop.before_phy_request() is None
                assert [item for item in events if isinstance(item, int)] == list(
                    range(8, -1, -1)
                )
                assert events.index('notification') > events.index('task')
                assert clock.targets == []
                loop.unbind_clock()

            runner.run(exercise())
    finally:
        reader.close()
        writer.close()


@requires_runner
def test_controller_gate_services_timer_before_future_radio_start():
    clock = Clock()
    events = []
    with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
        loop = runner.get_loop()
        loop.bind_clock(clock)

        async def exercise():
            loop.call_later(0.002, lambda: events.append(clock.now_us))
            limit = await loop.before_phy_request(start_us=3_000)
            assert events == [pytest.approx(2_000, abs=1)]
            assert limit is None
            assert clock.now_us < 3_000
            loop.unbind_clock()

        runner.run(exercise())


@requires_runner
def test_controller_wait_deadline_uses_simulation_timer():
    clock = Clock()
    with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
        loop = runner.get_loop()
        loop.bind_clock(clock)

        async def exercise():
            timer = loop.call_later(0.0005, lambda: None)
            try:
                limit = await loop.before_phy_request()
                assert limit == pytest.approx(500, abs=1)
                assert clock.targets == []
            finally:
                timer.cancel()
                loop.unbind_clock()

        runner.run(exercise())


@requires_runner
def test_controller_rejects_overlapping_requests_and_clears_cancelled_gate():
    with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
        loop = runner.get_loop()

        async def exercise():
            first = asyncio.create_task(loop.before_phy_request())
            await asyncio.sleep(0)
            with pytest.raises(RuntimeError, match='one pending PHY request'):
                await loop.before_phy_request()
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            assert loop.radio_selector.pending is None
            assert await loop.before_phy_request() is None
            loop.interrupt()
            with pytest.raises(asyncio.CancelledError):
                await loop.before_phy_request()

        runner.run(exercise())


@requires_runner
def test_controller_phy_io_watchdog_and_closed_loop_interrupt():
    reader, writer = socket.socketpair()
    try:
        with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
            loop = runner.get_loop()
            with pytest.raises(TimeoutError, match='waiting for BabbleSim'):
                loop.wait_for_phy_io(
                    reader.fileno(), write=False, deadline=time.monotonic()
                )
        loop.interrupt()
    finally:
        reader.close()
        writer.close()
