# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Thread-owned Controllers with packet-only HCI handoff to the Host loop."""

from __future__ import annotations

import asyncio
import sys
from concurrent.futures import Future
from functools import partial
from queue import Empty, SimpleQueue
from threading import Event, Thread

from bumble.controller import Controller
from bumble.radio_controller.controller_backend import RadioBackend
from bumble.radio_controller.radio import (
    PHY_TIME_UNITS_PER_SECOND,
    RADIO_DEFAULT_MAX_STEP_US,
)
from bumble.radio_controller.radio_asyncio import ControllerEventLoop
from bumble.radio_controller.radio_babblesim import BabbleSimRadio


class _ControllerOutput:
    def __init__(self, worker):
        self.worker = worker

    def on_packet(self, packet: bytes) -> None:
        if self.worker.sink is not None:
            self.worker._host_loop.call_soon_threadsafe(
                self.worker.sink.on_packet, packet
            )


# Wall-clock watchdog for terminating the worker thread.
RADIO_WORKER_JOIN_TIMEOUT_SECONDS = 5.0


class RadioControllerWorker:
    """An HCI source/sink whose Controller is constructed and used in one thread.

    Host input is consumed only between radio steps. Enqueuing a packet does not
    wake the Controller out of a pending PHY request.
    """

    def __init__(
        self,
        name: str,
        public_address: str = '00:00:00:00:00:00',
        *,
        max_step_us: int = RADIO_DEFAULT_MAX_STEP_US,
    ):
        if max_step_us <= 0:
            raise ValueError('max_step_us must be positive')
        self.name = name
        self.public_address = public_address
        self.max_step_us = max_step_us
        self.sink = None
        self._input: SimpleQueue[bytes] = SimpleQueue()
        self._ready: Future[None] = Future()
        self._result: Future[None] = Future()
        self._stopping = Event()
        self._thread: Thread | None = None
        self._loop: ControllerEventLoop | None = None
        self._task: asyncio.Task | None = None
        self._host_loop = asyncio.get_running_loop()
        self.terminated: asyncio.Future[None] = self._host_loop.create_future()

    def set_packet_sink(self, sink) -> None:
        if self._thread is not None:
            raise RuntimeError('attach the Host before starting the Controller')
        self.sink = sink

    def on_packet(self, packet: bytes) -> None:
        self.check()
        self._input.put(bytes(packet))

    def check(self) -> None:
        if self._result.done():
            self._result.result()
            raise RuntimeError('Controller worker has stopped')

    async def start(self, sim_id: str, dev_id: int) -> None:
        if self._thread is not None:
            raise RuntimeError('Controller worker is already started')
        self._thread = Thread(
            target=self._run, args=(sim_id, dev_id), name=f'radio:{self.name}'
        )
        self._thread.start()
        # Shield the cross-thread Future so cancellation cannot race set_result().
        await asyncio.shield(asyncio.wrap_future(self._ready))

    def _run(self, sim_id: str, dev_id: int) -> None:
        try:
            if sys.version_info < (3, 11):
                raise RuntimeError('radio workers require Python 3.11 or newer')
            with asyncio.Runner(
                loop_factory=partial(ControllerEventLoop, self.max_step_us)
            ) as runner:
                loop = runner.get_loop()
                assert isinstance(loop, ControllerEventLoop)
                self._loop = loop
                runner.run(self._drive(sim_id, dev_id))
        except asyncio.CancelledError:
            self._ready.cancel()
            self._result.set_result(None)
        except BaseException as error:  # noqa: BLE001 - report thread failure to owner.
            if not self._ready.done():
                self._ready.set_exception(error)
            self._result.set_exception(error)
        else:
            self._result.set_result(None)
        finally:
            self._host_loop.call_soon_threadsafe(self._terminate)

    def _terminate(self) -> None:
        if not self.terminated.done():
            self.terminated.set_result(None)

    def _handle_input(self, controller: Controller) -> None:
        while True:
            try:
                packet = self._input.get_nowait()
            except Empty:
                return
            controller.on_packet(packet)

    async def _receive_hci(self, controller: Controller) -> None:
        while True:
            await asyncio.sleep(self.max_step_us / PHY_TIME_UNITS_PER_SECOND)
            self._handle_input(controller)

    async def _drive(self, sim_id: str, dev_id: int) -> None:
        loop = self._loop
        assert loop is not None
        self._task = asyncio.current_task()
        radio = BabbleSimRadio()
        backend = RadioBackend(radio)
        controller = Controller(
            self.name,
            backend=backend,
            public_address=self.public_address,
            host_sink=_ControllerOutput(self),
        )
        try:
            if self._stopping.is_set():
                raise asyncio.CancelledError
            await radio.connect(sim_id, dev_id)
            radio.bind_loop(loop)
            self._ready.set_result(None)
            async with asyncio.TaskGroup() as tasks:
                input_task = tasks.create_task(self._receive_hci(controller))
                try:
                    while True:
                        self._handle_input(controller)
                        await backend.link.advance_to_us(
                            radio.now_us + self.max_step_us
                        )
                finally:
                    input_task.cancel()
        finally:
            if loop.radio_selector.clock is not None:
                loop.unbind_clock()
            radio.close()

    async def close(self) -> None:
        if self._thread is None:
            self._terminate()
            return
        self._stopping.set()
        if (
            self._loop is not None
            and self._task is not None
            and self._thread.is_alive()
        ):
            try:
                self._loop.interrupt()
                self._loop.call_soon_threadsafe(self._task.cancel)
            except RuntimeError:
                if not self._loop.is_closed():
                    raise
        await asyncio.to_thread(self._thread.join, RADIO_WORKER_JOIN_TIMEOUT_SECONDS)
        if self._thread.is_alive():
            raise TimeoutError(f'Controller thread did not stop: {self.name}')
        self._result.result()
