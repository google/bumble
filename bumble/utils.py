# Copyright 2021-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import asyncio
import logging
import traceback
import collections
import sys
from typing import Awaitable, TypeVar
from functools import wraps
from colors import color
from pyee import EventEmitter


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def setup_event_forwarding(emitter, forwarder, event_name):
    def emit(*args, **kwargs):
        forwarder.emit(event_name, *args, **kwargs)

    emitter.on(event_name, emit)


# -----------------------------------------------------------------------------
def composite_listener(cls):
    """
    Decorator that adds a `register` and `deregister` method to a class, which
    registers/deregisters all methods named `on_<event_name>` as a listener for
    the <event_name> event with an emitter.
    """
    # pylint: disable=protected-access

    def register(self, emitter):
        for method_name in dir(cls):
            if method_name.startswith('on_'):
                emitter.on(method_name[3:], getattr(self, method_name))

    def deregister(self, emitter):
        for method_name in dir(cls):
            if method_name.startswith('on_'):
                emitter.remove_listener(method_name[3:], getattr(self, method_name))

    cls._bumble_register_composite = register
    cls._bumble_deregister_composite = deregister
    return cls


# -----------------------------------------------------------------------------
_T = TypeVar('_T')


class AbortableEventEmitter(EventEmitter):
    def abort_on(self, event: str, awaitable: Awaitable[_T]) -> Awaitable[_T]:
        """
        Set a coroutine or future to abort when an event occur.
        """
        future = asyncio.ensure_future(awaitable)
        if future.done():
            return future

        def on_event(*_):
            msg = f'abort: {event} event occurred.'
            if isinstance(future, asyncio.Task):
                # python < 3.9 does not support passing a message on `Task.cancel`
                if sys.version_info < (3, 9, 0):
                    future.cancel()
                else:
                    future.cancel(msg)
            else:
                future.set_exception(asyncio.CancelledError(msg))

        def on_done(_):
            self.remove_listener(event, on_event)

        self.on(event, on_event)
        future.add_done_callback(on_done)
        return future


# -----------------------------------------------------------------------------
class CompositeEventEmitter(AbortableEventEmitter):
    def __init__(self):
        super().__init__()
        self._listener = None

    @property
    def listener(self):
        return self._listener

    @listener.setter
    def listener(self, listener):
        # pylint: disable=protected-access
        if self._listener:
            # Call the deregistration methods for each base class that has them
            for cls in self._listener.__class__.mro():
                if hasattr(cls, '_bumble_register_composite'):
                    cls._bumble_deregister_composite(listener, self)
        self._listener = listener
        if listener:
            # Call the registration methods for each base class that has them
            for cls in listener.__class__.mro():
                if hasattr(cls, '_bumble_deregister_composite'):
                    cls._bumble_register_composite(listener, self)


# -----------------------------------------------------------------------------
class AsyncRunner:
    class WorkQueue:
        def __init__(self, create_task=True):
            self.queue = None
            self.task = None
            self.create_task = create_task

        def enqueue(self, coroutine):
            # Create a task now if we need to and haven't done so already
            if self.create_task and self.task is None:
                self.task = asyncio.create_task(self.run())

            # Lazy-create the coroutine queue
            if self.queue is None:
                self.queue = asyncio.Queue()

            # Enqueue the work
            self.queue.put_nowait(coroutine)

        async def run(self):
            while True:
                item = await self.queue.get()
                try:
                    await item
                except Exception as error:
                    logger.warning(
                        f'{color("!!! Exception in work queue:", "red")} {error}'
                    )

    # Shared default queue
    default_queue = WorkQueue()

    @staticmethod
    def run_in_task(queue=None):
        """
        Function decorator used to adapt an async function into a sync function
        """

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                coroutine = func(*args, **kwargs)
                if queue is None:
                    # Create a task to run the coroutine
                    async def run():
                        try:
                            await coroutine
                        except Exception:
                            logger.warning(
                                f'{color("!!! Exception in wrapper:", "red")} '
                                f'{traceback.format_exc()}'
                            )

                    asyncio.create_task(run())
                else:
                    # Queue the coroutine to be awaited by the work queue
                    queue.enqueue(coroutine)

            return wrapper

        return decorator


# -----------------------------------------------------------------------------
class FlowControlAsyncPipe:
    """
    Asyncio pipe with flow control. When writing to the pipe, the source is
    paused (by calling a function passed in when the pipe is created) if the
    amount of queued data exceeds a specified threshold.
    """

    def __init__(
        self,
        pause_source,
        resume_source,
        write_to_sink=None,
        drain_sink=None,
        threshold=0,
    ):
        self.pause_source = pause_source
        self.resume_source = resume_source
        self.write_to_sink = write_to_sink
        self.drain_sink = drain_sink
        self.threshold = threshold
        self.queue = collections.deque()  # Queue of packets
        self.queued_bytes = 0  # Number of bytes in the queue
        self.ready_to_pump = asyncio.Event()
        self.paused = False
        self.source_paused = False
        self.pump_task = None

    def start(self):
        if self.pump_task is None:
            self.pump_task = asyncio.create_task(self.pump())

        self.check_pump()

    def stop(self):
        if self.pump_task is not None:
            self.pump_task.cancel()
            self.pump_task = None

    def write(self, packet):
        self.queued_bytes += len(packet)
        self.queue.append(packet)

        # Pause the source if we're over the threshold
        if self.queued_bytes > self.threshold and not self.source_paused:
            logger.debug(f'pausing source (queued={self.queued_bytes})')
            self.pause_source()
            self.source_paused = True

        self.check_pump()

    def pause(self):
        if not self.paused:
            self.paused = True
            if not self.source_paused:
                self.pause_source()
                self.source_paused = True
            self.check_pump()

    def resume(self):
        if self.paused:
            self.paused = False
            if self.source_paused:
                self.resume_source()
                self.source_paused = False
            self.check_pump()

    def can_pump(self):
        return self.queue and not self.paused and self.write_to_sink is not None

    def check_pump(self):
        if self.can_pump():
            self.ready_to_pump.set()
        else:
            self.ready_to_pump.clear()

    async def pump(self):
        while True:
            # Wait until we can try to pump packets
            await self.ready_to_pump.wait()

            # Try to pump a packet
            if self.can_pump():
                packet = self.queue.pop()
                self.write_to_sink(packet)
                self.queued_bytes -= len(packet)

                # Drain the sink if we can
                if self.drain_sink:
                    await self.drain_sink()

                # Check if we can accept more
                if self.queued_bytes <= self.threshold and self.source_paused:
                    logger.debug(f'resuming source (queued={self.queued_bytes})')
                    self.source_paused = False
                    self.resume_source()

            self.check_pump()
