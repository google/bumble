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
    def register(self, emitter):
        for method_name in dir(cls):
            if method_name.startswith('on_'):
                emitter.on(method_name[3:], getattr(self, method_name))

    def deregister(self, emitter):
        for method_name in dir(cls):
            if method_name.startswith('on_'):
                emitter.remove_listener(method_name[3:], getattr(self, method_name))

    cls._bumble_register_composite   = register
    cls._bumble_deregister_composite = deregister
    return cls


# -----------------------------------------------------------------------------
class CompositeEventEmitter(EventEmitter):
    def __init__(self):
        super().__init__()
        self._listener = None

    @property
    def listener(self):
        return self._listener

    @listener.setter
    def listener(self, listener):
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
                    logger.warning(f'{color("!!! Exception in work queue:", "red")} {error}')

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
                            logger.warning(f'{color("!!! Exception in wrapper:", "red")} {traceback.format_exc()}')

                    asyncio.create_task(run())
                else:
                    # Queue the coroutine to be awaited by the work queue
                    queue.enqueue(coroutine)

            return wrapper

        return decorator
