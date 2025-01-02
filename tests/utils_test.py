# Copyright 2021-2023 Google LLC
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
import contextlib
import logging
import os
import pytest
from unittest.mock import MagicMock, AsyncMock

from pyee import EventEmitter

from bumble import core
from bumble import utils


# -----------------------------------------------------------------------------
def test_on() -> None:
    emitter = EventEmitter()
    with contextlib.closing(utils.EventWatcher()) as context:
        mock = MagicMock()
        context.on(emitter, 'event', mock)

        emitter.emit('event')

    assert not emitter.listeners('event')
    assert mock.call_count == 1


# -----------------------------------------------------------------------------
def test_on_decorator() -> None:
    emitter = EventEmitter()
    with contextlib.closing(utils.EventWatcher()) as context:
        mock = MagicMock()

        @context.on(emitter, 'event')
        def on_event(*_) -> None:
            mock()

        emitter.emit('event')

    assert not emitter.listeners('event')
    assert mock.call_count == 1


# -----------------------------------------------------------------------------
def test_multiple_handlers() -> None:
    emitter = EventEmitter()
    with contextlib.closing(utils.EventWatcher()) as context:
        mock = MagicMock()

        context.once(emitter, 'a', mock)
        context.once(emitter, 'b', mock)

        emitter.emit('b', 'b')

    assert not emitter.listeners('a')
    assert not emitter.listeners('b')

    mock.assert_called_once_with('b')


# -----------------------------------------------------------------------------
def test_open_int_enums():
    class Foo(utils.OpenIntEnum):
        FOO = 1
        BAR = 2
        BLA = 3

    x = Foo(1)
    assert x.name == "FOO"
    assert x.value == 1
    assert int(x) == 1
    assert x == 1
    assert x + 1 == 2

    x = Foo(4)
    assert x.name == "Foo[4]"
    assert x.value == 4
    assert int(x) == 4
    assert x == 4
    assert x + 1 == 5

    print(list(Foo))


# -----------------------------------------------------------------------------
async def test_abort_on_coroutine_aborted():
    ee = utils.AbortableEventEmitter()

    future = ee.abort_on('e', asyncio.Event().wait())
    ee.emit('e')

    with pytest.raises(core.CancelledError):
        await future


# -----------------------------------------------------------------------------
async def test_abort_on_coroutine_non_aborted():
    ee = utils.AbortableEventEmitter()
    event = asyncio.Event()

    future = ee.abort_on('e', event.wait())
    event.set()

    await future


# -----------------------------------------------------------------------------
async def test_abort_on_coroutine_exception():
    ee = utils.AbortableEventEmitter()
    coroutine_factory = AsyncMock(side_effect=Exception("test"))

    future = ee.abort_on('e', coroutine_factory())
    with pytest.raises(Exception) as e:
        await future
    assert e.value.args == ("test",)


# -----------------------------------------------------------------------------
async def test_abort_on_future_aborted():
    ee = utils.AbortableEventEmitter()
    real_future = asyncio.get_running_loop().create_future()

    future = ee.abort_on('e', real_future)
    ee.emit('e')

    with pytest.raises(core.CancelledError):
        await future


# -----------------------------------------------------------------------------
async def test_abort_on_future_non_aborted():
    ee = utils.AbortableEventEmitter()
    real_future = asyncio.get_running_loop().create_future()

    future = ee.abort_on('e', real_future)
    real_future.set_result(None)

    await future


# -----------------------------------------------------------------------------
async def test_abort_on_future_exception():
    ee = utils.AbortableEventEmitter()
    real_future = asyncio.get_running_loop().create_future()

    future = ee.abort_on('e', real_future)
    real_future.set_exception(Exception("test"))

    with pytest.raises(Exception) as e:
        await future
    assert e.value.args == ("test",)


# -----------------------------------------------------------------------------
def run_tests():
    test_on()
    test_on_decorator()
    test_multiple_handlers()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    run_tests()
    test_open_int_enums()
