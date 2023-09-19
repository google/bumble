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
import contextlib
from pyee import EventEmitter

from bumble.utils import event_emitter_once_for_group, event_emitters_once_for_group


# -----------------------------------------------------------------------------
def test_event_emitter_once_for_group():
    results = {'event1': None, 'event2': None, 'released': 0}

    def handler1(x):
        results['event1'] = x

    def handler2(y):
        results['event2'] = y

    emitter = EventEmitter()

    event_emitter_once_for_group(
        emitter,
        {
            'event1': handler1,
            'event2': handler2,
        },
    )

    emitter.emit('event1', 'hello')

    assert results['event1'] == 'hello'
    assert results['event2'] is None

    results['event1'] = None

    emitter.emit('event1', 'hello')
    emitter.emit('event2', 1234)

    assert results['event1'] is None
    assert results['event2'] is None

    @contextlib.contextmanager
    def managed():
        try:
            yield 1234
        finally:
            results['released'] += 1

    event_emitter_once_for_group(
        emitter,
        {
            'event1': handler1,
            'event2': handler2,
        },
        managed(),
    )

    assert results['released'] == 0

    emitter.emit('event2', 7756)

    assert results['event1'] is None
    assert results['event2'] == 7756
    assert results['released'] == 1


# -----------------------------------------------------------------------------
def test_event_emitters_once_for_group():
    results = {'event1': None, 'event2': None, 'released': 0}

    def handler1(x):
        results['event1'] = x

    def handler2(y):
        results['event2'] = y

    emitter1 = EventEmitter()
    emitter2 = EventEmitter()

    event_emitters_once_for_group(
        {
            (emitter1, 'event1'): handler1,
            (emitter2, 'event2'): handler2,
        },
    )

    emitter1.emit('event1', 'hello')
    emitter2.emit('event1', 'foobar')

    assert results['event1'] == 'hello'
    assert results['event2'] is None

    results['event1'] = None

    emitter1.emit('event1', 'hello')
    emitter1.emit('event2', 1234)
    emitter2.emit('event1', 'hello')
    emitter2.emit('event2', 1234)

    assert results['event1'] is None
    assert results['event2'] is None


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_event_emitter_once_for_group()
    test_event_emitters_once_for_group()
