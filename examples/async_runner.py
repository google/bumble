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
import logging
import asyncio
import os

from bumble.utils import AsyncRunner

# -----------------------------------------------------------------------------
my_work_queue1 = AsyncRunner.WorkQueue()
my_work_queue2 = AsyncRunner.WorkQueue(create_task=False)

# -----------------------------------------------------------------------------
@AsyncRunner.run_in_task()
async def func1(x, y):
    print('FUNC1: start', x, y)
    await asyncio.sleep(x)
    print('FUNC1: end', x, y)


# -----------------------------------------------------------------------------
@AsyncRunner.run_in_task(queue=my_work_queue1)
async def func2(x, y):
    print('FUNC2: start', x, y)
    await asyncio.sleep(x)
    print('FUNC2: end', x, y)


# -----------------------------------------------------------------------------
@AsyncRunner.run_in_task(queue=my_work_queue2)
async def func3(x, y):
    print('FUNC3: start', x, y)
    await asyncio.sleep(x)
    print('FUNC3: end', x, y)


# -----------------------------------------------------------------------------
@AsyncRunner.run_in_task(queue=None)
async def func4(x, y):
    print('FUNC4: start', x, y)
    await asyncio.sleep(x)
    print('FUNC4: end', x, y)

    raise ValueError('test')


# -----------------------------------------------------------------------------
async def main():
    print("MAIN: start, loop=", asyncio.get_running_loop())
    print("MAIN: invoke func1")
    func1(1, 2)

    print("MAIN: invoke func2")
    func2(3, 4)

    print("MAIN: invoke func3")
    func3(5, 6)

    print("MAIN: invoke func4")
    func4(7, 8)

    print("MAIN: sleeping 2 seconds")
    await asyncio.sleep(2)
    print("MAIN: running my_work_queue2.run")
    await my_work_queue2.run()
    print("MAIN: end (should never get here)")


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
