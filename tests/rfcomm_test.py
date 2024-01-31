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
import pytest

from . import test_utils
from bumble.rfcomm import RFCOMM_Frame, Server, Client, DLC


# -----------------------------------------------------------------------------
def basic_frame_check(x):
    serialized = bytes(x)
    if len(serialized) < 500:
        print('Original:', x)
        print('Serialized:', serialized.hex())
    parsed = RFCOMM_Frame.from_bytes(serialized)
    if len(serialized) < 500:
        print('Parsed:', parsed)
    parsed_bytes = bytes(parsed)
    if len(serialized) < 500:
        print('Parsed Bytes:', parsed_bytes.hex())
    assert parsed_bytes == serialized
    x_str = str(x)
    parsed_str = str(parsed)
    assert x_str == parsed_str


# -----------------------------------------------------------------------------
def test_frames():
    data = bytes.fromhex('033f011c')
    frame = RFCOMM_Frame.from_bytes(data)
    basic_frame_check(frame)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_basic_connection():
    devices = test_utils.TwoDevices()
    await devices.setup_connection()

    accept_future: asyncio.Future[DLC] = asyncio.get_running_loop().create_future()
    channel = Server(devices[0]).listen(acceptor=accept_future.set_result)

    multiplexer = await Client(devices.connections[1]).start()
    dlcs = await asyncio.gather(accept_future, multiplexer.open_dlc(channel))

    queues = [asyncio.Queue(), asyncio.Queue()]
    for dlc, queue in zip(dlcs, queues):
        dlc.sink = queue.put_nowait

    dlcs[0].write(b'The quick brown fox jumps over the lazy dog')
    assert await queues[1].get() == b'The quick brown fox jumps over the lazy dog'

    dlcs[1].write(b'Lorem ipsum dolor sit amet')
    assert await queues[0].get() == b'Lorem ipsum dolor sit amet'


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_frames()
