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

from bumble import core
from bumble.rfcomm import (
    DLC,
    RFCOMM_PSM,
    Client,
    RFCOMM_Frame,
    Server,
    find_rfcomm_channel_with_uuid,
    find_rfcomm_channels,
    make_service_sdp_records,
)

from . import test_utils

_TIMEOUT = 0.1


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
async def test_connection_and_disconnection() -> None:
    devices = test_utils.TwoDevices()
    await devices.setup_connection()

    accept_future: asyncio.Future[DLC] = asyncio.get_running_loop().create_future()
    channel = Server(devices[0]).listen(acceptor=accept_future.set_result)

    assert devices.connections[1]
    multiplexer = await Client(devices.connections[1]).start()
    dlcs = await asyncio.gather(accept_future, multiplexer.open_dlc(channel))

    queues: list[asyncio.Queue] = [asyncio.Queue(), asyncio.Queue()]
    for dlc, queue in zip(dlcs, queues):
        dlc.sink = queue.put_nowait

    dlcs[0].write(b'The quick brown fox jumps over the lazy dog')
    assert await queues[1].get() == b'The quick brown fox jumps over the lazy dog'

    dlcs[1].write(b'Lorem ipsum dolor sit amet')
    assert await queues[0].get() == b'Lorem ipsum dolor sit amet'

    closed = asyncio.Event()
    dlcs[1].on('close', closed.set)
    await dlcs[1].disconnect()
    await closed.wait()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_receive_pdu_before_open_dlc_returns() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    DATA = b'123'

    accept_future: asyncio.Future[DLC] = asyncio.get_running_loop().create_future()
    channel = Server(devices[0]).listen(acceptor=accept_future.set_result)

    assert devices.connections[1]
    multiplexer = await Client(devices.connections[1]).start()
    open_dlc_task = asyncio.create_task(multiplexer.open_dlc(channel))

    dlc_responder = await accept_future
    dlc_responder.write(DATA)

    dlc_initiator = await open_dlc_task
    dlc_initiator_queue = asyncio.Queue()  # type: ignore[var-annotated]
    dlc_initiator.sink = dlc_initiator_queue.put_nowait

    assert await asyncio.wait_for(dlc_initiator_queue.get(), timeout=_TIMEOUT) == DATA


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_record():
    HANDLE = 2
    CHANNEL = 1
    SERVICE_UUID = core.UUID('00000000-0000-0000-0000-000000000001')

    devices = test_utils.TwoDevices()
    await devices.setup_connection()

    devices[0].sdp_service_records[HANDLE] = make_service_sdp_records(
        HANDLE, CHANNEL, SERVICE_UUID
    )

    assert SERVICE_UUID in (await find_rfcomm_channels(devices.connections[1]))[CHANNEL]
    assert (
        await find_rfcomm_channel_with_uuid(devices.connections[1], SERVICE_UUID)
        == CHANNEL
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_context():
    devices = test_utils.TwoDevices()
    await devices.setup_connection()

    server = Server(devices[0])
    with server:
        assert server.l2cap_server is not None

        client = Client(devices.connections[1])
        async with client:
            assert client.l2cap_channel is not None

        assert client.l2cap_channel is None
    assert RFCOMM_PSM not in devices[0].l2cap_channel_manager.servers


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_frames()
