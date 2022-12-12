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
import os
import random
import pytest

from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.device import Device
from bumble.host import Host
from bumble.transport import AsyncPipeSink
from bumble.core import ProtocolError
from bumble.l2cap import L2CAP_Connection_Request


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class TwoDevices:
    def __init__(self):
        self.connections = [None, None]

        self.link = LocalLink()
        self.controllers = [
            Controller('C1', link=self.link),
            Controller('C2', link=self.link),
        ]
        self.devices = [
            Device(
                address='F0:F1:F2:F3:F4:F5',
                host=Host(self.controllers[0], AsyncPipeSink(self.controllers[0])),
            ),
            Device(
                address='F5:F4:F3:F2:F1:F0',
                host=Host(self.controllers[1], AsyncPipeSink(self.controllers[1])),
            ),
        ]

        self.paired = [None, None]

    def on_connection(self, which, connection):
        self.connections[which] = connection

    def on_paired(self, which, keys):
        self.paired[which] = keys


# -----------------------------------------------------------------------------
async def setup_connection():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Attach listeners
    two_devices.devices[0].on(
        'connection', lambda connection: two_devices.on_connection(0, connection)
    )
    two_devices.devices[1].on(
        'connection', lambda connection: two_devices.on_connection(1, connection)
    )

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    await two_devices.devices[0].connect(two_devices.devices[1].random_address)

    # Check the post conditions
    assert two_devices.connections[0] is not None
    assert two_devices.connections[1] is not None

    return two_devices


# -----------------------------------------------------------------------------
def test_helpers():
    psm = L2CAP_Connection_Request.serialize_psm(0x01)
    assert psm == bytes([0x01, 0x00])

    psm = L2CAP_Connection_Request.serialize_psm(0x1023)
    assert psm == bytes([0x23, 0x10])

    psm = L2CAP_Connection_Request.serialize_psm(0x242311)
    assert psm == bytes([0x11, 0x23, 0x24])

    (offset, psm) = L2CAP_Connection_Request.parse_psm(
        bytes([0x00, 0x01, 0x00, 0x44]), 1
    )
    assert offset == 3
    assert psm == 0x01

    (offset, psm) = L2CAP_Connection_Request.parse_psm(
        bytes([0x00, 0x23, 0x10, 0x44]), 1
    )
    assert offset == 3
    assert psm == 0x1023

    (offset, psm) = L2CAP_Connection_Request.parse_psm(
        bytes([0x00, 0x11, 0x23, 0x24, 0x44]), 1
    )
    assert offset == 4
    assert psm == 0x242311

    rq = L2CAP_Connection_Request(psm=0x01, source_cid=0x44)
    brq = bytes(rq)
    srq = L2CAP_Connection_Request.from_bytes(brq)
    assert srq.psm == rq.psm
    assert srq.source_cid == rq.source_cid


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_basic_connection():
    devices = await setup_connection()
    psm = 1234

    # Check that if there's no one listening, we can't connect
    with pytest.raises(ProtocolError):
        l2cap_channel = await devices.connections[0].open_l2cap_channel(psm)

    # Now add a listener
    incoming_channel = None
    received = []

    def on_coc(channel):
        nonlocal incoming_channel
        incoming_channel = channel

        def on_data(data):
            received.append(data)

        channel.sink = on_data

    devices.devices[1].register_l2cap_channel_server(psm, on_coc)
    l2cap_channel = await devices.connections[0].open_l2cap_channel(psm)

    messages = (bytes([1, 2, 3]), bytes([4, 5, 6]), bytes(10000))
    for message in messages:
        l2cap_channel.write(message)
        await asyncio.sleep(0)

    await l2cap_channel.drain()

    # Test closing
    closed = [False, False]
    closed_event = asyncio.Event()

    def on_close(which, event):
        closed[which] = True
        if event:
            event.set()

    l2cap_channel.on('close', lambda: on_close(0, None))
    incoming_channel.on('close', lambda: on_close(1, closed_event))
    await l2cap_channel.disconnect()
    assert closed == [True, True]
    await closed_event.wait()

    sent_bytes = b''.join(messages)
    received_bytes = b''.join(received)
    assert sent_bytes == received_bytes


# -----------------------------------------------------------------------------
async def transfer_payload(max_credits, mtu, mps):
    devices = await setup_connection()

    received = []

    def on_coc(channel):
        def on_data(data):
            received.append(data)

        channel.sink = on_data

    psm = devices.devices[1].register_l2cap_channel_server(
        psm=0, server=on_coc, max_credits=max_credits, mtu=mtu, mps=mps
    )
    l2cap_channel = await devices.connections[0].open_l2cap_channel(psm)

    messages = [bytes([1, 2, 3, 4, 5, 6, 7]) * x for x in (3, 10, 100, 789)]
    for message in messages:
        l2cap_channel.write(message)
        await asyncio.sleep(0)
        if random.randint(0, 5) == 1:
            await l2cap_channel.drain()

    await l2cap_channel.drain()
    await l2cap_channel.disconnect()

    sent_bytes = b''.join(messages)
    received_bytes = b''.join(received)
    assert sent_bytes == received_bytes


@pytest.mark.asyncio
async def test_transfer():
    for max_credits in (1, 10, 100, 10000):
        for mtu in (50, 255, 256, 1000):
            for mps in (50, 255, 256, 1000):
                # print(max_credits, mtu, mps)
                await transfer_payload(max_credits, mtu, mps)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_bidirectional_transfer():
    devices = await setup_connection()

    client_received = []
    server_received = []
    server_channel = None

    def on_server_coc(channel):
        nonlocal server_channel
        server_channel = channel

        def on_server_data(data):
            server_received.append(data)

        channel.sink = on_server_data

    def on_client_data(data):
        client_received.append(data)

    psm = devices.devices[1].register_l2cap_channel_server(psm=0, server=on_server_coc)
    client_channel = await devices.connections[0].open_l2cap_channel(psm)
    client_channel.sink = on_client_data

    messages = [bytes([1, 2, 3, 4, 5, 6, 7]) * x for x in (3, 10, 100)]
    for message in messages:
        client_channel.write(message)
        await client_channel.drain()
        await asyncio.sleep(0)
        server_channel.write(message)
        await server_channel.drain()

    await client_channel.disconnect()

    message_bytes = b''.join(messages)
    client_received_bytes = b''.join(client_received)
    server_received_bytes = b''.join(server_received)
    assert client_received_bytes == message_bytes
    assert server_received_bytes == message_bytes


# -----------------------------------------------------------------------------
async def run():
    test_helpers()
    await test_basic_connection()
    await test_transfer()
    await test_bidirectional_transfer()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
