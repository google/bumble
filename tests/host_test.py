# Copyright 2021-2024 Google LLC
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
import unittest.mock
import pytest
import unittest

from bumble.controller import Controller
from bumble.host import Host, DataPacketQueue
from bumble.transport import AsyncPipeSink
from bumble.hci import HCI_AclDataPacket

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'supported_commands, lmp_features',
    [
        (
            # Default commands
            '2000800000c000000000e4000000a822000000000000040000f7ffff7f000000'
            '30f0f9ff01008004000000000000000000000000000000000000000000000000',
            # Only LE LMP feature
            '0000000060000000',
        ),
        (
            # All commands
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            # 3 pages of LMP features
            '000102030405060708090A0B0C0D0E0F011112131415161718191A1B1C1D1E1F',
        ),
    ],
)
async def test_reset(supported_commands: str, lmp_features: str):
    controller = Controller('C')
    controller.supported_commands = bytes.fromhex(supported_commands)
    controller.lmp_features = bytes.fromhex(lmp_features)
    host = Host(controller, AsyncPipeSink(controller))

    await host.reset()

    assert host.local_lmp_features == int.from_bytes(
        bytes.fromhex(lmp_features), 'little'
    )


# -----------------------------------------------------------------------------
def test_data_packet_queue():
    controller = unittest.mock.Mock()
    queue = DataPacketQueue(10, 2, controller.send)
    assert queue.queued == 0
    assert queue.completed == 0
    packet = HCI_AclDataPacket(
        connection_handle=123, pb_flag=0, bc_flag=0, data_total_length=0, data=b''
    )

    queue.enqueue(packet, packet.connection_handle)
    assert queue.queued == 1
    assert queue.completed == 0
    assert controller.send.call_count == 1

    queue.enqueue(packet, packet.connection_handle)
    assert queue.queued == 2
    assert queue.completed == 0
    assert controller.send.call_count == 2

    queue.enqueue(packet, packet.connection_handle)
    assert queue.queued == 3
    assert queue.completed == 0
    assert controller.send.call_count == 2

    queue.on_packets_completed(1, 8000)
    assert queue.queued == 3
    assert queue.completed == 0
    assert controller.send.call_count == 2

    queue.on_packets_completed(1, 123)
    assert queue.queued == 3
    assert queue.completed == 1
    assert controller.send.call_count == 3

    queue.enqueue(packet, packet.connection_handle)
    assert queue.queued == 4
    assert queue.completed == 1
    assert controller.send.call_count == 3

    queue.on_packets_completed(2, 123)
    assert queue.queued == 4
    assert queue.completed == 3
    assert controller.send.call_count == 4

    queue.on_packets_completed(1, 123)
    assert queue.queued == 4
    assert queue.completed == 4
    assert controller.send.call_count == 4

    queue.enqueue(packet, 123)
    queue.enqueue(packet, 123)
    queue.enqueue(packet, 123)
    queue.enqueue(packet, 124)
    queue.enqueue(packet, 124)
    queue.enqueue(packet, 124)
    queue.on_packets_completed(1, 123)
    assert queue.queued == 10
    assert queue.completed == 5
    queue.flush(123)
    queue.flush(124)
    assert queue.queued == 10
    assert queue.completed == 10

    queue.enqueue(packet, 123)
    queue.on_packets_completed(1, 124)
    assert queue.queued == 11
    assert queue.completed == 10
    queue.on_packets_completed(1000, 123)
    assert queue.queued == 11
    assert queue.completed == 11

    drain_listener = unittest.mock.Mock()
    queue.on('flow', drain_listener.on_flow)
    queue.enqueue(packet, 123)
    assert drain_listener.on_flow.call_count == 0
    queue.on_packets_completed(1, 123)
    assert drain_listener.on_flow.call_count == 1
    queue.enqueue(packet, 123)
    queue.enqueue(packet, 123)
    queue.enqueue(packet, 123)
    queue.flush(123)
    assert drain_listener.on_flow.call_count == 1
    assert queue.queued == 15
    assert queue.completed == 15
