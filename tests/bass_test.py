# Copyright 2024 Google LLC
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
import os
import logging

from bumble import hci
from bumble.profiles import bass


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def basic_operation_check(operation: bass.ControlPointOperation) -> None:
    serialized = bytes(operation)
    parsed = bass.ControlPointOperation.from_bytes(serialized)
    assert bytes(parsed) == serialized


# -----------------------------------------------------------------------------
def test_operations() -> None:
    op1 = bass.RemoteScanStoppedOperation()
    basic_operation_check(op1)

    op2 = bass.RemoteScanStartedOperation()
    basic_operation_check(op2)

    op3 = bass.AddSourceOperation(
        hci.Address("AA:BB:CC:DD:EE:FF"),
        34,
        123456,
        bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
        456,
        (),
    )
    basic_operation_check(op3)

    op4 = bass.AddSourceOperation(
        hci.Address("AA:BB:CC:DD:EE:FF"),
        34,
        123456,
        bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
        456,
        (
            bass.SubgroupInfo(6677, bytes.fromhex('aabbcc')),
            bass.SubgroupInfo(8899, bytes.fromhex('ddeeff')),
        ),
    )
    basic_operation_check(op4)

    op5 = bass.ModifySourceOperation(
        12,
        bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
        567,
        (),
    )
    basic_operation_check(op5)

    op6 = bass.ModifySourceOperation(
        12,
        bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
        567,
        (
            bass.SubgroupInfo(6677, bytes.fromhex('112233')),
            bass.SubgroupInfo(8899, bytes.fromhex('4567')),
        ),
    )
    basic_operation_check(op6)

    op7 = bass.SetBroadcastCodeOperation(
        7, bytes.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf')
    )
    basic_operation_check(op7)

    op8 = bass.RemoveSourceOperation(7)
    basic_operation_check(op8)


# -----------------------------------------------------------------------------
def basic_broadcast_receive_state_check(brs: bass.BroadcastReceiveState) -> None:
    serialized = bytes(brs)
    parsed = bass.BroadcastReceiveState.from_bytes(serialized)
    assert parsed is not None
    assert bytes(parsed) == serialized


def test_broadcast_receive_state() -> None:
    subgroups = [
        bass.SubgroupInfo(6677, bytes.fromhex('112233')),
        bass.SubgroupInfo(8899, bytes.fromhex('4567')),
    ]

    brs1 = bass.BroadcastReceiveState(
        12,
        hci.Address("AA:BB:CC:DD:EE:FF"),
        123,
        123456,
        bass.BroadcastReceiveState.PeriodicAdvertisingSyncState.SYNCHRONIZED_TO_PA,
        bass.BroadcastReceiveState.BigEncryption.DECRYPTING,
        b'',
        subgroups,
    )
    basic_broadcast_receive_state_check(brs1)

    brs2 = bass.BroadcastReceiveState(
        12,
        hci.Address("AA:BB:CC:DD:EE:FF"),
        123,
        123456,
        bass.BroadcastReceiveState.PeriodicAdvertisingSyncState.SYNCHRONIZED_TO_PA,
        bass.BroadcastReceiveState.BigEncryption.BAD_CODE,
        bytes.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'),
        subgroups,
    )
    basic_broadcast_receive_state_check(brs2)


# -----------------------------------------------------------------------------
async def run():
    test_operations()
    test_broadcast_receive_state()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
