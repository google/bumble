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
import os
import pytest
import struct
import logging

from bumble import device
from bumble.profiles import csip
from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_csis():
    SIRK = bytes.fromhex('2f62c8ae41867d1bb619e788a2605faa')

    devices = TwoDevices()
    devices[0].add_service(
        csip.CoordinatedSetIdentificationService(
            set_identity_resolving_key=SIRK,
            coordinated_set_size=2,
            set_member_lock=csip.MemberLock.UNLOCKED,
            set_member_rank=0,
        )
    )

    await devices.setup_connection()
    peer = device.Peer(devices.connections[1])
    csis_client = await peer.discover_service_and_create_proxy(
        csip.CoordinatedSetIdentificationProxy
    )

    assert (
        await csis_client.set_identity_resolving_key.read_value()
        == bytes([csip.SirkType.PLAINTEXT]) + SIRK
    )
    assert await csis_client.coordinated_set_size.read_value() == struct.pack('B', 2)
    assert await csis_client.set_member_lock.read_value() == struct.pack(
        'B', csip.MemberLock.UNLOCKED
    )
    assert await csis_client.set_member_rank.read_value() == struct.pack('B', 0)


# -----------------------------------------------------------------------------
async def run():
    await test_csis()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
