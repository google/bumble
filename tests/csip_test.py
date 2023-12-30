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
from unittest import mock

from bumble import device
from bumble.profiles import csip
from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def test_s1():
    assert (
        csip.s1(b'SIRKenc'[::-1])
        == bytes.fromhex('6901983f 18149e82 3c7d133a 7d774572')[::-1]
    )


# -----------------------------------------------------------------------------
def test_k1():
    K = bytes.fromhex('676e1b9b d448696f 061ec622 3ce5ced9')[::-1]
    SALT = csip.s1(b'SIRKenc'[::-1])
    P = b'csis'[::-1]
    assert (
        csip.k1(K, SALT, P)
        == bytes.fromhex('5277453c c094d982 b0e8ee53 2f2d1f8b')[::-1]
    )


# -----------------------------------------------------------------------------
def test_sih():
    SIRK = bytes.fromhex('457d7d09 21a1fd22 cecd8c86 dd72cccd')[::-1]
    PRAND = bytes.fromhex('69f563')[::-1]
    assert csip.sih(SIRK, PRAND) == bytes.fromhex('1948da')[::-1]


# -----------------------------------------------------------------------------
def test_sef():
    SIRK = bytes.fromhex('457d7d09 21a1fd22 cecd8c86 dd72cccd')[::-1]
    K = bytes.fromhex('676e1b9b d448696f 061ec622 3ce5ced9')[::-1]
    assert (
        csip.sef(K, SIRK) == bytes.fromhex('170a3835 e13524a0 7e2562d5 f25fd346')[::-1]
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'sirk_type,', [(csip.SirkType.ENCRYPTED), (csip.SirkType.PLAINTEXT)]
)
async def test_csis(sirk_type):
    SIRK = bytes.fromhex('2f62c8ae41867d1bb619e788a2605faa')
    LTK = bytes.fromhex('2f62c8ae41867d1bb619e788a2605faa')

    devices = TwoDevices()
    devices[0].add_service(
        csip.CoordinatedSetIdentificationService(
            set_identity_resolving_key=SIRK,
            set_identity_resolving_key_type=sirk_type,
            coordinated_set_size=2,
            set_member_lock=csip.MemberLock.UNLOCKED,
            set_member_rank=0,
        )
    )

    await devices.setup_connection()

    # Mock encryption.
    devices.connections[0].encryption = 1
    devices.connections[1].encryption = 1
    devices[0].get_long_term_key = mock.AsyncMock(return_value=LTK)
    devices[1].get_long_term_key = mock.AsyncMock(return_value=LTK)

    peer = device.Peer(devices.connections[1])
    csis_client = await peer.discover_service_and_create_proxy(
        csip.CoordinatedSetIdentificationProxy
    )

    assert await csis_client.read_set_identity_resolving_key() == (sirk_type, SIRK)
    assert await csis_client.coordinated_set_size.read_value() == struct.pack('B', 2)
    assert await csis_client.set_member_lock.read_value() == struct.pack(
        'B', csip.MemberLock.UNLOCKED
    )
    assert await csis_client.set_member_rank.read_value() == struct.pack('B', 0)


# -----------------------------------------------------------------------------
async def run():
    test_sih()
    await test_csis()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
