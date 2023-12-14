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
import logging

from bumble import device
from bumble import gatt
from bumble.profiles import cap
from bumble.profiles import csip
from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cas():
    SIRK = bytes.fromhex('2f62c8ae41867d1bb619e788a2605faa')

    devices = TwoDevices()
    devices[0].add_service(
        cap.CommonAudioServiceService(
            csip.CoordinatedSetIdentificationService(
                set_identity_resolving_key=SIRK,
                set_identity_resolving_key_type=csip.SirkType.PLAINTEXT,
            )
        )
    )

    await devices.setup_connection()
    peer = device.Peer(devices.connections[1])
    cas_client = await peer.discover_service_and_create_proxy(
        cap.CommonAudioServiceServiceProxy
    )

    included_services = await peer.discover_included_services(cas_client.service_proxy)
    assert any(
        service.uuid == gatt.GATT_COORDINATED_SET_IDENTIFICATION_SERVICE
        for service in included_services
    )


# -----------------------------------------------------------------------------
async def run():
    await test_cas()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
