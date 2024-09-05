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
import pytest
import pytest_asyncio

from bumble import device

from bumble.profiles.aics import Mute, AICSService, AICSServiceProxy, GainMode

from .test_utils import TwoDevices


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
@pytest_asyncio.fixture
async def aics_client():
    devices = TwoDevices()
    devices[0].add_service(AICSService())

    await devices.setup_connection()

    assert devices.connections[0] is not None
    assert devices.connections[1] is not None

    devices.connections[0].encryption = 1
    devices.connections[1].encryption = 1

    peer = device.Peer(devices.connections[1])
    aics_client = await peer.discover_service_and_create_proxy(AICSServiceProxy)

    yield aics_client

@pytest.mark.asyncio
async def test_init_service(aics_client: AICSServiceProxy):
    assert await aics_client.audio_input_state.read_value() == (
        0,
        Mute.NOT_MUTED,
        GainMode.AUTOMATIC_ONLY,
        0,
    )
