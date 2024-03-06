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
import dataclasses
import pytest
import pytest_asyncio
import struct
import logging

from bumble import device
from bumble.profiles import mcp
from tests.test_utils import TwoDevices


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
TIMEOUT = 0.1


@dataclasses.dataclass
class GmcsContext:
    devices: TwoDevices
    client: mcp.GenericMediaControlServiceProxy
    server: mcp.GenericMediaControlService


# -----------------------------------------------------------------------------
@pytest_asyncio.fixture
async def gmcs_context():
    devices = TwoDevices()
    server = mcp.GenericMediaControlService()
    devices[0].add_service(server)

    await devices.setup_connection()
    devices.connections[0].encryption = 1
    devices.connections[1].encryption = 1
    peer = device.Peer(devices.connections[1])
    client = await peer.discover_service_and_create_proxy(
        mcp.GenericMediaControlServiceProxy
    )
    await client.subscribe_characteristics()

    return GmcsContext(devices=devices, server=server, client=client)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_update_media_state(gmcs_context):
    state = asyncio.Queue()
    gmcs_context.client.on('media_state', state.put_nowait)

    await gmcs_context.devices[0].notify_subscribers(
        gmcs_context.server.media_state_characteristic,
        value=bytes([mcp.MediaState.PLAYING]),
    )

    assert (await asyncio.wait_for(state.get(), TIMEOUT)) == mcp.MediaState.PLAYING


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_update_track_title(gmcs_context):
    state = asyncio.Queue()
    gmcs_context.client.on('track_title', state.put_nowait)

    await gmcs_context.devices[0].notify_subscribers(
        gmcs_context.server.track_title_characteristic,
        value="My Song".encode(),
    )

    assert (await asyncio.wait_for(state.get(), TIMEOUT)) == "My Song"


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_update_track_duration(gmcs_context):
    state = asyncio.Queue()
    gmcs_context.client.on('track_duration', state.put_nowait)

    await gmcs_context.devices[0].notify_subscribers(
        gmcs_context.server.track_duration_characteristic,
        value=struct.pack("<i", 1000),
    )

    assert (await asyncio.wait_for(state.get(), TIMEOUT)) == 1000


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_update_track_position(gmcs_context):
    state = asyncio.Queue()
    gmcs_context.client.on('track_position', state.put_nowait)

    await gmcs_context.devices[0].notify_subscribers(
        gmcs_context.server.track_position_characteristic,
        value=struct.pack("<i", 1000),
    )

    assert (await asyncio.wait_for(state.get(), TIMEOUT)) == 1000


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_write_media_control_point(gmcs_context):
    assert (
        await asyncio.wait_for(
            gmcs_context.client.write_control_point(mcp.MediaControlPointOpcode.PAUSE),
            TIMEOUT,
        )
    ) == mcp.MediaControlPointResultCode.SUCCESS
