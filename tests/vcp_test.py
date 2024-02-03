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
import pytest
import pytest_asyncio
import logging

from bumble import device
from bumble.profiles import vcp
from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
@pytest_asyncio.fixture
async def vcp_client():
    devices = TwoDevices()
    devices[0].add_service(
        vcp.VolumeControlService(volume_setting=32, muted=1, volume_flags=1)
    )

    await devices.setup_connection()

    # Mock encryption.
    devices.connections[0].encryption = 1
    devices.connections[1].encryption = 1

    peer = device.Peer(devices.connections[1])
    vcp_client = await peer.discover_service_and_create_proxy(
        vcp.VolumeControlServiceProxy
    )
    yield vcp_client


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_init_service(vcp_client: vcp.VolumeControlServiceProxy):
    assert (await vcp_client.volume_flags.read_value()) == 1
    assert (await vcp_client.volume_state.read_value()) == (32, 1, 0)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_relative_volume_down(vcp_client: vcp.VolumeControlServiceProxy):
    await vcp_client.volume_control_point.write_value(
        bytes([vcp.VolumeControlPointOpcode.RELATIVE_VOLUME_DOWN, 0])
    )
    assert (await vcp_client.volume_state.read_value()) == (16, 1, 1)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_relative_volume_up(vcp_client: vcp.VolumeControlServiceProxy):
    await vcp_client.volume_control_point.write_value(
        bytes([vcp.VolumeControlPointOpcode.RELATIVE_VOLUME_UP, 0])
    )
    assert (await vcp_client.volume_state.read_value()) == (48, 1, 1)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unmute_relative_volume_down(vcp_client: vcp.VolumeControlServiceProxy):
    await vcp_client.volume_control_point.write_value(
        bytes([vcp.VolumeControlPointOpcode.UNMUTE_RELATIVE_VOLUME_DOWN, 0])
    )
    assert (await vcp_client.volume_state.read_value()) == (16, 0, 1)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unmute_relative_volume_up(vcp_client: vcp.VolumeControlServiceProxy):
    await vcp_client.volume_control_point.write_value(
        bytes([vcp.VolumeControlPointOpcode.UNMUTE_RELATIVE_VOLUME_UP, 0])
    )
    assert (await vcp_client.volume_state.read_value()) == (48, 0, 1)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_absolute_volume(vcp_client: vcp.VolumeControlServiceProxy):
    await vcp_client.volume_control_point.write_value(
        bytes([vcp.VolumeControlPointOpcode.SET_ABSOLUTE_VOLUME, 0, 255])
    )
    assert (await vcp_client.volume_state.read_value()) == (255, 1, 1)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_mute(vcp_client: vcp.VolumeControlServiceProxy):
    await vcp_client.volume_control_point.write_value(
        bytes([vcp.VolumeControlPointOpcode.MUTE, 0])
    )
    assert (await vcp_client.volume_state.read_value()) == (32, 1, 0)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unmute(vcp_client: vcp.VolumeControlServiceProxy):
    await vcp_client.volume_control_point.write_value(
        bytes([vcp.VolumeControlPointOpcode.UNMUTE, 0])
    )
    assert (await vcp_client.volume_state.read_value()) == (32, 0, 1)
