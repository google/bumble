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
from bumble.profiles.gmap import (
    GamingAudioService,
    GamingAudioServiceProxy,
    GmapRole,
    UggFeatures,
    UgtFeatures,
    BgrFeatures,
    BgsFeatures,
)

from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
gmas_service = GamingAudioService(
    gmap_role=GmapRole.UNICAST_GAME_GATEWAY
    | GmapRole.UNICAST_GAME_TERMINAL
    | GmapRole.BROADCAST_GAME_RECEIVER
    | GmapRole.BROADCAST_GAME_SENDER,
    ugg_features=UggFeatures.UGG_MULTISINK,
    ugt_features=UgtFeatures.UGT_SOURCE,
    bgr_features=BgrFeatures.BGR_MULTISINK,
    bgs_features=BgsFeatures.BGS_96_KBPS,
)


@pytest_asyncio.fixture
async def gmap_client():
    devices = TwoDevices()
    devices[0].add_service(gmas_service)

    await devices.setup_connection()

    assert devices.connections[0]
    assert devices.connections[1]

    devices.connections[0].encryption = 1
    devices.connections[1].encryption = 1

    peer = device.Peer(devices.connections[1])

    gmap_client = await peer.discover_service_and_create_proxy(GamingAudioServiceProxy)

    assert gmap_client
    yield gmap_client


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_init_service(gmap_client: GamingAudioServiceProxy):
    assert (
        await gmap_client.gmap_role.read_value()
        == GmapRole.UNICAST_GAME_GATEWAY
        | GmapRole.UNICAST_GAME_TERMINAL
        | GmapRole.BROADCAST_GAME_RECEIVER
        | GmapRole.BROADCAST_GAME_SENDER
    )
    assert gmap_client.ugg_features is not None
    assert await gmap_client.ugg_features.read_value() == UggFeatures.UGG_MULTISINK
    assert gmap_client.ugt_features is not None
    assert await gmap_client.ugt_features.read_value() == UgtFeatures.UGT_SOURCE
    assert gmap_client.bgr_features is not None
    assert await gmap_client.bgr_features.read_value() == BgrFeatures.BGR_MULTISINK
    assert gmap_client.bgs_features is not None
    assert await gmap_client.bgs_features.read_value() == BgsFeatures.BGS_96_KBPS
