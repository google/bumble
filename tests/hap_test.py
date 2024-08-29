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
import pytest
import functools
import pytest_asyncio
import logging

from bumble import device
from bumble.profiles import hap
from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

foo_preset = hap.PresetRecord(1, "foo preset")
bar_preset = hap.PresetRecord(50, "bar preset")
foobar_preset = hap.PresetRecord(5, "foobar preset")

server_features = hap.HearingAidFeatures(
    hap.HearingAidType.MONAURAL_HEARING_AID,
    hap.PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_NOT_SUPPORTED,
    hap.IndependentPresets.IDENTICAL_PRESET_RECORD,
    hap.DynamicPresets.PRESET_RECORDS_DOES_NOT_CHANGE,
    hap.WritablePresetsSupport.WRITABLE_PRESET_RECORDS_SUPPORTED,
)


# -----------------------------------------------------------------------------
@pytest_asyncio.fixture
async def hap_client():
    devices = TwoDevices()
    devices[0].add_service(
        hap.HearingAccessService(
            devices[1], server_features, [foo_preset, bar_preset, foobar_preset]
        )
    )

    await devices.setup_connection()
    # TODO negotiate MTU > 49 to not truncate preset names

    # Mock encryption.
    devices.connections[0].encryption = 1  # type: ignore
    devices.connections[1].encryption = 1  # type: ignore

    peer = device.Peer(devices.connections[1])  # type: ignore
    hap_client = await peer.discover_service_and_create_proxy(
        hap.HearingAccessServiceProxy
    )
    assert hap_client
    await hap_client.setup_subscription()

    yield hap_client


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_init_service(hap_client: hap.HearingAccessServiceProxy):
    assert (
        hap.HearingAidFeatures_from_bytes(await hap_client.server_features.read_value())
        == server_features
    )
    assert (await hap_client.active_preset_index.read_value()) == (foo_preset.index)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_all_presets(hap_client: hap.HearingAccessServiceProxy):
    await hap_client.hearing_aid_preset_control_point.write_value(
        bytes([hap.HearingAidPresetControlPointOpcode.READ_PRESETS_REQUEST, 1, 0xFF])
    )
    assert (await hap_client.preset_control_point_indications.get())[2:] == bytes(
        foo_preset
    )
    assert (await hap_client.preset_control_point_indications.get())[2:] == bytes(
        foobar_preset
    )
    assert (await hap_client.preset_control_point_indications.get())[2:] == bytes(
        bar_preset
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_partial_presets(hap_client: hap.HearingAccessServiceProxy):
    await hap_client.hearing_aid_preset_control_point.write_value(
        bytes([hap.HearingAidPresetControlPointOpcode.READ_PRESETS_REQUEST, 3, 2])
    )
    assert (await hap_client.preset_control_point_indications.get())[2:] == bytes(
        foobar_preset
    )
    assert (await hap_client.preset_control_point_indications.get())[2:] == bytes(
        bar_preset
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_active_preset_change(hap_client: hap.HearingAccessServiceProxy):
    await hap_client.hearing_aid_preset_control_point.write_value(
        bytes([hap.HearingAidPresetControlPointOpcode.SET_NEXT_PRESET])
    )
    # TODO: this does not work and the preset index is not updated receive update
    # assert (await hap_client.active_preset_index.read_value()) == (foobar_preset.index)
