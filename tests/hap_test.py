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
import sys

from bumble import att, device
from bumble.profiles import hap
from .test_utils import TwoDevices
from bumble.keys import PairingKeys

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

foo_preset = hap.PresetRecord(1, "foo preset")
bar_preset = hap.PresetRecord(50, "bar preset")
foobar_preset = hap.PresetRecord(5, "foobar preset")
unavailable_preset = hap.PresetRecord(
    78,
    "foobar preset",
    hap.PresetRecord.Property(
        hap.PresetRecord.Property.Writable.CANNOT_BE_WRITTEN,
        hap.PresetRecord.Property.IsAvailable.IS_UNAVAILABLE,
    ),
)

server_features = hap.HearingAidFeatures(
    hap.HearingAidType.MONAURAL_HEARING_AID,
    hap.PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_NOT_SUPPORTED,
    hap.IndependentPresets.IDENTICAL_PRESET_RECORD,
    hap.DynamicPresets.PRESET_RECORDS_DOES_NOT_CHANGE,
    hap.WritablePresetsSupport.WRITABLE_PRESET_RECORDS_SUPPORTED,
)

TIMEOUT = 0.1


async def assert_queue_is_empty(queue: asyncio.Queue):
    assert queue.empty()

    # Check that nothing is being added during TIMEOUT secondes
    if sys.version_info >= (3, 11):
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(queue.get(), TIMEOUT)
    else:
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(queue.get(), TIMEOUT)


# -----------------------------------------------------------------------------
@pytest_asyncio.fixture
async def hap_client():
    devices = TwoDevices()
    devices[0].add_service(
        hap.HearingAccessService(
            devices[0],
            server_features,
            [foo_preset, bar_preset, foobar_preset, unavailable_preset],
        )
    )

    await devices.setup_connection()
    # TODO negotiate MTU > 49 to not truncate preset names

    # Mock encryption.
    devices.connections[0].encryption = 1  # type: ignore
    devices.connections[1].encryption = 1  # type: ignore

    devices[0].on_pairing(
        devices.connections[0], devices.connections[0].peer_address, PairingKeys(), True
    )

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
    assert (await hap_client.preset_control_point_indications.get()) == bytes(
        [hap.HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE, 0]
    ) + bytes(foo_preset)
    assert (await hap_client.preset_control_point_indications.get()) == bytes(
        [hap.HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE, 0]
    ) + bytes(foobar_preset)
    assert (await hap_client.preset_control_point_indications.get()) == bytes(
        [hap.HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE, 0]
    ) + bytes(bar_preset)
    assert (await hap_client.preset_control_point_indications.get()) == bytes(
        [hap.HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE, 1]
    ) + bytes(unavailable_preset)

    await assert_queue_is_empty(hap_client.preset_control_point_indications)


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
async def test_set_active_preset_valid(hap_client: hap.HearingAccessServiceProxy):
    await hap_client.hearing_aid_preset_control_point.write_value(
        bytes(
            [hap.HearingAidPresetControlPointOpcode.SET_ACTIVE_PRESET, bar_preset.index]
        )
    )
    assert (await hap_client.active_preset_index_notification.get()) == bar_preset.index

    assert (await hap_client.active_preset_index.read_value()) == (bar_preset.index)

    await assert_queue_is_empty(hap_client.active_preset_index_notification)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_active_preset_invalid(hap_client: hap.HearingAccessServiceProxy):
    with pytest.raises(att.ATT_Error) as e:
        await hap_client.hearing_aid_preset_control_point.write_value(
            bytes(
                [
                    hap.HearingAidPresetControlPointOpcode.SET_ACTIVE_PRESET,
                    unavailable_preset.index,
                ]
            ),
            with_response=True,
        )
    assert e.value.error_code == hap.ErrorCode.PRESET_OPERATION_NOT_POSSIBLE


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_next_preset(hap_client: hap.HearingAccessServiceProxy):
    await hap_client.hearing_aid_preset_control_point.write_value(
        bytes([hap.HearingAidPresetControlPointOpcode.SET_NEXT_PRESET])
    )
    assert (
        await hap_client.active_preset_index_notification.get()
    ) == foobar_preset.index

    assert (await hap_client.active_preset_index.read_value()) == (foobar_preset.index)

    await assert_queue_is_empty(hap_client.active_preset_index_notification)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_next_preset_will_loop_to_first(
    hap_client: hap.HearingAccessServiceProxy,
):
    async def go_next(new_preset: hap.PresetRecord):
        await hap_client.hearing_aid_preset_control_point.write_value(
            bytes([hap.HearingAidPresetControlPointOpcode.SET_NEXT_PRESET])
        )
        assert (
            await hap_client.active_preset_index_notification.get()
        ) == new_preset.index

        assert (await hap_client.active_preset_index.read_value()) == (new_preset.index)

    await go_next(foobar_preset)
    await go_next(bar_preset)
    await go_next(foo_preset)

    # Note that there is a invalid preset in the preset record of the server

    await assert_queue_is_empty(hap_client.active_preset_index_notification)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_previous_preset_will_loop_to_last(
    hap_client: hap.HearingAccessServiceProxy,
):
    await hap_client.hearing_aid_preset_control_point.write_value(
        bytes([hap.HearingAidPresetControlPointOpcode.SET_PREVIOUS_PRESET])
    )
    assert (await hap_client.active_preset_index_notification.get()) == bar_preset.index

    assert (await hap_client.active_preset_index.read_value()) == (bar_preset.index)

    await assert_queue_is_empty(hap_client.active_preset_index_notification)
