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
import struct

from bumble import device

from bumble.att import ATT_Error

from bumble.profiles.vocs import (
    VolumeOffsetControlService,
    ErrorCode,
    MIN_VOLUME_OFFSET,
    MAX_VOLUME_OFFSET,
    SetVolumeOffsetOpCode,
    VolumeOffsetControlServiceProxy,
    VolumeOffsetState,
)
from bumble.profiles.vcs import VolumeControlService, VolumeControlServiceProxy
from bumble.profiles.bap import AudioLocation

from .test_utils import TwoDevices


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
vocs_service = VolumeOffsetControlService()
vcp_service = VolumeControlService(included_services=[vocs_service])


@pytest_asyncio.fixture
async def vocs_client():
    devices = TwoDevices()
    devices[0].add_service(vcp_service)

    await devices.setup_connection()

    assert devices.connections[0]
    assert devices.connections[1]

    devices.connections[0].encryption = 1
    devices.connections[1].encryption = 1

    peer = device.Peer(devices.connections[1])

    vcp_client = await peer.discover_service_and_create_proxy(VolumeControlServiceProxy)

    assert vcp_client
    included_services = await peer.discover_included_services(vcp_client.service_proxy)
    assert included_services
    vocs_service_discovered = included_services[0]
    await peer.discover_characteristics(service=vocs_service_discovered)
    vocs_client = VolumeOffsetControlServiceProxy(vocs_service_discovered)

    yield vocs_client


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_init_service(vocs_client: VolumeOffsetControlServiceProxy):
    assert await vocs_client.volume_offset_state.read_value() == VolumeOffsetState(
        volume_offset=0,
        change_counter=0,
    )
    assert await vocs_client.audio_location.read_value() == AudioLocation.NOT_ALLOWED
    description = await vocs_client.audio_output_description.read_value()
    assert description == ''


@pytest.mark.asyncio
async def test_wrong_opcode_raise_error(vocs_client: VolumeOffsetControlServiceProxy):
    with pytest.raises(ATT_Error) as e:
        await vocs_client.volume_offset_control_point.write_value(
            bytes(
                [
                    0xFF,
                ]
            ),
            with_response=True,
        )

    assert e.value.error_code == ErrorCode.OPCODE_NOT_SUPPORTED


@pytest.mark.asyncio
async def test_wrong_change_counter_raise_error(
    vocs_client: VolumeOffsetControlServiceProxy,
):
    initial_offset = vocs_service.volume_offset_state.volume_offset
    initial_counter = vocs_service.volume_offset_state.change_counter
    wrong_counter = initial_counter + 1

    with pytest.raises(ATT_Error) as e:
        await vocs_client.volume_offset_control_point.write_value(
            struct.pack(
                '<BBh', SetVolumeOffsetOpCode.SET_VOLUME_OFFSET, wrong_counter, 0
            ),
            with_response=True,
        )
    assert e.value.error_code == ErrorCode.INVALID_CHANGE_COUNTER

    counter = await vocs_client.volume_offset_state.read_value()
    assert counter == VolumeOffsetState(initial_offset, initial_counter)


@pytest.mark.asyncio
async def test_wrong_volume_offset_raise_error(
    vocs_client: VolumeOffsetControlServiceProxy,
):
    invalid_offset_low = MIN_VOLUME_OFFSET - 1
    invalid_offset_high = MAX_VOLUME_OFFSET + 1

    with pytest.raises(ATT_Error) as e_low:
        await vocs_client.volume_offset_control_point.write_value(
            struct.pack(
                '<BBh', SetVolumeOffsetOpCode.SET_VOLUME_OFFSET, 0, invalid_offset_low
            ),
            with_response=True,
        )
    assert e_low.value.error_code == ErrorCode.VALUE_OUT_OF_RANGE

    with pytest.raises(ATT_Error) as e_high:
        await vocs_client.volume_offset_control_point.write_value(
            struct.pack(
                '<BBh', SetVolumeOffsetOpCode.SET_VOLUME_OFFSET, 0, invalid_offset_high
            ),
            with_response=True,
        )
    assert e_high.value.error_code == ErrorCode.VALUE_OUT_OF_RANGE


@pytest.mark.asyncio
async def test_set_volume_offset(vocs_client: VolumeOffsetControlServiceProxy):
    await vocs_client.volume_offset_control_point.write_value(
        struct.pack('<BBh', SetVolumeOffsetOpCode.SET_VOLUME_OFFSET, 0, -255),
    )
    assert await vocs_client.volume_offset_state.read_value() == VolumeOffsetState(
        -255, 1
    )


@pytest.mark.asyncio
async def test_set_audio_channel_location(vocs_client: VolumeOffsetControlServiceProxy):
    new_audio_location = AudioLocation.FRONT_LEFT

    await vocs_client.audio_location.write_value(new_audio_location)

    location = await vocs_client.audio_location.read_value()
    assert location == new_audio_location


@pytest.mark.asyncio
async def test_set_audio_output_description(
    vocs_client: VolumeOffsetControlServiceProxy,
):
    new_description = 'Left Speaker'

    await vocs_client.audio_output_description.write_value(new_description)

    description = await vocs_client.audio_output_description.read_value()
    assert description == new_description
