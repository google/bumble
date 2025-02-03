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

from bumble.att import ATT_Error

from bumble.profiles.aics import (
    Mute,
    AICSService,
    AudioInputState,
    AICSServiceProxy,
    GainMode,
    GainSettingsProperties,
    AudioInputStatus,
    AudioInputControlPointOpCode,
    ErrorCode,
)
from bumble.profiles.vcs import VolumeControlService, VolumeControlServiceProxy

from .test_utils import TwoDevices


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
aics_service = AICSService()
vcp_service = VolumeControlService(
    volume_setting=32, muted=1, volume_flags=1, included_services=[aics_service]
)


@pytest_asyncio.fixture
async def aics_client():
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
    aics_service_discovered = included_services[0]
    await peer.discover_characteristics(service=aics_service_discovered)
    aics_client = AICSServiceProxy(aics_service_discovered)

    yield aics_client


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_init_service(aics_client: AICSServiceProxy):
    assert await aics_client.audio_input_state.read_value() == AudioInputState(
        gain_settings=0,
        mute=Mute.NOT_MUTED,
        gain_mode=GainMode.MANUAL,
        change_counter=0,
    )
    assert (
        await aics_client.gain_settings_properties.read_value()
        == GainSettingsProperties(
            gain_settings_unit=1, gain_settings_minimum=0, gain_settings_maximum=255
        )
    )
    assert await aics_client.audio_input_status.read_value() == (
        AudioInputStatus.ACTIVE
    )


@pytest.mark.asyncio
async def test_wrong_opcode_raise_error(aics_client: AICSServiceProxy):
    with pytest.raises(ATT_Error) as e:
        await aics_client.audio_input_control_point.write_value(
            bytes(
                [
                    0xFF,
                ]
            ),
            with_response=True,
        )

    assert e.value.error_code == ErrorCode.OPCODE_NOT_SUPPORTED


@pytest.mark.asyncio
async def test_set_gain_setting_when_gain_mode_automatic_only(
    aics_client: AICSServiceProxy,
):
    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC_ONLY

    change_counter = 0
    gain_settings = 120
    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.SET_GAIN_SETTING,
                change_counter,
                gain_settings,
            ]
        )
    )

    # Unchanged
    assert await aics_client.audio_input_state.read_value() == AudioInputState(
        gain_settings=0,
        mute=Mute.NOT_MUTED,
        gain_mode=GainMode.AUTOMATIC_ONLY,
        change_counter=0,
    )


@pytest.mark.asyncio
async def test_set_gain_setting_when_gain_mode_automatic(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC
    change_counter = 0
    gain_settings = 120
    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.SET_GAIN_SETTING,
                change_counter,
                gain_settings,
            ]
        )
    )

    # Unchanged
    assert await aics_client.audio_input_state.read_value() == AudioInputState(
        gain_settings=0,
        mute=Mute.NOT_MUTED,
        gain_mode=GainMode.AUTOMATIC,
        change_counter=0,
    )


@pytest.mark.asyncio
async def test_set_gain_setting_when_gain_mode_MANUAL(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.gain_mode = GainMode.MANUAL
    change_counter = 0
    gain_settings = 120
    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.SET_GAIN_SETTING,
                change_counter,
                gain_settings,
            ]
        )
    )

    assert await aics_client.audio_input_state.read_value() == AudioInputState(
        gain_settings=gain_settings,
        mute=Mute.NOT_MUTED,
        gain_mode=GainMode.MANUAL,
        change_counter=change_counter,
    )


@pytest.mark.asyncio
async def test_set_gain_setting_when_gain_mode_MANUAL_ONLY(
    aics_client: AICSServiceProxy,
):
    aics_service.audio_input_state.gain_mode = GainMode.MANUAL_ONLY
    change_counter = 0
    gain_settings = 120
    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.SET_GAIN_SETTING,
                change_counter,
                gain_settings,
            ]
        )
    )

    assert await aics_client.audio_input_state.read_value() == AudioInputState(
        gain_settings=gain_settings,
        mute=Mute.NOT_MUTED,
        gain_mode=GainMode.MANUAL_ONLY,
        change_counter=change_counter,
    )


@pytest.mark.asyncio
async def test_unmute_when_muted(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.mute = Mute.MUTED
    change_counter = 0
    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.UNMUTE,
                change_counter,
            ]
        )
    )

    change_counter += 1

    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.mute == Mute.NOT_MUTED
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_unmute_when_mute_disabled(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.mute = Mute.DISABLED
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    with pytest.raises(ATT_Error) as e:
        await aics_client.audio_input_control_point.write_value(
            bytes(
                [
                    AudioInputControlPointOpCode.UNMUTE,
                    change_counter,
                ]
            ),
            with_response=True,
        )

    assert e.value.error_code == ErrorCode.MUTE_DISABLED

    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.mute == Mute.DISABLED
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_mute_when_not_muted(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.mute = Mute.NOT_MUTED
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.MUTE,
                change_counter,
            ]
        )
    )

    change_counter += 1
    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.mute == Mute.MUTED
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_mute_when_mute_disabled(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.mute = Mute.DISABLED
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    with pytest.raises(ATT_Error) as e:
        await aics_client.audio_input_control_point.write_value(
            bytes(
                [
                    AudioInputControlPointOpCode.MUTE,
                    change_counter,
                ]
            ),
            with_response=True,
        )

    assert e.value.error_code == ErrorCode.MUTE_DISABLED

    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.mute == Mute.DISABLED
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_set_manual_gain_mode_when_automatic(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE,
                change_counter,
            ]
        )
    )

    change_counter += 1
    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.gain_mode == GainMode.MANUAL
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_set_manual_gain_mode_when_already_manual(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.gain_mode = GainMode.MANUAL
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE,
                change_counter,
            ]
        )
    )

    # No change expected
    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.gain_mode == GainMode.MANUAL
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_set_manual_gain_mode_when_manual_only(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.gain_mode = GainMode.MANUAL_ONLY
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    with pytest.raises(ATT_Error) as e:
        await aics_client.audio_input_control_point.write_value(
            bytes(
                [
                    AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE,
                    change_counter,
                ]
            ),
            with_response=True,
        )

    assert e.value.error_code == ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED

    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.gain_mode == GainMode.MANUAL_ONLY
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_set_manual_gain_mode_when_automatic_only(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC_ONLY
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    with pytest.raises(ATT_Error) as e:
        await aics_client.audio_input_control_point.write_value(
            bytes(
                [
                    AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE,
                    change_counter,
                ]
            ),
            with_response=True,
        )

    assert e.value.error_code == ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED

    # No change expected
    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.gain_mode == GainMode.AUTOMATIC_ONLY
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_set_automatic_gain_mode_when_manual(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.gain_mode = GainMode.MANUAL
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE,
                change_counter,
            ]
        )
    )

    change_counter += 1
    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.gain_mode == GainMode.AUTOMATIC
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_set_automatic_gain_mode_when_already_automatic(
    aics_client: AICSServiceProxy,
):
    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    await aics_client.audio_input_control_point.write_value(
        bytes(
            [
                AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE,
                change_counter,
            ]
        )
    )

    # No change expected
    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.gain_mode == GainMode.AUTOMATIC
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_set_automatic_gain_mode_when_manual_only(aics_client: AICSServiceProxy):
    aics_service.audio_input_state.gain_mode = GainMode.MANUAL_ONLY
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    with pytest.raises(ATT_Error) as e:
        await aics_client.audio_input_control_point.write_value(
            bytes(
                [
                    AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE,
                    change_counter,
                ]
            ),
            with_response=True,
        )

    assert e.value.error_code == ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED

    # No change expected
    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.gain_mode == GainMode.MANUAL_ONLY
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_set_automatic_gain_mode_when_automatic_only(
    aics_client: AICSServiceProxy,
):
    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC_ONLY
    aics_service.audio_input_state.change_counter = 0
    change_counter = 0

    with pytest.raises(ATT_Error) as e:
        await aics_client.audio_input_control_point.write_value(
            bytes(
                [
                    AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE,
                    change_counter,
                ]
            ),
            with_response=True,
        )

    assert e.value.error_code == ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED

    # No change expected
    state: AudioInputState = await aics_client.audio_input_state.read_value()
    assert state.gain_mode == GainMode.AUTOMATIC_ONLY
    assert state.change_counter == change_counter


@pytest.mark.asyncio
async def test_audio_input_description_initial_value(aics_client: AICSServiceProxy):
    description = await aics_client.audio_input_description.read_value()
    assert description == "Bluetooth"


@pytest.mark.asyncio
async def test_audio_input_description_write_and_read(aics_client: AICSServiceProxy):
    new_description = "Line Input"

    await aics_client.audio_input_description.write_value(new_description)

    description = await aics_client.audio_input_description.read_value()
    assert description == new_description
