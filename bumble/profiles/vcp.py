# Copyright 2021-2024 Google LLC
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
from __future__ import annotations
import enum

from bumble import att
from bumble import device
from bumble import gatt
from bumble import gatt_client

from typing import Optional

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

MIN_VOLUME = 0
MAX_VOLUME = 255


class ErrorCode(enum.IntEnum):
    '''
    See Volume Control Service 1.6. Application error codes.
    '''

    INVALID_CHANGE_COUNTER = 0x80
    OPCODE_NOT_SUPPORTED = 0x81


class VolumeFlags(enum.IntFlag):
    '''
    See Volume Control Service 3.3. Volume Flags.
    '''

    VOLUME_SETTING_PERSISTED = 0x01
    # RFU


class VolumeControlPointOpcode(enum.IntEnum):
    '''
    See Volume Control Service Table 3.3: Volume Control Point procedure requirements.
    '''

    # fmt: off
    RELATIVE_VOLUME_DOWN        = 0x00
    RELATIVE_VOLUME_UP          = 0x01
    UNMUTE_RELATIVE_VOLUME_DOWN = 0x02
    UNMUTE_RELATIVE_VOLUME_UP   = 0x03
    SET_ABSOLUTE_VOLUME         = 0x04
    UNMUTE                      = 0x05
    MUTE                        = 0x06


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class VolumeControlService(gatt.TemplateService):
    UUID = gatt.GATT_VOLUME_CONTROL_SERVICE

    volume_state: gatt.Characteristic
    volume_control_point: gatt.Characteristic
    volume_flags: gatt.Characteristic

    volume_setting: int
    muted: int
    change_counter: int

    def __init__(
        self,
        step_size: int = 16,
        volume_setting: int = 0,
        muted: int = 0,
        change_counter: int = 0,
        volume_flags: int = 0,
    ) -> None:
        self.step_size = step_size
        self.volume_setting = volume_setting
        self.muted = muted
        self.change_counter = change_counter

        self.volume_state = gatt.Characteristic(
            uuid=gatt.GATT_VOLUME_STATE_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY
            ),
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=gatt.CharacteristicValue(read=self._on_read_volume_state),
        )
        self.volume_control_point = gatt.Characteristic(
            uuid=gatt.GATT_VOLUME_CONTROL_POINT_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.WRITE,
            permissions=gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=gatt.CharacteristicValue(write=self._on_write_volume_control_point),
        )
        self.volume_flags = gatt.Characteristic(
            uuid=gatt.GATT_VOLUME_FLAGS_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=bytes([volume_flags]),
        )

        super().__init__(
            [
                self.volume_state,
                self.volume_control_point,
                self.volume_flags,
            ]
        )

    @property
    def volume_state_bytes(self) -> bytes:
        return bytes([self.volume_setting, self.muted, self.change_counter])

    @volume_state_bytes.setter
    def volume_state_bytes(self, new_value: bytes) -> None:
        self.volume_setting, self.muted, self.change_counter = new_value

    def _on_read_volume_state(self, _connection: Optional[device.Connection]) -> bytes:
        return self.volume_state_bytes

    def _on_write_volume_control_point(
        self, connection: Optional[device.Connection], value: bytes
    ) -> None:
        assert connection

        opcode = VolumeControlPointOpcode(value[0])
        change_counter = value[1]

        if change_counter != self.change_counter:
            raise att.ATT_Error(ErrorCode.INVALID_CHANGE_COUNTER)

        handler = getattr(self, '_on_' + opcode.name.lower())
        if handler(*value[2:]):
            self.change_counter = (self.change_counter + 1) % 256
            connection.abort_on(
                'disconnection',
                connection.device.notify_subscribers(
                    attribute=self.volume_state,
                    value=self.volume_state_bytes,
                ),
            )
            self.emit(
                'volume_state', self.volume_setting, self.muted, self.change_counter
            )

    def _on_relative_volume_down(self) -> bool:
        old_volume = self.volume_setting
        self.volume_setting = max(self.volume_setting - self.step_size, MIN_VOLUME)
        return self.volume_setting != old_volume

    def _on_relative_volume_up(self) -> bool:
        old_volume = self.volume_setting
        self.volume_setting = min(self.volume_setting + self.step_size, MAX_VOLUME)
        return self.volume_setting != old_volume

    def _on_unmute_relative_volume_down(self) -> bool:
        old_volume, old_muted_state = self.volume_setting, self.muted
        self.volume_setting = max(self.volume_setting - self.step_size, MIN_VOLUME)
        self.muted = 0
        return (self.volume_setting, self.muted) != (old_volume, old_muted_state)

    def _on_unmute_relative_volume_up(self) -> bool:
        old_volume, old_muted_state = self.volume_setting, self.muted
        self.volume_setting = min(self.volume_setting + self.step_size, MAX_VOLUME)
        self.muted = 0
        return (self.volume_setting, self.muted) != (old_volume, old_muted_state)

    def _on_set_absolute_volume(self, volume_setting: int) -> bool:
        old_volume_setting = self.volume_setting
        self.volume_setting = volume_setting
        return old_volume_setting != self.volume_setting

    def _on_unmute(self) -> bool:
        old_muted_state = self.muted
        self.muted = 0
        return self.muted != old_muted_state

    def _on_mute(self) -> bool:
        old_muted_state = self.muted
        self.muted = 1
        return self.muted != old_muted_state


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class VolumeControlServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = VolumeControlService

    volume_control_point: gatt_client.CharacteristicProxy

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.volume_state = gatt.PackedCharacteristicAdapter(
            service_proxy.get_characteristics_by_uuid(
                gatt.GATT_VOLUME_STATE_CHARACTERISTIC
            )[0],
            'BBB',
        )

        self.volume_control_point = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_VOLUME_CONTROL_POINT_CHARACTERISTIC
        )[0]

        self.volume_flags = gatt.PackedCharacteristicAdapter(
            service_proxy.get_characteristics_by_uuid(
                gatt.GATT_VOLUME_FLAGS_CHARACTERISTIC
            )[0],
            'B',
        )
