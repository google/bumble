# Copyright 2021-2025 Google LLC
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
import dataclasses
import enum

from typing import Optional, Sequence

from bumble import att
from bumble import utils
from bumble import device
from bumble import gatt
from bumble import gatt_adapters
from bumble import gatt_client


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


@dataclasses.dataclass
class VolumeState:
    volume_setting: int
    mute: int
    change_counter: int

    @classmethod
    def from_bytes(cls, data: bytes) -> VolumeState:
        return cls(data[0], data[1], data[2])

    def __bytes__(self) -> bytes:
        return bytes([self.volume_setting, self.mute, self.change_counter])


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class VolumeControlService(gatt.TemplateService):
    UUID = gatt.GATT_VOLUME_CONTROL_SERVICE

    volume_state: gatt.Characteristic[bytes]
    volume_control_point: gatt.Characteristic[bytes]
    volume_flags: gatt.Characteristic[bytes]

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
        included_services: Sequence[gatt.Service] = (),
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
            characteristics=[
                self.volume_state,
                self.volume_control_point,
                self.volume_flags,
            ],
            included_services=list(included_services),
        )

    def _on_read_volume_state(self, _connection: Optional[device.Connection]) -> bytes:
        return bytes(VolumeState(self.volume_setting, self.muted, self.change_counter))

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
            utils.cancel_on_event(
                connection,
                'disconnection',
                connection.device.notify_subscribers(attribute=self.volume_state),
            )
            self.emit('volume_state_change')

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

    volume_control_point: gatt_client.CharacteristicProxy[bytes]
    volume_state: gatt_client.CharacteristicProxy[VolumeState]
    volume_flags: gatt_client.CharacteristicProxy[VolumeFlags]

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.volume_state = gatt_adapters.SerializableCharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                gatt.GATT_VOLUME_STATE_CHARACTERISTIC
            ),
            VolumeState,
        )

        self.volume_control_point = service_proxy.get_required_characteristic_by_uuid(
            gatt.GATT_VOLUME_CONTROL_POINT_CHARACTERISTIC
        )

        self.volume_flags = gatt_adapters.DelegatedCharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                gatt.GATT_VOLUME_FLAGS_CHARACTERISTIC
            ),
            decode=lambda data: VolumeFlags(data[0]),
        )
