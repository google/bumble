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

"""Le Audio - Audio Input Control Service"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import enum
import logging

from typing import Union, Optional

from bumble.core import UUID

from bumble.device import Connection

from bumble.gatt import (
    Characteristic,
    TemplateService,
    Attribute,
    CharacteristicValue,
    Sequence,
    Descriptor,
    PackedCharacteristicAdapter,
    GATT_AUDIO_INPUT_CONTROL_SERVICE,
    GATT_AUDIO_INPUT_STATE_CHARACTERISTIC,
    GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC,
    GATT_AUDIO_INPUT_TYPE_CHARACTERISTIC,
    GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC,
    GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC,
    GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC,
)

from bumble.gatt_client import ProfileServiceProxy, ServiceProxy

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
class Mute(enum.IntEnum):
    '''
    Cf. 2.2.1.2 Mute Field
    '''

    NOT_MUTED = 0x00
    MUTED = 0x01
    DISABLED = 0x02


class GainMode(enum.IntEnum):
    '''
    Cf. 2.2.1.3 Gain Mode
    '''

    MANUAL_ONLY = 0x00
    AUTOMATIC_ONLY = 0x01
    MANUAL = 0x02
    AUTOMATIC = 0x03


class AudioInputType(enum.IntEnum):
    INATIVE = 0x00
    ACTIVE = 0x01


# -----------------------------------------------------------------------------
class AudioInputState(Characteristic):
    '''
    Cf. 2.2.1 Audio Input State
    '''

    def __init__(
        self,
        uuid: Union[str, bytes, UUID],
        properties: Characteristic.Properties,
        permissions: Union[str, Attribute.Permissions],
        descriptors: Sequence[Descriptor] = (),
    ):
        self.gain_settings: int = 0
        self.gain_settings_unit: int = 1
        self.mute: Mute = Mute.NOT_MUTED
        self.gain_mode: GainMode = GainMode.AUTOMATIC_ONLY
        self.change_counter: int = 0x00

        value = CharacteristicValue(read=self._on_read)

        super().__init__(uuid, properties, permissions, value, descriptors)

    def __bytes__(self) -> bytes:
        return bytes(
            [self.gain_settings, self.mute, self.gain_mode, self.change_counter]
        )

    def update_gain_settings_unit(self, gain_settings_unit: int) -> None:
        self.gain_settings_unit = gain_settings_unit

    def increment_gain(self) -> None:
        self.gain_settings += self.gain_settings_unit
        self._increment_change_counter()

    def decrement_gain(self) -> None:
        self.gain_settings -= self.gain_settings_unit
        self._increment_change_counter()

    def _increment_change_counter(self):
        self.change_counter += 1
        if self.change_counter > 255:
            self.change_counter = 0

    def _on_read(self, _connection: Optional[Connection]) -> bytes:
        return self.__bytes__()


class GainSettingsProperties(Characteristic):
    '''
    Cf. 3.2 Gain Settings Properties
    '''

    def __init__(
        self,
        uuid: Union[str, bytes, UUID],
        properties: Characteristic.Properties,
        permissions: Union[str, Attribute.Permissions],
        descriptors: Sequence[Descriptor] = (),
    ):
        self.gain_settings_unit: int = 1
        self.gain_settings_minimum: int = 0
        self.gain_settings_maximum: int = 255

        value = CharacteristicValue(read=self._on_read)
        super().__init__(uuid, properties, permissions, value, descriptors)

    def __bytes__(self) -> bytes:
        return bytes(
            [
                self.gain_settings_unit,
                self.gain_settings_minimum,
                self.gain_settings_maximum,
            ]
        )

    def _on_read(self, _connection: Optional[Connection]) -> bytes:
        return self.__bytes__()


class AICSService(TemplateService):
    UUID = GATT_AUDIO_INPUT_CONTROL_SERVICE

    def __init__(self):
        self.audio_input_state = AudioInputState(
            uuid=GATT_AUDIO_INPUT_STATE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ
            | Characteristic.Properties.NOTIFY,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
        )
        self.gain_settings_properties = GainSettingsProperties(
            uuid=GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
        )
        self.audio_input_type = Characteristic(
            uuid=GATT_AUDIO_INPUT_TYPE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.audio_input_status = Characteristic(
            uuid=GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.audio_input_control_point = Characteristic(
            uuid=GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC,
            properties=Characteristic.Properties.WRITE,
            permissions=Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.audio_input_description = Characteristic(
            uuid=GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC,
            properties=Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            permissions=Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=b'',
        )
        super().__init__(
            [
                self.audio_input_state,
                self.gain_settings_properties,
                self.audio_input_type,
                self.audio_input_status,
                self.audio_input_control_point,
                self.audio_input_description,
            ]
        )


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class AICSServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = AICSService

    def __init__(self, service_proxy: ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.audio_input_state = PackedCharacteristicAdapter(
            service_proxy.get_characteristics_by_uuid(
                GATT_AUDIO_INPUT_STATE_CHARACTERISTIC
            )[0],
            'BBBB',
        )

        self.gain_settings_properties = PackedCharacteristicAdapter(
            service_proxy.get_characteristics_by_uuid(
                GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC
            )[0],
            'BBB',
        )
