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

from bumble.att import ATT_Error

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
CHANGE_COUNTER_MAX_VALUE = 0xFF
GAIN_SETTINGS_MIN_VALUE = 0
GAIN_SETTINGS_MAX_VALUE = 255


class ErrorCode(enum.IntEnum):
    '''
    Cf. 1.6 Application error codes
    '''

    INVALID_CHANGE_COUNTER = 0x80
    OPCODE_NOT_SUPPORTED = 0x81
    MUTE_DISABLED = 0x82
    VALUE_OUT_OF_RANGE = 0x83
    GAIN_MODE_CHANGE_NOT_ALLOWED = 0x84


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


class AudioInputStatus(enum.IntEnum):
    '''
    Cf. 3.4 Audio Input Status
    '''

    INATIVE = 0x00
    ACTIVE = 0x01


class AudioInputControlPointOpCode(enum.IntEnum):
    '''
    Cf. 3.5.1 Audio Input Control Point procedure requirements
    '''

    SET_GAIN_SETTING = 0x00
    UNMUTE = 0x02
    MUTE = 0x03
    SET_MANUAL_GAIN_MODE = 0x04
    SET_AUTOMATIC_GAIN_MODE = 0x05


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
        gain_settings: int,
        gain_settings_unit: int,
        mute: Mute,
        gain_mode: GainMode,
        descriptors: Sequence[Descriptor] = (),
    ):
        self.gain_settings = gain_settings
        self.gain_settings_unit = gain_settings_unit
        self.mute: Mute = mute
        self.gain_mode: GainMode = gain_mode
        self.change_counter = 0

        value = CharacteristicValue(read=self._on_read)

        super().__init__(uuid, properties, permissions, value, descriptors)

    def __bytes__(self) -> bytes:
        return bytes(
            [self.gain_settings, self.mute, self.gain_mode, self.change_counter]
        )

    def update_gain_settings_unit(self, gain_settings_unit: int) -> None:
        self.gain_settings_unit = gain_settings_unit

    def increment_gain_settings(self) -> None:
        self.gain_settings += self.gain_settings_unit
        self.increment_change_counter()

    def decrement_gain_settings(self) -> None:
        self.gain_settings -= self.gain_settings_unit
        self.increment_change_counter()

    def increment_change_counter(self):
        self.change_counter += 0x01
        if self.change_counter > CHANGE_COUNTER_MAX_VALUE:
            self.change_counter = 0x00

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
        gain_settings_unit: int,
        descriptors: Sequence[Descriptor] = (),
    ):
        self.gain_settings_unit: int = gain_settings_unit
        self.gain_settings_minimum: int = GAIN_SETTINGS_MIN_VALUE
        self.gain_settings_maximum: int = GAIN_SETTINGS_MAX_VALUE

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


class AudioInputDescription(Characteristic):
    '''
    Cf. 3.6 Audio Input Description
    '''

    def __init__(
        self,
        uuid: Union[str, bytes, UUID],
        properties: Characteristic.Properties,
        permissions: Union[str, Attribute.Permissions],
        audio_input_description_value: str,
        descriptors: Sequence[Descriptor] = (),
    ):

        self.audio_input_status_value = audio_input_description_value

        value = CharacteristicValue(read=self._on_read, write=self._on_write)

        super().__init__(uuid, properties, permissions, value, descriptors)

    def _on_read(self, _connection: Optional[Connection]) -> bytes:
        return self.audio_input_status_value.encode('utf-8')

    def _on_write(self, _connection: Optional[Connection], value: bytes) -> None:
        self.audio_input_status_value = value.decode('utf-8')


class AudioInputControlPoint(Characteristic):
    '''
    Cf. 3.5.2 Audio Input Control Point
    '''

    def __init__(
        self,
        uuid: Union[str, bytes, UUID],
        properties: Characteristic.Properties,
        permissions: Union[str, Attribute.Permissions],
        audio_input_state: AudioInputState,
        gain_settings_properties: GainSettingsProperties,
        descriptors: Sequence[Descriptor] = (),
    ):

        self.audio_input_state = audio_input_state
        self.gain_settings_properties = gain_settings_properties

        value = CharacteristicValue(write=self._on_write)

        super().__init__(uuid, properties, permissions, value, descriptors)

    def _on_write(self, connection: Optional[Connection], value: bytes) -> None:
        assert connection

        def _set_gain_settings(gain_settings_operand: int) -> None:
            '''Cf. 3.5.2.1 Set Gain Settings Procedure'''

            gain_mode = self.audio_input_state.gain_mode

            if not (gain_mode == GainMode.MANUAL or gain_mode == GainMode.MANUAL_ONLY):
                logger.warning(
                    "GainMode should be either MANUAL or MANUAL_ONLY Cf Spec Audio Input Control Service 3.5.2.1"
                )
                return

            if (
                gain_settings_operand
                < self.gain_settings_properties.gain_settings_minimum
                or gain_settings_operand
                > self.gain_settings_properties.gain_settings_maximum
            ):
                logger.error("gain_seetings value out of range")
                raise ATT_Error(ErrorCode.VALUE_OUT_OF_RANGE)

            if self.audio_input_state.gain_settings != gain_settings_operand:
                self.audio_input_state.gain_settings = gain_settings_operand
                pass  # TODO: NOTIFY CLIENT

        def _unmute():
            '''Cf. 3.5.2.2 Unmute procedure'''

            logger.error(f'unmute: {self.audio_input_state.mute}')
            mute = self.audio_input_state.mute
            if mute == Mute.DISABLED:
                logger.error("unmute: Cannot change Mute value, Mute state is DISABLED")
                raise ATT_Error(ErrorCode.MUTE_DISABLED)

            if mute == Mute.NOT_MUTED:
                return

            self.audio_input_state.mute = Mute.NOT_MUTED
            self.audio_input_state.increment_change_counter()
            # TODO: NOTIFY CLIENT

        def _mute() -> None:
            '''Cf. 3.5.5.2 Mute procedure'''

            change_counter = self.audio_input_state.change_counter
            mute = self.audio_input_state.mute
            if mute == Mute.DISABLED:
                logger.error("mute: Cannot change Mute value, Mute state is DISABLED")
                raise ATT_Error(ErrorCode.MUTE_DISABLED)

            change_counter_operand = value[1]
            if change_counter != change_counter_operand:
                raise ATT_Error(ErrorCode.INVALID_CHANGE_COUNTER)

            if mute == Mute.MUTED:
                return

            self.audio_input_state.mute = Mute.MUTED
            self.audio_input_state.increment_change_counter()
            # TODO: NOTIFY CLIENT

        def _set_manual_gain_mode() -> None:
            '''Cf. 3.5.2.4 Set Manual Gain Mode procedure'''

            gain_mode = self.audio_input_state.gain_mode
            if gain_mode in (GainMode.AUTOMATIC_ONLY, GainMode.MANUAL_ONLY):
                logger.error(f"Cannot change gain_mode, bad state: {gain_mode}")
                raise ATT_Error(ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED)

            if gain_mode == GainMode.MANUAL:
                return

            self.audio_input_state.gain_mode = GainMode.MANUAL
            self.audio_input_state.increment_change_counter()
            # TODO: Notify client

        def _set_automatic_gain_mode() -> None:
            '''Cf. 3.5.2.5 Set Automatic Gain Mode'''

            gain_mode = self.audio_input_state.gain_mode
            if gain_mode in (GainMode.AUTOMATIC_ONLY, GainMode.MANUAL_ONLY):
                logger.error(f"Cannot change gain_mode, bad state: {gain_mode}")
                raise ATT_Error(ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED)

            if gain_mode == GainMode.AUTOMATIC:
                return

            self.audio_input_state.gain_mode = GainMode.AUTOMATIC
            self.audio_input_state.increment_change_counter()
            # TODO: NOTIFY CLIENT

        try:
            opcode = AudioInputControlPointOpCode(value[0])

            opcode = AudioInputControlPointOpCode(value[0])

            if opcode == AudioInputControlPointOpCode.SET_GAIN_SETTING:
                _set_gain_settings(value[2])
            elif opcode == AudioInputControlPointOpCode.UNMUTE:
                _unmute()
            elif opcode == AudioInputControlPointOpCode.MUTE:
                _mute()
            elif opcode == AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE:
                _set_manual_gain_mode()
            elif opcode == AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE:
                _set_automatic_gain_mode()

        except ValueError as e:
            logger.error(f"OpCode value is incorrect: {e}")
            raise ATT_Error(ErrorCode.OPCODE_NOT_SUPPORTED)


class AICSService(TemplateService):
    UUID = GATT_AUDIO_INPUT_CONTROL_SERVICE

    def __init__(
        self,
        audio_input_status: AudioInputStatus = AudioInputStatus.ACTIVE,
        gain_settings: int = 0,
        gain_settings_unit: int = 1,
        mute: Mute = Mute.NOT_MUTED,
        gain_mode: GainMode = GainMode.AUTOMATIC_ONLY,
        audio_input_description_value: str = 'Bluetooth',
    ):
        self.audio_input_status_value = audio_input_status

        self.audio_input_state = AudioInputState(
            uuid=GATT_AUDIO_INPUT_STATE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ
            | Characteristic.Properties.NOTIFY,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            gain_settings=gain_settings,
            gain_settings_unit=gain_settings_unit,
            mute=mute,
            gain_mode=gain_mode,
        )
        self.gain_settings_properties = GainSettingsProperties(
            uuid=GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            gain_settings_unit=gain_settings_unit,
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
            value=bytes([self.audio_input_status_value]),
        )
        self.audio_input_control_point = AudioInputControlPoint(
            uuid=GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC,
            properties=Characteristic.Properties.WRITE,
            permissions=Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            audio_input_state=self.audio_input_state,
            gain_settings_properties=self.gain_settings_properties,
        )
        self.audio_input_description = AudioInputDescription(
            uuid=GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC,
            properties=Characteristic.Properties.READ
            | Characteristic.Properties.NOTIFY
            | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
            | Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            audio_input_description_value=audio_input_description_value,
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

        self.audio_input_status = PackedCharacteristicAdapter(
            service_proxy.get_characteristics_by_uuid(
                GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC
            )[0],
            'B',
        )

        self.audio_input_control_point = service_proxy.get_characteristics_by_uuid(
            GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC
        )[0]

        self.audio_input_description = service_proxy.get_characteristics_by_uuid(
            GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC
        )[0]
