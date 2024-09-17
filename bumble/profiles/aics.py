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

"""LE Audio - Audio Input Control Service"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import logging
import struct

from dataclasses import dataclass
from typing import Optional

from bumble import gatt
from bumble.device import Connection
from bumble.att import ATT_Error
from bumble.gatt import (
    Characteristic,
    DelegatedCharacteristicAdapter,
    TemplateService,
    CharacteristicValue,
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
from bumble.utils import OpenIntEnum

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


class ErrorCode(OpenIntEnum):
    '''
    Cf. 1.6 Application error codes
    '''

    INVALID_CHANGE_COUNTER = 0x80
    OPCODE_NOT_SUPPORTED = 0x81
    MUTE_DISABLED = 0x82
    VALUE_OUT_OF_RANGE = 0x83
    GAIN_MODE_CHANGE_NOT_ALLOWED = 0x84


class Mute(OpenIntEnum):
    '''
    Cf. 2.2.1.2 Mute Field
    '''

    NOT_MUTED = 0x00
    MUTED = 0x01
    DISABLED = 0x02


class GainMode(OpenIntEnum):
    '''
    Cf. 2.2.1.3 Gain Mode
    '''

    MANUAL_ONLY = 0x00
    AUTOMATIC_ONLY = 0x01
    MANUAL = 0x02
    AUTOMATIC = 0x03


class AudioInputStatus(OpenIntEnum):
    '''
    Cf. 3.4 Audio Input Status
    '''

    INATIVE = 0x00
    ACTIVE = 0x01


class AudioInputControlPointOpCode(OpenIntEnum):
    '''
    Cf. 3.5.1 Audio Input Control Point procedure requirements
    '''

    SET_GAIN_SETTING = 0x00
    UNMUTE = 0x02
    MUTE = 0x03
    SET_MANUAL_GAIN_MODE = 0x04
    SET_AUTOMATIC_GAIN_MODE = 0x05


# -----------------------------------------------------------------------------
@dataclass
class AudioInputState:
    '''
    Cf. 2.2.1 Audio Input State
    '''

    gain_settings: int = 0
    mute: Mute = Mute.NOT_MUTED
    gain_mode: GainMode = GainMode.MANUAL
    change_counter: int = 0
    attribute_value: Optional[CharacteristicValue] = None

    def __bytes__(self) -> bytes:
        return bytes(
            [self.gain_settings, self.mute, self.gain_mode, self.change_counter]
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        gain_settings, mute, gain_mode, change_counter = struct.unpack("BBBB", data)
        return cls(gain_settings, mute, gain_mode, change_counter)

    def update_gain_settings_unit(self, gain_settings_unit: int) -> None:
        self.gain_settings_unit = gain_settings_unit

    def increment_gain_settings(self, gain_settings_unit: int) -> None:
        self.gain_settings += gain_settings_unit
        self.increment_change_counter()

    def decrement_gain_settings(self) -> None:
        self.gain_settings -= self.gain_settings_unit
        self.increment_change_counter()

    def increment_change_counter(self):
        self.change_counter = (self.change_counter + 1) % (CHANGE_COUNTER_MAX_VALUE + 1)

    async def notify_subscribers_via_connection(self, connection: Connection) -> None:
        assert self.attribute_value is not None
        await connection.device.notify_subscribers(
            attribute=self.attribute_value, value=bytes(self)
        )

    def on_read(self, _connection: Optional[Connection]) -> bytes:
        return bytes(self)


@dataclass
class GainSettingsProperties:
    '''
    Cf. 3.2 Gain Settings Properties
    '''

    gain_settings_unit: int = 1
    gain_settings_minimum: int = GAIN_SETTINGS_MIN_VALUE
    gain_settings_maximum: int = GAIN_SETTINGS_MAX_VALUE

    @classmethod
    def from_bytes(cls, data: bytes):
        (gain_settings_unit, gain_settings_minimum, gain_settings_maximum) = (
            struct.unpack('BBB', data)
        )
        GainSettingsProperties(
            gain_settings_unit, gain_settings_minimum, gain_settings_maximum
        )

    def __bytes__(self) -> bytes:
        return bytes(
            [
                self.gain_settings_unit,
                self.gain_settings_minimum,
                self.gain_settings_maximum,
            ]
        )

    def on_read(self, _connection: Optional[Connection]) -> bytes:
        return bytes(self)


@dataclass
class AudioInputControlPoint:
    '''
    Cf. 3.5.2 Audio Input Control Point
    '''

    audio_input_state: AudioInputState
    gain_settings_properties: GainSettingsProperties

    async def on_write(self, connection: Optional[Connection], value: bytes) -> None:
        assert connection

        opcode = AudioInputControlPointOpCode(value[0])

        if opcode == AudioInputControlPointOpCode.SET_GAIN_SETTING:
            gain_settings_operand = value[2]
            await self._set_gain_settings(connection, gain_settings_operand)
        elif opcode == AudioInputControlPointOpCode.UNMUTE:
            await self._unmute(connection)
        elif opcode == AudioInputControlPointOpCode.MUTE:
            change_counter_operand = value[1]
            await self._mute(connection, change_counter_operand)
        elif opcode == AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE:
            await self._set_manual_gain_mode(connection)
        elif opcode == AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE:
            await self._set_automatic_gain_mode(connection)
        else:
            logger.error(f"OpCode value is incorrect: {opcode}")
            raise ATT_Error(ErrorCode.OPCODE_NOT_SUPPORTED)

    async def _set_gain_settings(
        self, connection: Connection, gain_settings_operand: int
    ) -> None:
        '''Cf. 3.5.2.1 Set Gain Settings Procedure'''

        gain_mode = self.audio_input_state.gain_mode

        logger.error(f"set_gain_setting: gain_mode: {gain_mode}")
        if not (gain_mode == GainMode.MANUAL or gain_mode == GainMode.MANUAL_ONLY):
            logger.warning(
                "GainMode should be either MANUAL or MANUAL_ONLY Cf Spec Audio Input Control Service 3.5.2.1"
            )
            return

        if (
            gain_settings_operand < self.gain_settings_properties.gain_settings_minimum
            or gain_settings_operand
            > self.gain_settings_properties.gain_settings_maximum
        ):
            logger.error("gain_seetings value out of range")
            raise ATT_Error(ErrorCode.VALUE_OUT_OF_RANGE)

        if self.audio_input_state.gain_settings != gain_settings_operand:
            self.audio_input_state.gain_settings = gain_settings_operand
            await self.audio_input_state.notify_subscribers_via_connection(connection)

    async def _unmute(self, connection: Connection):
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
        await self.audio_input_state.notify_subscribers_via_connection(connection)

    async def _mute(self, connection: Connection, change_counter_operand: int) -> None:
        '''Cf. 3.5.5.2 Mute procedure'''

        change_counter = self.audio_input_state.change_counter
        mute = self.audio_input_state.mute
        if mute == Mute.DISABLED:
            logger.error("mute: Cannot change Mute value, Mute state is DISABLED")
            raise ATT_Error(ErrorCode.MUTE_DISABLED)

        if change_counter != change_counter_operand:
            raise ATT_Error(ErrorCode.INVALID_CHANGE_COUNTER)

        if mute == Mute.MUTED:
            return

        self.audio_input_state.mute = Mute.MUTED
        self.audio_input_state.increment_change_counter()
        await self.audio_input_state.notify_subscribers_via_connection(connection)

    async def _set_manual_gain_mode(self, connection: Connection) -> None:
        '''Cf. 3.5.2.4 Set Manual Gain Mode procedure'''

        gain_mode = self.audio_input_state.gain_mode
        if gain_mode in (GainMode.AUTOMATIC_ONLY, GainMode.MANUAL_ONLY):
            logger.error(f"Cannot change gain_mode, bad state: {gain_mode}")
            raise ATT_Error(ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED)

        if gain_mode == GainMode.MANUAL:
            return

        self.audio_input_state.gain_mode = GainMode.MANUAL
        self.audio_input_state.increment_change_counter()
        await self.audio_input_state.notify_subscribers_via_connection(connection)

    async def _set_automatic_gain_mode(self, connection: Connection) -> None:
        '''Cf. 3.5.2.5 Set Automatic Gain Mode'''

        gain_mode = self.audio_input_state.gain_mode
        if gain_mode in (GainMode.AUTOMATIC_ONLY, GainMode.MANUAL_ONLY):
            logger.error(f"Cannot change gain_mode, bad state: {gain_mode}")
            raise ATT_Error(ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED)

        if gain_mode == GainMode.AUTOMATIC:
            return

        self.audio_input_state.gain_mode = GainMode.AUTOMATIC
        self.audio_input_state.increment_change_counter()
        await self.audio_input_state.notify_subscribers_via_connection(connection)


@dataclass
class AudioInputDescription:
    '''
    Cf. 3.6 Audio Input Description
    '''

    audio_input_description: str = "Bluetooth"
    attribute_value: Optional[CharacteristicValue] = None

    @classmethod
    def from_bytes(cls, data: bytes):
        return cls(audio_input_description=data.decode('utf-8'))

    def __bytes__(self) -> bytes:
        return self.audio_input_description.encode('utf-8')

    def on_read(self, _connection: Optional[Connection]) -> bytes:
        return self.audio_input_description.encode('utf-8')

    async def on_write(self, connection: Optional[Connection], value: bytes) -> None:
        assert connection
        assert self.attribute_value

        self.audio_input_description = value.decode('utf-8')
        await connection.device.notify_subscribers(
            attribute=self.attribute_value, value=value
        )


class AICSService(TemplateService):
    UUID = GATT_AUDIO_INPUT_CONTROL_SERVICE

    def __init__(
        self,
        audio_input_state: Optional[AudioInputState] = None,
        gain_settings_properties: Optional[GainSettingsProperties] = None,
        audio_input_type: str = "local",
        audio_input_status: Optional[AudioInputStatus] = None,
        audio_input_description: Optional[AudioInputDescription] = None,
    ):
        self.audio_input_state = (
            AudioInputState() if audio_input_state is None else audio_input_state
        )
        self.gain_settings_properties = (
            GainSettingsProperties()
            if gain_settings_properties is None
            else gain_settings_properties
        )
        self.audio_input_status = (
            AudioInputStatus.ACTIVE
            if audio_input_status is None
            else audio_input_status
        )
        self.audio_input_description = (
            AudioInputDescription()
            if audio_input_description is None
            else audio_input_description
        )

        self.audio_input_control_point: AudioInputControlPoint = AudioInputControlPoint(
            self.audio_input_state, self.gain_settings_properties
        )

        self.audio_input_state_characteristic = DelegatedCharacteristicAdapter(
            Characteristic(
                uuid=GATT_AUDIO_INPUT_STATE_CHARACTERISTIC,
                properties=Characteristic.Properties.READ
                | Characteristic.Properties.NOTIFY,
                permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
                value=CharacteristicValue(read=self.audio_input_state.on_read),
            ),
            encode=lambda value: bytes(value),
        )
        self.audio_input_state.attribute_value = (
            self.audio_input_state_characteristic.value
        )

        self.gain_settings_properties_characteristic = DelegatedCharacteristicAdapter(
            Characteristic(
                uuid=GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC,
                properties=Characteristic.Properties.READ,
                permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
                value=CharacteristicValue(read=self.gain_settings_properties.on_read),
            )
        )

        self.audio_input_type_characteristic = Characteristic(
            uuid=GATT_AUDIO_INPUT_TYPE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=audio_input_type,
        )

        self.audio_input_status_characteristic = Characteristic(
            uuid=GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=bytes([self.audio_input_status]),
        )

        self.audio_input_control_point_characteristic = DelegatedCharacteristicAdapter(
            Characteristic(
                uuid=GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC,
                properties=Characteristic.Properties.WRITE,
                permissions=Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
                value=CharacteristicValue(
                    write=self.audio_input_control_point.on_write
                ),
            )
        )

        self.audio_input_description_characteristic = DelegatedCharacteristicAdapter(
            Characteristic(
                uuid=GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC,
                properties=Characteristic.Properties.READ
                | Characteristic.Properties.NOTIFY
                | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
                permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
                | Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
                value=CharacteristicValue(
                    write=self.audio_input_description.on_write,
                    read=self.audio_input_description.on_read,
                ),
            )
        )
        self.audio_input_description.attribute_value = (
            self.audio_input_control_point_characteristic.value
        )

        super().__init__(
            characteristics=[
                self.audio_input_state_characteristic,  # type: ignore
                self.gain_settings_properties_characteristic,  # type: ignore
                self.audio_input_type_characteristic,  # type: ignore
                self.audio_input_status_characteristic,  # type: ignore
                self.audio_input_control_point_characteristic,  # type: ignore
                self.audio_input_description_characteristic,  # type: ignore
            ],
            primary=False,
        )


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class AICSServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = AICSService

    def __init__(self, service_proxy: ServiceProxy) -> None:
        self.service_proxy = service_proxy

        if not (
            characteristics := service_proxy.get_characteristics_by_uuid(
                GATT_AUDIO_INPUT_STATE_CHARACTERISTIC
            )
        ):
            raise gatt.InvalidServiceError("Audio Input State Characteristic not found")
        self.audio_input_state = DelegatedCharacteristicAdapter(
            characteristic=characteristics[0], decode=AudioInputState.from_bytes
        )

        if not (
            characteristics := service_proxy.get_characteristics_by_uuid(
                GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC
            )
        ):
            raise gatt.InvalidServiceError(
                "Gain Settings Attribute Characteristic not found"
            )
        self.gain_settings_properties = PackedCharacteristicAdapter(
            characteristics[0],
            'BBB',
        )

        if not (
            characteristics := service_proxy.get_characteristics_by_uuid(
                GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC
            )
        ):
            raise gatt.InvalidServiceError(
                "Audio Input Status Characteristic not found"
            )
        self.audio_input_status = PackedCharacteristicAdapter(
            characteristics[0],
            'B',
        )

        if not (
            characteristics := service_proxy.get_characteristics_by_uuid(
                GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC
            )
        ):
            raise gatt.InvalidServiceError(
                "Audio Input Control Point Characteristic not found"
            )
        self.audio_input_control_point = characteristics[0]

        if not (
            characteristics := service_proxy.get_characteristics_by_uuid(
                GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC
            )
        ):
            raise gatt.InvalidServiceError(
                "Audio Input Description Characteristic not found"
            )
        self.audio_input_description = characteristics[0]
