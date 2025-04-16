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
import struct
from dataclasses import dataclass
from typing import Optional

from bumble.device import Connection
from bumble.att import ATT_Error
from bumble.gatt import (
    Characteristic,
    TemplateService,
    CharacteristicValue,
    GATT_VOLUME_OFFSET_CONTROL_SERVICE,
    GATT_VOLUME_OFFSET_STATE_CHARACTERISTIC,
    GATT_AUDIO_LOCATION_CHARACTERISTIC,
    GATT_VOLUME_OFFSET_CONTROL_POINT_CHARACTERISTIC,
    GATT_AUDIO_OUTPUT_DESCRIPTION_CHARACTERISTIC,
)
from bumble.gatt_adapters import (
    DelegatedCharacteristicProxyAdapter,
    SerializableCharacteristicProxyAdapter,
    UTF8CharacteristicProxyAdapter,
)
from bumble.gatt_client import ProfileServiceProxy, ServiceProxy
from bumble import utils
from bumble.profiles.bap import AudioLocation

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

MIN_VOLUME_OFFSET = -255
MAX_VOLUME_OFFSET = 255
CHANGE_COUNTER_MAX_VALUE = 0xFF


class SetVolumeOffsetOpCode(utils.OpenIntEnum):
    SET_VOLUME_OFFSET = 0x01


class ErrorCode(utils.OpenIntEnum):
    """
    See Volume Offset Control Service 1.6. Application error codes.
    """

    INVALID_CHANGE_COUNTER = 0x80
    OPCODE_NOT_SUPPORTED = 0x81
    VALUE_OUT_OF_RANGE = 0x82


# -----------------------------------------------------------------------------
@dataclass
class VolumeOffsetState:
    volume_offset: int = 0
    change_counter: int = 0
    attribute: Optional[Characteristic] = None

    def __bytes__(self) -> bytes:
        return struct.pack('<hB', self.volume_offset, self.change_counter)

    @classmethod
    def from_bytes(cls, data: bytes):
        volume_offset, change_counter = struct.unpack('<hB', data)
        return cls(volume_offset, change_counter)

    def increment_change_counter(self) -> None:
        self.change_counter = (self.change_counter + 1) % (CHANGE_COUNTER_MAX_VALUE + 1)

    async def notify_subscribers_via_connection(self, connection: Connection) -> None:
        assert self.attribute is not None
        await connection.device.notify_subscribers(attribute=self.attribute)

    def on_read(self, _connection: Optional[Connection]) -> bytes:
        return bytes(self)


@dataclass
class VocsAudioLocation:
    audio_location: AudioLocation = AudioLocation.NOT_ALLOWED
    attribute: Optional[Characteristic] = None

    def __bytes__(self) -> bytes:
        return struct.pack('<I', self.audio_location)

    @classmethod
    def from_bytes(cls, data: bytes):
        audio_location = AudioLocation(struct.unpack('<I', data)[0])
        return cls(audio_location)

    def on_read(self, _connection: Optional[Connection]) -> bytes:
        return bytes(self)

    async def on_write(self, connection: Optional[Connection], value: bytes) -> None:
        assert connection
        assert self.attribute

        self.audio_location = AudioLocation(int.from_bytes(value, 'little'))
        await connection.device.notify_subscribers(attribute=self.attribute)


@dataclass
class VolumeOffsetControlPoint:
    volume_offset_state: VolumeOffsetState

    async def on_write(self, connection: Optional[Connection], value: bytes) -> None:
        assert connection

        opcode = value[0]
        if opcode != SetVolumeOffsetOpCode.SET_VOLUME_OFFSET:
            raise ATT_Error(ErrorCode.OPCODE_NOT_SUPPORTED)

        change_counter, volume_offset = struct.unpack('<Bh', value[1:])
        await self._set_volume_offset(connection, change_counter, volume_offset)

    async def _set_volume_offset(
        self,
        connection: Connection,
        change_counter_operand: int,
        volume_offset_operand: int,
    ) -> None:
        change_counter = self.volume_offset_state.change_counter

        if change_counter != change_counter_operand:
            raise ATT_Error(ErrorCode.INVALID_CHANGE_COUNTER)

        if not MIN_VOLUME_OFFSET <= volume_offset_operand <= MAX_VOLUME_OFFSET:
            raise ATT_Error(ErrorCode.VALUE_OUT_OF_RANGE)

        self.volume_offset_state.volume_offset = volume_offset_operand
        self.volume_offset_state.increment_change_counter()
        await self.volume_offset_state.notify_subscribers_via_connection(connection)


@dataclass
class AudioOutputDescription:
    audio_output_description: str = ''
    attribute: Optional[Characteristic] = None

    @classmethod
    def from_bytes(cls, data: bytes):
        return cls(audio_output_description=data.decode('utf-8'))

    def __bytes__(self) -> bytes:
        return self.audio_output_description.encode('utf-8')

    def on_read(self, _connection: Optional[Connection]) -> bytes:
        return bytes(self)

    async def on_write(self, connection: Optional[Connection], value: bytes) -> None:
        assert connection
        assert self.attribute

        self.audio_output_description = value.decode('utf-8')
        await connection.device.notify_subscribers(attribute=self.attribute)


# -----------------------------------------------------------------------------
class VolumeOffsetControlService(TemplateService):
    UUID = GATT_VOLUME_OFFSET_CONTROL_SERVICE

    def __init__(
        self,
        volume_offset_state: Optional[VolumeOffsetState] = None,
        audio_location: Optional[VocsAudioLocation] = None,
        audio_output_description: Optional[AudioOutputDescription] = None,
    ) -> None:

        self.volume_offset_state = (
            VolumeOffsetState() if volume_offset_state is None else volume_offset_state
        )

        self.audio_location = (
            VocsAudioLocation() if audio_location is None else audio_location
        )

        self.audio_output_description = (
            AudioOutputDescription()
            if audio_output_description is None
            else audio_output_description
        )

        self.volume_offset_control_point: VolumeOffsetControlPoint = (
            VolumeOffsetControlPoint(self.volume_offset_state)
        )

        self.volume_offset_state_characteristic: Characteristic[bytes] = Characteristic(
            uuid=GATT_VOLUME_OFFSET_STATE_CHARACTERISTIC,
            properties=(
                Characteristic.Properties.READ | Characteristic.Properties.NOTIFY
            ),
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=CharacteristicValue(read=self.volume_offset_state.on_read),
        )

        self.audio_location_characteristic: Characteristic[bytes] = Characteristic(
            uuid=GATT_AUDIO_LOCATION_CHARACTERISTIC,
            properties=(
                Characteristic.Properties.READ
                | Characteristic.Properties.NOTIFY
                | Characteristic.Properties.WRITE_WITHOUT_RESPONSE
            ),
            permissions=(
                Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
                | Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION
            ),
            value=CharacteristicValue(
                read=self.audio_location.on_read,
                write=self.audio_location.on_write,
            ),
        )
        self.audio_location.attribute = self.audio_location_characteristic

        self.volume_offset_control_point_characteristic: Characteristic[bytes] = (
            Characteristic(
                uuid=GATT_VOLUME_OFFSET_CONTROL_POINT_CHARACTERISTIC,
                properties=Characteristic.Properties.WRITE,
                permissions=Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
                value=CharacteristicValue(
                    write=self.volume_offset_control_point.on_write
                ),
            )
        )

        self.audio_output_description_characteristic: Characteristic[bytes] = (
            Characteristic(
                uuid=GATT_AUDIO_OUTPUT_DESCRIPTION_CHARACTERISTIC,
                properties=(
                    Characteristic.Properties.READ
                    | Characteristic.Properties.NOTIFY
                    | Characteristic.Properties.WRITE_WITHOUT_RESPONSE
                ),
                permissions=(
                    Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
                    | Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION
                ),
                value=CharacteristicValue(
                    read=self.audio_output_description.on_read,
                    write=self.audio_output_description.on_write,
                ),
            )
        )
        self.audio_output_description.attribute = (
            self.audio_output_description_characteristic
        )

        super().__init__(
            characteristics=[
                self.volume_offset_state_characteristic,  # type: ignore
                self.audio_location_characteristic,  # type: ignore
                self.volume_offset_control_point_characteristic,  # type: ignore
                self.audio_output_description_characteristic,  # type: ignore
            ],
            primary=False,
        )


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class VolumeOffsetControlServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = VolumeOffsetControlService

    def __init__(self, service_proxy: ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.volume_offset_state = SerializableCharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                GATT_VOLUME_OFFSET_STATE_CHARACTERISTIC
            ),
            VolumeOffsetState,
        )

        self.audio_location = DelegatedCharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                GATT_AUDIO_LOCATION_CHARACTERISTIC
            ),
            encode=lambda value: bytes([int(value)]),
            decode=lambda data: AudioLocation(data[0]),
        )

        self.volume_offset_control_point = (
            service_proxy.get_required_characteristic_by_uuid(
                GATT_VOLUME_OFFSET_CONTROL_POINT_CHARACTERISTIC
            )
        )

        self.audio_output_description = UTF8CharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                GATT_AUDIO_OUTPUT_DESCRIPTION_CHARACTERISTIC
            )
        )
