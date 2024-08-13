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
from __future__ import annotations
from att import CommonErrorCode
from bumble import att
from bumble import device
from bumble import gatt, gatt_client
from bumble.utils import OpenIntEnum
from dataclasses import dataclass
from typing import Dict, List, Optional, Union


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
class ErrorCode(OpenIntEnum):
    '''See Hearing Access Service 2.4. Attribute Profile error codes.'''

    INVALID_OPCODE = 0x80
    WRITE_NAME_NOT_ALLOWED = 0x81
    PRESET_SYNCHRONIZATION_NOT_SUPPORTED = 0x82
    PRESET_OPERATION_NOT_POSSIBLE = 0x83
    INVALID_PARAMETERS_LENGTH = 0x84


class HearingAidType(OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    BINAURAL_HEARING_AID = 0b00
    MONAURAL_HEARING_AID = 0b01
    BANDED_HEARING_AID = 0b10


class PresetSynchronizationSupport(OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    PRESET_SYNCHRONIZATION_IS_NOT_SUPPORTED = 0b0
    PRESET_SYNCHRONIZATION_IS_SUPPORTED = 0b1


class IndependentPresets(OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    IDENTICAL_PRESET_RECORD = 0b0
    DIFFERENT_PRESET_RECORD = 0b1


class DynamicPresets(OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    PRESET_RECORDS_DOES_NOT_CHANGE = 0b0
    PRESET_RECORDS_MAY_CHANGE = 0b1


class WritablePresetsSupport(OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    WRITABLE_PRESET_RECORDS_NOT_SUPPORTED = 0b0
    WRITABLE_PRESET_RECORDS_SUPPORTED = 0b1


class HearingAidPresetControlPointOpcode(OpenIntEnum):
    '''See Hearing Access Service 3.3.1 Hearing Aid Preset Control Point operation requirements.'''

    # fmt: off
    READ_PRESETS_REQUEST                     = 0x01
    READ_PRESET_RESPONSE                     = 0x02
    PRESET_CHANGED                           = 0x03
    WRITE_PRESET_NAME                        = 0x04
    SET_ACTIVE_PRESET                        = 0x05
    SET_NEXT_PRESET                          = 0x06
    SET_PREVIOUS_PRESET                      = 0x07
    SET_ACTIVE_PRESET_SYNCHRONIZED_LOCALLY   = 0x08
    SET_NEXT_PRESET_SYNCHRONIZED_LOCALLY     = 0x09
    SET_PREVIOUS_PRESET_SYNCHRONIZED_LOCALLY = 0x0A


@dataclass
class PresetChangedOperation:
    '''See Hearing Access Service 3.2.2.2. Preset Changed operation.'''

    class ChangeId(OpenIntEnum):
        # fmt: off
        GENERIC_UPDATE            = 0x00
        PRESET_RECORD_DELETED     = 0x01
        PRESET_RECORD_AVAILABLE   = 0x02
        PRESET_RECORD_UNAVAILABLE = 0x03

    @dataclass
    class Generic:
        prev_index: int
        preset_record: PresetRecord

        def __bytes__(self) -> bytes:
            return bytes([self.prev_index]) + bytes(self.preset_record)

    change_id: ChangeId
    additional_parameters: Union[Generic, int]

    def __bytes__(self, is_last: bool) -> bytes:
        # TODO does the bytes concatenate correctly ?
        return bytes(
            [
                HearingAidPresetControlPointOpcode.PRESET_CHANGED,
                self.change_id,
                is_last,
            ]
        ) + bytes(self.additional_parameters)

    @staticmethod
    def get_index(op: PresetChangedOperation) -> int:
        if isinstance(op.additional_parameters, PresetChangedOperation.Generic):
            return op.additional_parameters.prev_index
        return op.additional_parameters


class PresetChangedOperationDeleted(PresetChangedOperation):
    def __init__(self, index):
        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_DELETED
        self.additional_parameters = index


class PresetChangedOperationAvailable(PresetChangedOperation):
    def __init__(self, index):
        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_AVAILABLE
        self.additional_parameters = index


class PresetChangedOperationUnavailable(PresetChangedOperation):
    def __init__(self, index):
        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_UNAVAILABLE
        self.additional_parameters = index


class PresetRecord:
    '''See Hearing Access Service 2.8. Preset record.'''

    class Property:
        class Writable(OpenIntEnum):
            CANNOT_BE_WRITTEN = 0b0
            CAN_BE_WRITTEN = 0b1

        class IsAvailable(OpenIntEnum):
            IS_UNAVAILABLE = 0b0
            IS_AVAILABLE = 0b1

        writable: Writable
        is_available: IsAvailable

        def __bytes__(self) -> bytes:
            return bytes([self.writable | (self.is_available << 1)])

    index: int
    properties: Property
    name: str

    def __bytes__(self) -> bytes:
        # TODO validate string encoding + concatenation of bytes
        return bytes([self.index]) + bytes(self.properties) + self.name.encode('utf-8')

    def is_available(self) -> bool:
        return (
            self.properties.is_available
            == PresetRecord.Property.IsAvailable.IS_AVAILABLE
        )


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class HearingAccessService(gatt.TemplateService):
    UUID = gatt.GATT_HEARING_ACCESS_SERVICE

    hearing_aid_features_characteristic: gatt.Characteristic
    hearing_aid_preset_control_point: gatt.Characteristic
    active_preset_index_characteristic: gatt.Characteristic
    active_preset_index: int

    # Server features
    class HearingAidFeatures:
        '''See Hearing Access Service 3.1. Hearing Aid Features.'''

        hearing_aid_type: HearingAidType
        preset_synchronization_support: PresetSynchronizationSupport
        independent_presets: IndependentPresets
        dynamic_presets: DynamicPresets
        writable_presets_support: WritablePresetsSupport

        def __bytes__(self) -> bytes:
            # TODO: Is thit the proper way to concatenate to bits ? and is this in correct endianness
            return bytes(
                [
                    (self.hearing_aid_type << 0)
                    | (self.hearing_aid_type << 2)
                    | (self.preset_synchronization_support << 3)
                    | (self.independent_presets << 4)
                    | (self.dynamic_presets << 5)
                    | (self.writable_presets_support << 6)
                ]
            )

    hearing_aid_features: HearingAidFeatures
    preset_records: Dict[int, PresetRecord]
    read_presets_request_in_progress: bool = False
    preset_changed_operations: List[PresetChangedOperation]

    preset_changed_operations_per_device: Dict[device.Connection, int]

    def __init__(self) -> None:
        self.hearing_aid_features_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_HEARING_AID_FEATURES_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ,  # optional: gatt.Characteristic.Properties.NOTIFY
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=gatt.CharacteristicValue(read=self._on_read_hearing_aid_features),
        )
        self.hearing_aid_preset_control_point = gatt.Characteristic(
            uuid=gatt.GATT_HEARING_AID_PRESET_CONTROL_POINT_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.WRITE
                | gatt.Characteristic.Properties.INDICATE
            ),  # optional: gatt.Characteristic.Properties.NOTIFY when EATT is supported
            permissions=gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=gatt.CharacteristicValue(
                write=self._on_write_hearing_aid_preset_control_point
            ),
        )
        self.active_preset_index = 0x00
        self.active_preset_index_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_ACTIVE_PRESET_INDEX_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY
            ),
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=bytes([self.active_preset_index]),
        )

        super().__init__(
            [
                self.hearing_aid_features_characteristic,
                self.hearing_aid_preset_control_point,
                self.active_preset_index_characteristic,
            ]
        )

    def _on_read_hearing_aid_features(
        self, connection: Optional[device.Connection]
    ) -> bytes:
        return bytes(self.hearing_aid_features)

    def _on_write_hearing_aid_preset_control_point(
        self, connection: Optional[device.Connection], value: bytes
    ) -> None:
        opcode = HearingAidPresetControlPointOpcode(value[0])
        handler = getattr(self, '_on_' + opcode.name.lower())
        handler(connection, value)

    async def _on_read_presets_request(
        self, connection: Optional[device.Connection], value: bytes
    ):
        assert connection
        start_index = value[1]
        num_preset = value[2]

        sorted_preset_records = [
            self.preset_records[key] for key in sorted(self.preset_records.keys())
        ]
        last_index = sorted_preset_records[-1].index
        if start_index > last_index or start_index == 0x00 or num_preset == 0x00:
            raise att.ATT_Error(CommonErrorCode.OUT_OF_RANGE)

        if self.read_presets_request_in_progress:
            raise att.ATT_Error(CommonErrorCode.PROCEDURE_ALREADY_IN_PROGRESS)

        async def read_preset_response(preset: PresetRecord, is_last: bool):
            # According to 3.2.2.1. Read Presets Request operation :
            # If the Read Presets Request opcode is written to the Hearing Aid
            # Preset Control Point characteristic, then the server shall reply
            # with an ATT_WRITE_RSP PDU, and the server shall send to the client
            # one notification or indication of the Hearing Aid Preset Control
            # Point characteristic for the preset beginning with an Index equal
            # to or greater than StartIndex followed by the next (NumPresets-1)
            # presets. If the server encounters a preset record with the isLast
            # value set to 0x01 (see Table 3.5) during this operation, then it
            # will notify or indicate that preset record and then terminate the
            # operation.

            # TODO Answer that
            # Does that mean the notification shall be sent after the ATT_WRITE_RSP ? and therefor this code is wrong ?

            await connection.device.notify_subscriber(
                connection,
                self.hearing_aid_preset_control_point,
                value=bytes(
                    [
                        HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE,
                        is_last,
                    ]
                )
                + bytes(preset),
            )

        self.read_presets_request_in_progress = True
        for record in sorted_preset_records:
            if record.index < start_index:
                continue

            num_preset -= 1
            is_last = num_preset == 0 or record.index == last_index
            await read_preset_response(record, is_last)
            if is_last:
                break

        self.read_presets_request_in_progress = False

    async def generic_update(self, op: PresetChangedOperation):
        # It is the responsibility of the caller to modify the self.preset_records to match what is being sent in the generic_update
        self.preset_changed_operations.append(op)
        await self.notifyPresetOperations()

    async def delete_preset(self, index):
        del self.preset_records[index]
        self.preset_changed_operations.append(PresetChangedOperationDeleted(index))
        await self.notifyPresetOperations()

    async def available_preset(self, index):
        self.preset_records[
            index
        ].properties.is_available = PresetRecord.Property.IsAvailable.IS_AVAILABLE
        self.preset_changed_operations.append(PresetChangedOperationAvailable(index))
        await self.notifyPresetOperations()

    async def unavailable_preset(self, index):
        self.preset_records[
            index
        ].properties.is_available = PresetRecord.Property.IsAvailable.IS_UNAVAILABLE
        self.preset_changed_operations.append(PresetChangedOperationUnavailable(index))
        await self.notifyPresetOperations()

    async def preset_changed_operation(self, connection: device.Connection):
        num_op = len(self.preset_changed_operations)
        idx = self.preset_changed_operations_per_device.get(connection, num_op)
        operations = self.preset_changed_operations[idx:]
        # Notification are sent in index order
        for op in sorted(operations, key=PresetChangedOperation.get_index):
            is_last = idx == num_op
            await connection.device.notify_subscriber(
                connection,
                self.hearing_aid_preset_control_point,
                value=op.__bytes__(is_last),
            )
            self.preset_changed_operations_per_device[connection] = idx
            idx += 1

    async def notifyPresetOperations(self):
        assert (
            self.hearing_aid_features.dynamic_presets
            == DynamicPresets.PRESET_RECORDS_MAY_CHANGE
        )
        for connection in self.preset_changed_operations_per_device.keys():
            # TODO : I have no idea how to check if the connection is currently active or not should be something like:
            # if connection.is_not_connected():
            #     continue
            await self.preset_changed_operation(connection)

    # TODO: The list of preset changed operation need to be sent to the bonded device when it reconnect.
    # How can the server be notified of connection / deconnection ?
    async def reconnecting_to_bonded_client(self, connection: device.Connection):
        await self.preset_changed_operation(connection)

    async def _on_write_preset_name(
        self, connection: Optional[device.Connection], value: bytes
    ):
        assert (
            self.hearing_aid_features.writable_presets_support
            == WritablePresetsSupport.WRITABLE_PRESET_RECORDS_SUPPORTED
        )
        if self.read_presets_request_in_progress:
            raise att.ATT_Error(CommonErrorCode.PROCEDURE_ALREADY_IN_PROGRESS)

        index = value[1]
        preset = self.preset_records.get(index, None)
        if (
            not preset
            or preset.properties.writable
            == PresetRecord.Property.Writable.CANNOT_BE_WRITTEN
        ):
            raise att.ATT_Error(ErrorCode.WRITE_NAME_NOT_ALLOWED)

        # TODO Is this a correct way of decoding utf8
        name = value[2:].decode('utf-8')
        if not name or len(name) > 40:
            raise att.ATT_Error(ErrorCode.INVALID_PARAMETERS_LENGTH)

        preset.name = name

        op = PresetChangedOperation(
            PresetChangedOperation.ChangeId.GENERIC_UPDATE,
            PresetChangedOperation.Generic(index, preset),
        )
        self.preset_changed_operations.append(op)
        await self.notifyPresetOperations()

    async def notify_active_preset(self, connection: device.Connection):
        await connection.device.notify_subscriber(
            connection,
            self.active_preset_index_characteristic,
            value=bytes([self.active_preset_index]),
        )
        # TODO: I have no idea how to notify other clients
        for other_connection in self.preset_changed_operations_per_device.keys():
            if other_connection == connection:
                continue
            await connection.device.notify_subscriber(
                other_connection,
                self.active_preset_index_characteristic,
                value=bytes([self.active_preset_index]),
            )

    async def set_active_preset(
        self, connection: Optional[device.Connection], value: bytes
    ) -> bool:
        assert connection
        index = value[1]
        preset = self.preset_records.get(index, None)
        if (
            not preset
            or preset.properties.is_available
            == PresetRecord.Property.IsAvailable.IS_AVAILABLE
        ):
            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)

        self.active_preset_index = index
        await self.notify_active_preset(connection)
        return True

    async def _on_set_active_preset(
        self, connection: Optional[device.Connection], value: bytes
    ):
        await self.set_active_preset(connection, value)

    async def set_next_preset(
        self, connection: Optional[device.Connection], is_reverse
    ):
        '''Set the next preset as active or previous if is_reverse is true'''
        assert connection

        if self.active_preset_index == 0x00:
            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)

        first_preset: Optional[PresetRecord] = None  # To loop to first preset
        next_preset: Optional[PresetRecord] = None
        for index, record in sorted(self.preset_records.items(), reverse=is_reverse):
            if not record.is_available():
                continue
            if first_preset == None:
                first_preset = record
            if index <= self.active_preset_index:
                continue
            next_preset = record
            break

        if not first_preset:  # if there is no first, there will be no next either
            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)

        if next_preset:
            self.active_preset_index = next_preset.index
        else:
            self.active_preset_index = first_preset.index
        await self.notify_active_preset(connection)

    async def _on_set_next_preset(self, connection: Optional[device.Connection]):
        await self.set_next_preset(connection, False)

    async def _on_set_previous_preset(self, connection: Optional[device.Connection]):
        await self.set_next_preset(connection, True)

    async def _on_set_active_preset_synchronized_locally(
        self, connection: Optional[device.Connection], value: bytes
    ):
        if (
            self.hearing_aid_features.preset_synchronization_support
            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
        ):
            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
        await self.set_active_preset(connection, value)
        # TODO (low priority) inform other server of the change

    async def _on_set_next_preset_synchronized_locally(
        self, connection: Optional[device.Connection]
    ):
        if (
            self.hearing_aid_features.preset_synchronization_support
            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
        ):
            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
        await self.set_next_preset(connection, False)
        # TODO (low priority) inform other server of the change

    async def _on_set_previous_preset_synchronized_locally(
        self, connection: Optional[device.Connection]
    ):
        if (
            self.hearing_aid_features.preset_synchronization_support
            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
        ):
            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
        await self.set_next_preset(connection, True)
        # TODO (low priority) inform other server of the change


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class HearingAccessServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = HearingAccessService

    hearing_aid_preset_control_point: gatt_client.CharacteristicProxy

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        # TODO use a InvalidServiceError instead of throwing a IndexError
        self.hearing_aid_preset_control_point = (
            service_proxy.get_characteristics_by_uuid(
                gatt.GATT_HEARING_AID_PRESET_CONTROL_POINT_CHARACTERISTIC
            )[0]
        )
