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
import asyncio
import functools
from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional, Set, Union

from bumble import att, gatt, gatt_adapters, gatt_client
from bumble.core import InvalidArgumentError, InvalidStateError
from bumble.device import Device, Connection
from bumble import utils
from bumble.hci import Address


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
class ErrorCode(utils.OpenIntEnum):
    '''See Hearing Access Service 2.4. Attribute Profile error codes.'''

    INVALID_OPCODE = 0x80
    WRITE_NAME_NOT_ALLOWED = 0x81
    PRESET_SYNCHRONIZATION_NOT_SUPPORTED = 0x82
    PRESET_OPERATION_NOT_POSSIBLE = 0x83
    INVALID_PARAMETERS_LENGTH = 0x84


class HearingAidType(utils.OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    BINAURAL_HEARING_AID = 0b00
    MONAURAL_HEARING_AID = 0b01
    BANDED_HEARING_AID = 0b10


class PresetSynchronizationSupport(utils.OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    PRESET_SYNCHRONIZATION_IS_NOT_SUPPORTED = 0b0
    PRESET_SYNCHRONIZATION_IS_SUPPORTED = 0b1


class IndependentPresets(utils.OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    IDENTICAL_PRESET_RECORD = 0b0
    DIFFERENT_PRESET_RECORD = 0b1


class DynamicPresets(utils.OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    PRESET_RECORDS_DOES_NOT_CHANGE = 0b0
    PRESET_RECORDS_MAY_CHANGE = 0b1


class WritablePresetsSupport(utils.OpenIntEnum):
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    WRITABLE_PRESET_RECORDS_NOT_SUPPORTED = 0b0
    WRITABLE_PRESET_RECORDS_SUPPORTED = 0b1


class HearingAidPresetControlPointOpcode(utils.OpenIntEnum):
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
class HearingAidFeatures:
    '''See Hearing Access Service 3.1. Hearing Aid Features.'''

    hearing_aid_type: HearingAidType
    preset_synchronization_support: PresetSynchronizationSupport
    independent_presets: IndependentPresets
    dynamic_presets: DynamicPresets
    writable_presets_support: WritablePresetsSupport

    def __bytes__(self) -> bytes:
        return bytes(
            [
                (self.hearing_aid_type << 0)
                | (self.preset_synchronization_support << 2)
                | (self.independent_presets << 3)
                | (self.dynamic_presets << 4)
                | (self.writable_presets_support << 5)
            ]
        )


def HearingAidFeatures_from_bytes(data: int) -> HearingAidFeatures:
    return HearingAidFeatures(
        HearingAidType(data & 0b11),
        PresetSynchronizationSupport(data >> 2 & 0b1),
        IndependentPresets(data >> 3 & 0b1),
        DynamicPresets(data >> 4 & 0b1),
        WritablePresetsSupport(data >> 5 & 0b1),
    )


@dataclass
class PresetChangedOperation:
    '''See Hearing Access Service 3.2.2.2. Preset Changed operation.'''

    class ChangeId(utils.OpenIntEnum):
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

    def to_bytes(self, is_last: bool) -> bytes:
        if isinstance(self.additional_parameters, PresetChangedOperation.Generic):
            additional_parameters_bytes = bytes(self.additional_parameters)
        else:
            additional_parameters_bytes = bytes([self.additional_parameters])

        return (
            bytes(
                [
                    HearingAidPresetControlPointOpcode.PRESET_CHANGED,
                    self.change_id,
                    is_last,
                ]
            )
            + additional_parameters_bytes
        )


class PresetChangedOperationDeleted(PresetChangedOperation):
    def __init__(self, index) -> None:
        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_DELETED
        self.additional_parameters = index


class PresetChangedOperationAvailable(PresetChangedOperation):
    def __init__(self, index) -> None:
        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_AVAILABLE
        self.additional_parameters = index


class PresetChangedOperationUnavailable(PresetChangedOperation):
    def __init__(self, index) -> None:
        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_UNAVAILABLE
        self.additional_parameters = index


@dataclass
class PresetRecord:
    '''See Hearing Access Service 2.8. Preset record.'''

    @dataclass
    class Property:
        class Writable(utils.OpenIntEnum):
            CANNOT_BE_WRITTEN = 0b0
            CAN_BE_WRITTEN = 0b1

        class IsAvailable(utils.OpenIntEnum):
            IS_UNAVAILABLE = 0b0
            IS_AVAILABLE = 0b1

        writable: Writable = Writable.CAN_BE_WRITTEN
        is_available: IsAvailable = IsAvailable.IS_AVAILABLE

        def __bytes__(self) -> bytes:
            return bytes([self.writable | (self.is_available << 1)])

    index: int
    name: str
    properties: Property = field(default_factory=Property)

    def __bytes__(self) -> bytes:
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

    hearing_aid_features_characteristic: gatt.Characteristic[bytes]
    hearing_aid_preset_control_point: gatt.Characteristic[bytes]
    active_preset_index_characteristic: gatt.Characteristic[bytes]
    active_preset_index: int
    active_preset_index_per_device: Dict[Address, int]

    device: Device

    server_features: HearingAidFeatures
    preset_records: Dict[int, PresetRecord]  # key is the preset index
    read_presets_request_in_progress: bool

    preset_changed_operations_history_per_device: Dict[
        Address, List[PresetChangedOperation]
    ]

    # Keep an updated list of connected client to send notification to
    currently_connected_clients: Set[Connection]

    def __init__(
        self, device: Device, features: HearingAidFeatures, presets: List[PresetRecord]
    ) -> None:
        self.active_preset_index_per_device = {}
        self.read_presets_request_in_progress = False
        self.preset_changed_operations_history_per_device = {}
        self.currently_connected_clients = set()

        self.device = device
        self.server_features = features
        if len(presets) < 1:
            raise InvalidArgumentError(f'Invalid presets: {presets}')

        self.preset_records = {}
        for p in presets:
            if len(p.name.encode()) < 1 or len(p.name.encode()) > 40:
                raise InvalidArgumentError(f'Invalid name: {p.name}')

            self.preset_records[p.index] = p

        # associate the lowest index as the current active preset at startup
        self.active_preset_index = sorted(self.preset_records.keys())[0]

        @device.on('connection')  # type: ignore
        def on_connection(connection: Connection) -> None:
            @connection.on('disconnection')  # type: ignore
            def on_disconnection(_reason) -> None:
                self.currently_connected_clients.remove(connection)

            @connection.on('pairing')  # type: ignore
            def on_pairing(*_: Any) -> None:
                self.on_incoming_paired_connection(connection)

            if connection.peer_resolvable_address:
                self.on_incoming_paired_connection(connection)

        self.hearing_aid_features_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_HEARING_AID_FEATURES_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=bytes(self.server_features),
        )
        self.hearing_aid_preset_control_point = gatt.Characteristic(
            uuid=gatt.GATT_HEARING_AID_PRESET_CONTROL_POINT_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.WRITE
                | gatt.Characteristic.Properties.INDICATE
            ),
            permissions=gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=gatt.CharacteristicValue(
                write=self._on_write_hearing_aid_preset_control_point
            ),
        )
        self.active_preset_index_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_ACTIVE_PRESET_INDEX_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY
            ),
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=gatt.CharacteristicValue(read=self._on_read_active_preset_index),
        )

        super().__init__(
            [
                self.hearing_aid_features_characteristic,
                self.hearing_aid_preset_control_point,
                self.active_preset_index_characteristic,
            ]
        )

    def on_incoming_paired_connection(self, connection: Connection):
        '''Setup initial operations to handle a remote bonded HAP device'''
        # TODO Should we filter on HAP device only ?
        self.currently_connected_clients.add(connection)
        if (
            connection.peer_address
            not in self.preset_changed_operations_history_per_device
        ):
            self.preset_changed_operations_history_per_device[
                connection.peer_address
            ] = []
            return

        async def on_connection_async() -> None:
            # Send all the PresetChangedOperation that occur when not connected
            await self._preset_changed_operation(connection)
            # Update the active preset index if needed
            await self.notify_active_preset_for_connection(connection)

        utils.cancel_on_event(connection, 'disconnection', on_connection_async())

    def _on_read_active_preset_index(
        self, __connection__: Optional[Connection]
    ) -> bytes:
        return bytes([self.active_preset_index])

    # TODO this need to be triggered when device is unbonded
    def on_forget(self, addr: Address) -> None:
        self.preset_changed_operations_history_per_device.pop(addr)

    async def _on_write_hearing_aid_preset_control_point(
        self, connection: Optional[Connection], value: bytes
    ):
        assert connection

        opcode = HearingAidPresetControlPointOpcode(value[0])
        handler = getattr(self, '_on_' + opcode.name.lower())
        await handler(connection, value)

    async def _on_read_presets_request(
        self, connection: Optional[Connection], value: bytes
    ):
        assert connection
        if connection.att_mtu < 49:  # 2.5. GATT sub-procedure requirements
            logging.warning(f'HAS require MTU >= 49: {connection}')

        if self.read_presets_request_in_progress:
            raise att.ATT_Error(att.ErrorCode.PROCEDURE_ALREADY_IN_PROGRESS)
        self.read_presets_request_in_progress = True

        start_index = value[1]
        if start_index == 0x00:
            raise att.ATT_Error(att.ErrorCode.OUT_OF_RANGE)

        num_presets = value[2]
        if num_presets == 0x00:
            raise att.ATT_Error(att.ErrorCode.OUT_OF_RANGE)

        # Sending `num_presets` presets ordered by increasing index field, starting from start_index
        presets = [
            self.preset_records[key]
            for key in sorted(self.preset_records.keys())
            if self.preset_records[key].index >= start_index
        ]
        del presets[num_presets:]
        if len(presets) == 0:
            raise att.ATT_Error(att.ErrorCode.OUT_OF_RANGE)

        utils.AsyncRunner.spawn(self._read_preset_response(connection, presets))

    async def _read_preset_response(
        self, connection: Connection, presets: List[PresetRecord]
    ):
        # If the ATT bearer is terminated before all notifications or indications are sent, then the server shall consider the Read Presets Request operation aborted and shall not either continue or restart the operation when the client reconnects.
        try:
            for i, preset in enumerate(presets):
                await connection.device.indicate_subscriber(
                    connection,
                    self.hearing_aid_preset_control_point,
                    value=bytes(
                        [
                            HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE,
                            i == len(presets) - 1,
                        ]
                    )
                    + bytes(preset),
                )

        finally:
            # indicate_subscriber can raise a TimeoutError, we need to gracefully terminate the operation
            self.read_presets_request_in_progress = False

    async def generic_update(self, op: PresetChangedOperation) -> None:
        '''Server API to perform a generic update. It is the responsibility of the caller to modify the preset_records to match the PresetChangedOperation being sent'''
        await self._notifyPresetOperations(op)

    async def delete_preset(self, index: int) -> None:
        '''Server API to delete a preset. It should not be the current active preset'''

        if index == self.active_preset_index:
            raise InvalidStateError('Cannot delete active preset')

        del self.preset_records[index]
        await self._notifyPresetOperations(PresetChangedOperationDeleted(index))

    async def available_preset(self, index: int) -> None:
        '''Server API to make a preset available'''

        preset = self.preset_records[index]
        preset.properties.is_available = PresetRecord.Property.IsAvailable.IS_AVAILABLE
        await self._notifyPresetOperations(PresetChangedOperationAvailable(index))

    async def unavailable_preset(self, index: int) -> None:
        '''Server API to make a preset unavailable. It should not be the current active preset'''

        if index == self.active_preset_index:
            raise InvalidStateError('Cannot set active preset as unavailable')

        preset = self.preset_records[index]
        preset.properties.is_available = (
            PresetRecord.Property.IsAvailable.IS_UNAVAILABLE
        )
        await self._notifyPresetOperations(PresetChangedOperationUnavailable(index))

    async def _preset_changed_operation(self, connection: Connection) -> None:
        '''Send all PresetChangedOperation saved for a given connection'''
        op_list = self.preset_changed_operations_history_per_device.get(
            connection.peer_address, []
        )

        # Notification will be sent in index order
        def get_op_index(op: PresetChangedOperation) -> int:
            if isinstance(op.additional_parameters, PresetChangedOperation.Generic):
                return op.additional_parameters.prev_index
            return op.additional_parameters

        op_list.sort(key=get_op_index)
        # If the ATT bearer is terminated before all notifications or indications are sent, then the server shall consider the Preset Changed operation aborted and shall continue the operation when the client reconnects.
        while len(op_list) > 0:
            try:
                await connection.device.indicate_subscriber(
                    connection,
                    self.hearing_aid_preset_control_point,
                    value=op_list[0].to_bytes(len(op_list) == 1),
                )
                # Remove item once sent, and keep the non sent item in the list
                op_list.pop(0)
            except TimeoutError:
                break

    async def _notifyPresetOperations(self, op: PresetChangedOperation) -> None:
        for historyList in self.preset_changed_operations_history_per_device.values():
            historyList.append(op)

        for connection in self.currently_connected_clients:
            await self._preset_changed_operation(connection)

    async def _on_write_preset_name(
        self, connection: Optional[Connection], value: bytes
    ):
        assert connection

        if self.read_presets_request_in_progress:
            raise att.ATT_Error(att.ErrorCode.PROCEDURE_ALREADY_IN_PROGRESS)

        index = value[1]
        preset = self.preset_records.get(index, None)
        if (
            not preset
            or preset.properties.writable
            == PresetRecord.Property.Writable.CANNOT_BE_WRITTEN
        ):
            raise att.ATT_Error(ErrorCode.WRITE_NAME_NOT_ALLOWED)

        name = value[2:].decode('utf-8')
        if not name or len(name) > 40:
            raise att.ATT_Error(ErrorCode.INVALID_PARAMETERS_LENGTH)

        preset.name = name

        await self.generic_update(
            PresetChangedOperation(
                PresetChangedOperation.ChangeId.GENERIC_UPDATE,
                PresetChangedOperation.Generic(index, preset),
            )
        )

    async def notify_active_preset_for_connection(self, connection: Connection) -> None:
        if (
            self.active_preset_index_per_device.get(connection.peer_address, 0x00)
            == self.active_preset_index
        ):
            # Nothing to do, peer is already updated
            return

        await connection.device.notify_subscriber(
            connection,
            attribute=self.active_preset_index_characteristic,
            value=bytes([self.active_preset_index]),
        )
        self.active_preset_index_per_device[connection.peer_address] = (
            self.active_preset_index
        )

    async def notify_active_preset(self) -> None:
        for connection in self.currently_connected_clients:
            await self.notify_active_preset_for_connection(connection)

    async def set_active_preset(
        self, connection: Optional[Connection], value: bytes
    ) -> None:
        assert connection
        index = value[1]
        preset = self.preset_records.get(index, None)
        if (
            not preset
            or preset.properties.is_available
            != PresetRecord.Property.IsAvailable.IS_AVAILABLE
        ):
            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)

        if index == self.active_preset_index:
            # Already at correct value
            return

        self.active_preset_index = index
        await self.notify_active_preset()

    async def _on_set_active_preset(
        self, connection: Optional[Connection], value: bytes
    ):
        await self.set_active_preset(connection, value)

    async def set_next_or_previous_preset(
        self, connection: Optional[Connection], is_previous
    ):
        '''Set the next or the previous preset as active'''
        assert connection

        if self.active_preset_index == 0x00:
            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)

        first_preset: Optional[PresetRecord] = None  # To loop to first preset
        next_preset: Optional[PresetRecord] = None
        for index, record in sorted(self.preset_records.items(), reverse=is_previous):
            if not record.is_available():
                continue
            if first_preset == None:
                first_preset = record
            if is_previous:
                if index >= self.active_preset_index:
                    continue
            elif index <= self.active_preset_index:
                continue
            next_preset = record
            break

        if not first_preset:  # If no other preset are available
            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)

        if next_preset:
            self.active_preset_index = next_preset.index
        else:
            self.active_preset_index = first_preset.index
        await self.notify_active_preset()

    async def _on_set_next_preset(
        self, connection: Optional[Connection], __value__: bytes
    ) -> None:
        await self.set_next_or_previous_preset(connection, False)

    async def _on_set_previous_preset(
        self, connection: Optional[Connection], __value__: bytes
    ) -> None:
        await self.set_next_or_previous_preset(connection, True)

    async def _on_set_active_preset_synchronized_locally(
        self, connection: Optional[Connection], value: bytes
    ):
        if (
            self.server_features.preset_synchronization_support
            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
        ):
            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
        await self.set_active_preset(connection, value)
        # TODO (low priority) inform other server of the change

    async def _on_set_next_preset_synchronized_locally(
        self, connection: Optional[Connection], __value__: bytes
    ):
        if (
            self.server_features.preset_synchronization_support
            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
        ):
            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
        await self.set_next_or_previous_preset(connection, False)
        # TODO (low priority) inform other server of the change

    async def _on_set_previous_preset_synchronized_locally(
        self, connection: Optional[Connection], __value__: bytes
    ):
        if (
            self.server_features.preset_synchronization_support
            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
        ):
            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
        await self.set_next_or_previous_preset(connection, True)
        # TODO (low priority) inform other server of the change


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class HearingAccessServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = HearingAccessService

    hearing_aid_preset_control_point: gatt_client.CharacteristicProxy
    preset_control_point_indications: asyncio.Queue
    active_preset_index_notification: asyncio.Queue

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.server_features = gatt_adapters.PackedCharacteristicProxyAdapter(
            service_proxy.get_characteristics_by_uuid(
                gatt.GATT_HEARING_AID_FEATURES_CHARACTERISTIC
            )[0],
            'B',
        )

        self.hearing_aid_preset_control_point = (
            service_proxy.get_characteristics_by_uuid(
                gatt.GATT_HEARING_AID_PRESET_CONTROL_POINT_CHARACTERISTIC
            )[0]
        )

        self.active_preset_index = gatt_adapters.PackedCharacteristicProxyAdapter(
            service_proxy.get_characteristics_by_uuid(
                gatt.GATT_ACTIVE_PRESET_INDEX_CHARACTERISTIC
            )[0],
            'B',
        )

    async def setup_subscription(self):
        self.preset_control_point_indications = asyncio.Queue()
        self.active_preset_index_notification = asyncio.Queue()

        def on_active_preset_index_notification(data: bytes):
            self.active_preset_index_notification.put_nowait(data)

        def on_preset_control_point_indication(data: bytes):
            self.preset_control_point_indications.put_nowait(data)

        await self.hearing_aid_preset_control_point.subscribe(
            functools.partial(on_preset_control_point_indication), prefer_notify=False
        )

        await self.active_preset_index.subscribe(
            functools.partial(on_active_preset_index_notification)
        )
