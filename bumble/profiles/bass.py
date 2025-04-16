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
# See the License for

"""LE Audio - Broadcast Audio Scan Service"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import dataclasses
import logging
import struct
from typing import ClassVar, Optional, Sequence

from bumble import core
from bumble import device
from bumble import gatt
from bumble import gatt_adapters
from bumble import gatt_client
from bumble import hci
from bumble import utils

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
class ApplicationError(utils.OpenIntEnum):
    OPCODE_NOT_SUPPORTED = 0x80
    INVALID_SOURCE_ID = 0x81


# -----------------------------------------------------------------------------
def encode_subgroups(subgroups: Sequence[SubgroupInfo]) -> bytes:
    return bytes([len(subgroups)]) + b"".join(
        struct.pack("<IB", subgroup.bis_sync, len(subgroup.metadata))
        + subgroup.metadata
        for subgroup in subgroups
    )


def decode_subgroups(data: bytes) -> list[SubgroupInfo]:
    num_subgroups = data[0]
    offset = 1
    subgroups = []
    for _ in range(num_subgroups):
        bis_sync = struct.unpack("<I", data[offset : offset + 4])[0]
        metadata_length = data[offset + 4]
        metadata = data[offset + 5 : offset + 5 + metadata_length]
        offset += 5 + metadata_length
        subgroups.append(SubgroupInfo(bis_sync, metadata))

    return subgroups


# -----------------------------------------------------------------------------
class PeriodicAdvertisingSyncParams(utils.OpenIntEnum):
    DO_NOT_SYNCHRONIZE_TO_PA = 0x00
    SYNCHRONIZE_TO_PA_PAST_AVAILABLE = 0x01
    SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE = 0x02


@dataclasses.dataclass
class SubgroupInfo:
    ANY_BIS: ClassVar[int] = 0xFFFFFFFF

    bis_sync: int
    metadata: bytes


class ControlPointOperation:
    class OpCode(utils.OpenIntEnum):
        REMOTE_SCAN_STOPPED = 0x00
        REMOTE_SCAN_STARTED = 0x01
        ADD_SOURCE = 0x02
        MODIFY_SOURCE = 0x03
        SET_BROADCAST_CODE = 0x04
        REMOVE_SOURCE = 0x05

    op_code: OpCode
    parameters: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> ControlPointOperation:
        op_code = data[0]

        if op_code == cls.OpCode.REMOTE_SCAN_STOPPED:
            return RemoteScanStoppedOperation()

        if op_code == cls.OpCode.REMOTE_SCAN_STARTED:
            return RemoteScanStartedOperation()

        if op_code == cls.OpCode.ADD_SOURCE:
            return AddSourceOperation.from_parameters(data[1:])

        if op_code == cls.OpCode.MODIFY_SOURCE:
            return ModifySourceOperation.from_parameters(data[1:])

        if op_code == cls.OpCode.SET_BROADCAST_CODE:
            return SetBroadcastCodeOperation.from_parameters(data[1:])

        if op_code == cls.OpCode.REMOVE_SOURCE:
            return RemoveSourceOperation.from_parameters(data[1:])

        raise core.InvalidArgumentError("invalid op code")

    def __init__(self, op_code: OpCode, parameters: bytes = b"") -> None:
        self.op_code = op_code
        self.parameters = parameters

    def __bytes__(self) -> bytes:
        return bytes([self.op_code]) + self.parameters


class RemoteScanStoppedOperation(ControlPointOperation):
    def __init__(self) -> None:
        super().__init__(ControlPointOperation.OpCode.REMOTE_SCAN_STOPPED)


class RemoteScanStartedOperation(ControlPointOperation):
    def __init__(self) -> None:
        super().__init__(ControlPointOperation.OpCode.REMOTE_SCAN_STARTED)


class AddSourceOperation(ControlPointOperation):
    @classmethod
    def from_parameters(cls, parameters: bytes) -> AddSourceOperation:
        instance = cls.__new__(cls)
        instance.op_code = ControlPointOperation.OpCode.ADD_SOURCE
        instance.parameters = parameters
        instance.advertiser_address = hci.Address.parse_address_preceded_by_type(
            parameters, 1
        )[1]
        instance.advertising_sid = parameters[7]
        instance.broadcast_id = int.from_bytes(parameters[8:11], "little")
        instance.pa_sync = PeriodicAdvertisingSyncParams(parameters[11])
        instance.pa_interval = struct.unpack("<H", parameters[12:14])[0]
        instance.subgroups = decode_subgroups(parameters[14:])
        return instance

    def __init__(
        self,
        advertiser_address: hci.Address,
        advertising_sid: int,
        broadcast_id: int,
        pa_sync: PeriodicAdvertisingSyncParams,
        pa_interval: int,
        subgroups: Sequence[SubgroupInfo],
    ) -> None:
        super().__init__(
            ControlPointOperation.OpCode.ADD_SOURCE,
            struct.pack(
                "<B6sB3sBH",
                advertiser_address.address_type,
                bytes(advertiser_address),
                advertising_sid,
                broadcast_id.to_bytes(3, "little"),
                pa_sync,
                pa_interval,
            )
            + encode_subgroups(subgroups),
        )
        self.advertiser_address = advertiser_address
        self.advertising_sid = advertising_sid
        self.broadcast_id = broadcast_id
        self.pa_sync = pa_sync
        self.pa_interval = pa_interval
        self.subgroups = list(subgroups)


class ModifySourceOperation(ControlPointOperation):
    @classmethod
    def from_parameters(cls, parameters: bytes) -> ModifySourceOperation:
        instance = cls.__new__(cls)
        instance.op_code = ControlPointOperation.OpCode.MODIFY_SOURCE
        instance.parameters = parameters
        instance.source_id = parameters[0]
        instance.pa_sync = PeriodicAdvertisingSyncParams(parameters[1])
        instance.pa_interval = struct.unpack("<H", parameters[2:4])[0]
        instance.subgroups = decode_subgroups(parameters[4:])
        return instance

    def __init__(
        self,
        source_id: int,
        pa_sync: PeriodicAdvertisingSyncParams,
        pa_interval: int,
        subgroups: Sequence[SubgroupInfo],
    ) -> None:
        super().__init__(
            ControlPointOperation.OpCode.MODIFY_SOURCE,
            struct.pack("<BBH", source_id, pa_sync, pa_interval)
            + encode_subgroups(subgroups),
        )
        self.source_id = source_id
        self.pa_sync = pa_sync
        self.pa_interval = pa_interval
        self.subgroups = list(subgroups)


class SetBroadcastCodeOperation(ControlPointOperation):
    @classmethod
    def from_parameters(cls, parameters: bytes) -> SetBroadcastCodeOperation:
        instance = cls.__new__(cls)
        instance.op_code = ControlPointOperation.OpCode.SET_BROADCAST_CODE
        instance.parameters = parameters
        instance.source_id = parameters[0]
        instance.broadcast_code = parameters[1:17]
        return instance

    def __init__(
        self,
        source_id: int,
        broadcast_code: bytes,
    ) -> None:
        super().__init__(
            ControlPointOperation.OpCode.SET_BROADCAST_CODE,
            bytes([source_id]) + broadcast_code,
        )
        self.source_id = source_id
        self.broadcast_code = broadcast_code

        if len(self.broadcast_code) != 16:
            raise core.InvalidArgumentError("broadcast_code must be 16 bytes")


class RemoveSourceOperation(ControlPointOperation):
    @classmethod
    def from_parameters(cls, parameters: bytes) -> RemoveSourceOperation:
        instance = cls.__new__(cls)
        instance.op_code = ControlPointOperation.OpCode.REMOVE_SOURCE
        instance.parameters = parameters
        instance.source_id = parameters[0]
        return instance

    def __init__(self, source_id: int) -> None:
        super().__init__(ControlPointOperation.OpCode.REMOVE_SOURCE, bytes([source_id]))
        self.source_id = source_id


@dataclasses.dataclass
class BroadcastReceiveState:
    class PeriodicAdvertisingSyncState(utils.OpenIntEnum):
        NOT_SYNCHRONIZED_TO_PA = 0x00
        SYNCINFO_REQUEST = 0x01
        SYNCHRONIZED_TO_PA = 0x02
        FAILED_TO_SYNCHRONIZE_TO_PA = 0x03
        NO_PAST = 0x04

    class BigEncryption(utils.OpenIntEnum):
        NOT_ENCRYPTED = 0x00
        BROADCAST_CODE_REQUIRED = 0x01
        DECRYPTING = 0x02
        BAD_CODE = 0x03

    source_id: int
    source_address: hci.Address
    source_adv_sid: int
    broadcast_id: int
    pa_sync_state: PeriodicAdvertisingSyncState
    big_encryption: BigEncryption
    bad_code: bytes
    subgroups: list[SubgroupInfo]

    @classmethod
    def from_bytes(cls, data: bytes) -> BroadcastReceiveState:
        source_id = data[0]
        _, source_address = hci.Address.parse_address_preceded_by_type(data, 2)
        source_adv_sid = data[8]
        broadcast_id = int.from_bytes(data[9:12], "little")
        pa_sync_state = cls.PeriodicAdvertisingSyncState(data[12])
        big_encryption = cls.BigEncryption(data[13])
        if big_encryption == cls.BigEncryption.BAD_CODE:
            bad_code = data[14:30]
            subgroups = decode_subgroups(data[30:])
        else:
            bad_code = b""
            subgroups = decode_subgroups(data[14:])

        return cls(
            source_id,
            source_address,
            source_adv_sid,
            broadcast_id,
            pa_sync_state,
            big_encryption,
            bad_code,
            subgroups,
        )

    def __bytes__(self) -> bytes:
        return (
            struct.pack(
                "<BB6sB3sBB",
                self.source_id,
                self.source_address.address_type,
                bytes(self.source_address),
                self.source_adv_sid,
                self.broadcast_id.to_bytes(3, "little"),
                self.pa_sync_state,
                self.big_encryption,
            )
            + self.bad_code
            + encode_subgroups(self.subgroups)
        )


# -----------------------------------------------------------------------------
class BroadcastAudioScanService(gatt.TemplateService):
    UUID = gatt.GATT_BROADCAST_AUDIO_SCAN_SERVICE

    def __init__(self):
        self.broadcast_audio_scan_control_point_characteristic = gatt.Characteristic(
            gatt.GATT_BROADCAST_AUDIO_SCAN_CONTROL_POINT_CHARACTERISTIC,
            gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            gatt.Characteristic.WRITEABLE,
            gatt.CharacteristicValue(
                write=self.on_broadcast_audio_scan_control_point_write
            ),
        )

        self.broadcast_receive_state_characteristic = gatt.Characteristic(
            gatt.GATT_BROADCAST_RECEIVE_STATE_CHARACTERISTIC,
            gatt.Characteristic.Properties.READ | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.Permissions.READABLE
            | gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            b"12",  # TEST
        )

        super().__init__([self.battery_level_characteristic])

    def on_broadcast_audio_scan_control_point_write(
        self, connection: device.Connection, value: bytes
    ) -> None:
        pass


# -----------------------------------------------------------------------------
class BroadcastAudioScanServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = BroadcastAudioScanService

    broadcast_audio_scan_control_point: gatt_client.CharacteristicProxy[bytes]
    broadcast_receive_states: list[
        gatt_client.CharacteristicProxy[Optional[BroadcastReceiveState]]
    ]

    def __init__(self, service_proxy: gatt_client.ServiceProxy):
        self.service_proxy = service_proxy

        self.broadcast_audio_scan_control_point = (
            service_proxy.get_required_characteristic_by_uuid(
                gatt.GATT_BROADCAST_AUDIO_SCAN_CONTROL_POINT_CHARACTERISTIC
            )
        )

        self.broadcast_receive_states = [
            gatt_adapters.DelegatedCharacteristicProxyAdapter(
                characteristic,
                decode=lambda x: BroadcastReceiveState.from_bytes(x) if x else None,
            )
            for characteristic in service_proxy.get_characteristics_by_uuid(
                gatt.GATT_BROADCAST_RECEIVE_STATE_CHARACTERISTIC
            )
        ]

    async def send_control_point_operation(
        self, operation: ControlPointOperation
    ) -> None:
        await self.broadcast_audio_scan_control_point.write_value(
            bytes(operation), with_response=True
        )

    async def remote_scan_started(self) -> None:
        await self.send_control_point_operation(RemoteScanStartedOperation())

    async def remote_scan_stopped(self) -> None:
        await self.send_control_point_operation(RemoteScanStoppedOperation())

    async def add_source(
        self,
        advertiser_address: hci.Address,
        advertising_sid: int,
        broadcast_id: int,
        pa_sync: PeriodicAdvertisingSyncParams,
        pa_interval: int,
        subgroups: Sequence[SubgroupInfo],
    ) -> None:
        await self.send_control_point_operation(
            AddSourceOperation(
                advertiser_address,
                advertising_sid,
                broadcast_id,
                pa_sync,
                pa_interval,
                subgroups,
            )
        )

    async def modify_source(
        self,
        source_id: int,
        pa_sync: PeriodicAdvertisingSyncParams,
        pa_interval: int,
        subgroups: Sequence[SubgroupInfo],
    ) -> None:
        await self.send_control_point_operation(
            ModifySourceOperation(
                source_id,
                pa_sync,
                pa_interval,
                subgroups,
            )
        )

    async def remove_source(self, source_id: int) -> None:
        await self.send_control_point_operation(RemoveSourceOperation(source_id))
