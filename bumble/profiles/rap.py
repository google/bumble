# Copyright 2025 Google LLC
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
import dataclasses
import enum
import functools
import logging
import struct

from typing_extensions import Self

from bumble import att
from bumble import core
from bumble import device
from bumble import gatt
from bumble import gatt_client
from bumble import hci
from bumble import utils

logger = logging.getLogger(__name__)


class RasFeatures(enum.IntFlag):
    '''Ranging Service - 3.1.1 RAS Features format.'''

    REAL_TIME_RANGING_DATA = 0x01
    RETRIEVE_LOST_RANGING_DATA_SEGMENTS = 0x02
    ABORT_OPERATION = 0x04
    FILTER_RANGING_DATA = 0x08


class RasControlPointOpCode(utils.OpenIntEnum):
    '''Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements.'''

    GET_RANGING_DATA = 0x00
    ACK_RANGING_DATA = 0x01
    RETRIEVE_LOST_RANGING_DATA_SEGMENTS = 0x02
    ABORT_OPERATION = 0x03
    SET_FILTER = 0x04


class RasControlPointResponseOpCode(utils.OpenIntEnum):
    '''Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements.'''

    COMPLETE_RANGING_DATA_RESPONSE = 0x00
    COMPLETE_LOST_RANGING_DATA_RESPONSE = 0x01
    RESPONSE_CODE = 0x02


class RasControlPointResponseCode(utils.OpenIntEnum):
    '''Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements.'''

    # RFU = 0x00

    # Normal response for a successful operation
    SUCCESS = 0x01
    # Normal response if an unsupported Op Code is received
    OP_CODE_NOT_SUPPORTED = 0x02
    # Normal response if Parameter received does not meet the requirements of the
    # service
    INVALID_PARAMETER = 0x03
    # Normal response for a successful write operation where the values written to the
    # RAS Control Point are being persisted.
    SUCCESS_PERSISTED = 0x04
    # Normal response if a request for Abort is unsuccessful
    ABORT_UNSUCCESSFUL = 0x05
    # Normal response if unable to complete a procedure for any reason
    PROCEDURE_NOT_COMPLETED = 0x06
    # Normal response if the Server is still busy with other requests
    SERVER_BUSY = 0x07
    # Normal response if the requested Ranging Counter is not found
    NO_RECORDS_FOUND = 0x08


@dataclasses.dataclass
class SegmentationHeader:
    '''Ranging Service - 3.2.1.1 Segmentation Header.'''

    is_first: bool
    is_last: bool
    segment_index: int

    def __bytes__(self) -> bytes:
        return bytes(
            [
                (
                    ((self.segment_index & 0x3F) << 2)
                    | (0x01 if self.is_first else 0x00)
                    | (0x02 if self.is_last else 0x00)
                )
            ]
        )

    @classmethod
    def from_bytes(cls: type[Self], data: bytes) -> Self:
        return cls(
            is_first=bool(data[0] & 0x01),
            is_last=bool(data[0] & 0x02),
            segment_index=data[0] >> 2,
        )


@dataclasses.dataclass
class RangingHeader:
    '''Ranging Service - Table 3.7: Ranging Header structure.'''

    configuration_id: int
    selected_tx_power: int
    antenna_paths_mask: int
    ranging_counter: int

    def __bytes__(self) -> bytes:
        return struct.pack(
            '<HbB',
            self.configuration_id << 12 | (self.ranging_counter & 0xFFF),
            self.selected_tx_power,
            self.antenna_paths_mask,
        )

    @classmethod
    def from_bytes(cls: type[Self], data: bytes) -> Self:
        ranging_counter_and_configuration_id, selected_tx_power, antenna_paths_mask = (
            struct.unpack_from('<HbB', data)
        )
        return cls(
            ranging_counter=ranging_counter_and_configuration_id & 0x3F,
            configuration_id=ranging_counter_and_configuration_id >> 12,
            selected_tx_power=selected_tx_power,
            antenna_paths_mask=antenna_paths_mask,
        )


@dataclasses.dataclass
class Step:
    '''Ranging Service - Table 3.8: Subevent Header and Data structure.'''

    mode: int
    data: bytes

    def __bytes__(self) -> bytes:
        return bytes([self.mode]) + self.data

    @classmethod
    def parse_from(
        cls: type[Self],
        data: bytes,
        config: device.ChannelSoundingConfig,
        num_antenna_paths: int,
        offset: int = 0,
    ) -> tuple[int, Self]:
        mode = data[offset]
        contain_sounding_sequence = config.rtt_type in (
            hci.RttType.SOUNDING_SEQUENCE_32_BIT,
            hci.RttType.SOUNDING_SEQUENCE_96_BIT,
        )
        is_initiator = config.role == hci.CsRole.INITIATOR

        # TODO: Parse mode/role-specific data.
        if mode == 0:
            length = 5 if is_initiator else 3
        elif mode == 1:
            length = 12 if contain_sounding_sequence else 6
        elif mode == 2:
            length = (num_antenna_paths + 1) * 4 + 1
        elif mode == 3:
            length = (num_antenna_paths + 1) * 4 + (
                13 if contain_sounding_sequence else 7
            )
        else:
            raise core.InvalidPacketError(f"Unknown mode 0x{mode:02X}")
        return (offset + length + 1), cls(
            mode=mode, data=data[offset + 1 : offset + 1 + length]
        )


@dataclasses.dataclass
class Subevent:
    '''Ranging Service - Table 3.8: Subevent Header and Data structure.'''

    start_acl_connection_event: int
    frequency_compensation: int
    ranging_done_status: int
    subevent_done_status: int
    ranging_abort_reason: int
    subevent_abort_reason: int
    reference_power_level: int
    steps: list[Step] = dataclasses.field(default_factory=list)

    def __bytes__(self) -> bytes:
        return struct.pack(
            '<HHBBbB',
            self.start_acl_connection_event,
            self.frequency_compensation,
            self.ranging_done_status | self.subevent_done_status << 4,
            self.ranging_abort_reason | self.subevent_abort_reason << 4,
            self.reference_power_level,
            len(self.steps),
        ) + b''.join(map(bytes, self.steps))

    @classmethod
    def parse_from(
        cls: type[Self],
        data: bytes,
        config: device.ChannelSoundingConfig,
        num_antenna_paths: int,
        offset: int = 0,
    ) -> tuple[int, Self]:
        (
            start_acl_connection_event,
            frequency_compensation,
            ranging_done_status_and_subevent_done_status,
            ranging_abort_reason_and_subevent_abort_reason,
            reference_power_level,
            num_reported_steps,
        ) = struct.unpack_from('<HHBBbB', data, offset)
        offset += 8
        steps: list[Step] = []
        for _ in range(num_reported_steps):
            offset, step = Step.parse_from(
                data=data,
                config=config,
                num_antenna_paths=num_antenna_paths,
                offset=offset,
            )
            steps.append(step)
        return offset, cls(
            start_acl_connection_event=start_acl_connection_event,
            frequency_compensation=frequency_compensation,
            ranging_done_status=ranging_done_status_and_subevent_done_status & 0x0F,
            subevent_done_status=ranging_done_status_and_subevent_done_status >> 4,
            ranging_abort_reason=ranging_abort_reason_and_subevent_abort_reason & 0x0F,
            subevent_abort_reason=ranging_abort_reason_and_subevent_abort_reason >> 4,
            reference_power_level=reference_power_level,
            steps=steps,
        )


@dataclasses.dataclass
class RangingData:
    '''Ranging Service - 3.2.1 Ranging Data format.'''

    ranging_header: RangingHeader
    subevents: list[Subevent] = dataclasses.field(default_factory=list)

    def __bytes__(self) -> bytes:
        return bytes(self.ranging_header) + b''.join(map(bytes, self.subevents))

    @classmethod
    def from_bytes(
        cls: type[Self],
        data: bytes,
        config: device.ChannelSoundingConfig,
    ) -> Self:
        pass
        ranging_header = RangingHeader.from_bytes(data)
        num_antenna_paths = 0
        antenna_path_mask = ranging_header.antenna_paths_mask
        while antenna_path_mask > 0:
            if antenna_path_mask & 0x01:
                num_antenna_paths += 1
            antenna_path_mask >>= 1

        subevents: list[Subevent] = []
        offset = 4
        while offset < len(data):
            offset, subevent = Subevent.parse_from(
                data=data,
                config=config,
                num_antenna_paths=num_antenna_paths,
                offset=offset,
            )
            subevents.append(subevent)
        return cls(ranging_header=ranging_header, subevents=subevents)


@dataclasses.dataclass
class Client:
    active_mode: Mode
    cccd_value: gatt.ClientCharacteristicConfigurationBits
    # procedure counter to ranging data
    ranging_data_table: dict[int, RangingData] = dataclasses.field(default_factory=dict)
    # config id to procedure counter
    active_procedure_counter: dict[int, int] = dataclasses.field(default_factory=dict)


class Mode(enum.IntEnum):
    '''Bumble-defined mode enum.'''

    INACTIVE = 0
    ON_DEMAND = 1
    REAL_TIME = 2


class RangingService(gatt.TemplateService):
    UUID = gatt.GATT_RANGING_SERVICE

    clients = dict[device.Connection, Client]()
    real_time_ranging_data_characteristic: gatt.Characteristic | None

    def __init__(
        self,
        device: device.Device,
        ras_features: RasFeatures,
    ) -> None:
        self.device = device
        self.device.host.on('cs_subevent_result', self._on_subevent_result)
        self.device.host.on('cs_subevent_result_continue', self._post_subevent_result)
        self.device.on('connection', self._on_connection)
        self.ras_features_characteristic = gatt.Characteristic(
            gatt.GATT_RAS_FEATURES_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ,
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=struct.pack("<I", ras_features),
        )
        if ras_features & RasFeatures.REAL_TIME_RANGING_DATA:
            self.real_time_ranging_data_characteristic = gatt.Characteristic(
                gatt.GATT_REAL_TIME_RANGING_DATA_CHARACTERISTIC,
                properties=(
                    gatt.Characteristic.Properties.INDICATE
                    | gatt.Characteristic.Properties.NOTIFY
                ),
                permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
                descriptors=[
                    gatt.Descriptor(
                        gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
                        permissions=(
                            gatt.Descriptor.Permissions.READ_REQUIRES_ENCRYPTION
                            | gatt.Descriptor.Permissions.WRITE_REQUIRES_ENCRYPTION
                        ),
                        value=gatt.AttributeValue(
                            read=functools.partial(self._on_cccd_read, Mode.REAL_TIME),
                            write=functools.partial(
                                self._on_cccd_write, Mode.REAL_TIME
                            ),
                        ),
                    )
                ],
            )
        else:
            self.real_time_ranging_data_characteristic = None

        self._on_demand_ranging_data_characteristic = gatt.Characteristic(
            gatt.GATT_ON_DEMAND_RANGING_DATA_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.INDICATE
                | gatt.Characteristic.Properties.NOTIFY
            ),
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            descriptors=[
                gatt.Descriptor(
                    gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
                    permissions=(
                        gatt.Descriptor.Permissions.READ_REQUIRES_ENCRYPTION
                        | gatt.Descriptor.Permissions.WRITE_REQUIRES_ENCRYPTION
                    ),
                    value=gatt.AttributeValue(
                        read=functools.partial(self._on_cccd_read, Mode.ON_DEMAND),
                        write=functools.partial(self._on_cccd_write, Mode.ON_DEMAND),
                    ),
                )
            ],
        )

        self.ras_control_point_characteristic = gatt.Characteristic(
            gatt.GATT_RAS_CONTROL_POINT_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.INDICATE
                | gatt.Characteristic.Properties.WRITE
                | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
            ),
            permissions=gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=gatt.CharacteristicValue(write=self._on_write_control_point),
        )

        self.ranging_data_ready_characteristic = gatt.Characteristic(
            gatt.GATT_RANGING_DATA_READY_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.INDICATE
                | gatt.Characteristic.Properties.NOTIFY
                | gatt.Characteristic.Properties.READ
            ),
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=struct.pack('<H', 0),
        )

        self.ranging_data_overwritten_characteristic = gatt.Characteristic(
            gatt.GATT_RANGING_DATA_OVERWRITTEN_CHARACTERISTIC,
            properties=(
                gatt.Characteristic.Properties.INDICATE
                | gatt.Characteristic.Properties.NOTIFY
                | gatt.Characteristic.Properties.READ
            ),
            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            # TODO: Improve data overwritten.
            value=struct.pack('<H', 0),
        )

        super().__init__(
            [
                characteristic
                for characteristic in (
                    self.ras_features_characteristic,
                    self.real_time_ranging_data_characteristic,
                    self._on_demand_ranging_data_characteristic,
                    self.ras_control_point_characteristic,
                    self.ranging_data_ready_characteristic,
                    self.ranging_data_overwritten_characteristic,
                )
                if characteristic is not None
            ]
        )

    def _on_cccd_write(
        self,
        mode: Mode,
        connection: device.Connection | None,
        data: bytes,
    ) -> None:
        assert connection
        cccd_value = gatt.ClientCharacteristicConfigurationBits(
            int.from_bytes(data, 'little')
        )
        logger.debug("on_cccd_write, connection=%s, value=%s", connection, cccd_value)
        if not (client := self.clients.get(connection)):
            client = self.clients[connection] = Client(
                active_mode=Mode.INACTIVE,
                cccd_value=gatt.ClientCharacteristicConfigurationBits.DEFAULT,
            )

        if client.active_mode not in (Mode.INACTIVE, mode):
            logger.error("Forbid subscribing when another mode is active!")
            raise att.ATT_Error(att.ErrorCode.WRITE_REQUEST_REJECTED)

        if cccd_value == gatt.ClientCharacteristicConfigurationBits.DEFAULT:
            client.active_mode = Mode.INACTIVE
        else:
            client.active_mode = mode
        client.cccd_value = cccd_value

    def _on_cccd_read(
        self,
        mode: Mode,
        connection: device.Connection | None,
    ) -> bytes:
        assert connection
        if not (client := self.clients.get(connection)):
            client = self.clients[connection] = Client(
                active_mode=Mode.INACTIVE,
                cccd_value=gatt.ClientCharacteristicConfigurationBits.DEFAULT,
            )
        if mode != client.active_mode:
            client.cccd_value = gatt.ClientCharacteristicConfigurationBits.DEFAULT
        return struct.pack("<H", client.cccd_value)

    def _on_subevent_result(self, event: hci.HCI_LE_CS_Subevent_Result_Event) -> None:
        if not (connection := self.device.lookup_connection(event.connection_handle)):
            logger.error(
                "Subevent for unknown connection 0x%04X", event.connection_handle
            )
            return
        if not (client := self.clients[connection]):
            return
        procedure_counter = event.procedure_counter
        if not (ranging_data := client.ranging_data_table.get(procedure_counter)):
            ranging_data = client.ranging_data_table[procedure_counter] = RangingData(
                ranging_header=RangingHeader(
                    event.config_id,
                    selected_tx_power=connection.cs_procedures[
                        event.config_id
                    ].selected_tx_power,
                    antenna_paths_mask=(1 << (event.num_antenna_paths + 1)) - 1,
                    ranging_counter=procedure_counter,
                )
            )

        subevent = Subevent(
            start_acl_connection_event=event.start_acl_conn_event_counter,
            frequency_compensation=event.frequency_compensation,
            ranging_abort_reason=event.procedure_done_status,
            ranging_done_status=event.procedure_done_status,
            subevent_done_status=event.subevent_done_status,
            subevent_abort_reason=event.abort_reason,
            reference_power_level=event.reference_power_level,
        )
        ranging_data.subevents.append(subevent)
        client.active_procedure_counter[event.config_id] = procedure_counter
        self.ranging_data_ready_characteristic.value = struct.pack(
            '<H', procedure_counter
        )
        self._post_subevent_result(event)

    def _post_subevent_result(
        self,
        event: (
            hci.HCI_LE_CS_Subevent_Result_Event
            | hci.HCI_LE_CS_Subevent_Result_Continue_Event
        ),
    ) -> None:
        if not (connection := self.device.lookup_connection(event.connection_handle)):
            logger.error(
                "Subevent for unknown connection 0x%04X", event.connection_handle
            )
            return
        if not (client := self.clients[connection]):
            return
        procedure_counter = client.active_procedure_counter[event.config_id]
        ranging_data = client.ranging_data_table[procedure_counter]
        subevent = ranging_data.subevents[-1]
        subevent.ranging_done_status = event.procedure_done_status
        subevent.subevent_done_status = event.subevent_done_status
        subevent.steps.extend(
            [Step(mode, data) for mode, data in zip(event.step_mode, event.step_data)]
        )

        if event.procedure_done_status == hci.CsDoneStatus.ALL_RESULTS_COMPLETED:
            self.device.abort_on(
                'flush',
                self.device.notify_subscribers(self.ranging_data_ready_characteristic),
            )
            if client.active_mode == Mode.REAL_TIME:
                connection.abort_on(
                    'disconnection',
                    self.send_ranging_data(
                        connection=connection,
                        data=bytes(ranging_data),
                    ),
                )

    async def _on_write_control_point(
        self, connection: device.Connection | None, data: bytes
    ) -> None:
        assert connection
        op_code = data[0]
        response: bytes
        if op_code == RasControlPointOpCode.GET_RANGING_DATA:
            ranging_counter = struct.unpack_from('<H', data, 1)[0]
            if not (client := self.clients.get(connection)) or not (
                ranging_data := client.ranging_data_table.get(ranging_counter)
            ):
                response = bytes(
                    [
                        RasControlPointResponseOpCode.RESPONSE_CODE,
                        RasControlPointResponseCode.NO_RECORDS_FOUND,
                    ]
                )
            else:
                await self.send_ranging_data(connection, bytes(ranging_data))
                response = bytes(
                    [RasControlPointResponseOpCode.COMPLETE_RANGING_DATA_RESPONSE]
                )
        elif op_code == RasControlPointOpCode.ACK_RANGING_DATA:
            ranging_counter = struct.unpack_from('<H', data, 1)[0]
            # Delete corresponding ranging data.
            if not (client := self.clients.get(connection)) or not (
                ranging_data := client.ranging_data_table.pop(ranging_counter)
            ):
                response = bytes(
                    [
                        RasControlPointResponseOpCode.RESPONSE_CODE,
                        RasControlPointResponseCode.NO_RECORDS_FOUND,
                    ]
                )
            else:
                response = bytes(
                    [
                        RasControlPointResponseOpCode.RESPONSE_CODE,
                        RasControlPointResponseCode.SUCCESS,
                    ]
                )
        else:
            # TODO: Implement remaining operations.
            response = bytes(
                [
                    RasControlPointResponseOpCode.RESPONSE_CODE,
                    RasControlPointResponseCode.OP_CODE_NOT_SUPPORTED,
                ]
            )
        await self.device.indicate_subscriber(
            connection=connection,
            attribute=self.ras_control_point_characteristic,
            value=response,
        )

    def _on_connection(self, connection: device.Connection) -> None:
        connection.once(
            'disconnection',
            functools.partial(self._on_disconnection, connection),
        )

    def _on_disconnection(self, connection: device.Connection, reason: int) -> None:
        del reason
        self.clients.pop(connection, None)

    async def send_ranging_data(
        self,
        connection: device.Connection,
        data: bytes,
    ) -> None:
        mps = connection.att_mtu - 6
        client = self.clients[connection]
        if client.active_mode == Mode.ON_DEMAND:
            characteristic = self._on_demand_ranging_data_characteristic
        elif client.active_mode == Mode.REAL_TIME:
            if not self.real_time_ranging_data_characteristic:
                logger.error(
                    "Trying to send real time ranging data, but it's not supported."
                )
                return
            characteristic = self.real_time_ranging_data_characteristic
        else:
            logger.debug('%s does not enable ranging data.', client)
            return

        if client.cccd_value & gatt.ClientCharacteristicConfigurationBits.NOTIFICATION:
            method = self.device.notify_subscriber
        elif client.cccd_value & gatt.ClientCharacteristicConfigurationBits.INDICATION:
            method = self.device.indicate_subscriber
        else:
            logger.debug('%s does not enable ranging data.', client)
            return

        for index, offset in enumerate(range(0, len(data), mps)):
            fragment = data[offset : offset + mps]
            header = SegmentationHeader(
                is_first=(offset == 0),
                is_last=(offset + len(fragment) >= len(data)),
                segment_index=index,
            )
            await method(
                connection=connection,
                attribute=characteristic,
                value=bytes(header) + fragment,
                force=True,
            )


# -----------------------------------------------------------------------------
class RangingServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = RangingService

    ras_features_characteristic: gatt_client.CharacteristicProxy
    on_demand_ranging_data_characteristic: gatt_client.CharacteristicProxy
    ras_control_point_characteristic: gatt_client.CharacteristicProxy
    ranging_data_ready_characteristic: gatt_client.CharacteristicProxy
    ranging_data_overwritten_characteristic: gatt_client.CharacteristicProxy

    # Optional.
    real_time_ranging_data_characteristic: gatt_client.CharacteristicProxy | None = None

    def __init__(self, service_proxy: gatt_client.ServiceProxy):
        self.service_proxy = service_proxy

        for attribute, uuid in {
            "ras_features_characteristic": gatt.GATT_RAS_FEATURES_CHARACTERISTIC,
            "on_demand_ranging_data_characteristic": gatt.GATT_ON_DEMAND_RANGING_DATA_CHARACTERISTIC,
            "ras_control_point_characteristic": gatt.GATT_RAS_CONTROL_POINT_CHARACTERISTIC,
            "ranging_data_ready_characteristic": gatt.GATT_RANGING_DATA_READY_CHARACTERISTIC,
            "ranging_data_overwritten_characteristic": gatt.GATT_RANGING_DATA_OVERWRITTEN_CHARACTERISTIC,
        }.items():
            if not (characteristics := service_proxy.get_characteristics_by_uuid(uuid)):
                raise gatt.InvalidServiceError(
                    f"Missing mandatory characteristic {uuid}"
                )
            setattr(self, attribute, characteristics[0])

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_REAL_TIME_RANGING_DATA_CHARACTERISTIC
        ):
            self.real_time_ranging_data_characteristic = characteristics[0]
