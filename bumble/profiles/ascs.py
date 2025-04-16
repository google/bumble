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

"""LE Audio - Audio Stream Control Service"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import enum
import logging
import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type, Union

from bumble import utils
from bumble import colors
from bumble.profiles.bap import CodecSpecificConfiguration
from bumble.profiles import le_audio
from bumble import device
from bumble import gatt
from bumble import gatt_client
from bumble import hci

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# ASE Operations
# -----------------------------------------------------------------------------


class ASE_Operation:
    '''
    See Audio Stream Control Service - 5 ASE Control operations.
    '''

    classes: Dict[int, Type[ASE_Operation]] = {}
    op_code: int
    name: str
    fields: Optional[Sequence[Any]] = None
    ase_id: List[int]

    class Opcode(enum.IntEnum):
        # fmt: off
        CONFIG_CODEC         = 0x01
        CONFIG_QOS           = 0x02
        ENABLE               = 0x03
        RECEIVER_START_READY = 0x04
        DISABLE              = 0x05
        RECEIVER_STOP_READY  = 0x06
        UPDATE_METADATA      = 0x07
        RELEASE              = 0x08

    @staticmethod
    def from_bytes(pdu: bytes) -> ASE_Operation:
        op_code = pdu[0]

        cls = ASE_Operation.classes.get(op_code)
        if cls is None:
            instance = ASE_Operation(pdu)
            instance.name = ASE_Operation.Opcode(op_code).name
            instance.op_code = op_code
            return instance
        self = cls.__new__(cls)
        ASE_Operation.__init__(self, pdu)
        if self.fields is not None:
            self.init_from_bytes(pdu, 1)
        return self

    @staticmethod
    def subclass(fields):
        def inner(cls: Type[ASE_Operation]):
            try:
                operation = ASE_Operation.Opcode[cls.__name__[4:].upper()]
                cls.name = operation.name
                cls.op_code = operation
            except:
                raise KeyError(f'PDU name {cls.name} not found in Ase_Operation.Opcode')
            cls.fields = fields

            # Register a factory for this class
            ASE_Operation.classes[cls.op_code] = cls

            return cls

        return inner

    def __init__(self, pdu: Optional[bytes] = None, **kwargs) -> None:
        if self.fields is not None and kwargs:
            hci.HCI_Object.init_from_fields(self, self.fields, kwargs)
        if pdu is None:
            pdu = bytes([self.op_code]) + hci.HCI_Object.dict_to_bytes(
                kwargs, self.fields
            )
        self.pdu = pdu

    def init_from_bytes(self, pdu: bytes, offset: int):
        return hci.HCI_Object.init_from_bytes(self, pdu, offset, self.fields)

    def __bytes__(self) -> bytes:
        return self.pdu

    def __str__(self) -> str:
        result = f'{colors.color(self.name, "yellow")} '
        if fields := getattr(self, 'fields', None):
            result += ':\n' + hci.HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if len(self.pdu) > 1:
                result += f': {self.pdu.hex()}'
        return result


@ASE_Operation.subclass(
    [
        [
            ('ase_id', 1),
            ('target_latency', 1),
            ('target_phy', 1),
            ('codec_id', hci.CodingFormat.parse_from_bytes),
            ('codec_specific_configuration', 'v'),
        ],
    ]
)
class ASE_Config_Codec(ASE_Operation):
    '''
    See Audio Stream Control Service 5.1 - Config Codec Operation
    '''

    target_latency: List[int]
    target_phy: List[int]
    codec_id: List[hci.CodingFormat]
    codec_specific_configuration: List[bytes]


@ASE_Operation.subclass(
    [
        [
            ('ase_id', 1),
            ('cig_id', 1),
            ('cis_id', 1),
            ('sdu_interval', 3),
            ('framing', 1),
            ('phy', 1),
            ('max_sdu', 2),
            ('retransmission_number', 1),
            ('max_transport_latency', 2),
            ('presentation_delay', 3),
        ],
    ]
)
class ASE_Config_QOS(ASE_Operation):
    '''
    See Audio Stream Control Service 5.2 - Config Qos Operation
    '''

    cig_id: List[int]
    cis_id: List[int]
    sdu_interval: List[int]
    framing: List[int]
    phy: List[int]
    max_sdu: List[int]
    retransmission_number: List[int]
    max_transport_latency: List[int]
    presentation_delay: List[int]


@ASE_Operation.subclass([[('ase_id', 1), ('metadata', 'v')]])
class ASE_Enable(ASE_Operation):
    '''
    See Audio Stream Control Service 5.3 - Enable Operation
    '''

    metadata: bytes


@ASE_Operation.subclass([[('ase_id', 1)]])
class ASE_Receiver_Start_Ready(ASE_Operation):
    '''
    See Audio Stream Control Service 5.4 - Receiver Start Ready Operation
    '''


@ASE_Operation.subclass([[('ase_id', 1)]])
class ASE_Disable(ASE_Operation):
    '''
    See Audio Stream Control Service 5.5 - Disable Operation
    '''


@ASE_Operation.subclass([[('ase_id', 1)]])
class ASE_Receiver_Stop_Ready(ASE_Operation):
    '''
    See Audio Stream Control Service 5.6 - Receiver Stop Ready Operation
    '''


@ASE_Operation.subclass([[('ase_id', 1), ('metadata', 'v')]])
class ASE_Update_Metadata(ASE_Operation):
    '''
    See Audio Stream Control Service 5.7 - Update Metadata Operation
    '''

    metadata: List[bytes]


@ASE_Operation.subclass([[('ase_id', 1)]])
class ASE_Release(ASE_Operation):
    '''
    See Audio Stream Control Service 5.8 - Release Operation
    '''


class AseResponseCode(enum.IntEnum):
    # fmt: off
    SUCCESS                                     = 0x00
    UNSUPPORTED_OPCODE                          = 0x01
    INVALID_LENGTH                              = 0x02
    INVALID_ASE_ID                              = 0x03
    INVALID_ASE_STATE_MACHINE_TRANSITION        = 0x04
    INVALID_ASE_DIRECTION                       = 0x05
    UNSUPPORTED_AUDIO_CAPABILITIES              = 0x06
    UNSUPPORTED_CONFIGURATION_PARAMETER_VALUE   = 0x07
    REJECTED_CONFIGURATION_PARAMETER_VALUE      = 0x08
    INVALID_CONFIGURATION_PARAMETER_VALUE       = 0x09
    UNSUPPORTED_METADATA                        = 0x0A
    REJECTED_METADATA                           = 0x0B
    INVALID_METADATA                            = 0x0C
    INSUFFICIENT_RESOURCES                      = 0x0D
    UNSPECIFIED_ERROR                           = 0x0E


class AseReasonCode(enum.IntEnum):
    # fmt: off
    NONE                            = 0x00
    CODEC_ID                        = 0x01
    CODEC_SPECIFIC_CONFIGURATION    = 0x02
    SDU_INTERVAL                    = 0x03
    FRAMING                         = 0x04
    PHY                             = 0x05
    MAXIMUM_SDU_SIZE                = 0x06
    RETRANSMISSION_NUMBER           = 0x07
    MAX_TRANSPORT_LATENCY           = 0x08
    PRESENTATION_DELAY              = 0x09
    INVALID_ASE_CIS_MAPPING         = 0x0A


# -----------------------------------------------------------------------------
class AudioRole(enum.IntEnum):
    SINK = device.CisLink.Direction.CONTROLLER_TO_HOST
    SOURCE = device.CisLink.Direction.HOST_TO_CONTROLLER


# -----------------------------------------------------------------------------
class AseStateMachine(gatt.Characteristic):
    class State(enum.IntEnum):
        # fmt: off
        IDLE             = 0x00
        CODEC_CONFIGURED = 0x01
        QOS_CONFIGURED   = 0x02
        ENABLING         = 0x03
        STREAMING        = 0x04
        DISABLING        = 0x05
        RELEASING        = 0x06

    cis_link: Optional[device.CisLink] = None

    # Additional parameters in CODEC_CONFIGURED State
    preferred_framing = 0  # Unframed PDU supported
    preferred_phy = 0
    preferred_retransmission_number = 13
    preferred_max_transport_latency = 100
    supported_presentation_delay_min = 0
    supported_presentation_delay_max = 0
    preferred_presentation_delay_min = 0
    preferred_presentation_delay_max = 0
    codec_id = hci.CodingFormat(hci.CodecID.LC3)
    codec_specific_configuration: Union[CodecSpecificConfiguration, bytes] = b''

    # Additional parameters in QOS_CONFIGURED State
    cig_id = 0
    cis_id = 0
    sdu_interval = 0
    framing = 0
    phy = 0
    max_sdu = 0
    retransmission_number = 0
    max_transport_latency = 0
    presentation_delay = 0

    # Additional parameters in ENABLING, STREAMING, DISABLING State
    metadata: le_audio.Metadata

    def __init__(
        self,
        role: AudioRole,
        ase_id: int,
        service: AudioStreamControlService,
    ) -> None:
        self.service = service
        self.ase_id = ase_id
        self._state = AseStateMachine.State.IDLE
        self.role = role
        self.metadata = le_audio.Metadata()

        uuid = (
            gatt.GATT_SINK_ASE_CHARACTERISTIC
            if role == AudioRole.SINK
            else gatt.GATT_SOURCE_ASE_CHARACTERISTIC
        )
        super().__init__(
            uuid=uuid,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=gatt.CharacteristicValue(read=self.on_read),
        )

        self.service.device.on('cis_request', self.on_cis_request)
        self.service.device.on('cis_establishment', self.on_cis_establishment)

    def on_cis_request(
        self,
        acl_connection: device.Connection,
        cis_handle: int,
        cig_id: int,
        cis_id: int,
    ) -> None:
        if (
            cig_id == self.cig_id
            and cis_id == self.cis_id
            and self.state == self.State.ENABLING
        ):
            utils.cancel_on_event(
                acl_connection,
                'flush',
                self.service.device.accept_cis_request(cis_handle),
            )

    def on_cis_establishment(self, cis_link: device.CisLink) -> None:
        if (
            cis_link.cig_id == self.cig_id
            and cis_link.cis_id == self.cis_id
            and self.state == self.State.ENABLING
        ):
            cis_link.on('disconnection', self.on_cis_disconnection)

            async def post_cis_established():
                await cis_link.setup_data_path(direction=self.role)
                if self.role == AudioRole.SINK:
                    self.state = self.State.STREAMING
                await self.service.device.notify_subscribers(self, self.value)

            utils.cancel_on_event(
                cis_link.acl_connection, 'flush', post_cis_established()
            )
            self.cis_link = cis_link

    def on_cis_disconnection(self, _reason) -> None:
        self.cis_link = None

    def on_config_codec(
        self,
        target_latency: int,
        target_phy: int,
        codec_id: hci.CodingFormat,
        codec_specific_configuration: bytes,
    ) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state not in (
            self.State.IDLE,
            self.State.CODEC_CONFIGURED,
            self.State.QOS_CONFIGURED,
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )

        self.max_transport_latency = target_latency
        self.phy = target_phy
        self.codec_id = codec_id
        if codec_id.codec_id == hci.CodecID.VENDOR_SPECIFIC:
            self.codec_specific_configuration = codec_specific_configuration
        else:
            self.codec_specific_configuration = CodecSpecificConfiguration.from_bytes(
                codec_specific_configuration
            )

        self.state = self.State.CODEC_CONFIGURED

        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_config_qos(
        self,
        cig_id: int,
        cis_id: int,
        sdu_interval: int,
        framing: int,
        phy: int,
        max_sdu: int,
        retransmission_number: int,
        max_transport_latency: int,
        presentation_delay: int,
    ) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state not in (
            AseStateMachine.State.CODEC_CONFIGURED,
            AseStateMachine.State.QOS_CONFIGURED,
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )

        self.cig_id = cig_id
        self.cis_id = cis_id
        self.sdu_interval = sdu_interval
        self.framing = framing
        self.phy = phy
        self.max_sdu = max_sdu
        self.retransmission_number = retransmission_number
        self.max_transport_latency = max_transport_latency
        self.presentation_delay = presentation_delay

        self.state = self.State.QOS_CONFIGURED

        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_enable(self, metadata: bytes) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state != AseStateMachine.State.QOS_CONFIGURED:
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )

        self.metadata = le_audio.Metadata.from_bytes(metadata)
        self.state = self.State.ENABLING

        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_receiver_start_ready(self) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state != AseStateMachine.State.ENABLING:
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.state = self.State.STREAMING
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_disable(self) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state not in (
            AseStateMachine.State.ENABLING,
            AseStateMachine.State.STREAMING,
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        if self.role == AudioRole.SINK:
            self.state = self.State.QOS_CONFIGURED
        else:
            self.state = self.State.DISABLING
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_receiver_stop_ready(self) -> Tuple[AseResponseCode, AseReasonCode]:
        if (
            self.role != AudioRole.SOURCE
            or self.state != AseStateMachine.State.DISABLING
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.state = self.State.QOS_CONFIGURED
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_update_metadata(
        self, metadata: bytes
    ) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state not in (
            AseStateMachine.State.ENABLING,
            AseStateMachine.State.STREAMING,
        ):
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.metadata = le_audio.Metadata.from_bytes(metadata)
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    def on_release(self) -> Tuple[AseResponseCode, AseReasonCode]:
        if self.state == AseStateMachine.State.IDLE:
            return (
                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
                AseReasonCode.NONE,
            )
        self.state = self.State.RELEASING

        async def remove_cis_async():
            if self.cis_link:
                await self.cis_link.remove_data_path(self.role)
            self.state = self.State.IDLE
            await self.service.device.notify_subscribers(self, self.value)

        utils.cancel_on_event(self.service.device, 'flush', remove_cis_async())
        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)

    @property
    def state(self) -> State:
        return self._state

    @state.setter
    def state(self, new_state: State) -> None:
        logger.debug(f'{self} state change -> {colors.color(new_state.name, "cyan")}')
        self._state = new_state
        self.emit('state_change')

    @property
    def value(self):
        '''Returns ASE_ID, ASE_STATE, and ASE Additional Parameters.'''

        if self.state == self.State.CODEC_CONFIGURED:
            codec_specific_configuration_bytes = bytes(
                self.codec_specific_configuration
            )
            additional_parameters = (
                struct.pack(
                    '<BBBH',
                    self.preferred_framing,
                    self.preferred_phy,
                    self.preferred_retransmission_number,
                    self.preferred_max_transport_latency,
                )
                + self.supported_presentation_delay_min.to_bytes(3, 'little')
                + self.supported_presentation_delay_max.to_bytes(3, 'little')
                + self.preferred_presentation_delay_min.to_bytes(3, 'little')
                + self.preferred_presentation_delay_max.to_bytes(3, 'little')
                + bytes(self.codec_id)
                + bytes([len(codec_specific_configuration_bytes)])
                + codec_specific_configuration_bytes
            )
        elif self.state == self.State.QOS_CONFIGURED:
            additional_parameters = (
                bytes([self.cig_id, self.cis_id])
                + self.sdu_interval.to_bytes(3, 'little')
                + struct.pack(
                    '<BBHBH',
                    self.framing,
                    self.phy,
                    self.max_sdu,
                    self.retransmission_number,
                    self.max_transport_latency,
                )
                + self.presentation_delay.to_bytes(3, 'little')
            )
        elif self.state in (
            self.State.ENABLING,
            self.State.STREAMING,
            self.State.DISABLING,
        ):
            metadata_bytes = bytes(self.metadata)
            additional_parameters = (
                bytes([self.cig_id, self.cis_id, len(metadata_bytes)]) + metadata_bytes
            )
        else:
            additional_parameters = b''

        return bytes([self.ase_id, self.state]) + additional_parameters

    @value.setter
    def value(self, _new_value):
        # Readonly. Do nothing in the setter.
        pass

    def on_read(self, _: Optional[device.Connection]) -> bytes:
        return self.value

    def __str__(self) -> str:
        return (
            f'AseStateMachine(id={self.ase_id}, role={self.role.name} '
            f'state={self._state.name})'
        )


# -----------------------------------------------------------------------------
class AudioStreamControlService(gatt.TemplateService):
    UUID = gatt.GATT_AUDIO_STREAM_CONTROL_SERVICE

    ase_state_machines: Dict[int, AseStateMachine]
    ase_control_point: gatt.Characteristic[bytes]
    _active_client: Optional[device.Connection] = None

    def __init__(
        self,
        device: device.Device,
        source_ase_id: Sequence[int] = (),
        sink_ase_id: Sequence[int] = (),
    ) -> None:
        self.device = device
        self.ase_state_machines = {
            **{
                id: AseStateMachine(role=AudioRole.SINK, ase_id=id, service=self)
                for id in sink_ase_id
            },
            **{
                id: AseStateMachine(role=AudioRole.SOURCE, ase_id=id, service=self)
                for id in source_ase_id
            },
        }  # ASE state machines, by ASE ID

        self.ase_control_point = gatt.Characteristic(
            uuid=gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.WRITEABLE,
            value=gatt.CharacteristicValue(write=self.on_write_ase_control_point),
        )

        super().__init__([self.ase_control_point, *self.ase_state_machines.values()])

    def on_operation(self, opcode: ASE_Operation.Opcode, ase_id: int, args):
        if ase := self.ase_state_machines.get(ase_id):
            handler = getattr(ase, 'on_' + opcode.name.lower())
            return (ase_id, *handler(*args))
        else:
            return (ase_id, AseResponseCode.INVALID_ASE_ID, AseReasonCode.NONE)

    def _on_client_disconnected(self, _reason: int) -> None:
        for ase in self.ase_state_machines.values():
            ase.state = AseStateMachine.State.IDLE
        self._active_client = None

    def on_write_ase_control_point(self, connection, data):
        if not self._active_client and connection:
            self._active_client = connection
            connection.once('disconnection', self._on_client_disconnected)

        operation = ASE_Operation.from_bytes(data)
        responses = []
        logger.debug(f'*** ASCS Write {operation} ***')

        if operation.op_code == ASE_Operation.Opcode.CONFIG_CODEC:
            for ase_id, *args in zip(
                operation.ase_id,
                operation.target_latency,
                operation.target_phy,
                operation.codec_id,
                operation.codec_specific_configuration,
            ):
                responses.append(self.on_operation(operation.op_code, ase_id, args))
        elif operation.op_code == ASE_Operation.Opcode.CONFIG_QOS:
            for ase_id, *args in zip(
                operation.ase_id,
                operation.cig_id,
                operation.cis_id,
                operation.sdu_interval,
                operation.framing,
                operation.phy,
                operation.max_sdu,
                operation.retransmission_number,
                operation.max_transport_latency,
                operation.presentation_delay,
            ):
                responses.append(self.on_operation(operation.op_code, ase_id, args))
        elif operation.op_code in (
            ASE_Operation.Opcode.ENABLE,
            ASE_Operation.Opcode.UPDATE_METADATA,
        ):
            for ase_id, *args in zip(
                operation.ase_id,
                operation.metadata,
            ):
                responses.append(self.on_operation(operation.op_code, ase_id, args))
        elif operation.op_code in (
            ASE_Operation.Opcode.RECEIVER_START_READY,
            ASE_Operation.Opcode.DISABLE,
            ASE_Operation.Opcode.RECEIVER_STOP_READY,
            ASE_Operation.Opcode.RELEASE,
        ):
            for ase_id in operation.ase_id:
                responses.append(self.on_operation(operation.op_code, ase_id, []))

        control_point_notification = bytes(
            [operation.op_code, len(responses)]
        ) + b''.join(map(bytes, responses))
        utils.cancel_on_event(
            self.device,
            'flush',
            self.device.notify_subscribers(
                self.ase_control_point, control_point_notification
            ),
        )

        for ase_id, *_ in responses:
            if ase := self.ase_state_machines.get(ase_id):
                utils.cancel_on_event(
                    self.device,
                    'flush',
                    self.device.notify_subscribers(ase, ase.value),
                )


# -----------------------------------------------------------------------------
class AudioStreamControlServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = AudioStreamControlService

    sink_ase: List[gatt_client.CharacteristicProxy[bytes]]
    source_ase: List[gatt_client.CharacteristicProxy[bytes]]
    ase_control_point: gatt_client.CharacteristicProxy[bytes]

    def __init__(self, service_proxy: gatt_client.ServiceProxy):
        self.service_proxy = service_proxy

        self.sink_ase = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SINK_ASE_CHARACTERISTIC
        )
        self.source_ase = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SOURCE_ASE_CHARACTERISTIC
        )
        self.ase_control_point = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC
        )[0]
