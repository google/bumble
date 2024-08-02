# Copyright 2021-2024 Google LLC
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

from bumble import colors
from bumble import core
from bumble import hci
from bumble import utils

from collections.abc import Sequence
from typing import Dict, Type, Optional, Any
from typing_extensions import Self


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------
class BnepError(core.ProtocolError):
    def __init__(self, error_code: int):
        super().__init__(error_code=error_code, error_namespace='BNEP')


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------


BNEP_PSM = 0x000F


class PacketType(utils.OpenIntEnum):
    # fmt: off
    BNEP_GENERAL_ETHERNET =0x00
    BNEP_CONTROL =0x01
    BNEP_COMPRESSED_ETHERNET =0x02
    BNEP_COMPRESSED_ETHERNET_SOURCE_ONLY =0x03
    BNEP_COMPRESSED_ETHERNET_DEST_ONLY =0x04


class ControlType(utils.OpenIntEnum):
    BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD = 0x00
    BNEP_SETUP_CONNECTION_REQUEST_MSG = 0x01
    BNEP_SETUP_CONNECTION_RESPONSE_MSG = 0x02
    BNEP_FILTER_NET_TYPE_SET_MSG = 0x03
    BNEP_FILTER_NET_TYPE_RESPONSE_MSG = 0x04
    BNEP_FILTER_MULTI_ADDR_SET_MSG = 0x05
    BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG = 0x06


class SetupConnectionResponseCode(utils.OpenIntEnum):
    OPERATION_SUCCESSFUL = 0x0000
    OPERATION_FAILED_INVALID_DESTINATION_SERVICE_UUID = 0x0001
    OPERATION_FAILED_INVALID_SOURCE_SERVICE_UUID = 0x0002
    OPERATION_FAILED_INVALID_SERVICE_UUID_SIZE = 0x0003
    OPERATION_FAILED_CONNECTION_NOT_ALLOWED = 0x0004

    def __bytes__(self) -> bytes:
        return self.value.to_bytes(2, 'big')


# -----------------------------------------------------------------------------
# Packet Definitions
# -----------------------------------------------------------------------------


class BNEP_Packet:
    '''
    See Audio Stream Control Service - 5 ASE Control operations.
    '''

    classes: Dict[int, Type[Self]] = {}
    name: str
    fields: Optional[Sequence[Any]] = None

    packet_type: int
    extension_flag: int

    @classmethod
    def from_bytes(base_cls: Type[Self], pdu: bytes) -> BNEP_Packet:
        packet_type = pdu[0] & 0x7F
        extension_flag = pdu[0] >> 7

        cls = base_cls.classes.get(packet_type)
        if cls is None:
            instance = BNEP_Packet(pdu)
            instance.name = PacketType(packet_type).name
            instance.packet_type = packet_type
            instance.extension_flag = extension_flag
            return instance
        self = cls.__new__(cls)
        BNEP_Packet.__init__(self, pdu)
        if self.fields is not None:
            self.init_from_bytes(pdu, 1)
        return self

    @classmethod
    def subclass(base_cls: Type[Self], fields):
        def inner(cls):
            try:
                operation = PacketType[cls.__name__.upper()]
                cls.name = operation.name
                cls.packet_type = operation
            except:
                raise KeyError(f'PDU name {cls.name} not found in BNEP Packet Type')
            cls.fields = fields

            # Register a factory for this class
            base_cls.classes[cls.packet_type] = cls

            return cls

        return inner

    def __init__(self, pdu: Optional[bytes] = None, **kwargs) -> None:
        if self.fields is not None and kwargs:
            hci.HCI_Object.init_from_fields(self, self.fields, kwargs)
        if pdu is None:
            pdu = bytes([self.packet_type]) + hci.HCI_Object.dict_to_bytes(
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


@BNEP_Packet.subclass(
    [
        ('destination_address', hci.Address.parse_address),
        ('source_address', hci.Address.parse_address),
        ('networking_protocol_type', 2),
        ('payload', '*'),
    ]
)
class BNEP_General_Ethernet(BNEP_Packet):
    destination_address: hci.Address
    source_address: hci.Address
    networking_protocol_type: int
    payload: bytes


@BNEP_Packet.subclass(
    [
        ('control_type', 1),
        ('payload', '*'),
    ]
)
class BNEP_Control(BNEP_Packet):
    control_type: int
    payload: bytes


@BNEP_Packet.subclass(
    [
        ('networking_protocol_type', 2),
        ('payload', '*'),
    ]
)
class BNEP_Compressed_Ethernet(BNEP_Packet):
    networking_protocol_type: int
    payload: bytes


@BNEP_Packet.subclass(
    [
        ('networking_protocol_type', 2),
        ('source_address', hci.Address.parse_address),
        ('payload', '*'),
    ]
)
class BNEP_Compressed_Ethernet_Source_Only(BNEP_Packet):
    networking_protocol_type: int
    payload: bytes
    source_address: hci.Address


@BNEP_Packet.subclass(
    [
        ('networking_protocol_type', 2),
        ('destination_address', hci.Address.parse_address),
        ('payload', '*'),
    ]
)
class BNEP_Compressed_Ethernet_Dest_Only(BNEP_Packet):
    networking_protocol_type: int
    destination_address: hci.Address
    payload: bytes
