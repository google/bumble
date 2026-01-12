# Copyright 2021-2022 Google LLC
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
# ATT - Attribute Protocol
#
# See Bluetooth spec @ Vol 3, Part F
#
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import dataclasses
import enum
import functools
import inspect
import struct
from collections.abc import Awaitable, Callable, Sequence
from typing import (
    TYPE_CHECKING,
    ClassVar,
    Generic,
    TypeAlias,
    TypeVar,
)

from typing_extensions import TypeIs

from bumble import hci, l2cap, utils
from bumble.colors import color
from bumble.core import UUID, InvalidOperationError, ProtocolError
from bumble.hci import HCI_Object

# -----------------------------------------------------------------------------
# Typing
# -----------------------------------------------------------------------------
if TYPE_CHECKING:
    from bumble.device import Connection

_T = TypeVar('_T')

Bearer: TypeAlias = "Connection | l2cap.LeCreditBasedChannel"
EnhancedBearer: TypeAlias = l2cap.LeCreditBasedChannel


def is_enhanced_bearer(bearer: Bearer) -> TypeIs[EnhancedBearer]:
    return isinstance(bearer, EnhancedBearer)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

ATT_CID = 0x04
ATT_PSM = 0x001F
EATT_PSM = 0x0027

class Opcode(hci.SpecableEnum):
    ATT_ERROR_RESPONSE                  = 0x01
    ATT_EXCHANGE_MTU_REQUEST            = 0x02
    ATT_EXCHANGE_MTU_RESPONSE           = 0x03
    ATT_FIND_INFORMATION_REQUEST        = 0x04
    ATT_FIND_INFORMATION_RESPONSE       = 0x05
    ATT_FIND_BY_TYPE_VALUE_REQUEST      = 0x06
    ATT_FIND_BY_TYPE_VALUE_RESPONSE     = 0x07
    ATT_READ_BY_TYPE_REQUEST            = 0x08
    ATT_READ_BY_TYPE_RESPONSE           = 0x09
    ATT_READ_REQUEST                    = 0x0A
    ATT_READ_RESPONSE                   = 0x0B
    ATT_READ_BLOB_REQUEST               = 0x0C
    ATT_READ_BLOB_RESPONSE              = 0x0D
    ATT_READ_MULTIPLE_REQUEST           = 0x0E
    ATT_READ_MULTIPLE_RESPONSE          = 0x0F
    ATT_READ_BY_GROUP_TYPE_REQUEST      = 0x10
    ATT_READ_BY_GROUP_TYPE_RESPONSE     = 0x11
    ATT_READ_MULTIPLE_VARIABLE_REQUEST  = 0x20
    ATT_READ_MULTIPLE_VARIABLE_RESPONSE = 0x21
    ATT_WRITE_REQUEST                   = 0x12
    ATT_WRITE_RESPONSE                  = 0x13
    ATT_WRITE_COMMAND                   = 0x52
    ATT_SIGNED_WRITE_COMMAND            = 0xD2
    ATT_PREPARE_WRITE_REQUEST           = 0x16
    ATT_PREPARE_WRITE_RESPONSE          = 0x17
    ATT_EXECUTE_WRITE_REQUEST           = 0x18
    ATT_EXECUTE_WRITE_RESPONSE          = 0x19
    ATT_HANDLE_VALUE_NOTIFICATION       = 0x1B
    ATT_HANDLE_VALUE_INDICATION         = 0x1D
    ATT_HANDLE_VALUE_CONFIRMATION       = 0x1E

ATT_REQUESTS = [
    Opcode.ATT_EXCHANGE_MTU_REQUEST,
    Opcode.ATT_FIND_INFORMATION_REQUEST,
    Opcode.ATT_FIND_BY_TYPE_VALUE_REQUEST,
    Opcode.ATT_READ_BY_TYPE_REQUEST,
    Opcode.ATT_READ_REQUEST,
    Opcode.ATT_READ_BLOB_REQUEST,
    Opcode.ATT_READ_MULTIPLE_REQUEST,
    Opcode.ATT_READ_BY_GROUP_TYPE_REQUEST,
    Opcode.ATT_READ_MULTIPLE_VARIABLE_REQUEST,
    Opcode.ATT_WRITE_REQUEST,
    Opcode.ATT_PREPARE_WRITE_REQUEST,
    Opcode.ATT_EXECUTE_WRITE_REQUEST,
]

ATT_RESPONSES = [
    Opcode.ATT_ERROR_RESPONSE,
    Opcode.ATT_EXCHANGE_MTU_RESPONSE,
    Opcode.ATT_FIND_INFORMATION_RESPONSE,
    Opcode.ATT_FIND_BY_TYPE_VALUE_RESPONSE,
    Opcode.ATT_READ_BY_TYPE_RESPONSE,
    Opcode.ATT_READ_RESPONSE,
    Opcode.ATT_READ_BLOB_RESPONSE,
    Opcode.ATT_READ_MULTIPLE_RESPONSE,
    Opcode.ATT_READ_BY_GROUP_TYPE_RESPONSE,
    Opcode.ATT_READ_MULTIPLE_VARIABLE_RESPONSE,
    Opcode.ATT_WRITE_RESPONSE,
    Opcode.ATT_PREPARE_WRITE_RESPONSE,
    Opcode.ATT_EXECUTE_WRITE_RESPONSE,
]

class ErrorCode(hci.SpecableEnum):
    '''
    See

    * Bluetooth spec @ Vol 3, Part F - 3.4.1.1 Error Response
    * Core Specification Supplement: Common Profile And Service Error Codes
    '''
    INVALID_HANDLE                   = 0x01
    READ_NOT_PERMITTED               = 0x02
    WRITE_NOT_PERMITTED              = 0x03
    INVALID_PDU                      = 0x04
    INSUFFICIENT_AUTHENTICATION      = 0x05
    REQUEST_NOT_SUPPORTED            = 0x06
    INVALID_OFFSET                   = 0x07
    INSUFFICIENT_AUTHORIZATION       = 0x08
    PREPARE_QUEUE_FULL               = 0x09
    ATTRIBUTE_NOT_FOUND              = 0x0A
    ATTRIBUTE_NOT_LONG               = 0x0B
    INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0x0C
    INVALID_ATTRIBUTE_LENGTH         = 0x0D
    UNLIKELY_ERROR                   = 0x0E
    INSUFFICIENT_ENCRYPTION          = 0x0F
    UNSUPPORTED_GROUP_TYPE           = 0x10
    INSUFFICIENT_RESOURCES           = 0x11
    DATABASE_OUT_OF_SYNC             = 0x12
    VALUE_NOT_ALLOWED                = 0x13
    # 0x80 – 0x9F: Application Error
    # 0xE0 – 0xFF: Common Profile and Service Error Codes
    WRITE_REQUEST_REJECTED           = 0xFC
    CCCD_IMPROPERLY_CONFIGURED       = 0xFD
    PROCEDURE_ALREADY_IN_PROGRESS    = 0xFE
    OUT_OF_RANGE                     = 0xFF

# Backward Compatible Constants
ATT_INVALID_HANDLE_ERROR                   = ErrorCode.INVALID_HANDLE
ATT_READ_NOT_PERMITTED_ERROR               = ErrorCode.READ_NOT_PERMITTED
ATT_WRITE_NOT_PERMITTED_ERROR              = ErrorCode.WRITE_NOT_PERMITTED
ATT_INVALID_PDU_ERROR                      = ErrorCode.INVALID_PDU
ATT_INSUFFICIENT_AUTHENTICATION_ERROR      = ErrorCode.INSUFFICIENT_AUTHENTICATION
ATT_REQUEST_NOT_SUPPORTED_ERROR            = ErrorCode.REQUEST_NOT_SUPPORTED
ATT_INVALID_OFFSET_ERROR                   = ErrorCode.INVALID_OFFSET
ATT_INSUFFICIENT_AUTHORIZATION_ERROR       = ErrorCode.INSUFFICIENT_AUTHORIZATION
ATT_PREPARE_QUEUE_FULL_ERROR               = ErrorCode.PREPARE_QUEUE_FULL
ATT_ATTRIBUTE_NOT_FOUND_ERROR              = ErrorCode.ATTRIBUTE_NOT_FOUND
ATT_ATTRIBUTE_NOT_LONG_ERROR               = ErrorCode.ATTRIBUTE_NOT_LONG
ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE_ERROR = ErrorCode.INSUFFICIENT_ENCRYPTION_KEY_SIZE
ATT_INVALID_ATTRIBUTE_LENGTH_ERROR         = ErrorCode.INVALID_ATTRIBUTE_LENGTH
ATT_UNLIKELY_ERROR_ERROR                   = ErrorCode.UNLIKELY_ERROR
ATT_INSUFFICIENT_ENCRYPTION_ERROR          = ErrorCode.INSUFFICIENT_ENCRYPTION
ATT_UNSUPPORTED_GROUP_TYPE_ERROR           = ErrorCode.UNSUPPORTED_GROUP_TYPE
ATT_INSUFFICIENT_RESOURCES_ERROR           = ErrorCode.INSUFFICIENT_RESOURCES

ATT_DEFAULT_MTU = 23

HANDLE_FIELD_SPEC    = {'size': 2, 'mapper': lambda x: f'0x{x:04X}'}
_SET_OF_HANDLES_METADATA = hci.metadata({
                'parser': lambda data, offset: (
                    len(data),
                    [
                        struct.unpack_from('<H', data, i)[0]
                        for i in range(offset, len(data), 2)
                    ],
                ),
                'serializer': lambda handles: b''.join(
                    [struct.pack('<H', handle) for handle in handles]
                ),
            })

# fmt: on
# pylint: enable=line-too-long
# pylint: disable=invalid-name


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------
class ATT_Error(ProtocolError):
    error_code: int
    att_handle: int

    def __init__(
        self, error_code: int, att_handle: int = 0x0000, message: str = ''
    ) -> None:
        super().__init__(
            error_code,
            error_namespace='att',
            error_name=ErrorCode(error_code).name,
        )
        self.att_handle = att_handle
        self.message = message

    def __str__(self):
        return (
            f'ATT_Error(error={self.error_name}, '
            f'handle={self.att_handle:04X}): {self.message}'
        )


# -----------------------------------------------------------------------------
# Attribute Protocol
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class ATT_PDU:
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.3 ATTRIBUTE PDU
    '''

    pdu_classes: ClassVar[dict[int, type[ATT_PDU]]] = {}
    fields: ClassVar[hci.Fields] = ()
    op_code: int = dataclasses.field(init=False)
    name: str = dataclasses.field(init=False)
    _payload: bytes | None = dataclasses.field(default=None, init=False)

    @classmethod
    def from_bytes(cls, pdu: bytes) -> ATT_PDU:
        op_code = pdu[0]

        subclass = ATT_PDU.pdu_classes.get(op_code)
        if subclass is None:
            instance = ATT_PDU()
            instance.op_code = op_code
            instance.payload = pdu[1:]
            instance.name = Opcode(op_code).name
            return instance
        instance = subclass(**HCI_Object.dict_from_bytes(pdu, 1, subclass.fields))
        instance.payload = pdu[1:]
        return instance

    _PDU = TypeVar("_PDU", bound="ATT_PDU")

    @classmethod
    def subclass(cls, subclass: type[_PDU]) -> type[_PDU]:
        subclass.name = subclass.__name__.upper()
        subclass.op_code = Opcode[subclass.name]
        subclass.fields = HCI_Object.fields_from_dataclass(subclass)

        # Register a factory for this class
        ATT_PDU.pdu_classes[subclass.op_code] = subclass

        return subclass

    def init_from_bytes(self, pdu, offset):
        return HCI_Object.init_from_bytes(self, pdu, offset, self.fields)

    @property
    def is_command(self):
        return ((self.op_code >> 6) & 1) == 1

    @property
    def has_authentication_signature(self):
        return ((self.op_code >> 7) & 1) == 1

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            self._payload = HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return self._payload

    @payload.setter
    def payload(self, value: bytes):
        self._payload = value

    def __bytes__(self) -> bytes:
        return bytes([self.op_code]) + self.payload

    def __str__(self):
        result = color(self.name, 'yellow')
        if fields := getattr(self, 'fields', None):
            result += ':\n' + HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if self.payload:
                result += f': {self.payload.hex()}'
        return result


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Error_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.1.1 Error Response
    '''

    request_opcode_in_error: int = dataclasses.field(metadata=Opcode.type_metadata(1))
    attribute_handle_in_error: int = dataclasses.field(
        metadata=hci.metadata(HANDLE_FIELD_SPEC)
    )
    error_code: int = dataclasses.field(metadata=ErrorCode.type_metadata(1))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Exchange_MTU_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.2.1 Exchange MTU Request
    '''

    client_rx_mtu: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Exchange_MTU_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.2.2 Exchange MTU Response
    '''

    server_rx_mtu: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Find_Information_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.3.1 Find Information Request
    '''

    starting_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    ending_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Find_Information_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.3.2 Find Information Response
    '''

    format: int = dataclasses.field(metadata=hci.metadata(1))
    information_data: bytes = dataclasses.field(metadata=hci.metadata("*"))
    information: list[tuple[int, bytes]] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.information = []
        offset = 0
        uuid_size = 2 if self.format == 1 else 16
        while offset + uuid_size <= len(self.information_data):
            handle = struct.unpack_from('<H', self.information_data, offset)[0]
            uuid = self.information_data[2 + offset : 2 + offset + uuid_size]
            self.information.append((handle, uuid))
            offset += 2 + uuid_size

    def __str__(self):
        result = color(self.name, 'yellow')
        result += ':\n' + HCI_Object.format_fields(
            self.__dict__,
            [
                ('format', 1),
                (
                    'information',
                    {
                        'mapper': lambda x: ', '.join(
                            [f'0x{handle:04X}:{uuid.hex()}' for handle, uuid in x]
                        )
                    },
                ),
            ],
            '  ',
        )
        return result


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Find_By_Type_Value_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.3.3 Find By Type Value Request
    '''

    starting_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    ending_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    attribute_type: UUID = dataclasses.field(metadata=hci.metadata(UUID.parse_uuid_2))
    attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Find_By_Type_Value_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.3.4 Find By Type Value Response
    '''

    handles_information_list: bytes = dataclasses.field(metadata=hci.metadata("*"))
    handles_information: list[tuple[int, int]] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.handles_information = []
        offset = 0
        while offset + 4 <= len(self.handles_information_list):
            found_attribute_handle, group_end_handle = struct.unpack_from(
                '<HH', self.handles_information_list, offset
            )
            self.handles_information.append((found_attribute_handle, group_end_handle))
            offset += 4

    def __str__(self):
        result = color(self.name, 'yellow')
        result += ':\n' + HCI_Object.format_fields(
            self.__dict__,
            [
                (
                    'handles_information',
                    {
                        'mapper': lambda x: ', '.join(
                            [
                                f'0x{handle1:04X}-0x{handle2:04X}'
                                for handle1, handle2 in x
                            ]
                        )
                    },
                )
            ],
            '  ',
        )
        return result


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_By_Type_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.1 Read By Type Request
    '''

    starting_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    ending_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    attribute_type: UUID = dataclasses.field(metadata=hci.metadata(UUID.parse_uuid))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_By_Type_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.2 Read By Type Response
    '''

    length: int = dataclasses.field(metadata=hci.metadata(1))
    attribute_data_list: bytes = dataclasses.field(metadata=hci.metadata("*"))
    attributes: list[tuple[int, bytes]] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.attributes = []
        offset = 0
        while self.length != 0 and offset + self.length <= len(
            self.attribute_data_list
        ):
            (attribute_handle,) = struct.unpack_from(
                '<H', self.attribute_data_list, offset
            )
            attribute_value = self.attribute_data_list[
                offset + 2 : offset + self.length
            ]
            self.attributes.append((attribute_handle, attribute_value))
            offset += self.length

    def __str__(self):
        result = color(self.name, 'yellow')
        result += ':\n' + HCI_Object.format_fields(
            self.__dict__,
            [
                ('length', 1),
                (
                    'attributes',
                    {
                        'mapper': lambda x: ', '.join(
                            [f'0x{handle:04X}:{value.hex()}' for handle, value in x]
                        )
                    },
                ),
            ],
            '  ',
        )
        return result


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.3 Read Request
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.4 Read Response
    '''

    attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_Blob_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.5 Read Blob Request
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    value_offset: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_Blob_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.6 Read Blob Response
    '''

    part_attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_Multiple_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.7 Read Multiple Request
    '''

    set_of_handles: Sequence[int] = dataclasses.field(metadata=_SET_OF_HANDLES_METADATA)


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_Multiple_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.8 Read Multiple Response
    '''

    set_of_values: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_By_Group_Type_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.9 Read by Group Type Request
    '''

    starting_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    ending_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    attribute_group_type: UUID = dataclasses.field(
        metadata=hci.metadata(UUID.parse_uuid)
    )


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_By_Group_Type_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.10 Read by Group Type Response
    '''

    length: int = dataclasses.field(metadata=hci.metadata(1))
    attribute_data_list: bytes = dataclasses.field(metadata=hci.metadata("*"))
    attributes: list[tuple[int, int, bytes]] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.attributes = []
        offset = 0
        while self.length != 0 and offset + self.length <= len(
            self.attribute_data_list
        ):
            attribute_handle, end_group_handle = struct.unpack_from(
                '<HH', self.attribute_data_list, offset
            )
            attribute_value = self.attribute_data_list[
                offset + 4 : offset + self.length
            ]
            self.attributes.append(
                (attribute_handle, end_group_handle, attribute_value)
            )
            offset += self.length

    def __str__(self):
        result = color(self.name, 'yellow')
        result += ':\n' + HCI_Object.format_fields(
            self.__dict__,
            [
                ('length', 1),
                (
                    'attributes',
                    {
                        'mapper': lambda x: ', '.join(
                            [
                                f'0x{handle:04X}-0x{end:04X}:{value.hex()}'
                                for handle, end, value in x
                            ]
                        )
                    },
                ),
            ],
            '  ',
        )
        return result


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_Multiple_Variable_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.11 Read Multiple Variable Request
    '''

    set_of_handles: Sequence[int] = dataclasses.field(metadata=_SET_OF_HANDLES_METADATA)


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Read_Multiple_Variable_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.12 Read Multiple Variable Response
    '''

    @classmethod
    def _parse_length_value_tuples(
        cls, data: bytes, offset: int
    ) -> tuple[int, list[tuple[int, bytes]]]:
        length_value_tuple_list: list[tuple[int, bytes]] = []
        while offset < len(data):
            length = struct.unpack_from('<H', data, offset)[0]
            length_value_tuple_list.append(
                (length, data[offset + 2 : offset + 2 + length])
            )
            offset += 2 + length
        return (len(data), length_value_tuple_list)

    length_value_tuple_list: Sequence[tuple[int, bytes]] = dataclasses.field(
        metadata=hci.metadata(
            {
                'parser': lambda data, offset: ATT_Read_Multiple_Variable_Response._parse_length_value_tuples(
                    data, offset
                ),
                'serializer': lambda length_value_tuple_list: b''.join(
                    [
                        struct.pack('<H', length) + value
                        for length, value in length_value_tuple_list
                    ]
                ),
            }
        )
    )


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Write_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.5.1 Write Request
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Write_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.5.2 Write Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Write_Command(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.5.3 Write Command
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Signed_Write_Command(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.5.4 Signed Write Command
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))
    # TODO: authentication_signature


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Prepare_Write_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.6.1 Prepare Write Request
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    value_offset: int = dataclasses.field(metadata=hci.metadata(2))
    part_attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Prepare_Write_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.6.2 Prepare Write Response
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    value_offset: int = dataclasses.field(metadata=hci.metadata(2))
    part_attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Execute_Write_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.6.3 Execute Write Request
    '''

    flags: int = dataclasses.field(metadata=hci.metadata(1))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Execute_Write_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.6.4 Execute Write Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Handle_Value_Notification(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.7.1 Handle Value Notification
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Handle_Value_Indication(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.7.2 Handle Value Indication
    '''

    attribute_handle: int = dataclasses.field(metadata=hci.metadata(HANDLE_FIELD_SPEC))
    attribute_value: bytes = dataclasses.field(metadata=hci.metadata("*"))


# -----------------------------------------------------------------------------
@ATT_PDU.subclass
@dataclasses.dataclass
class ATT_Handle_Value_Confirmation(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.7.3 Handle Value Confirmation
    '''


# -----------------------------------------------------------------------------
class AttributeValue(Generic[_T]):
    '''
    Attribute value where reading and/or writing is delegated to functions
    passed as arguments to the constructor.
    '''

    def __init__(
        self,
        read: (
            Callable[[Connection], _T] | Callable[[Connection], Awaitable[_T]] | None
        ) = None,
        write: (
            Callable[[Connection, _T], None]
            | Callable[[Connection, _T], Awaitable[None]]
            | None
        ) = None,
    ):
        self._read = read
        self._write = write

    def read(self, connection: Connection) -> _T | Awaitable[_T]:
        if self._read is None:
            raise InvalidOperationError('AttributeValue has no read function')
        return self._read(connection)

    def write(self, connection: Connection, value: _T) -> Awaitable[None] | None:
        if self._write is None:
            raise InvalidOperationError('AttributeValue has no write function')
        return self._write(connection, value)


# -----------------------------------------------------------------------------
class AttributeValueV2(Generic[_T]):
    '''
    Attribute value compatible with enhanced bearers.

    The only difference between AttributeValue and AttributeValueV2 is that the actual
    bearer (ACL connection for un-enhanced bearer, L2CAP channel for enhanced bearer)
    will be passed into read and write callbacks in V2, while in V1 it is always
    the base ACL connection.

    This is only required when attributes must distinguish bearers, otherwise normal
    `AttributeValue` objects are also applicable in enhanced bearers.
    '''

    def __init__(
        self,
        read: Callable[[Bearer], Awaitable[_T]] | Callable[[Bearer], _T] | None = None,
        write: (
            Callable[[Bearer, _T], Awaitable[None]]
            | Callable[[Bearer, _T], None]
            | None
        ) = None,
    ):
        self._read = read
        self._write = write

    def read(self, bearer: Bearer) -> _T | Awaitable[_T]:
        if self._read is None:
            raise InvalidOperationError('AttributeValue has no read function')
        return self._read(bearer)

    def write(self, bearer: Bearer, value: _T) -> Awaitable[None] | None:
        if self._write is None:
            raise InvalidOperationError('AttributeValue has no write function')
        return self._write(bearer, value)


# -----------------------------------------------------------------------------
class Attribute(utils.EventEmitter, Generic[_T]):
    class Permissions(enum.IntFlag):
        READABLE = 0x01
        WRITEABLE = 0x02
        READ_REQUIRES_ENCRYPTION = 0x04
        WRITE_REQUIRES_ENCRYPTION = 0x08
        READ_REQUIRES_AUTHENTICATION = 0x10
        WRITE_REQUIRES_AUTHENTICATION = 0x20
        READ_REQUIRES_AUTHORIZATION = 0x40
        WRITE_REQUIRES_AUTHORIZATION = 0x80

        @classmethod
        def from_string(cls, permissions_str: str) -> Attribute.Permissions:
            try:
                return functools.reduce(
                    lambda x, y: x | Attribute.Permissions[y],
                    permissions_str.replace('|', ',').split(","),
                    Attribute.Permissions(0),
                )
            except TypeError as exc:
                # The check for `p.name is not None` here is needed because for InFlag
                # enums, the .name property can be None, when the enum value is 0,
                # so the type hint for .name is Optional[str].
                enum_list: list[str] = [p.name for p in cls if p.name is not None]
                enum_list_str = ",".join(enum_list)
                raise TypeError(
                    f"Attribute::permissions error:\nExpected a string containing any of the keys, separated by commas: {enum_list_str}\nGot: {permissions_str}"
                ) from exc

    # Permission flags(legacy-use only)
    READABLE = Permissions.READABLE
    WRITEABLE = Permissions.WRITEABLE
    READ_REQUIRES_ENCRYPTION = Permissions.READ_REQUIRES_ENCRYPTION
    WRITE_REQUIRES_ENCRYPTION = Permissions.WRITE_REQUIRES_ENCRYPTION
    READ_REQUIRES_AUTHENTICATION = Permissions.READ_REQUIRES_AUTHENTICATION
    WRITE_REQUIRES_AUTHENTICATION = Permissions.WRITE_REQUIRES_AUTHENTICATION
    READ_REQUIRES_AUTHORIZATION = Permissions.READ_REQUIRES_AUTHORIZATION
    WRITE_REQUIRES_AUTHORIZATION = Permissions.WRITE_REQUIRES_AUTHORIZATION

    EVENT_READ = "read"
    EVENT_WRITE = "write"

    value: AttributeValue[_T] | _T | None

    def __init__(
        self,
        attribute_type: str | bytes | UUID,
        permissions: str | Attribute.Permissions,
        value: AttributeValue[_T] | _T | None = None,
    ) -> None:
        utils.EventEmitter.__init__(self)
        self.handle = 0
        self.end_group_handle = 0
        if isinstance(permissions, str):
            self.permissions = Attribute.Permissions.from_string(permissions)
        else:
            self.permissions = permissions

        # Convert the type to a UUID object if it isn't already
        if isinstance(attribute_type, str):
            self.type = UUID(attribute_type)
        elif isinstance(attribute_type, bytes):
            self.type = UUID.from_bytes(attribute_type)
        else:
            self.type = attribute_type

        self.value = value

    def encode_value(self, value: _T) -> bytes:
        return value  # type: ignore

    def decode_value(self, value: bytes) -> _T:
        return value  # type: ignore

    async def read_value(self, bearer: Bearer) -> bytes:
        connection = bearer.connection if is_enhanced_bearer(bearer) else bearer
        if (
            (self.permissions & self.READ_REQUIRES_ENCRYPTION)
            and connection is not None
            and not connection.encryption
        ):
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_ENCRYPTION_ERROR, att_handle=self.handle
            )
        if (
            (self.permissions & self.READ_REQUIRES_AUTHENTICATION)
            and connection is not None
            and not connection.authenticated
        ):
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_AUTHENTICATION_ERROR, att_handle=self.handle
            )
        if self.permissions & self.READ_REQUIRES_AUTHORIZATION:
            # TODO: handle authorization better
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_AUTHORIZATION_ERROR, att_handle=self.handle
            )

        value: _T | None
        if isinstance(self.value, AttributeValue):
            try:
                read_value = self.value.read(connection)
                if inspect.isawaitable(read_value):
                    value = await read_value
                else:
                    value = read_value
            except ATT_Error as error:
                raise ATT_Error(
                    error_code=error.error_code, att_handle=self.handle
                ) from error
        elif isinstance(self.value, AttributeValueV2):
            try:
                read_value = self.value.read(bearer)
                if inspect.isawaitable(read_value):
                    value = await read_value
                else:
                    value = read_value
            except ATT_Error as error:
                raise ATT_Error(
                    error_code=error.error_code, att_handle=self.handle
                ) from error
        else:
            value = self.value

        self.emit(self.EVENT_READ, connection, b'' if value is None else value)

        return b'' if value is None else self.encode_value(value)

    async def write_value(self, bearer: Bearer, value: bytes) -> None:
        connection = bearer.connection if is_enhanced_bearer(bearer) else bearer
        if (
            (self.permissions & self.WRITE_REQUIRES_ENCRYPTION)
            and connection is not None
            and not connection.encryption
        ):
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_ENCRYPTION_ERROR, att_handle=self.handle
            )
        if (
            (self.permissions & self.WRITE_REQUIRES_AUTHENTICATION)
            and connection is not None
            and not connection.authenticated
        ):
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_AUTHENTICATION_ERROR, att_handle=self.handle
            )
        if self.permissions & self.WRITE_REQUIRES_AUTHORIZATION:
            # TODO: handle authorization better
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_AUTHORIZATION_ERROR, att_handle=self.handle
            )

        decoded_value = self.decode_value(value)

        if isinstance(self.value, AttributeValue):
            try:
                result = self.value.write(connection, decoded_value)
                if inspect.isawaitable(result):
                    await result
            except ATT_Error as error:
                raise ATT_Error(
                    error_code=error.error_code, att_handle=self.handle
                ) from error
        elif isinstance(self.value, AttributeValueV2):
            try:
                result = self.value.write(bearer, decoded_value)
                if inspect.isawaitable(result):
                    await result
            except ATT_Error as error:
                raise ATT_Error(
                    error_code=error.error_code, att_handle=self.handle
                ) from error
        else:
            self.value = decoded_value

        self.emit(self.EVENT_WRITE, connection, decoded_value)

    def __repr__(self):
        if isinstance(self.value, bytes):
            value_str = self.value.hex()
        else:
            value_str = str(self.value)
        if value_str:
            value_string = f', value={self.value.hex()}'
        else:
            value_string = ''
        return (
            f'Attribute(handle=0x{self.handle:04X}, '
            f'type={self.type}, '
            f'permissions={self.permissions}{value_string})'
        )
