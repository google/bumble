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

import enum
import functools
import inspect
import struct
from typing import (
    Awaitable,
    Callable,
    Generic,
    Dict,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
    TYPE_CHECKING,
)


from bumble import utils
from bumble.core import UUID, name_or_number, InvalidOperationError, ProtocolError
from bumble.hci import HCI_Object, key_with_value
from bumble.colors import color

# -----------------------------------------------------------------------------
# Typing
# -----------------------------------------------------------------------------
if TYPE_CHECKING:
    from bumble.device import Connection

_T = TypeVar('_T')

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

ATT_CID = 0x04
ATT_PSM = 0x001F

ATT_ERROR_RESPONSE              = 0x01
ATT_EXCHANGE_MTU_REQUEST        = 0x02
ATT_EXCHANGE_MTU_RESPONSE       = 0x03
ATT_FIND_INFORMATION_REQUEST    = 0x04
ATT_FIND_INFORMATION_RESPONSE   = 0x05
ATT_FIND_BY_TYPE_VALUE_REQUEST  = 0x06
ATT_FIND_BY_TYPE_VALUE_RESPONSE = 0x07
ATT_READ_BY_TYPE_REQUEST        = 0x08
ATT_READ_BY_TYPE_RESPONSE       = 0x09
ATT_READ_REQUEST                = 0x0A
ATT_READ_RESPONSE               = 0x0B
ATT_READ_BLOB_REQUEST           = 0x0C
ATT_READ_BLOB_RESPONSE          = 0x0D
ATT_READ_MULTIPLE_REQUEST       = 0x0E
ATT_READ_MULTIPLE_RESPONSE      = 0x0F
ATT_READ_BY_GROUP_TYPE_REQUEST  = 0x10
ATT_READ_BY_GROUP_TYPE_RESPONSE = 0x11
ATT_WRITE_REQUEST               = 0x12
ATT_WRITE_RESPONSE              = 0x13
ATT_WRITE_COMMAND               = 0x52
ATT_SIGNED_WRITE_COMMAND        = 0xD2
ATT_PREPARE_WRITE_REQUEST       = 0x16
ATT_PREPARE_WRITE_RESPONSE      = 0x17
ATT_EXECUTE_WRITE_REQUEST       = 0x18
ATT_EXECUTE_WRITE_RESPONSE      = 0x19
ATT_HANDLE_VALUE_NOTIFICATION   = 0x1B
ATT_HANDLE_VALUE_INDICATION     = 0x1D
ATT_HANDLE_VALUE_CONFIRMATION   = 0x1E

ATT_PDU_NAMES = {
    ATT_ERROR_RESPONSE:              'ATT_ERROR_RESPONSE',
    ATT_EXCHANGE_MTU_REQUEST:        'ATT_EXCHANGE_MTU_REQUEST',
    ATT_EXCHANGE_MTU_RESPONSE:       'ATT_EXCHANGE_MTU_RESPONSE',
    ATT_FIND_INFORMATION_REQUEST:    'ATT_FIND_INFORMATION_REQUEST',
    ATT_FIND_INFORMATION_RESPONSE:   'ATT_FIND_INFORMATION_RESPONSE',
    ATT_FIND_BY_TYPE_VALUE_REQUEST:  'ATT_FIND_BY_TYPE_VALUE_REQUEST',
    ATT_FIND_BY_TYPE_VALUE_RESPONSE: 'ATT_FIND_BY_TYPE_VALUE_RESPONSE',
    ATT_READ_BY_TYPE_REQUEST:        'ATT_READ_BY_TYPE_REQUEST',
    ATT_READ_BY_TYPE_RESPONSE:       'ATT_READ_BY_TYPE_RESPONSE',
    ATT_READ_REQUEST:                'ATT_READ_REQUEST',
    ATT_READ_RESPONSE:               'ATT_READ_RESPONSE',
    ATT_READ_BLOB_REQUEST:           'ATT_READ_BLOB_REQUEST',
    ATT_READ_BLOB_RESPONSE:          'ATT_READ_BLOB_RESPONSE',
    ATT_READ_MULTIPLE_REQUEST:       'ATT_READ_MULTIPLE_REQUEST',
    ATT_READ_MULTIPLE_RESPONSE:      'ATT_READ_MULTIPLE_RESPONSE',
    ATT_READ_BY_GROUP_TYPE_REQUEST:  'ATT_READ_BY_GROUP_TYPE_REQUEST',
    ATT_READ_BY_GROUP_TYPE_RESPONSE: 'ATT_READ_BY_GROUP_TYPE_RESPONSE',
    ATT_WRITE_REQUEST:               'ATT_WRITE_REQUEST',
    ATT_WRITE_RESPONSE:              'ATT_WRITE_RESPONSE',
    ATT_WRITE_COMMAND:               'ATT_WRITE_COMMAND',
    ATT_SIGNED_WRITE_COMMAND:        'ATT_SIGNED_WRITE_COMMAND',
    ATT_PREPARE_WRITE_REQUEST:       'ATT_PREPARE_WRITE_REQUEST',
    ATT_PREPARE_WRITE_RESPONSE:      'ATT_PREPARE_WRITE_RESPONSE',
    ATT_EXECUTE_WRITE_REQUEST:       'ATT_EXECUTE_WRITE_REQUEST',
    ATT_EXECUTE_WRITE_RESPONSE:      'ATT_EXECUTE_WRITE_RESPONSE',
    ATT_HANDLE_VALUE_NOTIFICATION:   'ATT_HANDLE_VALUE_NOTIFICATION',
    ATT_HANDLE_VALUE_INDICATION:     'ATT_HANDLE_VALUE_INDICATION',
    ATT_HANDLE_VALUE_CONFIRMATION:   'ATT_HANDLE_VALUE_CONFIRMATION'
}

ATT_REQUESTS = [
    ATT_EXCHANGE_MTU_REQUEST,
    ATT_FIND_INFORMATION_REQUEST,
    ATT_FIND_BY_TYPE_VALUE_REQUEST,
    ATT_READ_BY_TYPE_REQUEST,
    ATT_READ_REQUEST,
    ATT_READ_BLOB_REQUEST,
    ATT_READ_MULTIPLE_REQUEST,
    ATT_READ_BY_GROUP_TYPE_REQUEST,
    ATT_WRITE_REQUEST,
    ATT_PREPARE_WRITE_REQUEST,
    ATT_EXECUTE_WRITE_REQUEST
]

ATT_RESPONSES = [
    ATT_ERROR_RESPONSE,
    ATT_EXCHANGE_MTU_RESPONSE,
    ATT_FIND_INFORMATION_RESPONSE,
    ATT_FIND_BY_TYPE_VALUE_RESPONSE,
    ATT_READ_BY_TYPE_RESPONSE,
    ATT_READ_RESPONSE,
    ATT_READ_BLOB_RESPONSE,
    ATT_READ_MULTIPLE_RESPONSE,
    ATT_READ_BY_GROUP_TYPE_RESPONSE,
    ATT_WRITE_RESPONSE,
    ATT_PREPARE_WRITE_RESPONSE,
    ATT_EXECUTE_WRITE_RESPONSE
]

class ErrorCode(utils.OpenIntEnum):
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
# pylint: disable-next=unnecessary-lambda-assignment,unnecessary-lambda
UUID_2_16_FIELD_SPEC = lambda x, y: UUID.parse_uuid(x, y)
# pylint: disable-next=unnecessary-lambda-assignment,unnecessary-lambda
UUID_2_FIELD_SPEC    = lambda x, y: UUID.parse_uuid_2(x, y)  # noqa: E731

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
            error_name=ATT_PDU.error_name(error_code),
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
class ATT_PDU:
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.3 ATTRIBUTE PDU
    '''

    pdu_classes: Dict[int, Type[ATT_PDU]] = {}
    op_code = 0
    name: str

    @staticmethod
    def from_bytes(pdu):
        op_code = pdu[0]

        cls = ATT_PDU.pdu_classes.get(op_code)
        if cls is None:
            instance = ATT_PDU(pdu)
            instance.name = ATT_PDU.pdu_name(op_code)
            instance.op_code = op_code
            return instance
        self = cls.__new__(cls)
        ATT_PDU.__init__(self, pdu)
        if hasattr(self, 'fields'):
            self.init_from_bytes(pdu, 1)
        return self

    @staticmethod
    def pdu_name(op_code):
        return name_or_number(ATT_PDU_NAMES, op_code, 2)

    @classmethod
    def error_name(cls, error_code: int) -> str:
        return ErrorCode(error_code).name

    @staticmethod
    def subclass(fields):
        def inner(cls):
            cls.name = cls.__name__.upper()
            cls.op_code = key_with_value(ATT_PDU_NAMES, cls.name)
            if cls.op_code is None:
                raise KeyError(f'PDU name {cls.name} not found in ATT_PDU_NAMES')
            cls.fields = fields

            # Register a factory for this class
            ATT_PDU.pdu_classes[cls.op_code] = cls

            return cls

        return inner

    def __init__(self, pdu=None, **kwargs):
        if hasattr(self, 'fields') and kwargs:
            HCI_Object.init_from_fields(self, self.fields, kwargs)
        if pdu is None:
            pdu = bytes([self.op_code]) + HCI_Object.dict_to_bytes(kwargs, self.fields)
        self.pdu = pdu

    def init_from_bytes(self, pdu, offset):
        return HCI_Object.init_from_bytes(self, pdu, offset, self.fields)

    @property
    def is_command(self):
        return ((self.op_code >> 6) & 1) == 1

    @property
    def has_authentication_signature(self):
        return ((self.op_code >> 7) & 1) == 1

    def __bytes__(self):
        return self.pdu

    def __str__(self):
        result = color(self.name, 'yellow')
        if fields := getattr(self, 'fields', None):
            result += ':\n' + HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if len(self.pdu) > 1:
                result += f': {self.pdu.hex()}'
        return result


# -----------------------------------------------------------------------------
@ATT_PDU.subclass(
    [
        ('request_opcode_in_error', {'size': 1, 'mapper': ATT_PDU.pdu_name}),
        ('attribute_handle_in_error', HANDLE_FIELD_SPEC),
        ('error_code', {'size': 1, 'mapper': ATT_PDU.error_name}),
    ]
)
class ATT_Error_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.1.1 Error Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('client_rx_mtu', 2)])
class ATT_Exchange_MTU_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.2.1 Exchange MTU Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('server_rx_mtu', 2)])
class ATT_Exchange_MTU_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.2.2 Exchange MTU Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass(
    [('starting_handle', HANDLE_FIELD_SPEC), ('ending_handle', HANDLE_FIELD_SPEC)]
)
class ATT_Find_Information_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.3.1 Find Information Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('format', 1), ('information_data', '*')])
class ATT_Find_Information_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.3.2 Find Information Response
    '''

    def parse_information_data(self):
        self.information = []
        offset = 0
        uuid_size = 2 if self.format == 1 else 16
        while offset + uuid_size <= len(self.information_data):
            handle = struct.unpack_from('<H', self.information_data, offset)[0]
            uuid = self.information_data[2 + offset : 2 + offset + uuid_size]
            self.information.append((handle, uuid))
            offset += 2 + uuid_size

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parse_information_data()

    def init_from_bytes(self, pdu, offset):
        super().init_from_bytes(pdu, offset)
        self.parse_information_data()

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
@ATT_PDU.subclass(
    [
        ('starting_handle', HANDLE_FIELD_SPEC),
        ('ending_handle', HANDLE_FIELD_SPEC),
        ('attribute_type', UUID_2_FIELD_SPEC),
        ('attribute_value', '*'),
    ]
)
class ATT_Find_By_Type_Value_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.3.3 Find By Type Value Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('handles_information_list', '*')])
class ATT_Find_By_Type_Value_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.3.4 Find By Type Value Response
    '''

    def parse_handles_information_list(self):
        self.handles_information = []
        offset = 0
        while offset + 4 <= len(self.handles_information_list):
            found_attribute_handle, group_end_handle = struct.unpack_from(
                '<HH', self.handles_information_list, offset
            )
            self.handles_information.append((found_attribute_handle, group_end_handle))
            offset += 4

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parse_handles_information_list()

    def init_from_bytes(self, pdu, offset):
        super().init_from_bytes(pdu, offset)
        self.parse_handles_information_list()

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
@ATT_PDU.subclass(
    [
        ('starting_handle', HANDLE_FIELD_SPEC),
        ('ending_handle', HANDLE_FIELD_SPEC),
        ('attribute_type', UUID_2_16_FIELD_SPEC),
    ]
)
class ATT_Read_By_Type_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.1 Read By Type Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('length', 1), ('attribute_data_list', '*')])
class ATT_Read_By_Type_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.2 Read By Type Response
    '''

    def parse_attribute_data_list(self):
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parse_attribute_data_list()

    def init_from_bytes(self, pdu, offset):
        super().init_from_bytes(pdu, offset)
        self.parse_attribute_data_list()

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
@ATT_PDU.subclass([('attribute_handle', HANDLE_FIELD_SPEC)])
class ATT_Read_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.3 Read Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('attribute_value', '*')])
class ATT_Read_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.4 Read Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('attribute_handle', HANDLE_FIELD_SPEC), ('value_offset', 2)])
class ATT_Read_Blob_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.5 Read Blob Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('part_attribute_value', '*')])
class ATT_Read_Blob_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.6 Read Blob Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('set_of_handles', '*')])
class ATT_Read_Multiple_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.7 Read Multiple Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('set_of_values', '*')])
class ATT_Read_Multiple_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.8 Read Multiple Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass(
    [
        ('starting_handle', HANDLE_FIELD_SPEC),
        ('ending_handle', HANDLE_FIELD_SPEC),
        ('attribute_group_type', UUID_2_16_FIELD_SPEC),
    ]
)
class ATT_Read_By_Group_Type_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.9 Read by Group Type Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('length', 1), ('attribute_data_list', '*')])
class ATT_Read_By_Group_Type_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.4.10 Read by Group Type Response
    '''

    def parse_attribute_data_list(self):
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parse_attribute_data_list()

    def init_from_bytes(self, pdu, offset):
        super().init_from_bytes(pdu, offset)
        self.parse_attribute_data_list()

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
@ATT_PDU.subclass([('attribute_handle', HANDLE_FIELD_SPEC), ('attribute_value', '*')])
class ATT_Write_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.5.1 Write Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([])
class ATT_Write_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.5.2 Write Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('attribute_handle', HANDLE_FIELD_SPEC), ('attribute_value', '*')])
class ATT_Write_Command(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.5.3 Write Command
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass(
    [
        ('attribute_handle', HANDLE_FIELD_SPEC),
        ('attribute_value', '*'),
        # ('authentication_signature', 'TODO')
    ]
)
class ATT_Signed_Write_Command(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.5.4 Signed Write Command
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass(
    [
        ('attribute_handle', HANDLE_FIELD_SPEC),
        ('value_offset', 2),
        ('part_attribute_value', '*'),
    ]
)
class ATT_Prepare_Write_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.6.1 Prepare Write Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass(
    [
        ('attribute_handle', HANDLE_FIELD_SPEC),
        ('value_offset', 2),
        ('part_attribute_value', '*'),
    ]
)
class ATT_Prepare_Write_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.6.2 Prepare Write Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([("flags", 1)])
class ATT_Execute_Write_Request(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.6.3 Execute Write Request
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([])
class ATT_Execute_Write_Response(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.6.4 Execute Write Response
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('attribute_handle', HANDLE_FIELD_SPEC), ('attribute_value', '*')])
class ATT_Handle_Value_Notification(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.7.1 Handle Value Notification
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([('attribute_handle', HANDLE_FIELD_SPEC), ('attribute_value', '*')])
class ATT_Handle_Value_Indication(ATT_PDU):
    '''
    See Bluetooth spec @ Vol 3, Part F - 3.4.7.2 Handle Value Indication
    '''


# -----------------------------------------------------------------------------
@ATT_PDU.subclass([])
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
        read: Union[
            Callable[[Optional[Connection]], _T],
            Callable[[Optional[Connection]], Awaitable[_T]],
            None,
        ] = None,
        write: Union[
            Callable[[Optional[Connection], _T], None],
            Callable[[Optional[Connection], _T], Awaitable[None]],
            None,
        ] = None,
    ):
        self._read = read
        self._write = write

    def read(self, connection: Optional[Connection]) -> Union[_T, Awaitable[_T]]:
        if self._read is None:
            raise InvalidOperationError('AttributeValue has no read function')
        return self._read(connection)

    def write(
        self, connection: Optional[Connection], value: _T
    ) -> Union[Awaitable[None], None]:
        if self._write is None:
            raise InvalidOperationError('AttributeValue has no write function')
        return self._write(connection, value)


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
                enum_list: List[str] = [p.name for p in cls if p.name is not None]
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

    value: Union[AttributeValue[_T], _T, None]

    def __init__(
        self,
        attribute_type: Union[str, bytes, UUID],
        permissions: Union[str, Attribute.Permissions],
        value: Union[AttributeValue[_T], _T, None] = None,
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

    async def read_value(self, connection: Optional[Connection]) -> bytes:
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

        value: Union[_T, None]
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
        else:
            value = self.value

        self.emit('read', connection, b'' if value is None else value)

        return b'' if value is None else self.encode_value(value)

    async def write_value(self, connection: Optional[Connection], value: bytes) -> None:
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
        else:
            self.value = decoded_value

        self.emit('write', connection, decoded_value)

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
