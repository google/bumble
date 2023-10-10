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
import struct
from pyee import EventEmitter
from typing import Dict, Type, List, Protocol, Union, Optional, Any, TYPE_CHECKING

from bumble.core import UUID, name_or_number, ProtocolError
from bumble.hci import HCI_Object, key_with_value
from bumble.colors import color

if TYPE_CHECKING:
    from bumble.device import Connection

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

ATT_CID = 0x04

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

ATT_INVALID_HANDLE_ERROR                   = 0x01
ATT_READ_NOT_PERMITTED_ERROR               = 0x02
ATT_WRITE_NOT_PERMITTED_ERROR              = 0x03
ATT_INVALID_PDU_ERROR                      = 0x04
ATT_INSUFFICIENT_AUTHENTICATION_ERROR      = 0x05
ATT_REQUEST_NOT_SUPPORTED_ERROR            = 0x06
ATT_INVALID_OFFSET_ERROR                   = 0x07
ATT_INSUFFICIENT_AUTHORIZATION_ERROR       = 0x08
ATT_PREPARE_QUEUE_FULL_ERROR               = 0x09
ATT_ATTRIBUTE_NOT_FOUND_ERROR              = 0x0A
ATT_ATTRIBUTE_NOT_LONG_ERROR               = 0x0B
ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE_ERROR = 0x0C
ATT_INVALID_ATTRIBUTE_LENGTH_ERROR         = 0x0D
ATT_UNLIKELY_ERROR_ERROR                   = 0x0E
ATT_INSUFFICIENT_ENCRYPTION_ERROR          = 0x0F
ATT_UNSUPPORTED_GROUP_TYPE_ERROR           = 0x10
ATT_INSUFFICIENT_RESOURCES_ERROR           = 0x11

ATT_ERROR_NAMES = {
    ATT_INVALID_HANDLE_ERROR:                   'ATT_INVALID_HANDLE_ERROR',
    ATT_READ_NOT_PERMITTED_ERROR:               'ATT_READ_NOT_PERMITTED_ERROR',
    ATT_WRITE_NOT_PERMITTED_ERROR:              'ATT_WRITE_NOT_PERMITTED_ERROR',
    ATT_INVALID_PDU_ERROR:                      'ATT_INVALID_PDU_ERROR',
    ATT_INSUFFICIENT_AUTHENTICATION_ERROR:      'ATT_INSUFFICIENT_AUTHENTICATION_ERROR',
    ATT_REQUEST_NOT_SUPPORTED_ERROR:            'ATT_REQUEST_NOT_SUPPORTED_ERROR',
    ATT_INVALID_OFFSET_ERROR:                   'ATT_INVALID_OFFSET_ERROR',
    ATT_INSUFFICIENT_AUTHORIZATION_ERROR:       'ATT_INSUFFICIENT_AUTHORIZATION_ERROR',
    ATT_PREPARE_QUEUE_FULL_ERROR:               'ATT_PREPARE_QUEUE_FULL_ERROR',
    ATT_ATTRIBUTE_NOT_FOUND_ERROR:              'ATT_ATTRIBUTE_NOT_FOUND_ERROR',
    ATT_ATTRIBUTE_NOT_LONG_ERROR:               'ATT_ATTRIBUTE_NOT_LONG_ERROR',
    ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE_ERROR: 'ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE_ERROR',
    ATT_INVALID_ATTRIBUTE_LENGTH_ERROR:         'ATT_INVALID_ATTRIBUTE_LENGTH_ERROR',
    ATT_UNLIKELY_ERROR_ERROR:                   'ATT_UNLIKELY_ERROR_ERROR',
    ATT_INSUFFICIENT_ENCRYPTION_ERROR:          'ATT_INSUFFICIENT_ENCRYPTION_ERROR',
    ATT_UNSUPPORTED_GROUP_TYPE_ERROR:           'ATT_UNSUPPORTED_GROUP_TYPE_ERROR',
    ATT_INSUFFICIENT_RESOURCES_ERROR:           'ATT_INSUFFICIENT_RESOURCES_ERROR'
}

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
    def __init__(self, error_code, att_handle=0x0000, message=''):
        super().__init__(
            error_code,
            error_namespace='att',
            error_name=ATT_PDU.error_name(error_code),
        )
        self.att_handle = att_handle
        self.message = message

    def __str__(self):
        return f'ATT_Error(error={self.error_name}, handle={self.att_handle:04X}): {self.message}'


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

    @staticmethod
    def error_name(error_code):
        return name_or_number(ATT_ERROR_NAMES, error_code, 2)

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

    def to_bytes(self):
        return self.pdu

    @property
    def is_command(self):
        return ((self.op_code >> 6) & 1) == 1

    @property
    def has_authentication_signature(self):
        return ((self.op_code >> 7) & 1) == 1

    def __bytes__(self):
        return self.to_bytes()

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
        ('attribute_value', '*')
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
@ATT_PDU.subclass([])
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
class ConnectionValue(Protocol):
    def read(self, connection) -> bytes:
        ...

    def write(self, connection, value: bytes) -> None:
        ...


# -----------------------------------------------------------------------------
class Attribute(EventEmitter):
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
                    f"Attribute::permissions error:\nExpected a string containing any of the keys, separated by commas: {enum_list_str  }\nGot: {permissions_str}"
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

    value: Union[str, bytes, ConnectionValue]

    def __init__(
        self,
        attribute_type: Union[str, bytes, UUID],
        permissions: Union[str, Attribute.Permissions],
        value: Union[str, bytes, ConnectionValue] = b'',
    ) -> None:
        EventEmitter.__init__(self)
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

        # Convert the value to a byte array
        if isinstance(value, str):
            self.value = bytes(value, 'utf-8')
        else:
            self.value = value

    def encode_value(self, value: Any) -> bytes:
        return value

    def decode_value(self, value_bytes: bytes) -> Any:
        return value_bytes

    def read_value(self, connection: Optional[Connection]) -> bytes:
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

        if hasattr(self.value, 'read'):
            try:
                value = self.value.read(connection)
            except ATT_Error as error:
                raise ATT_Error(
                    error_code=error.error_code, att_handle=self.handle
                ) from error
        else:
            value = self.value

        return self.encode_value(value)

    def write_value(self, connection: Connection, value_bytes: bytes) -> None:
        if (
            self.permissions & self.WRITE_REQUIRES_ENCRYPTION
        ) and not connection.encryption:
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_ENCRYPTION_ERROR, att_handle=self.handle
            )
        if (
            self.permissions & self.WRITE_REQUIRES_AUTHENTICATION
        ) and not connection.authenticated:
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_AUTHENTICATION_ERROR, att_handle=self.handle
            )
        if self.permissions & self.WRITE_REQUIRES_AUTHORIZATION:
            # TODO: handle authorization better
            raise ATT_Error(
                error_code=ATT_INSUFFICIENT_AUTHORIZATION_ERROR, att_handle=self.handle
            )

        value = self.decode_value(value_bytes)

        if hasattr(self.value, 'write'):
            try:
                self.value.write(connection, value)  # pylint: disable=not-callable
            except ATT_Error as error:
                raise ATT_Error(
                    error_code=error.error_code, att_handle=self.handle
                ) from error
        else:
            self.value = value

        self.emit('write', connection, value)

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
