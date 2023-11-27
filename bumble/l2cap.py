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
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import asyncio
import dataclasses
import enum
import logging
import struct

from collections import deque
from pyee import EventEmitter
from typing import (
    Dict,
    Type,
    List,
    Optional,
    Tuple,
    Callable,
    Any,
    Union,
    Deque,
    Iterable,
    SupportsBytes,
    TYPE_CHECKING,
)

from .utils import deprecated
from .colors import color
from .core import BT_CENTRAL_ROLE, InvalidStateError, ProtocolError
from .hci import (
    HCI_LE_Connection_Update_Command,
    HCI_Object,
    key_with_value,
    name_or_number,
)

if TYPE_CHECKING:
    from bumble.device import Connection
    from bumble.host import Host

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

L2CAP_SIGNALING_CID    = 0x01
L2CAP_LE_SIGNALING_CID = 0x05

L2CAP_MIN_LE_MTU     = 23
L2CAP_MIN_BR_EDR_MTU = 48

L2CAP_DEFAULT_MTU = 2048  # Default value for the MTU we are willing to accept

L2CAP_DEFAULT_CONNECTIONLESS_MTU = 1024

# See Bluetooth spec @ Vol 3, Part A - Table 2.1: CID name space on ACL-U, ASB-U, and AMP-U logical links
L2CAP_ACL_U_DYNAMIC_CID_RANGE_START = 0x0040
L2CAP_ACL_U_DYNAMIC_CID_RANGE_END   = 0xFFFF

# See Bluetooth spec @ Vol 3, Part A - Table 2.2: CID name space on LE-U logical link
L2CAP_LE_U_DYNAMIC_CID_RANGE_START = 0x0040
L2CAP_LE_U_DYNAMIC_CID_RANGE_END   = 0x007F

# PSM Range - See Bluetooth spec @ Vol 3, Part A / Table 4.5: PSM ranges and usage
L2CAP_PSM_DYNAMIC_RANGE_START = 0x1001
L2CAP_PSM_DYNAMIC_RANGE_END   = 0xFFFF

# LE PSM Ranges - See Bluetooth spec @ Vol 3, Part A / Table 4.19: LE Credit Based Connection Request LE_PSM ranges
L2CAP_LE_PSM_DYNAMIC_RANGE_START = 0x0080
L2CAP_LE_PSM_DYNAMIC_RANGE_END   = 0x00FF

# Frame types
L2CAP_COMMAND_REJECT                       = 0x01
L2CAP_CONNECTION_REQUEST                   = 0x02
L2CAP_CONNECTION_RESPONSE                  = 0x03
L2CAP_CONFIGURE_REQUEST                    = 0x04
L2CAP_CONFIGURE_RESPONSE                   = 0x05
L2CAP_DISCONNECTION_REQUEST                = 0x06
L2CAP_DISCONNECTION_RESPONSE               = 0x07
L2CAP_ECHO_REQUEST                         = 0x08
L2CAP_ECHO_RESPONSE                        = 0x09
L2CAP_INFORMATION_REQUEST                  = 0x0A
L2CAP_INFORMATION_RESPONSE                 = 0x0B
L2CAP_CREATE_CHANNEL_REQUEST               = 0x0C
L2CAP_CREATE_CHANNEL_RESPONSE              = 0x0D
L2CAP_MOVE_CHANNEL_REQUEST                 = 0x0E
L2CAP_MOVE_CHANNEL_RESPONSE                = 0x0F
L2CAP_MOVE_CHANNEL_CONFIRMATION            = 0x10
L2CAP_MOVE_CHANNEL_CONFIRMATION_RESPONSE   = 0x11
L2CAP_CONNECTION_PARAMETER_UPDATE_REQUEST  = 0x12
L2CAP_CONNECTION_PARAMETER_UPDATE_RESPONSE = 0x13
L2CAP_LE_CREDIT_BASED_CONNECTION_REQUEST   = 0x14
L2CAP_LE_CREDIT_BASED_CONNECTION_RESPONSE  = 0x15
L2CAP_LE_FLOW_CONTROL_CREDIT               = 0x16

L2CAP_CONTROL_FRAME_NAMES = {
    L2CAP_COMMAND_REJECT:                       'L2CAP_COMMAND_REJECT',
    L2CAP_CONNECTION_REQUEST:                   'L2CAP_CONNECTION_REQUEST',
    L2CAP_CONNECTION_RESPONSE:                  'L2CAP_CONNECTION_RESPONSE',
    L2CAP_CONFIGURE_REQUEST:                    'L2CAP_CONFIGURE_REQUEST',
    L2CAP_CONFIGURE_RESPONSE:                   'L2CAP_CONFIGURE_RESPONSE',
    L2CAP_DISCONNECTION_REQUEST:                'L2CAP_DISCONNECTION_REQUEST',
    L2CAP_DISCONNECTION_RESPONSE:               'L2CAP_DISCONNECTION_RESPONSE',
    L2CAP_ECHO_REQUEST:                         'L2CAP_ECHO_REQUEST',
    L2CAP_ECHO_RESPONSE:                        'L2CAP_ECHO_RESPONSE',
    L2CAP_INFORMATION_REQUEST:                  'L2CAP_INFORMATION_REQUEST',
    L2CAP_INFORMATION_RESPONSE:                 'L2CAP_INFORMATION_RESPONSE',
    L2CAP_CREATE_CHANNEL_REQUEST:               'L2CAP_CREATE_CHANNEL_REQUEST',
    L2CAP_CREATE_CHANNEL_RESPONSE:              'L2CAP_CREATE_CHANNEL_RESPONSE',
    L2CAP_MOVE_CHANNEL_REQUEST:                 'L2CAP_MOVE_CHANNEL_REQUEST',
    L2CAP_MOVE_CHANNEL_RESPONSE:                'L2CAP_MOVE_CHANNEL_RESPONSE',
    L2CAP_MOVE_CHANNEL_CONFIRMATION:            'L2CAP_MOVE_CHANNEL_CONFIRMATION',
    L2CAP_MOVE_CHANNEL_CONFIRMATION_RESPONSE:   'L2CAP_MOVE_CHANNEL_CONFIRMATION_RESPONSE',
    L2CAP_CONNECTION_PARAMETER_UPDATE_REQUEST:  'L2CAP_CONNECTION_PARAMETER_UPDATE_REQUEST',
    L2CAP_CONNECTION_PARAMETER_UPDATE_RESPONSE: 'L2CAP_CONNECTION_PARAMETER_UPDATE_RESPONSE',
    L2CAP_LE_CREDIT_BASED_CONNECTION_REQUEST:   'L2CAP_LE_CREDIT_BASED_CONNECTION_REQUEST',
    L2CAP_LE_CREDIT_BASED_CONNECTION_RESPONSE:  'L2CAP_LE_CREDIT_BASED_CONNECTION_RESPONSE',
    L2CAP_LE_FLOW_CONTROL_CREDIT:               'L2CAP_LE_FLOW_CONTROL_CREDIT'
}

L2CAP_CONNECTION_PARAMETERS_ACCEPTED_RESULT = 0x0000
L2CAP_CONNECTION_PARAMETERS_REJECTED_RESULT = 0x0001

L2CAP_COMMAND_NOT_UNDERSTOOD_REASON = 0x0000
L2CAP_SIGNALING_MTU_EXCEEDED_REASON = 0x0001
L2CAP_INVALID_CID_IN_REQUEST_REASON = 0x0002

L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_CREDITS             = 65535
L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MTU                 = 23
L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MPS                 = 23
L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_MPS                 = 65533
L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MTU             = 2046
L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MPS             = 2048
L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_INITIAL_CREDITS = 256

L2CAP_MAXIMUM_TRANSMISSION_UNIT_CONFIGURATION_OPTION_TYPE = 0x01

L2CAP_MTU_CONFIGURATION_PARAMETER_TYPE = 0x01

# fmt: on
# pylint: enable=line-too-long


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
# pylint: disable=invalid-name


@dataclasses.dataclass
class ClassicChannelSpec:
    psm: Optional[int] = None
    mtu: int = L2CAP_MIN_BR_EDR_MTU


@dataclasses.dataclass
class LeCreditBasedChannelSpec:
    psm: Optional[int] = None
    mtu: int = L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MTU
    mps: int = L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MPS
    max_credits: int = L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_INITIAL_CREDITS

    def __post_init__(self):
        if (
            self.max_credits < 1
            or self.max_credits > L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_CREDITS
        ):
            raise ValueError('max credits out of range')
        if self.mtu < L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MTU:
            raise ValueError('MTU too small')
        if (
            self.mps < L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MPS
            or self.mps > L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_MPS
        ):
            raise ValueError('MPS out of range')


class L2CAP_PDU:
    '''
    See Bluetooth spec @ Vol 3, Part A - 3 DATA PACKET FORMAT
    '''

    @staticmethod
    def from_bytes(data: bytes) -> L2CAP_PDU:
        # Sanity check
        if len(data) < 4:
            raise ValueError('not enough data for L2CAP header')

        _, l2cap_pdu_cid = struct.unpack_from('<HH', data, 0)
        l2cap_pdu_payload = data[4:]

        return L2CAP_PDU(l2cap_pdu_cid, l2cap_pdu_payload)

    def to_bytes(self) -> bytes:
        header = struct.pack('<HH', len(self.payload), self.cid)
        return header + self.payload

    def __init__(self, cid: int, payload: bytes) -> None:
        self.cid = cid
        self.payload = payload

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __str__(self) -> str:
        return f'{color("L2CAP", "green")} [CID={self.cid}]: {self.payload.hex()}'


# -----------------------------------------------------------------------------
class L2CAP_Control_Frame:
    '''
    See Bluetooth spec @ Vol 3, Part A - 4 SIGNALING PACKET FORMATS
    '''

    classes: Dict[int, Type[L2CAP_Control_Frame]] = {}
    code = 0
    name: str

    @staticmethod
    def from_bytes(pdu: bytes) -> L2CAP_Control_Frame:
        code = pdu[0]

        cls = L2CAP_Control_Frame.classes.get(code)
        if cls is None:
            instance = L2CAP_Control_Frame(pdu)
            instance.name = L2CAP_Control_Frame.code_name(code)
            instance.code = code
            return instance
        self = cls.__new__(cls)
        L2CAP_Control_Frame.__init__(self, pdu)
        self.identifier = pdu[1]
        length = struct.unpack_from('<H', pdu, 2)[0]
        if length + 4 != len(pdu):
            logger.warning(
                color(
                    f'!!! length mismatch: expected {len(pdu) - 4} but got {length}',
                    'red',
                )
            )
        if hasattr(self, 'fields'):
            self.init_from_bytes(pdu, 4)
        return self

    @staticmethod
    def code_name(code: int) -> str:
        return name_or_number(L2CAP_CONTROL_FRAME_NAMES, code)

    @staticmethod
    def decode_configuration_options(data: bytes) -> List[Tuple[int, bytes]]:
        options = []
        while len(data) >= 2:
            value_type = data[0]
            length = data[1]
            value = data[2 : 2 + length]
            data = data[2 + length :]
            options.append((value_type, value))

        return options

    @staticmethod
    def encode_configuration_options(options: List[Tuple[int, bytes]]) -> bytes:
        return b''.join(
            [bytes([option[0], len(option[1])]) + option[1] for option in options]
        )

    @staticmethod
    def subclass(fields):
        def inner(cls):
            cls.name = cls.__name__.upper()
            cls.code = key_with_value(L2CAP_CONTROL_FRAME_NAMES, cls.name)
            if cls.code is None:
                raise KeyError(
                    f'Control Frame name {cls.name} '
                    'not found in L2CAP_CONTROL_FRAME_NAMES'
                )
            cls.fields = fields

            # Register a factory for this class
            L2CAP_Control_Frame.classes[cls.code] = cls

            return cls

        return inner

    def __init__(self, pdu=None, **kwargs) -> None:
        self.identifier = kwargs.get('identifier', 0)
        if hasattr(self, 'fields'):
            if kwargs:
                HCI_Object.init_from_fields(self, self.fields, kwargs)
            if pdu is None:
                data = HCI_Object.dict_to_bytes(kwargs, self.fields)
                pdu = (
                    bytes([self.code, self.identifier])
                    + struct.pack('<H', len(data))
                    + data
                )
        self.pdu = pdu

    def init_from_bytes(self, pdu, offset):
        return HCI_Object.init_from_bytes(self, pdu, offset, self.fields)

    def to_bytes(self) -> bytes:
        return self.pdu

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __str__(self) -> str:
        result = f'{color(self.name, "yellow")} [ID={self.identifier}]'
        if fields := getattr(self, 'fields', None):
            result += ':\n' + HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if len(self.pdu) > 1:
                result += f': {self.pdu.hex()}'
        return result


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    # pylint: disable=unnecessary-lambda
    [
        (
            'reason',
            {'size': 2, 'mapper': lambda x: L2CAP_Command_Reject.reason_name(x)},
        ),
        ('data', '*'),
    ]
)
class L2CAP_Command_Reject(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.1 COMMAND REJECT
    '''

    COMMAND_NOT_UNDERSTOOD = 0x0000
    SIGNALING_MTU_EXCEEDED = 0x0001
    INVALID_CID_IN_REQUEST = 0x0002

    REASON_NAMES = {
        COMMAND_NOT_UNDERSTOOD: 'COMMAND_NOT_UNDERSTOOD',
        SIGNALING_MTU_EXCEEDED: 'SIGNALING_MTU_EXCEEDED',
        INVALID_CID_IN_REQUEST: 'INVALID_CID_IN_REQUEST',
    }

    @staticmethod
    def reason_name(reason: int) -> str:
        return name_or_number(L2CAP_Command_Reject.REASON_NAMES, reason)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    # pylint: disable=unnecessary-lambda
    [
        (
            'psm',
            {
                'parser': lambda data, offset: L2CAP_Connection_Request.parse_psm(
                    data, offset
                ),
                'serializer': lambda value: L2CAP_Connection_Request.serialize_psm(
                    value
                ),
            },
        ),
        ('source_cid', 2),
    ]
)
class L2CAP_Connection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.2 CONNECTION REQUEST
    '''

    psm: int
    source_cid: int

    @staticmethod
    def parse_psm(data: bytes, offset: int = 0) -> Tuple[int, int]:
        psm_length = 2
        psm = data[offset] | data[offset + 1] << 8

        # The PSM field extends until the first even octet (inclusive)
        while data[offset + psm_length - 1] % 2 == 1:
            psm |= data[offset + psm_length] << (8 * psm_length)
            psm_length += 1

        return offset + psm_length, psm

    @staticmethod
    def serialize_psm(psm: int) -> bytes:
        serialized = struct.pack('<H', psm & 0xFFFF)
        psm >>= 16
        while psm:
            serialized += bytes([psm & 0xFF])
            psm >>= 8

        return serialized


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    # pylint: disable=unnecessary-lambda
    [
        ('destination_cid', 2),
        ('source_cid', 2),
        (
            'result',
            {'size': 2, 'mapper': lambda x: L2CAP_Connection_Response.result_name(x)},
        ),
        ('status', 2),
    ]
)
class L2CAP_Connection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.3 CONNECTION RESPONSE
    '''

    source_cid: int
    destination_cid: int
    status: int
    result: int

    CONNECTION_SUCCESSFUL = 0x0000
    CONNECTION_PENDING = 0x0001
    CONNECTION_REFUSED_PSM_NOT_SUPPORTED = 0x0002
    CONNECTION_REFUSED_SECURITY_BLOCK = 0x0003
    CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE = 0x0004
    CONNECTION_REFUSED_INVALID_SOURCE_CID = 0x0006
    CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED = 0x0007
    CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS = 0x000B

    # pylint: disable=line-too-long
    RESULT_NAMES = {
        CONNECTION_SUCCESSFUL: 'CONNECTION_SUCCESSFUL',
        CONNECTION_PENDING: 'CONNECTION_PENDING',
        CONNECTION_REFUSED_PSM_NOT_SUPPORTED: 'CONNECTION_REFUSED_PSM_NOT_SUPPORTED',
        CONNECTION_REFUSED_SECURITY_BLOCK: 'CONNECTION_REFUSED_SECURITY_BLOCK',
        CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE: 'CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE',
        CONNECTION_REFUSED_INVALID_SOURCE_CID: 'CONNECTION_REFUSED_INVALID_SOURCE_CID',
        CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED: 'CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED',
        CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS: 'CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS',
    }

    @staticmethod
    def result_name(result: int) -> str:
        return name_or_number(L2CAP_Connection_Response.RESULT_NAMES, result)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([('destination_cid', 2), ('flags', 2), ('options', '*')])
class L2CAP_Configure_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.4 CONFIGURATION REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    # pylint: disable=unnecessary-lambda
    [
        ('source_cid', 2),
        ('flags', 2),
        (
            'result',
            {'size': 2, 'mapper': lambda x: L2CAP_Configure_Response.result_name(x)},
        ),
        ('options', '*'),
    ]
)
class L2CAP_Configure_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.5 CONFIGURATION RESPONSE
    '''

    SUCCESS = 0x0000
    FAILURE_UNACCEPTABLE_PARAMETERS = 0x0001
    FAILURE_REJECTED = 0x0002
    FAILURE_UNKNOWN_OPTIONS = 0x0003
    PENDING = 0x0004
    FAILURE_FLOW_SPEC_REJECTED = 0x0005

    RESULT_NAMES = {
        SUCCESS: 'SUCCESS',
        FAILURE_UNACCEPTABLE_PARAMETERS: 'FAILURE_UNACCEPTABLE_PARAMETERS',
        FAILURE_REJECTED: 'FAILURE_REJECTED',
        FAILURE_UNKNOWN_OPTIONS: 'FAILURE_UNKNOWN_OPTIONS',
        PENDING: 'PENDING',
        FAILURE_FLOW_SPEC_REJECTED: 'FAILURE_FLOW_SPEC_REJECTED',
    }

    @staticmethod
    def result_name(result: int) -> str:
        return name_or_number(L2CAP_Configure_Response.RESULT_NAMES, result)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([('destination_cid', 2), ('source_cid', 2)])
class L2CAP_Disconnection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.6 DISCONNECTION REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([('destination_cid', 2), ('source_cid', 2)])
class L2CAP_Disconnection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.7 DISCONNECTION RESPONSE
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([('data', '*')])
class L2CAP_Echo_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.8 ECHO REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([('data', '*')])
class L2CAP_Echo_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.9 ECHO RESPONSE
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    [
        (
            'info_type',
            {
                'size': 2,
                # pylint: disable-next=unnecessary-lambda
                'mapper': lambda x: L2CAP_Information_Request.info_type_name(x),
            },
        )
    ]
)
class L2CAP_Information_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.10 INFORMATION REQUEST
    '''

    CONNECTIONLESS_MTU = 0x0001
    EXTENDED_FEATURES_SUPPORTED = 0x0002
    FIXED_CHANNELS_SUPPORTED = 0x0003

    EXTENDED_FEATURE_FLOW_MODE_CONTROL = 0x0001
    EXTENDED_FEATURE_RETRANSMISSION_MODE = 0x0002
    EXTENDED_FEATURE_BIDIRECTIONAL_QOS = 0x0004
    EXTENDED_FEATURE_ENHANCED_RETRANSMISSION_MODE = 0x0008
    EXTENDED_FEATURE_STREAMING_MODE = 0x0010
    EXTENDED_FEATURE_FCS_OPTION = 0x0020
    EXTENDED_FEATURE_EXTENDED_FLOW_SPEC = 0x0040
    EXTENDED_FEATURE_FIXED_CHANNELS = 0x0080
    EXTENDED_FEATURE_EXTENDED_WINDOW_SIZE = 0x0100
    EXTENDED_FEATURE_UNICAST_CONNECTIONLESS_DATA = 0x0200
    EXTENDED_FEATURE_ENHANCED_CREDIT_BASE_FLOW_CONTROL = 0x0400

    INFO_TYPE_NAMES = {
        CONNECTIONLESS_MTU: 'CONNECTIONLESS_MTU',
        EXTENDED_FEATURES_SUPPORTED: 'EXTENDED_FEATURES_SUPPORTED',
        FIXED_CHANNELS_SUPPORTED: 'FIXED_CHANNELS_SUPPORTED',
    }

    @staticmethod
    def info_type_name(info_type: int) -> str:
        return name_or_number(L2CAP_Information_Request.INFO_TYPE_NAMES, info_type)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    [
        ('info_type', {'size': 2, 'mapper': L2CAP_Information_Request.info_type_name}),
        (
            'result',
            # pylint: disable-next=unnecessary-lambda
            {'size': 2, 'mapper': lambda x: L2CAP_Information_Response.result_name(x)},
        ),
        ('data', '*'),
    ]
)
class L2CAP_Information_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.11 INFORMATION RESPONSE
    '''

    SUCCESS = 0x00
    NOT_SUPPORTED = 0x01

    RESULT_NAMES = {SUCCESS: 'SUCCESS', NOT_SUPPORTED: 'NOT_SUPPORTED'}

    @staticmethod
    def result_name(result: int) -> str:
        return name_or_number(L2CAP_Information_Response.RESULT_NAMES, result)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    [('interval_min', 2), ('interval_max', 2), ('latency', 2), ('timeout', 2)]
)
class L2CAP_Connection_Parameter_Update_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.20 CONNECTION PARAMETER UPDATE REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([('result', 2)])
class L2CAP_Connection_Parameter_Update_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.21 CONNECTION PARAMETER UPDATE RESPONSE
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    [('le_psm', 2), ('source_cid', 2), ('mtu', 2), ('mps', 2), ('initial_credits', 2)]
)
class L2CAP_LE_Credit_Based_Connection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.22 LE CREDIT BASED CONNECTION REQUEST
    (CODE 0x14)
    '''

    source_cid: int


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass(
    # pylint: disable=unnecessary-lambda,line-too-long
    [
        ('destination_cid', 2),
        ('mtu', 2),
        ('mps', 2),
        ('initial_credits', 2),
        (
            'result',
            {
                'size': 2,
                'mapper': lambda x: L2CAP_LE_Credit_Based_Connection_Response.result_name(
                    x
                ),
            },
        ),
    ]
)
class L2CAP_LE_Credit_Based_Connection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.23 LE CREDIT BASED CONNECTION RESPONSE
    (CODE 0x15)
    '''

    CONNECTION_SUCCESSFUL = 0x0000
    CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED = 0x0002
    CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE = 0x0004
    CONNECTION_REFUSED_INSUFFICIENT_AUTHENTICATION = 0x0005
    CONNECTION_REFUSED_INSUFFICIENT_AUTHORIZATION = 0x0006
    CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0x0007
    CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION = 0x0008
    CONNECTION_REFUSED_INVALID_SOURCE_CID = 0x0009
    CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED = 0x000A
    CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS = 0x000B

    # pylint: disable=line-too-long
    RESULT_NAMES = {
        CONNECTION_SUCCESSFUL: 'CONNECTION_SUCCESSFUL',
        CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED: 'CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED',
        CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE: 'CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE',
        CONNECTION_REFUSED_INSUFFICIENT_AUTHENTICATION: 'CONNECTION_REFUSED_INSUFFICIENT_AUTHENTICATION',
        CONNECTION_REFUSED_INSUFFICIENT_AUTHORIZATION: 'CONNECTION_REFUSED_INSUFFICIENT_AUTHORIZATION',
        CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION_KEY_SIZE: 'CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION_KEY_SIZE',
        CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION: 'CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION',
        CONNECTION_REFUSED_INVALID_SOURCE_CID: 'CONNECTION_REFUSED_INVALID_SOURCE_CID',
        CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED: 'CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED',
        CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS: 'CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS',
    }

    @staticmethod
    def result_name(result: int) -> str:
        return name_or_number(
            L2CAP_LE_Credit_Based_Connection_Response.RESULT_NAMES, result
        )


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([('cid', 2), ('credits', 2)])
class L2CAP_LE_Flow_Control_Credit(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.24 LE FLOW CONTROL CREDIT (CODE 0x16)
    '''


# -----------------------------------------------------------------------------
class ClassicChannel(EventEmitter):
    class State(enum.IntEnum):
        # States
        CLOSED = 0x00
        WAIT_CONNECT = 0x01
        WAIT_CONNECT_RSP = 0x02
        OPEN = 0x03
        WAIT_DISCONNECT = 0x04
        WAIT_CREATE = 0x05
        WAIT_CREATE_RSP = 0x06
        WAIT_MOVE = 0x07
        WAIT_MOVE_RSP = 0x08
        WAIT_MOVE_CONFIRM = 0x09
        WAIT_CONFIRM_RSP = 0x0A

        # CONFIG substates
        WAIT_CONFIG = 0x10
        WAIT_SEND_CONFIG = 0x11
        WAIT_CONFIG_REQ_RSP = 0x12
        WAIT_CONFIG_RSP = 0x13
        WAIT_CONFIG_REQ = 0x14
        WAIT_IND_FINAL_RSP = 0x15
        WAIT_FINAL_RSP = 0x16
        WAIT_CONTROL_IND = 0x17

    connection_result: Optional[asyncio.Future[None]]
    disconnection_result: Optional[asyncio.Future[None]]
    response: Optional[asyncio.Future[bytes]]
    sink: Optional[Callable[[bytes], Any]]
    state: State
    connection: Connection

    def __init__(
        self,
        manager: ChannelManager,
        connection: Connection,
        signaling_cid: int,
        psm: int,
        source_cid: int,
        mtu: int,
    ) -> None:
        super().__init__()
        self.manager = manager
        self.connection = connection
        self.signaling_cid = signaling_cid
        self.state = self.State.CLOSED
        self.mtu = mtu
        self.psm = psm
        self.source_cid = source_cid
        self.destination_cid = 0
        self.response = None
        self.connection_result = None
        self.disconnection_result = None
        self.sink = None

    def _change_state(self, new_state: State) -> None:
        logger.debug(f'{self} state change -> {color(new_state.name, "cyan")}')
        self.state = new_state

    def send_pdu(self, pdu: Union[SupportsBytes, bytes]) -> None:
        self.manager.send_pdu(self.connection, self.destination_cid, pdu)

    def send_control_frame(self, frame: L2CAP_Control_Frame) -> None:
        self.manager.send_control_frame(self.connection, self.signaling_cid, frame)

    async def send_request(self, request: SupportsBytes) -> bytes:
        # Check that there isn't already a request pending
        if self.response:
            raise InvalidStateError('request already pending')
        if self.state != self.State.OPEN:
            raise InvalidStateError('channel not open')

        self.response = asyncio.get_running_loop().create_future()
        self.send_pdu(request)
        return await self.response

    def on_pdu(self, pdu: bytes) -> None:
        if self.response:
            self.response.set_result(pdu)
            self.response = None
        elif self.sink:
            # pylint: disable=not-callable
            self.sink(pdu)
        else:
            logger.warning(
                color('received pdu without a pending request or sink', 'red')
            )

    async def connect(self) -> None:
        if self.state != self.State.CLOSED:
            raise InvalidStateError('invalid state')

        # Check that we can start a new connection
        if self.connection_result:
            raise RuntimeError('connection already pending')

        self._change_state(self.State.WAIT_CONNECT_RSP)
        self.send_control_frame(
            L2CAP_Connection_Request(
                identifier=self.manager.next_identifier(self.connection),
                psm=self.psm,
                source_cid=self.source_cid,
            )
        )

        # Create a future to wait for the state machine to get to a success or error
        # state
        self.connection_result = asyncio.get_running_loop().create_future()

        # Wait for the connection to succeed or fail
        try:
            return await self.connection_result
        finally:
            self.connection_result = None

    async def disconnect(self) -> None:
        if self.state != self.State.OPEN:
            raise InvalidStateError('invalid state')

        self._change_state(self.State.WAIT_DISCONNECT)
        self.send_control_frame(
            L2CAP_Disconnection_Request(
                identifier=self.manager.next_identifier(self.connection),
                destination_cid=self.destination_cid,
                source_cid=self.source_cid,
            )
        )

        # Create a future to wait for the state machine to get to a success or error
        # state
        self.disconnection_result = asyncio.get_running_loop().create_future()
        return await self.disconnection_result

    def abort(self) -> None:
        if self.state == self.State.OPEN:
            self._change_state(self.State.CLOSED)
            self.emit('close')

    def send_configure_request(self) -> None:
        options = L2CAP_Control_Frame.encode_configuration_options(
            [
                (
                    L2CAP_MAXIMUM_TRANSMISSION_UNIT_CONFIGURATION_OPTION_TYPE,
                    struct.pack('<H', L2CAP_DEFAULT_MTU),
                )
            ]
        )
        self.send_control_frame(
            L2CAP_Configure_Request(
                identifier=self.manager.next_identifier(self.connection),
                destination_cid=self.destination_cid,
                flags=0x0000,
                options=options,
            )
        )

    def on_connection_request(self, request) -> None:
        self.destination_cid = request.source_cid
        self._change_state(self.State.WAIT_CONNECT)
        self.send_control_frame(
            L2CAP_Connection_Response(
                identifier=request.identifier,
                destination_cid=self.source_cid,
                source_cid=self.destination_cid,
                result=L2CAP_Connection_Response.CONNECTION_SUCCESSFUL,
                status=0x0000,
            )
        )
        self._change_state(self.State.WAIT_CONFIG)
        self.send_configure_request()
        self._change_state(self.State.WAIT_CONFIG_REQ_RSP)

    def on_connection_response(self, response):
        if self.state != self.State.WAIT_CONNECT_RSP:
            logger.warning(color('invalid state', 'red'))
            return

        if response.result == L2CAP_Connection_Response.CONNECTION_SUCCESSFUL:
            self.destination_cid = response.destination_cid
            self._change_state(self.State.WAIT_CONFIG)
            self.send_configure_request()
            self._change_state(self.State.WAIT_CONFIG_REQ_RSP)
        elif response.result == L2CAP_Connection_Response.CONNECTION_PENDING:
            pass
        else:
            self._change_state(self.State.CLOSED)
            self.connection_result.set_exception(
                ProtocolError(
                    response.result,
                    'l2cap',
                    L2CAP_Connection_Response.result_name(response.result),
                )
            )
            self.connection_result = None

    def on_configure_request(self, request) -> None:
        if self.state not in (
            self.State.WAIT_CONFIG,
            self.State.WAIT_CONFIG_REQ,
            self.State.WAIT_CONFIG_REQ_RSP,
        ):
            logger.warning(color('invalid state', 'red'))
            return

        # Decode the options
        options = L2CAP_Control_Frame.decode_configuration_options(request.options)
        for option in options:
            if option[0] == L2CAP_MTU_CONFIGURATION_PARAMETER_TYPE:
                self.mtu = struct.unpack('<H', option[1])[0]
                logger.debug(f'MTU = {self.mtu}')

        self.send_control_frame(
            L2CAP_Configure_Response(
                identifier=request.identifier,
                source_cid=self.destination_cid,
                flags=0x0000,
                result=L2CAP_Configure_Response.SUCCESS,
                options=request.options,  # TODO: don't accept everything blindly
            )
        )
        if self.state == self.State.WAIT_CONFIG:
            self._change_state(self.State.WAIT_SEND_CONFIG)
            self.send_configure_request()
            self._change_state(self.State.WAIT_CONFIG_RSP)
        elif self.state == self.State.WAIT_CONFIG_REQ:
            self._change_state(self.State.OPEN)
            if self.connection_result:
                self.connection_result.set_result(None)
                self.connection_result = None
            self.emit('open')
        elif self.state == self.State.WAIT_CONFIG_REQ_RSP:
            self._change_state(self.State.WAIT_CONFIG_RSP)

    def on_configure_response(self, response) -> None:
        if response.result == L2CAP_Configure_Response.SUCCESS:
            if self.state == self.State.WAIT_CONFIG_REQ_RSP:
                self._change_state(self.State.WAIT_CONFIG_REQ)
            elif self.state in (
                self.State.WAIT_CONFIG_RSP,
                self.State.WAIT_CONTROL_IND,
            ):
                self._change_state(self.State.OPEN)
                if self.connection_result:
                    self.connection_result.set_result(None)
                    self.connection_result = None
                self.emit('open')
            else:
                logger.warning(color('invalid state', 'red'))
        elif (
            response.result == L2CAP_Configure_Response.FAILURE_UNACCEPTABLE_PARAMETERS
        ):
            # Re-configure with what's suggested in the response
            self.send_control_frame(
                L2CAP_Configure_Request(
                    identifier=self.manager.next_identifier(self.connection),
                    destination_cid=self.destination_cid,
                    flags=0x0000,
                    options=response.options,
                )
            )
        else:
            logger.warning(
                color(
                    '!!! configuration rejected: '
                    f'{L2CAP_Configure_Response.result_name(response.result)}',
                    'red',
                )
            )
            # TODO: decide how to fail gracefully

    def on_disconnection_request(self, request) -> None:
        if self.state in (self.State.OPEN, self.State.WAIT_DISCONNECT):
            self.send_control_frame(
                L2CAP_Disconnection_Response(
                    identifier=request.identifier,
                    destination_cid=request.destination_cid,
                    source_cid=request.source_cid,
                )
            )
            self._change_state(self.State.CLOSED)
            self.emit('close')
            self.manager.on_channel_closed(self)
        else:
            logger.warning(color('invalid state', 'red'))

    def on_disconnection_response(self, response) -> None:
        if self.state != self.State.WAIT_DISCONNECT:
            logger.warning(color('invalid state', 'red'))
            return

        if (
            response.destination_cid != self.destination_cid
            or response.source_cid != self.source_cid
        ):
            logger.warning('unexpected source or destination CID')
            return

        self._change_state(self.State.CLOSED)
        if self.disconnection_result:
            self.disconnection_result.set_result(None)
            self.disconnection_result = None
        self.emit('close')
        self.manager.on_channel_closed(self)

    def __str__(self) -> str:
        return (
            f'Channel({self.source_cid}->{self.destination_cid}, '
            f'PSM={self.psm}, '
            f'MTU={self.mtu}, '
            f'state={self.state.name})'
        )


# -----------------------------------------------------------------------------
class LeCreditBasedChannel(EventEmitter):
    """
    LE Credit-based Connection Oriented Channel
    """

    class State(enum.IntEnum):
        INIT = 0
        CONNECTED = 1
        CONNECTING = 2
        DISCONNECTING = 3
        DISCONNECTED = 4
        CONNECTION_ERROR = 5

    out_queue: Deque[bytes]
    connection_result: Optional[asyncio.Future[LeCreditBasedChannel]]
    disconnection_result: Optional[asyncio.Future[None]]
    in_sdu: Optional[bytes]
    out_sdu: Optional[bytes]
    state: State
    connection: Connection
    sink: Optional[Callable[[bytes], Any]]

    def __init__(
        self,
        manager: ChannelManager,
        connection: Connection,
        le_psm: int,
        source_cid: int,
        destination_cid: int,
        mtu: int,
        mps: int,
        credits: int,  # pylint: disable=redefined-builtin
        peer_mtu: int,
        peer_mps: int,
        peer_credits: int,
        connected: bool,
    ) -> None:
        super().__init__()
        self.manager = manager
        self.connection = connection
        self.le_psm = le_psm
        self.source_cid = source_cid
        self.destination_cid = destination_cid
        self.mtu = mtu
        self.mps = mps
        self.credits = credits
        self.peer_mtu = peer_mtu
        self.peer_mps = peer_mps
        self.peer_credits = peer_credits
        self.peer_max_credits = self.peer_credits
        self.peer_credits_threshold = self.peer_max_credits // 2
        self.in_sdu = None
        self.in_sdu_length = 0
        self.out_queue = deque()
        self.out_sdu = None
        self.sink = None
        self.connected = False
        self.connection_result = None
        self.disconnection_result = None
        self.drained = asyncio.Event()

        self.drained.set()

        if connected:
            self.state = self.State.CONNECTED
        else:
            self.state = self.State.INIT

    def _change_state(self, new_state: State) -> None:
        logger.debug(f'{self} state change -> {color(new_state.name, "cyan")}')
        self.state = new_state

        if new_state == self.State.CONNECTED:
            self.emit('open')
        elif new_state == self.State.DISCONNECTED:
            self.emit('close')

    def send_pdu(self, pdu: Union[SupportsBytes, bytes]) -> None:
        self.manager.send_pdu(self.connection, self.destination_cid, pdu)

    def send_control_frame(self, frame: L2CAP_Control_Frame) -> None:
        self.manager.send_control_frame(self.connection, L2CAP_LE_SIGNALING_CID, frame)

    async def connect(self) -> LeCreditBasedChannel:
        # Check that we're in the right state
        if self.state != self.State.INIT:
            raise InvalidStateError('not in a connectable state')

        # Check that we can start a new connection
        identifier = self.manager.next_identifier(self.connection)
        if identifier in self.manager.le_coc_requests:
            raise RuntimeError('too many concurrent connection requests')

        self._change_state(self.State.CONNECTING)
        request = L2CAP_LE_Credit_Based_Connection_Request(
            identifier=identifier,
            le_psm=self.le_psm,
            source_cid=self.source_cid,
            mtu=self.mtu,
            mps=self.mps,
            initial_credits=self.peer_credits,
        )
        self.manager.le_coc_requests[identifier] = request
        self.send_control_frame(request)

        # Create a future to wait for the response
        self.connection_result = asyncio.get_running_loop().create_future()

        # Wait for the connection to succeed or fail
        return await self.connection_result

    async def disconnect(self) -> None:
        # Check that we're connected
        if self.state != self.State.CONNECTED:
            raise InvalidStateError('not connected')

        self._change_state(self.State.DISCONNECTING)
        self.flush_output()
        self.send_control_frame(
            L2CAP_Disconnection_Request(
                identifier=self.manager.next_identifier(self.connection),
                destination_cid=self.destination_cid,
                source_cid=self.source_cid,
            )
        )

        # Create a future to wait for the state machine to get to a success or error
        # state
        self.disconnection_result = asyncio.get_running_loop().create_future()
        return await self.disconnection_result

    def abort(self) -> None:
        if self.state == self.State.CONNECTED:
            self._change_state(self.State.DISCONNECTED)

    def on_pdu(self, pdu: bytes) -> None:
        if self.sink is None:
            logger.warning('received pdu without a sink')
            return

        if self.state != self.State.CONNECTED:
            logger.warning('received PDU while not connected, dropping')

        # Manage the peer credits
        if self.peer_credits == 0:
            logger.warning('received LE frame when peer out of credits')
        else:
            self.peer_credits -= 1
            if self.peer_credits <= self.peer_credits_threshold:
                # The credits fell below the threshold, replenish them to the max
                self.send_control_frame(
                    L2CAP_LE_Flow_Control_Credit(
                        identifier=self.manager.next_identifier(self.connection),
                        cid=self.source_cid,
                        credits=self.peer_max_credits - self.peer_credits,
                    )
                )
                self.peer_credits = self.peer_max_credits

        # Check if this starts a new SDU
        if self.in_sdu is None:
            # Start a new SDU
            self.in_sdu = pdu
        else:
            # Continue an SDU
            self.in_sdu += pdu

        # Check if the SDU is complete
        if self.in_sdu_length == 0:
            # We don't know the size yet, check if we have received the header to
            # compute it
            if len(self.in_sdu) >= 2:
                self.in_sdu_length = struct.unpack_from('<H', self.in_sdu, 0)[0]
        if self.in_sdu_length == 0:
            # We'll compute it later
            return
        if len(self.in_sdu) < 2 + self.in_sdu_length:
            # Not complete yet
            logger.debug(
                f'SDU: {len(self.in_sdu) - 2} of {self.in_sdu_length} bytes received'
            )
            return
        if len(self.in_sdu) != 2 + self.in_sdu_length:
            # Overflow
            logger.warning(
                f'SDU overflow: sdu_length={self.in_sdu_length}, '
                f'received {len(self.in_sdu) - 2}'
            )
            # TODO: we should disconnect
            self.in_sdu = None
            self.in_sdu_length = 0
            return

        # Send the SDU to the sink
        logger.debug(f'SDU complete: 2+{len(self.in_sdu) - 2} bytes')
        self.sink(self.in_sdu[2:])  # pylint: disable=not-callable

        # Prepare for a new SDU
        self.in_sdu = None
        self.in_sdu_length = 0

    def on_connection_response(self, response) -> None:
        # Look for a matching pending response result
        if self.connection_result is None:
            logger.warning(
                f'received unexpected connection response (id={response.identifier})'
            )
            return

        if (
            response.result
            == L2CAP_LE_Credit_Based_Connection_Response.CONNECTION_SUCCESSFUL
        ):
            self.destination_cid = response.destination_cid
            self.peer_mtu = response.mtu
            self.peer_mps = response.mps
            self.credits = response.initial_credits
            self.connected = True
            self.connection_result.set_result(self)
            self._change_state(self.State.CONNECTED)
        else:
            self.connection_result.set_exception(
                ProtocolError(
                    response.result,
                    'l2cap',
                    L2CAP_LE_Credit_Based_Connection_Response.result_name(
                        response.result
                    ),
                )
            )
            self._change_state(self.State.CONNECTION_ERROR)

        # Cleanup
        self.connection_result = None

    def on_credits(self, credits: int) -> None:  # pylint: disable=redefined-builtin
        self.credits += credits
        logger.debug(f'received {credits} credits, total = {self.credits}')

        # Try to send more data if we have any queued up
        self.process_output()

    def on_disconnection_request(self, request) -> None:
        self.send_control_frame(
            L2CAP_Disconnection_Response(
                identifier=request.identifier,
                destination_cid=request.destination_cid,
                source_cid=request.source_cid,
            )
        )
        self._change_state(self.State.DISCONNECTED)
        self.flush_output()

    def on_disconnection_response(self, response) -> None:
        if self.state != self.State.DISCONNECTING:
            logger.warning(color('invalid state', 'red'))
            return

        if (
            response.destination_cid != self.destination_cid
            or response.source_cid != self.source_cid
        ):
            logger.warning('unexpected source or destination CID')
            return

        self._change_state(self.State.DISCONNECTED)
        if self.disconnection_result:
            self.disconnection_result.set_result(None)
            self.disconnection_result = None

    def flush_output(self) -> None:
        self.out_queue.clear()
        self.out_sdu = None

    def process_output(self) -> None:
        while self.credits > 0:
            if self.out_sdu is not None:
                # Finish the current SDU
                packet = self.out_sdu[: self.peer_mps]
                self.send_pdu(packet)
                self.credits -= 1
                logger.debug(f'sent {len(packet)} bytes, {self.credits} credits left')
                if len(packet) == len(self.out_sdu):
                    # We sent everything
                    self.out_sdu = None
                else:
                    # Keep what's still left to send
                    self.out_sdu = self.out_sdu[len(packet) :]
                continue

            if self.out_queue:
                # Create the next SDU (2 bytes header plus up to MTU bytes payload)
                logger.debug(
                    f'assembling SDU from {len(self.out_queue)} packets in output queue'
                )
                payload = b''
                while self.out_queue and len(payload) < self.peer_mtu:
                    # We can add more data to the payload
                    chunk = self.out_queue[0][: self.peer_mtu - len(payload)]
                    payload += chunk
                    self.out_queue[0] = self.out_queue[0][len(chunk) :]
                    if len(self.out_queue[0]) == 0:
                        # We consumed the entire buffer, remove it
                        self.out_queue.popleft()
                        logger.debug(
                            f'packet completed, {len(self.out_queue)} left in queue'
                        )

                # Construct the SDU with its header
                assert len(payload) != 0
                logger.debug(f'SDU complete: {len(payload)} payload bytes')
                self.out_sdu = struct.pack('<H', len(payload)) + payload
            else:
                # Nothing left to send for now
                self.drained.set()
                return

    def write(self, data: bytes) -> None:
        if self.state != self.State.CONNECTED:
            logger.warning('not connected, dropping data')
            return

        # Queue the data
        self.out_queue.append(data)
        self.drained.clear()
        logger.debug(
            f'{len(data)} bytes packet queued, {len(self.out_queue)} packets in queue'
        )

        # Send what we can
        self.process_output()

    async def drain(self) -> None:
        await self.drained.wait()

    def pause_reading(self) -> None:
        # TODO: not implemented yet
        pass

    def resume_reading(self) -> None:
        # TODO: not implemented yet
        pass

    def __str__(self) -> str:
        return (
            f'CoC({self.source_cid}->{self.destination_cid}, '
            f'State={self.state.name}, '
            f'PSM={self.le_psm}, '
            f'MTU={self.mtu}/{self.peer_mtu}, '
            f'MPS={self.mps}/{self.peer_mps}, '
            f'credits={self.credits}/{self.peer_credits})'
        )


# -----------------------------------------------------------------------------
class ClassicChannelServer(EventEmitter):
    def __init__(
        self,
        manager: ChannelManager,
        psm: int,
        handler: Optional[Callable[[ClassicChannel], Any]],
        mtu: int,
    ) -> None:
        super().__init__()
        self.manager = manager
        self.handler = handler
        self.psm = psm
        self.mtu = mtu

    def on_connection(self, channel: ClassicChannel) -> None:
        self.emit('connection', channel)
        if self.handler:
            self.handler(channel)

    def close(self) -> None:
        if self.psm in self.manager.servers:
            del self.manager.servers[self.psm]


# -----------------------------------------------------------------------------
class LeCreditBasedChannelServer(EventEmitter):
    def __init__(
        self,
        manager: ChannelManager,
        psm: int,
        handler: Optional[Callable[[LeCreditBasedChannel], Any]],
        max_credits: int,
        mtu: int,
        mps: int,
    ) -> None:
        super().__init__()
        self.manager = manager
        self.handler = handler
        self.psm = psm
        self.max_credits = max_credits
        self.mtu = mtu
        self.mps = mps

    def on_connection(self, channel: LeCreditBasedChannel) -> None:
        self.emit('connection', channel)
        if self.handler:
            self.handler(channel)

    def close(self) -> None:
        if self.psm in self.manager.le_coc_servers:
            del self.manager.le_coc_servers[self.psm]


# -----------------------------------------------------------------------------
class ChannelManager:
    identifiers: Dict[int, int]
    channels: Dict[int, Dict[int, Union[ClassicChannel, LeCreditBasedChannel]]]
    servers: Dict[int, ClassicChannelServer]
    le_coc_channels: Dict[int, Dict[int, LeCreditBasedChannel]]
    le_coc_servers: Dict[int, LeCreditBasedChannelServer]
    le_coc_requests: Dict[int, L2CAP_LE_Credit_Based_Connection_Request]
    fixed_channels: Dict[int, Optional[Callable[[int, bytes], Any]]]
    _host: Optional[Host]
    connection_parameters_update_response: Optional[asyncio.Future[int]]

    def __init__(
        self,
        extended_features: Iterable[int] = (),
        connectionless_mtu: int = L2CAP_DEFAULT_CONNECTIONLESS_MTU,
    ) -> None:
        self._host = None
        self.identifiers = {}  # Incrementing identifier values by connection
        self.channels = {}  # All channels, mapped by connection and source cid
        self.fixed_channels = {  # Fixed channel handlers, mapped by cid
            L2CAP_SIGNALING_CID: None,
            L2CAP_LE_SIGNALING_CID: None,
        }
        self.servers = {}  # Servers accepting connections, by PSM
        self.le_coc_channels = (
            {}
        )  # LE CoC channels, mapped by connection and destination cid
        self.le_coc_servers = {}  # LE CoC - Servers accepting connections, by PSM
        self.le_coc_requests = {}  # LE CoC connection requests, by identifier
        self.extended_features = extended_features
        self.connectionless_mtu = connectionless_mtu
        self.connection_parameters_update_response = None

    @property
    def host(self) -> Host:
        assert self._host
        return self._host

    @host.setter
    def host(self, host: Host) -> None:
        if self._host is not None:
            self._host.remove_listener('disconnection', self.on_disconnection)
        self._host = host
        if host is not None:
            host.on('disconnection', self.on_disconnection)

    def find_channel(self, connection_handle: int, cid: int):
        if connection_channels := self.channels.get(connection_handle):
            return connection_channels.get(cid)

        return None

    def find_le_coc_channel(self, connection_handle: int, cid: int):
        if connection_channels := self.le_coc_channels.get(connection_handle):
            return connection_channels.get(cid)

        return None

    @staticmethod
    def find_free_br_edr_cid(channels: Iterable[int]) -> int:
        # Pick the smallest valid CID that's not already in the list
        # (not necessarily the most efficient algorithm, but the list of CID is
        # very small in practice)
        for cid in range(
            L2CAP_ACL_U_DYNAMIC_CID_RANGE_START, L2CAP_ACL_U_DYNAMIC_CID_RANGE_END + 1
        ):
            if cid not in channels:
                return cid

        raise RuntimeError('no free CID available')

    @staticmethod
    def find_free_le_cid(channels: Iterable[int]) -> int:
        # Pick the smallest valid CID that's not already in the list
        # (not necessarily the most efficient algorithm, but the list of CID is
        # very small in practice)
        for cid in range(
            L2CAP_LE_U_DYNAMIC_CID_RANGE_START, L2CAP_LE_U_DYNAMIC_CID_RANGE_END + 1
        ):
            if cid not in channels:
                return cid

        raise RuntimeError('no free CID')

    def next_identifier(self, connection: Connection) -> int:
        identifier = (self.identifiers.setdefault(connection.handle, 0) + 1) % 256
        self.identifiers[connection.handle] = identifier
        return identifier

    def register_fixed_channel(
        self, cid: int, handler: Callable[[int, bytes], Any]
    ) -> None:
        self.fixed_channels[cid] = handler

    def deregister_fixed_channel(self, cid: int) -> None:
        if cid in self.fixed_channels:
            del self.fixed_channels[cid]

    @deprecated("Please use create_classic_server")
    def register_server(
        self,
        psm: int,
        server: Callable[[ClassicChannel], Any],
    ) -> int:
        return self.create_classic_server(
            handler=server, spec=ClassicChannelSpec(psm=psm)
        ).psm

    def create_classic_server(
        self,
        spec: ClassicChannelSpec,
        handler: Optional[Callable[[ClassicChannel], Any]] = None,
    ) -> ClassicChannelServer:
        if not spec.psm:
            # Find a free PSM
            for candidate in range(
                L2CAP_PSM_DYNAMIC_RANGE_START, L2CAP_PSM_DYNAMIC_RANGE_END + 1, 2
            ):
                if (candidate >> 8) % 2 == 1:
                    continue
                if candidate in self.servers:
                    continue
                spec.psm = candidate
                break
            else:
                raise InvalidStateError('no free PSM')
        else:
            # Check that the PSM isn't already in use
            if spec.psm in self.servers:
                raise ValueError('PSM already in use')

            # Check that the PSM is valid
            if spec.psm % 2 == 0:
                raise ValueError('invalid PSM (not odd)')
            check = spec.psm >> 8
            while check:
                if check % 2 != 0:
                    raise ValueError('invalid PSM')
                check >>= 8

        self.servers[spec.psm] = ClassicChannelServer(self, spec.psm, handler, spec.mtu)

        return self.servers[spec.psm]

    @deprecated("Please use create_le_credit_based_server()")
    def register_le_coc_server(
        self,
        psm: int,
        server: Callable[[LeCreditBasedChannel], Any],
        max_credits: int,
        mtu: int,
        mps: int,
    ) -> int:
        return self.create_le_credit_based_server(
            spec=LeCreditBasedChannelSpec(
                psm=None if psm == 0 else psm, mtu=mtu, mps=mps, max_credits=max_credits
            ),
            handler=server,
        ).psm

    def create_le_credit_based_server(
        self,
        spec: LeCreditBasedChannelSpec,
        handler: Optional[Callable[[LeCreditBasedChannel], Any]] = None,
    ) -> LeCreditBasedChannelServer:
        if not spec.psm:
            # Find a free PSM
            for candidate in range(
                L2CAP_LE_PSM_DYNAMIC_RANGE_START, L2CAP_LE_PSM_DYNAMIC_RANGE_END + 1
            ):
                if candidate in self.le_coc_servers:
                    continue
                spec.psm = candidate
                break
            else:
                raise InvalidStateError('no free PSM')
        else:
            # Check that the PSM isn't already in use
            if spec.psm in self.le_coc_servers:
                raise ValueError('PSM already in use')

        self.le_coc_servers[spec.psm] = LeCreditBasedChannelServer(
            self,
            spec.psm,
            handler,
            max_credits=spec.max_credits,
            mtu=spec.mtu,
            mps=spec.mps,
        )

        return self.le_coc_servers[spec.psm]

    def on_disconnection(self, connection_handle: int, _reason: int) -> None:
        logger.debug(f'disconnection from {connection_handle}, cleaning up channels')
        if connection_handle in self.channels:
            for _, channel in self.channels[connection_handle].items():
                channel.abort()
            del self.channels[connection_handle]
        if connection_handle in self.le_coc_channels:
            for _, channel in self.le_coc_channels[connection_handle].items():
                channel.abort()
            del self.le_coc_channels[connection_handle]
        if connection_handle in self.identifiers:
            del self.identifiers[connection_handle]

    def send_pdu(self, connection, cid: int, pdu: Union[SupportsBytes, bytes]) -> None:
        pdu_str = pdu.hex() if isinstance(pdu, bytes) else str(pdu)
        logger.debug(
            f'{color(">>> Sending L2CAP PDU", "blue")} '
            f'on connection [0x{connection.handle:04X}] (CID={cid}) '
            f'{connection.peer_address}: {pdu_str}'
        )
        self.host.send_l2cap_pdu(connection.handle, cid, bytes(pdu))

    def on_pdu(self, connection: Connection, cid: int, pdu: bytes) -> None:
        if cid in (L2CAP_SIGNALING_CID, L2CAP_LE_SIGNALING_CID):
            # Parse the L2CAP payload into a Control Frame object
            control_frame = L2CAP_Control_Frame.from_bytes(pdu)

            self.on_control_frame(connection, cid, control_frame)
        elif cid in self.fixed_channels:
            handler = self.fixed_channels[cid]
            assert handler is not None
            handler(connection.handle, pdu)
        else:
            if (channel := self.find_channel(connection.handle, cid)) is None:
                logger.warning(
                    color(
                        f'channel not found for 0x{connection.handle:04X}:{cid}', 'red'
                    )
                )
                return

            channel.on_pdu(pdu)

    def send_control_frame(
        self, connection: Connection, cid: int, control_frame: L2CAP_Control_Frame
    ) -> None:
        logger.debug(
            f'{color(">>> Sending L2CAP Signaling Control Frame", "blue")} '
            f'on connection [0x{connection.handle:04X}] (CID={cid}) '
            f'{connection.peer_address}:\n{control_frame}'
        )
        self.host.send_l2cap_pdu(connection.handle, cid, bytes(control_frame))

    def on_control_frame(
        self, connection: Connection, cid: int, control_frame: L2CAP_Control_Frame
    ) -> None:
        logger.debug(
            f'{color("<<< Received L2CAP Signaling Control Frame", "green")} '
            f'on connection [0x{connection.handle:04X}] (CID={cid}) '
            f'{connection.peer_address}:\n{control_frame}'
        )

        # Find the handler method
        handler_name = f'on_{control_frame.name.lower()}'
        handler = getattr(self, handler_name, None)
        if handler:
            try:
                handler(connection, cid, control_frame)
            except Exception as error:
                logger.warning(f'{color("!!! Exception in handler:", "red")} {error}')
                self.send_control_frame(
                    connection,
                    cid,
                    L2CAP_Command_Reject(
                        identifier=control_frame.identifier,
                        reason=L2CAP_COMMAND_NOT_UNDERSTOOD_REASON,
                        data=b'',
                    ),
                )
                raise error
        else:
            logger.error(color('Channel Manager command not handled???', 'red'))
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Command_Reject(
                    identifier=control_frame.identifier,
                    reason=L2CAP_COMMAND_NOT_UNDERSTOOD_REASON,
                    data=b'',
                ),
            )

    def on_l2cap_command_reject(
        self, _connection: Connection, _cid: int, packet
    ) -> None:
        logger.warning(f'{color("!!! Command rejected:", "red")} {packet.reason}')

    def on_l2cap_connection_request(
        self, connection: Connection, cid: int, request
    ) -> None:
        # Check if there's a server for this PSM
        server = self.servers.get(request.psm)
        if server:
            # Find a free CID for this new channel
            connection_channels = self.channels.setdefault(connection.handle, {})
            source_cid = self.find_free_br_edr_cid(connection_channels)
            if source_cid is None:  # Should never happen!
                self.send_control_frame(
                    connection,
                    cid,
                    L2CAP_Connection_Response(
                        identifier=request.identifier,
                        destination_cid=request.source_cid,
                        source_cid=0,
                        # pylint: disable=line-too-long
                        result=L2CAP_Connection_Response.CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE,
                        status=0x0000,
                    ),
                )
                return

            # Create a new channel
            logger.debug(
                f'creating server channel with cid={source_cid} for psm {request.psm}'
            )
            channel = ClassicChannel(
                self, connection, cid, request.psm, source_cid, server.mtu
            )
            connection_channels[source_cid] = channel

            # Notify
            server.on_connection(channel)
            channel.on_connection_request(request)
        else:
            logger.warning(
                f'No server for connection 0x{connection.handle:04X} '
                f'on PSM {request.psm}'
            )
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Connection_Response(
                    identifier=request.identifier,
                    destination_cid=request.source_cid,
                    source_cid=0,
                    # pylint: disable=line-too-long
                    result=L2CAP_Connection_Response.CONNECTION_REFUSED_PSM_NOT_SUPPORTED,
                    status=0x0000,
                ),
            )

    def on_l2cap_connection_response(
        self, connection: Connection, cid: int, response
    ) -> None:
        if (
            channel := self.find_channel(connection.handle, response.source_cid)
        ) is None:
            logger.warning(
                color(
                    f'channel {response.source_cid} not found for '
                    f'0x{connection.handle:04X}:{cid}',
                    'red',
                )
            )
            return

        channel.on_connection_response(response)

    def on_l2cap_configure_request(
        self, connection: Connection, cid: int, request
    ) -> None:
        if (
            channel := self.find_channel(connection.handle, request.destination_cid)
        ) is None:
            logger.warning(
                color(
                    f'channel {request.destination_cid} not found for '
                    f'0x{connection.handle:04X}:{cid}',
                    'red',
                )
            )
            return

        channel.on_configure_request(request)

    def on_l2cap_configure_response(
        self, connection: Connection, cid: int, response
    ) -> None:
        if (
            channel := self.find_channel(connection.handle, response.source_cid)
        ) is None:
            logger.warning(
                color(
                    f'channel {response.source_cid} not found for '
                    f'0x{connection.handle:04X}:{cid}',
                    'red',
                )
            )
            return

        channel.on_configure_response(response)

    def on_l2cap_disconnection_request(
        self, connection: Connection, cid: int, request
    ) -> None:
        if (
            channel := self.find_channel(connection.handle, request.destination_cid)
        ) is None:
            logger.warning(
                color(
                    f'channel {request.destination_cid} not found for '
                    f'0x{connection.handle:04X}:{cid}',
                    'red',
                )
            )
            return

        channel.on_disconnection_request(request)

    def on_l2cap_disconnection_response(
        self, connection: Connection, cid: int, response
    ) -> None:
        if (
            channel := self.find_channel(connection.handle, response.source_cid)
        ) is None:
            logger.warning(
                color(
                    f'channel {response.source_cid} not found for '
                    f'0x{connection.handle:04X}:{cid}',
                    'red',
                )
            )
            return

        channel.on_disconnection_response(response)

    def on_l2cap_echo_request(self, connection: Connection, cid: int, request) -> None:
        logger.debug(f'<<< Echo request: data={request.data.hex()}')
        self.send_control_frame(
            connection,
            cid,
            L2CAP_Echo_Response(identifier=request.identifier, data=request.data),
        )

    def on_l2cap_echo_response(
        self, _connection: Connection, _cid: int, response
    ) -> None:
        logger.debug(f'<<< Echo response: data={response.data.hex()}')
        # TODO notify listeners

    def on_l2cap_information_request(
        self, connection: Connection, cid: int, request
    ) -> None:
        if request.info_type == L2CAP_Information_Request.CONNECTIONLESS_MTU:
            result = L2CAP_Information_Response.SUCCESS
            data = self.connectionless_mtu.to_bytes(2, 'little')
        elif request.info_type == L2CAP_Information_Request.EXTENDED_FEATURES_SUPPORTED:
            result = L2CAP_Information_Response.SUCCESS
            data = sum(self.extended_features).to_bytes(4, 'little')
        elif request.info_type == L2CAP_Information_Request.FIXED_CHANNELS_SUPPORTED:
            result = L2CAP_Information_Response.SUCCESS
            data = sum(1 << cid for cid in self.fixed_channels).to_bytes(8, 'little')
        else:
            result = L2CAP_Information_Response.NOT_SUPPORTED

        self.send_control_frame(
            connection,
            cid,
            L2CAP_Information_Response(
                identifier=request.identifier,
                info_type=request.info_type,
                result=result,
                data=data,
            ),
        )

    def on_l2cap_connection_parameter_update_request(
        self, connection: Connection, cid: int, request
    ):
        if connection.role == BT_CENTRAL_ROLE:
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Connection_Parameter_Update_Response(
                    identifier=request.identifier,
                    result=L2CAP_CONNECTION_PARAMETERS_ACCEPTED_RESULT,
                ),
            )
            self.host.send_command_sync(
                HCI_LE_Connection_Update_Command(
                    connection_handle=connection.handle,
                    connection_interval_min=request.interval_min,
                    connection_interval_max=request.interval_max,
                    max_latency=request.latency,
                    supervision_timeout=request.timeout,
                    min_ce_length=0,
                    max_ce_length=0,
                )  # type: ignore[call-arg]
            )
        else:
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Connection_Parameter_Update_Response(
                    identifier=request.identifier,
                    result=L2CAP_CONNECTION_PARAMETERS_REJECTED_RESULT,
                ),
            )

    async def update_connection_parameters(
        self,
        connection: Connection,
        interval_min: int,
        interval_max: int,
        latency: int,
        timeout: int,
    ) -> int:
        # Check that there isn't already a request pending
        if self.connection_parameters_update_response:
            raise InvalidStateError('request already pending')
        self.connection_parameters_update_response = (
            asyncio.get_running_loop().create_future()
        )
        self.send_control_frame(
            connection,
            L2CAP_LE_SIGNALING_CID,
            L2CAP_Connection_Parameter_Update_Request(
                interval_min=interval_min,
                interval_max=interval_max,
                latency=latency,
                timeout=timeout,
            ),
        )
        return await self.connection_parameters_update_response

    def on_l2cap_connection_parameter_update_response(
        self, connection: Connection, cid: int, response
    ) -> None:
        if self.connection_parameters_update_response:
            self.connection_parameters_update_response.set_result(response.result)
            self.connection_parameters_update_response = None
        else:
            logger.warning(
                color(
                    'received l2cap_connection_parameter_update_response without a pending request',
                    'red',
                )
            )

    def on_l2cap_le_credit_based_connection_request(
        self, connection: Connection, cid: int, request
    ) -> None:
        if request.le_psm in self.le_coc_servers:
            server = self.le_coc_servers[request.le_psm]

            # Check that the CID isn't already used
            le_connection_channels = self.le_coc_channels.setdefault(
                connection.handle, {}
            )
            if request.source_cid in le_connection_channels:
                logger.warning(f'source CID {request.source_cid} already in use')
                self.send_control_frame(
                    connection,
                    cid,
                    L2CAP_LE_Credit_Based_Connection_Response(
                        identifier=request.identifier,
                        destination_cid=0,
                        mtu=server.mtu,
                        mps=server.mps,
                        initial_credits=0,
                        # pylint: disable=line-too-long
                        result=L2CAP_LE_Credit_Based_Connection_Response.CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED,
                    ),
                )
                return

            # Find a free CID for this new channel
            connection_channels = self.channels.setdefault(connection.handle, {})
            source_cid = self.find_free_le_cid(connection_channels)
            if source_cid is None:  # Should never happen!
                self.send_control_frame(
                    connection,
                    cid,
                    L2CAP_LE_Credit_Based_Connection_Response(
                        identifier=request.identifier,
                        destination_cid=0,
                        mtu=server.mtu,
                        mps=server.mps,
                        initial_credits=0,
                        # pylint: disable=line-too-long
                        result=L2CAP_LE_Credit_Based_Connection_Response.CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE,
                    ),
                )
                return

            # Create a new channel
            logger.debug(
                f'creating LE CoC server channel with cid={source_cid} for psm '
                f'{request.le_psm}'
            )
            channel = LeCreditBasedChannel(
                self,
                connection,
                request.le_psm,
                source_cid,
                request.source_cid,
                server.mtu,
                server.mps,
                request.initial_credits,
                request.mtu,
                request.mps,
                server.max_credits,
                True,
            )
            connection_channels[source_cid] = channel
            le_connection_channels[request.source_cid] = channel

            # Respond
            self.send_control_frame(
                connection,
                cid,
                L2CAP_LE_Credit_Based_Connection_Response(
                    identifier=request.identifier,
                    destination_cid=source_cid,
                    mtu=server.mtu,
                    mps=server.mps,
                    initial_credits=server.max_credits,
                    # pylint: disable=line-too-long
                    result=L2CAP_LE_Credit_Based_Connection_Response.CONNECTION_SUCCESSFUL,
                ),
            )

            # Notify
            server.on_connection(channel)
        else:
            logger.info(
                f'No LE server for connection 0x{connection.handle:04X} '
                f'on PSM {request.le_psm}'
            )
            self.send_control_frame(
                connection,
                cid,
                L2CAP_LE_Credit_Based_Connection_Response(
                    identifier=request.identifier,
                    destination_cid=0,
                    mtu=L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MTU,
                    mps=L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MPS,
                    initial_credits=0,
                    # pylint: disable=line-too-long
                    result=L2CAP_LE_Credit_Based_Connection_Response.CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED,
                ),
            )

    def on_l2cap_le_credit_based_connection_response(
        self, connection: Connection, _cid: int, response
    ) -> None:
        # Find the pending request by identifier
        request = self.le_coc_requests.get(response.identifier)
        if request is None:
            logger.warning(color('!!! received response for unknown request', 'red'))
            return
        del self.le_coc_requests[response.identifier]

        # Find the channel for this request
        channel = self.find_channel(connection.handle, request.source_cid)
        if channel is None:
            logger.warning(
                color(
                    'received connection response for an unknown channel '
                    f'(cid={request.source_cid})',
                    'red',
                )
            )
            return

        # Process the response
        channel.on_connection_response(response)

    def on_l2cap_le_flow_control_credit(
        self, connection: Connection, _cid: int, credit
    ) -> None:
        channel = self.find_le_coc_channel(connection.handle, credit.cid)
        if channel is None:
            logger.warning(f'received credits for an unknown channel (cid={credit.cid}')
            return

        channel.on_credits(credit.credits)

    def on_channel_closed(self, channel: ClassicChannel) -> None:
        connection_channels = self.channels.get(channel.connection.handle)
        if connection_channels:
            if channel.source_cid in connection_channels:
                del connection_channels[channel.source_cid]

    @deprecated("Please use create_le_credit_based_channel()")
    async def open_le_coc(
        self, connection: Connection, psm: int, max_credits: int, mtu: int, mps: int
    ) -> LeCreditBasedChannel:
        return await self.create_le_credit_based_channel(
            connection=connection,
            spec=LeCreditBasedChannelSpec(
                psm=psm, max_credits=max_credits, mtu=mtu, mps=mps
            ),
        )

    async def create_le_credit_based_channel(
        self,
        connection: Connection,
        spec: LeCreditBasedChannelSpec,
    ) -> LeCreditBasedChannel:
        # Find a free CID for the new channel
        connection_channels = self.channels.setdefault(connection.handle, {})
        source_cid = self.find_free_le_cid(connection_channels)
        if source_cid is None:  # Should never happen!
            raise RuntimeError('all CIDs already in use')

        if spec.psm is None:
            raise ValueError('PSM cannot be None')

        # Create the channel
        logger.debug(f'creating coc channel with cid={source_cid} for psm {spec.psm}')
        channel = LeCreditBasedChannel(
            manager=self,
            connection=connection,
            le_psm=spec.psm,
            source_cid=source_cid,
            destination_cid=0,
            mtu=spec.mtu,
            mps=spec.mps,
            credits=0,
            peer_mtu=0,
            peer_mps=0,
            peer_credits=spec.max_credits,
            connected=False,
        )
        connection_channels[source_cid] = channel

        # Connect
        try:
            await channel.connect()
        except Exception as error:
            logger.warning(f'connection failed: {error}')
            del connection_channels[source_cid]
            raise

        # Remember the channel by source CID and destination CID
        le_connection_channels = self.le_coc_channels.setdefault(connection.handle, {})
        le_connection_channels[channel.destination_cid] = channel

        return channel

    @deprecated("Please use create_classic_channel()")
    async def connect(self, connection: Connection, psm: int) -> ClassicChannel:
        return await self.create_classic_channel(
            connection=connection, spec=ClassicChannelSpec(psm=psm)
        )

    async def create_classic_channel(
        self, connection: Connection, spec: ClassicChannelSpec
    ) -> ClassicChannel:
        # NOTE: this implementation hard-codes BR/EDR

        # Find a free CID for a new channel
        connection_channels = self.channels.setdefault(connection.handle, {})
        source_cid = self.find_free_br_edr_cid(connection_channels)
        if source_cid is None:  # Should never happen!
            raise RuntimeError('all CIDs already in use')

        if spec.psm is None:
            raise ValueError('PSM cannot be None')

        # Create the channel
        logger.debug(
            f'creating client channel with cid={source_cid} for psm {spec.psm}'
        )
        channel = ClassicChannel(
            self,
            connection,
            L2CAP_SIGNALING_CID,
            spec.psm,
            source_cid,
            spec.mtu,
        )
        connection_channels[source_cid] = channel

        # Connect
        try:
            await channel.connect()
        except Exception as e:
            del connection_channels[source_cid]
            raise e

        return channel


# -----------------------------------------------------------------------------
# Deprecated Classes
# -----------------------------------------------------------------------------


class Channel(ClassicChannel):
    @deprecated("Please use ClassicChannel")
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class LeConnectionOrientedChannel(LeCreditBasedChannel):
    @deprecated("Please use LeCreditBasedChannel")
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
