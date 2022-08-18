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
import asyncio
import logging
import struct

from colors import color
from pyee import EventEmitter

from .core import BT_CENTRAL_ROLE, InvalidStateError, ProtocolError
from .hci import (HCI_LE_Connection_Update_Command, HCI_Object, key_with_value,
                  name_or_number)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
L2CAP_SIGNALING_CID    = 0x01
L2CAP_LE_SIGNALING_CID = 0x05

L2CAP_MIN_LE_MTU     = 23
L2CAP_MIN_BR_EDR_MTU = 48

L2CAP_DEFAULT_MTU = 2048  # Default value for the MTU we are willing to accept

# See Bluetooth spec @ Vol 3, Part A - Table 2.1: CID name space on ACL-U, ASB-U, and AMP-U logical links
L2CAP_ACL_U_DYNAMIC_CID_RANGE_START = 0x0040
L2CAP_ACL_U_DYNAMIC_CID_RANGE_END   = 0xFFFF

# See Bluetooth spec @ Vol 3, Part A - Table 2.2: CID name space on LE-U logical link
L2CAP_LE_U_DYNAMIC_CID_RANGE_START = 0x0040
L2CAP_LE_U_DYNAMIC_CID_RANGE_START = 0x007F

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

L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MTU = 2048
L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MPS = 2048

L2CAP_MAXIMUM_TRANSMISSION_UNIT_CONFIGURATION_OPTION_TYPE = 0x01

L2CAP_MTU_CONFIGURATION_PARAMETER_TYPE = 0x01


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class L2CAP_PDU:
    '''
    See Bluetooth spec @ Vol 3, Part A - 3 DATA PACKET FORMAT
    '''

    @staticmethod
    def from_bytes(data):
        # Sanity check
        if len(data) < 4:
            raise ValueError('not enough data for L2CAP header')

        _, l2cap_pdu_cid = struct.unpack_from('<HH', data, 0)
        l2cap_pdu_payload = data[4:]

        return L2CAP_PDU(l2cap_pdu_cid, l2cap_pdu_payload)

    def to_bytes(self):
        header = struct.pack('<HH', len(self.payload), self.cid)
        return header + self.payload

    def __init__(self, cid, payload):
        self.cid     = cid
        self.payload = payload

    def __bytes__(self):
        return self.to_bytes()

    def __str__(self):
        return f'{color("L2CAP", "green")} [CID={self.cid}]: {self.payload.hex()}'


# -----------------------------------------------------------------------------
class L2CAP_Control_Frame:
    '''
    See Bluetooth spec @ Vol 3, Part A - 4 SIGNALING PACKET FORMATS
    '''
    classes = {}
    code = 0

    @staticmethod
    def from_bytes(pdu):
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
            logger.warn(color(f'!!! length mismatch: expected {len(pdu) - 4} but got {length}', 'red'))
        if hasattr(self, 'fields'):
            self.init_from_bytes(pdu, 4)
        return self

    @staticmethod
    def code_name(code):
        return name_or_number(L2CAP_CONTROL_FRAME_NAMES, code)

    @staticmethod
    def decode_configuration_options(data):
        options = []
        while len(data) >= 2:
            type = data[0]
            length = data[1]
            value = data[2:2 + length]
            data = data[2 + length:]
            options.append((type, value))

        return options

    @staticmethod
    def encode_configuration_options(options):
        return b''.join([bytes([option[0], len(option[1])]) + option[1] for option in options])

    @staticmethod
    def subclass(fields):
        def inner(cls):
            cls.name = cls.__name__.upper()
            cls.code = key_with_value(L2CAP_CONTROL_FRAME_NAMES, cls.name)
            if cls.code is None:
                raise KeyError(f'Control Frame name {cls.name} not found in L2CAP_CONTROL_FRAME_NAMES')
            cls.fields = fields

            # Register a factory for this class
            L2CAP_Control_Frame.classes[cls.code] = cls

            return cls

        return inner

    def __init__(self, pdu=None, **kwargs):
        self.identifier = kwargs.get('identifier', 0)
        if hasattr(self, 'fields') and kwargs:
            HCI_Object.init_from_fields(self, self.fields, kwargs)
        if pdu is None:
            data = HCI_Object.dict_to_bytes(kwargs, self.fields)
            pdu = bytes([self.code, self.identifier]) + struct.pack('<H', len(data)) + data
        self.pdu = pdu

    def init_from_bytes(self, pdu, offset):
        return HCI_Object.init_from_bytes(self, pdu, offset, self.fields)

    def to_bytes(self):
        return self.pdu

    def __bytes__(self):
        return self.to_bytes()

    def __str__(self):
        result = f'{color(self.name, "yellow")} [ID={self.identifier}]'
        if fields := getattr(self, 'fields', None):
            result += ':\n' + HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if len(self.pdu) > 1:
                result += f': {self.pdu.hex()}'
        return result


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('reason', {'size': 2, 'mapper': lambda x: L2CAP_Command_Reject.reason_name(x)}),
    ('data',   '*')
])
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
        INVALID_CID_IN_REQUEST: 'INVALID_CID_IN_REQUEST'
    }

    @staticmethod
    def reason_name(reason):
        return name_or_number(L2CAP_Command_Reject.REASON_NAMES, reason)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('psm',        2),
    ('source_cid', 2)
])
class L2CAP_Connection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.2 CONNECTION REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('destination_cid', 2),
    ('source_cid',      2),
    ('result',          {'size': 2, 'mapper': lambda x: L2CAP_Connection_Response.result_name(x)}),
    ('status',          2)
])
class L2CAP_Connection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.3 CONNECTION RESPONSE
    '''

    CONNECTION_SUCCESSFUL                               = 0x0000
    CONNECTION_PENDING                                  = 0x0001
    CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED             = 0x0002
    CONNECTION_REFUSED_SECURITY_BLOCK                   = 0x0003
    CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE           = 0x0004
    CONNECTION_REFUSED_INVALID_SOURCE_CID               = 0x0006
    CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED     = 0x0007
    CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS          = 0x000B

    CONNECTION_RESULT_NAMES = {
        CONNECTION_SUCCESSFUL:                           'CONNECTION_SUCCESSFUL',
        CONNECTION_PENDING:                              'CONNECTION_PENDING',
        CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED:         'CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED',
        CONNECTION_REFUSED_SECURITY_BLOCK:               'CONNECTION_REFUSED_SECURITY_BLOCK',
        CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE:       'CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE',
        CONNECTION_REFUSED_INVALID_SOURCE_CID:           'CONNECTION_REFUSED_INVALID_SOURCE_CID',
        CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED: 'CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED',
        CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS:      'CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS'
    }

    @staticmethod
    def result_name(result):
        return name_or_number(L2CAP_Connection_Response.CONNECTION_RESULT_NAMES, result)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('destination_cid', 2),
    ('flags',           2),
    ('options',         '*')
])
class L2CAP_Configure_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.4 CONFIGURATION REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('source_cid', 2),
    ('flags',      2),
    ('result',     {'size': 2, 'mapper': lambda x: L2CAP_Configure_Response.result_name(x)}),
    ('options',    '*')
])
class L2CAP_Configure_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.5 CONFIGURATION RESPONSE
    '''

    SUCCESS                         = 0x0000
    FAILURE_UNACCEPTABLE_PARAMETERS = 0x0001
    FAILURE_REJECTED                = 0x0002
    FAILURE_UNKNOWN_OPTIONS         = 0x0003
    PENDING                         = 0x0004
    FAILURE_FLOW_SPEC_REJECTED      = 0x0005

    RESULT_NAMES = {
        SUCCESS:                         'SUCCESS',
        FAILURE_UNACCEPTABLE_PARAMETERS: 'FAILURE_UNACCEPTABLE_PARAMETERS',
        FAILURE_REJECTED:                'FAILURE_REJECTED',
        FAILURE_UNKNOWN_OPTIONS:         'FAILURE_UNKNOWN_OPTIONS',
        PENDING:                         'PENDING',
        FAILURE_FLOW_SPEC_REJECTED:      'FAILURE_FLOW_SPEC_REJECTED'
    }

    @staticmethod
    def result_name(result):
        return name_or_number(L2CAP_Configure_Response.RESULT_NAMES, result)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('destination_cid', 2),
    ('source_cid',      2)
])
class L2CAP_Disconnection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.6 DISCONNECTION REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('destination_cid', 2),
    ('source_cid',      2)
])
class L2CAP_Disconnection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.7 DISCONNECTION RESPONSE
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('data', '*')
])
class L2CAP_Echo_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.8 ECHO REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('data', '*')
])
class L2CAP_Echo_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.9 ECHO RESPONSE
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('info_type', {'size': 2, 'mapper': lambda x: L2CAP_Information_Request.info_type_name(x)})
])
class L2CAP_Information_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.10 INFORMATION REQUEST
    '''

    CONNECTIONLESS_MTU          = 0x0001
    EXTENDED_FEATURES_SUPPORTED = 0x0002
    FIXED_CHANNELS_SUPPORTED    = 0x0003

    EXTENDED_FEATURE_FLOW_MODE_CONTROL                 = 0x0001
    EXTENDED_FEATURE_RETRANSMISSION_MODE               = 0x0002
    EXTENDED_FEATURE_BIDIRECTIONAL_QOS                 = 0x0004
    EXTENDED_FEATURE_ENHANCED_RETRANSMISSION_MODE      = 0x0008
    EXTENDED_FEATURE_STREAMING_MODE                    = 0x0010
    EXTENDED_FEATURE_FCS_OPTION                        = 0x0020
    EXTENDED_FEATURE_EXTENDED_FLOW_SPEC                = 0x0040
    EXTENDED_FEATURE_FIXED_CHANNELS                    = 0x0080
    EXTENDED_FEATURE_EXTENDED_WINDOW_SIZE              = 0x0100
    EXTENDED_FEATURE_UNICAST_CONNECTIONLESS_DATA       = 0x0200
    EXTENDED_FEATURE_ENHANCED_CREDIT_BASE_FLOW_CONTROL = 0x0400

    INFO_TYPE_NAMES = {
        CONNECTIONLESS_MTU:          'CONNECTIONLESS_MTU',
        EXTENDED_FEATURES_SUPPORTED: 'EXTENDED_FEATURES_SUPPORTED',
        FIXED_CHANNELS_SUPPORTED:    'FIXED_CHANNELS_SUPPORTED'
    }

    @staticmethod
    def info_type_name(info_type):
        return name_or_number(L2CAP_Information_Request.INFO_TYPE_NAMES, info_type)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('info_type', {'size': 2, 'mapper': L2CAP_Information_Request.info_type_name}),
    ('result',    {'size': 2, 'mapper': lambda x: L2CAP_Information_Response.result_name(x)}),
    ('data',     '*')
])
class L2CAP_Information_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.11 INFORMATION RESPONSE
    '''
    SUCCESS       = 0x00
    NOT_SUPPORTED = 0x01

    RESULT_NAMES = {
        SUCCESS:       'SUCCESS',
        NOT_SUPPORTED: 'NOT_SUPPORTED'
    }

    @staticmethod
    def result_name(result):
        return name_or_number(L2CAP_Information_Response.RESULT_NAMES, result)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('interval_min',       2),
    ('interval_max',       2),
    ('slave_latency',      2),
    ('timeout_multiplier', 2)
])
class L2CAP_Connection_Parameter_Update_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.20 CONNECTION PARAMETER UPDATE REQUEST
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('result', 2)
])
class L2CAP_Connection_Parameter_Update_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.21 CONNECTION PARAMETER UPDATE RESPONSE
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('le_psm', 2),
    ('source_cid', 2),
    ('mtu', 2),
    ('mps', 2),
    ('initial_credits', 2)
])
class L2CAP_LE_Credit_Based_Connection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.22 LE CREDIT BASED CONNECTION REQUEST (CODE 0x14)
    '''


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('destination_cid', 2),
    ('mtu',             2),
    ('mps',             2),
    ('initial_credits', 2),
    ('result',          {'size': 2, 'mapper': lambda x: L2CAP_LE_Credit_Based_Connection_Response.result_name(x)})
])
class L2CAP_LE_Credit_Based_Connection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.23 LE CREDIT BASED CONNECTION RESPONSE (CODE 0x15)
    '''

    CONNECTION_SUCCESSFUL                               = 0x0000
    CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED             = 0x0002
    CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE           = 0x0004
    CONNECTION_REFUSED_INSUFFICIENT_AUTHENTICATION      = 0x0005
    CONNECTION_REFUSED_INSUFFICIENT_AUTHORIZATION       = 0x0006
    CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0x0007
    CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION          = 0x0008
    CONNECTION_REFUSED_INVALID_SOURCE_CID               = 0x0009
    CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED     = 0x000A
    CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS          = 0x000B

    CONNECTION_RESULT_NAMES = {
        CONNECTION_SUCCESSFUL:                               'CONNECTION_SUCCESSFUL',
        CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED:             'CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED',
        CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE:           'CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE',
        CONNECTION_REFUSED_INSUFFICIENT_AUTHENTICATION:      'CONNECTION_REFUSED_INSUFFICIENT_AUTHENTICATION',
        CONNECTION_REFUSED_INSUFFICIENT_AUTHORIZATION:       'CONNECTION_REFUSED_INSUFFICIENT_AUTHORIZATION',
        CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION_KEY_SIZE: 'CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION_KEY_SIZE',
        CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION:          'CONNECTION_REFUSED_INSUFFICIENT_ENCRYPTION',
        CONNECTION_REFUSED_INVALID_SOURCE_CID:               'CONNECTION_REFUSED_INVALID_SOURCE_CID',
        CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED:     'CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED',
        CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS:          'CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS'
    }

    @staticmethod
    def result_name(result):
        return name_or_number(L2CAP_LE_Credit_Based_Connection_Response.CONNECTION_RESULT_NAMES, result)


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass([
    ('cid', 2),
    ('credits', 2)
])
class L2CAP_LE_Flow_Control_Credit(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.24 LE FLOW CONTROL CREDIT (CODE 0x16)
    '''


# -----------------------------------------------------------------------------
class Channel(EventEmitter):
    # States
    CLOSED            = 0x00
    WAIT_CONNECT      = 0x01
    WAIT_CONNECT_RSP  = 0x02
    OPEN              = 0x03
    WAIT_DISCONNECT   = 0x04
    WAIT_CREATE       = 0x05
    WAIT_CREATE_RSP   = 0x06
    WAIT_MOVE         = 0x07
    WAIT_MOVE_RSP     = 0x08
    WAIT_MOVE_CONFIRM = 0x09
    WAIT_CONFIRM_RSP  = 0x0A

    # CONFIG substates
    WAIT_CONFIG         = 0x10
    WAIT_SEND_CONFIG    = 0x11
    WAIT_CONFIG_REQ_RSP = 0x12
    WAIT_CONFIG_RSP     = 0x13
    WAIT_CONFIG_REQ     = 0x14
    WAIT_IND_FINAL_RSP  = 0x15
    WAIT_FINAL_RSP      = 0x16
    WAIT_CONTROL_IND    = 0x17

    STATE_NAMES = {
        CLOSED:            'CLOSED',
        WAIT_CONNECT:      'WAIT_CONNECT',
        WAIT_CONNECT_RSP:  'WAIT_CONNECT_RSP',
        OPEN:              'OPEN',
        WAIT_DISCONNECT:   'WAIT_DISCONNECT',
        WAIT_CREATE:       'WAIT_CREATE',
        WAIT_CREATE_RSP:   'WAIT_CREATE_RSP',
        WAIT_MOVE:         'WAIT_MOVE',
        WAIT_MOVE_RSP:     'WAIT_MOVE_RSP',
        WAIT_MOVE_CONFIRM: 'WAIT_MOVE_CONFIRM',
        WAIT_CONFIRM_RSP:  'WAIT_CONFIRM_RSP',

        WAIT_CONFIG:         'WAIT_CONFIG',
        WAIT_SEND_CONFIG:    'WAIT_SEND_CONFIG',
        WAIT_CONFIG_REQ_RSP: 'WAIT_CONFIG_REQ_RSP',
        WAIT_CONFIG_RSP:     'WAIT_CONFIG_RSP',
        WAIT_CONFIG_REQ:     'WAIT_CONFIG_REQ',
        WAIT_IND_FINAL_RSP:  'WAIT_IND_FINAL_RSP',
        WAIT_FINAL_RSP:      'WAIT_FINAL_RSP',
        WAIT_CONTROL_IND:    'WAIT_CONTROL_IND'
    }

    def __init__(self, manager, connection, signaling_cid, psm, source_cid, mtu):
        super().__init__()
        self.manager           = manager
        self.connection        = connection
        self.signaling_cid     = signaling_cid
        self.state             = Channel.CLOSED
        self.mtu               = mtu
        self.psm               = psm
        self.source_cid        = source_cid
        self.destination_cid   = 0
        self.response          = None
        self.connection_result = None
        self.sink              = None

    def change_state(self, new_state):
        logger.debug(f'{self} state change -> {color(Channel.STATE_NAMES[new_state], "cyan")}')
        self.state = new_state

    def send_pdu(self, pdu):
        self.manager.send_pdu(self.connection, self.destination_cid, pdu)

    async def send_request(self, request):
        # Check that there isn't already a request pending
        if self.response:
            raise InvalidStateError('request already pending')
        if self.state != Channel.OPEN:
            raise InvalidStateError('channel not open')

        self.response = asyncio.get_running_loop().create_future()
        self.send_pdu(request)
        return await self.response

    def on_pdu(self, pdu):
        if self.response:
            self.response.set_result(pdu)
            self.response = None
        elif self.sink:
            self.sink(pdu)
        else:
            logger.warn(color('received pdu without a pending request or sink', 'red'))

    def send_control_frame(self, frame):
        self.manager.send_control_frame(self.connection, self.signaling_cid, frame)

    async def connect(self):
        if self.state != Channel.CLOSED:
            raise InvalidStateError('invalid state')

        self.change_state(Channel.WAIT_CONNECT_RSP)
        self.send_control_frame(
            L2CAP_Connection_Request(
                identifier = self.manager.next_identifier(self.connection),
                psm        = self.psm,
                source_cid = self.source_cid
            )
        )

        # Create a future to wait for the state machine to get to a success or error state
        self.connection_result = asyncio.get_running_loop().create_future()
        return await self.connection_result

    async def disconnect(self):
        if self.state != Channel.OPEN:
            raise InvalidStateError('invalid state')

        self.change_state(Channel.WAIT_DISCONNECT)
        self.send_control_frame(
            L2CAP_Disconnection_Request(
                identifier      = self.manager.next_identifier(self.connection),
                destination_cid = self.destination_cid,
                source_cid      = self.source_cid
            )
        )

        # Create a future to wait for the state machine to get to a success or error state
        self.disconnection_result = asyncio.get_running_loop().create_future()
        return await self.disconnection_result

    def send_configure_request(self):
        options = L2CAP_Control_Frame.encode_configuration_options([(
            L2CAP_MAXIMUM_TRANSMISSION_UNIT_CONFIGURATION_OPTION_TYPE,
            struct.pack('<H', L2CAP_DEFAULT_MTU)
        )])
        self.send_control_frame(
            L2CAP_Configure_Request(
                identifier      = self.manager.next_identifier(self.connection),
                destination_cid = self.destination_cid,
                flags           = 0x0000,
                options         = options
            )
        )

    def on_connection_request(self, request):
        self.destination_cid = request.source_cid
        self.change_state(Channel.WAIT_CONNECT)
        self.send_control_frame(
            L2CAP_Connection_Response(
                identifier      = request.identifier,
                destination_cid = self.source_cid,
                source_cid      = self.destination_cid,
                result          = L2CAP_Connection_Response.CONNECTION_SUCCESSFUL,
                status          = 0x0000
            )
        )
        self.change_state(Channel.WAIT_CONFIG)
        self.send_configure_request()
        self.change_state(Channel.WAIT_CONFIG_REQ_RSP)

    def on_connection_response(self, response):
        if self.state != Channel.WAIT_CONNECT_RSP:
            logger.warn(color('invalid state', 'red'))
            return

        if response.result == L2CAP_Connection_Response.CONNECTION_SUCCESSFUL:
            self.destination_cid = response.destination_cid
            self.change_state(Channel.WAIT_CONFIG)
            self.send_configure_request()
            self.change_state(Channel.WAIT_CONFIG_REQ_RSP)
        elif response.result == L2CAP_Connection_Response.CONNECTION_PENDING:
            pass
        else:
            self.change_state(Channel.CLOSED)
            self.connection_result.set_exception(
                ProtocolError(
                    response.result,
                    'l2cap',
                    L2CAP_Connection_Response.result_name(response.result))
            )
            self.connection_result = None

    def on_configure_request(self, request):
        if (
            self.state != Channel.WAIT_CONFIG and
            self.state != Channel.WAIT_CONFIG_REQ and
            self.state != Channel.WAIT_CONFIG_REQ_RSP
        ):
            logger.warn(color('invalid state', 'red'))
            return

        # Decode the options
        options = L2CAP_Control_Frame.decode_configuration_options(request.options)
        for option in options:
            if option[0] == L2CAP_MTU_CONFIGURATION_PARAMETER_TYPE:
                self.mtu = struct.unpack('<H', option[1])[0]
                logger.debug(f'MTU = {self.mtu}')

        self.send_control_frame(
            L2CAP_Configure_Response(
                identifier = request.identifier,
                source_cid = self.destination_cid,
                flags      = 0x0000,
                result     = L2CAP_Configure_Response.SUCCESS,
                options    = request.options  # TODO: don't accept everthing blindly
            )
        )
        if self.state == Channel.WAIT_CONFIG:
            self.change_state(Channel.WAIT_SEND_CONFIG)
            self.send_configure_request()
            self.change_state(Channel.WAIT_CONFIG_RSP)
        elif self.state == Channel.WAIT_CONFIG_REQ:
            self.change_state(Channel.OPEN)
            if self.connection_result:
                self.connection_result.set_result(None)
                self.connection_result = None
            self.emit('open')
        elif self.state == Channel.WAIT_CONFIG_REQ_RSP:
            self.change_state(Channel.WAIT_CONFIG_RSP)

    def on_configure_response(self, response):
        if response.result == L2CAP_Configure_Response.SUCCESS:
            if self.state == Channel.WAIT_CONFIG_REQ_RSP:
                self.change_state(Channel.WAIT_CONFIG_REQ)
            elif self.state == Channel.WAIT_CONFIG_RSP or self.state == Channel.WAIT_CONTROL_IND:
                self.change_state(Channel.OPEN)
                if self.connection_result:
                    self.connection_result.set_result(None)
                    self.connection_result = None
                self.emit('open')
            else:
                logger.warn(color('invalid state', 'red'))
        elif response.result == L2CAP_Configure_Response.FAILURE_UNACCEPTABLE_PARAMETERS:
            # Re-configure with what's suggested in the response
            self.send_control_frame(
                L2CAP_Configure_Request(
                    identifier      = self.manager.next_identifier(self.connection),
                    destination_cid = self.destination_cid,
                    flags           = 0x0000,
                    options         = response.options
                )
            )
        else:
            logger.warn(color(f'!!! configuration rejected: {L2CAP_Configure_Response.result_name(response.result)}', 'red'))
            # TODO: decide how to fail gracefully

    def on_disconnection_request(self, request):
        if self.state == Channel.OPEN or self.state == Channel.WAIT_DISCONNECT:
            self.send_control_frame(
                L2CAP_Disconnection_Response(
                    identifier      = request.identifier,
                    destination_cid = request.destination_cid,
                    source_cid      = request.source_cid
                )
            )
            self.change_state(Channel.CLOSED)
            self.emit('close')
            self.manager.on_channel_closed(self)
        else:
            logger.warn(color('invalid state', 'red'))

    def on_disconnection_response(self, response):
        if self.state != Channel.WAIT_DISCONNECT:
            logger.warn(color('invalid state', 'red'))
            return

        if response.destination_cid != self.destination_cid or response.source_cid != self.source_cid:
            logger.warn('unexpected source or destination CID')
            return

        self.change_state(Channel.CLOSED)
        if self.disconnection_result:
            self.disconnection_result.set_result(None)
            self.disconnection_result = None
        self.emit('close')
        self.manager.on_channel_closed(self)

    def __str__(self):
        return f'Channel({self.source_cid}->{self.destination_cid}, PSM={self.psm}, MTU={self.mtu}, state={Channel.STATE_NAMES[self.state]})'


# -----------------------------------------------------------------------------
class ChannelManager:
    def __init__(self, extended_features=None, connectionless_mtu=1024):
        self.host               = None
        self.channels           = {}  # Channels, mapped by connection and cid
        # Fixed channel handlers, mapped by cid
        self.fixed_channels     = {
            L2CAP_SIGNALING_CID: None, L2CAP_LE_SIGNALING_CID: None}
        self.identifiers        = {}  # Incrementing identifier values by connection
        self.servers            = {}  # Servers accepting connections, by PSM
        self.extended_features  = [] if extended_features is None else extended_features
        self.connectionless_mtu = connectionless_mtu

    def find_channel(self, connection_handle, cid):
        if connection_channels := self.channels.get(connection_handle):
            return connection_channels.get(cid)

    @staticmethod
    def find_free_br_edr_cid(channels):
        # Pick the smallest valid CID that's not already in the list
        # (not necessarily the most efficient algorithm, but the list of CID is
        # very small in practice)
        for cid in range(L2CAP_ACL_U_DYNAMIC_CID_RANGE_START, L2CAP_ACL_U_DYNAMIC_CID_RANGE_END + 1):
            if cid not in channels:
                return cid

    def next_identifier(self, connection):
        identifier = (self.identifiers.setdefault(connection.handle, 0) + 1) % 256
        self.identifiers[connection.handle] = identifier
        return identifier
    
    def register_fixed_channel(self, cid, handler):
        self.fixed_channels[cid] = handler
    
    def deregister_fixed_channel(self, cid):
        if cid in self.fixed_channels:
            del self.fixed_channels[cid]

    def register_server(self, psm, server):
        self.servers[psm] = server

    def send_pdu(self, connection, cid, pdu):
        pdu_str = pdu.hex() if type(pdu) is bytes else str(pdu)
        logger.debug(f'{color(">>> Sending L2CAP PDU", "blue")} on connection [0x{connection.handle:04X}] (CID={cid}) {connection.peer_address}: {pdu_str}')
        self.host.send_l2cap_pdu(connection.handle, cid, bytes(pdu))

    def on_pdu(self, connection, cid, pdu):
        if cid == L2CAP_SIGNALING_CID or cid == L2CAP_LE_SIGNALING_CID:
            # Parse the L2CAP payload into a Control Frame object
            control_frame = L2CAP_Control_Frame.from_bytes(pdu)

            self.on_control_frame(connection, cid, control_frame)
        elif cid in self.fixed_channels:
            self.fixed_channels[cid](connection.handle, pdu)
        else:
            if (channel := self.find_channel(connection.handle, cid)) is None:
                logger.warn(color(f'channel not found for 0x{connection.handle:04X}:{cid}', 'red'))
                return

            channel.on_pdu(pdu)

    def send_control_frame(self, connection, cid, control_frame):
        logger.debug(f'{color(">>> Sending L2CAP Signaling Control Frame", "blue")} on connection [0x{connection.handle:04X}] (CID={cid}) {connection.peer_address}:\n{control_frame}')
        self.host.send_l2cap_pdu(connection.handle, cid, bytes(control_frame))

    def on_control_frame(self, connection, cid, control_frame):
        logger.debug(f'{color("<<< Received L2CAP Signaling Control Frame", "green")} on connection [0x{connection.handle:04X}] (CID={cid}) {connection.peer_address}:\n{control_frame}')

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
                        identifier = control_frame.identifier,
                        reason     = L2CAP_COMMAND_NOT_UNDERSTOOD_REASON,
                        data       = b''
                    )
                )
                raise error
        else:
            logger.error(color('Channel Manager command not handled???', 'red'))
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Command_Reject(
                    identifier = control_frame.identifier,
                    reason     = L2CAP_COMMAND_NOT_UNDERSTOOD_REASON,
                    data       = b''
                )
            )

    def on_l2cap_command_reject(self, connection, cid, packet):
        logger.warning(f'{color("!!! Command rejected:", "red")} {packet.reason}')
        pass

    def on_l2cap_connection_request(self, connection, cid, request):
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
                        identifier      = request.identifier,
                        destination_cid = request.source_cid,
                        source_cid      = 0,
                        result          = L2CAP_Connection_Response.CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE,
                        status          = 0x0000
                    )
                )
                return

            # Create a new channel
            logger.debug(f'creating server channel with cid={source_cid} for psm {request.psm}')
            channel = Channel(self, connection, cid, request.psm, source_cid, L2CAP_MIN_BR_EDR_MTU)
            connection_channels[source_cid] = channel

            # Notify
            server(channel)
            channel.on_connection_request(request)
        else:
            logger.warn(f'No server for connection 0x{connection.handle:04X} on PSM {request.psm}')
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Connection_Response(
                    identifier      = request.identifier,
                    destination_cid = request.source_cid,
                    source_cid      = 0,
                    result          = L2CAP_Connection_Response.CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED,
                    status          = 0x0000
                )
            )

    def on_l2cap_connection_response(self, connection, cid, response):
        if (channel := self.find_channel(connection.handle, response.source_cid)) is None:
            logger.warn(color(f'channel {response.source_cid} not found for 0x{connection.handle:04X}:{cid}', 'red'))
            return

        channel.on_connection_response(response)

    def on_l2cap_configure_request(self, connection, cid, request):
        if (channel := self.find_channel(connection.handle, request.destination_cid)) is None:
            logger.warn(color(f'channel {request.destination_cid} not found for 0x{connection.handle:04X}:{cid}', 'red'))
            return

        channel.on_configure_request(request)

    def on_l2cap_configure_response(self, connection, cid, response):
        if (channel := self.find_channel(connection.handle, response.source_cid)) is None:
            logger.warn(color(f'channel {response.source_cid} not found for 0x{connection.handle:04X}:{cid}', 'red'))
            return

        channel.on_configure_response(response)

    def on_l2cap_disconnection_request(self, connection, cid, request):
        if (channel := self.find_channel(connection.handle, request.destination_cid)) is None:
            logger.warn(color(f'channel {request.destination_cid} not found for 0x{connection.handle:04X}:{cid}', 'red'))
            return

        channel.on_disconnection_request(request)

    def on_l2cap_disconnection_response(self, connection, cid, response):
        if (channel := self.find_channel(connection.handle, response.source_cid)) is None:
            logger.warn(color(f'channel {response.source_cid} not found for 0x{connection.handle:04X}:{cid}', 'red'))
            return

        channel.on_disconnection_response(response)

    def on_l2cap_echo_request(self, connection, cid, request):
        logger.debug(f'<<< Echo request: data={request.data.hex()}')
        self.send_control_frame(
            connection,
            cid,
            L2CAP_Echo_Response(
                identifier = request.identifier,
                data       = request.data
            )
        )

    def on_l2cap_echo_response(self, connection, cid, response):
        logger.debug(f'<<< Echo response: data={response.data.hex()}')
        # TODO notify listeners

    def on_l2cap_information_request(self, connection, cid, request):
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
            result = L2CAP_Information_Request.NO_SUPPORTED

        self.send_control_frame(
            connection,
            cid,
            L2CAP_Information_Response(
                identifier = request.identifier,
                info_type  = request.info_type,
                result     = result,
                data       = data
            )
        )

    def on_l2cap_connection_parameter_update_request(self, connection, cid, request):
        if connection.role == BT_CENTRAL_ROLE:
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Connection_Parameter_Update_Response(
                    identifier = request.identifier,
                    result     = L2CAP_CONNECTION_PARAMETERS_ACCEPTED_RESULT
                )
            )
            self.host.send_command_sync(HCI_LE_Connection_Update_Command(
                connection_handle   = connection.handle,
                conn_interval_min   = request.interval_min,
                conn_interval_max   = request.interval_max,
                conn_latency        = request.slave_latency,
                supervision_timeout = request.timeout_multiplier,
                minimum_ce_length   = 0,
                maximum_ce_length   = 0
            ))
        else:
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Connection_Parameter_Update_Response(
                    identifier = request.identifier,
                    result     = L2CAP_CONNECTION_PARAMETERS_REJECTED_RESULT
                )
            )

    def on_l2cap_connection_parameter_update_response(self, connection, cid, response):
        pass

    def on_l2cap_le_credit_based_connection_request(self, connection, cid, request):
        # FIXME: temp fixed values
        self.send_control_frame(
            connection,
            cid,
            L2CAP_LE_Credit_Based_Connection_Response(
                identifier      = request.identifier,
                destination_cid = 194,  # FIXME: for testing only
                mtu             = L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MTU,
                mps             = L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MPS,
                initial_credits = 3,  # FIXME: for testing only
                result          = L2CAP_LE_Credit_Based_Connection_Response.CONNECTION_SUCCESSFUL
            )
        )

    def on_l2cap_le_flow_control_credit(self, connection, cid, packet):
        pass

    def on_channel_closed(self, channel):
        connection_channels = self.channels.get(channel.connection.handle)
        if connection_channels:
            if channel.source_cid in connection_channels:
                del connection_channels[channel.source_cid]

    async def connect(self, connection, psm):
        # NOTE: this implementation hard-codes BR/EDR more
        # TODO: LE mode (maybe?)

        # Find a free CID for a new channel
        connection_channels = self.channels.setdefault(connection.handle, {})
        cid = self.find_free_br_edr_cid(connection_channels)
        if cid is None:  # Should never happen!
            raise RuntimeError('all CIDs already in use')

        # Create the channel
        logger.debug(f'creating client channel with cid={cid} for psm {psm}')
        channel = Channel(self, connection, L2CAP_SIGNALING_CID, psm, cid, L2CAP_MIN_BR_EDR_MTU)
        connection_channels[cid] = channel

        # Connect
        await channel.connect()

        return channel
