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
from typing import (
    Optional,
    Callable,
    Any,
    Union,
    Iterable,
    SupportsBytes,
    TypeVar,
    ClassVar,
    TYPE_CHECKING,
)

from bumble import utils
from bumble import hci
from bumble.colors import color
from bumble.core import (
    InvalidStateError,
    InvalidArgumentError,
    InvalidPacketError,
    OutOfResourcesError,
    ProtocolError,
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
L2CAP_MAX_BR_EDR_MTU = 65535

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

class CommandCode(hci.SpecableEnum):
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

L2CAP_CONNECTION_PARAMETERS_ACCEPTED_RESULT = 0x0000
L2CAP_CONNECTION_PARAMETERS_REJECTED_RESULT = 0x0001

L2CAP_COMMAND_NOT_UNDERSTOOD_REASON = 0x0000
L2CAP_SIGNALING_MTU_EXCEEDED_REASON = 0x0001
L2CAP_INVALID_CID_IN_REQUEST_REASON = 0x0002

L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_CREDITS             = 65535
L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MTU                 = 23
L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_MTU                 = 65535
L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MPS                 = 23
L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_MPS                 = 65533
L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MTU             = 2048
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
    mtu: int = L2CAP_DEFAULT_MTU


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
            raise InvalidArgumentError('max credits out of range')
        if (
            self.mtu < L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MTU
            or self.mtu > L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_MTU
        ):
            raise InvalidArgumentError('MTU out of range')
        if (
            self.mps < L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MPS
            or self.mps > L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_MPS
        ):
            raise InvalidArgumentError('MPS out of range')


class L2CAP_PDU:
    '''
    See Bluetooth spec @ Vol 3, Part A - 3 DATA PACKET FORMAT
    '''

    @staticmethod
    def from_bytes(data: bytes) -> L2CAP_PDU:
        # Check parameters
        if len(data) < 4:
            raise InvalidPacketError('not enough data for L2CAP header')

        _, l2cap_pdu_cid = struct.unpack_from('<HH', data, 0)
        l2cap_pdu_payload = data[4:]

        return L2CAP_PDU(l2cap_pdu_cid, l2cap_pdu_payload)

    def __bytes__(self) -> bytes:
        header = struct.pack('<HH', len(self.payload), self.cid)
        return header + self.payload

    def __init__(self, cid: int, payload: bytes) -> None:
        self.cid = cid
        self.payload = payload

    def __str__(self) -> str:
        return f'{color("L2CAP", "green")} [CID={self.cid}]: {self.payload.hex()}'


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class L2CAP_Control_Frame:
    '''
    See Bluetooth spec @ Vol 3, Part A - 4 SIGNALING PACKET FORMATS
    '''

    classes: ClassVar[dict[int, type[L2CAP_Control_Frame]]] = {}
    fields: ClassVar[hci.Fields] = ()
    code: int = dataclasses.field(default=0, init=False)
    name: str = dataclasses.field(default='', init=False)
    _payload: Optional[bytes] = dataclasses.field(default=None, init=False)

    identifier: int

    @classmethod
    def from_bytes(cls, pdu: bytes) -> L2CAP_Control_Frame:
        code, identifier, length = struct.unpack_from("<BBH", pdu)

        subclass = L2CAP_Control_Frame.classes.get(code)
        if subclass is None:
            instance = L2CAP_Control_Frame(identifier=identifier)
            instance.payload = pdu[4:]
            instance.code = CommandCode(code)
            instance.name = instance.code.name
            return instance
        frame = subclass(
            **hci.HCI_Object.dict_from_bytes(pdu, 4, subclass.fields),
            identifier=identifier,
        )
        frame.identifier = identifier
        frame.payload = pdu[4:]
        if length != len(frame.payload):
            logger.warning(
                color(
                    f'!!! length mismatch: expected {length} but got {len(frame.payload)}',
                    'red',
                )
            )
        return frame

    @staticmethod
    def decode_configuration_options(data: bytes) -> list[tuple[int, bytes]]:
        options = []
        while len(data) >= 2:
            value_type = data[0]
            length = data[1]
            value = data[2 : 2 + length]
            data = data[2 + length :]
            options.append((value_type, value))

        return options

    @staticmethod
    def encode_configuration_options(options: list[tuple[int, bytes]]) -> bytes:
        return b''.join(
            [bytes([option[0], len(option[1])]) + option[1] for option in options]
        )

    _ControlFrame = TypeVar('_ControlFrame', bound='L2CAP_Control_Frame')

    @classmethod
    def subclass(cls, subclass: type[_ControlFrame]) -> type[_ControlFrame]:
        subclass.name = subclass.__name__.upper()
        subclass.code = CommandCode[subclass.name]
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)

        # Register a factory for this class
        L2CAP_Control_Frame.classes[subclass.code] = subclass

        return subclass

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            self._payload = hci.HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return self._payload

    @payload.setter
    def payload(self, payload: bytes) -> None:
        self._payload = payload

    def __bytes__(self) -> bytes:
        return (
            struct.pack('<BBH', self.code, self.identifier, len(self.payload))
            + self.payload
        )

    def __str__(self) -> str:
        result = f'{color(self.name, "yellow")} [ID={self.identifier}]'
        if fields := getattr(self, 'fields', None):
            result += ':\n' + hci.HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if len(self.payload) > 1:
                result += f': {self.payload.hex()}'
        return result


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Command_Reject(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.1 COMMAND REJECT
    '''

    class Reason(hci.SpecableEnum):
        COMMAND_NOT_UNDERSTOOD = 0x0000
        SIGNALING_MTU_EXCEEDED = 0x0001
        INVALID_CID_IN_REQUEST = 0x0002

    reason: int = dataclasses.field(metadata=Reason.type_metadata(2))
    data: bytes = dataclasses.field(metadata=hci.metadata('*'))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Connection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.2 CONNECTION REQUEST
    '''

    @staticmethod
    def parse_psm(data: bytes, offset: int = 0) -> tuple[int, int]:
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

    psm: int = dataclasses.field(
        metadata=hci.metadata(
            {
                'parser': lambda data, offset: L2CAP_Connection_Request.parse_psm(
                    data, offset
                ),
                'serializer': lambda value: L2CAP_Connection_Request.serialize_psm(
                    value
                ),
            }
        )
    )
    source_cid: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Connection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.3 CONNECTION RESPONSE
    '''

    class Result(hci.SpecableEnum):
        CONNECTION_SUCCESSFUL = 0x0000
        CONNECTION_PENDING = 0x0001
        CONNECTION_REFUSED_PSM_NOT_SUPPORTED = 0x0002
        CONNECTION_REFUSED_SECURITY_BLOCK = 0x0003
        CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE = 0x0004
        CONNECTION_REFUSED_INVALID_SOURCE_CID = 0x0006
        CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED = 0x0007
        CONNECTION_REFUSED_UNACCEPTABLE_PARAMETERS = 0x000B

    destination_cid: int = dataclasses.field(metadata=hci.metadata(2))
    source_cid: int = dataclasses.field(metadata=hci.metadata(2))
    result: int = dataclasses.field(metadata=Result.type_metadata(2))
    status: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Configure_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.4 CONFIGURATION REQUEST
    '''

    destination_cid: int = dataclasses.field(metadata=hci.metadata(2))
    flags: int = dataclasses.field(metadata=hci.metadata(2))
    options: bytes = dataclasses.field(metadata=hci.metadata('*'))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Configure_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.5 CONFIGURATION RESPONSE
    '''

    class Result(hci.SpecableEnum):
        SUCCESS = 0x0000
        FAILURE_UNACCEPTABLE_PARAMETERS = 0x0001
        FAILURE_REJECTED = 0x0002
        FAILURE_UNKNOWN_OPTIONS = 0x0003
        PENDING = 0x0004
        FAILURE_FLOW_SPEC_REJECTED = 0x0005

    source_cid: int = dataclasses.field(metadata=hci.metadata(2))
    flags: int = dataclasses.field(metadata=hci.metadata(2))
    result: int = dataclasses.field(metadata=Result.type_metadata(2))
    options: bytes = dataclasses.field(metadata=hci.metadata('*'))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Disconnection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.6 DISCONNECTION REQUEST
    '''

    destination_cid: int = dataclasses.field(metadata=hci.metadata(2))
    source_cid: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Disconnection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.7 DISCONNECTION RESPONSE
    '''

    destination_cid: int = dataclasses.field(metadata=hci.metadata(2))
    source_cid: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Echo_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.8 ECHO REQUEST
    '''

    data: bytes = dataclasses.field(metadata=hci.metadata('*'))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Echo_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.9 ECHO RESPONSE
    '''

    data: bytes = dataclasses.field(metadata=hci.metadata('*'))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Information_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.10 INFORMATION REQUEST
    '''

    class InfoType(hci.SpecableEnum):
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

    info_type: int = dataclasses.field(metadata=InfoType.type_metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Information_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.11 INFORMATION RESPONSE
    '''

    class Result(hci.SpecableEnum):
        SUCCESS = 0x00
        NOT_SUPPORTED = 0x01

    info_type: int = dataclasses.field(
        metadata=L2CAP_Information_Request.InfoType.type_metadata(2)
    )
    result: int = dataclasses.field(metadata=Result.type_metadata(2))
    data: bytes = dataclasses.field(metadata=hci.metadata('*'))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Connection_Parameter_Update_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.20 CONNECTION PARAMETER UPDATE REQUEST
    '''

    interval_min: int = dataclasses.field(metadata=hci.metadata(2))
    interval_max: int = dataclasses.field(metadata=hci.metadata(2))
    latency: int = dataclasses.field(metadata=hci.metadata(2))
    timeout: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_Connection_Parameter_Update_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.21 CONNECTION PARAMETER UPDATE RESPONSE
    '''

    result: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_LE_Credit_Based_Connection_Request(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.22 LE CREDIT BASED CONNECTION REQUEST
    (CODE 0x14)
    '''

    le_psm: int = dataclasses.field(metadata=hci.metadata(2))
    source_cid: int = dataclasses.field(metadata=hci.metadata(2))
    mtu: int = dataclasses.field(metadata=hci.metadata(2))
    mps: int = dataclasses.field(metadata=hci.metadata(2))
    initial_credits: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_LE_Credit_Based_Connection_Response(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.23 LE CREDIT BASED CONNECTION RESPONSE
    (CODE 0x15)
    '''

    class Result(hci.SpecableEnum):
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

    destination_cid: int = dataclasses.field(metadata=hci.metadata(2))
    mtu: int = dataclasses.field(metadata=hci.metadata(2))
    mps: int = dataclasses.field(metadata=hci.metadata(2))
    initial_credits: int = dataclasses.field(metadata=hci.metadata(2))
    result: int = dataclasses.field(metadata=Result.type_metadata(2))


# -----------------------------------------------------------------------------
@L2CAP_Control_Frame.subclass
@dataclasses.dataclass
class L2CAP_LE_Flow_Control_Credit(L2CAP_Control_Frame):
    '''
    See Bluetooth spec @ Vol 3, Part A - 4.24 LE FLOW CONTROL CREDIT (CODE 0x16)
    '''

    cid: int = dataclasses.field(metadata=hci.metadata(2))
    credits: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
class ClassicChannel(utils.EventEmitter):
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

    EVENT_OPEN = "open"
    EVENT_CLOSE = "close"

    connection_result: Optional[asyncio.Future[None]]
    disconnection_result: Optional[asyncio.Future[None]]
    response: Optional[asyncio.Future[bytes]]
    sink: Optional[Callable[[bytes], Any]]
    state: State
    connection: Connection
    mtu: int
    peer_mtu: int

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
        self.peer_mtu = L2CAP_MIN_BR_EDR_MTU
        self.psm = psm
        self.source_cid = source_cid
        self.destination_cid = 0
        self.connection_result = None
        self.disconnection_result = None
        self.sink = None

    def _change_state(self, new_state: State) -> None:
        logger.debug(f'{self} state change -> {color(new_state.name, "cyan")}')
        self.state = new_state

    def send_pdu(self, pdu: Union[SupportsBytes, bytes]) -> None:
        if self.state != self.State.OPEN:
            raise InvalidStateError('channel not open')
        self.manager.send_pdu(self.connection, self.destination_cid, pdu)

    def send_control_frame(self, frame: L2CAP_Control_Frame) -> None:
        self.manager.send_control_frame(self.connection, self.signaling_cid, frame)

    def on_pdu(self, pdu: bytes) -> None:
        if self.sink:
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
            raise InvalidStateError('connection already pending')

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
            return await self.connection.cancel_on_disconnection(self.connection_result)
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
            self.emit(self.EVENT_CLOSE)

    def send_configure_request(self) -> None:
        options = L2CAP_Control_Frame.encode_configuration_options(
            [
                (
                    L2CAP_MAXIMUM_TRANSMISSION_UNIT_CONFIGURATION_OPTION_TYPE,
                    struct.pack('<H', self.mtu),
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

    def on_connection_request(self, request: L2CAP_Connection_Request) -> None:
        self.destination_cid = request.source_cid
        self._change_state(self.State.WAIT_CONNECT)
        self.send_control_frame(
            L2CAP_Connection_Response(
                identifier=request.identifier,
                destination_cid=self.source_cid,
                source_cid=self.destination_cid,
                result=L2CAP_Connection_Response.Result.CONNECTION_SUCCESSFUL,
                status=0x0000,
            )
        )
        self._change_state(self.State.WAIT_CONFIG)
        self.send_configure_request()
        self._change_state(self.State.WAIT_CONFIG_REQ_RSP)

    def on_connection_response(self, response: L2CAP_Connection_Response):
        if self.state != self.State.WAIT_CONNECT_RSP:
            logger.warning(color('invalid state', 'red'))
            return

        if response.result == L2CAP_Connection_Response.Result.CONNECTION_SUCCESSFUL:
            self.destination_cid = response.destination_cid
            self._change_state(self.State.WAIT_CONFIG)
            self.send_configure_request()
            self._change_state(self.State.WAIT_CONFIG_REQ_RSP)
        elif response.result == L2CAP_Connection_Response.Result.CONNECTION_PENDING:
            pass
        else:
            self._change_state(self.State.CLOSED)
            if self.connection_result:
                self.connection_result.set_exception(
                    ProtocolError(
                        response.result,
                        'l2cap',
                        L2CAP_Connection_Response.Result(response.result).name,
                    )
                )
                self.connection_result = None

    def on_configure_request(self, request: L2CAP_Configure_Request) -> None:
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
                self.peer_mtu = struct.unpack('<H', option[1])[0]
                logger.debug(f'peer MTU = {self.peer_mtu}')

        self.send_control_frame(
            L2CAP_Configure_Response(
                identifier=request.identifier,
                source_cid=self.destination_cid,
                flags=0x0000,
                result=L2CAP_Configure_Response.Result.SUCCESS,
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
            self.emit(self.EVENT_OPEN)
        elif self.state == self.State.WAIT_CONFIG_REQ_RSP:
            self._change_state(self.State.WAIT_CONFIG_RSP)

    def on_configure_response(self, response: L2CAP_Configure_Response) -> None:
        if response.result == L2CAP_Configure_Response.Result.SUCCESS:
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
                self.emit(self.EVENT_OPEN)
            else:
                logger.warning(color('invalid state', 'red'))
        elif (
            response.result
            == L2CAP_Configure_Response.Result.FAILURE_UNACCEPTABLE_PARAMETERS
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
                    f'{L2CAP_Configure_Response.Result(response.result).name}',
                    'red',
                )
            )
            # TODO: decide how to fail gracefully

    def on_disconnection_request(self, request: L2CAP_Disconnection_Request) -> None:
        if self.state in (self.State.OPEN, self.State.WAIT_DISCONNECT):
            self.send_control_frame(
                L2CAP_Disconnection_Response(
                    identifier=request.identifier,
                    destination_cid=request.destination_cid,
                    source_cid=request.source_cid,
                )
            )
            self._change_state(self.State.CLOSED)
            self.emit(self.EVENT_CLOSE)
            self.manager.on_channel_closed(self)
        else:
            logger.warning(color('invalid state', 'red'))

    def on_disconnection_response(self, response: L2CAP_Disconnection_Response) -> None:
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
        self.emit(self.EVENT_CLOSE)
        self.manager.on_channel_closed(self)

    def __str__(self) -> str:
        return (
            f'Channel({self.source_cid}->{self.destination_cid}, '
            f'PSM={self.psm}, '
            f'MTU={self.mtu}/{self.peer_mtu}, '
            f'state={self.state.name})'
        )


# -----------------------------------------------------------------------------
class LeCreditBasedChannel(utils.EventEmitter):
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

    out_queue: deque[bytes]
    connection_result: Optional[asyncio.Future[LeCreditBasedChannel]]
    disconnection_result: Optional[asyncio.Future[None]]
    in_sdu: Optional[bytes]
    out_sdu: Optional[bytes]
    state: State
    connection: Connection
    sink: Optional[Callable[[bytes], Any]]

    EVENT_OPEN = "open"
    EVENT_CLOSE = "close"

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
            self.emit(self.EVENT_OPEN)
        elif new_state == self.State.DISCONNECTED:
            self.emit(self.EVENT_CLOSE)

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
            raise InvalidStateError('too many concurrent connection requests')

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

    def on_connection_response(
        self, response: L2CAP_LE_Credit_Based_Connection_Response
    ) -> None:
        # Look for a matching pending response result
        if self.connection_result is None:
            logger.warning(
                f'received unexpected connection response (id={response.identifier})'
            )
            return

        if (
            response.result
            == L2CAP_LE_Credit_Based_Connection_Response.Result.CONNECTION_SUCCESSFUL
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
                    L2CAP_LE_Credit_Based_Connection_Response.Result(
                        response.result
                    ).name,
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

    def on_disconnection_request(self, request: L2CAP_Disconnection_Request) -> None:
        self.send_control_frame(
            L2CAP_Disconnection_Response(
                identifier=request.identifier,
                destination_cid=request.destination_cid,
                source_cid=request.source_cid,
            )
        )
        self._change_state(self.State.DISCONNECTED)
        self.flush_output()

    def on_disconnection_response(self, response: L2CAP_Disconnection_Response) -> None:
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
class ClassicChannelServer(utils.EventEmitter):
    EVENT_CONNECTION = "connection"

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
        self.emit(self.EVENT_CONNECTION, channel)
        if self.handler:
            self.handler(channel)

    def close(self) -> None:
        if self.psm in self.manager.servers:
            del self.manager.servers[self.psm]


# -----------------------------------------------------------------------------
class LeCreditBasedChannelServer(utils.EventEmitter):
    EVENT_CONNECTION = "connection"

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
        self.emit(self.EVENT_CONNECTION, channel)
        if self.handler:
            self.handler(channel)

    def close(self) -> None:
        if self.psm in self.manager.le_coc_servers:
            del self.manager.le_coc_servers[self.psm]


# -----------------------------------------------------------------------------
class ChannelManager:
    identifiers: dict[int, int]
    channels: dict[int, dict[int, Union[ClassicChannel, LeCreditBasedChannel]]]
    servers: dict[int, ClassicChannelServer]
    le_coc_channels: dict[int, dict[int, LeCreditBasedChannel]]
    le_coc_servers: dict[int, LeCreditBasedChannelServer]
    le_coc_requests: dict[int, L2CAP_LE_Credit_Based_Connection_Request]
    fixed_channels: dict[int, Optional[Callable[[int, bytes], Any]]]
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

        raise OutOfResourcesError('no free CID available')

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

        raise OutOfResourcesError('no free CID')

    def next_identifier(self, connection: Connection) -> int:
        identifier = (self.identifiers.setdefault(connection.handle, 0) + 1) % 256
        # 0x00 is an invalid ID (BT Core Spec, Vol 3, Part A, Sect 4
        if identifier == 0:
            identifier = 1
        self.identifiers[connection.handle] = identifier
        return identifier

    def register_fixed_channel(
        self, cid: int, handler: Callable[[int, bytes], Any]
    ) -> None:
        self.fixed_channels[cid] = handler

    def deregister_fixed_channel(self, cid: int) -> None:
        if cid in self.fixed_channels:
            del self.fixed_channels[cid]

    @utils.deprecated("Please use create_classic_server")
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
                raise InvalidArgumentError('PSM already in use')

            # Check that the PSM is valid
            if spec.psm % 2 == 0:
                raise InvalidArgumentError('invalid PSM (not odd)')
            check = spec.psm >> 8
            while check:
                if check % 2 != 0:
                    raise InvalidArgumentError('invalid PSM')
                check >>= 8

        self.servers[spec.psm] = ClassicChannelServer(self, spec.psm, handler, spec.mtu)

        return self.servers[spec.psm]

    @utils.deprecated("Please use create_le_credit_based_server()")
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
                raise InvalidArgumentError('PSM already in use')

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
        pdu_bytes = bytes(pdu)
        logger.debug(
            f'{color(">>> Sending L2CAP PDU", "blue")} '
            f'on connection [0x{connection.handle:04X}] (CID={cid}) '
            f'{connection.peer_address}: {len(pdu_bytes)} bytes, {pdu_str}'
        )
        self.host.send_l2cap_pdu(connection.handle, cid, pdu_bytes)

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
        self, _connection: Connection, _cid: int, packet: L2CAP_Command_Reject
    ) -> None:
        logger.warning(f'{color("!!! Command rejected:", "red")} {packet.reason}')

    def on_l2cap_connection_request(
        self, connection: Connection, cid: int, request: L2CAP_Connection_Request
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
                        result=L2CAP_Connection_Response.Result.CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE,
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
                    result=L2CAP_Connection_Response.Result.CONNECTION_REFUSED_PSM_NOT_SUPPORTED,
                    status=0x0000,
                ),
            )

    def on_l2cap_connection_response(
        self,
        connection: Connection,
        cid: int,
        response: L2CAP_Connection_Response,
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
        self, connection: Connection, cid: int, request: L2CAP_Configure_Request
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
        self, connection: Connection, cid: int, response: L2CAP_Configure_Response
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
        self, connection: Connection, cid: int, request: L2CAP_Disconnection_Request
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
        self, connection: Connection, cid: int, response: L2CAP_Disconnection_Response
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

    def on_l2cap_echo_request(
        self, connection: Connection, cid: int, request: L2CAP_Echo_Request
    ) -> None:
        logger.debug(f'<<< Echo request: data={request.data.hex()}')
        self.send_control_frame(
            connection,
            cid,
            L2CAP_Echo_Response(identifier=request.identifier, data=request.data),
        )

    def on_l2cap_echo_response(
        self, _connection: Connection, _cid: int, response: L2CAP_Echo_Response
    ) -> None:
        logger.debug(f'<<< Echo response: data={response.data.hex()}')
        # TODO notify listeners

    def on_l2cap_information_request(
        self, connection: Connection, cid: int, request: L2CAP_Information_Request
    ) -> None:
        if request.info_type == L2CAP_Information_Request.InfoType.CONNECTIONLESS_MTU:
            result = L2CAP_Information_Response.Result.SUCCESS
            data = self.connectionless_mtu.to_bytes(2, 'little')
        elif (
            request.info_type
            == L2CAP_Information_Request.InfoType.EXTENDED_FEATURES_SUPPORTED
        ):
            result = L2CAP_Information_Response.Result.SUCCESS
            data = sum(self.extended_features).to_bytes(4, 'little')
        elif (
            request.info_type
            == L2CAP_Information_Request.InfoType.FIXED_CHANNELS_SUPPORTED
        ):
            result = L2CAP_Information_Response.Result.SUCCESS
            data = sum(1 << cid for cid in self.fixed_channels).to_bytes(8, 'little')
        else:
            result = L2CAP_Information_Response.Result.NOT_SUPPORTED
            data = b''

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
        self,
        connection: Connection,
        cid: int,
        request: L2CAP_Connection_Parameter_Update_Request,
    ):
        if connection.role == hci.Role.CENTRAL:
            self.send_control_frame(
                connection,
                cid,
                L2CAP_Connection_Parameter_Update_Response(
                    identifier=request.identifier,
                    result=L2CAP_CONNECTION_PARAMETERS_ACCEPTED_RESULT,
                ),
            )
            self.host.send_command_sync(
                hci.HCI_LE_Connection_Update_Command(
                    connection_handle=connection.handle,
                    connection_interval_min=request.interval_min,
                    connection_interval_max=request.interval_max,
                    max_latency=request.latency,
                    supervision_timeout=request.timeout,
                    min_ce_length=0,
                    max_ce_length=0,
                )
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
                identifier=self.next_identifier(connection),
                interval_min=interval_min,
                interval_max=interval_max,
                latency=latency,
                timeout=timeout,
            ),
        )
        return await self.connection_parameters_update_response

    def on_l2cap_connection_parameter_update_response(
        self,
        connection: Connection,
        cid: int,
        response: L2CAP_Connection_Parameter_Update_Response,
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
        self,
        connection: Connection,
        cid: int,
        request: L2CAP_LE_Credit_Based_Connection_Request,
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
                        result=L2CAP_LE_Credit_Based_Connection_Response.Result.CONNECTION_REFUSED_SOURCE_CID_ALREADY_ALLOCATED,
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
                        result=L2CAP_LE_Credit_Based_Connection_Response.Result.CONNECTION_REFUSED_NO_RESOURCES_AVAILABLE,
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
                    result=L2CAP_LE_Credit_Based_Connection_Response.Result.CONNECTION_SUCCESSFUL,
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
                    result=L2CAP_LE_Credit_Based_Connection_Response.Result.CONNECTION_REFUSED_LE_PSM_NOT_SUPPORTED,
                ),
            )

    def on_l2cap_le_credit_based_connection_response(
        self,
        connection: Connection,
        _cid: int,
        response: L2CAP_LE_Credit_Based_Connection_Response,
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
        self, connection: Connection, _cid: int, credit: L2CAP_LE_Flow_Control_Credit
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

    @utils.deprecated("Please use create_le_credit_based_channel()")
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
            raise OutOfResourcesError('all CIDs already in use')

        if spec.psm is None:
            raise InvalidArgumentError('PSM cannot be None')

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

    @utils.deprecated("Please use create_classic_channel()")
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
            raise OutOfResourcesError('all CIDs already in use')

        if spec.psm is None:
            raise InvalidArgumentError('PSM cannot be None')

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
        except BaseException as e:
            del connection_channels[source_cid]
            raise e

        return channel


# -----------------------------------------------------------------------------
# Deprecated Classes
# -----------------------------------------------------------------------------


class Channel(ClassicChannel):
    @utils.deprecated("Please use ClassicChannel")
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class LeConnectionOrientedChannel(LeCreditBasedChannel):
    @utils.deprecated("Please use LeCreditBasedChannel")
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
