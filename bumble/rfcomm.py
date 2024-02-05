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

import logging
import asyncio
import dataclasses
import enum
from typing import Callable, Dict, List, Optional, Tuple, Union, TYPE_CHECKING
from typing_extensions import Self

from pyee import EventEmitter

from bumble import core
from bumble import l2cap
from bumble import sdp
from .colors import color
from .core import (
    UUID,
    BT_RFCOMM_PROTOCOL_ID,
    BT_BR_EDR_TRANSPORT,
    BT_L2CAP_PROTOCOL_ID,
    InvalidStateError,
    ProtocolError,
)

if TYPE_CHECKING:
    from bumble.device import Device, Connection

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off

RFCOMM_PSM = 0x0003

class FrameType(enum.IntEnum):
    SABM = 0x2F  # Control field [1,1,1,1,_,1,0,0] LSB-first
    UA   = 0x63  # Control field [0,1,1,0,_,0,1,1] LSB-first
    DM   = 0x0F  # Control field [1,1,1,1,_,0,0,0] LSB-first
    DISC = 0x43  # Control field [0,1,0,_,0,0,1,1] LSB-first
    UIH  = 0xEF  # Control field [1,1,1,_,1,1,1,1] LSB-first
    UI   = 0x03  # Control field [0,0,0,_,0,0,1,1] LSB-first

class MccType(enum.IntEnum):
    PN  = 0x20
    MSC = 0x38


# FCS CRC
CRC_TABLE = bytes([
    0X00, 0X91, 0XE3, 0X72, 0X07, 0X96, 0XE4, 0X75,
    0X0E, 0X9F, 0XED, 0X7C, 0X09, 0X98, 0XEA, 0X7B,
    0X1C, 0X8D, 0XFF, 0X6E, 0X1B, 0X8A, 0XF8, 0X69,
    0X12, 0X83, 0XF1, 0X60, 0X15, 0X84, 0XF6, 0X67,
    0X38, 0XA9, 0XDB, 0X4A, 0X3F, 0XAE, 0XDC, 0X4D,
    0X36, 0XA7, 0XD5, 0X44, 0X31, 0XA0, 0XD2, 0X43,
    0X24, 0XB5, 0XC7, 0X56, 0X23, 0XB2, 0XC0, 0X51,
    0X2A, 0XBB, 0XC9, 0X58, 0X2D, 0XBC, 0XCE, 0X5F,
    0X70, 0XE1, 0X93, 0X02, 0X77, 0XE6, 0X94, 0X05,
    0X7E, 0XEF, 0X9D, 0X0C, 0X79, 0XE8, 0X9A, 0X0B,
    0X6C, 0XFD, 0X8F, 0X1E, 0X6B, 0XFA, 0X88, 0X19,
    0X62, 0XF3, 0X81, 0X10, 0X65, 0XF4, 0X86, 0X17,
    0X48, 0XD9, 0XAB, 0X3A, 0X4F, 0XDE, 0XAC, 0X3D,
    0X46, 0XD7, 0XA5, 0X34, 0X41, 0XD0, 0XA2, 0X33,
    0X54, 0XC5, 0XB7, 0X26, 0X53, 0XC2, 0XB0, 0X21,
    0X5A, 0XCB, 0XB9, 0X28, 0X5D, 0XCC, 0XBE, 0X2F,
    0XE0, 0X71, 0X03, 0X92, 0XE7, 0X76, 0X04, 0X95,
    0XEE, 0X7F, 0X0D, 0X9C, 0XE9, 0X78, 0X0A, 0X9B,
    0XFC, 0X6D, 0X1F, 0X8E, 0XFB, 0X6A, 0X18, 0X89,
    0XF2, 0X63, 0X11, 0X80, 0XF5, 0X64, 0X16, 0X87,
    0XD8, 0X49, 0X3B, 0XAA, 0XDF, 0X4E, 0X3C, 0XAD,
    0XD6, 0X47, 0X35, 0XA4, 0XD1, 0X40, 0X32, 0XA3,
    0XC4, 0X55, 0X27, 0XB6, 0XC3, 0X52, 0X20, 0XB1,
    0XCA, 0X5B, 0X29, 0XB8, 0XCD, 0X5C, 0X2E, 0XBF,
    0X90, 0X01, 0X73, 0XE2, 0X97, 0X06, 0X74, 0XE5,
    0X9E, 0X0F, 0X7D, 0XEC, 0X99, 0X08, 0X7A, 0XEB,
    0X8C, 0X1D, 0X6F, 0XFE, 0X8B, 0X1A, 0X68, 0XF9,
    0X82, 0X13, 0X61, 0XF0, 0X85, 0X14, 0X66, 0XF7,
    0XA8, 0X39, 0X4B, 0XDA, 0XAF, 0X3E, 0X4C, 0XDD,
    0XA6, 0X37, 0X45, 0XD4, 0XA1, 0X30, 0X42, 0XD3,
    0XB4, 0X25, 0X57, 0XC6, 0XB3, 0X22, 0X50, 0XC1,
    0XBA, 0X2B, 0X59, 0XC8, 0XBD, 0X2C, 0X5E, 0XCF
])

RFCOMM_DEFAULT_L2CAP_MTU      = 2048
RFCOMM_DEFAULT_WINDOW_SIZE    = 7
RFCOMM_DEFAULT_MAX_FRAME_SIZE = 2000

RFCOMM_DYNAMIC_CHANNEL_NUMBER_START = 1
RFCOMM_DYNAMIC_CHANNEL_NUMBER_END   = 30

# fmt: on


# -----------------------------------------------------------------------------
def make_service_sdp_records(
    service_record_handle: int, channel: int, uuid: Optional[UUID] = None
) -> List[sdp.ServiceAttribute]:
    """
    Create SDP records for an RFComm service given a channel number and an
    optional UUID. A Service Class Attribute is included only if the UUID is not None.
    """
    records = [
        sdp.ServiceAttribute(
            sdp.SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            sdp.DataElement.unsigned_integer_32(service_record_handle),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [sdp.DataElement.uuid(sdp.SDP_PUBLIC_BROWSE_ROOT)]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.sequence(
                        [sdp.DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]
                    ),
                    sdp.DataElement.sequence(
                        [
                            sdp.DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                            sdp.DataElement.unsigned_integer_8(channel),
                        ]
                    ),
                ]
            ),
        ),
    ]

    if uuid:
        records.append(
            sdp.ServiceAttribute(
                sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                sdp.DataElement.sequence([sdp.DataElement.uuid(uuid)]),
            )
        )

    return records


# -----------------------------------------------------------------------------
async def find_rfcomm_channels(connection: Connection) -> Dict[int, List[UUID]]:
    """Searches all RFCOMM channels and their associated UUID from SDP service records.

    Args:
        connection: ACL connection to make SDP search.

    Returns:
        Dictionary mapping from channel number to service class UUID list.
    """
    results = {}
    async with sdp.Client(connection) as sdp_client:
        search_result = await sdp_client.search_attributes(
            uuids=[core.BT_RFCOMM_PROTOCOL_ID],
            attribute_ids=[
                sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            ],
        )
        for attribute_lists in search_result:
            service_classes: List[UUID] = []
            channel: Optional[int] = None
            for attribute in attribute_lists:
                # The layout is [[L2CAP_PROTOCOL], [RFCOMM_PROTOCOL, RFCOMM_CHANNEL]].
                if attribute.id == sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                    protocol_descriptor_list = attribute.value.value
                    channel = protocol_descriptor_list[1].value[1].value
                elif attribute.id == sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID:
                    service_class_id_list = attribute.value.value
                    service_classes = [
                        service_class.value for service_class in service_class_id_list
                    ]
            if not service_classes or not channel:
                logger.warning(f"Bad result {attribute_lists}.")
            else:
                results[channel] = service_classes
    return results


# -----------------------------------------------------------------------------
async def find_rfcomm_channel_with_uuid(
    connection: Connection, uuid: str | UUID
) -> Optional[int]:
    """Searches an RFCOMM channel associated with given UUID from service records.

    Args:
        connection: ACL connection to make SDP search.
        uuid: UUID of service record to search for.

    Returns:
        RFCOMM channel number if found, otherwise None.
    """
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    return next(
        (
            channel
            for channel, class_id_list in (
                await find_rfcomm_channels(connection)
            ).items()
            if uuid in class_id_list
        ),
        None,
    )


# -----------------------------------------------------------------------------
def compute_fcs(buffer: bytes) -> int:
    result = 0xFF
    for byte in buffer:
        result = CRC_TABLE[result ^ byte]
    return 0xFF - result


# -----------------------------------------------------------------------------
class RFCOMM_Frame:
    def __init__(
        self,
        frame_type: FrameType,
        c_r: int,
        dlci: int,
        p_f: int,
        information: bytes = b'',
        with_credits: bool = False,
    ) -> None:
        self.type = frame_type
        self.c_r = c_r
        self.dlci = dlci
        self.p_f = p_f
        self.information = information
        length = len(information)
        if with_credits:
            length -= 1
        if length > 0x7F:
            # 2-byte length indicator
            self.length = bytes([(length & 0x7F) << 1, (length >> 7) & 0xFF])
        else:
            # 1-byte length indicator
            self.length = bytes([(length << 1) | 1])
        self.address = (dlci << 2) | (c_r << 1) | 1
        self.control = frame_type | (p_f << 4)
        if frame_type == FrameType.UIH:
            self.fcs = compute_fcs(bytes([self.address, self.control]))
        else:
            self.fcs = compute_fcs(bytes([self.address, self.control]) + self.length)

    @staticmethod
    def parse_mcc(data) -> Tuple[int, bool, bytes]:
        mcc_type = data[0] >> 2
        c_r = bool((data[0] >> 1) & 1)
        length = data[1]
        if data[1] & 1:
            length >>= 1
            value = data[2:]
        else:
            length = (data[3] << 7) & (length >> 1)
            value = data[3 : 3 + length]

        return (mcc_type, c_r, value)

    @staticmethod
    def make_mcc(mcc_type: int, c_r: int, data: bytes) -> bytes:
        return (
            bytes([(mcc_type << 2 | c_r << 1 | 1) & 0xFF, (len(data) & 0x7F) << 1 | 1])
            + data
        )

    @staticmethod
    def sabm(c_r: int, dlci: int):
        return RFCOMM_Frame(FrameType.SABM, c_r, dlci, 1)

    @staticmethod
    def ua(c_r: int, dlci: int):
        return RFCOMM_Frame(FrameType.UA, c_r, dlci, 1)

    @staticmethod
    def dm(c_r: int, dlci: int):
        return RFCOMM_Frame(FrameType.DM, c_r, dlci, 1)

    @staticmethod
    def disc(c_r: int, dlci: int):
        return RFCOMM_Frame(FrameType.DISC, c_r, dlci, 1)

    @staticmethod
    def uih(c_r: int, dlci: int, information: bytes, p_f: int = 0):
        return RFCOMM_Frame(
            FrameType.UIH, c_r, dlci, p_f, information, with_credits=(p_f == 1)
        )

    @staticmethod
    def from_bytes(data: bytes) -> RFCOMM_Frame:
        # Extract fields
        dlci = (data[0] >> 2) & 0x3F
        c_r = (data[0] >> 1) & 0x01
        frame_type = FrameType(data[1] & 0xEF)
        p_f = (data[1] >> 4) & 0x01
        length = data[2]
        if length & 0x01:
            length >>= 1
            information = data[3:-1]
        else:
            length = (data[3] << 7) & (length >> 1)
            information = data[4:-1]
        fcs = data[-1]

        # Construct the frame and check the CRC
        frame = RFCOMM_Frame(frame_type, c_r, dlci, p_f, information)
        if frame.fcs != fcs:
            logger.warning(f'FCS mismatch: got {fcs:02X}, expected {frame.fcs:02X}')
            raise ValueError('fcs mismatch')

        return frame

    def __bytes__(self) -> bytes:
        return (
            bytes([self.address, self.control])
            + self.length
            + self.information
            + bytes([self.fcs])
        )

    def __str__(self) -> str:
        return (
            f'{color(self.type.name, "yellow")}'
            f'(c/r={self.c_r},'
            f'dlci={self.dlci},'
            f'p/f={self.p_f},'
            f'length={len(self.information)},'
            f'fcs=0x{self.fcs:02X})'
        )


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class RFCOMM_MCC_PN:
    dlci: int
    cl: int
    priority: int
    ack_timer: int
    max_frame_size: int
    max_retransmissions: int
    window_size: int

    def __post_init__(self) -> None:
        if self.window_size < 1 or self.window_size > 7:
            logger.warning(
                f'Error Recovery Window size {self.window_size} is out of range [1, 7].'
            )

    @staticmethod
    def from_bytes(data: bytes) -> RFCOMM_MCC_PN:
        return RFCOMM_MCC_PN(
            dlci=data[0],
            cl=data[1],
            priority=data[2],
            ack_timer=data[3],
            max_frame_size=data[4] | data[5] << 8,
            max_retransmissions=data[6],
            window_size=data[7] & 0x07,
        )

    def __bytes__(self) -> bytes:
        return bytes(
            [
                self.dlci & 0xFF,
                self.cl & 0xFF,
                self.priority & 0xFF,
                self.ack_timer & 0xFF,
                self.max_frame_size & 0xFF,
                (self.max_frame_size >> 8) & 0xFF,
                self.max_retransmissions & 0xFF,
                # Only 3 bits are meaningful.
                self.window_size & 0x07,
            ]
        )


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class RFCOMM_MCC_MSC:
    dlci: int
    fc: int
    rtc: int
    rtr: int
    ic: int
    dv: int

    @staticmethod
    def from_bytes(data: bytes) -> RFCOMM_MCC_MSC:
        return RFCOMM_MCC_MSC(
            dlci=data[0] >> 2,
            fc=data[1] >> 1 & 1,
            rtc=data[1] >> 2 & 1,
            rtr=data[1] >> 3 & 1,
            ic=data[1] >> 6 & 1,
            dv=data[1] >> 7 & 1,
        )

    def __bytes__(self) -> bytes:
        return bytes(
            [
                (self.dlci << 2) | 3,
                1
                | self.fc << 1
                | self.rtc << 2
                | self.rtr << 3
                | self.ic << 6
                | self.dv << 7,
            ]
        )


# -----------------------------------------------------------------------------
class DLC(EventEmitter):
    class State(enum.IntEnum):
        INIT = 0x00
        CONNECTING = 0x01
        CONNECTED = 0x02
        DISCONNECTING = 0x03
        DISCONNECTED = 0x04
        RESET = 0x05

    connection_result: Optional[asyncio.Future]
    sink: Optional[Callable[[bytes], None]]

    def __init__(
        self,
        multiplexer: Multiplexer,
        dlci: int,
        max_frame_size: int,
        window_size: int,
    ) -> None:
        super().__init__()
        self.multiplexer = multiplexer
        self.dlci = dlci
        self.max_frame_size = max_frame_size
        self.window_size = window_size
        self.rx_credits = window_size
        self.rx_threshold = window_size // 2
        self.tx_credits = window_size
        self.tx_buffer = b''
        self.state = DLC.State.INIT
        self.role = multiplexer.role
        self.c_r = 1 if self.role == Multiplexer.Role.INITIATOR else 0
        self.sink = None
        self.connection_result = None
        self.drained = asyncio.Event()
        self.drained.set()

        # Compute the MTU
        max_overhead = 4 + 1  # header with 2-byte length + fcs
        self.mtu = min(
            max_frame_size, self.multiplexer.l2cap_channel.peer_mtu - max_overhead
        )

    def change_state(self, new_state: State) -> None:
        logger.debug(f'{self} state change -> {color(new_state.name, "magenta")}')
        self.state = new_state

    def send_frame(self, frame: RFCOMM_Frame) -> None:
        self.multiplexer.send_frame(frame)

    def on_frame(self, frame: RFCOMM_Frame) -> None:
        handler = getattr(self, f'on_{frame.type.name}_frame'.lower())
        handler(frame)

    def on_sabm_frame(self, _frame: RFCOMM_Frame) -> None:
        if self.state != DLC.State.CONNECTING:
            logger.warning(
                color('!!! received SABM when not in CONNECTING state', 'red')
            )
            return

        self.send_frame(RFCOMM_Frame.ua(c_r=1 - self.c_r, dlci=self.dlci))

        # Exchange the modem status with the peer
        msc = RFCOMM_MCC_MSC(dlci=self.dlci, fc=0, rtc=1, rtr=1, ic=0, dv=1)
        mcc = RFCOMM_Frame.make_mcc(mcc_type=MccType.MSC, c_r=1, data=bytes(msc))
        logger.debug(f'>>> MCC MSC Command: {msc}')
        self.send_frame(RFCOMM_Frame.uih(c_r=self.c_r, dlci=0, information=mcc))

        self.change_state(DLC.State.CONNECTED)
        self.emit('open')

    def on_ua_frame(self, _frame: RFCOMM_Frame) -> None:
        if self.state != DLC.State.CONNECTING:
            logger.warning(
                color('!!! received SABM when not in CONNECTING state', 'red')
            )
            return

        # Exchange the modem status with the peer
        msc = RFCOMM_MCC_MSC(dlci=self.dlci, fc=0, rtc=1, rtr=1, ic=0, dv=1)
        mcc = RFCOMM_Frame.make_mcc(mcc_type=MccType.MSC, c_r=1, data=bytes(msc))
        logger.debug(f'>>> MCC MSC Command: {msc}')
        self.send_frame(RFCOMM_Frame.uih(c_r=self.c_r, dlci=0, information=mcc))

        self.change_state(DLC.State.CONNECTED)
        self.multiplexer.on_dlc_open_complete(self)

    def on_dm_frame(self, frame: RFCOMM_Frame) -> None:
        # TODO: handle all states
        pass

    def on_disc_frame(self, _frame: RFCOMM_Frame) -> None:
        # TODO: handle all states
        self.send_frame(RFCOMM_Frame.ua(c_r=1 - self.c_r, dlci=self.dlci))

    def on_uih_frame(self, frame: RFCOMM_Frame) -> None:
        data = frame.information
        if frame.p_f == 1:
            # With credits
            received_credits = frame.information[0]
            self.tx_credits += received_credits

            logger.debug(
                f'<<< Credits [{self.dlci}]: '
                f'received {received_credits}, total={self.tx_credits}'
            )
            data = data[1:]

        logger.debug(
            f'{color("<<< Data", "yellow")} '
            f'[{self.dlci}] {len(data)} bytes, '
            f'rx_credits={self.rx_credits}: {data.hex()}'
        )
        if data:
            if self.sink:
                self.sink(data)  # pylint: disable=not-callable

            # Update the credits
            if self.rx_credits > 0:
                self.rx_credits -= 1
            else:
                logger.warning(color('!!! received frame with no rx credits', 'red'))

        # Check if there's anything to send (including credits)
        self.process_tx()

    def on_ui_frame(self, frame: RFCOMM_Frame) -> None:
        pass

    def on_mcc_msc(self, c_r: bool, msc: RFCOMM_MCC_MSC) -> None:
        if c_r:
            # Command
            logger.debug(f'<<< MCC MSC Command: {msc}')
            msc = RFCOMM_MCC_MSC(dlci=self.dlci, fc=0, rtc=1, rtr=1, ic=0, dv=1)
            mcc = RFCOMM_Frame.make_mcc(mcc_type=MccType.MSC, c_r=0, data=bytes(msc))
            logger.debug(f'>>> MCC MSC Response: {msc}')
            self.send_frame(RFCOMM_Frame.uih(c_r=self.c_r, dlci=0, information=mcc))
        else:
            # Response
            logger.debug(f'<<< MCC MSC Response: {msc}')

    def connect(self) -> None:
        if self.state != DLC.State.INIT:
            raise InvalidStateError('invalid state')

        self.change_state(DLC.State.CONNECTING)
        self.connection_result = asyncio.get_running_loop().create_future()
        self.send_frame(RFCOMM_Frame.sabm(c_r=self.c_r, dlci=self.dlci))

    def accept(self) -> None:
        if self.state != DLC.State.INIT:
            raise InvalidStateError('invalid state')

        pn = RFCOMM_MCC_PN(
            dlci=self.dlci,
            cl=0xE0,
            priority=7,
            ack_timer=0,
            max_frame_size=self.max_frame_size,
            max_retransmissions=0,
            window_size=self.window_size,
        )
        mcc = RFCOMM_Frame.make_mcc(mcc_type=MccType.PN, c_r=0, data=bytes(pn))
        logger.debug(f'>>> PN Response: {pn}')
        self.send_frame(RFCOMM_Frame.uih(c_r=self.c_r, dlci=0, information=mcc))
        self.change_state(DLC.State.CONNECTING)

    def rx_credits_needed(self) -> int:
        if self.rx_credits <= self.rx_threshold:
            return self.window_size - self.rx_credits

        return 0

    def process_tx(self) -> None:
        # Send anything we can (or an empty frame if we need to send rx credits)
        rx_credits_needed = self.rx_credits_needed()
        while (self.tx_buffer and self.tx_credits > 0) or rx_credits_needed > 0:
            # Get the next chunk, up to MTU size
            if rx_credits_needed > 0:
                chunk = bytes([rx_credits_needed]) + self.tx_buffer[: self.mtu - 1]
                self.tx_buffer = self.tx_buffer[len(chunk) - 1 :]
                self.rx_credits += rx_credits_needed
                tx_credit_spent = len(chunk) > 1
            else:
                chunk = self.tx_buffer[: self.mtu]
                self.tx_buffer = self.tx_buffer[len(chunk) :]
                tx_credit_spent = True

            # Update the tx credits
            # (no tx credit spent for empty frames that only contain rx credits)
            if tx_credit_spent:
                self.tx_credits -= 1

            # Send the frame
            logger.debug(
                f'>>> sending {len(chunk)} bytes with {rx_credits_needed} credits, '
                f'rx_credits={self.rx_credits}, '
                f'tx_credits={self.tx_credits}'
            )
            self.send_frame(
                RFCOMM_Frame.uih(
                    c_r=self.c_r,
                    dlci=self.dlci,
                    information=chunk,
                    p_f=1 if rx_credits_needed > 0 else 0,
                )
            )

            rx_credits_needed = 0
            if not self.tx_buffer:
                self.drained.set()

    # Stream protocol
    def write(self, data: Union[bytes, str]) -> None:
        # We can only send bytes
        if not isinstance(data, bytes):
            if isinstance(data, str):
                # Automatically convert strings to bytes using UTF-8
                data = data.encode('utf-8')
            else:
                raise ValueError('write only accept bytes or strings')

        self.tx_buffer += data
        self.drained.clear()
        self.process_tx()

    async def drain(self) -> None:
        await self.drained.wait()

    def __str__(self) -> str:
        return f'DLC(dlci={self.dlci},state={self.state.name})'


# -----------------------------------------------------------------------------
class Multiplexer(EventEmitter):
    class Role(enum.IntEnum):
        INITIATOR = 0x00
        RESPONDER = 0x01

    class State(enum.IntEnum):
        INIT = 0x00
        CONNECTING = 0x01
        CONNECTED = 0x02
        OPENING = 0x03
        DISCONNECTING = 0x04
        DISCONNECTED = 0x05
        RESET = 0x06

    connection_result: Optional[asyncio.Future]
    disconnection_result: Optional[asyncio.Future]
    open_result: Optional[asyncio.Future]
    acceptor: Optional[Callable[[int], bool]]
    dlcs: Dict[int, DLC]

    def __init__(self, l2cap_channel: l2cap.ClassicChannel, role: Role) -> None:
        super().__init__()
        self.role = role
        self.l2cap_channel = l2cap_channel
        self.state = Multiplexer.State.INIT
        self.dlcs = {}  # DLCs, by DLCI
        self.connection_result = None
        self.disconnection_result = None
        self.open_result = None
        self.acceptor = None

        # Become a sink for the L2CAP channel
        l2cap_channel.sink = self.on_pdu

    def change_state(self, new_state: State) -> None:
        logger.debug(f'{self} state change -> {color(new_state.name, "cyan")}')
        self.state = new_state

    def send_frame(self, frame: RFCOMM_Frame) -> None:
        logger.debug(f'>>> Multiplexer sending {frame}')
        self.l2cap_channel.send_pdu(frame)

    def on_pdu(self, pdu: bytes) -> None:
        frame = RFCOMM_Frame.from_bytes(pdu)
        logger.debug(f'<<< Multiplexer received {frame}')

        # Dispatch to this multiplexer or to a dlc, depending on the address
        if frame.dlci == 0:
            self.on_frame(frame)
        else:
            if frame.type == FrameType.DM:
                # DM responses are for a DLCI, but since we only create the dlc when we
                # receive a PN response (because we need the parameters), we handle DM
                # frames at the Multiplexer level
                self.on_dm_frame(frame)
            else:
                dlc = self.dlcs.get(frame.dlci)
                if dlc is None:
                    logger.warning(f'no dlc for DLCI {frame.dlci}')
                    return
                dlc.on_frame(frame)

    def on_frame(self, frame: RFCOMM_Frame) -> None:
        handler = getattr(self, f'on_{frame.type.name}_frame'.lower())
        handler(frame)

    def on_sabm_frame(self, _frame: RFCOMM_Frame) -> None:
        if self.state != Multiplexer.State.INIT:
            logger.debug('not in INIT state, ignoring SABM')
            return
        self.change_state(Multiplexer.State.CONNECTED)
        self.send_frame(RFCOMM_Frame.ua(c_r=1, dlci=0))

    def on_ua_frame(self, _frame: RFCOMM_Frame) -> None:
        if self.state == Multiplexer.State.CONNECTING:
            self.change_state(Multiplexer.State.CONNECTED)
            if self.connection_result:
                self.connection_result.set_result(0)
                self.connection_result = None
        elif self.state == Multiplexer.State.DISCONNECTING:
            self.change_state(Multiplexer.State.DISCONNECTED)
            if self.disconnection_result:
                self.disconnection_result.set_result(None)
                self.disconnection_result = None

    def on_dm_frame(self, _frame: RFCOMM_Frame) -> None:
        if self.state == Multiplexer.State.OPENING:
            self.change_state(Multiplexer.State.CONNECTED)
            if self.open_result:
                self.open_result.set_exception(
                    core.ConnectionError(
                        core.ConnectionError.CONNECTION_REFUSED,
                        BT_BR_EDR_TRANSPORT,
                        self.l2cap_channel.connection.peer_address,
                        'rfcomm',
                    )
                )
        else:
            logger.warning(f'unexpected state for DM: {self}')

    def on_disc_frame(self, _frame: RFCOMM_Frame) -> None:
        self.change_state(Multiplexer.State.DISCONNECTED)
        self.send_frame(
            RFCOMM_Frame.ua(
                c_r=0 if self.role == Multiplexer.Role.INITIATOR else 1, dlci=0
            )
        )

    def on_uih_frame(self, frame: RFCOMM_Frame) -> None:
        (mcc_type, c_r, value) = RFCOMM_Frame.parse_mcc(frame.information)

        if mcc_type == MccType.PN:
            pn = RFCOMM_MCC_PN.from_bytes(value)
            self.on_mcc_pn(c_r, pn)
        elif mcc_type == MccType.MSC:
            mcs = RFCOMM_MCC_MSC.from_bytes(value)
            self.on_mcc_msc(c_r, mcs)

    def on_ui_frame(self, frame: RFCOMM_Frame) -> None:
        pass

    def on_mcc_pn(self, c_r: bool, pn: RFCOMM_MCC_PN) -> None:
        if c_r:
            # Command
            logger.debug(f'<<< PN Command: {pn}')

            # Check with the multiplexer if there's an acceptor for this channel
            if pn.dlci & 1:
                # Not expected, this is an initiator-side number
                # TODO: error out
                logger.warning(f'invalid DLCI: {pn.dlci}')
            else:
                if self.acceptor:
                    channel_number = pn.dlci >> 1
                    if self.acceptor(channel_number):
                        # Create a new DLC
                        dlc = DLC(self, pn.dlci, pn.max_frame_size, pn.window_size)
                        self.dlcs[pn.dlci] = dlc

                        # Re-emit the handshake completion event
                        dlc.on('open', lambda: self.emit('dlc', dlc))

                        # Respond to complete the handshake
                        dlc.accept()
                    else:
                        # No acceptor, we're in Disconnected Mode
                        self.send_frame(RFCOMM_Frame.dm(c_r=1, dlci=pn.dlci))
                else:
                    # No acceptor?? shouldn't happen
                    logger.warning(color('!!! no acceptor registered', 'red'))
        else:
            # Response
            logger.debug(f'>>> PN Response: {pn}')
            if self.state == Multiplexer.State.OPENING:
                dlc = DLC(self, pn.dlci, pn.max_frame_size, pn.window_size)
                self.dlcs[pn.dlci] = dlc
                dlc.connect()
            else:
                logger.warning('ignoring PN response')

    def on_mcc_msc(self, c_r: bool, msc: RFCOMM_MCC_MSC) -> None:
        dlc = self.dlcs.get(msc.dlci)
        if dlc is None:
            logger.warning(f'no dlc for DLCI {msc.dlci}')
            return
        dlc.on_mcc_msc(c_r, msc)

    async def connect(self) -> None:
        if self.state != Multiplexer.State.INIT:
            raise InvalidStateError('invalid state')

        self.change_state(Multiplexer.State.CONNECTING)
        self.connection_result = asyncio.get_running_loop().create_future()
        self.send_frame(RFCOMM_Frame.sabm(c_r=1, dlci=0))
        return await self.connection_result

    async def disconnect(self) -> None:
        if self.state != Multiplexer.State.CONNECTED:
            return

        self.disconnection_result = asyncio.get_running_loop().create_future()
        self.change_state(Multiplexer.State.DISCONNECTING)
        self.send_frame(
            RFCOMM_Frame.disc(
                c_r=1 if self.role == Multiplexer.Role.INITIATOR else 0, dlci=0
            )
        )
        await self.disconnection_result

    async def open_dlc(
        self,
        channel: int,
        max_frame_size: int = RFCOMM_DEFAULT_MAX_FRAME_SIZE,
        window_size: int = RFCOMM_DEFAULT_WINDOW_SIZE,
    ) -> DLC:
        if self.state != Multiplexer.State.CONNECTED:
            if self.state == Multiplexer.State.OPENING:
                raise InvalidStateError('open already in progress')

            raise InvalidStateError('not connected')

        pn = RFCOMM_MCC_PN(
            dlci=channel << 1,
            cl=0xF0,
            priority=7,
            ack_timer=0,
            max_frame_size=max_frame_size,
            max_retransmissions=0,
            window_size=window_size,
        )
        mcc = RFCOMM_Frame.make_mcc(mcc_type=MccType.PN, c_r=1, data=bytes(pn))
        logger.debug(f'>>> Sending MCC: {pn}')
        self.open_result = asyncio.get_running_loop().create_future()
        self.change_state(Multiplexer.State.OPENING)
        self.send_frame(
            RFCOMM_Frame.uih(
                c_r=1 if self.role == Multiplexer.Role.INITIATOR else 0,
                dlci=0,
                information=mcc,
            )
        )
        result = await self.open_result
        self.open_result = None
        return result

    def on_dlc_open_complete(self, dlc: DLC) -> None:
        logger.debug(f'DLC [{dlc.dlci}] open complete')
        self.change_state(Multiplexer.State.CONNECTED)
        if self.open_result:
            self.open_result.set_result(dlc)

    def __str__(self) -> str:
        return f'Multiplexer(state={self.state.name})'


# -----------------------------------------------------------------------------
class Client:
    multiplexer: Optional[Multiplexer]
    l2cap_channel: Optional[l2cap.ClassicChannel]

    def __init__(
        self, connection: Connection, l2cap_mtu: int = RFCOMM_DEFAULT_L2CAP_MTU
    ) -> None:
        self.connection = connection
        self.l2cap_mtu = l2cap_mtu
        self.l2cap_channel = None
        self.multiplexer = None

    async def start(self) -> Multiplexer:
        # Create a new L2CAP connection
        try:
            self.l2cap_channel = await self.connection.create_l2cap_channel(
                spec=l2cap.ClassicChannelSpec(psm=RFCOMM_PSM, mtu=self.l2cap_mtu)
            )
        except ProtocolError as error:
            logger.warning(f'L2CAP connection failed: {error}')
            raise

        assert self.l2cap_channel is not None
        # Create a multiplexer to manage DLCs with the server
        self.multiplexer = Multiplexer(self.l2cap_channel, Multiplexer.Role.INITIATOR)

        # Connect the multiplexer
        await self.multiplexer.connect()

        return self.multiplexer

    async def shutdown(self) -> None:
        if self.multiplexer is None:
            return
        # Disconnect the multiplexer
        await self.multiplexer.disconnect()
        self.multiplexer = None

        # Close the L2CAP channel
        if self.l2cap_channel:
            await self.l2cap_channel.disconnect()
            self.l2cap_channel = None

    async def __aenter__(self) -> Multiplexer:
        return await self.start()

    async def __aexit__(self, *args) -> None:
        await self.shutdown()


# -----------------------------------------------------------------------------
class Server(EventEmitter):
    acceptors: Dict[int, Callable[[DLC], None]]

    def __init__(
        self, device: Device, l2cap_mtu: int = RFCOMM_DEFAULT_L2CAP_MTU
    ) -> None:
        super().__init__()
        self.device = device
        self.multiplexer = None
        self.acceptors = {}

        # Register ourselves with the L2CAP channel manager
        self.l2cap_server = device.create_l2cap_server(
            spec=l2cap.ClassicChannelSpec(psm=RFCOMM_PSM, mtu=l2cap_mtu),
            handler=self.on_connection,
        )

    def listen(self, acceptor: Callable[[DLC], None], channel: int = 0) -> int:
        if channel:
            if channel in self.acceptors:
                # Busy
                return 0
        else:
            # Find a free channel number
            for candidate in range(
                RFCOMM_DYNAMIC_CHANNEL_NUMBER_START,
                RFCOMM_DYNAMIC_CHANNEL_NUMBER_END + 1,
            ):
                if candidate not in self.acceptors:
                    channel = candidate
                    break

            if channel == 0:
                # All channels used...
                return 0

        self.acceptors[channel] = acceptor
        return channel

    def on_connection(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug(f'+++ new L2CAP connection: {l2cap_channel}')
        l2cap_channel.on('open', lambda: self.on_l2cap_channel_open(l2cap_channel))

    def on_l2cap_channel_open(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug(f'$$$ L2CAP channel open: {l2cap_channel}')

        # Create a new multiplexer for the channel
        multiplexer = Multiplexer(l2cap_channel, Multiplexer.Role.RESPONDER)
        multiplexer.acceptor = self.accept_dlc
        multiplexer.on('dlc', self.on_dlc)

        # Notify
        self.emit('start', multiplexer)

    def accept_dlc(self, channel_number: int) -> bool:
        return channel_number in self.acceptors

    def on_dlc(self, dlc: DLC) -> None:
        logger.debug(f'@@@ new DLC connected: {dlc}')

        # Let the acceptor know
        acceptor = self.acceptors.get(dlc.dlci >> 1)
        if acceptor:
            acceptor(dlc)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.l2cap_server.close()
