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
from dataclasses import dataclass
import logging
import asyncio
import enum

from pyee import EventEmitter
from typing import Optional, Tuple, Callable, Dict, Union, TYPE_CHECKING

from . import core, l2cap  # type: ignore
from .colors import color  # type: ignore
from .core import BT_BR_EDR_TRANSPORT, InvalidStateError, ProtocolError  # type: ignore

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




class Message():
    class HIDPsm(enum.IntEnum):
        HID_CONTROL_PSM            = 0x0011
        HID_INTERRUPT_PSM          = 0x0013

    # Report types
    class ReportType(enum.IntEnum):
        HID_OTHER_REPORT        = 0x00
        HID_INPUT_REPORT        = 0x01
        HID_OUTPUT_REPORT       = 0x02
        HID_FEATURE_REPORT      = 0x03

    # Handshake parameters
    class HandshakeState(enum.IntEnum):
        HANDSHAKE_SUCCESSFUL              = 0x00
        HANDSHAKE_NOT_READY               = 0x01
        HANDSHAKE_ERR_INVALID_REPORT_ID   = 0x02
        HANDSHAKE_ERR_UNSUPPORTED_REQUEST = 0x03
        HANDSHAKE_ERR_UNKNOWN             = 0x0E
        HANDSHAKE_ERR_FATAL               = 0x0F

    class Type(enum.IntEnum):
        HID_HANDSHAKE           = 0x00
        HID_CONTROL             = 0x01
        HID_GET_REPORT          = 0x04
        HID_SET_REPORT          = 0x05
        HID_GET_PROTOCOL        = 0x06
        HID_SET_PROTOCOL        = 0x07
        HID_DATA                = 0x0A

    # Protocol modes
    class ProtocolMode(enum.IntEnum):
        HID_BOOT_PROTOCOL_MODE      = 0x00
        HID_REPORT_PROTOCOL_MODE    = 0x01

    # Control Operations
    class ControlCommand(enum.IntEnum):
        HID_SUSPEND              = 0x03
        HID_EXIT_SUSPEND         = 0x04
        HID_VIRTUAL_CABLE_UNPLUG = 0x05


    # HIDP message types
@dataclass
class GetReportMessage(Message):
    report_type : int
    report_id : int
    buffer_size : int
    '''
    def __init__(self,
                 report_type: Optional[int] = None,
                 report_id: Optional[int] = None,
                 buffer_size: Optional[int] = None,
                  ):
        self.report_type = report_type
        self.report_id = report_id
        self.buffer_size = buffer_size
    '''
    def __bytes__(self) -> bytes:
        if(self.report_type == Message.ReportType.HID_OTHER_REPORT):
            param = self.report_type
        else:
            param = 0x08 | self.report_type
        header = ((Message.Type.HID_GET_REPORT << 4) | param)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        packet_bytes.append(self.report_id)
        packet_bytes.extend([(self.buffer_size & 0xff), ((self.buffer_size >> 8) & 0xff)])
        return bytes(packet_bytes)

class SetReportMessage(Message):

    def __init__(self,
                 report_type: int,
                 data : bytes):
            self.report_type = report_type
            self.data = data

    def __bytes__(self) -> bytes:
        header = ((Message.Type.HID_SET_REPORT << 4) | self.report_type)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        packet_bytes.extend(self.data)
        return bytes(packet_bytes)

class GetProtocolMessage(Message):


    def __bytes__(self) -> bytes:
        header = (Message.Type.HID_GET_PROTOCOL << 4)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        return bytes(packet_bytes)

class SetProtocolMessage(Message):

    def __init__(self, protocol_mode: int):
            self.protocol_mode = protocol_mode


    def __bytes__(self) -> bytes:
        header = (Message.Type.HID_SET_PROTOCOL << 4 | self.protocol_mode)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        packet_bytes.append(self.protocol_mode)
        return bytes(packet_bytes)

class SendData(Message):
    def __init__(self, data : bytes):
            self.data = data

    def __bytes__(self) -> bytes:
        header = ((Message.Type.HID_DATA << 4) | Message.ReportType.HID_OUTPUT_REPORT)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        packet_bytes.extend(self.data)
        return bytes(packet_bytes)
# -----------------------------------------------------------------------------
class Host(EventEmitter):
    l2cap_channel: Optional[l2cap.Channel]

    def __init__(self, device: Device, connection: Connection) -> None:
        super().__init__()
        self.device = device
        self.connection = connection
        self.l2cap_ctrl_channel= None
        self.l2cap_intr_channel = None

        # Register ourselves with the L2CAP channel manager
        device.register_l2cap_server(Message.HIDPsm.HID_CONTROL_PSM, self.on_connection)
        device.register_l2cap_server(Message.HIDPsm.HID_INTERRUPT_PSM, self.on_connection)

    async def connect_control_channel(self) -> None:
        # Create a new L2CAP connection - control channel
        try:
            self.l2cap_ctrl_channel = await self.device.l2cap_channel_manager.connect(
                self.connection, Message.HIDPsm.HID_CONTROL_PSM
            )
        except ProtocolError as error:
            logging.exception(f'L2CAP connection failed: {error}')
            raise

        assert self.l2cap_ctrl_channel is not None
        # Become a sink for the L2CAP channel
        self.l2cap_ctrl_channel.sink = self.on_ctrl_pdu

    async def connect_interrupt_channel(self) -> None:
        # Create a new L2CAP connection - interrupt channel
        try:
            self.l2cap_intr_channel = await self.device.l2cap_channel_manager.connect(
                self.connection, Message.HIDPsm.HID_INTERRUPT_PSM
            )
        except ProtocolError as error:
            logging.exception(f'L2CAP connection failed: {error}')
            raise

        assert self.l2cap_intr_channel is not None
        # Become a sink for the L2CAP channel
        self.l2cap_intr_channel.sink = self.on_intr_pdu

    async def disconnect_interrupt_channel(self) -> None:
        if self.l2cap_intr_channel is None:
            raise InvalidStateError('invalid state')
        await self.l2cap_intr_channel.disconnect()  # type: ignore
        channel = self.l2cap_intr_channel
        self.l2cap_intr_channel = None
        await channel.disconnect()  # type: ignore

    async def disconnect_control_channel(self) -> None:
        if self.l2cap_ctrl_channel is None:
            raise InvalidStateError('invalid state')
        await self.l2cap_ctrl_channel.disconnect()  # type: ignore
        channel = self.l2cap_ctrl_channel
        self.l2cap_ctrl_channel = None
        await channel.disconnect()  # type: ignore

    def on_connection(self, l2cap_channel: l2cap.Channel) -> None:
        logger.debug(f'+++ New L2CAP connection: {l2cap_channel}')
        l2cap_channel.on('open', lambda: self.on_l2cap_channel_open(l2cap_channel))

    def on_l2cap_channel_open(self, l2cap_channel: l2cap.Channel) -> None:
        if l2cap_channel.psm == Message.HIDPsm.HID_CONTROL_PSM:
            self.l2cap_ctrl_channel = l2cap_channel
            self.l2cap_ctrl_channel.sink = self.on_ctrl_pdu
        else:
            self.l2cap_intr_channel = l2cap_channel
            self.l2cap_intr_channel.sink = self.on_intr_pdu
        logger.debug(f'$$$ L2CAP channel open: {l2cap_channel}')

    def on_ctrl_pdu(self, pdu: bytes) -> None:
        logger.debug(f'<<< HID CONTROL PDU: {pdu.hex()}')
        # Here we will receive all kinds of packets, parse and then call respective callbacks
        message_type = pdu[0] >> 4
        param = pdu[0] & 0x0f

        for command in Message.ControlCommand.__members__items():
            if param == command:
                logger.debug(f'<<< ', command + pdu)
                self.handle_handshake(param)
                self.emit(command, pdu)
        '''
        if message_type == Message.Type.HID_HANDSHAKE :
            logger.debug('<<< HID HANDSHAKE')
            self.handle_handshake(param)
            self.emit('handshake', pdu)
        elif message_type == Message.Type.HID_DATA :
            logger.debug('<<< HID CONTROL DATA')
            self.emit('data', pdu)
        elif message_type == Message.Type.HID_CONTROL :
            if param == Message.ControlCommand.HID_SUSPEND :
                logger.debug('<<< HID SUSPEND')
                self.emit('suspend', pdu)
            elif param == HID_EXIT_SUSPEND :
                logger.debug('<<< HID EXIT SUSPEND')
                self.emit('exit_suspend', pdu)
            elif param == HID_VIRTUAL_CABLE_UNPLUG :
                logger.debug('<<< HID VIRTUAL CABLE UNPLUG')
                self.emit('virtual_cable_unplug')
            else:
                logger.debug('<<< HID CONTROL OPERATION UNSUPPORTED')
        else:
            logger.debug('<<< HID CONTROL DATA')
            self.emit('data', pdu)
        '''

    def on_intr_pdu(self, pdu: bytes) -> None:
        logger.debug(f'<<< HID INTERRUPT PDU: {pdu.hex()}')
        self.emit("data", pdu)

    def get_report(self, report_type: int, report_id: int, buffer_size: int) -> None:
        msg = GetReportMessage(report_type = report_type , report_id = report_id , buffer_size = buffer_size)
        hid_message = msg.__bytes__()
        logger.debug(f'>>> HID CONTROL GET REPORT, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)  # type: ignore

    def set_report(self, report_type: int, data: bytes):
        msg = SetReportMessage(report_type= report_type,data = data)
        hid_message = msg.__bytes__()
        logger.debug(f'>>> HID CONTROL SET REPORT, PDU:{hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)  # type: ignore

    def get_protocol(self):
        msg = GetProtocolMessage()
        hid_message = msg.__bytes__()
        logger.debug(f'>>> HID CONTROL GET PROTOCOL, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)  # type: ignore

    def set_protocol(self, protocol_mode: int):
        msg = SetProtocolMessage(protocol_mode= protocol_mode)
        hid_message = msg.__bytes__()
        logger.debug(f'>>> HID CONTROL SET PROTOCOL, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)  # type: ignore

    def send_pdu_on_ctrl(self, msg: bytes) -> None:
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def send_pdu_on_intr(self, msg: bytes) -> None:
        self.l2cap_intr_channel.send_pdu(msg)  # type: ignore

    def send_data(self, data):
        msg = Message(data= data)
        hid_message = msg.__bytes__()
        logger.debug(f'>>> HID INTERRUPT SEND DATA, PDU: {hid_message.hex()}')
        self.send_pdu_on_intr(hid_message)  # type: ignore

    def suspend(self):
        header = (Message.Type.HID_CONTROL << 4 | Message.ControlCommand.HID_SUSPEND)
        msg = bytearray([header])
        logger.debug(f'>>> HID CONTROL SUSPEND, PDU:{msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def exit_suspend(self):
        header = (Message.Type.HID_CONTROL << 4 | Message.ControlCommand.HID_EXIT_SUSPEND)
        msg = bytearray([header])
        logger.debug(f'>>> HID CONTROL EXIT SUSPEND, PDU:{msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def virtual_cable_unplug(self):
        header = (Message.Type.HID_CONTROL << 4 | Message.ControlCommand.HID_VIRTUAL_CABLE_UNPLUG)
        msg = bytearray([header])
        logger.debug(f'>>> HID CONTROL VIRTUAL CABLE UNPLUG, PDU: {msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def handle_handshake(self, param: Message.HandshakeState):
        for state in Message.HandshakeState.__members__items():
            if param == state:
                logger.debug(f'<<< HID HANDSHAKE: ', state)
        '''
        if param == HANDSHAKE_SUCCESSFUL :
            logger.debug(f'<<< HID HANDSHAKE: SUCCESSFUL')
        elif param == HANDSHAKE_NOT_READY :
            logger.warning(f'<<< HID HANDSHAKE: NOT_READY')
        elif param == HANDSHAKE_ERR_INVALID_REPORT_ID :
            logger.warning(f'<<< HID HANDSHAKE: ERR_INVALID_REPORT_ID')
        elif param == HANDSHAKE_ERR_UNSUPPORTED_REQUEST :
            logger.warning(f'<<< HID HANDSHAKE: ERR_UNSUPPORTED_REQUEST')
        elif param == HANDSHAKE_ERR_UNKNOWN :
            logger.warning(f'<<< HID HANDSHAKE: ERR_UNKNOWN')
        elif param == HANDSHAKE_ERR_FATAL :
            logger.warning(f'<<< HID HANDSHAKE: ERR_FATAL')
        else: # 0x5-0xD = Reserved
            logger.warning("<<< HID HANDSHAKE: RESERVED VALUE")
        '''