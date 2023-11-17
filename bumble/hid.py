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
import enum

from pyee import EventEmitter
from typing import Optional, TYPE_CHECKING

from bumble import l2cap
from bumble.colors import color
from bumble.core import InvalidStateError, ProtocolError

if TYPE_CHECKING:
    from bumble.device import Device, Connection


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: on
HID_CONTROL_PSM = 0x0011
HID_INTERRUPT_PSM = 0x0013


class Message:
    message_type: MessageType
    # Report types
    class ReportType(enum.IntEnum):
        OTHER_REPORT = 0x00
        INPUT_REPORT = 0x01
        OUTPUT_REPORT = 0x02
        FEATURE_REPORT = 0x03

    # Handshake parameters
    class Handshake(enum.IntEnum):
        SUCCESSFUL = 0x00
        NOT_READY = 0x01
        ERR_INVALID_REPORT_ID = 0x02
        ERR_UNSUPPORTED_REQUEST = 0x03
        ERR_UNKNOWN = 0x0E
        ERR_FATAL = 0x0F

    # Message Type
    class MessageType(enum.IntEnum):
        HANDSHAKE = 0x00
        CONTROL = 0x01
        GET_REPORT = 0x04
        SET_REPORT = 0x05
        GET_PROTOCOL = 0x06
        SET_PROTOCOL = 0x07
        DATA = 0x0A

    # Protocol modes
    class ProtocolMode(enum.IntEnum):
        BOOT_PROTOCOL = 0x00
        REPORT_PROTOCOL = 0x01

    # Control Operations
    class ControlCommand(enum.IntEnum):
        SUSPEND = 0x03
        EXIT_SUSPEND = 0x04
        VIRTUAL_CABLE_UNPLUG = 0x05

    # Class Method to derive header
    @classmethod
    def header(cls, lower_bits: int = 0x00) -> bytes:
        return bytes([(cls.message_type << 4) | lower_bits])


# HIDP messages
@dataclass
class GetReportMessage(Message):
    report_type: int
    report_id: int
    buffer_size: int
    message_type = Message.MessageType.GET_REPORT

    def __bytes__(self) -> bytes:
        packet_bytes = bytearray()
        packet_bytes.append(self.report_id)
        packet_bytes.extend(
            [(self.buffer_size & 0xFF), ((self.buffer_size >> 8) & 0xFF)]
        )
        if self.report_type == Message.ReportType.OTHER_REPORT:
            return self.header(self.report_type) + packet_bytes
        else:
            return self.header(0x08 | self.report_type) + packet_bytes


@dataclass
class SetReportMessage(Message):
    report_type: int
    data: bytes
    message_type = Message.MessageType.SET_REPORT

    def __bytes__(self) -> bytes:
        return self.header(self.report_type) + self.data


@dataclass
class GetProtocolMessage(Message):
    message_type = Message.MessageType.GET_PROTOCOL

    def __bytes__(self) -> bytes:
        return self.header()


@dataclass
class SetProtocolMessage(Message):
    protocol_mode: int
    message_type = Message.MessageType.SET_PROTOCOL

    def __bytes__(self) -> bytes:
        return self.header(self.protocol_mode)


@dataclass
class Suspend(Message):
    message_type = Message.MessageType.CONTROL

    def __bytes__(self) -> bytes:
        return self.header(Message.ControlCommand.SUSPEND)


@dataclass
class ExitSuspend(Message):
    message_type = Message.MessageType.CONTROL

    def __bytes__(self) -> bytes:
        return self.header(Message.ControlCommand.EXIT_SUSPEND)


@dataclass
class VirtualCableUnplug(Message):
    message_type = Message.MessageType.CONTROL

    def __bytes__(self) -> bytes:
        return self.header(Message.ControlCommand.VIRTUAL_CABLE_UNPLUG)


@dataclass
class SendData(Message):
    data: bytes
    message_type = Message.MessageType.DATA

    def __bytes__(self) -> bytes:
        return self.header(Message.ReportType.OUTPUT_REPORT) + self.data


# -----------------------------------------------------------------------------
class Host(EventEmitter):
    l2cap_ctrl_channel: Optional[l2cap.ClassicChannel]
    l2cap_intr_channel: Optional[l2cap.ClassicChannel]

    def __init__(self, device: Device, connection: Connection) -> None:
        super().__init__()
        self.device = device
        self.connection = connection

        self.l2cap_ctrl_channel = None
        self.l2cap_intr_channel = None

        # Register ourselves with the L2CAP channel manager
        device.register_l2cap_server(HID_CONTROL_PSM, self.on_connection)
        device.register_l2cap_server(HID_INTERRUPT_PSM, self.on_connection)

    async def connect_control_channel(self) -> None:
        # Create a new L2CAP connection - control channel
        try:
            self.l2cap_ctrl_channel = await self.device.l2cap_channel_manager.connect(
                self.connection, HID_CONTROL_PSM
            )
        except ProtocolError:
            logging.exception(f'L2CAP connection failed.')
            raise

        assert self.l2cap_ctrl_channel is not None
        # Become a sink for the L2CAP channel
        self.l2cap_ctrl_channel.sink = self.on_ctrl_pdu

    async def connect_interrupt_channel(self) -> None:
        # Create a new L2CAP connection - interrupt channel
        try:
            self.l2cap_intr_channel = await self.device.l2cap_channel_manager.connect(
                self.connection, HID_INTERRUPT_PSM
            )
        except ProtocolError:
            logging.exception(f'L2CAP connection failed.')
            raise

        assert self.l2cap_intr_channel is not None
        # Become a sink for the L2CAP channel
        self.l2cap_intr_channel.sink = self.on_intr_pdu

    async def disconnect_interrupt_channel(self) -> None:
        if self.l2cap_intr_channel is None:
            raise InvalidStateError('invalid state')
        channel = self.l2cap_intr_channel
        self.l2cap_intr_channel = None
        await channel.disconnect()

    async def disconnect_control_channel(self) -> None:
        if self.l2cap_ctrl_channel is None:
            raise InvalidStateError('invalid state')
        channel = self.l2cap_ctrl_channel
        self.l2cap_ctrl_channel = None
        await channel.disconnect()

    def on_connection(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug(f'+++ New L2CAP connection: {l2cap_channel}')
        l2cap_channel.on('open', lambda: self.on_l2cap_channel_open(l2cap_channel))

    def on_l2cap_channel_open(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        if l2cap_channel.psm == HID_CONTROL_PSM:
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
        param = pdu[0] & 0x0F

        if message_type == Message.MessageType.HANDSHAKE:
            logger.debug(f'<<< HID HANDSHAKE: {Message.Handshake(param).name}')
            self.emit('handshake', Message.Handshake(param))
        elif message_type == Message.MessageType.DATA:
            logger.debug('<<< HID CONTROL DATA')
            self.emit('data', pdu)
        elif message_type == Message.MessageType.CONTROL:
            if param == Message.ControlCommand.SUSPEND:
                logger.debug('<<< HID SUSPEND')
                self.emit('suspend', pdu)
            elif param == Message.ControlCommand.EXIT_SUSPEND:
                logger.debug('<<< HID EXIT SUSPEND')
                self.emit('exit_suspend', pdu)
            elif param == Message.ControlCommand.VIRTUAL_CABLE_UNPLUG:
                logger.debug('<<< HID VIRTUAL CABLE UNPLUG')
                self.emit('virtual_cable_unplug')
            else:
                logger.debug('<<< HID CONTROL OPERATION UNSUPPORTED')
        else:
            logger.debug('<<< HID CONTROL DATA')
            self.emit('data', pdu)

    def on_intr_pdu(self, pdu: bytes) -> None:
        logger.debug(f'<<< HID INTERRUPT PDU: {pdu.hex()}')
        self.emit("data", pdu)

    def get_report(self, report_type: int, report_id: int, buffer_size: int) -> None:
        msg = GetReportMessage(
            report_type=report_type, report_id=report_id, buffer_size=buffer_size
        )
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL GET REPORT, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def set_report(self, report_type: int, data: bytes):
        msg = SetReportMessage(report_type=report_type, data=data)
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL SET REPORT, PDU:{hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def get_protocol(self):
        msg = GetProtocolMessage()
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL GET PROTOCOL, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def set_protocol(self, protocol_mode: int):
        msg = SetProtocolMessage(protocol_mode=protocol_mode)
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL SET PROTOCOL, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def send_pdu_on_ctrl(self, msg: bytes) -> None:
        assert self.l2cap_ctrl_channel
        self.l2cap_ctrl_channel.send_pdu(msg)

    def send_pdu_on_intr(self, msg: bytes) -> None:
        assert self.l2cap_intr_channel
        self.l2cap_intr_channel.send_pdu(msg)

    def send_data(self, data):
        msg = SendData(data)
        hid_message = bytes(msg)
        logger.debug(f'>>> HID INTERRUPT SEND DATA, PDU: {hid_message.hex()}')
        self.send_pdu_on_intr(hid_message)

    def suspend(self):
        msg = Suspend()
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL SUSPEND, PDU:{hid_message.hex()}')
        self.send_pdu_on_ctrl(msg)

    def exit_suspend(self):
        msg = ExitSuspend()
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL EXIT SUSPEND, PDU:{hid_message.hex()}')
        self.send_pdu_on_ctrl(msg)

    def virtual_cable_unplug(self):
        msg = VirtualCableUnplug()
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL VIRTUAL CABLE UNPLUG, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(msg)
