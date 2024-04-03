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
import struct

from abc import ABC, abstractmethod
from pyee import EventEmitter
from typing import Optional, Callable, TYPE_CHECKING
from typing_extensions import override

from bumble import l2cap, device
from bumble.colors import color
from bumble.core import InvalidStateError, ProtocolError
from .hci import Address


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
        ERR_INVALID_PARAMETER = 0x04
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
        if self.buffer_size == 0:
            return self.header(self.report_type) + packet_bytes
        else:
            return (
                self.header(0x08 | self.report_type)
                + packet_bytes
                + struct.pack("<H", self.buffer_size)
            )


@dataclass
class SetReportMessage(Message):
    report_type: int
    data: bytes
    message_type = Message.MessageType.SET_REPORT

    def __bytes__(self) -> bytes:
        return self.header(self.report_type) + self.data


@dataclass
class SendControlData(Message):
    report_type: int
    data: bytes
    message_type = Message.MessageType.DATA

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


# Device sends input report, host sends output report.
@dataclass
class SendData(Message):
    data: bytes
    report_type: int
    message_type = Message.MessageType.DATA

    def __bytes__(self) -> bytes:
        return self.header(self.report_type) + self.data


@dataclass
class SendHandshakeMessage(Message):
    result_code: int
    message_type = Message.MessageType.HANDSHAKE

    def __bytes__(self) -> bytes:
        return self.header(self.result_code)


# -----------------------------------------------------------------------------
class HID(ABC, EventEmitter):
    l2cap_ctrl_channel: Optional[l2cap.ClassicChannel] = None
    l2cap_intr_channel: Optional[l2cap.ClassicChannel] = None
    connection: Optional[device.Connection] = None

    class Role(enum.IntEnum):
        HOST = 0x00
        DEVICE = 0x01

    def __init__(self, device: device.Device, role: Role) -> None:
        super().__init__()
        self.remote_device_bd_address: Optional[Address] = None
        self.device = device
        self.role = role

        # Register ourselves with the L2CAP channel manager
        device.register_l2cap_server(HID_CONTROL_PSM, self.on_l2cap_connection)
        device.register_l2cap_server(HID_INTERRUPT_PSM, self.on_l2cap_connection)

        device.on('connection', self.on_device_connection)

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

    def on_device_connection(self, connection: device.Connection) -> None:
        self.connection = connection
        self.remote_device_bd_address = connection.peer_address
        connection.on('disconnection', self.on_device_disconnection)

    def on_device_disconnection(self, reason: int) -> None:
        self.connection = None

    def on_l2cap_connection(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug(f'+++ New L2CAP connection: {l2cap_channel}')
        l2cap_channel.on('open', lambda: self.on_l2cap_channel_open(l2cap_channel))
        l2cap_channel.on('close', lambda: self.on_l2cap_channel_close(l2cap_channel))

    def on_l2cap_channel_open(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        if l2cap_channel.psm == HID_CONTROL_PSM:
            self.l2cap_ctrl_channel = l2cap_channel
            self.l2cap_ctrl_channel.sink = self.on_ctrl_pdu
        else:
            self.l2cap_intr_channel = l2cap_channel
            self.l2cap_intr_channel.sink = self.on_intr_pdu
        logger.debug(f'$$$ L2CAP channel open: {l2cap_channel}')

    def on_l2cap_channel_close(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        if l2cap_channel.psm == HID_CONTROL_PSM:
            self.l2cap_ctrl_channel = None
        else:
            self.l2cap_intr_channel = None
        logger.debug(f'$$$ L2CAP channel close: {l2cap_channel}')

    @abstractmethod
    def on_ctrl_pdu(self, pdu: bytes) -> None:
        pass

    def on_intr_pdu(self, pdu: bytes) -> None:
        logger.debug(f'<<< HID INTERRUPT PDU: {pdu.hex()}')
        self.emit("interrupt_data", pdu)

    def send_pdu_on_ctrl(self, msg: bytes) -> None:
        assert self.l2cap_ctrl_channel
        self.l2cap_ctrl_channel.send_pdu(msg)

    def send_pdu_on_intr(self, msg: bytes) -> None:
        assert self.l2cap_intr_channel
        self.l2cap_intr_channel.send_pdu(msg)

    def send_data(self, data: bytes) -> None:
        if self.role == HID.Role.HOST:
            report_type = Message.ReportType.OUTPUT_REPORT
        else:
            report_type = Message.ReportType.INPUT_REPORT
        msg = SendData(data, report_type)
        hid_message = bytes(msg)
        if self.l2cap_intr_channel is not None:
            logger.debug(f'>>> HID INTERRUPT SEND DATA, PDU: {hid_message.hex()}')
            self.send_pdu_on_intr(hid_message)

    def virtual_cable_unplug(self) -> None:
        msg = VirtualCableUnplug()
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL VIRTUAL CABLE UNPLUG, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)


# -----------------------------------------------------------------------------


class Device(HID):
    class GetSetReturn(enum.IntEnum):
        FAILURE = 0x00
        REPORT_ID_NOT_FOUND = 0x01
        ERR_UNSUPPORTED_REQUEST = 0x02
        ERR_UNKNOWN = 0x03
        ERR_INVALID_PARAMETER = 0x04
        SUCCESS = 0xFF

    class GetSetStatus:
        def __init__(self) -> None:
            self.data = bytearray()
            self.status = 0

    def __init__(self, device: device.Device) -> None:
        super().__init__(device, HID.Role.DEVICE)
        get_report_cb: Optional[Callable[[int, int, int], None]] = None
        set_report_cb: Optional[Callable[[int, int, int, bytes], None]] = None
        get_protocol_cb: Optional[Callable[[], None]] = None
        set_protocol_cb: Optional[Callable[[int], None]] = None

    @override
    def on_ctrl_pdu(self, pdu: bytes) -> None:
        logger.debug(f'<<< HID CONTROL PDU: {pdu.hex()}')
        param = pdu[0] & 0x0F
        message_type = pdu[0] >> 4

        if message_type == Message.MessageType.GET_REPORT:
            logger.debug('<<< HID GET REPORT')
            self.handle_get_report(pdu)
        elif message_type == Message.MessageType.SET_REPORT:
            logger.debug('<<< HID SET REPORT')
            self.handle_set_report(pdu)
        elif message_type == Message.MessageType.GET_PROTOCOL:
            logger.debug('<<< HID GET PROTOCOL')
            self.handle_get_protocol(pdu)
        elif message_type == Message.MessageType.SET_PROTOCOL:
            logger.debug('<<< HID SET PROTOCOL')
            self.handle_set_protocol(pdu)
        elif message_type == Message.MessageType.DATA:
            logger.debug('<<< HID CONTROL DATA')
            self.emit('control_data', pdu)
        elif message_type == Message.MessageType.CONTROL:
            if param == Message.ControlCommand.SUSPEND:
                logger.debug('<<< HID SUSPEND')
                self.emit('suspend')
            elif param == Message.ControlCommand.EXIT_SUSPEND:
                logger.debug('<<< HID EXIT SUSPEND')
                self.emit('exit_suspend')
            elif param == Message.ControlCommand.VIRTUAL_CABLE_UNPLUG:
                logger.debug('<<< HID VIRTUAL CABLE UNPLUG')
                self.emit('virtual_cable_unplug')
            else:
                logger.debug('<<< HID CONTROL OPERATION UNSUPPORTED')
        else:
            logger.debug('<<< HID MESSAGE TYPE UNSUPPORTED')
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)

    def send_handshake_message(self, result_code: int) -> None:
        msg = SendHandshakeMessage(result_code)
        hid_message = bytes(msg)
        logger.debug(f'>>> HID HANDSHAKE MESSAGE, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def send_control_data(self, report_type: int, data: bytes):
        msg = SendControlData(report_type=report_type, data=data)
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL DATA: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def handle_get_report(self, pdu: bytes):
        if self.get_report_cb is None:
            logger.debug("GetReport callback not registered !!")
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
            return
        report_type = pdu[0] & 0x03
        buffer_flag = (pdu[0] & 0x08) >> 3
        report_id = pdu[1]
        logger.debug(f"buffer_flag: {buffer_flag}")
        if buffer_flag == 1:
            buffer_size = (pdu[3] << 8) | pdu[2]
        else:
            buffer_size = 0

        ret = self.get_report_cb(report_id, report_type, buffer_size)
        assert ret is not None
        if ret.status == self.GetSetReturn.FAILURE:
            self.send_handshake_message(Message.Handshake.ERR_UNKNOWN)
        elif ret.status == self.GetSetReturn.SUCCESS:
            data = bytearray()
            data.append(report_id)
            data.extend(ret.data)
            if len(data) < self.l2cap_ctrl_channel.peer_mtu:  # type: ignore[union-attr]
                self.send_control_data(report_type=report_type, data=data)
            else:
                self.send_handshake_message(Message.Handshake.ERR_INVALID_PARAMETER)
        elif ret.status == self.GetSetReturn.REPORT_ID_NOT_FOUND:
            self.send_handshake_message(Message.Handshake.ERR_INVALID_REPORT_ID)
        elif ret.status == self.GetSetReturn.ERR_INVALID_PARAMETER:
            self.send_handshake_message(Message.Handshake.ERR_INVALID_PARAMETER)
        elif ret.status == self.GetSetReturn.ERR_UNSUPPORTED_REQUEST:
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)

    def register_get_report_cb(self, cb: Callable[[int, int, int], None]) -> None:
        self.get_report_cb = cb
        logger.debug("GetReport callback registered successfully")

    def handle_set_report(self, pdu: bytes):
        if self.set_report_cb is None:
            logger.debug("SetReport callback not registered !!")
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
            return
        report_type = pdu[0] & 0x03
        report_id = pdu[1]
        report_data = pdu[2:]
        report_size = len(report_data) + 1
        ret = self.set_report_cb(report_id, report_type, report_size, report_data)
        assert ret is not None
        if ret.status == self.GetSetReturn.SUCCESS:
            self.send_handshake_message(Message.Handshake.SUCCESSFUL)
        elif ret.status == self.GetSetReturn.ERR_INVALID_PARAMETER:
            self.send_handshake_message(Message.Handshake.ERR_INVALID_PARAMETER)
        elif ret.status == self.GetSetReturn.REPORT_ID_NOT_FOUND:
            self.send_handshake_message(Message.Handshake.ERR_INVALID_REPORT_ID)
        else:
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)

    def register_set_report_cb(
        self, cb: Callable[[int, int, int, bytes], None]
    ) -> None:
        self.set_report_cb = cb
        logger.debug("SetReport callback registered successfully")

    def handle_get_protocol(self, pdu: bytes):
        if self.get_protocol_cb is None:
            logger.debug("GetProtocol callback not registered !!")
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
            return
        ret = self.get_protocol_cb()
        assert ret is not None
        if ret.status == self.GetSetReturn.SUCCESS:
            self.send_control_data(Message.ReportType.OTHER_REPORT, ret.data)
        else:
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)

    def register_get_protocol_cb(self, cb: Callable[[], None]) -> None:
        self.get_protocol_cb = cb
        logger.debug("GetProtocol callback registered successfully")

    def handle_set_protocol(self, pdu: bytes):
        if self.set_protocol_cb is None:
            logger.debug("SetProtocol callback not registered !!")
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
            return
        ret = self.set_protocol_cb(pdu[0] & 0x01)
        assert ret is not None
        if ret.status == self.GetSetReturn.SUCCESS:
            self.send_handshake_message(Message.Handshake.SUCCESSFUL)
        else:
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)

    def register_set_protocol_cb(self, cb: Callable[[int], None]) -> None:
        self.set_protocol_cb = cb
        logger.debug("SetProtocol callback registered successfully")


# -----------------------------------------------------------------------------
class Host(HID):
    def __init__(self, device: device.Device) -> None:
        super().__init__(device, HID.Role.HOST)

    def get_report(self, report_type: int, report_id: int, buffer_size: int) -> None:
        msg = GetReportMessage(
            report_type=report_type, report_id=report_id, buffer_size=buffer_size
        )
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL GET REPORT, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def set_report(self, report_type: int, data: bytes) -> None:
        msg = SetReportMessage(report_type=report_type, data=data)
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL SET REPORT, PDU:{hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def get_protocol(self) -> None:
        msg = GetProtocolMessage()
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL GET PROTOCOL, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def set_protocol(self, protocol_mode: int) -> None:
        msg = SetProtocolMessage(protocol_mode=protocol_mode)
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL SET PROTOCOL, PDU: {hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def suspend(self) -> None:
        msg = Suspend()
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL SUSPEND, PDU:{hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    def exit_suspend(self) -> None:
        msg = ExitSuspend()
        hid_message = bytes(msg)
        logger.debug(f'>>> HID CONTROL EXIT SUSPEND, PDU:{hid_message.hex()}')
        self.send_pdu_on_ctrl(hid_message)

    @override
    def on_ctrl_pdu(self, pdu: bytes) -> None:
        logger.debug(f'<<< HID CONTROL PDU: {pdu.hex()}')
        param = pdu[0] & 0x0F
        message_type = pdu[0] >> 4
        if message_type == Message.MessageType.HANDSHAKE:
            logger.debug(f'<<< HID HANDSHAKE: {Message.Handshake(param).name}')
            self.emit('handshake', Message.Handshake(param))
        elif message_type == Message.MessageType.DATA:
            logger.debug('<<< HID CONTROL DATA')
            self.emit('control_data', pdu)
        elif message_type == Message.MessageType.CONTROL:
            if param == Message.ControlCommand.VIRTUAL_CABLE_UNPLUG:
                logger.debug('<<< HID VIRTUAL CABLE UNPLUG')
                self.emit('virtual_cable_unplug')
            else:
                logger.debug('<<< HID CONTROL OPERATION UNSUPPORTED')
        else:
            logger.debug('<<< HID MESSAGE TYPE UNSUPPORTED')
