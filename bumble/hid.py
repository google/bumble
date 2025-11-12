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
import logging
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, ClassVar, Optional, TypeVar

from typing_extensions import override

from bumble import core, device, l2cap, utils
from bumble.hci import Address

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


class HidProtocolError(core.ProtocolError):
    result_code: HandshakeMessage.ResultCode

    def __init__(self, result_code: HandshakeMessage.ResultCode):
        self.result_code = result_code
        super().__init__(
            result_code.value, error_namespace='HID', error_name=result_code.name
        )


# Report types
class ReportType(utils.OpenIntEnum):
    OTHER_REPORT = 0x00
    INPUT_REPORT = 0x01
    OUTPUT_REPORT = 0x02
    FEATURE_REPORT = 0x03


# Protocol modes
class ProtocolMode(utils.OpenIntEnum):
    BOOT_PROTOCOL = 0x00
    REPORT_PROTOCOL = 0x01


# Messages
class Message:

    class Type(utils.OpenIntEnum):
        HANDSHAKE = 0x00
        CONTROL = 0x01
        GET_REPORT = 0x04
        SET_REPORT = 0x05
        GET_PROTOCOL = 0x06
        SET_PROTOCOL = 0x07
        DATA = 0x0A

    message_type: Type

    subclasses: ClassVar[dict[Type, type[Message]]] = {}

    _Message = TypeVar('_Message', bound='Message')

    @classmethod
    def message(cls, subclass: type[_Message]) -> type[_Message]:
        cls.subclasses[subclass.message_type] = subclass
        return subclass

    # Class Method to derive header
    @classmethod
    def header(cls, lower_bits: int = 0x00) -> bytes:
        return bytes([(cls.message_type << 4) | lower_bits])

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:
        message_type = Message.Type(data[0] >> 4)
        if subclass := cls.subclasses.get(message_type):
            return subclass.from_bytes(data)
        else:
            raise core.InvalidPacketError(f"Unknown message type {message_type.name}")

    def __bytes__(self) -> bytes:
        raise NotImplementedError


@Message.message
@dataclass
class HandshakeMessage(Message):
    message_type = Message.Type.HANDSHAKE

    class ResultCode(utils.OpenIntEnum):
        SUCCESSFUL = 0x00
        NOT_READY = 0x01
        ERR_INVALID_REPORT_ID = 0x02
        ERR_UNSUPPORTED_REQUEST = 0x03
        ERR_INVALID_PARAMETER = 0x04
        ERR_UNKNOWN = 0x0E
        ERR_FATAL = 0x0F

    result_code: ResultCode

    def __bytes__(self) -> bytes:
        return self.header(self.result_code)

    @classmethod
    def from_bytes(cls, data: bytes) -> HandshakeMessage:
        return cls(result_code=cls.ResultCode(data[0] & 0xFF))


@Message.message
@dataclass
class ControlMessage(Message):
    message_type = Message.Type.CONTROL

    class Command(utils.OpenIntEnum):
        SUSPEND = 0x03
        EXIT_SUSPEND = 0x04
        VIRTUAL_CABLE_UNPLUG = 0x05

    command: Command

    def __bytes__(self) -> bytes:
        return self.header(self.command)

    @classmethod
    def from_bytes(cls, data: bytes) -> ControlMessage:
        return cls(command=ControlMessage.Command(data[0] & 0x0F))


@Message.message
@dataclass
class GetReportMessage(Message):
    message_type = Message.Type.GET_REPORT
    FLAG_HAS_SIZE = 0x08

    report_type: ReportType
    report_id: Optional[int] = None
    buffer_size: Optional[int] = None

    def __bytes__(self) -> bytes:
        data = self.header(
            self.report_type
            | (self.FLAG_HAS_SIZE if self.buffer_size is not None else 0)
        )
        if self.report_id is not None:
            data += bytes([self.report_id])
        if self.buffer_size is not None:
            data += struct.pack("<H", self.buffer_size)
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> GetReportMessage:
        report_type = ReportType(data[0] & 0x03)
        if len(data) == 1:
            return cls(report_type=report_type)
        report_id = data[1]
        if data[0] & cls.FLAG_HAS_SIZE:
            return cls(
                report_type=report_type,
                report_id=report_id,
                buffer_size=struct.unpack("<H", data[2:4])[0],
            )
        else:
            return cls(report_type=report_type, report_id=report_id)


@Message.message
@dataclass
class SetReportMessage(Message):
    message_type = Message.Type.SET_REPORT

    report_type: ReportType
    data: bytes

    def __bytes__(self) -> bytes:
        return self.header(self.report_type) + self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> SetReportMessage:
        return cls(report_type=ReportType(data[0] & 0x03), data=data[1:])


@Message.message
@dataclass
class GetProtocolMessage(Message):
    message_type = Message.Type.GET_PROTOCOL

    def __bytes__(self) -> bytes:
        return self.header()

    @classmethod
    def from_bytes(cls, data: bytes) -> GetProtocolMessage:
        del data  # unused.
        return cls()


@Message.message
@dataclass
class SetProtocolMessage(Message):
    message_type = Message.Type.SET_PROTOCOL

    protocol_mode: ProtocolMode

    def __bytes__(self) -> bytes:
        return self.header(self.protocol_mode)

    @classmethod
    def from_bytes(cls, data: bytes) -> SetProtocolMessage:
        return cls(protocol_mode=ProtocolMode(data[0] & 0x01))


# Device sends input report, host sends output report.
@Message.message
@dataclass
class DataMessage(Message):
    message_type = Message.Type.DATA

    data: bytes
    report_type: ReportType

    def __bytes__(self) -> bytes:
        return self.header(self.report_type) + self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> DataMessage:
        return cls(data=data[1:], report_type=ReportType(data[0] & 0x03))


# -----------------------------------------------------------------------------
class HID(ABC, utils.EventEmitter):
    control_channel: Optional[l2cap.ClassicChannel] = None
    interrupt_channel: Optional[l2cap.ClassicChannel] = None

    EVENT_INTERRUPT_DATA = "interrupt_data"
    EVENT_CONTROL_DATA = "control_data"
    EVENT_SUSPEND = "suspend"
    EVENT_EXIT_SUSPEND = "exit_suspend"
    EVENT_VIRTUAL_CABLE_UNPLUG = "virtual_cable_unplug"
    EVENT_CONNECTION = "connection"
    EVENT_DISCONNECTION = "disconnection"

    class Role(utils.OpenIntEnum):
        HOST = 0x00
        DEVICE = 0x01

    role: ClassVar[Role]

    def __init__(self, device: device.Device) -> None:
        super().__init__()
        self.remote_device_bd_address: Optional[Address] = None
        self.device = device

        # Register ourselves with the L2CAP channel manager
        device.create_l2cap_server(
            l2cap.ClassicChannelSpec(HID_CONTROL_PSM), self._on_l2cap_connection
        )
        device.create_l2cap_server(
            l2cap.ClassicChannelSpec(HID_INTERRUPT_PSM), self._on_l2cap_connection
        )

    async def connect(self, connection: device.Connection) -> None:
        self.control_channel = await connection.create_l2cap_channel(
            l2cap.ClassicChannelSpec(HID_CONTROL_PSM)
        )
        self.control_channel.sink = self._on_control_pdu
        self.interrupt_channel = await connection.create_l2cap_channel(
            l2cap.ClassicChannelSpec(HID_INTERRUPT_PSM)
        )
        self.interrupt_channel.sink = self._on_interrupt_pdu

    async def disconnect(self) -> None:
        if self.interrupt_channel:
            await self.interrupt_channel.disconnect()
            self.interrupt_channel = None
        if self.control_channel:
            await self.control_channel.disconnect()
            self.control_channel = None

    def _on_l2cap_connection(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug(f'+++ New L2CAP connection: {l2cap_channel}')
        l2cap_channel.on(
            l2cap_channel.EVENT_OPEN, lambda: self._on_l2cap_channel_open(l2cap_channel)
        )
        l2cap_channel.on(
            l2cap_channel.EVENT_CLOSE,
            lambda: self._on_l2cap_channel_close(l2cap_channel),
        )

    def _on_l2cap_channel_open(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        if l2cap_channel.psm == HID_CONTROL_PSM:
            self.control_channel = l2cap_channel
            self.control_channel.sink = self._on_control_pdu
        else:
            self.interrupt_channel = l2cap_channel
            self.interrupt_channel.sink = self._on_interrupt_pdu
            if not self.control_channel:
                logger.warning("Interrupt channel established before control channel!")
        logger.debug(f'$$$ L2CAP channel open: {l2cap_channel}')

        if self.control_channel and self.interrupt_channel:
            self.emit(self.EVENT_CONNECTION)

    def _on_l2cap_channel_close(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        if l2cap_channel.psm == HID_CONTROL_PSM:
            self.control_channel = None
        else:
            self.interrupt_channel = None
        logger.debug(f'$$$ L2CAP channel close: {l2cap_channel}')

        if not self.control_channel and not self.interrupt_channel:
            self.emit(self.EVENT_DISCONNECTION)

    @abstractmethod
    def _on_control_pdu(self, pdu: bytes) -> None:
        pass

    def _on_interrupt_pdu(self, pdu: bytes) -> None:
        message = DataMessage.from_bytes(pdu)
        logger.debug('<<< [Interrupt] %s', message)
        self.emit(
            self.EVENT_INTERRUPT_DATA,
            message.report_type,
            message.data,
        )

    def _send_control_pdu(self, message: Message) -> None:
        if not self.control_channel:
            raise core.InvalidStateError("Control channel is not connected")
        logger.debug('>>> [Control] %s', message)
        self.control_channel.send_pdu(message)

    def _send_interrupt_pdu(self, message: Message) -> None:
        if not self.interrupt_channel:
            raise core.InvalidStateError("Interrupt channel is not connected")
        logger.debug('>>> [Interrupt] %s', message)
        self.interrupt_channel.send_pdu(message)

    def send_interrupt_data(self, data: bytes) -> None:
        if self.role == HID.Role.HOST:
            report_type = ReportType.OUTPUT_REPORT
        else:
            report_type = ReportType.INPUT_REPORT
        if self.interrupt_channel is not None:
            self._send_interrupt_pdu(DataMessage(data, report_type))

    def virtual_cable_unplug(self) -> None:
        self._send_control_pdu(
            ControlMessage(ControlMessage.Command.VIRTUAL_CABLE_UNPLUG)
        )


# -----------------------------------------------------------------------------


class Device(HID):

    EVENT_PROTOCOL_CHANGED = "protocol_changed"

    class Delegate:
        def set_report(self, report_type: ReportType, data: bytes) -> None:
            del report_type, data  # unused.
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST)

        def get_report(
            self, report_type: ReportType, report_id: Optional[int]
        ) -> bytes:
            del report_type, report_id  # unused.
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST)

    role = HID.Role.DEVICE

    def __init__(
        self,
        device: device.Device,
        delegate: Optional[Delegate] = None,
        protocol: Optional[ProtocolMode] = None,
    ) -> None:
        super().__init__(device)
        self.delegate = delegate
        self.protocol = protocol

    @override
    def _on_control_pdu(self, pdu: bytes) -> None:
        message = Message.from_bytes(pdu)
        logger.debug('<<< [Control] %s', message)

        try:
            if isinstance(message, GetReportMessage):
                self._handle_get_report(message)
            elif isinstance(message, SetReportMessage):
                self._handle_set_report(message)
            elif isinstance(message, GetProtocolMessage):
                self._handle_get_protocol()
            elif isinstance(message, SetProtocolMessage):
                self._handle_set_protocol(message)
            elif isinstance(message, DataMessage):
                self.emit(self.EVENT_CONTROL_DATA, message)
            elif isinstance(message, ControlMessage):
                if message.command == ControlMessage.Command.SUSPEND:
                    self.emit(self.EVENT_SUSPEND)
                elif message.command == ControlMessage.Command.EXIT_SUSPEND:
                    self.emit(self.EVENT_EXIT_SUSPEND)
                elif message.command == ControlMessage.Command.VIRTUAL_CABLE_UNPLUG:
                    self.emit(self.EVENT_VIRTUAL_CABLE_UNPLUG)
                else:
                    logger.error('Unsupported command %s', message.command.name)
            else:
                logger.error('Unsupported command type %s', message.message_type.name)
                self._send_handshake_message(
                    HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
                )
        except NotImplementedError:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
        except HidProtocolError as e:
            self._send_handshake_message(e.result_code)

    def _send_handshake_message(self, result_code: HandshakeMessage.ResultCode) -> None:
        self._send_control_pdu(HandshakeMessage(result_code))

    def _send_control_data(self, report_type: ReportType, data: bytes):
        self._send_control_pdu(DataMessage(report_type=report_type, data=data))

    def _handle_get_report(self, message: GetReportMessage) -> None:
        if not self.delegate:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
            return
        result = self.delegate.get_report(message.report_type, message.report_id)
        data = (
            bytes(([message.report_id] if message.report_id is not None else []))
            + result
        )

        assert self.control_channel
        if len(data) < self.control_channel.peer_mtu:
            self._send_control_data(report_type=message.report_type, data=data)
        else:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
            )

    def _handle_set_report(self, message: SetReportMessage):
        if not self.delegate:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
            return
        self.delegate.set_report(message.report_type, message.data)
        self._send_handshake_message(HandshakeMessage.ResultCode.SUCCESSFUL)

    def _handle_get_protocol(self):
        if self.protocol is None:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
        else:
            self._send_control_data(ReportType.OTHER_REPORT, bytes([self.protocol]))

    def _handle_set_protocol(self, message: SetProtocolMessage):
        if self.protocol is None:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
        else:
            self.protocol = message.protocol_mode
            self._send_handshake_message(HandshakeMessage.ResultCode.SUCCESSFUL)
            self.emit(self.EVENT_PROTOCOL_CHANGED)


# -----------------------------------------------------------------------------
class Host(HID):
    role = HID.Role.HOST

    _pending_command_future: Optional[asyncio.Future[Optional[DataMessage]]] = None

    def __init__(self, device: device.Device) -> None:
        super().__init__(device)
        self._report_queue = asyncio.Queue[bytes]

    async def _send_control_message(self, message: Message) -> Optional[DataMessage]:
        self._pending_command_future = asyncio.get_running_loop().create_future()
        self._send_control_pdu(message)
        return await self._pending_command_future

    async def get_report(
        self,
        report_type: ReportType,
        report_id: Optional[int] = None,
        buffer_size: Optional[int] = None,
    ) -> bytes:
        result = await self._send_control_message(
            GetReportMessage(
                report_type=report_type, report_id=report_id, buffer_size=buffer_size
            )
        )
        if result:
            return result.data
        else:
            raise core.UnreachableError()

    async def set_report(self, report_type: ReportType, data: bytes) -> None:
        await self._send_control_message(
            SetReportMessage(report_type=report_type, data=data)
        )

    async def get_protocol(self) -> ProtocolMode:
        result = await self._send_control_message(GetProtocolMessage())
        if result:
            return ProtocolMode(result.data[0])
        else:
            raise core.UnreachableError()

    async def set_protocol(self, protocol_mode: ProtocolMode) -> None:
        await self._send_control_message(
            SetProtocolMessage(protocol_mode=protocol_mode)
        )

    def suspend(self) -> None:
        self._send_control_pdu(ControlMessage(ControlMessage.Command.SUSPEND))

    def exit_suspend(self) -> None:
        self._send_control_pdu(ControlMessage(ControlMessage.Command.EXIT_SUSPEND))

    @override
    def _on_control_pdu(self, pdu: bytes) -> None:
        message = Message.from_bytes(pdu)
        logger.debug('<<< [Control] %s', message)
        if isinstance(message, DataMessage):
            if self._pending_command_future and not self._pending_command_future.done():
                self._pending_command_future.set_result(message)
                self._pending_command_future = None
            else:
                logger.error('Unexpected message %s', message)
        elif isinstance(message, HandshakeMessage):
            if self._pending_command_future and not self._pending_command_future.done():
                if message.result_code == HandshakeMessage.ResultCode.SUCCESSFUL:
                    self._pending_command_future.set_result(None)
                else:
                    self._pending_command_future.set_exception(
                        HidProtocolError(message.result_code)
                    )
                self._pending_command_future = None
            else:
                logger.error('Unexpected message %s', message)
        elif isinstance(message, ControlMessage):
            if message.command == ControlMessage.Command.VIRTUAL_CABLE_UNPLUG:
                self.emit(self.EVENT_VIRTUAL_CABLE_UNPLUG)
            else:
                logger.debug('Unsupported command %s', message.command.name)
        else:
            logger.debug('Unsupported message %s', message.message_type.name)
