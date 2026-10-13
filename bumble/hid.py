# Copyright 2021-2025 Google LLC
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

import abc
import asyncio
import dataclasses
import enum
import logging
import struct
from collections.abc import Sequence
from typing import Any, ClassVar, TypeVar

from typing_extensions import Self, override

from bumble import core
from bumble import device as device_lib
from bumble import hci, l2cap, sdp, utils

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
HID_CONTROL_PSM = 0x0011
HID_INTERRUPT_PSM = 0x0013


class HidProtocolError(core.ProtocolError):
    result_code: HandshakeMessage.ResultCode

    def __init__(self, result_code: HandshakeMessage.ResultCode):
        self.result_code = result_code
        super().__init__(
            result_code.value, error_namespace="HID", error_name=result_code.name
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
    """Base class for HID messages."""

    class Type(utils.OpenIntEnum):
        HANDSHAKE = 0x00
        CONTROL = 0x01
        GET_REPORT = 0x04
        SET_REPORT = 0x05
        GET_PROTOCOL = 0x06
        SET_PROTOCOL = 0x07
        GET_IDLE = 0x08
        SET_IDLE = 0x09
        DATA = 0x0A

    message_type: ClassVar[Type]

    subclasses: ClassVar[dict[Type, type[Message]]] = {}

    _MESSAGE_TYPE = TypeVar("_MESSAGE_TYPE", bound="Message")

    @classmethod
    def message(cls, subclass: type[_MESSAGE_TYPE]) -> type[_MESSAGE_TYPE]:
        cls.subclasses[subclass.message_type] = subclass
        return subclass

    # Class Method to derive header
    @classmethod
    def header(cls, lower_bits: int = 0x00) -> bytes:
        return bytes([(cls.message_type << 4) | lower_bits])

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:
        if not data:
            raise core.InvalidPacketError("Empty HID message")
        message_type = Message.Type(data[0] >> 4)
        if subclass := cls.subclasses.get(message_type):
            return subclass.from_bytes(data)
        raise core.InvalidPacketError(f"Unknown message type {message_type.name}")

    def __bytes__(self) -> bytes:
        raise NotImplementedError


@Message.message
@dataclasses.dataclass
class HandshakeMessage(Message):
    """HID Handshake message.

    This message is used to acknowledge or reject control channel requests.
    """

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
        if len(data) != 1:
            raise HidProtocolError(cls.ResultCode.ERR_INVALID_PARAMETER)
        return cls(result_code=cls.ResultCode(data[0] & 0x0F))


@Message.message
@dataclasses.dataclass
class ControlMessage(Message):
    """HID Control message.

    This message is used to send control commands between the host and device.
    """

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
        if len(data) != 1:
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER)
        return cls(command=ControlMessage.Command(data[0] & 0x0F))


@Message.message
@dataclasses.dataclass
class GetReportMessage(Message):
    """HID Get Report message.

    This message is used by the host to request a report from the device.
    """

    message_type = Message.Type.GET_REPORT
    FLAG_HAS_SIZE = 0x08

    report_type: ReportType
    report_id: int | None = None
    buffer_size: int | None = None

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
        has_size = bool(data[0] & cls.FLAG_HAS_SIZE)
        match (has_size, len(data)):
            case (False, 1):
                return cls(report_type=report_type)
            case (False, 2):
                return cls(report_type=report_type, report_id=data[1])
            case (True, 3):
                return cls(
                    report_type=report_type,
                    buffer_size=struct.unpack("<H", data[1:3])[0],
                )
            case (True, 4):
                return cls(
                    report_type=report_type,
                    report_id=data[1],
                    buffer_size=struct.unpack("<H", data[2:4])[0],
                )
            case _:
                raise HidProtocolError(
                    HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
                )


@Message.message
@dataclasses.dataclass
class SetReportMessage(Message):
    """HID Set Report message.

    This message is used by the host to set the report for the device.
    """

    message_type = Message.Type.SET_REPORT

    report_type: ReportType
    data: bytes

    def __bytes__(self) -> bytes:
        return self.header(self.report_type) + self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> SetReportMessage:
        if len(data) < 2:
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER)
        return cls(report_type=ReportType(data[0] & 0x03), data=data[1:])


@Message.message
@dataclasses.dataclass
class GetProtocolMessage(Message):
    """HID Get Protocol message.

    This message is used by the host to get the protocol mode for the device.
    """

    message_type = Message.Type.GET_PROTOCOL

    def __bytes__(self) -> bytes:
        return self.header()

    @classmethod
    def from_bytes(cls, data: bytes) -> GetProtocolMessage:
        if len(data) != 1:
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER)
        return cls()


@Message.message
@dataclasses.dataclass
class SetProtocolMessage(Message):
    """HID Set Protocol message.

    This message is used by the host to set the protocol mode for the device.
    """

    message_type = Message.Type.SET_PROTOCOL

    protocol_mode: ProtocolMode

    def __bytes__(self) -> bytes:
        return self.header(self.protocol_mode)

    @classmethod
    def from_bytes(cls, data: bytes) -> SetProtocolMessage:
        if len(data) != 1:
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER)
        return cls(protocol_mode=ProtocolMode(data[0] & 0x01))


@Message.message
@dataclasses.dataclass
class GetIdleMessage(Message):
    """HID Get Idle message.

    This message is used by the host to get the idle time for the device.
    """

    message_type = Message.Type.GET_IDLE

    def __bytes__(self) -> bytes:
        return self.header()

    @classmethod
    def from_bytes(cls, data: bytes) -> GetIdleMessage:
        if len(data) != 1:
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER)
        return cls()


@Message.message
@dataclasses.dataclass
class SetIdleMessage(Message):
    """HID Set Idle message.

    This message is used by the host to set the idle time for the device.
    """

    message_type = Message.Type.SET_IDLE

    idle_time: int

    def __bytes__(self) -> bytes:
        return self.header() + bytes([self.idle_time])

    @classmethod
    def from_bytes(cls, data: bytes) -> SetIdleMessage:
        if len(data) != 2:
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER)
        return cls(idle_time=data[1])


# Device sends input report, host sends output report.
@Message.message
@dataclasses.dataclass
class DataMessage(Message):
    """HID Data message.

    This message is used to send report data. The direction of the report depends
    on the role:
    - Device sends input report.
    - Host sends output report.
    """

    message_type = Message.Type.DATA

    data: bytes
    report_type: ReportType

    def __bytes__(self) -> bytes:
        return self.header(self.report_type) + self.data

    @classmethod
    def from_bytes(cls, data: bytes) -> DataMessage:
        if not data:
            raise core.InvalidPacketError("Empty DATA message")
        return cls(data=data[1:], report_type=ReportType(data[0] & 0x03))


# -----------------------------------------------------------------------------
class HID(abc.ABC, utils.EventEmitter):
    """Base class for Bluetooth Human Interface Device (HID) profiles.

    This class provides the fundamental structure for both HID Host and HID Device
    roles, handling L2CAP channel management for control and interrupt channels.
    """

    control_channel: l2cap.ClassicChannel | None = None
    interrupt_channel: l2cap.ClassicChannel | None = None

    EVENT_INTERRUPT_DATA = "interrupt_data"
    EVENT_CONTROL_DATA = "control_data"
    EVENT_SUSPEND = "suspend"
    EVENT_EXIT_SUSPEND = "exit_suspend"
    EVENT_VIRTUAL_CABLE_UNPLUG = "virtual_cable_unplug"
    EVENT_HANDSHAKE = "handshake"
    EVENT_CONNECTION = "connection"
    EVENT_DISCONNECTION = "disconnection"

    class Role(utils.OpenIntEnum):
        HOST = 0x00
        DEVICE = 0x01

    role: ClassVar[Role]

    def __init__(self, device: device_lib.Device) -> None:
        super().__init__()
        self.remote_device_bd_address: hci.Address | None = None
        self.device = device

        # Register ourselves with the L2CAP channel manager
        device.create_l2cap_server(
            l2cap.ClassicChannelSpec(HID_CONTROL_PSM), self._on_l2cap_connection
        )
        device.create_l2cap_server(
            l2cap.ClassicChannelSpec(HID_INTERRUPT_PSM), self._on_l2cap_connection
        )

    async def connect(self, connection: device_lib.Connection) -> None:
        self.remote_device_bd_address = connection.peer_address
        self.control_channel = await connection.create_l2cap_channel(
            l2cap.ClassicChannelSpec(HID_CONTROL_PSM)
        )
        self.control_channel.sink = self._on_control_pdu
        try:
            self.interrupt_channel = await connection.create_l2cap_channel(
                l2cap.ClassicChannelSpec(HID_INTERRUPT_PSM)
            )
            self.interrupt_channel.sink = self._on_interrupt_pdu
        except Exception:
            await self.disconnect()
            raise

    async def disconnect(self) -> None:
        if self.interrupt_channel:
            await self.interrupt_channel.disconnect()
            self.interrupt_channel = None
        if self.control_channel:
            await self.control_channel.disconnect()
            self.control_channel = None

    def _on_l2cap_connection(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        logger.debug("+++ New L2CAP connection: %s", l2cap_channel)
        l2cap_channel.on(
            l2cap_channel.EVENT_OPEN,
            lambda: self._on_l2cap_channel_open(l2cap_channel),
        )
        l2cap_channel.on(
            l2cap_channel.EVENT_CLOSE,
            lambda: self._on_l2cap_channel_close(l2cap_channel),
        )

    def _on_l2cap_channel_open(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        self.remote_device_bd_address = l2cap_channel.connection.peer_address
        if l2cap_channel.psm == HID_CONTROL_PSM:
            self.control_channel = l2cap_channel
            self.control_channel.sink = self._on_control_pdu
        else:
            self.interrupt_channel = l2cap_channel
            self.interrupt_channel.sink = self._on_interrupt_pdu
            if not self.control_channel:
                logger.warning("Interrupt channel established before control channel!")
        logger.debug("$$$ L2CAP channel open: %s", l2cap_channel)

        if self.control_channel and self.interrupt_channel:
            self.emit(self.EVENT_CONNECTION)

    def _on_l2cap_channel_close(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        if l2cap_channel.psm == HID_CONTROL_PSM:
            self.control_channel = None
        else:
            self.interrupt_channel = None
        logger.debug("$$$ L2CAP channel close: %s", l2cap_channel)

        if not self.control_channel and not self.interrupt_channel:
            self.emit(self.EVENT_DISCONNECTION)

    @abc.abstractmethod
    def _on_control_pdu(self, pdu: bytes) -> None:
        pass

    def _on_interrupt_pdu(self, pdu: bytes) -> None:
        if not pdu:
            logger.warning("Ignoring empty HID interrupt PDU")
            return
        try:
            message = DataMessage.from_bytes(pdu)
        except (core.InvalidPacketError, HidProtocolError) as e:
            logger.warning("Ignoring invalid HID interrupt PDU: %s", e)
            return
        logger.debug("<<< [Interrupt] %s", message)
        self.emit(
            self.EVENT_INTERRUPT_DATA,
            message.report_type,
            message.data,
        )

    def _send_control_pdu(self, message: Message) -> None:
        if not self.control_channel:
            raise core.InvalidStateError("Control channel is not connected")
        logger.debug(">>> [Control] %s", message)
        self.control_channel.write(bytes(message))

    def _send_interrupt_pdu(self, message: Message) -> None:
        if not self.interrupt_channel:
            raise core.InvalidStateError("Interrupt channel is not connected")
        logger.debug(">>> [Interrupt] %s", message)
        self.interrupt_channel.write(bytes(message))

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
    """HID Device role implementation.

    This class represents a Bluetooth HID Device, handling incoming control and
    interrupt channel PDUs and providing an interface for sending data.
    """

    EVENT_PROTOCOL_CHANGED = "protocol_changed"
    EVENT_IDLE_TIME_CHANGED = "idle_time_changed"
    _idle_time: int | None = 0

    class Delegate:
        """Delegate class for handling HID device requests.

        This class defines the interface for handling `set_report` and `get_report`
        requests from the HID Host.
        """

        def set_report(self, report_type: ReportType, data: bytes) -> None:
            del report_type, data  # unused.
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST)

        def get_report(self, report_type: ReportType, report_id: int | None) -> bytes:
            del report_type, report_id  # unused.
            raise HidProtocolError(HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST)

    role = HID.Role.DEVICE

    def __init__(
        self,
        device: device_lib.Device,
        delegate: Delegate | None = None,
        protocol: ProtocolMode | None = ProtocolMode.REPORT_PROTOCOL,
        idle_time: int | None = 0,
    ) -> None:
        super().__init__(device)
        self.delegate = delegate
        self.protocol = protocol
        self._idle_time = idle_time

    @override
    def _on_control_pdu(self, pdu: bytes) -> None:
        if not pdu:
            logger.warning("Ignoring empty HID control PDU")
            return

        try:
            message = Message.from_bytes(pdu)
            logger.debug("<<< [Control] %s", message)

            match message:
                case GetReportMessage():
                    self._handle_get_report(message)
                case SetReportMessage():
                    self._handle_set_report(message)
                case GetProtocolMessage():
                    self._handle_get_protocol()
                case SetProtocolMessage():
                    self._handle_set_protocol(message)
                case GetIdleMessage():
                    self._handle_get_idle()
                case SetIdleMessage():
                    self._handle_set_idle(message)
                case DataMessage(data=data, report_type=report_type):
                    self.emit(self.EVENT_CONTROL_DATA, report_type, data)
                case ControlMessage(command=ControlMessage.Command.SUSPEND):
                    self.emit(self.EVENT_SUSPEND)
                case ControlMessage(command=ControlMessage.Command.EXIT_SUSPEND):
                    self.emit(self.EVENT_EXIT_SUSPEND)
                case ControlMessage(
                    command=ControlMessage.Command.VIRTUAL_CABLE_UNPLUG
                ):
                    self.emit(self.EVENT_VIRTUAL_CABLE_UNPLUG)
                case ControlMessage(command=command):
                    logger.error("Unsupported command %s", command.name)
                case _:
                    logger.error(
                        "Unsupported command type %s", message.message_type.name
                    )
                    self._send_handshake_message(
                        HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
                    )
        except (NotImplementedError, core.InvalidPacketError):
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
        except HidProtocolError as e:
            self._send_handshake_message(e.result_code)

    def _send_handshake_message(self, result_code: HandshakeMessage.ResultCode) -> None:
        self._send_control_pdu(HandshakeMessage(result_code))

    def _send_control_data(self, report_type: ReportType, data: bytes) -> None:
        self._send_control_pdu(DataMessage(report_type=report_type, data=data))

    def _handle_get_report(self, message: GetReportMessage) -> None:
        if not self.delegate:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
            return
        result = self.delegate.get_report(message.report_type, message.report_id)
        data = (
            bytes([message.report_id] if message.report_id is not None else []) + result
        )
        if message.buffer_size is not None:
            data = data[: message.buffer_size]

        assert self.control_channel
        if len(data) < self.control_channel.peer_mtu:
            self._send_control_data(report_type=message.report_type, data=data)
        else:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
            )

    def _handle_set_report(self, message: SetReportMessage) -> None:
        if not self.delegate:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
            return
        self.delegate.set_report(message.report_type, message.data)
        self._send_handshake_message(HandshakeMessage.ResultCode.SUCCESSFUL)

    def _handle_get_protocol(self) -> None:
        if self.protocol is None:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
        else:
            self._send_control_data(ReportType.OTHER_REPORT, bytes([self.protocol]))

    def _handle_set_protocol(self, message: SetProtocolMessage) -> None:
        if self.protocol is None:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
        else:
            self.protocol = message.protocol_mode
            self._send_handshake_message(HandshakeMessage.ResultCode.SUCCESSFUL)
            self.emit(self.EVENT_PROTOCOL_CHANGED)

    def _handle_get_idle(self) -> None:
        if self._idle_time is None:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
        else:
            self._send_control_data(ReportType.OTHER_REPORT, bytes([self._idle_time]))

    def _handle_set_idle(self, message: SetIdleMessage) -> None:
        if self._idle_time is None:
            self._send_handshake_message(
                HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
            )
        else:
            self._idle_time = message.idle_time
            self._send_handshake_message(HandshakeMessage.ResultCode.SUCCESSFUL)
            self.emit(self.EVENT_IDLE_TIME_CHANGED)


# -----------------------------------------------------------------------------
class Host(HID):
    """HID Host role implementation.

    This class represents a Bluetooth HID Host, handling the connection and
    communication with a HID Device. It provides methods to send and receive
    HID reports and control messages.
    """

    role = HID.Role.HOST

    def __init__(self, device: device_lib.Device) -> None:
        super().__init__(device)
        self._command_lock = asyncio.Lock()
        self._pending_command_future: asyncio.Future[DataMessage | None] | None = None

    def _abort_pending_command(self, error: Exception) -> None:
        if self._pending_command_future and not self._pending_command_future.done():
            self._pending_command_future.set_exception(error)
        self._pending_command_future = None

    @override
    async def disconnect(self) -> None:
        self._abort_pending_command(core.InvalidStateError("HID host disconnected"))
        await super().disconnect()

    @override
    def _on_l2cap_channel_close(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        if l2cap_channel.psm == HID_CONTROL_PSM:
            self._abort_pending_command(
                core.InvalidStateError("HID control channel closed")
            )
        super()._on_l2cap_channel_close(l2cap_channel)

    async def _send_control_message(self, message: Message) -> DataMessage | None:
        async with self._command_lock:
            loop = asyncio.get_running_loop()
            future: asyncio.Future[DataMessage | None] = loop.create_future()
            self._pending_command_future = future
            try:
                self._send_control_pdu(message)
                return await future
            finally:
                if self._pending_command_future is future:
                    self._pending_command_future = None

    async def get_report(
        self,
        report_type: ReportType,
        report_id: int | None = None,
        buffer_size: int | None = None,
    ) -> bytes:
        result = await self._send_control_message(
            GetReportMessage(
                report_type=report_type,
                report_id=report_id,
                buffer_size=buffer_size,
            )
        )
        if result:
            return result.data
        raise core.UnreachableError()

    async def set_report(self, report_type: ReportType, data: bytes) -> None:
        await self._send_control_message(
            SetReportMessage(report_type=report_type, data=data)
        )

    async def get_protocol(self) -> ProtocolMode:
        result = await self._send_control_message(GetProtocolMessage())
        if result:
            return ProtocolMode(result.data[0])
        raise core.UnreachableError()

    async def set_protocol(self, protocol_mode: ProtocolMode) -> None:
        await self._send_control_message(
            SetProtocolMessage(protocol_mode=protocol_mode)
        )

    async def get_idle(self) -> int:
        result = await self._send_control_message(GetIdleMessage())
        if result:
            return result.data[0]
        raise core.UnreachableError()

    async def set_idle(self, idle_time: int) -> None:
        await self._send_control_message(SetIdleMessage(idle_time=idle_time))

    def suspend(self) -> None:
        self._send_control_pdu(ControlMessage(ControlMessage.Command.SUSPEND))

    def exit_suspend(self) -> None:
        self._send_control_pdu(ControlMessage(ControlMessage.Command.EXIT_SUSPEND))

    @override
    def _on_control_pdu(self, pdu: bytes) -> None:
        if not pdu:
            logger.warning("Ignoring empty HID control PDU")
            return
        try:
            message = Message.from_bytes(pdu)
        except (core.InvalidPacketError, HidProtocolError) as e:
            logger.warning("Ignoring invalid HID control PDU: %s", e)
            self._abort_pending_command(e)
            return
        logger.debug("<<< [Control] %s", message)
        match message:
            case DataMessage(data=data, report_type=report_type):
                if (
                    self._pending_command_future
                    and not self._pending_command_future.done()
                ):
                    self._pending_command_future.set_result(message)
                    self._pending_command_future = None
                else:
                    self.emit(
                        self.EVENT_CONTROL_DATA,
                        report_type,
                        data,
                    )
            case HandshakeMessage(result_code=result_code):
                self.emit(self.EVENT_HANDSHAKE, result_code)
                if (
                    self._pending_command_future
                    and not self._pending_command_future.done()
                ):
                    if result_code == HandshakeMessage.ResultCode.SUCCESSFUL:
                        self._pending_command_future.set_result(None)
                    else:
                        self._pending_command_future.set_exception(
                            HidProtocolError(result_code)
                        )
                    self._pending_command_future = None
                else:
                    logger.debug("Unhandled handshake message %s", message)
            case ControlMessage(command=ControlMessage.Command.VIRTUAL_CABLE_UNPLUG):
                self.emit(self.EVENT_VIRTUAL_CABLE_UNPLUG)
            case ControlMessage(command=command):
                logger.debug("Unsupported command %s", command.name)
            case _:
                logger.debug("Unsupported message %s", message.message_type.name)


DEFAULT_REPORT_MAP = bytes(
    [
        # fmt: off
    # pylint: disable=line-too-long
    0x05, 0x01,        # Usage Page (Generic Desktop Ctrls)
    0x09, 0x06,        # Usage (Keyboard)
    0xA1, 0x01,        # Collection (Application)
    0x85, 0x01,        #   Report ID (1)
    0x05, 0x07,        #   Usage Page (Kbrd/Keypad)
    0x19, 0xE0,        #   Usage Minimum (0xE0)
    0x29, 0xE7,        #   Usage Maximum (0xE7)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x01,        #   Logical Maximum (1)
    0x75, 0x01,        #   Report Size (1)
    0x95, 0x08,        #   Report Count (8)
    0x81, 0x02,        #   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        #   Report Count (1)
    0x75, 0x08,        #   Report Size (8)
    0x81, 0x01,        #   Input (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x06,        #   Report Count (6)
    0x75, 0x08,        #   Report Size (8)
    0x15, 0x00,        #   Logical Minimum (0)
    0x25, 0x94,        #   Logical Maximum (-108)
    0x05, 0x07,        #   Usage Page (Kbrd/Keypad)
    0x19, 0x00,        #   Usage Minimum (0x00)
    0x29, 0x94,        #   Usage Maximum (0x94)
    0x81, 0x00,        #   Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x05,        #   Report Count (5)
    0x75, 0x01,        #   Report Size (1)
    0x05, 0x08,        #   Usage Page (LEDs)
    0x19, 0x01,        #   Usage Minimum (Num Lock)
    0x29, 0x05,        #   Usage Maximum (Kana)
    0x91, 0x02,        #   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x95, 0x01,        #   Report Count (1)
    0x75, 0x03,        #   Report Size (3)
    0x91, 0x01,        #   Output (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,              # End Collection
    0x05, 0x01,        # Usage Page (Generic Desktop Ctrls)
    0x09, 0x02,        # Usage (Mouse)
    0xA1, 0x01,        # Collection (Application)
    0x85, 0x02,        #   Report ID (2)
    0x09, 0x01,        #   Usage (Pointer)
    0xA1, 0x00,        #   Collection (Physical)
    0x05, 0x09,        #     Usage Page (Button)
    0x19, 0x01,        #     Usage Minimum (0x01)
    0x29, 0x05,        #     Usage Maximum (0x05)
    0x15, 0x00,        #     Logical Minimum (0)
    0x25, 0x01,        #     Logical Maximum (1)
    0x95, 0x05,        #     Report Count (5)
    0x75, 0x01,        #     Report Size (1)
    0x81, 0x02,        #     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        #     Report Count (1)
    0x75, 0x03,        #     Report Size (3)
    0x81, 0x01,        #     Input (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x05, 0x01,        #     Usage Page (Generic Desktop Ctrls)
    0x09, 0x30,        #     Usage (X)
    0x09, 0x31,        #     Usage (Y)
    0x16, 0x00, 0x80,  #     Logical Minimum (-32768)
    0x26, 0xFF, 0x7F,  #     Logical Maximum (32767)
    0x75, 0x10,        #     Report Size (16)
    0x95, 0x02,        #     Report Count (2)
    0x81, 0x06,        #     Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x38,        #     Usage (Wheel)
    0x15, 0x81,        #     Logical Minimum (-127)
    0x25, 0x7F,        #     Logical Maximum (127)
    0x75, 0x08,        #     Report Size (8)
    0x95, 0x01,        #     Report Count (1)
    0x81, 0x06,        #     Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              #   End Collection
    0xC0,  # End Collection
    ]
)


class AttributeId(enum.IntEnum):
    """SDP attribute IDs."""

    SERVICE_NAME = 0x0100
    SERVICE_DESCRIPTION = 0x0101
    PROVIDER_NAME = 0x0102
    DEVICE_RELEASE_NUMBER = 0x0200  # [DEPRECATED]
    PARSER_VERSION = 0x0201
    DEVICE_SUBCLASS = 0x0202
    COUNTRY_CODE = 0x0203
    VIRTUAL_CABLE = 0x0204
    RECONNECT_INITIATE = 0x0205
    DESCRIPTOR_LIST = 0x0206
    LANGID_BASE_LIST = 0x0207
    SDP_DISABLE = 0x0208  # [DEPRECATED]
    BATTERY_POWER = 0x0209
    REMOTE_WAKE = 0x020A
    PROFILE_VERSION = 0x020B  # [DEPRECATED]
    SUPERVISION_TIMEOUT = 0x020C
    NORMALLY_CONNECTABLE = 0x020D
    BOOT_DEVICE = 0x020E
    SSR_HOST_MAX_LATENCY = 0x020F
    SSR_HOST_MIN_TIMEOUT = 0x0210


# pylint: disable=too-many-instance-attributes
@dataclasses.dataclass
class DeviceSdpRecord:
    """HID Device SDP record."""

    service_record_handle: int
    report_map: bytes
    version_number: int = 0x0101  # 0x0101 uint16 version number (v1.1)
    parser_version: int = 0x0111  # uint16 0x0111 (v1.1.1)
    device_subclass: int = 0xC0  # Combo keyboard/pointing device
    country_code: int = 0x21  # 0x21 Uint8, USA
    virtual_cable: bool = True  # Virtual cable enabled
    reconnect_initiate: bool = True  # Reconnect initiate enabled
    report_descriptor_type: int = 0x22  # 0x22 Type = Report Descriptor
    langid_base_language: int = 0x0409  # 0x0409 Language = en_US
    langid_base_bluetooth_string_offset: int = 0x0100  # 0x0100 Default
    boot_device: bool = True  # Boot device support enabled
    battery_power: bool | None = True  # Battery power enabled
    remote_wake: bool | None = True  # Remote wake enabled
    supervision_timeout: int | None = 0xC80  # uint16 0xC80 (2s)
    normally_connectable: bool | None = True  # Normally connectable enabled
    service_name: bytes | None = b"Bumble HID"
    service_description: bytes | None = b"Bumble"
    provider_name: bytes | None = b"Bumble"
    ssr_host_max_latency: int | None = 0x640  # uint16 0x640 (1s)
    ssr_host_min_timeout: int | None = 0xC80  # uint16 0xC80 (2s)

    def to_service_attributes(self) -> list[sdp.ServiceAttribute]:
        """Converts the SDP record to a list of SDP service attributes."""
        attributes = [
            sdp.ServiceAttribute(
                sdp.SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                sdp.DataElement.unsigned_integer_32(self.service_record_handle),
            ),
            sdp.ServiceAttribute(
                sdp.SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
                sdp.DataElement.sequence(
                    [sdp.DataElement.uuid(sdp.SDP_PUBLIC_BROWSE_ROOT)]
                ),
            ),
            sdp.ServiceAttribute(
                sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                sdp.DataElement.sequence(
                    [
                        sdp.DataElement.uuid(core.BT_HUMAN_INTERFACE_DEVICE_SERVICE),
                    ]
                ),
            ),
            sdp.ServiceAttribute(
                sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.DataElement.sequence(
                    [
                        sdp.DataElement.sequence(
                            [
                                sdp.DataElement.uuid(core.BT_L2CAP_PROTOCOL_ID),
                                sdp.DataElement.unsigned_integer_16(HID_CONTROL_PSM),
                            ]
                        ),
                        sdp.DataElement.sequence(
                            [sdp.DataElement.uuid(core.BT_HIDP_PROTOCOL_ID)]
                        ),
                    ]
                ),
            ),
            sdp.ServiceAttribute(
                sdp.SDP_LANGUAGE_BASE_ATTRIBUTE_ID_LIST_ATTRIBUTE_ID,
                sdp.DataElement.sequence(
                    [
                        sdp.DataElement.unsigned_integer_16(0x656E),  # "en"
                        sdp.DataElement.unsigned_integer_16(0x6A),
                        sdp.DataElement.unsigned_integer_16(0x0100),
                    ]
                ),
            ),
            sdp.ServiceAttribute(
                sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.DataElement.sequence(
                    [
                        sdp.DataElement.sequence(
                            [
                                sdp.DataElement.uuid(
                                    core.BT_HUMAN_INTERFACE_DEVICE_SERVICE
                                ),
                                sdp.DataElement.unsigned_integer_16(
                                    self.version_number
                                ),
                            ]
                        ),
                    ]
                ),
            ),
            sdp.ServiceAttribute(
                sdp.SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.DataElement.sequence(
                    [
                        sdp.DataElement.sequence(
                            [
                                sdp.DataElement.sequence(
                                    [
                                        sdp.DataElement.uuid(core.BT_L2CAP_PROTOCOL_ID),
                                        sdp.DataElement.unsigned_integer_16(
                                            HID_INTERRUPT_PSM
                                        ),
                                    ]
                                ),
                                sdp.DataElement.sequence(
                                    [
                                        sdp.DataElement.uuid(core.BT_HIDP_PROTOCOL_ID),
                                    ]
                                ),
                            ]
                        ),
                    ]
                ),
            ),
            sdp.ServiceAttribute(
                AttributeId.PARSER_VERSION,
                sdp.DataElement.unsigned_integer_32(self.parser_version),
            ),
            sdp.ServiceAttribute(
                AttributeId.DEVICE_SUBCLASS,
                sdp.DataElement.unsigned_integer_32(self.device_subclass),
            ),
            sdp.ServiceAttribute(
                AttributeId.COUNTRY_CODE,
                sdp.DataElement.unsigned_integer_32(self.country_code),
            ),
            sdp.ServiceAttribute(
                AttributeId.VIRTUAL_CABLE,
                sdp.DataElement.boolean(self.virtual_cable),
            ),
            sdp.ServiceAttribute(
                AttributeId.RECONNECT_INITIATE,
                sdp.DataElement.boolean(self.reconnect_initiate),
            ),
            sdp.ServiceAttribute(
                AttributeId.DESCRIPTOR_LIST,
                sdp.DataElement.sequence(
                    [
                        sdp.DataElement.sequence(
                            [
                                sdp.DataElement.unsigned_integer_16(
                                    self.report_descriptor_type
                                ),
                                sdp.DataElement(
                                    sdp.DataElement.TEXT_STRING, self.report_map
                                ),
                            ]
                        ),
                    ]
                ),
            ),
            sdp.ServiceAttribute(
                AttributeId.LANGID_BASE_LIST,
                sdp.DataElement.sequence(
                    [
                        sdp.DataElement.sequence(
                            [
                                sdp.DataElement.unsigned_integer_16(
                                    self.langid_base_language
                                ),
                                sdp.DataElement.unsigned_integer_16(
                                    self.langid_base_bluetooth_string_offset
                                ),
                            ]
                        ),
                    ]
                ),
            ),
            sdp.ServiceAttribute(
                AttributeId.BOOT_DEVICE,
                sdp.DataElement.boolean(self.boot_device),
            ),
        ]
        if self.service_name is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.SERVICE_NAME,
                    sdp.DataElement(sdp.DataElement.TEXT_STRING, self.service_name),
                )
            )
        if self.service_description is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.SERVICE_DESCRIPTION,
                    sdp.DataElement(
                        sdp.DataElement.TEXT_STRING, self.service_description
                    ),
                )
            )
        if self.provider_name is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.PROVIDER_NAME,
                    sdp.DataElement(sdp.DataElement.TEXT_STRING, self.provider_name),
                )
            )
        if self.battery_power is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.BATTERY_POWER,
                    sdp.DataElement.boolean(self.battery_power),
                )
            )
        if self.remote_wake is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.REMOTE_WAKE,
                    sdp.DataElement.boolean(self.remote_wake),
                )
            )
        if self.supervision_timeout is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.SUPERVISION_TIMEOUT,
                    sdp.DataElement.unsigned_integer_16(self.supervision_timeout),
                )
            )
        if self.normally_connectable is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.NORMALLY_CONNECTABLE,
                    sdp.DataElement.boolean(self.normally_connectable),
                )
            )
        if self.ssr_host_max_latency is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.SSR_HOST_MAX_LATENCY,
                    sdp.DataElement.unsigned_integer_16(self.ssr_host_max_latency),
                )
            )
        if self.ssr_host_min_timeout is not None:
            attributes.append(
                sdp.ServiceAttribute(
                    AttributeId.SSR_HOST_MIN_TIMEOUT,
                    sdp.DataElement.unsigned_integer_16(self.ssr_host_min_timeout),
                )
            )
        return attributes

    @classmethod
    def from_service_attributes(
        cls, attributes: Sequence[sdp.ServiceAttribute]
    ) -> Self:
        """Creates a DeviceSdpRecord from a sequence of SDP service attributes."""
        attr: dict[str, Any] = {
            "battery_power": None,
            "remote_wake": None,
            "supervision_timeout": None,
            "normally_connectable": None,
            "service_name": None,
            "service_description": None,
            "provider_name": None,
            "ssr_host_max_latency": None,
            "ssr_host_min_timeout": None,
        }
        for attribute in attributes:
            match attribute.id:
                case sdp.SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID:
                    attr["service_record_handle"] = attribute.value.value
                case sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                    attr["version_number"] = attribute.value.value[0].value[1].value
                case AttributeId.SERVICE_NAME:
                    attr["service_name"] = attribute.value.value
                case AttributeId.SERVICE_DESCRIPTION:
                    attr["service_description"] = attribute.value.value
                case AttributeId.PROVIDER_NAME:
                    attr["provider_name"] = attribute.value.value
                case AttributeId.PARSER_VERSION:
                    attr["parser_version"] = attribute.value.value
                case AttributeId.DEVICE_SUBCLASS:
                    attr["device_subclass"] = attribute.value.value
                case AttributeId.COUNTRY_CODE:
                    attr["country_code"] = attribute.value.value
                case AttributeId.VIRTUAL_CABLE:
                    attr["virtual_cable"] = attribute.value.value
                case AttributeId.RECONNECT_INITIATE:
                    attr["reconnect_initiate"] = attribute.value.value
                case AttributeId.DESCRIPTOR_LIST:
                    attr["report_descriptor_type"] = (
                        attribute.value.value[0].value[0].value
                    )
                    attr["report_map"] = attribute.value.value[0].value[1].value
                case AttributeId.BATTERY_POWER:
                    attr["battery_power"] = attribute.value.value
                case AttributeId.REMOTE_WAKE:
                    attr["remote_wake"] = attribute.value.value
                case AttributeId.SUPERVISION_TIMEOUT:
                    attr["supervision_timeout"] = attribute.value.value
                case AttributeId.NORMALLY_CONNECTABLE:
                    attr["normally_connectable"] = attribute.value.value
                case AttributeId.LANGID_BASE_LIST:
                    attr["langid_base_language"] = (
                        attribute.value.value[0].value[0].value
                    )
                    attr["langid_base_bluetooth_string_offset"] = (
                        attribute.value.value[0].value[1].value
                    )
                case AttributeId.BOOT_DEVICE:
                    attr["boot_device"] = attribute.value.value
                case AttributeId.SSR_HOST_MAX_LATENCY:
                    attr["ssr_host_max_latency"] = attribute.value.value
                case AttributeId.SSR_HOST_MIN_TIMEOUT:
                    attr["ssr_host_min_timeout"] = attribute.value.value
                case _:
                    pass
        return cls(**attr)

    @classmethod
    async def find(cls, connection: device_lib.Connection) -> list[Self]:
        """Searches for HID Device SDP records on a remote device."""
        records: list[Self] = []
        async with sdp.Client(connection) as sdp_client:
            search_result = await sdp_client.search_attributes(
                uuids=[core.BT_HUMAN_INTERFACE_DEVICE_SERVICE],
                attribute_ids=[(0x0000, 0xFFFF)],
            )
            for attribute_list in search_result:
                try:
                    records.append(cls.from_service_attributes(attribute_list))
                except (TypeError, ValueError, IndexError, KeyError):
                    logger.exception("Cannot build HID DeviceSdpRecord")
        return records
