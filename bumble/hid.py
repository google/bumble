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
from typing import Optional, Callable, List, Dict, Any
from typing_extensions import override

from bumble import l2cap, device, sdp, core
from bumble.core import InvalidStateError, ProtocolError
from bumble.hci import Address


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
HID_CONTROL_PSM = 0x0011
HID_INTERRUPT_PSM = 0x0013


class AttributeId(enum.IntEnum):
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
    PROFILE_VERSION = 0x020B  # DEPRECATED]
    SUPERVISION_TIMEOUT = 0x020C
    NORMALLY_CONNECTABLE = 0x020D
    BOOT_DEVICE = 0x020E
    SSR_HOST_MAX_LATENCY = 0x020F
    SSR_HOST_MIN_TIMEOUT = 0x0210


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
# SDP
# -----------------------------------------------------------------------------
@dataclass
class SdpInformation:
    service_record_handle: int
    version_number: int
    hid_parser_version: int
    hid_device_subclass: int
    hid_country_code: int
    hid_virtual_cable: bool
    hid_reconnect_initiate: bool
    report_descriptor_type: int
    hid_report_map: bytes
    hid_langid_base_language: int
    hid_langid_base_bluetooth_string_offset: int
    hid_boot_device: bool
    hid_battery_power: Optional[bool] = None
    hid_remote_wake: Optional[bool] = None
    hid_supervision_timeout: Optional[int] = None
    hid_normally_connectable: Optional[bool] = None
    service_name: Optional[bytes] = None
    service_description: Optional[bytes] = None
    provider_name: Optional[bytes] = None
    hid_ssr_host_max_latency: Optional[int] = None
    hid_ssr_host_min_timeout: Optional[int] = None


def make_device_sdp_record(
    service_record_handle: int,
    hid_report_map: bytes,
    version_number=0x0101,  # 0x0101 uint16 version number (v1.1)
    service_name: bytes = b'Bumble HID',
    service_description: bytes = b'Bumble',
    provider_name: bytes = b'Bumble',
    hid_parser_version: int = 0x0111,  # uint16 0x0111 (v1.1.1)
    hid_device_subclass: int = 0xC0,  # Combo keyboard/pointing device
    hid_country_code: int = 0x21,  # 0x21 Uint8, USA
    hid_virtual_cable: bool = True,  # Virtual cable enabled
    hid_reconnect_initiate: bool = True,  #  Reconnect initiate enabled
    report_descriptor_type: int = 0x22,  # 0x22 Type = Report Descriptor
    hid_langid_base_language: int = 0x0409,  # 0x0409 Language = English (United States)
    hid_langid_base_bluetooth_string_offset: int = 0x100,  # 0x0100 Default
    hid_battery_power: Optional[bool] = True,  #  Battery power enabled
    hid_remote_wake: Optional[bool] = True,  #  Remote wake enabled
    hid_supervision_timeout: Optional[int] = 0xC80,  # uint16 0xC80 (2s)
    hid_normally_connectable: Optional[bool] = True,  #  Normally connectable enabled
    hid_boot_device: bool = True,  #  Boot device support enabled
    hid_ssr_host_max_latency: Optional[int] = 0x640,  # uint16 0x640 (1s)
    hid_ssr_host_min_timeout: Optional[int] = 0xC80,  # uint16 0xC80 (2s)
) -> List[sdp.ServiceAttribute]:
    attributes = [
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
                            sdp.DataElement.unsigned_integer_16(version_number),
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
            AttributeId.SERVICE_NAME,
            sdp.DataElement(sdp.DataElement.TEXT_STRING, service_name),
        ),
        sdp.ServiceAttribute(
            AttributeId.SERVICE_DESCRIPTION,
            sdp.DataElement(sdp.DataElement.TEXT_STRING, service_description),
        ),
        sdp.ServiceAttribute(
            AttributeId.PROVIDER_NAME,
            sdp.DataElement(sdp.DataElement.TEXT_STRING, provider_name),
        ),
        sdp.ServiceAttribute(
            AttributeId.PARSER_VERSION,
            sdp.DataElement.unsigned_integer_32(hid_parser_version),
        ),
        sdp.ServiceAttribute(
            AttributeId.DEVICE_SUBCLASS,
            sdp.DataElement.unsigned_integer_32(hid_device_subclass),
        ),
        sdp.ServiceAttribute(
            AttributeId.COUNTRY_CODE,
            sdp.DataElement.unsigned_integer_32(hid_country_code),
        ),
        sdp.ServiceAttribute(
            AttributeId.VIRTUAL_CABLE,
            sdp.DataElement.boolean(hid_virtual_cable),
        ),
        sdp.ServiceAttribute(
            AttributeId.RECONNECT_INITIATE,
            sdp.DataElement.boolean(hid_reconnect_initiate),
        ),
        sdp.ServiceAttribute(
            AttributeId.DESCRIPTOR_LIST,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.sequence(
                        [
                            sdp.DataElement.unsigned_integer_16(report_descriptor_type),
                            sdp.DataElement(
                                sdp.DataElement.TEXT_STRING, hid_report_map
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
                                hid_langid_base_language
                            ),
                            sdp.DataElement.unsigned_integer_16(
                                hid_langid_base_bluetooth_string_offset
                            ),
                        ]
                    ),
                ]
            ),
        ),
        sdp.ServiceAttribute(
            AttributeId.BOOT_DEVICE,
            sdp.DataElement.boolean(hid_boot_device),
        ),
    ]
    if hid_battery_power is not None:
        attributes.append(
            sdp.ServiceAttribute(
                AttributeId.BATTERY_POWER,
                sdp.DataElement.boolean(hid_battery_power),
            )
        )
    if hid_remote_wake is not None:
        attributes.append(
            sdp.ServiceAttribute(
                AttributeId.REMOTE_WAKE,
                sdp.DataElement.boolean(hid_remote_wake),
            )
        )
    if hid_supervision_timeout is not None:
        attributes.append(
            sdp.ServiceAttribute(
                AttributeId.SUPERVISION_TIMEOUT,
                sdp.DataElement.unsigned_integer_16(hid_supervision_timeout),
            )
        )
    if hid_normally_connectable is not None:
        attributes.append(
            sdp.ServiceAttribute(
                AttributeId.NORMALLY_CONNECTABLE,
                sdp.DataElement.boolean(hid_normally_connectable),
            )
        )
    if hid_ssr_host_max_latency is not None:
        attributes.append(
            sdp.ServiceAttribute(
                AttributeId.SSR_HOST_MAX_LATENCY,
                sdp.DataElement.unsigned_integer_16(hid_ssr_host_max_latency),
            )
        )
    if hid_ssr_host_min_timeout is not None:
        attributes.append(
            sdp.ServiceAttribute(
                AttributeId.SSR_HOST_MIN_TIMEOUT,
                sdp.DataElement.unsigned_integer_16(hid_ssr_host_min_timeout),
            )
        )
    return attributes


async def find_device_sdp_record(
    connection: device.Connection,
) -> Optional[SdpInformation]:

    async with sdp.Client(connection) as sdp_client:
        service_record_handles = await sdp_client.search_services(
            [core.BT_HUMAN_INTERFACE_DEVICE_SERVICE]
        )
        if not service_record_handles:
            return None
        if len(service_record_handles) > 1:
            logger.info(
                "Remote has more than one HID SDP records, only return the first one."
            )

        service_record_handle = service_record_handles[0]
        attr: Dict[str, Any] = {"service_record_handle": service_record_handle}

        attributes = await sdp_client.get_attributes(
            service_record_handle, [sdp.SDP_ALL_ATTRIBUTES_RANGE]
        )
        for attribute in attributes:
            if attribute.id == sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                attr["version_number"] = attribute.value.value[0].value[1].value
            elif attribute.id == AttributeId.SERVICE_NAME:
                attr["service_name"] = attribute.value.value
            elif attribute.id == AttributeId.SERVICE_DESCRIPTION:
                attr["service_description"] = attribute.value.value
            elif attribute.id == AttributeId.PROVIDER_NAME:
                attr["provider_name"] = attribute.value.value
            elif attribute.id == AttributeId.PARSER_VERSION:
                attr["hid_parser_version"] = attribute.value.value
            elif attribute.id == AttributeId.DEVICE_SUBCLASS:
                attr["hid_device_subclass"] = attribute.value.value
            elif attribute.id == AttributeId.COUNTRY_CODE:
                attr["hid_country_code"] = attribute.value.value
            elif attribute.id == AttributeId.VIRTUAL_CABLE:
                attr["hid_virtual_cable"] = attribute.value.value
            elif attribute.id == AttributeId.RECONNECT_INITIATE:
                attr["hid_reconnect_initiate"] = attribute.value.value
            elif attribute.id == AttributeId.DESCRIPTOR_LIST:
                attr["report_descriptor_type"] = attribute.value.value[0].value[0].value
                attr["hid_report_map"] = attribute.value.value[0].value[1].value
            elif attribute.id == AttributeId.BATTERY_POWER:
                attr["hid_battery_power"] = attribute.value.value
            elif attribute.id == AttributeId.REMOTE_WAKE:
                attr["hid_remote_wake"] = attribute.value.value
            elif attribute.id == AttributeId.SUPERVISION_TIMEOUT:
                attr["hid_supervision_timeout"] = attribute.value.value
            elif attribute.id == AttributeId.NORMALLY_CONNECTABLE:
                attr["hid_normally_connectable"] = attribute.value.value
            elif attribute.id == AttributeId.LANGID_BASE_LIST:
                attr["hid_langid_base_language"] = (
                    attribute.value.value[0].value[0].value
                )
                attr["hid_langid_base_bluetooth_string_offset"] = (
                    attribute.value.value[0].value[1].value
                )
            elif attribute.id == AttributeId.BOOT_DEVICE:
                attr["hid_boot_device"] = attribute.value.value
            elif attribute.id == AttributeId.SSR_HOST_MAX_LATENCY:
                attr["hid_ssr_host_max_latency"] = attribute.value.value
            elif attribute.id == AttributeId.SSR_HOST_MIN_TIMEOUT:
                attr["hid_ssr_host_min_timeout"] = attribute.value.value

        try:
            return SdpInformation(**attr)
        except:
            logger.exception("Cannot build SDP information")
            return None


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
            channel = await self.device.l2cap_channel_manager.connect(
                self.connection, HID_CONTROL_PSM
            )
            channel.sink = self.on_ctrl_pdu
            self.l2cap_ctrl_channel = channel
        except ProtocolError:
            logging.exception(f'L2CAP connection failed.')
            raise

    async def connect_interrupt_channel(self) -> None:
        # Create a new L2CAP connection - interrupt channel
        try:
            channel = await self.device.l2cap_channel_manager.connect(
                self.connection, HID_INTERRUPT_PSM
            )
            channel.sink = self.on_intr_pdu
            self.l2cap_intr_channel = channel
        except ProtocolError:
            logging.exception(f'L2CAP connection failed.')
            raise

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

    @dataclass
    class GetSetStatus:
        data: bytes = b''
        status: int = 0

    get_report_cb: Optional[Callable[[int, int, int], GetSetStatus]] = None
    set_report_cb: Optional[Callable[[int, int, int, bytes], GetSetStatus]] = None
    get_protocol_cb: Optional[Callable[[], GetSetStatus]] = None
    set_protocol_cb: Optional[Callable[[int], GetSetStatus]] = None

    def __init__(self, device: device.Device) -> None:
        super().__init__(device, HID.Role.DEVICE)

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

    def register_get_report_cb(
        self, cb: Callable[[int, int, int], Device.GetSetStatus]
    ) -> None:
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
        if ret.status == self.GetSetReturn.SUCCESS:
            self.send_handshake_message(Message.Handshake.SUCCESSFUL)
        elif ret.status == self.GetSetReturn.ERR_INVALID_PARAMETER:
            self.send_handshake_message(Message.Handshake.ERR_INVALID_PARAMETER)
        elif ret.status == self.GetSetReturn.REPORT_ID_NOT_FOUND:
            self.send_handshake_message(Message.Handshake.ERR_INVALID_REPORT_ID)
        else:
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)

    def register_set_report_cb(
        self, cb: Callable[[int, int, int, bytes], Device.GetSetStatus]
    ) -> None:
        self.set_report_cb = cb
        logger.debug("SetReport callback registered successfully")

    def handle_get_protocol(self, pdu: bytes):
        if self.get_protocol_cb is None:
            logger.debug("GetProtocol callback not registered !!")
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
            return
        ret = self.get_protocol_cb()
        if ret.status == self.GetSetReturn.SUCCESS:
            self.send_control_data(Message.ReportType.OTHER_REPORT, ret.data)
        else:
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)

    def register_get_protocol_cb(self, cb: Callable[[], Device.GetSetStatus]) -> None:
        self.get_protocol_cb = cb
        logger.debug("GetProtocol callback registered successfully")

    def handle_set_protocol(self, pdu: bytes):
        if self.set_protocol_cb is None:
            logger.debug("SetProtocol callback not registered !!")
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
            return
        ret = self.set_protocol_cb(pdu[0] & 0x01)
        if ret.status == self.GetSetReturn.SUCCESS:
            self.send_handshake_message(Message.Handshake.SUCCESSFUL)
        else:
            self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)

    def register_set_protocol_cb(
        self, cb: Callable[[int], Device.GetSetStatus]
    ) -> None:
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
