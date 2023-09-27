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

from pyee import EventEmitter
from typing import Optional, Tuple, Callable, Dict, Union
from .device import Device, Connection

from . import core, l2cap  # type: ignore
from .colors import color  # type: ignore
from .core import BT_BR_EDR_TRANSPORT, InvalidStateError, ProtocolError  # type: ignore

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off

HID_CONTROL_PSM            = 0x0011
HID_INTERRUPT_PSM          = 0x0013

# HIDP message types
HID_HANDSHAKE           = 0x00
HID_CONTROL             = 0x01
HID_GET_REPORT          = 0x04
HID_SET_REPORT          = 0x05
HID_GET_PROTOCOL        = 0x06
HID_SET_PROTOCOL        = 0x07
HID_DATA                = 0x0A

# Report types
HID_OTHER_REPORT        = 0x00
HID_INPUT_REPORT        = 0x01
HID_OUTPUT_REPORT       = 0x02
HID_FEATURE_REPORT      = 0x03

# Handshake parameters
HANDSHAKE_SUCCESSFUL              = 0x00
HANDSHAKE_NOT_READY               = 0x01
HANDSHAKE_ERR_INVALID_REPORT_ID   = 0x02
HANDSHAKE_ERR_UNSUPPORTED_REQUEST = 0x03
HANDSHAKE_ERR_UNKNOWN             = 0x0E
HANDSHAKE_ERR_FATAL               = 0x0F

# Protocol modes
HID_BOOT_PROTOCOL_MODE      = 0x00
HID_REPORT_PROTOCOL_MODE    = 0x01

# Control Operations
HID_SUSPEND              = 0x03
HID_EXIT_SUSPEND         = 0x04
HID_VIRTUAL_CABLE_UNPLUG = 0x05


class HIDPacket():
    def __init__(self,
                 report_type: Optional[int] = None,
                 report_id: Optional[int] = None,
                 buffer_size: Optional[int] = None,
                 protocol_mode: Optional[int] = None,
                 data: Optional[bytes] = None) -> None:

        self.report_type = report_type
        self.report_id = report_id
        self.buffer_size = buffer_size
        self.protocol_mode = protocol_mode
        self.data = data

    def to_bytes_gr(self) -> bytes:
        if(self.report_type == HID_OTHER_REPORT):
            param = self.report_type
        else:
            param = 0x08 | self.report_type
        header = ((HID_GET_REPORT << 4) | param)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        packet_bytes.append(self.report_id)
        packet_bytes.extend([(self.buffer_size & 0xff), ((self.buffer_size >> 8) & 0xff)])
        return bytes(packet_bytes)

    def to_bytes_sr(self) -> bytes:
        header = ((HID_SET_REPORT << 4) | self.report_type)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        packet_bytes.extend(self.data)
        return bytes(packet_bytes)

    def to_bytes_gp(self) -> bytes:
        header = (HID_GET_PROTOCOL << 4)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        return bytes(packet_bytes)

    def to_bytes_sp(self) -> bytes:
        header = (HID_SET_PROTOCOL << 4 | self.protocol_mode)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        packet_bytes.append(self.protocol_mode)
        return bytes(packet_bytes)

    def to_bytes_send_data(self) -> bytes:
        header = ((HID_DATA << 4) | HID_OUTPUT_REPORT)
        packet_bytes = bytearray()
        packet_bytes.append(header)
        packet_bytes.extend(self.data)
        return bytes(packet_bytes)
# -----------------------------------------------------------------------------
class HIDHost(EventEmitter):
    l2cap_channel: Optional[l2cap.Channel]

    def __init__(self, device: Device, connection: Connection) -> None:
        super().__init__()
        self.device = device
        self.connection = connection
        self.l2cap_ctrl_channel= None
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
        except ProtocolError as error:
            logger.error(f'L2CAP connection failed: {error}')
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
        except ProtocolError as error:
            logger.error(f'L2CAP connection failed: {error}')
            raise

        assert self.l2cap_intr_channel is not None
        # Become a sink for the L2CAP channel
        self.l2cap_intr_channel.sink = self.on_intr_pdu

    async def disconnect_interrupt_channel(self) -> None:
        if self.l2cap_intr_channel is None:
            raise InvalidStateError('invalid state')
        await self.l2cap_intr_channel.disconnect()  # type: ignore

    async def disconnect_control_channel(self) -> None:
        if self.l2cap_ctrl_channel is None:
            raise InvalidStateError('invalid state')
        await self.l2cap_ctrl_channel.disconnect()  # type: ignore

    def on_connection(self, l2cap_channel: l2cap.Channel) -> None:
        logger.debug(f'+++ New L2CAP connection: {l2cap_channel}')
        l2cap_channel.on('open', lambda: self.on_l2cap_channel_open(l2cap_channel))

    def on_l2cap_channel_open(self, l2cap_channel: l2cap.Channel) -> None:
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
        param = pdu[0] & 0x0f
        if message_type == HID_HANDSHAKE :
            logger.debug('<<< HID HANDSHAKE')
            self.handle_handshake(param)
            self.emit('handshake', pdu)
        elif message_type == HID_DATA :
            logger.debug('<<< HID CONTROL DATA')
            self.emit('data', pdu)
        elif message_type == HID_CONTROL :
            if param == HID_SUSPEND :
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

    def on_intr_pdu(self, pdu: bytes) -> None:
        logger.debug(f'<<< HID INTERRUPT PDU: {pdu.hex()}')
        self.emit("data", pdu)

    def get_report(self, report_type: int, report_id: int, buffer_size: int) -> None:
        msg = HIDPacket(report_type = report_type , report_id = report_id , buffer_size = buffer_size)
        hid_packet = msg.to_bytes_gr()
        logger.debug(f'>>> HID CONTROL GET REPORT, PDU: {hid_packet.hex()}')
        self.send_pdu_on_ctrl(hid_packet)  # type: ignore

    def set_report(self, report_type: int, data: bytes):
        msg = HIDPacket(report_type= report_type,data = data)
        hid_packet = msg.to_bytes_sr()
        logger.debug(f'>>> HID CONTROL SET REPORT, PDU:{hid_packet.hex()}')
        self.send_pdu_on_ctrl(hid_packet)  # type: ignore

    def get_protocol(self):
        msg = HIDPacket()
        hid_packet = msg.to_bytes_gp()
        logger.debug(f'>>> HID CONTROL GET PROTOCOL, PDU: {hid_packet.hex()}')
        self.send_pdu_on_ctrl(hid_packet)  # type: ignore

    def set_protocol(self, protocol_mode: int):
        msg = HIDPacket(protocol_mode= protocol_mode)
        hid_packet = msg.to_bytes_sp()
        logger.debug(f'>>> HID CONTROL SET PROTOCOL, PDU: {hid_packet.hex()}')
        self.send_pdu_on_ctrl(hid_packet)  # type: ignore

    def send_pdu_on_ctrl(self, msg: bytes) -> None:
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def send_pdu_on_intr(self, msg: bytes) -> None:
        self.l2cap_intr_channel.send_pdu(msg)  # type: ignore

    def send_data(self, data):
        msg = HIDPacket(data= data)
        hid_packet = msg.to_bytes_send_data()
        logger.debug(f'>>> HID INTERRUPT SEND DATA, PDU: {hid_packet.hex()}')
        self.send_pdu_on_intr(hid_packet)  # type: ignore

    def suspend(self):
        header = (HID_CONTROL << 4 | HID_SUSPEND)
        msg = bytearray([header])
        logger.debug(f'>>> HID CONTROL SUSPEND, PDU:{msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def exit_suspend(self):
        header = (HID_CONTROL << 4 | HID_EXIT_SUSPEND)
        msg = bytearray([header])
        logger.debug(f'>>> HID CONTROL EXIT SUSPEND, PDU:{msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def virtual_cable_unplug(self):
        header = (HID_CONTROL << 4 | HID_VIRTUAL_CABLE_UNPLUG)
        msg = bytearray([header])
        logger.debug(f'>>> HID CONTROL VIRTUAL CABLE UNPLUG, PDU: {msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def handle_handshake(self, param: int):
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
