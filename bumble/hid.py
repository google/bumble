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
import logging
import asyncio

from pyee import EventEmitter
from typing import Optional, Tuple, Callable, Dict, Union

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

HID_CTRL_PSM            = 0x0011
HID_INTR_PSM            = 0x0013

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

# -----------------------------------------------------------------------------
class HIDHost(EventEmitter):
    l2cap_channel: Optional[l2cap.Channel]

    def __init__(self, device, connection) -> None:
        super().__init__()
        self.device = device
        self.connection = connection
        self.l2cap_ctrl_channel= None
        self.l2cap_intr_channel = None

        # Register ourselves with the L2CAP channel manager
        device.register_l2cap_server(HID_CTRL_PSM, self.on_connection)
        device.register_l2cap_server(HID_INTR_PSM, self.on_connection)

    async def control_channel_connect(self) -> None:
        # Create a new L2CAP connection - control channel
        try:
            self.l2cap_ctrl_channel = await self.device.l2cap_channel_manager.connect(
                self.connection, HID_CTRL_PSM
            )
        except ProtocolError as error:
            logger.error(f'L2CAP connection failed: {error}')
            raise

        assert self.l2cap_ctrl_channel is not None
        # Become a sink for the L2CAP channel
        self.l2cap_ctrl_channel.sink = self.on_ctrl_pdu

    async def interrupt_channel_connect(self) -> None:
        # Create a new L2CAP connection - interrupt channel
        try:
            self.l2cap_intr_channel = await self.device.l2cap_channel_manager.connect(
                self.connection, HID_INTR_PSM
            )
        except ProtocolError as error:
            logger.error(f'L2CAP connection failed: {error}')
            raise

        assert self.l2cap_intr_channel is not None
        # Become a sink for the L2CAP channel
        self.l2cap_intr_channel.sink = self.on_intr_pdu

    async def interrupt_channel_disconnect(self):
        await self.l2cap_intr_channel.disconnect()  # type: ignore

    async def control_channel_disconnect(self):
        await self.l2cap_ctrl_channel.disconnect()  # type: ignore

    def on_connection(self, l2cap_channel: l2cap.Channel) -> None:
        logger.debug(f'+++ New L2CAP connection: {l2cap_channel}')
        l2cap_channel.on('open', lambda: self.on_l2cap_channel_open(l2cap_channel))

    def on_l2cap_channel_open(self, l2cap_channel: l2cap.Channel) -> None:
        if l2cap_channel.psm == HID_CTRL_PSM:
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
        if (message_type == HID_HANDSHAKE):
            logger.debug('<<< HID HANDSHAKE')
            self.handle_handshake(param)
            self.emit('handshake', )
        elif (message_type == HID_DATA):
            logger.debug('<<< HID CONTROL DATA')
            self.emit('data', pdu)
        elif (message_type == HID_CONTROL):
            if (param == HID_SUSPEND):
                logger.debug('<<< HID SUSPEND')
                self.emit('suspend', pdu)
            elif (param == HID_EXIT_SUSPEND):
                logger.debug('<<< HID EXIT SUSPEND')
                self.emit('exit_suspend', pdu)
            elif (param == HID_VIRTUAL_CABLE_UNPLUG):
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

    def register_data_cb(self, data_cb):
        self.on('data', data_cb)

    def register_handshake_cb(self, handshake_cb):
        self.on('handshake', handshake_cb)

    def register_virtual_cable_unplug(self, virtual_cable_unplug_cb):
        self.on('virtual_cable_unplug', virtual_cable_unplug_cb)

    def get_report(self, report_type, report_id, buffer_size):
        if(report_type == HID_OTHER_REPORT):
            param = report_type
        else:
            param = 0x08 | report_type
        header = ((HID_GET_REPORT << 4) | param)
        msg = bytes([header, report_id, (buffer_size & 0xff), ((buffer_size >> 8) & 0xff)])
        logger.debug(f'>>> HID CONTROL GET REPORT, PDU: {msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def set_report(self, report_type, data):
        header = ((HID_SET_REPORT << 4) | report_type)
        msg = bytearray([header])
        msg.extend(data)
        logger.debug(f'>>> HID CONTROL SET REPORT, PDU:{msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def get_protocol(self):
        header = (HID_GET_PROTOCOL << 4)
        msg = bytearray([header])
        logger.debug(f'>>> HID CONTROL GET PROTOCOL, PDU: {msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def set_protocol(self, protocol_mode):
        header = (HID_SET_PROTOCOL << 4 | protocol_mode)
        msg = bytearray([header])
        logger.debug(f'>>> HID CONTROL SET PROTOCOL, PDU: {msg.hex()}')
        self.l2cap_ctrl_channel.send_pdu(msg)  # type: ignore

    def send_data(self, data):
        header = ((HID_DATA << 4) | HID_OUTPUT_REPORT)
        msg = bytearray([header])
        msg.extend(data)
        logger.debug(f'>>> HID INTERRUPT SEND DATA, PDU: {msg.hex()}')
        self.l2cap_intr_channel.send_pdu(msg)  # type: ignore

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

    def handle_handshake(self, param):
        if (param == HANDSHAKE_SUCCESSFUL):
            logger.debug(f'<<< HID HANDSHAKE: SUCCESSFUL')
        elif (param == HANDSHAKE_NOT_READY):
            logger.warning(f'<<< HID HANDSHAKE: NOT_READY')
        elif (param == HANDSHAKE_ERR_INVALID_REPORT_ID):
            logger.warning(f'<<< HID HANDSHAKE: ERR_INVALID_REPORT_ID')
        elif (param == HANDSHAKE_ERR_UNSUPPORTED_REQUEST):
            logger.warning(f'<<< HID HANDSHAKE: ERR_UNSUPPORTED_REQUEST')
        elif (param == HANDSHAKE_ERR_UNKNOWN):
            logger.warning(f'<<< HID HANDSHAKE: ERR_UNKNOWN')
        elif (param == HANDSHAKE_ERR_FATAL):
            logger.warning(f'<<< HID HANDSHAKE: ERR_FATAL')
        else: # 0x5-0xD = Reserved
            logger.warning("<<< HID HANDSHAKE: RESERVED VALUE")

