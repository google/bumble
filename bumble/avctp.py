# Copyright 2021-2023 Google LLC
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
from enum import IntEnum
import logging
import struct
from typing import Callable, cast, Dict, Optional

from bumble.colors import color
from bumble import avc
from bumble import l2cap

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
AVCTP_PSM = 0x0017
AVCTP_BROWSING_PSM = 0x001B


# -----------------------------------------------------------------------------
class MessageAssembler:
    Callback = Callable[[int, bool, bool, int, bytes], None]

    transaction_label: int
    pid: int
    c_r: int
    ipid: int
    payload: bytes
    number_of_packets: int
    packets_received: int

    def __init__(self, callback: Callback) -> None:
        self.callback = callback
        self.reset()

    def reset(self) -> None:
        self.packets_received = 0
        self.transaction_label = -1
        self.pid = -1
        self.c_r = -1
        self.ipid = -1
        self.payload = b''
        self.number_of_packets = 0
        self.packet_count = 0

    def on_pdu(self, pdu: bytes) -> None:
        self.packets_received += 1

        transaction_label = pdu[0] >> 4
        packet_type = Protocol.PacketType((pdu[0] >> 2) & 3)
        c_r = (pdu[0] >> 1) & 1
        ipid = pdu[0] & 1

        if c_r == 0 and ipid != 0:
            logger.warning("invalid IPID in command frame")
            self.reset()
            return

        pid_offset = 1
        if packet_type in (Protocol.PacketType.SINGLE, Protocol.PacketType.START):
            if self.transaction_label >= 0:
                # We are already in a transaction
                logger.warning("received START or SINGLE fragment while in transaction")
                self.reset()
                self.packets_received = 1

            if packet_type == Protocol.PacketType.START:
                self.number_of_packets = pdu[1]
                pid_offset = 2

        pid = struct.unpack_from(">H", pdu, pid_offset)[0]
        self.payload += pdu[pid_offset + 2 :]

        if packet_type in (Protocol.PacketType.CONTINUE, Protocol.PacketType.END):
            if transaction_label != self.transaction_label:
                logger.warning("transaction label does not match")
                self.reset()
                return

            if pid != self.pid:
                logger.warning("PID does not match")
                self.reset()
                return

            if c_r != self.c_r:
                logger.warning("C/R does not match")
                self.reset()
                return

            if self.packets_received > self.number_of_packets:
                logger.warning("too many fragments in transaction")
                self.reset()
                return

            if packet_type == Protocol.PacketType.END:
                if self.packets_received != self.number_of_packets:
                    logger.warning("premature END")
                    self.reset()
                    return
        else:
            self.transaction_label = transaction_label
            self.c_r = c_r
            self.ipid = ipid
            self.pid = pid

        if packet_type in (Protocol.PacketType.SINGLE, Protocol.PacketType.END):
            self.on_message_complete()

    def on_message_complete(self):
        try:
            self.callback(
                self.transaction_label,
                self.c_r == 0,
                self.ipid != 0,
                self.pid,
                self.payload,
            )
        except Exception as error:
            logger.exception(color(f"!!! exception in callback: {error}", "red"))

        self.reset()


# -----------------------------------------------------------------------------
class Protocol:
    CommandHandler = Callable[[int, avc.CommandFrame], None]
    command_handlers: Dict[int, CommandHandler]  # Command handlers, by PID
    ResponseHandler = Callable[[int, Optional[avc.ResponseFrame]], None]
    response_handlers: Dict[int, ResponseHandler]  # Response handlers, by PID
    next_transaction_label: int
    message_assembler: MessageAssembler

    class PacketType(IntEnum):
        SINGLE = 0b00
        START = 0b01
        CONTINUE = 0b10
        END = 0b11

    def __init__(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        self.command_handlers = {}
        self.response_handlers = {}
        self.l2cap_channel = l2cap_channel
        self.message_assembler = MessageAssembler(self.on_message)

        # Register to receive PDUs from the channel
        l2cap_channel.sink = self.on_pdu
        l2cap_channel.on("open", self.on_l2cap_channel_open)
        l2cap_channel.on("close", self.on_l2cap_channel_close)

    def on_l2cap_channel_open(self):
        logger.debug(color("<<< AVCTP channel open", "magenta"))

    def on_l2cap_channel_close(self):
        logger.debug(color("<<< AVCTP channel closed", "magenta"))

    def on_pdu(self, pdu: bytes) -> None:
        self.message_assembler.on_pdu(pdu)

    def on_message(
        self,
        transaction_label: int,
        is_command: bool,
        ipid: bool,
        pid: int,
        payload: bytes,
    ) -> None:
        logger.debug(
            f"<<< AVCTP Message: pid={pid}, "
            f"transaction_label={transaction_label}, "
            f"is_command={is_command}, "
            f"ipid={ipid}, "
            f"payload={payload.hex()}"
        )

        # Check for invalid PID responses.
        if ipid:
            logger.debug(f"received IPID for PID={pid}")

        # Find the appropriate handler.
        if is_command:
            if pid not in self.command_handlers:
                logger.warning(f"no command handler for PID {pid}")
                self.send_ipid(transaction_label, pid)
                return

            command_frame = cast(avc.CommandFrame, avc.Frame.from_bytes(payload))
            self.command_handlers[pid](transaction_label, command_frame)
        else:
            if pid not in self.response_handlers:
                logger.warning(f"no response handler for PID {pid}")
                return

            # By convention, for an ipid, send a None payload to the response handler.
            if ipid:
                response_frame = None
            else:
                response_frame = cast(avc.ResponseFrame, avc.Frame.from_bytes(payload))

            self.response_handlers[pid](transaction_label, response_frame)

    def send_message(
        self,
        transaction_label: int,
        is_command: bool,
        ipid: bool,
        pid: int,
        payload: bytes,
    ):
        # TODO: fragment large messages
        packet_type = Protocol.PacketType.SINGLE
        pdu = (
            struct.pack(
                ">BH",
                transaction_label << 4
                | packet_type << 2
                | (0 if is_command else 1) << 1
                | (1 if ipid else 0),
                pid,
            )
            + payload
        )
        self.l2cap_channel.send_pdu(pdu)

    def send_command(self, transaction_label: int, pid: int, payload: bytes) -> None:
        logger.debug(
            ">>> AVCTP command: "
            f"transaction_label={transaction_label}, "
            f"pid={pid}, "
            f"payload={payload.hex()}"
        )
        self.send_message(transaction_label, True, False, pid, payload)

    def send_response(self, transaction_label: int, pid: int, payload: bytes):
        logger.debug(
            ">>> AVCTP response: "
            f"transaction_label={transaction_label}, "
            f"pid={pid}, "
            f"payload={payload.hex()}"
        )
        self.send_message(transaction_label, False, False, pid, payload)

    def send_ipid(self, transaction_label: int, pid: int) -> None:
        logger.debug(
            ">>> AVCTP ipid: " f"transaction_label={transaction_label}, " f"pid={pid}"
        )
        self.send_message(transaction_label, False, True, pid, b'')

    def register_command_handler(
        self, pid: int, handler: Protocol.CommandHandler
    ) -> None:
        self.command_handlers[pid] = handler

    def unregister_command_handler(
        self, pid: int, handler: Protocol.CommandHandler
    ) -> None:
        if pid not in self.command_handlers or self.command_handlers[pid] != handler:
            raise ValueError("command handler not registered")
        del self.command_handlers[pid]

    def register_response_handler(
        self, pid: int, handler: Protocol.ResponseHandler
    ) -> None:
        self.response_handlers[pid] = handler

    def unregister_response_handler(
        self, pid: int, handler: Protocol.ResponseHandler
    ) -> None:
        if pid not in self.response_handlers or self.response_handlers[pid] != handler:
            raise ValueError("response handler not registered")
        del self.response_handlers[pid]
