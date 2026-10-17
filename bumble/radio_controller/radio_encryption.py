# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LE encryption/refresh and authenticated payload supervision, Core 5.1.3/5.1.8."""

from __future__ import annotations

import struct
from enum import Enum, auto
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from bumble import crypto
from bumble.hci import HCI_ErrorCode as ErrorCode
from bumble.hci import LeFeatureMask, Role
from bumble.ll import (
    LL_AUTHENTICATED_PAYLOAD_TIMEOUT_DEFAULT,
    LL_AUTHENTICATED_PAYLOAD_TIMEOUT_UNIT_US,
    LL_CONN_INTERVAL_UNIT_US,
    LL_ENCRYPTION_COUNTER_BITS,
    LL_ENCRYPTION_COUNTER_SIZE,
    LL_ENCRYPTION_DIRECTION_MASK,
    LL_ENCRYPTION_IV_HALF_SIZE,
    LL_ENCRYPTION_KEY_SIZE,
    LL_ENCRYPTION_RANDOM_SIZE,
    LL_ENCRYPTION_SKD_HALF_SIZE,
    LL_RESPONSE_TIMEOUT_US,
    PDU_DATA_AUTHENTICATED_HEADER_MASK,
    PDU_DATA_LLID_MASK,
    PDU_DATA_MIC_SIZE,
    ControlPdu,
    LlId,
)

if TYPE_CHECKING:
    from bumble.radio_controller.radio_connection import Connection

PROCEDURE_COLLISION = (
    ErrorCode.LMP_ERROR_TRANSACTION_COLLISION_OR_LL_PROCEDURE_COLLISION_ERROR
)
Opcode = ControlPdu.Opcode
ENC_REQUEST = struct.Struct(
    f'<{LL_ENCRYPTION_RANDOM_SIZE}sH{LL_ENCRYPTION_SKD_HALF_SIZE}s'
    f'{LL_ENCRYPTION_IV_HALF_SIZE}s'
)
ENC_RESPONSE = struct.Struct(
    f'<{LL_ENCRYPTION_SKD_HALF_SIZE}s{LL_ENCRYPTION_IV_HALF_SIZE}s'
)


class PacketCipher:
    """Wire-order IV/SKD and HCI-order LTK; independent counters in each direction."""

    def __init__(self, key: bytes, iv: bytes, *, central: bool):
        if (
            len(key) != LL_ENCRYPTION_KEY_SIZE
            or len(iv) != 2 * LL_ENCRYPTION_IV_HALF_SIZE
        ):
            raise ValueError('LE encryption requires a 128-bit key and 64-bit IV')
        self.aes = AESCCM(key, tag_length=PDU_DATA_MIC_SIZE)
        self.iv = iv
        self.central = central
        self.tx_counter = self.rx_counter = 0

    def nonce(self, counter: int, central: bool) -> bytes:
        if not 0 <= counter < 1 << LL_ENCRYPTION_COUNTER_BITS:
            raise OverflowError('LE encryption packet counter exhausted')
        return (counter | (LL_ENCRYPTION_DIRECTION_MASK if central else 0)).to_bytes(
            LL_ENCRYPTION_COUNTER_SIZE, 'little'
        ) + self.iv

    def encrypt(self, header: int, payload: bytes) -> bytes:
        if not payload:
            return payload
        result = self.aes.encrypt(
            self.nonce(self.tx_counter, self.central),
            payload,
            bytes([header & PDU_DATA_AUTHENTICATED_HEADER_MASK]),
        )
        self.tx_counter += 1
        return result

    def decrypt(self, header: int, payload: bytes, *, duplicate: bool) -> bytes:
        if not payload:
            return payload
        if len(payload) <= PDU_DATA_MIC_SIZE:
            raise InvalidTag('an encrypted nonempty PDU requires payload and MIC')
        result = self.aes.decrypt(
            self.nonce(self.rx_counter - int(duplicate), not self.central),
            payload,
            bytes([header & PDU_DATA_AUTHENTICATED_HEADER_MASK]),
        )
        if not duplicate:
            self.rx_counter += 1
        return result


class State(Enum):
    IDLE = auto()
    ENC_RSP = auto()
    START_REQ = auto()
    KEY = auto()
    START_RSP = auto()
    START_ACK = auto()
    PAUSE_RSP = auto()
    PAUSE_ACK = auto()
    RESTART = auto()
    REJECT = auto()


class Encryption:
    def __init__(self, connection: Connection):
        self.connection = connection
        self.state = State.IDLE
        self.cipher: PacketCipher | None = None
        self.tx_enabled = self.rx_enabled = self.enabled = False
        self.refresh = False
        self.deadline_us = 0
        self.ltk = b''
        self.rand = b''
        self.ediv = 0
        self.skd_c = self.skd_p = self.iv_c = self.iv_p = b''
        self.auth_timeout = LL_AUTHENTICATED_PAYLOAD_TIMEOUT_DEFAULT
        self.last_authenticated_us = 0
        self.ping_pending = False
        self.last_received: tuple[int, bytes, bytes, bool] | None = None

    @property
    def busy(self) -> bool:
        return self.state != State.IDLE

    def can_send(self, llid: int, payload: bytes) -> bool:
        if not self.busy:
            return True
        return (
            llid == LlId.CONTROL
            and bool(payload)
            and payload[0]
            in (
                Opcode.LL_ENC_REQ,
                Opcode.LL_ENC_RSP,
                Opcode.LL_START_ENC_REQ,
                Opcode.LL_START_ENC_RSP,
                Opcode.LL_PAUSE_ENC_REQ,
                Opcode.LL_PAUSE_ENC_RSP,
                Opcode.LL_TERMINATE_IND,
                Opcode.LL_REJECT_IND,
                Opcode.LL_REJECT_EXT_IND,
            )
        )

    def enqueue(self, opcode: int, payload: bytes = b'') -> None:
        if self.busy:
            # Core Vol 6 Part B 5.2: queueing each procedure control PDU resets T_PRT.
            self.deadline_us = self.connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
        self.connection.enqueue_control(bytes([opcode]) + payload)

    def start(self, rand: bytes, ediv: int, ltk: bytes) -> None:
        self.rand, self.ediv, self.ltk = rand, ediv, ltk
        self.refresh = self.enabled
        self.deadline_us = 0
        if self.refresh:
            self.state = State.PAUSE_RSP
            self.enqueue(Opcode.LL_PAUSE_ENC_REQ)
        else:
            self.request()

    def request(self) -> None:
        generator = self.connection.link.random
        self.skd_c = generator.randbytes(LL_ENCRYPTION_SKD_HALF_SIZE)
        self.iv_c = generator.randbytes(LL_ENCRYPTION_IV_HALF_SIZE)
        self.state = State.ENC_RSP
        self.deadline_us = 0
        self.enqueue(
            Opcode.LL_ENC_REQ,
            ENC_REQUEST.pack(self.rand, self.ediv, self.skd_c, self.iv_c),
        )

    def install(self) -> None:
        # e() exposes little-endian Bluetooth AES; AESCCM expects the AES key order.
        key = crypto.e(self.ltk, self.skd_c + self.skd_p)[::-1]
        self.cipher = PacketCipher(
            key, self.iv_c + self.iv_p, central=self.connection.role == Role.CENTRAL
        )
        self.last_received = None

    def supply_key(self, ltk: bytes | None) -> None:
        if ltk is None:
            extended = self.connection.peer_features is not None and bool(
                self.connection.peer_features & LeFeatureMask.EXTENDED_REJECT_INDICATION
            )
            payload = bytes([Opcode.LL_ENC_REQ]) if extended else b''
            self.enqueue(
                Opcode.LL_REJECT_EXT_IND if extended else Opcode.LL_REJECT_IND,
                payload + bytes([ErrorCode.PIN_OR_KEY_MISSING_ERROR]),
            )
            self.state = State.REJECT if self.refresh else State.IDLE
            if not self.refresh:
                self.deadline_us = 0
            return
        self.ltk = ltk
        self.install()
        self.state = State.START_RSP
        self.enqueue(Opcode.LL_START_ENC_REQ)

    def finish(self, status: int = ErrorCode.SUCCESS) -> None:
        self.state = State.IDLE
        self.deadline_us = 0
        self.enabled = not status
        self.last_authenticated_us = self.connection.radio.now_us
        self.ping_pending = False
        self.connection.link.listener.on_encryption_changed(
            self.connection, status, self.refresh
        )
        if status:
            self.tx_enabled = self.rx_enabled = False
            if self.refresh:
                self.connection.complete(status)

    def control(self, payload: bytes) -> bool:
        opcode, data = payload[0], payload[1:]
        central = self.connection.role == Role.CENTRAL
        if (
            opcode == Opcode.LL_ENC_REQ
            and not central
            and len(data) == ENC_REQUEST.size
        ):
            if self.enabled and self.state == State.IDLE:
                self.connection.complete(
                    ErrorCode.CONNECTION_TERMINATED_DUE_TO_MIC_FAILURE_ERROR
                )
                return True
            if self.state not in (State.IDLE, State.RESTART):
                self.connection.controls.reject(
                    opcode,
                    PROCEDURE_COLLISION,
                )
                return True
            self.refresh = self.enabled or self.state == State.RESTART
            self.rand, self.ediv, self.skd_c, self.iv_c = ENC_REQUEST.unpack(data)
            generator = self.connection.link.random
            self.skd_p = generator.randbytes(LL_ENCRYPTION_SKD_HALF_SIZE)
            self.iv_p = generator.randbytes(LL_ENCRYPTION_IV_HALF_SIZE)
            self.state = State.KEY
            self.enqueue(Opcode.LL_ENC_RSP, ENC_RESPONSE.pack(self.skd_p, self.iv_p))
            self.connection.link.listener.on_long_term_key_request(
                self.connection, self.rand, self.ediv
            )
            return True
        if (
            opcode == Opcode.LL_ENC_RSP
            and central
            and self.state == State.ENC_RSP
            and len(data) == ENC_RESPONSE.size
        ):
            self.skd_p, self.iv_p = ENC_RESPONSE.unpack(data)
            self.install()
            self.state = State.START_REQ
            return True
        if (
            opcode == Opcode.LL_START_ENC_REQ
            and not data
            and central
            and self.state == State.START_REQ
        ):
            self.tx_enabled = self.rx_enabled = True
            self.state = State.START_RSP
            self.enqueue(Opcode.LL_START_ENC_RSP)
            return True
        if (
            opcode == Opcode.LL_START_ENC_RSP
            and not data
            and self.state == State.START_RSP
        ):
            if central:
                self.finish()
            else:
                self.tx_enabled = True
                self.state = State.START_ACK
                self.enqueue(Opcode.LL_START_ENC_RSP)
            return True
        if (
            opcode == Opcode.LL_PAUSE_ENC_REQ
            and not data
            and not central
            and self.enabled
            and not self.busy
        ):
            self.refresh = True
            self.state = State.PAUSE_ACK
            self.enqueue(Opcode.LL_PAUSE_ENC_RSP)
            return True
        if opcode == Opcode.LL_PAUSE_ENC_RSP and not data:
            if central and self.state == State.PAUSE_RSP:
                self.tx_enabled = self.rx_enabled = False
                self.state = State.PAUSE_ACK
                self.enqueue(Opcode.LL_PAUSE_ENC_RSP)
                return True
            if not central and self.state == State.PAUSE_ACK:
                self.tx_enabled = self.rx_enabled = False
                self.state = State.RESTART
                return True
        if (
            opcode
            in (Opcode.LL_REJECT_IND, Opcode.LL_REJECT_EXT_IND, Opcode.LL_UNKNOWN_RSP)
            and central
            and self.state in (State.ENC_RSP, State.START_REQ)
        ):
            if opcode == Opcode.LL_UNKNOWN_RSP and data == bytes([Opcode.LL_ENC_REQ]):
                self.finish(ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR)
                return True
            if (opcode == Opcode.LL_REJECT_IND and len(data) == 1) or (
                opcode == Opcode.LL_REJECT_EXT_IND
                and len(data) == 2
                and data[0] == Opcode.LL_ENC_REQ
            ):
                self.finish(data[-1])
                return True
        if opcode == Opcode.LL_PING_REQ and not data:
            self.enqueue(Opcode.LL_PING_RSP)
            return True
        return opcode == Opcode.LL_PING_RSP and not data

    def sent(self, payload: bytes) -> None:
        if (
            self.state == State.REJECT
            and payload
            and payload[0]
            in (
                Opcode.LL_REJECT_IND,
                Opcode.LL_REJECT_EXT_IND,
            )
        ):
            self.connection.complete(payload[-1])
            return
        if (
            payload == bytes([Opcode.LL_START_ENC_REQ])
            and self.state == State.START_RSP
        ):
            self.rx_enabled = True
        elif (
            payload == bytes([Opcode.LL_PAUSE_ENC_RSP])
            and self.connection.role == Role.PERIPHERAL
            and self.state == State.PAUSE_ACK
        ):
            self.rx_enabled = False

    def acknowledged(self, payload: bytes) -> None:
        if (
            payload == bytes([Opcode.LL_START_ENC_RSP])
            and self.state == State.START_ACK
        ):
            self.finish()
        elif (
            payload == bytes([Opcode.LL_PAUSE_ENC_RSP])
            and self.connection.role == Role.CENTRAL
            and self.state == State.PAUSE_ACK
        ):
            self.request()

    def receive(self, header: int, payload: bytes, *, duplicate: bool) -> bytes | None:
        if not payload:
            return payload
        authenticated_header = header & PDU_DATA_AUTHENTICATED_HEADER_MASK
        # The pause transition may change RX mode before an earlier PDU is retried.
        if duplicate and self.last_received is not None:
            previous_header, wire, plaintext, authenticated = self.last_received
            if (
                authenticated_header == previous_header
                and payload == wire
                and (
                    authenticated == self.rx_enabled
                    or (
                        authenticated and self.state in (State.PAUSE_ACK, State.RESTART)
                    )
                )
            ):
                if authenticated:
                    self.last_authenticated_us = self.connection.radio.now_us
                    self.ping_pending = False
                return plaintext
        wire, authenticated = payload, self.rx_enabled
        if self.rx_enabled:
            assert self.cipher is not None
            try:
                payload = self.cipher.decrypt(header, payload, duplicate=duplicate)
            except (InvalidTag, OverflowError, ValueError):
                self.connection.complete(
                    ErrorCode.CONNECTION_TERMINATED_DUE_TO_MIC_FAILURE_ERROR
                )
                return None
            self.last_authenticated_us = self.connection.radio.now_us
            self.ping_pending = False
        if not duplicate and self.state in (
            State.KEY,
            State.START_REQ,
            State.START_RSP,
            State.PAUSE_ACK,
            State.RESTART,
            State.REJECT,
        ):
            expected = {
                State.KEY: Opcode.LL_TERMINATE_IND,
                State.START_REQ: Opcode.LL_START_ENC_REQ,
                State.START_RSP: Opcode.LL_START_ENC_RSP,
                State.PAUSE_ACK: Opcode.LL_PAUSE_ENC_RSP,
                State.RESTART: Opcode.LL_ENC_REQ,
                State.REJECT: Opcode.LL_TERMINATE_IND,
            }[self.state]
            if header & PDU_DATA_LLID_MASK != LlId.CONTROL or payload[0] not in (
                expected,
                Opcode.LL_TERMINATE_IND,
                Opcode.LL_REJECT_IND,
                Opcode.LL_REJECT_EXT_IND,
            ):
                self.connection.complete(
                    ErrorCode.CONNECTION_TERMINATED_DUE_TO_MIC_FAILURE_ERROR
                )
                return None
        self.last_received = (authenticated_header, wire, payload, authenticated)
        return payload

    @property
    def next_deadline_us(self) -> int:
        if self.busy:
            return self.deadline_us
        if not self.enabled:
            return 0
        timeout_us = self.auth_timeout * LL_AUTHENTICATED_PAYLOAD_TIMEOUT_UNIT_US
        reserve_us = min(
            timeout_us // 2,
            # One interval to align the request to an event and another for
            # the peer's response when the request closes that event.
            2
            * self.connection.parameters.interval
            * LL_CONN_INTERVAL_UNIT_US
            * (self.connection.parameters.latency + 1),
        )
        return (
            self.last_authenticated_us
            + timeout_us
            - (0 if self.ping_pending else reserve_us)
        )

    def check_timeout(self) -> bool:
        now = self.connection.radio.now_us
        if self.busy and self.deadline_us and now >= self.deadline_us:
            self.connection.complete(ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR)
            return True
        if self.enabled and not self.busy and now >= self.next_deadline_us:
            if self.ping_pending:
                self.connection.link.listener.on_authenticated_payload_timeout(
                    self.connection
                )
                self.last_authenticated_us = now
                self.ping_pending = False
            else:
                self.enqueue(Opcode.LL_PING_REQ)
                self.ping_pending = True
        return False
