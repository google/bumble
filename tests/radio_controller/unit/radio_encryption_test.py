# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Nonce limits, encrypted retries and safe key-refresh queue transitions."""

import pytest
from cryptography.exceptions import InvalidTag

from bumble import hci
from bumble.ll import (
    LL_CONN_INTERVAL_UNIT_US,
    LL_RESPONSE_TIMEOUT_US,
    PDU_DATA_MD_MASK,
    PDU_HEADER_SIZE,
    ControlPdu,
    LlId,
)
from bumble.radio_controller.radio_encryption import PacketCipher, State
from tests.radio_controller.unit.helpers import add_connection

ErrorCode = hci.HCI_ErrorCode

Opcode = ControlPdu.Opcode

KEY = bytes.fromhex('99AD1B5226A37E3E058E3B8E27C2C666')

IV = bytes.fromhex('24ABDCBABEBAAFDE')


def test_encryption_setup_remains_per_connection(connection):
    connection.role = hci.Role.CENTRAL
    second = add_connection(connection, 1)
    listener = connection.link.listener
    for value, key in ((connection, b'1' * 16), (second, b'2' * 16)):
        listener.on_hci_le_enable_encryption_command(
            hci.HCI_LE_Enable_Encryption_Command(
                value.handle,
                bytes(8),
                0,
                key,
            )
        )
        assert listener.controller.events[-1].status == ErrorCode.SUCCESS
        assert value.encryption.ltk == key
    assert connection.encryption is not second.encryption
    assert len(connection.queue) == len(second.queue) == 1


@pytest.mark.parametrize(
    'state,opcode',
    [
        (State.ENC_RSP, Opcode.LL_ENC_REQ),
        (State.KEY, Opcode.LL_ENC_RSP),
        (State.START_RSP, Opcode.LL_START_ENC_REQ),
        (State.START_RSP, Opcode.LL_START_ENC_RSP),
        (State.PAUSE_RSP, Opcode.LL_PAUSE_ENC_REQ),
        (State.PAUSE_ACK, Opcode.LL_PAUSE_ENC_RSP),
    ],
)
def test_encryption_control_queue_resets_timer_but_retransmission_does_not(
    connection, state, opcode
):
    encryption = connection.encryption
    encryption.state = state
    encryption.deadline_us = 10
    connection.radio.now_us = 100
    encryption.enqueue(opcode)
    assert encryption.deadline_us == 100 + LL_RESPONSE_TIMEOUT_US
    connection.radio.now_us = 200
    encryption.sent(bytes([opcode]))
    encryption.sent(bytes([opcode]))
    assert encryption.deadline_us == 100 + LL_RESPONSE_TIMEOUT_US


def test_idle_ping_queue_does_not_start_encryption_procedure_timer(connection):
    connection.encryption.enqueue(Opcode.LL_PING_REQ)
    assert connection.encryption.deadline_us == 0


@pytest.mark.parametrize(
    'central,expected', [(True, '9FCDA7F448'), (False, 'A34C13A415')]
)
def test_core_start_encryption_vector(central, expected):
    cipher = PacketCipher(KEY, IV, central=central)
    assert cipher.encrypt(
        LlId.CONTROL, bytes([Opcode.LL_START_ENC_RSP])
    ) == bytes.fromhex(expected)


def test_ccm_masks_acknowledgement_bits_and_reuses_receive_counter():
    tx = PacketCipher(KEY, IV, central=True)
    rx = PacketCipher(KEY, IV, central=False)
    payload = tx.encrypt(LlId.START, b'encrypted payload')
    assert rx.decrypt(LlId.START, payload, duplicate=False) == b'encrypted payload'
    assert (
        rx.decrypt(LlId.START | 0x1C, payload, duplicate=True) == b'encrypted payload'
    )
    assert rx.rx_counter == tx.tx_counter == 1
    with pytest.raises(InvalidTag):
        rx.decrypt(LlId.CONTINUATION, payload, duplicate=True)


def test_empty_packets_have_no_mic_or_counter():
    cipher = PacketCipher(KEY, IV, central=True)
    assert cipher.encrypt(LlId.CONTINUATION, b'') == b''
    assert cipher.decrypt(LlId.CONTINUATION, b'', duplicate=False) == b''
    assert cipher.tx_counter == cipher.rx_counter == 0


def test_counter_exhaustion_never_reuses_a_nonce():
    cipher = PacketCipher(KEY, IV, central=True)
    receiver = PacketCipher(KEY, IV, central=False)
    cipher.tx_counter = (1 << 39) - 1
    receiver.rx_counter = (1 << 39) - 1
    wire = cipher.encrypt(LlId.START, b'last')
    assert receiver.decrypt(LlId.START, wire, duplicate=False) == b'last'
    assert receiver.decrypt(LlId.START, wire, duplicate=True) == b'last'
    with pytest.raises(OverflowError):
        cipher.encrypt(LlId.START, b'overflow')
    with pytest.raises(OverflowError):
        receiver.decrypt(LlId.START, wire, duplicate=False)


@pytest.mark.asyncio
async def test_encrypted_retransmission_preserves_ciphertext_and_counter(connection):
    connection.encryption.cipher = PacketCipher(KEY, IV, central=True)
    connection.encryption.tx_enabled = True
    connection.enqueue_acl(False, b'payload')
    await connection.send(0, 100)
    wire = connection.radio.sent[-1][2]
    await connection.send(0, connection.radio.now_us + 100)
    assert connection.radio.sent[-1][2] == wire
    assert connection.encryption.cipher.tx_counter == 1


def test_mic_failure_never_acknowledges_or_delivers_data(connection):
    connection.reported = True
    connection.encryption.cipher = PacketCipher(KEY, IV, central=False)
    connection.encryption.rx_enabled = True
    tx = PacketCipher(KEY, IV, central=True)
    payload = bytearray(tx.encrypt(LlId.START, b'bad mic'))
    payload[-1] ^= 1
    connection.accept(bytes([LlId.START, len(payload)]) + payload, True)
    assert connection.closed and connection.rx_nesn == 0
    assert (
        connection.link.listener.controller.events[-1].reason
        == hci.HCI_ErrorCode.CONNECTION_TERMINATED_DUE_TO_MIC_FAILURE_ERROR
    )


def test_unexpected_control_during_start_closes_connection(connection):
    connection.encryption.state = State.START_REQ
    connection.accept(bytes([LlId.CONTROL, 1, Opcode.LL_VERSION_IND]), True)
    assert connection.closed and connection.rx_nesn == 0


@pytest.mark.parametrize(
    'llid,payload',
    [(LlId.START, b'data'), (LlId.CONTROL, bytes([Opcode.LL_VERSION_IND]))],
)
def test_no_new_plaintext_procedure_while_host_key_is_pending(
    connection, llid, payload
):
    connection.encryption.state = State.KEY
    connection.accept(bytes([llid, len(payload)]) + payload, True)
    assert connection.closed and connection.rx_nesn == 0


@pytest.mark.parametrize(
    'opcode', [Opcode.LL_VERSION_IND, Opcode.LL_FEATURE_RSP, Opcode.LL_PING_RSP]
)
def test_overlapping_control_is_deferred_until_encryption_completes(connection, opcode):
    from bumble.radio_controller.radio_connection import Outbound

    connection.encryption.state = State.ENC_RSP
    connection.queue.append(Outbound(LlId.CONTROL, bytes([opcode])))
    assert connection._next_outbound().payload == b''
    connection.encryption.state = State.IDLE
    assert connection._next_outbound().payload == bytes([opcode])


def test_ping_budget_covers_request_alignment_and_peer_reply(connection):
    from bumble.ll import LL_AUTHENTICATED_PAYLOAD_TIMEOUT_UNIT_US

    encryption = connection.encryption
    encryption.enabled = True
    encryption.last_authenticated_us = 100
    spacing = (
        connection.parameters.interval
        * LL_CONN_INTERVAL_UNIT_US
        * (connection.parameters.latency + 1)
    )
    assert (
        encryption.next_deadline_us
        == 100
        + encryption.auth_timeout * LL_AUTHENTICATED_PAYLOAD_TIMEOUT_UNIT_US
        - 2 * spacing
    )


@pytest.mark.parametrize('key,iv', [(bytes(24), IV), (KEY, bytes(7))])
def test_cipher_rejects_non_le_key_or_iv(key, iv):
    with pytest.raises(ValueError, match='128-bit key'):
        PacketCipher(key, iv, central=True)


def test_failed_refresh_never_resumes_unencrypted_user_traffic(connection):
    connection.reported = True
    connection.role = hci.Role.CENTRAL
    encryption = connection.encryption
    encryption.enabled = encryption.tx_enabled = encryption.rx_enabled = True
    encryption.start(bytes(8), 0, KEY)
    encryption.finish(hci.HCI_ErrorCode.PIN_OR_KEY_MISSING_ERROR)
    assert connection.closed and not encryption.tx_enabled and not encryption.rx_enabled


def test_duplicate_pause_packet_survives_rx_mode_transition(connection):
    encryption = connection.encryption
    encryption.cipher = PacketCipher(KEY, IV, central=False)
    encryption.rx_enabled = True
    tx = PacketCipher(KEY, IV, central=True)
    wire = tx.encrypt(LlId.CONTROL, bytes([Opcode.LL_PAUSE_ENC_REQ]))
    assert encryption.receive(LlId.CONTROL, wire, duplicate=False) == bytes(
        [Opcode.LL_PAUSE_ENC_REQ]
    )
    encryption.rx_enabled = False
    encryption.state = State.PAUSE_ACK
    assert encryption.receive(LlId.CONTROL, wire, duplicate=True) == bytes(
        [Opcode.LL_PAUSE_ENC_REQ]
    )
    assert encryption.cipher.rx_counter == 1


def test_pre_encryption_plaintext_cannot_acknowledge_encrypted_data(connection):
    encryption = connection.encryption
    plain = bytes([Opcode.LL_VERSION_IND])
    assert encryption.receive(LlId.CONTROL, plain, duplicate=False) == plain
    encryption.cipher = PacketCipher(KEY, IV, central=False)
    encryption.rx_enabled = True
    assert encryption.receive(LlId.CONTROL, plain, duplicate=True) is None
    assert connection.closed


@pytest.mark.asyncio
async def test_paused_user_queue_sends_only_empty_packets_without_md(connection):
    connection.encryption.state = State.KEY
    connection.enqueue_acl(False, b'must wait for encryption')
    await connection.send(0, 100)
    packet = connection.radio.sent[-1][2]
    assert packet[PDU_HEADER_SIZE:] == b'' and not packet[0] & PDU_DATA_MD_MASK
    assert connection.queue[0].payload == b'must wait for encryption'


@pytest.mark.asyncio
async def test_missing_refresh_key_transmits_rejection_before_disconnect(connection):
    connection.reported = True
    encryption = connection.encryption
    encryption.refresh = True
    encryption.state = State.KEY
    encryption.supply_key(None)
    assert encryption.busy and not connection.closed
    connection.enqueue_acl(False, b'must not escape the failed refresh')
    await connection.send(0, 100)
    assert connection.radio.sent[-1][2][PDU_HEADER_SIZE:] == bytes(
        [
            Opcode.LL_REJECT_IND,
            hci.HCI_ErrorCode.PIN_OR_KEY_MISSING_ERROR,
        ]
    )
    assert connection.closed
