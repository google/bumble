# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Single LE ACL link, scheduled in integer PHY microseconds.

This module never connects Hosts directly: every data/control PDU crosses the PHY.
It implements CSA #1/#2, instant-based updates and per-direction encryption.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from bumble.hci import HCI_ErrorCode as ErrorCode
from bumble.hci import Role
from bumble.ll import (
    LL_CONN_CRC_ERROR_LIMIT,
    LL_CONN_ESTABLISHMENT_EVENTS,
    LL_CONN_INTERVAL_UNIT_US,
    LL_DATA_CHANNEL_COUNT,
    LL_EVENT_COUNTER_MASK,
    LL_IFS_US,
    LL_SUPERVISION_TIMEOUT_UNIT_US,
    PDU_CONTROL_PAYLOAD_SIZE_INITIAL_MAX,
    PDU_CONTROL_TERMINATE_SIZE,
    PDU_DATA_LLID_MASK,
    PDU_DATA_MD_MASK,
    PDU_DATA_MIC_SIZE,
    PDU_DATA_NESN_MASK,
    PDU_DATA_PAYLOAD_TIME_CODED_MIN_US,
    PDU_DATA_SN_MASK,
    PDU_HEADER_SIZE,
    ControlPdu,
    LlId,
)
from bumble.radio_controller.radio import (
    PHY_CODED_S8_FACTOR,
    RADIO_CONN_EVENT_GUARD_US,
    RADIO_CONN_RX_WINDOW_CODED_US,
    RADIO_CONN_RX_WINDOW_UNCODED_US,
    RADIO_HCI_ACL_BUFFER_SIZE,
    RADIO_RSSI_NOT_AVAILABLE,
    RADIO_TX_POWER_MAX_DBM,
    RADIO_TX_POWER_MIN_DBM,
    Phy,
    Radio,
    channel_selection_2,
    window_widening,
)
from bumble.radio_controller.radio_control import ControlProcedures
from bumble.radio_controller.radio_encryption import Encryption
from bumble.radio_controller.radio_parameters import Parameters as Parameters

if TYPE_CHECKING:
    from bumble.hci import Address
    from bumble.radio_controller.radio_link import RadioLink


Opcode = ControlPdu.Opcode

# Core Vol 6, Part B, 5.1: supported PDUs restricted to one sender role.
LL_CONTROL_PDU_SENDER_ROLES: dict[int, Role] = {
    Opcode.LL_CONNECTION_UPDATE_IND: Role.CENTRAL,
    Opcode.LL_CHANNEL_MAP_IND: Role.CENTRAL,
    Opcode.LL_ENC_REQ: Role.CENTRAL,
    Opcode.LL_FEATURE_REQ: Role.CENTRAL,
    Opcode.LL_PAUSE_ENC_REQ: Role.CENTRAL,
    Opcode.LL_PHY_UPDATE_IND: Role.CENTRAL,
    Opcode.LL_ENC_RSP: Role.PERIPHERAL,
    Opcode.LL_START_ENC_REQ: Role.PERIPHERAL,
    Opcode.LL_PERIPHERAL_FEATURE_REQ: Role.PERIPHERAL,
    Opcode.LL_PHY_RSP: Role.PERIPHERAL,
    Opcode.LL_MIN_USED_CHANNELS_IND: Role.PERIPHERAL,
}


@dataclass(frozen=True)
class Outbound:
    llid: int
    payload: bytes
    host_packet: bool = False


class Connection:
    def __init__(
        self,
        link: RadioLink,
        parameters: Parameters,
        peer: Address,
        role: int,
        connect_end_us: int,
        csa2: bool = False,
        self_address: Address | None = None,
        window_delay_us: int = LL_CONN_INTERVAL_UNIT_US,
        phy: Phy = Phy.LE_1M,
    ):
        self.link = link
        self.handle = link.listener.allocate_connection_handle()
        self.radio: Radio = link.radio
        self.parameters: Parameters = parameters
        self.peer = peer
        self.self_address = self_address
        self.role: int = role
        self.csa2 = csa2
        self.anchor_us: int = (
            connect_end_us
            + window_delay_us
            + parameters.window_offset * LL_CONN_INTERVAL_UNIT_US
        )
        self.event_counter: int = 0
        self.unmapped_channel = 0
        self.established = False
        self.reported = False
        self.last_rx_us: int = connect_end_us
        self.supervision_restart_us: int = connect_end_us
        self.last_event_us: int = connect_end_us
        self.tx_sn = 0
        self.rx_nesn = 0
        self.pending: Outbound | None = None
        self.sent_pending = False
        self.pending_wire: bytes | None = None
        self.queue: deque[Outbound] = deque()
        self.tx_start_pending = False
        self.remote_termination: int | None = None
        self.termination_deadline_us = 0
        self.closed: bool = False
        self.retries = 0
        self.advertising_handle: int | None = None
        self.advertising_events = 0
        self.tx_phy: Phy = phy
        self.rx_phy: Phy = phy
        self.peer_features: int | None = None
        self.rssi: int = RADIO_RSSI_NOT_AVAILABLE
        self.tx_coding: int = PHY_CODED_S8_FACTOR
        self.update_window: bool = False
        self.controls: ControlProcedures = ControlProcedures(self)
        self.encryption: Encryption = Encryption(self)
        self.link.trace(
            f"LL CREATED role={role} aa={parameters.access_address:08x} "
            f"anchor={self.anchor_us} "
            f"interval={parameters.interval * LL_CONN_INTERVAL_UNIT_US}"
        )

    def enqueue_acl(self, continuation: bool, payload: bytes) -> None:
        if len(payload) > RADIO_HCI_ACL_BUFFER_SIZE:
            raise ValueError(
                f"ACL payload exceeds the {RADIO_HCI_ACL_BUFFER_SIZE}-octet HCI buffer"
            )
        if not payload:
            # An empty HCI start retains its boundary, never LLID=2/Length=0 on air.
            self.tx_start_pending |= not continuation
            self.link.listener.on_acl_completed(self)
            return
        continuation = continuation and not self.tx_start_pending
        self.tx_start_pending = False
        self.queue.append(
            Outbound(LlId.CONTINUATION if continuation else LlId.START, payload, True)
        )

    def terminate(self, reason: int) -> None:
        if not self.termination_deadline_us:
            self.termination_deadline_us = (
                self.radio.now_us
                + self.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
            )
        self.enqueue_control(bytes([Opcode.LL_TERMINATE_IND, reason]), priority=True)

    def enqueue_control(self, payload: bytes, *, priority: bool = False) -> None:
        item = Outbound(LlId.CONTROL, payload)
        if priority:
            self.queue.appendleft(item)
        else:
            self.queue.append(item)

    def complete(self, reason: int) -> None:
        if self.closed:
            return
        self.controls.finish_features(reason)
        self.controls.finish_version(None)
        self.closed = True
        self.link.trace(f"LL DISCONNECTED reason=0x{reason:02x} retries={self.retries}")
        self.link.connections.pop(self.handle, None)
        self.link.listener.on_disconnected(self, reason)

    def report_created(self) -> None:
        if not self.reported:
            self.reported = True
            self.link.listener.on_connected(self)

    def establish(self) -> None:
        if self.established:
            return
        self.established = True
        self.link.trace("LL ESTABLISHED")
        self.report_created()
        self.controls.data_length.start_if_needed()

    def control(self, payload: bytes) -> None:
        if not payload:
            return
        opcode = payload[0]
        if LL_CONTROL_PDU_SENDER_ROLES.get(opcode) == self.role:
            self.enqueue_control(bytes([Opcode.LL_UNKNOWN_RSP, opcode]), priority=True)
            return
        if self.encryption.control(payload):
            return
        if self.controls.control(payload):
            return
        if (
            opcode == Opcode.LL_TERMINATE_IND
            and len(payload) == PDU_CONTROL_TERMINATE_SIZE
        ):
            self.remote_termination = payload[1]
        elif opcode not in (
            Opcode.LL_UNKNOWN_RSP,
            Opcode.LL_FEATURE_RSP,
            Opcode.LL_VERSION_IND,
        ):
            self.enqueue_control(bytes([Opcode.LL_UNKNOWN_RSP, opcode]), priority=True)

    def accept(self, pdu: bytes, valid_crc: bool) -> None:
        if (
            not valid_crc
            or len(pdu) < PDU_HEADER_SIZE
            or pdu[1] != len(pdu) - PDU_HEADER_SIZE
        ):
            return
        header, _ = pdu[:PDU_HEADER_SIZE]
        payload = self.encryption.receive(
            header,
            pdu[PDU_HEADER_SIZE:],
            duplicate=bool(header & PDU_DATA_SN_MASK) != self.rx_nesn,
        )
        if payload is None or len(payload) > (
            PDU_CONTROL_PAYLOAD_SIZE_INITIAL_MAX
            if header & PDU_DATA_LLID_MASK == LlId.CONTROL
            else self.controls.data_length.local.rx_octets
        ):
            return
        self.last_rx_us = self.radio.now_us
        self.establish()
        if (
            self.pending is not None
            and self.sent_pending
            and bool(header & PDU_DATA_NESN_MASK) != self.tx_sn
        ):
            acknowledged = self.pending
            self.pending = None
            self.sent_pending = False
            self.pending_wire = None
            self.tx_sn ^= 1
            if acknowledged.llid == LlId.CONTROL:
                self.controls.acknowledge(acknowledged.payload)
                self.encryption.acknowledged(acknowledged.payload)
            if acknowledged.host_packet:
                self.link.listener.on_acl_completed(self)
            if acknowledged.llid == LlId.CONTROL and acknowledged.payload[:1] == bytes(
                [Opcode.LL_TERMINATE_IND]
            ):
                self.complete(ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR)
                return
        if bool(header & PDU_DATA_SN_MASK) != self.rx_nesn:
            self.link.trace("LL RX DUPLICATE")
            return
        self.rx_nesn ^= 1
        llid = header & PDU_DATA_LLID_MASK
        # Reserved LLID participates in ARQ, but has no payload interpretation.
        if llid == LlId.CONTROL:
            self.control(payload)
        elif llid != LlId.RESERVED and payload:
            self.link.listener.on_acl_received(self, llid == LlId.CONTINUATION, payload)

    def _next_outbound(self) -> Outbound:
        if self.encryption.busy:
            return next(
                (
                    item
                    for item in self.queue
                    if self.encryption.can_send(item.llid, item.payload)
                ),
                Outbound(LlId.CONTINUATION, b''),
            )
        return self.queue[0] if self.queue else Outbound(LlId.CONTINUATION, b'')

    async def send(self, channel: int, start_us: int) -> bool:
        if self.pending is None:
            self.pending = self._next_outbound()
            if self.pending in self.queue:
                self.queue.remove(self.pending)
            if self.pending.llid != LlId.CONTROL:
                limit = self.controls.data_length.tx_payload_limit()
                if len(self.pending.payload) > limit:
                    packet = self.pending
                    self.queue.appendleft(
                        Outbound(
                            LlId.CONTINUATION,
                            packet.payload[limit:],
                            packet.host_packet,
                        )
                    )
                    self.pending = replace(
                        packet, payload=packet.payload[:limit], host_packet=False
                    )
        elif self.sent_pending:
            self.retries += 1
            self.link.trace(f"LL RETRANSMIT sn={self.tx_sn}")
        item = self.pending
        if item.llid == LlId.CONTROL and not self.sent_pending:
            item = Outbound(LlId.CONTROL, self.controls.prepare(item.payload))
            self.pending = item
        more = (
            any(
                self.encryption.can_send(entry.llid, entry.payload)
                for entry in self.queue
            )
            if self.encryption.busy
            else bool(self.queue)
        )
        header = (
            item.llid
            | (PDU_DATA_NESN_MASK if self.rx_nesn else 0)
            | (PDU_DATA_SN_MASK if self.tx_sn else 0)
            | (PDU_DATA_MD_MASK if more else 0)
        )
        if self.pending_wire is None:
            self.pending_wire = item.payload
            if self.encryption.tx_enabled:
                assert self.encryption.cipher is not None
                self.pending_wire = self.encryption.cipher.encrypt(
                    header, self.pending_wire
                )
        pdu = bytes([header, len(self.pending_wire)]) + self.pending_wire
        self.link.trace(
            f"LL TX event={self.event_counter} ch={channel} pdu={pdu.hex()}"
        )
        await self.radio.transmit(
            channel,
            pdu,
            start_us=start_us,
            access_address=self.parameters.access_address,
            crc_init=self.parameters.crc_init,
            phy=self.tx_phy,
            coding=self.tx_coding,
        )
        if item.llid == LlId.CONTROL and not self.sent_pending:
            self.controls.sent(item.payload)
        self.sent_pending = True
        if item.llid == LlId.CONTROL:
            self.encryption.sent(item.payload)
        return bool(header & PDU_DATA_MD_MASK)

    async def receive(
        self, channel: int, until_us: int, *, start_us: int | None = None
    ):
        # End address search at the next timer; an already found frame is nonpreemptive.
        packet = await self.radio.receive(
            channel,
            min(until_us, self.next_deadline_us),
            start_us=start_us,
            access_address=self.parameters.access_address,
            crc_init=self.parameters.crc_init,
            accept_bad_crc=True,
            phy=self.rx_phy,
        )
        if packet is not None:
            self.link.trace(
                f"LL RX event={self.event_counter} ch={channel} "
                f"crc={int(packet.valid_crc)} pdu={packet.pdu.hex()}"
            )
            # Connection establishment is a physical reception, independent of CRC.
            self.establish()
            if packet.valid_crc:
                self.rssi = max(
                    RADIO_TX_POWER_MIN_DBM,
                    min(RADIO_TX_POWER_MAX_DBM, round(packet.rssi)),
                )
            within_time = len(packet.pdu) >= PDU_HEADER_SIZE and (
                packet.pdu[0] & PDU_DATA_LLID_MASK == LlId.CONTROL
                or packet.end_us - packet.start_us
                <= max(
                    self.controls.data_length.local.rx_time,
                    (
                        PDU_DATA_PAYLOAD_TIME_CODED_MIN_US
                        if self.rx_phy == Phy.LE_CODED
                        else 0
                    ),
                )
            )
            self.accept(packet.pdu, packet.valid_crc and within_time)
        return packet

    def next_exchange_us(self, *, max_rx: bool = True) -> int:
        item = self.pending or self._next_outbound()
        lengths = self.controls.data_length
        tx_length = (
            len(item.payload)
            if self.pending or item.llid == LlId.CONTROL
            else min(len(item.payload), lengths.tx_payload_limit())
        )
        effective = lengths.effective()
        tx_length += (
            PDU_DATA_MIC_SIZE if self.encryption.tx_enabled and tx_length else 0
        )
        rx_length = (
            max(
                PDU_CONTROL_PAYLOAD_SIZE_INITIAL_MAX,
                lengths.packet_limit(
                    self.rx_phy,
                    effective.rx_time,
                    effective.rx_octets,
                    encrypted=self.encryption.rx_enabled,
                ),
            )
            if max_rx
            else 0
        )
        rx_length += (
            PDU_DATA_MIC_SIZE if self.encryption.rx_enabled and rx_length else 0
        )
        return (
            self.tx_phy.airtime_us(PDU_HEADER_SIZE + tx_length, self.tx_coding)
            + self.rx_phy.airtime_us(PDU_HEADER_SIZE + rx_length)
            + 2 * LL_IFS_US
        )

    @property
    def response_window_us(self) -> int:
        return (
            RADIO_CONN_RX_WINDOW_CODED_US
            if self.rx_phy == Phy.LE_CODED
            else RADIO_CONN_RX_WINDOW_UNCODED_US
        )

    @property
    def receive_window_us(self) -> int:
        return (
            self.parameters.window_size * LL_CONN_INTERVAL_UNIT_US
            if not self.established or self.update_window
            else self.response_window_us
        )

    def skip_missed_events(self) -> None:
        """A radio conflict advances counters and Instants, never transmits late."""
        while not self.closed:
            latest = self.anchor_us
            if self.role == Role.PERIPHERAL:
                latest += self.receive_window_us + window_widening(
                    self.anchor_us - self.last_rx_us, self.parameters.sca
                )
            if latest > self.radio.now_us:
                break
            update = self.controls.pending
            self.controls.apply()
            if self.closed:
                return
            if update is not self.controls.pending:
                # An Instant can move or widen this event's receive window.
                continue
            self.unmapped_channel = (
                self.unmapped_channel + self.parameters.hop
            ) % LL_DATA_CHANNEL_COUNT
            self.anchor_us += self.parameters.interval * LL_CONN_INTERVAL_UNIT_US
            self.event_counter = (self.event_counter + 1) & LL_EVENT_COUNTER_MASK
            self.link.trace(
                f'LL MISSED handle={self.handle} next_event={self.event_counter}'
            )

    async def advance_to_us(
        self, target_us: int, *, radio_until_us: int | None = None
    ) -> int:
        self.skip_missed_events()
        if self.check_timeout():
            return self.radio.now_us
        deadline = self.next_deadline_us
        if target_us < self.event_start_us or self.event_start_us >= deadline:
            await self.radio.advance_to_us(min(target_us, deadline))
            self.check_timeout()
            return self.radio.now_us
        self.controls.apply()
        if self.closed:
            return self.radio.now_us
        self.unmapped_channel = (
            self.unmapped_channel + self.parameters.hop
        ) % LL_DATA_CHANNEL_COUNT
        enabled = [
            index
            for index in range(LL_DATA_CHANNEL_COUNT)
            if self.parameters.channel_map & (1 << index)
        ]
        channel = (
            channel_selection_2(
                self.event_counter,
                self.parameters.access_address,
                self.parameters.channel_map,
            )
            if self.csa2
            else (
                self.unmapped_channel
                if self.unmapped_channel in enabled
                else enabled[self.unmapped_channel % len(enabled)]
            )
        )
        # Leave room for the next connection event. MD may extend this event,
        # but never beyond its connection interval.
        event_end_us = (
            self.anchor_us
            + self.parameters.interval * LL_CONN_INTERVAL_UNIT_US
            - RADIO_CONN_EVENT_GUARD_US
        )
        if radio_until_us is not None:
            event_end_us = min(event_end_us, radio_until_us)
        if max(self.radio.now_us + 1, self.event_start_us) + self.next_exchange_us(
            max_rx=False
        ) >= event_end_us or (
            self.role == Role.CENTRAL
            and self.radio.earliest_start_us(channel, self.tx_phy, transmit=True)
            > self.anchor_us
        ):
            # Admit known TX plus an empty ACK. An actual received frame is
            # nonpreemptive; its size must not be guessed from the maximum DLE.
            self.anchor_us += self.parameters.interval * LL_CONN_INTERVAL_UNIT_US
            self.event_counter = (self.event_counter + 1) & LL_EVENT_COUNTER_MASK
            return self.radio.now_us
        self.last_event_us = self.radio.now_us
        if self.role == Role.CENTRAL:
            start_us = self.anchor_us
            while not self.closed:
                more = await self.send(channel, start_us)
                if self.remote_termination is not None:
                    self.complete(self.remote_termination)
                    break
                packet = await self.receive(
                    channel,
                    self.radio.now_us + LL_IFS_US + self.response_window_us,
                )
                if packet is None or not packet.valid_crc or self.closed:
                    break
                start_us = packet.end_us + LL_IFS_US
                if (
                    not (more or packet.pdu[0] & PDU_DATA_MD_MASK)
                    or start_us + self.next_exchange_us() >= event_end_us
                ):
                    break
        else:
            widening = window_widening(
                self.anchor_us - self.last_rx_us, self.parameters.sca
            )
            packet = await self.receive(
                channel,
                self.anchor_us
                + self.receive_window_us
                + widening
                + self.rx_phy.address_us
                - 1,
                start_us=max(self.radio.now_us + 1, self.anchor_us - widening),
            )
            if packet is not None:
                self.update_window = False
                self.anchor_us = packet.start_us
            crc_errors = 0
            while packet is not None and not self.closed:
                crc_errors = 0 if packet.valid_crc else crc_errors + 1
                if crc_errors == LL_CONN_CRC_ERROR_LIMIT:
                    break
                more = await self.send(channel, packet.end_us + LL_IFS_US)
                if self.remote_termination is not None:
                    self.complete(self.remote_termination)
                    break
                if (
                    packet.valid_crc and not (more or packet.pdu[0] & PDU_DATA_MD_MASK)
                ) or self.radio.now_us + self.next_exchange_us() >= event_end_us:
                    break
                packet = await self.receive(
                    channel,
                    self.radio.now_us + LL_IFS_US + self.response_window_us,
                )
        self.anchor_us += self.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        self.event_counter = (self.event_counter + 1) & LL_EVENT_COUNTER_MASK
        self.check_timeout()
        return self.radio.now_us

    @property
    def supervision_deadline_us(self) -> int:
        timeout = (
            self.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
            if self.established
            else LL_CONN_ESTABLISHMENT_EVENTS
            * self.parameters.interval
            * LL_CONN_INTERVAL_UNIT_US
        )
        return max(self.last_rx_us, self.supervision_restart_us) + timeout

    @property
    def next_deadline_us(self) -> int:
        deadline = self.supervision_deadline_us
        return min(
            deadline,
            self.termination_deadline_us or deadline,
            self.controls.next_deadline_us or deadline,
            self.encryption.next_deadline_us or deadline,
        )

    def check_timeout(self) -> bool:
        if (
            self.closed
            or self.controls.check_timeout()
            or self.encryption.check_timeout()
        ):
            return True
        if (
            self.termination_deadline_us
            and self.radio.now_us >= self.termination_deadline_us
        ):
            self.complete(ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR)
        elif self.radio.now_us >= self.supervision_deadline_us:
            self.complete(
                ErrorCode.CONNECTION_TIMEOUT_ERROR
                if self.established
                else ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR
            )
        return self.closed

    @property
    def next_operation_us(self) -> int:
        return min(self.event_start_us, self.next_deadline_us)

    @property
    def event_start_us(self) -> int:
        start = self.anchor_us
        if self.role == Role.PERIPHERAL:
            start -= window_widening(
                self.anchor_us - self.last_rx_us, self.parameters.sca
            )
        return start
