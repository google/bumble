# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL data-length negotiation and per-PHY transmission limits, Core 4.5.10/5.1.9."""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from bumble.hci import HCI_ErrorCode as ErrorCode
from bumble.hci import LeFeatureMask, Role
from bumble.ll import (
    LL_CONN_INTERVAL_UNIT_US,
    LL_IFS_US,
    LL_RESPONSE_TIMEOUT_US,
    PDU_CONTROL_OPCODE_SIZE,
    PDU_CONTROL_REJECT_EXT_SIZE,
    PDU_CONTROL_UNKNOWN_RSP_SIZE,
    PDU_DATA_EMPTY_TIME_CODED_S8_US,
    PDU_DATA_MIC_SIZE,
    PDU_DATA_OCTET_TIME_CODED_S8_US,
    PDU_DATA_PAYLOAD_SIZE_MAX,
    PDU_DATA_PAYLOAD_SIZE_MIN,
    PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    PDU_DATA_PAYLOAD_TIME_CODED_MIN_US,
    PDU_DATA_PAYLOAD_TIME_MIN_US,
    PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US,
    PDU_HEADER_SIZE,
    ControlPdu,
)
from bumble.radio_controller.radio import PHY_CODED_S8_FACTOR, Phy

if TYPE_CHECKING:
    from bumble.radio_controller.radio_connection import Connection

Opcode = ControlPdu.Opcode
LENGTH_PARAMETERS = struct.Struct('<HHHH')


def valid_data_length(octets: int, time_us: int) -> bool:
    return (
        PDU_DATA_PAYLOAD_SIZE_MIN <= octets <= PDU_DATA_PAYLOAD_SIZE_MAX
        and PDU_DATA_PAYLOAD_TIME_MIN_US
        <= time_us
        <= PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
    )


@dataclass(frozen=True)
class DataLengths:
    rx_octets: int
    rx_time: int
    tx_octets: int
    tx_time: int

    def encode(self) -> bytes:
        return LENGTH_PARAMETERS.pack(
            self.rx_octets, self.rx_time, self.tx_octets, self.tx_time
        )


class DataLengthProcedure:
    def __init__(self, connection: Connection):
        self.connection = connection
        initial_time = (
            PDU_DATA_PAYLOAD_TIME_CODED_MIN_US
            if connection.tx_phy == Phy.LE_CODED
            else PDU_DATA_PAYLOAD_TIME_MIN_US
        )
        self.local = DataLengths(
            PDU_DATA_PAYLOAD_SIZE_MIN,
            initial_time,
            connection.link.default_tx_octets,
            max(initial_time, connection.link.default_tx_time),
        )
        self.remote = DataLengths(
            PDU_DATA_PAYLOAD_SIZE_MIN,
            initial_time,
            PDU_DATA_PAYLOAD_SIZE_MIN,
            initial_time,
        )
        self.pending = False
        self.deadline_us = 0
        self.reported = self.effective()

    def effective(self, *, tx_phy=None, rx_phy=None, interval_us=None) -> DataLengths:
        connection = self.connection
        tx_phy = connection.tx_phy if tx_phy is None else tx_phy
        rx_phy = connection.rx_phy if rx_phy is None else rx_phy
        interval_us = (
            connection.parameters.interval * LL_CONN_INTERVAL_UNIT_US
            if interval_us is None
            else interval_us
        )
        rx_octets = min(self.local.rx_octets, self.remote.tx_octets)
        tx_octets = min(self.local.tx_octets, self.remote.rx_octets)
        rx_time = min(self.local.rx_time, self.remote.tx_time)
        tx_time = min(self.local.tx_time, self.remote.rx_time)
        if rx_phy == Phy.LE_CODED:
            rx_time = max(PDU_DATA_PAYLOAD_TIME_CODED_MIN_US, rx_time)
        if tx_phy == Phy.LE_CODED:
            required = 2 * LL_IFS_US + min(
                rx_time,
                rx_octets * PDU_DATA_OCTET_TIME_CODED_S8_US
                + PDU_DATA_EMPTY_TIME_CODED_S8_US,
            )
            tx_time = max(
                PDU_DATA_PAYLOAD_TIME_CODED_MIN_US, min(tx_time, interval_us - required)
            )
        return DataLengths(rx_octets, rx_time, tx_octets, tx_time)

    def refresh(self) -> None:
        effective = self.effective()
        if effective != self.reported:
            self.reported = effective
            self.connection.link.listener.on_data_length_changed(self.connection)

    def packet_limit(
        self,
        phy: Phy,
        time_us: int,
        octets: int,
        coding=PHY_CODED_S8_FACTOR,
        *,
        encrypted=False,
    ) -> int:
        return next(
            size
            for size in range(octets, -1, -1)
            if phy.airtime_us(
                PDU_HEADER_SIZE
                + size
                + (PDU_DATA_MIC_SIZE if encrypted and size else 0),
                coding,
            )
            <= time_us
        )

    def tx_payload_limit(self) -> int:
        connection, controls = self.connection, self.connection.controls
        tx_phys = {connection.tx_phy}
        rx_phy = connection.rx_phy
        interval = connection.parameters.interval
        if controls.requested_interval_min:
            interval = min(interval, controls.requested_interval_min)
        if controls.pending:
            update = controls.pending
            if update.parameters:
                interval = min(interval, update.parameters.interval)
            tx, rx = (
                (update.central_tx_phy, update.peripheral_tx_phy)
                if connection.role == Role.CENTRAL
                else (update.peripheral_tx_phy, update.central_tx_phy)
            )
            # PHY packet-time restrictions start at the local control transmission.
            if update.local and not controls.transmitted:
                tx = rx = 0
            if tx:
                tx_phys.add(Phy(tx))
            if rx:
                rx_phy = Phy(rx)
        elif (
            controls.phy_request
            and controls.transmitted
            and connection.role == Role.PERIPHERAL
        ):
            tx_phys.update(phy for phy in Phy if controls.tx_phys & (1 << (phy - 1)))
        limits = []
        for phy in tx_phys:
            effective = self.effective(
                tx_phy=phy,
                rx_phy=rx_phy,
                interval_us=interval * LL_CONN_INTERVAL_UNIT_US,
            )
            limits.append(
                self.packet_limit(
                    phy,
                    effective.tx_time,
                    effective.tx_octets,
                    connection.tx_coding,
                    encrypted=connection.encryption.tx_enabled,
                )
            )
        return min(limits)

    def enqueue(self, opcode: int) -> None:
        parameters = self.local
        features = self.connection.peer_features
        if features is not None and not features & LeFeatureMask.LE_CODED_PHY:
            parameters = replace(
                parameters,
                rx_time=min(parameters.rx_time, PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US),
                tx_time=min(parameters.tx_time, PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US),
            )
        self.connection.enqueue_control(
            bytes([opcode]) + parameters.encode(), priority=True
        )

    def request(self, octets: int, time_us: int) -> None:
        self.local = DataLengths(
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
            octets,
            time_us,
        )
        self.pending = True
        self.deadline_us = self.connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
        self.enqueue(Opcode.LL_LENGTH_REQ)

    def start_if_needed(self) -> None:
        initial_time = (
            PDU_DATA_PAYLOAD_TIME_CODED_MIN_US
            if self.connection.tx_phy == Phy.LE_CODED
            else PDU_DATA_PAYLOAD_TIME_MIN_US
        )
        if (
            self.local.tx_octets != PDU_DATA_PAYLOAD_SIZE_MIN
            or self.local.tx_time != initial_time
        ):
            self.request(self.local.tx_octets, self.local.tx_time)

    def control(self, payload: bytes) -> bool:
        opcode = payload[0]
        if opcode in (Opcode.LL_LENGTH_REQ, Opcode.LL_LENGTH_RSP):
            if len(payload) != PDU_CONTROL_OPCODE_SIZE + LENGTH_PARAMETERS.size:
                # Use the common LL_UNKNOWN_RSP path for an invalid PDU length.
                return False
            rx, rx_time, tx, tx_time = LENGTH_PARAMETERS.unpack(
                payload[PDU_CONTROL_OPCODE_SIZE:]
            )
            if not valid_data_length(rx, rx_time) or not valid_data_length(tx, tx_time):
                self.connection.controls.reject(
                    opcode, ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR
                )
                return True
            if opcode == Opcode.LL_LENGTH_RSP and not self.pending:
                return True
            self.remote = DataLengths(rx, rx_time, tx, tx_time)
            if opcode == Opcode.LL_LENGTH_REQ:
                self.local = replace(
                    self.local,
                    rx_octets=PDU_DATA_PAYLOAD_SIZE_MAX,
                    rx_time=PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
                )
                self.enqueue(Opcode.LL_LENGTH_RSP)
            else:
                self.pending = False
                self.deadline_us = 0
            self.refresh()
            return True
        if (
            opcode == Opcode.LL_UNKNOWN_RSP
            and len(payload) == PDU_CONTROL_UNKNOWN_RSP_SIZE
            and payload[1] == Opcode.LL_LENGTH_REQ
        ) or (
            opcode == Opcode.LL_REJECT_EXT_IND
            and len(payload) == PDU_CONTROL_REJECT_EXT_SIZE
            and payload[1] == Opcode.LL_LENGTH_REQ
        ):
            if self.pending:
                self.pending = False
                self.deadline_us = 0
                initial_time = (
                    PDU_DATA_PAYLOAD_TIME_CODED_MIN_US
                    if self.connection.tx_phy == Phy.LE_CODED
                    else PDU_DATA_PAYLOAD_TIME_MIN_US
                )
                self.local = self.remote = DataLengths(
                    PDU_DATA_PAYLOAD_SIZE_MIN,
                    initial_time,
                    PDU_DATA_PAYLOAD_SIZE_MIN,
                    initial_time,
                )
                self.refresh()
            return True
        return False

    def check_timeout(self) -> bool:
        if self.deadline_us and self.connection.radio.now_us >= self.deadline_us:
            self.connection.complete(ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR)
            return True
        return False
