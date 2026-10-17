# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL control procedures and event-counter instants.

Wire procedures own pending state, not the radio scheduler. Changes are applied
at the start of a connection event before channel/PHY selection.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from bumble.hci import HCI_ErrorCode as ErrorCode
from bumble.hci import LeFeatureMask, Role
from bumble.ll import (
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_INTERVAL_UNIT_US,
    LL_CONN_PREFERRED_PERIODICITY_MIN,
    LL_CONN_WINDOW_SIZE_MAX,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_COUNT_MIN,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    LL_INSTANT_MIN_LISTENING_EVENTS,
    LL_RESPONSE_TIMEOUT_US,
    PDU_CONTROL_CHANNEL_MAP_SIZE,
    PDU_CONTROL_CONN_PARAM_OFFSET_COUNT,
    PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED,
    PDU_CONTROL_FEATURE_SET_SIZE,
    PDU_CONTROL_FEATURE_SIZE,
    PDU_CONTROL_INSTANT_SIZE,
    PDU_CONTROL_MIN_USED_CHANNELS_SIZE,
    PDU_CONTROL_OPCODE_SIZE,
    PDU_CONTROL_PHY_REQ_SIZE,
    PDU_CONTROL_PHY_UPDATE_SIZE,
    PDU_CONTROL_REJECT_EXT_SIZE,
    PDU_CONTROL_REJECT_SIZE,
    PDU_CONTROL_UNKNOWN_RSP_SIZE,
    PDU_CONTROL_VERSION_SIZE,
    ControlPdu,
)
from bumble.radio_controller.radio import (
    PHY_OCTET_MASK,
    RADIO_INSTANT_PAST_THRESHOLD,
    RADIO_SUPPORTED_PHY_MASK,
    Phy,
)
from bumble.radio_controller.radio_data_length import DataLengthProcedure
from bumble.radio_controller.radio_parameters import valid_channel_map, valid_timing

if TYPE_CHECKING:
    from bumble.radio_controller.radio_connection import Connection
    from bumble.radio_controller.radio_parameters import Parameters

UPDATE = struct.Struct('<BHHHHH')
PARAM_REQUEST = struct.Struct('<HHHHBH6H')
PROCEDURE_COLLISION = (
    ErrorCode.LMP_ERROR_TRANSACTION_COLLISION_OR_LL_PROCEDURE_COLLISION_ERROR
)
Opcode = ControlPdu.Opcode


def valid_minimum_channels(phys: int, minimum: int) -> bool:
    return (
        bool(phys)
        and not phys & ~RADIO_SUPPORTED_PHY_MASK
        and LL_DATA_CHANNEL_COUNT_MIN <= minimum <= LL_DATA_CHANNEL_COUNT
    )


def preferred_interval(minimum: int, maximum: int, periodicity: int) -> int:
    """Prefer a periodicity multiple only when it exists in the accepted range."""
    if periodicity:
        candidate = (minimum + periodicity - 1) // periodicity * periodicity
        if candidate <= maximum:
            return candidate
    return minimum


def preferred_periodicity(minimum: int, maximum: int, preference: int = 0) -> int:
    """Encode a valid preference for an interval range, or zero for a fixed interval."""
    if minimum == maximum:
        return 0
    return (
        preference if 0 < preference <= maximum else LL_CONN_PREFERRED_PERIODICITY_MIN
    )


def anchor_offset(
    reference: tuple[int, int], instant: int, old_interval: int, interval: int
) -> int:
    """Express a preferred reference anchor relative to the update Instant."""
    counter, offset = reference
    distance = (instant - counter) & LL_EVENT_COUNTER_MASK
    return (offset - distance * old_interval) % interval


@dataclass(frozen=True)
class InstantUpdate:
    instant: int
    parameters: Parameters | None = None
    channel_map: int | None = None
    central_tx_phy: int = 0
    peripheral_tx_phy: int = 0
    local: bool = False
    anchor_reference: tuple[int, int] | None = None
    notify: bool | None = None


class ControlProcedures:
    def __init__(self, connection: Connection):
        self.connection = connection
        self.pending: InstantUpdate | None = None
        self.remote_parameters: bytes | None = None
        self.parameter_request = False
        # UNKNOWN_RSP supplies procedure knowledge, not an entire feature set.
        self.parameter_request_unsupported = False
        self.phy_request = False
        # Accepted HCI Set PHY requires completion even when no PHY changes.
        self.phy_request_local = False
        # A Peripheral defers the Central's colliding request until local rejection.
        self.remote_phy_request: bytes | None = None
        self.tx_phys = RADIO_SUPPORTED_PHY_MASK
        self.rx_phys = RADIO_SUPPORTED_PHY_MASK
        self.deadline_us = 0
        self.transmitted = False
        self.acknowledged = False
        self.data_length = DataLengthProcedure(connection)
        self.requested_interval_min = 0
        self.requested_parameters: tuple[int, int, int, int] | None = None
        self.feature_request = False
        self.feature_deadline_us = 0
        # Includes a local indication queued but not yet transmitted during a collision.
        self.version_sent = False
        self.peer_version: tuple[int, int, int] | None = None
        self.version_request = False
        self.version_deadline_us = 0
        self.host_channel_map = connection.parameters.channel_map
        self.peer_minimum_channel_phys = 0
        self.peer_minimum_used_channels = LL_DATA_CHANNEL_COUNT_MIN

    @property
    def busy(self) -> bool:
        return bool(
            self.pending
            or self.remote_parameters
            or self.parameter_request
            or self.phy_request
            or self.data_length.pending
            or self.feature_request
        )

    @property
    def supports_parameter_request(self) -> bool:
        features = self.connection.peer_features
        return not self.parameter_request_unsupported and (
            features is None
            or bool(features & LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE)
        )

    @property
    def next_deadline_us(self) -> int:
        deadlines = [
            deadline
            for deadline in (
                self.deadline_us,
                self.data_length.deadline_us,
                self.feature_deadline_us,
                self.version_deadline_us,
            )
            if deadline
        ]
        return min(deadlines) if deadlines else 0

    def enqueue(self, payload: bytes) -> None:
        self.connection.enqueue_control(payload)

    def reject(self, opcode: int, reason: int) -> None:
        self.enqueue(bytes([Opcode.LL_REJECT_EXT_IND, opcode, reason]))

    def instant(self) -> int:
        return (
            self.connection.event_counter
            + LL_INSTANT_MIN_LISTENING_EVENTS * (self.connection.parameters.latency + 1)
        ) & LL_EVENT_COUNTER_MASK

    def accept_instant(self, update: InstantUpdate) -> None:
        distance = (
            update.instant - self.connection.event_counter
        ) & LL_EVENT_COUNTER_MASK
        if distance >= RADIO_INSTANT_PAST_THRESHOLD:
            self.connection.complete(ErrorCode.INSTANT_PASSED_ERROR)
        elif self.pending is not None:
            self.connection.complete(ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR)
        else:
            self.pending = update
            if distance == 0:
                self.apply(received_at_instant=True)

    def request_update(
        self,
        interval: int,
        latency: int,
        timeout: int,
        *,
        reference: tuple[int, int] | None = None,
        notify: bool = True,
    ) -> None:
        instant = self.instant()
        offset = (
            anchor_offset(
                reference, instant, self.connection.parameters.interval, interval
            )
            if reference
            else 0
        )
        parameters = replace(
            self.connection.parameters,
            window_size=LL_CONN_WINDOW_SIZE_MIN,
            window_offset=offset,
            interval=interval,
            latency=latency,
            timeout=timeout,
        )
        self.pending = InstantUpdate(
            instant,
            parameters=parameters,
            local=True,
            anchor_reference=reference,
            notify=notify,
        )
        self.transmitted = self.acknowledged = False
        self.enqueue(
            bytes([Opcode.LL_CONNECTION_UPDATE_IND])
            + UPDATE.pack(
                LL_CONN_WINDOW_SIZE_MIN, offset, interval, latency, timeout, instant
            )
        )

    def request_channel_map(self, channel_map: int) -> None:
        self.host_channel_map = channel_map
        self._start_channel_map(self.selected_channel_map())

    def selected_channel_map(self) -> int:
        """Prefer Host-usable channels; fill missing indices in ascending order.

        This deterministic classification policy is local, not a Core-mandated
        AFH algorithm. The peer's latest indication applies to its listed PHYs.
        """
        value = self.host_channel_map
        if self.peer_minimum_channel_phys & (1 << (self.connection.rx_phy - 1)):
            for channel in range(LL_DATA_CHANNEL_COUNT):
                if value.bit_count() >= self.peer_minimum_used_channels:
                    break
                value |= 1 << channel
        return value & LL_DATA_CHANNEL_MAP_ALL

    def _refresh_channel_map(self) -> None:
        if (
            self.connection.role == Role.CENTRAL
            and not self.connection.closed
            and self.peer_minimum_channel_phys
            and not self.busy
        ):
            value = self.selected_channel_map()
            if value != self.connection.parameters.channel_map:
                self._start_channel_map(value)

    def _start_channel_map(self, channel_map: int) -> None:
        instant = self.instant()
        self.pending = InstantUpdate(instant, channel_map=channel_map, local=True)
        self.transmitted = self.acknowledged = False
        self.enqueue(
            bytes([Opcode.LL_CHANNEL_MAP_IND])
            + channel_map.to_bytes(LL_CHANNEL_MAP_SIZE, 'little')
            + instant.to_bytes(PDU_CONTROL_INSTANT_SIZE, 'little')
        )

    def request_minimum_channels(self, phys: int, minimum: int) -> None:
        """Queue a Peripheral indication after Feature Exchange, on its radio thread."""
        feature = LeFeatureMask.MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE
        if self.connection.closed or self.connection.role != Role.PERIPHERAL:
            raise ValueError('minimum used channels requires a live Peripheral link')
        if not valid_minimum_channels(phys, minimum):
            raise ValueError('invalid PHY mask or minimum used channel count')
        if not (
            self.connection.link.features
            & (self.connection.peer_features or 0)
            & feature
        ):
            raise ValueError('minimum used channels requires negotiated peer support')
        self.enqueue(bytes([Opcode.LL_MIN_USED_CHANNELS_IND, phys, minimum]))

    def prepare(self, payload: bytes) -> bytes:
        if self.connection.role == Role.PERIPHERAL and payload[0] in (
            Opcode.LL_PHY_REQ,
            Opcode.LL_PHY_RSP,
        ):
            self.transmitted = True
        update = self.pending
        if (
            update is not None
            and update.local
            and not self.transmitted
            and payload[0]
            in (
                Opcode.LL_CONNECTION_UPDATE_IND,
                Opcode.LL_CHANNEL_MAP_IND,
                Opcode.LL_PHY_UPDATE_IND,
            )
        ):
            # A queued ACL retransmission can delay the first control transmission.
            # Reserve six listening events from actual transmission, not HCI input.
            instant = self.instant()
            if update.parameters is not None and update.anchor_reference is not None:
                parameters = replace(
                    update.parameters,
                    window_offset=anchor_offset(
                        update.anchor_reference,
                        instant,
                        self.connection.parameters.interval,
                        update.parameters.interval,
                    ),
                )
                update = replace(update, parameters=parameters)
                payload = bytes([Opcode.LL_CONNECTION_UPDATE_IND]) + UPDATE.pack(
                    parameters.window_size,
                    parameters.window_offset,
                    parameters.interval,
                    parameters.latency,
                    parameters.timeout,
                    instant,
                )
            self.pending = replace(update, instant=instant)
            self.transmitted = True
            return payload[:-PDU_CONTROL_INSTANT_SIZE] + instant.to_bytes(
                PDU_CONTROL_INSTANT_SIZE, 'little'
            )
        return payload

    def acknowledge(self, payload: bytes) -> None:
        update = self.pending
        if (
            update
            and update.local
            and payload[0]
            in (
                Opcode.LL_CONNECTION_UPDATE_IND,
                Opcode.LL_CHANNEL_MAP_IND,
                Opcode.LL_PHY_UPDATE_IND,
            )
            and int.from_bytes(payload[-PDU_CONTROL_INSTANT_SIZE:], 'little')
            == update.instant
        ):
            self.acknowledged = True

    def sent(self, payload: bytes) -> None:
        if payload[0] != Opcode.LL_PHY_UPDATE_IND:
            return
        self.deadline_us = 0
        if not (payload[1] or payload[2]):
            self.phy_request = False
            if self.phy_request_local:
                self.connection.link.listener.on_phy_updated(
                    self.connection, ErrorCode.SUCCESS
                )
            self.phy_request_local = False

    def request_parameters(
        self, minimum: int, maximum: int, latency: int, timeout: int
    ) -> None:
        self.parameter_request = True
        self.requested_interval_min = minimum
        self.requested_parameters = (minimum, maximum, latency, timeout)
        self.deadline_us = self.connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
        self.enqueue(
            bytes([Opcode.LL_CONNECTION_PARAM_REQ])
            + PARAM_REQUEST.pack(
                minimum,
                maximum,
                latency,
                timeout,
                preferred_periodicity(minimum, maximum),
                self.connection.event_counter,
                *(
                    [PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED]
                    * PDU_CONTROL_CONN_PARAM_OFFSET_COUNT
                ),
            )
        )

    def reply_parameters(
        self,
        minimum: int,
        maximum: int,
        latency: int,
        timeout: int,
        *,
        notify: bool = True,
    ) -> None:
        assert self.remote_parameters is not None
        _, _, _, _, periodicity, reference, *offsets = PARAM_REQUEST.unpack(
            self.remote_parameters
        )
        self.remote_parameters = None
        interval = preferred_interval(minimum, maximum, periodicity)
        if self.connection.role == Role.CENTRAL:
            offset = next((value for value in offsets if value < interval), None)
            self.request_update(
                interval,
                latency,
                timeout,
                reference=(reference, offset) if offset is not None else None,
                notify=notify,
            )
        else:
            self.requested_interval_min = minimum if notify else 0
            self.enqueue(
                bytes([Opcode.LL_CONNECTION_PARAM_RSP])
                + PARAM_REQUEST.pack(
                    minimum,
                    maximum,
                    latency,
                    timeout,
                    preferred_periodicity(minimum, maximum, periodicity),
                    self.connection.event_counter,
                    *(
                        [PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED]
                        * PDU_CONTROL_CONN_PARAM_OFFSET_COUNT
                    ),
                )
            )
        self.deadline_us = self.connection.radio.now_us + LL_RESPONSE_TIMEOUT_US

    def request_features(self) -> None:
        self.feature_request = True
        if self.connection.peer_features is not None:
            self.finish_features(ErrorCode.SUCCESS)
            return
        self.feature_deadline_us = self.connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
        self.enqueue(
            bytes(
                [
                    (
                        Opcode.LL_FEATURE_REQ
                        if self.connection.role == Role.CENTRAL
                        else Opcode.LL_PERIPHERAL_FEATURE_REQ
                    )
                ]
            )
            + self.connection.link.features.to_bytes(
                PDU_CONTROL_FEATURE_SET_SIZE, 'little'
            )
        )

    def finish_features(self, status: int) -> None:
        if not self.feature_request:
            return
        self.feature_request = False
        self.feature_deadline_us = 0
        self.connection.link.listener.on_remote_features(self.connection, status)

    def send_version(self) -> None:
        if not self.version_sent:
            self.version_sent = True
            self.connection.enqueue_control(
                bytes([Opcode.LL_VERSION_IND])
                + struct.pack('<BHH', *self.connection.link.listener.local_version),
                priority=True,
            )

    def request_version(self) -> None:
        self.version_request = True
        if self.peer_version is not None:
            self.finish_version(ErrorCode.SUCCESS)
            return
        self.version_deadline_us = self.connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
        self.send_version()

    def finish_version(self, status: int | None) -> None:
        if not self.version_request:
            return
        self.version_request = False
        self.version_deadline_us = 0
        if status is not None:
            self.connection.link.listener.on_remote_version(self.connection, status)

    def reject_parameters(self, reason: int) -> None:
        requested = self.requested_parameters
        self.parameter_request = False
        self.requested_interval_min = 0
        self.requested_parameters = None
        self.deadline_us = 0
        if reason == ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR:
            self.parameter_request_unsupported = True
            if self.connection.peer_features is not None:
                self.connection.peer_features &= ~int(
                    LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE
                )
        if (
            self.connection.role == Role.CENTRAL
            and reason == ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
            and requested is not None
        ):
            minimum, _, latency, timeout = requested
            self.request_update(minimum, latency, timeout)
        else:
            self.connection.link.listener.on_connection_updated(self.connection, reason)
            if self.remote_parameters is not None:
                self.notify_remote_parameters()

    def reject_remote_parameters(self, reason: int) -> None:
        self.reject(Opcode.LL_CONNECTION_PARAM_REQ, reason)
        self.remote_parameters = None
        self.deadline_us = 0

    def notify_remote_parameters(self) -> None:
        assert self.remote_parameters is not None
        minimum, maximum, latency, timeout, *_ = PARAM_REQUEST.unpack(
            self.remote_parameters
        )
        self.deadline_us = self.connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
        parameters = self.connection.parameters
        if (
            minimum == maximum == parameters.interval
            and latency == parameters.latency
            and timeout == parameters.timeout
        ):
            self.reply_parameters(minimum, maximum, latency, timeout, notify=False)
            return
        self.connection.link.listener.on_remote_parameters(
            self.connection, minimum, maximum, latency, timeout
        )

    def request_phy(self, tx_phys: int, rx_phys: int) -> None:
        self.tx_phys, self.rx_phys = tx_phys, rx_phys
        self.phy_request = True
        self.phy_request_local = True
        self.transmitted = False
        self.deadline_us = self.connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
        self.enqueue(bytes([Opcode.LL_PHY_REQ, tx_phys, rx_phys]))

    @staticmethod
    def choose_phy(mask: int, current: int) -> int:
        if mask & (1 << (current - 1)):
            return current
        return next(
            (
                phy
                for phy in (Phy.LE_2M, Phy.LE_1M, Phy.LE_CODED)
                if mask & (1 << (phy - 1))
            ),
            current,
        )

    def _phy_update(self, peer_tx: int, peer_rx: int) -> None:
        connection = self.connection
        peer_tx &= RADIO_SUPPORTED_PHY_MASK
        peer_rx &= RADIO_SUPPORTED_PHY_MASK
        tx_mask, rx_mask = self.tx_phys & peer_rx, self.rx_phys & peer_tx
        # A single identical peer preference requires a symmetric selection.
        if peer_tx == peer_rx and peer_tx.bit_count() == 1:
            tx_mask = rx_mask = tx_mask & rx_mask
        central = self.choose_phy(tx_mask, connection.tx_phy)
        peripheral = self.choose_phy(rx_mask, connection.rx_phy)
        central_change = central if central != connection.tx_phy else 0
        peripheral_change = peripheral if peripheral != connection.rx_phy else 0
        instant = self.instant() if central_change or peripheral_change else 0
        self.enqueue(
            struct.pack(
                '<BBBH',
                Opcode.LL_PHY_UPDATE_IND,
                (1 << (central_change - 1)) if central_change else 0,
                (1 << (peripheral_change - 1)) if peripheral_change else 0,
                instant,
            )
        )
        if instant:
            self.pending = InstantUpdate(
                instant,
                central_tx_phy=central_change,
                peripheral_tx_phy=peripheral_change,
                local=True,
            )
            self.transmitted = self.acknowledged = False

    def control(self, payload: bytes) -> bool:
        connection = self.connection
        if self.data_length.control(payload):
            return True
        opcode = payload[0]
        if (
            opcode in (Opcode.LL_FEATURE_REQ, Opcode.LL_PERIPHERAL_FEATURE_REQ)
            and len(payload) == PDU_CONTROL_FEATURE_SIZE
        ):
            connection.peer_features = int.from_bytes(payload[1:], 'little')
            features = (connection.link.features & ~PHY_OCTET_MASK) | (
                connection.link.features & payload[1]
            )
            connection.enqueue_control(
                bytes([Opcode.LL_FEATURE_RSP])
                + features.to_bytes(PDU_CONTROL_FEATURE_SET_SIZE, "little"),
                priority=True,
            )
            return True
        if opcode == Opcode.LL_FEATURE_RSP and len(payload) == PDU_CONTROL_FEATURE_SIZE:
            connection.peer_features = int.from_bytes(payload[1:], 'little')
            self.finish_features(ErrorCode.SUCCESS)
            return True
        if (
            opcode == Opcode.LL_MIN_USED_CHANNELS_IND
            and len(payload) == PDU_CONTROL_MIN_USED_CHANNELS_SIZE
            and connection.role == Role.CENTRAL
            and connection.link.features
            & LeFeatureMask.MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE
        ):
            phys = payload[1] & RADIO_SUPPORTED_PHY_MASK
            minimum = payload[2]
            if not valid_minimum_channels(phys, minimum):
                return False
            self.peer_minimum_channel_phys = phys
            self.peer_minimum_used_channels = minimum
            self._refresh_channel_map()
            return True
        if opcode == Opcode.LL_VERSION_IND and len(payload) == PDU_CONTROL_VERSION_SIZE:
            if self.peer_version is None:
                self.peer_version = struct.unpack(
                    '<BHH', payload[PDU_CONTROL_OPCODE_SIZE:]
                )
                self.send_version()
                self.finish_version(ErrorCode.SUCCESS)
            return True
        if (
            opcode == Opcode.LL_CONNECTION_UPDATE_IND
            and len(payload) == PDU_CONTROL_OPCODE_SIZE + UPDATE.size
        ):
            if connection.role != Role.PERIPHERAL:
                self.reject(opcode, ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR)
                return True
            size, offset, interval, latency, timeout, instant = UPDATE.unpack(
                payload[PDU_CONTROL_OPCODE_SIZE:]
            )
            if (
                not valid_timing(interval, interval, latency, timeout)
                or not LL_CONN_WINDOW_SIZE_MIN
                <= size
                <= min(LL_CONN_WINDOW_SIZE_MAX, interval - 1)
                or offset > interval
            ):
                connection.complete(ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR)
            else:
                self.accept_instant(
                    InstantUpdate(
                        instant,
                        parameters=replace(
                            connection.parameters,
                            window_size=size,
                            window_offset=offset,
                            interval=interval,
                            latency=latency,
                            timeout=timeout,
                        ),
                    )
                )
            return True
        if (
            opcode == Opcode.LL_CHANNEL_MAP_IND
            and len(payload) == PDU_CONTROL_CHANNEL_MAP_SIZE
        ):
            channel_map = int.from_bytes(
                payload[
                    PDU_CONTROL_OPCODE_SIZE : PDU_CONTROL_OPCODE_SIZE
                    + LL_CHANNEL_MAP_SIZE
                ],
                'little',
            )
            if connection.role != Role.PERIPHERAL or not valid_channel_map(channel_map):
                connection.complete(ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR)
            else:
                self.accept_instant(
                    InstantUpdate(
                        int.from_bytes(
                            payload[PDU_CONTROL_OPCODE_SIZE + LL_CHANNEL_MAP_SIZE :],
                            'little',
                        ),
                        channel_map=channel_map,
                    )
                )
            return True
        if (
            opcode in (Opcode.LL_CONNECTION_PARAM_REQ, Opcode.LL_CONNECTION_PARAM_RSP)
            and len(payload) == PDU_CONTROL_OPCODE_SIZE + PARAM_REQUEST.size
        ):
            minimum, maximum, latency, timeout, *_ = PARAM_REQUEST.unpack(
                payload[PDU_CONTROL_OPCODE_SIZE:]
            )
            if not valid_timing(minimum, maximum, latency, timeout):
                self.reject(opcode, ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR)
            elif opcode == Opcode.LL_CONNECTION_PARAM_REQ:
                if (
                    connection.role == Role.PERIPHERAL
                    and (self.parameter_request or self.phy_request_local)
                    and not (
                        self.remote_parameters
                        or self.pending
                        or self.remote_phy_request
                        or self.data_length.pending
                    )
                ):
                    # Preserve the Central's request across local rejection. Only a
                    # same-procedure collision delays its Host notification.
                    self.remote_parameters = payload[PDU_CONTROL_OPCODE_SIZE:]
                    if self.phy_request_local:
                        self.notify_remote_parameters()
                elif self.busy:
                    self.reject(
                        opcode,
                        (
                            ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR
                            if self.pending and self.pending.channel_map is not None
                            else PROCEDURE_COLLISION
                        ),
                    )
                else:
                    self.remote_parameters = payload[PDU_CONTROL_OPCODE_SIZE:]
                    self.notify_remote_parameters()
            elif self.parameter_request and connection.role == Role.CENTRAL:
                requested = self.requested_parameters
                if requested is not None and max(minimum, requested[0]) > min(
                    maximum, requested[1]
                ):
                    self.reject_parameters(
                        ErrorCode.UNACCEPTABLE_CONNECTION_PARAMETERS_ERROR
                    )
                else:
                    self.request_update(
                        max(minimum, requested[0]) if requested else minimum,
                        latency,
                        timeout,
                    )
            return True
        if (
            opcode == Opcode.LL_UNKNOWN_RSP
            and len(payload) == PDU_CONTROL_UNKNOWN_RSP_SIZE
        ):
            if self.feature_request and payload[1] in (
                Opcode.LL_FEATURE_REQ,
                Opcode.LL_PERIPHERAL_FEATURE_REQ,
            ):
                self.finish_features(ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR)
            elif (
                self.parameter_request and payload[1] == Opcode.LL_CONNECTION_PARAM_REQ
            ):
                self.reject_parameters(ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR)
            return True
        if opcode == Opcode.LL_REJECT_IND and len(payload) == PDU_CONTROL_REJECT_SIZE:
            if self.feature_request:
                self.finish_features(payload[1])
            elif self.parameter_request:
                self.reject_parameters(payload[1])
            return True
        if (
            opcode == Opcode.LL_REJECT_EXT_IND
            and len(payload) == PDU_CONTROL_REJECT_EXT_SIZE
            and payload[1] in (Opcode.LL_FEATURE_REQ, Opcode.LL_PERIPHERAL_FEATURE_REQ)
        ):
            self.finish_features(payload[2])
            return True
        if (
            opcode in (Opcode.LL_PHY_REQ, Opcode.LL_PHY_RSP)
            and len(payload) == PDU_CONTROL_PHY_REQ_SIZE
        ):
            peer_tx, peer_rx = payload[PDU_CONTROL_OPCODE_SIZE:]
            # RFU preference bits are ignored; selection intersects local support.
            if not peer_tx or not peer_rx:
                self.reject(opcode, ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR)
            elif opcode == Opcode.LL_PHY_REQ:
                if (
                    connection.role == Role.PERIPHERAL
                    and self.phy_request_local
                    and not (
                        self.pending
                        or self.remote_phy_request
                        or self.remote_parameters
                        or self.parameter_request
                        or self.data_length.pending
                        or self.feature_request
                    )
                ):
                    self.remote_phy_request = payload
                elif self.busy:
                    self.reject(
                        opcode,
                        (
                            PROCEDURE_COLLISION
                            if self.phy_request
                            else ErrorCode.DIFFERENT_TRANSACTION_COLLISION_ERROR
                        ),
                    )
                else:
                    self.phy_request = True
                    self.transmitted = False
                    self.deadline_us = connection.radio.now_us + LL_RESPONSE_TIMEOUT_US
                    if connection.role == Role.CENTRAL:
                        self._phy_update(peer_tx, peer_rx)
                    else:
                        self.enqueue(
                            bytes([Opcode.LL_PHY_RSP, self.tx_phys, self.rx_phys])
                        )
            elif self.phy_request and connection.role == Role.CENTRAL:
                self._phy_update(peer_tx, peer_rx)
            return True
        if (
            opcode == Opcode.LL_PHY_UPDATE_IND
            and len(payload) == PDU_CONTROL_PHY_UPDATE_SIZE
        ):
            central, peripheral, instant = struct.unpack(
                '<BBH', payload[PDU_CONTROL_OPCODE_SIZE:]
            )
            if (
                connection.role != Role.PERIPHERAL
                or central not in (0, *(1 << (phy - 1) for phy in Phy))
                or peripheral not in (0, *(1 << (phy - 1) for phy in Phy))
            ):
                connection.complete(ErrorCode.INVALID_LMP_OR_LL_PARAMETERS_ERROR)
            elif central or peripheral:
                self.accept_instant(
                    InstantUpdate(
                        instant,
                        central_tx_phy=central.bit_length(),
                        peripheral_tx_phy=peripheral.bit_length(),
                    )
                )
                self.deadline_us = 0
            else:
                self.phy_request = False
                self.deadline_us = 0
                if self.phy_request_local:
                    connection.link.listener.on_phy_updated(
                        connection, ErrorCode.SUCCESS
                    )
                self.phy_request_local = False
            return True
        if (
            opcode == Opcode.LL_REJECT_EXT_IND
            and len(payload) == PDU_CONTROL_REJECT_EXT_SIZE
            and payload[1] in (Opcode.LL_CONNECTION_PARAM_REQ, Opcode.LL_PHY_REQ)
        ):
            if payload[1] == Opcode.LL_CONNECTION_PARAM_REQ and self.parameter_request:
                self.reject_parameters(payload[2])
            elif payload[1] == Opcode.LL_PHY_REQ and self.phy_request:
                self.phy_request = False
                self.phy_request_local = False
                connection.link.listener.on_phy_updated(connection, payload[2])
                if self.remote_phy_request is not None:
                    request, self.remote_phy_request = self.remote_phy_request, None
                    self.control(request)
                elif not (self.remote_parameters or self.requested_interval_min):
                    # A queued Peripheral PARAM_RSP still awaits UPDATE_IND.
                    self.deadline_us = 0
            return True
        return False

    def apply(self, *, received_at_instant: bool = False) -> None:
        connection = self.connection
        update = self.pending
        if self.check_timeout():
            return
        if update is None:
            self._refresh_channel_map()
            return
        if update.instant != connection.event_counter:
            return
        if update.local and not self.transmitted:
            return
        if update.local and not self.acknowledged:
            connection.complete(ErrorCode.INSTANT_PASSED_ERROR)
            return
        self.pending = None
        self.deadline_us = 0
        if update.parameters is not None:
            old = connection.parameters
            notify = (
                update.notify
                if update.notify is not None
                else (
                    self.parameter_request
                    or self.requested_interval_min
                    or (old.interval, old.latency, old.timeout)
                    != (
                        update.parameters.interval,
                        update.parameters.latency,
                        update.parameters.timeout,
                    )
                )
            )
            connection.parameters = update.parameters
            if not received_at_instant:
                connection.anchor_us += (
                    update.parameters.window_offset * LL_CONN_INTERVAL_UNIT_US
                )
            connection.update_window = not received_at_instant
            connection.supervision_restart_us = connection.anchor_us
            self.parameter_request = False
            self.requested_interval_min = 0
            self.requested_parameters = None
            if notify:
                connection.link.listener.on_connection_updated(
                    connection, ErrorCode.SUCCESS
                )
        if update.channel_map is not None:
            connection.parameters = replace(
                connection.parameters, channel_map=update.channel_map
            )
        if update.central_tx_phy or update.peripheral_tx_phy:
            tx, rx = (
                (update.central_tx_phy, update.peripheral_tx_phy)
                if connection.role == Role.CENTRAL
                else (update.peripheral_tx_phy, update.central_tx_phy)
            )
            connection.tx_phy = Phy(tx or connection.tx_phy)
            connection.rx_phy = Phy(rx or connection.rx_phy)
            self.phy_request = False
            self.phy_request_local = False
            connection.link.listener.on_phy_updated(connection, ErrorCode.SUCCESS)
        self.data_length.refresh()
        self._refresh_channel_map()

    def check_timeout(self) -> bool:
        if self.data_length.check_timeout():
            return True
        if (
            self.version_deadline_us
            and self.connection.radio.now_us >= self.version_deadline_us
        ):
            self.finish_version(ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR)
            self.connection.complete(ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR)
            return True
        if (
            self.feature_deadline_us
            and self.connection.radio.now_us >= self.feature_deadline_us
        ):
            self.finish_features(ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR)
            self.connection.complete(ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR)
            return True
        if self.deadline_us and self.connection.radio.now_us >= self.deadline_us:
            self.connection.complete(ErrorCode.LMP_OR_LL_RESPONSE_TIMEOUT_ERROR)
            return True
        return False
