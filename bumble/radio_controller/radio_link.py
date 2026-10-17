# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LE radio procedures; no HCI serialization, transport, or simulator binding."""

from __future__ import annotations

import random
from dataclasses import replace
from typing import Protocol

from bumble.hci import Address
from bumble.hci import HCI_ErrorCode as ErrorCode
from bumble.hci import HCI_LE_Extended_Advertising_Report_Event as AdvertisingReport
from bumble.hci import Role
from bumble.ll import (
    LL_ADV_DELAY_MAX_US,
    LL_ADV_PRIMARY_CHANNELS,
    LL_CONN_INTERVAL_UNIT_US,
    LL_EVENT_COUNTER_MASK,
    LL_HOP_INCREMENT_MAX,
    LL_HOP_INCREMENT_MIN,
    LL_IFS_US,
    LL_MAFS_US,
    LL_PERIODIC_INTERVAL_UNIT_US,
    LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS,
    PDU_ADV_EXT_PAYLOAD_SIZE_MAX,
    PDU_CRC_SIZE,
    PDU_DATA_PAYLOAD_SIZE_MIN,
    PDU_DATA_PAYLOAD_TIME_MIN_US,
    PDU_HEADER_SIZE,
)
from bumble.radio_controller.radio import (
    PHY_OCTET_BITS,
    RADIO_CONN_EVENT_GUARD_US,
    RADIO_CONNECTION_COUNT,
    RADIO_DEFAULT_SCAN_INTERVAL_US,
    RADIO_RESPONSE_START_TOLERANCE_US,
    RADIO_SWITCH_TIME_US,
    Phy,
    Radio,
    Received,
    generate_access_address,
    window_widening,
)
from bumble.radio_controller.radio_connection import Connection
from bumble.radio_controller.radio_discovery import (
    Advertising,
    Initiating,
    PeriodicSync,
)
from bumble.radio_controller.radio_discovery import ScanBackoff as ScanBackoff
from bumble.radio_controller.radio_discovery import Scanning, ScanWindow, scan_window_at
from bumble.radio_controller.radio_extended import ExtendedProcedures, periodic_time_us
from bumble.radio_controller.radio_parameters import Parameters
from bumble.radio_controller.radio_periodic import periodic_receive, periodic_transmit
from bumble.radio_controller.radio_primary import (
    advertise_legacy,
    advertising_event_time_us,
    advertising_request,
    initiate,
    scan_extended,
    scan_packet,
)
from bumble.radio_controller.radio_scheduler import (
    RadioPriority,
    RadioReservation,
    first_radio_gap,
)


class Listener(Protocol):
    @property
    def local_version(self) -> tuple[int, int, int]: ...

    def allocate_connection_handle(self) -> int: ...
    def trace(self, message: str) -> None: ...
    def on_connected(self, connection: Connection) -> None: ...
    def on_disconnected(self, connection: Connection, reason: int) -> None: ...
    def on_acl_received(
        self, connection: Connection, continuation: bool, data: bytes
    ) -> None: ...
    def on_acl_completed(self, connection: Connection) -> None: ...
    def on_advertisement(
        self,
        address: Address,
        data: bytes,
        rssi: float,
        event_type: int,
        sid: int,
        interval: int,
        tx_power: int,
        *,
        target: Address | None = None,
        primary_phy: int = Phy.LE_1M,
        secondary_phy: int = Phy.LE_1M,
    ) -> None: ...
    def on_sync_established(self, sync: PeriodicSync, status: int) -> None: ...
    def on_periodic_report(
        self,
        sync: PeriodicSync,
        data: bytes,
        rssi: float,
        tx_power: int,
        data_status: int = AdvertisingReport.DATA_COMPLETE,
    ) -> None: ...
    def on_sync_lost(self, sync: PeriodicSync) -> None: ...
    def on_advertising_ended(self, item: Advertising, status: int) -> None: ...
    def on_connection_updated(self, connection: Connection, status: int) -> None: ...
    def on_phy_updated(self, connection: Connection, status: int) -> None: ...
    def on_data_length_changed(self, connection: Connection) -> None: ...
    def on_remote_features(self, connection: Connection, status: int) -> None: ...

    def on_remote_version(self, connection: Connection, status: int) -> None: ...
    def on_long_term_key_request(
        self, connection: Connection, rand: bytes, ediv: int
    ) -> None: ...
    def on_encryption_changed(
        self, connection: Connection, status: int, refresh: bool
    ) -> None: ...
    def on_authenticated_payload_timeout(self, connection: Connection) -> None: ...
    def on_remote_parameters(
        self,
        connection: Connection,
        minimum: int,
        maximum: int,
        latency: int,
        timeout: int,
    ) -> None: ...
    def on_scan_request(self, item: Advertising, peer: Address) -> None: ...
    def on_scan_timeout(self) -> None: ...
    def on_scan_period(self) -> None: ...


class RadioLink:
    """One physical radio, with explicit, integer-microsecond operation deadlines."""

    # Bound stateless procedures use this link's radio and active contexts.
    _advertising_request = advertising_request
    _initiate = initiate
    _scan_packet = scan_packet
    _scan_extended = scan_extended
    _periodic_transmit = periodic_transmit
    _periodic_receive = periodic_receive

    def __init__(
        self, radio: Radio, listener: Listener, features: int = 0, seed: int = 1
    ):
        self.radio = radio
        self.listener = listener
        self.features = features
        self.advertisers: dict[int, Advertising] = {}
        self.scan: Scanning | None = None
        self.initiating: Initiating | None = None
        self.connections: dict[int, Connection] = {}
        self.sync: PeriodicSync | None = None
        self.syncs: dict[int, PeriodicSync] = {}
        self.seed = seed
        self.random = random.Random(seed)
        self.extended = ExtendedProcedures(self)
        self.radio_deadline_us: int | None = None
        self.scan_cursor = 0
        self.accept_list: set[Address] = set()
        self.periodic_advertiser_list: set[tuple[Address, int]] = set()
        self.default_tx_octets = PDU_DATA_PAYLOAD_SIZE_MIN
        self.default_tx_time = PDU_DATA_PAYLOAD_TIME_MIN_US

    def trace(self, message: str) -> None:
        self.listener.trace(message)

    def reset(self) -> None:
        self.advertisers.clear()
        self.scan = self.initiating = self.sync = None
        self.connections.clear()
        self.syncs.clear()
        self.radio_deadline_us = None
        self.scan_cursor = 0
        self.random.seed(self.seed)
        self.accept_list.clear()
        self.periodic_advertiser_list.clear()
        self.default_tx_octets = PDU_DATA_PAYLOAD_SIZE_MIN
        self.default_tx_time = PDU_DATA_PAYLOAD_TIME_MIN_US

    @property
    def now_us(self) -> int:
        return self.radio.now_us

    def can_connect(self, peer: Address) -> bool:
        return len(self.connections) < RADIO_CONNECTION_COUNT and not any(
            connection.peer == peer for connection in self.connections.values()
        )

    def create_connection(
        self,
        parameters: Parameters,
        peer: Address,
        role: Role,
        connect_end_us: int,
        *,
        self_address: Address,
        csa2: bool,
        advertiser: Advertising | None = None,
        window_delay_us: int = LL_CONN_INTERVAL_UNIT_US,
        phy: Phy = Phy.LE_1M,
    ) -> Connection:
        if advertiser is not None:
            advertiser.enabled = False
        connection = Connection(
            self,
            parameters,
            peer,
            role,
            connect_end_us,
            csa2=csa2,
            self_address=self_address,
            window_delay_us=window_delay_us,
            phy=phy,
        )
        if advertiser is not None:
            handle = next(
                key for key, value in self.advertisers.items() if value is advertiser
            )
            if handle != -1:
                connection.advertising_handle = handle
                connection.advertising_events = advertiser.events
        self.connections[connection.handle] = connection
        connection.report_created()
        return connection

    def new_access_address(self) -> int:
        used = {
            connection.parameters.access_address
            for connection in self.connections.values()
        }
        used.update(
            item.periodic_aa
            for item in self.advertisers.values()
            if item.periodic_enabled
        )
        return generate_access_address(self.random, used)

    def reservations(self, *, exclude: object = None) -> list[RadioReservation]:
        result = []
        for connection in self.connections.values():
            if connection is exclude:
                continue
            result.append(
                RadioReservation(
                    connection.event_start_us - RADIO_SWITCH_TIME_US,
                    max(
                        connection.next_exchange_us(),
                        (
                            connection.parameters.window_size * LL_CONN_INTERVAL_UNIT_US
                            if not connection.established
                            else 0
                        ),
                    )
                    + RADIO_CONN_EVENT_GUARD_US
                    + RADIO_SWITCH_TIME_US,
                    connection.parameters.interval * LL_CONN_INTERVAL_UNIT_US,
                )
            )
        for item in self.advertisers.values():
            if item is not exclude and item.periodic_enabled:
                result.append(
                    RadioReservation(
                        item.periodic_next_us - RADIO_SWITCH_TIME_US,
                        periodic_time_us(item) + LL_MAFS_US + RADIO_SWITCH_TIME_US,
                        item.periodic_interval * LL_PERIODIC_INTERVAL_UNIT_US,
                        RadioPriority.PERIODIC_TX,
                    )
                )
        for sync in list(self.syncs.values()) + ([self.sync] if self.sync else []):
            if sync is exclude or sync.info is None:
                continue
            widening = window_widening(sync.next_us - sync.last_rx_us, sync.info.sca)
            result.append(
                RadioReservation(
                    sync.next_us - widening - RADIO_SWITCH_TIME_US,
                    2 * widening
                    + sync.phy.airtime_us(
                        PDU_HEADER_SIZE + PDU_ADV_EXT_PAYLOAD_SIZE_MAX
                    )
                    + RADIO_SWITCH_TIME_US,
                    sync.info.interval * LL_PERIODIC_INTERVAL_UNIT_US * sync.event_step,
                    RadioPriority.PERIODIC_RX,
                )
            )
        return result

    def connection_parameters(
        self,
        parameters: Parameters,
        request_end_us: int,
        window_delay_us: int,
        phy: Phy = Phy.LE_1M,
    ) -> Parameters | None:
        """Allocate independent wire identity and a legal initial transmit window."""
        start = request_end_us + window_delay_us
        gap = first_radio_gap(
            self.reservations(),
            start,
            max(
                parameters.window_size * LL_CONN_INTERVAL_UNIT_US,
                2 * phy.airtime_us(PDU_HEADER_SIZE + PDU_DATA_PAYLOAD_SIZE_MIN)
                + 2 * LL_IFS_US,
            )
            + RADIO_CONN_EVENT_GUARD_US,
            start
            + (parameters.interval - parameters.window_size) * LL_CONN_INTERVAL_UNIT_US,
            quantum_us=LL_CONN_INTERVAL_UNIT_US,
        )
        if gap is None:
            return None
        return replace(
            parameters,
            window_offset=(gap - start) // LL_CONN_INTERVAL_UNIT_US,
            access_address=self.new_access_address(),
            crc_init=self.random.getrandbits(PDU_CRC_SIZE * PHY_OCTET_BITS),
            hop=self.random.randint(LL_HOP_INCREMENT_MIN, LL_HOP_INCREMENT_MAX),
        )

    def set_periodic_enabled(self, item: Advertising, enable: bool) -> None:
        if item.periodic_enabled == enable:
            return
        interval_us = item.periodic_interval * LL_PERIODIC_INTERVAL_UNIT_US
        next_us = self.now_us + interval_us
        if enable:
            duration_us = periodic_time_us(item) + LL_MAFS_US
            phase = first_radio_gap(
                self.reservations(exclude=item),
                next_us,
                duration_us,
                next_us + interval_us - duration_us,
            )
            # Scheduling conflicts may lose events, not disable legal states.
            if phase is not None:
                next_us = phase
            item.periodic_aa = self.new_access_address()
            item.periodic_crc = self.random.getrandbits(PDU_CRC_SIZE * PHY_OCTET_BITS)
        item.periodic_enabled = enable
        item.periodic_next_us = next_us
        item.periodic_counter = 0

    def fits_radio(self, end_us: int) -> bool:
        return self.radio_deadline_us is None or end_us <= self.radio_deadline_us

    def radio_limit(self, owner: object = None) -> int | None:
        starts = [
            start
            for reservation in self.reservations(exclude=owner)
            for start, _ in [reservation.window_after(self.now_us + 1)]
            if start > self.now_us + 1
        ]
        return min(starts) if starts else None

    async def _transmit(self, channel: int, pdu: bytes, **kwargs) -> int:
        self.trace(f'RADIO TX ch={channel} pdu={pdu.hex()}')
        return await self.radio.transmit(channel, pdu, **kwargs)

    async def receive_response(
        self,
        channel: int,
        transmit_end_us: int,
        phy: Phy = Phy.LE_1M,
        *,
        deadline_us: int | None = None,
    ) -> Received | None:
        """Limit address detection, not the length of an acquired response."""
        response_start = transmit_end_us + LL_IFS_US
        until_us = response_start + RADIO_RESPONSE_START_TOLERANCE_US + phy.address_us
        if deadline_us is not None:
            until_us = min(until_us, deadline_us)
        return await self.radio.receive(
            channel,
            until_us,
            start_us=response_start - RADIO_RESPONSE_START_TOLERANCE_US,
            phy=phy,
        )

    async def _advertise(self, item: Advertising) -> None:
        channel = next(
            channel
            for bit, channel in enumerate(LL_ADV_PRIMARY_CHANNELS)
            if item.channel_map & (1 << bit)
        )
        start = self.radio.earliest_start_us(channel, item.primary_phy, transmit=True)
        reservations = self.reservations()
        if reservations:
            duration = advertising_event_time_us(item)
            latest = (
                item.deadline_us - duration
                if item.deadline_us
                else (
                    start + max(reservation.interval_us for reservation in reservations)
                )
            )
            gap = first_radio_gap(reservations, start, duration, latest)
            if gap != start:
                item.next_us = (
                    gap
                    if gap is not None
                    else (item.deadline_us or start + item.interval_us)
                )
                return
        event_start = start
        item.events += 1
        if item.extended:
            await self.extended.advertise(item)
        else:
            await advertise_legacy(self, item)
        item.next_us = max(
            event_start
            + item.interval_us
            + (0 if item.high_duty else self.random.randint(0, LL_ADV_DELAY_MAX_US)),
            self.now_us + 1,
        )

    def _pending_operations(self, sync: PeriodicSync | None):
        now = self.now_us
        deadlines: list[
            tuple[int, RadioPriority, Connection | Advertising | PeriodicSync]
        ] = []
        for connection in self.connections.values():
            deadlines.append(
                (
                    connection.next_operation_us - RADIO_SWITCH_TIME_US,
                    RadioPriority.CONNECTION,
                    connection,
                )
            )
        for item in self.advertisers.values():
            if item.enabled and (
                (item.deadline_us and now >= item.deadline_us)
                or (item.max_events and item.events >= item.max_events)
            ):
                item.enabled = False
                self.listener.on_advertising_ended(
                    item,
                    (
                        ErrorCode.ADVERTISING_TIMEOUT_ERROR
                        if item.deadline_us and now >= item.deadline_us
                        else ErrorCode.LIMIT_REACHED_ERROR
                    ),
                )
            if item.enabled:
                deadlines.append(
                    (
                        item.next_us,
                        RadioPriority.ADVERTISING,
                        item,
                    )
                )
                if item.deadline_us:
                    deadlines.append(
                        (
                            item.deadline_us,
                            RadioPriority.EXPIRY,
                            item,
                        )
                    )
            if item.periodic_enabled:
                deadlines.append(
                    (
                        item.periodic_next_us - RADIO_SWITCH_TIME_US,
                        RadioPriority.PERIODIC_TX,
                        item,
                    )
                )
        contexts = list(self.syncs.values()) + ([sync] if sync else [])
        for context in contexts:
            if context.info is None:
                continue
            widening = window_widening(
                context.next_us - context.last_rx_us, context.info.sca
            )
            deadlines.append(
                (
                    context.next_us - widening - RADIO_SWITCH_TIME_US,
                    RadioPriority.PERIODIC_RX,
                    context,
                )
            )
        return deadlines, contexts

    async def _scan_until(self, scan: Scanning | Initiating, end: int) -> None:
        now = self.now_us
        if isinstance(scan, Scanning) and scan.deadline_us and now >= scan.deadline_us:
            if not scan.period_us:
                self.scan = None
                self.listener.on_scan_timeout()
                return
            scan.start_us += scan.period_us
            scan.deadline_us = scan.start_us + scan.duration_us
            self.listener.on_scan_period()
        if scan.start_us > now:
            await self.radio.advance_to_us(min(end, scan.start_us))
            return
        windows = scan.windows or (
            ScanWindow(
                Phy.LE_1M,
                scan.interval_us,
                scan.window_us,
                getattr(scan, 'active', False),
            ),
        )
        window, cycle, boundary = scan_window_at(windows, now - scan.start_us)
        end = min(end, scan.start_us + boundary)
        if isinstance(scan, Scanning):
            if window is not None:
                scan.active = window.active
            if scan.deadline_us:
                end = min(end, scan.deadline_us)
        if window is not None:
            channel = LL_ADV_PRIMARY_CHANNELS[cycle % len(LL_ADV_PRIMARY_CHANNELS)]
            self.radio_deadline_us = self.radio_limit()
            try:
                packet = await self.radio.receive(channel, end, phy=window.phy)
                if packet:
                    if scan is self.initiating:
                        await self._initiate(channel, packet)
                    else:
                        await self._scan_packet(channel, packet)
            finally:
                self.radio_deadline_us = None
            return
        await self.radio.advance_to_us(end)

    async def advance_to_us(self, target_us: int) -> int:
        while self.now_us < target_us:
            now = self.now_us
            for connection in list(self.connections.values()):
                connection.skip_missed_events()
            sync = self.sync
            if (
                sync
                and sync.info is not None
                and (
                    now >= sync.deadline_us
                    or (sync.counter - sync.info.event_counter) & LL_EVENT_COUNTER_MASK
                    >= LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS
                )
            ):
                self.sync = None
                self.listener.on_sync_established(
                    sync, ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR
                )
                continue
            for handle, active in list(self.syncs.items()):
                if now >= active.deadline_us:
                    del self.syncs[handle]
                    self.listener.on_sync_lost(active)
            deadlines, contexts = self._pending_operations(sync)
            if deadlines:
                due, priority, owner = min(
                    deadlines,
                    key=lambda entry: (
                        entry[0],
                        entry[1],
                        (
                            entry[2].last_event_us
                            if isinstance(entry[2], Connection)
                            else 0
                        ),
                    ),
                )
                if due <= now + 1:
                    self.radio_deadline_us = self.radio_limit(owner)
                    try:
                        if isinstance(owner, Connection):
                            await owner.advance_to_us(
                                target_us, radio_until_us=self.radio_deadline_us
                            )
                        elif priority == RadioPriority.PERIODIC_TX:
                            await self._periodic_transmit(owner)
                        elif priority == RadioPriority.PERIODIC_RX:
                            await self._periodic_receive(owner)
                        elif priority == RadioPriority.EXPIRY:
                            await self._expire_advertiser(owner)
                        else:
                            await self._advertise(owner)
                    finally:
                        self.radio_deadline_us = None
                    continue
                end = min(target_us, due - 1)
            else:
                end = target_us
            for context in contexts:
                if context.info is not None:
                    end = min(end, context.deadline_us)
            scans = [scan for scan in (self.initiating, self.scan) if scan is not None]
            if self.scan is None and sync and sync.info is None:
                scans.append(
                    Scanning(
                        sync.address,
                        RADIO_DEFAULT_SCAN_INTERVAL_US,
                        RADIO_DEFAULT_SCAN_INTERVAL_US,
                    )
                )
            scan = scans[self.scan_cursor % len(scans)] if scans else None
            self.scan_cursor += 1
            if scan:
                await self._scan_until(scan, end)
            else:
                await self.radio.advance_to_us(end)
        return self.now_us

    async def _expire_advertiser(self, item: Advertising) -> None:
        item.enabled = False
        self.listener.on_advertising_ended(item, ErrorCode.ADVERTISING_TIMEOUT_ERROR)
