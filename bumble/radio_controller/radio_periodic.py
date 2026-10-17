# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Periodic train transmission and synchronization receive RF procedures.

These stateless operations execute on the owning link's one radio and use its
admission and lifetime transitions. They never start an independent task.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from bumble.hci import HCI_ErrorCode as ErrorCode
from bumble.hci import HCI_LE_Extended_Advertising_Report_Event as AdvertisingReport
from bumble.ll import (
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    LL_MAFS_US,
    LL_PERIODIC_INTERVAL_UNIT_US,
    AdvertisingMode,
)
from bumble.radio_controller.radio import (
    RADIO_SWITCH_TIME_US,
    channel_selection_2,
    window_widening,
)
from bumble.radio_controller.radio_advertising import ExtendedPdu
from bumble.radio_controller.radio_discovery import Advertising, PeriodicSync
from bumble.radio_controller.radio_extended import periodic_time_us
from bumble.radio_controller.radio_scheduler import (
    RadioPriority,
    higher_priority_overlap,
)

if TYPE_CHECKING:
    from bumble.radio_controller.radio_link import RadioLink


async def periodic_transmit(link: RadioLink, item: Advertising) -> None:
    # A single radio cannot replay a train anchor that another event occupied.
    interval_us = item.periodic_interval * LL_PERIODIC_INTERVAL_UNIT_US
    channel = channel_selection_2(
        item.periodic_counter, item.periodic_aa, LL_DATA_CHANNEL_MAP_ALL
    )
    if item.periodic_next_us < link.radio.earliest_start_us(
        channel, item.secondary_phy, transmit=True
    ) or higher_priority_overlap(
        link.reservations(exclude=item),
        item.periodic_next_us - RADIO_SWITCH_TIME_US,
        item.periodic_next_us + periodic_time_us(item) + LL_MAFS_US,
        RadioPriority.PERIODIC_TX,
    ):
        missed = max(0, (link.now_us - item.periodic_next_us) // interval_us) + 1
        item.periodic_next_us += missed * interval_us
        item.periodic_counter = (item.periodic_counter + missed) & LL_EVENT_COUNTER_MASK
        return
    await link.extended.transmit_chain(
        channel,
        ExtendedPdu(),
        item.periodic_data,
        item.periodic_next_us,
        item.secondary_phy,
        access_address=item.periodic_aa,
        crc_init=item.periodic_crc,
        power_dbm=item.tx_power_dbm,
    )
    item.periodic_next_us += item.periodic_interval * LL_PERIODIC_INTERVAL_UNIT_US
    item.periodic_counter = (item.periodic_counter + 1) & LL_EVENT_COUNTER_MASK


async def periodic_receive(link: RadioLink, sync: PeriodicSync) -> None:
    sync.apply_channel_map()
    info = sync.info
    assert info is not None
    widening = window_widening(sync.next_us - sync.last_rx_us, info.sca)
    window_end = sync.next_us + widening + info.unit_us + sync.phy.address_us
    if window_end <= link.now_us or higher_priority_overlap(
        link.reservations(exclude=sync),
        max(link.now_us + 1, sync.next_us - widening),
        window_end,
        RadioPriority.PERIODIC_RX,
    ):
        step = sync.event_step
        interval_us = info.interval * LL_PERIODIC_INTERVAL_UNIT_US * step
        missed = max(0, (link.now_us - window_end) // interval_us) + 1
        sync.next_us += missed * interval_us
        sync.counter = (sync.counter + missed * step) & LL_EVENT_COUNTER_MASK
        return
    packet = await link.radio.receive(
        channel_selection_2(sync.counter, info.access_address, info.channel_map),
        window_end,
        start_us=max(link.now_us + 1, sync.next_us - widening),
        access_address=info.access_address,
        crc_init=info.crc_init,
        phy=sync.phy,
    )
    if packet:
        try:
            ext = ExtendedPdu.decode(packet.pdu)
        except ValueError:
            ext = None
        if ext is not None and ext.mode == AdvertisingMode.NONCONNECTABLE_NONSCANNABLE:
            sync.next_us = packet.start_us
            sync.last_rx_us = packet.start_us
            sync.deadline_us = packet.end_us + sync.timeout_us
            sync.receive_channel_map(ext.acad)
            if not sync.established:
                sync.established = True
                link.sync = None
                link.syncs[sync.handle] = sync
                link.listener.on_sync_established(sync, ErrorCode.SUCCESS)

            def report_fragment(data, status, received):
                if link.syncs.get(sync.handle) is sync and sync.reports_enabled:
                    link.listener.on_periodic_report(
                        sync,
                        data,
                        received.rssi,
                        (
                            ext.tx_power
                            if ext.tx_power is not None
                            else (AdvertisingReport.TX_POWER_INFORMATION_NOT_AVAILABLE)
                        ),
                        status,
                    )

            data, status, _ = await link.extended.collect(
                packet,
                ext,
                on_fragment=report_fragment,
                access_address=info.access_address,
                crc_init=info.crc_init,
            )
            report_fragment(data, status, packet)
    step = sync.event_step
    sync.next_us += info.interval * LL_PERIODIC_INTERVAL_UNIT_US * step
    sync.counter = (sync.counter + step) & LL_EVENT_COUNTER_MASK
