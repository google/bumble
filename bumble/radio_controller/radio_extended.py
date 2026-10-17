# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Auxiliary advertising, scan-response and connection transactions.

Operations use the owning RadioLink's one radio. No procedure owns an event
loop or schedules a second, concurrent radio operation.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from bumble.hci import (
    HCI_LE_ADV_DATA_SIZE_MAX,
    HCI_LE_ADV_FILTER_CONNECT_MASK,
    HCI_LE_ADV_FILTER_SCAN_MASK,
    HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT,
    Address,
    AddressType,
)
from bumble.hci import HCI_LE_Extended_Advertising_Report_Event as AdvertisingReport
from bumble.hci import Role
from bumble.ll import (
    LL_ADV_PRIMARY_CHANNELS,
    LL_CONN_AUX_WINDOW_DELAY_CODED_US,
    LL_CONN_AUX_WINDOW_DELAY_UNCODED_US,
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_IFS_US,
    LL_MAFS_US,
    LL_PERIODIC_INTERVAL_MIN,
    LL_PERIODIC_INTERVAL_UNIT_US,
    LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS,
    LL_SCA_50_PPM,
    LL_SCA_500_PPM,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_ADDRESSES_END,
    PDU_ADV_ADI_DID_BITS,
    PDU_ADV_AUX_CONNECT_RSP_SIZE,
    PDU_ADV_CONNECT_PAYLOAD_SIZE,
    PDU_ADV_CONNECT_SIZE,
    PDU_ADV_OFFSET_UNIT_30_US,
    PDU_ADV_RXADD_MASK,
    PDU_ADV_SCAN_REQ_SIZE,
    PDU_ADV_TXADD_MASK,
    PDU_ADV_TYPE_MASK,
    AdvertisingMode,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import RADIO_SWITCH_TIME_US, Phy, window_widening
from bumble.radio_controller.radio_advertising import (
    AuxPtr,
    ExtendedPdu,
    SyncInfo,
    advertising_request_peer,
    align_offset_us,
    scan_request,
)
from bumble.radio_controller.radio_parameters import Parameters

if TYPE_CHECKING:
    from bumble.radio_controller.radio import Received
    from bumble.radio_controller.radio_discovery import Advertising
    from bumble.radio_controller.radio_link import RadioLink

# Auxiliary scheduling policy: preferred start-to-start offset, not a Core minimum.
# Actual offsets also include packet airtime plus LL_MAFS_US and offset rounding.
RADIO_AUX_OFFSET_DEFAULT_US = 600


def auxiliary_offset(pdu: bytes, phy: Phy) -> int:
    return align_offset_us(
        max(RADIO_AUX_OFFSET_DEFAULT_US, phy.airtime_us(len(pdu)) + LL_MAFS_US)
    )


def fragments(first: ExtendedPdu, data: bytes | bytearray, channel: int, phy: Phy):
    """Bounded AUX_CHAIN sequence; all offsets are measured from packet start."""
    if len(data) > HCI_LE_ADV_DATA_SIZE_MAX:
        raise ValueError(
            f'extended advertising data exceeds {HCI_LE_ADV_DATA_SIZE_MAX} octets'
        )
    remaining = data
    result = []
    pdu = first
    while True:
        pdu = replace(pdu, data=b'', aux_ptr=None)
        capacity = pdu.data_capacity()
        if len(remaining) > capacity:
            if first.mode == AdvertisingMode.CONNECTABLE:
                raise ValueError('connectable advertising data must fit one PDU')
            pdu = replace(
                pdu, aux_ptr=AuxPtr(channel, RADIO_AUX_OFFSET_DEFAULT_US, phy)
            )
            capacity = pdu.data_capacity()
        count = min(len(remaining), capacity)
        chunk, remaining = bytes(remaining[:count]), remaining[count:]
        pdu = replace(pdu, data=chunk, aux_ptr=None)
        if remaining:
            probe = replace(
                pdu, aux_ptr=AuxPtr(channel, RADIO_AUX_OFFSET_DEFAULT_US, phy)
            ).encode()
            pdu = replace(
                pdu, aux_ptr=AuxPtr(channel, auxiliary_offset(probe, phy), phy)
            )
        result.append(pdu)
        if not remaining:
            return result
        pdu = ExtendedPdu(adi=first.adi)


def auxiliary_pdu(item: Advertising, sync: SyncInfo | None = None) -> ExtendedPdu:
    return ExtendedPdu(
        address=None if item.anonymous else bytes(item.address),
        random_address=not item.anonymous and item.address.is_random,
        target=bytes(item.target) if item.target else None,
        random_target=bool(item.target and item.target.is_random),
        adi=item.sid << PDU_ADV_ADI_DID_BITS | item.did,
        mode=item.mode,
        sync_info=sync,
        tx_power=item.tx_power_dbm if item.include_tx_power else None,
    )


def chain_time_us(packets, phy: Phy) -> int:
    return sum(packet.aux_ptr.offset_us for packet in packets[:-1]) + phy.airtime_us(
        len(packets[-1].encode())
    )


def periodic_time_us(item: Advertising) -> int:
    return chain_time_us(
        fragments(ExtendedPdu(), item.periodic_data, 0, item.secondary_phy),
        item.secondary_phy,
    )


def primary_offset_us(item: Advertising) -> int:
    primary = ExtendedPdu(
        mode=item.mode,
        adi=item.sid << PDU_ADV_ADI_DID_BITS | item.did,
        aux_ptr=AuxPtr(0, RADIO_AUX_OFFSET_DEFAULT_US, item.secondary_phy),
    ).encode()
    return align_offset_us(
        max(
            RADIO_AUX_OFFSET_DEFAULT_US,
            item.channel_map.bit_count() * item.primary_phy.airtime_us(len(primary))
            + (item.channel_map.bit_count() - 1) * RADIO_SWITCH_TIME_US
            + LL_MAFS_US,
        )
    )


def advertising_time_us(item: Advertising) -> int:
    if not item.extended:
        return 0
    sync = (
        SyncInfo(
            PDU_ADV_OFFSET_UNIT_30_US,
            max(LL_PERIODIC_INTERVAL_MIN, item.periodic_interval),
            LL_DATA_CHANNEL_MAP_ALL,
            item.periodic_aa,
            item.periodic_crc,
            0,
        )
        if item.periodic_enabled
        else None
    )
    data = b'' if item.mode == AdvertisingMode.SCANNABLE else item.data
    phy = item.secondary_phy
    duration = primary_offset_us(item) + chain_time_us(
        fragments(auxiliary_pdu(item, sync), data, 0, phy), phy
    )
    if item.mode == AdvertisingMode.SCANNABLE:
        response = ExtendedPdu(address=bytes(item.address))
        duration += (
            2 * LL_IFS_US
            + phy.airtime_us(PDU_ADV_SCAN_REQ_SIZE)
            + chain_time_us(fragments(response, item.scan_response, 0, phy), phy)
        )
    elif item.mode == AdvertisingMode.CONNECTABLE:
        duration += (
            2 * LL_IFS_US
            + phy.airtime_us(PDU_ADV_CONNECT_SIZE)
            + phy.airtime_us(PDU_ADV_AUX_CONNECT_RSP_SIZE)
        )
    return duration


class ExtendedProcedures:
    def __init__(self, link: RadioLink):
        self.link = link

    async def transmit_chain(self, channel, first, data, start, phy, **parameters):
        for pdu in fragments(first, data, channel, phy):
            await self.link._transmit(
                channel, pdu.encode(), start_us=start, phy=phy, **parameters
            )
            if pdu.aux_ptr:
                start += pdu.aux_ptr.offset_us

    async def follow(self, packet: Received, ext: ExtendedPdu, **parameters):
        aux = ext.aux_ptr
        assert aux is not None
        start = packet.start_us + aux.offset_us
        phy = Phy(aux.phy)
        widening = window_widening(
            aux.offset_us, LL_SCA_50_PPM if aux.clock_accuracy else LL_SCA_500_PPM
        )
        unit = aux.unit_us
        if start + unit <= packet.end_us + LL_MAFS_US:
            return None
        until = start + widening + unit + phy.address_us
        if until <= self.link.now_us or not self.link.fits_radio(until):
            return None
        received = await self.link.radio.receive(
            aux.channel,
            until,
            start_us=max(self.link.now_us + 1, start - widening),
            phy=phy,
            **parameters,
        )
        return (
            received
            if received and received.start_us >= packet.end_us + LL_MAFS_US
            else None
        )

    async def collect(
        self, packet: Received, first: ExtendedPdu, *, on_fragment=None, **parameters
    ):
        """Return whole-PDU data, completion status and the last received TxPower."""
        data = first.data
        current = first
        total = len(data)
        status = AdvertisingReport.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME
        while current.aux_ptr:
            if current.aux_ptr.phy != packet.phy:
                break
            if on_fragment is not None and data:
                on_fragment(
                    data,
                    AdvertisingReport.DATA_INCOMPLETE_MORE_TO_COME,
                    packet,
                )
                data = b''
            received = await self.follow(packet, current, **parameters)
            if received is None:
                break
            try:
                ext = ExtendedPdu.decode(received.pdu)
            except ValueError:
                break
            if (
                ext.kind != AdvertisingPduType.AUX_CHAIN_IND
                or ext.mode
                or (first.adi is not None and ext.adi != first.adi)
            ):
                break
            if ext.aux_ptr and not ext.data:
                break
            # Core Vol6 PartB Table2.7:chain addresses/SyncInfo/ACAD are ignored.
            current = ext
            if total + len(ext.data) > HCI_LE_ADV_DATA_SIZE_MAX:
                break
            data += ext.data
            total += len(ext.data)
            packet = received
        else:
            status = AdvertisingReport.DATA_COMPLETE
        return (
            data,
            status,
            (
                current.tx_power
                if current.tx_power is not None
                else AdvertisingReport.TX_POWER_INFORMATION_NOT_AVAILABLE
            ),
        )

    async def advertise(self, item: Advertising) -> None:
        link = self.link
        start = link.radio.earliest_start_us(
            next(
                channel
                for bit, channel in enumerate(LL_ADV_PRIMARY_CHANNELS)
                if item.channel_map & (1 << bit)
            ),
            item.primary_phy,
            transmit=True,
        )
        aux_channel = item.did % LL_DATA_CHANNEL_COUNT
        aux_start = start + primary_offset_us(item)
        info = (
            SyncInfo(
                item.periodic_next_us - aux_start,
                item.periodic_interval,
                LL_DATA_CHANNEL_MAP_ALL,
                item.periodic_aa,
                item.periodic_crc,
                item.periodic_counter,
            )
            if item.periodic_enabled
            else None
        )
        # All enabled primary channels point to one auxiliary event, not three
        # independent copies of the advertising data chain.
        for bit, channel in enumerate(LL_ADV_PRIMARY_CHANNELS):
            if not item.channel_map & (1 << bit):
                continue
            start = link.radio.earliest_start_us(
                channel, item.primary_phy, transmit=True
            )
            offset = (
                (aux_start - start)
                // PDU_ADV_OFFSET_UNIT_30_US
                * PDU_ADV_OFFSET_UNIT_30_US
            )
            primary = ExtendedPdu(
                mode=item.mode,
                adi=item.sid << PDU_ADV_ADI_DID_BITS | item.did,
                aux_ptr=AuxPtr(aux_channel, offset, item.secondary_phy),
            )
            await link._transmit(
                channel,
                primary.encode(),
                start_us=start,
                phy=item.primary_phy,
                power_dbm=item.tx_power_dbm,
            )
        await self.transmit_chain(
            aux_channel,
            auxiliary_pdu(item, info),
            b'' if item.mode == AdvertisingMode.SCANNABLE else item.data,
            aux_start,
            item.secondary_phy,
            power_dbm=item.tx_power_dbm,
        )
        if item.mode:
            packet = await link.receive_response(
                aux_channel,
                link.now_us + 1,
                item.secondary_phy,
            )
            if packet:
                await self.request(item, aux_channel, packet)

    async def request(self, item: Advertising, channel: int, packet: Received) -> bool:
        link, pdu = self.link, packet.pdu
        peer = advertising_request_peer(pdu, item.address, item.target)
        if peer is None:
            return False
        if (
            item.mode == AdvertisingMode.SCANNABLE
            and pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.SCAN_REQ
            and len(pdu) == PDU_ADV_SCAN_REQ_SIZE
        ):
            if (
                item.filter_policy & HCI_LE_ADV_FILTER_SCAN_MASK
                and peer not in link.accept_list
            ):
                return False
            if item.notify_scan_request:
                link.listener.on_scan_request(item, peer)
            await self.transmit_chain(
                channel,
                ExtendedPdu(
                    address=bytes(item.address),
                    random_address=item.address.is_random,
                ),
                item.scan_response,
                packet.end_us + LL_IFS_US,
                item.secondary_phy,
                power_dbm=item.tx_power_dbm,
            )
        elif (
            item.mode == AdvertisingMode.CONNECTABLE
            and pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.CONNECT_IND
            and len(pdu) == PDU_ADV_CONNECT_SIZE
        ):
            if not link.can_connect(peer):
                return False
            if (
                item.target is None
                and item.filter_policy & HCI_LE_ADV_FILTER_CONNECT_MASK
                and peer not in link.accept_list
            ):
                return False
            try:
                parameters = Parameters.decode(pdu[PDU_ADV_ADDRESSES_END:])
            except ValueError:
                return False
            response = ExtendedPdu(
                kind=AdvertisingPduType.AUX_CONNECT_RSP,
                address=bytes(item.address),
                random_address=item.address.is_random,
                target=bytes(peer),
                random_target=peer.is_random,
            )
            await link._transmit(
                channel,
                response.encode(),
                start_us=packet.end_us + LL_IFS_US,
                phy=item.secondary_phy,
                power_dbm=item.tx_power_dbm,
            )
            link.create_connection(
                parameters,
                peer,
                Role.PERIPHERAL,
                packet.end_us,
                csa2=True,
                self_address=item.address,
                advertiser=item,
                window_delay_us=(
                    LL_CONN_AUX_WINDOW_DELAY_CODED_US
                    if packet.phy == Phy.LE_CODED
                    else LL_CONN_AUX_WINDOW_DELAY_UNCODED_US
                ),
                phy=packet.phy,
            )
            return True
        return False

    async def scan(self, packet: Received, *, initiating: bool = False) -> None:
        link = self.link
        # Primary SyncInfo,CTEInfo,ACAD and AdvData are context-reserved CEAP fields.
        primary = replace(
            ExtendedPdu.decode(packet.pdu), sync_info=None, cte=None, acad=b'', data=b''
        )
        if primary.kind != AdvertisingPduType.ADV_EXT_IND:
            return
        ext, received, channel = primary, packet, None
        if primary.aux_ptr:
            channel = primary.aux_ptr.channel
            received = await self.follow(packet, primary)
            if received is None:
                return
            ext = ExtendedPdu.decode(received.pdu)
            if (
                ext.kind != AdvertisingPduType.AUX_ADV_IND
                or ext.mode != primary.mode
                or (primary.adi is not None and ext.adi != primary.adi)
            ):
                return
            # Table 2.5 C.1/C.2: repeated auxiliary addresses are RFU.
            primary_addresses_valid = not primary.mode and packet.phy == Phy.LE_1M
            if primary_addresses_valid and primary.address is not None:
                ext = replace(
                    ext,
                    address=primary.address,
                    random_address=primary.random_address,
                )
            if primary_addresses_valid and primary.target is not None:
                ext = replace(
                    ext,
                    target=primary.target,
                    random_target=primary.random_target,
                )
        if ext.address is None and (ext.mode or ext.target is not None):
            return
        if channel is not None and ext.mode:
            # Core Table2.5 reserves AuxPtr/SyncInfo in connectable/scannable
            # AUX_ADV_IND.
            ext = replace(
                ext,
                aux_ptr=None,
                sync_info=None,
                data=b'' if ext.mode == AdvertisingMode.SCANNABLE else ext.data,
            )
        address = (
            Address(ext.address, AddressType(ext.random_address))
            if ext.address is not None
            else Address(bytes(PDU_ADV_ADDRESS_SIZE), AddressType.ANONYMOUS)
        )
        target = (
            Address(ext.target, AddressType(ext.random_target)) if ext.target else None
        )
        local = link.initiating if initiating else link.scan
        if target is not None and (local is None or target != local.address):
            return
        if initiating:
            item = link.initiating
            if item is None:
                return
            accepted = (
                address in link.accept_list
                if item.filter_policy
                else address == item.peer
            )
            if (
                ext.mode == AdvertisingMode.CONNECTABLE
                and channel is not None
                and accepted
            ):
                await self.initiate(channel, received, ext, address)
            return
        sid = (
            ext.adi >> PDU_ADV_ADI_DID_BITS
            if ext.adi is not None
            else AdvertisingReport.NO_ADI_FIELD_PROVIDED
        )
        info = ext.sync_info
        sync = link.sync
        if (
            sync
            and sync.info is None
            and info
            and not any(
                active.address == address and active.sid == sid
                for active in link.syncs.values()
            )
            and (
                (address, sid) in link.periodic_advertiser_list
                if sync.use_list
                else sync.address == address and sync.sid == sid
            )
        ):
            sync.address, sync.sid = address, sid
            sync.info, sync.next_us, sync.counter = (
                info,
                received.start_us + info.offset_us,
                info.event_counter,
            )
            sync.last_rx_us, sync.phy = received.start_us, received.phy
            sync.deadline_us = sync.next_us + (
                LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS
                * info.interval
                * LL_PERIODIC_INTERVAL_UNIT_US
            )
        if link.scan and link.scan.filter_policy and address not in link.accept_list:
            return
        data, status, tx_power = await self.collect(received, ext)
        flags = ext.mode | (
            AdvertisingReport.EventType.DIRECTED_ADVERTISING if target else 0
        )
        link.listener.on_advertisement(
            address,
            data,
            received.rssi,
            flags | status << HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT,
            sid,
            info.interval if info else 0,
            tx_power,
            target=target,
            primary_phy=packet.phy,
            secondary_phy=received.phy if channel is not None else 0,
        )
        if (
            link.scan
            and link.scan.active
            and ext.mode == AdvertisingMode.SCANNABLE
            and channel is not None
            and not ext.aux_ptr
            and link.scan.backoff.permit()
        ):
            scan = link.scan
            request = scan_request(scan.address, address)
            end_us = await link._transmit(
                channel, request, start_us=received.end_us + LL_IFS_US, phy=received.phy
            )
            response = await link.receive_response(channel, end_us, received.phy)
            if response:
                try:
                    rsp = ExtendedPdu.decode(response.pdu)
                except ValueError:
                    scan.backoff.complete(False, link.random)
                    return
                if (
                    rsp.kind == AdvertisingPduType.AUX_SCAN_RSP
                    and not rsp.mode
                    and rsp.address == ext.address
                    and rsp.random_address == ext.random_address
                    and (rsp.adi is None or rsp.adi == ext.adi)
                ):
                    scan.backoff.complete(True, link.random)
                    data, status, tx_power = await self.collect(response, rsp)
                    link.listener.on_advertisement(
                        address,
                        data,
                        response.rssi,
                        flags
                        | AdvertisingReport.EventType.SCAN_RESPONSE
                        | status << HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT,
                        sid,
                        0,
                        tx_power,
                        target=target,
                        primary_phy=packet.phy,
                        secondary_phy=received.phy,
                    )
                    return
            scan.backoff.complete(False, link.random)

    async def initiate(self, channel, packet, ext, address):
        link, item = self.link, self.link.initiating
        assert item is not None
        if not link.can_connect(address):
            return
        # Core Vol 4, Part E, 7.8.66 permits a supplied PHY's parameters as fallback.
        parameters = (item.phy_parameters or {}).get(packet.phy, item.parameters)
        window_delay = (
            LL_CONN_AUX_WINDOW_DELAY_CODED_US
            if packet.phy == Phy.LE_CODED
            else LL_CONN_AUX_WINDOW_DELAY_UNCODED_US
        )
        request_end = (
            packet.end_us + LL_IFS_US + packet.phy.airtime_us(PDU_ADV_CONNECT_SIZE)
        )
        parameters = link.connection_parameters(
            parameters, request_end, window_delay, packet.phy
        )
        if parameters is None or not link.fits_radio(
            request_end
            + LL_IFS_US
            + packet.phy.airtime_us(PDU_ADV_AUX_CONNECT_RSP_SIZE)
        ):
            return
        request = (
            bytes(
                [
                    AdvertisingPduType.CONNECT_IND
                    | (PDU_ADV_TXADD_MASK if item.address.is_random else 0)
                    | (PDU_ADV_RXADD_MASK if address.is_random else 0),
                    PDU_ADV_CONNECT_PAYLOAD_SIZE,
                ]
            )
            + bytes(item.address)
            + bytes(address)
            + parameters.encode()
        )
        request_end = await link._transmit(
            channel, request, start_us=packet.end_us + LL_IFS_US, phy=packet.phy
        )
        response = await link.receive_response(channel, request_end, packet.phy)
        if response is None:
            return
        rsp = ExtendedPdu.decode(response.pdu)
        if (
            rsp.kind != AdvertisingPduType.AUX_CONNECT_RSP
            or rsp.mode
            or rsp.address != ext.address
            or rsp.target != bytes(item.address)
            or rsp.random_address != ext.random_address
            or rsp.random_target != item.address.is_random
        ):
            return
        link.initiating = None
        link.create_connection(
            parameters,
            address,
            Role.CENTRAL,
            request_end,
            csa2=True,
            self_address=item.address,
            window_delay_us=window_delay,
            phy=packet.phy,
        )
