# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Legacy primary-channel advertising, scanning and initiating RF procedures.

These stateless operations execute on the owning link's one radio and use its
admission and lifetime transitions. They never start an independent task.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from bumble.hci import (
    HCI_LE_ADV_FILTER_CONNECT_MASK,
    HCI_LE_ADV_FILTER_SCAN_MASK,
    Address,
    AddressType,
)
from bumble.hci import HCI_LE_Extended_Advertising_Report_Event as AdvertisingReport
from bumble.hci import Role
from bumble.ll import (
    LL_ADV_PRIMARY_CHANNELS,
    LL_CONN_INTERVAL_UNIT_US,
    LL_IFS_US,
    PDU_ADV_ADDRESS_OFFSET,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_ADDRESSES_END,
    PDU_ADV_CHSEL_MASK,
    PDU_ADV_CONNECT_PAYLOAD_SIZE,
    PDU_ADV_CONNECT_SIZE,
    PDU_ADV_DIRECT_SIZE,
    PDU_ADV_LEGACY_SIZE_MAX,
    PDU_ADV_LEGACY_SIZE_MIN,
    PDU_ADV_RXADD_MASK,
    PDU_ADV_SCAN_REQ_SIZE,
    PDU_ADV_SECOND_ADDRESS_OFFSET,
    PDU_ADV_TXADD_MASK,
    PDU_ADV_TYPE_MASK,
    PDU_HEADER_SIZE,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import (
    RADIO_RESPONSE_START_TOLERANCE_US,
    RADIO_SWITCH_TIME_US,
    Phy,
    Received,
)
from bumble.radio_controller.radio_advertising import (
    advertising_request_peer,
    scan_request,
)
from bumble.radio_controller.radio_discovery import Advertising
from bumble.radio_controller.radio_extended import advertising_time_us
from bumble.radio_controller.radio_parameters import Parameters

if TYPE_CHECKING:
    from bumble.radio_controller.radio_link import RadioLink


def advertising_event_time_us(item: Advertising) -> int:
    """Reserve a complete primary event, including possible request exchanges."""
    if item.extended:
        return advertising_time_us(item) + (
            RADIO_RESPONSE_START_TOLERANCE_US if item.mode else 0
        )
    payload_size = (
        PDU_HEADER_SIZE
        + PDU_ADV_ADDRESS_SIZE
        + (PDU_ADV_ADDRESS_SIZE if item.target else len(item.data))
    )
    response_us = 0
    if item.pdu_type in (
        AdvertisingPduType.ADV_IND,
        AdvertisingPduType.ADV_SCAN_IND,
    ):
        response_us = (
            2 * LL_IFS_US
            + RADIO_RESPONSE_START_TOLERANCE_US
            + Phy.LE_1M.airtime_us(PDU_ADV_SCAN_REQ_SIZE)
            + Phy.LE_1M.airtime_us(
                PDU_HEADER_SIZE + PDU_ADV_ADDRESS_SIZE + len(item.scan_response)
            )
        )
    elif item.pdu_type == AdvertisingPduType.ADV_DIRECT_IND:
        response_us = (
            LL_IFS_US
            + RADIO_RESPONSE_START_TOLERANCE_US
            + Phy.LE_1M.airtime_us(PDU_ADV_CONNECT_SIZE)
        )
    return item.channel_map.bit_count() * (
        Phy.LE_1M.airtime_us(payload_size) + RADIO_SWITCH_TIME_US + response_us
    )


async def advertising_request(
    link: RadioLink, item: Advertising, channel: int, packet: Received
) -> bool:
    pdu = packet.pdu
    peer = advertising_request_peer(pdu, item.address, item.target)
    if peer is None:
        return False
    if (
        item.pdu_type in (AdvertisingPduType.ADV_IND, AdvertisingPduType.ADV_SCAN_IND)
        and pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.SCAN_REQ
        and len(pdu) == PDU_ADV_SCAN_REQ_SIZE
    ):
        if (
            item.filter_policy & HCI_LE_ADV_FILTER_SCAN_MASK
            and peer not in link.accept_list
        ):
            return False
        payload = bytes(item.address) + item.scan_response
        await link._transmit(
            channel,
            bytes(
                [
                    AdvertisingPduType.SCAN_RSP
                    | (PDU_ADV_TXADD_MASK if item.address.is_random else 0),
                    len(payload),
                ]
            )
            + payload,
            start_us=packet.end_us + LL_IFS_US,
            power_dbm=item.tx_power_dbm,
        )
    elif (
        item.pdu_type in (AdvertisingPduType.ADV_IND, AdvertisingPduType.ADV_DIRECT_IND)
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
        except ValueError as error:
            link.trace(f'LL CONNECT REJECTED {error}')
            return False
        link.create_connection(
            parameters,
            peer,
            Role.PERIPHERAL,
            packet.end_us,
            csa2=bool(pdu[0] & PDU_ADV_CHSEL_MASK),
            self_address=item.address,
            advertiser=item,
        )
        return True
    return False


async def initiate(link: RadioLink, channel: int, packet: Received) -> None:
    item = link.initiating
    pdu = packet.pdu
    if pdu and pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND:
        await link._scan_extended(packet, initiating=True)
        return
    if (
        item is None
        or len(pdu) < PDU_ADV_LEGACY_SIZE_MIN
        or pdu[0] & PDU_ADV_TYPE_MASK
        not in (AdvertisingPduType.ADV_IND, AdvertisingPduType.ADV_DIRECT_IND)
        or pdu[1] != len(pdu) - PDU_HEADER_SIZE
    ):
        return
    if pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_DIRECT_IND and (
        len(pdu) != PDU_ADV_DIRECT_SIZE
        or pdu[PDU_ADV_SECOND_ADDRESS_OFFSET:PDU_ADV_ADDRESSES_END]
        != bytes(item.address)
        or bool(pdu[0] & PDU_ADV_RXADD_MASK) != item.address.is_random
    ):
        return
    peer = Address(
        pdu[PDU_ADV_ADDRESS_OFFSET:PDU_ADV_SECOND_ADDRESS_OFFSET],
        AddressType(bool(pdu[0] & PDU_ADV_TXADD_MASK)),
    )
    if peer not in link.accept_list if item.filter_policy else peer != item.peer:
        return
    if not link.can_connect(peer):
        return
    request_end = packet.end_us + LL_IFS_US + Phy.LE_1M.airtime_us(PDU_ADV_CONNECT_SIZE)
    parameters = link.connection_parameters(
        item.parameters, request_end, LL_CONN_INTERVAL_UNIT_US
    )
    if parameters is None:
        return
    csa2 = bool(pdu[0] & PDU_ADV_CHSEL_MASK)
    header = (
        AdvertisingPduType.CONNECT_IND
        | (PDU_ADV_CHSEL_MASK if csa2 else 0)
        | (PDU_ADV_TXADD_MASK if item.address.is_random else 0)
        | (PDU_ADV_RXADD_MASK if peer.is_random else 0)
    )
    pdu = (
        bytes([header, PDU_ADV_CONNECT_PAYLOAD_SIZE])
        + bytes(item.address)
        + bytes(peer)
        + parameters.encode()
    )
    end_us = await link._transmit(channel, pdu, start_us=packet.end_us + LL_IFS_US)
    link.initiating = None
    link.create_connection(
        parameters,
        peer,
        Role.CENTRAL,
        end_us,
        csa2=csa2,
        self_address=item.address,
    )


async def scan_packet(link: RadioLink, channel: int, packet: Received) -> None:
    pdu = packet.pdu
    if len(pdu) < PDU_HEADER_SIZE or pdu[1] != len(pdu) - PDU_HEADER_SIZE:
        return
    if pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND:
        await link._scan_extended(packet)
        return
    flags = AdvertisingReport.EventType
    types: dict[int, AdvertisingReport.EventType] = {
        AdvertisingPduType.ADV_IND: flags.LEGACY_ADVERTISING_PDU_USED
        | flags.CONNECTABLE_ADVERTISING
        | flags.SCANNABLE_ADVERTISING,
        AdvertisingPduType.ADV_DIRECT_IND: flags.LEGACY_ADVERTISING_PDU_USED
        | flags.CONNECTABLE_ADVERTISING
        | flags.DIRECTED_ADVERTISING,
        AdvertisingPduType.ADV_NONCONN_IND: flags.LEGACY_ADVERTISING_PDU_USED,
        AdvertisingPduType.ADV_SCAN_IND: flags.LEGACY_ADVERTISING_PDU_USED
        | flags.SCANNABLE_ADVERTISING,
    }
    if (
        not PDU_ADV_LEGACY_SIZE_MIN <= len(pdu) <= PDU_ADV_LEGACY_SIZE_MAX
        or pdu[0] & PDU_ADV_TYPE_MASK not in types
    ):
        return
    address = Address(
        pdu[PDU_ADV_ADDRESS_OFFSET:PDU_ADV_SECOND_ADDRESS_OFFSET],
        AddressType(bool(pdu[0] & PDU_ADV_TXADD_MASK)),
    )
    if link.scan and link.scan.filter_policy and address not in link.accept_list:
        return
    if pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_DIRECT_IND:
        if len(pdu) != PDU_ADV_DIRECT_SIZE or link.scan is None:
            return
        target = Address(
            pdu[PDU_ADV_SECOND_ADDRESS_OFFSET:PDU_ADV_ADDRESSES_END],
            AddressType(bool(pdu[0] & PDU_ADV_RXADD_MASK)),
        )
        if target != link.scan.address:
            return
        link.listener.on_advertisement(
            address,
            b'',
            packet.rssi,
            types[AdvertisingPduType.ADV_DIRECT_IND],
            AdvertisingReport.NO_ADI_FIELD_PROVIDED,
            0,
            AdvertisingReport.TX_POWER_INFORMATION_NOT_AVAILABLE,
            target=target,
        )
        return
    link.listener.on_advertisement(
        address,
        pdu[PDU_ADV_SECOND_ADDRESS_OFFSET:],
        packet.rssi,
        types[pdu[0] & PDU_ADV_TYPE_MASK],
        AdvertisingReport.NO_ADI_FIELD_PROVIDED,
        0,
        AdvertisingReport.TX_POWER_INFORMATION_NOT_AVAILABLE,
    )
    if (
        link.scan
        and link.scan.active
        and pdu[0] & PDU_ADV_TYPE_MASK
        in (AdvertisingPduType.ADV_IND, AdvertisingPduType.ADV_SCAN_IND)
        and link.scan.backoff.permit()
    ):
        request = scan_request(link.scan.address, address)
        end_us = await link._transmit(
            channel, request, start_us=packet.end_us + LL_IFS_US
        )
        response = await link.receive_response(channel, end_us)
        success = bool(
            response
            and PDU_ADV_LEGACY_SIZE_MIN <= len(response.pdu) <= PDU_ADV_LEGACY_SIZE_MAX
            and response.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.SCAN_RSP
            and response.pdu[1] == len(response.pdu) - PDU_HEADER_SIZE
            and response.pdu[PDU_ADV_ADDRESS_OFFSET:PDU_ADV_SECOND_ADDRESS_OFFSET]
            == bytes(address)
            and bool(response.pdu[0] & PDU_ADV_TXADD_MASK) == address.is_random
        )
        link.scan.backoff.complete(success, link.random)
        if success and response is not None:
            link.listener.on_advertisement(
                address,
                response.pdu[PDU_ADV_SECOND_ADDRESS_OFFSET:],
                response.rssi,
                types[pdu[0] & PDU_ADV_TYPE_MASK] | flags.SCAN_RESPONSE,
                AdvertisingReport.NO_ADI_FIELD_PROVIDED,
                0,
                AdvertisingReport.TX_POWER_INFORMATION_NOT_AVAILABLE,
            )


async def scan_extended(
    link: RadioLink, packet: Received, *, initiating: bool = False
) -> None:
    try:
        await link.extended.scan(packet, initiating=initiating)
    except ValueError as error:
        link.trace(f'LL EXTENDED REJECTED {error}')


async def advertise_legacy(link: RadioLink, item: Advertising) -> None:
    payload = bytes(item.address) + (bytes(item.target) if item.target else item.data)
    chsel = (
        PDU_ADV_CHSEL_MASK
        if item.pdu_type
        in (AdvertisingPduType.ADV_IND, AdvertisingPduType.ADV_DIRECT_IND)
        else 0
    )
    pdu = (
        bytes(
            [
                item.pdu_type
                | chsel
                | (PDU_ADV_TXADD_MASK if item.address.is_random else 0)
                | (PDU_ADV_RXADD_MASK if item.target and item.target.is_random else 0),
                len(payload),
            ]
        )
        + payload
    )
    for bit, channel in enumerate(LL_ADV_PRIMARY_CHANNELS):
        if item.channel_map & (1 << bit):
            if (
                item.high_duty
                and link.now_us + 1 + Phy.LE_1M.airtime_us(len(pdu)) > item.deadline_us
            ):
                await link.radio.advance_to_us(item.deadline_us)
                break
            end_us = await link._transmit(channel, pdu, power_dbm=item.tx_power_dbm)
            if item.pdu_type in (
                AdvertisingPduType.ADV_IND,
                AdvertisingPduType.ADV_DIRECT_IND,
                AdvertisingPduType.ADV_SCAN_IND,
            ):
                packet = await link.receive_response(
                    channel,
                    end_us,
                    deadline_us=item.deadline_us if item.high_duty else None,
                )
                if packet and await link._advertising_request(item, channel, packet):
                    break
