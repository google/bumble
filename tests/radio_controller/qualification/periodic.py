# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Independent periodic advertiser/observer derived from the on-air SyncInfo."""

import struct
from dataclasses import dataclass

from bumble import hci
from bumble.ll import (
    LL_CHANNEL_ID_BITS,
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    LL_MAFS_US,
    LL_PERIODIC_INTERVAL_UNIT_US,
    PDU_ADV_ADI_DID_BITS,
    PDU_ADV_EXT_HEADER_LENGTH_BITS,
    PDU_ADV_EXT_PAYLOAD_SIZE_MAX,
    PDU_ADV_OFFSET_UNIT_30_US,
    PDU_ADV_OFFSET_UNIT_300_US,
    PDU_ADV_OFFSET_VALUE_MASK,
    PDU_ADV_SYNC_INFO_SIZE,
    PDU_ADV_SYNC_OFFSET_ADJUST_MASK,
    PDU_ADV_SYNC_OFFSET_ADJUST_US,
    PDU_ADV_SYNC_OFFSET_UNITS_MASK,
    PDU_ADV_TYPE_MASK,
    PDU_HEADER_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import Phy
from tests.radio_controller.qualification.tester import (
    LOWER_PERIPHERAL_PUBLIC_ADDRESS,
    PEER_ADDRESS,
    LinkParameters,
    aux_pointer,
    chain,
    csa2_channel,
    csa2_mam,
    csa2_prn,
    decode_extended,
    ext_pdu,
)

# Selected preparation gap when a periodic PDU displaced an announcement.
ANNOUNCEMENT_GUARD_US = 100


def subevent_channels(counter, access_address, count=3):
    """Independent CSA#2 subevents for the selected all37-channel PAwR train."""
    channel_id, value = csa2_prn(counter, access_address)
    channel = (value ^ channel_id) % LL_DATA_CHANNEL_COUNT
    result = [channel]
    distance = max(
        1, min(3, LL_DATA_CHANNEL_COUNT - 5), min(11, (LL_DATA_CHANNEL_COUNT - 10) // 2)
    )
    for _ in range(count - 1):
        value = csa2_mam(value, channel_id)
        channel = (
            channel
            + distance
            + (
                (value ^ channel_id) * (LL_DATA_CHANNEL_COUNT - 2 * distance + 1)
                >> LL_CHANNEL_ID_BITS
            )
        ) % LL_DATA_CHANNEL_COUNT
        result.append(channel)
    return result


@dataclass
class PeriodicTrain:
    anchor: int
    interval: int = 80
    counter: int = 0
    access_address: int = LinkParameters.access_address
    crc_init: int = LinkParameters.crc_init
    channel_map: int = LL_DATA_CHANNEL_MAP_ALL
    phy: Phy = Phy.LE_1M
    offset_unit: int = PDU_ADV_OFFSET_UNIT_30_US

    @classmethod
    def from_advertisement(cls, packet, fields):
        offset, interval, channels, aa, crc, counter = struct.unpack(
            '<HH5sI3sH', fields['sync']
        )
        unit = (
            PDU_ADV_OFFSET_UNIT_300_US
            if offset & PDU_ADV_SYNC_OFFSET_UNITS_MASK
            else PDU_ADV_OFFSET_UNIT_30_US
        )
        delay = (offset & PDU_ADV_OFFSET_VALUE_MASK) * unit
        if offset & PDU_ADV_SYNC_OFFSET_ADJUST_MASK:
            delay += PDU_ADV_SYNC_OFFSET_ADJUST_US
        return cls(
            packet.start_us + delay,
            interval,
            counter,
            aa,
            int.from_bytes(crc, 'little'),
            int.from_bytes(channels, 'little') & LL_DATA_CHANNEL_MAP_ALL,
            packet.phy,
            unit,
        )

    @property
    def channel(self):
        return csa2_channel(self.counter, self.access_address, self.channel_map)

    @property
    def parameters(self):
        return {
            'access_address': self.access_address,
            'crc_init': self.crc_init,
            'phy': self.phy,
        }

    def next_event(self):
        self.anchor += self.interval * LL_PERIODIC_INTERVAL_UNIT_US
        self.counter = (self.counter + 1) & LL_EVENT_COUNTER_MASK

    async def receive(self, tester, *, required=True):
        packet = await tester.receive(
            self.channel,
            start_us=max(tester.radio.now_us + 1, self.anchor - 1),
            duration_us=max(1000, self.anchor - tester.radio.now_us + 3000),
            **self.parameters,
        )
        if packet is None:
            assert not required, f'periodic PDU absent: {self}'
            self.next_event()
            return None
        assert packet.valid_crc
        assert packet.phy == self.phy
        assert packet.pdu[0] & PDU_ADV_TYPE_MASK == AdvertisingPduType.ADV_EXT_IND
        assert self.anchor <= packet.start_us < self.anchor + self.offset_unit
        assert packet.pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS == (
            AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
        )
        fields = decode_extended(packet.pdu)
        assert (
            'address' not in fields and 'target' not in fields and 'sync' not in fields
        )
        assert 'adi' not in fields
        payload = await chain(
            tester, packet, fields, expected_phy=self.phy, **self.parameters
        )
        self.anchor = packet.start_us
        self.next_event()
        return payload

    async def transmit(self, tester, data=b'periodic'):
        for offset, wire in self.packets(data):
            await tester.transmit(
                self.channel,
                wire,
                start_us=self.anchor + offset,
                **self.parameters,
            )
        self.next_event()

    def packets(self, data):
        """Pack independent AUX_SYNC/CHAIN PDUs with full nonfinal payloads."""
        offset = consumed = 0
        while True:
            more = len(data) - consumed > (
                PDU_ADV_EXT_PAYLOAD_SIZE_MAX - len(ext_pdu()) + PDU_HEADER_SIZE
            )
            pointer = aux_pointer(self.channel, PDU_ADV_OFFSET_UNIT_30_US, self.phy)
            fields = {'aux': pointer} if more else {}
            capacity = (
                PDU_ADV_EXT_PAYLOAD_SIZE_MAX - len(ext_pdu(**fields)) + PDU_HEADER_SIZE
            )
            chunk = data[consumed : consumed + capacity]
            if more:
                duration = self.phy.airtime_us(len(ext_pdu(**fields, data=chunk)))
                distance = (
                    (duration + LL_MAFS_US + PDU_ADV_OFFSET_UNIT_30_US - 1)
                    // PDU_ADV_OFFSET_UNIT_30_US
                    * PDU_ADV_OFFSET_UNIT_30_US
                )
                fields['aux'] = aux_pointer(self.channel, distance, self.phy)
            yield offset, ext_pdu(**fields, data=chunk)
            consumed += len(chunk)
            if not more:
                break
            offset += distance

    def sync_info(self, reference_us):
        """Encode SyncInfo independently, including long-offset units/adjustment."""
        delay = self.anchor - reference_us
        adjustment = 0
        if delay > PDU_ADV_OFFSET_VALUE_MASK * PDU_ADV_OFFSET_UNIT_300_US:
            delay -= PDU_ADV_SYNC_OFFSET_ADJUST_US
            adjustment = PDU_ADV_SYNC_OFFSET_ADJUST_MASK
        unit = (
            PDU_ADV_OFFSET_UNIT_30_US
            if delay < (PDU_ADV_OFFSET_VALUE_MASK + 1) * PDU_ADV_OFFSET_UNIT_30_US
            else PDU_ADV_OFFSET_UNIT_300_US
        )
        offset = delay // unit
        assert 0 < offset <= PDU_ADV_OFFSET_VALUE_MASK, (
            self.anchor,
            reference_us,
            delay,
            unit,
        )
        encoded_offset = offset | adjustment
        if unit == PDU_ADV_OFFSET_UNIT_300_US:
            encoded_offset |= PDU_ADV_SYNC_OFFSET_UNITS_MASK
        return struct.pack(
            '<HH5sI3sH',
            encoded_offset,
            self.interval,
            self.channel_map.to_bytes(5, 'little'),
            self.access_address,
            self.crc_init.to_bytes(3, 'little'),
            self.counter,
        )

    async def announce(
        self,
        tester,
        *,
        sid=3,
        start=None,
        primary_phy=Phy.LE_1M,
        primary_channel=37,
        address=PEER_ADDRESS,
        auxiliary_offset=600,
        acad=b'',
    ):
        start = tester.radio.now_us + 100 if start is None else start
        auxiliary = start + auxiliary_offset
        sync = self.sync_info(auxiliary)
        pointer = aux_pointer(0, auxiliary - start, self.phy)
        await tester.transmit(
            primary_channel,
            ext_pdu(adi=sid << 12, aux=pointer),
            start_us=start,
            phy=primary_phy,
        )
        await tester.transmit(
            0,
            ext_pdu(
                address=address,
                adi=sid << 12,
                sync=sync,
                data=b'announcement',
                acad=acad,
            ),
            start_us=auxiliary,
            phy=self.phy,
        )


@dataclass
class PeriodicAdvertiser:
    """Interleave one independent periodic train with its extended announcements."""

    train: PeriodicTrain
    next_advertisement: int
    advertising_interval_us: int
    sid: int = 3
    address: hci.Address = LOWER_PERIPHERAL_PUBLIC_ADDRESS
    auxiliary_offset_us: int = 600
    advertising: bool = True
    primary_phy: Phy = Phy.LE_1M
    acad: bytes = b''

    async def announce_until(self, tester, target):
        announcement = ext_pdu(
            address=self.address,
            adi=self.sid << PDU_ADV_ADI_DID_BITS,
            sync=bytes(PDU_ADV_SYNC_INFO_SIZE),
            data=b'announcement',
            acad=self.acad,
        )
        budget = (
            self.auxiliary_offset_us
            + self.train.phy.airtime_us(len(announcement))
            + LL_MAFS_US
        )
        while self.advertising and self.next_advertisement + budget < target:
            start = max(
                self.next_advertisement, tester.radio.now_us + ANNOUNCEMENT_GUARD_US
            )
            if start + budget >= target:
                break
            await self.train.announce(
                tester,
                start=start,
                sid=self.sid,
                address=self.address,
                auxiliary_offset=self.auxiliary_offset_us,
                primary_phy=self.primary_phy,
                acad=self.acad,
            )
            self.next_advertisement = start + self.advertising_interval_us

    async def transmit(self, tester, data):
        await self.announce_until(tester, self.train.anchor)
        await self.train.transmit(tester, data)
