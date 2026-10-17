# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Advertising request codecs and extended/periodic wire formats, Core 6.B.2.3."""

import struct
from dataclasses import dataclass, field

from bumble.hci import Address, AddressType
from bumble.ll import (
    LL_CHANNEL_MAP_SIZE,
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_MAP_ALL,
    LL_EVENT_COUNTER_MASK,
    LL_PERIODIC_INTERVAL_MAX,
    LL_PERIODIC_INTERVAL_MIN,
    LL_SCA_50_PPM,
    LL_SCA_MAX,
    PDU_ACCESS_ADDRESS_SIZE,
    PDU_ADV_ADDRESS_OFFSET,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_ADDRESSES_END,
    PDU_ADV_ADI_SIZE,
    PDU_ADV_AUX_CA_MASK,
    PDU_ADV_AUX_CHANNEL_MASK,
    PDU_ADV_AUX_OFFSET_PHY_SIZE,
    PDU_ADV_AUX_OFFSET_UNITS_MASK,
    PDU_ADV_AUX_PTR_SIZE,
    PDU_ADV_CTE_INFO_SIZE,
    PDU_ADV_EXT_FIELDS_OFFSET,
    PDU_ADV_EXT_HEADER_LENGTH_BITS,
    PDU_ADV_EXT_HEADER_OFFSET,
    PDU_ADV_EXT_HEADER_SIZE_MAX,
    PDU_ADV_EXT_MODE_RESERVED,
    PDU_ADV_EXT_PAYLOAD_SIZE_MAX,
    PDU_ADV_OFFSET_30_RANGE_US,
    PDU_ADV_OFFSET_BITS,
    PDU_ADV_OFFSET_UNIT_30_US,
    PDU_ADV_OFFSET_UNIT_300_US,
    PDU_ADV_OFFSET_VALUE_MASK,
    PDU_ADV_RXADD_MASK,
    PDU_ADV_SCAN_REQ_PAYLOAD_SIZE,
    PDU_ADV_SCAN_REQ_SIZE,
    PDU_ADV_SECOND_ADDRESS_OFFSET,
    PDU_ADV_SYNC_ACCESS_ADDRESS_OFFSET,
    PDU_ADV_SYNC_CHANNEL_MAP_OFFSET,
    PDU_ADV_SYNC_CRC_INIT_OFFSET,
    PDU_ADV_SYNC_EVENT_COUNTER_OFFSET,
    PDU_ADV_SYNC_EVENT_COUNTER_SIZE,
    PDU_ADV_SYNC_INFO_SIZE,
    PDU_ADV_SYNC_OFFSET_ADJUST_MASK,
    PDU_ADV_SYNC_OFFSET_ADJUST_US,
    PDU_ADV_SYNC_OFFSET_UNITS_MASK,
    PDU_ADV_TX_POWER_SIZE,
    PDU_ADV_TXADD_MASK,
    PDU_ADV_TYPE_MASK,
    PDU_CRC_SIZE,
    PDU_HEADER_SIZE,
    AdvertisingMode,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import Phy
from bumble.radio_controller.radio_parameters import valid_channel_map


def advertising_request_peer(
    pdu: bytes, advertiser: Address, target: Address | None
) -> Address | None:
    """Validate the common SCAN_REQ/CONNECT_IND addresses before interpreting LLData."""
    if (
        len(pdu) < PDU_ADV_SCAN_REQ_SIZE
        or pdu[1] != len(pdu) - PDU_HEADER_SIZE
        or pdu[PDU_ADV_SECOND_ADDRESS_OFFSET:PDU_ADV_ADDRESSES_END] != bytes(advertiser)
        or bool(pdu[0] & PDU_ADV_RXADD_MASK) != advertiser.is_random
    ):
        return None
    peer = Address(
        pdu[PDU_ADV_ADDRESS_OFFSET:PDU_ADV_SECOND_ADDRESS_OFFSET],
        AddressType(bool(pdu[0] & PDU_ADV_TXADD_MASK)),
    )
    return peer if target is None or peer == target else None


def scan_request(scanner: Address, advertiser: Address) -> bytes:
    return (
        bytes(
            [
                AdvertisingPduType.SCAN_REQ
                | (PDU_ADV_TXADD_MASK if scanner.is_random else 0)
                | (PDU_ADV_RXADD_MASK if advertiser.is_random else 0),
                PDU_ADV_SCAN_REQ_PAYLOAD_SIZE,
            ]
        )
        + bytes(scanner)
        + bytes(advertiser)
    )


def offset_unit_us(offset_us: int) -> int:
    return (
        PDU_ADV_OFFSET_UNIT_30_US
        if offset_us < PDU_ADV_OFFSET_30_RANGE_US
        else PDU_ADV_OFFSET_UNIT_300_US
    )


def align_offset_us(offset_us: int) -> int:
    unit = offset_unit_us(offset_us)
    rounded = (offset_us + unit - 1) // unit * unit
    unit = offset_unit_us(rounded)
    return (offset_us + unit - 1) // unit * unit


@dataclass(frozen=True)
class AuxPtr:
    channel: int
    offset_us: int
    phy: int = Phy.LE_1M
    clock_accuracy: bool = True
    offset_unit: int | None = field(default=None, compare=False)

    @property
    def unit_us(self) -> int:
        return (
            self.offset_unit
            if self.offset_unit is not None
            else offset_unit_us(self.offset_us)
        )

    def encode(self) -> bytes:
        if not 0 <= self.channel <= LL_DATA_CHANNEL_COUNT - 1 or self.phy not in tuple(
            Phy
        ):
            raise ValueError('invalid AuxPtr channel or PHY')
        unit = self.unit_us
        if unit not in (PDU_ADV_OFFSET_UNIT_30_US, PDU_ADV_OFFSET_UNIT_300_US):
            raise ValueError('invalid AuxPtr offset unit')
        offset = self.offset_us // unit
        if not 1 <= offset <= PDU_ADV_OFFSET_VALUE_MASK:
            raise ValueError('invalid AuxPtr offset')
        return bytes(
            [
                self.channel
                | int(self.clock_accuracy) * PDU_ADV_AUX_CA_MASK
                | (
                    PDU_ADV_AUX_OFFSET_UNITS_MASK
                    if unit == PDU_ADV_OFFSET_UNIT_300_US
                    else 0
                )
            ]
        ) + (offset | (self.phy - 1) << PDU_ADV_OFFSET_BITS).to_bytes(
            PDU_ADV_AUX_OFFSET_PHY_SIZE, 'little'
        )

    @classmethod
    def decode(cls, data: bytes):
        if len(data) != PDU_ADV_AUX_PTR_SIZE:
            raise ValueError('invalid AuxPtr size')
        field = int.from_bytes(data[1:], 'little')
        result = cls(
            data[0] & PDU_ADV_AUX_CHANNEL_MASK,
            (field & PDU_ADV_OFFSET_VALUE_MASK)
            * (
                PDU_ADV_OFFSET_UNIT_300_US
                if data[0] & PDU_ADV_AUX_OFFSET_UNITS_MASK
                else PDU_ADV_OFFSET_UNIT_30_US
            ),
            (field >> PDU_ADV_OFFSET_BITS) + 1,
            bool(data[0] & PDU_ADV_AUX_CA_MASK),
            (
                PDU_ADV_OFFSET_UNIT_300_US
                if data[0] & PDU_ADV_AUX_OFFSET_UNITS_MASK
                else PDU_ADV_OFFSET_UNIT_30_US
            ),
        )
        result.encode()
        return result


@dataclass(frozen=True)
class SyncInfo:
    offset_us: int
    interval: int
    channel_map: int
    access_address: int
    crc_init: int
    event_counter: int
    sca: int = LL_SCA_50_PPM
    offset_unit: int | None = field(default=None, compare=False)

    @property
    def unit_us(self) -> int:
        return (
            self.offset_unit
            if self.offset_unit is not None
            else offset_unit_us(self.offset_us)
        )

    def encode(self) -> bytes:
        unit = self.unit_us
        if unit not in (PDU_ADV_OFFSET_UNIT_30_US, PDU_ADV_OFFSET_UNIT_300_US):
            raise ValueError('invalid SyncInfo offset unit')
        offset = self.offset_us // unit
        if (
            not 1 <= offset <= PDU_ADV_OFFSET_VALUE_MASK
            or not LL_PERIODIC_INTERVAL_MIN <= self.interval <= LL_PERIODIC_INTERVAL_MAX
        ):
            raise ValueError('invalid SyncInfo timing')
        if not valid_channel_map(self.channel_map) or not 0 <= self.sca <= LL_SCA_MAX:
            raise ValueError('invalid SyncInfo channel map or SCA')
        return (
            struct.pack(
                '<HH',
                offset
                | (
                    PDU_ADV_SYNC_OFFSET_UNITS_MASK
                    if unit == PDU_ADV_OFFSET_UNIT_300_US
                    else 0
                ),
                self.interval,
            )
            + (self.channel_map | self.sca << LL_DATA_CHANNEL_COUNT).to_bytes(
                LL_CHANNEL_MAP_SIZE, 'little'
            )
            + self.access_address.to_bytes(PDU_ACCESS_ADDRESS_SIZE, 'little')
            + self.crc_init.to_bytes(PDU_CRC_SIZE, 'little')
            + (self.event_counter & LL_EVENT_COUNTER_MASK).to_bytes(
                PDU_ADV_SYNC_EVENT_COUNTER_SIZE, 'little'
            )
        )

    @classmethod
    def decode(cls, data: bytes):
        if len(data) != PDU_ADV_SYNC_INFO_SIZE:
            raise ValueError('invalid SyncInfo size')
        offset, interval = struct.unpack_from('<HH', data)
        unit = (
            PDU_ADV_OFFSET_UNIT_300_US
            if offset & PDU_ADV_SYNC_OFFSET_UNITS_MASK
            else PDU_ADV_OFFSET_UNIT_30_US
        )
        channels = int.from_bytes(
            data[PDU_ADV_SYNC_CHANNEL_MAP_OFFSET:PDU_ADV_SYNC_ACCESS_ADDRESS_OFFSET],
            'little',
        )
        result = cls(
            (offset & PDU_ADV_OFFSET_VALUE_MASK) * unit
            + (
                PDU_ADV_SYNC_OFFSET_ADJUST_US
                if offset & PDU_ADV_SYNC_OFFSET_ADJUST_MASK
                else 0
            ),
            interval,
            channels & LL_DATA_CHANNEL_MAP_ALL,
            int.from_bytes(
                data[PDU_ADV_SYNC_ACCESS_ADDRESS_OFFSET:PDU_ADV_SYNC_CRC_INIT_OFFSET],
                'little',
            ),
            int.from_bytes(
                data[PDU_ADV_SYNC_CRC_INIT_OFFSET:PDU_ADV_SYNC_EVENT_COUNTER_OFFSET],
                'little',
            ),
            int.from_bytes(
                data[PDU_ADV_SYNC_EVENT_COUNTER_OFFSET:PDU_ADV_SYNC_INFO_SIZE], 'little'
            ),
            channels >> LL_DATA_CHANNEL_COUNT,
            offset_unit=unit,
        )
        if (
            not offset & PDU_ADV_OFFSET_VALUE_MASK
            or interval < LL_PERIODIC_INTERVAL_MIN
            or not valid_channel_map(result.channel_map)
        ):
            raise ValueError('invalid SyncInfo')
        return result


@dataclass(frozen=True)
class ExtendedPdu:
    data: bytes = b''
    address: bytes | None = None
    random_address: bool = False
    adi: int | None = None
    aux_ptr: AuxPtr | None = None
    sync_info: SyncInfo | None = None
    tx_power: int | None = None
    mode: int = AdvertisingMode.NONCONNECTABLE_NONSCANNABLE
    target: bytes | None = None
    cte: int | None = None
    random_target: bool = False
    kind: int = AdvertisingPduType.ADV_EXT_IND
    acad: bytes = b''

    def encode(self) -> bytes:
        fields = (
            self.address,
            self.target,
            None if self.cte is None else bytes([self.cte]),
            None if self.adi is None else self.adi.to_bytes(PDU_ADV_ADI_SIZE, 'little'),
            None if self.aux_ptr is None else self.aux_ptr.encode(),
            None if self.sync_info is None else self.sync_info.encode(),
            (
                None
                if self.tx_power is None
                else self.tx_power.to_bytes(
                    PDU_ADV_TX_POWER_SIZE, 'little', signed=True
                )
            ),
        )
        flags = sum(1 << bit for bit, value in enumerate(fields) if value is not None)
        header = (
            bytes([flags])
            + b''.join(value for value in fields if value is not None)
            + self.acad
            if flags or self.acad
            else b''
        )
        payload = (
            bytes([len(header) | self.mode << PDU_ADV_EXT_HEADER_LENGTH_BITS])
            + header
            + self.data
        )
        if (
            len(header) > PDU_ADV_EXT_HEADER_SIZE_MAX
            or len(payload) > PDU_ADV_EXT_PAYLOAD_SIZE_MAX
            or self.mode not in tuple(AdvertisingMode)
        ):
            raise ValueError('extended advertising PDU too large or invalid mode')
        if self.kind not in (
            AdvertisingPduType.ADV_EXT_IND,
            AdvertisingPduType.AUX_CONNECT_RSP,
        ):
            raise ValueError('invalid extended PDU type')
        return (
            bytes(
                [
                    self.kind
                    | (PDU_ADV_TXADD_MASK if self.random_address else 0)
                    | (PDU_ADV_RXADD_MASK if self.random_target else 0),
                    len(payload),
                ]
            )
            + payload
        )

    def data_capacity(self) -> int:
        return PDU_ADV_EXT_PAYLOAD_SIZE_MAX - (
            len(self.encode()) - PDU_HEADER_SIZE - len(self.data)
        )

    @classmethod
    def decode(cls, pdu: bytes):
        if (
            len(pdu) < PDU_ADV_EXT_HEADER_OFFSET
            or pdu[0] & PDU_ADV_TYPE_MASK
            not in (AdvertisingPduType.ADV_EXT_IND, AdvertisingPduType.AUX_CONNECT_RSP)
            or pdu[1] != len(pdu) - PDU_HEADER_SIZE
        ):
            raise ValueError('invalid extended advertising PDU')
        size, mode = (
            pdu[PDU_HEADER_SIZE] & PDU_ADV_EXT_HEADER_SIZE_MAX,
            pdu[PDU_HEADER_SIZE] >> PDU_ADV_EXT_HEADER_LENGTH_BITS,
        )
        if mode == PDU_ADV_EXT_MODE_RESERVED or PDU_ADV_EXT_HEADER_OFFSET + size > len(
            pdu
        ):
            raise ValueError('invalid extended advertising header')
        if not size:
            return cls(
                data=pdu[PDU_ADV_EXT_HEADER_OFFSET:],
                mode=mode,
                kind=pdu[0] & PDU_ADV_TYPE_MASK,
            )
        flags = pdu[PDU_ADV_EXT_HEADER_OFFSET]
        offset = PDU_ADV_EXT_FIELDS_OFFSET
        values: list[bytes | None] = []
        for bit, length in enumerate(
            (
                PDU_ADV_ADDRESS_SIZE,
                PDU_ADV_ADDRESS_SIZE,
                PDU_ADV_CTE_INFO_SIZE,
                PDU_ADV_ADI_SIZE,
                PDU_ADV_AUX_PTR_SIZE,
                PDU_ADV_SYNC_INFO_SIZE,
                PDU_ADV_TX_POWER_SIZE,
            )
        ):
            if flags & (1 << bit):
                if offset + length > PDU_ADV_EXT_HEADER_OFFSET + size:
                    raise ValueError('truncated extended header')
                values.append(pdu[offset : offset + length])
                offset += length
            else:
                values.append(None)
        address, target, cte, adi, aux, sync, power = values
        return cls(
            data=pdu[PDU_ADV_EXT_HEADER_OFFSET + size :],
            address=address,
            random_address=bool(pdu[0] & PDU_ADV_TXADD_MASK),
            adi=None if adi is None else int.from_bytes(adi, 'little'),
            aux_ptr=None if aux is None else AuxPtr.decode(aux),
            sync_info=None if sync is None else SyncInfo.decode(sync),
            tx_power=(
                None if power is None else int.from_bytes(power, 'little', signed=True)
            ),
            mode=mode,
            target=target,
            cte=None if cte is None else cte[0],
            random_target=bool(pdu[0] & PDU_ADV_RXADD_MASK),
            kind=pdu[0] & PDU_ADV_TYPE_MASK,
            acad=pdu[offset : PDU_ADV_EXT_HEADER_OFFSET + size],
        )
