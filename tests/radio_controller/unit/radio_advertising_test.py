# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Fixed advertising wire vectors, reserved fields and offset quantization."""

import pytest

from bumble import hci
from bumble.core import AdvertisingData
from bumble.ll import (
    LL_DATA_CHANNEL_MAP_ALL,
    LL_SCA_50_PPM,
    PDU_ADV_ADDRESS_SIZE,
    PDU_ADV_CHSEL_MASK,
    PDU_ADV_EXT_FLAGS_RESERVED_MASK,
    PDU_ADV_EXT_HEADER_OFFSET,
    PDU_ADV_OFFSET_UNIT_300_US,
    PDU_ADV_RESERVED_MASK,
    PDU_ADV_SYNC_INFO_SIZE,
    PDU_ADV_SYNC_OFFSET_RESERVED_MASK,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import Phy
from bumble.radio_controller.radio_advertising import (
    AuxPtr,
    ExtendedPdu,
    SyncInfo,
    align_offset_us,
)
from tests.radio_controller.unit.helpers import PARAMETERS

PEER_ADDRESS = hci.Address('C0:12:34:56:78:9A')


@pytest.mark.parametrize(
    'pointer,wire',
    [
        (AuxPtr(36, 600, Phy.LE_CODED), bytes.fromhex('641440')),
        (
            AuxPtr(36, 600, Phy.LE_2M, False, PDU_ADV_OFFSET_UNIT_300_US),
            bytes.fromhex('a40220'),
        ),
    ],
)
def test_auxptr_wire_fields(pointer, wire):
    assert pointer.encode() == wire
    assert AuxPtr.decode(wire) == pointer


def test_sync_info_wire_fields():
    info = SyncInfo(
        600,
        0x1234,
        0x1FFFFFFFFF,
        PARAMETERS.access_address,
        PARAMETERS.crc_init,
        0xBEEF,
        LL_SCA_50_PPM,
    )
    wire = bytes.fromhex('14003412ffffffffbf7083329a563412efbe')
    assert info.encode() == wire
    assert SyncInfo.decode(wire) == info


@pytest.mark.parametrize('unit', [0, 31])
def test_sync_info_rejects_unencodable_offset_units(unit):
    info = SyncInfo(
        900,
        80,
        LL_DATA_CHANNEL_MAP_ALL,
        PARAMETERS.access_address,
        PARAMETERS.crc_init,
        0,
        offset_unit=unit,
    )
    with pytest.raises(ValueError, match='offset unit'):
        info.encode()


@pytest.mark.parametrize('offset', [30, 600, 245_730, 246_000, 2_457_300])
def test_syncinfo_rfu_bit_preserves_offset_units_and_all_other_fields(offset):
    info = SyncInfo(
        offset,
        80,
        LL_DATA_CHANNEL_MAP_ALL,
        PARAMETERS.access_address,
        PARAMETERS.crc_init,
        0xBEEF,
        LL_SCA_50_PPM,
    )
    wire = bytearray(info.encode())
    wire[:2] = (
        int.from_bytes(wire[:2], 'little') | PDU_ADV_SYNC_OFFSET_RESERVED_MASK
    ).to_bytes(2, 'little')
    assert SyncInfo.decode(wire) == info


@pytest.mark.parametrize('encoding', range(3, 8))
def test_reserved_aux_phy_codes_are_invalid_values_not_ignorable_bits(encoding):
    # Valid channel12 and offset600us; only the three-bit Aux PHY is reserved.
    wire = bytes([12, 20, encoding << 5])
    with pytest.raises(ValueError, match='PHY'):
        AuxPtr.decode(wire)


def test_extended_header_with_only_rfu_flag_is_empty_not_malformed():
    assert ExtendedPdu.decode(bytes.fromhex('07020180')) == ExtendedPdu()


@pytest.mark.parametrize(
    'fields',
    [
        {'adi': 0x3001},
        {'address': bytes.fromhex('010203040506'), 'adi': 0x3001},
        {'aux_ptr': AuxPtr(12, 600, Phy.LE_2M)},
        {'cte': 0x12, 'target': bytes.fromhex('0708090a0b0c'), 'tx_power': -20},
    ],
)
def test_extended_rfu_flag_does_not_shift_fields_or_consume_data(fields):
    original = ExtendedPdu(data=b'payload', **fields)
    wire = bytearray(original.encode())
    wire[0] |= PDU_ADV_RESERVED_MASK | PDU_ADV_CHSEL_MASK
    wire[PDU_ADV_EXT_HEADER_OFFSET] |= PDU_ADV_EXT_FLAGS_RESERVED_MASK
    assert ExtendedPdu.decode(wire) == original


def test_extended_header_wire_fields():
    pdu = ExtendedPdu(
        data=b'payload',
        address=bytes.fromhex('010203040506'),
        random_address=True,
        target=bytes.fromhex('0708090a0b0c'),
        random_target=True,
        cte=0x12,
        adi=0xABCD,
        aux_ptr=AuxPtr(36, 600, Phy.LE_CODED),
        sync_info=SyncInfo(
            600,
            0x1234,
            0x1FFFFFFFFF,
            PARAMETERS.access_address,
            PARAMETERS.crc_init,
            0xBEEF,
        ),
        tx_power=-5,
    )
    wire = (
        bytes.fromhex(
            'c72e267f0102030405060708090a0b0c12cdab641440'
            '14003412ffffffffbf7083329a563412efbefb'
        )
        + b'payload'
    )
    assert pdu.encode() == wire
    assert ExtendedPdu.decode(wire) == pdu


def test_large_unit_auxptr_preserves_wire_unit_at_small_offsets():
    raw = bytes([7 | 128, 2, 0])  # 600 us in 300-us units, LE 1M.
    pointer = AuxPtr.decode(raw)
    assert pointer.offset_us == 600 and pointer.unit_us == PDU_ADV_OFFSET_UNIT_300_US
    assert pointer.encode() == raw


@pytest.mark.parametrize(
    'offset,expected',
    [(1, 30), (600, 600), (601, 630), (245759, 246000), (245761, 246000)],
)
def test_offset_rounding_and_unit_transition(offset, expected):
    assert align_offset_us(offset) == expected
    encoded = AuxPtr(7, expected, Phy.LE_1M).encode()
    assert AuxPtr.decode(encoded).offset_us == expected


def test_auxiliary_connection_response_codec():
    packet = ExtendedPdu(
        kind=AdvertisingPduType.AUX_CONNECT_RSP,
        address=bytes(PDU_ADV_ADDRESS_SIZE),
        target=bytes(range(6)),
        random_target=True,
    )
    encoded = packet.encode()
    assert encoded[0] == 0x88 and encoded[2] >> 6 == 0
    assert ExtendedPdu.decode(encoded) == packet


def test_syncinfo_keeps_received_offset_unit_even_when_delay_fits_smaller_units():
    info = SyncInfo(
        900,
        80,
        LL_DATA_CHANNEL_MAP_ALL,
        PARAMETERS.access_address,
        PARAMETERS.crc_init,
        1,
        offset_unit=PDU_ADV_OFFSET_UNIT_300_US,
    )
    decoded = SyncInfo.decode(info.encode())
    assert decoded.unit_us == PDU_ADV_OFFSET_UNIT_300_US
    assert decoded.encode() == info.encode()


def test_extended_header_preserves_acad_separately_from_advertising_data():
    acad = bytes(
        AdvertisingData(
            [
                (
                    AdvertisingData.Type.CHANNEL_MAP_UPDATE_INDICATION,
                    b'\x15\x00\x00\x00\x00\x14\x00',
                )
            ]
        )
    )
    for pdu in (
        ExtendedPdu(acad=acad, data=b'payload'),
        ExtendedPdu(address=bytes(PEER_ADDRESS), acad=acad),
    ):
        assert ExtendedPdu.decode(pdu.encode()) == pdu


@pytest.mark.parametrize(
    'data', [b'', bytes(2), bytes([37, 1, 0]), bytes([1, 0, 0]), bytes([1, 1, 0xE0])]
)
def test_invalid_aux_pointer(data):
    with pytest.raises(ValueError):
        AuxPtr.decode(data)


@pytest.mark.parametrize(
    'data',
    [
        b'',
        bytes(PDU_ADV_SYNC_INFO_SIZE - 1),
        bytes(PDU_ADV_SYNC_INFO_SIZE),
        b'\x01\x80' + bytes(16),
    ],
)
def test_invalid_sync_info(data):
    with pytest.raises(ValueError):
        SyncInfo.decode(data)


@pytest.mark.parametrize(
    'data',
    [b'', b'\x07\x01\x02', b'\x07\x02\x01\x10', b'\x07\x01\xc0'],
)
def test_malformed_extended_header(data):
    with pytest.raises(ValueError):
        ExtendedPdu.decode(data)
