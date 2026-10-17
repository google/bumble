# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Connection wire vectors and strict timing/channel-map boundaries."""

from dataclasses import replace

import pytest

from bumble.ll import (
    LL_CONN_INTERVAL_MAX,
    LL_CONN_INTERVAL_MIN,
    LL_CONN_LATENCY_MAX,
    LL_CONN_WINDOW_SIZE_MAX,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_DATA_CHANNEL_COUNT,
    LL_HOP_INCREMENT_MAX,
    LL_HOP_INCREMENT_MIN,
    LL_SUPERVISION_TIMEOUT_MAX,
    LL_SUPERVISION_TIMEOUT_MIN,
    PDU_ADV_ACCESS_ADDRESS,
    PDU_ADV_CONNECT_DATA_SIZE,
)
from bumble.radio_controller.radio_parameters import (
    Parameters,
    valid_channel_map,
    valid_timing,
)
from tests.radio_controller.unit.helpers import PARAMETERS


@pytest.mark.parametrize(
    'value,expected',
    [
        (0, False),
        (1, False),
        (3, True),
        ((1 << (LL_DATA_CHANNEL_COUNT - 1)) | 1, True),
        (1 << LL_DATA_CHANNEL_COUNT | 3, False),
        (-1, False),
    ],
)
def test_channel_map_validation(value, expected):
    assert valid_channel_map(value) == expected


@pytest.mark.parametrize(
    'timing,expected',
    [
        (
            (LL_CONN_INTERVAL_MIN, LL_CONN_INTERVAL_MAX, 0, LL_SUPERVISION_TIMEOUT_MAX),
            True,
        ),
        ((LL_CONN_INTERVAL_MIN - 1, LL_CONN_INTERVAL_MIN, 0, 100), False),
        ((24, 23, 0, 100), False),
        ((24, 24, LL_CONN_LATENCY_MAX + 1, LL_SUPERVISION_TIMEOUT_MAX), False),
        ((24, 24, 0, 6), False),
        ((24, 24, 0, LL_SUPERVISION_TIMEOUT_MIN), True),
        ((24, 24, 1, 12), False),
    ],
)
def test_connection_timing_validation(timing, expected):
    assert valid_timing(*timing) == expected


def test_connect_ind_uses_fixed_little_endian_fields_and_packed_sca():
    parameters = replace(PARAMETERS, crc_init=0xABCDEF, window_offset=2, sca=5)
    wire = bytes.fromhex('7083329aefcdab010200180000006400ffffffff1fa7')
    assert len(wire) == PDU_ADV_CONNECT_DATA_SIZE
    assert parameters.encode() == wire
    assert Parameters.decode(wire) == parameters


@pytest.mark.parametrize('length', [0, 21, 23])
def test_connect_ind_rejects_truncated_or_extra_data(length):
    with pytest.raises(ValueError, match='22 octets'):
        Parameters.decode(bytes(length))


@pytest.mark.parametrize(
    "field,value",
    [
        ("interval", LL_CONN_INTERVAL_MIN - 1),
        ("interval", LL_CONN_INTERVAL_MAX + 1),
        ("latency", LL_CONN_LATENCY_MAX + 1),
        ("timeout", LL_SUPERVISION_TIMEOUT_MIN - 1),
        ("timeout", LL_SUPERVISION_TIMEOUT_MAX + 1),
        ("latency", 20),
        ("window_size", LL_CONN_WINDOW_SIZE_MIN - 1),
        ("window_size", LL_CONN_WINDOW_SIZE_MAX + 1),
        ("window_offset", PARAMETERS.interval + 1),
        ("hop", LL_HOP_INCREMENT_MIN - 1),
        ("hop", LL_HOP_INCREMENT_MAX + 1),
        ("channel_map", 1),
        ("channel_map", 1 << LL_DATA_CHANNEL_COUNT | 3),
        ("access_address", 0),
        ("access_address", 0xFFFFFFFF),
        ("access_address", PDU_ADV_ACCESS_ADDRESS),
    ],
)
def test_invalid_connection_parameters(field, value):
    with pytest.raises(ValueError):
        Parameters.decode(replace(PARAMETERS, **{field: value}).encode())
