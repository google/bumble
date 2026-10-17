# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""CONNECT_IND parameters and shared Link Layer timing/channel-map constraints."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from bumble.ll import (
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_INTERVAL_MAX,
    LL_CONN_INTERVAL_MIN,
    LL_CONN_INTERVAL_UNIT_US,
    LL_CONN_LATENCY_MAX,
    LL_CONN_WINDOW_SIZE_MAX,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_DATA_CHANNEL_COUNT,
    LL_DATA_CHANNEL_COUNT_MIN,
    LL_HOP_INCREMENT_MAX,
    LL_HOP_INCREMENT_MIN,
    LL_SUPERVISION_TIMEOUT_INTERVAL_FACTOR,
    LL_SUPERVISION_TIMEOUT_MAX,
    LL_SUPERVISION_TIMEOUT_MIN,
    LL_SUPERVISION_TIMEOUT_UNIT_US,
    PDU_ACCESS_ADDRESS_SIZE,
    PDU_ADV_ACCESS_ADDRESS,
    PDU_ADV_CONNECT_HOP_MASK,
    PDU_ADV_CONNECT_SCA_SHIFT,
    PDU_CRC_SIZE,
)

CONNECT_DATA = struct.Struct("<I3sBHHHH5sB")


def valid_channel_map(value: int) -> bool:
    return (
        value >= 0
        and not value >> LL_DATA_CHANNEL_COUNT
        and value.bit_count() >= LL_DATA_CHANNEL_COUNT_MIN
    )


def valid_timing(
    interval_min: int, interval_max: int, latency: int, timeout: int
) -> bool:
    return (
        LL_CONN_INTERVAL_MIN <= interval_min <= interval_max <= LL_CONN_INTERVAL_MAX
        and 0 <= latency <= LL_CONN_LATENCY_MAX
        and LL_SUPERVISION_TIMEOUT_MIN <= timeout <= LL_SUPERVISION_TIMEOUT_MAX
        and timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
        > LL_SUPERVISION_TIMEOUT_INTERVAL_FACTOR
        * (latency + 1)
        * interval_max
        * LL_CONN_INTERVAL_UNIT_US
    )


@dataclass(frozen=True)
class Parameters:
    access_address: int
    crc_init: int
    window_size: int
    window_offset: int
    interval: int
    latency: int
    timeout: int
    channel_map: int
    hop: int
    sca: int = 0

    @classmethod
    def decode(cls, data: bytes) -> Parameters:
        if len(data) != CONNECT_DATA.size:
            raise ValueError(
                f"CONNECT_IND LLData must contain {CONNECT_DATA.size} octets"
            )
        aa, crc, size, offset, interval, latency, timeout, channels, hop_sca = (
            CONNECT_DATA.unpack(data)
        )
        result = cls(
            aa,
            int.from_bytes(crc, "little"),
            size,
            offset,
            interval,
            latency,
            timeout,
            int.from_bytes(channels, "little"),
            hop_sca & PDU_ADV_CONNECT_HOP_MASK,
            hop_sca >> PDU_ADV_CONNECT_SCA_SHIFT,
        )
        if not valid_timing(interval, interval, latency, timeout):
            raise ValueError("invalid connection timing")
        if not (
            LL_CONN_WINDOW_SIZE_MIN
            <= size
            <= min(LL_CONN_WINDOW_SIZE_MAX, interval - 1)
            and offset <= interval
            and LL_HOP_INCREMENT_MIN <= result.hop <= LL_HOP_INCREMENT_MAX
        ):
            raise ValueError("invalid transmit window or hop increment")
        if not valid_channel_map(result.channel_map):
            raise ValueError("invalid data channel map")
        if aa in (
            0,
            (1 << (PDU_ACCESS_ADDRESS_SIZE * 8)) - 1,
            PDU_ADV_ACCESS_ADDRESS,
        ):
            raise ValueError("invalid data access address")
        return result

    def encode(self) -> bytes:
        return CONNECT_DATA.pack(
            self.access_address,
            self.crc_init.to_bytes(PDU_CRC_SIZE, "little"),
            self.window_size,
            self.window_offset,
            self.interval,
            self.latency,
            self.timeout,
            self.channel_map.to_bytes(LL_CHANNEL_MAP_SIZE, "little"),
            self.hop | self.sca << PDU_ADV_CONNECT_SCA_SHIFT,
        )
