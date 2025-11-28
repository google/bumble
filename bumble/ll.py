# Copyright 2021-2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import dataclasses
from typing import ClassVar

from bumble import hci


# -----------------------------------------------------------------------------
# Advertising PDU
# -----------------------------------------------------------------------------
class AdvertisingPdu:
    """Base Advertising Physical Channel PDU class.

    See Core Spec 6.0, Volume 6, Part B, 2.3. Advertising physical channel PDU.

    Currently these messages don't really follow the LL spec, because LL protocol is
    context-aware and we don't have real physical transport.
    """


@dataclasses.dataclass
class ConnectInd(AdvertisingPdu):
    initiator_address: hci.Address
    advertiser_address: hci.Address
    interval: int
    latency: int
    timeout: int


@dataclasses.dataclass
class AdvInd(AdvertisingPdu):
    advertiser_address: hci.Address
    data: bytes


@dataclasses.dataclass
class AdvDirectInd(AdvertisingPdu):
    advertiser_address: hci.Address
    target_address: hci.Address


@dataclasses.dataclass
class AdvNonConnInd(AdvertisingPdu):
    advertiser_address: hci.Address
    data: bytes


@dataclasses.dataclass
class AdvExtInd(AdvertisingPdu):
    advertiser_address: hci.Address
    data: bytes

    target_address: hci.Address | None = None
    adi: int | None = None
    tx_power: int | None = None


# -----------------------------------------------------------------------------
# LL Control PDU
# -----------------------------------------------------------------------------
class ControlPdu:
    """Base LL Control PDU Class.

    See Core Spec 6.0, Volume 6, Part B, 2.4.2. LL Control PDU.

    Currently these messages don't really follow the LL spec, because LL protocol is
    context-aware and we don't have real physical transport.
    """

    class Opcode(hci.SpecableEnum):
        LL_CONNECTION_UPDATE_IND = 0x00
        LL_CHANNEL_MAP_IND = 0x01
        LL_TERMINATE_IND = 0x02
        LL_ENC_REQ = 0x03
        LL_ENC_RSP = 0x04
        LL_START_ENC_REQ = 0x05
        LL_START_ENC_RSP = 0x06
        LL_UNKNOWN_RSP = 0x07
        LL_FEATURE_REQ = 0x08
        LL_FEATURE_RSP = 0x09
        LL_PAUSE_ENC_REQ = 0x0A
        LL_PAUSE_ENC_RSP = 0x0B
        LL_VERSION_IND = 0x0C
        LL_REJECT_IND = 0x0D
        LL_PERIPHERAL_FEATURE_REQ = 0x0E
        LL_CONNECTION_PARAM_REQ = 0x0F
        LL_CONNECTION_PARAM_RSP = 0x10
        LL_REJECT_EXT_IND = 0x11
        LL_PING_REQ = 0x12
        LL_PING_RSP = 0x13
        LL_LENGTH_REQ = 0x14
        LL_LENGTH_RSP = 0x15
        LL_PHY_REQ = 0x16
        LL_PHY_RSP = 0x17
        LL_PHY_UPDATE_IND = 0x18
        LL_MIN_USED_CHANNELS_IND = 0x19
        LL_CTE_REQ = 0x1A
        LL_CTE_RSP = 0x1B
        LL_PERIODIC_SYNC_IND = 0x1C
        LL_CLOCK_ACCURACY_REQ = 0x1D
        LL_CLOCK_ACCURACY_RSP = 0x1E
        LL_CIS_REQ = 0x1F
        LL_CIS_RSP = 0x20
        LL_CIS_IND = 0x21
        LL_CIS_TERMINATE_IND = 0x22
        LL_POWER_CONTROL_REQ = 0x23
        LL_POWER_CONTROL_RSP = 0x24
        LL_POWER_CHANGE_IND = 0x25
        LL_SUBRATE_REQ = 0x26
        LL_SUBRATE_IND = 0x27
        LL_CHANNEL_REPORTING_IND = 0x28
        LL_CHANNEL_STATUS_IND = 0x29
        LL_PERIODIC_SYNC_WR_IND = 0x2A
        LL_FEATURE_EXT_REQ = 0x2B
        LL_FEATURE_EXT_RSP = 0x2C
        LL_CS_SEC_RSP = 0x2D
        LL_CS_CAPABILITIES_REQ = 0x2E
        LL_CS_CAPABILITIES_RSP = 0x2F
        LL_CS_CONFIG_REQ = 0x30
        LL_CS_CONFIG_RSP = 0x31
        LL_CS_REQ = 0x32
        LL_CS_RSP = 0x33
        LL_CS_IND = 0x34
        LL_CS_TERMINATE_REQ = 0x35
        LL_CS_FAE_REQ = 0x36
        LL_CS_FAE_RSP = 0x37
        LL_CS_CHANNEL_MAP_IND = 0x38
        LL_CS_SEC_REQ = 0x39
        LL_CS_TERMINATE_RSP = 0x3A
        LL_FRAME_SPACE_REQ = 0x3B
        LL_FRAME_SPACE_RSP = 0x3C

    opcode: ClassVar[Opcode]


@dataclasses.dataclass
class TerminateInd(ControlPdu):
    opcode = ControlPdu.Opcode.LL_TERMINATE_IND

    error_code: int


@dataclasses.dataclass
class EncReq(ControlPdu):
    opcode = ControlPdu.Opcode.LL_ENC_REQ

    rand: bytes
    ediv: int
    ltk: bytes


@dataclasses.dataclass
class CisReq(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CIS_REQ

    cig_id: int
    cis_id: int


@dataclasses.dataclass
class CisRsp(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CIS_REQ

    cig_id: int
    cis_id: int


@dataclasses.dataclass
class CisInd(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CIS_REQ

    cig_id: int
    cis_id: int


@dataclasses.dataclass
class CisTerminateInd(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CIS_TERMINATE_IND

    cig_id: int
    cis_id: int
    error_code: int
