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
# Constants
# -----------------------------------------------------------------------------
# PDU_* describes packet fields; LL_* describes procedure timing and counters.
# SIZE is in octets; time values end in _US; MASK values are encoded bit masks.
# Normative references in this section use Bluetooth Core 5.4.

# Physical packet fields: Core Vol 6, Part B, 2. Sizes exclude other fields.
PDU_PREAMBLE_1M_SIZE = 1
PDU_PREAMBLE_2M_SIZE = 2
PDU_ACCESS_ADDRESS_SIZE = 4
# Core Vol 6, Part B, 2.1.2: data Access Address bit-pattern constraints.
PDU_ACCESS_ADDRESS_CONSECUTIVE_BITS_MAX = 6
PDU_ACCESS_ADDRESS_TRANSITIONS_MAX = 24
PDU_ACCESS_ADDRESS_MSB_WINDOW_BITS = 6
PDU_ACCESS_ADDRESS_MSB_TRANSITIONS_MIN = 2
# Additional data Access Address requirements for the LE Coded PHY.
PDU_ACCESS_ADDRESS_CODED_LSB_BITS = 8
PDU_ACCESS_ADDRESS_CODED_LSB_ONES_MIN = 3
PDU_ACCESS_ADDRESS_CODED_TRANSITION_BITS = 16
PDU_ACCESS_ADDRESS_CODED_TRANSITIONS_MAX = 11
PDU_HEADER_SIZE = 2
PDU_CRC_SIZE = 3
# Core Vol 6, Part E, 2: encrypted payload MIC length in octets.
PDU_DATA_MIC_SIZE = 4
# Core Vol 6, Part E, 1: the LE session key is 128 bits.
LL_ENCRYPTION_KEY_SIZE = 16
# Core Vol 6, Part B, 2.4.2.3/4: each role contributes 64 SKD bits.
LL_ENCRYPTION_SKD_HALF_SIZE = 8
# Core Vol 6, Part B, 2.4.2.3/4: each role contributes 32 IV bits.
LL_ENCRYPTION_IV_HALF_SIZE = 4
# Core Vol 6, Part B, 2.4.2.3: Rand is an eight-octet field.
LL_ENCRYPTION_RANDOM_SIZE = 8
# Core Vol 6, Part B, 2.4.2.4: EDIV is a 16-bit encrypted diversifier.
LL_ENCRYPTION_EDIV_SIZE = 2
# Core Vol 6, Part E, 2.1: nonce packet counter plus direction occupy five octets.
LL_ENCRYPTION_COUNTER_SIZE = 5
# The counter must not wrap or reuse an encrypted-packet nonce.
LL_ENCRYPTION_COUNTER_BITS = 39
# Central transmission uses direction bit 1; Peripheral transmission uses 0.
LL_ENCRYPTION_DIRECTION_MASK = 1 << 39
# NESN, SN and MD are excluded from CCM additional authenticated data.
PDU_DATA_AUTHENTICATED_HEADER_MASK = 0xE3
# Core Vol 4, Part E, 7.3.93: 30-s default, encoded in units of 10 ms.
LL_AUTHENTICATED_PAYLOAD_TIMEOUT_DEFAULT = 3000
# HCI Authenticated_Payload_Timeout encoding unit, independent of radio ticks.
LL_AUTHENTICATED_PAYLOAD_TIMEOUT_UNIT_US = 10_000
# Channel map field in advertising and control PDUs.
LL_CHANNEL_MAP_SIZE = 5
# Core Vol 6, Part B, 3.1.1: polynomial in the CRC engine's LSB-first form.
PDU_CRC_POLYNOMIAL_REFLECTED = 0xDA6000

# Advertising header: Core Vol 6, Part B, 2.3.1.
PDU_ADV_TYPE_MASK = 0x0F
# Advertising header bit4 is RFU.
PDU_ADV_RESERVED_MASK = 1 << 4
# Channel Selection Algorithm #2 support for specified legacy PDUs; RFU otherwise.
PDU_ADV_CHSEL_MASK = 1 << 5
# Transmitter address type: 1 = random.
PDU_ADV_TXADD_MASK = 1 << 6
# Receiver address type: 1 = random.
PDU_ADV_RXADD_MASK = 1 << 7
# Fixed advertising-channel Access Address.
PDU_ADV_ACCESS_ADDRESS = 0x8E89BED6
# Fixed advertising-channel CRC initialization.
PDU_ADV_CRC_INIT = 0x555555

# Advertising data: Core Vol 6, Part B, 2.3.1 and 2.3.4.
# AdvData/ScanRspData only; excludes AdvA.
PDU_ADV_LEGACY_DATA_SIZE_MAX = 31
# Includes extended header; excludes LL header.
PDU_ADV_EXT_PAYLOAD_SIZE_MAX = 255
# ExtHdrLen width in the common extended format.
PDU_ADV_EXT_HEADER_LENGTH_BITS = 6
# ExtHdrLen excludes the octet containing AdvMode and ExtHdrLen itself.
PDU_ADV_EXT_HEADER_SIZE_MAX = (1 << PDU_ADV_EXT_HEADER_LENGTH_BITS) - 1

# Common advertising fields: Core Vol 6, Part B, 2.3.
PDU_ADV_ADDRESS_SIZE = 6
# AdvA (or ScanA/InitA) follows the LL header; the second address follows it.
PDU_ADV_ADDRESS_OFFSET = PDU_HEADER_SIZE
PDU_ADV_SECOND_ADDRESS_OFFSET = PDU_ADV_ADDRESS_OFFSET + PDU_ADV_ADDRESS_SIZE
PDU_ADV_ADDRESSES_END = PDU_ADV_SECOND_ADDRESS_OFFSET + PDU_ADV_ADDRESS_SIZE
# Legacy advertising/scan-response PDU bounds, including the LL header.
PDU_ADV_LEGACY_SIZE_MIN = PDU_HEADER_SIZE + PDU_ADV_ADDRESS_SIZE
PDU_ADV_LEGACY_SIZE_MAX = PDU_ADV_LEGACY_SIZE_MIN + PDU_ADV_LEGACY_DATA_SIZE_MAX
# SCAN_REQ and ADV_DIRECT_IND contain two addresses.
PDU_ADV_SCAN_REQ_PAYLOAD_SIZE = 2 * PDU_ADV_ADDRESS_SIZE
PDU_ADV_SCAN_REQ_SIZE = PDU_HEADER_SIZE + PDU_ADV_SCAN_REQ_PAYLOAD_SIZE
PDU_ADV_DIRECT_SIZE = PDU_ADV_SCAN_REQ_SIZE
# CONNECT_IND/AUX_CONNECT_REQ add LLData after the two addresses.
PDU_ADV_CONNECT_DATA_SIZE = 22
PDU_ADV_CONNECT_PAYLOAD_SIZE = PDU_ADV_SCAN_REQ_PAYLOAD_SIZE + PDU_ADV_CONNECT_DATA_SIZE
PDU_ADV_CONNECT_SIZE = PDU_HEADER_SIZE + PDU_ADV_CONNECT_PAYLOAD_SIZE

# Common extended advertising format: Core Vol 6, Part B, 2.3.4.
# One octet contains ExtHdrLen and AdvMode; one optional octet contains flags.
PDU_ADV_EXT_COMMON_HEADER_SIZE = 1
PDU_ADV_EXT_FLAGS_SIZE = 1
PDU_ADV_EXT_HEADER_OFFSET = PDU_HEADER_SIZE + PDU_ADV_EXT_COMMON_HEADER_SIZE
PDU_ADV_EXT_FIELDS_OFFSET = PDU_ADV_EXT_HEADER_OFFSET + PDU_ADV_EXT_FLAGS_SIZE
# AdvMode 0b11 and extended-header flag bit 7 are reserved.
PDU_ADV_EXT_MODE_RESERVED = 0x03
PDU_ADV_EXT_FLAGS_RESERVED_MASK = 1 << 7
# AuxPtr presence in the common extended-header flags.
PDU_ADV_EXT_AUX_PTR_MASK = 1 << 4
# TxPower presence in the common extended-header flags.
PDU_ADV_EXT_TX_POWER_MASK = 1 << 6
# Core 6.1 Vol 6, Part B, 2.3.1.11: Decision Type Flags bit 0 includes a tag.
PDU_ADV_DECISION_RESOLVABLE_TAG_MASK = 1 << 0
PDU_ADV_CTE_INFO_SIZE = 1
PDU_ADV_ADI_SIZE = 2
PDU_ADV_TX_POWER_SIZE = 1
# ADI: 12-bit DID followed by 4-bit SID.
PDU_ADV_ADI_DID_BITS = 12
PDU_ADV_ADI_DID_MASK = (1 << PDU_ADV_ADI_DID_BITS) - 1
PDU_ADV_ADI_SID_MAX = 0x0F
PDU_ADV_AUX_PTR_SIZE = 3
# AuxPtr octet 0: Channel Index, CA, Offset Units.
PDU_ADV_AUX_CHANNEL_MASK = 0x3F
PDU_ADV_AUX_CA_MASK = 1 << 6
PDU_ADV_AUX_OFFSET_UNITS_MASK = 1 << 7
# Remaining two octets contain Aux Offset and Aux PHY.
PDU_ADV_AUX_OFFSET_PHY_SIZE = 2
# SyncInfo field layout, relative to the start of SyncInfo.
PDU_ADV_SYNC_CHANNEL_MAP_OFFSET = 4
PDU_ADV_SYNC_ACCESS_ADDRESS_OFFSET = (
    PDU_ADV_SYNC_CHANNEL_MAP_OFFSET + LL_CHANNEL_MAP_SIZE
)
PDU_ADV_SYNC_CRC_INIT_OFFSET = (
    PDU_ADV_SYNC_ACCESS_ADDRESS_OFFSET + PDU_ACCESS_ADDRESS_SIZE
)
PDU_ADV_SYNC_EVENT_COUNTER_OFFSET = PDU_ADV_SYNC_CRC_INIT_OFFSET + PDU_CRC_SIZE
# SyncInfo contains a 16-bit periodic event counter.
PDU_ADV_SYNC_EVENT_COUNTER_SIZE = 2
PDU_ADV_SYNC_INFO_SIZE = (
    PDU_ADV_SYNC_EVENT_COUNTER_OFFSET + PDU_ADV_SYNC_EVENT_COUNTER_SIZE
)
# Minimum AUX_CONNECT_RSP: common header, flags, AdvA and TargetA.
PDU_ADV_AUX_CONNECT_RSP_SIZE = PDU_ADV_EXT_FIELDS_OFFSET + 2 * PDU_ADV_ADDRESS_SIZE

# AuxPtr/SyncInfo offset encoding: Core Vol 6, Part B, 2.3.4.5 and 2.3.4.6.
PDU_ADV_OFFSET_BITS = 13
PDU_ADV_OFFSET_UNIT_30_US = 30
PDU_ADV_OFFSET_UNIT_300_US = 300
PDU_ADV_OFFSET_VALUE_MASK = (1 << PDU_ADV_OFFSET_BITS) - 1
# Exclusive upper bound for an offset represented in 30-us units.
PDU_ADV_OFFSET_30_RANGE_US = (PDU_ADV_OFFSET_VALUE_MASK + 1) * PDU_ADV_OFFSET_UNIT_30_US
PDU_ADV_SYNC_OFFSET_ADJUST_US = 2_457_600
# 1 = 300-us; 0 = 30-us.
PDU_ADV_SYNC_OFFSET_UNITS_MASK = 1 << PDU_ADV_OFFSET_BITS
# Add Offset Adjust.
PDU_ADV_SYNC_OFFSET_ADJUST_MASK = 1 << (PDU_ADV_OFFSET_BITS + 1)
# RFU: transmitted as zero and ignored on reception.
PDU_ADV_SYNC_OFFSET_RESERVED_MASK = 1 << (PDU_ADV_OFFSET_BITS + 2)

# Data header: Core Vol 6, Part B, 2.4.1.
PDU_DATA_LLID_MASK = 0x03
# Next Expected Sequence Number.
PDU_DATA_NESN_MASK = 1 << 2
# Sequence Number.
PDU_DATA_SN_MASK = 1 << 3
# More Data.
PDU_DATA_MD_MASK = 1 << 4

# Data length management: Core Vol 6, Part B, 4.5.10, Table 4.6.
# Octet limits exclude the MIC; time bounds allow for a four-octet MIC.
# They are negotiation bounds, not the airtime of an unencrypted packet.
PDU_DATA_PAYLOAD_SIZE_MIN = 27
PDU_DATA_PAYLOAD_SIZE_MAX = 251
PDU_DATA_PAYLOAD_TIME_MIN_US = 328
# 27 data octets on Coded S=8.
PDU_DATA_PAYLOAD_TIME_CODED_MIN_US = 2704
# LE 1M, without a CTE.
PDU_DATA_PAYLOAD_TIME_UNCODED_MAX_US = 2120
# 251 data octets on Coded S=8.
PDU_DATA_PAYLOAD_TIME_CODED_MAX_US = 17040
# Coded connection-interval budget coefficients: Core 4.5.10.
PDU_DATA_OCTET_TIME_CODED_S8_US = 64
# Empty data packet, with MIC allowance.
PDU_DATA_EMPTY_TIME_CODED_S8_US = 976
# Core 4.5.11: before Feature Exchange, CtrData <=26 octets plus one opcode.
PDU_CONTROL_PAYLOAD_SIZE_INITIAL_MAX = 27

# Channel selection and clock accuracy: Core Vol 6, Part B, 2.3.3 and 4.5.8.
LL_DATA_CHANNEL_COUNT = 37
LL_DATA_CHANNEL_COUNT_MIN = 2
LL_ADV_PRIMARY_CHANNELS = (37, 38, 39)
LL_ADV_PRIMARY_CHANNEL_MAP_ALL = (1 << len(LL_ADV_PRIMARY_CHANNELS)) - 1
# Hop/SCA byte in CONNECT_IND.
PDU_ADV_CONNECT_HOP_MASK = 0x1F
PDU_ADV_CONNECT_SCA_SHIFT = 5
LL_HOP_INCREMENT_MIN = 5
LL_HOP_INCREMENT_MAX = 16
# Encoded SCA categories and their upper bounds in ppm.
LL_SCA_500_PPM = 0
LL_SCA_50_PPM = 5
LL_SCA_MAX = 7
LL_SCA_PPM = (500, 250, 150, 100, 75, 50, 30, 20)
# CSA #2: 16-bit PRN, three permute/MAM rounds, MAM multiplier 17.
LL_CHANNEL_ID_BITS = 16
LL_CHANNEL_ID_MASK = (1 << LL_CHANNEL_ID_BITS) - 1
LL_CSA2_MAM_ROUNDS = 3
LL_CSA2_MAM_MULTIPLIER = 17

# Data-channel bits 0..36 set; reserved bits zero.
LL_DATA_CHANNEL_MAP_ALL = (1 << LL_DATA_CHANNEL_COUNT) - 1

# Connection parameter bounds: Core Vol 6, Part B, 4.5.1 and 4.5.2.
LL_CONN_INTERVAL_MIN = 6
LL_CONN_INTERVAL_MAX = 3200
LL_CONN_LATENCY_MAX = 499
LL_SUPERVISION_TIMEOUT_MIN = 10
LL_SUPERVISION_TIMEOUT_MAX = 3200
# Supervision timeout must exceed twice the maximum connection-event spacing.
LL_SUPERVISION_TIMEOUT_INTERVAL_FACTOR = 2
LL_CONN_WINDOW_SIZE_MIN = 1
LL_CONN_WINDOW_SIZE_MAX = 8
# Nonzero interval ranges require a periodicity: Core Vol 6, Part B, 5.1.7.1.
LL_CONN_PREFERRED_PERIODICITY_MIN = 1
# AUX_CONNECT_REQ transmit-window delay: Core Vol 6, Part B, 4.5.3.
LL_CONN_AUX_WINDOW_DELAY_UNCODED_US = 2500
LL_CONN_AUX_WINDOW_DELAY_CODED_US = 3750
# Initial connection establishment and consecutive CRC-error limits.
LL_CONN_ESTABLISHMENT_EVENTS = 6
LL_CONN_CRC_ERROR_LIMIT = 2
# Periodic interval field is an unsigned 16-bit value.
LL_PERIODIC_INTERVAL_MAX = 0xFFFF

# LL control fields: Core Vol 6, Part B, 2.4.2.
PDU_CONTROL_OPCODE_SIZE = 1
PDU_CONTROL_FEATURE_SET_SIZE = 8
PDU_CONTROL_FEATURE_SIZE = PDU_CONTROL_OPCODE_SIZE + PDU_CONTROL_FEATURE_SET_SIZE
PDU_CONTROL_TERMINATE_SIZE = 2
# LL_ENC_REQ carries Rand, EDIV, SKDc and IVc after its opcode.
PDU_CONTROL_ENC_REQ_SIZE = (
    PDU_CONTROL_OPCODE_SIZE
    + LL_ENCRYPTION_RANDOM_SIZE
    + LL_ENCRYPTION_EDIV_SIZE
    + LL_ENCRYPTION_SKD_HALF_SIZE
    + LL_ENCRYPTION_IV_HALF_SIZE
)
# LL_ENC_RSP carries SKDp and IVp after its opcode.
PDU_CONTROL_ENC_RSP_SIZE = (
    PDU_CONTROL_OPCODE_SIZE + LL_ENCRYPTION_SKD_HALF_SIZE + LL_ENCRYPTION_IV_HALF_SIZE
)
# LL_UNKNOWN_RSP contains the opcode of the unrecognized PDU.
PDU_CONTROL_UNKNOWN_RSP_SIZE = 2
PDU_CONTROL_VERSION_SIZE = 6
PDU_CONTROL_PHY_REQ_SIZE = 3
PDU_CONTROL_PHY_UPDATE_SIZE = 5
# LL_MIN_USED_CHANNELS_IND: Opcode, PHYS and MinUsedChannels (Vol 6 Part B 2.4.2.24).
PDU_CONTROL_MIN_USED_CHANNELS_SIZE = 3
# LL_REJECT_IND carries only the reason, unlike LL_REJECT_EXT_IND.
PDU_CONTROL_REJECT_SIZE = 2
PDU_CONTROL_REJECT_EXT_SIZE = 3
PDU_CONTROL_INSTANT_SIZE = 2
PDU_CONTROL_CHANNEL_MAP_SIZE = (
    PDU_CONTROL_OPCODE_SIZE + LL_CHANNEL_MAP_SIZE + PDU_CONTROL_INSTANT_SIZE
)
# Connection Parameter Request: six candidate offsets; 0xFFFF = unspecified.
PDU_CONTROL_CONN_PARAM_OFFSET_COUNT = 6
PDU_CONTROL_CONN_PARAM_OFFSET_UNSPECIFIED = 0xFFFF

# Event spacing: Core Vol 6, Part B, 4.1.1 and 4.1.2.
# Inter Frame Space, measured from the preceding packet's end.
LL_IFS_US = 150
# Minimum AUX Frame Space.
LL_MAFS_US = 300

# Procedure timing: Core Vol 6, Part B, 4.4.2, 4.4.2.12, 4.5.1, 4.5.2 and 5.2.
# Random advDelay in [0, 10 ms].
LL_ADV_DELAY_MAX_US = 10_000
# High-duty directed advertising.
LL_ADV_DIRECT_HIGH_DUTY_TIMEOUT_US = 1_280_000
# Interval/WinSize/WinOffset in connection PDUs.
LL_CONN_INTERVAL_UNIT_US = 1250
# SyncInfo Interval.
LL_PERIODIC_INTERVAL_UNIT_US = 1250
# Core Vol6 PartB4.4.5.1: six events to acquire the first periodic packet.
# This is independent of the Host timeout for an established synchronization.
LL_PERIODIC_SYNC_ESTABLISHMENT_EVENTS = 6
# Encoded interval: 6 * 1250 us = 7.5 ms.
LL_PERIODIC_INTERVAL_MIN = 6
# Timeout in connection PDUs.
LL_SUPERVISION_TIMEOUT_UNIT_US = 10_000
# Link Layer procedure response timeout.
LL_RESPONSE_TIMEOUT_US = 40_000_000
# Connection and periodic event counters wrap at 16 bits.
LL_EVENT_COUNTER_MASK = 0xFFFF
# Core 5.1.1, 5.1.2 and 5.1.10: at least six listening events before the Instant.
LL_INSTANT_MIN_LISTENING_EVENTS = 6

# Active scanning backoff: Core Vol 6, Part B, 4.4.3.2.
LL_SCAN_BACKOFF_COUNT_MIN = 1
LL_SCAN_BACKOFF_COUNT_MAX = 256
LL_SCAN_BACKOFF_OUTCOME_COUNT = 2
LL_SCAN_BACKOFF_SCALE = 2


# -----------------------------------------------------------------------------
# Advertising PDU
# -----------------------------------------------------------------------------
class AdvertisingPduType(hci.SpecableEnum):
    """On-air PDU Type field, Core Vol 6, Part B, 2.3."""

    ADV_IND = 0x00
    ADV_DIRECT_IND = 0x01
    ADV_NONCONN_IND = 0x02
    SCAN_REQ = 0x03
    SCAN_RSP = 0x04
    CONNECT_IND = 0x05
    ADV_SCAN_IND = 0x06
    ADV_EXT_IND = 0x07
    AUX_ADV_IND = ADV_EXT_IND
    AUX_SCAN_RSP = ADV_EXT_IND
    AUX_SYNC_IND = ADV_EXT_IND
    AUX_CHAIN_IND = ADV_EXT_IND
    AUX_CONNECT_RSP = 0x08
    ADV_DECISION_IND = 0x09


class AdvertisingMode(hci.SpecableEnum):
    NONCONNECTABLE_NONSCANNABLE = 0
    CONNECTABLE = 1
    SCANNABLE = 2


# -----------------------------------------------------------------------------
# Data PDU
# -----------------------------------------------------------------------------
class LlId(hci.SpecableEnum):
    """Data Physical Channel PDU LLID, Core Vol 6, Part B, 2.4.1."""

    RESERVED = 0x00
    CONTINUATION = 0x01
    START = 0x02
    CONTROL = 0x03


# -----------------------------------------------------------------------------
# Advertising PDU Objects
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
    sid: int = 0
    tx_power: int | None = None
    periodic_advertising_data: bytes | None = None


# -----------------------------------------------------------------------------
# LL Control PDU
# -----------------------------------------------------------------------------
class ControlPdu:
    """Base LL Control PDU Class.

    See Core Spec 6.3, Volume 6, Part B, 2.4.2. LL Control PDU.

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
        LL_OTA_UTP_IND = 0x3D
        LL_CONNECTION_RATE_REQ = 0x3E
        LL_CONNECTION_RATE_IND = 0x3F

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
class StartEncRsp(ControlPdu):
    opcode = ControlPdu.Opcode.LL_START_ENC_RSP


@dataclasses.dataclass
class RejectExtInd(ControlPdu):
    opcode = ControlPdu.Opcode.LL_REJECT_EXT_IND

    reject_opcode: int
    error_code: int


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


@dataclasses.dataclass
class FeatureReq(ControlPdu):
    opcode = ControlPdu.Opcode.LL_FEATURE_REQ

    feature_set: bytes


@dataclasses.dataclass
class FeatureRsp(ControlPdu):
    opcode = ControlPdu.Opcode.LL_FEATURE_RSP

    feature_set: bytes


@dataclasses.dataclass
class PeripheralFeatureReq(ControlPdu):
    opcode = ControlPdu.Opcode.LL_PERIPHERAL_FEATURE_REQ

    feature_set: bytes


@dataclasses.dataclass
class ConnectionUpdateInd(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CONNECTION_UPDATE_IND

    interval: int
    latency: int
    timeout: int


@dataclasses.dataclass
class ConnectionRateInd(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CONNECTION_UPDATE_IND

    interval: int
    subrate_factor: int
    peripheral_latency: int
    continuation_number: int
    timeout: int


@dataclasses.dataclass
class SubrateInd(ControlPdu):
    opcode = ControlPdu.Opcode.LL_SUBRATE_IND

    subrate_factor: int
    peripheral_latency: int
    continuation_number: int
    timeout: int


@dataclasses.dataclass
class CsConfigReq(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CS_CONFIG_REQ

    config_id: int
    action: int
    main_mode_type: int
    sub_mode_type: int
    min_main_mode_steps: int
    max_main_mode_steps: int
    main_mode_repetition: int
    mode_0_steps: int
    role: int
    rtt_type: int
    cs_sync_phy: int
    channel_map: bytes
    channel_map_repetition: int
    channel_selection_type: int
    ch3c_shape: int
    ch3c_jump: int


@dataclasses.dataclass
class CsConfigRsp(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CS_CONFIG_RSP

    config_id: int
    action: int
    main_mode_type: int
    sub_mode_type: int
    min_main_mode_steps: int
    max_main_mode_steps: int
    main_mode_repetition: int
    mode_0_steps: int
    role: int
    rtt_type: int
    cs_sync_phy: int
    channel_map: bytes
    channel_map_repetition: int
    channel_selection_type: int
    ch3c_shape: int
    ch3c_jump: int


@dataclasses.dataclass
class CsSecReq(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CS_SEC_REQ


@dataclasses.dataclass
class CsSecRsp(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CS_SEC_RSP


@dataclasses.dataclass
class CsReq(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CS_REQ

    config_id: int
    state: int


@dataclasses.dataclass
class CsRsp(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CS_RSP

    config_id: int
    state: int


@dataclasses.dataclass
class CsInd(ControlPdu):
    opcode = ControlPdu.Opcode.LL_CS_IND

    config_id: int
    state: int
