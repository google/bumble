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

import struct
from dataclasses import dataclass, field
from typing import TypeVar

from bumble import hci, utils


class Opcode(utils.OpenIntEnum):
    '''
    See Bluetooth spec @ Vol 2, Part C - 5.1 PDU summary.

    Follow the alphabetical order defined there.
    '''

    # fmt: off
    LMP_ACCEPTED                    = 3
    LMP_ACCEPTED_EXT                = 127 << 8 + 1
    LMP_AU_RAND                     = 11
    LMP_AUTO_RATE                   = 35
    LMP_CHANNEL_CLASSIFICATION      = 127 << 8 + 17
    LMP_CHANNEL_CLASSIFICATION_REQ  = 127 << 8 + 16
    LMP_CLK_ADJ                     = 127 << 8 + 5
    LMP_CLK_ADJ_ACK                 = 127 << 8 + 6
    LMP_CLK_ADJ_REQ                 = 127 << 8 + 7
    LMP_CLKOFFSET_REQ               = 5
    LMP_CLKOFFSET_RES               = 6
    LMP_COMB_KEY                    = 9
    LMP_DECR_POWER_REQ              = 32
    LMP_DETACH                      = 7
    LMP_DHKEY_CHECK                 = 65
    LMP_ENCAPSULATED_HEADER         = 61
    LMP_ENCAPSULATED_PAYLOAD        = 62
    LMP_ENCRYPTION_KEY_SIZE_MASK_REQ= 58
    LMP_ENCRYPTION_KEY_SIZE_MASK_RES= 59
    LMP_ENCRYPTION_KEY_SIZE_REQ     = 16
    LMP_ENCRYPTION_MODE_REQ         = 15
    LMP_ESCO_LINK_REQ               = 127 << 8 + 12
    LMP_FEATURES_REQ                = 39
    LMP_FEATURES_REQ_EXT            = 127 << 8 + 3
    LMP_FEATURES_RES                = 40
    LMP_FEATURES_RES_EXT            = 127 << 8 + 4
    LMP_HOLD                        = 20
    LMP_HOLD_REQ                    = 21
    LMP_HOST_CONNECTION_REQ         = 51
    LMP_IN_RAND                     = 8
    LMP_INCR_POWER_REQ              = 31
    LMP_IO_CAPABILITY_REQ           = 127 << 8 + 25
    LMP_IO_CAPABILITY_RES           = 127 << 8 + 26
    LMP_KEYPRESS_NOTIFICATION       = 127 << 8 + 30
    LMP_MAX_POWER                   = 33
    LMP_MAX_SLOT                    = 45
    LMP_MAX_SLOT_REQ                = 46
    LMP_MIN_POWER                   = 34
    LMP_NAME_REQ                    = 1
    LMP_NAME_RES                    = 2
    LMP_NOT_ACCEPTED                = 4
    LMP_NOT_ACCEPTED_EXT            = 127 << 8 + 2
    LMP_NUMERIC_COMPARISON_FAILED   = 127 << 8 + 27
    LMP_OOB_FAILED                  = 127 << 8 + 29
    LMP_PACKET_TYPE_TABLE_REQ       = 127 << 8 + 11
    LMP_PAGE_MODE_REQ               = 53
    LMP_PAGE_SCAN_MODE_REQ          = 54
    LMP_PASSKEY_FAILED              = 127 << 8 + 28
    LMP_PAUSE_ENCRYPTION_AES_REQ    = 66
    LMP_PAUSE_ENCRYPTION_REQ        = 127 << 8 + 23
    LMP_PING_REQ                    = 127 << 8 + 33
    LMP_PING_RES                    = 127 << 8 + 34
    LMP_POWER_CONTROL_REQ           = 127 << 8 + 31
    LMP_POWER_CONTROL_RES           = 127 << 8 + 32
    LMP_PREFERRED_RATE              = 36
    LMP_QUALITY_OF_SERVICE          = 41
    LMP_QUALITY_OF_SERVICE_REQ      = 42
    LMP_REMOVE_ESCO_LINK_REQ        = 127 << 8 + 13
    LMP_REMOVE_SCO_LINK_REQ         = 44
    LMP_RESUME_ENCRYPTION_REQ       = 127 << 8 + 24
    LMP_SAM_DEFINE_MAP              = 127 << 8 + 36
    LMP_SAM_SET_TYPE0               = 127 << 8 + 35
    LMP_SAM_SWITCH                  = 127 << 8 + 37
    LMP_SCO_LINK_REQ                = 43
    LMP_SET_AFH                     = 60
    LMP_SETUP_COMPLETE              = 49
    LMP_SIMPLE_PAIRING_CONFIRM      = 63
    LMP_SIMPLE_PAIRING_NUMBER       = 64
    LMP_SLOT_OFFSET                 = 52
    LMP_SNIFF_REQ                   = 23
    LMP_SNIFF_SUBRATING_REQ         = 127 << 8 + 21
    LMP_SNIFF_SUBRATING_RES         = 127 << 8 + 22
    LMP_SRES                        = 12
    LMP_START_ENCRYPTION_REQ        = 17
    LMP_STOP_ENCRYPTION_REQ         = 18
    LMP_SUPERVISION_TIMEOUT         = 55
    LMP_SWITCH_REQ                  = 19
    LMP_TEMP_KEY                    = 14
    LMP_TEMP_RAND                   = 13
    LMP_TEST_ACTIVATE               = 56
    LMP_TEST_CONTROL                = 57
    LMP_TIMING_ACCURACY_REQ         = 47
    LMP_TIMING_ACCURACY_RES         = 48
    LMP_UNIT_KEY                    = 10
    LMP_UNSNIFF_REQ                 = 24
    LMP_USE_SEMI_PERMANENT_KEY      = 50
    LMP_VERSION_REQ                 = 37
    LMP_VERSION_RES                 = 38
    # fmt: on

    @classmethod
    def parse_from(cls, data: bytes, offset: int = 0) -> tuple[int, Opcode]:
        opcode = data[offset]
        if opcode in (124, 127):
            opcode = struct.unpack('>H', data)[0]
            return offset + 2, Opcode(opcode)
        return offset + 1, Opcode(opcode)

    def __bytes__(self) -> bytes:
        if self.value >> 8:
            return struct.pack('>H', self.value)
        return bytes([self.value])

    @classmethod
    def type_metadata(cls):
        return hci.metadata(
            {
                'serializer': bytes,
                'parser': lambda data, offset: (Opcode.parse_from(data, offset)),
            }
        )


class Packet:
    '''
    See Bluetooth spec @ Vol 2, Part C - 5.1 PDU summary
    '''

    subclasses: dict[int, type[Packet]] = {}
    opcode: Opcode
    fields: hci.Fields = ()
    _payload: bytes = b''

    _Packet = TypeVar("_Packet", bound="Packet")

    @classmethod
    def subclass(cls, subclass: type[_Packet]) -> type[_Packet]:
        # Register a factory for this class
        cls.subclasses[subclass.opcode] = subclass
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)

        return subclass

    @classmethod
    def from_bytes(cls, data: bytes) -> Packet:
        offset, opcode = Opcode.parse_from(data)
        if not (subclass := cls.subclasses.get(opcode)):
            instance = Packet()
            instance.opcode = opcode
        else:
            instance = subclass(
                **hci.HCI_Object.dict_from_bytes(data, offset, subclass.fields)
            )
        instance.payload = data[offset:]
        return instance

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            self._payload = hci.HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return self._payload

    @payload.setter
    def payload(self, value: bytes) -> None:
        self._payload = value

    def __bytes__(self) -> bytes:
        return bytes(self.opcode) + self.payload


@Packet.subclass
@dataclass
class LmpAccepted(Packet):
    opcode = Opcode.LMP_ACCEPTED

    response_opcode: Opcode = field(metadata=Opcode.type_metadata())


@Packet.subclass
@dataclass
class LmpNotAccepted(Packet):
    opcode = Opcode.LMP_NOT_ACCEPTED

    response_opcode: Opcode = field(metadata=Opcode.type_metadata())
    error_code: int = field(metadata=hci.metadata(1))


@Packet.subclass
@dataclass
class LmpAcceptedExt(Packet):
    opcode = Opcode.LMP_ACCEPTED_EXT

    response_opcode: Opcode = field(metadata=Opcode.type_metadata())


@Packet.subclass
@dataclass
class LmpNotAcceptedExt(Packet):
    opcode = Opcode.LMP_NOT_ACCEPTED_EXT

    response_opcode: Opcode = field(metadata=Opcode.type_metadata())
    error_code: int = field(metadata=hci.metadata(1))


@Packet.subclass
@dataclass
class LmpAuRand(Packet):
    opcode = Opcode.LMP_AU_RAND

    random_number: bytes = field(metadata=hci.metadata(16))


@Packet.subclass
@dataclass
class LmpDetach(Packet):
    opcode = Opcode.LMP_DETACH

    error_code: int = field(metadata=hci.metadata(1))


@Packet.subclass
@dataclass
class LmpEscoLinkReq(Packet):
    opcode = Opcode.LMP_ESCO_LINK_REQ

    esco_handle: int = field(metadata=hci.metadata(1))
    esco_lt_addr: int = field(metadata=hci.metadata(1))
    timing_control_flags: int = field(metadata=hci.metadata(1))
    d_esco: int = field(metadata=hci.metadata(1))
    t_esco: int = field(metadata=hci.metadata(1))
    w_esco: int = field(metadata=hci.metadata(1))
    esco_packet_type_c_to_p: int = field(metadata=hci.metadata(1))
    esco_packet_type_p_to_c: int = field(metadata=hci.metadata(1))
    packet_length_c_to_p: int = field(metadata=hci.metadata(2))
    packet_length_p_to_c: int = field(metadata=hci.metadata(2))
    air_mode: int = field(metadata=hci.metadata(1))
    negotiation_state: int = field(metadata=hci.metadata(1))


@Packet.subclass
@dataclass
class LmpHostConnectionReq(Packet):
    opcode = Opcode.LMP_HOST_CONNECTION_REQ


@Packet.subclass
@dataclass
class LmpRemoveEscoLinkReq(Packet):
    opcode = Opcode.LMP_REMOVE_ESCO_LINK_REQ

    esco_handle: int = field(metadata=hci.metadata(1))
    error_code: int = field(metadata=hci.metadata(1))


@Packet.subclass
@dataclass
class LmpRemoveScoLinkReq(Packet):
    opcode = Opcode.LMP_REMOVE_SCO_LINK_REQ

    sco_handle: int = field(metadata=hci.metadata(1))
    error_code: int = field(metadata=hci.metadata(1))


@Packet.subclass
@dataclass
class LmpScoLinkReq(Packet):
    opcode = Opcode.LMP_SCO_LINK_REQ

    sco_handle: int = field(metadata=hci.metadata(1))
    timing_control_flags: int = field(metadata=hci.metadata(1))
    d_sco: int = field(metadata=hci.metadata(1))
    t_sco: int = field(metadata=hci.metadata(1))
    sco_packet: int = field(metadata=hci.metadata(1))
    air_mode: int = field(metadata=hci.metadata(1))


@Packet.subclass
@dataclass
class LmpSwitchReq(Packet):
    opcode = Opcode.LMP_SWITCH_REQ

    switch_instant: int = field(metadata=hci.metadata(4), default=0)


@Packet.subclass
@dataclass
class LmpNameReq(Packet):
    opcode = Opcode.LMP_NAME_REQ

    name_offset: int = field(metadata=hci.metadata(2))


@Packet.subclass
@dataclass
class LmpNameRes(Packet):
    opcode = Opcode.LMP_NAME_RES

    name_offset: int = field(metadata=hci.metadata(2))
    name_length: int = field(metadata=hci.metadata(3))
    name_fregment: bytes = field(metadata=hci.metadata('*'))
