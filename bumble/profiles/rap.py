# Copyright 2021-2026 Google LLC
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

"""Bluetooth Ranging Profile."""


# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import dataclasses
import enum
import struct
from collections.abc import Sequence
from typing import ClassVar, TypeVar

from typing_extensions import Self

from bumble import core, device, hci, utils


class RasFeatures(enum.IntFlag):
    """Ranging Service - 3.1.1 RAS Features format."""

    REAL_TIME_RANGING_DATA = 0x01
    RETRIEVE_LOST_RANGING_DATA_SEGMENTS = 0x02
    ABORT_OPERATION = 0x04
    FILTER_RANGING_DATA = 0x08


# -----------------------------------------------------------------------------
# RAS Control Point Operations
# -----------------------------------------------------------------------------


class RasControlPointOpCode(utils.OpenIntEnum):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    GET_RANGING_DATA = 0x00
    ACK_RANGING_DATA = 0x01
    RETRIEVE_LOST_RANGING_DATA_SEGMENTS = 0x02
    ABORT_OPERATION = 0x03
    SET_FILTER = 0x04


class RasControlPointResponseOpCode(utils.OpenIntEnum):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    COMPLETE_RANGING_DATA_RESPONSE = 0x00
    COMPLETE_LOST_RANGING_DATA_RESPONSE = 0x01
    RESPONSE_CODE = 0x02


class RasControlPointResponseCode(utils.OpenIntEnum):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    # RFU = 0x00

    # Normal response for a successful operation
    SUCCESS = 0x01
    # Normal response if an unsupported Op Code is received
    OP_CODE_NOT_SUPPORTED = 0x02
    # Normal response if Parameter received does not meet the requirements of the
    # service
    INVALID_PARAMETER = 0x03
    # Normal response for a successful write operation where the values written to
    # the RAS Control Point are being persisted.
    SUCCESS_PERSISTED = 0x04
    # Normal response if a request for Abort is unsuccessful
    ABORT_UNSUCCESSFUL = 0x05
    # Normal response if unable to complete a procedure for any reason
    PROCEDURE_NOT_COMPLETED = 0x06
    # Normal response if the Server is still busy with other requests
    SERVER_BUSY = 0x07
    # Normal response if the requested Ranging Counter is not found
    NO_RECORDS_FOUND = 0x08


@dataclasses.dataclass
class RasControlPointOperation:
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code: ClassVar[RasControlPointOpCode]
    fields: ClassVar[hci.Fields]
    subclasses: ClassVar[
        dict[RasControlPointOpCode, type[RasControlPointOperation]]
    ] = {}
    _payload: bytes | None = dataclasses.field(default=None, init=False, repr=False)

    _OP = TypeVar("_OP", bound="RasControlPointOperation")

    @classmethod
    def subclass(cls, subclass: type[_OP]) -> type[_OP]:
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)

        # Register a factory for this class
        RasControlPointOperation.subclasses[subclass.op_code] = subclass

        return subclass

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            self._payload = hci.HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return self._payload

    @payload.setter
    def payload(self, value: bytes) -> None:
        self._payload = value

    @classmethod
    def from_bytes(cls, pdu: bytes) -> RasControlPointOperation:
        op_code = RasControlPointOpCode(pdu[0])

        subclass = cls.subclasses[op_code]
        instance = subclass(**hci.HCI_Object.dict_from_bytes(pdu, 1, subclass.fields))
        instance.payload = pdu[1:]
        return instance

    def __bytes__(self):
        return bytes([self.op_code]) + self.payload


@RasControlPointOperation.subclass
@dataclasses.dataclass
class GetRangingDataOperation(RasControlPointOperation):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code = RasControlPointOpCode.GET_RANGING_DATA

    ranging_counter: int = dataclasses.field(metadata=hci.metadata(2))


@RasControlPointOperation.subclass
@dataclasses.dataclass
class AckRangingDataOperation(RasControlPointOperation):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code = RasControlPointOpCode.ACK_RANGING_DATA

    ranging_counter: int = dataclasses.field(metadata=hci.metadata(2))


@RasControlPointOperation.subclass
@dataclasses.dataclass
class RetrieveLostRangingDataSegmentsOperation(RasControlPointOperation):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code = RasControlPointOpCode.RETRIEVE_LOST_RANGING_DATA_SEGMENTS

    ranging_counter: int = dataclasses.field(metadata=hci.metadata(2))
    first_segment_index: int = dataclasses.field(metadata=hci.metadata(1))
    last_segment_index: int = dataclasses.field(metadata=hci.metadata(1))


@RasControlPointOperation.subclass
@dataclasses.dataclass
class AbortOperationOperation(RasControlPointOperation):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code = RasControlPointOpCode.ABORT_OPERATION


@RasControlPointOperation.subclass
@dataclasses.dataclass
class SetFilterOperation(RasControlPointOperation):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code = RasControlPointOpCode.SET_FILTER

    filter_configuration: int = dataclasses.field(metadata=hci.metadata(2))


# -----------------------------------------------------------------------------
# RAS Control Point Operation Responses
# -----------------------------------------------------------------------------


@dataclasses.dataclass
class ControlPointOperationResponse:
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code: ClassVar[RasControlPointResponseOpCode]
    fields: ClassVar[hci.Fields]
    subclasses: ClassVar[
        dict[RasControlPointResponseOpCode, type[ControlPointOperationResponse]]
    ] = {}
    _payload: bytes | None = dataclasses.field(default=None, init=False, repr=False)

    _OP = TypeVar("_OP", bound="ControlPointOperationResponse")

    @classmethod
    def subclass(cls, subclass: type[_OP]) -> type[_OP]:
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)

        # Register a factory for this class
        ControlPointOperationResponse.subclasses[subclass.op_code] = subclass

        return subclass

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            self._payload = hci.HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return self._payload

    @payload.setter
    def payload(self, value: bytes) -> None:
        self._payload = value

    @classmethod
    def from_bytes(cls, pdu: bytes) -> ControlPointOperationResponse:
        op_code = RasControlPointResponseOpCode(pdu[0])

        subclass = cls.subclasses[op_code]
        instance = subclass(**hci.HCI_Object.dict_from_bytes(pdu, 1, subclass.fields))
        instance.payload = pdu[1:]
        return instance

    def __bytes__(self):
        return bytes([self.op_code]) + self.payload


@ControlPointOperationResponse.subclass
@dataclasses.dataclass
class CompleteRangingDataResponse(ControlPointOperationResponse):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code = RasControlPointResponseOpCode.COMPLETE_RANGING_DATA_RESPONSE

    ranging_counter: int = dataclasses.field(metadata=hci.metadata(2))


@ControlPointOperationResponse.subclass
@dataclasses.dataclass
class CompleteLostRangingDataResponse(ControlPointOperationResponse):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code = RasControlPointResponseOpCode.COMPLETE_LOST_RANGING_DATA_RESPONSE

    ranging_counter: int = dataclasses.field(metadata=hci.metadata(2))
    first_segment_index: int = dataclasses.field(metadata=hci.metadata(1))
    last_segment_index: int = dataclasses.field(metadata=hci.metadata(1))


@ControlPointOperationResponse.subclass
@dataclasses.dataclass
class CodeResponse(ControlPointOperationResponse):
    """Ranging Service - 3.3.1 RAS Control Point Op Codes and Parameters requirements."""

    op_code = RasControlPointResponseOpCode.RESPONSE_CODE

    value: int = dataclasses.field(metadata=hci.metadata(1))


@dataclasses.dataclass
class SegmentationHeader:
    """Ranging Service - 3.2.1.1 Segmentation Header."""

    is_first: bool
    is_last: bool
    segment_index: int

    def __bytes__(self) -> bytes:
        return bytes(
            [
                (
                    ((self.segment_index & 0x3F) << 2)
                    | (0x01 if self.is_first else 0x00)
                    | (0x02 if self.is_last else 0x00)
                )
            ]
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Parse Segmentation Header from bytes."""
        return cls(
            is_first=bool(data[0] & 0x01),
            is_last=bool(data[0] & 0x02),
            segment_index=data[0] >> 2,
        )


@dataclasses.dataclass
class RangingHeader:
    """Ranging Service - Table 3.7: Ranging Header structure."""

    configuration_id: int
    selected_tx_power: int
    antenna_paths_mask: int
    ranging_counter: int

    def __bytes__(self) -> bytes:
        return struct.pack(
            '<HbB',
            self.configuration_id << 12 | (self.ranging_counter & 0xFFF),
            self.selected_tx_power,
            self.antenna_paths_mask,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Parse Ranging Header from bytes."""
        (
            ranging_counter_and_configuration_id,
            selected_tx_power,
            antenna_paths_mask,
        ) = struct.unpack_from('<HbB', data)
        return cls(
            ranging_counter=ranging_counter_and_configuration_id & 0x3F,
            configuration_id=ranging_counter_and_configuration_id >> 12,
            selected_tx_power=selected_tx_power,
            antenna_paths_mask=antenna_paths_mask,
        )


# -----------------------------------------------------------------------------
# Ranging Data
# -----------------------------------------------------------------------------


@dataclasses.dataclass
class Step:
    """Ranging Service - Table 3.8: Subevent Header and Data structure."""

    mode: int
    data: bytes

    def __bytes__(self) -> bytes:
        return bytes([self.mode]) + self.data

    @classmethod
    def parse_from(
        cls,
        data: bytes,
        config: device.ChannelSoundingConfig,
        num_antenna_paths: int,
        offset: int = 0,
    ) -> tuple[int, Self]:
        """Parse Step from bytes."""
        mode = data[offset]
        contain_sounding_sequence = config.rtt_type in (
            hci.RttType.SOUNDING_SEQUENCE_32_BIT,
            hci.RttType.SOUNDING_SEQUENCE_96_BIT,
        )
        is_initiator = config.role == hci.CsRole.INITIATOR

        match mode:
            case 0:
                length = 5 if is_initiator else 3
            case 1:
                length = 12 if contain_sounding_sequence else 6
            case 2:
                length = (num_antenna_paths + 1) * 4 + 1
            case 3:
                length = (num_antenna_paths + 1) * 4 + (
                    13 if contain_sounding_sequence else 7
                )
            case _:
                raise core.InvalidPacketError(f'Unknown mode 0x{mode:02X}')
        return (offset + length + 1), cls(
            mode=mode, data=data[offset + 1 : offset + 1 + length]
        )


@dataclasses.dataclass
class Subevent:
    """Ranging Service - Table 3.8: Subevent Header and Data structure."""

    start_acl_connection_event: int
    frequency_compensation: int
    ranging_done_status: int
    subevent_done_status: int
    ranging_abort_reason: int
    subevent_abort_reason: int
    reference_power_level: int
    steps: Sequence[Step] = dataclasses.field(default_factory=list)

    def __bytes__(self) -> bytes:
        return struct.pack(
            '<HHBBbB',
            self.start_acl_connection_event,
            self.frequency_compensation,
            self.ranging_done_status | self.subevent_done_status << 4,
            self.ranging_abort_reason | self.subevent_abort_reason << 4,
            self.reference_power_level,
            len(self.steps),
        ) + b''.join(map(bytes, self.steps))

    @classmethod
    def parse_from(
        cls,
        data: bytes,
        config: device.ChannelSoundingConfig,
        num_antenna_paths: int,
        offset: int = 0,
    ) -> tuple[int, Self]:
        """Parse Subevent from bytes."""
        (
            start_acl_connection_event,
            frequency_compensation,
            ranging_done_status_and_subevent_done_status,
            ranging_abort_reason_and_subevent_abort_reason,
            reference_power_level,
            num_reported_steps,
        ) = struct.unpack_from('<HHBBbB', data, offset)
        offset += 8
        steps: list[Step] = []
        for _ in range(num_reported_steps):
            offset, step = Step.parse_from(
                data=data,
                config=config,
                num_antenna_paths=num_antenna_paths,
                offset=offset,
            )
            steps.append(step)
        return offset, cls(
            start_acl_connection_event=start_acl_connection_event,
            frequency_compensation=frequency_compensation,
            ranging_done_status=ranging_done_status_and_subevent_done_status & 0x0F,
            subevent_done_status=ranging_done_status_and_subevent_done_status >> 4,
            ranging_abort_reason=ranging_abort_reason_and_subevent_abort_reason & 0x0F,
            subevent_abort_reason=ranging_abort_reason_and_subevent_abort_reason >> 4,
            reference_power_level=reference_power_level,
            steps=steps,
        )


@dataclasses.dataclass
class RangingData:
    """Ranging Service - 3.2.1 Ranging Data format."""

    ranging_header: RangingHeader
    subevents: Sequence[Subevent] = dataclasses.field(default_factory=list)

    def __bytes__(self) -> bytes:
        return bytes(self.ranging_header) + b''.join(map(bytes, self.subevents))

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        config: device.ChannelSoundingConfig,
    ) -> Self:
        """Parse Ranging Data from bytes."""
        ranging_header = RangingHeader.from_bytes(data)
        num_antenna_paths = 0
        antenna_path_mask = ranging_header.antenna_paths_mask
        while antenna_path_mask > 0:
            if antenna_path_mask & 0x01:
                num_antenna_paths += 1
            antenna_path_mask >>= 1

        subevents: list[Subevent] = []
        offset = 4
        while offset < len(data):
            offset, subevent = Subevent.parse_from(
                data=data,
                config=config,
                num_antenna_paths=num_antenna_paths,
                offset=offset,
            )
            subevents.append(subevent)
        return cls(ranging_header=ranging_header, subevents=subevents)
