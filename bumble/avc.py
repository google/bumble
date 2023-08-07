# Copyright 2021-2023 Google LLC
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
import enum
import struct
from typing import Dict, Type, Union, Tuple

from bumble.utils import OpenIntEnum


# -----------------------------------------------------------------------------
class Frame:
    class SubunitType(enum.IntEnum):
        # AV/C Digital Interface Command Set General Specification Version 4.1
        # Table 7.4
        MONITOR = 0x00
        AUDIO = 0x01
        PRINTER = 0x02
        DISC = 0x03
        TAPE_RECORDER_OR_PLAYER = 0x04
        TUNER = 0x05
        CA = 0x06
        CAMERA = 0x07
        PANEL = 0x09
        BULLETIN_BOARD = 0x0A
        VENDOR_UNIQUE = 0x1C
        EXTENDED = 0x1E
        UNIT = 0x1F

    class OperationCode(OpenIntEnum):
        # 0x00 - 0x0F: Unit and subunit commands
        VENDOR_DEPENDENT = 0x00
        RESERVE = 0x01
        PLUG_INFO = 0x02

        # 0x10 - 0x3F: Unit commands
        DIGITAL_OUTPUT = 0x10
        DIGITAL_INPUT = 0x11
        CHANNEL_USAGE = 0x12
        OUTPUT_PLUG_SIGNAL_FORMAT = 0x18
        INPUT_PLUG_SIGNAL_FORMAT = 0x19
        GENERAL_BUS_SETUP = 0x1F
        CONNECT_AV = 0x20
        DISCONNECT_AV = 0x21
        CONNECTIONS = 0x22
        CONNECT = 0x24
        DISCONNECT = 0x25
        UNIT_INFO = 0x30
        SUBUNIT_INFO = 0x31

        # 0x40 - 0x7F: Subunit commands
        PASS_THROUGH = 0x7C
        GUI_UPDATE = 0x7D
        PUSH_GUI_DATA = 0x7E
        USER_ACTION = 0x7F

        # 0xA0 - 0xBF: Unit and subunit commands
        VERSION = 0xB0
        POWER = 0xB2

    subunit_type: SubunitType
    subunit_id: int
    opcode: OperationCode
    operands: bytes

    @staticmethod
    def subclass(subclass):
        # Infer the opcode from the class name
        if subclass.__name__.endswith("CommandFrame"):
            short_name = subclass.__name__.replace("CommandFrame", "")
            category_class = CommandFrame
        elif subclass.__name__.endswith("ResponseFrame"):
            short_name = subclass.__name__.replace("ResponseFrame", "")
            category_class = ResponseFrame
        else:
            raise ValueError(f"invalid subclass name {subclass.__name__}")

        uppercase_indexes = [
            i for i in range(len(short_name)) if short_name[i].isupper()
        ]
        uppercase_indexes.append(len(short_name))
        words = [
            short_name[uppercase_indexes[i] : uppercase_indexes[i + 1]].upper()
            for i in range(len(uppercase_indexes) - 1)
        ]
        opcode_name = "_".join(words)
        opcode = Frame.OperationCode[opcode_name]
        category_class.subclasses[opcode] = subclass
        return subclass

    @staticmethod
    def from_bytes(data: bytes) -> Frame:
        if data[0] >> 4 != 0:
            raise ValueError("first 4 bits must be 0s")

        ctype_or_response = data[0] & 0xF
        subunit_type = Frame.SubunitType(data[1] >> 3)
        subunit_id = data[1] & 7

        if subunit_type == Frame.SubunitType.EXTENDED:
            # Not supported
            raise NotImplementedError("extended subunit types not supported")

        if subunit_id < 5:
            opcode_offset = 2
        elif subunit_id == 5:
            # Extended to the next byte
            extension = data[2]
            if extension == 0:
                raise ValueError("extended subunit ID value reserved")
            if extension == 0xFF:
                subunit_id = 5 + 254 + data[3]
                opcode_offset = 4
            else:
                subunit_id = 5 + extension
                opcode_offset = 3

        elif subunit_id == 6:
            raise ValueError("reserved subunit ID")

        opcode = Frame.OperationCode(data[opcode_offset])
        operands = data[opcode_offset + 1 :]

        # Look for a registered subclass
        if ctype_or_response < 8:
            # Command
            ctype = CommandFrame.CommandType(ctype_or_response)
            if c_subclass := CommandFrame.subclasses.get(opcode):
                return c_subclass(
                    ctype,
                    subunit_type,
                    subunit_id,
                    *c_subclass.parse_operands(operands),
                )
            return CommandFrame(ctype, subunit_type, subunit_id, opcode, operands)
        else:
            # Response
            response = ResponseFrame.ResponseCode(ctype_or_response)
            if r_subclass := ResponseFrame.subclasses.get(opcode):
                return r_subclass(
                    response,
                    subunit_type,
                    subunit_id,
                    *r_subclass.parse_operands(operands),
                )
            return ResponseFrame(response, subunit_type, subunit_id, opcode, operands)

    def to_bytes(
        self,
        ctype_or_response: Union[CommandFrame.CommandType, ResponseFrame.ResponseCode],
    ) -> bytes:
        # TODO: support extended subunit types and ids.
        return (
            bytes(
                [
                    ctype_or_response,
                    self.subunit_type << 3 | self.subunit_id,
                    self.opcode,
                ]
            )
            + self.operands
        )

    def to_string(self, extra: str) -> str:
        return (
            f"{self.__class__.__name__}({extra}"
            f"subunit_type={self.subunit_type.name}, "
            f"subunit_id=0x{self.subunit_id:02X}, "
            f"opcode={self.opcode.name}, "
            f"operands={self.operands.hex()})"
        )

    def __init__(
        self,
        subunit_type: SubunitType,
        subunit_id: int,
        opcode: OperationCode,
        operands: bytes,
    ) -> None:
        self.subunit_type = subunit_type
        self.subunit_id = subunit_id
        self.opcode = opcode
        self.operands = operands


# -----------------------------------------------------------------------------
class CommandFrame(Frame):
    class CommandType(OpenIntEnum):
        # AV/C Digital Interface Command Set General Specification Version 4.1
        # Table 7.1
        CONTROL = 0x00
        STATUS = 0x01
        SPECIFIC_INQUIRY = 0x02
        NOTIFY = 0x03
        GENERAL_INQUIRY = 0x04

    subclasses: Dict[Frame.OperationCode, Type[CommandFrame]] = {}
    ctype: CommandType

    @staticmethod
    def parse_operands(operands: bytes) -> Tuple:
        raise NotImplementedError

    def __init__(
        self,
        ctype: CommandType,
        subunit_type: Frame.SubunitType,
        subunit_id: int,
        opcode: Frame.OperationCode,
        operands: bytes,
    ) -> None:
        super().__init__(subunit_type, subunit_id, opcode, operands)
        self.ctype = ctype

    def __bytes__(self):
        return self.to_bytes(self.ctype)

    def __str__(self):
        return self.to_string(f"ctype={self.ctype.name}, ")


# -----------------------------------------------------------------------------
class ResponseFrame(Frame):
    class ResponseCode(OpenIntEnum):
        # AV/C Digital Interface Command Set General Specification Version 4.1
        # Table 7.2
        NOT_IMPLEMENTED = 0x08
        ACCEPTED = 0x09
        REJECTED = 0x0A
        IN_TRANSITION = 0x0B
        IMPLEMENTED_OR_STABLE = 0x0C
        CHANGED = 0x0D
        INTERIM = 0x0F

    subclasses: Dict[Frame.OperationCode, Type[ResponseFrame]] = {}
    response: ResponseCode

    @staticmethod
    def parse_operands(operands: bytes) -> Tuple:
        raise NotImplementedError

    def __init__(
        self,
        response: ResponseCode,
        subunit_type: Frame.SubunitType,
        subunit_id: int,
        opcode: Frame.OperationCode,
        operands: bytes,
    ) -> None:
        super().__init__(subunit_type, subunit_id, opcode, operands)
        self.response = response

    def __bytes__(self):
        return self.to_bytes(self.response)

    def __str__(self):
        return self.to_string(f"response={self.response.name}, ")


# -----------------------------------------------------------------------------
class VendorDependentFrame:
    company_id: int
    vendor_dependent_data: bytes

    @staticmethod
    def parse_operands(operands: bytes) -> Tuple:
        return (
            struct.unpack(">I", b"\x00" + operands[:3])[0],
            operands[3:],
        )

    def make_operands(self) -> bytes:
        return struct.pack(">I", self.company_id)[1:] + self.vendor_dependent_data

    def __init__(self, company_id: int, vendor_dependent_data: bytes):
        self.company_id = company_id
        self.vendor_dependent_data = vendor_dependent_data


# -----------------------------------------------------------------------------
@Frame.subclass
class VendorDependentCommandFrame(VendorDependentFrame, CommandFrame):
    def __init__(
        self,
        ctype: CommandFrame.CommandType,
        subunit_type: Frame.SubunitType,
        subunit_id: int,
        company_id: int,
        vendor_dependent_data: bytes,
    ) -> None:
        VendorDependentFrame.__init__(self, company_id, vendor_dependent_data)
        CommandFrame.__init__(
            self,
            ctype,
            subunit_type,
            subunit_id,
            Frame.OperationCode.VENDOR_DEPENDENT,
            self.make_operands(),
        )

    def __str__(self):
        return (
            f"VendorDependentCommandFrame(ctype={self.ctype.name}, "
            f"subunit_type={self.subunit_type.name}, "
            f"subunit_id=0x{self.subunit_id:02X}, "
            f"company_id=0x{self.company_id:06X}, "
            f"vendor_dependent_data={self.vendor_dependent_data.hex()})"
        )


# -----------------------------------------------------------------------------
@Frame.subclass
class VendorDependentResponseFrame(VendorDependentFrame, ResponseFrame):
    def __init__(
        self,
        response: ResponseFrame.ResponseCode,
        subunit_type: Frame.SubunitType,
        subunit_id: int,
        company_id: int,
        vendor_dependent_data: bytes,
    ) -> None:
        VendorDependentFrame.__init__(self, company_id, vendor_dependent_data)
        ResponseFrame.__init__(
            self,
            response,
            subunit_type,
            subunit_id,
            Frame.OperationCode.VENDOR_DEPENDENT,
            self.make_operands(),
        )

    def __str__(self):
        return (
            f"VendorDependentResponseFrame(response={self.response.name}, "
            f"subunit_type={self.subunit_type.name}, "
            f"subunit_id=0x{self.subunit_id:02X}, "
            f"company_id=0x{self.company_id:06X}, "
            f"vendor_dependent_data={self.vendor_dependent_data.hex()})"
        )


# -----------------------------------------------------------------------------
class PassThroughFrame:
    """
    See AV/C Panel Subunit Specification 1.1 - 9.4 PASS THROUGH control command
    """

    class StateFlag(enum.IntEnum):
        PRESSED = 0
        RELEASED = 1

    class OperationId(OpenIntEnum):
        SELECT = 0x00
        UP = 0x01
        DOWN = 0x01
        LEFT = 0x03
        RIGHT = 0x04
        RIGHT_UP = 0x05
        RIGHT_DOWN = 0x06
        LEFT_UP = 0x07
        LEFT_DOWN = 0x08
        ROOT_MENU = 0x09
        SETUP_MENU = 0x0A
        CONTENTS_MENU = 0x0B
        FAVORITE_MENU = 0x0C
        EXIT = 0x0D
        NUMBER_0 = 0x20
        NUMBER_1 = 0x21
        NUMBER_2 = 0x22
        NUMBER_3 = 0x23
        NUMBER_4 = 0x24
        NUMBER_5 = 0x25
        NUMBER_6 = 0x26
        NUMBER_7 = 0x27
        NUMBER_8 = 0x28
        NUMBER_9 = 0x29
        DOT = 0x2A
        ENTER = 0x2B
        CLEAR = 0x2C
        CHANNEL_UP = 0x30
        CHANNEL_DOWN = 0x31
        PREVIOUS_CHANNEL = 0x32
        SOUND_SELECT = 0x33
        INPUT_SELECT = 0x34
        DISPLAY_INFORMATION = 0x35
        HELP = 0x36
        PAGE_UP = 0x37
        PAGE_DOWN = 0x38
        POWER = 0x40
        VOLUME_UP = 0x41
        VOLUME_DOWN = 0x42
        MUTE = 0x43
        PLAY = 0x44
        STOP = 0x45
        PAUSE = 0x46
        RECORD = 0x47
        REWIND = 0x48
        FAST_FORWARD = 0x49
        EJECT = 0x4A
        FORWARD = 0x4B
        BACKWARD = 0x4C
        ANGLE = 0x50
        SUBPICTURE = 0x51
        F1 = 0x71
        F2 = 0x72
        F3 = 0x73
        F4 = 0x74
        F5 = 0x75
        VENDOR_UNIQUE = 0x7E

    state_flag: StateFlag
    operation_id: OperationId
    operation_data: bytes

    @staticmethod
    def parse_operands(operands: bytes) -> Tuple:
        return (
            PassThroughFrame.StateFlag(operands[0] >> 7),
            PassThroughFrame.OperationId(operands[0] & 0x7F),
            operands[1 : 1 + operands[1]],
        )

    def make_operands(self):
        return (
            bytes([self.state_flag << 7 | self.operation_id, len(self.operation_data)])
            + self.operation_data
        )

    def __init__(
        self,
        state_flag: StateFlag,
        operation_id: OperationId,
        operation_data: bytes,
    ) -> None:
        if len(operation_data) > 255:
            raise ValueError("operation data must be <= 255 bytes")
        self.state_flag = state_flag
        self.operation_id = operation_id
        self.operation_data = operation_data


# -----------------------------------------------------------------------------
@Frame.subclass
class PassThroughCommandFrame(PassThroughFrame, CommandFrame):
    def __init__(
        self,
        ctype: CommandFrame.CommandType,
        subunit_type: Frame.SubunitType,
        subunit_id: int,
        state_flag: PassThroughFrame.StateFlag,
        operation_id: PassThroughFrame.OperationId,
        operation_data: bytes,
    ) -> None:
        PassThroughFrame.__init__(self, state_flag, operation_id, operation_data)
        CommandFrame.__init__(
            self,
            ctype,
            subunit_type,
            subunit_id,
            Frame.OperationCode.PASS_THROUGH,
            self.make_operands(),
        )

    def __str__(self):
        return (
            f"PassThroughCommandFrame(ctype={self.ctype.name}, "
            f"subunit_type={self.subunit_type.name}, "
            f"subunit_id=0x{self.subunit_id:02X}, "
            f"state_flag={self.state_flag.name}, "
            f"operation_id={self.operation_id.name}, "
            f"operation_data={self.operation_data.hex()})"
        )


# -----------------------------------------------------------------------------
@Frame.subclass
class PassThroughResponseFrame(PassThroughFrame, ResponseFrame):
    def __init__(
        self,
        response: ResponseFrame.ResponseCode,
        subunit_type: Frame.SubunitType,
        subunit_id: int,
        state_flag: PassThroughFrame.StateFlag,
        operation_id: PassThroughFrame.OperationId,
        operation_data: bytes,
    ) -> None:
        PassThroughFrame.__init__(self, state_flag, operation_id, operation_data)
        ResponseFrame.__init__(
            self,
            response,
            subunit_type,
            subunit_id,
            Frame.OperationCode.PASS_THROUGH,
            self.make_operands(),
        )

    def __str__(self):
        return (
            f"PassThroughResponseFrame(response={self.response.name}, "
            f"subunit_type={self.subunit_type.name}, "
            f"subunit_id=0x{self.subunit_id:02X}, "
            f"state_flag={self.state_flag.name}, "
            f"operation_id={self.operation_id.name}, "
            f"operation_data={self.operation_data.hex()})"
        )
