from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from typing import ClassVar as _ClassVar

DESCRIPTOR: _descriptor.FileDescriptor

class ChipKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNSPECIFIED: _ClassVar[ChipKind]
    BLUETOOTH: _ClassVar[ChipKind]
    WIFI: _ClassVar[ChipKind]
    UWB: _ClassVar[ChipKind]
    BLUETOOTH_BEACON: _ClassVar[ChipKind]
UNSPECIFIED: ChipKind
BLUETOOTH: ChipKind
WIFI: ChipKind
UWB: ChipKind
BLUETOOTH_BEACON: ChipKind
