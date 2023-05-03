from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from typing import ClassVar as _ClassVar

BLUETOOTH: ChipKind
DESCRIPTOR: _descriptor.FileDescriptor
UNSPECIFIED: ChipKind
UWB: ChipKind
WIFI: ChipKind

class ChipKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
