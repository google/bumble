from . import common_pb2 as _common_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Chip(_message.Message):
    __slots__ = ["fd_in", "fd_out", "id", "kind", "loopback", "manufacturer", "product_name"]
    FD_IN_FIELD_NUMBER: _ClassVar[int]
    FD_OUT_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    LOOPBACK_FIELD_NUMBER: _ClassVar[int]
    MANUFACTURER_FIELD_NUMBER: _ClassVar[int]
    PRODUCT_NAME_FIELD_NUMBER: _ClassVar[int]
    fd_in: int
    fd_out: int
    id: str
    kind: _common_pb2.ChipKind
    loopback: bool
    manufacturer: str
    product_name: str
    def __init__(self, kind: _Optional[_Union[_common_pb2.ChipKind, str]] = ..., id: _Optional[str] = ..., manufacturer: _Optional[str] = ..., product_name: _Optional[str] = ..., fd_in: _Optional[int] = ..., fd_out: _Optional[int] = ..., loopback: bool = ...) -> None: ...

class ChipInfo(_message.Message):
    __slots__ = ["chip", "name"]
    CHIP_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    chip: Chip
    name: str
    def __init__(self, name: _Optional[str] = ..., chip: _Optional[_Union[Chip, _Mapping]] = ...) -> None: ...

class StartupInfo(_message.Message):
    __slots__ = ["devices"]
    class Device(_message.Message):
        __slots__ = ["chips", "name"]
        CHIPS_FIELD_NUMBER: _ClassVar[int]
        NAME_FIELD_NUMBER: _ClassVar[int]
        chips: _containers.RepeatedCompositeFieldContainer[Chip]
        name: str
        def __init__(self, name: _Optional[str] = ..., chips: _Optional[_Iterable[_Union[Chip, _Mapping]]] = ...) -> None: ...
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    devices: _containers.RepeatedCompositeFieldContainer[StartupInfo.Device]
    def __init__(self, devices: _Optional[_Iterable[_Union[StartupInfo.Device, _Mapping]]] = ...) -> None: ...
