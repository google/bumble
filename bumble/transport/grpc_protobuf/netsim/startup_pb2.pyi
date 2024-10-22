from bumble.transport.grpc_protobuf.netsim import common_pb2 as _common_pb2
from bumble.transport.grpc_protobuf.netsim import model_pb2 as _model_pb2
from bumble.transport.grpc_protobuf.rootcanal import configuration_pb2 as _configuration_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class StartupInfo(_message.Message):
    __slots__ = ("devices",)
    class Device(_message.Message):
        __slots__ = ("name", "chips", "device_info")
        NAME_FIELD_NUMBER: _ClassVar[int]
        CHIPS_FIELD_NUMBER: _ClassVar[int]
        DEVICE_INFO_FIELD_NUMBER: _ClassVar[int]
        name: str
        chips: _containers.RepeatedCompositeFieldContainer[Chip]
        device_info: DeviceInfo
        def __init__(self, name: _Optional[str] = ..., chips: _Optional[_Iterable[_Union[Chip, _Mapping]]] = ..., device_info: _Optional[_Union[DeviceInfo, _Mapping]] = ...) -> None: ...
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    devices: _containers.RepeatedCompositeFieldContainer[StartupInfo.Device]
    def __init__(self, devices: _Optional[_Iterable[_Union[StartupInfo.Device, _Mapping]]] = ...) -> None: ...

class ChipInfo(_message.Message):
    __slots__ = ("name", "chip", "device_info")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CHIP_FIELD_NUMBER: _ClassVar[int]
    DEVICE_INFO_FIELD_NUMBER: _ClassVar[int]
    name: str
    chip: Chip
    device_info: DeviceInfo
    def __init__(self, name: _Optional[str] = ..., chip: _Optional[_Union[Chip, _Mapping]] = ..., device_info: _Optional[_Union[DeviceInfo, _Mapping]] = ...) -> None: ...

class DeviceInfo(_message.Message):
    __slots__ = ("name", "kind", "version", "sdk_version", "build_id", "variant", "arch")
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SDK_VERSION_FIELD_NUMBER: _ClassVar[int]
    BUILD_ID_FIELD_NUMBER: _ClassVar[int]
    VARIANT_FIELD_NUMBER: _ClassVar[int]
    ARCH_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: str
    version: str
    sdk_version: str
    build_id: str
    variant: str
    arch: str
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[str] = ..., version: _Optional[str] = ..., sdk_version: _Optional[str] = ..., build_id: _Optional[str] = ..., variant: _Optional[str] = ..., arch: _Optional[str] = ...) -> None: ...

class Chip(_message.Message):
    __slots__ = ("kind", "id", "manufacturer", "product_name", "fd_in", "fd_out", "loopback", "bt_properties", "address", "offset")
    KIND_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    MANUFACTURER_FIELD_NUMBER: _ClassVar[int]
    PRODUCT_NAME_FIELD_NUMBER: _ClassVar[int]
    FD_IN_FIELD_NUMBER: _ClassVar[int]
    FD_OUT_FIELD_NUMBER: _ClassVar[int]
    LOOPBACK_FIELD_NUMBER: _ClassVar[int]
    BT_PROPERTIES_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    kind: _common_pb2.ChipKind
    id: str
    manufacturer: str
    product_name: str
    fd_in: int
    fd_out: int
    loopback: bool
    bt_properties: _configuration_pb2.Controller
    address: str
    offset: _model_pb2.Position
    def __init__(self, kind: _Optional[_Union[_common_pb2.ChipKind, str]] = ..., id: _Optional[str] = ..., manufacturer: _Optional[str] = ..., product_name: _Optional[str] = ..., fd_in: _Optional[int] = ..., fd_out: _Optional[int] = ..., loopback: bool = ..., bt_properties: _Optional[_Union[_configuration_pb2.Controller, _Mapping]] = ..., address: _Optional[str] = ..., offset: _Optional[_Union[_model_pb2.Position, _Mapping]] = ...) -> None: ...
