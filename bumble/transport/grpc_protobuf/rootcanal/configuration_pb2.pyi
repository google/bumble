from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ControllerPreset(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DEFAULT: _ClassVar[ControllerPreset]
    LAIRD_BL654: _ClassVar[ControllerPreset]
    CSR_RCK_PTS_DONGLE: _ClassVar[ControllerPreset]
DEFAULT: ControllerPreset
LAIRD_BL654: ControllerPreset
CSR_RCK_PTS_DONGLE: ControllerPreset

class ControllerFeatures(_message.Message):
    __slots__ = ("le_extended_advertising", "le_periodic_advertising", "ll_privacy", "le_2m_phy", "le_coded_phy", "le_connected_isochronous_stream")
    LE_EXTENDED_ADVERTISING_FIELD_NUMBER: _ClassVar[int]
    LE_PERIODIC_ADVERTISING_FIELD_NUMBER: _ClassVar[int]
    LL_PRIVACY_FIELD_NUMBER: _ClassVar[int]
    LE_2M_PHY_FIELD_NUMBER: _ClassVar[int]
    LE_CODED_PHY_FIELD_NUMBER: _ClassVar[int]
    LE_CONNECTED_ISOCHRONOUS_STREAM_FIELD_NUMBER: _ClassVar[int]
    le_extended_advertising: bool
    le_periodic_advertising: bool
    ll_privacy: bool
    le_2m_phy: bool
    le_coded_phy: bool
    le_connected_isochronous_stream: bool
    def __init__(self, le_extended_advertising: bool = ..., le_periodic_advertising: bool = ..., ll_privacy: bool = ..., le_2m_phy: bool = ..., le_coded_phy: bool = ..., le_connected_isochronous_stream: bool = ...) -> None: ...

class ControllerQuirks(_message.Message):
    __slots__ = ("send_acl_data_before_connection_complete", "has_default_random_address", "hardware_error_before_reset")
    SEND_ACL_DATA_BEFORE_CONNECTION_COMPLETE_FIELD_NUMBER: _ClassVar[int]
    HAS_DEFAULT_RANDOM_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    HARDWARE_ERROR_BEFORE_RESET_FIELD_NUMBER: _ClassVar[int]
    send_acl_data_before_connection_complete: bool
    has_default_random_address: bool
    hardware_error_before_reset: bool
    def __init__(self, send_acl_data_before_connection_complete: bool = ..., has_default_random_address: bool = ..., hardware_error_before_reset: bool = ...) -> None: ...

class VendorFeatures(_message.Message):
    __slots__ = ("csr", "android")
    CSR_FIELD_NUMBER: _ClassVar[int]
    ANDROID_FIELD_NUMBER: _ClassVar[int]
    csr: bool
    android: bool
    def __init__(self, csr: bool = ..., android: bool = ...) -> None: ...

class Controller(_message.Message):
    __slots__ = ("preset", "features", "quirks", "strict", "vendor")
    PRESET_FIELD_NUMBER: _ClassVar[int]
    FEATURES_FIELD_NUMBER: _ClassVar[int]
    QUIRKS_FIELD_NUMBER: _ClassVar[int]
    STRICT_FIELD_NUMBER: _ClassVar[int]
    VENDOR_FIELD_NUMBER: _ClassVar[int]
    preset: ControllerPreset
    features: ControllerFeatures
    quirks: ControllerQuirks
    strict: bool
    vendor: VendorFeatures
    def __init__(self, preset: _Optional[_Union[ControllerPreset, str]] = ..., features: _Optional[_Union[ControllerFeatures, _Mapping]] = ..., quirks: _Optional[_Union[ControllerQuirks, _Mapping]] = ..., strict: bool = ..., vendor: _Optional[_Union[VendorFeatures, _Mapping]] = ...) -> None: ...

class TcpServer(_message.Message):
    __slots__ = ("tcp_port", "configuration")
    TCP_PORT_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    tcp_port: int
    configuration: Controller
    def __init__(self, tcp_port: _Optional[int] = ..., configuration: _Optional[_Union[Controller, _Mapping]] = ...) -> None: ...

class Configuration(_message.Message):
    __slots__ = ("tcp_server",)
    TCP_SERVER_FIELD_NUMBER: _ClassVar[int]
    tcp_server: _containers.RepeatedCompositeFieldContainer[TcpServer]
    def __init__(self, tcp_server: _Optional[_Iterable[_Union[TcpServer, _Mapping]]] = ...) -> None: ...
