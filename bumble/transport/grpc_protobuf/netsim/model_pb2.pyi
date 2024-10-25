from bumble.transport.grpc_protobuf.netsim import common_pb2 as _common_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from bumble.transport.grpc_protobuf.rootcanal import configuration_pb2 as _configuration_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PhyKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NONE: _ClassVar[PhyKind]
    BLUETOOTH_CLASSIC: _ClassVar[PhyKind]
    BLUETOOTH_LOW_ENERGY: _ClassVar[PhyKind]
    WIFI: _ClassVar[PhyKind]
    UWB: _ClassVar[PhyKind]
    WIFI_RTT: _ClassVar[PhyKind]
NONE: PhyKind
BLUETOOTH_CLASSIC: PhyKind
BLUETOOTH_LOW_ENERGY: PhyKind
WIFI: PhyKind
UWB: PhyKind
WIFI_RTT: PhyKind

class Position(_message.Message):
    __slots__ = ("x", "y", "z")
    X_FIELD_NUMBER: _ClassVar[int]
    Y_FIELD_NUMBER: _ClassVar[int]
    Z_FIELD_NUMBER: _ClassVar[int]
    x: float
    y: float
    z: float
    def __init__(self, x: _Optional[float] = ..., y: _Optional[float] = ..., z: _Optional[float] = ...) -> None: ...

class Orientation(_message.Message):
    __slots__ = ("yaw", "pitch", "roll")
    YAW_FIELD_NUMBER: _ClassVar[int]
    PITCH_FIELD_NUMBER: _ClassVar[int]
    ROLL_FIELD_NUMBER: _ClassVar[int]
    yaw: float
    pitch: float
    roll: float
    def __init__(self, yaw: _Optional[float] = ..., pitch: _Optional[float] = ..., roll: _Optional[float] = ...) -> None: ...

class Chip(_message.Message):
    __slots__ = ("kind", "id", "name", "manufacturer", "product_name", "bt", "ble_beacon", "uwb", "wifi", "offset")
    class Radio(_message.Message):
        __slots__ = ("state", "range", "tx_count", "rx_count")
        STATE_FIELD_NUMBER: _ClassVar[int]
        RANGE_FIELD_NUMBER: _ClassVar[int]
        TX_COUNT_FIELD_NUMBER: _ClassVar[int]
        RX_COUNT_FIELD_NUMBER: _ClassVar[int]
        state: bool
        range: float
        tx_count: int
        rx_count: int
        def __init__(self, state: bool = ..., range: _Optional[float] = ..., tx_count: _Optional[int] = ..., rx_count: _Optional[int] = ...) -> None: ...
    class Bluetooth(_message.Message):
        __slots__ = ("low_energy", "classic", "address", "bt_properties")
        LOW_ENERGY_FIELD_NUMBER: _ClassVar[int]
        CLASSIC_FIELD_NUMBER: _ClassVar[int]
        ADDRESS_FIELD_NUMBER: _ClassVar[int]
        BT_PROPERTIES_FIELD_NUMBER: _ClassVar[int]
        low_energy: Chip.Radio
        classic: Chip.Radio
        address: str
        bt_properties: _configuration_pb2.Controller
        def __init__(self, low_energy: _Optional[_Union[Chip.Radio, _Mapping]] = ..., classic: _Optional[_Union[Chip.Radio, _Mapping]] = ..., address: _Optional[str] = ..., bt_properties: _Optional[_Union[_configuration_pb2.Controller, _Mapping]] = ...) -> None: ...
    class BleBeacon(_message.Message):
        __slots__ = ("bt", "address", "settings", "adv_data", "scan_response")
        class AdvertiseSettings(_message.Message):
            __slots__ = ("advertise_mode", "milliseconds", "tx_power_level", "dbm", "scannable", "timeout")
            class AdvertiseMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                LOW_POWER: _ClassVar[Chip.BleBeacon.AdvertiseSettings.AdvertiseMode]
                BALANCED: _ClassVar[Chip.BleBeacon.AdvertiseSettings.AdvertiseMode]
                LOW_LATENCY: _ClassVar[Chip.BleBeacon.AdvertiseSettings.AdvertiseMode]
            LOW_POWER: Chip.BleBeacon.AdvertiseSettings.AdvertiseMode
            BALANCED: Chip.BleBeacon.AdvertiseSettings.AdvertiseMode
            LOW_LATENCY: Chip.BleBeacon.AdvertiseSettings.AdvertiseMode
            class AdvertiseTxPower(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                ULTRA_LOW: _ClassVar[Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower]
                LOW: _ClassVar[Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower]
                MEDIUM: _ClassVar[Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower]
                HIGH: _ClassVar[Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower]
            ULTRA_LOW: Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower
            LOW: Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower
            MEDIUM: Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower
            HIGH: Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower
            ADVERTISE_MODE_FIELD_NUMBER: _ClassVar[int]
            MILLISECONDS_FIELD_NUMBER: _ClassVar[int]
            TX_POWER_LEVEL_FIELD_NUMBER: _ClassVar[int]
            DBM_FIELD_NUMBER: _ClassVar[int]
            SCANNABLE_FIELD_NUMBER: _ClassVar[int]
            TIMEOUT_FIELD_NUMBER: _ClassVar[int]
            advertise_mode: Chip.BleBeacon.AdvertiseSettings.AdvertiseMode
            milliseconds: int
            tx_power_level: Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower
            dbm: int
            scannable: bool
            timeout: int
            def __init__(self, advertise_mode: _Optional[_Union[Chip.BleBeacon.AdvertiseSettings.AdvertiseMode, str]] = ..., milliseconds: _Optional[int] = ..., tx_power_level: _Optional[_Union[Chip.BleBeacon.AdvertiseSettings.AdvertiseTxPower, str]] = ..., dbm: _Optional[int] = ..., scannable: bool = ..., timeout: _Optional[int] = ...) -> None: ...
        class AdvertiseData(_message.Message):
            __slots__ = ("include_device_name", "include_tx_power_level", "manufacturer_data", "services")
            class Service(_message.Message):
                __slots__ = ("uuid", "data")
                UUID_FIELD_NUMBER: _ClassVar[int]
                DATA_FIELD_NUMBER: _ClassVar[int]
                uuid: str
                data: bytes
                def __init__(self, uuid: _Optional[str] = ..., data: _Optional[bytes] = ...) -> None: ...
            INCLUDE_DEVICE_NAME_FIELD_NUMBER: _ClassVar[int]
            INCLUDE_TX_POWER_LEVEL_FIELD_NUMBER: _ClassVar[int]
            MANUFACTURER_DATA_FIELD_NUMBER: _ClassVar[int]
            SERVICES_FIELD_NUMBER: _ClassVar[int]
            include_device_name: bool
            include_tx_power_level: bool
            manufacturer_data: bytes
            services: _containers.RepeatedCompositeFieldContainer[Chip.BleBeacon.AdvertiseData.Service]
            def __init__(self, include_device_name: bool = ..., include_tx_power_level: bool = ..., manufacturer_data: _Optional[bytes] = ..., services: _Optional[_Iterable[_Union[Chip.BleBeacon.AdvertiseData.Service, _Mapping]]] = ...) -> None: ...
        BT_FIELD_NUMBER: _ClassVar[int]
        ADDRESS_FIELD_NUMBER: _ClassVar[int]
        SETTINGS_FIELD_NUMBER: _ClassVar[int]
        ADV_DATA_FIELD_NUMBER: _ClassVar[int]
        SCAN_RESPONSE_FIELD_NUMBER: _ClassVar[int]
        bt: Chip.Bluetooth
        address: str
        settings: Chip.BleBeacon.AdvertiseSettings
        adv_data: Chip.BleBeacon.AdvertiseData
        scan_response: Chip.BleBeacon.AdvertiseData
        def __init__(self, bt: _Optional[_Union[Chip.Bluetooth, _Mapping]] = ..., address: _Optional[str] = ..., settings: _Optional[_Union[Chip.BleBeacon.AdvertiseSettings, _Mapping]] = ..., adv_data: _Optional[_Union[Chip.BleBeacon.AdvertiseData, _Mapping]] = ..., scan_response: _Optional[_Union[Chip.BleBeacon.AdvertiseData, _Mapping]] = ...) -> None: ...
    KIND_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    MANUFACTURER_FIELD_NUMBER: _ClassVar[int]
    PRODUCT_NAME_FIELD_NUMBER: _ClassVar[int]
    BT_FIELD_NUMBER: _ClassVar[int]
    BLE_BEACON_FIELD_NUMBER: _ClassVar[int]
    UWB_FIELD_NUMBER: _ClassVar[int]
    WIFI_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    kind: _common_pb2.ChipKind
    id: int
    name: str
    manufacturer: str
    product_name: str
    bt: Chip.Bluetooth
    ble_beacon: Chip.BleBeacon
    uwb: Chip.Radio
    wifi: Chip.Radio
    offset: Position
    def __init__(self, kind: _Optional[_Union[_common_pb2.ChipKind, str]] = ..., id: _Optional[int] = ..., name: _Optional[str] = ..., manufacturer: _Optional[str] = ..., product_name: _Optional[str] = ..., bt: _Optional[_Union[Chip.Bluetooth, _Mapping]] = ..., ble_beacon: _Optional[_Union[Chip.BleBeacon, _Mapping]] = ..., uwb: _Optional[_Union[Chip.Radio, _Mapping]] = ..., wifi: _Optional[_Union[Chip.Radio, _Mapping]] = ..., offset: _Optional[_Union[Position, _Mapping]] = ...) -> None: ...

class ChipCreate(_message.Message):
    __slots__ = ("kind", "address", "name", "manufacturer", "product_name", "ble_beacon", "bt_properties")
    class BleBeaconCreate(_message.Message):
        __slots__ = ("address", "settings", "adv_data", "scan_response")
        ADDRESS_FIELD_NUMBER: _ClassVar[int]
        SETTINGS_FIELD_NUMBER: _ClassVar[int]
        ADV_DATA_FIELD_NUMBER: _ClassVar[int]
        SCAN_RESPONSE_FIELD_NUMBER: _ClassVar[int]
        address: str
        settings: Chip.BleBeacon.AdvertiseSettings
        adv_data: Chip.BleBeacon.AdvertiseData
        scan_response: Chip.BleBeacon.AdvertiseData
        def __init__(self, address: _Optional[str] = ..., settings: _Optional[_Union[Chip.BleBeacon.AdvertiseSettings, _Mapping]] = ..., adv_data: _Optional[_Union[Chip.BleBeacon.AdvertiseData, _Mapping]] = ..., scan_response: _Optional[_Union[Chip.BleBeacon.AdvertiseData, _Mapping]] = ...) -> None: ...
    KIND_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    MANUFACTURER_FIELD_NUMBER: _ClassVar[int]
    PRODUCT_NAME_FIELD_NUMBER: _ClassVar[int]
    BLE_BEACON_FIELD_NUMBER: _ClassVar[int]
    BT_PROPERTIES_FIELD_NUMBER: _ClassVar[int]
    kind: _common_pb2.ChipKind
    address: str
    name: str
    manufacturer: str
    product_name: str
    ble_beacon: ChipCreate.BleBeaconCreate
    bt_properties: _configuration_pb2.Controller
    def __init__(self, kind: _Optional[_Union[_common_pb2.ChipKind, str]] = ..., address: _Optional[str] = ..., name: _Optional[str] = ..., manufacturer: _Optional[str] = ..., product_name: _Optional[str] = ..., ble_beacon: _Optional[_Union[ChipCreate.BleBeaconCreate, _Mapping]] = ..., bt_properties: _Optional[_Union[_configuration_pb2.Controller, _Mapping]] = ...) -> None: ...

class Device(_message.Message):
    __slots__ = ("id", "name", "visible", "position", "orientation", "chips")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VISIBLE_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    ORIENTATION_FIELD_NUMBER: _ClassVar[int]
    CHIPS_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    visible: bool
    position: Position
    orientation: Orientation
    chips: _containers.RepeatedCompositeFieldContainer[Chip]
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., visible: bool = ..., position: _Optional[_Union[Position, _Mapping]] = ..., orientation: _Optional[_Union[Orientation, _Mapping]] = ..., chips: _Optional[_Iterable[_Union[Chip, _Mapping]]] = ...) -> None: ...

class DeviceCreate(_message.Message):
    __slots__ = ("name", "position", "orientation", "chips")
    NAME_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    ORIENTATION_FIELD_NUMBER: _ClassVar[int]
    CHIPS_FIELD_NUMBER: _ClassVar[int]
    name: str
    position: Position
    orientation: Orientation
    chips: _containers.RepeatedCompositeFieldContainer[ChipCreate]
    def __init__(self, name: _Optional[str] = ..., position: _Optional[_Union[Position, _Mapping]] = ..., orientation: _Optional[_Union[Orientation, _Mapping]] = ..., chips: _Optional[_Iterable[_Union[ChipCreate, _Mapping]]] = ...) -> None: ...

class Scene(_message.Message):
    __slots__ = ("devices",)
    DEVICES_FIELD_NUMBER: _ClassVar[int]
    devices: _containers.RepeatedCompositeFieldContainer[Device]
    def __init__(self, devices: _Optional[_Iterable[_Union[Device, _Mapping]]] = ...) -> None: ...

class Capture(_message.Message):
    __slots__ = ("id", "chip_kind", "device_name", "state", "size", "records", "timestamp", "valid")
    ID_FIELD_NUMBER: _ClassVar[int]
    CHIP_KIND_FIELD_NUMBER: _ClassVar[int]
    DEVICE_NAME_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    VALID_FIELD_NUMBER: _ClassVar[int]
    id: int
    chip_kind: _common_pb2.ChipKind
    device_name: str
    state: bool
    size: int
    records: int
    timestamp: _timestamp_pb2.Timestamp
    valid: bool
    def __init__(self, id: _Optional[int] = ..., chip_kind: _Optional[_Union[_common_pb2.ChipKind, str]] = ..., device_name: _Optional[str] = ..., state: bool = ..., size: _Optional[int] = ..., records: _Optional[int] = ..., timestamp: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., valid: bool = ...) -> None: ...
