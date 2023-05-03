from . import grpc_endpoint_description_pb2 as _grpc_endpoint_description_pb2
from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Advertisement(_message.Message):
    __slots__ = ["connection_mode", "device_name", "discovery_mode"]
    class ConnectionMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class DiscoveryMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    CONNECTION_MODE_DIRECTED: Advertisement.ConnectionMode
    CONNECTION_MODE_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_MODE_NON_CONNECTABLE: Advertisement.ConnectionMode
    CONNECTION_MODE_UNDIRECTED: Advertisement.ConnectionMode
    CONNECTION_MODE_UNSPECIFIED: Advertisement.ConnectionMode
    DEVICE_NAME_FIELD_NUMBER: _ClassVar[int]
    DISCOVERY_MODE_FIELD_NUMBER: _ClassVar[int]
    DISCOVERY_MODE_GENERAL: Advertisement.DiscoveryMode
    DISCOVERY_MODE_LIMITED: Advertisement.DiscoveryMode
    DISCOVERY_MODE_NON_DISCOVERABLE: Advertisement.DiscoveryMode
    DISCOVERY_MODE_UNSPECIFIED: Advertisement.DiscoveryMode
    connection_mode: Advertisement.ConnectionMode
    device_name: str
    discovery_mode: Advertisement.DiscoveryMode
    def __init__(self, device_name: _Optional[str] = ..., connection_mode: _Optional[_Union[Advertisement.ConnectionMode, str]] = ..., discovery_mode: _Optional[_Union[Advertisement.DiscoveryMode, str]] = ...) -> None: ...

class CallbackIdentifier(_message.Message):
    __slots__ = ["identity"]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    identity: str
    def __init__(self, identity: _Optional[str] = ...) -> None: ...

class CharacteristicValueRequest(_message.Message):
    __slots__ = ["callback_device_id", "callback_id", "data", "from_device"]
    CALLBACK_DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    CALLBACK_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    FROM_DEVICE_FIELD_NUMBER: _ClassVar[int]
    callback_device_id: CallbackIdentifier
    callback_id: Uuid
    data: bytes
    from_device: DeviceIdentifier
    def __init__(self, callback_device_id: _Optional[_Union[CallbackIdentifier, _Mapping]] = ..., from_device: _Optional[_Union[DeviceIdentifier, _Mapping]] = ..., callback_id: _Optional[_Union[Uuid, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class CharacteristicValueResponse(_message.Message):
    __slots__ = ["data", "status"]
    class GattStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    DATA_FIELD_NUMBER: _ClassVar[int]
    GATT_STATUS_FAILURE: CharacteristicValueResponse.GattStatus
    GATT_STATUS_SUCCESS: CharacteristicValueResponse.GattStatus
    GATT_STATUS_UNSPECIFIED: CharacteristicValueResponse.GattStatus
    STATUS_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    status: CharacteristicValueResponse.GattStatus
    def __init__(self, status: _Optional[_Union[CharacteristicValueResponse.GattStatus, str]] = ..., data: _Optional[bytes] = ...) -> None: ...

class ConnectionStateChange(_message.Message):
    __slots__ = ["callback_device_id", "from_device", "new_state"]
    class ConnectionState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    CALLBACK_DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_STATE_CONNECTED: ConnectionStateChange.ConnectionState
    CONNECTION_STATE_DISCONNECTED: ConnectionStateChange.ConnectionState
    CONNECTION_STATE_UNDEFINED: ConnectionStateChange.ConnectionState
    FROM_DEVICE_FIELD_NUMBER: _ClassVar[int]
    NEW_STATE_FIELD_NUMBER: _ClassVar[int]
    callback_device_id: CallbackIdentifier
    from_device: DeviceIdentifier
    new_state: ConnectionStateChange.ConnectionState
    def __init__(self, callback_device_id: _Optional[_Union[CallbackIdentifier, _Mapping]] = ..., from_device: _Optional[_Union[DeviceIdentifier, _Mapping]] = ..., new_state: _Optional[_Union[ConnectionStateChange.ConnectionState, str]] = ...) -> None: ...

class DeviceIdentifier(_message.Message):
    __slots__ = ["address"]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: str
    def __init__(self, address: _Optional[str] = ...) -> None: ...

class GattCharacteristic(_message.Message):
    __slots__ = ["callback_id", "permissions", "properties", "uuid"]
    class Permissions(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    class Properties(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    CALLBACK_ID_FIELD_NUMBER: _ClassVar[int]
    PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_READ: GattCharacteristic.Permissions
    PERMISSION_READ_ENCRYPTED: GattCharacteristic.Permissions
    PERMISSION_READ_ENCRYPTED_MITM: GattCharacteristic.Permissions
    PERMISSION_UNSPECIFIED: GattCharacteristic.Permissions
    PERMISSION_WRITE: GattCharacteristic.Permissions
    PERMISSION_WRITE_ENCRYPTED: GattCharacteristic.Permissions
    PERMISSION_WRITE_ENCRYPTED_MITM: GattCharacteristic.Permissions
    PERMISSION_WRITE_SIGNED: GattCharacteristic.Permissions
    PERMISSION_WRITE_SIGNED_MITM: GattCharacteristic.Permissions
    PROPERTIES_FIELD_NUMBER: _ClassVar[int]
    PROPERTY_BROADCAST: GattCharacteristic.Properties
    PROPERTY_EXTENDED_PROPS: GattCharacteristic.Properties
    PROPERTY_INDICATE: GattCharacteristic.Properties
    PROPERTY_NOTIFY: GattCharacteristic.Properties
    PROPERTY_READ: GattCharacteristic.Properties
    PROPERTY_SIGNED_WRITE: GattCharacteristic.Properties
    PROPERTY_UNSPECIFIED: GattCharacteristic.Properties
    PROPERTY_WRITE: GattCharacteristic.Properties
    PROPERTY_WRITE_NO_RESPONSE: GattCharacteristic.Properties
    UUID_FIELD_NUMBER: _ClassVar[int]
    callback_id: Uuid
    permissions: int
    properties: int
    uuid: Uuid
    def __init__(self, uuid: _Optional[_Union[Uuid, _Mapping]] = ..., properties: _Optional[int] = ..., permissions: _Optional[int] = ..., callback_id: _Optional[_Union[Uuid, _Mapping]] = ...) -> None: ...

class GattDevice(_message.Message):
    __slots__ = ["advertisement", "endpoint", "profile"]
    ADVERTISEMENT_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    advertisement: Advertisement
    endpoint: _grpc_endpoint_description_pb2.Endpoint
    profile: GattProfile
    def __init__(self, endpoint: _Optional[_Union[_grpc_endpoint_description_pb2.Endpoint, _Mapping]] = ..., advertisement: _Optional[_Union[Advertisement, _Mapping]] = ..., profile: _Optional[_Union[GattProfile, _Mapping]] = ...) -> None: ...

class GattProfile(_message.Message):
    __slots__ = ["services"]
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    services: _containers.RepeatedCompositeFieldContainer[GattService]
    def __init__(self, services: _Optional[_Iterable[_Union[GattService, _Mapping]]] = ...) -> None: ...

class GattService(_message.Message):
    __slots__ = ["characteristics", "service_type", "uuid"]
    class ServiceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    CHARACTERISTICS_FIELD_NUMBER: _ClassVar[int]
    SERVICE_TYPE_FIELD_NUMBER: _ClassVar[int]
    SERVICE_TYPE_PRIMARY: GattService.ServiceType
    SERVICE_TYPE_SECONDARY: GattService.ServiceType
    SERVICE_TYPE_UNSPECIFIED: GattService.ServiceType
    UUID_FIELD_NUMBER: _ClassVar[int]
    characteristics: _containers.RepeatedCompositeFieldContainer[GattCharacteristic]
    service_type: GattService.ServiceType
    uuid: Uuid
    def __init__(self, uuid: _Optional[_Union[Uuid, _Mapping]] = ..., service_type: _Optional[_Union[GattService.ServiceType, str]] = ..., characteristics: _Optional[_Iterable[_Union[GattCharacteristic, _Mapping]]] = ...) -> None: ...

class Uuid(_message.Message):
    __slots__ = ["id", "lsb", "msb"]
    ID_FIELD_NUMBER: _ClassVar[int]
    LSB_FIELD_NUMBER: _ClassVar[int]
    MSB_FIELD_NUMBER: _ClassVar[int]
    id: int
    lsb: int
    msb: int
    def __init__(self, id: _Optional[int] = ..., lsb: _Optional[int] = ..., msb: _Optional[int] = ...) -> None: ...
