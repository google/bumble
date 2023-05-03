from . import emulated_bluetooth_packets_pb2 as _emulated_bluetooth_packets_pb2
from . import emulated_bluetooth_device_pb2 as _emulated_bluetooth_device_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RawData(_message.Message):
    __slots__ = ["packet"]
    PACKET_FIELD_NUMBER: _ClassVar[int]
    packet: bytes
    def __init__(self, packet: _Optional[bytes] = ...) -> None: ...

class RegistrationStatus(_message.Message):
    __slots__ = ["callback_device_id"]
    CALLBACK_DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    callback_device_id: _emulated_bluetooth_device_pb2.CallbackIdentifier
    def __init__(self, callback_device_id: _Optional[_Union[_emulated_bluetooth_device_pb2.CallbackIdentifier, _Mapping]] = ...) -> None: ...
