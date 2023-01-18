from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HCIPacket(_message.Message):
    __slots__ = ["packet", "packet_type"]
    class PacketType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    ACL: HCIPacket.PacketType
    COMMAND: HCIPacket.PacketType
    EVENT: HCIPacket.PacketType
    HCI_PACKET_UNSPECIFIED: HCIPacket.PacketType
    ISO: HCIPacket.PacketType
    PACKET_FIELD_NUMBER: _ClassVar[int]
    PACKET_TYPE_FIELD_NUMBER: _ClassVar[int]
    SCO: HCIPacket.PacketType
    packet: bytes
    packet_type: HCIPacket.PacketType
    def __init__(self, packet_type: _Optional[_Union[HCIPacket.PacketType, str]] = ..., packet: _Optional[bytes] = ...) -> None: ...
