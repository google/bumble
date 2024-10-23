from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HCIPacket(_message.Message):
    __slots__ = ("packet_type", "packet")
    class PacketType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        HCI_PACKET_UNSPECIFIED: _ClassVar[HCIPacket.PacketType]
        COMMAND: _ClassVar[HCIPacket.PacketType]
        ACL: _ClassVar[HCIPacket.PacketType]
        SCO: _ClassVar[HCIPacket.PacketType]
        EVENT: _ClassVar[HCIPacket.PacketType]
        ISO: _ClassVar[HCIPacket.PacketType]
    HCI_PACKET_UNSPECIFIED: HCIPacket.PacketType
    COMMAND: HCIPacket.PacketType
    ACL: HCIPacket.PacketType
    SCO: HCIPacket.PacketType
    EVENT: HCIPacket.PacketType
    ISO: HCIPacket.PacketType
    PACKET_TYPE_FIELD_NUMBER: _ClassVar[int]
    PACKET_FIELD_NUMBER: _ClassVar[int]
    packet_type: HCIPacket.PacketType
    packet: bytes
    def __init__(self, packet_type: _Optional[_Union[HCIPacket.PacketType, str]] = ..., packet: _Optional[bytes] = ...) -> None: ...
