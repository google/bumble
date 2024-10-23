from bumble.transport.grpc_protobuf.netsim import hci_packet_pb2 as _hci_packet_pb2
from bumble.transport.grpc_protobuf.netsim import startup_pb2 as _startup_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PacketRequest(_message.Message):
    __slots__ = ("initial_info", "hci_packet", "packet")
    INITIAL_INFO_FIELD_NUMBER: _ClassVar[int]
    HCI_PACKET_FIELD_NUMBER: _ClassVar[int]
    PACKET_FIELD_NUMBER: _ClassVar[int]
    initial_info: _startup_pb2.ChipInfo
    hci_packet: _hci_packet_pb2.HCIPacket
    packet: bytes
    def __init__(self, initial_info: _Optional[_Union[_startup_pb2.ChipInfo, _Mapping]] = ..., hci_packet: _Optional[_Union[_hci_packet_pb2.HCIPacket, _Mapping]] = ..., packet: _Optional[bytes] = ...) -> None: ...

class PacketResponse(_message.Message):
    __slots__ = ("error", "hci_packet", "packet")
    ERROR_FIELD_NUMBER: _ClassVar[int]
    HCI_PACKET_FIELD_NUMBER: _ClassVar[int]
    PACKET_FIELD_NUMBER: _ClassVar[int]
    error: str
    hci_packet: _hci_packet_pb2.HCIPacket
    packet: bytes
    def __init__(self, error: _Optional[str] = ..., hci_packet: _Optional[_Union[_hci_packet_pb2.HCIPacket, _Mapping]] = ..., packet: _Optional[bytes] = ...) -> None: ...
