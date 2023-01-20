# Copyright 2021-2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HCIPacket(_message.Message):
    __slots__ = ["packet", "type"]

    class PacketType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = []
    PACKET_FIELD_NUMBER: _ClassVar[int]
    PACKET_TYPE_ACL: HCIPacket.PacketType
    PACKET_TYPE_EVENT: HCIPacket.PacketType
    PACKET_TYPE_HCI_COMMAND: HCIPacket.PacketType
    PACKET_TYPE_ISO: HCIPacket.PacketType
    PACKET_TYPE_SCO: HCIPacket.PacketType
    PACKET_TYPE_UNSPECIFIED: HCIPacket.PacketType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    packet: bytes
    type: HCIPacket.PacketType
    def __init__(
        self,
        type: _Optional[_Union[HCIPacket.PacketType, str]] = ...,
        packet: _Optional[bytes] = ...,
    ) -> None: ...
