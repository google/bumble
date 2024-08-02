# Copyright 2021-2024 Google LLC
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

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import asyncio
import binascii
import dataclasses
import logging
import struct

import bumble.device
from bumble import bnep
from bumble import core
from bumble import hci
from bumble import utils
from bumble import sdp
from bumble import l2cap

from typing import List, Optional, Callable, Type
from typing_extensions import Self


# -----------------------------------------------------------------------------
# Logger
# -----------------------------------------------------------------------------
_logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------


LANGUAGE = 0x656E  # 0x656E uint16 “en” (English)
ENCODING = 0x6A  # 0x006A uint16 UTF-8 encoding
PRIMARY_LANGUAGE_BASE_ID = 0x100  # 0x0100 uint16 PrimaryLanguageBaseID


class AttributeId(utils.OpenIntEnum):
    IP_SUBNET = 0x0200
    SECURITY_DESCRIPTION = 0x030A
    NET_ACCESS_TYPE = 0x030B
    MAX_NET_ACCESS_RATE = 0x030C
    IPV4_SUBNET = 0x030D
    IPV6_SUBNET = 0x030E


class SecurityDescription(utils.OpenIntEnum):
    NONE = 0x0000
    SERVICE_LEVEL_ENFORCEDSECURITY = 0x0001
    IEEE_802_1X = 0x0002


class NetAccessType(utils.OpenIntEnum):
    PSTN = 0x0000
    ISDN = 0x0001
    DSL = 0x0002
    CABLE_MODEM = 0x0003
    ETHERNET_10MB = 0x0004
    ETHERNET_100MB = 0x0005
    TOKEN_RING_4_MB = 0x0006
    TOKEN_RING_16_MB = 0x0007
    TOKEN_RING_100_MB = 0x0008
    FDDI = 0x0009
    GSM = 0x000A
    CDMA = 0x000B
    GPRS = 0x000C
    CELLULAR_3G = 0x000D
    OTHER = 0xFFFE


@dataclasses.dataclass
class EthernetFrame:
    protocol_type: int
    payload: bytes
    source_address: Optional[hci.Address] = None
    destination_address: Optional[hci.Address] = None

    def __bytes__(self) -> bytes:
        body_without_fcs = (
            struct.pack(
                "!6s6sH",
                bytes(self.source_address or hci.Address.ANY),
                bytes(self.destination_address or hci.Address.ANY),
                self.protocol_type,
            )
            + self.payload
        )
        fcs = binascii.crc32(body_without_fcs)
        return body_without_fcs + struct.pack("!I", fcs)

    @classmethod
    def from_bytes(cls: Type[Self], pdu: bytes) -> Self:
        source_address = hci.Address.parse_address(pdu, 0)
        destination_address = hci.Address.parse_address(pdu, 6)
        protocol_type = int.from_bytes(pdu[12:14], 'big')
        payload = pdu[14:-1]
        return cls(
            source_address=source_address,
            destination_address=destination_address,
            protocol_type=protocol_type,
            payload=payload,
        )


# -----------------------------------------------------------------------------
# SDP record helpers
# -----------------------------------------------------------------------------


def _make_generic_service_record(
    service_record_handle: int,
    service_class_uuid: core.UUID,
    service_name: str,
    service_description: str,
    security_description: SecurityDescription,
) -> List[sdp.ServiceAttribute]:
    return [
        sdp.ServiceAttribute(
            sdp.SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            sdp.DataElement.unsigned_integer_32(service_record_handle),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence([sdp.DataElement.uuid(service_class_uuid)]),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.sequence(
                        [
                            sdp.DataElement.uuid(core.BT_L2CAP_PROTOCOL_ID),
                            sdp.DataElement.unsigned_integer_16(bnep.BNEP_PSM),
                        ]
                    ),
                    sdp.DataElement.sequence(
                        [
                            sdp.DataElement.uuid(core.BT_BNEP_PROTOCOL_ID),
                            sdp.DataElement.unsigned_integer_16(0x0100),
                        ]
                    ),
                ]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_LANGUAGE_BASE_ATTRIBUTE_ID_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.unsigned_integer_16(LANGUAGE),
                    sdp.DataElement.unsigned_integer_16(ENCODING),
                    sdp.DataElement.unsigned_integer_16(PRIMARY_LANGUAGE_BASE_ID),
                ]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.uuid(service_class_uuid),
                    sdp.DataElement.unsigned_integer_16(0x0100),
                ]
            ),
        ),
        sdp.ServiceAttribute(
            PRIMARY_LANGUAGE_BASE_ID + sdp.SDP_SERVICE_NAME_ATTRIBUTE_ID_OFFSET,
            sdp.DataElement.text_string(service_name.encode("utf-8")),
        ),
        sdp.ServiceAttribute(
            PRIMARY_LANGUAGE_BASE_ID + sdp.SDP_SERVICE_DESCRIPTION_ATTRIBUTE_ID_OFFSET,
            sdp.DataElement.text_string(service_description.encode("utf-8")),
        ),
        sdp.ServiceAttribute(
            AttributeId.SECURITY_DESCRIPTION,
            sdp.DataElement.unsigned_integer_16(security_description.value),
        ),
    ]


def make_nap_service_record(
    service_record_handle: int,
    service_name: str = "Network Access Point Service",
    service_description: str = "Network Access Point Service",
    security_description: SecurityDescription = SecurityDescription.NONE,
    net_access_type: NetAccessType = NetAccessType.ETHERNET_10MB,
    max_net_access_rate: int = 1_000_000,
) -> List[sdp.ServiceAttribute]:
    return _make_generic_service_record(
        service_record_handle=service_record_handle,
        service_class_uuid=core.BT_NAP_SERVICE,
        service_name=service_name,
        service_description=service_description,
        security_description=security_description,
    ) + [
        sdp.ServiceAttribute(
            AttributeId.NET_ACCESS_TYPE,
            sdp.DataElement.unsigned_integer_16(net_access_type.value),
        ),
        sdp.ServiceAttribute(
            AttributeId.MAX_NET_ACCESS_RATE,
            sdp.DataElement.unsigned_integer_32(max_net_access_rate),
        ),
    ]


def make_gn_service_record(
    service_record_handle: int,
    service_name: str = "Network Access Point Service",
    service_description: str = "Network Access Point Service",
    security_description: SecurityDescription = SecurityDescription.NONE,
) -> List[sdp.ServiceAttribute]:
    return _make_generic_service_record(
        service_record_handle=service_record_handle,
        service_class_uuid=core.BT_GN_SERVICE,
        service_name=service_name,
        service_description=service_description,
        security_description=security_description,
    )


def make_panu_service_record(
    service_record_handle: int,
    service_name: str = "Network Access Point Service",
    service_description: str = "Network Access Point Service",
    security_description: SecurityDescription = SecurityDescription.NONE,
) -> List[sdp.ServiceAttribute]:
    return _make_generic_service_record(
        service_record_handle=service_record_handle,
        service_class_uuid=core.BT_PANU_SERVICE,
        service_name=service_name,
        service_description=service_description,
        security_description=security_description,
    )


# -----------------------------------------------------------------------------
# Connection
# -----------------------------------------------------------------------------
class Connection(utils.CompositeEventEmitter):
    ethernet_sink: Optional[Callable[[EthernetFrame], None]] = None
    source_service: core.UUID = core.BT_PANU_SERVICE
    destination_service: core.UUID = core.BT_PANU_SERVICE

    _connection_result: Optional[asyncio.Future[None]] = None

    def __init__(self, l2cap_channel: l2cap.ClassicChannel) -> None:
        super().__init__()
        self.l2cap_channel = l2cap_channel
        self.l2cap_channel.sink = self._on_pdu

    @classmethod
    async def connect(
        cls: Type[Self],
        connection: bumble.device.Connection,
        source_service: Optional[core.UUID] = None,
        destination_service: Optional[core.UUID] = None,
    ) -> Self:
        l2cap_channel = await connection.create_l2cap_channel(
            spec=l2cap.ClassicChannelSpec(psm=bnep.BNEP_PSM)
        )
        pan_connection = cls(l2cap_channel)
        pan_connection.source_service = source_service or core.BT_PANU_SERVICE
        pan_connection.destination_service = destination_service or core.BT_PANU_SERVICE
        pan_connection._connection_result = asyncio.get_running_loop().create_future()

        pan_connection.send_packet(
            bnep.BNEP_Control(
                control_type=bnep.ControlType.BNEP_SETUP_CONNECTION_REQUEST_MSG,
                payload=bytes([2])
                + pan_connection.destination_service.to_bytes()[::-1]
                + pan_connection.source_service.to_bytes()[::-1],
            )
        )
        await pan_connection._connection_result
        return pan_connection

    def send_ethernet_frame(self, packet: EthernetFrame) -> None:
        _logger.debug(f">> {packet}")
        self.l2cap_channel.send_pdu(
            bnep.BNEP_Compressed_Ethernet(
                networking_protocol_type=packet.protocol_type, payload=packet
            )
        )

    def send_packet(self, packet: bnep.BNEP_Packet) -> None:
        _logger.debug(f">> {packet}")
        self.l2cap_channel.send_pdu(packet)

    def _on_pdu(self, pdu: bytes) -> None:
        bnep_packet = bnep.BNEP_Packet.from_bytes(pdu)
        _logger.debug(f"<< {bnep_packet}")
        if handler := getattr(self, f"_on_{bnep_packet.name.lower()}", None):
            handler(bnep_packet)
        else:
            _logger.info(f"No handler for {bnep_packet.name}")

    def _on_bnep_control(self, packet: bnep.BNEP_Control) -> None:
        if packet.control_type == bnep.ControlType.BNEP_SETUP_CONNECTION_REQUEST_MSG:
            uuid_size = packet.payload[0]
            # PAN uses a reversed endianness.
            self.destination_service = core.UUID.from_bytes(
                packet.payload[1 : 1 + uuid_size : -1]
            )
            self.source_service = core.UUID.from_bytes(
                packet.payload[1 + uuid_size : 1 + uuid_size * 2 : -1]
            )
            self.l2cap_channel.send_pdu(
                bnep.BNEP_Control(
                    control_type=bnep.ControlType.BNEP_SETUP_CONNECTION_RESPONSE_MSG,
                    payload=bytes(
                        bnep.SetupConnectionResponseCode.OPERATION_SUCCESSFUL
                    ),
                )
            )
        elif packet.control_type == bnep.ControlType.BNEP_SETUP_CONNECTION_RESPONSE_MSG:
            if not self._connection_result or self._connection_result.done():
                return
            response_code = int.from_bytes(packet.payload, "big")
            if response_code == bnep.SetupConnectionResponseCode.OPERATION_SUCCESSFUL:
                self._connection_result.set_result(None)
            else:
                self._connection_result.set_exception(bnep.BnepError(response_code))

    def _on_bnep_compressed_ethernet_dest_only(
        self, packet: bnep.BNEP_Compressed_Ethernet_Dest_Only
    ) -> None:
        if self.ethernet_sink:
            self.ethernet_sink(  # pylint: disable=not-callable
                EthernetFrame(
                    destination_address=packet.destination_address,
                    protocol_type=packet.networking_protocol_type,
                    payload=packet.payload,
                )
            )

    def _on_bnep_compressed_ethernet_source_only(
        self, packet: bnep.BNEP_Compressed_Ethernet_Source_Only
    ) -> None:
        if self.ethernet_sink:
            self.ethernet_sink(  # pylint: disable=not-callable
                EthernetFrame(
                    source_address=packet.source_address,
                    protocol_type=packet.networking_protocol_type,
                    payload=packet.payload,
                )
            )

    def _on_bnep_general_ethernet(self, packet: bnep.BNEP_General_Ethernet) -> None:
        if self.ethernet_sink:
            self.ethernet_sink(  # pylint: disable=not-callable
                EthernetFrame(
                    source_address=packet.source_address,
                    destination_address=packet.destination_address,
                    protocol_type=packet.networking_protocol_type,
                    payload=packet.payload,
                )
            )

    def _on_bnep_compressed_ethernet(
        self, packet: bnep.BNEP_Compressed_Ethernet
    ) -> None:
        if self.ethernet_sink:
            self.ethernet_sink(  # pylint: disable=not-callable
                EthernetFrame(
                    protocol_type=packet.networking_protocol_type,
                    payload=packet.payload,
                )
            )


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class Server(utils.CompositeEventEmitter):
    connections: List[Connection] = []

    def __init__(self, device: bumble.device.Device) -> None:
        super().__init__()
        self.device = device
        self.device.create_l2cap_server(
            spec=l2cap.ClassicChannelSpec(psm=bnep.BNEP_PSM),
            handler=self._on_connection,
        )

    def _on_connection(self, channel: l2cap.ClassicChannel) -> None:
        connection = Connection(channel)
        self.emit('connection', connection)
