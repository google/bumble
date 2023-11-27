# Copyright 2021-2022 Google LLC
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

from collections.abc import Callable, MutableMapping
from typing import cast, Any
import logging

from bumble import avdtp
from bumble.colors import color
from bumble.att import ATT_CID, ATT_PDU
from bumble.smp import SMP_CID, SMP_Command
from bumble.core import name_or_number
from bumble.l2cap import (
    L2CAP_PDU,
    L2CAP_CONNECTION_REQUEST,
    L2CAP_CONNECTION_RESPONSE,
    L2CAP_SIGNALING_CID,
    L2CAP_LE_SIGNALING_CID,
    L2CAP_Control_Frame,
    L2CAP_Connection_Request,
    L2CAP_Connection_Response,
)
from bumble.hci import (
    HCI_EVENT_PACKET,
    HCI_ACL_DATA_PACKET,
    HCI_DISCONNECTION_COMPLETE_EVENT,
    HCI_AclDataPacketAssembler,
    HCI_Packet,
    HCI_Event,
    HCI_AclDataPacket,
    HCI_Disconnection_Complete_Event,
)
from bumble.rfcomm import RFCOMM_Frame, RFCOMM_PSM
from bumble.sdp import SDP_PDU, SDP_PSM

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
PSM_NAMES = {
    RFCOMM_PSM: 'RFCOMM',
    SDP_PSM: 'SDP',
    avdtp.AVDTP_PSM: 'AVDTP',
}


# -----------------------------------------------------------------------------
class PacketTracer:
    class AclStream:
        psms: MutableMapping[int, int]
        peer: PacketTracer.AclStream
        avdtp_assemblers: MutableMapping[int, avdtp.MessageAssembler]

        def __init__(self, analyzer: PacketTracer.Analyzer) -> None:
            self.analyzer = analyzer
            self.packet_assembler = HCI_AclDataPacketAssembler(self.on_acl_pdu)
            self.avdtp_assemblers = {}  # AVDTP assemblers, by source_cid
            self.psms = {}  # PSM, by source_cid

        # pylint: disable=too-many-nested-blocks
        def on_acl_pdu(self, pdu: bytes) -> None:
            l2cap_pdu = L2CAP_PDU.from_bytes(pdu)

            if l2cap_pdu.cid == ATT_CID:
                att_pdu = ATT_PDU.from_bytes(l2cap_pdu.payload)
                self.analyzer.emit(att_pdu)
            elif l2cap_pdu.cid == SMP_CID:
                smp_command = SMP_Command.from_bytes(l2cap_pdu.payload)
                self.analyzer.emit(smp_command)
            elif l2cap_pdu.cid in (L2CAP_SIGNALING_CID, L2CAP_LE_SIGNALING_CID):
                control_frame = L2CAP_Control_Frame.from_bytes(l2cap_pdu.payload)
                self.analyzer.emit(control_frame)

                # Check if this signals a new channel
                if control_frame.code == L2CAP_CONNECTION_REQUEST:
                    connection_request = cast(L2CAP_Connection_Request, control_frame)
                    self.psms[connection_request.source_cid] = connection_request.psm
                elif control_frame.code == L2CAP_CONNECTION_RESPONSE:
                    connection_response = cast(L2CAP_Connection_Response, control_frame)
                    if (
                        connection_response.result
                        == L2CAP_Connection_Response.CONNECTION_SUCCESSFUL
                    ):
                        if self.peer:
                            if psm := self.peer.psms.get(
                                connection_response.source_cid
                            ):
                                # Found a pending connection
                                self.psms[connection_response.destination_cid] = psm

                                # For AVDTP connections, create a packet assembler for
                                # each direction
                                if psm == avdtp.AVDTP_PSM:
                                    self.avdtp_assemblers[
                                        connection_response.source_cid
                                    ] = avdtp.MessageAssembler(self.on_avdtp_message)
                                    self.peer.avdtp_assemblers[
                                        connection_response.destination_cid
                                    ] = avdtp.MessageAssembler(
                                        self.peer.on_avdtp_message
                                    )

            else:
                # Try to find the PSM associated with this PDU
                if self.peer and (psm := self.peer.psms.get(l2cap_pdu.cid)):
                    if psm == SDP_PSM:
                        sdp_pdu = SDP_PDU.from_bytes(l2cap_pdu.payload)
                        self.analyzer.emit(sdp_pdu)
                    elif psm == RFCOMM_PSM:
                        rfcomm_frame = RFCOMM_Frame.from_bytes(l2cap_pdu.payload)
                        self.analyzer.emit(rfcomm_frame)
                    elif psm == avdtp.AVDTP_PSM:
                        self.analyzer.emit(
                            f'{color("L2CAP", "green")} [CID={l2cap_pdu.cid}, '
                            f'PSM=AVDTP]: {l2cap_pdu.payload.hex()}'
                        )
                        assembler = self.avdtp_assemblers.get(l2cap_pdu.cid)
                        if assembler:
                            assembler.on_pdu(l2cap_pdu.payload)
                    else:
                        psm_string = name_or_number(PSM_NAMES, psm)
                        self.analyzer.emit(
                            f'{color("L2CAP", "green")} [CID={l2cap_pdu.cid}, '
                            f'PSM={psm_string}]: {l2cap_pdu.payload.hex()}'
                        )
                else:
                    self.analyzer.emit(l2cap_pdu)

        def on_avdtp_message(
            self, transaction_label: int, message: avdtp.Message
        ) -> None:
            self.analyzer.emit(
                f'{color("AVDTP", "green")} [{transaction_label}] {message}'
            )

        def feed_packet(self, packet: HCI_AclDataPacket) -> None:
            self.packet_assembler.feed_packet(packet)

    class Analyzer:
        acl_streams: MutableMapping[int, PacketTracer.AclStream]
        peer: PacketTracer.Analyzer

        def __init__(self, label: str, emit_message: Callable[..., None]) -> None:
            self.label = label
            self.emit_message = emit_message
            self.acl_streams = {}  # ACL streams, by connection handle

        def start_acl_stream(self, connection_handle: int) -> PacketTracer.AclStream:
            logger.info(
                f'[{self.label}] +++ Creating ACL stream for connection '
                f'0x{connection_handle:04X}'
            )
            stream = PacketTracer.AclStream(self)
            self.acl_streams[connection_handle] = stream

            # Associate with a peer stream if we can
            if peer_stream := self.peer.acl_streams.get(connection_handle):
                stream.peer = peer_stream
                peer_stream.peer = stream

            return stream

        def end_acl_stream(self, connection_handle: int) -> None:
            if connection_handle in self.acl_streams:
                logger.info(
                    f'[{self.label}] --- Removing ACL stream for connection '
                    f'0x{connection_handle:04X}'
                )
                del self.acl_streams[connection_handle]

                # Let the other forwarder know so it can cleanup its stream as well
                self.peer.end_acl_stream(connection_handle)

        def on_packet(self, packet: HCI_Packet) -> None:
            self.emit(packet)

            if packet.hci_packet_type == HCI_ACL_DATA_PACKET:
                acl_packet = cast(HCI_AclDataPacket, packet)
                # Look for an existing stream for this handle, create one if it is the
                # first ACL packet for that connection handle
                if (
                    stream := self.acl_streams.get(acl_packet.connection_handle)
                ) is None:
                    stream = self.start_acl_stream(acl_packet.connection_handle)
                stream.feed_packet(acl_packet)
            elif packet.hci_packet_type == HCI_EVENT_PACKET:
                event_packet = cast(HCI_Event, packet)
                if event_packet.event_code == HCI_DISCONNECTION_COMPLETE_EVENT:
                    self.end_acl_stream(
                        cast(HCI_Disconnection_Complete_Event, packet).connection_handle
                    )

        def emit(self, message: Any) -> None:
            self.emit_message(f'[{self.label}] {message}')

    def trace(self, packet: HCI_Packet, direction: int = 0) -> None:
        if direction == 0:
            self.host_to_controller_analyzer.on_packet(packet)
        else:
            self.controller_to_host_analyzer.on_packet(packet)

    def __init__(
        self,
        host_to_controller_label: str = color('HOST->CONTROLLER', 'blue'),
        controller_to_host_label: str = color('CONTROLLER->HOST', 'cyan'),
        emit_message: Callable[..., None] = logger.info,
    ) -> None:
        self.host_to_controller_analyzer = PacketTracer.Analyzer(
            host_to_controller_label, emit_message
        )
        self.controller_to_host_analyzer = PacketTracer.Analyzer(
            controller_to_host_label, emit_message
        )
        self.host_to_controller_analyzer.peer = self.controller_to_host_analyzer
        self.controller_to_host_analyzer.peer = self.host_to_controller_analyzer
