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

import datetime
import logging
from collections.abc import Callable, MutableMapping
from typing import Any, Optional, cast

from bumble import avc, avctp, avdtp, avrcp, crypto, rfcomm, sdp
from bumble.att import ATT_CID, ATT_PDU
from bumble.colors import color
from bumble.core import name_or_number
from bumble.hci import (
    HCI_ACL_DATA_PACKET,
    HCI_DISCONNECTION_COMPLETE_EVENT,
    HCI_EVENT_PACKET,
    Address,
    HCI_AclDataPacket,
    HCI_AclDataPacketAssembler,
    HCI_Disconnection_Complete_Event,
    HCI_Event,
    HCI_Packet,
)
from bumble.l2cap import (
    L2CAP_LE_SIGNALING_CID,
    L2CAP_PDU,
    L2CAP_SIGNALING_CID,
    CommandCode,
    L2CAP_Connection_Request,
    L2CAP_Connection_Response,
    L2CAP_Control_Frame,
)
from bumble.smp import SMP_CID, SMP_Command

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
PSM_NAMES = {
    rfcomm.RFCOMM_PSM: 'RFCOMM',
    sdp.SDP_PSM: 'SDP',
    avdtp.AVDTP_PSM: 'AVDTP',
    avctp.AVCTP_PSM: 'AVCTP',
    # TODO: add more PSM values
}

AVCTP_PID_NAMES = {avrcp.AVRCP_PID: 'AVRCP'}


# -----------------------------------------------------------------------------
class PacketTracer:
    class AclStream:
        psms: MutableMapping[int, int]
        peer: Optional[PacketTracer.AclStream]
        avdtp_assemblers: MutableMapping[int, avdtp.MessageAssembler]
        avctp_assemblers: MutableMapping[int, avctp.MessageAssembler]

        def __init__(self, analyzer: PacketTracer.Analyzer) -> None:
            self.analyzer = analyzer
            self.packet_assembler = HCI_AclDataPacketAssembler(self.on_acl_pdu)
            self.avdtp_assemblers = {}  # AVDTP assemblers, by source_cid
            self.avctp_assemblers = {}  # AVCTP assemblers, by source_cid
            self.psms = {}  # PSM, by source_cid
            self.peer = None

        # pylint: disable=too-many-nested-blocks
        def on_acl_pdu(self, pdu: bytes) -> None:
            l2cap_pdu = L2CAP_PDU.from_bytes(pdu)
            self.analyzer.emit(l2cap_pdu)

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
                if control_frame.code == CommandCode.L2CAP_CONNECTION_REQUEST:
                    connection_request = cast(L2CAP_Connection_Request, control_frame)
                    self.psms[connection_request.source_cid] = connection_request.psm
                elif control_frame.code == CommandCode.L2CAP_CONNECTION_RESPONSE:
                    connection_response = cast(L2CAP_Connection_Response, control_frame)
                    if (
                        connection_response.result
                        == L2CAP_Connection_Response.Result.CONNECTION_SUCCESSFUL
                    ):
                        if self.peer and (
                            psm := self.peer.psms.get(connection_response.source_cid)
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
                                ] = avdtp.MessageAssembler(self.peer.on_avdtp_message)
                            elif psm == avctp.AVCTP_PSM:
                                self.avctp_assemblers[
                                    connection_response.source_cid
                                ] = avctp.MessageAssembler(self.on_avctp_message)
                                self.peer.avctp_assemblers[
                                    connection_response.destination_cid
                                ] = avctp.MessageAssembler(self.peer.on_avctp_message)
            else:
                # Try to find the PSM associated with this PDU
                if self.peer and (psm := self.peer.psms.get(l2cap_pdu.cid)):
                    if psm == sdp.SDP_PSM:
                        sdp_pdu = sdp.SDP_PDU.from_bytes(l2cap_pdu.payload)
                        self.analyzer.emit(sdp_pdu)
                    elif psm == rfcomm.RFCOMM_PSM:
                        rfcomm_frame = rfcomm.RFCOMM_Frame.from_bytes(l2cap_pdu.payload)
                        self.analyzer.emit(rfcomm_frame)
                    elif psm == avdtp.AVDTP_PSM:
                        self.analyzer.emit(
                            f'{color("L2CAP", "green")} [CID={l2cap_pdu.cid}, '
                            f'PSM=AVDTP]: {l2cap_pdu.payload.hex()}'
                        )
                        if avdtp_assembler := self.avdtp_assemblers.get(l2cap_pdu.cid):
                            avdtp_assembler.on_pdu(l2cap_pdu.payload)
                    elif psm == avctp.AVCTP_PSM:
                        self.analyzer.emit(
                            f'{color("L2CAP", "green")} [CID={l2cap_pdu.cid}, '
                            f'PSM=AVCTP]: {l2cap_pdu.payload.hex()}'
                        )
                        if avctp_assembler := self.avctp_assemblers.get(l2cap_pdu.cid):
                            avctp_assembler.on_pdu(l2cap_pdu.payload)
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

        def on_avctp_message(
            self,
            transaction_label: int,
            is_command: bool,
            ipid: bool,
            pid: int,
            payload: bytes,
        ):
            if pid == avrcp.AVRCP_PID:
                avc_frame = avc.Frame.from_bytes(payload)
                details = str(avc_frame)
            else:
                details = payload.hex()

            c_r = 'Command' if is_command else 'Response'
            self.analyzer.emit(
                f'{color("AVCTP", "green")} '
                f'{c_r}[{transaction_label}][{name_or_number(AVCTP_PID_NAMES, pid)}] '
                f'{"#" if ipid else ""}'
                f'{details}'
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
            self.packet_timestamp: Optional[datetime.datetime] = None

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

        def on_packet(
            self, timestamp: Optional[datetime.datetime], packet: HCI_Packet
        ) -> None:
            self.packet_timestamp = timestamp
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
            if self.packet_timestamp:
                prefix = f"[{self.packet_timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')}]"
            else:
                prefix = ""
            self.emit_message(f'{prefix}[{self.label}] {message}')

    def trace(
        self,
        packet: HCI_Packet,
        direction: int = 0,
        timestamp: Optional[datetime.datetime] = None,
    ) -> None:
        if direction == 0:
            self.host_to_controller_analyzer.on_packet(timestamp, packet)
        else:
            self.controller_to_host_analyzer.on_packet(timestamp, packet)

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


def generate_irk() -> bytes:
    return crypto.r()


def verify_rpa_with_irk(rpa: Address, irk: bytes) -> bool:
    rpa_bytes = bytes(rpa)
    prand_given = rpa_bytes[3:]
    hash_given = rpa_bytes[:3]
    hash_local = crypto.ah(irk, prand_given)
    return hash_local[:3] == hash_given
