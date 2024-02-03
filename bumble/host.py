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
import asyncio
import collections
import dataclasses
import logging
import struct

from typing import Any, Awaitable, Callable, Deque, Dict, Optional, cast, TYPE_CHECKING

from bumble.colors import color
from bumble.l2cap import L2CAP_PDU
from bumble.snoop import Snooper
from bumble import drivers
from bumble import hci
from bumble.core import (
    BT_BR_EDR_TRANSPORT,
    BT_LE_TRANSPORT,
    ConnectionPHY,
    ConnectionParameters,
)
from bumble.utils import AbortableEventEmitter
from bumble.transport.common import TransportLostError

if TYPE_CHECKING:
    from .transport.common import TransportSink, TransportSource


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class AclPacketQueue:
    max_packet_size: int

    def __init__(
        self,
        max_packet_size: int,
        max_in_flight: int,
        send: Callable[[hci.HCI_Packet], None],
    ) -> None:
        self.max_packet_size = max_packet_size
        self.max_in_flight = max_in_flight
        self.in_flight = 0
        self.send = send
        self.packets: Deque[hci.HCI_AclDataPacket] = collections.deque()

    def enqueue(self, packet: hci.HCI_AclDataPacket) -> None:
        self.packets.appendleft(packet)
        self.check_queue()

        if self.packets:
            logger.debug(
                f'{self.in_flight} ACL packets in flight, '
                f'{len(self.packets)} in queue'
            )

    def check_queue(self) -> None:
        while self.packets and self.in_flight < self.max_in_flight:
            packet = self.packets.pop()
            self.send(packet)
            self.in_flight += 1

    def on_packets_completed(self, packet_count: int) -> None:
        if packet_count > self.in_flight:
            logger.warning(
                color(
                    '!!! {packet_count} completed but only '
                    f'{self.in_flight} in flight'
                )
            )
            packet_count = self.in_flight

        self.in_flight -= packet_count
        self.check_queue()


# -----------------------------------------------------------------------------
class Connection:
    def __init__(
        self, host: Host, handle: int, peer_address: hci.Address, transport: int
    ):
        self.host = host
        self.handle = handle
        self.peer_address = peer_address
        self.assembler = hci.HCI_AclDataPacketAssembler(self.on_acl_pdu)
        self.transport = transport
        acl_packet_queue: Optional[AclPacketQueue] = (
            host.le_acl_packet_queue
            if transport == BT_LE_TRANSPORT
            else host.acl_packet_queue
        )
        assert acl_packet_queue
        self.acl_packet_queue = acl_packet_queue

    def on_hci_acl_data_packet(self, packet: hci.HCI_AclDataPacket) -> None:
        self.assembler.feed_packet(packet)

    def on_acl_pdu(self, pdu: bytes) -> None:
        l2cap_pdu = L2CAP_PDU.from_bytes(pdu)
        self.host.on_l2cap_pdu(self, l2cap_pdu.cid, l2cap_pdu.payload)


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class ScoLink:
    peer_address: hci.Address
    handle: int


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class CisLink:
    peer_address: hci.Address
    handle: int


# -----------------------------------------------------------------------------
class Host(AbortableEventEmitter):
    connections: Dict[int, Connection]
    cis_links: Dict[int, CisLink]
    sco_links: Dict[int, ScoLink]
    acl_packet_queue: Optional[AclPacketQueue] = None
    le_acl_packet_queue: Optional[AclPacketQueue] = None
    hci_sink: Optional[TransportSink] = None
    hci_metadata: Dict[str, Any]
    long_term_key_provider: Optional[
        Callable[[int, bytes, int], Awaitable[Optional[bytes]]]
    ]
    link_key_provider: Optional[Callable[[hci.Address], Awaitable[Optional[bytes]]]]

    def __init__(
        self,
        controller_source: Optional[TransportSource] = None,
        controller_sink: Optional[TransportSink] = None,
    ) -> None:
        super().__init__()

        self.hci_metadata = {}
        self.ready = False  # True when we can accept incoming packets
        self.connections = {}  # Connections, by connection handle
        self.cis_links = {}  # CIS links, by connection handle
        self.sco_links = {}  # SCO links, by connection handle
        self.pending_command = None
        self.pending_response = None
        self.number_of_supported_advertising_sets = 0
        self.maximum_advertising_data_length = 31
        self.local_version = None
        self.local_supported_commands = bytes(64)
        self.local_le_features = 0
        self.local_lmp_features = hci.LmpFeatureMask(0)  # Classic LMP features
        self.suggested_max_tx_octets = 251  # Max allowed
        self.suggested_max_tx_time = 2120  # Max allowed
        self.command_semaphore = asyncio.Semaphore(1)
        self.long_term_key_provider = None
        self.link_key_provider = None
        self.pairing_io_capability_provider = None  # Classic only
        self.snooper = None

        # Connect to the source and sink if specified
        if controller_source:
            self.set_packet_source(controller_source)
        if controller_sink:
            self.set_packet_sink(controller_sink)

    def find_connection_by_bd_addr(
        self,
        bd_addr: hci.Address,
        transport: Optional[int] = None,
        check_address_type: bool = False,
    ) -> Optional[Connection]:
        for connection in self.connections.values():
            if connection.peer_address.to_bytes() == bd_addr.to_bytes():
                if (
                    check_address_type
                    and connection.peer_address.address_type != bd_addr.address_type
                ):
                    continue
                if transport is None or connection.transport == transport:
                    return connection

        return None

    async def flush(self) -> None:
        # Make sure no command is pending
        await self.command_semaphore.acquire()

        # Flush current host state, then release command semaphore
        self.emit('flush')
        self.command_semaphore.release()

    async def reset(self, driver_factory=drivers.get_driver_for_host):
        if self.ready:
            self.ready = False
            await self.flush()

        # Instantiate and init a driver for the host if needed.
        # NOTE: we don't keep a reference to the driver here, because we don't
        # currently have a need for the driver later on. But if the driver interface
        # evolves, it may be required, then, to store a reference to the driver in
        # an object property.
        reset_needed = True
        if driver_factory is not None:
            if driver := await driver_factory(self):
                await driver.init_controller()
                reset_needed = False

        # Send a reset command unless a driver has already done so.
        if reset_needed:
            await self.send_command(hci.HCI_Reset_Command(), check_result=True)
            self.ready = True

        response = await self.send_command(
            hci.HCI_Read_Local_Supported_Commands_Command(), check_result=True
        )
        self.local_supported_commands = response.return_parameters.supported_commands

        if self.supports_command(hci.HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND):
            response = await self.send_command(
                hci.HCI_LE_Read_Local_Supported_Features_Command(), check_result=True
            )
            self.local_le_features = struct.unpack(
                '<Q', response.return_parameters.le_features
            )[0]

        if self.supports_command(hci.HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND):
            response = await self.send_command(
                hci.HCI_Read_Local_Version_Information_Command(), check_result=True
            )
            self.local_version = response.return_parameters

        if self.supports_command(hci.HCI_READ_LOCAL_EXTENDED_FEATURES_COMMAND):
            max_page_number = 0
            page_number = 0
            lmp_features = 0
            while page_number <= max_page_number:
                response = await self.send_command(
                    hci.HCI_Read_Local_Extended_Features_Command(
                        page_number=page_number
                    ),
                    check_result=True,
                )
                lmp_features |= int.from_bytes(
                    response.return_parameters.extended_lmp_features, 'little'
                ) << (64 * page_number)
                max_page_number = response.return_parameters.maximum_page_number
                page_number += 1
            self.local_lmp_features = hci.LmpFeatureMask(lmp_features)

        elif self.supports_command(hci.HCI_READ_LOCAL_SUPPORTED_FEATURES_COMMAND):
            response = await self.send_command(
                hci.HCI_Read_Local_Supported_Features_Command(), check_result=True
            )
            self.local_lmp_features = hci.LmpFeatureMask(
                int.from_bytes(response.return_parameters.lmp_features, 'little')
            )

        await self.send_command(
            hci.HCI_Set_Event_Mask_Command(
                event_mask=hci.HCI_Set_Event_Mask_Command.mask(
                    [
                        hci.HCI_INQUIRY_COMPLETE_EVENT,
                        hci.HCI_INQUIRY_RESULT_EVENT,
                        hci.HCI_CONNECTION_COMPLETE_EVENT,
                        hci.HCI_CONNECTION_REQUEST_EVENT,
                        hci.HCI_DISCONNECTION_COMPLETE_EVENT,
                        hci.HCI_AUTHENTICATION_COMPLETE_EVENT,
                        hci.HCI_REMOTE_NAME_REQUEST_COMPLETE_EVENT,
                        hci.HCI_ENCRYPTION_CHANGE_EVENT,
                        hci.HCI_CHANGE_CONNECTION_LINK_KEY_COMPLETE_EVENT,
                        hci.HCI_LINK_KEY_TYPE_CHANGED_EVENT,
                        hci.HCI_READ_REMOTE_SUPPORTED_FEATURES_COMPLETE_EVENT,
                        hci.HCI_READ_REMOTE_VERSION_INFORMATION_COMPLETE_EVENT,
                        hci.HCI_QOS_SETUP_COMPLETE_EVENT,
                        hci.HCI_HARDWARE_ERROR_EVENT,
                        hci.HCI_FLUSH_OCCURRED_EVENT,
                        hci.HCI_ROLE_CHANGE_EVENT,
                        hci.HCI_MODE_CHANGE_EVENT,
                        hci.HCI_RETURN_LINK_KEYS_EVENT,
                        hci.HCI_PIN_CODE_REQUEST_EVENT,
                        hci.HCI_LINK_KEY_REQUEST_EVENT,
                        hci.HCI_LINK_KEY_NOTIFICATION_EVENT,
                        hci.HCI_LOOPBACK_COMMAND_EVENT,
                        hci.HCI_DATA_BUFFER_OVERFLOW_EVENT,
                        hci.HCI_MAX_SLOTS_CHANGE_EVENT,
                        hci.HCI_READ_CLOCK_OFFSET_COMPLETE_EVENT,
                        hci.HCI_CONNECTION_PACKET_TYPE_CHANGED_EVENT,
                        hci.HCI_QOS_VIOLATION_EVENT,
                        hci.HCI_PAGE_SCAN_REPETITION_MODE_CHANGE_EVENT,
                        hci.HCI_FLOW_SPECIFICATION_COMPLETE_EVENT,
                        hci.HCI_INQUIRY_RESULT_WITH_RSSI_EVENT,
                        hci.HCI_READ_REMOTE_EXTENDED_FEATURES_COMPLETE_EVENT,
                        hci.HCI_SYNCHRONOUS_CONNECTION_COMPLETE_EVENT,
                        hci.HCI_SYNCHRONOUS_CONNECTION_CHANGED_EVENT,
                        hci.HCI_SNIFF_SUBRATING_EVENT,
                        hci.HCI_EXTENDED_INQUIRY_RESULT_EVENT,
                        hci.HCI_ENCRYPTION_KEY_REFRESH_COMPLETE_EVENT,
                        hci.HCI_IO_CAPABILITY_REQUEST_EVENT,
                        hci.HCI_IO_CAPABILITY_RESPONSE_EVENT,
                        hci.HCI_USER_CONFIRMATION_REQUEST_EVENT,
                        hci.HCI_USER_PASSKEY_REQUEST_EVENT,
                        hci.HCI_REMOTE_OOB_DATA_REQUEST_EVENT,
                        hci.HCI_SIMPLE_PAIRING_COMPLETE_EVENT,
                        hci.HCI_LINK_SUPERVISION_TIMEOUT_CHANGED_EVENT,
                        hci.HCI_ENHANCED_FLUSH_COMPLETE_EVENT,
                        hci.HCI_USER_PASSKEY_NOTIFICATION_EVENT,
                        hci.HCI_KEYPRESS_NOTIFICATION_EVENT,
                        hci.HCI_REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION_EVENT,
                        hci.HCI_LE_META_EVENT,
                    ]
                )
            )
        )

        if (
            self.local_version is not None
            and self.local_version.hci_version <= hci.HCI_VERSION_BLUETOOTH_CORE_4_0
        ):
            # Some older controllers don't like event masks with bits they don't
            # understand
            le_event_mask = bytes.fromhex('1F00000000000000')
        else:
            le_event_mask = hci.HCI_LE_Set_Event_Mask_Command.mask(
                [
                    hci.HCI_LE_CONNECTION_COMPLETE_EVENT,
                    hci.HCI_LE_ADVERTISING_REPORT_EVENT,
                    hci.HCI_LE_CONNECTION_UPDATE_COMPLETE_EVENT,
                    hci.HCI_LE_READ_REMOTE_FEATURES_COMPLETE_EVENT,
                    hci.HCI_LE_LONG_TERM_KEY_REQUEST_EVENT,
                    hci.HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_EVENT,
                    hci.HCI_LE_DATA_LENGTH_CHANGE_EVENT,
                    hci.HCI_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE_EVENT,
                    hci.HCI_LE_GENERATE_DHKEY_COMPLETE_EVENT,
                    hci.HCI_LE_ENHANCED_CONNECTION_COMPLETE_EVENT,
                    hci.HCI_LE_DIRECTED_ADVERTISING_REPORT_EVENT,
                    hci.HCI_LE_PHY_UPDATE_COMPLETE_EVENT,
                    hci.HCI_LE_EXTENDED_ADVERTISING_REPORT_EVENT,
                    hci.HCI_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_EVENT,
                    hci.HCI_LE_PERIODIC_ADVERTISING_REPORT_EVENT,
                    hci.HCI_LE_PERIODIC_ADVERTISING_SYNC_LOST_EVENT,
                    hci.HCI_LE_SCAN_TIMEOUT_EVENT,
                    hci.HCI_LE_ADVERTISING_SET_TERMINATED_EVENT,
                    hci.HCI_LE_SCAN_REQUEST_RECEIVED_EVENT,
                    hci.HCI_LE_CONNECTIONLESS_IQ_REPORT_EVENT,
                    hci.HCI_LE_CONNECTION_IQ_REPORT_EVENT,
                    hci.HCI_LE_CTE_REQUEST_FAILED_EVENT,
                    hci.HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_EVENT,
                    hci.HCI_LE_CIS_ESTABLISHED_EVENT,
                    hci.HCI_LE_CIS_REQUEST_EVENT,
                    hci.HCI_LE_CREATE_BIG_COMPLETE_EVENT,
                    hci.HCI_LE_TERMINATE_BIG_COMPLETE_EVENT,
                    hci.HCI_LE_BIG_SYNC_ESTABLISHED_EVENT,
                    hci.HCI_LE_BIG_SYNC_LOST_EVENT,
                    hci.HCI_LE_REQUEST_PEER_SCA_COMPLETE_EVENT,
                    hci.HCI_LE_PATH_LOSS_THRESHOLD_EVENT,
                    hci.HCI_LE_TRANSMIT_POWER_REPORTING_EVENT,
                    hci.HCI_LE_BIGINFO_ADVERTISING_REPORT_EVENT,
                    hci.HCI_LE_SUBRATE_CHANGE_EVENT,
                ]
            )

        await self.send_command(
            hci.HCI_LE_Set_Event_Mask_Command(le_event_mask=le_event_mask)
        )

        if self.supports_command(hci.HCI_READ_BUFFER_SIZE_COMMAND):
            response = await self.send_command(
                hci.HCI_Read_Buffer_Size_Command(), check_result=True
            )
            hc_acl_data_packet_length = (
                response.return_parameters.hc_acl_data_packet_length
            )
            hc_total_num_acl_data_packets = (
                response.return_parameters.hc_total_num_acl_data_packets
            )

            logger.debug(
                'HCI ACL flow control: '
                f'hc_acl_data_packet_length={hc_acl_data_packet_length},'
                f'hc_total_num_acl_data_packets={hc_total_num_acl_data_packets}'
            )

            self.acl_packet_queue = AclPacketQueue(
                max_packet_size=hc_acl_data_packet_length,
                max_in_flight=hc_total_num_acl_data_packets,
                send=self.send_hci_packet,
            )

        hc_le_acl_data_packet_length = 0
        hc_total_num_le_acl_data_packets = 0
        if self.supports_command(hci.HCI_LE_READ_BUFFER_SIZE_COMMAND):
            response = await self.send_command(
                hci.HCI_LE_Read_Buffer_Size_Command(), check_result=True
            )
            hc_le_acl_data_packet_length = (
                response.return_parameters.hc_le_acl_data_packet_length
            )
            hc_total_num_le_acl_data_packets = (
                response.return_parameters.hc_total_num_le_acl_data_packets
            )

            logger.debug(
                'HCI LE ACL flow control: '
                f'hc_le_acl_data_packet_length={hc_le_acl_data_packet_length},'
                f'hc_total_num_le_acl_data_packets={hc_total_num_le_acl_data_packets}'
            )

        if hc_le_acl_data_packet_length == 0 or hc_total_num_le_acl_data_packets == 0:
            # LE and Classic share the same queue
            self.le_acl_packet_queue = self.acl_packet_queue
        else:
            # Create a separate queue for LE
            self.le_acl_packet_queue = AclPacketQueue(
                max_packet_size=hc_le_acl_data_packet_length,
                max_in_flight=hc_total_num_le_acl_data_packets,
                send=self.send_hci_packet,
            )

        if self.supports_command(
            hci.HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND
        ) and self.supports_command(
            hci.HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND
        ):
            response = await self.send_command(
                hci.HCI_LE_Read_Suggested_Default_Data_Length_Command()
            )
            suggested_max_tx_octets = response.return_parameters.suggested_max_tx_octets
            suggested_max_tx_time = response.return_parameters.suggested_max_tx_time
            if (
                suggested_max_tx_octets != self.suggested_max_tx_octets
                or suggested_max_tx_time != self.suggested_max_tx_time
            ):
                await self.send_command(
                    hci.HCI_LE_Write_Suggested_Default_Data_Length_Command(
                        suggested_max_tx_octets=self.suggested_max_tx_octets,
                        suggested_max_tx_time=self.suggested_max_tx_time,
                    )
                )

        if self.supports_command(
            hci.HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND
        ):
            response = await self.send_command(
                hci.HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command(),
                check_result=True,
            )
            self.number_of_supported_advertising_sets = (
                response.return_parameters.num_supported_advertising_sets
            )

        if self.supports_command(
            hci.HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND
        ):
            response = await self.send_command(
                hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command(),
                check_result=True,
            )
            self.maximum_advertising_data_length = (
                response.return_parameters.max_advertising_data_length
            )

    @property
    def controller(self) -> Optional[TransportSink]:
        return self.hci_sink

    @controller.setter
    def controller(self, controller) -> None:
        self.set_packet_sink(controller)
        if controller:
            controller.set_packet_sink(self)

    def set_packet_sink(self, sink: Optional[TransportSink]) -> None:
        self.hci_sink = sink

    def set_packet_source(self, source: TransportSource) -> None:
        source.set_packet_sink(self)
        self.hci_metadata = getattr(source, 'metadata', self.hci_metadata)

    def send_hci_packet(self, packet: hci.HCI_Packet) -> None:
        logger.debug(f'{color("### HOST -> CONTROLLER", "blue")}: {packet}')
        if self.snooper:
            self.snooper.snoop(bytes(packet), Snooper.Direction.HOST_TO_CONTROLLER)
        if self.hci_sink:
            self.hci_sink.on_packet(bytes(packet))

    async def send_command(self, command, check_result=False):
        # Wait until we can send (only one pending command at a time)
        async with self.command_semaphore:
            assert self.pending_command is None
            assert self.pending_response is None

            # Create a future value to hold the eventual response
            self.pending_response = asyncio.get_running_loop().create_future()
            self.pending_command = command

            try:
                self.send_hci_packet(command)
                response = await self.pending_response

                # Check the return parameters if required
                if check_result:
                    if isinstance(response.return_parameters, int):
                        status = response.return_parameters
                    elif isinstance(response.return_parameters, bytes):
                        # return parameters first field is a one byte status code
                        status = response.return_parameters[0]
                    else:
                        status = response.return_parameters.status

                    if status != hci.HCI_SUCCESS:
                        logger.warning(
                            f'{command.name} failed '
                            f'({hci.HCI_Constant.error_name(status)})'
                        )
                        raise hci.HCI_Error(status)

                return response
            except Exception as error:
                logger.warning(
                    f'{color("!!! Exception while sending command:", "red")} {error}'
                )
                raise error
            finally:
                self.pending_command = None
                self.pending_response = None

    # Use this method to send a command from a task
    def send_command_sync(self, command: hci.HCI_Command) -> None:
        async def send_command(command: hci.HCI_Command) -> None:
            await self.send_command(command)

        asyncio.create_task(send_command(command))

    def send_l2cap_pdu(self, connection_handle: int, cid: int, pdu: bytes) -> None:
        if not (connection := self.connections.get(connection_handle)):
            logger.warning(f'connection 0x{connection_handle:04X} not found')
            return
        packet_queue = connection.acl_packet_queue
        if packet_queue is None:
            logger.warning(
                f'no ACL packet queue for connection 0x{connection_handle:04X}'
            )
            return

        # Create a PDU
        l2cap_pdu = bytes(L2CAP_PDU(cid, pdu))

        # Send the data to the controller via ACL packets
        bytes_remaining = len(l2cap_pdu)
        offset = 0
        pb_flag = 0
        while bytes_remaining:
            data_total_length = min(bytes_remaining, packet_queue.max_packet_size)
            acl_packet = hci.HCI_AclDataPacket(
                connection_handle=connection_handle,
                pb_flag=pb_flag,
                bc_flag=0,
                data_total_length=data_total_length,
                data=l2cap_pdu[offset : offset + data_total_length],
            )
            logger.debug(f'>>> ACL packet enqueue: (CID={cid}) {acl_packet}')
            packet_queue.enqueue(acl_packet)
            pb_flag = 1
            offset += data_total_length
            bytes_remaining -= data_total_length

    def supports_command(self, command):
        # Find the support flag position for this command
        for octet, flags in enumerate(hci.HCI_SUPPORTED_COMMANDS_FLAGS):
            for flag_position, value in enumerate(flags):
                if value == command:
                    # Check if the flag is set
                    if octet < len(self.local_supported_commands) and flag_position < 8:
                        return (
                            self.local_supported_commands[octet] & (1 << flag_position)
                        ) != 0

        return False

    @property
    def supported_commands(self):
        commands = []
        for octet, flags in enumerate(self.local_supported_commands):
            if octet < len(hci.HCI_SUPPORTED_COMMANDS_FLAGS):
                for flag in range(8):
                    if flags & (1 << flag) != 0:
                        command = hci.HCI_SUPPORTED_COMMANDS_FLAGS[octet][flag]
                        if command is not None:
                            commands.append(command)

        return commands

    def supports_le_features(self, feature: hci.LeFeatureMask) -> bool:
        return (self.local_le_features & feature) == feature

    def supports_lmp_features(self, feature: hci.LmpFeatureMask) -> bool:
        return self.local_lmp_features & (feature) == feature

    @property
    def supported_le_features(self):
        return [
            feature for feature in range(64) if self.local_le_features & (1 << feature)
        ]

    # Packet Sink protocol (packets coming from the controller via HCI)
    def on_packet(self, packet: bytes) -> None:
        hci_packet = hci.HCI_Packet.from_bytes(packet)
        if self.ready or (
            isinstance(hci_packet, hci.HCI_Command_Complete_Event)
            and hci_packet.command_opcode == hci.HCI_RESET_COMMAND
        ):
            self.on_hci_packet(hci_packet)
        else:
            logger.debug('reset not done, ignoring packet from controller')

    def on_transport_lost(self):
        # Called by the source when the transport has been lost.
        if self.pending_response:
            self.pending_response.set_exception(TransportLostError('transport lost'))

        self.emit('flush')

    def on_hci_packet(self, packet: hci.HCI_Packet) -> None:
        logger.debug(f'{color("### CONTROLLER -> HOST", "green")}: {packet}')

        if self.snooper:
            self.snooper.snoop(bytes(packet), Snooper.Direction.CONTROLLER_TO_HOST)

        # If the packet is a command, invoke the handler for this packet
        if packet.hci_packet_type == hci.HCI_COMMAND_PACKET:
            self.on_hci_command_packet(cast(hci.HCI_Command, packet))
        elif packet.hci_packet_type == hci.HCI_EVENT_PACKET:
            self.on_hci_event_packet(cast(hci.HCI_Event, packet))
        elif packet.hci_packet_type == hci.HCI_ACL_DATA_PACKET:
            self.on_hci_acl_data_packet(cast(hci.HCI_AclDataPacket, packet))
        elif packet.hci_packet_type == hci.HCI_SYNCHRONOUS_DATA_PACKET:
            self.on_hci_sco_data_packet(cast(hci.HCI_SynchronousDataPacket, packet))
        elif packet.hci_packet_type == hci.HCI_ISO_DATA_PACKET:
            self.on_hci_iso_data_packet(cast(hci.HCI_IsoDataPacket, packet))
        else:
            logger.warning(f'!!! unknown packet type {packet.hci_packet_type}')

    def on_hci_command_packet(self, command: hci.HCI_Command) -> None:
        logger.warning(f'!!! unexpected command packet: {command}')

    def on_hci_event_packet(self, event: hci.HCI_Event) -> None:
        handler_name = f'on_{event.name.lower()}'
        handler = getattr(self, handler_name, self.on_hci_event)
        handler(event)

    def on_hci_acl_data_packet(self, packet: hci.HCI_AclDataPacket) -> None:
        # Look for the connection to which this data belongs
        if connection := self.connections.get(packet.connection_handle):
            connection.on_hci_acl_data_packet(packet)

    def on_hci_sco_data_packet(self, packet: hci.HCI_SynchronousDataPacket) -> None:
        # Experimental
        self.emit('sco_packet', packet.connection_handle, packet)

    def on_hci_iso_data_packet(self, packet: hci.HCI_IsoDataPacket) -> None:
        # Experimental
        self.emit('iso_packet', packet.connection_handle, packet)

    def on_l2cap_pdu(self, connection: Connection, cid: int, pdu: bytes) -> None:
        self.emit('l2cap_pdu', connection.handle, cid, pdu)

    def on_command_processed(self, event):
        if self.pending_response:
            # Check that it is what we were expecting
            if self.pending_command.op_code != event.command_opcode:
                logger.warning(
                    '!!! command result mismatch, expected '
                    f'0x{self.pending_command.op_code:X} but got '
                    f'0x{event.command_opcode:X}'
                )

            self.pending_response.set_result(event)
        else:
            logger.warning('!!! no pending response future to set')

    ############################################################
    # HCI handlers
    ############################################################
    def on_hci_event(self, event):
        logger.warning(f'{color(f"--- Ignoring event {event}", "red")}')

    def on_hci_command_complete_event(self, event):
        if event.command_opcode == 0:
            # This is used just for the Num_HCI_Command_Packets field, not related to
            # an actual command
            logger.debug('no-command event')
            return

        return self.on_command_processed(event)

    def on_hci_command_status_event(self, event):
        return self.on_command_processed(event)

    def on_hci_number_of_completed_packets_event(self, event):
        for connection_handle, num_completed_packets in zip(
            event.connection_handles, event.num_completed_packets
        ):
            if not (connection := self.connections.get(connection_handle)):
                logger.warning(
                    'received packet completion event for unknown handle '
                    f'0x{connection_handle:04X}'
                )
                continue

            connection.acl_packet_queue.on_packets_completed(num_completed_packets)

    # Classic only
    def on_hci_connection_request_event(self, event):
        # Notify the listeners
        self.emit(
            'connection_request',
            event.bd_addr,
            event.class_of_device,
            event.link_type,
        )

    def on_hci_le_connection_complete_event(self, event):
        # Check if this is a cancellation
        if event.status == hci.HCI_SUCCESS:
            # Create/update the connection
            logger.debug(
                f'### LE CONNECTION: [0x{event.connection_handle:04X}] '
                f'{event.peer_address} as {hci.HCI_Constant.role_name(event.role)}'
            )

            connection = self.connections.get(event.connection_handle)
            if connection is None:
                connection = Connection(
                    self,
                    event.connection_handle,
                    event.peer_address,
                    BT_LE_TRANSPORT,
                )
                self.connections[event.connection_handle] = connection

            # Notify the client
            connection_parameters = ConnectionParameters(
                event.connection_interval,
                event.peripheral_latency,
                event.supervision_timeout,
            )
            self.emit(
                'connection',
                event.connection_handle,
                BT_LE_TRANSPORT,
                event.peer_address,
                event.role,
                connection_parameters,
            )
        else:
            logger.debug(f'### CONNECTION FAILED: {event.status}')

            # Notify the listeners
            self.emit(
                'connection_failure', BT_LE_TRANSPORT, event.peer_address, event.status
            )

    def on_hci_le_enhanced_connection_complete_event(self, event):
        # Just use the same implementation as for the non-enhanced event for now
        self.on_hci_le_connection_complete_event(event)

    def on_hci_connection_complete_event(self, event):
        if event.status == hci.HCI_SUCCESS:
            # Create/update the connection
            logger.debug(
                f'### BR/EDR CONNECTION: [0x{event.connection_handle:04X}] '
                f'{event.bd_addr}'
            )

            connection = self.connections.get(event.connection_handle)
            if connection is None:
                connection = Connection(
                    self,
                    event.connection_handle,
                    event.bd_addr,
                    BT_BR_EDR_TRANSPORT,
                )
                self.connections[event.connection_handle] = connection

            # Notify the client
            self.emit(
                'connection',
                event.connection_handle,
                BT_BR_EDR_TRANSPORT,
                event.bd_addr,
                None,
                None,
            )
        else:
            logger.debug(f'### BR/EDR CONNECTION FAILED: {event.status}')

            # Notify the client
            self.emit(
                'connection_failure', BT_BR_EDR_TRANSPORT, event.bd_addr, event.status
            )

    def on_hci_disconnection_complete_event(self, event):
        # Find the connection
        handle = event.connection_handle
        if (
            connection := (
                self.connections.get(handle)
                or self.cis_links.get(handle)
                or self.sco_links.get(handle)
            )
        ) is None:
            logger.warning('!!! DISCONNECTION COMPLETE: unknown handle')
            return

        if event.status == hci.HCI_SUCCESS:
            logger.debug(
                f'### DISCONNECTION: [0x{handle:04X}] '
                f'{connection.peer_address} '
                f'reason={event.reason}'
            )

            # Notify the listeners
            self.emit('disconnection', handle, event.reason)

            # Remove the handle reference
            _ = (
                self.connections.pop(handle, 0)
                or self.cis_links.pop(handle, 0)
                or self.sco_links.pop(handle, 0)
            )
        else:
            logger.debug(f'### DISCONNECTION FAILED: {event.status}')

            # Notify the listeners
            self.emit('disconnection_failure', handle, event.status)

    def on_hci_le_connection_update_complete_event(self, event):
        if (connection := self.connections.get(event.connection_handle)) is None:
            logger.warning('!!! CONNECTION PARAMETERS UPDATE COMPLETE: unknown handle')
            return

        # Notify the client
        if event.status == hci.HCI_SUCCESS:
            connection_parameters = ConnectionParameters(
                event.connection_interval,
                event.peripheral_latency,
                event.supervision_timeout,
            )
            self.emit(
                'connection_parameters_update', connection.handle, connection_parameters
            )
        else:
            self.emit(
                'connection_parameters_update_failure', connection.handle, event.status
            )

    def on_hci_le_phy_update_complete_event(self, event):
        if (connection := self.connections.get(event.connection_handle)) is None:
            logger.warning('!!! CONNECTION PHY UPDATE COMPLETE: unknown handle')
            return

        # Notify the client
        if event.status == hci.HCI_SUCCESS:
            connection_phy = ConnectionPHY(event.tx_phy, event.rx_phy)
            self.emit('connection_phy_update', connection.handle, connection_phy)
        else:
            self.emit('connection_phy_update_failure', connection.handle, event.status)

    def on_hci_le_advertising_report_event(self, event):
        for report in event.reports:
            self.emit('advertising_report', report)

    def on_hci_le_extended_advertising_report_event(self, event):
        self.on_hci_le_advertising_report_event(event)

    def on_hci_le_advertising_set_terminated_event(self, event):
        self.emit(
            'advertising_set_termination',
            event.status,
            event.advertising_handle,
            event.connection_handle,
            event.num_completed_extended_advertising_events,
        )

    def on_hci_le_cis_request_event(self, event):
        self.emit(
            'cis_request',
            event.acl_connection_handle,
            event.cis_connection_handle,
            event.cig_id,
            event.cis_id,
        )

    def on_hci_le_cis_established_event(self, event):
        # The remaining parameters are unused for now.
        if event.status == hci.HCI_SUCCESS:
            self.cis_links[event.connection_handle] = CisLink(
                handle=event.connection_handle,
                peer_address=hci.Address.ANY,
            )
            self.emit('cis_establishment', event.connection_handle)
        else:
            self.emit(
                'cis_establishment_failure', event.connection_handle, event.status
            )

    def on_hci_le_remote_connection_parameter_request_event(self, event):
        if event.connection_handle not in self.connections:
            logger.warning('!!! REMOTE CONNECTION PARAMETER REQUEST: unknown handle')
            return

        # For now, just accept everything
        # TODO: delegate the decision
        self.send_command_sync(
            hci.HCI_LE_Remote_Connection_Parameter_Request_Reply_Command(
                connection_handle=event.connection_handle,
                interval_min=event.interval_min,
                interval_max=event.interval_max,
                max_latency=event.max_latency,
                timeout=event.timeout,
                min_ce_length=0,
                max_ce_length=0,
            )
        )

    def on_hci_le_long_term_key_request_event(self, event):
        if (connection := self.connections.get(event.connection_handle)) is None:
            logger.warning('!!! LE LONG TERM KEY REQUEST: unknown handle')
            return

        async def send_long_term_key():
            if self.long_term_key_provider is None:
                logger.debug('no long term key provider')
                long_term_key = None
            else:
                long_term_key = await self.abort_on(
                    'flush',
                    # pylint: disable-next=not-callable
                    self.long_term_key_provider(
                        connection.handle,
                        event.random_number,
                        event.encryption_diversifier,
                    ),
                )
            if long_term_key:
                response = hci.HCI_LE_Long_Term_Key_Request_Reply_Command(
                    connection_handle=event.connection_handle,
                    long_term_key=long_term_key,
                )
            else:
                response = hci.HCI_LE_Long_Term_Key_Request_Negative_Reply_Command(
                    connection_handle=event.connection_handle
                )

            await self.send_command(response)

        asyncio.create_task(send_long_term_key())

    def on_hci_synchronous_connection_complete_event(self, event):
        if event.status == hci.HCI_SUCCESS:
            # Create/update the connection
            logger.debug(
                f'### SCO CONNECTION: [0x{event.connection_handle:04X}] '
                f'{event.bd_addr}'
            )

            self.sco_links[event.connection_handle] = ScoLink(
                peer_address=event.bd_addr,
                handle=event.connection_handle,
            )

            # Notify the client
            self.emit(
                'sco_connection',
                event.bd_addr,
                event.connection_handle,
                event.link_type,
            )
        else:
            logger.debug(f'### SCO CONNECTION FAILED: {event.status}')

            # Notify the client
            self.emit('sco_connection_failure', event.bd_addr, event.status)

    def on_hci_synchronous_connection_changed_event(self, event):
        pass

    def on_hci_role_change_event(self, event):
        if event.status == hci.HCI_SUCCESS:
            logger.debug(
                f'role change for {event.bd_addr}: '
                f'{hci.HCI_Constant.role_name(event.new_role)}'
            )
            self.emit('role_change', event.bd_addr, event.new_role)
        else:
            logger.debug(
                f'role change for {event.bd_addr} failed: '
                f'{hci.HCI_Constant.error_name(event.status)}'
            )
            self.emit('role_change_failure', event.bd_addr, event.status)

    def on_hci_le_data_length_change_event(self, event):
        self.emit(
            'connection_data_length_change',
            event.connection_handle,
            event.max_tx_octets,
            event.max_tx_time,
            event.max_rx_octets,
            event.max_rx_time,
        )

    def on_hci_authentication_complete_event(self, event):
        # Notify the client
        if event.status == hci.HCI_SUCCESS:
            self.emit('connection_authentication', event.connection_handle)
        else:
            self.emit(
                'connection_authentication_failure',
                event.connection_handle,
                event.status,
            )

    def on_hci_encryption_change_event(self, event):
        # Notify the client
        if event.status == hci.HCI_SUCCESS:
            self.emit(
                'connection_encryption_change',
                event.connection_handle,
                event.encryption_enabled,
            )
        else:
            self.emit(
                'connection_encryption_failure', event.connection_handle, event.status
            )

    def on_hci_encryption_key_refresh_complete_event(self, event):
        # Notify the client
        if event.status == hci.HCI_SUCCESS:
            self.emit('connection_encryption_key_refresh', event.connection_handle)
        else:
            self.emit(
                'connection_encryption_key_refresh_failure',
                event.connection_handle,
                event.status,
            )

    def on_hci_link_supervision_timeout_changed_event(self, event):
        pass

    def on_hci_max_slots_change_event(self, event):
        pass

    def on_hci_page_scan_repetition_mode_change_event(self, event):
        pass

    def on_hci_link_key_notification_event(self, event):
        logger.debug(
            f'link key for {event.bd_addr}: {event.link_key.hex()}, '
            f'type={hci.HCI_Constant.link_key_type_name(event.key_type)}'
        )
        self.emit('link_key', event.bd_addr, event.link_key, event.key_type)

    def on_hci_simple_pairing_complete_event(self, event):
        logger.debug(
            f'simple pairing complete for {event.bd_addr}: '
            f'status={hci.HCI_Constant.status_name(event.status)}'
        )
        if event.status == hci.HCI_SUCCESS:
            self.emit('classic_pairing', event.bd_addr)
        else:
            self.emit('classic_pairing_failure', event.bd_addr, event.status)

    def on_hci_pin_code_request_event(self, event):
        self.emit('pin_code_request', event.bd_addr)

    def on_hci_link_key_request_event(self, event):
        async def send_link_key():
            if self.link_key_provider is None:
                logger.debug('no link key provider')
                link_key = None
            else:
                link_key = await self.abort_on(
                    'flush',
                    # pylint: disable-next=not-callable
                    self.link_key_provider(event.bd_addr),
                )
            if link_key:
                response = hci.HCI_Link_Key_Request_Reply_Command(
                    bd_addr=event.bd_addr, link_key=link_key
                )
            else:
                response = hci.HCI_Link_Key_Request_Negative_Reply_Command(
                    bd_addr=event.bd_addr
                )

            await self.send_command(response)

        asyncio.create_task(send_link_key())

    def on_hci_io_capability_request_event(self, event):
        self.emit('authentication_io_capability_request', event.bd_addr)

    def on_hci_io_capability_response_event(self, event):
        self.emit(
            'authentication_io_capability_response',
            event.bd_addr,
            event.io_capability,
            event.authentication_requirements,
        )

    def on_hci_user_confirmation_request_event(self, event):
        self.emit(
            'authentication_user_confirmation_request',
            event.bd_addr,
            event.numeric_value,
        )

    def on_hci_user_passkey_request_event(self, event):
        self.emit('authentication_user_passkey_request', event.bd_addr)

    def on_hci_user_passkey_notification_event(self, event):
        self.emit(
            'authentication_user_passkey_notification', event.bd_addr, event.passkey
        )

    def on_hci_inquiry_complete_event(self, _event):
        self.emit('inquiry_complete')

    def on_hci_inquiry_result_with_rssi_event(self, event):
        for response in event.responses:
            self.emit(
                'inquiry_result',
                response.bd_addr,
                response.class_of_device,
                b'',
                response.rssi,
            )

    def on_hci_extended_inquiry_result_event(self, event):
        self.emit(
            'inquiry_result',
            event.bd_addr,
            event.class_of_device,
            event.extended_inquiry_response,
            event.rssi,
        )

    def on_hci_remote_name_request_complete_event(self, event):
        if event.status != hci.HCI_SUCCESS:
            self.emit('remote_name_failure', event.bd_addr, event.status)
        else:
            utf8_name = event.remote_name
            terminator = utf8_name.find(0)
            if terminator >= 0:
                utf8_name = utf8_name[0:terminator]

            self.emit('remote_name', event.bd_addr, utf8_name)

    def on_hci_remote_host_supported_features_notification_event(self, event):
        self.emit(
            'remote_host_supported_features',
            event.bd_addr,
            event.host_supported_features,
        )

    def on_hci_le_read_remote_features_complete_event(self, event):
        if event.status != hci.HCI_SUCCESS:
            self.emit(
                'le_remote_features_failure', event.connection_handle, event.status
            )
        else:
            self.emit(
                'le_remote_features',
                event.connection_handle,
                int.from_bytes(event.le_features, 'little'),
            )
