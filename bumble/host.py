# Copyright 2021-2025 Google LLC
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

from typing import (
    Any,
    Awaitable,
    Callable,
    Deque,
    Dict,
    Optional,
    Set,
    cast,
    TYPE_CHECKING,
)


from bumble.colors import color
from bumble.l2cap import L2CAP_PDU
from bumble.snoop import Snooper
from bumble import drivers
from bumble import hci
from bumble.core import (
    PhysicalTransport,
    PhysicalTransport,
    ConnectionPHY,
    ConnectionParameters,
)
from bumble import utils
from bumble.transport.common import TransportLostError

if TYPE_CHECKING:
    from bumble.transport.common import TransportSink, TransportSource


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class DataPacketQueue(utils.EventEmitter):
    """
    Flow-control queue for host->controller data packets (ACL, ISO).

    The queue holds packets associated with a connection handle. The packets
    are sent to the controller, up to a maximum total number of packets in flight.
    A packet is considered to be "in flight" when it has been sent to the controller
    but not completed yet. Packets are no longer "in flight" when the controller
    declares them as completed.

    The queue emits a 'flow' event whenever one or more packets are completed.
    """

    max_packet_size: int

    def __init__(
        self,
        max_packet_size: int,
        max_in_flight: int,
        send: Callable[[hci.HCI_Packet], None],
    ) -> None:
        super().__init__()
        self.max_packet_size = max_packet_size
        self.max_in_flight = max_in_flight
        self._in_flight = 0  # Total number of packets in flight across all connections
        self._in_flight_per_connection: dict[int, int] = collections.defaultdict(
            int
        )  # Number of packets in flight per connection
        self._send = send
        self._packets: Deque[tuple[hci.HCI_Packet, int]] = collections.deque()
        self._queued = 0
        self._completed = 0

    @property
    def queued(self) -> int:
        """Total number of packets queued since creation."""
        return self._queued

    @property
    def completed(self) -> int:
        """Total number of packets completed since creation."""
        return self._completed

    @property
    def pending(self) -> int:
        """Number of packets that have been queued but not completed."""
        return self._queued - self._completed

    def enqueue(self, packet: hci.HCI_Packet, connection_handle: int) -> None:
        """Enqueue a packet associated with a connection"""
        self._packets.appendleft((packet, connection_handle))
        self._queued += 1
        self._check_queue()

        if self._packets:
            logger.debug(
                f'{self._in_flight} packets in flight, '
                f'{len(self._packets)} in queue'
            )

    def flush(self, connection_handle: int) -> None:
        """
        Remove all packets associated with a connection.

        All packets associated with the connection that are in flight are implicitly
        marked as completed, but no 'flow' event is emitted.
        """

        packets_to_keep = [
            (packet, handle)
            for (packet, handle) in self._packets
            if handle != connection_handle
        ]
        if flushed_count := len(self._packets) - len(packets_to_keep):
            self._completed += flushed_count
            self._packets = collections.deque(packets_to_keep)

        if connection_handle in self._in_flight_per_connection:
            in_flight = self._in_flight_per_connection[connection_handle]
            self._completed += in_flight
            self._in_flight -= in_flight
            del self._in_flight_per_connection[connection_handle]

    def _check_queue(self) -> None:
        while self._packets and self._in_flight < self.max_in_flight:
            packet, connection_handle = self._packets.pop()
            self._send(packet)
            self._in_flight += 1
            self._in_flight_per_connection[connection_handle] += 1

    def on_packets_completed(self, packet_count: int, connection_handle: int) -> None:
        """Mark one or more packets associated with a connection as completed."""
        if connection_handle not in self._in_flight_per_connection:
            logger.warning(
                f'received completion for unknown connection {connection_handle}'
            )
            return

        in_flight_for_connection = self._in_flight_per_connection[connection_handle]
        if packet_count <= in_flight_for_connection:
            self._in_flight_per_connection[connection_handle] -= packet_count
        else:
            logger.warning(
                f'{packet_count} completed for {connection_handle} '
                f'but only {in_flight_for_connection} in flight'
            )
            self._in_flight_per_connection[connection_handle] = 0

        if packet_count <= self._in_flight:
            self._in_flight -= packet_count
            self._completed += packet_count
        else:
            logger.warning(
                f'{packet_count} completed but only {self._in_flight} in flight'
            )
            self._in_flight = 0
            self._completed = self._queued

        self._check_queue()
        self.emit('flow')


# -----------------------------------------------------------------------------
class Connection:
    def __init__(
        self,
        host: Host,
        handle: int,
        peer_address: hci.Address,
        transport: PhysicalTransport,
    ):
        self.host = host
        self.handle = handle
        self.peer_address = peer_address
        self.assembler = hci.HCI_AclDataPacketAssembler(self.on_acl_pdu)
        self.transport = transport
        acl_packet_queue: Optional[DataPacketQueue] = (
            host.le_acl_packet_queue
            if transport == PhysicalTransport.LE
            else host.acl_packet_queue
        )
        assert acl_packet_queue
        self.acl_packet_queue = acl_packet_queue

    def on_hci_acl_data_packet(self, packet: hci.HCI_AclDataPacket) -> None:
        self.assembler.feed_packet(packet)

    def on_acl_pdu(self, pdu: bytes) -> None:
        l2cap_pdu = L2CAP_PDU.from_bytes(pdu)
        self.host.on_l2cap_pdu(self, l2cap_pdu.cid, l2cap_pdu.payload)

    def __str__(self) -> str:
        return (
            f'Connection(transport={self.transport}, peer_address={self.peer_address})'
        )


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class ScoLink:
    peer_address: hci.Address
    connection_handle: int


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class IsoLink:
    handle: int
    packet_queue: DataPacketQueue = dataclasses.field(repr=False)
    packet_sequence_number: int = 0


# -----------------------------------------------------------------------------
class Host(utils.EventEmitter):
    connections: Dict[int, Connection]
    cis_links: Dict[int, IsoLink]
    bis_links: Dict[int, IsoLink]
    sco_links: Dict[int, ScoLink]
    bigs: dict[int, set[int]]
    acl_packet_queue: Optional[DataPacketQueue] = None
    le_acl_packet_queue: Optional[DataPacketQueue] = None
    iso_packet_queue: Optional[DataPacketQueue] = None
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
        self.bis_links = {}  # BIS links, by connection handle
        self.sco_links = {}  # SCO links, by connection handle
        self.bigs = {}  # BIG Handle to BIS Handles
        self.pending_command = None
        self.pending_response: Optional[asyncio.Future[Any]] = None
        self.number_of_supported_advertising_sets = 0
        self.maximum_advertising_data_length = 31
        self.local_version = None
        self.local_supported_commands = 0
        self.local_le_features = 0
        self.local_lmp_features = hci.LmpFeatureMask(0)  # Classic LMP features
        self.suggested_max_tx_octets = 251  # Max allowed
        self.suggested_max_tx_time = 2120  # Max allowed
        self.command_semaphore = asyncio.Semaphore(1)
        self.long_term_key_provider = None
        self.link_key_provider = None
        self.pairing_io_capability_provider = None  # Classic only
        self.snooper: Optional[Snooper] = None

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
            if bytes(connection.peer_address) == bytes(bd_addr):
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
        self.local_supported_commands = int.from_bytes(
            response.return_parameters.supported_commands, 'little'
        )

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
                    hci.HCI_LE_CS_READ_REMOTE_SUPPORTED_CAPABILITIES_COMPLETE_EVENT,
                    hci.HCI_LE_CS_PROCEDURE_ENABLE_COMPLETE_EVENT,
                    hci.HCI_LE_CS_SECURITY_ENABLE_COMPLETE_EVENT,
                    hci.HCI_LE_CS_CONFIG_COMPLETE_EVENT,
                    hci.HCI_LE_CS_SUBEVENT_RESULT_EVENT,
                    hci.HCI_LE_CS_SUBEVENT_RESULT_CONTINUE_EVENT,
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

            self.acl_packet_queue = DataPacketQueue(
                max_packet_size=hc_acl_data_packet_length,
                max_in_flight=hc_total_num_acl_data_packets,
                send=self.send_hci_packet,
            )

        le_acl_data_packet_length = 0
        total_num_le_acl_data_packets = 0
        iso_data_packet_length = 0
        total_num_iso_data_packets = 0
        if self.supports_command(hci.HCI_LE_READ_BUFFER_SIZE_V2_COMMAND):
            response = await self.send_command(
                hci.HCI_LE_Read_Buffer_Size_V2_Command(), check_result=True
            )
            le_acl_data_packet_length = (
                response.return_parameters.le_acl_data_packet_length
            )
            total_num_le_acl_data_packets = (
                response.return_parameters.total_num_le_acl_data_packets
            )
            iso_data_packet_length = response.return_parameters.iso_data_packet_length
            total_num_iso_data_packets = (
                response.return_parameters.total_num_iso_data_packets
            )

            logger.debug(
                'HCI LE flow control: '
                f'le_acl_data_packet_length={le_acl_data_packet_length},'
                f'total_num_le_acl_data_packets={total_num_le_acl_data_packets}'
                f'iso_data_packet_length={iso_data_packet_length},'
                f'total_num_iso_data_packets={total_num_iso_data_packets}'
            )
        elif self.supports_command(hci.HCI_LE_READ_BUFFER_SIZE_COMMAND):
            response = await self.send_command(
                hci.HCI_LE_Read_Buffer_Size_Command(), check_result=True
            )
            le_acl_data_packet_length = (
                response.return_parameters.le_acl_data_packet_length
            )
            total_num_le_acl_data_packets = (
                response.return_parameters.total_num_le_acl_data_packets
            )

            logger.debug(
                'HCI LE ACL flow control: '
                f'le_acl_data_packet_length={le_acl_data_packet_length},'
                f'total_num_le_acl_data_packets={total_num_le_acl_data_packets}'
            )

        if le_acl_data_packet_length == 0 or total_num_le_acl_data_packets == 0:
            # LE and Classic share the same queue
            self.le_acl_packet_queue = self.acl_packet_queue
        else:
            # Create a separate queue for LE
            self.le_acl_packet_queue = DataPacketQueue(
                max_packet_size=le_acl_data_packet_length,
                max_in_flight=total_num_le_acl_data_packets,
                send=self.send_hci_packet,
            )

        if iso_data_packet_length and total_num_iso_data_packets:
            self.iso_packet_queue = DataPacketQueue(
                max_packet_size=iso_data_packet_length,
                max_in_flight=total_num_iso_data_packets,
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
            self.set_packet_source(controller)

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

    async def send_command(
        self, command, check_result=False, response_timeout: Optional[int] = None
    ):
        # Wait until we can send (only one pending command at a time)
        async with self.command_semaphore:
            assert self.pending_command is None
            assert self.pending_response is None

            # Create a future value to hold the eventual response
            self.pending_response = asyncio.get_running_loop().create_future()
            self.pending_command = command

            try:
                self.send_hci_packet(command)
                await asyncio.wait_for(self.pending_response, timeout=response_timeout)
                response = self.pending_response.result()

                # Check the return parameters if required
                if check_result:
                    if isinstance(response, hci.HCI_Command_Status_Event):
                        status = response.status  # type: ignore[attr-defined]
                    elif isinstance(response.return_parameters, int):
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
                logger.exception(
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
            packet_queue.enqueue(acl_packet, connection_handle)
            pb_flag = 1
            offset += data_total_length
            bytes_remaining -= data_total_length

    def get_data_packet_queue(self, connection_handle: int) -> DataPacketQueue | None:
        if connection := self.connections.get(connection_handle):
            return connection.acl_packet_queue

        if iso_link := self.cis_links.get(connection_handle) or self.bis_links.get(
            connection_handle
        ):
            return iso_link.packet_queue

        return None

    def send_iso_sdu(self, connection_handle: int, sdu: bytes) -> None:
        if not (
            iso_link := self.cis_links.get(connection_handle)
            or self.bis_links.get(connection_handle)
        ):
            logger.warning(f"no ISO link for connection handle {connection_handle}")
            return

        if iso_link.packet_queue is None:
            logger.warning("ISO link has no data packet queue")
            return

        bytes_remaining = len(sdu)
        offset = 0
        while bytes_remaining:
            is_first_fragment = offset == 0
            header_length = 4 if is_first_fragment else 0
            assert iso_link.packet_queue.max_packet_size > header_length
            fragment_length = min(
                bytes_remaining, iso_link.packet_queue.max_packet_size - header_length
            )
            is_last_fragment = bytes_remaining == fragment_length
            iso_sdu_fragment = sdu[offset : offset + fragment_length]
            iso_link.packet_queue.enqueue(
                (
                    hci.HCI_IsoDataPacket(
                        connection_handle=connection_handle,
                        data_total_length=header_length + fragment_length,
                        packet_sequence_number=iso_link.packet_sequence_number,
                        pb_flag=0b10 if is_last_fragment else 0b00,
                        packet_status_flag=0,
                        iso_sdu_length=len(sdu),
                        iso_sdu_fragment=iso_sdu_fragment,
                    )
                    if is_first_fragment
                    else hci.HCI_IsoDataPacket(
                        connection_handle=connection_handle,
                        data_total_length=fragment_length,
                        pb_flag=0b11 if is_last_fragment else 0b01,
                        iso_sdu_fragment=iso_sdu_fragment,
                    )
                ),
                connection_handle,
            )

            offset += fragment_length
            bytes_remaining -= fragment_length

        iso_link.packet_sequence_number = (iso_link.packet_sequence_number + 1) & 0xFFFF

    def remove_big(self, big_handle: int) -> None:
        if big := self.bigs.pop(big_handle, None):
            for connection_handle in big:
                if bis_link := self.bis_links.pop(connection_handle, None):
                    bis_link.packet_queue.flush(bis_link.handle)

    def supports_command(self, op_code: int) -> bool:
        return (
            self.local_supported_commands
            & hci.HCI_SUPPORTED_COMMANDS_MASKS.get(op_code, 0)
        ) != 0

    @property
    def supported_commands(self) -> Set[int]:
        return set(
            op_code
            for op_code, mask in hci.HCI_SUPPORTED_COMMANDS_MASKS.items()
            if self.local_supported_commands & mask
        )

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
        try:
            hci_packet = hci.HCI_Packet.from_bytes(packet)
        except Exception as error:
            logger.warning(f'!!! error parsing packet from bytes: {error}')
            return

        if self.ready or (
            isinstance(hci_packet, hci.HCI_Command_Complete_Event)
            and hci_packet.command_opcode == hci.HCI_RESET_COMMAND
        ):
            self.on_hci_packet(hci_packet)
        else:
            logger.debug(
                f'reset not done, ignoring packet from controller: {hci_packet}'
            )

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

    def on_hci_number_of_completed_packets_event(
        self, event: hci.HCI_Number_Of_Completed_Packets_Event
    ) -> None:
        for connection_handle, num_completed_packets in zip(
            event.connection_handles, event.num_completed_packets
        ):
            if queue := self.get_data_packet_queue(connection_handle):
                queue.on_packets_completed(num_completed_packets, connection_handle)
                continue

            if connection_handle not in self.sco_links:
                logger.warning(
                    'received packet completion event for unknown handle '
                    f'0x{connection_handle:04X}'
                )

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
                    PhysicalTransport.LE,
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
                PhysicalTransport.LE,
                event.peer_address,
                getattr(event, 'local_resolvable_private_address', None),
                getattr(event, 'peer_resolvable_private_address', None),
                hci.Role(event.role),
                connection_parameters,
            )
        else:
            logger.debug(f'### CONNECTION FAILED: {event.status}')

            # Notify the listeners
            self.emit(
                'connection_failure',
                PhysicalTransport.LE,
                event.peer_address,
                event.status,
            )

    def on_hci_le_enhanced_connection_complete_event(self, event):
        # Just use the same implementation as for the non-enhanced event for now
        self.on_hci_le_connection_complete_event(event)

    def on_hci_le_enhanced_connection_complete_v2_event(self, event):
        # Just use the same implementation as for the v1 event for now
        self.on_hci_le_enhanced_connection_complete_event(event)

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
                    PhysicalTransport.BR_EDR,
                )
                self.connections[event.connection_handle] = connection

            # Notify the client
            self.emit(
                'connection',
                event.connection_handle,
                PhysicalTransport.BR_EDR,
                event.bd_addr,
                None,
                None,
                None,
                None,
            )
        else:
            logger.debug(f'### BR/EDR CONNECTION FAILED: {event.status}')

            # Notify the client
            self.emit(
                'connection_failure',
                PhysicalTransport.BR_EDR,
                event.bd_addr,
                event.status,
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
            logger.debug(f'### DISCONNECTION: {connection}, reason={event.reason}')

            # Notify the listeners
            self.emit('disconnection', handle, event.reason)

            # Remove the handle reference
            _ = (
                self.connections.pop(handle, 0)
                or self.cis_links.pop(handle, 0)
                or self.sco_links.pop(handle, 0)
            )

            # Flush the data queues
            if self.acl_packet_queue:
                self.acl_packet_queue.flush(handle)
            if self.le_acl_packet_queue:
                self.le_acl_packet_queue.flush(handle)
            if self.iso_packet_queue:
                self.iso_packet_queue.flush(handle)
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
            self.emit(
                'connection_phy_update',
                connection.handle,
                ConnectionPHY(event.tx_phy, event.rx_phy),
            )
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

    def on_hci_le_periodic_advertising_sync_established_event(self, event):
        self.emit(
            'periodic_advertising_sync_establishment',
            event.status,
            event.sync_handle,
            event.advertising_sid,
            event.advertiser_address,
            event.advertiser_phy,
            event.periodic_advertising_interval,
            event.advertiser_clock_accuracy,
        )

    def on_hci_le_periodic_advertising_sync_lost_event(self, event):
        self.emit('periodic_advertising_sync_loss', event.sync_handle)

    def on_hci_le_periodic_advertising_report_event(self, event):
        self.emit('periodic_advertising_report', event.sync_handle, event)

    def on_hci_le_biginfo_advertising_report_event(self, event):
        self.emit('biginfo_advertising_report', event.sync_handle, event)

    def on_hci_le_cis_request_event(self, event):
        self.emit(
            'cis_request',
            event.acl_connection_handle,
            event.cis_connection_handle,
            event.cig_id,
            event.cis_id,
        )

    def on_hci_le_create_big_complete_event(self, event):
        self.bigs[event.big_handle] = set(event.connection_handle)
        if self.iso_packet_queue is None:
            logger.warning("BIS established but ISO packets not supported")

        for connection_handle in event.connection_handle:
            self.bis_links[connection_handle] = IsoLink(
                connection_handle, self.iso_packet_queue
            )

        self.emit(
            'big_establishment',
            event.status,
            event.big_handle,
            event.connection_handle,
            event.big_sync_delay,
            event.transport_latency_big,
            event.phy,
            event.nse,
            event.bn,
            event.pto,
            event.irc,
            event.max_pdu,
            event.iso_interval,
        )

    def on_hci_le_big_sync_established_event(self, event):
        self.bigs[event.big_handle] = set(event.connection_handle)
        for connection_handle in event.connection_handle:
            self.bis_links[connection_handle] = IsoLink(
                connection_handle, self.iso_packet_queue
            )

        self.emit(
            'big_sync_establishment',
            event.status,
            event.big_handle,
            event.transport_latency_big,
            event.nse,
            event.bn,
            event.pto,
            event.irc,
            event.max_pdu,
            event.iso_interval,
            event.connection_handle,
        )

    def on_hci_le_big_sync_lost_event(self, event):
        self.remove_big(event.big_handle)
        self.emit('big_sync_lost', event.big_handle, event.reason)

    def on_hci_le_terminate_big_complete_event(self, event):
        self.remove_big(event.big_handle)
        self.emit('big_termination', event.reason, event.big_handle)

    def on_hci_le_periodic_advertising_sync_transfer_received_event(self, event):
        self.emit(
            'periodic_advertising_sync_transfer',
            event.status,
            event.connection_handle,
            event.sync_handle,
            event.advertising_sid,
            event.advertiser_address,
            event.advertiser_phy,
            event.periodic_advertising_interval,
            event.advertiser_clock_accuracy,
        )

    def on_hci_le_periodic_advertising_sync_transfer_received_v2_event(self, event):
        self.emit(
            'periodic_advertising_sync_transfer',
            event.status,
            event.connection_handle,
            event.sync_handle,
            event.advertising_sid,
            event.advertiser_address,
            event.advertiser_phy,
            event.periodic_advertising_interval,
            event.advertiser_clock_accuracy,
        )

    def on_hci_le_cis_established_event(self, event):
        # The remaining parameters are unused for now.
        if event.status == hci.HCI_SUCCESS:
            if self.iso_packet_queue is None:
                logger.warning("CIS established but ISO packets not supported")
            self.cis_links[event.connection_handle] = IsoLink(
                handle=event.connection_handle, packet_queue=self.iso_packet_queue
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
                long_term_key = await utils.cancel_on_event(
                    self,
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
                connection_handle=event.connection_handle,
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
            self.emit('role_change', event.bd_addr, hci.Role(event.new_role))
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

    def on_hci_qos_setup_complete_event(self, event):
        if event.status == hci.HCI_SUCCESS:
            self.emit(
                'connection_qos_setup', event.connection_handle, event.service_type
            )
        else:
            self.emit(
                'connection_qos_setup_failure',
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
                link_key = await utils.cancel_on_event(
                    self,
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

    def on_hci_le_cs_read_remote_supported_capabilities_complete_event(self, event):
        self.emit('cs_remote_supported_capabilities', event)

    def on_hci_le_cs_security_enable_complete_event(self, event):
        self.emit('cs_security', event)

    def on_hci_le_cs_config_complete_event(self, event):
        self.emit('cs_config', event)

    def on_hci_le_cs_procedure_enable_complete_event(self, event):
        self.emit('cs_procedure', event)

    def on_hci_le_cs_subevent_result_event(self, event):
        self.emit('cs_subevent_result', event)

    def on_hci_le_cs_subevent_result_continue_event(self, event):
        self.emit('cs_subevent_result_continue', event)

    def on_hci_vendor_event(self, event):
        self.emit('vendor_event', event)
