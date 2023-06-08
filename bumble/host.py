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
import logging
import struct

from typing import Optional, TYPE_CHECKING, Dict, Callable, Awaitable, cast

from bumble.colors import color
from bumble.l2cap import L2CAP_PDU
from bumble.snoop import Snooper
from bumble import drivers

from .hci import (
    Address,
    HCI_ACL_DATA_PACKET,
    HCI_COMMAND_PACKET,
    HCI_COMMAND_COMPLETE_EVENT,
    HCI_EVENT_PACKET,
    HCI_LE_READ_BUFFER_SIZE_COMMAND,
    HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
    HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
    HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
    HCI_READ_BUFFER_SIZE_COMMAND,
    HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND,
    HCI_RESET_COMMAND,
    HCI_SUCCESS,
    HCI_SUPPORTED_COMMANDS_FLAGS,
    HCI_SYNCHRONOUS_DATA_PACKET,
    HCI_VERSION_BLUETOOTH_CORE_4_0,
    HCI_AclDataPacket,
    HCI_AclDataPacketAssembler,
    HCI_Command,
    HCI_Command_Complete_Event,
    HCI_Constant,
    HCI_Error,
    HCI_Event,
    HCI_LE_Long_Term_Key_Request_Negative_Reply_Command,
    HCI_LE_Long_Term_Key_Request_Reply_Command,
    HCI_LE_Read_Buffer_Size_Command,
    HCI_LE_Read_Local_Supported_Features_Command,
    HCI_LE_Read_Suggested_Default_Data_Length_Command,
    HCI_LE_Remote_Connection_Parameter_Request_Reply_Command,
    HCI_LE_Set_Event_Mask_Command,
    HCI_LE_Write_Suggested_Default_Data_Length_Command,
    HCI_Link_Key_Request_Negative_Reply_Command,
    HCI_Link_Key_Request_Reply_Command,
    HCI_Packet,
    HCI_Read_Buffer_Size_Command,
    HCI_Read_Local_Supported_Commands_Command,
    HCI_Read_Local_Version_Information_Command,
    HCI_Reset_Command,
    HCI_Set_Event_Mask_Command,
    HCI_SynchronousDataPacket,
)
from .core import (
    BT_BR_EDR_TRANSPORT,
    BT_LE_TRANSPORT,
    ConnectionPHY,
    ConnectionParameters,
    InvalidStateError,
)
from .utils import AbortableEventEmitter
from .transport.common import TransportLostError

if TYPE_CHECKING:
    from .transport.common import TransportSink, TransportSource


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off

HOST_DEFAULT_HC_LE_ACL_DATA_PACKET_LENGTH = 27
HOST_HC_TOTAL_NUM_LE_ACL_DATA_PACKETS     = 1
HOST_DEFAULT_HC_ACL_DATA_PACKET_LENGTH    = 27
HOST_HC_TOTAL_NUM_ACL_DATA_PACKETS        = 1

# fmt: on


# -----------------------------------------------------------------------------
class Connection:
    def __init__(self, host: Host, handle: int, peer_address: Address, transport: int):
        self.host = host
        self.handle = handle
        self.peer_address = peer_address
        self.assembler = HCI_AclDataPacketAssembler(self.on_acl_pdu)
        self.transport = transport

    def on_hci_acl_data_packet(self, packet: HCI_AclDataPacket) -> None:
        self.assembler.feed_packet(packet)

    def on_acl_pdu(self, pdu: bytes) -> None:
        l2cap_pdu = L2CAP_PDU.from_bytes(pdu)
        self.host.on_l2cap_pdu(self, l2cap_pdu.cid, l2cap_pdu.payload)


# -----------------------------------------------------------------------------
class Host(AbortableEventEmitter):
    connections: Dict[int, Connection]
    acl_packet_queue: collections.deque[HCI_AclDataPacket]
    hci_sink: TransportSink
    long_term_key_provider: Optional[
        Callable[[int, bytes, int], Awaitable[Optional[bytes]]]
    ]
    link_key_provider: Optional[Callable[[Address], Awaitable[Optional[bytes]]]]

    def __init__(
        self,
        controller_source: Optional[TransportSource] = None,
        controller_sink: Optional[TransportSink] = None,
    ) -> None:
        super().__init__()

        self.hci_metadata = None
        self.ready = False  # True when we can accept incoming packets
        self.reset_done = False
        self.connections = {}  # Connections, by connection handle
        self.pending_command = None
        self.pending_response = None
        self.hc_le_acl_data_packet_length = HOST_DEFAULT_HC_LE_ACL_DATA_PACKET_LENGTH
        self.hc_total_num_le_acl_data_packets = HOST_HC_TOTAL_NUM_LE_ACL_DATA_PACKETS
        self.hc_acl_data_packet_length = HOST_DEFAULT_HC_ACL_DATA_PACKET_LENGTH
        self.hc_total_num_acl_data_packets = HOST_HC_TOTAL_NUM_ACL_DATA_PACKETS
        self.acl_packet_queue = collections.deque()
        self.acl_packets_in_flight = 0
        self.local_version = None
        self.local_supported_commands = bytes(64)
        self.local_le_features = 0
        self.suggested_max_tx_octets = 251  # Max allowed
        self.suggested_max_tx_time = 2120  # Max allowed
        self.command_semaphore = asyncio.Semaphore(1)
        self.long_term_key_provider = None
        self.link_key_provider = None
        self.pairing_io_capability_provider = None  # Classic only
        self.snooper = None

        # Connect to the source and sink if specified
        if controller_source:
            controller_source.set_packet_sink(self)
            self.hci_metadata = getattr(
                controller_source, 'metadata', self.hci_metadata
            )
        if controller_sink:
            self.set_packet_sink(controller_sink)

    def find_connection_by_bd_addr(
        self,
        bd_addr: Address,
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

        await self.send_command(HCI_Reset_Command(), check_result=True)
        self.ready = True

        # Instantiate and init a driver for the host if needed.
        # NOTE: we don't keep a reference to the driver here, because we don't
        # currently have a need for the driver later on. But if the driver interface
        # evolves, it may be required, then, to store a reference to the driver in
        # an object property.
        if driver_factory is not None:
            if driver := await driver_factory(self):
                await driver.init_controller()

        response = await self.send_command(
            HCI_Read_Local_Supported_Commands_Command(), check_result=True
        )
        self.local_supported_commands = response.return_parameters.supported_commands

        if self.supports_command(HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND):
            response = await self.send_command(
                HCI_LE_Read_Local_Supported_Features_Command(), check_result=True
            )
            self.local_le_features = struct.unpack(
                '<Q', response.return_parameters.le_features
            )[0]

        if self.supports_command(HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND):
            response = await self.send_command(
                HCI_Read_Local_Version_Information_Command(), check_result=True
            )
            self.local_version = response.return_parameters

        await self.send_command(
            HCI_Set_Event_Mask_Command(event_mask=bytes.fromhex('FFFFFFFFFFFFFF3F'))
        )

        if (
            self.local_version is not None
            and self.local_version.hci_version <= HCI_VERSION_BLUETOOTH_CORE_4_0
        ):
            # Some older controllers don't like event masks with bits they don't
            # understand
            le_event_mask = bytes.fromhex('1F00000000000000')
        else:
            le_event_mask = bytes.fromhex('FFFFF00000000000')

        await self.send_command(
            HCI_LE_Set_Event_Mask_Command(le_event_mask=le_event_mask)
        )

        if self.supports_command(HCI_READ_BUFFER_SIZE_COMMAND):
            response = await self.send_command(
                HCI_Read_Buffer_Size_Command(), check_result=True
            )
            self.hc_acl_data_packet_length = (
                response.return_parameters.hc_acl_data_packet_length
            )
            self.hc_total_num_acl_data_packets = (
                response.return_parameters.hc_total_num_acl_data_packets
            )

            logger.debug(
                'HCI ACL flow control: '
                f'hc_acl_data_packet_length={self.hc_acl_data_packet_length},'
                f'hc_total_num_acl_data_packets={self.hc_total_num_acl_data_packets}'
            )

        if self.supports_command(HCI_LE_READ_BUFFER_SIZE_COMMAND):
            response = await self.send_command(
                HCI_LE_Read_Buffer_Size_Command(), check_result=True
            )
            self.hc_le_acl_data_packet_length = (
                response.return_parameters.hc_le_acl_data_packet_length
            )
            self.hc_total_num_le_acl_data_packets = (
                response.return_parameters.hc_total_num_le_acl_data_packets
            )

            logger.debug(
                'HCI LE ACL flow control: '
                f'hc_le_acl_data_packet_length={self.hc_le_acl_data_packet_length},'
                'hc_total_num_le_acl_data_packets='
                f'{self.hc_total_num_le_acl_data_packets}'
            )

            if (
                response.return_parameters.hc_le_acl_data_packet_length == 0
                or response.return_parameters.hc_total_num_le_acl_data_packets == 0
            ):
                # LE and Classic share the same values
                self.hc_le_acl_data_packet_length = self.hc_acl_data_packet_length
                self.hc_total_num_le_acl_data_packets = (
                    self.hc_total_num_acl_data_packets
                )

        if self.supports_command(
            HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND
        ) and self.supports_command(HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND):
            response = await self.send_command(
                HCI_LE_Read_Suggested_Default_Data_Length_Command()
            )
            suggested_max_tx_octets = response.return_parameters.suggested_max_tx_octets
            suggested_max_tx_time = response.return_parameters.suggested_max_tx_time
            if (
                suggested_max_tx_octets != self.suggested_max_tx_octets
                or suggested_max_tx_time != self.suggested_max_tx_time
            ):
                await self.send_command(
                    HCI_LE_Write_Suggested_Default_Data_Length_Command(
                        suggested_max_tx_octets=self.suggested_max_tx_octets,
                        suggested_max_tx_time=self.suggested_max_tx_time,
                    )
                )

        self.reset_done = True

    @property
    def controller(self) -> TransportSink:
        return self.hci_sink

    @controller.setter
    def controller(self, controller):
        self.set_packet_sink(controller)
        if controller:
            controller.set_packet_sink(self)

    def set_packet_sink(self, sink: TransportSink) -> None:
        self.hci_sink = sink

    def send_hci_packet(self, packet: HCI_Packet) -> None:
        if self.snooper:
            self.snooper.snoop(bytes(packet), Snooper.Direction.HOST_TO_CONTROLLER)
        self.hci_sink.on_packet(bytes(packet))

    async def send_command(self, command, check_result=False):
        logger.debug(f'{color("### HOST -> CONTROLLER", "blue")}: {command}')

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

                    if status != HCI_SUCCESS:
                        logger.warning(
                            f'{command.name} failed ({HCI_Constant.error_name(status)})'
                        )
                        raise HCI_Error(status)

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
    def send_command_sync(self, command: HCI_Command) -> None:
        async def send_command(command: HCI_Command) -> None:
            await self.send_command(command)

        asyncio.create_task(send_command(command))

    def send_l2cap_pdu(self, connection_handle: int, cid: int, pdu: bytes) -> None:
        l2cap_pdu = bytes(L2CAP_PDU(cid, pdu))

        # Send the data to the controller via ACL packets
        bytes_remaining = len(l2cap_pdu)
        offset = 0
        pb_flag = 0
        while bytes_remaining:
            # TODO: support different LE/Classic lengths
            data_total_length = min(bytes_remaining, self.hc_le_acl_data_packet_length)
            acl_packet = HCI_AclDataPacket(
                connection_handle=connection_handle,
                pb_flag=pb_flag,
                bc_flag=0,
                data_total_length=data_total_length,
                data=l2cap_pdu[offset : offset + data_total_length],
            )
            logger.debug(
                f'{color("### HOST -> CONTROLLER", "blue")}: (CID={cid}) {acl_packet}'
            )
            self.queue_acl_packet(acl_packet)
            pb_flag = 1
            offset += data_total_length
            bytes_remaining -= data_total_length

    def queue_acl_packet(self, acl_packet: HCI_AclDataPacket) -> None:
        self.acl_packet_queue.appendleft(acl_packet)
        self.check_acl_packet_queue()

        if len(self.acl_packet_queue):
            logger.debug(
                f'{self.acl_packets_in_flight} ACL packets in flight, '
                f'{len(self.acl_packet_queue)} in queue'
            )

    def check_acl_packet_queue(self) -> None:
        # Send all we can (TODO: support different LE/Classic limits)
        while (
            len(self.acl_packet_queue) > 0
            and self.acl_packets_in_flight < self.hc_total_num_le_acl_data_packets
        ):
            packet = self.acl_packet_queue.pop()
            self.send_hci_packet(packet)
            self.acl_packets_in_flight += 1

    def supports_command(self, command):
        # Find the support flag position for this command
        for octet, flags in enumerate(HCI_SUPPORTED_COMMANDS_FLAGS):
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
            if octet < len(HCI_SUPPORTED_COMMANDS_FLAGS):
                for flag in range(8):
                    if flags & (1 << flag) != 0:
                        command = HCI_SUPPORTED_COMMANDS_FLAGS[octet][flag]
                        if command is not None:
                            commands.append(command)

        return commands

    def supports_le_feature(self, feature):
        return (self.local_le_features & (1 << feature)) != 0

    @property
    def supported_le_features(self):
        return [
            feature for feature in range(64) if self.local_le_features & (1 << feature)
        ]

    # Packet Sink protocol (packets coming from the controller via HCI)
    def on_packet(self, packet: bytes) -> None:
        hci_packet = HCI_Packet.from_bytes(packet)
        if self.ready or (
            isinstance(hci_packet, HCI_Command_Complete_Event)
            and hci_packet.command_opcode == HCI_RESET_COMMAND
        ):
            self.on_hci_packet(hci_packet)
        else:
            logger.debug('reset not done, ignoring packet from controller')

    def on_transport_lost(self):
        # Called by the source when the transport has been lost.
        if self.pending_response:
            self.pending_response.set_exception(TransportLostError('transport lost'))

        self.emit('flush')

    def on_hci_packet(self, packet: HCI_Packet) -> None:
        logger.debug(f'{color("### CONTROLLER -> HOST", "green")}: {packet}')

        if self.snooper:
            self.snooper.snoop(bytes(packet), Snooper.Direction.CONTROLLER_TO_HOST)

        # If the packet is a command, invoke the handler for this packet
        if packet.hci_packet_type == HCI_COMMAND_PACKET:
            self.on_hci_command_packet(cast(HCI_Command, packet))
        elif packet.hci_packet_type == HCI_EVENT_PACKET:
            self.on_hci_event_packet(cast(HCI_Event, packet))
        elif packet.hci_packet_type == HCI_ACL_DATA_PACKET:
            self.on_hci_acl_data_packet(cast(HCI_AclDataPacket, packet))
        elif packet.hci_packet_type == HCI_SYNCHRONOUS_DATA_PACKET:
            self.on_hci_sco_data_packet(cast(HCI_SynchronousDataPacket, packet))
        else:
            logger.warning(f'!!! unknown packet type {packet.hci_packet_type}')

    def on_hci_command_packet(self, command: HCI_Command) -> None:
        logger.warning(f'!!! unexpected command packet: {command}')

    def on_hci_event_packet(self, event: HCI_Event) -> None:
        handler_name = f'on_{event.name.lower()}'
        handler = getattr(self, handler_name, self.on_hci_event)
        handler(event)

    def on_hci_acl_data_packet(self, packet: HCI_AclDataPacket) -> None:
        # Look for the connection to which this data belongs
        if connection := self.connections.get(packet.connection_handle):
            connection.on_hci_acl_data_packet(packet)

    def on_hci_sco_data_packet(self, packet: HCI_SynchronousDataPacket) -> None:
        # Experimental
        self.emit('sco_packet', packet.connection_handle, packet)

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
            return None

        return self.on_command_processed(event)

    def on_hci_command_status_event(self, event):
        return self.on_command_processed(event)

    def on_hci_number_of_completed_packets_event(self, event):
        total_packets = sum(event.num_completed_packets)
        if total_packets <= self.acl_packets_in_flight:
            self.acl_packets_in_flight -= total_packets
            self.check_acl_packet_queue()
        else:
            logger.warning(
                color(
                    '!!! {total_packets} completed but only '
                    f'{self.acl_packets_in_flight} in flight'
                )
            )
            self.acl_packets_in_flight = 0

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
        if event.status == HCI_SUCCESS:
            # Create/update the connection
            logger.debug(
                f'### LE CONNECTION: [0x{event.connection_handle:04X}] '
                f'{event.peer_address} as {HCI_Constant.role_name(event.role)}'
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
        if event.status == HCI_SUCCESS:
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
        if (connection := self.connections.get(event.connection_handle)) is None:
            logger.warning('!!! DISCONNECTION COMPLETE: unknown handle')
            return

        if event.status == HCI_SUCCESS:
            logger.debug(
                f'### DISCONNECTION: [0x{event.connection_handle:04X}] '
                f'{connection.peer_address} '
                f'reason={event.reason}'
            )
            del self.connections[event.connection_handle]

            # Notify the listeners
            self.emit('disconnection', event.connection_handle, event.reason)
        else:
            logger.debug(f'### DISCONNECTION FAILED: {event.status}')

            # Notify the listeners
            self.emit('disconnection_failure', event.connection_handle, event.status)

    def on_hci_le_connection_update_complete_event(self, event):
        if (connection := self.connections.get(event.connection_handle)) is None:
            logger.warning('!!! CONNECTION PARAMETERS UPDATE COMPLETE: unknown handle')
            return

        # Notify the client
        if event.status == HCI_SUCCESS:
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
        if event.status == HCI_SUCCESS:
            connection_phy = ConnectionPHY(event.tx_phy, event.rx_phy)
            self.emit('connection_phy_update', connection.handle, connection_phy)
        else:
            self.emit('connection_phy_update_failure', connection.handle, event.status)

    def on_hci_le_advertising_report_event(self, event):
        for report in event.reports:
            self.emit('advertising_report', report)

    def on_hci_le_extended_advertising_report_event(self, event):
        self.on_hci_le_advertising_report_event(event)

    def on_hci_le_remote_connection_parameter_request_event(self, event):
        if event.connection_handle not in self.connections:
            logger.warning('!!! REMOTE CONNECTION PARAMETER REQUEST: unknown handle')
            return

        # For now, just accept everything
        # TODO: delegate the decision
        self.send_command_sync(
            HCI_LE_Remote_Connection_Parameter_Request_Reply_Command(
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
                response = HCI_LE_Long_Term_Key_Request_Reply_Command(
                    connection_handle=event.connection_handle,
                    long_term_key=long_term_key,
                )
            else:
                response = HCI_LE_Long_Term_Key_Request_Negative_Reply_Command(
                    connection_handle=event.connection_handle
                )

            await self.send_command(response)

        asyncio.create_task(send_long_term_key())

    def on_hci_synchronous_connection_complete_event(self, event):
        if event.status == HCI_SUCCESS:
            # Create/update the connection
            logger.debug(
                f'### SCO CONNECTION: [0x{event.connection_handle:04X}] '
                f'{event.bd_addr}'
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
        if event.status == HCI_SUCCESS:
            logger.debug(
                f'role change for {event.bd_addr}: '
                f'{HCI_Constant.role_name(event.new_role)}'
            )
            self.emit('role_change', event.bd_addr, event.new_role)
        else:
            logger.debug(
                f'role change for {event.bd_addr} failed: '
                f'{HCI_Constant.error_name(event.status)}'
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
        if event.status == HCI_SUCCESS:
            self.emit('connection_authentication', event.connection_handle)
        else:
            self.emit(
                'connection_authentication_failure',
                event.connection_handle,
                event.status,
            )

    def on_hci_encryption_change_event(self, event):
        # Notify the client
        if event.status == HCI_SUCCESS:
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
        if event.status == HCI_SUCCESS:
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
            f'type={HCI_Constant.link_key_type_name(event.key_type)}'
        )
        self.emit('link_key', event.bd_addr, event.link_key, event.key_type)

    def on_hci_simple_pairing_complete_event(self, event):
        logger.debug(
            f'simple pairing complete for {event.bd_addr}: '
            f'status={HCI_Constant.status_name(event.status)}'
        )
        if event.status == HCI_SUCCESS:
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
                response = HCI_Link_Key_Request_Reply_Command(
                    bd_addr=event.bd_addr, link_key=link_key
                )
            else:
                response = HCI_Link_Key_Request_Negative_Reply_Command(
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
        if event.status != HCI_SUCCESS:
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
