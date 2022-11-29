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
import asyncio
import logging
from pyee import EventEmitter
from colors import color

from .hci import *
from .l2cap import *
from .att import *
from .gatt import *
from .smp import *
from .core import ConnectionParameters

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
HOST_DEFAULT_HC_LE_ACL_DATA_PACKET_LENGTH = 27
HOST_HC_TOTAL_NUM_LE_ACL_DATA_PACKETS     = 1
HOST_DEFAULT_HC_ACL_DATA_PACKET_LENGTH    = 27
HOST_HC_TOTAL_NUM_ACL_DATA_PACKETS        = 1


# -----------------------------------------------------------------------------
class Connection:
    def __init__(self, host, handle, role, peer_address, transport):
        self.host                  = host
        self.handle                = handle
        self.role                  = role
        self.peer_address          = peer_address
        self.assembler             = HCI_AclDataPacketAssembler(self.on_acl_pdu)
        self.transport             = transport

    def on_hci_acl_data_packet(self, packet):
        self.assembler.feed_packet(packet)

    def on_acl_pdu(self, pdu):
        l2cap_pdu = L2CAP_PDU.from_bytes(pdu)
        self.host.on_l2cap_pdu(self, l2cap_pdu.cid, l2cap_pdu.payload)


# -----------------------------------------------------------------------------
class Host(EventEmitter):
    def __init__(self, controller_source = None, controller_sink = None):
        super().__init__()

        self.hci_sink                         = None
        self.ready                            = False  # True when we can accept incoming packets
        self.connections                      = {}     # Connections, by connection handle
        self.pending_command                  = None
        self.pending_response                 = None
        self.hc_le_acl_data_packet_length     = HOST_DEFAULT_HC_LE_ACL_DATA_PACKET_LENGTH
        self.hc_total_num_le_acl_data_packets = HOST_HC_TOTAL_NUM_LE_ACL_DATA_PACKETS
        self.hc_acl_data_packet_length        = HOST_DEFAULT_HC_ACL_DATA_PACKET_LENGTH
        self.hc_total_num_acl_data_packets    = HOST_HC_TOTAL_NUM_ACL_DATA_PACKETS
        self.acl_packet_queue                 = collections.deque()
        self.acl_packets_in_flight            = 0
        self.local_version                    = None
        self.local_supported_commands         = bytes(64)
        self.local_le_features                = 0
        self.suggested_max_tx_octets          = 251   # Max allowed
        self.suggested_max_tx_time            = 2120  # Max allowed
        self.command_semaphore                = asyncio.Semaphore(1)
        self.long_term_key_provider           = None
        self.link_key_provider                = None
        self.pairing_io_capability_provider   = None  # Classic only

        # Connect to the source and sink if specified
        if controller_source:
            controller_source.set_packet_sink(self)
        if controller_sink:
            self.set_packet_sink(controller_sink)

    async def reset(self):
        await self.send_command(HCI_Reset_Command(), check_result=True)
        self.ready = True

        response = await self.send_command(HCI_Read_Local_Supported_Commands_Command(), check_result=True)
        self.local_supported_commands = response.return_parameters.supported_commands

        if self.supports_command(HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND):
            response = await self.send_command(HCI_LE_Read_Local_Supported_Features_Command(), check_result=True)
            self.local_le_features = struct.unpack('<Q', response.return_parameters.le_features)[0]

        if self.supports_command(HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND):
            response = await self.send_command(HCI_Read_Local_Version_Information_Command(), check_result=True)
            self.local_version = response.return_parameters

        await self.send_command(HCI_Set_Event_Mask_Command(event_mask = bytes.fromhex('FFFFFFFFFFFFFF3F')))

        if self.local_version is not None and self.local_version.hci_version <= HCI_VERSION_BLUETOOTH_CORE_4_0:
            # Some older controllers don't like event masks with bits they don't understand
            le_event_mask = bytes.fromhex('1F00000000000000')
        else:
            le_event_mask = bytes.fromhex('FFFFF00000000000')
        await self.send_command(HCI_LE_Set_Event_Mask_Command(le_event_mask = le_event_mask))

        if self.supports_command(HCI_READ_BUFFER_SIZE_COMMAND):
            response = await self.send_command(HCI_Read_Buffer_Size_Command(), check_result=True)
            self.hc_acl_data_packet_length     = response.return_parameters.hc_acl_data_packet_length
            self.hc_total_num_acl_data_packets = response.return_parameters.hc_total_num_acl_data_packets

            logger.debug(
                f'HCI ACL flow control: hc_acl_data_packet_length={self.hc_acl_data_packet_length},'
                f'hc_total_num_acl_data_packets={self.hc_total_num_acl_data_packets}'
            )

        if self.supports_command(HCI_LE_READ_BUFFER_SIZE_COMMAND):
            response = await self.send_command(HCI_LE_Read_Buffer_Size_Command(), check_result=True)
            self.hc_le_acl_data_packet_length     = response.return_parameters.hc_le_acl_data_packet_length
            self.hc_total_num_le_acl_data_packets = response.return_parameters.hc_total_num_le_acl_data_packets

            logger.debug(
                f'HCI LE ACL flow control: hc_le_acl_data_packet_length={self.hc_le_acl_data_packet_length},'
                f'hc_total_num_le_acl_data_packets={self.hc_total_num_le_acl_data_packets}'
            )

            if (
                response.return_parameters.hc_le_acl_data_packet_length == 0 or
                response.return_parameters.hc_total_num_le_acl_data_packets == 0
            ):
                # LE and Classic share the same values
                self.hc_le_acl_data_packet_length     = self.hc_acl_data_packet_length
                self.hc_total_num_le_acl_data_packets = self.hc_total_num_acl_data_packets

        if (
            self.supports_command(HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND) and
            self.supports_command(HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND)
        ):
            response = await self.send_command(HCI_LE_Read_Suggested_Default_Data_Length_Command())
            suggested_max_tx_octets = response.return_parameters.suggested_max_tx_octets
            suggested_max_tx_time   = response.return_parameters.suggested_max_tx_time
            if (
                suggested_max_tx_octets != self.suggested_max_tx_octets or
                suggested_max_tx_time != self.suggested_max_tx_time
            ):
                await self.send_command(HCI_LE_Write_Suggested_Default_Data_Length_Command(
                    suggested_max_tx_octets = self.suggested_max_tx_octets,
                    suggested_max_tx_time   = self.suggested_max_tx_time
                ))

        self.reset_done = True

    @property
    def controller(self):
        return self.hci_sink

    @controller.setter
    def controller(self, controller):
        self.set_packet_sink(controller)
        if controller:
            controller.set_packet_sink(self)

    def set_packet_sink(self, sink):
        self.hci_sink = sink

    def send_hci_packet(self, packet):
        self.hci_sink.on_packet(packet.to_bytes())

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
                    if type(response.return_parameters) is int:
                        status = response.return_parameters
                    elif type(response.return_parameters) is bytes:
                        # return parameters first field is a one byte status code
                        status = response.return_parameters[0]
                    else:
                        status = response.return_parameters.status

                    if status != HCI_SUCCESS:
                        logger.warning(f'{command.name} failed ({HCI_Constant.error_name(status)})')
                        raise HCI_Error(status)

                return response
            except Exception as error:
                logger.warning(f'{color("!!! Exception while sending HCI packet:", "red")} {error}')
                raise error
            finally:
                self.pending_command = None
                self.pending_response = None

    # Use this method to send a command from a task
    def send_command_sync(self, command):
        async def send_command(command):
            await self.send_command(command)

        asyncio.create_task(send_command(command))

    def send_l2cap_pdu(self, connection_handle, cid, pdu):
        l2cap_pdu = L2CAP_PDU(cid, pdu).to_bytes()

        # Send the data to the controller via ACL packets
        bytes_remaining = len(l2cap_pdu)
        offset = 0
        pb_flag = 0
        while bytes_remaining:
            # TODO: support different LE/Classic lengths
            data_total_length = min(bytes_remaining, self.hc_le_acl_data_packet_length)
            acl_packet = HCI_AclDataPacket(
                connection_handle  = connection_handle,
                pb_flag            = pb_flag,
                bc_flag            = 0,
                data_total_length  = data_total_length,
                data               = l2cap_pdu[offset:offset + data_total_length]
            )
            logger.debug(f'{color("### HOST -> CONTROLLER", "blue")}: (CID={cid}) {acl_packet}')
            self.queue_acl_packet(acl_packet)
            pb_flag = 1
            offset += data_total_length
            bytes_remaining -= data_total_length

    def queue_acl_packet(self, acl_packet):
        self.acl_packet_queue.appendleft(acl_packet)
        self.check_acl_packet_queue()

        if len(self.acl_packet_queue):
            logger.debug(f'{self.acl_packets_in_flight} ACL packets in flight, {len(self.acl_packet_queue)} in queue')

    def check_acl_packet_queue(self):
        # Send all we can (TODO: support different LE/Classic limits)
        while len(self.acl_packet_queue) > 0 and self.acl_packets_in_flight < self.hc_total_num_le_acl_data_packets:
            packet = self.acl_packet_queue.pop()
            self.send_hci_packet(packet)
            self.acl_packets_in_flight += 1

    def supports_command(self, command):
        # Find the support flag position for this command
        for (octet, flags) in enumerate(HCI_SUPPORTED_COMMANDS_FLAGS):
            for (flag_position, value) in enumerate(flags):
                if value == command:
                    # Check if the flag is set
                    if octet < len(self.local_supported_commands) and flag_position < 8:
                        return (self.local_supported_commands[octet] & (1 << flag_position)) != 0

        return False

    @property
    def supported_commands(self):
        commands = []
        for (octet, flags) in enumerate(self.local_supported_commands):
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
        return [feature for feature in range(64) if self.local_le_features & (1 << feature)]

    # Packet Sink protocol (packets coming from the controller via HCI)
    def on_packet(self, packet):
        hci_packet = HCI_Packet.from_bytes(packet)
        if self.ready or (
            hci_packet.hci_packet_type == HCI_EVENT_PACKET and
            hci_packet.event_code == HCI_COMMAND_COMPLETE_EVENT and
            hci_packet.command_opcode == HCI_RESET_COMMAND
        ):
            self.on_hci_packet(hci_packet)
        else:
            logger.debug('reset not done, ignoring packet from controller')

    def on_hci_packet(self, packet):
        logger.debug(f'{color("### CONTROLLER -> HOST", "green")}: {packet}')

        # If the packet is a command, invoke the handler for this packet
        if packet.hci_packet_type == HCI_COMMAND_PACKET:
            self.on_hci_command_packet(packet)
        elif packet.hci_packet_type == HCI_EVENT_PACKET:
            self.on_hci_event_packet(packet)
        elif packet.hci_packet_type == HCI_ACL_DATA_PACKET:
            self.on_hci_acl_data_packet(packet)
        else:
            logger.warning(f'!!! unknown packet type {packet.hci_packet_type}')

    def on_hci_command_packet(self, command):
        logger.warning(f'!!! unexpected command packet: {command}')

    def on_hci_event_packet(self, event):
        handler_name = f'on_{event.name.lower()}'
        handler = getattr(self, handler_name, self.on_hci_event)
        handler(event)

    def on_hci_acl_data_packet(self, packet):
        # Look for the connection to which this data belongs
        if connection := self.connections.get(packet.connection_handle):
            connection.on_hci_acl_data_packet(packet)

    def on_l2cap_pdu(self, connection, cid, pdu):
        self.emit('l2cap_pdu', connection.handle, cid, pdu)

    def on_command_processed(self, event):
        if self.pending_response:
            # Check that it is what we were expecting
            if self.pending_command.op_code != event.command_opcode:
                logger.warning(f'!!! command result mismatch, expected 0x{self.pending_command.op_code:X} but got 0x{event.command_opcode:X}')

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
            # This is used just for the Num_HCI_Command_Packets field, not related to an actual command
            logger.debug('no-command event')
        else:
            return self.on_command_processed(event)

    def on_hci_command_status_event(self, event):
        return self.on_command_processed(event)

    def on_hci_number_of_completed_packets_event(self, event):
        total_packets = sum(event.num_completed_packets)
        if total_packets <= self.acl_packets_in_flight:
            self.acl_packets_in_flight -= total_packets
            self.check_acl_packet_queue()
        else:
            logger.warning(color(f'!!! {total_packets} completed but only {self.acl_packets_in_flight} in flight'))
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
            logger.debug(f'### CONNECTION: [0x{event.connection_handle:04X}] {event.peer_address} as {HCI_Constant.role_name(event.role)}')

            connection = self.connections.get(event.connection_handle)
            if connection is None:
                connection = Connection(self, event.connection_handle, event.role, event.peer_address, BT_LE_TRANSPORT)
                self.connections[event.connection_handle] = connection

            # Notify the client
            connection_parameters = ConnectionParameters(
                event.connection_interval,
                event.peripheral_latency,
                event.supervision_timeout
            )
            self.emit(
                'connection',
                event.connection_handle,
                BT_LE_TRANSPORT,
                event.peer_address,
                None,
                event.role,
                connection_parameters
            )
        else:
            logger.debug(f'### CONNECTION FAILED: {event.status}')

            # Notify the listeners
            self.emit('connection_failure', BT_LE_TRANSPORT, event.peer_address, event.status)

    def on_hci_le_enhanced_connection_complete_event(self, event):
        # Just use the same implementation as for the non-enhanced event for now
        self.on_hci_le_connection_complete_event(event)

    def on_hci_connection_complete_event(self, event):
        if event.status == HCI_SUCCESS:
            # Create/update the connection
            logger.debug(f'### BR/EDR CONNECTION: [0x{event.connection_handle:04X}] {event.bd_addr}')

            connection = self.connections.get(event.connection_handle)
            if connection is None:
                connection = Connection(self, event.connection_handle, BT_CENTRAL_ROLE, event.bd_addr, BT_BR_EDR_TRANSPORT)
                self.connections[event.connection_handle] = connection

            # Notify the client
            self.emit(
                'connection',
                event.connection_handle,
                BT_BR_EDR_TRANSPORT,
                event.bd_addr,
                None,
                BT_CENTRAL_ROLE,
                None
            )
        else:
            logger.debug(f'### BR/EDR CONNECTION FAILED: {event.status}')

            # Notify the client
            self.emit('connection_failure', BT_BR_EDR_TRANSPORT, event.bd_addr, event.status)

    def on_hci_disconnection_complete_event(self, event):
        # Find the connection
        if (connection := self.connections.get(event.connection_handle)) is None:
            logger.warning('!!! DISCONNECTION COMPLETE: unknown handle')
            return

        if event.status == HCI_SUCCESS:
            logger.debug(f'### DISCONNECTION: [0x{event.connection_handle:04X}] {connection.peer_address} as {HCI_Constant.role_name(connection.role)}, reason={event.reason}')
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
                event.supervision_timeout
            )
            self.emit('connection_parameters_update', connection.handle, connection_parameters)
        else:
            self.emit('connection_parameters_update_failure', connection.handle, event.status)

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
                connection_handle = event.connection_handle,
                interval_min      = event.interval_min,
                interval_max      = event.interval_max,
                latency           = event.latency,
                timeout           = event.timeout,
                min_ce_length     = 0,
                max_ce_length     = 0
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
                long_term_key = await self.long_term_key_provider(
                    connection.handle,
                    event.random_number,
                    event.encryption_diversifier
                )
            if long_term_key:
                response = HCI_LE_Long_Term_Key_Request_Reply_Command(
                    connection_handle = event.connection_handle,
                    long_term_key     = long_term_key
                )
            else:
                response = HCI_LE_Long_Term_Key_Request_Negative_Reply_Command(
                    connection_handle = event.connection_handle
                )

            await self.send_command(response)

        asyncio.create_task(send_long_term_key())

    def on_hci_synchronous_connection_complete_event(self, event):
        pass

    def on_hci_synchronous_connection_changed_event(self, event):
        pass

    def on_hci_role_change_event(self, event):
        if event.status == HCI_SUCCESS:
            logger.debug(f'role change for {event.bd_addr}: {HCI_Constant.role_name(event.new_role)}')
            # TODO: lookup the connection and update the role
        else:
            logger.debug(f'role change for {event.bd_addr} failed: {HCI_Constant.error_name(event.status)}')

    def on_hci_le_data_length_change_event(self, event):
        self.emit(
            'connection_data_length_change',
            event.connection_handle,
            event.max_tx_octets,
            event.max_tx_time,
            event.max_rx_octets,
            event.max_rx_time
        )

    def on_hci_authentication_complete_event(self, event):
        # Notify the client
        if event.status == HCI_SUCCESS:
            self.emit('connection_authentication', event.connection_handle)
        else:
            self.emit('connection_authentication_failure', event.connection_handle, event.status)

    def on_hci_encryption_change_event(self, event):
        # Notify the client
        if event.status == HCI_SUCCESS:
            self.emit('connection_encryption_change', event.connection_handle, event.encryption_enabled)
        else:
            self.emit('connection_encryption_failure', event.connection_handle, event.status)

    def on_hci_encryption_key_refresh_complete_event(self, event):
        # Notify the client
        if event.status == HCI_SUCCESS:
            self.emit('connection_encryption_key_refresh', event.connection_handle)
        else:
            self.emit('connection_encryption_key_refresh_failure', event.connection_handle, event.status)

    def on_hci_link_supervision_timeout_changed_event(self, event):
        pass

    def on_hci_max_slots_change_event(self, event):
        pass

    def on_hci_page_scan_repetition_mode_change_event(self, event):
        pass

    def on_hci_link_key_notification_event(self, event):
        logger.debug(f'link key for {event.bd_addr}: {event.link_key.hex()}, type={HCI_Constant.link_key_type_name(event.key_type)}')
        self.emit('link_key', event.bd_addr, event.link_key, event.key_type)

    def on_hci_simple_pairing_complete_event(self, event):
        logger.debug(f'simple pairing complete for {event.bd_addr}: status={HCI_Constant.status_name(event.status)}')
        # Notify the client
        if event.status == HCI_SUCCESS:
            self.emit('ssp_complete', event.bd_addr)

    def on_hci_pin_code_request_event(self, event):
        # For now, just refuse all requests
        # TODO: delegate the decision
        self.send_command_sync(
            HCI_PIN_Code_Request_Negative_Reply_Command(
                bd_addr = event.bd_addr
            )
        )

    def on_hci_link_key_request_event(self, event):
        async def send_link_key():
            if self.link_key_provider is None:
                logger.debug('no link key provider')
                link_key = None
            else:
                link_key = await self.link_key_provider(event.bd_addr)
            if link_key:
                response = HCI_Link_Key_Request_Reply_Command(
                    bd_addr  = event.bd_addr,
                    link_key = link_key
                )
            else:
                response = HCI_Link_Key_Request_Negative_Reply_Command(
                    bd_addr = event.bd_addr
                )

            await self.send_command(response)

        asyncio.create_task(send_link_key())

    def on_hci_io_capability_request_event(self, event):
        self.emit('authentication_io_capability_request', event.bd_addr)

    def on_hci_io_capability_response_event(self, event):
        pass

    def on_hci_user_confirmation_request_event(self, event):
        self.emit('authentication_user_confirmation_request', event.bd_addr, event.numeric_value)

    def on_hci_user_passkey_request_event(self, event):
        self.emit('authentication_user_passkey_request', event.bd_addr)

    def on_hci_user_passkey_notification_event(self, event):
        self.emit('authentication_user_passkey_notification', event.bd_addr, event.passkey)

    def on_hci_inquiry_complete_event(self, event):
        self.emit('inquiry_complete')

    def on_hci_inquiry_result_with_rssi_event(self, event):
        for response in event.responses:
            self.emit(
                'inquiry_result',
                response.bd_addr,
                response.class_of_device,
                b'',
                response.rssi
            )

    def on_hci_extended_inquiry_result_event(self, event):
        self.emit(
            'inquiry_result',
            event.bd_addr,
            event.class_of_device,
            event.extended_inquiry_response,
            event.rssi
        )

    def on_hci_remote_name_request_complete_event(self, event):
        if event.status != HCI_SUCCESS:
            self.emit('remote_name_failure', event.bd_addr, event.status)
        else:
            self.emit('remote_name', event.bd_addr, event.remote_name)

    def on_hci_remote_host_supported_features_notification_event(self, event):
        self.emit('remote_host_supported_features', event.bd_addr, event.host_supported_features)
