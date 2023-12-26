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

import logging
import asyncio
import heapq
import itertools
import random
import struct
import time
from dataclasses import dataclass

from bumble.colors import color
from bumble.core import (
    BT_CENTRAL_ROLE,
    BT_PERIPHERAL_ROLE,
    BT_LE_TRANSPORT,
    BT_BR_EDR_TRANSPORT,
)

from bumble.hci import (
    HCI_ACL_DATA_PACKET,
    HCI_COMMAND_DISALLOWED_ERROR,
    HCI_COMMAND_PACKET,
    HCI_COMMAND_STATUS_PENDING,
    HCI_CONNECTION_PARAMETERS_REQUEST_PROCEDURE_LE_SUPPORTED_FEATURE,
    HCI_CONNECTION_TIMEOUT_ERROR,
    HCI_CONTROLLER_BUSY_ERROR,
    HCI_DISCONNECT_COMMAND,
    HCI_EVENT_PACKET,
    HCI_EXTENDED_REJECT_INDICATION_LE_SUPPORTED_FEATURE,
    HCI_LE_2M_PHY_LE_SUPPORTED_FEATURE,
    HCI_LE_CLEAR_ADVERTISING_SETS_COMMAND,
    HCI_LE_EXTENDED_ADVERTISING_LE_SUPPORTED_FEATURE,
    HCI_HOST_BUFFER_SIZE_COMMAND,
    HCI_HOST_NUMBER_OF_COMPLETED_PACKETS_COMMAND,
    HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR,
    HCI_LE_1M_PHY,
    HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST_COMMAND,
    HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND,
    HCI_LE_CLEAR_FILTER_ACCEPT_LIST_COMMAND,
    HCI_LE_CLEAR_RESOLVING_LIST_COMMAND,
    HCI_LE_CONNECTION_UPDATE_COMMAND,
    HCI_LE_CREATE_CONNECTION_CANCEL_COMMAND,
    HCI_LE_CREATE_CONNECTION_COMMAND,
    HCI_LE_DATA_PACKET_LENGTH_EXTENSION_LE_SUPPORTED_FEATURE,
    HCI_LE_ENABLE_ENCRYPTION_COMMAND,
    HCI_LE_ENCRYPT_COMMAND,
    HCI_LE_ENCRYPTION_LE_SUPPORTED_FEATURE,
    HCI_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY_COMMAND,
    HCI_LE_LONG_TERM_KEY_REQUEST_REPLY_COMMAND,
    HCI_LE_PING_LE_SUPPORTED_FEATURE,
    HCI_LE_RAND_COMMAND,
    HCI_LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER_COMMAND,
    HCI_LE_READ_BUFFER_SIZE_COMMAND,
    HCI_LE_READ_CHANNEL_MAP_COMMAND,
    HCI_LE_READ_FILTER_ACCEPT_LIST_SIZE_COMMAND,
    HCI_LE_READ_LOCAL_RESOLVABLE_ADDRESS_COMMAND,
    HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
    HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND,
    HCI_LE_READ_MAXIMUM_DATA_LENGTH_COMMAND,
    HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND,
    HCI_LE_READ_PEER_RESOLVABLE_ADDRESS_COMMAND,
    HCI_LE_READ_PHY_COMMAND,
    HCI_LE_READ_REMOTE_FEATURES_COMMAND,
    HCI_LE_READ_RESOLVING_LIST_SIZE_COMMAND,
    HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
    HCI_LE_READ_SUPPORTED_STATES_COMMAND,
    HCI_LE_READ_TRANSMIT_POWER_COMMAND,
    HCI_LE_RECEIVER_TEST_COMMAND,
    HCI_LE_RECEIVER_TEST_V2_COMMAND,
    HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY_COMMAND,
    HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY_COMMAND,
    HCI_LE_REMOVE_ADVERTISING_SET_COMMAND,
    HCI_LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST_COMMAND,
    HCI_LE_REMOVE_DEVICE_FROM_RESOLVING_LIST_COMMAND,
    HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE_COMMAND,
    HCI_LE_SET_ADVERTISING_DATA_COMMAND,
    HCI_LE_SET_ADVERTISING_ENABLE_COMMAND,
    HCI_LE_SET_ADVERTISING_PARAMETERS_COMMAND,
    HCI_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_COMMAND,
    HCI_LE_SET_DATA_LENGTH_COMMAND,
    HCI_LE_SET_DEFAULT_PHY_COMMAND,
    HCI_LE_SET_EVENT_MASK_COMMAND,
    HCI_LE_SET_EXTENDED_ADVERTISING_DATA_COMMAND,
    HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE_COMMAND,
    HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_COMMAND,
    HCI_LE_SET_EXTENDED_SCAN_ENABLE_COMMAND,
    HCI_LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND,
    HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA_COMMAND,
    HCI_LE_SET_HOST_CHANNEL_CLASSIFICATION_COMMAND,
    HCI_LE_SET_PHY_COMMAND,
    HCI_LE_SET_PRIVACY_MODE_COMMAND,
    HCI_LE_SET_RANDOM_ADDRESS_COMMAND,
    HCI_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT_COMMAND,
    HCI_LE_SET_SCAN_ENABLE_COMMAND,
    HCI_LE_SET_SCAN_PARAMETERS_COMMAND,
    HCI_LE_SET_SCAN_RESPONSE_DATA_COMMAND,
    HCI_LE_TEST_END_COMMAND,
    HCI_LE_TRANSMITTER_TEST_COMMAND,
    HCI_LE_TRANSMITTER_TEST_V2_COMMAND,
    HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
    HCI_LL_PRIVACY_LE_SUPPORTED_FEATURE,
    HCI_PERIPHERAL_INITIATED_FEATURE_EXCHANGE_LE_SUPPORTED_FEATURE,
    HCI_READ_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND,
    HCI_READ_BD_ADDR_COMMAND,
    HCI_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
    HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND,
    HCI_READ_REMOTE_VERSION_INFORMATION_COMMAND,
    HCI_READ_RSSI_COMMAND,
    HCI_READ_TRANSMIT_POWER_LEVEL_COMMAND,
    HCI_RESET_COMMAND,
    HCI_SET_CONTROLLER_TO_HOST_FLOW_CONTROL_COMMAND,
    HCI_SET_EVENT_MASK_COMMAND,
    HCI_SET_EVENT_MASK_PAGE_2_COMMAND,
    HCI_SUCCESS,
    HCI_SUPPORTED_COMMANDS_FLAGS,
    HCI_UNKNOWN_ADVERTISING_IDENTIFIER_ERROR,
    HCI_UNKNOWN_HCI_COMMAND_ERROR,
    HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
    HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR,
    HCI_MEMORY_CAPACITY_EXCEEDED_ERROR,
    HCI_VERSION_BLUETOOTH_CORE_5_0,
    HCI_WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND,
    Address,
    HCI_AclDataPacket,
    HCI_AclDataPacketAssembler,
    HCI_Command_Complete_Event,
    HCI_Command_Status_Event,
    HCI_Connection_Complete_Event,
    HCI_Connection_Request_Event,
    HCI_Constant,
    HCI_Disconnection_Complete_Event,
    HCI_Encryption_Change_Event,
    HCI_LE_Advertising_Report_Event,
    HCI_LE_Connection_Complete_Event,
    HCI_LE_Extended_Advertising_Report_Event,
    HCI_LE_Read_Remote_Features_Complete_Event,
    HCI_Number_Of_Completed_Packets_Event,
    HCI_Packet,
    HCI_Role_Change_Event,
    HCI_Command,
)
from typing import Dict, List, Optional, Sequence, Tuple, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from bumble.transport.common import TransportSink, TransportSource

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
TIMER_TOLERANCE = 0.01  # 10ms


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
class DataObject:
    pass


# -----------------------------------------------------------------------------
def le_supported_features_as_bytes(supported_features: Sequence[int]) -> bytes:
    return struct.pack('<Q', sum((1 << bit for bit in supported_features)))


# -----------------------------------------------------------------------------
def supported_commands_as_bytes(supported_commands: Sequence[HCI_Command]) -> bytes:
    result = [0] * 64

    for command in supported_commands:
        for octet in range(64):
            flags = HCI_SUPPORTED_COMMANDS_FLAGS[octet]
            if command in flags:
                result[octet] |= 1 << flags.index(command)
                break

    return bytes(result)


# -----------------------------------------------------------------------------
class Connection:
    def __init__(self, controller, handle, role, peer_address, link, transport):
        self.controller = controller
        self.handle = handle
        self.role = role
        self.peer_address = peer_address
        self.link = link
        self.assembler = HCI_AclDataPacketAssembler(self.on_acl_pdu)
        self.transport = transport

    def on_hci_acl_data_packet(self, packet):
        self.assembler.feed_packet(packet)
        self.controller.send_hci_packet(
            HCI_Number_Of_Completed_Packets_Event([(self.handle, 1)])
        )

    def on_acl_pdu(self, data):
        self.link.send_acl_data(
            self.controller, self.peer_address, self.transport, data
        )

    def __str__(self):
        return (
            f'Connection[{HCI_Constant.role_name(self.role)}]'
            f'({self.controller.random_address} -> '
            f'{self.peer_address})'
        )


# -----------------------------------------------------------------------------
@dataclass
class Options:
    extended_advertising: bool = False


# -----------------------------------------------------------------------------
class Advertiser:
    enabled: bool = False

    def send_advertising_data(self, controller: Controller):
        pass


# -----------------------------------------------------------------------------
class LegacyAdvertiser(Advertiser):
    def __init__(self, parameters, address):
        self.address = address
        self.parameters = parameters
        self.data = b''
        self.scan_response_data = b''

    def send_advertising_data(self, controller: Controller):
        if self.parameters is None or not self.enabled:
            return

        controller.link.send_advertising_data(
            self.address, self.data, self.scan_response_data
        )

        next_advertising_time = (
            time.time() + self.parameters.advertising_interval_min / 625.0
        )
        controller.schedule_advertiser(self, next_advertising_time)


# -----------------------------------------------------------------------------
class ExtendedAdvertiser(Advertiser):
    def __init__(self, parameters, address):
        self.parameters = parameters
        self.address = address
        self.data = b''
        self.scan_response_data = b''
        self.max_extended_advertising_events = 0
        self.extended_advertising_events = 0
        self.duration = 0
        self.first_advertising_time = 0.0
        self.expired = False

    @property
    def tx_power(self):
        return (
            0
            if self.parameters.advertising_tx_power == 0x7F
            else self.parameters.advertising_tx_power
        )

    @property
    def is_connectable(self):
        return self.parameters.advertising_event_properties & (1 << 0) != 0

    @property
    def is_scannable(self):
        return self.parameters.advertising_event_properties & (1 << 1) != 0

    @property
    def is_directed(self):
        return self.parameters.advertising_event_properties & (1 << 2) != 0

    @property
    def is_high_duty_cycle_directed(self):
        return self.parameters.advertising_event_properties & (1 << 3) != 0

    @property
    def is_legacy(self):
        return self.parameters.advertising_event_properties & (1 << 4) != 0

    @property
    def is_anonymous(self):
        return self.parameters.advertising_event_properties & (1 << 5) != 0

    def send_advertising_data(self, controller: Controller):
        if not self.enabled or self.expired:
            return

        now = time.time()
        if self.extended_advertising_events == 0:
            self.first_advertising_time = now

        if self.duration:
            elapsed = now - self.first_advertising_time
            if elapsed > self.duration / 100.0:
                self.expired = True
                return

        controller.link.send_extended_advertising_data(
            self.address,
            self.parameters.advertising_event_properties,
            self.data,
            self.scan_response_data,
        )

        self.extended_advertising_events += 1
        if (
            self.max_extended_advertising_events > 0
            and self.extended_advertising_events >= self.max_extended_advertising_events
        ):
            self.expired = True
            return

        next_advertising_time = (
            time.time() + self.parameters.primary_advertising_interval_min / 625.0
        )
        controller.schedule_advertiser(self, next_advertising_time)


# -----------------------------------------------------------------------------
class Controller:
    def __init__(
        self,
        name,
        host_source=None,
        host_sink: Optional[TransportSink] = None,
        link=None,
        public_address: Optional[Union[bytes, str, Address]] = None,
        options: Optional[Options] = None,
    ):
        self.name = name
        self.hci_sink = None
        self.link = link
        self.options = options or Options()

        self.le_connections: Dict[Address, Connection] = {}  # BLE Connections
        self.classic_connections: Dict[Address, Connection] = {}  # BR/EDR Connections

        self.hci_version = HCI_VERSION_BLUETOOTH_CORE_5_0
        self.hci_revision = 0
        self.lmp_version = HCI_VERSION_BLUETOOTH_CORE_5_0
        self.lmp_subversion = 0
        self.lmp_features = bytes.fromhex(
            '0000000060000000'
        )  # BR/EDR Not Supported, LE Supported (Controller)
        self.manufacturer_name = 0xFFFF
        self.hc_le_data_packet_length = 27
        self.hc_total_num_le_data_packets = 64
        self.event_mask = 0
        self.event_mask_page_2 = 0
        supported_commands = [
            HCI_DISCONNECT_COMMAND,
            HCI_READ_REMOTE_VERSION_INFORMATION_COMMAND,
            HCI_SET_EVENT_MASK_COMMAND,
            HCI_RESET_COMMAND,
            HCI_READ_TRANSMIT_POWER_LEVEL_COMMAND,
            HCI_SET_CONTROLLER_TO_HOST_FLOW_CONTROL_COMMAND,
            HCI_HOST_BUFFER_SIZE_COMMAND,
            HCI_HOST_NUMBER_OF_COMPLETED_PACKETS_COMMAND,
            HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND,
            HCI_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
            HCI_READ_BD_ADDR_COMMAND,
            HCI_READ_RSSI_COMMAND,
            HCI_SET_EVENT_MASK_PAGE_2_COMMAND,
            HCI_LE_SET_EVENT_MASK_COMMAND,
            HCI_LE_READ_BUFFER_SIZE_COMMAND,
            HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
            HCI_LE_SET_RANDOM_ADDRESS_COMMAND,
            HCI_LE_SET_ADVERTISING_PARAMETERS_COMMAND,
            HCI_LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER_COMMAND,
            HCI_LE_SET_ADVERTISING_DATA_COMMAND,
            HCI_LE_SET_SCAN_RESPONSE_DATA_COMMAND,
            HCI_LE_SET_ADVERTISING_ENABLE_COMMAND,
            HCI_LE_SET_SCAN_PARAMETERS_COMMAND,
            HCI_LE_SET_SCAN_ENABLE_COMMAND,
            HCI_LE_CREATE_CONNECTION_COMMAND,
            HCI_LE_CREATE_CONNECTION_CANCEL_COMMAND,
            HCI_LE_READ_FILTER_ACCEPT_LIST_SIZE_COMMAND,
            HCI_LE_CLEAR_FILTER_ACCEPT_LIST_COMMAND,
            HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST_COMMAND,
            HCI_LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST_COMMAND,
            HCI_LE_CONNECTION_UPDATE_COMMAND,
            HCI_LE_SET_HOST_CHANNEL_CLASSIFICATION_COMMAND,
            HCI_LE_READ_CHANNEL_MAP_COMMAND,
            HCI_LE_READ_REMOTE_FEATURES_COMMAND,
            HCI_LE_ENCRYPT_COMMAND,
            HCI_LE_RAND_COMMAND,
            HCI_LE_ENABLE_ENCRYPTION_COMMAND,
            HCI_LE_LONG_TERM_KEY_REQUEST_REPLY_COMMAND,
            HCI_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY_COMMAND,
            HCI_LE_READ_SUPPORTED_STATES_COMMAND,
            HCI_LE_RECEIVER_TEST_COMMAND,
            HCI_LE_TRANSMITTER_TEST_COMMAND,
            HCI_LE_TEST_END_COMMAND,
            HCI_READ_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND,
            HCI_WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND,
            HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY_COMMAND,
            HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY_COMMAND,
            HCI_LE_SET_DATA_LENGTH_COMMAND,
            HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
            HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
            HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND,
            HCI_LE_REMOVE_DEVICE_FROM_RESOLVING_LIST_COMMAND,
            HCI_LE_CLEAR_RESOLVING_LIST_COMMAND,
            HCI_LE_READ_RESOLVING_LIST_SIZE_COMMAND,
            HCI_LE_READ_PEER_RESOLVABLE_ADDRESS_COMMAND,
            HCI_LE_READ_LOCAL_RESOLVABLE_ADDRESS_COMMAND,
            HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE_COMMAND,
            HCI_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT_COMMAND,
            HCI_LE_READ_MAXIMUM_DATA_LENGTH_COMMAND,
            HCI_LE_READ_PHY_COMMAND,
            HCI_LE_SET_DEFAULT_PHY_COMMAND,
            HCI_LE_SET_PHY_COMMAND,
            HCI_LE_RECEIVER_TEST_V2_COMMAND,
            HCI_LE_TRANSMITTER_TEST_V2_COMMAND,
            HCI_LE_READ_TRANSMIT_POWER_COMMAND,
            HCI_LE_SET_PRIVACY_MODE_COMMAND,
        ]
        if self.options.extended_advertising:
            supported_commands.extend(
                [
                    HCI_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_COMMAND,
                    HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_COMMAND,
                    HCI_LE_SET_EXTENDED_ADVERTISING_DATA_COMMAND,
                    HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA_COMMAND,
                    HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE_COMMAND,
                    HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND,
                    HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND,
                    HCI_LE_REMOVE_ADVERTISING_SET_COMMAND,
                    HCI_LE_CLEAR_ADVERTISING_SETS_COMMAND,
                    HCI_LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND,
                    HCI_LE_SET_EXTENDED_SCAN_ENABLE_COMMAND,
                ]
            )
        self.supported_commands = supported_commands_as_bytes(supported_commands)
        self.le_event_mask = 0
        le_features = [
            HCI_LE_ENCRYPTION_LE_SUPPORTED_FEATURE,
            HCI_CONNECTION_PARAMETERS_REQUEST_PROCEDURE_LE_SUPPORTED_FEATURE,
            HCI_EXTENDED_REJECT_INDICATION_LE_SUPPORTED_FEATURE,
            HCI_PERIPHERAL_INITIATED_FEATURE_EXCHANGE_LE_SUPPORTED_FEATURE,
            HCI_LE_PING_LE_SUPPORTED_FEATURE,
            HCI_LE_DATA_PACKET_LENGTH_EXTENSION_LE_SUPPORTED_FEATURE,
            HCI_LL_PRIVACY_LE_SUPPORTED_FEATURE,
            HCI_LE_2M_PHY_LE_SUPPORTED_FEATURE,
        ]
        if self.options.extended_advertising:
            le_features.append(HCI_LE_EXTENDED_ADVERTISING_LE_SUPPORTED_FEATURE)
        self.le_features = le_supported_features_as_bytes(le_features)
        self.le_states = bytes.fromhex('ffff3fffff030000')
        self.advertising_channel_tx_power = 0
        self.filter_accept_list_size = 8
        self.filter_duplicates = False
        self.resolving_list_size = 8
        self.supported_max_tx_octets = 27
        self.supported_max_tx_time = 10000  # microseconds
        self.supported_max_rx_octets = 27
        self.supported_max_rx_time = 10000  # microseconds
        self.suggested_max_tx_octets = 27
        self.suggested_max_tx_time = 0x0148  # microseconds
        self.default_phy = bytes([0, 0, 0])
        self.le_scan_type = 0
        self.le_scan_interval = 0x10
        self.le_scan_window = 0x10
        self.le_scan_enable = 0
        self.le_scan_own_address_type = Address.RANDOM_DEVICE_ADDRESS
        self.le_scanning_filter_policy = 0
        self.le_address_resolution = False
        self.le_rpa_timeout = 0
        self.le_maximum_advertising_data_length = 0x0672
        self.le_number_of_supported_advertising_sets = 64
        self.sync_flow_control = False
        self.local_name = 'Bumble'

        self._random_address = Address('00:00:00:00:00:00')
        if isinstance(public_address, Address):
            self._public_address = public_address
        elif public_address is not None:
            self._public_address = Address(
                public_address, Address.PUBLIC_DEVICE_ADDRESS
            )
        else:
            self._public_address = Address('00:00:00:00:00:00')

        self.advertising_timer_handle = None
        self.advertising_times: List[Tuple[float, Advertiser]]
        self.legacy_advertiser = LegacyAdvertiser(None, self.random_address)
        self.extended_advertisers: Dict[int, Exception] = {}  # Advertisers, by handle

        # Set the source and sink interfaces
        if host_source:
            host_source.set_packet_sink(self)
        self.host = host_sink

        # Add this controller to the link if specified
        if link:
            link.add_controller(self)

        self.terminated = asyncio.get_running_loop().create_future()

    @property
    def host(self):
        return self.hci_sink

    @host.setter
    def host(self, host):
        '''
        Sets the host (sink) for this controller, and set this controller as the
        controller (sink) for the host
        '''
        self.set_packet_sink(host)
        if host:
            host.controller = self

    def set_packet_sink(self, sink):
        '''
        Method from the Packet Source interface
        '''
        self.hci_sink = sink

    @property
    def public_address(self):
        return self._public_address

    @public_address.setter
    def public_address(self, address):
        if isinstance(address, str):
            address = Address(address)
        self._public_address = address

    @property
    def random_address(self):
        return self._random_address

    @random_address.setter
    def random_address(self, address):
        if isinstance(address, str):
            address = Address(address)
        self._random_address = address
        logger.debug(f'new random address: {address}')

        self.link.on_address_changed(self)

    # Packet Sink protocol (packets coming from the host via HCI)
    def on_packet(self, packet):
        self.on_hci_packet(HCI_Packet.from_bytes(packet))

    def on_hci_packet(self, packet):
        logger.debug(
            f'{color("<<<", "blue")} [{self.name}] '
            f'{color("HOST -> CONTROLLER", "blue")}: {packet}'
        )

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
        handler_name = f'on_{command.name.lower()}'
        handler = getattr(self, handler_name, self.on_hci_command)
        result = handler(command)
        if isinstance(result, bytes):
            self.send_hci_packet(
                HCI_Command_Complete_Event(
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                    return_parameters=result,
                )
            )

    def on_hci_event_packet(self, _event):
        logger.warning('!!! unexpected event packet')

    def on_hci_acl_data_packet(self, packet):
        # Look for the connection to which this data belongs
        connection = self.find_connection_by_handle(packet.connection_handle)
        if connection is None:
            logger.warning(
                f'!!! no connection for handle 0x{packet.connection_handle:04X}'
            )
            return

        # Pass the packet to the connection
        connection.on_hci_acl_data_packet(packet)

    def send_hci_packet(self, packet):
        logger.debug(
            f'{color(">>>", "green")} [{self.name}] '
            f'{color("CONTROLLER -> HOST", "green")}: {packet}'
        )
        if self.host:
            self.host.on_packet(packet.to_bytes())

    # This method allows the controller to emulate the same API as a transport source
    async def wait_for_termination(self):
        await self.terminated

    ############################################################
    # Link connections
    ############################################################
    def allocate_connection_handle(self):
        handle = 0
        max_handle = 0
        for connection in itertools.chain(
            self.le_connections.values(),
            self.classic_connections.values(),
        ):
            max_handle = max(max_handle, connection.handle)
            if connection.handle == handle:
                # Already used, continue searching after the current max
                handle = max_handle + 1
        return handle

    def find_le_connection_by_address(self, address):
        return self.le_connections.get(address)

    def find_classic_connection_by_address(self, address):
        return self.classic_connections.get(address)

    def find_connection_by_handle(self, handle):
        for connection in itertools.chain(
            self.le_connections.values(),
            self.classic_connections.values(),
        ):
            if connection.handle == handle:
                return connection
        return None

    def find_le_connection_by_handle(self, handle):
        for connection in self.le_connections.values():
            if connection.handle == handle:
                return connection
        return None

    def find_classic_connection_by_handle(self, handle):
        for connection in self.classic_connections.values():
            if connection.handle == handle:
                return connection
        return None

    def on_link_central_connected(self, central_address):
        '''
        Called when an incoming connection occurs from a central on the link
        '''

        # Allocate (or reuse) a connection handle
        peer_address = central_address
        peer_address_type = central_address.address_type
        connection = self.le_connections.get(peer_address)
        if connection is None:
            connection_handle = self.allocate_connection_handle()
            connection = Connection(
                self,
                connection_handle,
                BT_PERIPHERAL_ROLE,
                peer_address,
                self.link,
                BT_LE_TRANSPORT,
            )
            self.le_connections[peer_address] = connection
            logger.debug(f'New PERIPHERAL connection handle: 0x{connection_handle:04X}')

        # Then say that the connection has completed
        self.send_hci_packet(
            HCI_LE_Connection_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=connection.handle,
                role=connection.role,
                peer_address_type=peer_address_type,
                peer_address=peer_address,
                connection_interval=10,  # FIXME
                peripheral_latency=0,  # FIXME
                supervision_timeout=10,  # FIXME
                central_clock_accuracy=7,  # FIXME
            )
        )

    def on_link_peer_disconnected(self, peer_address, reason):
        '''
        Called when an active disconnection occurs from a peer
        '''

        # Send a disconnection complete event
        if connection := self.le_connections.get(peer_address):
            self.send_hci_packet(
                HCI_Disconnection_Complete_Event(
                    status=HCI_SUCCESS,
                    connection_handle=connection.handle,
                    reason=reason,
                )
            )

            # Remove the connection
            logger.debug(f'PEER connection removed: {connection}')
            del self.le_connections[peer_address]
        else:
            for address in self.le_connections:
                print(str(address), str(self.le_connections[address]))
            logger.warning(f'!!! No peripheral connection found for {peer_address}')

    def on_link_peripheral_connection_complete(
        self, le_create_connection_command, status
    ):
        '''
        Called by the link when a connection has been made or has failed to be made
        '''

        if status == HCI_SUCCESS:
            # Allocate (or reuse) a connection handle
            peer_address = le_create_connection_command.peer_address
            connection = self.le_connections.get(peer_address)
            if connection is None:
                connection_handle = self.allocate_connection_handle()
                connection = Connection(
                    self,
                    connection_handle,
                    BT_CENTRAL_ROLE,
                    peer_address,
                    self.link,
                    BT_LE_TRANSPORT,
                )
                self.le_connections[peer_address] = connection
                logger.debug(
                    f'New CENTRAL connection handle: 0x{connection_handle:04X}'
                )
        else:
            connection = None

        # Say that the connection has completed
        self.send_hci_packet(
            # pylint: disable=line-too-long
            HCI_LE_Connection_Complete_Event(
                status=status,
                connection_handle=connection.handle if connection else 0,
                role=BT_CENTRAL_ROLE,
                peer_address_type=le_create_connection_command.peer_address_type,
                peer_address=le_create_connection_command.peer_address,
                connection_interval=le_create_connection_command.connection_interval_min,
                peripheral_latency=le_create_connection_command.max_latency,
                supervision_timeout=le_create_connection_command.supervision_timeout,
                central_clock_accuracy=0,
            )
        )

    def on_link_initiated_disconnection_complete(self, disconnection_command, status):
        '''
        Called when a disconnection that we initiated has been completed
        '''

        # Send a disconnection complete event
        self.send_hci_packet(
            HCI_Disconnection_Complete_Event(
                status=status,
                connection_handle=disconnection_command.connection_handle,
                reason=HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR,
            )
        )

        # Remove the connection
        if connection := self.find_le_connection_by_handle(
            disconnection_command.connection_handle
        ):
            logger.debug(f'INITIATOR connection removed: {connection}')
            del self.le_connections[connection.peer_address]

    def on_link_connection_lost(self, peer_address):
        '''
        Called when a connection to a peer is broken
        '''

        # Send a disconnection complete event
        if connection := self.le_connections.get(peer_address):
            self.send_hci_packet(
                HCI_Disconnection_Complete_Event(
                    status=HCI_SUCCESS,
                    connection_handle=connection.handle,
                    reason=HCI_CONNECTION_TIMEOUT_ERROR,
                )
            )

            # Remove the connection
            logger.debug(f'PEER connection lost: {connection}')
            del self.le_connections[peer_address]
        else:
            logger.warning(f'!!! No central connection found for {peer_address}')

    def on_link_encrypted(self, peer_address, _rand, _ediv, _ltk):
        # For now, just setup the encryption without asking the host
        if connection := self.find_le_connection_by_address(peer_address):
            self.send_hci_packet(
                HCI_Encryption_Change_Event(
                    status=0, connection_handle=connection.handle, encryption_enabled=1
                )
            )

    def on_link_acl_data(self, sender_address, transport, data):
        # Look for the connection to which this data belongs
        if transport == BT_LE_TRANSPORT:
            connection = self.find_le_connection_by_address(sender_address)
        else:
            connection = self.find_classic_connection_by_address(sender_address)
        if connection is None:
            logger.warning(f'!!! no connection for {sender_address}')
            return

        # Send the data to the host
        # TODO: should fragment
        acl_packet = HCI_AclDataPacket(connection.handle, 2, 0, len(data), data)
        self.send_hci_packet(acl_packet)

    def on_link_advertising_data(self, sender_address, data, scan_response):
        # Ignore if we're not scanning
        if self.le_scan_enable == 0:
            return

        # Send an advertising report
        report = HCI_LE_Advertising_Report_Event.Report(
            HCI_LE_Advertising_Report_Event.Report.FIELDS,
            event_type=HCI_LE_Advertising_Report_Event.ADV_IND,
            address_type=sender_address.address_type,
            address=sender_address,
            data=data,
            rssi=-50,
        )
        self.send_hci_packet(HCI_LE_Advertising_Report_Event([report]))

        # Simulate a scan response
        report = HCI_LE_Advertising_Report_Event.Report(
            HCI_LE_Advertising_Report_Event.Report.FIELDS,
            event_type=HCI_LE_Advertising_Report_Event.SCAN_RSP,
            address_type=sender_address.address_type,
            address=sender_address,
            data=scan_response,
            rssi=-50,
        )
        self.send_hci_packet(HCI_LE_Advertising_Report_Event([report]))

    def on_link_extended_advertising_data(
        self, sender_address, event_properties, data, scan_response
    ):
        # Ignore if we're not scanning
        if self.le_scan_enable == 0:
            return

        # Send an advertising report
        event_type = (
            1 << HCI_LE_Extended_Advertising_Report_Event.CONNECTABLE_ADVERTISING
        )
        report = HCI_LE_Extended_Advertising_Report_Event.Report(
            HCI_LE_Extended_Advertising_Report_Event.Report.FIELDS,
            event_type=event_type,
            address_type=sender_address.address_type,
            address=sender_address,
            primary_phy=HCI_LE_1M_PHY,
            secondary_phy=HCI_LE_1M_PHY,
            advertising_sid=0,
            tx_power=0,
            rssi=-50,
            periodic_advertising_interval=0,
            direct_address_type=0,
            direct_address=Address.NIL,
            data=data,
        )
        self.send_hci_packet(HCI_LE_Extended_Advertising_Report_Event([report]))

        # Simulate a scan response if needed
        if event_properties & (1 << 1) == 0:
            # The event is not scannable
            return

        event_type |= 1 << HCI_LE_Extended_Advertising_Report_Event.SCAN_RESPONSE
        report = HCI_LE_Extended_Advertising_Report_Event.Report(
            HCI_LE_Extended_Advertising_Report_Event.Report.FIELDS,
            event_type=event_type,
            address_type=sender_address.address_type,
            address=sender_address,
            primary_phy=HCI_LE_1M_PHY,
            secondary_phy=HCI_LE_1M_PHY,
            advertising_sid=0,
            tx_power=0,
            rssi=-50,
            periodic_advertising_interval=0,
            direct_address_type=0,
            direct_address=Address.NIL,
            data=scan_response,
        )
        self.send_hci_packet(HCI_LE_Extended_Advertising_Report_Event([report]))

    ############################################################
    # Classic link connections
    ############################################################

    def on_classic_connection_request(self, peer_address, link_type):
        self.send_hci_packet(
            HCI_Connection_Request_Event(
                bd_addr=peer_address,
                class_of_device=0,
                link_type=link_type,
            )
        )

    def on_classic_connection_complete(self, peer_address, status):
        if status == HCI_SUCCESS:
            # Allocate (or reuse) a connection handle
            peer_address = peer_address
            connection = self.classic_connections.get(peer_address)
            if connection is None:
                connection_handle = self.allocate_connection_handle()
                connection = Connection(
                    controller=self,
                    handle=connection_handle,
                    # Role doesn't matter in Classic because they are managed by HCI_Role_Change and HCI_Role_Discovery
                    role=BT_CENTRAL_ROLE,
                    peer_address=peer_address,
                    link=self.link,
                    transport=BT_BR_EDR_TRANSPORT,
                )
                self.classic_connections[peer_address] = connection
                logger.debug(
                    f'New CLASSIC connection handle: 0x{connection_handle:04X}'
                )
            else:
                connection_handle = connection.handle
            self.send_hci_packet(
                HCI_Connection_Complete_Event(
                    status=status,
                    connection_handle=connection_handle,
                    bd_addr=peer_address,
                    encryption_enabled=False,
                    link_type=HCI_Connection_Complete_Event.ACL_LINK_TYPE,
                )
            )
        else:
            connection = None
            self.send_hci_packet(
                HCI_Connection_Complete_Event(
                    status=status,
                    connection_handle=0,
                    bd_addr=peer_address,
                    encryption_enabled=False,
                    link_type=HCI_Connection_Complete_Event.ACL_LINK_TYPE,
                )
            )

    def on_classic_disconnected(self, peer_address, reason):
        # Send a disconnection complete event
        if connection := self.classic_connections.get(peer_address):
            self.send_hci_packet(
                HCI_Disconnection_Complete_Event(
                    status=HCI_SUCCESS,
                    connection_handle=connection.handle,
                    reason=reason,
                )
            )

            # Remove the connection
            del self.classic_connections[peer_address]
        else:
            logger.warning(f'!!! No classic connection found for {peer_address}')

    def on_classic_role_change(self, peer_address, new_role):
        self.send_hci_packet(
            HCI_Role_Change_Event(
                status=HCI_SUCCESS,
                bd_addr=peer_address,
                new_role=new_role,
            )
        )

    ############################################################
    # Advertising support
    ############################################################
    def on_advertising_timer_fired(self):
        self.advertising_timer_handle = None

        while self.advertising_times:
            now = time.time()
            (when, advertiser) = self.advertising_times[0]
            if when + TIMER_TOLERANCE < now:
                break
            advertiser.send_advertising_data(self)

        # Schedule the next event
        if self.advertising_times:
            delay = max(self.advertising_times[0][0] - time.time(), 0)
            self.advertising_timer_handle = asyncio.get_running_loop().call_later(
                delay, self.on_advertising_timer_fired
            )

    def schedule_advertiser(self, advertiser: Advertiser, when: float):
        heapq.heappush(self.advertising_times, (when, advertiser))
        if self.advertising_timer_handle is None:
            self.advertising_timer_handle = asyncio.get_running_loop().call_soon(
                self.on_advertising_timer_fired
            )

    ############################################################
    # HCI handlers
    ############################################################
    def on_hci_command(self, command):
        logger.warning(color(f'--- Unsupported command {command}', 'red'))
        return bytes([HCI_UNKNOWN_HCI_COMMAND_ERROR])

    def on_hci_create_connection_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.5 Create Connection command
        '''

        logger.debug(f'Connection request to {command.bd_addr}')

        # Check that we don't already have a pending connection
        if self.link.get_pending_connection():
            self.send_hci_packet(
                HCI_Command_Status_Event(
                    status=HCI_CONTROLLER_BUSY_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return

        self.link.classic_connect(self, command.bd_addr)

        # Say that the connection is pending
        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

    def on_hci_disconnect_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.6 Disconnect Command
        '''
        # First, say that the disconnection is pending
        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

        # Notify the link of the disconnection
        handle = command.connection_handle
        if connection := self.find_le_connection_by_handle(handle):
            self.link.disconnect(self.random_address, connection.peer_address, command)
        elif connection := self.find_classic_connection_by_handle(handle):
            self.link.classic_disconnect(
                self,
                connection.peer_address,
                HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
            )

    def on_hci_accept_connection_request_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.8 Accept Connection Request command
        '''

        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.link.classic_accept_connection(self, command.bd_addr, command.role)

    def on_hci_switch_role_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.2.8 Switch Role command
        '''

        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.link.classic_switch_role(self, command.bd_addr, command.role)

    def on_hci_set_event_mask_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.1 Set Event Mask Command
        '''
        self.event_mask = command.event_mask
        return bytes([HCI_SUCCESS])

    def on_hci_reset_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.2 Reset Command
        '''
        # TODO: cleanup what needs to be reset
        return bytes([HCI_SUCCESS])

    def on_hci_write_local_name_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.11 Write Local Name Command
        '''
        local_name = command.local_name
        if len(local_name):
            try:
                first_null = local_name.find(0)
                if first_null >= 0:
                    local_name = local_name[:first_null]
                self.local_name = str(local_name, 'utf-8')
            except UnicodeDecodeError:
                pass
        return bytes([HCI_SUCCESS])

    def on_hci_read_local_name_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.12 Read Local Name Command
        '''
        local_name = bytes(self.local_name, 'utf-8')[:248]
        if len(local_name) < 248:
            local_name = local_name + bytes(248 - len(local_name))

        return bytes([HCI_SUCCESS]) + local_name

    def on_hci_read_class_of_device_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.25 Read Class of Device Command
        '''
        return bytes([HCI_SUCCESS, 0, 0, 0])

    def on_hci_write_class_of_device_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.26 Write Class of Device Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_read_synchronous_flow_control_enable_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.36 Read Synchronous Flow Control Enable
        Command
        '''
        if self.sync_flow_control:
            ret = 1
        else:
            ret = 0
        return bytes([HCI_SUCCESS, ret])

    def on_hci_write_synchronous_flow_control_enable_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.37 Write Synchronous Flow Control Enable
        Command
        '''
        ret = HCI_SUCCESS
        if command.synchronous_flow_control_enable == 1:
            self.sync_flow_control = True
        elif command.synchronous_flow_control_enable == 0:
            self.sync_flow_control = False
        else:
            ret = HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR
        return bytes([ret])

    def on_hci_set_controller_to_host_flow_control_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.38 Set Controller To Host Flow Control
        Command
        '''
        # For now we just accept the command but ignore the values.
        # TODO: respect the passed in values.
        return bytes([HCI_SUCCESS])

    def on_hci_host_buffer_size_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.39 Host Buffer Size Command
        '''
        # For now we just accept the command but ignore the values.
        # TODO: respect the passed in values.
        return bytes([HCI_SUCCESS])

    def on_hci_write_extended_inquiry_response_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.56 Write Extended Inquiry Response
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_write_simple_pairing_mode_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.59 Write Simple Pairing Mode Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_set_event_mask_page_2_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.69 Set Event Mask Page 2 Command
        '''
        self.event_mask_page_2 = command.event_mask_page_2
        return bytes([HCI_SUCCESS])

    def on_hci_read_le_host_support_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.78 Write LE Host Support Command
        '''
        return bytes([HCI_SUCCESS, 1, 0])

    def on_hci_write_le_host_support_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.79 Write LE Host Support Command
        '''
        # TODO / Just ignore for now
        return bytes([HCI_SUCCESS])

    def on_hci_write_authenticated_payload_timeout_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.94 Write Authenticated Payload Timeout
        Command
        '''
        # TODO
        return struct.pack('<BH', HCI_SUCCESS, command.connection_handle)

    def on_hci_read_local_version_information_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.1 Read Local Version Information Command
        '''
        return struct.pack(
            '<BBHBHH',
            HCI_SUCCESS,
            self.hci_version,
            self.hci_revision,
            self.lmp_version,
            self.manufacturer_name,
            self.lmp_subversion,
        )

    def on_hci_read_local_supported_commands_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.2 Read Local Supported Commands Command
        '''
        return bytes([HCI_SUCCESS]) + self.supported_commands

    def on_hci_read_local_supported_features_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.3 Read Local Supported Features Command
        '''
        return bytes([HCI_SUCCESS]) + self.lmp_features

    def on_hci_read_bd_addr_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.6 Read BD_ADDR Command
        '''
        bd_addr = (
            self._public_address.to_bytes()
            if self._public_address is not None
            else bytes(6)
        )
        return bytes([HCI_SUCCESS]) + bd_addr

    def on_hci_read_local_extended_features_command(self, _command):
        '''
        See Bluetooth spec @ 7.4.4 Read Local Extended Features Command
        '''
        return bytes([HCI_SUCCESS]) + bytes(8)

    def on_hci_le_set_event_mask_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.1 LE Set Event Mask Command
        '''
        self.le_event_mask = command.le_event_mask
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_buffer_size_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.2 LE Read Buffer Size Command
        '''
        return struct.pack(
            '<BHB',
            HCI_SUCCESS,
            self.hc_le_data_packet_length,
            self.hc_total_num_le_data_packets,
        )

    def on_hci_le_read_local_supported_features_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.3 LE Read Local Supported Features
        Command
        '''
        return bytes([HCI_SUCCESS]) + self.le_features

    def on_hci_le_set_random_address_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.4 LE Set Random Address Command
        '''
        self.random_address = command.random_address
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_advertising_parameters_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.5 LE Set Advertising Parameters Command
        '''
        self.legacy_advertiser.parameters = command
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_advertising_physical_channel_tx_power_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.6 LE Read Advertising Physical Channel
        Tx Power Command
        '''
        return bytes([HCI_SUCCESS, self.advertising_channel_tx_power])

    def on_hci_le_set_advertising_data_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.7 LE Set Advertising Data Command
        '''
        self.legacy_advertiser.data = command.advertising_data
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_scan_response_data_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.8 LE Set Scan Response Data Command
        '''
        self.legacy_advertiser.scan_response_data = command.scan_response_data
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_advertising_enable_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.9 LE Set Advertising Enable Command
        '''
        if command.advertising_enable:
            if not self.legacy_advertiser.enabled:
                self.legacy_advertiser.enabled = True
                self.schedule_advertiser(self.legacy_advertiser, time.time())
        else:
            self.legacy_advertiser.enabled = False

        return bytes([HCI_SUCCESS])

    def on_hci_le_set_scan_parameters_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.10 LE Set Scan Parameters Command
        '''
        if self.le_scan_enable:
            return bytes([HCI_COMMAND_DISALLOWED_ERROR])

        self.le_scan_type = command.le_scan_type
        self.le_scan_interval = command.le_scan_interval
        self.le_scan_window = command.le_scan_window
        self.le_scan_own_address_type = command.own_address_type
        self.le_scanning_filter_policy = command.scanning_filter_policy
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_scan_enable_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.11 LE Set Scan Enable Command
        '''
        self.le_scan_enable = command.le_scan_enable
        self.filter_duplicates = command.filter_duplicates
        return bytes([HCI_SUCCESS])

    def on_hci_le_create_connection_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.12 LE Create Connection Command
        '''

        if not self.link:
            return

        logger.debug(f'Connection request to {command.peer_address}')

        # Check that we don't already have a pending connection
        if self.link.get_pending_connection():
            self.send_hci_packet(
                HCI_Command_Status_Event(
                    status=HCI_COMMAND_DISALLOWED_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return

        # Initiate the connection
        self.link.connect(self.random_address, command)

        # Say that the connection is pending
        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

    def on_hci_le_create_connection_cancel_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.13 LE Create Connection Cancel Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_filter_accept_list_size_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.14 LE Read Filter Accept List Size
        Command
        '''
        return bytes([HCI_SUCCESS, self.filter_accept_list_size])

    def on_hci_le_clear_filter_accept_list_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.15 LE Clear Filter Accept List Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_add_device_to_filter_accept_list_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.16 LE Add Device To Filter Accept List
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_remove_device_from_filter_accept_list_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.17 LE Remove Device From Filter Accept
        List Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_remote_features_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.21 LE Read Remote Features Command
        '''

        # First, say that the command is pending
        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

        # Then send the remote features
        self.send_hci_packet(
            HCI_LE_Read_Remote_Features_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=0,
                le_features=bytes.fromhex('dd40000000000000'),
            )
        )

    def on_hci_le_rand_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.23 LE Rand Command
        '''
        return bytes([HCI_SUCCESS]) + struct.pack('Q', random.randint(0, 1 << 64))

    def on_hci_le_enable_encryption_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.24 LE Enable Encryption Command
        '''

        # Check the parameters
        if not (
            connection := self.find_le_connection_by_handle(command.connection_handle)
        ):
            logger.warning('connection not found')
            return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

        # Notify that the connection is now encrypted
        self.link.on_connection_encrypted(
            self.random_address,
            connection.peer_address,
            command.random_number,
            command.encrypted_diversifier,
            command.long_term_key,
        )

        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

        return None

    def on_hci_le_read_supported_states_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.27 LE Read Supported States Command
        '''
        return bytes([HCI_SUCCESS]) + self.le_states

    def on_hci_le_read_suggested_default_data_length_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.34 LE Read Suggested Default Data Length
        Command
        '''
        return struct.pack(
            '<BHH',
            HCI_SUCCESS,
            self.suggested_max_tx_octets,
            self.suggested_max_tx_time,
        )

    def on_hci_le_write_suggested_default_data_length_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.35 LE Write Suggested Default Data Length
        Command
        '''
        self.suggested_max_tx_octets, self.suggested_max_tx_time = struct.unpack(
            '<HH', command.parameters[:4]
        )
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_local_p_256_public_key_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.36 LE Read P-256 Public Key Command
        '''
        # TODO create key and send HCI_LE_Read_Local_P-256_Public_Key_Complete event
        return bytes([HCI_SUCCESS])

    def on_hci_le_add_device_to_resolving_list_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.38 LE Add Device To Resolving List
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_clear_resolving_list_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.40 LE Clear Resolving List Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_resolving_list_size_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.41 LE Read Resolving List Size Command
        '''
        return bytes([HCI_SUCCESS, self.resolving_list_size])

    def on_hci_le_set_address_resolution_enable_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.44 LE Set Address Resolution Enable
        Command
        '''
        ret = HCI_SUCCESS
        if command.address_resolution_enable == 1:
            self.le_address_resolution = True
        elif command.address_resolution_enable == 0:
            self.le_address_resolution = False
        else:
            ret = HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR
        return bytes([ret])

    def on_hci_le_set_resolvable_private_address_timeout_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.45 LE Set Resolvable Private Address
        Timeout Command
        '''
        self.le_rpa_timeout = command.rpa_timeout
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_maximum_data_length_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.46 LE Read Maximum Data Length Command
        '''
        return struct.pack(
            '<BHHHH',
            HCI_SUCCESS,
            self.supported_max_tx_octets,
            self.supported_max_tx_time,
            self.supported_max_rx_octets,
            self.supported_max_rx_time,
        )

    def on_hci_le_read_phy_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.47 LE Read PHY Command
        '''
        return struct.pack(
            '<BHBB',
            HCI_SUCCESS,
            command.connection_handle,
            HCI_LE_1M_PHY,
            HCI_LE_1M_PHY,
        )

    def on_hci_le_set_default_phy_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.48 LE Set Default PHY Command
        '''
        self.default_phy = {
            'all_phys': command.all_phys,
            'tx_phys': command.tx_phys,
            'rx_phys': command.rx_phys,
        }
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_advertising_set_random_address_command(self, command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.52 LE Set Advertising Set Random Address
        Command
        '''
        if (
            advertiser := self.extended_advertisers.get(
                command.advertising_handle, None
            )
        ) is None:
            return bytes([HCI_UNKNOWN_ADVERTISING_IDENTIFIER_ERROR])

        if advertiser.enabled and advertiser.is_connectable:
            return bytes([HCI_COMMAND_DISALLOWED_ERROR])

        advertiser.address = command.random_address

        return bytes([HCI_SUCCESS])

    def on_hci_le_set_extended_advertising_parameters_command(self, command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.53 LE Set Extended Advertising Parameters
        Command
        '''
        # Check if the advertiser already exists
        if advertiser := self.extended_advertisers.get(
            command.advertising_handle, None
        ):
            # We cannot update an advertiser that's currently enabled
            if advertiser.enabled:
                return bytes([HCI_COMMAND_DISALLOWED_ERROR, 0])

            # Update the advertiser
            advertiser.parameters = command
        else:
            # Try to create a new advertiser
            if (
                len(self.extended_advertisers)
                >= self.le_number_of_supported_advertising_sets
            ):
                logger.warning('too many advertisers')
                return bytes([HCI_MEMORY_CAPACITY_EXCEEDED_ERROR, 0])

            logger.debug(f'new advertiser: {command.advertising_handle}')
            # TODO: allow other addresses
            advertiser = ExtendedAdvertiser(command, self.random_address)
            self.extended_advertisers[command.advertising_handle] = advertiser

        return bytes([HCI_SUCCESS, advertiser.tx_power])

    def on_hci_le_set_extended_advertising_data_command(self, command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.54 LE Set Extended Advertising Data
        Command
        '''
        if (
            advertiser := self.extended_advertisers.get(
                command.advertising_handle, None
            )
        ) is None:
            return bytes([HCI_UNKNOWN_ADVERTISING_IDENTIFIER_ERROR])

        if command.operation not in (3, 4) and not command.advertising_data:
            return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

        if advertiser.enabled and command.operation not in (3, 4):
            return bytes([HCI_COMMAND_DISALLOWED_ERROR])

        updated_data = None
        if command.operation == 0:
            # Intermediate fragment of fragmented extended advertising data
            updated_data = advertiser.data + command.advertising_data
        elif command.operation == 1:
            # First fragment of fragmented extended advertising data
            updated_data = command.advertising_data
        elif command.operation == 2:
            # Last fragment of fragmented extended advertising data
            updated_data = advertiser.data + command.advertising_data
        elif command.operation == 3:
            # Complete extended advertising data
            updated_data = command.advertising_data
        elif command.operation == 4:
            # Unchanged data (just update the Advertising DID)
            if (
                not advertiser.enabled
                or not advertiser.data
                or advertiser.is_legacy
                or command.advertising_data
            ):
                return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])
        else:
            return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

        if updated_data is not None:
            if len(updated_data) > self.le_maximum_advertising_data_length:
                return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])
            advertiser.data = updated_data
            logger.debug(f'updating advertiser data: {updated_data.hex()}')

        return bytes([HCI_SUCCESS])

    def on_hci_le_set_extended_scan_response_data_command(self, _command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.55 LE Set Extended Scan Response Data
        Command
        '''
        # TODO: not implemented yet
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_extended_advertising_enable_command(self, command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.56 LE Set Extended Advertising Enable
        Command
        '''
        for advertising_handle in command.advertising_handles:
            if (
                advertiser := self.extended_advertisers.get(advertising_handle, None)
            ) is None:
                return bytes([HCI_UNKNOWN_ADVERTISING_IDENTIFIER_ERROR])

        for i, advertising_handle in enumerate(command.advertising_handles):
            advertiser = self.extended_advertisers[advertising_handle]
            if command.enable:
                if advertiser.expired or not advertiser.enabled:
                    advertiser.enabled = True
                    advertiser.duration = command.durations[i]
                    advertiser.extended_advertising_events = 0
                    advertiser.max_extended_advertising_events = (
                        command.max_extended_advertising_events[i]
                    )
                    self.schedule_advertiser(advertiser, time.time())
            else:
                advertiser.enabled = False

        return bytes([HCI_SUCCESS])

    def on_hci_le_read_maximum_advertising_data_length_command(self, _command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.57 LE Read Maximum Advertising Data
        Length Command
        '''
        return struct.pack('<BH', HCI_SUCCESS, self.le_maximum_advertising_data_length)

    def on_hci_le_read_number_of_supported_advertising_sets_command(self, _command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.58 LE Read Number Of Supported
        Advertising Sets Command
        '''
        return struct.pack(
            'BB', HCI_SUCCESS, self.le_number_of_supported_advertising_sets
        )

    def on_hci_le_remove_advertising_set_command(self, command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.59 LE Remove Advertising Set Command
        '''
        if command.advertising_handle not in self.extended_advertisers:
            return bytes([HCI_UNKNOWN_ADVERTISING_IDENTIFIER_ERROR])

        del self.extended_advertisers[command.advertising_handle]
        return bytes([HCI_SUCCESS])

    def on_hci_le_clear_advertising_sets_command(self, _command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.60 LE Clear Advertising Sets Command
        '''
        self.extended_advertisers = {}
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_extended_scan_parameters_command(self, _command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.64 LE Set Extended Scan Parameters
        Command
        '''
        # TODO: not implemented yet
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_extended_scan_enable_command(self, command):
        '''
        See Bluetooth spec Vol 2, Part E - 7.8.65 LE Set Extended Scan Enable Command
        '''
        self.le_scan_enable = command.enable
        self.filter_duplicates = command.filter_duplicates
        # TODO: support period and duration
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_transmit_power_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.74 LE Read Transmit Power Command
        '''
        return struct.pack('<BBB', HCI_SUCCESS, 0, 0)

    def on_hci_le_setup_iso_data_path_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.109 LE Setup ISO Data Path Command
        '''
        return struct.pack('<BH', HCI_SUCCESS, command.connection_handle)

    def on_hci_le_remove_iso_data_path_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.110 LE Remove ISO Data Path Command
        '''
        return struct.pack('<BH', HCI_SUCCESS, command.connection_handle)
