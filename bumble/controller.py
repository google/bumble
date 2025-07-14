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
import dataclasses
import itertools
import random
import struct
from bumble.colors import color
from bumble.core import (
    PhysicalTransport,
)
from bumble import hci
from bumble.hci import (
    HCI_ACL_DATA_PACKET,
    HCI_COMMAND_DISALLOWED_ERROR,
    HCI_COMMAND_PACKET,
    HCI_COMMAND_STATUS_PENDING,
    HCI_CONNECTION_TIMEOUT_ERROR,
    HCI_CONTROLLER_BUSY_ERROR,
    HCI_EVENT_PACKET,
    HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR,
    HCI_LE_1M_PHY,
    HCI_SUCCESS,
    HCI_UNKNOWN_HCI_COMMAND_ERROR,
    HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
    HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
    HCI_VERSION_BLUETOOTH_CORE_5_0,
    Address,
    Role,
    HCI_AclDataPacket,
    HCI_AclDataPacketAssembler,
    HCI_Command_Complete_Event,
    HCI_Command_Status_Event,
    HCI_Connection_Complete_Event,
    HCI_Connection_Request_Event,
    HCI_Disconnection_Complete_Event,
    HCI_Encryption_Change_Event,
    HCI_Synchronous_Connection_Complete_Event,
    HCI_LE_Advertising_Report_Event,
    HCI_LE_CIS_Established_Event,
    HCI_LE_CIS_Request_Event,
    HCI_LE_Connection_Complete_Event,
    HCI_LE_Read_Remote_Features_Complete_Event,
    HCI_Number_Of_Completed_Packets_Event,
    HCI_Packet,
    HCI_Role_Change_Event,
)
from typing import Optional, Union, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from bumble.link import LocalLink
    from bumble.transport.common import TransportSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
class DataObject:
    pass


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class CisLink:
    handle: int
    cis_id: int
    cig_id: int
    acl_connection: Optional[Connection] = None


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class Connection:
    controller: Controller
    handle: int
    role: Role
    peer_address: Address
    link: Any
    transport: int
    link_type: int

    def __post_init__(self):
        self.assembler = HCI_AclDataPacketAssembler(self.on_acl_pdu)

    def on_hci_acl_data_packet(self, packet):
        self.assembler.feed_packet(packet)
        self.controller.send_hci_packet(
            HCI_Number_Of_Completed_Packets_Event(
                connection_handles=[self.handle], num_completed_packets=[1]
            )
        )

    def on_acl_pdu(self, data):
        if self.link:
            self.link.send_acl_data(
                self.controller, self.peer_address, self.transport, data
            )


# -----------------------------------------------------------------------------
class Controller:
    def __init__(
        self,
        name: str,
        host_source=None,
        host_sink: Optional[TransportSink] = None,
        link: Optional[LocalLink] = None,
        public_address: Optional[Union[bytes, str, Address]] = None,
    ):
        self.name = name
        self.hci_sink = None
        self.link = link

        self.central_connections: dict[Address, Connection] = (
            {}
        )  # Connections where this controller is the central
        self.peripheral_connections: dict[Address, Connection] = (
            {}
        )  # Connections where this controller is the peripheral
        self.classic_connections: dict[Address, Connection] = (
            {}
        )  # Connections in BR/EDR
        self.central_cis_links: dict[int, CisLink] = {}  # CIS links by handle
        self.peripheral_cis_links: dict[int, CisLink] = {}  # CIS links by handle

        self.hci_version = HCI_VERSION_BLUETOOTH_CORE_5_0
        self.hci_revision = 0
        self.lmp_version = HCI_VERSION_BLUETOOTH_CORE_5_0
        self.lmp_subversion = 0
        self.lmp_features = bytes.fromhex(
            '0000000060000000'
        )  # BR/EDR Not Supported, LE Supported (Controller)
        self.manufacturer_name = 0xFFFF
        self.acl_data_packet_length = 27
        self.total_num_acl_data_packets = 64
        self.le_acl_data_packet_length = 27
        self.total_num_le_acl_data_packets = 64
        self.iso_data_packet_length = 960
        self.total_num_iso_data_packets = 64
        self.event_mask = 0
        self.event_mask_page_2 = 0
        self.supported_commands = bytes.fromhex(
            '2000800000c000000000e4000000a822000000000000040000f7ffff7f000000'
            '30f0f9ff01008004002000000000000000000000000000000000000000000000'
        )
        self.le_event_mask = 0
        self.advertising_parameters = None
        self.le_features = bytes.fromhex('ff49010000000000')
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
        self.le_scan_response_data = None
        self.le_address_resolution = False
        self.le_rpa_timeout = 0
        self.sync_flow_control = False
        self.local_name = 'Bumble'

        self.advertising_interval = 2000  # Fixed for now
        self.advertising_data = None
        self.advertising_timer_handle = None

        self._random_address = Address('00:00:00:00:00:00')
        if isinstance(public_address, Address):
            self._public_address = public_address
        elif public_address is not None:
            self._public_address = Address(
                public_address, Address.PUBLIC_DEVICE_ADDRESS
            )
        else:
            self._public_address = Address('00:00:00:00:00:00')

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

        if self.link:
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
            self.host.on_packet(bytes(packet))

    # This method allows the controller to emulate the same API as a transport source
    async def wait_for_termination(self):
        await self.terminated

    ############################################################
    # Link connections
    ############################################################
    def allocate_connection_handle(self) -> int:
        handle = 0
        max_handle = 0
        for connection in itertools.chain(
            self.central_connections.values(),
            self.peripheral_connections.values(),
            self.classic_connections.values(),
        ):
            max_handle = max(max_handle, connection.handle)
            if connection.handle == handle:
                # Already used, continue searching after the current max
                handle = max_handle + 1
        for cis_handle in itertools.chain(
            self.central_cis_links.keys(), self.peripheral_cis_links.keys()
        ):
            max_handle = max(max_handle, cis_handle)
            if cis_handle == handle:
                # Already used, continue searching after the current max
                handle = max_handle + 1
        return handle

    def find_le_connection_by_address(self, address):
        return self.central_connections.get(address) or self.peripheral_connections.get(
            address
        )

    def find_classic_connection_by_address(self, address):
        return self.classic_connections.get(address)

    def find_connection_by_handle(self, handle):
        for connection in itertools.chain(
            self.central_connections.values(),
            self.peripheral_connections.values(),
            self.classic_connections.values(),
        ):
            if connection.handle == handle:
                return connection
        return None

    def find_central_connection_by_handle(self, handle):
        for connection in self.central_connections.values():
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
        connection = self.peripheral_connections.get(peer_address)
        if connection is None:
            connection_handle = self.allocate_connection_handle()
            connection = Connection(
                controller=self,
                handle=connection_handle,
                role=Role.PERIPHERAL,
                peer_address=peer_address,
                link=self.link,
                transport=PhysicalTransport.LE,
                link_type=HCI_Connection_Complete_Event.LinkType.ACL,
            )
            self.peripheral_connections[peer_address] = connection
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

    def on_link_central_disconnected(self, peer_address, reason):
        '''
        Called when an active disconnection occurs from a peer
        '''

        # Send a disconnection complete event
        if connection := self.peripheral_connections.get(peer_address):
            self.send_hci_packet(
                HCI_Disconnection_Complete_Event(
                    status=HCI_SUCCESS,
                    connection_handle=connection.handle,
                    reason=reason,
                )
            )

            # Remove the connection
            del self.peripheral_connections[peer_address]
        else:
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
            connection = self.central_connections.get(peer_address)
            if connection is None:
                connection_handle = self.allocate_connection_handle()
                connection = Connection(
                    controller=self,
                    handle=connection_handle,
                    role=Role.CENTRAL,
                    peer_address=peer_address,
                    link=self.link,
                    transport=PhysicalTransport.LE,
                    link_type=HCI_Connection_Complete_Event.LinkType.ACL,
                )
                self.central_connections[peer_address] = connection
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
                role=Role.CENTRAL,
                peer_address_type=le_create_connection_command.peer_address_type,
                peer_address=le_create_connection_command.peer_address,
                connection_interval=le_create_connection_command.connection_interval_min,
                peripheral_latency=le_create_connection_command.max_latency,
                supervision_timeout=le_create_connection_command.supervision_timeout,
                central_clock_accuracy=0,
            )
        )

    def on_link_peripheral_disconnection_complete(self, disconnection_command, status):
        '''
        Called when a disconnection has been completed
        '''

        # Send a disconnection complete event
        self.send_hci_packet(
            HCI_Disconnection_Complete_Event(
                status=status,
                connection_handle=disconnection_command.connection_handle,
                reason=disconnection_command.reason,
            )
        )

        # Remove the connection
        if connection := self.find_central_connection_by_handle(
            disconnection_command.connection_handle
        ):
            logger.debug(f'CENTRAL Connection removed: {connection}')
            del self.central_connections[connection.peer_address]

    def on_link_peripheral_disconnected(self, peer_address):
        '''
        Called when a connection to a peripheral is broken
        '''

        # Send a disconnection complete event
        if connection := self.central_connections.get(peer_address):
            self.send_hci_packet(
                HCI_Disconnection_Complete_Event(
                    status=HCI_SUCCESS,
                    connection_handle=connection.handle,
                    reason=HCI_CONNECTION_TIMEOUT_ERROR,
                )
            )

            # Remove the connection
            del self.central_connections[peer_address]
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
        if transport == PhysicalTransport.LE:
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

    def on_link_advertising_data(self, sender_address: Address, data: bytes):
        # Ignore if we're not scanning
        if self.le_scan_enable == 0:
            return

        # Send a scan report
        report = HCI_LE_Advertising_Report_Event.Report(
            event_type=HCI_LE_Advertising_Report_Event.EventType.ADV_IND,
            address_type=sender_address.address_type,
            address=sender_address,
            data=data,
            rssi=-50,
        )
        self.send_hci_packet(HCI_LE_Advertising_Report_Event([report]))

        # Simulate a scan response
        report = HCI_LE_Advertising_Report_Event.Report(
            event_type=HCI_LE_Advertising_Report_Event.EventType.SCAN_RSP,
            address_type=sender_address.address_type,
            address=sender_address,
            data=data,
            rssi=-50,
        )
        self.send_hci_packet(HCI_LE_Advertising_Report_Event([report]))

    def on_link_cis_request(
        self, central_address: Address, cig_id: int, cis_id: int
    ) -> None:
        '''
        Called when an incoming CIS request occurs from a central on the link
        '''

        connection = self.peripheral_connections.get(central_address)
        assert connection

        pending_cis_link = CisLink(
            handle=self.allocate_connection_handle(),
            cis_id=cis_id,
            cig_id=cig_id,
            acl_connection=connection,
        )
        self.peripheral_cis_links[pending_cis_link.handle] = pending_cis_link

        self.send_hci_packet(
            HCI_LE_CIS_Request_Event(
                acl_connection_handle=connection.handle,
                cis_connection_handle=pending_cis_link.handle,
                cig_id=cig_id,
                cis_id=cis_id,
            )
        )

    def on_link_cis_established(self, cig_id: int, cis_id: int) -> None:
        '''
        Called when an incoming CIS established.
        '''

        cis_link = next(
            cis_link
            for cis_link in itertools.chain(
                self.central_cis_links.values(), self.peripheral_cis_links.values()
            )
            if cis_link.cis_id == cis_id and cis_link.cig_id == cig_id
        )

        self.send_hci_packet(
            HCI_LE_CIS_Established_Event(
                status=HCI_SUCCESS,
                connection_handle=cis_link.handle,
                # CIS parameters are ignored.
                cig_sync_delay=0,
                cis_sync_delay=0,
                transport_latency_c_to_p=0,
                transport_latency_p_to_c=0,
                phy_c_to_p=1,
                phy_p_to_c=1,
                nse=0,
                bn_c_to_p=0,
                bn_p_to_c=0,
                ft_c_to_p=0,
                ft_p_to_c=0,
                max_pdu_c_to_p=0,
                max_pdu_p_to_c=0,
                iso_interval=0,
            )
        )

    def on_link_cis_disconnected(self, cig_id: int, cis_id: int) -> None:
        '''
        Called when a CIS disconnected.
        '''

        if cis_link := next(
            (
                cis_link
                for cis_link in self.peripheral_cis_links.values()
                if cis_link.cis_id == cis_id and cis_link.cig_id == cig_id
            ),
            None,
        ):
            # Remove peripheral CIS on disconnection.
            self.peripheral_cis_links.pop(cis_link.handle)
        elif cis_link := next(
            (
                cis_link
                for cis_link in self.central_cis_links.values()
                if cis_link.cis_id == cis_id and cis_link.cig_id == cig_id
            ),
            None,
        ):
            # Keep central CIS on disconnection. They should be removed by HCI_LE_Remove_CIG_Command.
            cis_link.acl_connection = None
        else:
            return

        self.send_hci_packet(
            HCI_Disconnection_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=cis_link.handle,
                reason=HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
            )
        )

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
                    role=Role.CENTRAL,
                    peer_address=peer_address,
                    link=self.link,
                    transport=PhysicalTransport.BR_EDR,
                    link_type=HCI_Connection_Complete_Event.LinkType.ACL,
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
                    link_type=HCI_Connection_Complete_Event.LinkType.ACL,
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
                    link_type=HCI_Connection_Complete_Event.LinkType.ACL,
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

    def on_classic_sco_connection_complete(
        self, peer_address: Address, status: int, link_type: int
    ):
        if status == HCI_SUCCESS:
            # Allocate (or reuse) a connection handle
            connection_handle = self.allocate_connection_handle()
            connection = Connection(
                controller=self,
                handle=connection_handle,
                # Role doesn't matter in SCO.
                role=Role.CENTRAL,
                peer_address=peer_address,
                link=self.link,
                transport=PhysicalTransport.BR_EDR,
                link_type=link_type,
            )
            self.classic_connections[peer_address] = connection
            logger.debug(f'New SCO connection handle: 0x{connection_handle:04X}')
        else:
            connection_handle = 0

        self.send_hci_packet(
            HCI_Synchronous_Connection_Complete_Event(
                status=status,
                connection_handle=connection_handle,
                bd_addr=peer_address,
                link_type=link_type,
                # TODO: Provide SCO connection parameters.
                transmission_interval=0,
                retransmission_window=0,
                rx_packet_length=0,
                tx_packet_length=0,
                air_mode=0,
            )
        )

    ############################################################
    # Advertising support
    ############################################################
    def on_advertising_timer_fired(self):
        self.send_advertising_data()
        self.advertising_timer_handle = asyncio.get_running_loop().call_later(
            self.advertising_interval / 1000.0, self.on_advertising_timer_fired
        )

    def start_advertising(self):
        # Stop any ongoing advertising before we start again
        self.stop_advertising()

        # Advertise now
        self.advertising_timer_handle = asyncio.get_running_loop().call_soon(
            self.on_advertising_timer_fired
        )

    def stop_advertising(self):
        if self.advertising_timer_handle is not None:
            self.advertising_timer_handle.cancel()
            self.advertising_timer_handle = None

    def send_advertising_data(self):
        if self.link and self.advertising_data:
            self.link.send_advertising_data(self.random_address, self.advertising_data)

    @property
    def is_advertising(self):
        return self.advertising_timer_handle is not None

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

        if self.link is None:
            return
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
        if connection := self.find_central_connection_by_handle(handle):
            if self.link:
                self.link.disconnect(
                    self.random_address, connection.peer_address, command
                )
            else:
                # Remove the connection
                del self.central_connections[connection.peer_address]
        elif connection := self.find_classic_connection_by_handle(handle):
            if self.link:
                self.link.classic_disconnect(
                    self,
                    connection.peer_address,
                    HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
                )
            else:
                # Remove the connection
                del self.classic_connections[connection.peer_address]
        elif cis_link := (
            self.central_cis_links.get(handle) or self.peripheral_cis_links.get(handle)
        ):
            if self.link:
                self.link.disconnect_cis(
                    initiator_controller=self,
                    peer_address=cis_link.acl_connection.peer_address,
                    cig_id=cis_link.cig_id,
                    cis_id=cis_link.cis_id,
                )
            # Spec requires handle to be kept after disconnection.

    def on_hci_accept_connection_request_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.8 Accept Connection Request command
        '''

        if self.link is None:
            return
        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.link.classic_accept_connection(self, command.bd_addr, command.role)

    def on_hci_enhanced_setup_synchronous_connection_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.45 Enhanced Setup Synchronous Connection command
        '''

        if self.link is None:
            return

        if not (
            connection := self.find_classic_connection_by_handle(
                command.connection_handle
            )
        ):
            self.send_hci_packet(
                HCI_Command_Status_Event(
                    status=HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return

        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.link.classic_sco_connect(
            self, connection.peer_address, HCI_Connection_Complete_Event.LinkType.ESCO
        )

    def on_hci_enhanced_accept_synchronous_connection_request_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.46 Enhanced Accept Synchronous Connection Request command
        '''

        if self.link is None:
            return

        if not (connection := self.find_classic_connection_by_address(command.bd_addr)):
            self.send_hci_packet(
                HCI_Command_Status_Event(
                    status=HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return

        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.link.classic_accept_sco_connection(
            self, connection.peer_address, HCI_Connection_Complete_Event.LinkType.ESCO
        )

    def on_hci_sniff_mode_command(self, command: hci.HCI_Sniff_Mode_Command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.2.2 Sniff Mode command
        '''
        if self.link is None:
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.send_hci_packet(
            hci.HCI_Mode_Change_Event(
                status=HCI_SUCCESS,
                connection_handle=command.connection_handle,
                current_mode=hci.HCI_Mode_Change_Event.Mode.SNIFF,
                interval=2,
            )
        )

    def on_hci_exit_sniff_mode_command(self, command: hci.HCI_Exit_Sniff_Mode_Command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.2.3 Exit Sniff Mode command
        '''

        if self.link is None:
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.send_hci_packet(
            hci.HCI_Mode_Change_Event(
                status=HCI_SUCCESS,
                connection_handle=command.connection_handle,
                current_mode=hci.HCI_Mode_Change_Event.Mode.ACTIVE,
                interval=2,
            )
        )

    def on_hci_switch_role_command(self, command: hci.HCI_Switch_Role_Command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.2.8 Switch Role command
        '''

        if self.link is None:
            return
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
        return bytes([HCI_SUCCESS]) + self.lmp_features[:8]

    def on_hci_read_local_extended_features_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.4 Read Local Extended Features Command
        '''
        if command.page_number * 8 > len(self.lmp_features):
            return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])
        return (
            bytes(
                [
                    # Status
                    HCI_SUCCESS,
                    # Page number
                    command.page_number,
                    # Max page number
                    len(self.lmp_features) // 8 - 1,
                ]
            )
            # Features of the current page
            + self.lmp_features[command.page_number * 8 : (command.page_number + 1) * 8]
        )

    def on_hci_read_buffer_size_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.5 Read Buffer Size Command
        '''
        return struct.pack(
            '<BHBHH',
            HCI_SUCCESS,
            self.acl_data_packet_length,
            0,
            self.total_num_acl_data_packets,
            0,
        )

    def on_hci_read_bd_addr_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.6 Read BD_ADDR Command
        '''
        bd_addr = (
            bytes(self._public_address)
            if self._public_address is not None
            else bytes(6)
        )
        return bytes([HCI_SUCCESS]) + bd_addr

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
            self.le_acl_data_packet_length,
            self.total_num_le_acl_data_packets,
        )

    def on_hci_le_read_buffer_size_v2_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.2 LE Read Buffer Size Command
        '''
        return struct.pack(
            '<BHBHB',
            HCI_SUCCESS,
            self.le_acl_data_packet_length,
            self.total_num_le_acl_data_packets,
            self.iso_data_packet_length,
            self.total_num_iso_data_packets,
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
        self.advertising_parameters = command
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
        self.advertising_data = command.advertising_data
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_scan_response_data_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.8 LE Set Scan Response Data Command
        '''
        self.le_scan_response_data = command.scan_response_data
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_advertising_enable_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.9 LE Set Advertising Enable Command
        '''
        if command.advertising_enable:
            self.start_advertising()
        else:
            self.stop_advertising()

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

        handle = command.connection_handle

        if not self.find_connection_by_handle(handle):
            self.send_hci_packet(
                HCI_Command_Status_Event(
                    status=HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return

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
                connection_handle=handle,
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
            connection := self.find_central_connection_by_handle(
                command.connection_handle
            )
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

    def on_hci_le_set_advertising_set_random_address_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.52 LE Set Advertising Set Random Address
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_extended_advertising_parameters_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.53 LE Set Extended Advertising Parameters
        Command
        '''
        return bytes([HCI_SUCCESS, 0])

    def on_hci_le_set_extended_advertising_data_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.54 LE Set Extended Advertising Data
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_extended_scan_response_data_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.55 LE Set Extended Scan Response Data
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_extended_advertising_enable_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.56 LE Set Extended Advertising Enable
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_maximum_advertising_data_length_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.57 LE Read Maximum Advertising Data
        Length Command
        '''
        return struct.pack('<BH', HCI_SUCCESS, 0x0672)

    def on_hci_le_read_number_of_supported_advertising_sets_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.58 LE Read Number of Supported
        Advertising Set Command
        '''
        return struct.pack('<BB', HCI_SUCCESS, 0xF0)

    def on_hci_le_set_periodic_advertising_parameters_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.61 LE Set Periodic Advertising Parameters
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_periodic_advertising_data_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.62 LE Set Periodic Advertising Data
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_set_periodic_advertising_enable_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.63 LE Set Periodic Advertising Enable
        Command
        '''
        return bytes([HCI_SUCCESS])

    def on_hci_le_read_transmit_power_command(self, _command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.74 LE Read Transmit Power Command
        '''
        return struct.pack('<BBB', HCI_SUCCESS, 0, 0)

    def on_hci_le_set_cig_parameters_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.97 LE Set CIG Parameter Command
        '''

        # Remove old CIG implicitly.
        for handle, cis_link in self.central_cis_links.items():
            if cis_link.cig_id == command.cig_id:
                self.central_cis_links.pop(handle)

        handles = []
        for cis_id in command.cis_id:
            handle = self.allocate_connection_handle()
            handles.append(handle)
            self.central_cis_links[handle] = CisLink(
                cis_id=cis_id,
                cig_id=command.cig_id,
                handle=handle,
            )
        return struct.pack(
            '<BBB', HCI_SUCCESS, command.cig_id, len(handles)
        ) + b''.join([struct.pack('<H', handle) for handle in handles])

    def on_hci_le_create_cis_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.99 LE Create CIS Command
        '''
        if not self.link:
            return

        for cis_handle, acl_handle in zip(
            command.cis_connection_handle, command.acl_connection_handle
        ):
            if not (connection := self.find_connection_by_handle(acl_handle)):
                logger.error(f'Cannot find connection with handle={acl_handle}')
                return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

            if not (cis_link := self.central_cis_links.get(cis_handle)):
                logger.error(f'Cannot find CIS with handle={cis_handle}')
                return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

            cis_link.acl_connection = connection

            self.link.create_cis(
                self,
                peripheral_address=connection.peer_address,
                cig_id=cis_link.cig_id,
                cis_id=cis_link.cis_id,
            )

        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

    def on_hci_le_remove_cig_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.100 LE Remove CIG Command
        '''

        status = HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR

        for cis_handle, cis_link in self.central_cis_links.items():
            if cis_link.cig_id == command.cig_id:
                self.central_cis_links.pop(cis_handle)
                status = HCI_SUCCESS

        return struct.pack('<BH', status, command.cig_id)

    def on_hci_le_accept_cis_request_command(self, command):
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.101 LE Accept CIS Request Command
        '''
        if not self.link:
            return

        if not (
            pending_cis_link := self.peripheral_cis_links.get(command.connection_handle)
        ):
            logger.error(f'Cannot find CIS with handle={command.connection_handle}')
            return bytes([HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

        assert pending_cis_link.acl_connection
        self.link.accept_cis(
            peripheral_controller=self,
            central_address=pending_cis_link.acl_connection.peer_address,
            cig_id=pending_cis_link.cig_id,
            cis_id=pending_cis_link.cis_id,
        )

        self.send_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

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
