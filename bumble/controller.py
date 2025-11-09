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
import dataclasses
import itertools
import logging
import random
import struct
from typing import TYPE_CHECKING, Any, Optional, Union, cast

from bumble import hci, lmp
from bumble.colors import color
from bumble.core import PhysicalTransport

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
    data_paths: set[int] = dataclasses.field(default_factory=set)


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class ScoLink:
    handle: int
    link_type: int
    peer_address: hci.Address


# -----------------------------------------------------------------------------
@dataclasses.dataclass
class Connection:
    controller: Controller
    handle: int
    role: hci.Role
    peer_address: hci.Address
    link: Any
    transport: int
    link_type: int
    classic_allow_role_switch: bool = False

    def __post_init__(self) -> None:
        self.assembler = hci.HCI_AclDataPacketAssembler(self.on_acl_pdu)

    def on_hci_acl_data_packet(self, packet: hci.HCI_AclDataPacket) -> None:
        self.assembler.feed_packet(packet)
        self.controller.send_hci_packet(
            hci.HCI_Number_Of_Completed_Packets_Event(
                connection_handles=[self.handle], num_completed_packets=[1]
            )
        )

    def on_acl_pdu(self, pdu: bytes) -> None:
        if self.link:
            self.link.send_acl_data(
                self.controller, self.peer_address, self.transport, pdu
            )


# -----------------------------------------------------------------------------
class Controller:
    hci_sink: Optional[TransportSink] = None

    central_connections: dict[
        hci.Address, Connection
    ]  # Connections where this controller is the central
    peripheral_connections: dict[
        hci.Address, Connection
    ]  # Connections where this controller is the peripheral
    classic_connections: dict[hci.Address, Connection]  # Connections in BR/EDR
    classic_pending_commands: dict[hci.Address, dict[lmp.Opcode, asyncio.Future[int]]]
    sco_links: dict[hci.Address, ScoLink]  # SCO links by address
    central_cis_links: dict[int, CisLink]  # CIS links by handle
    peripheral_cis_links: dict[int, CisLink]  # CIS links by handle

    hci_version: int = hci.HCI_VERSION_BLUETOOTH_CORE_5_0
    hci_revision: int = 0
    lmp_version: int = hci.HCI_VERSION_BLUETOOTH_CORE_5_0
    lmp_subversion: int = 0
    lmp_features: bytes = bytes.fromhex(
        '0000000060000000'
    )  # BR/EDR Not Supported, LE Supported (Controller)
    manufacturer_name: int = 0xFFFF
    acl_data_packet_length: int = 27
    total_num_acl_data_packets: int = 64
    le_acl_data_packet_length: int = 27
    total_num_le_acl_data_packets: int = 64
    iso_data_packet_length: int = 960
    total_num_iso_data_packets: int = 64
    event_mask: int = 0
    event_mask_page_2: int = 0
    supported_commands: bytes = bytes.fromhex(
        '2000800000c000000000e4000000a822000000000000040000f7ffff7f000000'
        '30f0f9ff01008004002000000000000000000000000000000000000000000000'
    )
    le_event_mask: int = 0
    advertising_parameters: Optional[hci.HCI_LE_Set_Advertising_Parameters_Command] = (
        None
    )
    le_features: bytes = bytes.fromhex('ff49010000000000')
    le_states: bytes = bytes.fromhex('ffff3fffff030000')
    advertising_channel_tx_power: int = 0
    filter_accept_list_size: int = 8
    filter_duplicates: bool = False
    resolving_list_size: int = 8
    supported_max_tx_octets: int = 27
    supported_max_tx_time: int = 10000
    supported_max_rx_octets: int = 27
    supported_max_rx_time: int = 10000
    suggested_max_tx_octets: int = 27
    suggested_max_tx_time: int = 0x0148
    default_phy: dict[str, int]
    le_scan_type: int = 0
    le_scan_interval: int = 0x10
    le_scan_window: int = 0x10
    le_scan_enable: int = 0
    le_scan_own_address_type: int = hci.Address.RANDOM_DEVICE_ADDRESS
    le_scanning_filter_policy: int = 0
    le_scan_response_data: Optional[bytes] = None
    le_address_resolution: bool = False
    le_rpa_timeout: int = 0
    sync_flow_control: bool = False
    local_name: str = 'Bumble'
    advertising_interval: int = 2000
    advertising_data: Optional[bytes] = None
    advertising_timer_handle: Optional[asyncio.Handle] = None
    classic_scan_enable: int = 0
    classic_allow_role_switch: bool = True

    _random_address: hci.Address = hci.Address('00:00:00:00:00:00')

    def __init__(
        self,
        name: str,
        host_source=None,
        host_sink: Optional[TransportSink] = None,
        link: Optional[LocalLink] = None,
        public_address: Optional[Union[bytes, str, hci.Address]] = None,
    ) -> None:
        self.name = name
        self.link = link
        self.central_connections = {}
        self.peripheral_connections = {}
        self.classic_connections = {}
        self.sco_links = {}
        self.classic_pending_commands = {}
        self.central_cis_links = {}
        self.peripheral_cis_links = {}
        self.default_phy = {
            'all_phys': 0,
            'tx_phys': 0,
            'rx_phys': 0,
        }

        if isinstance(public_address, hci.Address):
            self._public_address = public_address
        elif public_address is not None:
            self._public_address = hci.Address(
                public_address, hci.Address.PUBLIC_DEVICE_ADDRESS
            )
        else:
            self._public_address = hci.Address('00:00:00:00:00:00')

        # Set the source and sink interfaces
        if host_source:
            host_source.set_packet_sink(self)
        self.host = host_sink

        # Add this controller to the link if specified
        if link:
            link.add_controller(self)

        self.terminated: asyncio.Future[Any] = (
            asyncio.get_running_loop().create_future()
        )

    @property
    def host(self) -> Optional[TransportSink]:
        return self.hci_sink

    @host.setter
    def host(self, host: Optional[TransportSink]) -> None:
        '''
        Sets the host (sink) for this controller, and set this controller as the
        controller (sink) for the host
        '''
        self.set_packet_sink(host)

    def set_packet_sink(self, sink: Optional[TransportSink]) -> None:
        '''
        Method from the Packet Source interface
        '''
        self.hci_sink = sink

    @property
    def public_address(self) -> hci.Address:
        return self._public_address

    @public_address.setter
    def public_address(self, address: Union[hci.Address, str]) -> None:
        if isinstance(address, str):
            address = hci.Address(address)
        self._public_address = address

    @property
    def random_address(self) -> hci.Address:
        return self._random_address

    @random_address.setter
    def random_address(self, address: Union[hci.Address, str]) -> None:
        if isinstance(address, str):
            address = hci.Address(address)
        self._random_address = address
        logger.debug(f'new random address: {address}')

        if self.link:
            self.link.on_address_changed(self)

    # Packet Sink protocol (packets coming from the host via HCI)
    def on_packet(self, packet: bytes) -> None:
        self.on_hci_packet(hci.HCI_Packet.from_bytes(packet))

    def on_hci_packet(self, packet: hci.HCI_Packet) -> None:
        logger.debug(
            f'{color("<<<", "blue")} [{self.name}] '
            f'{color("HOST -> CONTROLLER", "blue")}: {packet}'
        )

        # If the packet is a command, invoke the handler for this packet
        if isinstance(packet, hci.HCI_Command):
            self.on_hci_command_packet(packet)
        elif isinstance(packet, hci.HCI_AclDataPacket):
            self.on_hci_acl_data_packet(packet)
        elif isinstance(packet, hci.HCI_Event):
            self.on_hci_event_packet(packet)
        else:
            logger.warning(f'!!! unknown packet type {packet.hci_packet_type}')

    def on_hci_command_packet(self, command: hci.HCI_Command) -> None:
        handler_name = f'on_{command.name.lower()}'
        handler = getattr(self, handler_name, self.on_hci_command)
        result: Optional[bytes] = handler(command)
        if isinstance(result, bytes):
            self.send_hci_packet(
                hci.HCI_Command_Complete_Event(
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                    return_parameters=result,
                )
            )

    def on_hci_event_packet(self, _event: hci.HCI_Packet) -> None:
        logger.warning('!!! unexpected event packet')

    def on_hci_acl_data_packet(self, packet: hci.HCI_AclDataPacket) -> None:
        # Look for the connection to which this data belongs
        connection = self.find_connection_by_handle(packet.connection_handle)
        if connection is None:
            logger.warning(
                f'!!! no connection for handle 0x{packet.connection_handle:04X}'
            )
            return

        # Pass the packet to the connection
        connection.on_hci_acl_data_packet(packet)

    def send_hci_packet(self, packet: hci.HCI_Packet) -> None:
        logger.debug(
            f'{color(">>>", "green")} [{self.name}] '
            f'{color("CONTROLLER -> HOST", "green")}: {packet}'
        )
        if self.host:
            asyncio.get_running_loop().call_soon(self.host.on_packet, bytes(packet))

    # This method allows the controller to emulate the same API as a transport source
    async def wait_for_termination(self) -> None:
        await self.terminated

    ############################################################
    # Link connections
    ############################################################
    def allocate_connection_handle(self) -> int:
        current_handles = set(
            cast(Connection | CisLink | ScoLink, link).handle
            for link in itertools.chain(
                self.central_connections.values(),
                self.peripheral_connections.values(),
                self.classic_connections.values(),
                self.sco_links.values(),
                self.central_cis_links.values(),
                self.peripheral_cis_links.values(),
            )
        )
        return next(
            handle for handle in range(0xEFF + 1) if handle not in current_handles
        )

    def find_le_connection_by_address(
        self, address: hci.Address
    ) -> Optional[Connection]:
        return self.central_connections.get(address) or self.peripheral_connections.get(
            address
        )

    def find_classic_connection_by_address(
        self, address: hci.Address
    ) -> Optional[Connection]:
        return self.classic_connections.get(address)

    def find_connection_by_handle(self, handle: int) -> Optional[Connection]:
        for connection in itertools.chain(
            self.central_connections.values(),
            self.peripheral_connections.values(),
            self.classic_connections.values(),
        ):
            if connection.handle == handle:
                return connection
        return None

    def find_central_connection_by_handle(self, handle: int) -> Optional[Connection]:
        for connection in self.central_connections.values():
            if connection.handle == handle:
                return connection
        return None

    def find_peripheral_connection_by_handle(self, handle: int) -> Optional[Connection]:
        for connection in self.peripheral_connections.values():
            if connection.handle == handle:
                return connection
        return None

    def find_classic_connection_by_handle(self, handle: int) -> Optional[Connection]:
        for connection in self.classic_connections.values():
            if connection.handle == handle:
                return connection
        return None

    def find_classic_sco_link_by_handle(self, handle: int) -> Optional[ScoLink]:
        for connection in self.sco_links.values():
            if connection.handle == handle:
                return connection
        return None

    def find_iso_link_by_handle(self, handle: int) -> Optional[CisLink]:
        return self.central_cis_links.get(handle) or self.peripheral_cis_links.get(
            handle
        )

    def on_link_central_connected(self, central_address: hci.Address) -> None:
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
                role=hci.Role.PERIPHERAL,
                peer_address=peer_address,
                link=self.link,
                transport=PhysicalTransport.LE,
                link_type=hci.HCI_Connection_Complete_Event.LinkType.ACL,
            )
            self.peripheral_connections[peer_address] = connection
            logger.debug(f'New PERIPHERAL connection handle: 0x{connection_handle:04X}')

        # Then say that the connection has completed
        self.send_hci_packet(
            hci.HCI_LE_Connection_Complete_Event(
                status=hci.HCI_SUCCESS,
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

    def on_link_disconnected(self, peer_address: hci.Address, reason: int) -> None:
        '''
        Called when an active disconnection occurs from a peer
        '''

        # Send a disconnection complete event
        if connection := self.peripheral_connections.get(peer_address):
            self.send_hci_packet(
                hci.HCI_Disconnection_Complete_Event(
                    status=hci.HCI_SUCCESS,
                    connection_handle=connection.handle,
                    reason=reason,
                )
            )

            # Remove the connection
            del self.peripheral_connections[peer_address]
        elif connection := self.central_connections.get(peer_address):
            self.send_hci_packet(
                hci.HCI_Disconnection_Complete_Event(
                    status=hci.HCI_SUCCESS,
                    connection_handle=connection.handle,
                    reason=reason,
                )
            )

            # Remove the connection
            del self.central_connections[peer_address]
        else:
            logger.warning(f'!!! No peripheral connection found for {peer_address}')

    def on_link_peripheral_connection_complete(
        self,
        le_create_connection_command: hci.HCI_LE_Create_Connection_Command,
        status: int,
    ) -> None:
        '''
        Called by the link when a connection has been made or has failed to be made
        '''

        if status == hci.HCI_SUCCESS:
            # Allocate (or reuse) a connection handle
            peer_address = le_create_connection_command.peer_address
            connection = self.central_connections.get(peer_address)
            if connection is None:
                connection_handle = self.allocate_connection_handle()
                connection = Connection(
                    controller=self,
                    handle=connection_handle,
                    role=hci.Role.CENTRAL,
                    peer_address=peer_address,
                    link=self.link,
                    transport=PhysicalTransport.LE,
                    link_type=hci.HCI_Connection_Complete_Event.LinkType.ACL,
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
            hci.HCI_LE_Connection_Complete_Event(
                status=status,
                connection_handle=connection.handle if connection else 0,
                role=hci.Role.CENTRAL,
                peer_address_type=le_create_connection_command.peer_address_type,
                peer_address=le_create_connection_command.peer_address,
                connection_interval=le_create_connection_command.connection_interval_min,
                peripheral_latency=le_create_connection_command.max_latency,
                supervision_timeout=le_create_connection_command.supervision_timeout,
                central_clock_accuracy=0,
            )
        )

    def on_link_disconnection_complete(
        self, disconnection_command: hci.HCI_Disconnect_Command, status: int
    ) -> None:
        '''
        Called when a disconnection has been completed
        '''

        # Send a disconnection complete event
        self.send_hci_packet(
            hci.HCI_Disconnection_Complete_Event(
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
        elif connection := self.find_peripheral_connection_by_handle(
            disconnection_command.connection_handle
        ):
            logger.debug(f'PERIPHERAL Connection removed: {connection}')
            del self.peripheral_connections[connection.peer_address]

    def on_link_encrypted(
        self, peer_address: hci.Address, _rand: bytes, _ediv: int, _ltk: bytes
    ) -> None:
        # For now, just setup the encryption without asking the host
        if connection := self.find_le_connection_by_address(peer_address):
            self.send_hci_packet(
                hci.HCI_Encryption_Change_Event(
                    status=0, connection_handle=connection.handle, encryption_enabled=1
                )
            )

    def on_link_acl_data(
        self, sender_address: hci.Address, transport: PhysicalTransport, data: bytes
    ) -> None:
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
        acl_packet = hci.HCI_AclDataPacket(connection.handle, 2, 0, len(data), data)
        self.send_hci_packet(acl_packet)

    def on_link_advertising_data(
        self, sender_address: hci.Address, data: bytes
    ) -> None:
        # Ignore if we're not scanning
        if self.le_scan_enable == 0:
            return

        # Send a scan report
        report = hci.HCI_LE_Advertising_Report_Event.Report(
            event_type=hci.HCI_LE_Advertising_Report_Event.EventType.ADV_IND,
            address_type=sender_address.address_type,
            address=sender_address,
            data=data,
            rssi=-50,
        )
        self.send_hci_packet(hci.HCI_LE_Advertising_Report_Event([report]))

        # Simulate a scan response
        report = hci.HCI_LE_Advertising_Report_Event.Report(
            event_type=hci.HCI_LE_Advertising_Report_Event.EventType.SCAN_RSP,
            address_type=sender_address.address_type,
            address=sender_address,
            data=data,
            rssi=-50,
        )
        self.send_hci_packet(hci.HCI_LE_Advertising_Report_Event([report]))

    def on_link_cis_request(
        self, central_address: hci.Address, cig_id: int, cis_id: int
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
            hci.HCI_LE_CIS_Request_Event(
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
            hci.HCI_LE_CIS_Established_Event(
                status=hci.HCI_SUCCESS,
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
            # Keep central CIS on disconnection. They should be removed by hci.HCI_LE_Remove_CIG_Command.
            cis_link.acl_connection = None
        else:
            return

        self.send_hci_packet(
            hci.HCI_Disconnection_Complete_Event(
                status=hci.HCI_SUCCESS,
                connection_handle=cis_link.handle,
                reason=hci.HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
            )
        )

    ############################################################
    # Classic link connections
    ############################################################

    def send_lmp_packet(
        self, receiver_address: hci.Address, packet: lmp.Packet
    ) -> asyncio.Future[int]:
        loop = asyncio.get_running_loop()
        assert self.link
        self.link.send_lmp_packet(self, receiver_address, packet)
        future = self.classic_pending_commands.setdefault(receiver_address, {})[
            packet.opcode
        ] = loop.create_future()
        return future

    def on_lmp_packet(self, sender_address: hci.Address, packet: lmp.Packet):
        if isinstance(packet, (lmp.LmpAccepted, lmp.LmpAcceptedExt)):
            if future := self.classic_pending_commands.setdefault(
                sender_address, {}
            ).get(packet.response_opcode):
                future.set_result(hci.HCI_SUCCESS)
            else:
                logger.error("!!! Unhandled packet: %s", packet)
        elif isinstance(packet, (lmp.LmpNotAccepted, lmp.LmpNotAcceptedExt)):
            if future := self.classic_pending_commands.setdefault(
                sender_address, {}
            ).get(packet.response_opcode):
                future.set_result(packet.error_code)
            else:
                logger.error("!!! Unhandled packet: %s", packet)
        elif isinstance(packet, (lmp.LmpHostConnectionReq)):
            self.on_classic_connection_request(
                sender_address, hci.HCI_Connection_Complete_Event.LinkType.ACL
            )
        elif isinstance(packet, (lmp.LmpScoLinkReq)):
            self.on_classic_connection_request(
                sender_address, hci.HCI_Connection_Complete_Event.LinkType.SCO
            )
        elif isinstance(packet, (lmp.LmpEscoLinkReq)):
            self.on_classic_connection_request(
                sender_address, hci.HCI_Connection_Complete_Event.LinkType.ESCO
            )
        elif isinstance(packet, (lmp.LmpDetach)):
            self.on_classic_disconnected(
                sender_address, hci.HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR
            )
        elif isinstance(packet, (lmp.LmpSwitchReq)):
            self.on_classic_role_change_request(sender_address)
        elif isinstance(packet, (lmp.LmpRemoveScoLinkReq, lmp.LmpRemoveEscoLinkReq)):
            self.on_classic_sco_disconnected(sender_address, packet.error_code)
        else:
            logger.error("!!! Unhandled packet: %s", packet)

    def on_classic_connection_request(
        self, peer_address: hci.Address, link_type: int
    ) -> None:
        if link_type == hci.HCI_Connection_Complete_Event.LinkType.ACL:
            self.classic_connections[peer_address] = Connection(
                controller=self,
                handle=0,
                role=hci.Role.PERIPHERAL,
                peer_address=peer_address,
                link=self.link,
                transport=PhysicalTransport.BR_EDR,
                link_type=link_type,
                classic_allow_role_switch=self.classic_allow_role_switch,
            )
        else:
            self.sco_links[peer_address] = ScoLink(
                handle=0,
                link_type=link_type,
                peer_address=peer_address,
            )
        self.send_hci_packet(
            hci.HCI_Connection_Request_Event(
                bd_addr=peer_address,
                class_of_device=0,
                link_type=link_type,
            )
        )

    def on_classic_connection_complete(
        self, peer_address: hci.Address, status: int
    ) -> None:
        if status == hci.HCI_SUCCESS:
            # Allocate (or reuse) a connection handle
            peer_address = peer_address
            connection_handle = self.allocate_connection_handle()
            if connection := self.classic_connections.get(peer_address):
                connection.handle = connection_handle
            else:
                connection = Connection(
                    controller=self,
                    handle=connection_handle,
                    role=hci.Role.CENTRAL,
                    peer_address=peer_address,
                    link=self.link,
                    transport=PhysicalTransport.BR_EDR,
                    link_type=hci.HCI_Connection_Complete_Event.LinkType.ACL,
                )
                self.classic_connections[peer_address] = connection
                logger.debug(
                    f'New CLASSIC connection handle: 0x{connection_handle:04X}'
                )
            self.send_hci_packet(
                hci.HCI_Connection_Complete_Event(
                    status=status,
                    connection_handle=connection_handle,
                    bd_addr=peer_address,
                    encryption_enabled=False,
                    link_type=hci.HCI_Connection_Complete_Event.LinkType.ACL,
                )
            )
        else:
            connection = None
            self.send_hci_packet(
                hci.HCI_Connection_Complete_Event(
                    status=status,
                    connection_handle=0,
                    bd_addr=peer_address,
                    encryption_enabled=False,
                    link_type=hci.HCI_Connection_Complete_Event.LinkType.ACL,
                )
            )

    def on_classic_disconnected(self, peer_address: hci.Address, reason: int) -> None:
        # Send a disconnection complete event
        if connection := self.classic_connections.pop(peer_address, None):
            self.send_hci_packet(
                hci.HCI_Disconnection_Complete_Event(
                    status=hci.HCI_SUCCESS,
                    connection_handle=connection.handle,
                    reason=reason,
                )
            )
        else:
            logger.warning(f'!!! No classic connection found for {peer_address}')

    def on_classic_sco_disconnected(
        self, peer_address: hci.Address, reason: int
    ) -> None:
        # Send a disconnection complete event
        if sco_link := self.sco_links.pop(peer_address, None):
            self.send_hci_packet(
                hci.HCI_Disconnection_Complete_Event(
                    status=hci.HCI_SUCCESS,
                    connection_handle=sco_link.handle,
                    reason=reason,
                )
            )
        else:
            logger.warning(f'!!! No classic connection found for {peer_address}')

    def on_classic_role_change_request(self, peer_address: hci.Address) -> None:
        assert (connection := self.classic_connections.get(peer_address))
        if not connection.classic_allow_role_switch:
            self.send_lmp_packet(
                peer_address,
                lmp.LmpNotAccepted(
                    lmp.Opcode.LMP_SWITCH_REQ, hci.HCI_ROLE_CHANGE_NOT_ALLOWED_ERROR
                ),
            )
        else:
            self.send_lmp_packet(
                peer_address,
                lmp.LmpAccepted(lmp.Opcode.LMP_SWITCH_REQ),
            )
            self.classic_role_change(connection)

    def classic_role_change(self, connection: Connection) -> None:
        new_role = (
            hci.Role.CENTRAL
            if connection.role == hci.Role.PERIPHERAL
            else hci.Role.PERIPHERAL
        )
        connection.role = new_role
        self.send_hci_packet(
            hci.HCI_Role_Change_Event(
                status=hci.HCI_SUCCESS,
                bd_addr=connection.peer_address,
                new_role=new_role,
            )
        )

    def on_classic_sco_connection_complete(
        self, peer_address: hci.Address, status: int, link_type: int
    ) -> None:
        if status == hci.HCI_SUCCESS:
            # Allocate (or reuse) a connection handle
            connection_handle = self.allocate_connection_handle()
            sco_link = ScoLink(
                handle=connection_handle,
                link_type=link_type,
                peer_address=peer_address,
            )
            self.sco_links[peer_address] = sco_link
            logger.debug(f'New SCO connection handle: 0x{connection_handle:04X}')
        else:
            connection_handle = 0

        self.send_hci_packet(
            hci.HCI_Synchronous_Connection_Complete_Event(
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
    def on_advertising_timer_fired(self) -> None:
        self.send_advertising_data()
        self.advertising_timer_handle = asyncio.get_running_loop().call_later(
            self.advertising_interval / 1000.0, self.on_advertising_timer_fired
        )

    def start_advertising(self) -> None:
        # Stop any ongoing advertising before we start again
        self.stop_advertising()

        # Advertise now
        self.advertising_timer_handle = asyncio.get_running_loop().call_soon(
            self.on_advertising_timer_fired
        )

    def stop_advertising(self) -> None:
        if self.advertising_timer_handle is not None:
            self.advertising_timer_handle.cancel()
            self.advertising_timer_handle = None

    def send_advertising_data(self) -> None:
        if self.link and self.advertising_data:
            self.link.send_advertising_data(self.random_address, self.advertising_data)

    @property
    def is_advertising(self) -> bool:
        return self.advertising_timer_handle is not None

    ############################################################
    # HCI handlers
    ############################################################
    def on_hci_command(self, command: hci.HCI_Command) -> Optional[bytes]:
        logger.warning(color(f'--- Unsupported command {command}', 'red'))
        return bytes([hci.HCI_UNKNOWN_HCI_COMMAND_ERROR])

    def on_hci_create_connection_command(
        self, command: hci.HCI_Create_Connection_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.5 Create Connection command
        '''

        if self.link is None:
            return None
        logger.debug(f'Connection request to {command.bd_addr}')

        # Check that we don't already have a pending connection
        if self.link.get_pending_connection():
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_CONTROLLER_BUSY_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return None

        self.classic_connections[command.bd_addr] = Connection(
            controller=self,
            handle=0,
            role=hci.Role.CENTRAL,
            peer_address=command.bd_addr,
            link=self.link,
            transport=PhysicalTransport.BR_EDR,
            link_type=hci.HCI_Connection_Complete_Event.LinkType.ACL,
            classic_allow_role_switch=bool(command.allow_role_switch),
        )

        # Say that the connection is pending
        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        future = self.send_lmp_packet(command.bd_addr, lmp.LmpHostConnectionReq())

        def on_response(future: asyncio.Future[int]):
            self.on_classic_connection_complete(command.bd_addr, future.result())

        future.add_done_callback(on_response)
        return None

    def on_hci_disconnect_command(
        self, command: hci.HCI_Disconnect_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.6 Disconnect Command
        '''
        # First, say that the disconnection is pending
        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_COMMAND_STATUS_PENDING,
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
        elif connection := self.find_peripheral_connection_by_handle(handle):
            if self.link:
                self.link.disconnect(
                    self.random_address, connection.peer_address, command
                )
            else:
                # Remove the connection
                del self.peripheral_connections[connection.peer_address]
        elif connection := self.find_classic_connection_by_handle(handle):
            if self.link:
                self.send_lmp_packet(
                    connection.peer_address,
                    lmp.LmpDetach(command.reason),
                )
                self.on_classic_disconnected(connection.peer_address, command.reason)
            else:
                # Remove the connection
                del self.classic_connections[connection.peer_address]
        elif sco_link := self.find_classic_sco_link_by_handle(handle):
            if self.link:
                if (
                    sco_link.link_type
                    == hci.HCI_Connection_Complete_Event.LinkType.ESCO
                ):
                    self.send_lmp_packet(
                        sco_link.peer_address,
                        lmp.LmpRemoveScoLinkReq(
                            sco_handle=0, error_code=command.reason
                        ),
                    )
                else:
                    self.send_lmp_packet(
                        sco_link.peer_address,
                        lmp.LmpRemoveEscoLinkReq(
                            esco_handle=0, error_code=command.reason
                        ),
                    )
                self.on_classic_sco_disconnected(sco_link.peer_address, command.reason)
            else:
                # Remove the connection
                del self.sco_links[sco_link.peer_address]
        elif cis_link := (
            self.central_cis_links.get(handle) or self.peripheral_cis_links.get(handle)
        ):
            if self.link and cis_link.acl_connection:
                self.link.disconnect_cis(
                    initiator_controller=self,
                    peer_address=cis_link.acl_connection.peer_address,
                    cig_id=cis_link.cig_id,
                    cis_id=cis_link.cis_id,
                )
            # Spec requires handle to be kept after disconnection.

        return None

    def on_hci_accept_connection_request_command(
        self, command: hci.HCI_Accept_Connection_Request_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.8 Accept Connection Request command
        '''

        if self.link is None:
            return None

        if not (connection := self.classic_connections.get(command.bd_addr)):
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return None
        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

        if command.role == hci.Role.CENTRAL:
            # Perform role switching before accept.
            future = self.send_lmp_packet(command.bd_addr, lmp.LmpSwitchReq())

            def on_response(future: asyncio.Future[int]):
                if (status := future.result()) == hci.HCI_SUCCESS:
                    self.classic_role_change(connection)
                    # Continue connection setup.
                    self.send_lmp_packet(
                        command.bd_addr,
                        lmp.LmpAccepted(lmp.Opcode.LMP_HOST_CONNECTION_REQ),
                    )
                else:
                    # Abort connection setup.
                    self.send_lmp_packet(
                        command.bd_addr,
                        lmp.LmpNotAccepted(lmp.Opcode.LMP_HOST_CONNECTION_REQ, status),
                    )
                self.on_classic_connection_complete(command.bd_addr, status)

            future.add_done_callback(on_response)

        else:
            # Simply accept connection.
            self.send_lmp_packet(
                command.bd_addr,
                lmp.LmpAccepted(lmp.Opcode.LMP_HOST_CONNECTION_REQ),
            )
            self.on_classic_connection_complete(command.bd_addr, hci.HCI_SUCCESS)
        return None

    def on_hci_enhanced_setup_synchronous_connection_command(
        self, command: hci.HCI_Enhanced_Setup_Synchronous_Connection_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.45 Enhanced Setup Synchronous Connection command
        '''

        if self.link is None:
            return None

        if not (
            connection := self.find_classic_connection_by_handle(
                command.connection_handle
            )
        ):
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return None

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        future = self.send_lmp_packet(
            connection.peer_address,
            lmp.LmpEscoLinkReq(
                esco_handle=0,
                esco_lt_addr=0,
                timing_control_flags=0,
                d_esco=0,
                t_esco=0,
                w_esco=0,
                esco_packet_type_c_to_p=0,
                esco_packet_type_p_to_c=0,
                packet_length_c_to_p=0,
                packet_length_p_to_c=0,
                air_mode=0,
                negotiation_state=0,
            ),
        )

        def on_response(future: asyncio.Future[int]):
            self.on_classic_sco_connection_complete(
                connection.peer_address,
                future.result(),
                hci.HCI_Connection_Complete_Event.LinkType.ESCO,
            )

        future.add_done_callback(on_response)
        return None

    def on_hci_enhanced_accept_synchronous_connection_request_command(
        self, command: hci.HCI_Enhanced_Accept_Synchronous_Connection_Request_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.1.46 Enhanced Accept Synchronous Connection Request command
        '''

        if self.link is None:
            return None

        if not (connection := self.find_classic_connection_by_address(command.bd_addr)):
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return None

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.send_lmp_packet(
            connection.peer_address,
            lmp.LmpAcceptedExt(lmp.Opcode.LMP_ESCO_LINK_REQ),
        )
        self.on_classic_sco_connection_complete(
            connection.peer_address,
            hci.HCI_SUCCESS,
            hci.HCI_Connection_Complete_Event.LinkType.ESCO,
        )
        return None

    def on_hci_sniff_mode_command(
        self, command: hci.HCI_Sniff_Mode_Command
    ) -> Optional[bytes]:
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
            return None

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.send_hci_packet(
            hci.HCI_Mode_Change_Event(
                status=hci.HCI_SUCCESS,
                connection_handle=command.connection_handle,
                current_mode=hci.HCI_Mode_Change_Event.Mode.SNIFF,
                interval=2,
            )
        )
        return None

    def on_hci_exit_sniff_mode_command(
        self, command: hci.HCI_Exit_Sniff_Mode_Command
    ) -> Optional[bytes]:
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
            return None

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        self.send_hci_packet(
            hci.HCI_Mode_Change_Event(
                status=hci.HCI_SUCCESS,
                connection_handle=command.connection_handle,
                current_mode=hci.HCI_Mode_Change_Event.Mode.ACTIVE,
                interval=2,
            )
        )
        return None

    def on_hci_switch_role_command(
        self, command: hci.HCI_Switch_Role_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.2.8 Switch hci.Role command
        '''

        if self.link is None:
            return None

        if connection := self.classic_connections.get(command.bd_addr):
            current_role = connection.role
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_SUCCESS,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
        else:
            # Connection doesn't exist, reject.
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_COMMAND_DISALLOWED_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return None

        # If role doesn't change, only send event to local host.
        if current_role == command.role:
            self.send_hci_packet(
                hci.HCI_Role_Change_Event(
                    status=hci.HCI_SUCCESS,
                    bd_addr=command.bd_addr,
                    new_role=current_role,
                )
            )
        else:
            future = self.send_lmp_packet(command.bd_addr, lmp.LmpSwitchReq())

            def on_response(future: asyncio.Future[int]):
                if (status := future.result()) == hci.HCI_SUCCESS:
                    connection.role = hci.Role(command.role)
                self.send_hci_packet(
                    hci.HCI_Role_Change_Event(
                        status=status,
                        bd_addr=command.bd_addr,
                        new_role=connection.role,
                    )
                )

            future.add_done_callback(on_response)

        return None

    def on_hci_set_event_mask_command(
        self, command: hci.HCI_Set_Event_Mask_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.1 Set Event Mask Command
        '''
        self.event_mask = int.from_bytes(
            command.event_mask, byteorder='little', signed=False
        )
        return bytes([hci.HCI_SUCCESS])

    def on_hci_reset_command(self, _command: hci.HCI_Reset_Command) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.2 Reset Command
        '''
        # TODO: cleanup what needs to be reset
        return bytes([hci.HCI_SUCCESS])

    def on_hci_write_local_name_command(
        self, command: hci.HCI_Write_Local_Name_Command
    ) -> Optional[bytes]:
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
        return bytes([hci.HCI_SUCCESS])

    def on_hci_read_local_name_command(
        self, _command: hci.HCI_Read_Local_Name_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.12 Read Local Name Command
        '''
        local_name = bytes(self.local_name, 'utf-8')[:248]
        if len(local_name) < 248:
            local_name = local_name + bytes(248 - len(local_name))

        return bytes([hci.HCI_SUCCESS]) + local_name

    def on_hci_read_class_of_device_command(
        self, _command: hci.HCI_Read_Class_Of_Device_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.25 Read Class of Device Command
        '''
        return bytes([hci.HCI_SUCCESS, 0, 0, 0])

    def on_hci_write_class_of_device_command(
        self, _command: hci.HCI_Write_Class_Of_Device_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.26 Write Class of Device Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_read_synchronous_flow_control_enable_command(
        self, _command: hci.HCI_Read_Synchronous_Flow_Control_Enable_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.36 Read Synchronous Flow Control Enable
        Command
        '''
        if self.sync_flow_control:
            ret = 1
        else:
            ret = 0
        return bytes([hci.HCI_SUCCESS, ret])

    def on_hci_write_synchronous_flow_control_enable_command(
        self, command: hci.HCI_Write_Synchronous_Flow_Control_Enable_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.37 Write Synchronous Flow Control Enable
        Command
        '''
        ret = hci.HCI_SUCCESS
        if command.synchronous_flow_control_enable == 1:
            self.sync_flow_control = True
        elif command.synchronous_flow_control_enable == 0:
            self.sync_flow_control = False
        else:
            ret = hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR
        return bytes([ret])

    def on_hci_set_controller_to_host_flow_control_command(
        self, _command: hci.HCI_Set_Controller_To_Host_Flow_Control_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.38 Set Controller To Host Flow Control
        Command
        '''
        # For now we just accept the command but ignore the values.
        # TODO: respect the passed in values.
        return bytes([hci.HCI_SUCCESS])

    def on_hci_host_buffer_size_command(
        self, _command: hci.HCI_Host_Buffer_Size_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.39 Host Buffer Size Command
        '''
        # For now we just accept the command but ignore the values.
        # TODO: respect the passed in values.
        return bytes([hci.HCI_SUCCESS])

    def on_hci_write_extended_inquiry_response_command(
        self, _command: hci.HCI_Write_Extended_Inquiry_Response_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.56 Write Extended Inquiry Response
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_write_simple_pairing_mode_command(
        self, _command: hci.HCI_Write_Simple_Pairing_Mode_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.59 Write Simple Pairing Mode Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_set_event_mask_page_2_command(
        self, command: hci.HCI_Set_Event_Mask_Page_2_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.69 Set Event Mask Page 2 Command
        '''
        self.event_mask_page_2 = int.from_bytes(
            command.event_mask_page_2, byteorder='little', signed=False
        )
        return bytes([hci.HCI_SUCCESS])

    def on_hci_read_le_host_support_command(
        self, _command: hci.HCI_Read_LE_Host_Support_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.78 Write LE Host Support Command
        '''
        return bytes([hci.HCI_SUCCESS, 1, 0])

    def on_hci_write_le_host_support_command(
        self, _command: hci.HCI_Write_LE_Host_Support_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.79 Write LE Host Support Command
        '''
        # TODO / Just ignore for now
        return bytes([hci.HCI_SUCCESS])

    def on_hci_write_authenticated_payload_timeout_command(
        self, command: hci.HCI_Write_Authenticated_Payload_Timeout_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.94 Write Authenticated Payload Timeout
        Command
        '''
        # TODO
        return struct.pack('<BH', hci.HCI_SUCCESS, command.connection_handle)

    def on_hci_read_local_version_information_command(
        self, _command: hci.HCI_Read_Local_Version_Information_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.1 Read Local Version Information Command
        '''
        return struct.pack(
            '<BBHBHH',
            hci.HCI_SUCCESS,
            self.hci_version,
            self.hci_revision,
            self.lmp_version,
            self.manufacturer_name,
            self.lmp_subversion,
        )

    def on_hci_read_local_supported_commands_command(
        self, _command: hci.HCI_Read_Local_Supported_Commands_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.2 Read Local Supported Commands Command
        '''
        return bytes([hci.HCI_SUCCESS]) + self.supported_commands

    def on_hci_read_local_supported_features_command(
        self, _command: hci.HCI_Read_Local_Supported_Features_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.3 Read Local Supported Features Command
        '''
        return bytes([hci.HCI_SUCCESS]) + self.lmp_features[:8]

    def on_hci_read_local_extended_features_command(
        self, command: hci.HCI_Read_Local_Extended_Features_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.4 Read Local Extended Features Command
        '''
        if command.page_number * 8 > len(self.lmp_features):
            return bytes([hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])
        return (
            bytes(
                [
                    # Status
                    hci.HCI_SUCCESS,
                    # Page number
                    command.page_number,
                    # Max page number
                    len(self.lmp_features) // 8 - 1,
                ]
            )
            # Features of the current page
            + self.lmp_features[command.page_number * 8 : (command.page_number + 1) * 8]
        )

    def on_hci_read_buffer_size_command(
        self, _command: hci.HCI_Read_Buffer_Size_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.5 Read Buffer Size Command
        '''
        return struct.pack(
            '<BHBHH',
            hci.HCI_SUCCESS,
            self.acl_data_packet_length,
            0,
            self.total_num_acl_data_packets,
            0,
        )

    def on_hci_read_bd_addr_command(
        self, _command: hci.HCI_Read_BD_ADDR_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.4.6 Read BD_ADDR Command
        '''
        bd_addr = (
            bytes(self._public_address)
            if self._public_address is not None
            else bytes(6)
        )
        return bytes([hci.HCI_SUCCESS]) + bd_addr

    def on_hci_le_set_default_subrate_command(
        self, command: hci.HCI_LE_Set_Default_Subrate_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 6, Part E - 7.8.123 LE Set Event Mask Command
        '''

        if (
            command.subrate_max * (command.max_latency) > 500
            or command.subrate_max < command.subrate_min
            or command.continuation_number >= command.subrate_max
        ):
            return bytes([hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_subrate_request_command(
        self, command: hci.HCI_LE_Subrate_Request_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 6, Part E - 7.8.124 LE Subrate Request command
        '''
        if (
            command.subrate_max * (command.max_latency) > 500
            or command.continuation_number < command.continuation_number
            or command.subrate_max < command.subrate_min
            or command.continuation_number >= command.subrate_max
        ):
            return bytes([hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_SUCCESS,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

        self.send_hci_packet(
            hci.HCI_LE_Subrate_Change_Event(
                status=hci.HCI_SUCCESS,
                connection_handle=command.connection_handle,
                subrate_factor=2,
                peripheral_latency=2,
                continuation_number=command.continuation_number,
                supervision_timeout=command.supervision_timeout,
            )
        )
        return None

    def on_hci_le_set_event_mask_command(
        self, command: hci.HCI_LE_Set_Event_Mask_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.1 LE Set Event Mask Command
        '''
        self.le_event_mask = int.from_bytes(
            command.le_event_mask, byteorder='little', signed=False
        )
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_buffer_size_command(
        self, _command: hci.HCI_LE_Read_Buffer_Size_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.2 LE Read Buffer Size Command
        '''
        return struct.pack(
            '<BHB',
            hci.HCI_SUCCESS,
            self.le_acl_data_packet_length,
            self.total_num_le_acl_data_packets,
        )

    def on_hci_le_read_buffer_size_v2_command(
        self, _command: hci.HCI_LE_Read_Buffer_Size_V2_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.2 LE Read Buffer Size Command
        '''
        return struct.pack(
            '<BHBHB',
            hci.HCI_SUCCESS,
            self.le_acl_data_packet_length,
            self.total_num_le_acl_data_packets,
            self.iso_data_packet_length,
            self.total_num_iso_data_packets,
        )

    def on_hci_le_read_local_supported_features_command(
        self, _command: hci.HCI_LE_Read_Local_Supported_Features_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.3 LE Read Local Supported Features
        Command
        '''
        return bytes([hci.HCI_SUCCESS]) + self.le_features

    def on_hci_le_set_random_address_command(
        self, command: hci.HCI_LE_Set_Random_Address_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.4 LE Set Random hci.Address Command
        '''
        self.random_address = command.random_address
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_advertising_parameters_command(
        self, command: hci.HCI_LE_Set_Advertising_Parameters_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.5 LE Set Advertising Parameters Command
        '''
        self.advertising_parameters = command
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_advertising_physical_channel_tx_power_command(
        self, _command: hci.HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.6 LE Read Advertising Physical Channel
        Tx Power Command
        '''
        return bytes([hci.HCI_SUCCESS, self.advertising_channel_tx_power])

    def on_hci_le_set_advertising_data_command(
        self, command: hci.HCI_LE_Set_Advertising_Data_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.7 LE Set Advertising Data Command
        '''
        self.advertising_data = command.advertising_data
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_scan_response_data_command(
        self, command: hci.HCI_LE_Set_Scan_Response_Data_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.8 LE Set Scan Response Data Command
        '''
        self.le_scan_response_data = command.scan_response_data
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_advertising_enable_command(
        self, command: hci.HCI_LE_Set_Advertising_Enable_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.9 LE Set Advertising Enable Command
        '''
        if command.advertising_enable:
            self.start_advertising()
        else:
            self.stop_advertising()

        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_scan_parameters_command(
        self, command: hci.HCI_LE_Set_Scan_Parameters_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.10 LE Set Scan Parameters Command
        '''
        if self.le_scan_enable:
            return bytes([hci.HCI_COMMAND_DISALLOWED_ERROR])

        self.le_scan_type = command.le_scan_type
        self.le_scan_interval = command.le_scan_interval
        self.le_scan_window = command.le_scan_window
        self.le_scan_own_address_type = hci.AddressType(command.own_address_type)
        self.le_scanning_filter_policy = command.scanning_filter_policy
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_scan_enable_command(
        self, command: hci.HCI_LE_Set_Scan_Enable_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.11 LE Set Scan Enable Command
        '''
        self.le_scan_enable = bool(command.le_scan_enable)
        self.filter_duplicates = bool(command.filter_duplicates)
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_create_connection_command(
        self, command: hci.HCI_LE_Create_Connection_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.12 LE Create Connection Command
        '''

        if not self.link:
            return None

        logger.debug(f'Connection request to {command.peer_address}')

        # Check that we don't already have a pending connection
        if self.link.get_pending_connection():
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_COMMAND_DISALLOWED_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return None

        # Initiate the connection
        self.link.connect(self.random_address, command)

        # Say that the connection is pending
        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        return None

    def on_hci_le_create_connection_cancel_command(
        self, _command: hci.HCI_LE_Create_Connection_Cancel_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.13 LE Create Connection Cancel Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_filter_accept_list_size_command(
        self, _command: hci.HCI_LE_Read_Filter_Accept_List_Size_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.14 LE Read Filter Accept List Size
        Command
        '''
        return bytes([hci.HCI_SUCCESS, self.filter_accept_list_size])

    def on_hci_le_clear_filter_accept_list_command(
        self, _command: hci.HCI_LE_Clear_Filter_Accept_List_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.15 LE Clear Filter Accept List Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_add_device_to_filter_accept_list_command(
        self, _command: hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.16 LE Add Device To Filter Accept List
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_remove_device_from_filter_accept_list_command(
        self, _command: hci.HCI_LE_Remove_Device_From_Filter_Accept_List_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.17 LE Remove Device From Filter Accept
        List Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_write_scan_enable_command(
        self, command: hci.HCI_Write_Scan_Enable_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.3.18 Write Scan Enable Command
        '''
        self.classic_scan_enable = command.scan_enable
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_remote_features_command(
        self, command: hci.HCI_LE_Read_Remote_Features_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.21 LE Read Remote Features Command
        '''

        handle = command.connection_handle

        if not self.find_connection_by_handle(handle):
            self.send_hci_packet(
                hci.HCI_Command_Status_Event(
                    status=hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR,
                    num_hci_command_packets=1,
                    command_opcode=command.op_code,
                )
            )
            return None

        # First, say that the command is pending
        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

        # Then send the remote features
        self.send_hci_packet(
            hci.HCI_LE_Read_Remote_Features_Complete_Event(
                status=hci.HCI_SUCCESS,
                connection_handle=handle,
                le_features=bytes.fromhex('dd40000000000000'),
            )
        )
        return None

    def on_hci_le_rand_command(
        self, _command: hci.HCI_LE_Rand_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.23 LE Rand Command
        '''
        return bytes([hci.HCI_SUCCESS]) + struct.pack('Q', random.randint(0, 1 << 64))

    def on_hci_le_enable_encryption_command(
        self, command: hci.HCI_LE_Enable_Encryption_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.24 LE Enable Encryption Command
        '''
        if not self.link:
            return None

        # Check the parameters
        if not (
            connection := self.find_central_connection_by_handle(
                command.connection_handle
            )
        ):
            logger.warning('connection not found')
            return bytes([hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

        # Notify that the connection is now encrypted
        self.link.on_connection_encrypted(
            self.random_address,
            connection.peer_address,
            command.random_number,
            command.encrypted_diversifier,
            command.long_term_key,
        )

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )

        return None

    def on_hci_le_read_supported_states_command(
        self, _command: hci.HCI_LE_Read_Supported_States_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.27 LE Read Supported States Command
        '''
        return bytes([hci.HCI_SUCCESS]) + self.le_states

    def on_hci_le_read_suggested_default_data_length_command(
        self, _command: hci.HCI_LE_Read_Suggested_Default_Data_Length_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.34 LE Read Suggested Default Data Length
        Command
        '''
        return struct.pack(
            '<BHH',
            hci.HCI_SUCCESS,
            self.suggested_max_tx_octets,
            self.suggested_max_tx_time,
        )

    def on_hci_le_write_suggested_default_data_length_command(
        self, command: hci.HCI_LE_Write_Suggested_Default_Data_Length_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.35 LE Write Suggested Default Data Length
        Command
        '''
        self.suggested_max_tx_octets, self.suggested_max_tx_time = struct.unpack(
            '<HH', command.parameters[:4]
        )
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_local_p_256_public_key_command(
        self, _command: hci.HCI_LE_Read_Local_P_256_Public_Key_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.36 LE Read P-256 Public Key Command
        '''
        # TODO create key and send hci.HCI_LE_Read_Local_P-256_Public_Key_Complete event
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_add_device_to_resolving_list_command(
        self, _command: hci.HCI_LE_Add_Device_To_Resolving_List_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.38 LE Add Device To Resolving List
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_clear_resolving_list_command(
        self, _command: hci.HCI_LE_Clear_Resolving_List_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.40 LE Clear Resolving List Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_resolving_list_size_command(
        self, _command: hci.HCI_LE_Read_Resolving_List_Size_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.41 LE Read Resolving List Size Command
        '''
        return bytes([hci.HCI_SUCCESS, self.resolving_list_size])

    def on_hci_le_set_address_resolution_enable_command(
        self, command: hci.HCI_LE_Set_Address_Resolution_Enable_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.44 LE Set hci.Address Resolution Enable
        Command
        '''
        ret = hci.HCI_SUCCESS
        if command.address_resolution_enable == 1:
            self.le_address_resolution = True
        elif command.address_resolution_enable == 0:
            self.le_address_resolution = False
        else:
            ret = hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR
        return bytes([ret])

    def on_hci_le_set_resolvable_private_address_timeout_command(
        self, command: hci.HCI_LE_Set_Resolvable_Private_Address_Timeout_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.45 LE Set Resolvable Private hci.Address
        Timeout Command
        '''
        self.le_rpa_timeout = command.rpa_timeout
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_maximum_data_length_command(
        self, _command: hci.HCI_LE_Read_Maximum_Data_Length_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.46 LE Read Maximum Data Length Command
        '''
        return struct.pack(
            '<BHHHH',
            hci.HCI_SUCCESS,
            self.supported_max_tx_octets,
            self.supported_max_tx_time,
            self.supported_max_rx_octets,
            self.supported_max_rx_time,
        )

    def on_hci_le_read_phy_command(
        self, command: hci.HCI_LE_Read_PHY_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.47 LE Read PHY Command
        '''
        return struct.pack(
            '<BHBB',
            hci.HCI_SUCCESS,
            command.connection_handle,
            hci.HCI_LE_1M_PHY,
            hci.HCI_LE_1M_PHY,
        )

    def on_hci_le_set_default_phy_command(
        self, command: hci.HCI_LE_Set_Default_PHY_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.48 LE Set Default PHY Command
        '''
        self.default_phy['all_phys'] = command.all_phys
        self.default_phy['tx_phys'] = command.tx_phys
        self.default_phy['rx_phys'] = command.rx_phys
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_advertising_set_random_address_command(
        self, _command: hci.HCI_LE_Set_Advertising_Set_Random_Address_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.52 LE Set Advertising Set Random hci.Address
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_extended_advertising_parameters_command(
        self, _command: hci.HCI_LE_Set_Extended_Advertising_Parameters_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.53 LE Set Extended Advertising Parameters
        Command
        '''
        return bytes([hci.HCI_SUCCESS, 0])

    def on_hci_le_set_extended_advertising_data_command(
        self, _command: hci.HCI_LE_Set_Extended_Advertising_Data_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.54 LE Set Extended Advertising Data
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_extended_scan_response_data_command(
        self, _command: hci.HCI_LE_Set_Extended_Scan_Response_Data_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.55 LE Set Extended Scan Response Data
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_extended_advertising_enable_command(
        self, _command: hci.HCI_LE_Set_Extended_Advertising_Enable_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.56 LE Set Extended Advertising Enable
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_maximum_advertising_data_length_command(
        self, _command: hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.57 LE Read Maximum Advertising Data
        Length Command
        '''
        return struct.pack('<BH', hci.HCI_SUCCESS, 0x0672)

    def on_hci_le_read_number_of_supported_advertising_sets_command(
        self, _command: hci.HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.58 LE Read Number of Supported
        Advertising Set Command
        '''
        return struct.pack('<BB', hci.HCI_SUCCESS, 0xF0)

    def on_hci_le_set_periodic_advertising_parameters_command(
        self, _command: hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.61 LE Set Periodic Advertising Parameters
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_periodic_advertising_data_command(
        self, _command: hci.HCI_LE_Set_Periodic_Advertising_Data_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.62 LE Set Periodic Advertising Data
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_set_periodic_advertising_enable_command(
        self, _command: hci.HCI_LE_Set_Periodic_Advertising_Enable_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.63 LE Set Periodic Advertising Enable
        Command
        '''
        return bytes([hci.HCI_SUCCESS])

    def on_hci_le_read_transmit_power_command(
        self, _command: hci.HCI_LE_Read_Transmit_Power_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.74 LE Read Transmit Power Command
        '''
        return struct.pack('<BBB', hci.HCI_SUCCESS, 0, 0)

    def on_hci_le_set_cig_parameters_command(
        self, command: hci.HCI_LE_Set_CIG_Parameters_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.97 LE Set CIG Parameter Command
        '''

        # Remove old CIG implicitly.
        cis_links = list(self.central_cis_links.items())
        for handle, cis_link in cis_links:
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
            '<BBB', hci.HCI_SUCCESS, command.cig_id, len(handles)
        ) + b''.join([struct.pack('<H', handle) for handle in handles])

    def on_hci_le_create_cis_command(
        self, command: hci.HCI_LE_Create_CIS_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.99 LE Create CIS Command
        '''
        if not self.link:
            return None

        for cis_handle, acl_handle in zip(
            command.cis_connection_handle, command.acl_connection_handle
        ):
            if not (connection := self.find_connection_by_handle(acl_handle)):
                logger.error(f'Cannot find connection with handle={acl_handle}')
                return bytes([hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

            if not (cis_link := self.central_cis_links.get(cis_handle)):
                logger.error(f'Cannot find CIS with handle={cis_handle}')
                return bytes([hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

            cis_link.acl_connection = connection

            self.link.create_cis(
                self,
                peripheral_address=connection.peer_address,
                cig_id=cis_link.cig_id,
                cis_id=cis_link.cis_id,
            )

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        return None

    def on_hci_le_remove_cig_command(
        self, command: hci.HCI_LE_Remove_CIG_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.100 LE Remove CIG Command
        '''

        status = hci.HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR

        cis_links = list(self.central_cis_links.items())
        for cis_handle, cis_link in cis_links:
            if cis_link.cig_id == command.cig_id:
                self.central_cis_links.pop(cis_handle)
                status = hci.HCI_SUCCESS

        return struct.pack('<BH', status, command.cig_id)

    def on_hci_le_accept_cis_request_command(
        self, command: hci.HCI_LE_Accept_CIS_Request_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.101 LE Accept CIS Request Command
        '''
        if not self.link:
            return None

        if not (
            pending_cis_link := self.peripheral_cis_links.get(command.connection_handle)
        ):
            logger.error(f'Cannot find CIS with handle={command.connection_handle}')
            return bytes([hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR])

        assert pending_cis_link.acl_connection
        self.link.accept_cis(
            peripheral_controller=self,
            central_address=pending_cis_link.acl_connection.peer_address,
            cig_id=pending_cis_link.cig_id,
            cis_id=pending_cis_link.cis_id,
        )

        self.send_hci_packet(
            hci.HCI_Command_Status_Event(
                status=hci.HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=command.op_code,
            )
        )
        return None

    def on_hci_le_setup_iso_data_path_command(
        self, command: hci.HCI_LE_Setup_ISO_Data_Path_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.109 LE Setup ISO Data Path Command
        '''
        if not (iso_link := self.find_iso_link_by_handle(command.connection_handle)):
            return struct.pack(
                '<BH',
                hci.HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                command.connection_handle,
            )
        if command.data_path_direction in iso_link.data_paths:
            return struct.pack(
                '<BH',
                hci.HCI_COMMAND_DISALLOWED_ERROR,
                command.connection_handle,
            )
        iso_link.data_paths.add(command.data_path_direction)
        return struct.pack('<BH', hci.HCI_SUCCESS, command.connection_handle)

    def on_hci_le_remove_iso_data_path_command(
        self, command: hci.HCI_LE_Remove_ISO_Data_Path_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.110 LE Remove ISO Data Path Command
        '''
        if not (iso_link := self.find_iso_link_by_handle(command.connection_handle)):
            return struct.pack(
                '<BH',
                hci.HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                command.connection_handle,
            )
        data_paths: set[int] = set(
            direction
            for direction in hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction
            if (1 << direction) & command.data_path_direction
        )
        if not data_paths.issubset(iso_link.data_paths):
            return struct.pack(
                '<BH',
                hci.HCI_COMMAND_DISALLOWED_ERROR,
                command.connection_handle,
            )
        iso_link.data_paths.difference_update(data_paths)
        return struct.pack('<BH', hci.HCI_SUCCESS, command.connection_handle)

    def on_hci_le_set_host_feature_command(
        self, _command: hci.HCI_LE_Set_Host_Feature_Command
    ) -> Optional[bytes]:
        '''
        See Bluetooth spec Vol 4, Part E - 7.8.115 LE Set Host Feature command
        '''
        return bytes([hci.HCI_SUCCESS])
