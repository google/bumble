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
import logging
import asyncio

from bumble import core
from bumble.hci import (
    Address,
    Role,
    HCI_SUCCESS,
    HCI_CONNECTION_ACCEPT_TIMEOUT_ERROR,
    HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
    HCI_PAGE_TIMEOUT_ERROR,
    HCI_Connection_Complete_Event,
)
from bumble import controller

from typing import Optional

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def parse_parameters(params_str):
    result = {}
    for param_str in params_str.split(','):
        if '=' in param_str:
            key, value = param_str.split('=')
            result[key] = value
    return result


# -----------------------------------------------------------------------------
# TODO: add more support for various LL exchanges
# (see Vol 6, Part B - 2.4 DATA CHANNEL PDU)
# -----------------------------------------------------------------------------
class LocalLink:
    '''
    Link bus for controllers to communicate with each other
    '''

    controllers: set[controller.Controller]

    def __init__(self):
        self.controllers = set()
        self.pending_connection = None
        self.pending_classic_connection = None

    ############################################################
    # Common utils
    ############################################################

    def add_controller(self, controller):
        logger.debug(f'new controller: {controller}')
        self.controllers.add(controller)

    def remove_controller(self, controller):
        self.controllers.remove(controller)

    def find_controller(self, address):
        for controller in self.controllers:
            if controller.random_address == address:
                return controller
        return None

    def find_classic_controller(
        self, address: Address
    ) -> Optional[controller.Controller]:
        for controller in self.controllers:
            if controller.public_address == address:
                return controller
        return None

    def get_pending_connection(self):
        return self.pending_connection

    ############################################################
    # LE handlers
    ############################################################

    def on_address_changed(self, controller):
        pass

    def send_advertising_data(self, sender_address, data):
        # Send the advertising data to all controllers, except the sender
        for controller in self.controllers:
            if controller.random_address != sender_address:
                controller.on_link_advertising_data(sender_address, data)

    def send_acl_data(self, sender_controller, destination_address, transport, data):
        # Send the data to the first controller with a matching address
        if transport == core.PhysicalTransport.LE:
            destination_controller = self.find_controller(destination_address)
            source_address = sender_controller.random_address
        elif transport == core.PhysicalTransport.BR_EDR:
            destination_controller = self.find_classic_controller(destination_address)
            source_address = sender_controller.public_address
        else:
            raise ValueError("unsupported transport type")

        if destination_controller is not None:
            destination_controller.on_link_acl_data(source_address, transport, data)

    def on_connection_complete(self):
        # Check that we expect this call
        if not self.pending_connection:
            logger.warning('on_connection_complete with no pending connection')
            return

        central_address, le_create_connection_command = self.pending_connection
        self.pending_connection = None

        # Find the controller that initiated the connection
        if not (central_controller := self.find_controller(central_address)):
            logger.warning('!!! Initiating controller not found')
            return

        # Connect to the first controller with a matching address
        if peripheral_controller := self.find_controller(
            le_create_connection_command.peer_address
        ):
            central_controller.on_link_peripheral_connection_complete(
                le_create_connection_command, HCI_SUCCESS
            )
            peripheral_controller.on_link_central_connected(central_address)
            return

        # No peripheral found
        central_controller.on_link_peripheral_connection_complete(
            le_create_connection_command, HCI_CONNECTION_ACCEPT_TIMEOUT_ERROR
        )

    def connect(self, central_address, le_create_connection_command):
        logger.debug(
            f'$$$ CONNECTION {central_address} -> '
            f'{le_create_connection_command.peer_address}'
        )
        self.pending_connection = (central_address, le_create_connection_command)
        asyncio.get_running_loop().call_soon(self.on_connection_complete)

    def on_disconnection_complete(
        self, initiating_address, target_address, disconnect_command
    ):
        # Find the controller that initiated the disconnection
        if not (initiating_controller := self.find_controller(initiating_address)):
            logger.warning('!!! Initiating controller not found')
            return

        # Disconnect from the first controller with a matching address
        if target_controller := self.find_controller(target_address):
            target_controller.on_link_disconnected(
                initiating_address, disconnect_command.reason
            )

        initiating_controller.on_link_disconnection_complete(
            disconnect_command, HCI_SUCCESS
        )

    def disconnect(self, initiating_address, target_address, disconnect_command):
        logger.debug(
            f'$$$ DISCONNECTION {initiating_address} -> '
            f'{target_address}: reason = {disconnect_command.reason}'
        )
        args = [initiating_address, target_address, disconnect_command]
        asyncio.get_running_loop().call_soon(self.on_disconnection_complete, *args)

    # pylint: disable=too-many-arguments
    def on_connection_encrypted(
        self, central_address, peripheral_address, rand, ediv, ltk
    ):
        logger.debug(f'*** ENCRYPTION {central_address} -> {peripheral_address}')

        if central_controller := self.find_controller(central_address):
            central_controller.on_link_encrypted(peripheral_address, rand, ediv, ltk)

        if peripheral_controller := self.find_controller(peripheral_address):
            peripheral_controller.on_link_encrypted(central_address, rand, ediv, ltk)

    def create_cis(
        self,
        central_controller: controller.Controller,
        peripheral_address: Address,
        cig_id: int,
        cis_id: int,
    ) -> None:
        logger.debug(
            f'$$$ CIS Request {central_controller.random_address} -> {peripheral_address}'
        )
        if peripheral_controller := self.find_controller(peripheral_address):
            asyncio.get_running_loop().call_soon(
                peripheral_controller.on_link_cis_request,
                central_controller.random_address,
                cig_id,
                cis_id,
            )

    def accept_cis(
        self,
        peripheral_controller: controller.Controller,
        central_address: Address,
        cig_id: int,
        cis_id: int,
    ) -> None:
        logger.debug(
            f'$$$ CIS Accept {peripheral_controller.random_address} -> {central_address}'
        )
        if central_controller := self.find_controller(central_address):
            asyncio.get_running_loop().call_soon(
                central_controller.on_link_cis_established, cig_id, cis_id
            )
            asyncio.get_running_loop().call_soon(
                peripheral_controller.on_link_cis_established, cig_id, cis_id
            )

    def disconnect_cis(
        self,
        initiator_controller: controller.Controller,
        peer_address: Address,
        cig_id: int,
        cis_id: int,
    ) -> None:
        logger.debug(
            f'$$$ CIS Disconnect {initiator_controller.random_address} -> {peer_address}'
        )
        if peer_controller := self.find_controller(peer_address):
            asyncio.get_running_loop().call_soon(
                initiator_controller.on_link_cis_disconnected, cig_id, cis_id
            )
            asyncio.get_running_loop().call_soon(
                peer_controller.on_link_cis_disconnected, cig_id, cis_id
            )

    ############################################################
    # Classic handlers
    ############################################################

    def classic_connect(self, initiator_controller, responder_address):
        logger.debug(
            f'[Classic] {initiator_controller.public_address} connects to {responder_address}'
        )
        responder_controller = self.find_classic_controller(responder_address)
        if responder_controller is None:
            initiator_controller.on_classic_connection_complete(
                responder_address, HCI_PAGE_TIMEOUT_ERROR
            )
            return
        self.pending_classic_connection = (initiator_controller, responder_controller)

        responder_controller.on_classic_connection_request(
            initiator_controller.public_address,
            HCI_Connection_Complete_Event.LinkType.ACL,
        )

    def classic_accept_connection(
        self, responder_controller, initiator_address, responder_role
    ):
        logger.debug(
            f'[Classic] {responder_controller.public_address} accepts to connect {initiator_address}'
        )
        initiator_controller = self.find_classic_controller(initiator_address)
        if initiator_controller is None:
            responder_controller.on_classic_connection_complete(
                responder_controller.public_address, HCI_PAGE_TIMEOUT_ERROR
            )
            return

        async def task():
            if responder_role != Role.PERIPHERAL:
                initiator_controller.on_classic_role_change(
                    responder_controller.public_address, int(not (responder_role))
                )
            initiator_controller.on_classic_connection_complete(
                responder_controller.public_address, HCI_SUCCESS
            )

        asyncio.create_task(task())
        responder_controller.on_classic_role_change(
            initiator_controller.public_address, responder_role
        )
        responder_controller.on_classic_connection_complete(
            initiator_controller.public_address, HCI_SUCCESS
        )
        self.pending_classic_connection = None

    def classic_disconnect(self, initiator_controller, responder_address, reason):
        logger.debug(
            f'[Classic] {initiator_controller.public_address} disconnects {responder_address}'
        )
        responder_controller = self.find_classic_controller(responder_address)

        async def task():
            initiator_controller.on_classic_disconnected(responder_address, reason)

        asyncio.create_task(task())
        responder_controller.on_classic_disconnected(
            initiator_controller.public_address, reason
        )

    def classic_switch_role(
        self, initiator_controller, responder_address, initiator_new_role
    ):
        responder_controller = self.find_classic_controller(responder_address)
        if responder_controller is None:
            return

        async def task():
            initiator_controller.on_classic_role_change(
                responder_address, initiator_new_role
            )

        asyncio.create_task(task())
        responder_controller.on_classic_role_change(
            initiator_controller.public_address, int(not (initiator_new_role))
        )

    def classic_sco_connect(
        self,
        initiator_controller: controller.Controller,
        responder_address: Address,
        link_type: int,
    ):
        logger.debug(
            f'[Classic] {initiator_controller.public_address} connects SCO to {responder_address}'
        )
        responder_controller = self.find_classic_controller(responder_address)
        # Initiator controller should handle it.
        assert responder_controller

        responder_controller.on_classic_connection_request(
            initiator_controller.public_address,
            link_type,
        )

    def classic_accept_sco_connection(
        self,
        responder_controller: controller.Controller,
        initiator_address: Address,
        link_type: int,
    ):
        logger.debug(
            f'[Classic] {responder_controller.public_address} accepts to connect SCO {initiator_address}'
        )
        initiator_controller = self.find_classic_controller(initiator_address)
        if initiator_controller is None:
            responder_controller.on_classic_sco_connection_complete(
                responder_controller.public_address,
                HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                link_type,
            )
            return

        async def task():
            initiator_controller.on_classic_sco_connection_complete(
                responder_controller.public_address, HCI_SUCCESS, link_type
            )

        asyncio.create_task(task())
        responder_controller.on_classic_sco_connection_complete(
            initiator_controller.public_address, HCI_SUCCESS, link_type
        )
