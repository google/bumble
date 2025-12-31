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
from __future__ import annotations

import asyncio

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import logging
from typing import TYPE_CHECKING

from bumble import core, hci, ll, lmp

if TYPE_CHECKING:
    from bumble import controller

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


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
        self.pending_classic_connection = None

    ############################################################
    # Common utils
    ############################################################

    def add_controller(self, controller: controller.Controller):
        logger.debug(f'new controller: {controller}')
        self.controllers.add(controller)

    def remove_controller(self, controller: controller.Controller):
        self.controllers.remove(controller)

    def find_le_controller(self, address: hci.Address) -> controller.Controller | None:
        for controller in self.controllers:
            for connection in controller.le_connections.values():
                if connection.self_address == address:
                    return controller
        return None

    def find_classic_controller(
        self, address: hci.Address
    ) -> controller.Controller | None:
        for controller in self.controllers:
            if controller.public_address == address:
                return controller
        return None

    ############################################################
    # LE handlers
    ############################################################

    def on_address_changed(self, controller):
        pass

    def send_acl_data(
        self,
        sender_controller: controller.Controller,
        destination_address: hci.Address,
        transport: core.PhysicalTransport,
        data: bytes,
    ):
        # Send the data to the first controller with a matching address
        if transport == core.PhysicalTransport.LE:
            destination_controller = self.find_le_controller(destination_address)
            source_address = sender_controller.random_address
        elif transport == core.PhysicalTransport.BR_EDR:
            destination_controller = self.find_classic_controller(destination_address)
            source_address = sender_controller.public_address
        else:
            raise ValueError("unsupported transport type")

        if destination_controller is not None:
            asyncio.get_running_loop().call_soon(
                lambda: destination_controller.on_link_acl_data(
                    source_address, transport, data
                )
            )

    def send_advertising_pdu(
        self,
        sender_controller: controller.Controller,
        packet: ll.AdvertisingPdu,
    ):
        loop = asyncio.get_running_loop()
        for c in self.controllers:
            if c != sender_controller:
                loop.call_soon(c.on_ll_advertising_pdu, packet)

    def send_ll_control_pdu(
        self,
        sender_address: hci.Address,
        receiver_address: hci.Address,
        packet: ll.ControlPdu,
    ):
        if not (receiver_controller := self.find_le_controller(receiver_address)):
            raise core.InvalidArgumentError(
                f"Unable to find controller for address {receiver_address}"
            )
        asyncio.get_running_loop().call_soon(
            lambda: receiver_controller.on_ll_control_pdu(sender_address, packet)
        )

    ############################################################
    # Classic handlers
    ############################################################

    def send_lmp_packet(
        self,
        sender_controller: controller.Controller,
        receiver_address: hci.Address,
        packet: lmp.Packet,
    ):
        if not (receiver_controller := self.find_classic_controller(receiver_address)):
            raise core.InvalidArgumentError(
                f"Unable to find controller for address {receiver_address}"
            )
        asyncio.get_running_loop().call_soon(
            lambda: receiver_controller.on_lmp_packet(
                sender_controller.public_address, packet
            )
        )
