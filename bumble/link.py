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

    def __init__(self) -> None:
        self.controllers = set()

    ############################################################
    # Common utils
    ############################################################

    def add_controller(self, controller: controller.Controller) -> None:
        logger.debug('new controller: %s', controller)
        self.controllers.add(controller)

    def remove_controller(self, controller: controller.Controller) -> None:
        self.controllers.remove(controller)

    ############################################################
    # Packet delivery
    ############################################################

    def send_acl_data(
        self,
        sender_controller: controller.Controller,
        *,
        sender_address: hci.Address,
        receiver_address: hci.Address,
        transport: core.PhysicalTransport,
        data: bytes,
    ) -> None:
        if transport not in (
            core.PhysicalTransport.LE,
            core.PhysicalTransport.BR_EDR,
        ):
            raise ValueError("unsupported transport type")

        loop = asyncio.get_running_loop()
        for c in self.controllers:
            if c != sender_controller:
                loop.call_soon(
                    c.on_link_acl_data,
                    sender_address,
                    receiver_address,
                    transport,
                    data,
                )

    def send_advertising_pdu(
        self,
        sender_controller: controller.Controller,
        packet: ll.AdvertisingPdu,
    ) -> None:
        loop = asyncio.get_running_loop()
        for c in self.controllers:
            if c != sender_controller:
                loop.call_soon(c.on_ll_advertising_pdu, packet)

    def send_ll_control_pdu(
        self,
        sender_controller: controller.Controller,
        sender_address: hci.Address,
        receiver_address: hci.Address,
        packet: ll.ControlPdu,
    ) -> None:
        loop = asyncio.get_running_loop()
        for c in self.controllers:
            if c != sender_controller:
                loop.call_soon(
                    c.on_ll_control_pdu,
                    sender_address,
                    receiver_address,
                    packet,
                )

    def send_lmp_packet(
        self,
        sender_controller: controller.Controller,
        sender_address: hci.Address,
        receiver_address: hci.Address,
        packet: lmp.Packet,
    ) -> None:
        loop = asyncio.get_running_loop()
        for c in self.controllers:
            if c != sender_controller:
                loop.call_soon(
                    c.on_lmp_packet,
                    sender_address,
                    receiver_address,
                    packet,
                )
