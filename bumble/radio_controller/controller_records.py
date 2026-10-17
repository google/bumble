# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Public Controller connection records backed by live radio identities."""

from __future__ import annotations

from bumble import hci
from bumble.controller import Connection, Controller
from bumble.core import PhysicalTransport
from bumble.radio_controller.radio_connection import Connection as RadioConnection


class RadioConnectionRecord(Connection):
    """Keep Controller lookups and RF execution on the same connection identity."""

    def __init__(self, controller: Controller, connection: RadioConnection):
        self.connection = connection
        super().__init__(
            controller,
            connection.handle,
            hci.Role(connection.role),
            connection.self_address or controller.public_address,
            connection.peer,
            None,
            PhysicalTransport.LE,
            hci.HCI_Connection_Complete_Event.LinkType.ACL,
        )

    @property
    def handle(self) -> int:
        return self.connection.handle

    @handle.setter
    def handle(self, value: int) -> None:
        self.connection.handle = value

    @property
    def role(self) -> hci.Role:
        return hci.Role(self.connection.role)

    @role.setter
    def role(self, value: hci.Role) -> None:
        self.connection.role = value

    @property
    def self_address(self) -> hci.Address:
        return self.connection.self_address or self.controller.public_address

    @self_address.setter
    def self_address(self, value: hci.Address) -> None:
        self.connection.self_address = value

    @property
    def peer_address(self) -> hci.Address:
        return self.connection.peer

    @peer_address.setter
    def peer_address(self, value: hci.Address) -> None:
        self.connection.peer = value
