# Copyright 2023 Google LLC
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
from typing import Optional

from typing_extensions import Self

from bumble.controller import Controller
from bumble.device import Connection, Device
from bumble.hci import Address
from bumble.host import Host
from bumble.keys import PairingKeys
from bumble.link import LocalLink
from bumble.transport.common import AsyncPipeSink


# -----------------------------------------------------------------------------
class TwoDevices:
    connections: list[Optional[Connection]]

    def __init__(self) -> None:
        self.connections = [None, None]

        self.link = LocalLink()
        addresses = ['F0:F1:F2:F3:F4:F5', 'F5:F4:F3:F2:F1:F0']
        self.controllers = [
            Controller('C1', link=self.link, public_address=addresses[0]),
            Controller('C2', link=self.link, public_address=addresses[1]),
        ]
        self.devices = [
            Device(
                address=Address(addresses[0]),
                host=Host(self.controllers[0], AsyncPipeSink(self.controllers[0])),
            ),
            Device(
                address=Address(addresses[1]),
                host=Host(self.controllers[1], AsyncPipeSink(self.controllers[1])),
            ),
        ]

        self.devices[0].on(
            'connection', lambda connection: self.on_connection(0, connection)
        )
        self.devices[1].on(
            'connection', lambda connection: self.on_connection(1, connection)
        )

        self.paired = [
            asyncio.get_event_loop().create_future(),
            asyncio.get_event_loop().create_future(),
        ]

    def on_connection(self, which, connection):
        self.connections[which] = connection
        connection.on('disconnection', lambda code: self.on_disconnection(which))

    def on_disconnection(self, which):
        self.connections[which] = None

    def on_paired(self, which: int, keys: PairingKeys) -> None:
        self.paired[which].set_result(keys)

    async def setup_connection(self) -> None:
        # Start
        await self.devices[0].power_on()
        await self.devices[1].power_on()

        # Connect the two devices
        await self.devices[0].connect(self.devices[1].random_address)

        # Check the post conditions
        assert self.connections[0] is not None
        assert self.connections[1] is not None

    def __getitem__(self, index: int) -> Device:
        return self.devices[index]

    @classmethod
    async def create_with_connection(cls: type[Self]) -> Self:
        devices = cls()
        await devices.setup_connection()
        return devices


# -----------------------------------------------------------------------------
async def async_barrier():
    ready = asyncio.get_running_loop().create_future()
    asyncio.get_running_loop().call_soon(ready.set_result, None)
    await ready
