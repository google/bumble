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
import functools

from typing_extensions import Self

from bumble.controller import Controller
from bumble.device import Connection, Device
from bumble.hci import Address
from bumble.host import Host
from bumble.keys import PairingKeys
from bumble.link import LocalLink
from bumble.transport.common import AsyncPipeSink


# -----------------------------------------------------------------------------
class Devices:
    connections: dict[int, Connection]

    def __init__(self, num_devices: int) -> None:
        self.connections = {}

        self.link = LocalLink()
        addresses = [":".join([f"F{i}"] * 6) for i in range(num_devices)]
        self.controllers = [
            Controller(f'C{i + i}', link=self.link, public_address=addresses[i])
            for i in range(num_devices)
        ]
        self.devices = [
            Device(
                address=Address(addresses[i]),
                host=Host(self.controllers[i], AsyncPipeSink(self.controllers[i])),
            )
            for i in range(num_devices)
        ]

        for i in range(num_devices):
            self.devices[i].on(
                self.devices[i].EVENT_CONNECTION,
                functools.partial(self.on_connection, i),
            )

        self.paired = [
            asyncio.get_event_loop().create_future() for _ in range(num_devices)
        ]

    def on_connection(self, which: int, connection: Connection) -> None:
        self.connections[which] = connection
        connection.on(
            connection.EVENT_DISCONNECTION, lambda *_: self.on_disconnection(which)
        )

    def on_disconnection(self, which: int) -> None:
        self.connections.pop(which, None)

    def on_paired(self, which: int, keys: PairingKeys) -> None:
        self.paired[which].set_result(keys)

    async def setup_connection(self) -> None:
        # Start
        for dev in self.devices:
            await dev.power_on()

        # Connect devices
        for dev in self.devices[1:]:
            connection_future = asyncio.get_running_loop().create_future()
            dev.once(dev.EVENT_CONNECTION, connection_future.set_result)
            await dev.start_advertising(advertising_interval_min=1.0)
            await self.devices[0].connect(dev.random_address)
            await connection_future

    def __getitem__(self, index: int) -> Device:
        return self.devices[index]


# -----------------------------------------------------------------------------
class TwoDevices(Devices):
    def __init__(self) -> None:
        super().__init__(2)

    @classmethod
    async def create_with_connection(cls: type[Self]) -> Self:
        devices = cls()
        await devices.setup_connection()
        return devices


# -----------------------------------------------------------------------------
async def async_barrier():
    # TODO: Remove async barrier - this doesn't always mean what we want.
    for _ in range(3):
        ready = asyncio.get_running_loop().create_future()
        asyncio.get_running_loop().call_soon(ready.set_result, None)
        await ready
