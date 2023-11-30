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

from typing import List, Optional

from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.device import Device, Connection
from bumble.host import Host
from bumble.transport import AsyncPipeSink
from bumble.hci import Address


class TwoDevices:
    connections: List[Optional[Connection]]

    def __init__(self) -> None:
        self.connections = [None, None]

        self.link = LocalLink()
        self.controllers = [
            Controller('C1', link=self.link),
            Controller('C2', link=self.link),
        ]
        self.devices = [
            Device(
                address=Address('F0:F1:F2:F3:F4:F5'),
                host=Host(self.controllers[0], AsyncPipeSink(self.controllers[0])),
            ),
            Device(
                address=Address('F5:F4:F3:F2:F1:F0'),
                host=Host(self.controllers[1], AsyncPipeSink(self.controllers[1])),
            ),
        ]

        self.paired = [None, None]

    def on_connection(self, which, connection):
        self.connections[which] = connection

    def on_paired(self, which, keys):
        self.paired[which] = keys

    async def setup_connection(self) -> None:
        # Attach listeners
        self.devices[0].on(
            'connection', lambda connection: self.on_connection(0, connection)
        )
        self.devices[1].on(
            'connection', lambda connection: self.on_connection(1, connection)
        )

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
