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
import logging
import os
import pytest
from typing import List, Optional
from unittest.mock import MagicMock

from bumble.device import Connection, Device
from bumble.host import Host
from bumble.link import LocalLink
from bumble.controller import Controller
from bumble.hci import (
    Address,
    HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR,
    HCI_REMOTE_DEVICE_TERMINATED_CONNECTION_DUE_TO_LOW_RESOURCES_ERROR,
)
from bumble.transport import AsyncPipeSink


# -----------------------------------------------------------------------------
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
        connection.on(
            'disconnection', lambda reason: self.on_disconnection(which, reason)
        )

    def on_disconnection(self, which, _):
        self.connections[which] = None

    async def setup(self):
        self.devices[0].on(
            'connection', lambda connection: self.on_connection(0, connection)
        )
        self.devices[1].on(
            'connection', lambda connection: self.on_connection(1, connection)
        )

        await self.devices[0].power_on()
        await self.devices[1].power_on()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_connection():
    two_devices = TwoDevices()
    await two_devices.setup()

    await two_devices.devices[0].connect(two_devices.devices[1].random_address)

    assert two_devices.connections[0] is not None
    assert two_devices.connections[1] is not None

    mock0 = MagicMock()
    mock1 = MagicMock()
    two_devices.connections[0].once('disconnection', mock0)
    two_devices.connections[1].once('disconnection', mock1)
    await two_devices.connections[0].disconnect(
        HCI_REMOTE_DEVICE_TERMINATED_CONNECTION_DUE_TO_LOW_RESOURCES_ERROR
    )
    mock0.assert_called_once_with(HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR)
    mock1.assert_called_once_with(
        HCI_REMOTE_DEVICE_TERMINATED_CONNECTION_DUE_TO_LOW_RESOURCES_ERROR
    )

    assert two_devices.connections[0] is None
    assert two_devices.connections[1] is None

    await two_devices.devices[0].connect(two_devices.devices[1].random_address)

    assert two_devices.connections[0] is not None
    assert two_devices.connections[1] is not None

    mock0 = MagicMock()
    mock1 = MagicMock()
    two_devices.connections[0].once('disconnection', mock0)
    two_devices.connections[1].once('disconnection', mock1)
    await two_devices.connections[1].disconnect(
        HCI_REMOTE_DEVICE_TERMINATED_CONNECTION_DUE_TO_LOW_RESOURCES_ERROR
    )
    mock1.assert_called_once_with(HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR)
    mock0.assert_called_once_with(
        HCI_REMOTE_DEVICE_TERMINATED_CONNECTION_DUE_TO_LOW_RESOURCES_ERROR
    )

    assert two_devices.connections[0] is None
    assert two_devices.connections[1] is None


# -----------------------------------------------------------------------------
async def run_test_controller():
    await test_self_connection()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_test_controller())
