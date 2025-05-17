# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import logging
import pytest
from unittest import mock

from bumble.controller import Controller
from bumble.device import Connection, Device
from bumble.hci import HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR
from bumble.host import Host
from bumble.link import LocalLink

logger = logging.getLogger(__name__)


@pytest.fixture
def link() -> LocalLink:
    return LocalLink()


@pytest.fixture
async def central_device(link) -> Device:
    controller = Controller('Central', link=link)
    host = Host()
    host.controller = controller
    device = Device(host=host)
    await device.power_on()
    return device


@pytest.fixture
async def peripheral_device(link) -> Device:
    controller = Controller('Peripheral', link=link)
    host = Host()
    host.controller = controller
    device = Device(host=host)
    await device.power_on()
    return device


async def connect(central_device, peripheral_device) -> Connection:
    return await central_device.connect(
        peripheral_device.host.controller.random_address
    )


@pytest.mark.asyncio
async def test_connect(central_device, peripheral_device):
    conn = await connect(central_device, peripheral_device)
    assert conn.self_address == central_device.host.controller.random_address
    assert conn.peer_address == peripheral_device.host.controller.random_address


@pytest.fixture
async def connection(central_device, peripheral_device) -> Connection:
    return await connect(central_device, peripheral_device)


@pytest.mark.asyncio
async def test_disconnect_from_central(central_device, peripheral_device, connection):
    assert peripheral_device.connections
    await asyncio.wait_for(
        central_device.disconnect(
            connection, reason=HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR
        ),
        timeout=1.0,
    )
    assert not peripheral_device.connections


@pytest.mark.asyncio
async def test_disconnect_from_peripheral(
    central_device, peripheral_device, connection
):
    assert central_device.connections
    await asyncio.wait_for(
        peripheral_device.disconnect(
            connection, reason=HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR
        ),
        timeout=1.0,
    )
    assert not central_device.connections
