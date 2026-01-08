# Copyright 2021-2026 Google LLC
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


import pytest

from bumble import device as device_module
from bumble.profiles import battery_service

from . import test_utils


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_battery_level():
    devices = await test_utils.TwoDevices.create_with_connection()
    service = battery_service.BatteryService(lambda _: 1)
    devices[0].add_service(service)

    async with device_module.Peer(devices.connections[1]) as peer:
        client = peer.create_service_proxy(battery_service.BatteryServiceProxy)
        assert client
        assert await client.battery_level.read_value() == 1
