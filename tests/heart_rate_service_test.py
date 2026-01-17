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

import asyncio
import itertools
from collections.abc import Sequence

import pytest

from bumble import device as device_module
from bumble.profiles import heart_rate_service

from . import test_utils


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "heart_rate, sensor_contact_detected, energy_expanded, rr_intervals",
    itertools.product(
        (1, 1000), (True, False, None), (2, None), ((3.0, 4.0, 5.0), None)
    ),
)
async def test_read_measurement(
    heart_rate: int,
    sensor_contact_detected: bool | None,
    energy_expanded: int | None,
    rr_intervals: Sequence[int] | None,
):
    devices = await test_utils.TwoDevices.create_with_connection()
    measurement = heart_rate_service.HeartRateService.HeartRateMeasurement(
        heart_rate, sensor_contact_detected, energy_expanded, rr_intervals
    )
    service = heart_rate_service.HeartRateService(lambda _: measurement)
    devices[0].add_service(service)

    async with device_module.Peer(devices.connections[1]) as peer:
        client = peer.create_service_proxy(heart_rate_service.HeartRateServiceProxy)
        assert client
        assert await client.heart_rate_measurement.read_value() == measurement


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_body_sensor_location():
    devices = await test_utils.TwoDevices.create_with_connection()
    measurement = heart_rate_service.HeartRateService.HeartRateMeasurement(0)
    location = heart_rate_service.HeartRateService.BodySensorLocation.FINGER
    service = heart_rate_service.HeartRateService(
        lambda _: measurement,
        body_sensor_location=location,
    )
    devices[0].add_service(service)

    async with device_module.Peer(devices.connections[1]) as peer:
        client = peer.create_service_proxy(heart_rate_service.HeartRateServiceProxy)
        assert client
        assert client.body_sensor_location
        assert await client.body_sensor_location.read_value() == location


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reset_energy_expended() -> None:
    devices = await test_utils.TwoDevices.create_with_connection()
    measurement = heart_rate_service.HeartRateService.HeartRateMeasurement(1)
    reset_energy_expended = asyncio.Queue[None]()
    service = heart_rate_service.HeartRateService(
        lambda _: measurement,
        reset_energy_expended=lambda _: reset_energy_expended.put_nowait(None),
    )
    devices[0].add_service(service)

    async with device_module.Peer(devices.connections[1]) as peer:
        client = peer.create_service_proxy(heart_rate_service.HeartRateServiceProxy)
        assert client
        await client.reset_energy_expended()
        await reset_energy_expended.get()
