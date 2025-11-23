# Copyright 2021-2025 Google LLC
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
from __future__ import annotations

import asyncio
import logging

import pytest

from bumble import hid

from . import test_utils

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def hid_protocols() -> tuple[hid.Host, hid.Device]:
    devices = await test_utils.TwoDevices.create_with_connection()
    host = hid.Host(devices[0])
    device = hid.Device(devices[1])
    assert devices.connections[0]
    await host.connect(devices.connections[0])
    return host, device


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_connection():
    devices = await test_utils.TwoDevices.create_with_connection()
    host = hid.Host(devices[0])
    device = hid.Device(devices[1])

    connected = asyncio.Event()
    device.on(device.EVENT_CONNECTION, lambda: connected.set())
    await host.connect(devices.connections[0])
    await connected.wait()

    disconnected = asyncio.Event()
    device.on(device.EVENT_DISCONNECTION, lambda: disconnected.set())
    await host.disconnect()
    await disconnected.wait()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_device_send_interrupt_data():
    host, device = await hid_protocols()
    queue = asyncio.Queue[tuple[hid.ReportType, bytes]]()

    @host.on(host.EVENT_INTERRUPT_DATA)
    def _(report_type: hid.ReportType, data: bytes):
        queue.put_nowait((report_type, data))

    device.send_interrupt_data(b'123')
    assert (await queue.get()) == (hid.ReportType.INPUT_REPORT, b'123')


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_host_send_interrupt_data():
    host, device = await hid_protocols()
    queue = asyncio.Queue[tuple[hid.ReportType, bytes]]()

    @device.on(device.EVENT_INTERRUPT_DATA)
    def _(report_type: hid.ReportType, data: bytes):
        queue.put_nowait((report_type, data))

    host.send_interrupt_data(b'123')
    assert (await queue.get()) == (hid.ReportType.OUTPUT_REPORT, b'123')


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_device_virtual_cable_unplug():
    host, device = await hid_protocols()
    unplugged = asyncio.Event()
    host.on(host.EVENT_VIRTUAL_CABLE_UNPLUG, lambda: unplugged.set())

    device.virtual_cable_unplug()
    await unplugged.wait()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_host_virtual_cable_unplug():
    host, device = await hid_protocols()
    unplugged = asyncio.Event()
    device.on(device.EVENT_VIRTUAL_CABLE_UNPLUG, lambda: unplugged.set())

    host.virtual_cable_unplug()
    await unplugged.wait()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_get_protocol():
    host, device = await hid_protocols()

    device.protocol = hid.ProtocolMode.BOOT_PROTOCOL
    assert await host.get_protocol() == hid.ProtocolMode.BOOT_PROTOCOL

    await host.set_protocol(hid.ProtocolMode.REPORT_PROTOCOL)
    assert await host.get_protocol() == hid.ProtocolMode.REPORT_PROTOCOL

    device.protocol = None
    with pytest.raises(hid.HidProtocolError):
        await host.get_protocol()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_get_report():
    host, device = await hid_protocols()

    class Delegate(hid.Device.Delegate):
        def __init__(self):
            super().__init__()
            self.reports = {}

        def get_report(
            self, report_type: hid.ReportType, report_id: int | None
        ) -> bytes:
            return self.reports[report_type]

        def set_report(self, report_type: hid.ReportType, data: bytes) -> None:
            self.reports[report_type] = data

    device.delegate = Delegate()
    device.delegate.reports[hid.ReportType.INPUT_REPORT] = b'123'

    assert await host.get_report(hid.ReportType.INPUT_REPORT) == b'123'

    await host.set_report(hid.ReportType.OUTPUT_REPORT, b'456')
    assert await host.get_report(hid.ReportType.OUTPUT_REPORT) == b'456'

    device.delegate = None
    with pytest.raises(hid.HidProtocolError):
        await host.get_report(hid.ReportType.INPUT_REPORT)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_suspend_resume():
    host, device = await hid_protocols()

    suspended = asyncio.Event()
    device.on(device.EVENT_SUSPEND, lambda: suspended.set())
    host.suspend()
    await suspended.wait()

    resumed = asyncio.Event()
    device.on(device.EVENT_EXIT_SUSPEND, lambda: resumed.set())
    host.exit_suspend()
    await resumed.wait()
