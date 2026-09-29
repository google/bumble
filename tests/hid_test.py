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

import pytest
from typing_extensions import override

from bumble import core, hid, l2cap
from bumble.testing import test_utils

_STEP_TIMEOUT_SECONDS = 0.5

# Handshake result codes 0x05..0x0D are reserved by the HID Profile 1.1
# specification (section 3.1.2.1, Table 3.2), so a peer may legitimately
# send a value that Bumble does not name.
RESERVED_HANDSHAKE_CODES = tuple(range(0x05, 0x0E))


class MockDelegate(hid.Device.Delegate):
    def __init__(self) -> None:
        self.get_report_response = b"\x00"
        self.last_set_report_data: bytes | None = None
        self.last_set_report_type: hid.ReportType | None = None

    @override
    def get_report(
        self, report_type: hid.ReportType, report_id: int | None = None
    ) -> bytes:
        if report_id is None:
            raise hid.HidProtocolError(
                hid.HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
            )
        return self.get_report_response

    @override
    def set_report(self, report_type: hid.ReportType, data: bytes) -> None:
        self.last_set_report_type = report_type
        self.last_set_report_data = data


async def open_control_channel(
    devices: test_utils.TwoDevices,
) -> tuple[l2cap.ClassicChannel, asyncio.Queue[bytes]]:
    """Open an L2CAP channel to the HID control PSM and capture responses."""
    channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.ClassicChannelSpec(hid.HID_CONTROL_PSM)
    )
    received: asyncio.Queue[bytes] = asyncio.Queue()
    channel.sink = received.put_nowait
    return channel, received


async def _setup_hid_pair() -> (
    tuple[test_utils.TwoDevices, MockDelegate, hid.Device, hid.Host]
):
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    delegate = MockDelegate()
    device = hid.Device(devices[0], delegate=delegate)
    host = hid.Host(devices[1])
    await host.connect(devices.connections[1])
    return devices, delegate, device, host


@pytest.mark.asyncio
async def test_find_device_sdp_record() -> None:
    devices = test_utils.TwoDevices()
    await devices.setup_connection()

    expected_record = hid.DeviceSdpRecord(
        service_record_handle=1,
        report_map=b"123",
        version_number=2,
        service_name=b"456",
        service_description=b"abc",
        provider_name=b"def",
        parser_version=3,
        device_subclass=4,
        country_code=5,
        virtual_cable=False,
        reconnect_initiate=True,
        report_descriptor_type=6,
        langid_base_language=7,
        langid_base_bluetooth_string_offset=8,
        battery_power=True,
        remote_wake=False,
        supervision_timeout=9,
        normally_connectable=True,
        boot_device=False,
        ssr_host_max_latency=10,
        ssr_host_min_timeout=11,
    )
    devices[0].sdp_service_records = {1: expected_record.to_service_attributes()}
    found_records = await asyncio.wait_for(
        hid.DeviceSdpRecord.find(devices.connections[1]),
        timeout=_STEP_TIMEOUT_SECONDS,
    )

    assert found_records == [expected_record]


@pytest.mark.asyncio
async def test_device_send_data() -> None:
    _, _, device, host = await _setup_hid_pair()
    event_queue: asyncio.Queue[tuple[hid.ReportType, bytes]] = asyncio.Queue()

    host.on(
        host.EVENT_INTERRUPT_DATA,
        lambda r_type, data: event_queue.put_nowait((r_type, data)),
    )

    device.send_interrupt_data(b"123")

    report_type, data = await asyncio.wait_for(
        event_queue.get(), timeout=_STEP_TIMEOUT_SECONDS
    )

    assert report_type == hid.ReportType.INPUT_REPORT
    assert data == b"123"


@pytest.mark.asyncio
async def test_device_virtual_cable_unplug() -> None:
    _, _, device, host = await _setup_hid_pair()
    event_queue: asyncio.Queue[None] = asyncio.Queue()

    host.on(
        host.EVENT_VIRTUAL_CABLE_UNPLUG,
        lambda: event_queue.put_nowait(None),
    )
    device.virtual_cable_unplug()
    await asyncio.wait_for(event_queue.get(), timeout=_STEP_TIMEOUT_SECONDS)


@pytest.mark.asyncio
async def test_device_send_handshake_message() -> None:
    _, _, device, host = await _setup_hid_pair()
    event_queue: asyncio.Queue[hid.HandshakeMessage.ResultCode] = asyncio.Queue()

    host.on(host.EVENT_HANDSHAKE, event_queue.put_nowait)

    # pylint: disable=protected-access
    device._send_handshake_message(hid.HandshakeMessage.ResultCode.SUCCESSFUL)

    result = await asyncio.wait_for(event_queue.get(), timeout=_STEP_TIMEOUT_SECONDS)
    assert result == hid.HandshakeMessage.ResultCode.SUCCESSFUL


@pytest.mark.asyncio
async def test_host_get_report() -> None:
    _, delegate, _, host = await _setup_hid_pair()
    expected_data = b"\x01\x02\x03"
    delegate.get_report_response = expected_data

    data = await asyncio.wait_for(
        host.get_report(report_type=hid.ReportType.INPUT_REPORT, report_id=1),
        timeout=_STEP_TIMEOUT_SECONDS,
    )

    assert data == b"\x01" + expected_data


@pytest.mark.asyncio
async def test_host_get_report_buffer_size_truncation() -> None:
    _, delegate, _, host = await _setup_hid_pair()
    delegate.get_report_response = b"\x01\x02\x03"

    # buffer_size=3 limits total DATA payload (1-byte Report ID + 2 bytes of data)
    data = await asyncio.wait_for(
        host.get_report(
            report_type=hid.ReportType.INPUT_REPORT, report_id=1, buffer_size=3
        ),
        timeout=_STEP_TIMEOUT_SECONDS,
    )

    assert data == b"\x01\x01\x02"


@pytest.mark.asyncio
async def test_host_set_report() -> None:
    _, delegate, _, host = await _setup_hid_pair()
    data_to_send = b"\xab\xcd"

    await asyncio.wait_for(
        host.set_report(report_type=hid.ReportType.OUTPUT_REPORT, data=data_to_send),
        timeout=_STEP_TIMEOUT_SECONDS,
    )

    assert delegate.last_set_report_data == data_to_send
    assert delegate.last_set_report_type == hid.ReportType.OUTPUT_REPORT


@pytest.mark.asyncio
async def test_host_get_protocol() -> None:
    _, _, device, host = await _setup_hid_pair()
    device.protocol = hid.ProtocolMode.REPORT_PROTOCOL

    protocol = await asyncio.wait_for(
        host.get_protocol(), timeout=_STEP_TIMEOUT_SECONDS
    )

    assert protocol == hid.ProtocolMode.REPORT_PROTOCOL


@pytest.mark.asyncio
async def test_host_set_protocol() -> None:
    _, _, device, host = await _setup_hid_pair()

    await asyncio.wait_for(
        host.set_protocol(protocol_mode=hid.ProtocolMode.BOOT_PROTOCOL),
        timeout=_STEP_TIMEOUT_SECONDS,
    )

    assert device.protocol == hid.ProtocolMode.BOOT_PROTOCOL


@pytest.mark.asyncio
async def test_host_get_and_set_idle() -> None:
    _, _, device, host = await _setup_hid_pair()

    await asyncio.wait_for(
        host.set_idle(idle_time=42),
        timeout=_STEP_TIMEOUT_SECONDS,
    )
    assert device._idle_time == 42  # pylint: disable=protected-access

    idle_time = await asyncio.wait_for(
        host.get_idle(),
        timeout=_STEP_TIMEOUT_SECONDS,
    )
    assert idle_time == 42


@pytest.mark.asyncio
async def test_host_suspend() -> None:
    _, _, device, host = await _setup_hid_pair()
    event_queue: asyncio.Queue[None] = asyncio.Queue()

    device.on(device.EVENT_SUSPEND, lambda: event_queue.put_nowait(None))

    host.suspend()
    await asyncio.wait_for(event_queue.get(), timeout=_STEP_TIMEOUT_SECONDS)


@pytest.mark.asyncio
async def test_host_exit_suspend() -> None:
    _, _, device, host = await _setup_hid_pair()
    event_queue: asyncio.Queue[None] = asyncio.Queue()

    device.on(
        device.EVENT_EXIT_SUSPEND,
        lambda: event_queue.put_nowait(None),
    )

    host.exit_suspend()
    await asyncio.wait_for(event_queue.get(), timeout=_STEP_TIMEOUT_SECONDS)


@pytest.mark.asyncio
async def test_host_send_data() -> None:
    _, _, device, host = await _setup_hid_pair()
    event_queue: asyncio.Queue[tuple[hid.ReportType, bytes]] = asyncio.Queue()

    device.on(
        device.EVENT_INTERRUPT_DATA,
        lambda r_type, data: event_queue.put_nowait((r_type, data)),
    )

    host.send_interrupt_data(b"123")

    report_type, data = await asyncio.wait_for(
        event_queue.get(), timeout=_STEP_TIMEOUT_SECONDS
    )

    assert report_type == hid.ReportType.OUTPUT_REPORT
    assert data == b"123"


@pytest.mark.asyncio
async def test_host_virtual_cable_unplug() -> None:
    _, _, device, host = await _setup_hid_pair()
    event_queue: asyncio.Queue[None] = asyncio.Queue()

    device.on(
        device.EVENT_VIRTUAL_CABLE_UNPLUG,
        lambda: event_queue.put_nowait(None),
    )
    host.virtual_cable_unplug()
    await asyncio.wait_for(event_queue.get(), timeout=_STEP_TIMEOUT_SECONDS)


@pytest.mark.parametrize("result_code", RESERVED_HANDSHAKE_CODES)
def test_reserved_handshake_result_code_does_not_raise(result_code: int) -> None:
    """A reserved HANDSHAKE result code must be parsed without raising ValueError."""
    assert hid.HandshakeMessage.ResultCode(result_code) == result_code


@pytest.mark.asyncio
async def test_host_handles_reserved_handshake_result_code() -> None:
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    hid_host = hid.Host(devices[1])
    handshakes: list[int] = []
    hid_host.on(hid_host.EVENT_HANDSHAKE, handshakes.append)

    channel, _ = await open_control_channel(devices)
    for result_code in RESERVED_HANDSHAKE_CODES:
        channel.write(bytes([result_code]))
    await test_utils.async_barrier()

    assert handshakes == list(RESERVED_HANDSHAKE_CODES)


@pytest.mark.asyncio
async def test_host_handles_defined_handshake_result_code() -> None:
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    hid_host = hid.Host(devices[1])
    handshakes: list[int] = []
    hid_host.on(hid_host.EVENT_HANDSHAKE, handshakes.append)

    channel, _ = await open_control_channel(devices)
    channel.write(bytes([hid.HandshakeMessage.ResultCode.ERR_FATAL]))
    await test_utils.async_barrier()

    assert handshakes == [hid.HandshakeMessage.ResultCode.ERR_FATAL]


@pytest.mark.parametrize("role", ("host", "device"))
@pytest.mark.asyncio
async def test_empty_control_pdu_is_ignored(role: str) -> None:
    """An empty control PDU must be dropped rather than raise IndexError."""
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    if role == "host":
        hid.Host(devices[1])
    else:
        hid.Device(devices[1], delegate=MockDelegate())

    loop = asyncio.get_running_loop()
    escaped: list[BaseException] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(
        lambda _loop, context: escaped.append(context["exception"])
    )
    try:
        channel, received = await open_control_channel(devices)
        channel.write(b"")
        await test_utils.async_barrier()
    finally:
        loop.set_exception_handler(previous_handler)

    assert not escaped
    assert received.empty()


@pytest.mark.parametrize(
    "pdu",
    (
        bytes([0x48]),  # GET_REPORT, buffer flag set, no buffer size
        bytes([0x48, 0x01]),  # GET_REPORT, buffer flag set, 1-byte buffer size
        bytes([0x40, 0x01, 0x02]),  # GET_REPORT, buffer flag clear, extra trailing byte
        bytes([0x50]),  # SET_REPORT, no report ID / payload
        bytes([0x90]),  # SET_IDLE, no idle time byte
    ),
    ids=(
        "get_report_no_size",
        "get_report_short_size",
        "get_report_extra_bytes",
        "set_report_empty",
        "set_idle_empty",
    ),
)
@pytest.mark.asyncio
async def test_truncated_report_pdu_is_rejected(pdu: bytes) -> None:
    """A malformed/truncated request must return ERR_INVALID_PARAMETER."""
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    hid.Device(devices[1], delegate=MockDelegate())

    channel, received = await open_control_channel(devices)
    channel.write(pdu)
    await test_utils.async_barrier()

    assert received.get_nowait() == bytes(
        [hid.HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER]
    )


@pytest.mark.parametrize(
    "pdu",
    (
        bytes([0x40]),  # GET_REPORT without report ID
        bytes(
            [0x48, 0x01, 0x20]
        ),  # GET_REPORT with buffer_size=0x2001, without report ID
    ),
    ids=("get_report_no_id", "get_report_with_size_no_id"),
)
@pytest.mark.asyncio
async def test_get_report_without_report_id_rejected_by_delegate(
    pdu: bytes,
) -> None:
    """Report-ID-less GET_REPORT rejected by delegate returns ERR_INVALID_PARAMETER."""
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    hid.Device(devices[1], delegate=MockDelegate())

    channel, received = await open_control_channel(devices)
    channel.write(pdu)
    await test_utils.async_barrier()

    assert received.get_nowait() == bytes(
        [hid.HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER]
    )


@pytest.mark.asyncio
async def test_host_command_error_handshake_raises() -> None:
    _, _, _, host = await _setup_hid_pair()

    with pytest.raises(hid.HidProtocolError) as exc_info:
        await asyncio.wait_for(
            host.get_report(
                report_type=hid.ReportType.INPUT_REPORT,
                report_id=None,  # Rejected by MockDelegate -> ERR_INVALID_PARAMETER
            ),
            timeout=_STEP_TIMEOUT_SECONDS,
        )

    assert (
        exc_info.value.result_code
        == hid.HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
    )


@pytest.mark.asyncio
async def test_host_command_aborted_on_disconnect() -> None:
    _, _, device, host = await _setup_hid_pair()

    # Suppress device response so the command remains in flight when disconnect happens
    device._handle_get_report = (  # type: ignore[method-assign,assignment]  # pylint: disable=protected-access
        lambda message: None
    )

    task = asyncio.create_task(
        host.get_report(report_type=hid.ReportType.INPUT_REPORT, report_id=1)
    )
    await asyncio.sleep(0.05)
    await host.disconnect()

    with pytest.raises(core.InvalidStateError):
        await asyncio.wait_for(task, timeout=_STEP_TIMEOUT_SECONDS)
