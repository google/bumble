# Copyright 2021-2022 Google LLC
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

import pytest

from bumble import hid, l2cap
from bumble.testing import test_utils

# -----------------------------------------------------------------------------
# Handshake result codes 0x05..0x0D are reserved by the HID Profile 1.1
# specification (section 3.1.2.1, Table 3.2), so a peer may legitimately
# send a value that Bumble does not name.
RESERVED_HANDSHAKE_CODES = tuple(range(0x05, 0x0E))


# -----------------------------------------------------------------------------
async def open_control_channel(
    devices: test_utils.TwoDevices,
) -> tuple[l2cap.ClassicChannel, asyncio.Queue[bytes]]:
    '''Open an L2CAP channel to the HID control PSM and capture what comes back.'''
    channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.ClassicChannelSpec(hid.HID_CONTROL_PSM)
    )
    received = asyncio.Queue[bytes]()
    channel.sink = received.put_nowait
    return channel, received


# -----------------------------------------------------------------------------
def make_hid_device(devices: test_utils.TwoDevices) -> hid.Device:
    '''A HID device with the application callbacks a real one would register.'''
    hid_device = hid.Device(devices[1])
    hid_device.register_get_report_cb(
        lambda report_id, report_type, buffer_size: hid.Device.GetSetStatus(
            data=b'\xaa', status=hid.Device.GetSetReturn.SUCCESS
        )
    )
    hid_device.register_set_report_cb(
        lambda report_id, report_type, report_size, data: hid.Device.GetSetStatus(
            status=hid.Device.GetSetReturn.SUCCESS
        )
    )
    return hid_device


# -----------------------------------------------------------------------------
@pytest.mark.parametrize('result_code', RESERVED_HANDSHAKE_CODES)
def test_reserved_handshake_result_code_does_not_raise(result_code: int) -> None:
    '''A reserved HANDSHAKE result code must be reported, not raise ValueError.'''
    assert hid.Message.Handshake(result_code) == result_code


# -----------------------------------------------------------------------------
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


# -----------------------------------------------------------------------------
async def test_host_handles_defined_handshake_result_code() -> None:
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    hid_host = hid.Host(devices[1])
    handshakes: list[int] = []
    hid_host.on(hid_host.EVENT_HANDSHAKE, handshakes.append)

    channel, _ = await open_control_channel(devices)
    channel.write(bytes([hid.Message.Handshake.ERR_FATAL]))
    await test_utils.async_barrier()

    assert handshakes == [hid.Message.Handshake.ERR_FATAL]


# -----------------------------------------------------------------------------
@pytest.mark.parametrize('role', ('host', 'device'))
async def test_empty_control_pdu_is_ignored(role: str) -> None:
    '''An empty control PDU must be dropped rather than raise IndexError.

    The PDU is delivered from the L2CAP receive path, so an exception raised
    while handling it surfaces on the event loop rather than at the call site.
    '''
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    if role == 'host':
        hid.Host(devices[1])
    else:
        make_hid_device(devices)

    loop = asyncio.get_running_loop()
    escaped: list[BaseException] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(
        lambda _loop, context: escaped.append(context['exception'])
    )
    try:
        channel, received = await open_control_channel(devices)
        channel.write(b'')
        await test_utils.async_barrier()
    finally:
        loop.set_exception_handler(previous_handler)

    assert not escaped
    assert received.empty()


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'pdu',
    (
        bytes([0x40]),  # GET_REPORT, no report ID
        bytes([0x48, 0x01]),  # GET_REPORT, buffer flag set, no buffer size
        bytes([0x48, 0x01, 0x20]),  # GET_REPORT, buffer flag set, truncated size
        bytes([0x50]),  # SET_REPORT, no report ID
    ),
    ids=('get_report', 'get_report_no_size', 'get_report_short_size', 'set_report'),
)
async def test_truncated_report_pdu_is_rejected(pdu: bytes) -> None:
    '''A GET/SET_REPORT shorter than the format Bumble implements must be
    answered, not raise IndexError.
    '''
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    make_hid_device(devices)

    channel, received = await open_control_channel(devices)
    channel.write(pdu)
    await test_utils.async_barrier()

    assert received.get_nowait() == bytes([hid.Message.Handshake.ERR_INVALID_PARAMETER])


# -----------------------------------------------------------------------------
async def test_well_formed_get_report_still_works() -> None:
    devices = test_utils.TwoDevices()
    await devices.setup_connection()
    make_hid_device(devices)

    channel, received = await open_control_channel(devices)
    channel.write(bytes([0x40 | hid.Message.ReportType.INPUT_REPORT, 0x01]))
    await test_utils.async_barrier()

    # DATA message carrying the report ID followed by the report payload.
    assert received.get_nowait() == bytes(
        [
            (hid.Message.MessageType.DATA << 4) | hid.Message.ReportType.INPUT_REPORT,
            0x01,
            0xAA,
        ]
    )


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    pytest.main([__file__])
