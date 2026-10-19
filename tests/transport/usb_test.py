# Copyright 2026 Google LLC
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
from unittest import mock

import pytest

from bumble import hci
from bumble.transport import usb


def test_safe_call_soon_ignores_closed_loop():
    closed_loop = asyncio.new_event_loop()
    closed_loop.close()
    callback = mock.Mock()

    usb._safe_call_soon(closed_loop, callback)

    callback.assert_not_called()


@pytest.mark.asyncio
async def test_safe_call_soon_schedules_callback_on_open_loop():
    called = asyncio.Event()
    args = []

    def callback(value):
        args.append(value)
        called.set()

    usb._safe_call_soon(asyncio.get_running_loop(), callback, 'scheduled')

    await asyncio.wait_for(called.wait(), timeout=1.0)
    assert args == ['scheduled']


@pytest.mark.asyncio
async def test_usb_packet_sink_iso_routing():
    # Mock usb1 device and endpoints
    mock_device = mock.Mock()
    mock_bulk_out = mock.Mock()
    mock_bulk_out.getAddress.return_value = 0x02

    # Scenario 1: Isochronous endpoints are not enabled (isochronous_out is None)
    mock_transfer = mock.Mock()
    mock_device.getTransfer.return_value = mock_transfer

    sink = usb.UsbPacketSink(mock_device, mock_bulk_out, isochronous_out=None)
    sink.start()

    # Send HCI_ISO_DATA_PACKET
    iso_packet = bytes([hci.HCI_ISO_DATA_PACKET, 0x01, 0x02, 0x03])
    sink.on_packet(iso_packet)

    # Yield control to let the queue processor run
    await asyncio.sleep(0.01)

    # Verify it was sent via bulk transfer
    mock_transfer.setBulk.assert_called_once_with(
        0x02,
        bytes([0x01, 0x02, 0x03]),
        callback=sink.transfer_callback,
    )
    mock_transfer.submit.assert_called_once()

    if sink.queue_task:
        sink.queue_task.cancel()
        try:
            await sink.queue_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_usb_packet_sink_iso_routing_with_iso_endpoint():
    # Mock usb1 device and endpoints
    mock_device = mock.Mock()
    mock_bulk_out = mock.Mock()
    mock_bulk_out.getAddress.return_value = 0x02
    mock_iso_out = mock.Mock()
    mock_iso_out.getMaxPacketSize.return_value = 64

    # Scenario 2: Isochronous endpoints are enabled
    mock_transfer_bulk = mock.Mock()
    mock_transfer_iso = mock.Mock()

    # getTransfer is called twice: once for bulk_or_control and once for isochronous
    mock_device.getTransfer.side_effect = [mock_transfer_bulk, mock_transfer_iso]

    sink = usb.UsbPacketSink(mock_device, mock_bulk_out, isochronous_out=mock_iso_out)
    sink.start()

    # Send HCI_ISO_DATA_PACKET
    iso_packet = bytes([hci.HCI_ISO_DATA_PACKET, 0x01, 0x02, 0x03])
    sink.on_packet(iso_packet)

    # Yield control to let the queue processor run
    await asyncio.sleep(0.01)

    # Verify it was NOT sent via bulk transfer
    mock_transfer_bulk.setBulk.assert_not_called()

    if sink.queue_task:
        sink.queue_task.cancel()
        try:
            await sink.queue_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('interface_number', 'request_type'),
    [
        # Single function controller: addressed to the device
        (0, 0x20),
        # Controller behind other functions in a composite device: addressed to
        # its interface
        (2, 0x21),
    ],
)
async def test_usb_packet_sink_command_addressing(interface_number, request_type):
    mock_device = mock.Mock()
    mock_bulk_out = mock.Mock()
    mock_transfer = mock.Mock()
    mock_device.getTransfer.return_value = mock_transfer

    sink = usb.UsbPacketSink(
        mock_device,
        mock_bulk_out,
        isochronous_out=None,
        interface_number=interface_number,
    )
    sink.start()

    # Send HCI_Reset
    sink.on_packet(bytes([hci.HCI_COMMAND_PACKET, 0x03, 0x0C, 0x00]))

    # Yield control to let the queue processor run
    await asyncio.sleep(0.01)

    mock_transfer.setControl.assert_called_once_with(
        request_type,
        0,
        0,
        interface_number,
        bytes([0x03, 0x0C, 0x00]),
        callback=sink.transfer_callback,
    )
    mock_transfer.submit.assert_called_once()

    if sink.queue_task:
        sink.queue_task.cancel()
        try:
            await sink.queue_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'device_class',
    [
        # Class defined per interface
        0x00,
        # Miscellaneous: composite device with interface associations
        0xEF,
    ],
)
async def test_open_usb_transport_by_index_checks_interfaces(device_class):
    # A Bluetooth interface without endpoints: enough to be selected by index,
    # but not to open a transport
    setting = mock.MagicMock()
    setting.getClass.return_value = 0xE0
    setting.getSubClass.return_value = 0x01
    setting.getProtocol.return_value = 0x01
    setting.__iter__.side_effect = lambda: iter([])
    interface = mock.MagicMock()
    interface.__iter__.side_effect = lambda: iter([setting])
    configuration = mock.MagicMock()
    configuration.__iter__.side_effect = lambda: iter([interface])
    device = mock.MagicMock()
    device.getDeviceClass.return_value = device_class
    device.getDeviceSubClass.return_value = 0x02
    device.getDeviceProtocol.return_value = 0x01
    device.__iter__.side_effect = lambda: iter([configuration])
    context = mock.Mock()
    context.getDeviceIterator.return_value = [device]

    with (
        mock.patch.object(usb, 'load_libusb'),
        mock.patch.object(usb.usb1, 'USBContext', return_value=context),
        pytest.raises(usb.TransportInitError, match='no compatible interface'),
    ):
        await usb.open_usb_transport('0')


@pytest.mark.asyncio
async def test_usb_packet_source_acl_ordering():
    source = usb.UsbPacketSource(
        mock.Mock(),
        {},
        mock.Mock(),
        mock.Mock(),
        None,
        intr_interval=0.05,
    )
    acl = b'\x00\x28\x02\x00\xaa\xbb'
    enc_event = b'\x08\x04\x00\x00\x08\x01'
    disconn_event = bytes(
        [hci.HCI_DISCONNECTION_COMPLETE_EVENT, 0x04, 0x00, 0x00, 0x08, 0x13]
    )

    # 1. Event arrives while ACL is deferred -> Event is queued before ACL.
    source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl)
    source.splitters[hci.HCI_EVENT_PACKET].feed(enc_event)
    await asyncio.sleep(0)
    assert source.queue.get_nowait() == bytes([hci.HCI_EVENT_PACKET]) + enc_event
    assert source.queue.get_nowait() == bytes([hci.HCI_ACL_DATA_PACKET]) + acl

    # 2. Disconnection Complete arrives while ACL is deferred -> ACL is flushed
    # immediately before the timer expires, ahead of Disconnection Complete.
    source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl)
    source.splitters[hci.HCI_EVENT_PACKET].feed(disconn_event)
    await asyncio.sleep(0)
    assert source.acl_flush_handle is None
    assert len(source.acl_queue) == 0
    assert source.queue.get_nowait() == bytes([hci.HCI_ACL_DATA_PACKET]) + acl
    assert source.queue.get_nowait() == bytes([hci.HCI_EVENT_PACKET]) + disconn_event

    # 3. Standalone ACL packet remains deferred after _enqueue_packet runs, and is
    # flushed only after intr_interval expires.
    source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl)
    await asyncio.sleep(0)
    assert source.queue.empty()
    assert len(source.acl_queue) == 1
    assert await asyncio.wait_for(source.queue.get(), timeout=1.0) == (
        bytes([hci.HCI_ACL_DATA_PACKET]) + acl
    )
    source.close()


@pytest.mark.asyncio
async def test_usb_packet_source_staggered_acl_deadlines():
    loop = asyncio.get_running_loop()
    now = 100.0
    with mock.patch.object(loop, 'time', side_effect=lambda: now):
        source = usb.UsbPacketSource(
            mock.Mock(),
            {},
            mock.Mock(),
            mock.Mock(),
            None,
            intr_interval=0.04,
        )
        acl_1 = b'\x00\x28\x02\x00\x01\x01'
        acl_2 = b'\x00\x28\x02\x00\x02\x02'

        source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl_1)
        await asyncio.sleep(0)
        now = 100.02
        source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl_2)
        await asyncio.sleep(0)
        assert len(source.acl_queue) == 2

        # When acl_1's deadline (100.04) expires, acl_2 (100.06) remains deferred.
        now = 100.04
        assert await asyncio.wait_for(source.queue.get(), timeout=1.0) == (
            bytes([hci.HCI_ACL_DATA_PACKET]) + acl_1
        )
        assert source.queue.empty()
        assert len(source.acl_queue) == 1

        now = 100.06
        assert await asyncio.wait_for(source.queue.get(), timeout=1.0) == (
            bytes([hci.HCI_ACL_DATA_PACKET]) + acl_2
        )
        source.close()


@pytest.mark.asyncio
async def test_usb_packet_source_close_cancels_pending_timer():
    source = usb.UsbPacketSource(
        mock.Mock(),
        {},
        mock.Mock(),
        mock.Mock(),
        None,
        intr_interval=0.03,
    )
    acl = b'\x00\x28\x02\x00\xaa\xbb'

    # 1. _clear_acl_queue() directly cancels pending timer and clears acl_queue.
    source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl)
    await asyncio.sleep(0)
    assert source.acl_flush_handle is not None
    assert len(source.acl_queue) == 1
    source._clear_acl_queue()
    assert source.acl_flush_handle is None
    assert len(source.acl_queue) == 0

    # 2. on_transport_lost() cancels pending timer and clears acl_queue.
    source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl)
    await asyncio.sleep(0)
    assert source.acl_flush_handle is not None
    assert len(source.acl_queue) == 1
    source.on_transport_lost()
    assert source.acl_flush_handle is None
    assert len(source.acl_queue) == 0

    # 3. close() cancels pending timer and clears acl_queue.
    source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl)
    await asyncio.sleep(0)
    assert source.acl_flush_handle is not None
    assert len(source.acl_queue) == 1

    source.close()
    assert source.acl_flush_handle is None
    assert len(source.acl_queue) == 0

    await asyncio.sleep(0.04)
    assert source.queue.empty()


@pytest.mark.asyncio
async def test_usb_packet_source_zero_intr_interval_bypass():
    source = usb.UsbPacketSource(
        mock.Mock(),
        {},
        mock.Mock(),
        mock.Mock(),
        None,
        intr_interval=0,
    )
    acl = b'\x00\x28\x02\x00\xaa\xbb'

    source.splitters[hci.HCI_ACL_DATA_PACKET].feed(acl)
    await asyncio.sleep(0)
    assert source.acl_flush_handle is None
    assert len(source.acl_queue) == 0
    assert source.queue.get_nowait() == bytes([hci.HCI_ACL_DATA_PACKET]) + acl
    source.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('speed', 'via_handle', 'b_interval', 'expected'),
    [
        (usb.usb1.SPEED_FULL, False, 1, 0.001),
        (usb.usb1.SPEED_LOW, False, 10, 0.010),
        (usb.usb1.SPEED_HIGH, False, 4, 0.001),
        (usb.usb1.SPEED_HIGH, True, 1, 0.000125),
        (usb.usb1.SPEED_SUPER, True, 4, 0.001),
        (usb.usb1.SPEED_FULL, False, 0, usb.DEFAULT_INTR_INTERVAL),
        (usb.usb1.SPEED_FULL, False, None, usb.DEFAULT_INTR_INTERVAL),
    ],
)
async def test_usb_packet_source_endpoint_interval_derivation(
    speed, via_handle, b_interval, expected
):
    mock_device = mock.Mock(spec=['getDevice'] if via_handle else ['getDeviceSpeed'])
    if via_handle:
        usb_device = mock.Mock(spec=['getDeviceSpeed'])
        usb_device.getDeviceSpeed.return_value = speed
        mock_device.getDevice.return_value = usb_device
    else:
        mock_device.getDeviceSpeed.return_value = speed

    mock_interrupt_in = mock.Mock(spec=['getInterval'])
    mock_interrupt_in.getInterval.return_value = b_interval

    source = usb.UsbPacketSource(
        mock_device,
        {},
        mock_interrupt_in,
        mock.Mock(),
        None,
    )
    assert source.intr_interval == pytest.approx(expected)
    source.close()
