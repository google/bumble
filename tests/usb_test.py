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
