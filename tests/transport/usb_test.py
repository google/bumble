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

    # getTransfer is called once for bulk_or_control, then for each isochronous transfer
    mock_device.getTransfer.side_effect = [mock_transfer_bulk] + [
        mock_transfer_iso
    ] * usb.NUMBER_OF_SCO_OUT_TRANSFERS

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


# -----------------------------------------------------------------------------
def _make_sco_sink(iso_max_packet_size: int, sco_alternate_setting: int = 0):
    mock_device = mock.Mock()
    mock_bulk_out = mock.Mock()
    mock_iso_out = mock.Mock()
    mock_iso_out.getAddress.return_value = 0x03
    mock_iso_out.getMaxPacketSize.return_value = iso_max_packet_size
    sent_packets: list[bytes] = []
    iso_transfers = [mock.Mock() for _ in range(usb.NUMBER_OF_SCO_OUT_TRANSFERS)]
    for transfer in iso_transfers:
        transfer.isSubmitted.return_value = False
        # Record the packets in the order they are sent.
        transfer.setIsochronous.side_effect = (
            lambda _address, buffer, **_kwargs: sent_packets.append(buffer)
        )
    mock_device.getTransfer.side_effect = [mock.Mock()] + iso_transfers
    sink = usb.UsbPacketSink(
        mock_device,
        mock_bulk_out,
        isochronous_out=mock_iso_out,
        sco_alternate_setting=sco_alternate_setting,
    )
    return sink, iso_transfers, sent_packets


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('iso_max_packet_size', 'sco_packet_data_size'),
    [
        # Alternate setting 1
        (9, 24),
        # Alternate setting 2
        (17, 48),
    ],
)
async def test_usb_packet_sink_sco_repacketization(
    iso_max_packet_size, sco_packet_data_size
):
    sink, iso_transfers, sent_packets = _make_sco_sink(iso_max_packet_size)
    assert sink.sco_packet_data_size == sco_packet_data_size
    sink.start()

    # 2 SCO packets of 60 bytes on handle 0x0101, sent faster than they complete.
    data = bytes(range(120))
    for i in (0, 60):
        sink.on_packet(
            bytes([hci.HCI_SYNCHRONOUS_DATA_PACKET, 0x01, 0x01, 60]) + data[i : i + 60]
        )
    await asyncio.sleep(0.01)

    expected_packets = [
        bytes([0x01, 0x01, sco_packet_data_size]) + data[i : i + sco_packet_data_size]
        for i in range(
            0,
            len(data) // sco_packet_data_size * sco_packet_data_size,
            sco_packet_data_size,
        )
    ]
    in_flight = min(len(expected_packets), usb.NUMBER_OF_SCO_OUT_TRANSFERS)
    # Several transfers are in flight at the same time.
    assert sent_packets == expected_packets[:in_flight]
    for transfer in iso_transfers:
        for call in transfer.setIsochronous.call_args_list:
            assert (
                call.kwargs['iso_transfer_length_list']
                == [iso_max_packet_size] * usb.USB_FRAMES_PER_SCO_PACKET
            )

    # Completing transfers lets the remaining packets go.
    for transfer in iso_transfers:
        transfer.getStatus.return_value = usb.usb1.TRANSFER_COMPLETED
        if transfer.setIsochronous.called:
            sink.sco_transfer_callback(transfer)
    await asyncio.sleep(0.01)
    assert sent_packets == expected_packets

    # The remainder is kept until more data comes in.
    assert len(sink.sco_buffers[0x0101]) == len(data) % sco_packet_data_size

    await sink.terminate()


def _make_sco_setting(alternate: int, max_packet_size: int):
    setting = mock.MagicMock()
    setting.getClass.return_value = 0xE0
    setting.getSubClass.return_value = 0x01
    setting.getProtocol.return_value = 0x01
    setting.getAlternateSetting.return_value = alternate
    endpoints = []
    for address in (0x83, 0x03):
        endpoint = mock.Mock()
        endpoint.getAttributes.return_value = usb.USB_ENDPOINT_TRANSFER_TYPE_ISOCHRONOUS
        endpoint.getAddress.return_value = address
        endpoint.getMaxPacketSize.return_value = max_packet_size
        endpoints.append(endpoint)
    setting.__iter__.side_effect = lambda: iter(endpoints)
    return setting, endpoints


def _make_acl_setting():
    setting = mock.MagicMock()
    setting.getClass.return_value = 0xE0
    setting.getSubClass.return_value = 0x01
    setting.getProtocol.return_value = 0x01
    endpoints = []
    for attributes, address in (
        (usb.USB_ENDPOINT_TRANSFER_TYPE_INTERRUPT, 0x81),
        (usb.USB_ENDPOINT_TRANSFER_TYPE_BULK, 0x82),
        (usb.USB_ENDPOINT_TRANSFER_TYPE_BULK, 0x02),
    ):
        endpoint = mock.Mock()
        endpoint.getAttributes.return_value = attributes
        endpoint.getAddress.return_value = address
        endpoints.append(endpoint)
    setting.__iter__.side_effect = lambda: iter(endpoints)
    return setting


@pytest.mark.parametrize(
    ('sco_alternate', 'expected_alternate'),
    [
        (1, 1),
        (2, 2),
        # Largest max packet size, which isn't the last setting here.
        (0, 2),
    ],
)
def test_find_endpoints_returns_selected_sco_endpoints(
    sco_alternate, expected_alternate
):
    acl_interface = mock.MagicMock()
    acl_setting = _make_acl_setting()
    acl_interface.__iter__.side_effect = lambda: iter([acl_setting])
    sco_settings = {
        1: _make_sco_setting(1, 9),
        2: _make_sco_setting(2, 17),
        3: _make_sco_setting(3, 13),
    }
    sco_interface = mock.MagicMock()
    sco_interface.__iter__.side_effect = lambda: iter(
        [setting for setting, _ in sco_settings.values()]
    )
    configuration = mock.MagicMock()
    configuration.__iter__.side_effect = lambda: iter([acl_interface, sco_interface])
    device = mock.MagicMock()
    device.__iter__.side_effect = lambda: iter([configuration])

    endpoints = usb.find_endpoints(device, False, sco_alternate)

    assert endpoints is not None
    _, _, selected_setting, _, _, isochronous_in, _, isochronous_out = endpoints
    expected_setting, (expected_in, expected_out) = sco_settings[expected_alternate]
    assert selected_setting is expected_setting
    assert isochronous_in is expected_in
    assert isochronous_out is expected_out


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_usb_packet_sink_sco_alternate_setting_6():
    sink, iso_transfers, sent_packets = _make_sco_sink(63, sco_alternate_setting=6)
    # One codec frame (60 bytes) per HCI SCO packet, in a single USB frame.
    assert sink.sco_packet_data_size == 60
    sink.start()

    frames = [bytes([i]) * 60 for i in range(2)]
    for frame in frames:
        sink.on_packet(bytes([hci.HCI_SYNCHRONOUS_DATA_PACKET, 0x0A, 0x01, 60]) + frame)
    await asyncio.sleep(0.01)

    assert sent_packets == [bytes([0x0A, 0x01, 60]) + frame for frame in frames]
    for transfer in iso_transfers:
        for call in transfer.setIsochronous.call_args_list:
            assert call.kwargs['iso_transfer_length_list'] == [63]

    await sink.terminate()


def _make_dynamic_sco_transport(alternate_settings):
    transport = usb.UsbTransport.__new__(usb.UsbTransport)
    transport.device = mock.Mock()
    transport.sco_interface = mock.Mock()
    transport.sco_interface.getNumber.return_value = 1
    transport.usb_source = mock.Mock()
    transport.usb_sink = mock.Mock()
    sco_settings = {
        alternate_setting: (mock.Mock(name=f'in{alternate_setting}'), mock.Mock())
        for alternate_setting in alternate_settings
    }
    transport.enable_dynamic_sco_alternate_setting(sco_settings)
    return transport, sco_settings


def _sync_connection_complete(handle: int, air_mode: int) -> bytes:
    parameters = (
        bytes([hci.HCI_SUCCESS])
        + handle.to_bytes(2, 'little')
        + bytes(6)  # BD_ADDR
        + bytes([0x02, 0x0C, 0x06])  # Link_Type, Transmission_Interval, Window
        + (60).to_bytes(2, 'little')  # RX_Packet_Length
        + (60).to_bytes(2, 'little')  # TX_Packet_Length
        + bytes([air_mode])
    )
    return (
        bytes(
            [
                hci.HCI_EVENT_PACKET,
                hci.HCI_SYNCHRONOUS_CONNECTION_COMPLETE_EVENT,
                len(parameters),
            ]
        )
        + parameters
    )


def _disconnection_complete(handle: int) -> bytes:
    return (
        bytes([hci.HCI_EVENT_PACKET, hci.HCI_DISCONNECTION_COMPLETE_EVENT, 4, 0])
        + handle.to_bytes(2, 'little')
        + bytes([0x13])
    )


def _current_alternate_setting(transport) -> int:
    return transport.device.setInterfaceAltSetting.call_args.args[1]


@pytest.mark.parametrize(
    ('alternate_settings', 'expected_alternate_setting'),
    [
        ((1, 2, 3, 4, 5, 6), 6),
        # Without alternate setting 6, fall back to alternate setting 1
        ((1, 2, 3, 4, 5), 1),
    ],
)
def test_dynamic_sco_alternate_setting_transparent(
    alternate_settings, expected_alternate_setting
):
    transport, sco_settings = _make_dynamic_sco_transport(alternate_settings)
    # No SCO link: alternate setting 0
    assert _current_alternate_setting(transport) == 0
    transport.usb_source.start_sco.assert_not_called()

    transport.on_event_for_sco(
        _sync_connection_complete(0x010A, hci.CodecID.TRANSPARENT)
    )
    assert _current_alternate_setting(transport) == expected_alternate_setting
    isochronous_in, isochronous_out = sco_settings[expected_alternate_setting]
    transport.usb_source.start_sco.assert_called_once_with(isochronous_in)
    transport.usb_sink.configure_sco.assert_called_once_with(
        isochronous_out, expected_alternate_setting
    )

    transport.on_event_for_sco(_disconnection_complete(0x010A))
    assert _current_alternate_setting(transport) == 0


def test_dynamic_sco_alternate_setting_cvsd():
    transport, _ = _make_dynamic_sco_transport((1, 2, 3, 4, 5, 6))

    # 16-bit samples (default): 2, 4 and 5 for 1, 2 and 3 links
    transport.on_event_for_sco(_sync_connection_complete(0x0101, 0x02))
    assert _current_alternate_setting(transport) == 2
    transport.on_event_for_sco(_sync_connection_complete(0x0102, 0x02))
    assert _current_alternate_setting(transport) == 4
    transport.on_event_for_sco(_disconnection_complete(0x0102))
    assert _current_alternate_setting(transport) == 2
    transport.on_event_for_sco(_disconnection_complete(0x0101))
    assert _current_alternate_setting(transport) == 0

    # 8-bit samples (Voice_Setting input sample size bit cleared): number of links
    transport.on_command_for_sco(
        bytes([hci.HCI_COMMAND_PACKET])
        + hci.HCI_WRITE_VOICE_SETTING_COMMAND.to_bytes(2, 'little')
        + bytes([2, 0x40, 0x00])
    )
    transport.on_event_for_sco(_sync_connection_complete(0x0101, 0x02))
    assert _current_alternate_setting(transport) == 1


@pytest.mark.asyncio
async def test_usb_packet_source_drops_empty_sco_packets():
    source = usb.UsbPacketSource(mock.Mock(), {}, None, None, None)
    source.queue_packet(hci.HCI_SYNCHRONOUS_DATA_PACKET, bytes([0x0A, 0x01, 0]))
    source.queue_packet(hci.HCI_SYNCHRONOUS_DATA_PACKET, bytes([0x0A, 0x01, 1, 0xAB]))
    await asyncio.sleep(0.01)
    assert source.queue.qsize() == 1
    assert source.queue.get_nowait() == bytes(
        [hci.HCI_SYNCHRONOUS_DATA_PACKET, 0x0A, 0x01, 1, 0xAB]
    )
