# Copyright 2021-2024 Google LLC
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
import pytest
import struct
from unittest import mock

from bumble import device as bumble_device
from bumble.profiles import asha

from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
HI_SYNC_ID = b'\x00\x01\x02\x03\x04\x05\x06\x07'
TIMEOUT = 0.1


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_only_properties():
    devices = TwoDevices()
    await devices.setup_connection()

    asha_service = asha.AshaService(
        hisyncid=HI_SYNC_ID,
        device=devices[0],
        protocol_version=0x01,
        capability=0x02,
        feature_map=0x03,
        render_delay_milliseconds=0x04,
        supported_codecs=0x05,
    )
    devices[0].add_service(asha_service)

    async with bumble_device.Peer(devices.connections[1]) as peer:
        asha_client = peer.create_service_proxy(asha.AshaServiceProxy)
        assert asha_client

        read_only_properties = (
            await asha_client.read_only_properties_characteristic.read_value()
        )
        (
            protocol_version,
            capabilities,
            hi_sync_id,
            feature_map,
            render_delay_milliseconds,
            _,
            supported_codecs,
        ) = struct.unpack("<BB8sBHHH", read_only_properties)
        assert protocol_version == 0x01
        assert capabilities == 0x02
        assert hi_sync_id == HI_SYNC_ID
        assert feature_map == 0x03
        assert render_delay_milliseconds == 0x04
        assert supported_codecs == 0x05


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_psm():
    devices = TwoDevices()
    await devices.setup_connection()

    asha_service = asha.AshaService(
        hisyncid=HI_SYNC_ID,
        device=devices[0],
        capability=0,
    )
    devices[0].add_service(asha_service)

    async with bumble_device.Peer(devices.connections[1]) as peer:
        asha_client = peer.create_service_proxy(asha.AshaServiceProxy)
        assert asha_client

        psm = (await asha_client.psm_characteristic.read_value())[0]
        assert psm == asha_service.psm


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_write_audio_control_point_start():
    devices = TwoDevices()
    await devices.setup_connection()

    asha_service = asha.AshaService(
        hisyncid=HI_SYNC_ID,
        device=devices[0],
        capability=0,
    )
    devices[0].add_service(asha_service)

    async with bumble_device.Peer(devices.connections[1]) as peer:
        asha_client = peer.create_service_proxy(asha.AshaServiceProxy)
        assert asha_client
        status_notifications = asyncio.Queue()
        await asha_client.audio_status_point_characteristic.subscribe(
            status_notifications.put_nowait
        )

        start_cb = mock.MagicMock()
        asha_service.on('started', start_cb)
        await asha_client.audio_control_point_characteristic.write_value(
            bytes(
                [asha.OpCode.START, asha.Codec.G_722_16KHZ, asha.AudioType.MEDIA, 0, 1]
            )
        )
        status = (await asyncio.wait_for(status_notifications.get(), TIMEOUT))[0]
        assert status == asha.AudioStatus.OK

        start_cb.assert_called_once()
        assert asha_service.active_codec == asha.Codec.G_722_16KHZ
        assert asha_service.volume == 0
        assert asha_service.other_state == 1
        assert asha_service.audio_type == asha.AudioType.MEDIA


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_write_audio_control_point_stop():
    devices = TwoDevices()
    await devices.setup_connection()

    asha_service = asha.AshaService(
        hisyncid=HI_SYNC_ID,
        device=devices[0],
        capability=0,
    )
    devices[0].add_service(asha_service)

    async with bumble_device.Peer(devices.connections[1]) as peer:
        asha_client = peer.create_service_proxy(asha.AshaServiceProxy)
        assert asha_client
        status_notifications = asyncio.Queue()
        await asha_client.audio_status_point_characteristic.subscribe(
            status_notifications.put_nowait
        )

        stop_cb = mock.MagicMock()
        asha_service.on('stopped', stop_cb)
        await asha_client.audio_control_point_characteristic.write_value(
            bytes([asha.OpCode.STOP])
        )
        status = (await asyncio.wait_for(status_notifications.get(), TIMEOUT))[0]
        assert status == asha.AudioStatus.OK

        stop_cb.assert_called_once()
        assert asha_service.active_codec is None
        assert asha_service.volume is None
        assert asha_service.other_state is None
        assert asha_service.audio_type is None
