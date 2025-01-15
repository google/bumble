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

from . import test_utils

from bumble import att
from bumble import device
from bumble import gatt
from bumble import hci
from bumble.profiles import rap


# -----------------------------------------------------------------------------
def make_config(role: hci.CsRole, rtt_type: hci.RttType = hci.RttType.AA_ONLY):
    return device.ChannelSoundingConfig(
        config_id=0,
        main_mode_type=0,
        sub_mode_type=0,
        min_main_mode_steps=0,
        max_main_mode_steps=0,
        main_mode_repetition=0,
        mode_0_steps=0,
        role=role,
        rtt_type=rtt_type,
        cs_sync_phy=0,
        channel_map=b'',
        channel_map_repetition=0,
        channel_selection_type=0,
        ch3c_shape=0,
        ch3c_jump=0,
        reserved=0,
        t_ip1_time=0,
        t_ip2_time=0,
        t_fcs_time=0,
        t_pm_time=0,
    )


# -----------------------------------------------------------------------------
async def make_connections(
    ras_features: rap.RasFeatures,
) -> tuple[rap.RangingService, rap.RangingServiceProxy]:
    devices = await test_utils.TwoDevices.create_with_connection()
    assert (server_connection := devices.connections[0])
    assert (client_connection := devices.connections[1])
    # Mock encryption.
    server_connection.encryption = 1
    client_connection.encryption = 1
    server = rap.RangingService(devices[0], ras_features)
    devices[0].add_service(server)

    peer = device.Peer(client_connection)
    client = await peer.discover_service_and_create_proxy(rap.RangingServiceProxy)
    assert client
    return server, client


# -----------------------------------------------------------------------------
def test_parse_ranging_data_initiator_without_sounding_sequence() -> None:
    config = make_config(role=hci.CsRole.INITIATOR)
    expected_ranging_data = rap.RangingData(
        ranging_header=rap.RangingHeader(
            configuration_id=0,
            selected_tx_power=-1,
            antenna_paths_mask=0x0F,
            ranging_counter=2,
        ),
        subevents=[
            rap.Subevent(
                start_acl_connection_event=0,
                frequency_compensation=1,
                ranging_done_status=2,
                ranging_abort_reason=3,
                subevent_abort_reason=4,
                subevent_done_status=5,
                reference_power_level=-2,
                steps=[
                    rap.Step(mode=0, data=bytes(5)),
                    rap.Step(mode=1, data=bytes(6)),
                    rap.Step(mode=2, data=bytes(21)),
                    rap.Step(mode=3, data=bytes(27)),
                ],
            )
        ],
    )

    assert (
        rap.RangingData.from_bytes(bytes(expected_ranging_data), config)
        == expected_ranging_data
    )


# -----------------------------------------------------------------------------
def test_parse_ranging_data_reflector_without_sounding_sequence() -> None:
    config = make_config(role=hci.CsRole.REFLECTOR)
    expected_ranging_data = rap.RangingData(
        ranging_header=rap.RangingHeader(
            configuration_id=0,
            selected_tx_power=-1,
            antenna_paths_mask=0x0F,
            ranging_counter=2,
        ),
        subevents=[
            rap.Subevent(
                start_acl_connection_event=0,
                frequency_compensation=1,
                ranging_done_status=2,
                ranging_abort_reason=3,
                subevent_abort_reason=4,
                subevent_done_status=5,
                reference_power_level=-2,
                steps=[
                    rap.Step(mode=0, data=bytes(3)),
                    rap.Step(mode=1, data=bytes(6)),
                    rap.Step(mode=2, data=bytes(21)),
                    rap.Step(mode=3, data=bytes(27)),
                ],
            )
        ],
    )

    assert (
        rap.RangingData.from_bytes(bytes(expected_ranging_data), config)
        == expected_ranging_data
    )


# -----------------------------------------------------------------------------
def test_parse_ranging_data_initiator_with_sounding_sequence() -> None:
    config = make_config(
        role=hci.CsRole.INITIATOR, rtt_type=hci.RttType.SOUNDING_SEQUENCE_32_BIT
    )
    expected_ranging_data = rap.RangingData(
        ranging_header=rap.RangingHeader(
            configuration_id=0,
            selected_tx_power=-1,
            antenna_paths_mask=0x0F,
            ranging_counter=2,
        ),
        subevents=[
            rap.Subevent(
                start_acl_connection_event=0,
                frequency_compensation=1,
                ranging_done_status=2,
                ranging_abort_reason=3,
                subevent_abort_reason=4,
                subevent_done_status=5,
                reference_power_level=-2,
                steps=[
                    rap.Step(mode=0, data=bytes(5)),
                    rap.Step(mode=1, data=bytes(12)),
                    rap.Step(mode=2, data=bytes(21)),
                    rap.Step(mode=3, data=bytes(33)),
                ],
            )
        ],
    )

    assert (
        rap.RangingData.from_bytes(bytes(expected_ranging_data), config)
        == expected_ranging_data
    )


# -----------------------------------------------------------------------------
def test_parse_ranging_data_reflector_with_sounding_sequence() -> None:
    config = make_config(
        role=hci.CsRole.REFLECTOR,
        rtt_type=hci.RttType.SOUNDING_SEQUENCE_96_BIT,
    )
    expected_ranging_data = rap.RangingData(
        ranging_header=rap.RangingHeader(
            configuration_id=0,
            selected_tx_power=-1,
            antenna_paths_mask=0x0F,
            ranging_counter=2,
        ),
        subevents=[
            rap.Subevent(
                start_acl_connection_event=0,
                frequency_compensation=1,
                ranging_done_status=2,
                ranging_abort_reason=3,
                subevent_abort_reason=4,
                subevent_done_status=5,
                reference_power_level=-2,
                steps=[
                    rap.Step(mode=0, data=bytes(3)),
                    rap.Step(mode=1, data=bytes(12)),
                    rap.Step(mode=2, data=bytes(21)),
                    rap.Step(mode=3, data=bytes(33)),
                ],
            )
        ]
        * 2,
    )

    assert (
        rap.RangingData.from_bytes(bytes(expected_ranging_data), config)
        == expected_ranging_data
    )


# -----------------------------------------------------------------------------
async def test_subscribe_on_demand_cccd() -> None:
    server, client = await make_connections(rap.RasFeatures.REAL_TIME_RANGING_DATA)
    server_connection = next(iter(server.device.connections.values()))

    assert client.real_time_ranging_data_characteristic
    await client.on_demand_ranging_data_characteristic.subscribe(prefer_notify=True)
    assert (
        server.clients[server_connection].active_mode
        == rap.RangingService.Mode.ON_DEMAND
    )
    assert (
        server.clients[server_connection].cccd_value
        == gatt.ClientCharacteristicConfigurationBits.NOTIFICATION
    )
    assert (
        cccd := client.on_demand_ranging_data_characteristic.get_descriptor(
            gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
        )
    )
    assert (
        int.from_bytes(await cccd.read_value(), 'little')
        == gatt.ClientCharacteristicConfigurationBits.NOTIFICATION
    )

    await client.on_demand_ranging_data_characteristic.unsubscribe()
    assert (
        server.clients[server_connection].active_mode
        == rap.RangingService.Mode.INACTIVE
    )


# -----------------------------------------------------------------------------
async def test_subscribe_real_time_cccd() -> None:
    server, client = await make_connections(rap.RasFeatures.REAL_TIME_RANGING_DATA)
    server_connection = next(iter(server.device.connections.values()))

    assert client.real_time_ranging_data_characteristic
    await client.real_time_ranging_data_characteristic.subscribe(prefer_notify=True)
    assert (
        server.clients[server_connection].active_mode
        == rap.RangingService.Mode.REAL_TIME
    )
    assert (
        server.clients[server_connection].cccd_value
        == gatt.ClientCharacteristicConfigurationBits.NOTIFICATION
    )
    assert (
        cccd := client.real_time_ranging_data_characteristic.get_descriptor(
            gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
        )
    )
    assert (
        int.from_bytes(await cccd.read_value(), 'little')
        == gatt.ClientCharacteristicConfigurationBits.NOTIFICATION
    )

    await client.real_time_ranging_data_characteristic.unsubscribe()
    assert (
        server.clients[server_connection].active_mode
        == rap.RangingService.Mode.INACTIVE
    )


# -----------------------------------------------------------------------------
async def test_read_cccd_without_on_inactive() -> None:
    server, client = await make_connections(rap.RasFeatures.REAL_TIME_RANGING_DATA)

    assert client.real_time_ranging_data_characteristic
    await client.real_time_ranging_data_characteristic.discover_descriptors()
    assert (
        cccd := client.real_time_ranging_data_characteristic.get_descriptor(
            gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
        )
    )
    assert (await cccd.read_value()) == bytes(2)


# -----------------------------------------------------------------------------
async def test_subscribe_real_time_when_on_demand_is_on() -> None:
    server, client = await make_connections(rap.RasFeatures.REAL_TIME_RANGING_DATA)
    assert client.real_time_ranging_data_characteristic

    await client.on_demand_ranging_data_characteristic.subscribe(prefer_notify=True)
    with pytest.raises(att.ATT_Error):
        await client.real_time_ranging_data_characteristic.subscribe(prefer_notify=True)


# -----------------------------------------------------------------------------
async def test_subscribe_on_demand_when_real_time_is_on() -> None:
    server, client = await make_connections(rap.RasFeatures.REAL_TIME_RANGING_DATA)
    assert client.real_time_ranging_data_characteristic

    await client.real_time_ranging_data_characteristic.subscribe(prefer_notify=True)
    with pytest.raises(att.ATT_Error):
        await client.on_demand_ranging_data_characteristic.subscribe(prefer_notify=True)


# -----------------------------------------------------------------------------
@pytest.mark.parametrize('prefer_notify,', (True, False))
async def test_send_ranging_data_on_demand(prefer_notify: bool) -> None:
    server, client = await make_connections(rap.RasFeatures.REAL_TIME_RANGING_DATA)
    server_connection = next(iter(server.device.connections.values()))

    notifications = asyncio.Queue[bytes]()
    await client.on_demand_ranging_data_characteristic.subscribe(
        notifications.put_nowait, prefer_notify=prefer_notify
    )
    expected_data = bytes([i % 256 for i in range(4096)])
    await server.send_ranging_data(server_connection, expected_data)

    actual_data = b''
    while True:
        notification = await asyncio.wait_for(notifications.get(), 0.1)
        segmentation_header = rap.SegmentationHeader.from_bytes(notification)
        actual_data += notification[1:]
        if segmentation_header.is_last:
            break
    assert actual_data == expected_data


# -----------------------------------------------------------------------------
@pytest.mark.parametrize('prefer_notify,', (True, False))
async def test_send_ranging_data_real_time(prefer_notify: bool) -> None:
    server, client = await make_connections(rap.RasFeatures.REAL_TIME_RANGING_DATA)
    assert client.real_time_ranging_data_characteristic
    server_connection = next(iter(server.device.connections.values()))

    notifications = asyncio.Queue[bytes]()
    await client.real_time_ranging_data_characteristic.subscribe(
        notifications.put_nowait, prefer_notify=prefer_notify
    )
    expected_data = bytes([i % 256 for i in range(4096)])
    await server.send_ranging_data(server_connection, expected_data)

    actual_data = b''
    while True:
        notification = await asyncio.wait_for(notifications.get(), 0.1)
        segmentation_header = rap.SegmentationHeader.from_bytes(notification)
        actual_data += notification[1:]
        if segmentation_header.is_last:
            break
    assert actual_data == expected_data


# -----------------------------------------------------------------------------
async def test_send_ranging_data_inactive() -> None:
    server, client = await make_connections(rap.RasFeatures.REAL_TIME_RANGING_DATA)
    server_connection = next(iter(server.device.connections.values()))
    await client.on_demand_ranging_data_characteristic.subscribe()
    await client.on_demand_ranging_data_characteristic.unsubscribe()

    expected_data = bytes([i % 256 for i in range(4096)])
    await server.send_ranging_data(server_connection, expected_data)
