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
import functools
import inspect
import logging
import os
from unittest import mock

import pytest

from bumble import gatt, hci, smp, utils
from bumble.core import (
    AdvertisingData,
    InvalidStateError,
    OutOfResourcesError,
    PhysicalTransport,
)
from bumble.device import (
    Advertisement,
    AdvertisingEventProperties,
    AdvertisingParameters,
    BigParameters,
    BigSyncParameters,
    CigParameters,
    CisLink,
    Connection,
    Device,
    DeviceConfiguration,
    PeriodicAdvertisingParameters,
    PeriodicAdvertisingSync,
)
from bumble.hci import (
    HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
    HCI_COMMAND_STATUS_PENDING,
    HCI_CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR,
    HCI_CREATE_CONNECTION_COMMAND,
    HCI_SUCCESS,
    Address,
    HCI_Command_Status_Event,
    HCI_Connection_Complete_Event,
    HCI_Connection_Request_Event,
    HCI_Error,
    HCI_Packet,
    OwnAddressType,
    Role,
)
from bumble.host import DataPacketQueue, Host
from bumble.keys import MemoryKeyStore, PairingKeys
from bumble.pairing import PairingConfig, PairingDelegate
from bumble.testing.test_utils import TwoDevices, async_barrier

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
_TIMEOUT = 0.1

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class Sink:
    def __init__(self, flow):
        self.flow = flow
        next(self.flow)

    def on_packet(self, packet):
        self.flow.send(packet)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_device_connect_parallel():
    d0 = Device(host=Host(None, None))
    d1 = Device(host=Host(None, None))
    d2 = Device(host=Host(None, None))

    def _send(packet):
        pass

    d0.host.acl_packet_queue = DataPacketQueue(0, 0, _send)
    d1.host.acl_packet_queue = DataPacketQueue(0, 0, _send)
    d2.host.acl_packet_queue = DataPacketQueue(0, 0, _send)

    # enable classic
    d0.classic_enabled = True
    d1.classic_enabled = True
    d2.classic_enabled = True

    # set public addresses
    d0.public_address = Address(
        'F0:F1:F2:F3:F4:F5', address_type=Address.PUBLIC_DEVICE_ADDRESS
    )
    d1.public_address = Address(
        'F5:F4:F3:F2:F1:F0', address_type=Address.PUBLIC_DEVICE_ADDRESS
    )
    d2.public_address = Address(
        'F5:F4:F3:F3:F4:F5', address_type=Address.PUBLIC_DEVICE_ADDRESS
    )

    def d0_flow():
        packet = HCI_Packet.from_bytes((yield))
        assert packet.name == 'HCI_CREATE_CONNECTION_COMMAND'
        assert packet.bd_addr == d1.public_address

        d0.host.on_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=HCI_CREATE_CONNECTION_COMMAND,
            )
        )

        d1.host.on_hci_packet(
            HCI_Connection_Request_Event(
                bd_addr=d0.public_address,
                class_of_device=0,
                link_type=HCI_Connection_Complete_Event.LinkType.ACL,
            )
        )

        packet = HCI_Packet.from_bytes((yield))
        assert packet.name == 'HCI_CREATE_CONNECTION_COMMAND'
        assert packet.bd_addr == d2.public_address

        d0.host.on_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=HCI_CREATE_CONNECTION_COMMAND,
            )
        )

        d2.host.on_hci_packet(
            HCI_Connection_Request_Event(
                bd_addr=d0.public_address,
                class_of_device=0,
                link_type=HCI_Connection_Complete_Event.LinkType.ACL,
            )
        )

        assert (yield) is None

    def d1_flow():
        packet = HCI_Packet.from_bytes((yield))
        assert packet.name == 'HCI_ACCEPT_CONNECTION_REQUEST_COMMAND'

        d1.host.on_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
            )
        )

        d1.host.on_hci_packet(
            HCI_Connection_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=0x100,
                bd_addr=d0.public_address,
                link_type=HCI_Connection_Complete_Event.LinkType.ACL,
                encryption_enabled=True,
            )
        )

        d0.host.on_hci_packet(
            HCI_Connection_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=0x100,
                bd_addr=d1.public_address,
                link_type=HCI_Connection_Complete_Event.LinkType.ACL,
                encryption_enabled=True,
            )
        )

        assert (yield) is None

    def d2_flow():
        packet = HCI_Packet.from_bytes((yield))
        assert packet.name == 'HCI_ACCEPT_CONNECTION_REQUEST_COMMAND'

        d2.host.on_hci_packet(
            HCI_Command_Status_Event(
                status=HCI_COMMAND_STATUS_PENDING,
                num_hci_command_packets=1,
                command_opcode=HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
            )
        )

        d2.host.on_hci_packet(
            HCI_Connection_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=0x101,
                bd_addr=d0.public_address,
                link_type=HCI_Connection_Complete_Event.LinkType.ACL,
                encryption_enabled=True,
            )
        )

        d0.host.on_hci_packet(
            HCI_Connection_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=0x101,
                bd_addr=d2.public_address,
                link_type=HCI_Connection_Complete_Event.LinkType.ACL,
                encryption_enabled=True,
            )
        )

        assert (yield) is None

    d0.host.set_packet_sink(Sink(d0_flow()))
    d1.host.set_packet_sink(Sink(d1_flow()))
    d2.host.set_packet_sink(Sink(d2_flow()))

    d1_accept_task = asyncio.create_task(d1.accept(peer_address=d0.public_address))
    d2_accept_task = asyncio.create_task(d2.accept())

    # Ensure that the accept tasks have started.
    await async_barrier()

    [c01, c02, a10, a20] = await asyncio.gather(
        *[
            asyncio.create_task(
                d0.connect(d1.public_address, transport=PhysicalTransport.BR_EDR)
            ),
            asyncio.create_task(
                d0.connect(d2.public_address, transport=PhysicalTransport.BR_EDR)
            ),
            d1_accept_task,
            d2_accept_task,
        ]
    )

    assert isinstance(c01, Connection)
    assert isinstance(c02, Connection)
    assert isinstance(a10, Connection)
    assert isinstance(a20, Connection)

    assert c01.handle == a10.handle and c01.handle == 0x100
    assert c02.handle == a20.handle and c02.handle == 0x101


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_flush():
    d0 = Device(host=Host(None, None))
    task = utils.cancel_on_event(d0, 'flush', asyncio.sleep(10000))
    await d0.host.flush()
    try:
        await task
        assert False
    except asyncio.CancelledError:
        pass


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_legacy_advertising():
    device = TwoDevices()[0]
    await device.power_on()

    # Start advertising
    await device.start_advertising()
    assert device.is_advertising

    # Stop advertising
    await device.stop_advertising()
    assert not device.is_advertising


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'auto_restart',
    (True, False),
)
@pytest.mark.asyncio
async def test_legacy_advertising_disconnection(auto_restart):
    devices = TwoDevices()
    for controller in devices.controllers:
        controller.le_features |= hci.LeFeatureMask.LE_EXTENDED_ADVERTISING
    for dev in devices:
        await dev.power_on()
    await devices[0].start_advertising(
        auto_restart=auto_restart, advertising_interval_min=1.0
    )
    connection = await devices[1].connect(devices[0].random_address)

    await connection.disconnect()

    await async_barrier()
    await async_barrier()

    if auto_restart:
        assert devices[0].legacy_advertising_set
        started = asyncio.Event()
        if not devices[0].is_advertising:
            devices[0].legacy_advertising_set.once('start', started.set)
            await asyncio.wait_for(started.wait(), _TIMEOUT)
        assert devices[0].is_advertising
    else:
        assert not devices[0].is_advertising


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_multiple_connects():
    devices = TwoDevices()
    for controller in devices.controllers:
        controller.le_features |= hci.LeFeatureMask.LE_EXTENDED_ADVERTISING
    for dev in devices:
        await dev.power_on()
    await devices[0].start_advertising(auto_restart=True, advertising_interval_min=1.0)

    connection = await devices[1].connect(devices[0].random_address)
    await connection.disconnect()

    await async_barrier()
    await async_barrier()

    # a second connection attempt is working
    connection = await devices[1].connect(devices[0].random_address)
    await connection.disconnect()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_advertising_and_scanning():
    devices = TwoDevices()
    for dev in devices:
        await dev.power_on()

    # Start scanning
    advertisements = asyncio.Queue[Advertisement]()
    devices[1].on(devices[1].EVENT_ADVERTISEMENT, advertisements.put_nowait)
    await devices[1].start_scanning()

    # Start advertising
    advertising_set = await devices[0].create_advertising_set(advertising_data=b'123')
    assert devices[0].extended_advertising_sets
    assert advertising_set.enabled

    advertisement = await asyncio.wait_for(advertisements.get(), _TIMEOUT)
    assert advertisement.data_bytes == b'123'

    # Stop advertising
    await advertising_set.stop()
    assert not advertising_set.enabled


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'own_address_type',
    (OwnAddressType.PUBLIC, OwnAddressType.RANDOM),
)
@pytest.mark.asyncio
async def test_extended_advertising_connection(own_address_type):
    devices = TwoDevices()
    for dev in devices:
        await dev.power_on()
    advertising_set = await devices[0].create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            own_address_type=own_address_type, primary_advertising_interval_min=1.0
        )
    )
    await asyncio.wait_for(
        devices[1].connect(advertising_set.random_address or devices[0].public_address),
        _TIMEOUT,
    )
    await async_barrier()

    # Advertising set should be terminated after connected.
    assert not advertising_set.enabled

    if own_address_type == OwnAddressType.PUBLIC:
        assert (
            devices[0].lookup_connection(0x0001).self_address
            == devices[0].public_address
        )
    else:
        assert (
            devices[0].lookup_connection(0x0001).self_address
            == devices[0].random_address
        )

    await async_barrier()


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'own_address_type',
    (OwnAddressType.PUBLIC, OwnAddressType.RANDOM),
)
@pytest.mark.asyncio
async def test_extended_advertising_connection_out_of_order(own_address_type):
    devices = TwoDevices()
    device = devices[0]
    devices.controllers[0].le_features |= hci.LeFeatureMask.LE_EXTENDED_ADVERTISING
    await device.power_on()
    advertising_set = await device.create_advertising_set(
        advertising_parameters=AdvertisingParameters(own_address_type=own_address_type)
    )
    device.on_advertising_set_termination(
        HCI_SUCCESS,
        advertising_set.advertising_handle,
        0x0001,
        0,
    )
    device.on_le_connection(
        0x0001,
        Address('F0:F1:F2:F3:F4:F5'),
        None,
        None,
        Role.PERIPHERAL,
        0,
        0,
        0,
    )

    if own_address_type == OwnAddressType.PUBLIC:
        assert device.lookup_connection(0x0001).self_address == device.public_address
    else:
        assert device.lookup_connection(0x0001).self_address == device.random_address

    await async_barrier()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_periodic_advertising():
    device = TwoDevices()[0]
    await device.power_on()

    # Start advertising
    advertising_set = await device.create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            advertising_event_properties=AdvertisingEventProperties(
                is_connectable=False
            )
        ),
        advertising_data=b'123',
        periodic_advertising_parameters=PeriodicAdvertisingParameters(),
        periodic_advertising_data=b'abc',
    )
    assert device.extended_advertising_sets
    assert advertising_set.enabled
    assert not advertising_set.periodic_enabled

    await advertising_set.start_periodic()
    assert advertising_set.periodic_enabled

    await advertising_set.stop_periodic()
    assert not advertising_set.periodic_enabled


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_remote_le_features():
    devices = TwoDevices()
    await devices.setup_connection()

    assert (
        await devices.connections[0].get_remote_le_features()
    ) == devices.controllers[1].le_features


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_remote_le_features_failed():
    devices = TwoDevices()
    await devices.setup_connection()

    def on_hci_le_read_remote_features_complete_event(event):
        devices[0].host.emit(
            'le_remote_features_failure',
            event.connection_handle,
            HCI_CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR,
        )

    devices[0].host.on_hci_le_read_remote_features_complete_event = (
        on_hci_le_read_remote_features_complete_event
    )

    with pytest.raises(HCI_Error):
        await asyncio.wait_for(
            devices.connections[0].get_remote_le_features(), _TIMEOUT
        )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cis():
    devices = TwoDevices()
    await devices.setup_connection()

    peripheral_cis_futures = {}

    def on_cis_request(cis_link: CisLink):
        cis_link.acl_connection.cancel_on_disconnection(
            devices[1].accept_cis_request(cis_link),
        )
        peripheral_cis_futures[cis_link.handle] = (
            asyncio.get_running_loop().create_future()
        )

    devices[1].on('cis_request', on_cis_request)
    devices[1].on(
        'cis_establishment',
        lambda cis_link: peripheral_cis_futures[cis_link.handle].set_result(None),
    )

    cis_handles = await devices[0].setup_cig(
        CigParameters(
            cig_id=1,
            cis_parameters=[
                CigParameters.CisParameters(cis_id=2),
                CigParameters.CisParameters(cis_id=3),
            ],
            sdu_interval_c_to_p=0,
            sdu_interval_p_to_c=0,
        ),
    )
    assert len(cis_handles) == 2
    cis_links = await devices[0].create_cis(
        [
            (cis_handles[0], devices.connections[0]),
            (cis_handles[1], devices.connections[0]),
        ]
    )
    await asyncio.gather(*peripheral_cis_futures.values())
    assert len(cis_links) == 2

    await cis_links[0].disconnect()
    await cis_links[1].disconnect()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cis_setup_failure():
    devices = TwoDevices()
    await devices.setup_connection()

    cis_requests = asyncio.Queue()

    def on_cis_request(cis_link: CisLink):
        cis_requests.put_nowait(cis_link)

    devices[1].on('cis_request', on_cis_request)

    cis_handles = await devices[0].setup_cig(
        CigParameters(
            cig_id=1,
            cis_parameters=[
                CigParameters.CisParameters(cis_id=2),
            ],
            sdu_interval_c_to_p=0,
            sdu_interval_p_to_c=0,
        ),
    )
    assert len(cis_handles) == 1

    cis_create_task = asyncio.create_task(
        devices[0].create_cis(
            [
                (cis_handles[0], devices.connections[0]),
            ]
        )
    )

    def on_hci_le_cis_established_event(host, event):
        host.emit(
            'cis_establishment_failure',
            event.connection_handle,
            HCI_CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR,
        )

    for device in devices:
        device.host.on_hci_le_cis_established_event = functools.partial(
            on_hci_le_cis_established_event, device.host
        )

    cis_request = await asyncio.wait_for(cis_requests.get(), _TIMEOUT)

    with pytest.raises(HCI_Error):
        await asyncio.wait_for(devices[1].accept_cis_request(cis_request), _TIMEOUT)

    with pytest.raises(HCI_Error):
        await asyncio.wait_for(cis_create_task, _TIMEOUT)


# -----------------------------------------------------------------------------
def test_cis_parameters_unidirectional():
    # Test C2P unidirectional (P to C not used)
    cis_c2p = CigParameters.CisParameters(cis_id=1, max_sdu_p_to_c=0)
    assert cis_c2p.max_sdu_c_to_p != 0
    assert cis_c2p.rtn_c_to_p != 0
    assert cis_c2p.phy_c_to_p != hci.PhyBit(0)
    assert cis_c2p.rtn_p_to_c == 0
    assert cis_c2p.phy_p_to_c != hci.PhyBit(0)

    # Test P2C unidirectional (C to P not used)
    cis_p2c = CigParameters.CisParameters(cis_id=2, max_sdu_c_to_p=0)
    assert cis_p2c.max_sdu_p_to_c != 0
    assert cis_p2c.rtn_p_to_c != 0
    assert cis_p2c.phy_p_to_c != hci.PhyBit(0)
    assert cis_p2c.rtn_c_to_p == 0
    assert cis_p2c.phy_c_to_p != hci.PhyBit(0)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_enter_and_exit_sniff_mode():
    devices = TwoDevices()
    await devices.setup_connection()

    q = asyncio.Queue()

    def on_mode_change():
        q.put_nowait(lambda: None)

    devices.connections[0].on(Connection.EVENT_MODE_CHANGE, on_mode_change)

    await devices[0].send_command(
        hci.HCI_Sniff_Mode_Command(
            connection_handle=devices.connections[0].handle,
            sniff_max_interval=2,
            sniff_min_interval=2,
            sniff_attempt=2,
            sniff_timeout=2,
        ),
    )

    await asyncio.wait_for(q.get(), _TIMEOUT)
    assert devices.connections[0].classic_mode == hci.HCI_Mode_Change_Event.Mode.SNIFF
    assert devices.connections[0].classic_interval == 2

    await devices[0].send_command(
        hci.HCI_Exit_Sniff_Mode_Command(connection_handle=devices.connections[0].handle)
    )

    await asyncio.wait_for(q.get(), _TIMEOUT)
    assert devices.connections[0].classic_mode == hci.HCI_Mode_Change_Event.Mode.ACTIVE
    assert devices.connections[0].classic_interval == 2


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_request_subrate():
    devices = TwoDevices()
    await devices.setup_connection()

    q = asyncio.Queue()

    def on_le_subrate_change():
        q.put_nowait(lambda: None)

    devices.connections[0].on(
        Connection.EVENT_CONNECTION_PARAMETERS_UPDATE, on_le_subrate_change
    )

    await devices[0].send_command(
        hci.HCI_LE_Subrate_Request_Command(
            connection_handle=devices.connections[0].handle,
            subrate_min=2,
            subrate_max=2,
            max_latency=2,
            continuation_number=1,
            supervision_timeout=2,
        )
    )

    await asyncio.wait_for(q.get(), _TIMEOUT)
    assert devices.connections[0].parameters.subrate_factor == 2
    assert devices.connections[0].parameters.peripheral_latency == 2
    assert devices.connections[0].parameters.continuation_number == 1
    assert devices.connections[0].parameters.supervision_timeout == 20


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_power_on_default_static_address_should_not_be_any():
    devices = TwoDevices()
    devices[0].static_address = devices[0].random_address = Address.ANY_RANDOM
    await devices[0].power_on()

    assert devices[0].static_address != Address.ANY_RANDOM


# -----------------------------------------------------------------------------
def test_cs_channel_map_excludes_forbidden_channels():
    forbidden = {0, 1, 23, 24, 25, 76, 77, 78, 79}
    default_map = (
        inspect.signature(Device.create_cs_config).parameters['channel_map'].default
    )

    enabled = {
        byte_idx * 8 + bit
        for byte_idx, byte in enumerate(default_map)
        for bit in range(8)
        if byte & (1 << bit)
    }

    assert enabled.isdisjoint(
        forbidden
    ), f"Default channel_map enables forbidden CS channels: {enabled & forbidden}"


# -----------------------------------------------------------------------------
def test_gatt_services_with_gas_and_gatt():
    device = Device(host=Host(None, None))

    # there should be 2 service, 5 chars, and 1 descriptors, therefore 13 attributes
    assert len(device.gatt_server.attributes) == 13
    assert device.gatt_server.attributes[0].uuid == gatt.GATT_GENERIC_ACCESS_SERVICE
    assert (
        device.gatt_server.attributes[1].type == gatt.GATT_CHARACTERISTIC_ATTRIBUTE_TYPE
    )
    assert device.gatt_server.attributes[2].uuid == gatt.GATT_DEVICE_NAME_CHARACTERISTIC
    assert (
        device.gatt_server.attributes[3].type == gatt.GATT_CHARACTERISTIC_ATTRIBUTE_TYPE
    )
    assert device.gatt_server.attributes[4].uuid == gatt.GATT_APPEARANCE_CHARACTERISTIC

    assert device.gatt_server.attributes[5].uuid == gatt.GATT_GENERIC_ATTRIBUTE_SERVICE
    assert (
        device.gatt_server.attributes[6].type == gatt.GATT_CHARACTERISTIC_ATTRIBUTE_TYPE
    )
    assert (
        device.gatt_server.attributes[7].uuid
        == gatt.GATT_SERVICE_CHANGED_CHARACTERISTIC
    )
    assert (
        device.gatt_server.attributes[8].type
        == gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
    )
    assert (
        device.gatt_server.attributes[9].type == gatt.GATT_CHARACTERISTIC_ATTRIBUTE_TYPE
    )
    assert (
        device.gatt_server.attributes[10].uuid
        == gatt.GATT_CLIENT_SUPPORTED_FEATURES_CHARACTERISTIC
    )
    assert (
        device.gatt_server.attributes[11].type
        == gatt.GATT_CHARACTERISTIC_ATTRIBUTE_TYPE
    )
    assert (
        device.gatt_server.attributes[12].uuid == gatt.GATT_DATABASE_HASH_CHARACTERISTIC
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_inquiry_result():
    d = (await TwoDevices.create_with_connection())[0]
    m = mock.Mock()
    d.on(d.EVENT_INQUIRY_RESULT, m)
    d.host.on_packet(
        bytes(
            hci.HCI_Extended_Inquiry_Result_Event(
                num_responses=1,
                bd_addr=hci.Address("00:11:22:33:44:55/P"),
                page_scan_repetition_mode=2,
                reserved=0,
                class_of_device=3,
                clock_offset=4,
                rssi=5,
                extended_inquiry_response=b"6789",
            )
        )
    )
    m.assert_called_with(hci.Address("00:11:22:33:44:55/P"), 3, mock.ANY, 5)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_extended_inquiry_result():
    d = (await TwoDevices.create_with_connection())[0]
    m = mock.Mock()
    d.on(d.EVENT_INQUIRY_RESULT, m)
    d.host.on_packet(
        bytes(
            hci.HCI_Extended_Inquiry_Result_Event(
                num_responses=1,
                bd_addr=hci.Address("00:11:22:33:44:55/P"),
                page_scan_repetition_mode=2,
                reserved=0,
                class_of_device=3,
                clock_offset=4,
                rssi=5,
                extended_inquiry_response=b"6789",
            )
        )
    )
    m.assert_called_with(hci.Address("00:11:22:33:44:55/P"), 3, mock.ANY, 5)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_inquiry_result_with_rssi():
    d = (await TwoDevices.create_with_connection())[0]
    m = mock.Mock()
    d.on(d.EVENT_INQUIRY_RESULT, m)
    d.host.on_packet(
        bytes(
            hci.HCI_Inquiry_Result_With_RSSI_Event(
                bd_addr=[hci.Address("00:11:22:33:44:55/P")],
                page_scan_repetition_mode=[2],
                reserved=[0],
                class_of_device=[3],
                clock_offset=[4],
                rssi=[5],
            )
        )
    )
    m.assert_called_with(hci.Address("00:11:22:33:44:55/P"), 3, mock.ANY, 5)


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "roles",
    (
        (hci.Role.PERIPHERAL, hci.Role.CENTRAL),
        (hci.Role.CENTRAL, hci.Role.PERIPHERAL),
    ),
)
@pytest.mark.asyncio
async def test_accept_classic_connection(roles: tuple[hci.Role, hci.Role]):
    devices = TwoDevices()
    devices[0].classic_enabled = True
    devices[1].classic_enabled = True
    await devices[0].power_on()
    await devices[1].power_on()

    accept_task = asyncio.create_task(devices[1].accept(role=roles[1]))
    await devices[0].connect(
        devices[1].public_address, transport=PhysicalTransport.BR_EDR
    )
    await accept_task

    assert devices.connections[0]
    assert devices.connections[0].role == roles[0]
    assert devices.connections[1]
    assert devices.connections[1].role == roles[1]


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_remote_name_request():
    devices = TwoDevices()
    devices[0].classic_enabled = True
    devices[1].classic_enabled = True
    expected_name = devices[1].name = "An Awesome Name"
    await devices[0].power_on()
    await devices[1].power_on()
    actual_name = await devices[0].request_remote_name(devices[1].public_address)
    assert actual_name == expected_name


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_remote_classic_features():
    devices = TwoDevices()
    devices[0].classic_enabled = True
    devices[1].classic_enabled = True
    await devices[0].power_on()
    await devices[1].power_on()
    connection = await devices[0].connect_classic(devices[1].public_address)

    assert (
        await asyncio.wait_for(connection.get_remote_classic_features(), _TIMEOUT)
        == devices.controllers[1].lmp_features
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_create_big_sync_failure_propagates_hci_error():
    # Regression: on a BIG sync establishment failure the event handler removes
    # the big_syncs entry, and create_big_sync's except clause then removed it
    # again with `del`, raising KeyError and masking the real HCI status.
    device = Device(host=Host(None, None))
    status = HCI_CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR

    async def fake_send_async_command(command, check_status=True):
        # The controller accepted the command; a failure event then arrives and
        # its handler removes the entry before create_big_sync's except runs.
        big_handle = next(iter(device.big_syncs))
        asyncio.get_running_loop().call_soon(
            device.on_big_sync_establishment,
            status,
            big_handle,
            0,  # transport_latency_big
            0,  # nse
            0,  # bn
            0,  # pto
            0,  # irc
            0,  # max_pdu
            0,  # iso_interval
            [],  # bis_handles
        )
        return HCI_SUCCESS

    device.send_async_command = fake_send_async_command  # type: ignore[assignment]
    pa_sync = mock.Mock(sync_handle=0)
    parameters = BigSyncParameters(big_sync_timeout=1000, bis=[1])

    with pytest.raises(HCI_Error) as exc_info:
        await device.create_big_sync(pa_sync, parameters)

    assert exc_info.value.error_code == status
    assert device.big_syncs == {}


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_classic_ssp_just_works():
    two_devices = TwoDevices()
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    for dev in two_devices.devices:
        await dev.power_on()

    connection0, connection1 = await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=PhysicalTransport.BR_EDR
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    await two_devices.devices[0].authenticate(connection0)
    await async_barrier()
    assert connection0.authenticated
    assert connection1.authenticated
    link_key0 = await two_devices.devices[0].get_link_key(
        two_devices.devices[1].public_address
    )
    link_key1 = await two_devices.devices[1].get_link_key(
        two_devices.devices[0].public_address
    )
    assert link_key0 is not None
    assert link_key0 == link_key1


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_classic_ssp_numeric_comparison():
    two_devices = TwoDevices()
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    numbers_compared: list[int] = []

    class ComparingDelegate(PairingDelegate):
        async def compare_numbers(self, number: int, digits: int = 6) -> bool:
            numbers_compared.append(number)
            return True

    for dev in two_devices.devices:
        dev.pairing_config_factory = lambda conn: PairingConfig(
            bonding=True,
            mitm=True,
            delegate=ComparingDelegate(
                io_capability=PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_YES_NO_INPUT
            ),
        )
        await dev.power_on()

    connection0, connection1 = await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=PhysicalTransport.BR_EDR
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    await two_devices.devices[0].authenticate(connection0)
    await async_barrier()
    assert connection0.authenticated
    assert connection1.authenticated
    assert len(numbers_compared) == 2
    assert numbers_compared[0] == numbers_compared[1]
    link_key0 = await two_devices.devices[0].get_link_key(
        two_devices.devices[1].public_address
    )
    link_key1 = await two_devices.devices[1].get_link_key(
        two_devices.devices[0].public_address
    )
    assert link_key0 is not None
    assert link_key0 == link_key1


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_classic_ssp_user_confirmation_rejected():
    two_devices = TwoDevices()
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    class RejectingDelegate(PairingDelegate):
        async def compare_numbers(self, number: int, digits: int = 6) -> bool:
            return False

    two_devices.devices[0].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=PairingDelegate(
            io_capability=PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_YES_NO_INPUT
        ),
    )
    two_devices.devices[1].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=RejectingDelegate(
            io_capability=PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_YES_NO_INPUT
        ),
    )

    for dev in two_devices.devices:
        await dev.power_on()

    connection0, _ = await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=PhysicalTransport.BR_EDR
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    with pytest.raises(HCI_Error):
        await two_devices.devices[0].authenticate(connection0)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_classic_ssp_passkey_entry():
    two_devices = TwoDevices()
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    displayed_passkey: int | None = None

    class DisplayPasskeyDelegate(PairingDelegate):
        async def display_number(self, number: int, digits: int = 6) -> None:
            nonlocal displayed_passkey
            displayed_passkey = number

    class InputPasskeyDelegate(PairingDelegate):
        async def get_number(self) -> int:
            while displayed_passkey is None:
                await asyncio.sleep(0.01)
            return displayed_passkey

    two_devices.devices[0].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=InputPasskeyDelegate(
            io_capability=PairingDelegate.IoCapability.KEYBOARD_INPUT_ONLY
        ),
    )
    two_devices.devices[1].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=DisplayPasskeyDelegate(
            io_capability=PairingDelegate.IoCapability.DISPLAY_OUTPUT_ONLY
        ),
    )

    for dev in two_devices.devices:
        await dev.power_on()

    connection0, connection1 = await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=PhysicalTransport.BR_EDR
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    await two_devices.devices[0].authenticate(connection0)
    await async_barrier()
    assert connection0.authenticated
    assert connection1.authenticated
    assert displayed_passkey is not None
    link_key0 = await two_devices.devices[0].get_link_key(
        two_devices.devices[1].public_address
    )
    link_key1 = await two_devices.devices[1].get_link_key(
        two_devices.devices[0].public_address
    )
    assert link_key0 is not None
    assert link_key0 == link_key1


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_classic_ssp_passkey_entry_mismatch():
    two_devices = TwoDevices()
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    class MismatchedPasskeyDelegate(PairingDelegate):
        async def get_number(self) -> int:
            return 999999

    two_devices.devices[0].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=MismatchedPasskeyDelegate(
            io_capability=PairingDelegate.IoCapability.KEYBOARD_INPUT_ONLY
        ),
    )
    two_devices.devices[1].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=PairingDelegate(
            io_capability=PairingDelegate.IoCapability.DISPLAY_OUTPUT_ONLY
        ),
    )

    for dev in two_devices.devices:
        await dev.power_on()

    connection0, _ = await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=PhysicalTransport.BR_EDR
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    with pytest.raises(HCI_Error):
        await two_devices.devices[0].authenticate(connection0)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_classic_ssp_passkey_entry_rejected():
    two_devices = TwoDevices()
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    class RejectingPasskeyDelegate(PairingDelegate):
        async def get_number(self) -> int | None:
            return None

    two_devices.devices[0].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=RejectingPasskeyDelegate(
            io_capability=PairingDelegate.IoCapability.KEYBOARD_INPUT_ONLY
        ),
    )
    two_devices.devices[1].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=PairingDelegate(
            io_capability=PairingDelegate.IoCapability.DISPLAY_OUTPUT_ONLY
        ),
    )

    for dev in two_devices.devices:
        await dev.power_on()

    connection0, _ = await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=PhysicalTransport.BR_EDR
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    with pytest.raises(HCI_Error):
        await two_devices.devices[0].authenticate(connection0)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_classic_ssp_no_input_no_output_keyboard_fallback():
    two_devices = TwoDevices()
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    two_devices.devices[0].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=PairingDelegate(
            io_capability=PairingDelegate.IoCapability.KEYBOARD_INPUT_ONLY
        ),
    )
    two_devices.devices[1].pairing_config_factory = lambda conn: PairingConfig(
        bonding=True,
        mitm=True,
        delegate=PairingDelegate(
            io_capability=PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT
        ),
    )

    for dev in two_devices.devices:
        await dev.power_on()

    connection0, connection1 = await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=PhysicalTransport.BR_EDR
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    await two_devices.devices[0].authenticate(connection0)
    await async_barrier()
    assert connection0.authenticated
    assert connection1.authenticated
    link_key0 = await two_devices.devices[0].get_link_key(
        two_devices.devices[1].public_address
    )
    link_key1 = await two_devices.devices[1].get_link_key(
        two_devices.devices[0].public_address
    )
    assert link_key0 is not None
    assert link_key0 == link_key1


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_connection_parameters_and_subrate():
    two_devices = TwoDevices()
    await two_devices.setup_connection()
    connection = two_devices.connections[0]
    remote_connection = two_devices.connections[1]

    await connection.update_parameters(
        connection_interval_min=15.0,
        connection_interval_max=30.0,
        max_latency=2,
        supervision_timeout=1000.0,
    )
    await async_barrier()
    assert connection.parameters.connection_interval == 30.0
    assert connection.parameters.peripheral_latency == 2
    assert remote_connection.parameters.connection_interval == 30.0
    assert remote_connection.parameters.peripheral_latency == 2

    await two_devices.devices[0].set_default_connection_subrate(
        subrate_min=1,
        subrate_max=4,
        max_latency=1,
        continuation_number=0,
        supervision_timeout=1000.0,
    )

    await connection.update_subrate(
        subrate_min=1,
        subrate_max=4,
        max_latency=1,
        continuation_number=0,
        supervision_timeout=1000.0,
    )
    await async_barrier()
    assert connection.parameters.subrate_factor == 2
    assert remote_connection.parameters.subrate_factor == 2

    await connection.update_parameters_with_subrate(
        connection_interval_min=15.0,
        connection_interval_max=20.0,
        subrate_min=1,
        subrate_max=3,
        max_latency=1,
        continuation_number=0,
        supervision_timeout=1000.0,
        min_ce_length=0.0,
        max_ce_length=0.0,
    )
    await async_barrier()
    assert connection.parameters.subrate_factor == 3
    assert remote_connection.parameters.subrate_factor == 3


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_periodic_advertising_sync():
    two_devices = TwoDevices()
    for dev in two_devices.devices:
        await dev.power_on()

    adv_set = await two_devices.devices[0].create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            advertising_event_properties=AdvertisingEventProperties(
                is_connectable=False, is_scannable=False
            ),
            primary_advertising_interval_min=20,
            primary_advertising_interval_max=40,
        ),
        periodic_advertising_parameters=PeriodicAdvertisingParameters(
            periodic_advertising_interval_min=100, periodic_advertising_interval_max=200
        ),
        periodic_advertising_data=b'\x05\x09Sync',
        auto_start=True,
    )
    await adv_set.start_periodic()

    established = asyncio.Event()
    report_received = asyncio.Event()
    received_reports = []

    sync = await two_devices.devices[1].create_periodic_advertising_sync(
        advertiser_address=two_devices.devices[0].random_address,
        sid=0,
    )
    sync.on('establishment', established.set)
    sync.on(
        'periodic_advertisement',
        lambda report: (received_reports.append(report), report_received.set()),
    )

    if sync.state != PeriodicAdvertisingSync.State.ESTABLISHED:
        await asyncio.wait_for(established.wait(), _TIMEOUT)
    assert sync.state == PeriodicAdvertisingSync.State.ESTABLISHED

    await asyncio.wait_for(report_received.wait(), _TIMEOUT)
    assert len(received_reports) > 0

    await sync.terminate()
    assert sync.state == PeriodicAdvertisingSync.State.TERMINATED


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_big_and_big_sync():
    two_devices = TwoDevices()
    for dev in two_devices.devices:
        await dev.power_on()

    adv_set = await two_devices.devices[0].create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            advertising_event_properties=AdvertisingEventProperties(
                is_connectable=False, is_scannable=False
            ),
            primary_advertising_interval_min=20,
            primary_advertising_interval_max=40,
        ),
        periodic_advertising_parameters=PeriodicAdvertisingParameters(
            periodic_advertising_interval_min=100, periodic_advertising_interval_max=200
        ),
        auto_start=True,
    )
    await adv_set.start_periodic()

    big = await two_devices.devices[0].create_big(
        advertising_set=adv_set,
        parameters=BigParameters(
            num_bis=2,
            sdu_interval=10000,
            max_sdu=100,
            max_transport_latency=40,
            rtn=2,
        ),
    )
    assert len(big.bis_links) == 2

    established = asyncio.Event()
    pa_sync = await two_devices.devices[1].create_periodic_advertising_sync(
        advertiser_address=two_devices.devices[0].random_address,
        sid=0,
    )
    pa_sync.on('establishment', established.set)
    if pa_sync.state != PeriodicAdvertisingSync.State.ESTABLISHED:
        await asyncio.wait_for(established.wait(), _TIMEOUT)

    big_sync = await two_devices.devices[1].create_big_sync(
        pa_sync,
        BigSyncParameters(big_sync_timeout=1000, bis=[1, 2]),
    )
    assert len(big_sync.bis_links) == 2

    await big_sync.terminate()
    await big.terminate()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_find_peer_by_name_and_identity_address():
    two_devices = TwoDevices()
    for dev in two_devices.devices:
        await dev.power_on()

    two_devices.devices[0].advertising_data = bytes(
        AdvertisingData([(AdvertisingData.Type.COMPLETE_LOCAL_NAME, b'TargetPeer')])
    )
    await two_devices.devices[0].start_advertising()

    addr = await two_devices.devices[1].find_peer_by_name('TargetPeer')
    assert addr == two_devices.devices[0].random_address

    two_devices.devices[1].address_resolver = smp.AddressResolver(
        [(b'\x11' * 16, two_devices.devices[0].public_address)]
    )
    addr2 = await two_devices.devices[1].find_peer_by_identity_address(
        two_devices.devices[0].random_address
    )
    assert addr2 == two_devices.devices[0].random_address


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_channel_sounding():
    two_devices = TwoDevices()
    await two_devices.setup_connection()
    connection = two_devices.connections[0]
    remote_connection = two_devices.connections[1]

    config = await two_devices.devices[0].create_cs_config(
        connection=connection, create_context=1
    )
    await async_barrier()
    assert config.config_id == 0
    assert config.role == hci.CsRole.INITIATOR
    assert 0 in remote_connection.cs_configs
    assert remote_connection.cs_configs[0].role == hci.CsRole.REFLECTOR

    await two_devices.devices[0].enable_cs_security(connection=connection)
    await async_barrier()

    await two_devices.devices[0].set_cs_procedure_parameters(
        connection=connection, config=config
    )
    procedure = await two_devices.devices[0].enable_cs_procedure(
        connection=connection, config=config
    )
    await async_barrier()
    assert procedure.config_id == 0
    assert 0 in remote_connection.cs_procedures
    assert remote_connection.cs_procedures[0].state == 1


# -----------------------------------------------------------------------------
def test_device_configuration_load_from_dict():
    config = DeviceConfiguration()
    config.load_from_dict(
        {
            'name': 'TestDevice',
            'address': 'F0:F1:F2:F3:F4:F5',
            'class_of_device': 0x240404,
            'advertising_interval_min': 100,
            'advertising_interval_max': 200,
            'le_enabled': True,
            'classic_enabled': True,
            'le_subrate_enabled': True,
            'irk': '00112233445566778899aabbccddeeff',
            'keystore': 'JsonKeyStore',
        }
    )
    assert config.name == 'TestDevice'
    assert config.le_subrate_enabled is True


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_multiple_periodic_advertising_and_big_syncs():
    two_devices = TwoDevices()
    for dev in two_devices.devices:
        await dev.power_on()

    adv_set_0 = await two_devices.devices[0].create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            advertising_event_properties=AdvertisingEventProperties(
                is_connectable=False, is_scannable=False
            ),
            advertising_sid=0,
            primary_advertising_interval_min=20,
            primary_advertising_interval_max=40,
        ),
        periodic_advertising_parameters=PeriodicAdvertisingParameters(
            periodic_advertising_interval_min=100, periodic_advertising_interval_max=200
        ),
        periodic_advertising_data=b'\x07\x09Train0',
        auto_start=True,
    )
    await adv_set_0.start_periodic()

    adv_set_1 = await two_devices.devices[0].create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            advertising_event_properties=AdvertisingEventProperties(
                is_connectable=False, is_scannable=False
            ),
            advertising_sid=1,
            primary_advertising_interval_min=20,
            primary_advertising_interval_max=40,
        ),
        periodic_advertising_parameters=PeriodicAdvertisingParameters(
            periodic_advertising_interval_min=100, periodic_advertising_interval_max=200
        ),
        periodic_advertising_data=b'\x07\x09Train1',
        auto_start=True,
    )
    await adv_set_1.start_periodic()

    big_0 = await two_devices.devices[0].create_big(
        advertising_set=adv_set_0,
        parameters=BigParameters(
            num_bis=2,
            sdu_interval=10000,
            max_sdu=100,
            max_transport_latency=40,
            rtn=2,
        ),
    )
    big_1 = await two_devices.devices[0].create_big(
        advertising_set=adv_set_1,
        parameters=BigParameters(
            num_bis=1,
            sdu_interval=10000,
            max_sdu=100,
            max_transport_latency=40,
            rtn=2,
        ),
    )
    assert len(big_0.bis_links) == 2
    assert len(big_1.bis_links) == 1

    est_0 = asyncio.Event()
    est_1 = asyncio.Event()
    rep_0 = asyncio.Event()
    rep_1 = asyncio.Event()
    data_0 = []
    data_1 = []

    sync_0 = await two_devices.devices[1].create_periodic_advertising_sync(
        advertiser_address=two_devices.devices[0].random_address,
        sid=0,
    )
    sync_0.on('establishment', est_0.set)
    sync_0.on(
        'periodic_advertisement',
        lambda r: (data_0.append(bytes(r.data)), rep_0.set()),
    )
    if sync_0.state != PeriodicAdvertisingSync.State.ESTABLISHED:
        await asyncio.wait_for(est_0.wait(), _TIMEOUT)

    sync_1 = await two_devices.devices[1].create_periodic_advertising_sync(
        advertiser_address=two_devices.devices[0].random_address,
        sid=1,
    )
    sync_1.on('establishment', est_1.set)
    sync_1.on(
        'periodic_advertisement',
        lambda r: (data_1.append(bytes(r.data)), rep_1.set()),
    )
    if sync_1.state != PeriodicAdvertisingSync.State.ESTABLISHED:
        await asyncio.wait_for(est_1.wait(), _TIMEOUT)

    await asyncio.wait_for(rep_0.wait(), _TIMEOUT)
    await asyncio.wait_for(rep_1.wait(), _TIMEOUT)
    assert b'\x07\x09Train0' in data_0
    assert b'\x07\x09Train1' in data_1

    big_sync_0 = await two_devices.devices[1].create_big_sync(
        sync_0, BigSyncParameters(big_sync_timeout=1000, bis=[1, 2])
    )
    big_sync_1 = await two_devices.devices[1].create_big_sync(
        sync_1, BigSyncParameters(big_sync_timeout=1000, bis=[1])
    )
    assert len(big_sync_0.bis_links) == 2
    assert len(big_sync_1.bis_links) == 1

    await big_sync_0.terminate()
    await big_sync_1.terminate()
    await sync_0.terminate()
    await sync_1.terminate()
    await big_0.terminate()
    await big_1.terminate()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_periodic_advertising_and_big_failure_exceptions():
    two_devices = TwoDevices()
    for dev in two_devices.devices:
        await dev.power_on()

    # 1. Duplicate Periodic Advertising Sync raises ValueError
    sync = await two_devices.devices[1].create_periodic_advertising_sync(
        advertiser_address=two_devices.devices[0].random_address,
        sid=5,
    )
    with pytest.raises(ValueError, match="equivalent entry already created"):
        await two_devices.devices[1].create_periodic_advertising_sync(
            advertiser_address=two_devices.devices[0].random_address,
            sid=5,
        )

    # 2. Create BIG Sync on unestablished PA Sync raises InvalidStateError
    with pytest.raises(InvalidStateError, match="PA Sync is not established"):
        await two_devices.devices[1].create_big_sync(
            sync, BigSyncParameters(big_sync_timeout=1000, bis=[1])
        )

    # 3. Cancel pending Periodic Advertising Sync before establishment via terminate()
    await sync.terminate()
    assert sync.state == PeriodicAdvertisingSync.State.CANCELLED

    # 4. Periodic Advertising Sync establishment timeout error (status != SUCCESS)
    sync_err = await two_devices.devices[1].create_periodic_advertising_sync(
        advertiser_address=two_devices.devices[0].random_address,
        sid=6,
        sync_timeout=0.02,
    )
    error_event = asyncio.Event()
    sync_err.on('establishment_error', error_event.set)
    await asyncio.wait_for(error_event.wait(), _TIMEOUT)
    assert sync_err.state == PeriodicAdvertisingSync.State.ERROR
    assert (
        sync_err.status == hci.HCI_ErrorCode.CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR
    )

    # 5. Exhaust BIG handles raises OutOfResourcesError
    original_bigs = dict(two_devices.devices[1].big_syncs)
    try:
        for handle in range(0x00, 0xEF + 1):
            two_devices.devices[1].big_syncs[handle] = None  # type: ignore
        with pytest.raises(
            OutOfResourcesError, match="All valid BIG handles already in use"
        ):
            await two_devices.devices[1].create_big_sync(
                sync, BigSyncParameters(big_sync_timeout=1000, bis=[1])
            )
    finally:
        two_devices.devices[1].big_syncs = original_bigs


# -----------------------------------------------------------------------------
async def _setup_le_encryption(peripheral_ltk: bytes | None):
    two_devices = TwoDevices()
    await two_devices.setup_connection()
    central, peripheral = two_devices.connections[0], two_devices.connections[1]

    ltk = bytes(range(16))
    two_devices.devices[0].keystore = MemoryKeyStore()
    await two_devices.devices[0].keystore.update(
        str(central.peer_address), PairingKeys(ltk=PairingKeys.Key(value=ltk))
    )

    requests = []

    async def long_term_key_provider(connection_handle, rand, ediv):
        requests.append((connection_handle, rand, ediv))
        return peripheral_ltk

    two_devices.devices[1].host.long_term_key_provider = long_term_key_provider
    return ltk, central, peripheral, requests


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_encryption():
    ltk, central, peripheral, requests = await _setup_le_encryption(bytes(range(16)))

    await central.encrypt()
    await async_barrier()

    assert requests == [(peripheral.handle, bytes(8), 0)]
    assert central.is_encrypted
    assert peripheral.is_encrypted


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_encryption_without_peripheral_key():
    _, central, peripheral, requests = await _setup_le_encryption(None)

    with pytest.raises(hci.HCI_Error) as error:
        await central.encrypt()
    await async_barrier()

    assert error.value.error_code == hci.HCI_ErrorCode.PIN_OR_KEY_MISSING_ERROR
    assert len(requests) == 1
    assert not central.is_encrypted
    assert not peripheral.is_encrypted


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_encryption_with_mismatched_keys():
    _, central, peripheral, _ = await _setup_le_encryption(bytes(16))
    reasons = []
    central.on(central.EVENT_DISCONNECTION, reasons.append)
    peripheral.on(peripheral.EVENT_DISCONNECTION, reasons.append)

    with pytest.raises(asyncio.CancelledError):
        await central.encrypt()
    await async_barrier()

    mic_failure = hci.HCI_ErrorCode.CONNECTION_TERMINATED_DUE_TO_MIC_FAILURE_ERROR
    assert reasons == [mic_failure, mic_failure]
    assert not central.is_encrypted
    assert not peripheral.is_encrypted


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_le_set_privacy_mode():
    device = TwoDevices()[0]
    await device.power_on()

    await device.send_sync_command(
        hci.HCI_LE_Set_Privacy_Mode_Command(
            peer_identity_address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
            peer_identity_address=hci.Address('F0:BB:1E:00:00:01'),
            privacy_mode=hci.HCI_LE_Set_Privacy_Mode_Command.PrivacyMode.DEVICE_PRIVACY_MODE,
        )
    )


# -----------------------------------------------------------------------------
async def run_test_device():
    await test_device_connect_parallel()
    await test_flush()
    await test_gatt_services_with_gas_and_gatt()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_test_device())
