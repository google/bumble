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
import logging
import os
from unittest import mock

import pytest

from bumble import gatt, hci, utils
from bumble.core import PhysicalTransport
from bumble.device import (
    Advertisement,
    AdvertisingEventProperties,
    AdvertisingParameters,
    CigParameters,
    CisLink,
    Connection,
    Device,
    PeriodicAdvertisingParameters,
)
from bumble.hci import (
    HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
    HCI_COMMAND_STATUS_PENDING,
    HCI_CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR,
    HCI_CREATE_CONNECTION_COMMAND,
    HCI_SUCCESS,
    Address,
    HCI_Command_Complete_Event,
    HCI_Command_Status_Event,
    HCI_Connection_Complete_Event,
    HCI_Connection_Request_Event,
    HCI_Error,
    HCI_Packet,
    OwnAddressType,
    Role,
)
from bumble.host import DataPacketQueue, Host

from .test_utils import TwoDevices, async_barrier

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
            HCI_Command_Complete_Event(
                num_hci_command_packets=1,
                command_opcode=HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
                return_parameters=b"\x00",
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
            HCI_Command_Complete_Event(
                num_hci_command_packets=1,
                command_opcode=HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
                return_parameters=b"\x00",
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
    'auto_restart,',
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
    'own_address_type,',
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
    'own_address_type,',
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

    assert (await devices.connections[0].get_remote_le_features()) is not None


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

    devices.connections[0].on(Connection.EVENT_LE_SUBRATE_CHANGE, on_le_subrate_change)

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
async def run_test_device():
    await test_device_connect_parallel()
    await test_flush()
    await test_gatt_services_with_gas_and_gatt()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_test_device())
