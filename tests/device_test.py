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
import pytest

from bumble.core import (
    PhysicalTransport,
    ConnectionParameters,
)
from bumble.device import (
    AdvertisingEventProperties,
    AdvertisingParameters,
    Connection,
    Device,
    PeriodicAdvertisingParameters,
)
from bumble.host import DataPacketQueue, Host
from bumble.hci import (
    HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
    HCI_COMMAND_STATUS_PENDING,
    HCI_CREATE_CONNECTION_COMMAND,
    HCI_SUCCESS,
    HCI_CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR,
    Address,
    OwnAddressType,
    Role,
    HCI_Command_Complete_Event,
    HCI_Command_Status_Event,
    HCI_Connection_Complete_Event,
    HCI_Connection_Request_Event,
    HCI_Error,
    HCI_Packet,
)
from bumble import utils
from bumble import gatt

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
                link_type=HCI_Connection_Complete_Event.ACL_LINK_TYPE,
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
                link_type=HCI_Connection_Complete_Event.ACL_LINK_TYPE,
            )
        )

        assert (yield) == None

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
                link_type=HCI_Connection_Complete_Event.ACL_LINK_TYPE,
                encryption_enabled=True,
            )
        )

        d0.host.on_hci_packet(
            HCI_Connection_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=0x100,
                bd_addr=d1.public_address,
                link_type=HCI_Connection_Complete_Event.ACL_LINK_TYPE,
                encryption_enabled=True,
            )
        )

        assert (yield) == None

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
                link_type=HCI_Connection_Complete_Event.ACL_LINK_TYPE,
                encryption_enabled=True,
            )
        )

        d0.host.on_hci_packet(
            HCI_Connection_Complete_Event(
                status=HCI_SUCCESS,
                connection_handle=0x101,
                bd_addr=d2.public_address,
                link_type=HCI_Connection_Complete_Event.ACL_LINK_TYPE,
                encryption_enabled=True,
            )
        )

        assert (yield) == None

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

    assert type(c01) == Connection
    assert type(c02) == Connection
    assert type(a10) == Connection
    assert type(a20) == Connection

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
    device = devices[0]
    devices.controllers[0].le_features = bytes.fromhex('ffffffffffffffff')
    await device.power_on()
    peer_address = Address('F0:F1:F2:F3:F4:F5')
    await device.start_advertising(auto_restart=auto_restart)
    device.on_connection(
        0x0001,
        PhysicalTransport.LE,
        peer_address,
        None,
        None,
        Role.PERIPHERAL,
        ConnectionParameters(0, 0, 0),
    )

    device.on_advertising_set_termination(
        HCI_SUCCESS, device.legacy_advertising_set.advertising_handle, 0x0001, 0
    )

    device.on_disconnection(0x0001, 0)
    await async_barrier()
    await async_barrier()

    if auto_restart:
        assert device.legacy_advertising_set
        started = asyncio.Event()
        if not device.is_advertising:
            device.legacy_advertising_set.once('start', started.set)
            await asyncio.wait_for(started.wait(), _TIMEOUT)
        assert device.is_advertising
    else:
        assert not device.is_advertising


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_extended_advertising():
    device = TwoDevices()[0]
    await device.power_on()

    # Start advertising
    advertising_set = await device.create_advertising_set()
    assert device.extended_advertising_sets
    assert advertising_set.enabled

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
    device = TwoDevices()[0]
    await device.power_on()
    peer_address = Address('F0:F1:F2:F3:F4:F5')
    advertising_set = await device.create_advertising_set(
        advertising_parameters=AdvertisingParameters(own_address_type=own_address_type)
    )
    device.on_connection(
        0x0001,
        PhysicalTransport.LE,
        peer_address,
        None,
        None,
        Role.PERIPHERAL,
        ConnectionParameters(0, 0, 0),
    )
    device.on_advertising_set_termination(
        HCI_SUCCESS,
        advertising_set.advertising_handle,
        0x0001,
        0,
    )

    if own_address_type == OwnAddressType.PUBLIC:
        assert device.lookup_connection(0x0001).self_address == device.public_address
    else:
        assert device.lookup_connection(0x0001).self_address == device.random_address

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
    devices.controllers[0].le_features = bytes.fromhex('ffffffffffffffff')
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
    device.on_connection(
        0x0001,
        PhysicalTransport.LE,
        Address('F0:F1:F2:F3:F4:F5'),
        None,
        None,
        Role.PERIPHERAL,
        ConnectionParameters(0, 0, 0),
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

    def on_cis_request(
        acl_connection: Connection,
        cis_handle: int,
        _cig_id: int,
        _cis_id: int,
    ):
        utils.cancel_on_event(
            acl_connection, 'disconnection', devices[1].accept_cis_request(cis_handle)
        )
        peripheral_cis_futures[cis_handle] = asyncio.get_running_loop().create_future()

    devices[1].on('cis_request', on_cis_request)
    devices[1].on(
        'cis_establishment',
        lambda cis_link: peripheral_cis_futures[cis_link.handle].set_result(None),
    )

    cis_handles = await devices[0].setup_cig(
        cig_id=1,
        cis_id=[2, 3],
        sdu_interval=(0, 0),
        framing=0,
        max_sdu=(0, 0),
        retransmission_number=0,
        max_transport_latency=(0, 0),
    )
    assert len(cis_handles) == 2
    cis_links = await devices[0].create_cis(
        [
            (cis_handles[0], devices.connections[0].handle),
            (cis_handles[1], devices.connections[0].handle),
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

    def on_cis_request(
        acl_connection: Connection,
        cis_handle: int,
        cig_id: int,
        cis_id: int,
    ):
        del acl_connection, cig_id, cis_id
        cis_requests.put_nowait(cis_handle)

    devices[1].on('cis_request', on_cis_request)

    cis_handles = await devices[0].setup_cig(
        cig_id=1,
        cis_id=[2],
        sdu_interval=(0, 0),
        framing=0,
        max_sdu=(0, 0),
        retransmission_number=0,
        max_transport_latency=(0, 0),
    )
    assert len(cis_handles) == 1

    cis_create_task = asyncio.create_task(
        devices[0].create_cis(
            [
                (cis_handles[0], devices.connections[0].handle),
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
async def run_test_device():
    await test_device_connect_parallel()
    await test_flush()
    await test_gatt_services_with_gas_and_gatt()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_test_device())
