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
import logging
import os
from types import LambdaType
import pytest

from bumble.core import BT_BR_EDR_TRANSPORT
from bumble.device import Connection, Device
from bumble.host import Host
from bumble.hci import (
    HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
    HCI_COMMAND_STATUS_PENDING,
    HCI_CREATE_CONNECTION_COMMAND,
    HCI_SUCCESS,
    Address,
    HCI_Command_Complete_Event,
    HCI_Command_Status_Event,
    HCI_Connection_Complete_Event,
    HCI_Connection_Request_Event,
    HCI_Packet,
)
from bumble.gatt import (
    GATT_GENERIC_ACCESS_SERVICE,
    GATT_CHARACTERISTIC_ATTRIBUTE_TYPE,
    GATT_DEVICE_NAME_CHARACTERISTIC,
    GATT_APPEARANCE_CHARACTERISTIC,
)

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

    [c01, c02, a10, a20] = await asyncio.gather(
        *[
            asyncio.create_task(
                d0.connect(d1.public_address, transport=BT_BR_EDR_TRANSPORT)
            ),
            asyncio.create_task(
                d0.connect(d2.public_address, transport=BT_BR_EDR_TRANSPORT)
            ),
            asyncio.create_task(d1.accept(peer_address=d0.public_address)),
            asyncio.create_task(d2.accept()),
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
    task = d0.abort_on('flush', asyncio.sleep(10000))
    await d0.host.flush()
    try:
        await task
        assert False
    except asyncio.CancelledError:
        pass


# -----------------------------------------------------------------------------
def test_gatt_services_with_gas():
    device = Device(host=Host(None, None))

    # there should be one service and two chars, therefore 5 attributes
    assert len(device.gatt_server.attributes) == 5
    assert device.gatt_server.attributes[0].uuid == GATT_GENERIC_ACCESS_SERVICE
    assert device.gatt_server.attributes[1].type == GATT_CHARACTERISTIC_ATTRIBUTE_TYPE
    assert device.gatt_server.attributes[2].uuid == GATT_DEVICE_NAME_CHARACTERISTIC
    assert device.gatt_server.attributes[3].type == GATT_CHARACTERISTIC_ATTRIBUTE_TYPE
    assert device.gatt_server.attributes[4].uuid == GATT_APPEARANCE_CHARACTERISTIC


# -----------------------------------------------------------------------------
def test_gatt_services_without_gas():
    device = Device(host=Host(None, None), generic_access_service=False)

    # there should be no services
    assert len(device.gatt_server.attributes) == 0


# -----------------------------------------------------------------------------
async def run_test_device():
    await test_device_connect_parallel()
    await test_flush()
    await test_gatt_services_with_gas()
    await test_gatt_services_without_gas()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_test_device())
