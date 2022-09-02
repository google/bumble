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
import itertools
import logging
import os
import pytest

from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.device import Device, Peer
from bumble.host import Host
from bumble.gatt import Service, Characteristic
from bumble.transport import AsyncPipeSink
from bumble.smp import (
    PairingConfig,
    PairingDelegate,
    SMP_PAIRING_NOT_SUPPORTED_ERROR,
    SMP_CONFIRM_VALUE_FAILED_ERROR,
    SMP_ID_KEY_DISTRIBUTION_FLAG,
)
from bumble.core import ProtocolError


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class TwoDevices:
    def __init__(self):
        self.connections = [None, None]

        self.link = LocalLink()
        self.controllers = [
            Controller('C1', link = self.link),
            Controller('C2', link = self.link)
        ]
        self.devices = [
            Device(
                address = 'F0:F1:F2:F3:F4:F5',
                host    = Host(self.controllers[0], AsyncPipeSink(self.controllers[0]))
            ),
            Device(
                address = 'F5:F4:F3:F2:F1:F0',
                host    = Host(self.controllers[1], AsyncPipeSink(self.controllers[1]))
            )
        ]

        self.paired = [None, None]

    def on_connection(self, which, connection):
        self.connections[which] = connection

    def on_paired(self, which, keys):
        self.paired[which] = keys


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_connection():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Attach listeners
    two_devices.devices[0].on('connection', lambda connection: two_devices.on_connection(0, connection))
    two_devices.devices[1].on('connection', lambda connection: two_devices.on_connection(1, connection))

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    await two_devices.devices[0].connect(two_devices.devices[1].random_address)

    # Check the post conditions
    assert(two_devices.connections[0] is not None)
    assert(two_devices.connections[1] is not None)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_gatt():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Add some GATT characteristics to device 1
    c1 = Characteristic(
        '3A143AD7-D4A7-436B-97D6-5B62C315E833',
        Characteristic.READ,
        Characteristic.READABLE,
        bytes([1, 2, 3])
    )
    c2 = Characteristic(
        '9557CCE2-DB37-46EB-94C4-50AE5B9CB0F8',
        Characteristic.READ | Characteristic.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([4, 5, 6])
    )
    c3 = Characteristic(
        '84FC1A2E-C52D-4A2D-B8C3-8855BAB86638',
        Characteristic.READ | Characteristic.WRITE_WITHOUT_RESPONSE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([7, 8, 9])
    )
    c4 = Characteristic(
        '84FC1A2E-C52D-4A2D-B8C3-8855BAB86638',
        Characteristic.READ | Characteristic.NOTIFY | Characteristic.INDICATE,
        Characteristic.READABLE,
        bytes([1, 1, 1])
    )

    s1 = Service('8140E247-04F0-42C1-BC34-534C344DAFCA', [c1, c2, c3])
    s2 = Service('97210A0F-1875-4D05-9E5D-326EB171257A', [c4])
    two_devices.devices[1].add_services([s1, s2])

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    connection = await two_devices.devices[0].connect(two_devices.devices[1].random_address)
    peer = Peer(connection)

    bogus_uuid = 'A0AA6007-0B48-4BBE-80AC-0DE9AAF541EA'
    result = await peer.discover_services([bogus_uuid])
    assert(result == [])
    services = peer.get_services_by_uuid(bogus_uuid)
    assert(len(services) == 0)

    result = await peer.discover_service(s1.uuid)
    assert(len(result) == 1)
    services = peer.get_services_by_uuid(s1.uuid)
    assert(len(services) == 1)
    s = services[0]
    assert(services[0].uuid == s1.uuid)

    result = await peer.discover_characteristics([c1.uuid], s)
    assert(len(result) == 1)
    characteristics = peer.get_characteristics_by_uuid(c1.uuid)
    assert(len(characteristics) == 1)
    c = characteristics[0]
    assert(c.uuid == c1.uuid)
    result = await peer.read_value(c)
    assert(result is not None)
    assert(result == c1.value)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_gatt_long_read():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Add some GATT characteristics to device 1
    characteristics = [
        Characteristic(
            f'3A143AD7-D4A7-436B-97D6-5B62C315{i:04X}',
            Characteristic.READ,
            Characteristic.READABLE,
            bytes([x & 255 for x in range(i)])
        )
        for i in range(0, 513)
    ]

    service = Service('8140E247-04F0-42C1-BC34-534C344DAFCA', characteristics)
    two_devices.devices[1].add_service(service)

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    connection = await two_devices.devices[0].connect(two_devices.devices[1].random_address)
    peer = Peer(connection)

    result = await peer.discover_service(service.uuid)
    assert(len(result) == 1)
    found_service = result[0]
    found_characteristics = await found_service.discover_characteristics()
    assert(len(found_characteristics) == 513)
    for (i, characteristic) in enumerate(found_characteristics):
        value = await characteristic.read_value()
        assert(value == characteristics[i].value)


# -----------------------------------------------------------------------------
async def _test_self_smp_with_configs(pairing_config1, pairing_config2):
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Attach listeners
    two_devices.devices[0].on('connection', lambda connection: two_devices.on_connection(0, connection))
    two_devices.devices[1].on('connection', lambda connection: two_devices.on_connection(1, connection))

    # Connect the two devices
    connection = await two_devices.devices[0].connect(two_devices.devices[1].random_address)
    assert(not connection.is_encrypted)

    # Attach connection listeners
    two_devices.connections[0].on('pairing', lambda keys: two_devices.on_paired(0, keys))
    two_devices.connections[1].on('pairing', lambda keys: two_devices.on_paired(1, keys))

    # Set up the pairing configs
    if pairing_config1:
        two_devices.devices[0].pairing_config_factory = lambda connection: pairing_config1
    if pairing_config2:
        two_devices.devices[1].pairing_config_factory = lambda connection: pairing_config2

    # Pair
    await two_devices.devices[0].pair(connection)
    assert(connection.is_encrypted)
    assert(two_devices.paired[0] is not None)
    assert(two_devices.paired[1] is not None)


# -----------------------------------------------------------------------------
IO_CAP = [
    PairingDelegate.NO_OUTPUT_NO_INPUT,
    PairingDelegate.KEYBOARD_INPUT_ONLY,
    PairingDelegate.DISPLAY_OUTPUT_ONLY,
    PairingDelegate.DISPLAY_OUTPUT_AND_YES_NO_INPUT,
    PairingDelegate.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT
]
SC = [False, True]
MITM = [False, True]
# Key distribution is a 4-bit bitmask
KEY_DIST = range(16)

@pytest.mark.asyncio
@pytest.mark.parametrize('io_cap, sc, mitm, key_dist',
    itertools.product(IO_CAP, SC, MITM, KEY_DIST)
)
async def test_self_smp(io_cap, sc, mitm, key_dist):
    class Delegate(PairingDelegate):
        def __init__(self, name, io_capability, local_initiator_key_distribution, local_responder_key_distribution):
            super().__init__(io_capability, local_initiator_key_distribution,
                             local_responder_key_distribution)
            self.name = name
            self.reset()

        def reset(self):
            self.peer_delegate = None
            self.number = asyncio.get_running_loop().create_future()

        async def compare_numbers(self, number, digits):
            if self.peer_delegate is None:
                logger.warn(f'[{self.name}] no peer delegate')
                return False
            await self.display_number(number, digits=6)
            logger.debug(f'[{self.name}] waiting for peer number')
            peer_number = await self.peer_delegate.number
            logger.debug(f'[{self.name}] comparing numbers: {number} and {peer_number}')
            return number == peer_number

        async def get_number(self):
            if self.peer_delegate is None:
                logger.warn(f'[{self.name}] no peer delegate')
                return 0
            else:
                if self.peer_delegate.io_capability == PairingDelegate.KEYBOARD_INPUT_ONLY:
                    peer_number = 6789
                else:
                    logger.debug(f'[{self.name}] waiting for peer number')
                    peer_number = await self.peer_delegate.number
                logger.debug(f'[{self.name}] returning number: {peer_number}')
                return peer_number

        async def display_number(self, number, digits):
            logger.debug(f'[{self.name}] displaying number: {number}')
            self.number.set_result(number)

        def __str__(self):
            return f'Delegate(name={self.name}, io_capability={self.io_capability})'

    pairing_config_sets = [('Initiator', [None]), ('Responder', [None])]
    for pairing_config_set in pairing_config_sets:
        delegate = Delegate(pairing_config_set[0], io_cap, key_dist, key_dist)
        pairing_config_set[1].append(PairingConfig(sc, mitm, True, delegate))

    for pairing_config1 in pairing_config_sets[0][1]:
        for pairing_config2 in pairing_config_sets[1][1]:
            logger.info(f'########## self_smp with {pairing_config1} and {pairing_config2}')
            if pairing_config1:
                pairing_config1.delegate.reset()
            if pairing_config2:
                pairing_config2.delegate.reset()
            if pairing_config1 and pairing_config2:
                pairing_config1.delegate.peer_delegate = pairing_config2.delegate
                pairing_config2.delegate.peer_delegate = pairing_config1.delegate

            await _test_self_smp_with_configs(pairing_config1, pairing_config2)



# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_smp_reject():
    class RejectingDelegate(PairingDelegate):
        def __init__(self):
            super().__init__(PairingDelegate.NO_OUTPUT_NO_INPUT)

        async def accept(self):
            return False

    rejecting_pairing_config = PairingConfig(delegate = RejectingDelegate())
    paired = False
    try:
        await _test_self_smp_with_configs(None, rejecting_pairing_config)
        paired = True
    except ProtocolError as error:
        assert(error.error_code == SMP_PAIRING_NOT_SUPPORTED_ERROR)

    assert(not paired)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_smp_wrong_pin():
    class WrongPinDelegate(PairingDelegate):
        def __init__(self):
            super().__init__(PairingDelegate.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT)

        async def compare_numbers(self, number, digits):
            return False

    wrong_pin_pairing_config = PairingConfig(delegate = WrongPinDelegate())
    paired = False
    try:
        await _test_self_smp_with_configs(wrong_pin_pairing_config, wrong_pin_pairing_config)
        paired = True
    except ProtocolError as error:
        assert(error.error_code == SMP_CONFIRM_VALUE_FAILED_ERROR)

    assert(not paired)


# -----------------------------------------------------------------------------
async def run_test_self():
    await test_self_connection()
    await test_self_gatt()
    await test_self_gatt_long_read()
    await test_self_smp()
    await test_self_smp_reject()
    await test_self_smp_wrong_pin()

# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_test_self())
