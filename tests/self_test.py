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

from unittest.mock import AsyncMock, MagicMock, patch

from bumble.controller import Controller
from bumble.core import BT_BR_EDR_TRANSPORT, BT_PERIPHERAL_ROLE, BT_CENTRAL_ROLE
from bumble.link import LocalLink
from bumble.device import Device, Peer
from bumble.host import Host
from bumble.gatt import Service, Characteristic
from bumble.transport import AsyncPipeSink
from bumble.pairing import PairingConfig, PairingDelegate
from bumble.smp import (
    SMP_PAIRING_NOT_SUPPORTED_ERROR,
    SMP_CONFIRM_VALUE_FAILED_ERROR,
    OobContext,
    OobLegacyContext,
)
from bumble.core import ProtocolError
from bumble.keys import PairingKeys


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class TwoDevices:
    def __init__(self):
        self.connections = [None, None]

        addresses = ['F0:F1:F2:F3:F4:F5', 'F5:F4:F3:F2:F1:F0']
        self.link = LocalLink()
        self.controllers = [
            Controller('C1', link=self.link, public_address=addresses[0]),
            Controller('C2', link=self.link, public_address=addresses[1]),
        ]
        self.devices = [
            Device(
                address=addresses[0],
                host=Host(self.controllers[0], AsyncPipeSink(self.controllers[0])),
            ),
            Device(
                address=addresses[1],
                host=Host(self.controllers[1], AsyncPipeSink(self.controllers[1])),
            ),
        ]

        self.paired = [
            asyncio.get_event_loop().create_future(),
            asyncio.get_event_loop().create_future(),
        ]

    def on_connection(self, which, connection):
        self.connections[which] = connection

    def on_paired(self, which: int, keys: PairingKeys):
        self.paired[which].set_result(keys)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_connection():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Attach listeners
    two_devices.devices[0].on(
        'connection', lambda connection: two_devices.on_connection(0, connection)
    )
    two_devices.devices[1].on(
        'connection', lambda connection: two_devices.on_connection(1, connection)
    )

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    await two_devices.devices[0].connect(two_devices.devices[1].random_address)

    # Check the post conditions
    assert two_devices.connections[0] is not None
    assert two_devices.connections[1] is not None


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'responder_role,',
    (BT_CENTRAL_ROLE, BT_PERIPHERAL_ROLE),
)
async def test_self_classic_connection(responder_role):
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Attach listeners
    two_devices.devices[0].on(
        'connection', lambda connection: two_devices.on_connection(0, connection)
    )
    two_devices.devices[1].on(
        'connection', lambda connection: two_devices.on_connection(1, connection)
    )

    # Enable Classic connections
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=BT_BR_EDR_TRANSPORT
        ),
        two_devices.devices[1].accept(
            two_devices.devices[0].public_address, responder_role
        ),
    )

    # Check the post conditions
    assert two_devices.connections[0] is not None
    assert two_devices.connections[1] is not None

    # Check the role
    assert two_devices.connections[0].role != responder_role
    assert two_devices.connections[1].role == responder_role

    # Role switch
    await two_devices.connections[0].switch_role(responder_role)

    # Check the role
    assert two_devices.connections[0].role == responder_role
    assert two_devices.connections[1].role != responder_role

    await two_devices.connections[0].disconnect()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_gatt():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Add some GATT characteristics to device 1
    c1 = Characteristic(
        '3A143AD7-D4A7-436B-97D6-5B62C315E833',
        Characteristic.Properties.READ,
        Characteristic.READABLE,
        bytes([1, 2, 3]),
    )
    c2 = Characteristic(
        '9557CCE2-DB37-46EB-94C4-50AE5B9CB0F8',
        Characteristic.Properties.READ | Characteristic.Properties.WRITE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([4, 5, 6]),
    )
    c3 = Characteristic(
        '84FC1A2E-C52D-4A2D-B8C3-8855BAB86638',
        Characteristic.Properties.READ
        | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
        Characteristic.READABLE | Characteristic.WRITEABLE,
        bytes([7, 8, 9]),
    )
    c4 = Characteristic(
        '84FC1A2E-C52D-4A2D-B8C3-8855BAB86638',
        Characteristic.Properties.READ
        | Characteristic.Properties.NOTIFY
        | Characteristic.Properties.INDICATE,
        Characteristic.READABLE,
        bytes([1, 1, 1]),
    )

    s1 = Service('8140E247-04F0-42C1-BC34-534C344DAFCA', [c1, c2, c3])
    s2 = Service('97210A0F-1875-4D05-9E5D-326EB171257A', [c4])
    s3 = Service('1853', [])
    s4 = Service('3A12C182-14E2-4FE0-8C5B-65D7C569F9DB', [], included_services=[s2, s3])
    two_devices.devices[1].add_services([s1, s2, s4])

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    connection = await two_devices.devices[0].connect(
        two_devices.devices[1].random_address
    )
    peer = Peer(connection)

    bogus_uuid = 'A0AA6007-0B48-4BBE-80AC-0DE9AAF541EA'
    result = await peer.discover_services([bogus_uuid])
    assert result == []
    services = peer.get_services_by_uuid(bogus_uuid)
    assert len(services) == 0

    result = await peer.discover_service(s1.uuid)
    assert len(result) == 1
    services = peer.get_services_by_uuid(s1.uuid)
    assert len(services) == 1
    s = services[0]
    assert services[0].uuid == s1.uuid

    result = await peer.discover_characteristics([c1.uuid], s)
    assert len(result) == 1
    characteristics = peer.get_characteristics_by_uuid(c1.uuid)
    assert len(characteristics) == 1
    c = characteristics[0]
    assert c.uuid == c1.uuid
    result = await peer.read_value(c)
    assert result is not None
    assert result == c1.value

    result = await peer.discover_service(s4.uuid)
    assert len(result) == 1
    result = await peer.discover_included_services(result[0])
    assert len(result) == 2
    # Service UUID is only present when the UUID is 16-bit Bluetooth UUID
    assert result[1].uuid.to_bytes() == s3.uuid.to_bytes()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_gatt_long_read():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Add some GATT characteristics to device 1
    characteristics = [
        Characteristic(
            f'3A143AD7-D4A7-436B-97D6-5B62C315{i:04X}',
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            bytes([x & 255 for x in range(i)]),
        )
        for i in range(0, 513)
    ]

    service = Service('8140E247-04F0-42C1-BC34-534C344DAFCA', characteristics)
    two_devices.devices[1].add_service(service)

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    connection = await two_devices.devices[0].connect(
        two_devices.devices[1].random_address
    )
    peer = Peer(connection)

    result = await peer.discover_service(service.uuid)
    assert len(result) == 1
    found_service = result[0]
    found_characteristics = await found_service.discover_characteristics()
    assert len(found_characteristics) == 513
    for i, characteristic in enumerate(found_characteristics):
        value = await characteristic.read_value()
        assert value == characteristics[i].value


# -----------------------------------------------------------------------------
async def _test_self_smp_with_configs(pairing_config1, pairing_config2):
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Attach listeners
    two_devices.devices[0].on(
        'connection', lambda connection: two_devices.on_connection(0, connection)
    )
    two_devices.devices[1].on(
        'connection', lambda connection: two_devices.on_connection(1, connection)
    )

    # Connect the two devices
    connection = await two_devices.devices[0].connect(
        two_devices.devices[1].random_address
    )
    assert not connection.is_encrypted

    # Attach connection listeners
    two_devices.connections[0].on(
        'pairing', lambda keys: two_devices.on_paired(0, keys)
    )
    two_devices.connections[1].on(
        'pairing', lambda keys: two_devices.on_paired(1, keys)
    )

    # Set up the pairing configs
    if pairing_config1:
        two_devices.devices[
            0
        ].pairing_config_factory = lambda connection: pairing_config1
    if pairing_config2:
        two_devices.devices[
            1
        ].pairing_config_factory = lambda connection: pairing_config2

    # Pair
    await two_devices.devices[0].pair(connection)
    assert connection.is_encrypted
    assert await two_devices.paired[0] is not None
    assert await two_devices.paired[1] is not None


# -----------------------------------------------------------------------------
IO_CAP = [
    PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT,
    PairingDelegate.IoCapability.KEYBOARD_INPUT_ONLY,
    PairingDelegate.IoCapability.DISPLAY_OUTPUT_ONLY,
    PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_YES_NO_INPUT,
    PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT,
]
SC = [False, True]
MITM = [False, True]
# Key distribution is a 4-bit bitmask
KEY_DIST = range(16)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'io_caps, sc, mitm, key_dist',
    itertools.chain(
        itertools.product([IO_CAP], SC, MITM, [15]),
        itertools.product(
            [[PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT]],
            SC,
            MITM,
            KEY_DIST,
        ),
    ),
)
async def test_self_smp(io_caps, sc, mitm, key_dist):
    class Delegate(PairingDelegate):
        def __init__(
            self,
            name,
            io_capability,
            local_initiator_key_distribution,
            local_responder_key_distribution,
        ):
            super().__init__(
                io_capability,
                local_initiator_key_distribution,
                local_responder_key_distribution,
            )
            self.name = name
            self.reset()

        def reset(self):
            self.peer_delegate = None
            self.number = asyncio.get_running_loop().create_future()

        # pylint: disable-next=unused-argument
        async def compare_numbers(self, number, digits):
            if self.peer_delegate is None:
                logger.warning(f'[{self.name}] no peer delegate')
                return False
            await self.display_number(number, digits=6)
            logger.debug(f'[{self.name}] waiting for peer number')
            peer_number = await self.peer_delegate.number
            logger.debug(f'[{self.name}] comparing numbers: {number} and {peer_number}')
            return number == peer_number

        async def get_number(self):
            if self.peer_delegate is None:
                logger.warning(f'[{self.name}] no peer delegate')
                return 0
            else:
                if (
                    self.peer_delegate.io_capability
                    == PairingDelegate.IoCapability.KEYBOARD_INPUT_ONLY
                ):
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
        for io_cap in io_caps:
            delegate = Delegate(pairing_config_set[0], io_cap, key_dist, key_dist)
            pairing_config_set[1].append(PairingConfig(sc, mitm, True, delegate))

    for pairing_config1 in pairing_config_sets[0][1]:
        for pairing_config2 in pairing_config_sets[1][1]:
            logger.info(
                f'########## self_smp with {pairing_config1} and {pairing_config2}'
            )
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
            super().__init__(PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT)

        async def accept(self):
            return False

    rejecting_pairing_config = PairingConfig(delegate=RejectingDelegate())
    paired = False
    try:
        await _test_self_smp_with_configs(None, rejecting_pairing_config)
        paired = True
    except ProtocolError as error:
        assert error.error_code == SMP_PAIRING_NOT_SUPPORTED_ERROR

    assert not paired


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_smp_wrong_pin():
    class WrongPinDelegate(PairingDelegate):
        def __init__(self):
            super().__init__(
                PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT
            )

        async def compare_numbers(self, number, digits):
            return False

    wrong_pin_pairing_config = PairingConfig(mitm=True, delegate=WrongPinDelegate())
    paired = False
    try:
        await _test_self_smp_with_configs(
            wrong_pin_pairing_config, wrong_pin_pairing_config
        )
        paired = True
    except ProtocolError as error:
        assert error.error_code == SMP_CONFIRM_VALUE_FAILED_ERROR

    assert not paired


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_smp_over_classic():
    # Create two devices, each with a controller, attached to the same link
    two_devices = TwoDevices()

    # Attach listeners
    two_devices.devices[0].on(
        'connection', lambda connection: two_devices.on_connection(0, connection)
    )
    two_devices.devices[1].on(
        'connection', lambda connection: two_devices.on_connection(1, connection)
    )

    # Enable Classic connections
    two_devices.devices[0].classic_enabled = True
    two_devices.devices[1].classic_enabled = True

    # Start
    await two_devices.devices[0].power_on()
    await two_devices.devices[1].power_on()

    # Connect the two devices
    await asyncio.gather(
        two_devices.devices[0].connect(
            two_devices.devices[1].public_address, transport=BT_BR_EDR_TRANSPORT
        ),
        two_devices.devices[1].accept(two_devices.devices[0].public_address),
    )

    # Check the post conditions
    assert two_devices.connections[0] is not None
    assert two_devices.connections[1] is not None

    # Mock connection
    # TODO: Implement Classic SSP and encryption in link relayer
    LINK_KEY = bytes.fromhex('287ad379dca402530a39f1f43047b835')
    two_devices.devices[0].get_link_key = AsyncMock(return_value=LINK_KEY)
    two_devices.devices[1].get_link_key = AsyncMock(return_value=LINK_KEY)
    two_devices.connections[0].encryption = 1
    two_devices.connections[1].encryption = 1

    two_devices.connections[0].on(
        'pairing', lambda keys: two_devices.on_paired(0, keys)
    )
    two_devices.connections[1].on(
        'pairing', lambda keys: two_devices.on_paired(1, keys)
    )

    # Mock SMP
    with patch('bumble.smp.Session', spec=True) as MockSmpSession:
        MockSmpSession.send_pairing_confirm_command = MagicMock()
        MockSmpSession.send_pairing_dhkey_check_command = MagicMock()
        MockSmpSession.send_public_key_command = MagicMock()
        MockSmpSession.send_pairing_random_command = MagicMock()

        # Start CTKD
        await two_devices.connections[0].pair()
        await asyncio.gather(*two_devices.paired)

        # Phase 2 commands should not be invoked
        MockSmpSession.send_pairing_confirm_command.assert_not_called()
        MockSmpSession.send_pairing_dhkey_check_command.assert_not_called()
        MockSmpSession.send_public_key_command.assert_not_called()
        MockSmpSession.send_pairing_random_command.assert_not_called()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_smp_public_address():
    pairing_config = PairingConfig(
        mitm=True,
        sc=True,
        bonding=True,
        identity_address_type=PairingConfig.AddressType.PUBLIC,
        delegate=PairingDelegate(
            PairingDelegate.IoCapability.DISPLAY_OUTPUT_AND_YES_NO_INPUT,
            PairingDelegate.KeyDistribution.DISTRIBUTE_ENCRYPTION_KEY
            | PairingDelegate.KeyDistribution.DISTRIBUTE_IDENTITY_KEY
            | PairingDelegate.KeyDistribution.DISTRIBUTE_SIGNING_KEY
            | PairingDelegate.KeyDistribution.DISTRIBUTE_LINK_KEY,
        ),
    )

    await _test_self_smp_with_configs(pairing_config, pairing_config)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_smp_oob_sc():
    oob_context_1 = OobContext()
    oob_context_2 = OobContext()

    pairing_config_1 = PairingConfig(
        mitm=True,
        sc=True,
        bonding=True,
        oob=PairingConfig.OobConfig(oob_context_1, oob_context_2.share(), None),
    )

    pairing_config_2 = PairingConfig(
        mitm=True,
        sc=True,
        bonding=True,
        oob=PairingConfig.OobConfig(oob_context_2, oob_context_1.share(), None),
    )

    await _test_self_smp_with_configs(pairing_config_1, pairing_config_2)

    pairing_config_3 = PairingConfig(
        mitm=True,
        sc=True,
        bonding=True,
        oob=PairingConfig.OobConfig(oob_context_2, None, None),
    )

    await _test_self_smp_with_configs(pairing_config_1, pairing_config_3)
    await _test_self_smp_with_configs(pairing_config_3, pairing_config_1)

    pairing_config_4 = PairingConfig(
        mitm=True,
        sc=True,
        bonding=True,
        oob=PairingConfig.OobConfig(oob_context_2, oob_context_2.share(), None),
    )

    with pytest.raises(ProtocolError) as error:
        await _test_self_smp_with_configs(pairing_config_1, pairing_config_4)
    assert error.value.error_code == SMP_CONFIRM_VALUE_FAILED_ERROR

    with pytest.raises(ProtocolError):
        await _test_self_smp_with_configs(pairing_config_4, pairing_config_1)
    assert error.value.error_code == SMP_CONFIRM_VALUE_FAILED_ERROR


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_self_smp_oob_legacy():
    legacy_context = OobLegacyContext()

    pairing_config_1 = PairingConfig(
        mitm=True,
        sc=False,
        bonding=True,
        oob=PairingConfig.OobConfig(None, None, legacy_context),
    )

    pairing_config_2 = PairingConfig(
        mitm=True,
        sc=True,
        bonding=True,
        oob=PairingConfig.OobConfig(OobContext(), None, legacy_context),
    )

    await _test_self_smp_with_configs(pairing_config_1, pairing_config_2)
    await _test_self_smp_with_configs(pairing_config_2, pairing_config_1)


# -----------------------------------------------------------------------------
async def run_test_self():
    await test_self_connection()
    await test_self_gatt()
    await test_self_gatt_long_read()
    await test_self_smp()
    await test_self_smp_reject()
    await test_self_smp_wrong_pin()
    await test_self_smp_over_classic()
    await test_self_smp_public_address()
    await test_self_smp_oob_sc()
    await test_self_smp_oob_legacy()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_test_self())
