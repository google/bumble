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
import struct

import click
from prompt_toolkit.shortcuts import PromptSession

from bumble import data_types
from bumble.a2dp import make_audio_sink_service_sdp_records
from bumble.att import (
    ATT_INSUFFICIENT_AUTHENTICATION_ERROR,
    ATT_INSUFFICIENT_ENCRYPTION_ERROR,
    ATT_Error,
)
from bumble.colors import color
from bumble.core import (
    UUID,
    AdvertisingData,
    Appearance,
    DataType,
    PhysicalTransport,
    ProtocolError,
)
from bumble.device import Device, Peer
from bumble.gatt import (
    GATT_DEVICE_NAME_CHARACTERISTIC,
    GATT_GENERIC_ACCESS_SERVICE,
    GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC,
    GATT_HEART_RATE_SERVICE,
    Characteristic,
    Service,
)
from bumble.hci import OwnAddressType
from bumble.keys import JsonKeyStore
from bumble.pairing import OobData, PairingConfig, PairingDelegate
from bumble.smp import OobContext, OobLegacyContext
from bumble.smp import error_name as smp_error_name
from bumble.transport import open_transport
from bumble.utils import AsyncRunner

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
POST_PAIRING_DELAY = 1


# -----------------------------------------------------------------------------
class Waiter:
    instance = None

    def __init__(self, linger=False):
        self.done = asyncio.get_running_loop().create_future()
        self.linger = linger

    def terminate(self):
        if not self.linger and not self.done.done:
            self.done.set_result(None)

    async def wait_until_terminated(self):
        return await self.done


# -----------------------------------------------------------------------------
class Delegate(PairingDelegate):
    def __init__(self, mode, connection, capability_string, do_prompt):
        super().__init__(
            io_capability={
                'keyboard': PairingDelegate.KEYBOARD_INPUT_ONLY,
                'display': PairingDelegate.DISPLAY_OUTPUT_ONLY,
                'display+keyboard': PairingDelegate.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT,
                'display+yes/no': PairingDelegate.DISPLAY_OUTPUT_AND_YES_NO_INPUT,
                'none': PairingDelegate.NO_OUTPUT_NO_INPUT,
            }[capability_string.lower()]
        )

        self.mode = mode
        self.peer = Peer(connection)
        self.peer_name = None
        self.do_prompt = do_prompt

    def print(self, message):
        print(color(message, 'yellow'))

    async def prompt(self, message):
        # Wait a bit to allow some of the log lines to print before we prompt
        await asyncio.sleep(1)

        session = PromptSession(message)
        response = await session.prompt_async()
        return response.lower().strip()

    async def update_peer_name(self):
        if self.peer_name is not None:
            # We already asked the peer
            return

        # Try to get the peer's name
        if self.peer:
            peer_name = await get_peer_name(self.peer, self.mode)
            self.peer_name = f'{peer_name or ""} [{self.peer.connection.peer_address}]'
        else:
            self.peer_name = '[?]'

    async def accept(self):
        if self.do_prompt:
            await self.update_peer_name()

            # Prompt for acceptance
            self.print('###-----------------------------------')
            self.print(f'### Pairing request from {self.peer_name}')
            self.print('###-----------------------------------')
            while True:
                response = await self.prompt('>>> Accept? ')

                if response == 'yes':
                    return True

                if response == 'no':
                    return False

        # Accept silently
        return True

    async def compare_numbers(self, number, digits):
        await self.update_peer_name()

        # Prompt for a numeric comparison
        self.print('###-----------------------------------')
        self.print(f'### Pairing with {self.peer_name}')
        self.print('###-----------------------------------')
        while True:
            response = await self.prompt(
                f'>>> Does the other device display {number:0{digits}}? '
            )

            if response == 'yes':
                return True

            if response == 'no':
                return False

    async def get_number(self):
        await self.update_peer_name()

        # Prompt for a PIN
        while True:
            try:
                self.print('###-----------------------------------')
                self.print(f'### Pairing with {self.peer_name}')
                self.print('###-----------------------------------')
                return int(await self.prompt('>>> Enter PIN: '))
            except ValueError:
                pass

    async def display_number(self, number, digits):
        await self.update_peer_name()

        # Display a PIN code
        self.print('###-----------------------------------')
        self.print(f'### Pairing with {self.peer_name}')
        self.print(f'### PIN: {number:0{digits}}')
        self.print('###-----------------------------------')

    async def get_string(self, max_length: int):
        await self.update_peer_name()

        # Prompt a PIN (for legacy pairing in classic)
        self.print('###-----------------------------------')
        self.print(f'### Pairing with {self.peer_name}')
        self.print('###-----------------------------------')
        count = 0
        while True:
            response = await self.prompt('>>> Enter PIN (1-6 chars):')
            if len(response) == 0:
                count += 1
                if count > 3:
                    self.print('too many tries, stopping the pairing')
                    return None

                self.print('no PIN was entered, try again')
                continue
            return response


# -----------------------------------------------------------------------------
async def get_peer_name(peer, mode):
    if peer.connection.transport == PhysicalTransport.BR_EDR:
        return await peer.request_name()

    # Try to get the peer name from GATT
    services = await peer.discover_service(GATT_GENERIC_ACCESS_SERVICE)
    if not services:
        return None

    values = await peer.read_characteristics_by_uuid(
        GATT_DEVICE_NAME_CHARACTERISTIC, services[0]
    )
    if values:
        return values[0].decode('utf-8')

    return None


# -----------------------------------------------------------------------------
AUTHENTICATION_ERROR_RETURNED = [False, False]


def read_with_error(connection):
    if not connection.is_encrypted:
        raise ATT_Error(ATT_INSUFFICIENT_ENCRYPTION_ERROR)

    if AUTHENTICATION_ERROR_RETURNED[0]:
        return bytes([1])

    AUTHENTICATION_ERROR_RETURNED[0] = True
    raise ATT_Error(ATT_INSUFFICIENT_AUTHENTICATION_ERROR)


# -----------------------------------------------------------------------------
def sdp_records():
    service_record_handle = 0x00010001
    return {
        service_record_handle: make_audio_sink_service_sdp_records(
            service_record_handle
        )
    }


# -----------------------------------------------------------------------------
def on_connection(connection, request):
    print(color(f'<<< Connection: {connection}', 'green'))

    # Listen for pairing events
    connection.on(connection.EVENT_PAIRING_START, on_pairing_start)
    connection.on(connection.EVENT_PAIRING, lambda keys: on_pairing(connection, keys))
    connection.on(
        connection.EVENT_CLASSIC_PAIRING, lambda: on_classic_pairing(connection)
    )
    connection.on(
        connection.EVENT_PAIRING_FAILURE,
        lambda reason: on_pairing_failure(connection, reason),
    )

    # Listen for encryption changes
    connection.on(
        connection.EVENT_CONNECTION_ENCRYPTION_CHANGE,
        lambda: on_connection_encryption_change(connection),
    )

    # Request pairing if needed
    if request:
        print(color('>>> Requesting pairing', 'green'))
        connection.request_pairing()


# -----------------------------------------------------------------------------
def on_connection_encryption_change(connection):
    print(color('@@@-----------------------------------', 'blue'))
    print(
        color(
            f'@@@ Connection is {"" if connection.is_encrypted else "not"}encrypted',
            'blue',
        )
    )
    print(color('@@@-----------------------------------', 'blue'))


# -----------------------------------------------------------------------------
def on_pairing_start():
    print(color('***-----------------------------------', 'magenta'))
    print(color('*** Pairing starting', 'magenta'))
    print(color('***-----------------------------------', 'magenta'))


# -----------------------------------------------------------------------------
@AsyncRunner.run_in_task()
async def on_pairing(connection, keys):
    print(color('***-----------------------------------', 'cyan'))
    print(color(f'*** Paired! (peer identity={connection.peer_address})', 'cyan'))
    keys.print(prefix=color('*** ', 'cyan'))
    print(color('***-----------------------------------', 'cyan'))
    await asyncio.sleep(POST_PAIRING_DELAY)
    await connection.disconnect()
    Waiter.instance.terminate()


# -----------------------------------------------------------------------------
@AsyncRunner.run_in_task()
async def on_classic_pairing(connection):
    print(color('***-----------------------------------', 'cyan'))
    print(
        color(
            f'*** Paired [Classic]! (peer identity={connection.peer_address})', 'cyan'
        )
    )
    print(color('***-----------------------------------', 'cyan'))
    await asyncio.sleep(POST_PAIRING_DELAY)
    Waiter.instance.terminate()


# -----------------------------------------------------------------------------
@AsyncRunner.run_in_task()
async def on_pairing_failure(connection, reason):
    print(color('***-----------------------------------', 'red'))
    print(color(f'*** Pairing failed: {smp_error_name(reason)}', 'red'))
    print(color('***-----------------------------------', 'red'))
    await connection.disconnect()
    Waiter.instance.terminate()


# -----------------------------------------------------------------------------
async def pair(
    mode,
    sc,
    mitm,
    bond,
    ctkd,
    advertising_address,
    identity_address,
    linger,
    io,
    oob,
    prompt,
    request,
    print_keys,
    keystore_file,
    advertise_service_uuids,
    advertise_appearance,
    device_config,
    hci_transport,
    address_or_name,
):
    Waiter.instance = Waiter(linger=linger)

    print('<<< connecting to HCI...')
    async with await open_transport(hci_transport) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device to manage the host
        device = Device.from_config_file_with_hci(device_config, hci_source, hci_sink)

        # Expose a GATT characteristic that can be used to trigger pairing by
        # responding with an authentication error when read
        if mode in ('le', 'dual'):
            device.add_service(
                Service(
                    GATT_HEART_RATE_SERVICE,
                    [
                        Characteristic(
                            GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC,
                            Characteristic.Properties.READ,
                            Characteristic.READ_REQUIRES_AUTHENTICATION,
                            bytes(1),
                        )
                    ],
                )
            )

        # LE and Classic support
        if mode in ('classic', 'dual'):
            device.classic_enabled = True
            device.classic_smp_enabled = ctkd
        if mode in ('le', 'dual'):
            device.le_enabled = True
        if mode == 'dual':
            device.le_simultaneous_enabled = True

        # Setup SDP
        if mode in ('classic', 'dual'):
            device.sdp_service_records = sdp_records()

        # Get things going
        await device.power_on()

        # Set a custom keystore if specified on the command line
        if keystore_file:
            device.keystore = JsonKeyStore.from_device(device, filename=keystore_file)

        # Print the existing keys before pairing
        if print_keys and device.keystore:
            print(color('@@@-----------------------------------', 'blue'))
            print(color('@@@ Pairing Keys:', 'blue'))
            await device.keystore.print(prefix=color('@@@ ', 'blue'))
            print(color('@@@-----------------------------------', 'blue'))

        # Create an OOB context if needed
        if oob:
            our_oob_context = OobContext()
            if oob == '-':
                shared_data = None
                legacy_context = OobLegacyContext()
            else:
                oob_data = OobData.from_ad(
                    AdvertisingData.from_bytes(bytes.fromhex(oob))
                )
                shared_data = oob_data.shared_data
                legacy_context = oob_data.legacy_context
                if legacy_context is None and not sc:
                    print(color('OOB pairing in legacy mode requires TK', 'red'))
                    return

            oob_contexts = PairingConfig.OobConfig(
                our_context=our_oob_context,
                peer_data=shared_data,
                legacy_context=legacy_context,
            )
            print(color('@@@-----------------------------------', 'yellow'))
            print(color('@@@ OOB Data:', 'yellow'))
            if shared_data is None:
                oob_data = OobData(
                    address=device.random_address,
                    shared_data=our_oob_context.share(),
                    legacy_context=(None if sc else legacy_context),
                )
                print(
                    color(
                        f'@@@   SHARE: {bytes(oob_data.to_ad()).hex()}',
                        'yellow',
                    )
                )
            if legacy_context:
                print(color(f'@@@   TK={legacy_context.tk.hex()}', 'yellow'))
            print(color('@@@-----------------------------------', 'yellow'))
        else:
            oob_contexts = None

        # Set up a pairing config factory
        if identity_address == 'public':
            identity_address_type = PairingConfig.AddressType.PUBLIC
        elif identity_address == 'random':
            identity_address_type = PairingConfig.AddressType.RANDOM
        else:
            identity_address_type = None
        device.pairing_config_factory = lambda connection: PairingConfig(
            sc=sc,
            mitm=mitm,
            bonding=bond,
            oob=oob_contexts,
            identity_address_type=identity_address_type,
            delegate=Delegate(mode, connection, io, prompt),
        )

        # Connect to a peer or wait for a connection
        device.on('connection', lambda connection: on_connection(connection, request))
        if address_or_name is not None:
            print(color(f'=== Connecting to {address_or_name}...', 'green'))
            connection = await device.connect(
                address_or_name,
                transport=(
                    PhysicalTransport.LE if mode == 'le' else PhysicalTransport.BR_EDR
                ),
            )

            if not request:
                try:
                    if mode == 'le':
                        await connection.pair()
                    else:
                        await connection.authenticate()
                except ProtocolError as error:
                    print(color(f'Pairing failed: {error}', 'red'))

        else:
            if mode in ('le', 'dual'):
                # Advertise so that peers can find us and connect.
                # Include the heart rate service UUID in the advertisement data
                # so that devices like iPhones can show this device in their
                # Bluetooth selector.
                service_uuids_16 = []
                service_uuids_32 = []
                service_uuids_128 = []
                if advertise_service_uuids:
                    for uuid in advertise_service_uuids:
                        uuid = uuid.replace("-", "")
                        if len(uuid) == 4:
                            service_uuids_16.append(UUID(uuid))
                        elif len(uuid) == 8:
                            service_uuids_32.append(UUID(uuid))
                        elif len(uuid) == 32:
                            service_uuids_128.append(UUID(uuid))
                        else:
                            print(color('Invalid UUID format', 'red'))
                            return
                else:
                    service_uuids_16.append(GATT_HEART_RATE_SERVICE)

                flags = AdvertisingData.Flags.LE_LIMITED_DISCOVERABLE_MODE
                if mode == 'le':
                    flags |= AdvertisingData.Flags.BR_EDR_NOT_SUPPORTED
                if mode == 'dual':
                    flags |= AdvertisingData.Flags.SIMULTANEOUS_LE_BR_EDR_CAPABLE

                advertising_data_types: list[DataType] = [
                    data_types.Flags(flags),
                    data_types.CompleteLocalName('Bumble'),
                ]
                if service_uuids_16:
                    advertising_data_types.append(
                        data_types.IncompleteListOf16BitServiceUUIDs(service_uuids_16)
                    )
                if service_uuids_32:
                    advertising_data_types.append(
                        data_types.IncompleteListOf32BitServiceUUIDs(service_uuids_32)
                    )
                if service_uuids_128:
                    advertising_data_types.append(
                        data_types.IncompleteListOf128BitServiceUUIDs(service_uuids_128)
                    )

                if advertise_appearance:
                    advertise_appearance = advertise_appearance.upper()
                    try:
                        advertise_appearance_int = int(advertise_appearance)
                    except ValueError:
                        category, subcategory = advertise_appearance.split('/')
                        try:
                            category_enum = Appearance.Category[category]
                        except ValueError:
                            print(
                                color(f'Invalid appearance category {category}', 'red')
                            )
                            return
                        subcategory_class = Appearance.SUBCATEGORY_CLASSES[
                            category_enum
                        ]
                        try:
                            subcategory_enum = subcategory_class[subcategory]
                        except ValueError:
                            print(color(f'Invalid subcategory {subcategory}', 'red'))
                            return
                        advertise_appearance_int = int(
                            Appearance(category_enum, subcategory_enum)
                        )
                    advertising_data_types.append(
                        data_types.Appearance(category_enum, subcategory_enum)
                    )
                device.advertising_data = bytes(AdvertisingData(advertising_data_types))
                await device.start_advertising(
                    auto_restart=True,
                    own_address_type=(
                        OwnAddressType.PUBLIC
                        if advertising_address == 'public'
                        else OwnAddressType.RANDOM
                    ),
                )

            if mode in ('classic', 'dual'):
                # Become discoverable and connectable
                await device.set_discoverable(True)
                await device.set_connectable(True)
                print(color('Ready for connections on', 'blue'), device.public_address)

        # Run until the user asks to exit
        await Waiter.instance.wait_until_terminated()


# -----------------------------------------------------------------------------
class LogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))

    def emit(self, record):
        message = self.format(record)
        print(message)


# -----------------------------------------------------------------------------
@click.command()
@click.option(
    '--mode',
    type=click.Choice(['le', 'classic', 'dual']),
    default='le',
    show_default=True,
)
@click.option(
    '--sc',
    type=bool,
    default=True,
    help='Use the Secure Connections protocol',
    show_default=True,
)
@click.option(
    '--mitm', type=bool, default=True, help='Request MITM protection', show_default=True
)
@click.option(
    '--bond', type=bool, default=True, help='Enable bonding', show_default=True
)
@click.option(
    '--ctkd',
    type=bool,
    default=True,
    help='Enable CTKD',
    show_default=True,
)
@click.option(
    '--advertising-address',
    type=click.Choice(['random', 'public']),
)
@click.option(
    '--identity-address',
    type=click.Choice(['random', 'public']),
)
@click.option('--linger', default=False, is_flag=True, help='Linger after pairing')
@click.option(
    '--io',
    type=click.Choice(
        ['keyboard', 'display', 'display+keyboard', 'display+yes/no', 'none']
    ),
    default='display+keyboard',
    show_default=True,
)
@click.option(
    '--oob',
    metavar='<oob-data-hex>',
    help=(
        'Use OOB pairing with this data from the peer '
        '(use "-" to enable OOB without peer data)'
    ),
)
@click.option('--prompt', is_flag=True, help='Prompt to accept/reject pairing request')
@click.option(
    '--request', is_flag=True, help='Request that the connecting peer initiate pairing'
)
@click.option('--print-keys', is_flag=True, help='Print the bond keys before pairing')
@click.option(
    '--keystore-file',
    metavar='FILENAME',
    help='File in which to store the pairing keys',
)
@click.option(
    '--advertise-service-uuid',
    metavar="UUID",
    multiple=True,
    help="Advertise a GATT service UUID (may be specified more than once)",
)
@click.option(
    '--advertise-appearance',
    metavar='APPEARANCE',
    help='Advertise an Appearance ID (int value or string)',
)
@click.argument('device-config')
@click.argument('hci_transport')
@click.argument('address-or-name', required=False)
def main(
    mode,
    sc,
    mitm,
    bond,
    ctkd,
    advertising_address,
    identity_address,
    linger,
    io,
    oob,
    prompt,
    request,
    print_keys,
    keystore_file,
    advertise_service_uuid,
    advertise_appearance,
    device_config,
    hci_transport,
    address_or_name,
):
    # Setup logging
    log_handler = LogHandler()
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)
    root_logger.setLevel(os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())

    # Pair
    asyncio.run(
        pair(
            mode,
            sc,
            mitm,
            bond,
            ctkd,
            advertising_address,
            identity_address,
            linger,
            io,
            oob,
            prompt,
            request,
            print_keys,
            keystore_file,
            advertise_service_uuid,
            advertise_appearance,
            device_config,
            hci_transport,
            address_or_name,
        )
    )


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
