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
import os
import logging
import click
from prompt_toolkit.shortcuts import PromptSession

from bumble.colors import color
from bumble.device import Device, Peer
from bumble.transport import open_transport_or_link
from bumble.pairing import OobData, PairingDelegate, PairingConfig
from bumble.smp import OobContext, OobLegacyContext
from bumble.smp import error_name as smp_error_name
from bumble.keys import JsonKeyStore
from bumble.core import (
    AdvertisingData,
    ProtocolError,
    BT_LE_TRANSPORT,
    BT_BR_EDR_TRANSPORT,
)
from bumble.gatt import (
    GATT_DEVICE_NAME_CHARACTERISTIC,
    GATT_GENERIC_ACCESS_SERVICE,
    Service,
    Characteristic,
    CharacteristicValue,
)
from bumble.att import (
    ATT_Error,
    ATT_INSUFFICIENT_AUTHENTICATION_ERROR,
    ATT_INSUFFICIENT_ENCRYPTION_ERROR,
)


# -----------------------------------------------------------------------------
class Waiter:
    instance = None

    def __init__(self):
        self.done = asyncio.get_running_loop().create_future()

    def terminate(self):
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
    if mode == 'classic':
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


def write_with_error(connection, _value):
    if not connection.is_encrypted:
        raise ATT_Error(ATT_INSUFFICIENT_ENCRYPTION_ERROR)

    if not AUTHENTICATION_ERROR_RETURNED[1]:
        AUTHENTICATION_ERROR_RETURNED[1] = True
        raise ATT_Error(ATT_INSUFFICIENT_AUTHENTICATION_ERROR)


# -----------------------------------------------------------------------------
def on_connection(connection, request):
    print(color(f'<<< Connection: {connection}', 'green'))

    # Listen for pairing events
    connection.on('pairing_start', on_pairing_start)
    connection.on('pairing', lambda keys: on_pairing(connection.peer_address, keys))
    connection.on('pairing_failure', on_pairing_failure)

    # Listen for encryption changes
    connection.on(
        'connection_encryption_change',
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
def on_pairing(address, keys):
    print(color('***-----------------------------------', 'cyan'))
    print(color(f'*** Paired! (peer identity={address})', 'cyan'))
    keys.print(prefix=color('*** ', 'cyan'))
    print(color('***-----------------------------------', 'cyan'))
    Waiter.instance.terminate()


# -----------------------------------------------------------------------------
def on_pairing_failure(reason):
    print(color('***-----------------------------------', 'red'))
    print(color(f'*** Pairing failed: {smp_error_name(reason)}', 'red'))
    print(color('***-----------------------------------', 'red'))
    Waiter.instance.terminate()


# -----------------------------------------------------------------------------
async def pair(
    mode,
    sc,
    mitm,
    bond,
    ctkd,
    linger,
    io,
    oob,
    prompt,
    request,
    print_keys,
    keystore_file,
    device_config,
    hci_transport,
    address_or_name,
):
    Waiter.instance = Waiter()

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(hci_transport) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device to manage the host
        device = Device.from_config_file_with_hci(device_config, hci_source, hci_sink)

        # Expose a GATT characteristic that can be used to trigger pairing by
        # responding with an authentication error when read
        if mode == 'le':
            device.le_enabled = True
            device.add_service(
                Service(
                    '50DB505C-8AC4-4738-8448-3B1D9CC09CC5',
                    [
                        Characteristic(
                            '552957FB-CF1F-4A31-9535-E78847E1A714',
                            Characteristic.Properties.READ
                            | Characteristic.Properties.WRITE,
                            Characteristic.READABLE | Characteristic.WRITEABLE,
                            CharacteristicValue(
                                read=read_with_error, write=write_with_error
                            ),
                        )
                    ],
                )
            )

        # Select LE or Classic
        if mode == 'classic':
            device.classic_enabled = True
            device.classic_smp_enabled = ctkd

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
            shared_data = (
                None
                if oob == '-'
                else OobData.from_ad(AdvertisingData.from_bytes(bytes.fromhex(oob)))
            )
            legacy_context = OobLegacyContext()
            oob_contexts = PairingConfig.OobConfig(
                our_context=our_oob_context,
                peer_data=shared_data,
                legacy_context=legacy_context,
            )
            oob_data = OobData(
                address=device.random_address,
                shared_data=shared_data,
                legacy_context=legacy_context,
            )
            print(color('@@@-----------------------------------', 'yellow'))
            print(color('@@@ OOB Data:', 'yellow'))
            print(color(f'@@@   {our_oob_context.share()}', 'yellow'))
            print(color(f'@@@   TK={legacy_context.tk.hex()}', 'yellow'))
            print(color(f'@@@   HEX: ({bytes(oob_data.to_ad()).hex()})', 'yellow'))
            print(color('@@@-----------------------------------', 'yellow'))
        else:
            oob_contexts = None

        # Set up a pairing config factory
        device.pairing_config_factory = lambda connection: PairingConfig(
            sc=sc,
            mitm=mitm,
            bonding=bond,
            oob=oob_contexts,
            delegate=Delegate(mode, connection, io, prompt),
        )

        # Connect to a peer or wait for a connection
        device.on('connection', lambda connection: on_connection(connection, request))
        if address_or_name is not None:
            print(color(f'=== Connecting to {address_or_name}...', 'green'))
            connection = await device.connect(
                address_or_name,
                transport=BT_LE_TRANSPORT if mode == 'le' else BT_BR_EDR_TRANSPORT,
            )
            pairing_failure = False

            if not request:
                try:
                    if mode == 'le':
                        await connection.pair()
                    else:
                        await connection.authenticate()
                except ProtocolError as error:
                    pairing_failure = True
                    print(color(f'Pairing failed: {error}', 'red'))

            if not linger or pairing_failure:
                return
        else:
            if mode == 'le':
                # Advertise so that peers can find us and connect
                await device.start_advertising(auto_restart=True)
            else:
                # Become discoverable and connectable
                await device.set_discoverable(True)
                await device.set_connectable(True)

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
    '--mode', type=click.Choice(['le', 'classic']), default='le', show_default=True
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
@click.option('--linger', default=True, is_flag=True, help='Linger after pairing')
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
    metavar='<filename>',
    help='File in which to store the pairing keys',
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
    linger,
    io,
    oob,
    prompt,
    request,
    print_keys,
    keystore_file,
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
            linger,
            io,
            oob,
            prompt,
            request,
            print_keys,
            keystore_file,
            device_config,
            hci_transport,
            address_or_name,
        )
    )


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
