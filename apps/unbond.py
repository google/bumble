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

from bumble.device import Device
from bumble.keys import JsonKeyStore
from bumble.transport import open_transport

# -----------------------------------------------------------------------------
async def unbond_with_keystore(keystore, address):
    if address is None:
        return await keystore.print()

    try:
        await keystore.delete(address)
    except KeyError:
        print('!!! pairing not found')


# -----------------------------------------------------------------------------
async def unbond(keystore_file, device_config, hci_transport, address):
    # With a keystore file, we can instantiate the keystore directly
    if keystore_file:
        return await unbond_with_keystore(JsonKeyStore(None, keystore_file), address)

    # Without a keystore file, we need to obtain the keystore from the device
    async with await open_transport(hci_transport) as (hci_source, hci_sink):
        # Create a device to manage the host
        device = Device.from_config_file_with_hci(device_config, hci_source, hci_sink)

        # Power-on the device to ensure we have a key store
        await device.power_on()

        return await unbond_with_keystore(device.keystore, address)


# -----------------------------------------------------------------------------
@click.command()
@click.option('--keystore-file', help='File in which the pairing keys are stored')
@click.option('--hci-transport', help='HCI transport for the controller')
@click.argument('device-config', required=False)
@click.argument('address', required=False)
def main(keystore_file, hci_transport, device_config, address):
    """
    Remove pairing keys for a device, given its address.

    If no keystore file is specified, the --hci-transport option must be used to
    connect to a controller, so that the keystore for that controller can be
    instantiated.
    If no address is passed, the existing pairing keys for all addresses are printed.
    """
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())

    if not keystore_file and not hci_transport:
        print('either --keystore-file or --hci-transport must be specified.')
        return

    asyncio.run(unbond(keystore_file, device_config, hci_transport, address))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
