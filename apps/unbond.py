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


# -----------------------------------------------------------------------------
async def unbond(keystore_file, device_config, address):
    # Create a device to manage the host
    device = Device.from_config_file(device_config)

    # Get all entries in the keystore
    if keystore_file:
        keystore = JsonKeyStore(None, keystore_file)
    else:
        keystore = device.keystore

    if keystore is None:
        print('no keystore')
        return

    if address is None:
        await keystore.print()
    else:
        try:
            await keystore.delete(address)
        except KeyError:
            print('!!! pairing not found')


# -----------------------------------------------------------------------------
@click.command()
@click.option('--keystore-file', help='File in which to store the pairing keys')
@click.argument('device-config')
@click.argument('address', required=False)
def main(keystore_file, device_config, address):
    logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(unbond(keystore_file, device_config, address))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
