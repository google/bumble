# Copyright 2024 Google LLC
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
from __future__ import annotations

import asyncio
import logging
import sys
import os
import functools

from bumble import core
from bumble import hci
from bumble.device import Connection, Device, ChannelSoundingCapabilities
from bumble.transport import open_transport_or_link

# From https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/Bluetooth/system/gd/hci/distance_measurement_manager.cc.
CS_TONE_ANTENNA_CONFIG_MAPPING_TABLE = [
    [0, 4, 5, 6],
    [1, 7, 7, 7],
    [2, 7, 7, 7],
    [3, 7, 7, 7],
]
CS_PREFERRED_PEER_ANTENNA_MAPPING_TABLE = [1, 1, 1, 1, 3, 7, 15, 3]
CS_ANTENNA_PERMUTATION_ARRAY = [
    [1, 2, 3, 4],
    [2, 1, 3, 4],
    [1, 3, 2, 4],
    [3, 1, 2, 4],
    [3, 2, 1, 4],
    [2, 3, 1, 4],
    [1, 2, 4, 3],
    [2, 1, 4, 3],
    [1, 4, 2, 3],
    [4, 1, 2, 3],
    [4, 2, 1, 3],
    [2, 4, 1, 3],
    [1, 4, 3, 2],
    [4, 1, 3, 2],
    [1, 3, 4, 2],
    [3, 1, 4, 2],
    [3, 4, 1, 2],
    [4, 3, 1, 2],
    [4, 2, 3, 1],
    [2, 4, 3, 1],
    [4, 3, 2, 1],
    [3, 4, 2, 1],
    [3, 2, 4, 1],
    [2, 3, 4, 1],
]


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_channel_sounding.py <config-file> <transport-spec-for-device>'
            '[target_address](If missing, run as reflector)'
        )
        print('example: run_channel_sounding.py cs_reflector.json usb:0')
        print(
            'example: run_channel_sounding.py cs_initiator.json usb:0 F0:F1:F2:F3:F4:F5'
        )
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        await device.power_on()
        assert (local_cs_capabilities := device.cs_capabilities)

        if len(sys.argv) == 3:
            print('<<< Start Advertising')
            await device.start_advertising(
                own_address_type=hci.OwnAddressType.RANDOM, auto_restart=True
            )

            def on_cs_capabilities(
                connection: Connection, capabilities: ChannelSoundingCapabilities
            ):
                del capabilities
                print('<<< Set CS Settings')
                asyncio.create_task(device.set_default_cs_settings(connection))

            device.on(
                'connection',
                lambda connection: connection.on(
                    'channel_sounding_capabilities',
                    functools.partial(on_cs_capabilities, connection),
                ),
            )
        else:
            target_address = hci.Address(sys.argv[3])

            print(f'<<< Connecting to {target_address}')
            connection = await device.connect(
                target_address, transport=core.PhysicalTransport.LE
            )
            print('<<< ACL Connected')
            if not (await device.get_long_term_key(connection.handle, b'', 0)):
                print('<<< No bond, start pairing')
                await connection.pair()
                print('<<< Pairing complete')

            print('<<< Encrypting Connection')
            await connection.encrypt()

            print('<<< Getting remote CS Capabilities...')
            remote_capabilities = await device.get_remote_cs_capabilities(connection)
            print('<<< Set CS Settings...')
            await device.set_default_cs_settings(connection)
            print('<<< Set CS Config...')
            config = await device.create_cs_config(connection)
            print('<<< Enable CS Security...')
            await device.enable_cs_security(connection)
            tone_antenna_config_selection = CS_TONE_ANTENNA_CONFIG_MAPPING_TABLE[
                local_cs_capabilities.num_antennas_supported - 1
            ][remote_capabilities.num_antennas_supported - 1]
            print('<<< Set CS Procedure Parameters...')
            await device.set_cs_procedure_parameters(
                connection=connection,
                config=config,
                tone_antenna_config_selection=tone_antenna_config_selection,
                preferred_peer_antenna=CS_PREFERRED_PEER_ANTENNA_MAPPING_TABLE[
                    tone_antenna_config_selection
                ],
            )
            print('<<< Enable CS Procedure...')
            await device.enable_cs_procedure(connection=connection, config=config)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
