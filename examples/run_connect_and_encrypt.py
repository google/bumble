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
import sys

import bumble.logging
from bumble.device import Device
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_connect_and_encrypt.py <device-config> <transport-spec> '
            '<bluetooth-address>'
        )
        print(
            'example: run_connect_and_encrypt.py device1.json usb:0 E1:CA:72:48:C4:E8'
        )
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        await device.power_on()

        # Connect to the peer
        target_address = sys.argv[3]
        print(f'=== Connecting to {target_address}...')
        connection = await device.connect(target_address)
        print('=== Connected')
        print('*** Encrypting...')
        try:
            await connection.encrypt()
        except Exception as error:
            print(f'!!! Encryption failed: {error}')
            return

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
