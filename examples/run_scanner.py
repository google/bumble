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
import os
import logging
from bumble.colors import color

from bumble.device import Device
from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 2:
        print('Usage: run_scanner.py <transport-spec> [filter]')
        print('example: run_scanner.py usb:0')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[1]) as (hci_source, hci_sink):
        print('<<< connected')
        filter_duplicates = len(sys.argv) == 3 and sys.argv[2] == 'filter'

        device = Device.with_hci('Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)

        @device.on('advertisement')
        def _(advertisement):
            address_type_string = ('PUBLIC', 'RANDOM', 'PUBLIC_ID', 'RANDOM_ID')[
                advertisement.address.address_type
            ]
            address_color = 'yellow' if advertisement.is_connectable else 'red'
            address_qualifier = ''
            if address_type_string.startswith('P'):
                type_color = 'cyan'
            else:
                if advertisement.address.is_static:
                    type_color = 'green'
                    address_qualifier = '(static)'
                elif advertisement.address.is_resolvable:
                    type_color = 'magenta'
                    address_qualifier = '(resolvable)'
                else:
                    type_color = 'white'

            separator = '\n  '
            print(
                f'>>> {color(advertisement.address, address_color)} '
                f'[{color(address_type_string, type_color)}]'
                f'{address_qualifier}:{separator}RSSI: {advertisement.rssi}'
                f'{separator}'
                f'{advertisement.data.to_string(separator)}'
            )

        await device.power_on()
        await device.start_scanning(filter_duplicates=filter_duplicates)

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
