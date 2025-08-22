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

from bumble import logging
from bumble.colors import color
from bumble.device import Device
from bumble.hci import Address
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: run_scanner.py <transport-spec> [filter]')
        print('example: run_scanner.py usb:0')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[1]) as hci_transport:
        print('<<< connected')
        filter_duplicates = len(sys.argv) == 3 and sys.argv[2] == 'filter'

        device = Device.with_hci(
            'Bumble',
            Address('F0:F1:F2:F3:F4:F5'),
            hci_transport.source,
            hci_transport.sink,
        )

        def on_adv(advertisement):
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

        device.on('advertisement', on_adv)
        await device.power_on()
        await device.start_scanning(filter_duplicates=filter_duplicates)

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.setup_basic_logging('DEBUG')
asyncio.run(main())
