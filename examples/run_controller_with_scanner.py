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
from bumble.colors import color
from bumble.controller import Controller
from bumble.device import Device
from bumble.hci import Address
from bumble.link import LocalLink
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
class ScannerListener(Device.Listener):
    def on_advertisement(self, advertisement):
        address_type_string = ('P', 'R', 'PI', 'RI')[advertisement.address.address_type]
        address_color = 'yellow' if advertisement.is_connectable else 'red'
        if address_type_string.startswith('P'):
            type_color = 'green'
        else:
            type_color = 'cyan'

        print(
            f'>>> {color(advertisement.address, address_color)} '
            f'[{color(address_type_string, type_color)}]: '
            f'RSSI={advertisement.rssi}, {advertisement.data}'
        )


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) != 2:
        print('Usage: run_controller.py <transport-spec>')
        print('example: run_controller_with_scanner.py serial:/dev/pts/14,1000000')
        return

    print('>>> connecting to HCI...')
    async with await open_transport(sys.argv[1]) as hci_transport:
        print('>>> connected')

        # Create a local link
        link = LocalLink()

        # Create a first controller using the packet source/sink as its host interface
        controller1 = Controller(
            'C1',
            host_source=hci_transport.source,
            host_sink=hci_transport.sink,
            link=link,
            public_address='E0:E1:E2:E3:E4:E5',
        )

        # Create a second controller using the same link
        controller2 = Controller('C2', link=link)

        # Create a device with a scanner listener
        device = Device.with_hci(
            'Bumble', Address('F0:F1:F2:F3:F4:F5'), controller2, controller2
        )
        device.listener = ScannerListener()
        await device.power_on()
        await device.start_scanning()

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
