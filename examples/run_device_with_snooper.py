# Copyright 2021-2023 Google LLC
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
from bumble.hci import Address
from bumble.snoop import BtSnooper
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) != 3:
        print('Usage: run_device_with_snooper.py <transport-spec> <snoop-file>')
        print('example: run_device_with_snooper.py usb:0 btsnoop.log')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[1]) as hci_transport:
        print('<<< connected')

        device = Device.with_hci(
            'Bumble',
            Address('F0:F1:F2:F3:F4:F5'),
            hci_transport.source,
            hci_transport.sink,
        )

        with open(sys.argv[2], "wb") as snoop_file:
            device.host.snooper = BtSnooper(snoop_file)
            await device.power_on()
            await device.start_scanning()

            await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
