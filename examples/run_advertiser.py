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
import sys
import os
from bumble.device import AdvertisingType, Device
from bumble.hci import Address

from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print(
            'Usage: run_advertiser.py <config-file> <transport-spec> [type] [address]'
        )
        print('example: run_advertiser.py device1.json usb:0')
        return

    if len(sys.argv) >= 4:
        advertising_type = AdvertisingType(int(sys.argv[3]))
    else:
        advertising_type = AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE

    if advertising_type.is_directed:
        if len(sys.argv) < 5:
            print('<address> required for directed advertising')
            return
        target = Address(sys.argv[4])
    else:
        target = None

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        await device.power_on()
        await device.start_advertising(advertising_type=advertising_type, target=target)
        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
