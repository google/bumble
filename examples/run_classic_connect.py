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
from bumble.core import BT_BR_EDR_TRANSPORT, BT_L2CAP_PROTOCOL_ID, CommandTimeoutError
from bumble.sdp import (
    Client as SDP_Client,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_ALL_ATTRIBUTES_RANGE,
)


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print(
            'Usage: run_classic_connect.py <device-config> <transport-spec> '
            '<bluetooth-addresses..>'
        )
        print('example: run_classic_connect.py classic1.json usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True
        device.le_enabled = False
        await device.power_on()

        async def connect(target_address):
            print(f'=== Connecting to {target_address}...')
            try:
                connection = await device.connect(
                    target_address, transport=BT_BR_EDR_TRANSPORT
                )
            except CommandTimeoutError:
                print('!!! Connection timed out')
                return
            print(f'=== Connected to {connection.peer_address}!')

            # Connect to the SDP Server
            sdp_client = SDP_Client(connection)
            await sdp_client.connect()

            # List all services in the root browse group
            service_record_handles = await sdp_client.search_services(
                [SDP_PUBLIC_BROWSE_ROOT]
            )
            print(color('\n==================================', 'blue'))
            print(color('SERVICES:', 'yellow'), service_record_handles)

            # For each service in the root browse group, get all its attributes
            for service_record_handle in service_record_handles:
                attributes = await sdp_client.get_attributes(
                    service_record_handle, [SDP_ALL_ATTRIBUTES_RANGE]
                )
                print(
                    color(f'SERVICE {service_record_handle:04X} attributes:', 'yellow')
                )
                for attribute in attributes:
                    print('  ', attribute.to_string(with_colors=True))

            # Search for services with an L2CAP service attribute
            search_result = await sdp_client.search_attributes(
                [BT_L2CAP_PROTOCOL_ID], [SDP_ALL_ATTRIBUTES_RANGE]
            )
            print(color('\n==================================', 'blue'))
            print(color('SEARCH RESULTS:', 'yellow'))
            for attribute_list in search_result:
                print(color('SERVICE:', 'green'))
                print(
                    '  '
                    + '\n  '.join(
                        [
                            attribute.to_string(with_colors=True)
                            for attribute in attribute_list
                        ]
                    )
                )

            await sdp_client.disconnect()

        # Connect to a peer
        target_addresses = sys.argv[3:]
        await asyncio.wait(
            [
                asyncio.create_task(connect(target_address))
                for target_address in target_addresses
            ]
        )


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
