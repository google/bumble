# Copyright 2021-2025 Google LLC
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

from typing import Optional

import bumble.logging
from bumble.device import Device
from bumble import l2cap
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main() -> None:

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True
        device.l2cap_channel_manager.extended_features.add(
            l2cap.L2CAP_Information_Request.ExtendedFeatures.ENHANCED_RETRANSMISSION_MODE
        )

        # Start the controller
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        channels: list[l2cap.ClassicChannel] = []

        def on_connection(channel: l2cap.ClassicChannel):

            def on_sdu(sdu: bytes):
                print(f'<<< {sdu.decode()}')

            channel.sink = on_sdu
            if channels:
                channels.clear()
            channels.append(channel)

        server = device.create_l2cap_server(
            spec=l2cap.ClassicChannelSpec(
                mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION
            ),
            handler=on_connection,
        )
        print(f'Listen L2CAP on channel {server.psm}')

        while sdu := await asyncio.to_thread(lambda: input('>>> ')):
            if channels:
                channels[0].write(sdu.encode())

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('INFO')
asyncio.run(main())
