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
from __future__ import annotations

import argparse
import asyncio
import sys

import bumble.logging
from bumble import core, l2cap
from bumble.device import Device
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main(
    config_file: str, transport: str, mode: int, peer_address: str, psm: int
) -> None:
    print('<<< connecting to HCI...')
    async with await open_transport(transport) as hci_transport:
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(
            config_file, hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True
        device.l2cap_channel_manager.extended_features.add(
            l2cap.L2CAP_Information_Request.ExtendedFeatures.ENHANCED_RETRANSMISSION_MODE
        )
        device.l2cap_channel_manager.extended_features.add(
            l2cap.L2CAP_Information_Request.ExtendedFeatures.FCS_OPTION
        )

        # Start the controller
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        active_channel: l2cap.ClassicChannel | None = None

        def on_connection(channel: l2cap.ClassicChannel):
            def on_sdu(sdu: bytes):
                print(f'<<< {sdu.decode()}')

            channel.sink = on_sdu
            nonlocal active_channel
            active_channel = channel

        server = device.create_l2cap_server(
            spec=l2cap.ClassicChannelSpec(
                mode=l2cap.TransmissionMode(mode), psm=psm if psm else None
            ),
            handler=on_connection,
        )
        print(f'Listen L2CAP on channel {server.psm}')

        if peer_address:
            connection = await device.connect(
                peer_address, transport=core.PhysicalTransport.BR_EDR
            )
            channel = await connection.create_l2cap_channel(
                spec=l2cap.ClassicChannelSpec(
                    mode=l2cap.TransmissionMode(mode), psm=psm
                )
            )
            active_channel = channel

        while sdu := await asyncio.to_thread(lambda: input('>>> ')):
            if active_channel:
                active_channel.write(sdu.encode())

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('INFO')
parser = argparse.ArgumentParser()
parser.add_argument('config')
parser.add_argument('transport')
parser.add_argument('-p', '--peer_address', default='')
parser.add_argument(
    '-m', '--mode', default=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION
)
parser.add_argument('--psm', default=0)
args = parser.parse_args(sys.argv[1:])
asyncio.run(main(args.config, args.transport, args.mode, args.peer_address, args.psm))
