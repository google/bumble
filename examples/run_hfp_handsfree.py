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
import json
import websockets
from typing import Optional

from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.rfcomm import Server as RfcommServer
from bumble import hfp
from bumble.hfp import HfProtocol


# -----------------------------------------------------------------------------
class UiServer:
    protocol: Optional[HfProtocol] = None

    async def start(self):
        """Start a Websocket server to receive events from a web page."""

        async def serve(websocket, _path):
            while True:
                try:
                    message = await websocket.recv()
                    print('Received: ', str(message))

                    parsed = json.loads(message)
                    message_type = parsed['type']
                    if message_type == 'at_command':
                        if self.protocol is not None:
                            await self.protocol.execute_command(parsed['command'])

                except websockets.exceptions.ConnectionClosedOK:
                    pass

        # pylint: disable=no-member
        await websockets.serve(serve, 'localhost', 8989)


# -----------------------------------------------------------------------------
def on_dlc(dlc, configuration: hfp.Configuration):
    print('*** DLC connected', dlc)
    protocol = HfProtocol(dlc, configuration)
    UiServer.protocol = protocol
    asyncio.create_task(protocol.run())


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print('Usage: run_classic_hfp.py <device-config> <transport-spec>')
        print('example: run_classic_hfp.py classic2.json usb:04b4:f901')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Hands-Free profile configuration.
        # TODO: load configuration from file.
        configuration = hfp.Configuration(
            supported_hf_features=[
                hfp.HfFeature.THREE_WAY_CALLING,
                hfp.HfFeature.REMOTE_VOLUME_CONTROL,
                hfp.HfFeature.ENHANCED_CALL_STATUS,
                hfp.HfFeature.ENHANCED_CALL_CONTROL,
                hfp.HfFeature.CODEC_NEGOTIATION,
                hfp.HfFeature.HF_INDICATORS,
                hfp.HfFeature.ESCO_S4_SETTINGS_SUPPORTED,
            ],
            supported_hf_indicators=[
                hfp.HfIndicator.BATTERY_LEVEL,
            ],
            supported_audio_codecs=[
                hfp.AudioCodec.CVSD,
                hfp.AudioCodec.MSBC,
            ],
        )

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True

        # Create and register a server
        rfcomm_server = RfcommServer(device)

        # Listen for incoming DLC connections
        channel_number = rfcomm_server.listen(lambda dlc: on_dlc(dlc, configuration))
        print(f'### Listening for connection on channel {channel_number}')

        # Advertise the HFP RFComm channel in the SDP
        device.sdp_service_records = {
            0x00010001: hfp.sdp_records(0x00010001, channel_number, configuration)
        }

        # Let's go!
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        # Start the UI websocket server to offer a few buttons and input boxes
        ui_server = UiServer()
        await ui_server.start()

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
