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
import websockets
import json


from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.rfcomm import Server as RfommServer
from bumble.sdp import (
    DataElement,
    ServiceAttribute,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID
)
from bumble.core import (
    BT_GENERIC_AUDIO_SERVICE,
    BT_HANDSFREE_SERVICE,
    BT_L2CAP_PROTOCOL_ID,
    BT_RFCOMM_PROTOCOL_ID
)
from bumble.hfp import HfpProtocol


# -----------------------------------------------------------------------------
def make_sdp_records(rfcomm_channel):
    return {
        0x00010001: [
            ServiceAttribute(
                SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                DataElement.unsigned_integer_32(0x00010001)
            ),
            ServiceAttribute(
                SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                DataElement.sequence([
                    DataElement.uuid(BT_HANDSFREE_SERVICE),
                    DataElement.uuid(BT_GENERIC_AUDIO_SERVICE)
                ])
            ),
            ServiceAttribute(
                SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence([
                    DataElement.sequence([
                        DataElement.uuid(BT_L2CAP_PROTOCOL_ID)
                    ]),
                    DataElement.sequence([
                        DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                        DataElement.unsigned_integer_8(rfcomm_channel)
                    ])
                ])
            ),
            ServiceAttribute(
                SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence([
                    DataElement.sequence([
                        DataElement.uuid(BT_HANDSFREE_SERVICE),
                        DataElement.unsigned_integer_16(0x0105)
                    ])
                ])
            )
        ]
    }


# -----------------------------------------------------------------------------
class UiServer:
    protocol = None

    async def start(self):
        # Start a Websocket server to receive events from a web page
        async def serve(websocket, path):
            while True:
                try:
                    message = await websocket.recv()
                    print('Received: ', str(message))

                    parsed = json.loads(message)
                    message_type = parsed['type']
                    if message_type == 'at_command':
                        if self.protocol is not None:
                            self.protocol.send_command_line(parsed['command'])

                except websockets.exceptions.ConnectionClosedOK:
                    pass
        await websockets.serve(serve, 'localhost', 8989)


# -----------------------------------------------------------------------------
async def protocol_loop(protocol):
    await protocol.initialize_service()

    while True:
        await(protocol.next_line())


# -----------------------------------------------------------------------------
def on_dlc(dlc):
    print('*** DLC connected', dlc)
    protocol = HfpProtocol(dlc)
    UiServer.protocol = protocol
    asyncio.create_task(protocol_loop(protocol))


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print('Usage: run_classic_hfp.py <device-config> <transport-spec>')
        print('example: run_classic_hfp.py classic2.json usb:04b4:f901')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True

        # Create and register a server
        rfcomm_server = RfommServer(device)

        # Listen for incoming DLC connections
        channel_number = rfcomm_server.listen(on_dlc)
        print(f'### Listening for connection on channel {channel_number}')

        # Advertise the HFP RFComm channel in the SDP
        device.sdp_service_records = make_sdp_records(channel_number)

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
logging.basicConfig(level = os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
