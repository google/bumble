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

from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import BT_L2CAP_PROTOCOL_ID, BT_RFCOMM_PROTOCOL_ID, UUID
from bumble.rfcomm import Server
from bumble.sdp import (
    DataElement,
    ServiceAttribute,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
)


# -----------------------------------------------------------------------------
def sdp_records(channel):
    return {
        0x00010001: [
            ServiceAttribute(
                SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                DataElement.unsigned_integer_32(0x00010001),
            ),
            ServiceAttribute(
                SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
                DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
            ),
            ServiceAttribute(
                SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [DataElement.uuid(UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE'))]
                ),
            ),
            ServiceAttribute(
                SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence([DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]),
                        DataElement.sequence(
                            [
                                DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                                DataElement.unsigned_integer_8(channel),
                            ]
                        ),
                    ]
                ),
            ),
        ]
    }


# -----------------------------------------------------------------------------
def on_dlc(dlc):
    print('*** DLC connected', dlc)
    dlc.sink = lambda data: on_rfcomm_data_received(dlc, data)


# -----------------------------------------------------------------------------
def on_rfcomm_data_received(dlc, data):
    print(f'<<< Data received: {data.hex()}')
    try:
        message = data.decode('utf-8')
        print(f'<<< Message = {message}')
    except Exception:
        pass

    # Echo everything back
    dlc.write(data)


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 3:
        print('Usage: run_rfcomm_server.py <device-config> <transport-spec>')
        print('example: run_rfcomm_server.py classic2.json usb:04b4:f901')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True

        # Create and register a server
        rfcomm_server = Server(device)

        # Listen for incoming DLC connections
        channel_number = rfcomm_server.listen(on_dlc)
        print(f'### Listening for connection on channel {channel_number}')

        # Setup the SDP to advertise this channel
        device.sdp_service_records = sdp_records(channel_number)

        # Start the controller
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
