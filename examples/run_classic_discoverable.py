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
from bumble.core import (
    BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE,
    BT_AUDIO_SINK_SERVICE,
    BT_AVDTP_PROTOCOL_ID,
    BT_L2CAP_PROTOCOL_ID,
)
from bumble.device import Device
from bumble.sdp import (
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    DataElement,
    ServiceAttribute,
)
from bumble.transport import open_transport

# -----------------------------------------------------------------------------
SDP_SERVICE_RECORDS = {
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
            DataElement.sequence([DataElement.uuid(BT_AUDIO_SINK_SERVICE)]),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_L2CAP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(25),
                        ]
                    ),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_AVDTP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(256),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE),
                            DataElement.unsigned_integer_16(256),
                        ]
                    )
                ]
            ),
        ),
    ]
}


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: run_classic_discoverable.py <device-config> <transport-spec>')
        print('example: run_classic_discoverable.py classic1.json usb:04b4:f901')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True
        device.sdp_service_records = SDP_SERVICE_RECORDS
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
