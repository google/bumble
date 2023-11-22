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
from bumble.core import (
    BT_BR_EDR_TRANSPORT,
    BT_AVDTP_PROTOCOL_ID,
    BT_AUDIO_SINK_SERVICE,
    BT_L2CAP_PROTOCOL_ID,
)
from bumble.avdtp import Protocol as AVDTP_Protocol
from bumble.a2dp import make_audio_source_service_sdp_records
from bumble.sdp import (
    Client as SDP_Client,
    ServiceAttribute,
    DataElement,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
)


# -----------------------------------------------------------------------------
def sdp_records():
    service_record_handle = 0x00010001
    return {
        service_record_handle: make_audio_source_service_sdp_records(
            service_record_handle
        )
    }


# -----------------------------------------------------------------------------
# pylint: disable-next=too-many-nested-blocks
async def find_a2dp_service(connection):
    # Connect to the SDP Server
    sdp_client = SDP_Client(connection)
    await sdp_client.connect()

    # Search for services with an Audio Sink service class
    search_result = await sdp_client.search_attributes(
        [BT_AUDIO_SINK_SERVICE],
        [
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
        ],
    )

    print(color('==================================', 'blue'))
    print(color('A2DP Sink Services:', 'yellow'))

    service_version = None

    for attribute_list in search_result:
        print(color('SERVICE:', 'green'))

        # Service classes
        service_class_id_list = ServiceAttribute.find_attribute_in_list(
            attribute_list, SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID
        )
        if service_class_id_list:
            if service_class_id_list.value:
                print(color('  Service Classes:', 'green'))
                for service_class_id in service_class_id_list.value:
                    print('   ', service_class_id.value)

        # Protocol info
        protocol_descriptor_list = ServiceAttribute.find_attribute_in_list(
            attribute_list, SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID
        )
        if protocol_descriptor_list:
            print(color('  Protocol:', 'green'))
            for protocol_descriptor in protocol_descriptor_list.value:
                if protocol_descriptor.value[0].value == BT_L2CAP_PROTOCOL_ID:
                    if len(protocol_descriptor.value) >= 2:
                        psm = protocol_descriptor.value[1].value
                        print(f'{color("    L2CAP PSM:", "cyan")}     {psm}')
                elif protocol_descriptor.value[0].value == BT_AVDTP_PROTOCOL_ID:
                    if len(protocol_descriptor.value) >= 2:
                        avdtp_version_major = protocol_descriptor.value[1].value >> 8
                        avdtp_version_minor = protocol_descriptor.value[1].value & 0xFF
                        print(
                            f'{color("    AVDTP Version:", "cyan")} '
                            f'{avdtp_version_major}.{avdtp_version_minor}'
                        )
                        service_version = (avdtp_version_major, avdtp_version_minor)

        # Profile info
        bluetooth_profile_descriptor_list = ServiceAttribute.find_attribute_in_list(
            attribute_list, SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID
        )
        if bluetooth_profile_descriptor_list:
            if bluetooth_profile_descriptor_list.value:
                if (
                    bluetooth_profile_descriptor_list.value[0].type
                    == DataElement.SEQUENCE
                ):
                    bluetooth_profile_descriptors = (
                        bluetooth_profile_descriptor_list.value
                    )
                else:
                    # Sometimes, instead of a list of lists, we just find a list.
                    # Fix that.
                    bluetooth_profile_descriptors = [bluetooth_profile_descriptor_list]

                print(color('  Profiles:', 'green'))
                for bluetooth_profile_descriptor in bluetooth_profile_descriptors:
                    version_major = bluetooth_profile_descriptor.value[1].value >> 8
                    version_minor = bluetooth_profile_descriptor.value[1].value & 0xFF
                    print(
                        f'    {bluetooth_profile_descriptor.value[0].value}'
                        f' - version {version_major}.{version_minor}'
                    )

    await sdp_client.disconnect()
    return service_version


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 4:
        print('Usage: run_a2dp_info.py <device-config> <transport-spec> <bt-addr>')
        print('example: run_a2dp_info.py classic1.json usb:0 14:7D:DA:4E:53:A8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True

        # Start the controller
        await device.power_on()

        # Setup the SDP to expose a SRC service, in case the remote device queries us
        # back
        device.sdp_service_records = sdp_records()

        # Connect to a peer
        target_address = sys.argv[3]
        print(f'=== Connecting to {target_address}...')
        connection = await device.connect(target_address, transport=BT_BR_EDR_TRANSPORT)
        print(f'=== Connected to {connection.peer_address}!')

        # Request authentication
        print('*** Authenticating...')
        await connection.authenticate()
        print('*** Authenticated')

        # Enable encryption
        print('*** Enabling encryption...')
        await connection.encrypt()
        print('*** Encryption on')

        # Look for an A2DP service
        avdtp_version = await find_a2dp_service(connection)
        if not avdtp_version:
            print(color('!!! no AVDTP service found'))
            return
        print(f'AVDTP version: {avdtp_version[0]}.{avdtp_version[1]}')

        # Create a client to interact with the remote device
        client = await AVDTP_Protocol.connect(connection, avdtp_version)

        # Discover all endpoints on the remote device
        endpoints = await client.discover_remote_endpoints()
        print(f'@@@ Found {len(endpoints)} endpoints')
        for endpoint in endpoints:
            print('@@@', endpoint)


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
