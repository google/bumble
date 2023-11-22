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

import bumble.core
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import (
    BT_HANDSFREE_SERVICE,
    BT_RFCOMM_PROTOCOL_ID,
    BT_BR_EDR_TRANSPORT,
)
from bumble import rfcomm, hfp
from bumble.hci import HCI_SynchronousDataPacket
from bumble.sdp import (
    Client as SDP_Client,
    DataElement,
    ServiceAttribute,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
)


logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# pylint: disable-next=too-many-nested-blocks
async def list_rfcomm_channels(device, connection):
    # Connect to the SDP Server
    sdp_client = SDP_Client(connection)
    await sdp_client.connect()

    # Search for services that support the Handsfree Profile
    search_result = await sdp_client.search_attributes(
        [BT_HANDSFREE_SERVICE],
        [
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
        ],
    )
    print(color('==================================', 'blue'))
    print(color('Handsfree Services:', 'yellow'))
    rfcomm_channels = []
    # pylint: disable-next=too-many-nested-blocks
    for attribute_list in search_result:
        # Look for the RFCOMM Channel number
        protocol_descriptor_list = ServiceAttribute.find_attribute_in_list(
            attribute_list, SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID
        )
        if protocol_descriptor_list:
            for protocol_descriptor in protocol_descriptor_list.value:
                if len(protocol_descriptor.value) >= 2:
                    if protocol_descriptor.value[0].value == BT_RFCOMM_PROTOCOL_ID:
                        print(color('SERVICE:', 'green'))
                        print(
                            color('  RFCOMM Channel:', 'cyan'),
                            protocol_descriptor.value[1].value,
                        )
                        rfcomm_channels.append(protocol_descriptor.value[1].value)

                        # List profiles
                        bluetooth_profile_descriptor_list = (
                            ServiceAttribute.find_attribute_in_list(
                                attribute_list,
                                SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                            )
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
                                    # Sometimes, instead of a list of lists, we just
                                    # find a list. Fix that
                                    bluetooth_profile_descriptors = [
                                        bluetooth_profile_descriptor_list
                                    ]

                                print(color('  Profiles:', 'green'))
                                for (
                                    bluetooth_profile_descriptor
                                ) in bluetooth_profile_descriptors:
                                    version_major = (
                                        bluetooth_profile_descriptor.value[1].value >> 8
                                    )
                                    version_minor = (
                                        bluetooth_profile_descriptor.value[1].value
                                        & 0xFF
                                    )
                                    print(
                                        '    '
                                        f'{bluetooth_profile_descriptor.value[0].value}'
                                        f' - version {version_major}.{version_minor}'
                                    )

                        # List service classes
                        service_class_id_list = ServiceAttribute.find_attribute_in_list(
                            attribute_list, SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID
                        )
                        if service_class_id_list:
                            if service_class_id_list.value:
                                print(color('  Service Classes:', 'green'))
                                for service_class_id in service_class_id_list.value:
                                    print('   ', service_class_id.value)

    await sdp_client.disconnect()
    return rfcomm_channels


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 4:
        print(
            'Usage: run_hfp_gateway.py <device-config> <transport-spec> '
            '<bluetooth-address>'
        )
        print(
            '  specifying a channel number, or "discover" to list all RFCOMM channels'
        )
        print('example: run_hfp_gateway.py hfp_gateway.json usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True
        await device.power_on()

        # Connect to a peer
        target_address = sys.argv[3]
        print(f'=== Connecting to {target_address}...')
        connection = await device.connect(target_address, transport=BT_BR_EDR_TRANSPORT)
        print(f'=== Connected to {connection.peer_address}!')

        # Get a list of all the Handsfree services (should only be 1)
        channels = await list_rfcomm_channels(device, connection)
        if len(channels) == 0:
            print('!!! no service found')
            return

        # Pick the first one
        channel = channels[0]

        # Request authentication
        print('*** Authenticating...')
        await connection.authenticate()
        print('*** Authenticated')

        # Enable encryption
        print('*** Enabling encryption...')
        await connection.encrypt()
        print('*** Encryption on')

        # Create a client and start it
        print('@@@ Starting to RFCOMM client...')
        rfcomm_client = rfcomm.Client(connection)
        rfcomm_mux = await rfcomm_client.start()
        print('@@@ Started')

        print(f'### Opening session for channel {channel}...')
        try:
            session = await rfcomm_mux.open_dlc(channel)
            print('### Session open', session)
        except bumble.core.ConnectionError as error:
            print(f'### Session open failed: {error}')
            await rfcomm_mux.disconnect()
            print('@@@ Disconnected from RFCOMM server')
            return

        def on_sco(connection_handle: int, packet: HCI_SynchronousDataPacket):
            # Reset packet and loopback
            packet.packet_status = 0
            device.host.send_hci_packet(packet)

        device.host.on('sco_packet', on_sco)

        # Protocol loop (just for testing at this point)
        protocol = hfp.HfpProtocol(session)
        while True:
            line = await protocol.next_line()

            if line.startswith('AT+BRSF='):
                protocol.send_response_line('+BRSF: 30')
                protocol.send_response_line('OK')
            elif line.startswith('AT+CIND=?'):
                protocol.send_response_line(
                    '+CIND: ("call",(0,1)),("callsetup",(0-3)),("service",(0-1)),'
                    '("signal",(0-5)),("roam",(0,1)),("battchg",(0-5)),'
                    '("callheld",(0-2))'
                )
                protocol.send_response_line('OK')
            elif line.startswith('AT+CIND?'):
                protocol.send_response_line('+CIND: 0,0,1,4,1,5,0')
                protocol.send_response_line('OK')
            elif line.startswith('AT+CMER='):
                protocol.send_response_line('OK')
            elif line.startswith('AT+CHLD=?'):
                protocol.send_response_line('+CHLD: 0')
                protocol.send_response_line('OK')
            elif line.startswith('AT+BTRH?'):
                protocol.send_response_line('+BTRH: 0')
                protocol.send_response_line('OK')
            elif line.startswith('AT+CLIP='):
                protocol.send_response_line('OK')
            elif line.startswith('AT+VGS='):
                protocol.send_response_line('OK')
            elif line.startswith('AT+BIA='):
                protocol.send_response_line('OK')
            elif line.startswith('AT+BVRA='):
                protocol.send_response_line(
                    '+BVRA: 1,1,12AA,1,1,"Message 1 from Janina"'
                )
            elif line.startswith('AT+XEVENT='):
                protocol.send_response_line('OK')
            elif line.startswith('AT+XAPL='):
                protocol.send_response_line('OK')
            else:
                print(color('UNSUPPORTED AT COMMAND', 'red'))
                protocol.send_response_line('ERROR')

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
