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
    BT_L2CAP_PROTOCOL_ID,
    BT_RFCOMM_PROTOCOL_ID,
    BT_BR_EDR_TRANSPORT,
)
from bumble.rfcomm import Client
from bumble.sdp import (
    Client as SDP_Client,
    DataElement,
    ServiceAttribute,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
)


# -----------------------------------------------------------------------------
async def list_rfcomm_channels(connection):
    # Connect to the SDP Server
    sdp_client = SDP_Client(connection)
    await sdp_client.connect()

    # Search for services with an L2CAP service attribute
    search_result = await sdp_client.search_attributes(
        [BT_L2CAP_PROTOCOL_ID],
        [
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
        ],
    )
    print(color('==================================', 'blue'))
    print(color('RFCOMM Services:', 'yellow'))
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


# -----------------------------------------------------------------------------
class TcpServerProtocol(asyncio.Protocol):
    def __init__(self, rfcomm_session):
        self.rfcomm_session = rfcomm_session
        self.transport = None

    def connection_made(self, transport):
        peer_name = transport.get_extra_info('peer_name')
        print(f'<<< TCP Server: connection from {peer_name}')
        self.transport = transport
        self.rfcomm_session.sink = self.rfcomm_data_received

    def rfcomm_data_received(self, data):
        print(f'<<< RFCOMM Data: {data.hex()}')
        if self.transport:
            self.transport.write(data)
        else:
            print('!!! no TCP connection, dropping data')

    def data_received(self, data):
        print(f'<<< TCP Server: data received: {len(data)} bytes - {data.hex()}')
        self.rfcomm_session.write(data)


# -----------------------------------------------------------------------------
async def tcp_server(tcp_port, rfcomm_session):
    print(f'$$$ Starting TCP server on port {tcp_port}')

    server = await asyncio.get_running_loop().create_server(
        lambda: TcpServerProtocol(rfcomm_session), '127.0.0.1', tcp_port
    )
    await asyncio.get_running_loop().create_future()

    async with server:
        await server.serve_forever()


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 5:
        print(
            'Usage: run_rfcomm_client.py <device-config> <transport-spec> '
            '<bluetooth-address> <channel>|discover [tcp-port]'
        )
        print(
            '  specifying a channel number, or "discover" to list all RFCOMM channels'
        )
        print('example: run_rfcomm_client.py classic1.json usb:0 E1:CA:72:48:C4:E8 8')
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

        channel = sys.argv[4]
        if channel == 'discover':
            await list_rfcomm_channels(connection)
            return

        # Request authentication
        print('*** Authenticating...')
        await connection.authenticate()
        print('*** Authenticated')

        # Enable encryption
        print('*** Enabling encryption...')
        await connection.encrypt()
        print('*** Encryption on')

        # Create a client and start it
        print('@@@ Starting RFCOMM client...')
        rfcomm_client = Client(connection)
        rfcomm_mux = await rfcomm_client.start()
        print('@@@ Started')

        channel = int(channel)
        print(f'### Opening session for channel {channel}...')
        try:
            session = await rfcomm_mux.open_dlc(channel)
            print('### Session open', session)
        except bumble.core.ConnectionError as error:
            print(f'### Session open failed: {error}')
            await rfcomm_mux.disconnect()
            print('@@@ Disconnected from RFCOMM server')
            return

        if len(sys.argv) == 6:
            # A TCP port was specified, start listening
            tcp_port = int(sys.argv[5])
            asyncio.create_task(tcp_server(tcp_port, session))

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
