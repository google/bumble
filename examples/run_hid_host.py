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
    BT_HUMAN_INTERFACE_DEVICE_SERVICE,
    BT_BR_EDR_TRANSPORT,
)
from bumble.hci import Address
from bumble.hid import Host, Message
from bumble.sdp import (
    Client as SDP_Client,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_ALL_ATTRIBUTES_RANGE,
    SDP_LANGUAGE_BASE_ATTRIBUTE_ID_LIST_ATTRIBUTE_ID,
    SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
)
from hid_report_parser import ReportParser

# -----------------------------------------------------------------------------
# SDP attributes for Bluetooth HID devices
SDP_HID_SERVICE_NAME_ATTRIBUTE_ID = 0x0100
SDP_HID_SERVICE_DESCRIPTION_ATTRIBUTE_ID = 0x0101
SDP_HID_PROVIDER_NAME_ATTRIBUTE_ID = 0x0102
SDP_HID_DEVICE_RELEASE_NUMBER_ATTRIBUTE_ID = 0x0200  # [DEPRECATED]
SDP_HID_PARSER_VERSION_ATTRIBUTE_ID = 0x0201
SDP_HID_DEVICE_SUBCLASS_ATTRIBUTE_ID = 0x0202
SDP_HID_COUNTRY_CODE_ATTRIBUTE_ID = 0x0203
SDP_HID_VIRTUAL_CABLE_ATTRIBUTE_ID = 0x0204
SDP_HID_RECONNECT_INITIATE_ATTRIBUTE_ID = 0x0205
SDP_HID_DESCRIPTOR_LIST_ATTRIBUTE_ID = 0x0206
SDP_HID_LANGID_BASE_LIST_ATTRIBUTE_ID = 0x0207
SDP_HID_SDP_DISABLE_ATTRIBUTE_ID = 0x0208  # [DEPRECATED]
SDP_HID_BATTERY_POWER_ATTRIBUTE_ID = 0x0209
SDP_HID_REMOTE_WAKE_ATTRIBUTE_ID = 0x020A
SDP_HID_PROFILE_VERSION_ATTRIBUTE_ID = 0x020B  # DEPRECATED]
SDP_HID_SUPERVISION_TIMEOUT_ATTRIBUTE_ID = 0x020C
SDP_HID_NORMALLY_CONNECTABLE_ATTRIBUTE_ID = 0x020D
SDP_HID_BOOT_DEVICE_ATTRIBUTE_ID = 0x020E
SDP_HID_SSR_HOST_MAX_LATENCY_ATTRIBUTE_ID = 0x020F
SDP_HID_SSR_HOST_MIN_TIMEOUT_ATTRIBUTE_ID = 0x0210


# -----------------------------------------------------------------------------


async def get_hid_device_sdp_record(connection):

    # Connect to the SDP Server
    sdp_client = SDP_Client(connection)
    await sdp_client.connect()
    if sdp_client:
        print(color('Connected to SDP Server', 'blue'))
    else:
        print(color('Failed to connect to SDP Server', 'red'))

    # List BT HID Device service in the root browse group
    service_record_handles = await sdp_client.search_services(
        [BT_HUMAN_INTERFACE_DEVICE_SERVICE]
    )

    if len(service_record_handles) < 1:
        await sdp_client.disconnect()
        raise Exception(
            color(f'BT HID Device service not found on peer device!!!!', 'red')
        )

    # For BT_HUMAN_INTERFACE_DEVICE_SERVICE service, get all its attributes
    for service_record_handle in service_record_handles:
        attributes = await sdp_client.get_attributes(
            service_record_handle, [SDP_ALL_ATTRIBUTES_RANGE]
        )
        print(color(f'SERVICE {service_record_handle:04X} attributes:', 'yellow'))
        print(color(f'SDP attributes for HID device', 'magenta'))
        for attribute in attributes:
            if attribute.id == SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID:
                print(
                    color('  Service Record Handle : ', 'cyan'),
                    hex(attribute.value.value),
                )

            elif attribute.id == SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID:
                print(
                    color('  Service Class : ', 'cyan'), attribute.value.value[0].value
                )

            elif attribute.id == SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID:
                print(
                    color('  SDP Browse Group List : ', 'cyan'),
                    attribute.value.value[0].value,
                )

            elif attribute.id == SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                print(
                    color('  BT_L2CAP_PROTOCOL_ID : ', 'cyan'),
                    attribute.value.value[0].value[0].value,
                )
                print(
                    color('  PSM for Bluetooth HID Control channel : ', 'cyan'),
                    hex(attribute.value.value[0].value[1].value),
                )
                print(
                    color('  BT_HIDP_PROTOCOL_ID : ', 'cyan'),
                    attribute.value.value[1].value[0].value,
                )

            elif attribute.id == SDP_LANGUAGE_BASE_ATTRIBUTE_ID_LIST_ATTRIBUTE_ID:
                print(
                    color('  Lanugage : ', 'cyan'), hex(attribute.value.value[0].value)
                )
                print(
                    color('  Encoding : ', 'cyan'), hex(attribute.value.value[1].value)
                )
                print(
                    color('  PrimaryLanguageBaseID : ', 'cyan'),
                    hex(attribute.value.value[2].value),
                )

            elif attribute.id == SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                print(
                    color('  BT_HUMAN_INTERFACE_DEVICE_SERVICE ', 'cyan'),
                    attribute.value.value[0].value[0].value,
                )
                print(
                    color('  HID Profileversion number : ', 'cyan'),
                    hex(attribute.value.value[0].value[1].value),
                )

            elif attribute.id == SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                print(
                    color('  BT_L2CAP_PROTOCOL_ID : ', 'cyan'),
                    attribute.value.value[0].value[0].value[0].value,
                )
                print(
                    color('  PSM for Bluetooth HID Interrupt channel : ', 'cyan'),
                    hex(attribute.value.value[0].value[0].value[1].value),
                )
                print(
                    color('  BT_HIDP_PROTOCOL_ID : ', 'cyan'),
                    attribute.value.value[0].value[1].value[0].value,
                )

            elif attribute.id == SDP_HID_SERVICE_NAME_ATTRIBUTE_ID:
                print(color('  Service Name: ', 'cyan'), attribute.value.value)

            elif attribute.id == SDP_HID_SERVICE_DESCRIPTION_ATTRIBUTE_ID:
                print(color('  Service Description: ', 'cyan'), attribute.value.value)

            elif attribute.id == SDP_HID_PROVIDER_NAME_ATTRIBUTE_ID:
                print(color('  Provider Name: ', 'cyan'), attribute.value.value)

            elif attribute.id == SDP_HID_DEVICE_RELEASE_NUMBER_ATTRIBUTE_ID:
                print(color('  Release Number: ', 'cyan'), hex(attribute.value.value))

            elif attribute.id == SDP_HID_PARSER_VERSION_ATTRIBUTE_ID:
                print(
                    color('  HID Parser Version: ', 'cyan'), hex(attribute.value.value)
                )

            elif attribute.id == SDP_HID_DEVICE_SUBCLASS_ATTRIBUTE_ID:
                print(
                    color('  HIDDeviceSubclass: ', 'cyan'), hex(attribute.value.value)
                )

            elif attribute.id == SDP_HID_COUNTRY_CODE_ATTRIBUTE_ID:
                print(color('  HIDCountryCode: ', 'cyan'), hex(attribute.value.value))

            elif attribute.id == SDP_HID_VIRTUAL_CABLE_ATTRIBUTE_ID:
                print(color('  HIDVirtualCable: ', 'cyan'), attribute.value.value)

            elif attribute.id == SDP_HID_RECONNECT_INITIATE_ATTRIBUTE_ID:
                print(color('  HIDReconnectInitiate: ', 'cyan'), attribute.value.value)

            elif attribute.id == SDP_HID_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                print(
                    color('  HID Report Descriptor type: ', 'cyan'),
                    hex(attribute.value.value[0].value[0].value),
                )
                print(
                    color('  HID Report DescriptorList: ', 'cyan'),
                    attribute.value.value[0].value[1].value,
                )

            elif attribute.id == SDP_HID_LANGID_BASE_LIST_ATTRIBUTE_ID:
                print(
                    color('  HID LANGID Base Language: ', 'cyan'),
                    hex(attribute.value.value[0].value[0].value),
                )
                print(
                    color('  HID LANGID Base Bluetooth String Offset: ', 'cyan'),
                    hex(attribute.value.value[0].value[1].value),
                )

            elif attribute.id == SDP_HID_BATTERY_POWER_ATTRIBUTE_ID:
                print(color('  HIDBatteryPower: ', 'cyan'), attribute.value.value)

            elif attribute.id == SDP_HID_REMOTE_WAKE_ATTRIBUTE_ID:
                print(color('  HIDRemoteWake: ', 'cyan'), attribute.value.value)

            elif attribute.id == SDP_HID_PROFILE_VERSION_ATTRIBUTE_ID:
                print(
                    color('  HIDProfileVersion : ', 'cyan'), hex(attribute.value.value)
                )

            elif attribute.id == SDP_HID_SUPERVISION_TIMEOUT_ATTRIBUTE_ID:
                print(
                    color('  HIDSupervisionTimeout: ', 'cyan'),
                    hex(attribute.value.value),
                )

            elif attribute.id == SDP_HID_NORMALLY_CONNECTABLE_ATTRIBUTE_ID:
                print(
                    color('  HIDNormallyConnectable: ', 'cyan'), attribute.value.value
                )

            elif attribute.id == SDP_HID_BOOT_DEVICE_ATTRIBUTE_ID:
                print(color('  HIDBootDevice: ', 'cyan'), attribute.value.value)

            elif attribute.id == SDP_HID_SSR_HOST_MAX_LATENCY_ATTRIBUTE_ID:
                print(
                    color('  HIDSSRHostMaxLatency: ', 'cyan'),
                    hex(attribute.value.value),
                )

            elif attribute.id == SDP_HID_SSR_HOST_MIN_TIMEOUT_ATTRIBUTE_ID:
                print(
                    color('  HIDSSRHostMinTimeout: ', 'cyan'),
                    hex(attribute.value.value),
                )

            else:
                print(
                    color(
                        f'  Warning: Attribute ID: {attribute.id} match not found.\n  Attribute Info: {attribute}',
                        'yellow',
                    )
                )

    await sdp_client.disconnect()


# -----------------------------------------------------------------------------
async def get_stream_reader(pipe) -> asyncio.StreamReader:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, pipe)
    return reader


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) < 4:
        print(
            'Usage: run_hid_host.py <device-config> <transport-spec> '
            '<bluetooth-address> [test-mode]'
        )

        print('example: run_hid_host.py classic1.json usb:0 E1:CA:72:48:C4:E8/P')
        return

    def on_hid_data_cb(pdu):
        report_type = pdu[0] & 0x0F
        if len(pdu) == 1:
            print(color(f'Warning: No report received', 'yellow'))
            return
        report_length = len(pdu[1:])
        report_id = pdu[1]

        if report_type != Message.ReportType.OTHER_REPORT:
            print(
                color(
                    f' Report type = {report_type}, Report length = {report_length}, Report id = {report_id}',
                    'blue',
                    None,
                    'bold',
                )
            )

        if (report_length <= 1) or (report_id == 0):
            return

        if report_type == Message.ReportType.INPUT_REPORT:
            ReportParser.parse_input_report(pdu[1:])  # type: ignore

    async def handle_virtual_cable_unplug():
        await hid_host.disconnect_interrupt_channel()
        await hid_host.disconnect_control_channel()
        await device.keystore.delete(target_address)  # type: ignore
        await connection.disconnect()

    def on_hid_virtual_cable_unplug_cb():
        asyncio.create_task(handle_virtual_cable_unplug())

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        print('<<< CONNECTED')

        # Create a device
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)
        device.classic_enabled = True
        await device.power_on()

        # Connect to a peer
        target_address = sys.argv[3]
        print(f'=== Connecting to {target_address}...')
        connection = await device.connect(target_address, transport=BT_BR_EDR_TRANSPORT)
        print(f'=== Connected to {connection.peer_address}!')

        # Request authentication
        print('*** Authenticating...')
        await connection.authenticate()
        print('*** Authenticated...')

        # Enable encryption
        print('*** Enabling encryption...')
        await connection.encrypt()
        print('*** Encryption on')

        await get_hid_device_sdp_record(connection)

        # Create HID host and start it
        print('@@@ Starting HID Host...')
        hid_host = Host(device, connection)

        # Register for HID data call back
        hid_host.on('data', on_hid_data_cb)

        # Register for virtual cable unplug call back
        hid_host.on('virtual_cable_unplug', on_hid_virtual_cable_unplug_cb)

        async def menu():
            reader = await get_stream_reader(sys.stdin)
            while True:
                print(
                    "\n************************ HID Host Menu *****************************\n"
                )
                print(" 1. Connect Control Channel")
                print(" 2. Connect Interrupt Channel")
                print(" 3. Disconnect Control Channel")
                print(" 4. Disconnect Interrupt Channel")
                print(" 5. Get Report")
                print(" 6. Set Report")
                print(" 7. Set Protocol Mode")
                print(" 8. Get Protocol Mode")
                print(" 9. Send Report")
                print("10. Suspend")
                print("11. Exit Suspend")
                print("12. Virtual Cable Unplug")
                print("13. Disconnect device")
                print("14. Delete Bonding")
                print("15. Re-connect to device")
                print("\nEnter your choice : \n")

                choice = await reader.readline()
                choice = choice.decode('utf-8').strip()

                if choice == '1':
                    await hid_host.connect_control_channel()

                elif choice == '2':
                    await hid_host.connect_interrupt_channel()

                elif choice == '3':
                    await hid_host.disconnect_control_channel()

                elif choice == '4':
                    await hid_host.disconnect_interrupt_channel()

                elif choice == '5':
                    print(" 1. Report ID 0x02")
                    print(" 2. Report ID 0x03")
                    print(" 3. Report ID 0x05")
                    choice1 = await reader.readline()
                    choice1 = choice1.decode('utf-8').strip()

                    if choice1 == '1':
                        hid_host.get_report(1, 2, 3)

                    elif choice1 == '2':
                        hid_host.get_report(2, 3, 2)

                    elif choice1 == '3':
                        hid_host.get_report(3, 5, 3)

                    else:
                        print('Incorrect option selected')

                elif choice == '6':
                    print(" 1. Report type 1 and Report id 0x01")
                    print(" 2. Report type 2 and Report id 0x03")
                    print(" 3. Report type 3 and Report id 0x05")
                    choice1 = await reader.readline()
                    choice1 = choice1.decode('utf-8').strip()

                    if choice1 == '1':
                        # data includes first octet as report id
                        data = bytearray(
                            [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]
                        )
                        hid_host.set_report(1, data)

                    elif choice1 == '2':
                        data = bytearray([0x03, 0x01, 0x01])
                        hid_host.set_report(2, data)

                    elif choice1 == '3':
                        data = bytearray([0x05, 0x01, 0x01, 0x01])
                        hid_host.set_report(3, data)

                    else:
                        print('Incorrect option selected')

                elif choice == '7':
                    print(" 0. Boot")
                    print(" 1. Report")
                    choice1 = await reader.readline()
                    choice1 = choice1.decode('utf-8').strip()

                    if choice1 == '0':
                        hid_host.set_protocol(Message.ProtocolMode.BOOT_PROTOCOL)

                    elif choice1 == '1':
                        hid_host.set_protocol(Message.ProtocolMode.REPORT_PROTOCOL)

                    else:
                        print('Incorrect option selected')

                elif choice == '8':
                    hid_host.get_protocol()

                elif choice == '9':
                    print(" 1. Report ID 0x01")
                    print(" 2. Report ID 0x03")
                    choice1 = await reader.readline()
                    choice1 = choice1.decode('utf-8').strip()

                    if choice1 == '1':
                        data = bytearray(
                            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                        )
                        hid_host.send_data(data)

                    elif choice1 == '2':
                        data = bytearray([0x03, 0x00, 0x0D, 0xFD, 0x00, 0x00])
                        hid_host.send_data(data)

                    else:
                        print('Incorrect option selected')

                elif choice == '10':
                    hid_host.suspend()

                elif choice == '11':
                    hid_host.exit_suspend()

                elif choice == '12':
                    hid_host.virtual_cable_unplug()
                    try:
                        await device.keystore.delete(target_address)
                    except KeyError:
                        print('Device not found or Device already unpaired.')

                elif choice == '13':
                    peer_address = Address.from_string_for_transport(
                        target_address, transport=BT_BR_EDR_TRANSPORT
                    )
                    connection = device.find_connection_by_bd_addr(
                        peer_address, transport=BT_BR_EDR_TRANSPORT
                    )
                    if connection is not None:
                        await connection.disconnect()
                    else:
                        print("Already disconnected from device")

                elif choice == '14':
                    try:
                        await device.keystore.delete(target_address)
                        print("Unpair successful")
                    except KeyError:
                        print('Device not found or Device already unpaired.')

                elif choice == '15':
                    connection = await device.connect(
                        target_address, transport=BT_BR_EDR_TRANSPORT
                    )
                    await connection.authenticate()
                    await connection.encrypt()

                else:
                    print("Invalid option selected.")

        if (len(sys.argv) > 4) and (sys.argv[4] == 'test-mode'):
            # Enabling menu for testing
            await menu()
        else:
            # HID Connection
            # Control channel
            await hid_host.connect_control_channel()
            # Interrupt Channel
            await hid_host.connect_interrupt_channel()

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------

logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
