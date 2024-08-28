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
from bumble.core import BT_BR_EDR_TRANSPORT
from bumble.hci import Address
from bumble.hid import Host, Message, find_device_sdp_record
from hid_report_parser import ReportParser


# -----------------------------------------------------------------------------
async def get_stream_reader(pipe) -> asyncio.StreamReader:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, pipe)
    return reader


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 4:
        print(
            'Usage: run_hid_host.py <device-config> <transport-spec> '
            '<bluetooth-address> [test-mode]'
        )

        print('example: run_hid_host.py classic1.json usb:0 E1:CA:72:48:C4:E8/P')
        return

    def on_hid_control_data_cb(pdu: bytes):
        print(f'Received Control Data, PDU: {pdu.hex()}')

    def on_hid_interrupt_data_cb(pdu: bytes):
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
        # Parse report over interrupt channel
        if report_type == Message.ReportType.INPUT_REPORT:
            ReportParser.parse_input_report(pdu[1:])  # type: ignore

    async def handle_virtual_cable_unplug():
        await hid_host.disconnect_interrupt_channel()
        await hid_host.disconnect_control_channel()
        await device.keystore.delete(target_address)  # type: ignore
        connection = hid_host.connection
        if connection is not None:
            await connection.disconnect()

    def on_hid_virtual_cable_unplug_cb():
        asyncio.create_task(handle_virtual_cable_unplug())

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< CONNECTED')

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True

        # Create HID host and start it
        print('@@@ Starting HID Host...')
        hid_host = Host(device)

        # Register for HID data call back
        hid_host.on('interrupt_data', on_hid_interrupt_data_cb)
        hid_host.on('control_data', on_hid_control_data_cb)

        # Register for virtual cable unplug call back
        hid_host.on('virtual_cable_unplug', on_hid_virtual_cable_unplug_cb)

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

        sdp_record = await find_device_sdp_record(connection)
        print(sdp_record)

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
                print(" 9. Send Report on Interrupt Channel")
                print("10. Suspend")
                print("11. Exit Suspend")
                print("12. Virtual Cable Unplug")
                print("13. Disconnect device")
                print("14. Delete Bonding")
                print("15. Re-connect to device")
                print("16. Exit")
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
                    print(" 1. Input Report with ID 0x01")
                    print(" 2. Input Report with ID 0x02")
                    print(" 3. Input Report with ID 0x0F - Invalid ReportId")
                    print(" 4. Output Report with ID 0x02")
                    print(" 5. Feature Report with ID 0x05 - Unsupported Request")
                    print(" 6. Input Report with ID 0x02, BufferSize 3")
                    print(" 7. Output Report with ID 0x03, BufferSize 2")
                    print(" 8. Feature Report with ID 0x05,  BufferSize 3")
                    choice1 = await reader.readline()
                    choice1 = choice1.decode('utf-8').strip()

                    if choice1 == '1':
                        hid_host.get_report(1, 1, 0)

                    elif choice1 == '2':
                        hid_host.get_report(1, 2, 0)

                    elif choice1 == '3':
                        hid_host.get_report(1, 5, 0)

                    elif choice1 == '4':
                        hid_host.get_report(2, 2, 0)

                    elif choice1 == '5':
                        hid_host.get_report(3, 15, 0)

                    elif choice1 == '6':
                        hid_host.get_report(1, 2, 3)

                    elif choice1 == '7':
                        hid_host.get_report(2, 3, 2)

                    elif choice1 == '8':
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
                        print("Unpair successful")
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

                elif choice == '16':
                    sys.exit("Exit successful")

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

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------

logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
