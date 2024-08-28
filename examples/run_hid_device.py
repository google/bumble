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
import struct

from bumble import hid
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import BT_BR_EDR_TRANSPORT

HID_REPORT_MAP = bytes(  # Text String, 117 Octet Report Descriptor
    # pylint: disable=line-too-long
    # fmt: off
    [
        0x05, 0x01,        # Usage Page (Generic Desktop Ctrls)
        0x09, 0x06,        # Usage (Keyboard)
        0xA1, 0x01,        # Collection (Application)
        0x85, 0x01,        #   Report ID (1)
        0x05, 0x07,        #   Usage Page (Kbrd/Keypad)
        0x19, 0xE0,        #   Usage Minimum (0xE0)
        0x29, 0xE7,        #   Usage Maximum (0xE7)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x01,        #   Logical Maximum (1)
        0x75, 0x01,        #   Report Size (1)
        0x95, 0x08,        #   Report Count (8)
        0x81, 0x02,        #   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
        0x95, 0x01,        #   Report Count (1)
        0x75, 0x08,        #   Report Size (8)
        0x81, 0x03,        #   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
        0x95, 0x05,        #   Report Count (5)
        0x75, 0x01,        #   Report Size (1)
        0x05, 0x08,        #   Usage Page (LEDs)
        0x19, 0x01,        #   Usage Minimum (Num Lock)
        0x29, 0x05,        #   Usage Maximum (Kana)
        0x91, 0x02,        #   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
        0x95, 0x01,        #   Report Count (1)
        0x75, 0x03,        #   Report Size (3)
        0x91, 0x03,        #   Output (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
        0x95, 0x06,        #   Report Count (6)
        0x75, 0x08,        #   Report Size (8)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x65,        #   Logical Maximum (101)
        0x05, 0x07,        #   Usage Page (Kbrd/Keypad)
        0x19, 0x00,        #   Usage Minimum (0x00)
        0x29, 0x65,        #   Usage Maximum (0x65)
        0x81, 0x00,        #   Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
        0xC0,              # End Collection
        0x05, 0x01,        # Usage Page (Generic Desktop Ctrls)
        0x09, 0x02,        # Usage (Mouse)
        0xA1, 0x01,        # Collection (Application)
        0x85, 0x02,        #   Report ID (2)
        0x09, 0x01,        #   Usage (Pointer)
        0xA1, 0x00,        #   Collection (Physical)
        0x05, 0x09,        #     Usage Page (Button)
        0x19, 0x01,        #     Usage Minimum (0x01)
        0x29, 0x03,        #     Usage Maximum (0x03)
        0x15, 0x00,        #     Logical Minimum (0)
        0x25, 0x01,        #     Logical Maximum (1)
        0x95, 0x03,        #     Report Count (3)
        0x75, 0x01,        #     Report Size (1)
        0x81, 0x02,        #     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
        0x95, 0x01,        #     Report Count (1)
        0x75, 0x05,        #     Report Size (5)
        0x81, 0x03,        #     Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
        0x05, 0x01,        #     Usage Page (Generic Desktop Ctrls)
        0x09, 0x30,        #     Usage (X)
        0x09, 0x31,        #     Usage (Y)
        0x15, 0x81,        #     Logical Minimum (-127)
        0x25, 0x7F,        #     Logical Maximum (127)
        0x75, 0x08,        #     Report Size (8)
        0x95, 0x02,        #     Report Count (2)
        0x81, 0x06,        #     Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
        0xC0,              #   End Collection
        0xC0,              # End Collection
    ]
)


# Default protocol mode set to report protocol
protocol_mode = hid.Message.ProtocolMode.REPORT_PROTOCOL


# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
async def get_stream_reader(pipe) -> asyncio.StreamReader:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, pipe)
    return reader


class DeviceData:
    def __init__(self) -> None:
        self.keyboardData = bytearray(
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        )
        self.mouseData = bytearray([0x02, 0x00, 0x00, 0x00])


# Device's live data - Mouse and Keyboard will be stored in this
deviceData = DeviceData()


# -----------------------------------------------------------------------------
async def keyboard_device(hid_device: hid.Device):

    # Start a Websocket server to receive events from a web page
    async def serve(websocket, _path):
        global deviceData
        while True:
            try:
                message = await websocket.recv()
                print('Received: ', str(message))
                parsed = json.loads(message)
                message_type = parsed['type']
                if message_type == 'keydown':
                    # Only deal with keys a to z for now
                    key = parsed['key']
                    if len(key) == 1:
                        code = ord(key)
                        if ord('a') <= code <= ord('z'):
                            hid_code = 0x04 + code - ord('a')
                            deviceData.keyboardData = bytearray(
                                [
                                    0x01,
                                    0x00,
                                    0x00,
                                    hid_code,
                                    0x00,
                                    0x00,
                                    0x00,
                                    0x00,
                                    0x00,
                                ]
                            )
                            hid_device.send_data(deviceData.keyboardData)
                elif message_type == 'keyup':
                    deviceData.keyboardData = bytearray(
                        [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                    )
                    hid_device.send_data(deviceData.keyboardData)
                elif message_type == "mousemove":
                    # logical min and max values
                    log_min = -127
                    log_max = 127
                    x = parsed['x']
                    y = parsed['y']
                    # limiting x and y values within logical max and min range
                    x = max(log_min, min(log_max, x))
                    y = max(log_min, min(log_max, y))
                    deviceData.mouseData = bytearray([0x02, 0x00]) + struct.pack(
                        ">bb", x, y
                    )
                    hid_device.send_data(deviceData.mouseData)
            except websockets.exceptions.ConnectionClosedOK:
                pass

    # pylint: disable-next=no-member
    await websockets.serve(serve, 'localhost', 8989)
    await asyncio.get_event_loop().create_future()


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: python run_hid_device.py <device-config> <transport-spec> <command>'
            '  where <command> is one of:\n'
            '  test-mode (run with menu enabled for testing)\n'
            '  web (run a keyboard with keypress input from a web page, '
            'see keyboard.html'
        )
        print('example: python run_hid_device.py hid_keyboard.json usb:0 web')
        print('example: python run_hid_device.py hid_keyboard.json usb:0 test-mode')

        return

    async def handle_virtual_cable_unplug():
        hid_host_bd_addr = str(hid_device.remote_device_bd_address)
        await hid_device.disconnect_interrupt_channel()
        await hid_device.disconnect_control_channel()
        await device.keystore.delete(hid_host_bd_addr)  # type: ignore
        connection = hid_device.connection
        if connection is not None:
            await connection.disconnect()

    def on_hid_data_cb(pdu: bytes):
        print(f'Received Data, PDU: {pdu.hex()}')

    def on_get_report_cb(
        report_id: int, report_type: int, buffer_size: int
    ) -> hid.Device.GetSetStatus:
        retValue = hid_device.GetSetStatus()
        print(
            "GET_REPORT report_id: "
            + str(report_id)
            + "report_type: "
            + str(report_type)
            + "buffer_size:"
            + str(buffer_size)
        )
        if report_type == hid.Message.ReportType.INPUT_REPORT:
            if report_id == 1:
                retValue.data = deviceData.keyboardData[1:]
                retValue.status = hid_device.GetSetReturn.SUCCESS
            elif report_id == 2:
                retValue.data = deviceData.mouseData[1:]
                retValue.status = hid_device.GetSetReturn.SUCCESS
            else:
                retValue.status = hid_device.GetSetReturn.REPORT_ID_NOT_FOUND

            if buffer_size:
                data_len = buffer_size - 1
                retValue.data = retValue.data[:data_len]
        elif report_type == hid.Message.ReportType.OUTPUT_REPORT:
            # This sample app has nothing to do with the report received, to enable PTS
            # testing, we will return single byte random data.
            retValue.data = bytearray([0x11])
            retValue.status = hid_device.GetSetReturn.SUCCESS
        elif report_type == hid.Message.ReportType.FEATURE_REPORT:
            retValue.status = hid_device.GetSetReturn.ERR_INVALID_PARAMETER
        elif report_type == hid.Message.ReportType.OTHER_REPORT:
            if report_id == 3:
                retValue.status = hid_device.GetSetReturn.REPORT_ID_NOT_FOUND
        else:
            retValue.status = hid_device.GetSetReturn.FAILURE

        return retValue

    def on_set_report_cb(
        report_id: int, report_type: int, report_size: int, data: bytes
    ) -> hid.Device.GetSetStatus:
        print(
            "SET_REPORT report_id: "
            + str(report_id)
            + "report_type: "
            + str(report_type)
            + "report_size "
            + str(report_size)
            + "data:"
            + str(data)
        )
        if report_type == hid.Message.ReportType.FEATURE_REPORT:
            status = hid.Device.GetSetReturn.ERR_INVALID_PARAMETER
        elif report_type == hid.Message.ReportType.INPUT_REPORT:
            if report_id == 1 and report_size != len(deviceData.keyboardData):
                status = hid.Device.GetSetReturn.ERR_INVALID_PARAMETER
            elif report_id == 2 and report_size != len(deviceData.mouseData):
                status = hid.Device.GetSetReturn.ERR_INVALID_PARAMETER
            elif report_id == 3:
                status = hid.Device.GetSetReturn.REPORT_ID_NOT_FOUND
            else:
                status = hid.Device.GetSetReturn.SUCCESS
        else:
            status = hid.Device.GetSetReturn.SUCCESS

        return hid.Device.GetSetStatus(status=status)

    def on_get_protocol_cb() -> hid.Device.GetSetStatus:
        return hid.Device.GetSetStatus(
            data=bytes([protocol_mode]),
            status=hid_device.GetSetReturn.SUCCESS,
        )

    def on_set_protocol_cb(protocol: int) -> hid.Device.GetSetStatus:
        # We do not support SET_PROTOCOL.
        print(f"SET_PROTOCOL report_id: {protocol}")
        return hid.Device.GetSetStatus(
            status=hid_device.GetSetReturn.ERR_UNSUPPORTED_REQUEST
        )

    def on_virtual_cable_unplug_cb():
        print('Received Virtual Cable Unplug')
        asyncio.create_task(handle_virtual_cable_unplug())

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True

        # Create and register HID device
        hid_device = hid.Device(device)

        # Register for  call backs
        hid_device.on('interrupt_data', on_hid_data_cb)

        hid_device.register_get_report_cb(on_get_report_cb)
        hid_device.register_set_report_cb(on_set_report_cb)
        hid_device.register_get_protocol_cb(on_get_protocol_cb)
        hid_device.register_set_protocol_cb(on_set_protocol_cb)

        # Register for virtual cable unplug call back
        hid_device.on('virtual_cable_unplug', on_virtual_cable_unplug_cb)

        # Setup the SDP to advertise HID Device service
        device.sdp_service_records = {
            1: hid.make_device_sdp_record(
                service_record_handle=1, hid_report_map=HID_REPORT_MAP
            )
        }

        # Start the controller
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        async def menu():
            reader = await get_stream_reader(sys.stdin)
            while True:
                print(
                    "\n************************ HID Device Menu *****************************\n"
                )
                print(" 1. Connect Control Channel")
                print(" 2. Connect Interrupt Channel")
                print(" 3. Disconnect Control Channel")
                print(" 4. Disconnect Interrupt Channel")
                print(" 5. Send Report on Interrupt Channel")
                print(" 6. Virtual Cable Unplug")
                print(" 7. Disconnect device")
                print(" 8. Delete Bonding")
                print(" 9. Re-connect to device")
                print("10. Exit ")
                print("\nEnter your choice : \n")

                choice = await reader.readline()
                choice = choice.decode('utf-8').strip()

                if choice == '1':
                    await hid_device.connect_control_channel()

                elif choice == '2':
                    await hid_device.connect_interrupt_channel()

                elif choice == '3':
                    await hid_device.disconnect_control_channel()

                elif choice == '4':
                    await hid_device.disconnect_interrupt_channel()

                elif choice == '5':
                    print(" 1. Report ID 0x01")
                    print(" 2. Report ID 0x02")
                    print(" 3. Invalid Report ID")

                    choice1 = await reader.readline()
                    choice1 = choice1.decode('utf-8').strip()

                    if choice1 == '1':
                        data = bytearray(
                            [0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
                        )
                        hid_device.send_data(data)
                        data = bytearray(
                            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                        )
                        hid_device.send_data(data)

                    elif choice1 == '2':
                        data = bytearray([0x02, 0x00, 0x00, 0xF6])
                        hid_device.send_data(data)
                        data = bytearray([0x02, 0x00, 0x00, 0x00])
                        hid_device.send_data(data)

                    elif choice1 == '3':
                        data = bytearray([0x00, 0x00, 0x00, 0x00])
                        hid_device.send_data(data)
                        data = bytearray([0x00, 0x00, 0x00, 0x00])
                        hid_device.send_data(data)

                    else:
                        print('Incorrect option selected')

                elif choice == '6':
                    hid_device.virtual_cable_unplug()
                    try:
                        hid_host_bd_addr = str(hid_device.remote_device_bd_address)
                        await device.keystore.delete(hid_host_bd_addr)
                    except KeyError:
                        print('Device not found or Device already unpaired.')

                elif choice == '7':
                    connection = hid_device.connection
                    if connection is not None:
                        await connection.disconnect()
                    else:
                        print("Already disconnected from device")

                elif choice == '8':
                    try:
                        hid_host_bd_addr = str(hid_device.remote_device_bd_address)
                        await device.keystore.delete(hid_host_bd_addr)
                    except KeyError:
                        print('Device NOT found or Device already unpaired.')

                elif choice == '9':
                    hid_host_bd_addr = str(hid_device.remote_device_bd_address)
                    connection = await device.connect(
                        hid_host_bd_addr, transport=BT_BR_EDR_TRANSPORT
                    )
                    await connection.authenticate()
                    await connection.encrypt()

                elif choice == '10':
                    sys.exit("Exit successful")

                else:
                    print("Invalid option selected.")

        if (len(sys.argv) > 3) and (sys.argv[3] == 'test-mode'):
            # Test mode for PTS/Unit testing
            await menu()
        else:
            # default option is using keyboard.html (web)
            print("Executing in Web mode")
            await keyboard_device(hid_device)

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
