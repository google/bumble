# Copyright 2021-2025 Google LLC
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
# pylint: disable=duplicate-code
from __future__ import annotations

import asyncio
import json
import struct
import sys

import websockets.asyncio.server
from typing_extensions import override

import bumble.logging
from bumble import hid
from bumble.core import PhysicalTransport
from bumble.device import Connection, Device
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def get_stream_reader(pipe) -> asyncio.StreamReader:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, pipe)
    return reader


class DeviceData:
    def __init__(self) -> None:
        self.keyboard_data = bytearray(
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        )
        self.mouse_data = bytearray([0x02, 0x00, 0x00, 0x00])


# Device's live data - Mouse and Keyboard will be stored in this
device_data = DeviceData()


class HidDeviceDelegate(hid.Device.Delegate):
    @override
    def get_report(self, report_type: hid.ReportType, report_id: int | None) -> bytes:
        print(f"GET_REPORT report_id: {report_id}, report_type: {report_type.name}")
        match (report_type, report_id):
            case (hid.ReportType.INPUT_REPORT, 1):
                return bytes(device_data.keyboard_data[1:])
            case (hid.ReportType.INPUT_REPORT, 2):
                return bytes(device_data.mouse_data[1:])
            case (hid.ReportType.INPUT_REPORT, _) | (
                hid.ReportType.OTHER_REPORT,
                3,
            ):
                raise hid.HidProtocolError(
                    hid.HandshakeMessage.ResultCode.ERR_INVALID_REPORT_ID
                )
            case (hid.ReportType.OUTPUT_REPORT, _):
                # Return single byte sample data for testing
                return bytes([0x11])
            case (hid.ReportType.FEATURE_REPORT, _):
                raise hid.HidProtocolError(
                    hid.HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
                )
            case _:
                raise hid.HidProtocolError(
                    hid.HandshakeMessage.ResultCode.ERR_UNSUPPORTED_REQUEST
                )

    @override
    def set_report(self, report_type: hid.ReportType, data: bytes) -> None:
        report_id = data[0] if data else 0
        print(
            f"SET_REPORT report_id: {report_id}, report_type: {report_type.name}, "
            f"report_size: {len(data)}, data: {data.hex()}"
        )
        match (report_type, report_id):
            case (hid.ReportType.FEATURE_REPORT, _):
                raise hid.HidProtocolError(
                    hid.HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
                )
            case (hid.ReportType.INPUT_REPORT, 1) if len(data) != len(
                device_data.keyboard_data
            ):
                raise hid.HidProtocolError(
                    hid.HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
                )
            case (hid.ReportType.INPUT_REPORT, 2) if len(data) != len(
                device_data.mouse_data
            ):
                raise hid.HidProtocolError(
                    hid.HandshakeMessage.ResultCode.ERR_INVALID_PARAMETER
                )
            case (hid.ReportType.INPUT_REPORT, 3):
                raise hid.HidProtocolError(
                    hid.HandshakeMessage.ResultCode.ERR_INVALID_REPORT_ID
                )


# -----------------------------------------------------------------------------
async def keyboard_device(hid_device: hid.Device) -> None:
    # Start a Websocket server to receive events from a web page
    async def serve(websocket: websockets.asyncio.server.ServerConnection) -> None:
        while True:
            try:
                message = await websocket.recv()
                print("Received: ", str(message))
                parsed = json.loads(message)
                match parsed["type"]:
                    case "keydown":
                        # Only deal with keys a to z for now
                        key = parsed["key"]
                        if len(key) == 1:
                            code = ord(key)
                            if ord("a") <= code <= ord("z"):
                                hid_code = 0x04 + code - ord("a")
                                device_data.keyboard_data = bytearray(
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
                                hid_device.send_interrupt_data(
                                    bytes(device_data.keyboard_data)
                                )
                    case "keyup":
                        device_data.keyboard_data = bytearray(
                            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                        )
                        hid_device.send_interrupt_data(bytes(device_data.keyboard_data))
                    case "mousemove":
                        # logical min and max values
                        log_min = -127
                        log_max = 127
                        x = max(log_min, min(log_max, parsed["x"]))
                        y = max(log_min, min(log_max, parsed["y"]))
                        device_data.mouse_data = bytearray([0x02, 0x00]) + struct.pack(
                            ">bb", x, y
                        )
                        hid_device.send_interrupt_data(bytes(device_data.mouse_data))
            except websockets.exceptions.ConnectionClosedOK:
                pass

    # pylint: disable-next=no-member
    await websockets.asyncio.server.serve(serve, "localhost", 8989)
    await asyncio.get_event_loop().create_future()


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            "Usage: python run_hid_device.py <device-config> <transport-spec> "
            "<command>\n"
            "  where <command> is one of:\n"
            "  test-mode (run with menu enabled for testing)\n"
            "  web (run a keyboard with keypress input from a web page, "
            "see keyboard.html"
        )
        print("example: python run_hid_device.py hid_keyboard.json usb:0 web")
        print("example: python run_hid_device.py hid_keyboard.json usb:0 test-mode")
        return

    print("<<< connecting to HCI...")
    async with await open_transport(sys.argv[2]) as hci_transport:
        print("<<< connected")

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True

        active_connection: Connection | None = None

        def on_connection(connection: Connection) -> None:
            nonlocal active_connection
            active_connection = connection

            def on_disconnection(_reason: int) -> None:
                nonlocal active_connection
                active_connection = None

            connection.on(
                connection.EVENT_DISCONNECTION,
                on_disconnection,
            )

        device.on(device.EVENT_CONNECTION, on_connection)

        # Create and register HID device
        delegate = HidDeviceDelegate()
        hid_device = hid.Device(device, delegate=delegate)

        async def handle_virtual_cable_unplug() -> None:
            await hid_device.disconnect()
            if hid_device.remote_device_bd_address and device.keystore:
                try:
                    await device.keystore.delete(
                        str(hid_device.remote_device_bd_address)
                    )
                except KeyError:
                    pass
            if active_connection is not None:
                await active_connection.disconnect()

        def on_hid_data_cb(report_type: hid.ReportType, data: bytes) -> None:
            print(f"Received Data, report_type: {report_type.name}, PDU: {data.hex()}")

        def on_virtual_cable_unplug_cb() -> None:
            print("Received Virtual Cable Unplug")
            asyncio.create_task(handle_virtual_cable_unplug())

        hid_device.on(hid_device.EVENT_INTERRUPT_DATA, on_hid_data_cb)
        hid_device.on(hid_device.EVENT_VIRTUAL_CABLE_UNPLUG, on_virtual_cable_unplug_cb)

        # Setup the SDP to advertise HID Device service
        device.sdp_service_records = {
            0x00010002: hid.DeviceSdpRecord(
                service_record_handle=0x00010002,
                report_map=hid.DEFAULT_REPORT_MAP,
            ).to_service_attributes()
        }

        # Start the controller
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        async def menu() -> None:
            nonlocal active_connection
            reader = await get_stream_reader(sys.stdin)
            while True:
                print("\n" + "*" * 20 + " HID Device Menu " + "*" * 20 + "\n")
                print(" 1. Connect HID Channels")
                print(" 2. Disconnect HID Channels")
                print(" 3. Send Report on Interrupt Channel")
                print(" 4. Virtual Cable Unplug")
                print(" 5. Disconnect device")
                print(" 6. Delete Bonding")
                print(" 7. Re-connect to device")
                print(" 8. Exit ")
                print("\nEnter your choice : \n")

                choice_line = await reader.readline()
                choice = choice_line.decode("utf-8").strip()

                match choice:
                    case "1":
                        if active_connection is not None:
                            await hid_device.connect(active_connection)
                        else:
                            print("No active connection")

                    case "2":
                        await hid_device.disconnect()

                    case "3":
                        print(" 1. Report ID 0x01")
                        print(" 2. Report ID 0x02")
                        print(" 3. Invalid Report ID")

                        choice1_line = await reader.readline()
                        choice1 = choice1_line.decode("utf-8").strip()

                        match choice1:
                            case "1":
                                hid_device.send_interrupt_data(
                                    bytes(
                                        [
                                            0x01,
                                            0x00,
                                            0x00,
                                            0x04,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00,
                                        ]
                                    )
                                )
                                hid_device.send_interrupt_data(
                                    bytes(
                                        [
                                            0x01,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0x00,
                                        ]
                                    )
                                )
                            case "2":
                                hid_device.send_interrupt_data(
                                    bytes([0x02, 0x00, 0x00, 0xF6])
                                )
                                hid_device.send_interrupt_data(
                                    bytes([0x02, 0x00, 0x00, 0x00])
                                )
                            case "3":
                                hid_device.send_interrupt_data(
                                    bytes([0x00, 0x00, 0x00, 0x00])
                                )
                                hid_device.send_interrupt_data(
                                    bytes([0x00, 0x00, 0x00, 0x00])
                                )
                            case _:
                                print("Incorrect option selected")

                    case "4":
                        hid_device.virtual_cable_unplug()
                        if hid_device.remote_device_bd_address and device.keystore:
                            try:
                                await device.keystore.delete(
                                    str(hid_device.remote_device_bd_address)
                                )
                            except KeyError:
                                print("Device not found or Device already unpaired.")

                    case "5":
                        if active_connection is not None:
                            await active_connection.disconnect()
                            active_connection = None
                        else:
                            print("Already disconnected from device")

                    case "6":
                        if hid_device.remote_device_bd_address and device.keystore:
                            try:
                                await device.keystore.delete(
                                    str(hid_device.remote_device_bd_address)
                                )
                            except KeyError:
                                print("Device NOT found or Device already unpaired.")

                    case "7":
                        if hid_device.remote_device_bd_address:
                            active_connection = await device.connect(
                                hid_device.remote_device_bd_address,
                                transport=PhysicalTransport.BR_EDR,
                            )
                            await active_connection.authenticate()
                            await active_connection.encrypt()
                        else:
                            print("Remote device address unknown.")

                    case "8":
                        sys.exit("Exit successful")

                    case _:
                        print("Invalid option selected.")

        if (len(sys.argv) > 3) and (sys.argv[3] == "test-mode"):
            # Test mode for PTS/Unit testing
            await menu()
        else:
            # default option is using keyboard.html (web)
            print("Executing in Web mode")
            await keyboard_device(hid_device)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    bumble.logging.setup_basic_logging("DEBUG")
    asyncio.run(main())
