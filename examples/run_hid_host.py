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
import dataclasses
import sys

from hid_report_parser import ReportParser

import bumble.logging
from bumble import hid
from bumble.colors import color
from bumble.core import PhysicalTransport
from bumble.device import Connection, Device
from bumble.hci import Address
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def get_hid_device_sdp_record(connection: Connection) -> None:
    sdp_records = await hid.DeviceSdpRecord.find(connection)
    if not sdp_records:
        raise RuntimeError(
            color("BT HID Device service not found on peer device!", "red")
        )
    sdp_info = sdp_records[0]

    print(color("SDP attributes for HID device:", "magenta"))
    for field in dataclasses.fields(sdp_info):
        val = getattr(sdp_info, field.name)
        if isinstance(val, int) and not isinstance(val, bool):
            print(color(f"  {field.name}: ", "cyan"), hex(val))
        else:
            print(color(f"  {field.name}: ", "cyan"), val)


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
            "Usage: run_hid_host.py <device-config> <transport-spec> "
            "<bluetooth-address> [test-mode]"
        )
        print("example: run_hid_host.py classic1.json usb:0 E1:CA:72:48:C4:E8/P")
        return

    def on_hid_control_data_cb(report_type: hid.ReportType, data: bytes) -> None:
        print(
            f"Received Control Data, report_type: {report_type.name}, "
            f"PDU: {data.hex()}"
        )

    def on_hid_interrupt_data_cb(report_type: hid.ReportType, data: bytes) -> None:
        if not data:
            print(color("Warning: No report received", "yellow"))
            return
        report_id = data[0]
        report_length = len(data)

        if report_type != hid.ReportType.OTHER_REPORT:
            msg = (
                f" Report type = {report_type.name}, "
                f"Report length = {report_length}, "
                f"Report id = {report_id}"
            )
            print(color(msg, "blue", None, "bold"))

        if (report_length <= 1) or (report_id == 0):
            return
        # Parse report over interrupt channel
        if report_type == hid.ReportType.INPUT_REPORT:
            ReportParser.parse_input_report(data)

    print("<<< connecting to HCI...")
    async with await open_transport(sys.argv[2]) as hci_transport:
        print("<<< CONNECTED")

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True

        # Create HID host and start it
        print("@@@ Starting HID Host...")
        hid_host = hid.Host(device)

        target_address = sys.argv[3]
        active_connection: Connection | None = None

        async def handle_virtual_cable_unplug() -> None:
            nonlocal active_connection
            await hid_host.disconnect()
            if device.keystore:
                try:
                    await device.keystore.delete(target_address)
                except KeyError:
                    pass
            if active_connection is not None:
                await active_connection.disconnect()
                active_connection = None

        def on_hid_virtual_cable_unplug_cb() -> None:
            asyncio.create_task(handle_virtual_cable_unplug())

        # Register for HID data callbacks
        hid_host.on(hid_host.EVENT_INTERRUPT_DATA, on_hid_interrupt_data_cb)
        hid_host.on(hid_host.EVENT_CONTROL_DATA, on_hid_control_data_cb)
        hid_host.on(hid_host.EVENT_VIRTUAL_CABLE_UNPLUG, on_hid_virtual_cable_unplug_cb)

        await device.power_on()

        # Connect to a peer
        print(f"=== Connecting to {target_address}...")
        active_connection = await device.connect(
            target_address, transport=PhysicalTransport.BR_EDR
        )
        print(f"=== Connected to {active_connection.peer_address}!")

        # Request authentication
        print("*** Authenticating...")
        await active_connection.authenticate()
        print("*** Authenticated...")

        # Enable encryption
        print("*** Enabling encryption...")
        await active_connection.encrypt()
        print("*** Encryption on")

        await get_hid_device_sdp_record(active_connection)

        async def menu() -> None:
            nonlocal active_connection
            reader = await get_stream_reader(sys.stdin)
            while True:
                print("\n" + "*" * 20 + " HID Host Menu " + "*" * 20 + "\n")
                print(" 1. Connect HID Channels")
                print(" 2. Disconnect HID Channels")
                print(" 3. Get Report")
                print(" 4. Set Report")
                print(" 5. Set Protocol Mode")
                print(" 6. Get Protocol Mode")
                print(" 7. Send Report on Interrupt Channel")
                print(" 8. Suspend")
                print(" 9. Exit Suspend")
                print("10. Virtual Cable Unplug")
                print("11. Disconnect device")
                print("12. Delete Bonding")
                print("13. Re-connect to device")
                print("14. Exit")
                print("\nEnter your choice : \n")

                choice_line = await reader.readline()
                choice = choice_line.decode("utf-8").strip()

                try:
                    match choice:
                        case "1":
                            if active_connection is not None:
                                await hid_host.connect(active_connection)
                            else:
                                print("No active connection")

                        case "2":
                            await hid_host.disconnect()

                        case "3":
                            print(" 1. Input Report with ID 0x01")
                            print(" 2. Input Report with ID 0x02")
                            print(" 3. Input Report with ID 0x05 - Invalid ReportId")
                            print(" 4. Output Report with ID 0x02")
                            print(
                                " 5. Feature Report with ID 0x0F - Unsupported Request"
                            )
                            print(" 6. Input Report with ID 0x02, BufferSize 3")
                            print(" 7. Output Report with ID 0x03, BufferSize 2")
                            print(" 8. Feature Report with ID 0x05, BufferSize 3")
                            choice1_line = await reader.readline()
                            choice1 = choice1_line.decode("utf-8").strip()

                            match choice1:
                                case "1":
                                    res = await hid_host.get_report(
                                        hid.ReportType.INPUT_REPORT, 1
                                    )
                                    print(f"Report received: {res.hex()}")
                                case "2":
                                    res = await hid_host.get_report(
                                        hid.ReportType.INPUT_REPORT, 2
                                    )
                                    print(f"Report received: {res.hex()}")
                                case "3":
                                    res = await hid_host.get_report(
                                        hid.ReportType.INPUT_REPORT, 5
                                    )
                                    print(f"Report received: {res.hex()}")
                                case "4":
                                    res = await hid_host.get_report(
                                        hid.ReportType.OUTPUT_REPORT, 2
                                    )
                                    print(f"Report received: {res.hex()}")
                                case "5":
                                    res = await hid_host.get_report(
                                        hid.ReportType.FEATURE_REPORT, 15
                                    )
                                    print(f"Report received: {res.hex()}")
                                case "6":
                                    res = await hid_host.get_report(
                                        hid.ReportType.INPUT_REPORT, 2, 3
                                    )
                                    print(f"Report received: {res.hex()}")
                                case "7":
                                    res = await hid_host.get_report(
                                        hid.ReportType.OUTPUT_REPORT, 3, 2
                                    )
                                    print(f"Report received: {res.hex()}")
                                case "8":
                                    res = await hid_host.get_report(
                                        hid.ReportType.FEATURE_REPORT, 5, 3
                                    )
                                    print(f"Report received: {res.hex()}")
                                case _:
                                    print("Incorrect option selected")

                        case "4":
                            print(" 1. Report type 1 (INPUT) and Report id 0x01")
                            print(" 2. Report type 2 (OUTPUT) and Report id 0x03")
                            print(" 3. Report type 3 (FEATURE) and Report id 0x05")
                            choice1_line = await reader.readline()
                            choice1 = choice1_line.decode("utf-8").strip()

                            match choice1:
                                case "1":
                                    await hid_host.set_report(
                                        hid.ReportType.INPUT_REPORT,
                                        bytes(
                                            [
                                                0x01,
                                                0x01,
                                                0x01,
                                                0x01,
                                                0x01,
                                                0x01,
                                                0x01,
                                                0x01,
                                                0x01,
                                            ]
                                        ),
                                    )
                                case "2":
                                    await hid_host.set_report(
                                        hid.ReportType.OUTPUT_REPORT,
                                        bytes([0x03, 0x01, 0x01]),
                                    )
                                case "3":
                                    await hid_host.set_report(
                                        hid.ReportType.FEATURE_REPORT,
                                        bytes([0x05, 0x01, 0x01, 0x01]),
                                    )
                                case _:
                                    print("Incorrect option selected")

                        case "5":
                            print(" 0. Boot")
                            print(" 1. Report")
                            choice1_line = await reader.readline()
                            choice1 = choice1_line.decode("utf-8").strip()

                            match choice1:
                                case "0":
                                    await hid_host.set_protocol(
                                        hid.ProtocolMode.BOOT_PROTOCOL
                                    )
                                case "1":
                                    await hid_host.set_protocol(
                                        hid.ProtocolMode.REPORT_PROTOCOL
                                    )
                                case _:
                                    print("Incorrect option selected")

                        case "6":
                            proto = await hid_host.get_protocol()
                            print(f"Protocol mode: {proto.name}")

                        case "7":
                            print(" 1. Report ID 0x01")
                            print(" 2. Report ID 0x03")
                            choice1_line = await reader.readline()
                            choice1 = choice1_line.decode("utf-8").strip()

                            match choice1:
                                case "1":
                                    hid_host.send_interrupt_data(
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
                                    hid_host.send_interrupt_data(
                                        bytes([0x03, 0x00, 0x0D, 0xFD, 0x00, 0x00])
                                    )
                                case _:
                                    print("Incorrect option selected")

                        case "8":
                            hid_host.suspend()

                        case "9":
                            hid_host.exit_suspend()

                        case "10":
                            hid_host.virtual_cable_unplug()
                            if device.keystore:
                                try:
                                    await device.keystore.delete(target_address)
                                    print("Unpair successful")
                                except KeyError:
                                    print(
                                        "Device not found or Device already unpaired."
                                    )

                        case "11":
                            peer_address = Address.from_string_for_transport(
                                target_address, transport=PhysicalTransport.BR_EDR
                            )
                            conn = device.find_connection_by_bd_addr(
                                peer_address, transport=PhysicalTransport.BR_EDR
                            )
                            if conn is not None:
                                await conn.disconnect()
                                active_connection = None
                            else:
                                print("Already disconnected from device")

                        case "12":
                            if device.keystore:
                                try:
                                    await device.keystore.delete(target_address)
                                    print("Unpair successful")
                                except KeyError:
                                    print(
                                        "Device not found or Device already unpaired."
                                    )

                        case "13":
                            active_connection = await device.connect(
                                target_address, transport=PhysicalTransport.BR_EDR
                            )
                            await active_connection.authenticate()
                            await active_connection.encrypt()

                        case "14":
                            sys.exit("Exit successful")

                        case _:
                            print("Invalid option selected.")
                except hid.HidProtocolError as err:
                    print(color(f"HID Protocol Error: {err}", "red"))

        if (len(sys.argv) > 4) and (sys.argv[4] == "test-mode"):
            # Enabling menu for testing
            await menu()
        else:
            # Connect HID Control & Interrupt Channels
            await hid_host.connect(active_connection)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    bumble.logging.setup_basic_logging("DEBUG")
    asyncio.run(main())
