# Copyright 2024 Google LLC
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
import logging
import os
import time
from typing import Optional

import click

from bumble.colors import color
from bumble.device import Device, DeviceConfiguration, Connection
from bumble import core
from bumble import hci
from bumble import rfcomm
from bumble import transport
from bumble import utils


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_RFCOMM_UUID = "E6D55659-C8B4-4B85-96BB-B1143AF6D3AE"
DEFAULT_MTU = 4096
DEFAULT_CLIENT_TCP_PORT = 9544
DEFAULT_SERVER_TCP_PORT = 9545

TRACE_MAX_SIZE = 48


# -----------------------------------------------------------------------------
class Tracer:
    """
    Trace data buffers transmitted from one endpoint to another, with stats.
    """

    def __init__(self, channel_name: str) -> None:
        self.channel_name = channel_name
        self.last_ts: float = 0.0

    def trace_data(self, data: bytes) -> None:
        now = time.time()
        elapsed_s = now - self.last_ts if self.last_ts else 0
        elapsed_ms = int(elapsed_s * 1000)
        instant_throughput_kbps = ((len(data) / elapsed_s) / 1000) if elapsed_s else 0.0

        hex_str = data[:TRACE_MAX_SIZE].hex() + (
            "..." if len(data) > TRACE_MAX_SIZE else ""
        )
        print(
            f"[{self.channel_name}] {len(data):4} bytes "
            f"(+{elapsed_ms:4}ms, {instant_throughput_kbps: 7.2f}kB/s) "
            f" {hex_str}"
        )

        self.last_ts = now


# -----------------------------------------------------------------------------
class ServerBridge:
    """
    RFCOMM server bridge: waits for a peer to connect an RFCOMM channel.
    The RFCOMM channel may be associated with a UUID published in an SDP service
    description, or simply be on a system-assigned channel number.
    When the connection is made, the bridge connects a TCP socket to a remote host and
    bridges the data in both directions, with flow control.
    When the RFCOMM channel is closed, the bridge disconnects the TCP socket
    and waits for a new channel to be connected.
    """

    READ_CHUNK_SIZE = 4096

    def __init__(
        self, channel: int, uuid: str, trace: bool, tcp_host: str, tcp_port: int
    ) -> None:
        self.device: Optional[Device] = None
        self.channel = channel
        self.uuid = uuid
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.rfcomm_channel: Optional[rfcomm.DLC] = None
        self.tcp_tracer: Optional[Tracer]
        self.rfcomm_tracer: Optional[Tracer]

        if trace:
            self.tcp_tracer = Tracer(color("RFCOMM->TCP", "cyan"))
            self.rfcomm_tracer = Tracer(color("TCP->RFCOMM", "magenta"))
        else:
            self.rfcomm_tracer = None
            self.tcp_tracer = None

    async def start(self, device: Device) -> None:
        self.device = device

        # Create and register a server
        rfcomm_server = rfcomm.Server(self.device)

        # Listen for incoming DLC connections
        self.channel = rfcomm_server.listen(self.on_rfcomm_channel, self.channel)

        # Setup the SDP to advertise this channel
        service_record_handle = 0x00010001
        self.device.sdp_service_records = {
            service_record_handle: rfcomm.make_service_sdp_records(
                service_record_handle, self.channel, core.UUID(self.uuid)
            )
        }

        # We're ready for a connection
        self.device.on("connection", self.on_connection)
        await self.set_available(True)

        print(
            color(
                (
                    f"### Listening for RFCOMM connection on {device.public_address}, "
                    f"channel {self.channel}"
                ),
                "yellow",
            )
        )

    async def set_available(self, available: bool):
        # Become discoverable and connectable
        assert self.device
        await self.device.set_connectable(available)
        await self.device.set_discoverable(available)

    def on_connection(self, connection):
        print(color(f"@@@ Bluetooth connection: {connection}", "blue"))
        connection.on("disconnection", self.on_disconnection)

        # Don't accept new connections until we're disconnected
        utils.AsyncRunner.spawn(self.set_available(False))

    def on_disconnection(self, reason: int):
        print(
            color("@@@ Bluetooth disconnection:", "red"),
            hci.HCI_Constant.error_name(reason),
        )

        # We're ready for a new connection
        utils.AsyncRunner.spawn(self.set_available(True))

    # Called when an RFCOMM channel is established
    @utils.AsyncRunner.run_in_task()
    async def on_rfcomm_channel(self, rfcomm_channel):
        print(color("*** RFCOMM channel:", "cyan"), rfcomm_channel)

        # Connect to the TCP server
        print(
            color(
                f"### Connecting to TCP {self.tcp_host}:{self.tcp_port}",
                "yellow",
            )
        )
        try:
            reader, writer = await asyncio.open_connection(self.tcp_host, self.tcp_port)
        except OSError:
            print(color("!!! Connection failed", "red"))
            await rfcomm_channel.disconnect()
            return

        # Pipe data from RFCOMM to TCP
        def on_rfcomm_channel_closed():
            print(color("*** RFCOMM channel closed", "cyan"))
            writer.close()

        def write_rfcomm_data(data):
            if self.rfcomm_tracer:
                self.rfcomm_tracer.trace_data(data)

            writer.write(data)

        rfcomm_channel.sink = write_rfcomm_data
        rfcomm_channel.on("close", on_rfcomm_channel_closed)

        # Pipe data from TCP to RFCOMM
        while True:
            try:
                data = await reader.read(self.READ_CHUNK_SIZE)

                if len(data) == 0:
                    print(color("### TCP end of stream", "yellow"))
                    if rfcomm_channel.state == rfcomm.DLC.State.CONNECTED:
                        await rfcomm_channel.disconnect()
                    return

                if self.tcp_tracer:
                    self.tcp_tracer.trace_data(data)

                rfcomm_channel.write(data)
                await rfcomm_channel.drain()
            except Exception as error:
                print(f"!!! Exception: {error}")
                break

        writer.close()
        await writer.wait_closed()
        print(color("~~~ Bye bye", "magenta"))


# -----------------------------------------------------------------------------
class ClientBridge:
    """
    RFCOMM client bridge: connects to a BR/EDR device, then waits for an inbound
    TCP connection on a specified port number. When a TCP client connects, an
    RFCOMM connection to the device is established, and the data is bridged in both
    directions, with flow control.
    When the TCP connection is closed by the client, the RFCOMM channel is
    disconnected, but the connection to the device remains, ready for a new TCP client
    to connect.
    """

    READ_CHUNK_SIZE = 4096

    def __init__(
        self,
        channel: int,
        uuid: str,
        trace: bool,
        address: str,
        tcp_host: str,
        tcp_port: int,
        authenticate: bool,
        encrypt: bool,
    ):
        self.channel = channel
        self.uuid = uuid
        self.trace = trace
        self.address = address
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.authenticate = authenticate
        self.encrypt = encrypt
        self.device: Optional[Device] = None
        self.connection: Optional[Connection] = None
        self.rfcomm_client: Optional[rfcomm.Client]
        self.rfcomm_mux: Optional[rfcomm.Multiplexer]
        self.tcp_connected: bool = False

        self.tcp_tracer: Optional[Tracer]
        self.rfcomm_tracer: Optional[Tracer]

        if trace:
            self.tcp_tracer = Tracer(color("RFCOMM->TCP", "cyan"))
            self.rfcomm_tracer = Tracer(color("TCP->RFCOMM", "magenta"))
        else:
            self.rfcomm_tracer = None
            self.tcp_tracer = None

    async def connect(self) -> None:
        if self.connection:
            return

        print(color(f"@@@ Connecting to Bluetooth {self.address}", "blue"))
        assert self.device
        self.connection = await self.device.connect(
            self.address, transport=core.PhysicalTransport.BR_EDR
        )
        print(color(f"@@@ Bluetooth connection: {self.connection}", "blue"))
        self.connection.on("disconnection", self.on_disconnection)

        if self.authenticate:
            print(color("@@@ Authenticating Bluetooth connection", "blue"))
            await self.connection.authenticate()
            print(color("@@@ Bluetooth connection authenticated", "blue"))

        if self.encrypt:
            print(color("@@@ Encrypting Bluetooth connection", "blue"))
            await self.connection.encrypt()
            print(color("@@@ Bluetooth connection encrypted", "blue"))

        self.rfcomm_client = rfcomm.Client(self.connection)
        try:
            self.rfcomm_mux = await self.rfcomm_client.start()
        except BaseException as e:
            print(color("!!! Failed to setup RFCOMM connection", "red"), e)
            raise

    async def start(self, device: Device) -> None:
        self.device = device
        await device.set_connectable(False)
        await device.set_discoverable(False)

        # Called when a TCP connection is established
        async def on_tcp_connection(reader, writer):
            print(color("<<< TCP connection", "magenta"))
            if self.tcp_connected:
                print(
                    color("!!! TCP connection already active, rejecting new one", "red")
                )
                writer.close()
                return
            self.tcp_connected = True

            try:
                await self.pipe(reader, writer)
            except BaseException as error:
                print(color("!!! Exception while piping data:", "red"), error)
                return
            finally:
                writer.close()
                await writer.wait_closed()
                self.tcp_connected = False

        await asyncio.start_server(
            on_tcp_connection,
            host=self.tcp_host if self.tcp_host != "_" else None,
            port=self.tcp_port,
        )
        print(
            color(
                f"### Listening for TCP connections on port {self.tcp_port}", "magenta"
            )
        )

    async def pipe(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Resolve the channel number from the UUID if needed
        if self.channel == 0:
            await self.connect()
            assert self.connection
            channel = await rfcomm.find_rfcomm_channel_with_uuid(
                self.connection, self.uuid
            )
            if channel:
                print(color(f"### Found RFCOMM channel {channel}", "yellow"))
            else:
                print(color(f"!!! RFCOMM channel with UUID {self.uuid} not found"))
                return
        else:
            channel = self.channel

        # Connect a new RFCOMM channel
        await self.connect()
        assert self.rfcomm_mux
        print(color(f"*** Opening RFCOMM channel {channel}", "green"))
        try:
            rfcomm_channel = await self.rfcomm_mux.open_dlc(channel)
            print(color(f"*** RFCOMM channel open: {rfcomm_channel}", "green"))
        except Exception as error:
            print(color(f"!!! RFCOMM open failed: {error}", "red"))
            return

        # Pipe data from RFCOMM to TCP
        def on_rfcomm_channel_closed():
            print(color("*** RFCOMM channel closed", "green"))

        def write_rfcomm_data(data):
            if self.trace:
                self.rfcomm_tracer.trace_data(data)

            writer.write(data)

        rfcomm_channel.on("close", on_rfcomm_channel_closed)
        rfcomm_channel.sink = write_rfcomm_data

        # Pipe data from TCP to RFCOMM
        while True:
            try:
                data = await reader.read(self.READ_CHUNK_SIZE)

                if len(data) == 0:
                    print(color("### TCP end of stream", "yellow"))
                    if rfcomm_channel.state == rfcomm.DLC.State.CONNECTED:
                        await rfcomm_channel.disconnect()
                    self.tcp_connected = False
                    return

                if self.tcp_tracer:
                    self.tcp_tracer.trace_data(data)

                rfcomm_channel.write(data)
                await rfcomm_channel.drain()
            except Exception as error:
                print(f"!!! Exception: {error}")
                break

        print(color("~~~ Bye bye", "magenta"))

    def on_disconnection(self, reason: int) -> None:
        print(
            color("@@@ Bluetooth disconnection:", "red"),
            hci.HCI_Constant.error_name(reason),
        )
        self.connection = None


# -----------------------------------------------------------------------------
async def run(device_config, hci_transport, bridge):
    print("<<< connecting to HCI...")
    async with await transport.open_transport_or_link(hci_transport) as (
        hci_source,
        hci_sink,
    ):
        print("<<< connected")

        if device_config:
            device = Device.from_config_file_with_hci(
                device_config, hci_source, hci_sink
            )
        else:
            device = Device.from_config_with_hci(
                DeviceConfiguration(), hci_source, hci_sink
            )
        device.classic_enabled = True

        # Let's go
        await device.power_on()
        try:
            await bridge.start(device)

            # Wait until the transport terminates
            await hci_source.wait_for_termination()
        except core.ConnectionError as error:
            print(color(f"!!! Bluetooth connection failed: {error}", "red"))
        except Exception as error:
            print(f"Exception while running bridge: {error}")


# -----------------------------------------------------------------------------
@click.group()
@click.pass_context
@click.option(
    "--device-config",
    metavar="CONFIG_FILE",
    help="Device configuration file",
)
@click.option(
    "--hci-transport", metavar="TRANSPORT_NAME", help="HCI transport", required=True
)
@click.option("--trace", is_flag=True, help="Trace bridged data to stdout")
@click.option(
    "--channel",
    metavar="CHANNEL_NUMER",
    help="RFCOMM channel number",
    type=int,
    default=0,
)
@click.option(
    "--uuid",
    metavar="UUID",
    help="UUID for the RFCOMM channel",
    default=DEFAULT_RFCOMM_UUID,
)
def cli(
    context,
    device_config,
    hci_transport,
    trace,
    channel,
    uuid,
):
    context.ensure_object(dict)
    context.obj["device_config"] = device_config
    context.obj["hci_transport"] = hci_transport
    context.obj["trace"] = trace
    context.obj["channel"] = channel
    context.obj["uuid"] = uuid


# -----------------------------------------------------------------------------
@cli.command()
@click.pass_context
@click.option("--tcp-host", help="TCP host", default="localhost")
@click.option("--tcp-port", help="TCP port", default=DEFAULT_SERVER_TCP_PORT)
def server(context, tcp_host, tcp_port):
    bridge = ServerBridge(
        context.obj["channel"],
        context.obj["uuid"],
        context.obj["trace"],
        tcp_host,
        tcp_port,
    )
    asyncio.run(run(context.obj["device_config"], context.obj["hci_transport"], bridge))


# -----------------------------------------------------------------------------
@cli.command()
@click.pass_context
@click.argument("bluetooth-address")
@click.option("--tcp-host", help="TCP host", default="_")
@click.option("--tcp-port", help="TCP port", default=DEFAULT_CLIENT_TCP_PORT)
@click.option("--authenticate", is_flag=True, help="Authenticate the connection")
@click.option("--encrypt", is_flag=True, help="Encrypt the connection")
def client(context, bluetooth_address, tcp_host, tcp_port, authenticate, encrypt):
    bridge = ClientBridge(
        context.obj["channel"],
        context.obj["uuid"],
        context.obj["trace"],
        bluetooth_address,
        tcp_host,
        tcp_port,
        authenticate,
        encrypt,
    )
    asyncio.run(run(context.obj["device_config"], context.obj["hci_transport"], bridge))


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get("BUMBLE_LOGLEVEL", "WARNING").upper())
if __name__ == "__main__":
    cli(obj={})  # pylint: disable=no-value-for-parameter
