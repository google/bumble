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
import logging
import os
import click

from bumble import l2cap
from bumble.colors import color
from bumble.transport import open_transport_or_link
from bumble.device import Device
from bumble.utils import FlowControlAsyncPipe
from bumble.hci import HCI_Constant


# -----------------------------------------------------------------------------
class ServerBridge:
    """
    L2CAP CoC server bridge: waits for a peer to connect an L2CAP CoC channel
    on a specified PSM. When the connection is made, the bridge connects a TCP
    socket to a remote host and bridges the data in both directions, with flow
    control.
    When the L2CAP CoC channel is closed, the bridge disconnects the TCP socket
    and waits for a new L2CAP CoC channel to be connected.
    When the TCP connection is closed by the TCP server, XXXX
    """

    def __init__(self, psm, max_credits, mtu, mps, tcp_host, tcp_port):
        self.psm = psm
        self.max_credits = max_credits
        self.mtu = mtu
        self.mps = mps
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port

    async def start(self, device: Device) -> None:
        # Listen for incoming L2CAP CoC connections
        device.create_l2cap_server(
            spec=l2cap.LeCreditBasedChannelSpec(
                psm=self.psm, mtu=self.mtu, mps=self.mps, max_credits=self.max_credits
            ),
            handler=self.on_coc,
        )
        print(color(f'### Listening for CoC connection on PSM {self.psm}', 'yellow'))

        def on_ble_connection(connection):
            def on_ble_disconnection(reason):
                print(
                    color('@@@ Bluetooth disconnection:', 'red'),
                    HCI_Constant.error_name(reason),
                )

            print(color('@@@ Bluetooth connection:', 'green'), connection)
            connection.on('disconnection', on_ble_disconnection)

        device.on('connection', on_ble_connection)

        await device.start_advertising(auto_restart=True)

    # Called when a new L2CAP connection is established
    def on_coc(self, l2cap_channel):
        print(color('*** L2CAP channel:', 'cyan'), l2cap_channel)

        class Pipe:
            def __init__(self, bridge, l2cap_channel):
                self.bridge = bridge
                self.tcp_transport = None
                self.l2cap_channel = l2cap_channel

                l2cap_channel.on('close', self.on_l2cap_close)
                l2cap_channel.sink = self.on_coc_sdu

            async def connect_to_tcp(self):
                # Connect to the TCP server
                print(
                    color(
                        f'### Connecting to TCP {self.bridge.tcp_host}:'
                        f'{self.bridge.tcp_port}...',
                        'yellow',
                    )
                )

                class TcpClientProtocol(asyncio.Protocol):
                    def __init__(self, pipe):
                        self.pipe = pipe

                    def connection_lost(self, exc):
                        print(color(f'!!! TCP connection lost: {exc}', 'red'))
                        if self.pipe.l2cap_channel is not None:
                            asyncio.create_task(self.pipe.l2cap_channel.disconnect())

                    def data_received(self, data):
                        print(color(f'<<< [TCP DATA]: {len(data)} bytes', 'blue'))
                        self.pipe.l2cap_channel.write(data)

                try:
                    (
                        self.tcp_transport,
                        _,
                    ) = await asyncio.get_running_loop().create_connection(
                        lambda: TcpClientProtocol(self),
                        host=self.bridge.tcp_host,
                        port=self.bridge.tcp_port,
                    )
                    print(color('### Connected', 'green'))
                except Exception as error:
                    print(color(f'!!! Connection failed: {error}', 'red'))
                    await self.l2cap_channel.disconnect()

            def on_l2cap_close(self):
                print(color('*** L2CAP channel closed', 'red'))
                self.l2cap_channel = None
                if self.tcp_transport is not None:
                    self.tcp_transport.close()

            def on_coc_sdu(self, sdu):
                print(color(f'<<< [L2CAP SDU]: {len(sdu)} bytes', 'cyan'))
                if self.tcp_transport is None:
                    print(color('!!! TCP socket not open, dropping', 'red'))
                    return
                self.tcp_transport.write(sdu)

        pipe = Pipe(self, l2cap_channel)

        asyncio.create_task(pipe.connect_to_tcp())


# -----------------------------------------------------------------------------
class ClientBridge:
    """
    L2CAP CoC client bridge: connects to a BLE device, then waits for an inbound
    TCP connection on a specified port number. When a TCP client connects, an
    L2CAP CoC channel connection to the BLE device is established, and the data
    is bridged in both directions, with flow control.
    When the TCP connection is closed by the client, the L2CAP CoC channel is
    disconnected, but the connection to the BLE device remains, ready for a new
    TCP client to connect.
    When the L2CAP CoC channel is closed, XXXX
    """

    READ_CHUNK_SIZE = 4096

    def __init__(self, psm, max_credits, mtu, mps, address, tcp_host, tcp_port):
        self.psm = psm
        self.max_credits = max_credits
        self.mtu = mtu
        self.mps = mps
        self.address = address
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port

    async def start(self, device):
        print(color(f'### Connecting to {self.address}...', 'yellow'))
        connection = await device.connect(self.address)
        print(color('### Connected', 'green'))

        # Called when the BLE connection is disconnected
        def on_ble_disconnection(reason):
            print(
                color('@@@ Bluetooth disconnection:', 'red'),
                HCI_Constant.error_name(reason),
            )

        connection.on('disconnection', on_ble_disconnection)

        # Called when a TCP connection is established
        async def on_tcp_connection(reader, writer):
            peer_name = writer.get_extra_info('peer_name')
            print(color(f'<<< TCP connection from {peer_name}', 'magenta'))

            def on_coc_sdu(sdu):
                print(color(f'<<< [L2CAP SDU]: {len(sdu)} bytes', 'cyan'))
                l2cap_to_tcp_pipe.write(sdu)

            def on_l2cap_close():
                print(color('*** L2CAP channel closed', 'red'))
                l2cap_to_tcp_pipe.stop()
                writer.close()

            # Connect a new L2CAP channel
            print(color(f'>>> Opening L2CAP channel on PSM = {self.psm}', 'yellow'))
            try:
                l2cap_channel = await connection.create_l2cap_channel(
                    spec=l2cap.LeCreditBasedChannelSpec(
                        psm=self.psm,
                        max_credits=self.max_credits,
                        mtu=self.mtu,
                        mps=self.mps,
                    )
                )
                print(color('*** L2CAP channel:', 'cyan'), l2cap_channel)
            except Exception as error:
                print(color(f'!!! Connection failed: {error}', 'red'))
                writer.close()
                return

            l2cap_channel.sink = on_coc_sdu
            l2cap_channel.on('close', on_l2cap_close)

            # Start a flow control pipe from L2CAP to TCP
            l2cap_to_tcp_pipe = FlowControlAsyncPipe(
                l2cap_channel.pause_reading,
                l2cap_channel.resume_reading,
                writer.write,
                writer.drain,
            )
            l2cap_to_tcp_pipe.start()

            # Pipe data from TCP to L2CAP
            while True:
                try:
                    data = await reader.read(self.READ_CHUNK_SIZE)

                    if len(data) == 0:
                        print(color('!!! End of stream', 'red'))
                        await l2cap_channel.disconnect()
                        return

                    print(color(f'<<< [TCP DATA]: {len(data)} bytes', 'blue'))
                    l2cap_channel.write(data)
                    await l2cap_channel.drain()
                except Exception as error:
                    print(f'!!! Exception: {error}')
                    break

            writer.close()
            print(color('~~~ Bye bye', 'magenta'))

        await asyncio.start_server(
            on_tcp_connection,
            host=self.tcp_host if self.tcp_host != '_' else None,
            port=self.tcp_port,
        )
        print(
            color(
                f'### Listening for TCP connections on port {self.tcp_port}', 'magenta'
            )
        )


# -----------------------------------------------------------------------------
async def run(device_config, hci_transport, bridge):
    print('<<< connecting to HCI...')
    async with await open_transport_or_link(hci_transport) as (hci_source, hci_sink):
        print('<<< connected')

        device = Device.from_config_file_with_hci(device_config, hci_source, hci_sink)

        # Let's go
        await device.power_on()
        await bridge.start(device)

        # Wait until the transport terminates
        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
@click.group()
@click.pass_context
@click.option('--device-config', help='Device configuration file', required=True)
@click.option('--hci-transport', help='HCI transport', required=True)
@click.option('--psm', help='PSM for L2CAP CoC', type=int, default=1234)
@click.option(
    '--l2cap-coc-max-credits',
    help='Maximum L2CAP CoC Credits',
    type=click.IntRange(1, 65535),
    default=128,
)
@click.option(
    '--l2cap-coc-mtu',
    help='L2CAP CoC MTU',
    type=click.IntRange(23, 65535),
    default=1022,
)
@click.option(
    '--l2cap-coc-mps',
    help='L2CAP CoC MPS',
    type=click.IntRange(23, 65533),
    default=1024,
)
def cli(
    context,
    device_config,
    hci_transport,
    psm,
    l2cap_coc_max_credits,
    l2cap_coc_mtu,
    l2cap_coc_mps,
):
    context.ensure_object(dict)
    context.obj['device_config'] = device_config
    context.obj['hci_transport'] = hci_transport
    context.obj['psm'] = psm
    context.obj['max_credits'] = l2cap_coc_max_credits
    context.obj['mtu'] = l2cap_coc_mtu
    context.obj['mps'] = l2cap_coc_mps


# -----------------------------------------------------------------------------
@cli.command()
@click.pass_context
@click.option('--tcp-host', help='TCP host', default='localhost')
@click.option('--tcp-port', help='TCP port', default=9544)
def server(context, tcp_host, tcp_port):
    bridge = ServerBridge(
        context.obj['psm'],
        context.obj['max_credits'],
        context.obj['mtu'],
        context.obj['mps'],
        tcp_host,
        tcp_port,
    )
    asyncio.run(run(context.obj['device_config'], context.obj['hci_transport'], bridge))


# -----------------------------------------------------------------------------
@cli.command()
@click.pass_context
@click.argument('bluetooth-address')
@click.option('--tcp-host', help='TCP host', default='_')
@click.option('--tcp-port', help='TCP port', default=9543)
def client(context, bluetooth_address, tcp_host, tcp_port):
    bridge = ClientBridge(
        context.obj['psm'],
        context.obj['max_credits'],
        context.obj['mtu'],
        context.obj['mps'],
        bluetooth_address,
        tcp_host,
        tcp_port,
    )
    asyncio.run(run(context.obj['device_config'], context.obj['hci_transport'], bridge))


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())
if __name__ == '__main__':
    cli(obj={})  # pylint: disable=no-value-for-parameter
