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

import os

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import random
import socket
import sys

import pytest

from bumble import controller, device, hci, link, transport
from bumble.transport import common


# -----------------------------------------------------------------------------
def _make_controller_from_transport(transport: transport.Transport):
    return controller.Controller(
        name="server",
        host_sink=transport.sink,
        host_source=transport.source,
        link=link.LocalLink(),
    )


# -----------------------------------------------------------------------------
def _make_device_from_transport(
    transport: transport.Transport, address: str = "11:22:33:44:55:66"
):
    return device.Device.with_hci(
        name="client",
        address=hci.Address(address),
        hci_sink=transport.sink,
        hci_source=transport.source,
    )


# -----------------------------------------------------------------------------
class Sink:
    def __init__(self):
        self.packets = []

    def on_packet(self, packet):
        self.packets.append(packet)


# -----------------------------------------------------------------------------
def test_parser():
    sink1 = Sink()
    parser1 = common.PacketParser(sink1)
    sink2 = Sink()
    parser2 = common.PacketParser(sink2)

    for parser in [parser1, parser2]:
        with open(
            os.path.join(os.path.dirname(__file__), 'hci_data_001.bin'), 'rb'
        ) as input:
            while True:
                n = random.randint(1, 9)
                data = input.read(n)
                if not data:
                    break
                parser.feed_data(data)

    assert sink1.packets == sink2.packets


# -----------------------------------------------------------------------------
def test_parser_extensions():
    sink = Sink()
    parser = common.PacketParser(sink)

    # Check that an exception is thrown for an unknown type
    try:
        parser.feed_data(bytes([0x77, 0x00, 0x02, 0x01, 0x02]))
        exception_thrown = False
    except ValueError:
        exception_thrown = True

    assert exception_thrown

    # Now add a custom info
    parser.extended_packet_info[0x77] = (1, 1, 'B')
    parser.reset()
    parser.feed_data(bytes([0x77, 0x00, 0x02, 0x01, 0x02]))
    assert len(sink.packets) == 1


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "address,",
    ("127.0.0.1", "::1"),
)
async def test_tcp_connection(address):
    server_transport = await transport.open_transport(f"tcp-server:{address}:0")
    port = server_transport.server.sockets[0].getsockname()[1]
    _make_controller_from_transport(server_transport)

    client_transport = await transport.open_transport(f"tcp-client:{address}:{port}")
    client_device = _make_device_from_transport(client_transport)
    await client_device.power_on()

    await client_transport.close()
    await server_transport.close()


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "address, family",
    (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)),
)
async def test_udp_connection(address, family):
    # Pick empty ports
    ports = []
    for _ in range(2):
        sock = socket.socket(family=family, type=socket.SOCK_DGRAM)
        sock.bind((address, 0))
        ports.append(sock.getsockname()[1])
        sock.close()

    server_transport = await transport.open_transport(
        f"udp:{address}:{ports[0]},{address}:{ports[1]}"
    )
    _make_controller_from_transport(server_transport)

    client_transport = await transport.open_transport(
        f"udp:{address}:{ports[1]},{address}:{ports[0]}"
    )
    client_device = _make_device_from_transport(client_transport)
    await client_device.power_on()

    await client_transport.close()
    await server_transport.close()


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "server_address, client_address",
    (
        ("127.0.0.1", "ws://127.0.0.1"),
        ("::1", "ws://[::1]"),
    ),
)
async def test_ws_connection(server_address, client_address):
    server_transport = await transport.open_transport(f"ws-server:{server_address}:0")
    port = server_transport.server.sockets[0].getsockname()[1]
    _make_controller_from_transport(server_transport)

    client_transport = await transport.open_transport(
        f"ws-client:{client_address}:{port}"
    )
    client_device = _make_device_from_transport(client_transport)
    await client_device.power_on()

    await client_transport.close()
    await server_transport.close()


# -----------------------------------------------------------------------------
@pytest.mark.skipif(
    sys.platform != 'linux', reason='Unix socket is only fully supported on Linux'
)
async def test_unix_connection_file(tmpdir):
    path = str(tmpdir / 'bumble.sock')
    server_transport = await transport.open_transport(f"unix-server:{path}")
    _make_controller_from_transport(server_transport)

    client_transport = await transport.open_transport(f"unix-client:{path}")
    client_device = _make_device_from_transport(client_transport)
    await client_device.power_on()

    await client_transport.close()
    await server_transport.close()


# -----------------------------------------------------------------------------
@pytest.mark.skipif(
    sys.platform != 'linux', reason='Unix socket is only fully supported on Linux'
)
async def test_unix_connection_abstract():
    server_transport = await transport.open_transport("unix-server:@bumble.test.sock")
    _make_controller_from_transport(server_transport)

    client_transport = await transport.open_transport("unix-client:@bumble.test.sock")
    client_device = _make_device_from_transport(client_transport)
    await client_device.power_on()

    await client_transport.close()
    await server_transport.close()


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "address,",
    ("127.0.0.1", "[::1]"),
)
async def test_android_netsim_connection(address):
    controller_transport = await transport.open_transport(
        "android-netsim:_:0,mode=controller"
    )
    port = controller_transport.source.port
    _make_controller_from_transport(controller_transport)

    client_transport = await transport.open_transport(
        f"android-netsim:{address}:{port},mode=host"
    )
    client_device = _make_device_from_transport(client_transport)
    await client_device.power_on()

    await client_transport.close()
    await controller_transport.source.grpc_server.stop(None)
    await controller_transport.close()


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "spec,",
    (
        "android-netsim:[::1]:{port},mode=host[a=b,c=d]",
        "android-netsim:localhost:{port},mode=host[a=b,c=d]",
        "android-netsim:[a=b,c=d][::1]:{port},mode=host",
        "android-netsim:[a=b,c=d]localhost:{port},mode=host",
    ),
)
async def test_open_transport_with_metadata(spec):
    controller_transport = await transport.open_transport(
        "android-netsim:_:0,mode=controller"
    )
    port = controller_transport.source.port
    _make_controller_from_transport(controller_transport)

    client_transport = await transport.open_transport(spec.format(port=port))
    assert client_transport.source.metadata['a'] == 'b'
    assert client_transport.source.metadata['c'] == 'd'

    await client_transport.close()
    await controller_transport.source.grpc_server.stop(None)
    await controller_transport.close()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_parser()
    test_parser_extensions()
