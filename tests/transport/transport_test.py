# Copyright 2021-2026 Google LLC
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

import asyncio
import os

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import random
import socket
import sys

import pytest
import serial as pyserial  # type: ignore[import-untyped]

from bumble import controller, device, hci, link, transport
from bumble.transport import common, serial, usb


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
HCI_RESET = bytes(hci.HCI_Reset_Command())
HCI_READ_LOCAL_VERSION_INFORMATION = bytes(
    hci.HCI_Read_Local_Version_Information_Command()
)
# Command Complete events for those commands, with Num_HCI_Command_Packets 10: a
# newline byte
HCI_RESET_COMPLETE = bytes.fromhex('040e040a030c00')
HCI_READ_LOCAL_VERSION_INFORMATION_COMPLETE = bytes.fromhex('040e0c0a011000') + bytes(8)
# The header of a vendor command announcing 255 bytes of parameters, and none of them
PARTIAL_COMMAND = bytes.fromhex('0100fcff')
# The header of an LE Meta event announcing 16 bytes of parameters, and only 2 of them
PARTIAL_EVENT = bytes.fromhex('043e100102')


class FakeSerialController:
    '''
    The controller side of a pseudo-terminal.

    It reads commands as an H:4 controller does, skipping any byte that cannot start
    one, starting with the bytes in `pending`. It answers them one after the other: an
    HCI_Reset after `reset_time` seconds, unless `honors_reset` is unset, and an
    HCI_Read_Local_Version_Information after 10 ms, so that the two answers are not
    read together. When `split_reply` is set, each answer is sent in three writes. When
    `stale_reply` is set, it is sent ahead of the answer to the first HCI_Reset, in the
    same write. When `chatter` is set, it keeps sending the start of an event until it
    reads an HCI_Reset, as a controller that was left transmitting.
    '''

    def __init__(
        self,
        chatter: bool = False,
        honors_reset: bool = True,
        reset_time: float = 0.0,
        split_reply: bool = False,
        stale_reply: bytes = b'',
        pending: bytes = b'',
    ) -> None:
        import tty

        self.replies = {
            hci.HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND: (
                HCI_READ_LOCAL_VERSION_INFORMATION_COMPLETE
            )
        }
        if honors_reset:
            self.replies[hci.HCI_RESET_COMMAND] = HCI_RESET_COMPLETE
        self.reset_time = reset_time
        self.split_reply = split_reply
        self.stale_reply = stale_reply
        self.stale_reply_sent_at: float | None = None
        self.received = bytearray()
        self.unread = bytearray(pending)
        # Op codes, with the time each command was read or answered
        self.commands: list[tuple[int, float]] = []
        self.answers: list[tuple[int, float]] = []
        self.busy_until = 0.0
        self.timers: list[asyncio.TimerHandle] = []
        self.master, self.slave = os.openpty()
        tty.setraw(self.slave)
        os.set_blocking(self.master, False)
        self.chatter = asyncio.create_task(self._chatter()) if chatter else None
        asyncio.get_running_loop().add_reader(self.master, self._on_readable)
        self._read_commands()

    @property
    def path(self) -> str:
        return os.ttyname(self.slave)

    def open_count(self) -> int:
        '''Number of file descriptors this process holds on the port'''
        fds = os.listdir('/proc/self/fd')
        return sum(os.path.realpath(f'/proc/self/fd/{fd}') == self.path for fd in fds)

    def times(self, events: list[tuple[int, float]], op_code: int) -> list[float]:
        return [time for event_op_code, time in events if event_op_code == op_code]

    async def _chatter(self) -> None:
        while not self.times(self.commands, hci.HCI_RESET_COMMAND):
            os.write(self.master, PARTIAL_EVENT)
            await asyncio.sleep(0.01)

    def _on_readable(self) -> None:
        data = os.read(self.master, 4096)
        self.received += data
        self.unread += data
        self._read_commands()

    def _read_commands(self) -> None:
        loop = asyncio.get_running_loop()
        while self.unread:
            if self.unread[0] != hci.HCI_COMMAND_PACKET:
                del self.unread[0]
                continue
            if len(self.unread) < 4 or len(self.unread) < 4 + self.unread[3]:
                return
            op_code = int.from_bytes(self.unread[1:3], 'little')
            del self.unread[: 4 + self.unread[3]]
            self.commands.append((op_code, loop.time()))
            if op_code not in self.replies:
                continue
            self.busy_until = max(self.busy_until, loop.time())
            if op_code == hci.HCI_RESET_COMMAND:
                self.busy_until += self.reset_time
            else:
                self.busy_until += 0.01
            self.timers.append(loop.call_at(self.busy_until, self._answer, op_code))

    def _answer(self, op_code: int) -> None:
        loop = asyncio.get_running_loop()
        self.answers.append((op_code, loop.time()))
        reply = self.replies[op_code]
        if op_code == hci.HCI_RESET_COMMAND and self.stale_reply:
            reply = self.stale_reply + reply
            self.stale_reply = b''
            self.stale_reply_sent_at = loop.time()
        if not self.split_reply:
            os.write(self.master, reply)
            return
        os.write(self.master, reply[:3])
        for delay, piece in ((0.01, reply[3:6]), (0.02, reply[6:])):
            self.timers.append(loop.call_later(delay, os.write, self.master, piece))

    def close(self) -> None:
        if self.chatter:
            self.chatter.cancel()
        for timer in self.timers:
            timer.cancel()
        asyncio.get_running_loop().remove_reader(self.master)
        os.close(self.master)
        os.close(self.slave)


async def open_with_resync(
    fake_controller: FakeSerialController,
    monkeypatch,
    options: str = 'resync',
    injected=lambda: None,
) -> transport.Transport:
    '''
    Open the port with `options`, call `injected` to check that the scenario under test
    took place, then check that nothing the resync discarded reaches the host, and that
    the resync read the local version information once a reset was complete.
    '''
    passed = bytearray()
    data_received = common.StreamPacketSource.data_received

    def spy(source, data):
        passed.extend(data)
        data_received(source, data)

    monkeypatch.setattr(common.StreamPacketSource, 'data_received', spy)
    loop = asyncio.get_running_loop()
    serial_transport = await asyncio.wait_for(
        serial.open_serial_transport(f'{fake_controller.path},{options}'), 5
    )
    opened_at = loop.time()
    passed_at_open = len(passed)
    sink = Sink()
    serial_transport.source.set_packet_sink(sink)
    injected()

    # No answer reached the parser during the resync, and the parser is ready for a
    # packet to start
    assert b'\x04\x0e' not in passed[:passed_at_open]
    os.write(fake_controller.master, HCI_RESET_COMPLETE)
    await asyncio.sleep(0.1)
    assert passed[passed_at_open:] == HCI_RESET_COMPLETE
    assert sink.packets == [HCI_RESET_COMPLETE]

    assert fake_controller.received == (
        bytes(serial.RESYNC_PADDING_SIZE)
        + HCI_RESET
        + HCI_READ_LOCAL_VERSION_INFORMATION
    )
    resets_answered_at = fake_controller.times(
        fake_controller.answers, hci.HCI_RESET_COMMAND
    )
    [commands_read_at] = fake_controller.times(
        fake_controller.commands, hci.HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND
    )
    [commands_answered_at] = fake_controller.times(
        fake_controller.answers, hci.HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND
    )
    assert resets_answered_at[0] <= commands_read_at
    assert commands_answered_at < opened_at
    return serial_transport


# -----------------------------------------------------------------------------
def test_parser():
    sink1 = Sink()
    parser1 = common.PacketParser(sink1)
    sink2 = Sink()
    parser2 = common.PacketParser(sink2)

    for parser in [parser1, parser2]:
        with open(
            os.path.join(os.path.dirname(__file__), '..', 'hci_data_001.bin'), 'rb'
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
    "address",
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


requires_pty = pytest.mark.skipif(
    sys.platform != 'linux', reason='The pseudo-terminal is only tested on Linux'
)


# -----------------------------------------------------------------------------
@requires_pty
async def test_resync(monkeypatch):
    # The delay lets the parser see part of the chatter before the resync starts
    monkeypatch.setattr(serial, 'DEFAULT_POST_OPEN_DELAY', 0.05)
    fake_controller = FakeSerialController(chatter=True, pending=PARTIAL_COMMAND)
    try:
        serial_transport = await open_with_resync(
            fake_controller, monkeypatch, 'delay,resync'
        )
        # The padding completed the partial command
        assert [op_code for op_code, _ in fake_controller.commands] == [
            0xFC00,
            hci.HCI_RESET_COMMAND,
            hci.HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND,
        ]
        await serial_transport.close()
    finally:
        fake_controller.close()


# -----------------------------------------------------------------------------
@requires_pty
async def test_resync_after_a_partial_reset(monkeypatch):
    # The controller is left reading an HCI_Reset command without its length. The first
    # padding byte completes it, so the controller resets twice.
    fake_controller = FakeSerialController(reset_time=0.15, pending=HCI_RESET[:3])

    def injected():
        reads = fake_controller.times(fake_controller.commands, hci.HCI_RESET_COMMAND)
        answers = fake_controller.times(fake_controller.answers, hci.HCI_RESET_COMMAND)
        [commands_answered_at] = fake_controller.times(
            fake_controller.answers, hci.HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND
        )
        assert len(reads) == 2
        assert reads[1] < answers[0]
        assert answers[1] < commands_answered_at

    try:
        serial_transport = await open_with_resync(
            fake_controller, monkeypatch, injected=injected
        )
        await serial_transport.close()
    finally:
        fake_controller.close()


# -----------------------------------------------------------------------------
@requires_pty
async def test_resync_ignores_a_completion_received_before_its_command(monkeypatch):
    fake_controller = FakeSerialController(
        split_reply=True, stale_reply=HCI_READ_LOCAL_VERSION_INFORMATION_COMPLETE
    )

    def injected():
        [commands_read_at] = fake_controller.times(
            fake_controller.commands, hci.HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND
        )
        assert fake_controller.stale_reply_sent_at is not None
        assert fake_controller.stale_reply_sent_at < commands_read_at

    try:
        serial_transport = await open_with_resync(
            fake_controller, monkeypatch, injected=injected
        )
        await serial_transport.close()
    finally:
        fake_controller.close()


# -----------------------------------------------------------------------------
@requires_pty
async def test_resync_writes_in_small_chunks(monkeypatch):
    sizes = []
    write = pyserial.Serial.write

    def spy(self, data):
        sizes.append(len(data))
        return write(self, data)

    monkeypatch.setattr(pyserial.Serial, 'write', spy)
    fake_controller = FakeSerialController()
    try:
        serial_transport = await open_with_resync(fake_controller, monkeypatch)
        assert sum(sizes) == len(fake_controller.received)
        assert max(sizes) <= 64
        await serial_transport.close()
    finally:
        fake_controller.close()


# -----------------------------------------------------------------------------
@requires_pty
async def test_no_resync_by_default():
    fake_controller = FakeSerialController()
    try:
        serial_transport = await serial.open_serial_transport(fake_controller.path)
        sink = Sink()
        serial_transport.source.set_packet_sink(sink)

        # Nothing was sent, and the parser is lost: it takes the event for the rest of
        # the partial one that came before it.
        assert not fake_controller.received
        os.write(fake_controller.master, PARTIAL_EVENT + HCI_RESET_COMPLETE)
        await asyncio.sleep(0.1)
        assert not sink.packets

        await serial_transport.close()
    finally:
        fake_controller.close()


# -----------------------------------------------------------------------------
@requires_pty
async def test_resync_fails_when_the_reset_is_not_answered(monkeypatch):
    monkeypatch.setattr(serial, 'RESYNC_MAX_TIME', 0.3)
    fake_controller = FakeSerialController(honors_reset=False)
    try:
        loop = asyncio.get_running_loop()
        started_at = loop.time()
        with pytest.raises(common.TransportInitError) as error:
            await asyncio.wait_for(
                serial.open_serial_transport(f'{fake_controller.path},resync'), 5
            )
        assert loop.time() - started_at >= 0.3
        assert 'did not answer' in str(error.value)

        assert fake_controller.received == bytes(serial.RESYNC_PADDING_SIZE) + HCI_RESET
        await asyncio.sleep(0.1)
        assert fake_controller.open_count() == 1
    finally:
        fake_controller.close()


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
    "address",
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
    "spec",
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
def test_packet_splitter_complete():
    emitted = []
    splitter = usb.AclPacketSplitter(emitted.append)
    packet = bytes([0x01, 0x00, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44])
    splitter.feed(packet)
    assert emitted == [packet]


def test_packet_splitter_chunks():
    emitted = []
    splitter = usb.AclPacketSplitter(emitted.append)
    packet = bytes([0x01, 0x00, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44])
    splitter.feed(packet[:4])
    assert emitted == []
    splitter.feed(packet[4:])
    assert emitted == [packet]


def test_packet_splitter_multiple():
    emitted = []
    splitter = usb.AclPacketSplitter(emitted.append)
    packet1 = bytes([0x01, 0x00, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44])
    packet2 = bytes([0x02, 0x00, 0x02, 0x00, 0x55, 0x66])
    splitter.feed(packet1 + packet2)
    assert emitted == [packet1, packet2]


def test_packet_splitter_partial():
    emitted = []
    splitter = usb.AclPacketSplitter(emitted.append)
    packet1 = bytes([0x01, 0x00, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44])
    packet2 = bytes([0x02, 0x00, 0x02, 0x00, 0x55, 0x66])
    splitter.feed(packet1 + packet2[:4])
    assert emitted == [packet1]
    splitter.feed(packet2[4:])
    assert emitted == [packet1, packet2]


def test_packet_splitter_empty_payload():
    emitted = []
    splitter = usb.AclPacketSplitter(emitted.append)
    packet = bytes([0x01, 0x00, 0x00, 0x00])
    splitter.feed(packet)
    assert emitted == [packet]


def test_sco_packet_splitter():
    emitted = []
    splitter = usb.ScoPacketSplitter(emitted.append)
    packet = bytes([0x01, 0x00, 0x03, 0x11, 0x22, 0x33])
    splitter.feed(packet)
    assert emitted == [packet]


def test_event_packet_splitter():
    emitted = []
    splitter = usb.EventPacketSplitter(emitted.append)
    packet = bytes([0x04, 0x02, 0x11, 0x22])
    splitter.feed(packet)
    assert emitted == [packet]


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_parser()
    test_parser_extensions()
