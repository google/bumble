# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Expose a BabbleSim-backed LE Controller as a Unix-socket H4 endpoint."""

import argparse
import asyncio
import sys
from pathlib import Path

import bumble.logging
from bumble.radio_controller.radio_asyncio import RadioEventLoop
from bumble.radio_controller.radio_babblesim import BabbleSimSession
from bumble.radio_controller.radio_thread import RadioControllerWorker
from bumble.transport.common import PacketParser, StreamPacketSink, TransportSink


async def serve(args: argparse.Namespace) -> None:
    controller = RadioControllerWorker('radio', public_address=args.address)
    loop = asyncio.get_running_loop()
    assert isinstance(loop, RadioEventLoop)
    stopped = loop.create_future()
    client_writer = None

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        nonlocal client_writer
        if client_writer is not None:
            writer.close()
            await writer.wait_closed()
            return
        client_writer = writer
        output.sink = StreamPacketSink(writer.transport)
        parser = PacketParser(controller)
        try:
            while data := await reader.read(4096):
                parser.feed_data(data)
        except Exception as error:  # noqa: BLE001
            # Propagate client failure to serve().
            if not stopped.done():
                stopped.set_exception(error)
        finally:
            writer.close()
            if not stopped.done():
                stopped.set_result(None)

    class Output:
        sink: TransportSink | None = None

        def on_packet(self, packet):
            if self.sink is not None:
                self.sink.on_packet(packet)

    output = Output()
    controller.set_packet_sink(output)
    server = await asyncio.start_unix_server(accept, path=args.hci_socket)
    try:
        async with BabbleSimSession(
            args.sim_id, [(args.dev_id, controller)], clock_dev_id=args.clock_id
        ):
            print(f'HCI listening on {args.hci_socket}', flush=True)
            async with server:
                await stopped
    finally:
        server.close()
        await server.wait_closed()
        if client_writer is not None:
            client_writer.close()
            await client_writer.wait_closed()
        args.hci_socket.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-s', '--sim-id', required=True)
    parser.add_argument('-d', '--dev-id', type=int, required=True)
    parser.add_argument('--clock-id', type=int, required=True)
    parser.add_argument('--hci-socket', type=Path, required=True)
    parser.add_argument('--address', default='F0:F1:F2:F3:F4:01')
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        parser.error('radio controller requires Python 3.11 or newer')
    bumble.logging.setup_basic_logging('INFO')
    with asyncio.Runner(loop_factory=RadioEventLoop) as runner:
        runner.run(serve(args))


if __name__ == '__main__':
    main()
