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
from __future__ import annotations
import contextlib
import struct
import asyncio
import logging
import io
from typing import ContextManager, Tuple, Optional, Protocol, Dict

from bumble import hci
from bumble.colors import color
from bumble.snoop import Snooper


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Information needed to parse HCI packets with a generic parser:
# For each packet type, the info represents:
# (length-size, length-offset, unpack-type)
HCI_PACKET_INFO: Dict[int, Tuple[int, int, str]] = {
    hci.HCI_COMMAND_PACKET: (1, 2, 'B'),
    hci.HCI_ACL_DATA_PACKET: (2, 2, 'H'),
    hci.HCI_SYNCHRONOUS_DATA_PACKET: (1, 2, 'B'),
    hci.HCI_EVENT_PACKET: (1, 1, 'B'),
}


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------
class TransportLostError(Exception):
    """
    The Transport has been lost/disconnected.
    """


# -----------------------------------------------------------------------------
# Typing Protocols
# -----------------------------------------------------------------------------
class TransportSink(Protocol):
    def on_packet(self, packet: bytes) -> None:
        ...


class TransportSource(Protocol):
    terminated: asyncio.Future[None]

    def set_packet_sink(self, sink: TransportSink) -> None:
        ...


# -----------------------------------------------------------------------------
class PacketPump:
    """
    Pump HCI packets from a reader to a sink.
    """

    def __init__(self, reader: AsyncPacketReader, sink: TransportSink) -> None:
        self.reader = reader
        self.sink = sink

    async def run(self) -> None:
        while True:
            try:
                # Deliver the packet to the sink
                self.sink.on_packet(await self.reader.next_packet())
            except Exception as error:
                logger.warning(f'!!! {error}')


# -----------------------------------------------------------------------------
class PacketParser:
    """
    In-line parser that accepts data and emits 'on_packet' when a full packet has been
    parsed.
    """

    # pylint: disable=attribute-defined-outside-init

    NEED_TYPE = 0
    NEED_LENGTH = 1
    NEED_BODY = 2

    sink: Optional[TransportSink]
    extended_packet_info: Dict[int, Tuple[int, int, str]]
    packet_info: Optional[Tuple[int, int, str]] = None

    def __init__(self, sink: Optional[TransportSink] = None) -> None:
        self.sink = sink
        self.extended_packet_info = {}
        self.reset()

    def reset(self) -> None:
        self.state = PacketParser.NEED_TYPE
        self.bytes_needed = 1
        self.packet = bytearray()
        self.packet_info = None

    def feed_data(self, data: bytes) -> None:
        data_offset = 0
        data_left = len(data)
        while data_left and self.bytes_needed:
            consumed = min(self.bytes_needed, data_left)
            self.packet.extend(data[data_offset : data_offset + consumed])
            data_offset += consumed
            data_left -= consumed
            self.bytes_needed -= consumed

            if self.bytes_needed == 0:
                if self.state == PacketParser.NEED_TYPE:
                    packet_type = self.packet[0]
                    self.packet_info = HCI_PACKET_INFO.get(
                        packet_type
                    ) or self.extended_packet_info.get(packet_type)
                    if self.packet_info is None:
                        raise ValueError(f'invalid packet type {packet_type}')
                    self.state = PacketParser.NEED_LENGTH
                    self.bytes_needed = self.packet_info[0] + self.packet_info[1]
                elif self.state == PacketParser.NEED_LENGTH:
                    assert self.packet_info is not None
                    body_length = struct.unpack_from(
                        self.packet_info[2], self.packet, 1 + self.packet_info[1]
                    )[0]
                    self.bytes_needed = body_length
                    self.state = PacketParser.NEED_BODY

                # Emit a packet if one is complete
                if self.state == PacketParser.NEED_BODY and not self.bytes_needed:
                    if self.sink:
                        try:
                            self.sink.on_packet(bytes(self.packet))
                        except Exception as error:
                            logger.exception(
                                color(f'!!! Exception in on_packet: {error}', 'red')
                            )
                    self.reset()

    def set_packet_sink(self, sink: TransportSink) -> None:
        self.sink = sink


# -----------------------------------------------------------------------------
class PacketReader:
    """
    Reader that reads HCI packets from a sync source.
    """

    def __init__(self, source: io.BufferedReader) -> None:
        self.source = source

    def next_packet(self) -> Optional[bytes]:
        # Get the packet type
        packet_type = self.source.read(1)
        if len(packet_type) != 1:
            return None

        # Get the packet info based on its type
        packet_info = HCI_PACKET_INFO.get(packet_type[0])
        if packet_info is None:
            raise ValueError(f'invalid packet type {packet_type[0]} found')

        # Read the header (that includes the length)
        header_size = packet_info[0] + packet_info[1]
        header = self.source.read(header_size)
        if len(header) != header_size:
            raise ValueError('packet too short')

        # Read the body
        body_length = struct.unpack_from(packet_info[2], header, packet_info[1])[0]
        body = self.source.read(body_length)
        if len(body) != body_length:
            raise ValueError('packet too short')

        return packet_type + header + body


# -----------------------------------------------------------------------------
class AsyncPacketReader:
    """
    Reader that reads HCI packets from an async source.
    """

    def __init__(self, source: asyncio.StreamReader) -> None:
        self.source = source

    async def next_packet(self) -> bytes:
        # Get the packet type
        packet_type = await self.source.readexactly(1)

        # Get the packet info based on its type
        packet_info = HCI_PACKET_INFO.get(packet_type[0])
        if packet_info is None:
            raise ValueError(f'invalid packet type {packet_type[0]} found')

        # Read the header (that includes the length)
        header_size = packet_info[0] + packet_info[1]
        header = await self.source.readexactly(header_size)

        # Read the body
        body_length = struct.unpack_from(packet_info[2], header, packet_info[1])[0]
        body = await self.source.readexactly(body_length)

        return packet_type + header + body


# -----------------------------------------------------------------------------
class AsyncPipeSink:
    """
    Sink that forwards packets asynchronously to another sink.
    """

    def __init__(self, sink: TransportSink) -> None:
        self.sink = sink
        self.loop = asyncio.get_running_loop()

    def on_packet(self, packet: bytes) -> None:
        self.loop.call_soon(self.sink.on_packet, packet)


# -----------------------------------------------------------------------------
class ParserSource:
    """
    Base class designed to be subclassed by transport-specific source classes
    """

    terminated: asyncio.Future[None]
    parser: PacketParser

    def __init__(self) -> None:
        self.parser = PacketParser()
        self.terminated = asyncio.get_running_loop().create_future()

    def set_packet_sink(self, sink: TransportSink) -> None:
        self.parser.set_packet_sink(sink)

    def on_transport_lost(self) -> None:
        self.terminated.set_result(None)
        if self.parser.sink:
            if hasattr(self.parser.sink, 'on_transport_lost'):
                self.parser.sink.on_transport_lost()

    async def wait_for_termination(self) -> None:
        """
        Convenience method for backward compatibility. Prefer using the `terminated`
        attribute instead.
        """
        return await self.terminated

    def close(self) -> None:
        pass


# -----------------------------------------------------------------------------
class StreamPacketSource(asyncio.Protocol, ParserSource):
    def data_received(self, data: bytes) -> None:
        self.parser.feed_data(data)


# -----------------------------------------------------------------------------
class StreamPacketSink:
    def __init__(self, transport: asyncio.WriteTransport) -> None:
        self.transport = transport

    def on_packet(self, packet: bytes) -> None:
        self.transport.write(packet)

    def close(self) -> None:
        self.transport.close()


# -----------------------------------------------------------------------------
class Transport:
    """
    Base class for all transports.

    A Transport represents a source and a sink together.
    An instance must be closed by calling close() when no longer used. Instances
    implement the ContextManager protocol so that they may be used in a `async with`
    statement.
    An instance is iterable. The iterator yields, in order, its source and sink, so
    that it may be used with a convenient call syntax like:

    async with create_transport() as (source, sink):
        ...
    """

    def __init__(self, source: TransportSource, sink: TransportSink) -> None:
        self.source = source
        self.sink = sink

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def __iter__(self):
        return iter((self.source, self.sink))

    async def close(self) -> None:
        if hasattr(self.source, 'close'):
            self.source.close()
        if hasattr(self.sink, 'close'):
            self.sink.close()


# -----------------------------------------------------------------------------
class PumpedPacketSource(ParserSource):
    pump_task: Optional[asyncio.Task[None]]

    def __init__(self, receive) -> None:
        super().__init__()
        self.receive_function = receive
        self.pump_task = None

    def start(self) -> None:
        async def pump_packets() -> None:
            while True:
                try:
                    packet = await self.receive_function()
                    self.parser.feed_data(packet)
                except asyncio.CancelledError:
                    logger.debug('source pump task done')
                    self.terminated.set_result(None)
                    break
                except Exception as error:
                    logger.warning(f'exception while waiting for packet: {error}')
                    self.terminated.set_exception(error)
                    break

        self.pump_task = asyncio.create_task(pump_packets())

    def close(self) -> None:
        if self.pump_task:
            self.pump_task.cancel()


# -----------------------------------------------------------------------------
class PumpedPacketSink:
    def __init__(self, send):
        self.send_function = send
        self.packet_queue = asyncio.Queue()
        self.pump_task = None

    def on_packet(self, packet: bytes) -> None:
        self.packet_queue.put_nowait(packet)

    def start(self):
        async def pump_packets():
            while True:
                try:
                    packet = await self.packet_queue.get()
                    await self.send_function(packet)
                except asyncio.CancelledError:
                    logger.debug('sink pump task done')
                    break
                except Exception as error:
                    logger.warning(f'exception while sending packet: {error}')
                    break

        self.pump_task = asyncio.create_task(pump_packets())

    def close(self):
        if self.pump_task:
            self.pump_task.cancel()


# -----------------------------------------------------------------------------
class PumpedTransport(Transport):
    source: PumpedPacketSource
    sink: PumpedPacketSink

    def __init__(
        self,
        source: PumpedPacketSource,
        sink: PumpedPacketSink,
    ) -> None:
        super().__init__(source, sink)

    def start(self) -> None:
        self.source.start()
        self.sink.start()


# -----------------------------------------------------------------------------
class SnoopingTransport(Transport):
    """Transport wrapper that snoops on packets to/from a wrapped transport."""

    @staticmethod
    def create_with(
        transport: Transport, snooper: ContextManager[Snooper]
    ) -> SnoopingTransport:
        """
        Create an instance given a snooper that works as as context manager.

        The returned instance will exit the snooper context when it is closed.
        """
        with contextlib.ExitStack() as exit_stack:
            return SnoopingTransport(
                transport, exit_stack.enter_context(snooper), exit_stack.pop_all().close
            )
        raise RuntimeError('unexpected code path')  # Satisfy the type checker

    class Source:
        sink: TransportSink

        def __init__(self, source: TransportSource, snooper: Snooper):
            self.source = source
            self.snooper = snooper
            self.terminated = source.terminated

        def set_packet_sink(self, sink: TransportSink) -> None:
            self.sink = sink
            self.source.set_packet_sink(self)

        def on_packet(self, packet: bytes) -> None:
            self.snooper.snoop(packet, Snooper.Direction.CONTROLLER_TO_HOST)
            if self.sink:
                self.sink.on_packet(packet)

    class Sink:
        def __init__(self, sink: TransportSink, snooper: Snooper) -> None:
            self.sink = sink
            self.snooper = snooper

        def on_packet(self, packet: bytes) -> None:
            self.snooper.snoop(packet, Snooper.Direction.HOST_TO_CONTROLLER)
            if self.sink:
                self.sink.on_packet(packet)

    def __init__(
        self,
        transport: Transport,
        snooper: Snooper,
        close_snooper=None,
    ) -> None:
        super().__init__(
            self.Source(transport.source, snooper), self.Sink(transport.sink, snooper)
        )
        self.transport = transport
        self.close_snooper = close_snooper

    async def close(self):
        await self.transport.close()
        if self.close_snooper:
            self.close_snooper()
