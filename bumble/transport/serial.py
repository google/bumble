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
import re

import serial_asyncio

from bumble import hci
from bumble.transport.common import (
    StreamPacketSink,
    StreamPacketSource,
    Transport,
    TransportInitError,
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_POST_OPEN_DELAY = 0.5  # in seconds

# Enough to complete a command or SCO packet the controller is still reading: a 3-byte
# header and up to 255 bytes of payload. ACL and ISO packets have 16-bit lengths and
# are not covered. Zero is not a valid H:4 packet type.
RESYNC_PADDING_SIZE = 3 + 255
# Through a J-Link OB virtual COM port, larger writes left the controller hung
RESYNC_WRITE_SIZE = 64
RESYNC_MAX_TIME = 2.0  # in seconds

# -----------------------------------------------------------------------------
# Classes and Functions
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
class SerialPacketSource(StreamPacketSource):
    def __init__(self) -> None:
        super().__init__()
        self._ready = asyncio.Event()
        self._awaited: re.Pattern[bytes] | None = None
        self._discarded = bytearray()
        self._answered = asyncio.Event()

    async def wait_until_ready(self) -> None:
        await self._ready.wait()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        logger.debug('connection made')
        self._ready.set()

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug('connection lost')
        self.on_transport_lost()

    def data_received(self, data: bytes) -> None:
        if self._awaited is None:
            super().data_received(data)
            return
        self._discarded += data
        if self._awaited.search(self._discarded):
            self._answered.set()

    async def resync(self, transport: asyncio.WriteTransport, max_time: float) -> None:
        '''
        Send zero padding and an HCI_Reset command, then, once a reset is complete, an
        HCI_Read_Local_Version_Information command, discarding everything received until
        that command is complete. If that takes more than `max_time` seconds, closes
        the port and raises TransportInitError.
        '''

        async def write(data: bytes) -> None:
            for offset in range(0, len(data), RESYNC_WRITE_SIZE):
                transport.write(data[offset : offset + RESYNC_WRITE_SIZE])
                while transport.get_write_buffer_size():
                    await asyncio.sleep(0)

        async def exchange(
            command: hci.HCI_Command, return_parameters_size: int, padding: bytes = b''
        ) -> None:
            # A completion received before the command is sent is not an answer to it
            self._discarded.clear()
            self._answered.clear()
            self._awaited = re.compile(
                re.escape(bytes([0x04, 0x0E, 3 + return_parameters_size]))
                + b'.'
                + re.escape(command.op_code.to_bytes(2, 'little'))
                + b'.{%d}' % return_parameters_size,
                re.DOTALL,
            )
            await write(padding + bytes(command))
            await self._answered.wait()

        async def run() -> None:
            await exchange(hci.HCI_Reset_Command(), 1, bytes(RESYNC_PADDING_SIZE))
            # That completion can be for an earlier reset. Anything still pending arrives
            # before the completion of the next command.
            await exchange(hci.HCI_Read_Local_Version_Information_Command(), 9)

        try:
            await asyncio.wait_for(run(), max_time)
        except asyncio.TimeoutError:
            transport.close()
            raise TransportInitError(
                'the controller did not answer the commands sent to resynchronize'
            ) from None
        finally:
            self._awaited = None
            self.parser.reset()


# -----------------------------------------------------------------------------
async def open_serial_transport(spec: str) -> Transport:
    '''
    Open a serial port transport.
    The parameter string has this syntax:
    <device-path>[,<speed>][,rtscts][,dsrdtr][,delay][,resync]
    When <speed> is omitted, the default value of 1000000 is used
    When "rtscts" is specified, RTS/CTS hardware flow control is enabled
    When "dsrdtr" is specified, DSR/DTR hardware flow control is enabled
    When "delay" is specified, a short delay is added after opening the port
    When "resync" is specified, zero padding followed by an HCI_Reset command is sent
    after opening the port, then, once a reset is complete, an
    HCI_Read_Local_Version_Information command, and everything received is discarded
    until that command is complete. This recovers a controller left sending data or
    waiting for the rest of a command or SCO packet, but not of an ACL or ISO packet.
    If the commands are not answered within 2 seconds, the port is closed and a
    TransportInitError is raised

    Examples:
    /dev/tty.usbmodem0006839912172
    /dev/tty.usbmodem0006839912172,1000000
    /dev/tty.usbmodem0006839912172,rtscts
    /dev/tty.usbmodem0006839912172,rtscts,delay
    /dev/tty.usbmodem0006839912172,resync
    '''

    speed = 1000000
    rtscts = False
    dsrdtr = False
    delay = 0.0
    resync = False
    if ',' in spec:
        parts = spec.split(',')
        device = parts[0]
        for part in parts[1:]:
            if part == 'rtscts':
                rtscts = True
            elif part == 'dsrdtr':
                dsrdtr = True
            elif part == 'delay':
                delay = DEFAULT_POST_OPEN_DELAY
            elif part == 'resync':
                resync = True
            elif part.isnumeric():
                speed = int(part)
    else:
        device = spec

    serial_transport, packet_source = await serial_asyncio.create_serial_connection(
        asyncio.get_running_loop(),
        SerialPacketSource,
        device,
        baudrate=speed,
        rtscts=rtscts,
        dsrdtr=dsrdtr,
    )
    packet_sink = StreamPacketSink(serial_transport)

    logger.debug('waiting for the port to be ready')
    await packet_source.wait_until_ready()
    logger.debug('port is ready')

    # Try to assert DTR
    assert serial_transport.serial is not None
    try:
        serial_transport.serial.dtr = True
        logger.debug(
            f"DSR={serial_transport.serial.dsr}, DTR={serial_transport.serial.dtr}"
        )
    except Exception as e:
        logger.warning(f'could not assert DTR: {e}')

    # Wait a bit after opening the port, if requested
    if delay > 0.0:
        logger.debug(f'waiting {delay} seconds after opening the port')
        await asyncio.sleep(delay)

    if resync:
        logger.debug('resynchronizing with the controller')
        await packet_source.resync(serial_transport, RESYNC_MAX_TIME)

    return Transport(packet_source, packet_sink)
