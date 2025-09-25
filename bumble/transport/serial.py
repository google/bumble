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

import serial_asyncio

from bumble.transport.common import StreamPacketSink, StreamPacketSource, Transport

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_POST_OPEN_DELAY = 0.5  # in seconds

# -----------------------------------------------------------------------------
# Classes and Functions
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
class SerialPacketSource(StreamPacketSource):
    def __init__(self) -> None:
        super().__init__()
        self._ready = asyncio.Event()

    async def wait_until_ready(self) -> None:
        await self._ready.wait()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        logger.debug('connection made')
        self._ready.set()

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug('connection lost')
        self.on_transport_lost()


# -----------------------------------------------------------------------------
async def open_serial_transport(spec: str) -> Transport:
    '''
    Open a serial port transport.
    The parameter string has this syntax:
    <device-path>[,<speed>][,rtscts][,dsrdtr][,delay]
    When <speed> is omitted, the default value of 1000000 is used
    When "rtscts" is specified, RTS/CTS hardware flow control is enabled
    When "dsrdtr" is specified, DSR/DTR hardware flow control is enabled
    When "delay" is specified, a short delay is added after opening the port

    Examples:
    /dev/tty.usbmodem0006839912172
    /dev/tty.usbmodem0006839912172,1000000
    /dev/tty.usbmodem0006839912172,rtscts
    /dev/tty.usbmodem0006839912172,rtscts,delay
    '''

    speed = 1000000
    rtscts = False
    dsrdtr = False
    delay = 0.0
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

    return Transport(packet_source, packet_sink)
