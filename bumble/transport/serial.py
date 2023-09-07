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

from .common import Transport, StreamPacketSource, StreamPacketSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_serial_transport(spec: str) -> Transport:
    '''
    Open a serial port transport.
    The parameter string has this syntax:
    <device-path>[,<speed>][,rtscts][,dsrdtr]
    When <speed> is omitted, the default value of 1000000 is used
    When "rtscts" is specified, RTS/CTS hardware flow control is enabled
    When "dsrdtr" is specified, DSR/DTR hardware flow control is enabled

    Examples:
    /dev/tty.usbmodem0006839912172
    /dev/tty.usbmodem0006839912172,1000000
    /dev/tty.usbmodem0006839912172,rtscts
    '''

    speed = 1000000
    rtscts = False
    dsrdtr = False
    if ',' in spec:
        parts = spec.split(',')
        device = parts[0]
        for part in parts[1:]:
            if part == 'rtscts':
                rtscts = True
            elif part == 'dsrdtr':
                dsrdtr = True
            elif part.isnumeric():
                speed = int(part)
    else:
        device = spec
    serial_transport, packet_source = await serial_asyncio.create_serial_connection(
        asyncio.get_running_loop(),
        StreamPacketSource,
        device,
        baudrate=speed,
        rtscts=rtscts,
        dsrdtr=dsrdtr,
    )
    packet_sink = StreamPacketSink(serial_transport)

    return Transport(packet_source, packet_sink)
