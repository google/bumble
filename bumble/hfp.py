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
import logging
import asyncio
import collections
from colors import color


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Protocol Support
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
class HfpProtocol:
    def __init__(self, dlc):
        self.dlc             = dlc
        self.buffer          = ''
        self.lines           = collections.deque()
        self.lines_available = asyncio.Event()

        dlc.sink = self.feed

    def feed(self, data):
        # Convert the data to a string if needed
        if type(data) == bytes:
            data = data.decode('utf-8')

        logger.debug(f'<<< Data received: {data}')

        # Add to the buffer and look for lines
        self.buffer += data
        while (separator := self.buffer.find('\r')) >= 0:
            line = self.buffer[:separator].strip()
            self.buffer = self.buffer[separator + 1:]
            if len(line) > 0:
                self.on_line(line)

    def on_line(self, line):
        self.lines.append(line)
        self.lines_available.set()

    def send_command_line(self, line):
        logger.debug(color(f'>>> {line}', 'yellow'))
        self.dlc.write(line + '\r')

    def send_response_line(self, line):
        logger.debug(color(f'>>> {line}', 'yellow'))
        self.dlc.write('\r\n' + line + '\r\n')

    async def next_line(self):
        await self.lines_available.wait()
        line = self.lines.popleft()
        if not self.lines:
            self.lines_available.clear()
        logger.debug(color(f'<<< {line}', 'green'))
        return line

    async def initialize_service(self):
        # Perform Service Level Connection Initialization
        self.send_command_line('AT+BRSF=2072')  # Retrieve Supported Features
        line = await(self.next_line())
        line = await(self.next_line())

        self.send_command_line('AT+CIND=?')
        line = await(self.next_line())
        line = await(self.next_line())

        self.send_command_line('AT+CIND?')
        line = await(self.next_line())
        line = await(self.next_line())

        self.send_command_line('AT+CMER=3,0,0,1')
        line = await(self.next_line())
