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
import io
import logging

from .common import Transport, StreamPacketSource, StreamPacketSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_file_transport(spec: str) -> Transport:
    '''
    Open a File transport (typically not for a real file, but for a PTY or other unix
    virtual files).
    The parameter string is the path of the file to open.
    '''

    # Open the file
    file = io.open(spec, 'r+b', buffering=0)

    # Setup reading
    read_transport, packet_source = await asyncio.get_running_loop().connect_read_pipe(
        StreamPacketSource, file
    )

    # Setup writing
    write_transport, _ = await asyncio.get_running_loop().connect_write_pipe(
        asyncio.BaseProtocol, file
    )
    packet_sink = StreamPacketSink(write_transport)

    class FileTransport(Transport):
        async def close(self):
            read_transport.close()
            write_transport.close()
            file.close()

    return FileTransport(packet_source, packet_sink)
