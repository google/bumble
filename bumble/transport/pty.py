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
import pty
import tty
import io
import atexit
import os
import logging

from typing import Optional

from .common import Transport, StreamPacketSource, StreamPacketSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_pty_transport(spec: Optional[str]) -> Transport:
    '''
    Open a PTY transport.
    The parameter string may be empty, or a path name where a symbolic link
    to the PTY will be created (the link will be removed when the transport
    is closed or when the process exits)
    '''

    primary, replica = pty.openpty()
    replica_path = os.ttyname(replica)
    logger.debug(f'pty open at {replica_path}')
    tty.setraw(primary)
    tty.setraw(replica)

    read_transport, packet_source = await asyncio.get_running_loop().connect_read_pipe(
        StreamPacketSource, io.open(primary, 'rb', closefd=False)
    )

    write_transport, _ = await asyncio.get_running_loop().connect_write_pipe(
        asyncio.BaseProtocol, io.open(primary, 'wb', closefd=False)
    )
    packet_sink = StreamPacketSink(write_transport)

    def cleanup():
        if spec:
            try:
                os.unlink(spec)
            except FileNotFoundError:
                pass

    # If required, create a symbolic link to the replica
    # NOTE: the link will be removed when this process exits
    if spec:
        os.symlink(replica_path, spec)
        logger.debug(f'linked pty at {spec}')
        atexit.register(cleanup)

    class PtyTransport(Transport):
        async def close(self):
            write_transport.close()
            read_transport.close()
            os.close(primary)
            os.close(replica)
            cleanup()

    return PtyTransport(packet_source, packet_sink)
