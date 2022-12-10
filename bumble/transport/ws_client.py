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
import websockets

from .common import PumpedPacketSource, PumpedPacketSink, PumpedTransport

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_ws_client_transport(spec):
    '''
    Open a WebSocket client transport.
    The parameter string has this syntax:
    <remote-host>:<remote-port>

    Example: 127.0.0.1:9001
    '''

    remote_host, remote_port = spec.split(':')
    uri = f'ws://{remote_host}:{remote_port}'
    websocket = await websockets.connect(uri)

    transport = PumpedTransport(
        PumpedPacketSource(websocket.recv),
        PumpedPacketSink(websocket.send),
        websocket.close,
    )
    transport.start()
    return transport
