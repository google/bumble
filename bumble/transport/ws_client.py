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
import websockets.client

from .common import PumpedPacketSource, PumpedPacketSink, PumpedTransport, Transport

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_ws_client_transport(spec: str) -> Transport:
    '''
    Open a WebSocket client transport.
    The parameter string has this syntax:
    <websocket-url>

    Example: ws://localhost:7681/v1/websocket/bt
    '''

    websocket = await websockets.client.connect(spec)

    class WsTransport(PumpedTransport):
        async def close(self):
            await super().close()
            await websocket.close()

    transport = WsTransport(
        PumpedPacketSource(websocket.recv),
        PumpedPacketSink(websocket.send),
    )
    transport.start()
    return transport
