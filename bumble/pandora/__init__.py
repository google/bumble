# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Bumble Pandora server.
This module implement the Pandora Bluetooth test APIs for the Bumble stack.
"""

__version__ = "0.0.1"

import grpc
import grpc.aio

from .config import Config
from .device import PandoraDevice
from .host import HostService
from .security import SecurityService, SecurityStorageService
from pandora.host_grpc_aio import add_HostServicer_to_server
from pandora.security_grpc_aio import (
    add_SecurityServicer_to_server,
    add_SecurityStorageServicer_to_server,
)
from typing import Callable, List, Optional

# public symbols
__all__ = [
    'register_servicer_hook',
    'serve',
    'Config',
    'PandoraDevice',
]


# Add servicers hooks.
_SERVICERS_HOOKS: List[Callable[[PandoraDevice, Config, grpc.aio.Server], None]] = []


def register_servicer_hook(
    hook: Callable[[PandoraDevice, Config, grpc.aio.Server], None]
) -> None:
    _SERVICERS_HOOKS.append(hook)


async def serve(
    bumble: PandoraDevice,
    config: Config = Config(),
    grpc_server: Optional[grpc.aio.Server] = None,
    port: int = 0,
) -> None:
    # initialize a gRPC server if not provided.
    server = grpc_server if grpc_server is not None else grpc.aio.server()
    port = server.add_insecure_port(f'localhost:{port}')

    try:
        while True:
            # load server config from dict.
            config.load_from_dict(bumble.config.get('server', {}))

            # add Pandora services to the gRPC server.
            add_HostServicer_to_server(
                HostService(server, bumble.device, config), server
            )
            add_SecurityServicer_to_server(
                SecurityService(bumble.device, config), server
            )
            add_SecurityStorageServicer_to_server(
                SecurityStorageService(bumble.device, config), server
            )

            # call hooks if any.
            for hook in _SERVICERS_HOOKS:
                hook(bumble, config, server)

            # open device.
            await bumble.open()
            try:
                # Pandora require classic devices to be discoverable & connectable.
                if bumble.device.classic_enabled:
                    await bumble.device.set_discoverable(True)
                    await bumble.device.set_connectable(True)

                # start & serve gRPC server.
                await server.start()
                await server.wait_for_termination()
            finally:
                # close device.
                await bumble.close()

            # re-initialize the gRPC server.
            server = grpc.aio.server()
            server.add_insecure_port(f'localhost:{port}')
    finally:
        # stop server.
        await server.stop(None)
