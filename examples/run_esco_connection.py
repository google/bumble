# Copyright 2021-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
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
import sys

import bumble.logging
from bumble import hfp
from bumble.core import PhysicalTransport
from bumble.device import Connection, Device, ScoLink
from bumble.hfp import ESCO_PARAMETERS, DefaultCodecParameters
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_esco_connection.py <config-file>'
            '<transport-spec-for-device-1> <transport-spec-for-device-2>'
        )
        print(
            'example: run_esco_connection.py classic1.json'
            'tcp-client:127.0.0.1:6402 tcp-client:127.0.0.1:6402'
        )
        return

    print('<<< connecting to HCI...')
    hci_transports = await asyncio.gather(
        open_transport(sys.argv[2]), open_transport(sys.argv[3])
    )
    print('<<< connected')

    devices = [
        Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        for hci_transport in hci_transports
    ]

    devices[0].classic_enabled = True
    devices[1].classic_enabled = True

    await asyncio.gather(*[device.power_on() for device in devices])

    connections = await asyncio.gather(
        devices[0].accept(devices[1].public_address),
        devices[1].connect(
            devices[0].public_address, transport=PhysicalTransport.BR_EDR
        ),
    )

    esco_parameters = ESCO_PARAMETERS[DefaultCodecParameters.ESCO_CVSD_S3]

    # The peer controller asks its host to accept the SCO or eSCO link before the
    # connection can complete.
    def on_sco_request(connection: Connection, _link_type: int) -> None:
        connection.abort_on(
            'disconnection',
            connection.device.send_async_command(
                hfp.accept_synchronous_connection_request_command(
                    connection.device.host, connection.peer_address, esco_parameters
                )
            ),
        )

    devices[1].on(Device.EVENT_SCO_REQUEST, on_sco_request)

    def on_sco(sco_link: ScoLink) -> None:
        connections[0].abort_on('disconnection', sco_link.disconnect())

    devices[0].once(Device.EVENT_SCO_CONNECTION, on_sco)

    await devices[0].send_command(
        hfp.setup_synchronous_connection_command(
            devices[0].host, connections[0].handle, esco_parameters
        )
    )

    await asyncio.gather(
        *[hci_transport.source.terminated for hci_transport in hci_transports]
    )


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
