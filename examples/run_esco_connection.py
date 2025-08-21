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
import sys

import bumble.logging
from bumble.core import PhysicalTransport
from bumble.device import Device, ScoLink
from bumble.hci import HCI_Enhanced_Setup_Synchronous_Connection_Command
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

    def on_sco(sco_link: ScoLink):
        connections[0].abort_on('disconnection', sco_link.disconnect())

    devices[0].once('sco_connection', on_sco)

    await devices[0].send_command(
        HCI_Enhanced_Setup_Synchronous_Connection_Command(
            connection_handle=connections[0].handle,
            **ESCO_PARAMETERS[DefaultCodecParameters.ESCO_CVSD_S3].asdict(),
        )
    )

    await asyncio.gather(
        *[hci_transport.source.terminated for hci_transport in hci_transports]
    )


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
