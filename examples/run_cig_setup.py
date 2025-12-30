# Copyright 2021-2023 Google LLC
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
from bumble.device import CigParameters, CisLink, Connection, Device
from bumble.hci import OwnAddressType
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_cig_setup.py <config-file> '
            '<transport-spec-for-device-1> <transport-spec-for-device-2>'
        )
        print('example: run_cig_setup.py device1.json hci-socket:0 hci-socket:1')
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

    devices[0].cis_enabled = True
    devices[1].cis_enabled = True

    await asyncio.gather(*[device.power_on() for device in devices])

    connection = await devices[1].connect(
        devices[0].random_address, own_address_type=OwnAddressType.RANDOM
    )

    cis_handles = await devices[1].setup_cig(
        CigParameters(
            cig_id=1,
            cis_parameters=[
                CigParameters.CisParameters(
                    cis_id=2,
                    max_sdu_c_to_p=120,
                    max_sdu_p_to_c=0,
                    rtn_c_to_p=13,
                    rtn_p_to_c=13,
                ),
                CigParameters.CisParameters(
                    cis_id=3,
                    max_sdu_c_to_p=120,
                    max_sdu_p_to_c=0,
                    rtn_c_to_p=13,
                    rtn_p_to_c=13,
                ),
            ],
            sdu_interval_c_to_p=10000,
            sdu_interval_p_to_c=255,
            framing=CigParameters.Framing.UNFRAMED,
            max_transport_latency_c_to_p=100,
            max_transport_latency_p_to_c=5,
        ),
    )

    def on_cis_request(connection: Connection, cis_link: CisLink):
        connection.cancel_on_disconnection(devices[0].accept_cis_request(cis_link))

    devices[0].on('cis_request', on_cis_request)

    cis_links = await devices[1].create_cis([(cis, connection) for cis in cis_handles])

    for cis_link in cis_links:
        await cis_link.disconnect()

    await asyncio.gather(
        *[hci_transport.source.terminated for hci_transport in hci_transports]
    )


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
