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
import logging
import sys
import os
from bumble.device import (
    Device,
    Connection,
    AdvertisingParameters,
    AdvertisingEventProperties,
)
from bumble.hci import (
    OwnAddressType,
)

from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_cig_setup.py <config-file>'
            '<transport-spec-for-device-1> <transport-spec-for-device-2>'
        )
        print(
            'example: run_cig_setup.py device1.json'
            'tcp-client:127.0.0.1:6402 tcp-client:127.0.0.1:6402'
        )
        return

    print('<<< connecting to HCI...')
    hci_transports = await asyncio.gather(
        open_transport_or_link(sys.argv[2]), open_transport_or_link(sys.argv[3])
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
    advertising_set = await devices[0].create_advertising_set()

    connection = await devices[1].connect(
        devices[0].public_address, own_address_type=OwnAddressType.PUBLIC
    )

    cid_ids = [2, 3]
    cis_handles = await devices[1].setup_cig(
        cig_id=1,
        cis_id=cid_ids,
        sdu_interval=(10000, 0),
        framing=0,
        max_sdu=(120, 0),
        retransmission_number=13,
        max_transport_latency=(100, 0),
    )

    def on_cis_request(
        connection: Connection, cis_handle: int, _cig_id: int, _cis_id: int
    ):
        connection.abort_on('disconnection', devices[0].accept_cis_request(cis_handle))

    devices[0].on('cis_request', on_cis_request)

    cis_links = await devices[1].create_cis(
        [(cis, connection.handle) for cis in cis_handles]
    )

    for cis_link in cis_links:
        await cis_link.disconnect()

    await asyncio.gather(
        *[hci_transport.source.terminated for hci_transport in hci_transports]
    )


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
