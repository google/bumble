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
import secrets

from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.hci import (
    Address,
    OwnAddressType,
    HCI_LE_Set_Extended_Advertising_Parameters_Command,
)
from bumble.profiles.cap import CommonAudioServiceService
from bumble.profiles.csip import CoordinatedSetIdentificationService, SirkType

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

    sirk = secrets.token_bytes(16)

    for i, device in enumerate(devices):
        device.random_address = Address(secrets.token_bytes(6))
        await device.power_on()
        csis = CoordinatedSetIdentificationService(
            set_identity_resolving_key=sirk,
            set_identity_resolving_key_type=SirkType.PLAINTEXT,
            coordinated_set_size=2,
        )
        device.add_service(CommonAudioServiceService(csis))
        advertising_data = (
            bytes(
                AdvertisingData(
                    [
                        (
                            AdvertisingData.COMPLETE_LOCAL_NAME,
                            bytes(f'Bumble LE Audio-{i}', 'utf-8'),
                        ),
                        (
                            AdvertisingData.FLAGS,
                            bytes(
                                [
                                    AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG
                                    | AdvertisingData.BR_EDR_HOST_FLAG
                                    | AdvertisingData.BR_EDR_CONTROLLER_FLAG
                                ]
                            ),
                        ),
                        (
                            AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                            bytes(CoordinatedSetIdentificationService.UUID),
                        ),
                    ]
                )
            )
            + csis.get_advertising_data()
        )
        await device.create_advertising_set(advertising_data=advertising_data)

    await asyncio.gather(
        *[hci_transport.source.terminated for hci_transport in hci_transports]
    )


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
