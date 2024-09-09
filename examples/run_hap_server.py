# Copyright 2024 Google LLC
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

from bumble.core import AdvertisingData
from bumble.device import Device
from bumble import att
from bumble.profiles.hap import (
    HearingAccessService,
    HearingAidFeatures,
    HearingAidType,
    PresetSynchronizationSupport,
    IndependentPresets,
    DynamicPresets,
    WritablePresetsSupport,
    PresetRecord,
)

from bumble.transport import open_transport_or_link

server_features = HearingAidFeatures(
    HearingAidType.MONAURAL_HEARING_AID,
    PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_NOT_SUPPORTED,
    IndependentPresets.IDENTICAL_PRESET_RECORD,
    DynamicPresets.PRESET_RECORDS_DOES_NOT_CHANGE,
    WritablePresetsSupport.WRITABLE_PRESET_RECORDS_SUPPORTED,
)

foo_preset = PresetRecord(1, "foo preset")
bar_preset = PresetRecord(50, "bar preset")
foobar_preset = PresetRecord(5, "foobar preset")


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: run_hap_server.py <config-file> <transport-spec-for-device>')
        print('example: run_hap_server.py device1.json pty:hci_pty')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )

        await device.power_on()

        hap = HearingAccessService(
            device, server_features, [foo_preset, bar_preset, foobar_preset]
        )
        device.add_service(hap)

        advertising_data = bytes(
            AdvertisingData(
                [
                    (
                        AdvertisingData.COMPLETE_LOCAL_NAME,
                        bytes('Bumble HearingAccessService', 'utf-8'),
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
                        bytes(HearingAccessService.UUID),
                    ),
                ]
            )
        )

        await device.create_advertising_set(
            advertising_data=advertising_data,
            auto_restart=True,
        )


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
