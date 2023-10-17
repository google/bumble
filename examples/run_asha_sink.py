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
import struct
import sys
import os
import logging

from bumble import l2cap
from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import UUID
from bumble.gatt import Service, Characteristic, CharacteristicValue


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
ASHA_SERVICE = UUID.from_16_bits(0xFDF0, 'Audio Streaming for Hearing Aid')
ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC = UUID(
    '6333651e-c481-4a3e-9169-7c902aad37bb', 'ReadOnlyProperties'
)
ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC = UUID(
    'f0d4de7e-4a88-476c-9d9f-1937b0996cc0', 'AudioControlPoint'
)
ASHA_AUDIO_STATUS_CHARACTERISTIC = UUID(
    '38663f1a-e711-4cac-b641-326b56404837', 'AudioStatus'
)
ASHA_VOLUME_CHARACTERISTIC = UUID('00e4ca9e-ab14-41e4-8823-f9e70c7e91df', 'Volume')
ASHA_LE_PSM_OUT_CHARACTERISTIC = UUID(
    '2d410339-82b6-42aa-b34e-e2e01df8cc1a', 'LE_PSM_OUT'
)


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 4:
        print(
            'Usage: python run_asha_sink.py <device-config> <transport-spec> '
            '<audio-file>'
        )
        print('example: python run_asha_sink.py device1.json usb:0 audio_out.g722')
        return

    audio_out = open(sys.argv[3], 'wb')

    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)

        # Handler for audio control commands
        def on_audio_control_point_write(_connection, value):
            print('--- AUDIO CONTROL POINT Write:', value.hex())
            opcode = value[0]
            if opcode == 1:
                # Start
                audio_type = ('Unknown', 'Ringtone', 'Phone Call', 'Media')[value[2]]
                print(
                    f'### START: codec={value[1]}, audio_type={audio_type}, '
                    f'volume={value[3]}, otherstate={value[4]}'
                )
            elif opcode == 2:
                print('### STOP')
            elif opcode == 3:
                print(f'### STATUS: connected={value[1]}')

            # Respond with a status
            asyncio.create_task(
                device.notify_subscribers(audio_status_characteristic, force=True)
            )

        # Handler for volume control
        def on_volume_write(_connection, value):
            print('--- VOLUME Write:', value[0])

        # Register an L2CAP CoC server
        def on_coc(channel):
            def on_data(data):
                print('<<< Voice data received:', data.hex())
                audio_out.write(data)

            channel.sink = on_data

        server = device.create_l2cap_server(
            spec=l2cap.LeCreditBasedChannelSpec(max_credits=8), handler=on_coc
        )
        print(f'### LE_PSM_OUT = {server.psm}')

        # Add the ASHA service to the GATT server
        read_only_properties_characteristic = Characteristic(
            ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            bytes(
                [
                    0x01,  # Version
                    0x00,  # Device Capabilities [Left, Monaural]
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                    0x05,
                    0x06,
                    0x07,
                    0x08,  # HiSyncId
                    0x01,  # Feature Map [LE CoC audio output streaming supported]
                    0x00,
                    0x00,  # Render Delay
                    0x00,
                    0x00,  # RFU
                    0x02,
                    0x00,  # Codec IDs [G.722 at 16 kHz]
                ]
            ),
        )
        audio_control_point_characteristic = Characteristic(
            ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
            Characteristic.Properties.WRITE | Characteristic.WRITE_WITHOUT_RESPONSE,
            Characteristic.WRITEABLE,
            CharacteristicValue(write=on_audio_control_point_write),
        )
        audio_status_characteristic = Characteristic(
            ASHA_AUDIO_STATUS_CHARACTERISTIC,
            Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
            Characteristic.READABLE,
            bytes([0]),
        )
        volume_characteristic = Characteristic(
            ASHA_VOLUME_CHARACTERISTIC,
            Characteristic.WRITE_WITHOUT_RESPONSE,
            Characteristic.WRITEABLE,
            CharacteristicValue(write=on_volume_write),
        )
        le_psm_out_characteristic = Characteristic(
            ASHA_LE_PSM_OUT_CHARACTERISTIC,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            struct.pack('<H', server.psm),
        )
        device.add_service(
            Service(
                ASHA_SERVICE,
                [
                    read_only_properties_characteristic,
                    audio_control_point_characteristic,
                    audio_status_characteristic,
                    volume_characteristic,
                    le_psm_out_characteristic,
                ],
            )
        )

        # Set the advertising data
        device.advertising_data = bytes(
            AdvertisingData(
                [
                    (AdvertisingData.COMPLETE_LOCAL_NAME, bytes(device.name, 'utf-8')),
                    (AdvertisingData.FLAGS, bytes([0x06])),
                    (
                        AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                        bytes(ASHA_SERVICE),
                    ),
                    (
                        AdvertisingData.SERVICE_DATA_16_BIT_UUID,
                        bytes(ASHA_SERVICE)
                        + bytes(
                            [
                                0x01,  # Protocol Version
                                0x00,  # Capability
                                0x01,
                                0x02,
                                0x03,
                                0x04,  # Truncated HiSyncID
                            ]
                        ),
                    ),
                ]
            )
        )

        # Go!
        await device.power_on()
        await device.start_advertising(auto_restart=True)

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
