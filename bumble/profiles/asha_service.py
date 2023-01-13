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
import struct
import logging
from typing import List
from ..core import AdvertisingData
from ..gatt import (
    GATT_ASHA_SERVICE,
    GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
    GATT_ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
    GATT_ASHA_AUDIO_STATUS_CHARACTERISTIC,
    GATT_ASHA_VOLUME_CHARACTERISTIC,
    GATT_ASHA_LE_PSM_OUT_CHARACTERISTIC,
    TemplateService,
    Characteristic,
    CharacteristicValue,
)
from ..device import Device

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class AshaService(TemplateService):
    UUID = GATT_ASHA_SERVICE
    OPCODE_START = 1
    OPCODE_STOP = 2
    OPCODE_STATUS = 3
    PROTOCOL_VERSION = 0x01
    RESERVED_FOR_FUTURE_USE = [00, 00]
    FEATURE_MAP = [0x01]  # [LE CoC audio output streaming supported]
    SUPPORTED_CODEC_ID = [0x02, 0x01]  # Codec IDs [G.722 at 16 kHz]
    RENDER_DELAY = [00, 00]

    def __init__(self, capability: int, hisyncid: List[int], device: Device, psm=0):
        self.hisyncid = hisyncid
        self.capability = capability  # Device Capabilities [Left, Monaural]
        self.device = device
        self.emitted_data_name = 'ASHA_data_' + str(self.capability)
        self.audio_out_data = b''
        self.psm = psm  # a non-zero psm is mainly for testing purpose

        # Handler for volume control
        def on_volume_write(_connection, value):
            logger.info(f'--- VOLUME Write:{value[0]}')

        # Handler for audio control commands
        def on_audio_control_point_write(_connection, value):
            logger.info(f'--- AUDIO CONTROL POINT Write:{value.hex()}')
            opcode = value[0]
            if opcode == AshaService.OPCODE_START:
                # Start
                audio_type = ('Unknown', 'Ringtone', 'Phone Call', 'Media')[value[2]]
                logger.info(
                    f'### START: codec={value[1]}, '
                    f'audio_type={audio_type}, '
                    f'volume={value[3]}, '
                    f'otherstate={value[4]}'
                )
            elif opcode == AshaService.OPCODE_STOP:
                logger.info('### STOP')
            elif opcode == AshaService.OPCODE_STATUS:
                logger.info(f'### STATUS: connected={value[1]}')

            # TODO Respond with a status
            # asyncio.create_task(device.notify_subscribers(audio_status_characteristic,
            # force=True))

        self.read_only_properties_characteristic = Characteristic(
            GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
            Characteristic.READ,
            Characteristic.READABLE,
            bytes(
                [
                    AshaService.PROTOCOL_VERSION,  # Version
                    self.capability,
                ]
            )
            + bytes(self.hisyncid)
            + bytes(AshaService.FEATURE_MAP)
            + bytes(AshaService.RENDER_DELAY)
            + bytes(AshaService.RESERVED_FOR_FUTURE_USE)
            + bytes(AshaService.SUPPORTED_CODEC_ID),
        )

        self.audio_control_point_characteristic = Characteristic(
            GATT_ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
            Characteristic.WRITE | Characteristic.WRITE_WITHOUT_RESPONSE,
            Characteristic.WRITEABLE,
            CharacteristicValue(write=on_audio_control_point_write),
        )
        self.audio_status_characteristic = Characteristic(
            GATT_ASHA_AUDIO_STATUS_CHARACTERISTIC,
            Characteristic.READ | Characteristic.NOTIFY,
            Characteristic.READABLE,
            bytes([0]),
        )
        self.volume_characteristic = Characteristic(
            GATT_ASHA_VOLUME_CHARACTERISTIC,
            Characteristic.WRITE_WITHOUT_RESPONSE,
            Characteristic.WRITEABLE,
            CharacteristicValue(write=on_volume_write),
        )

        # Register an L2CAP CoC server
        def on_coc(channel):
            def on_data(data):
                logging.debug(f'<<< data received:{data}')

                self.emit(self.emitted_data_name, data)
                self.audio_out_data += data

            channel.sink = on_data

        # let the server find a free PSM
        self.psm = self.device.register_l2cap_channel_server(self.psm, on_coc, 8)
        self.le_psm_out_characteristic = Characteristic(
            GATT_ASHA_LE_PSM_OUT_CHARACTERISTIC,
            Characteristic.READ,
            Characteristic.READABLE,
            struct.pack('<H', self.psm),
        )

        characteristics = [
            self.read_only_properties_characteristic,
            self.audio_control_point_characteristic,
            self.audio_status_characteristic,
            self.volume_characteristic,
            self.le_psm_out_characteristic,
        ]

        super().__init__(characteristics)

    def get_advertising_data(self):
        # Advertisement only uses 4 least significant bytes of the HiSyncId.
        return bytes(
            AdvertisingData(
                [
                    (
                        AdvertisingData.SERVICE_DATA_16_BIT_UUID,
                        bytes(GATT_ASHA_SERVICE)
                        + bytes(
                            [
                                AshaService.PROTOCOL_VERSION,
                                self.capability,
                            ]
                        )
                        + bytes(self.hisyncid[:4]),
                    ),
                ]
            )
        )
