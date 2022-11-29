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
from ..device import (
  Device, AdvertisingType
)
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
  PackedCharacteristicAdapter
)


# -----------------------------------------------------------------------------
class AshaService(TemplateService):
  UUID = GATT_ASHA_SERVICE

  def __init__(self,device:Device):
    self.device=device

    # Handler for volume control
    def on_volume_write(connection, value):
      print('--- VOLUME Write:', value[0])

    # Handler for audio control commands
    def on_audio_control_point_write(connection, value):
      print('--- AUDIO CONTROL POINT Write:', value.hex())
      opcode = value[0]
      if opcode == 1:
        # Start
        audio_type = ('Unknown', 'Ringtone', 'Phone Call', 'Media')[value[2]]
        print(
            f'### START: codec={value[1]}, audio_type={audio_type}, volume={value[3]}, otherstate={value[4]}')
      elif opcode == 2:
        print('### STOP')
      elif opcode == 3:
        print(f'### STATUS: connected={value[1]}')

      # TODO Respond with a status
      # asyncio.create_task(device.notify_subscribers(audio_status_characteristic, force=True))

    self.read_only_properties_characteristic = Characteristic(
        GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
        Characteristic.READ,
        Characteristic.READABLE,
        bytes([
            0x01,  # Version
            0x00,  # Device Capabilities [Left, Monaural]
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  # HiSyncId
            0x01,  # Feature Map [LE CoC audio output streaming supported]
            0x00, 0x00,  # Render Delay
            0x00, 0x00,  # RFU
            0x02, 0x00  # Codec IDs [G.722 at 16 kHz]
        ])
    )

    self.audio_control_point_characteristic = Characteristic(
        GATT_ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
        Characteristic.WRITE | Characteristic.WRITE_WITHOUT_RESPONSE,
        Characteristic.WRITEABLE,
        CharacteristicValue(write=on_audio_control_point_write)
    )
    self.audio_status_characteristic = Characteristic(
        GATT_ASHA_AUDIO_STATUS_CHARACTERISTIC,
        Characteristic.READ | Characteristic.NOTIFY,
        Characteristic.READABLE,
        bytes([0])
    )
    self.volume_characteristic = Characteristic(
        GATT_ASHA_VOLUME_CHARACTERISTIC,
        Characteristic.WRITE_WITHOUT_RESPONSE,
        Characteristic.WRITEABLE,
        CharacteristicValue(write=on_volume_write)
    )

    # TODO add real psm value
    self.psm=0x0080
    # self.psm = device.register_l2cap_channel_server(0, on_coc, 8)
    self.le_psm_out_characteristic = Characteristic(
        GATT_ASHA_LE_PSM_OUT_CHARACTERISTIC,
        Characteristic.READ,
        Characteristic.READABLE,
        struct.pack('<H', self.psm)
    )

    characteristics = [self.read_only_properties_characteristic,
                       self.audio_control_point_characteristic,
                       self.audio_status_characteristic,
                       self.volume_characteristic,
                       self.le_psm_out_characteristic]

    super().__init__(characteristics)

  async def start_advertising(self, capability: int,
      truncated_hisyncid: []):
    assert self.device
    self.device.advertising_data = bytes(
        AdvertisingData([
            (AdvertisingData.COMPLETE_LOCAL_NAME, bytes(self.device.name, 'utf-8')),
            (AdvertisingData.FLAGS, bytes([0x06])),
            (AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, bytes(GATT_ASHA_SERVICE)),
            (AdvertisingData.SERVICE_DATA_16_BIT_UUID, bytes(GATT_ASHA_SERVICE) + bytes([
                0x01,  # Protocol Version
                capability,  # Capability
            ]) + bytes(truncated_hisyncid))
        ])
    )

    # TODO enable more advertising_type and own_address_type
    advertising_type = AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE

    await self.device.start_advertising(
        advertising_type=advertising_type
    )
