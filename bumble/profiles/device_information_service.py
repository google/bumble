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
from typing import Optional, Tuple

from ..gatt_client import ProfileServiceProxy
from ..gatt import (
    GATT_DEVICE_INFORMATION_SERVICE,
    GATT_FIRMWARE_REVISION_STRING_CHARACTERISTIC,
    GATT_HARDWARE_REVISION_STRING_CHARACTERISTIC,
    GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
    GATT_MODEL_NUMBER_STRING_CHARACTERISTIC,
    GATT_SERIAL_NUMBER_STRING_CHARACTERISTIC,
    GATT_SOFTWARE_REVISION_STRING_CHARACTERISTIC,
    GATT_SYSTEM_ID_CHARACTERISTIC,
    GATT_REGULATORY_CERTIFICATION_DATA_LIST_CHARACTERISTIC,
    TemplateService,
    Characteristic,
    DelegatedCharacteristicAdapter,
    UTF8CharacteristicAdapter,
)


# -----------------------------------------------------------------------------
class DeviceInformationService(TemplateService):
    UUID = GATT_DEVICE_INFORMATION_SERVICE

    @staticmethod
    def pack_system_id(oui, manufacturer_id):
        return struct.pack('<Q', oui << 40 | manufacturer_id)

    @staticmethod
    def unpack_system_id(buffer):
        system_id = struct.unpack('<Q', buffer)[0]
        return (system_id >> 40, system_id & 0xFFFFFFFFFF)

    def __init__(
        self,
        manufacturer_name: Optional[str] = None,
        model_number: Optional[str] = None,
        serial_number: Optional[str] = None,
        hardware_revision: Optional[str] = None,
        firmware_revision: Optional[str] = None,
        software_revision: Optional[str] = None,
        system_id: Optional[Tuple[int, int]] = None,  # (OUI, Manufacturer ID)
        ieee_regulatory_certification_data_list: Optional[bytes] = None
        # TODO: pnp_id
    ):
        characteristics = [
            Characteristic(
                uuid, Characteristic.Properties.READ, Characteristic.READABLE, field
            )
            for (field, uuid) in (
                (manufacturer_name, GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC),
                (model_number, GATT_MODEL_NUMBER_STRING_CHARACTERISTIC),
                (serial_number, GATT_SERIAL_NUMBER_STRING_CHARACTERISTIC),
                (hardware_revision, GATT_HARDWARE_REVISION_STRING_CHARACTERISTIC),
                (firmware_revision, GATT_FIRMWARE_REVISION_STRING_CHARACTERISTIC),
                (software_revision, GATT_SOFTWARE_REVISION_STRING_CHARACTERISTIC),
            )
            if field is not None
        ]

        if system_id is not None:
            characteristics.append(
                Characteristic(
                    GATT_SYSTEM_ID_CHARACTERISTIC,
                    Characteristic.Properties.READ,
                    Characteristic.READABLE,
                    self.pack_system_id(*system_id),
                )
            )

        if ieee_regulatory_certification_data_list is not None:
            characteristics.append(
                Characteristic(
                    GATT_REGULATORY_CERTIFICATION_DATA_LIST_CHARACTERISTIC,
                    Characteristic.Properties.READ,
                    Characteristic.READABLE,
                    ieee_regulatory_certification_data_list,
                )
            )

        super().__init__(characteristics)


# -----------------------------------------------------------------------------
class DeviceInformationServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = DeviceInformationService

    def __init__(self, service_proxy):
        self.service_proxy = service_proxy

        for (field, uuid) in (
            ('manufacturer_name', GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC),
            ('model_number', GATT_MODEL_NUMBER_STRING_CHARACTERISTIC),
            ('serial_number', GATT_SERIAL_NUMBER_STRING_CHARACTERISTIC),
            ('hardware_revision', GATT_HARDWARE_REVISION_STRING_CHARACTERISTIC),
            ('firmware_revision', GATT_FIRMWARE_REVISION_STRING_CHARACTERISTIC),
            ('software_revision', GATT_SOFTWARE_REVISION_STRING_CHARACTERISTIC),
        ):
            if characteristics := service_proxy.get_characteristics_by_uuid(uuid):
                characteristic = UTF8CharacteristicAdapter(characteristics[0])
            else:
                characteristic = None
            self.__setattr__(field, characteristic)

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_SYSTEM_ID_CHARACTERISTIC
        ):
            self.system_id = DelegatedCharacteristicAdapter(
                characteristics[0],
                encode=lambda v: DeviceInformationService.pack_system_id(*v),
                decode=DeviceInformationService.unpack_system_id,
            )
        else:
            self.system_id = None

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_REGULATORY_CERTIFICATION_DATA_LIST_CHARACTERISTIC
        ):
            self.ieee_regulatory_certification_data_list = characteristics[0]
        else:
            self.ieee_regulatory_certification_data_list = None
