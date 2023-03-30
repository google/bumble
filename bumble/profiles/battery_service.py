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
from ..gatt_client import ProfileServiceProxy
from ..gatt import (
    GATT_BATTERY_SERVICE,
    GATT_BATTERY_LEVEL_CHARACTERISTIC,
    TemplateService,
    Characteristic,
    CharacteristicValue,
    PackedCharacteristicAdapter,
)


# -----------------------------------------------------------------------------
class BatteryService(TemplateService):
    UUID = GATT_BATTERY_SERVICE
    BATTERY_LEVEL_FORMAT = 'B'

    def __init__(self, read_battery_level):
        self.battery_level_characteristic = PackedCharacteristicAdapter(
            Characteristic(
                GATT_BATTERY_LEVEL_CHARACTERISTIC,
                Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
                Characteristic.READABLE,
                CharacteristicValue(read=read_battery_level),
            ),
            pack_format=BatteryService.BATTERY_LEVEL_FORMAT,
        )
        super().__init__([self.battery_level_characteristic])


# -----------------------------------------------------------------------------
class BatteryServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = BatteryService

    def __init__(self, service_proxy):
        self.service_proxy = service_proxy

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_BATTERY_LEVEL_CHARACTERISTIC
        ):
            self.battery_level = PackedCharacteristicAdapter(
                characteristics[0], pack_format=BatteryService.BATTERY_LEVEL_FORMAT
            )
        else:
            self.battery_level = None
