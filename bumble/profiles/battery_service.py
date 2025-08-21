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
from typing import Optional

from bumble.gatt import (
    GATT_BATTERY_LEVEL_CHARACTERISTIC,
    GATT_BATTERY_SERVICE,
    Characteristic,
    CharacteristicValue,
    TemplateService,
)
from bumble.gatt_adapters import (
    PackedCharacteristicAdapter,
    PackedCharacteristicProxyAdapter,
)
from bumble.gatt_client import CharacteristicProxy, ProfileServiceProxy


# -----------------------------------------------------------------------------
class BatteryService(TemplateService):
    UUID = GATT_BATTERY_SERVICE
    BATTERY_LEVEL_FORMAT = 'B'

    battery_level_characteristic: Characteristic[int]

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

    battery_level: Optional[CharacteristicProxy[int]]

    def __init__(self, service_proxy):
        self.service_proxy = service_proxy

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_BATTERY_LEVEL_CHARACTERISTIC
        ):
            self.battery_level = PackedCharacteristicProxyAdapter(
                characteristics[0], pack_format=BatteryService.BATTERY_LEVEL_FORMAT
            )
        else:
            self.battery_level = None
