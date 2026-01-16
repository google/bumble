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
from collections.abc import Callable

from bumble import device, gatt, gatt_adapters, gatt_client


# -----------------------------------------------------------------------------
class BatteryService(gatt.TemplateService):
    UUID = gatt.GATT_BATTERY_SERVICE
    BATTERY_LEVEL_FORMAT = 'B'

    battery_level_characteristic: gatt.Characteristic[int]

    def __init__(self, read_battery_level: Callable[[device.Connection], int]) -> None:
        self.battery_level_characteristic = gatt_adapters.PackedCharacteristicAdapter(
            gatt.Characteristic(
                gatt.GATT_BATTERY_LEVEL_CHARACTERISTIC,
                properties=(
                    gatt.Characteristic.Properties.READ
                    | gatt.Characteristic.Properties.NOTIFY
                ),
                permissions=gatt.Characteristic.READABLE,
                value=gatt.CharacteristicValue(read=read_battery_level),
            ),
            pack_format=BatteryService.BATTERY_LEVEL_FORMAT,
        )
        super().__init__([self.battery_level_characteristic])


# -----------------------------------------------------------------------------
class BatteryServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = BatteryService

    battery_level: gatt_client.CharacteristicProxy[int]

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.battery_level = gatt_adapters.PackedCharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                gatt.GATT_BATTERY_LEVEL_CHARACTERISTIC
            ),
            pack_format=BatteryService.BATTERY_LEVEL_FORMAT,
        )
