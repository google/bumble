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

"""Generic Access Profile"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import logging
import struct
from typing import Optional, Tuple, Union

from bumble.core import Appearance
from bumble.gatt import (
    TemplateService,
    Characteristic,
    GATT_GENERIC_ACCESS_SERVICE,
    GATT_DEVICE_NAME_CHARACTERISTIC,
    GATT_APPEARANCE_CHARACTERISTIC,
)
from bumble.gatt_adapters import (
    DelegatedCharacteristicProxyAdapter,
    UTF8CharacteristicProxyAdapter,
)
from bumble.gatt_client import CharacteristicProxy, ProfileServiceProxy, ServiceProxy

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
class GenericAccessService(TemplateService):
    UUID = GATT_GENERIC_ACCESS_SERVICE

    device_name_characteristic: Characteristic[bytes]
    appearance_characteristic: Characteristic[bytes]

    def __init__(
        self, device_name: str, appearance: Union[Appearance, Tuple[int, int], int] = 0
    ):
        if isinstance(appearance, int):
            appearance_int = appearance
        elif isinstance(appearance, tuple):
            appearance_int = (appearance[0] << 6) | appearance[1]
        elif isinstance(appearance, Appearance):
            appearance_int = int(appearance)
        else:
            raise TypeError()

        self.device_name_characteristic = Characteristic(
            GATT_DEVICE_NAME_CHARACTERISTIC,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            device_name.encode('utf-8')[:248],
        )

        self.appearance_characteristic = Characteristic(
            GATT_APPEARANCE_CHARACTERISTIC,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            struct.pack('<H', appearance_int),
        )

        super().__init__(
            [self.device_name_characteristic, self.appearance_characteristic]
        )


# -----------------------------------------------------------------------------
class GenericAccessServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = GenericAccessService

    device_name: Optional[CharacteristicProxy[str]]
    appearance: Optional[CharacteristicProxy[Appearance]]

    def __init__(self, service_proxy: ServiceProxy):
        self.service_proxy = service_proxy

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_DEVICE_NAME_CHARACTERISTIC
        ):
            self.device_name = UTF8CharacteristicProxyAdapter(characteristics[0])
        else:
            self.device_name = None

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_APPEARANCE_CHARACTERISTIC
        ):
            self.appearance = DelegatedCharacteristicProxyAdapter(
                characteristics[0],
                decode=lambda value: Appearance.from_int(
                    struct.unpack_from('<H', value, 0)[0],
                ),
            )
        else:
            self.appearance = None
