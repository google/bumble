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
import logging
import struct

from .gatt import (
    Service,
    Characteristic,
    GATT_GENERIC_ACCESS_SERVICE,
    GATT_DEVICE_NAME_CHARACTERISTIC,
    GATT_APPEARANCE_CHARACTERISTIC,
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
class GenericAccessService(Service):
    def __init__(self, device_name, appearance=(0, 0)):
        device_name_characteristic = Characteristic(
            GATT_DEVICE_NAME_CHARACTERISTIC,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            device_name.encode('utf-8')[:248],
        )

        appearance_characteristic = Characteristic(
            GATT_APPEARANCE_CHARACTERISTIC,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            struct.pack('<H', (appearance[0] << 6) | appearance[1]),
        )

        super().__init__(
            GATT_GENERIC_ACCESS_SERVICE,
            [device_name_characteristic, appearance_characteristic],
        )
