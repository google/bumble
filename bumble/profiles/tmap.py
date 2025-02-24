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

"""LE Audio - Telephony and Media Audio Profile"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import enum
import logging
import struct

from bumble.gatt import (
    TemplateService,
    Characteristic,
    GATT_TELEPHONY_AND_MEDIA_AUDIO_SERVICE,
    GATT_TMAP_ROLE_CHARACTERISTIC,
)
from bumble.gatt_adapters import DelegatedCharacteristicProxyAdapter
from bumble.gatt_client import CharacteristicProxy, ProfileServiceProxy, ServiceProxy


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class Role(enum.IntFlag):
    CALL_GATEWAY = 1 << 0
    CALL_TERMINAL = 1 << 1
    UNICAST_MEDIA_SENDER = 1 << 2
    UNICAST_MEDIA_RECEIVER = 1 << 3
    BROADCAST_MEDIA_SENDER = 1 << 4
    BROADCAST_MEDIA_RECEIVER = 1 << 5


# -----------------------------------------------------------------------------
class TelephonyAndMediaAudioService(TemplateService):
    UUID = GATT_TELEPHONY_AND_MEDIA_AUDIO_SERVICE

    role_characteristic: Characteristic[bytes]

    def __init__(self, role: Role):
        self.role_characteristic = Characteristic(
            GATT_TMAP_ROLE_CHARACTERISTIC,
            Characteristic.Properties.READ,
            Characteristic.READABLE,
            struct.pack('<H', int(role)),
        )

        super().__init__([self.role_characteristic])


# -----------------------------------------------------------------------------
class TelephonyAndMediaAudioServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = TelephonyAndMediaAudioService

    role: CharacteristicProxy[Role]

    def __init__(self, service_proxy: ServiceProxy):
        self.service_proxy = service_proxy

        self.role = DelegatedCharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                GATT_TMAP_ROLE_CHARACTERISTIC
            ),
            decode=lambda value: Role(
                struct.unpack_from('<H', value, 0)[0],
            ),
        )
