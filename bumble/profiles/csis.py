# Copyright 2021-2023 Google LLC
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
from __future__ import annotations
import enum
import struct
from typing import Optional

from bumble import gatt
from bumble import gatt_client

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------


class MemberLock(enum.IntEnum):
    UNLOCKED = 0x01
    LOCKED = 0x02


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class Service(gatt.TemplateService):
    UUID = gatt.GATT_COORDINATED_SET_IDENTIFICATION_SERVICE

    def __init__(
        self,
        set_identity_resolving_key: bytes,
        coordinated_set_size: Optional[int] = None,
        set_member_lock: Optional[MemberLock] = None,
        set_member_rank: Optional[int] = None,
    ) -> None:
        characteristics = []

        set_identity_resolving_key_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=set_identity_resolving_key,
        )
        characteristics.append(set_identity_resolving_key_characteristic)

        if coordinated_set_size is not None:
            coordinated_set_size_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('B', coordinated_set_size),
            )
            characteristics.append(coordinated_set_size_characteristic)

        if set_member_lock is not None:
            set_member_lock_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY
                | gatt.Characteristic.Properties.WRITE,
                permissions=gatt.Characteristic.Permissions.READABLE
                | gatt.Characteristic.Permissions.WRITEABLE,
                value=struct.pack('B', set_member_lock),
            )
            characteristics.append(set_member_lock_characteristic)

        if set_member_rank is not None:
            set_member_rank_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('B', set_member_rank),
            )
            characteristics.append(set_member_rank_characteristic)

        super().__init__(characteristics)


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class ServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = Service

    set_identity_resolving_key: gatt_client.CharacteristicProxy
    coordinated_set_size: Optional[gatt_client.CharacteristicProxy] = None
    set_member_lock: Optional[gatt_client.CharacteristicProxy] = None
    set_member_rank: Optional[gatt_client.CharacteristicProxy] = None

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.set_identity_resolving_key = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC
        )[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_COORDINATED_SET_SIZE_CHARACTERISTIC
        ):
            self.coordinated_set_size = characteristics[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SET_MEMBER_LOCK_CHARACTERISTIC
        ):
            self.set_member_lock = characteristics[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SET_MEMBER_RANK_CHARACTERISTIC
        ):
            self.set_member_rank = characteristics[0]
