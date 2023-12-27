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

from bumble import core
from bumble import crypto
from bumble import device
from bumble import gatt
from bumble import gatt_client


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
class SirkType(enum.IntEnum):
    '''Coordinated Set Identification Service - 5.1 Set Identity Resolving Key.'''

    ENCRYPTED = 0x00
    PLAINTEXT = 0x01


class MemberLock(enum.IntEnum):
    '''Coordinated Set Identification Service - 5.3 Set Member Lock.'''

    UNLOCKED = 0x01
    LOCKED = 0x02


# -----------------------------------------------------------------------------
# Crypto Toolbox
# -----------------------------------------------------------------------------
def s1(m: bytes) -> bytes:
    '''
    Coordinated Set Identification Service - 4.3 s1 SALT generation function.
    '''
    return crypto.aes_cmac(m[::-1], bytes(16))[::-1]


def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    '''
    Coordinated Set Identification Service - 4.4 k1 derivation function.
    '''
    t = crypto.aes_cmac(n[::-1], salt[::-1])
    return crypto.aes_cmac(p[::-1], t)[::-1]


def sef(k: bytes, r: bytes) -> bytes:
    '''
    Coordinated Set Identification Service - 4.5 SIRK encryption function sef.
    '''
    return crypto.xor(k1(k, s1(b'SIRKenc'[::-1]), b'csis'[::-1]), r)


def sih(k: bytes, r: bytes) -> bytes:
    '''
    Coordinated Set Identification Service - 4.7 Resolvable Set Identifier hash function sih.
    '''
    return crypto.e(k, r + bytes(13))[:3]


def generate_rsi(sirk: bytes) -> bytes:
    '''
    Coordinated Set Identification Service - 4.8 Resolvable Set Identifier generation operation.
    '''
    prand = crypto.generate_prand()
    return sih(sirk, prand) + prand


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class CoordinatedSetIdentificationService(gatt.TemplateService):
    UUID = gatt.GATT_COORDINATED_SET_IDENTIFICATION_SERVICE

    set_identity_resolving_key: bytes
    set_identity_resolving_key_characteristic: gatt.Characteristic
    coordinated_set_size_characteristic: Optional[gatt.Characteristic] = None
    set_member_lock_characteristic: Optional[gatt.Characteristic] = None
    set_member_rank_characteristic: Optional[gatt.Characteristic] = None

    def __init__(
        self,
        set_identity_resolving_key: bytes,
        set_identity_resolving_key_type: SirkType,
        coordinated_set_size: Optional[int] = None,
        set_member_lock: Optional[MemberLock] = None,
        set_member_rank: Optional[int] = None,
    ) -> None:
        characteristics = []

        self.set_identity_resolving_key = set_identity_resolving_key
        self.set_identity_resolving_key_type = set_identity_resolving_key_type
        self.set_identity_resolving_key_characteristic = gatt.Characteristic(
            uuid=gatt.GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC,
            properties=gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.NOTIFY,
            permissions=gatt.Characteristic.Permissions.READABLE,
            value=gatt.CharacteristicValue(read=self.on_sirk_read),
        )
        characteristics.append(self.set_identity_resolving_key_characteristic)

        if coordinated_set_size is not None:
            self.coordinated_set_size_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_COORDINATED_SET_SIZE_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('B', coordinated_set_size),
            )
            characteristics.append(self.coordinated_set_size_characteristic)

        if set_member_lock is not None:
            self.set_member_lock_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SET_MEMBER_LOCK_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY
                | gatt.Characteristic.Properties.WRITE,
                permissions=gatt.Characteristic.Permissions.READABLE
                | gatt.Characteristic.Permissions.WRITEABLE,
                value=struct.pack('B', set_member_lock),
            )
            characteristics.append(self.set_member_lock_characteristic)

        if set_member_rank is not None:
            self.set_member_rank_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SET_MEMBER_RANK_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=struct.pack('B', set_member_rank),
            )
            characteristics.append(self.set_member_rank_characteristic)

        super().__init__(characteristics)

    def on_sirk_read(self, _connection: Optional[device.Connection]) -> bytes:
        if self.set_identity_resolving_key_type == SirkType.PLAINTEXT:
            return bytes([SirkType.PLAINTEXT]) + self.set_identity_resolving_key
        else:
            raise NotImplementedError('TODO: Pending async Characteristic read.')

    def get_advertising_data(self) -> bytes:
        return bytes(
            core.AdvertisingData(
                [
                    (
                        core.AdvertisingData.RESOLVABLE_SET_IDENTIFIER,
                        generate_rsi(self.set_identity_resolving_key),
                    ),
                ]
            )
        )


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class CoordinatedSetIdentificationProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = CoordinatedSetIdentificationService

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
