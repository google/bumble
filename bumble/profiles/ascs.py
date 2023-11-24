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
from typing import Optional, List

from bumble import device
from bumble import gatt
from bumble import gatt_client

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------


class MemberLock(enum.IntEnum):
    # fmt: off
    UNLOCKED = 0x01
    LOCKED   = 0x02


class AseState(enum.IntEnum):
    # fmt: off
    IDLE              = 0x00
    CODEC_CONFIGURED  = 0x01
    QOS_CONFIGURED    = 0x02
    ENABLING          = 0x03
    STREAMING         = 0x04
    DISABLING         = 0x05
    RELEASING         = 0x06


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class AudioStreamEndpoint:
    state = AseState.IDLE

    def __init__(self, id: int, characteristic: gatt.Characteristic) -> None:
        self.id = id
        self.characteristic = characteristic
        self.characteristic.value = gatt.CharacteristicValue(read=self.on_read)

    def on_read(self, connection: device.Connection) -> bytes:
        return struct.pack('BB', self.id, self.state)


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class Service(gatt.TemplateService):
    UUID = gatt.GATT_COORDINATED_SET_IDENTIFICATION_SERVICE

    sink_ase: List[AudioStreamEndpoint] = []
    source_ase: List[AudioStreamEndpoint] = []

    def __init__(self, num_sink_ase: int = 0, num_source_ase: int = 0) -> None:
        characteristics = []

        for i in range(1, num_sink_ase + 1):
            characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SINK_ASE_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY,
                permissions=gatt.Characteristic.Permissions.READABLE,
            )
            self.sink_ase.append(
                AudioStreamEndpoint(
                    id=i,
                    characteristic=characteristic,
                )
            )
            characteristics.append(characteristic)

        for i in range(1, num_source_ase + 1):
            characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SOURCE_ASE_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ
                | gatt.Characteristic.Properties.NOTIFY,
                permissions=gatt.Characteristic.Permissions.READABLE,
            )
            self.source_ase.append(
                AudioStreamEndpoint(
                    id=i,
                    characteristic=characteristic,
                )
            )
            characteristics.append(characteristic)
        characteristics.append(
            gatt.Characteristic(
                uuid=gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.WRITE
                | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
                | gatt.Characteristic.Properties.NOTIFY,
                permissions=gatt.Characteristic.Permissions.READABLE
                | gatt.Characteristic.Permissions.WRITEABLE,
                value=gatt.CharacteristicValue(write=self.on_ase_control_point),
            )
        )

        super().__init__(characteristics)

    def on_ase_control_point(self, connection: device.Connection, data: bytes) -> None:
        pass


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class ServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = Service

    sirk: gatt_client.CharacteristicProxy
    set_size: Optional[gatt_client.CharacteristicProxy] = None
    lock: Optional[gatt_client.CharacteristicProxy] = None
    rank: Optional[gatt_client.CharacteristicProxy] = None

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.sirk = service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC
        )[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_COORDINATED_SET_SIZE_CHARACTERISTIC
        ):
            self.set_size = characteristics[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SET_MEMBER_LOCK_CHARACTERISTIC
        ):
            self.lock = characteristics[0]

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_SET_MEMBER_RANK_CHARACTERISTIC
        ):
            self.rank = characteristics[0]
