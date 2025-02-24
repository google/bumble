# Copyright 2024 Google LLC
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

"""LE Audio - Gaming Audio Profile"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import struct
from typing import Optional

from bumble.gatt import (
    TemplateService,
    Characteristic,
    GATT_GAMING_AUDIO_SERVICE,
    GATT_GMAP_ROLE_CHARACTERISTIC,
    GATT_UGG_FEATURES_CHARACTERISTIC,
    GATT_UGT_FEATURES_CHARACTERISTIC,
    GATT_BGS_FEATURES_CHARACTERISTIC,
    GATT_BGR_FEATURES_CHARACTERISTIC,
)
from bumble.gatt_adapters import DelegatedCharacteristicProxyAdapter
from bumble.gatt_client import CharacteristicProxy, ProfileServiceProxy, ServiceProxy
from enum import IntFlag


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class GmapRole(IntFlag):
    UNICAST_GAME_GATEWAY = 1 << 0
    UNICAST_GAME_TERMINAL = 1 << 1
    BROADCAST_GAME_SENDER = 1 << 2
    BROADCAST_GAME_RECEIVER = 1 << 3


class UggFeatures(IntFlag):
    UGG_MULTIPLEX = 1 << 0
    UGG_96_KBPS_SOURCE = 1 << 1
    UGG_MULTISINK = 1 << 2


class UgtFeatures(IntFlag):
    UGT_SOURCE = 1 << 0
    UGT_80_KBPS_SOURCE = 1 << 1
    UGT_SINK = 1 << 2
    UGT_64_KBPS_SINK = 1 << 3
    UGT_MULTIPLEX = 1 << 4
    UGT_MULTISINK = 1 << 5
    UGT_MULTISOURCE = 1 << 6


class BgsFeatures(IntFlag):
    BGS_96_KBPS = 1 << 0


class BgrFeatures(IntFlag):
    BGR_MULTISINK = 1 << 0
    BGR_MULTIPLEX = 1 << 1


# -----------------------------------------------------------------------------
# Server
# -----------------------------------------------------------------------------
class GamingAudioService(TemplateService):
    UUID = GATT_GAMING_AUDIO_SERVICE

    gmap_role: Characteristic
    ugg_features: Optional[Characteristic] = None
    ugt_features: Optional[Characteristic] = None
    bgs_features: Optional[Characteristic] = None
    bgr_features: Optional[Characteristic] = None

    def __init__(
        self,
        gmap_role: GmapRole,
        ugg_features: Optional[UggFeatures] = None,
        ugt_features: Optional[UgtFeatures] = None,
        bgs_features: Optional[BgsFeatures] = None,
        bgr_features: Optional[BgrFeatures] = None,
    ) -> None:
        characteristics = []

        ugg_features = UggFeatures(0) if ugg_features is None else ugg_features
        ugt_features = UgtFeatures(0) if ugt_features is None else ugt_features
        bgs_features = BgsFeatures(0) if bgs_features is None else bgs_features
        bgr_features = BgrFeatures(0) if bgr_features is None else bgr_features

        self.gmap_role = Characteristic(
            uuid=GATT_GMAP_ROLE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READABLE,
            value=struct.pack('B', gmap_role),
        )
        characteristics.append(self.gmap_role)

        if gmap_role & GmapRole.UNICAST_GAME_GATEWAY:
            self.ugg_features = Characteristic(
                uuid=GATT_UGG_FEATURES_CHARACTERISTIC,
                properties=Characteristic.Properties.READ,
                permissions=Characteristic.Permissions.READABLE,
                value=struct.pack('B', ugg_features),
            )
            characteristics.append(self.ugg_features)

        if gmap_role & GmapRole.UNICAST_GAME_TERMINAL:
            self.ugt_features = Characteristic(
                uuid=GATT_UGT_FEATURES_CHARACTERISTIC,
                properties=Characteristic.Properties.READ,
                permissions=Characteristic.Permissions.READABLE,
                value=struct.pack('B', ugt_features),
            )
            characteristics.append(self.ugt_features)

        if gmap_role & GmapRole.BROADCAST_GAME_SENDER:
            self.bgs_features = Characteristic(
                uuid=GATT_BGS_FEATURES_CHARACTERISTIC,
                properties=Characteristic.Properties.READ,
                permissions=Characteristic.Permissions.READABLE,
                value=struct.pack('B', bgs_features),
            )
            characteristics.append(self.bgs_features)

        if gmap_role & GmapRole.BROADCAST_GAME_RECEIVER:
            self.bgr_features = Characteristic(
                uuid=GATT_BGR_FEATURES_CHARACTERISTIC,
                properties=Characteristic.Properties.READ,
                permissions=Characteristic.Permissions.READABLE,
                value=struct.pack('B', bgr_features),
            )
            characteristics.append(self.bgr_features)

        super().__init__(characteristics)


# -----------------------------------------------------------------------------
# Client
# -----------------------------------------------------------------------------
class GamingAudioServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = GamingAudioService

    ugg_features: Optional[CharacteristicProxy[UggFeatures]] = None
    ugt_features: Optional[CharacteristicProxy[UgtFeatures]] = None
    bgs_features: Optional[CharacteristicProxy[BgsFeatures]] = None
    bgr_features: Optional[CharacteristicProxy[BgrFeatures]] = None

    def __init__(self, service_proxy: ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.gmap_role = DelegatedCharacteristicProxyAdapter(
            service_proxy.get_required_characteristic_by_uuid(
                GATT_GMAP_ROLE_CHARACTERISTIC
            ),
            decode=lambda value: GmapRole(value[0]),
        )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_UGG_FEATURES_CHARACTERISTIC
        ):
            self.ugg_features = DelegatedCharacteristicProxyAdapter(
                characteristics[0],
                decode=lambda value: UggFeatures(value[0]),
            )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_UGT_FEATURES_CHARACTERISTIC
        ):
            self.ugt_features = DelegatedCharacteristicProxyAdapter(
                characteristics[0],
                decode=lambda value: UgtFeatures(value[0]),
            )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_BGS_FEATURES_CHARACTERISTIC
        ):
            self.bgs_features = DelegatedCharacteristicProxyAdapter(
                characteristics[0],
                decode=lambda value: BgsFeatures(value[0]),
            )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_BGR_FEATURES_CHARACTERISTIC
        ):
            self.bgr_features = DelegatedCharacteristicProxyAdapter(
                characteristics[0],
                decode=lambda value: BgrFeatures(value[0]),
            )
