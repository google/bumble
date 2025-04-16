# Copyright 2021-2025 Google LLC
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

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from bumble import att
from bumble import gatt
from bumble import gatt_client
from bumble import crypto

if TYPE_CHECKING:
    from bumble import device


# -----------------------------------------------------------------------------
class GenericAttributeProfileService(gatt.TemplateService):
    '''See Vol 3, Part G - 7 - DEFINED GENERIC ATTRIBUTE PROFILE SERVICE.'''

    UUID = gatt.GATT_GENERIC_ATTRIBUTE_SERVICE

    client_supported_features_characteristic: gatt.Characteristic[bytes] | None = None
    server_supported_features_characteristic: gatt.Characteristic[bytes] | None = None
    database_hash_characteristic: gatt.Characteristic[bytes] | None = None
    service_changed_characteristic: gatt.Characteristic[bytes] | None = None

    def __init__(
        self,
        server_supported_features: gatt.ServerSupportedFeatures | None = None,
        database_hash_enabled: bool = True,
        service_change_enabled: bool = True,
    ) -> None:

        if server_supported_features is not None:
            self.server_supported_features_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SERVER_SUPPORTED_FEATURES_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=bytes([server_supported_features]),
            )

        if database_hash_enabled:
            self.database_hash_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_DATABASE_HASH_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READABLE,
                value=gatt.CharacteristicValue(read=self.get_database_hash),
            )

        if service_change_enabled:
            self.service_changed_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_SERVICE_CHANGED_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.INDICATE,
                permissions=gatt.Characteristic.Permissions(0),
                value=b'',
            )

        if (database_hash_enabled and service_change_enabled) or (
            server_supported_features
            and (
                server_supported_features & gatt.ServerSupportedFeatures.EATT_SUPPORTED
            )
        ):  # TODO: Support Multiple Handle Value Notifications
            self.client_supported_features_characteristic = gatt.Characteristic(
                uuid=gatt.GATT_CLIENT_SUPPORTED_FEATURES_CHARACTERISTIC,
                properties=(
                    gatt.Characteristic.Properties.READ
                    | gatt.Characteristic.Properties.WRITE
                ),
                permissions=(
                    gatt.Characteristic.Permissions.READABLE
                    | gatt.Characteristic.Permissions.WRITEABLE
                ),
                value=bytes(1),
            )

        super().__init__(
            characteristics=[
                c
                for c in (
                    self.service_changed_characteristic,
                    self.client_supported_features_characteristic,
                    self.database_hash_characteristic,
                    self.server_supported_features_characteristic,
                )
                if c is not None
            ],
            primary=True,
        )

    @classmethod
    def get_attribute_data(cls, attribute: att.Attribute) -> bytes:
        if attribute.type in (
            gatt.GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE,
            gatt.GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE,
            gatt.GATT_INCLUDE_ATTRIBUTE_TYPE,
            gatt.GATT_CHARACTERISTIC_ATTRIBUTE_TYPE,
            gatt.GATT_CHARACTERISTIC_EXTENDED_PROPERTIES_DESCRIPTOR,
        ):
            assert isinstance(attribute.value, bytes)
            return (
                struct.pack("<H", attribute.handle)
                + attribute.type.to_bytes()
                + attribute.value
            )
        elif attribute.type in (
            gatt.GATT_CHARACTERISTIC_USER_DESCRIPTION_DESCRIPTOR,
            gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
            gatt.GATT_SERVER_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
            gatt.GATT_CHARACTERISTIC_PRESENTATION_FORMAT_DESCRIPTOR,
            gatt.GATT_CHARACTERISTIC_AGGREGATE_FORMAT_DESCRIPTOR,
        ):
            return struct.pack("<H", attribute.handle) + attribute.type.to_bytes()

        return b''

    def get_database_hash(self, connection: device.Connection | None) -> bytes:
        assert connection

        m = b''.join(
            [
                self.get_attribute_data(attribute)
                for attribute in connection.device.gatt_server.attributes
            ]
        )

        return crypto.aes_cmac(m=m, k=bytes(16))


class GenericAttributeProfileServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = GenericAttributeProfileService

    client_supported_features_characteristic: (
        gatt_client.CharacteristicProxy[bytes] | None
    ) = None
    server_supported_features_characteristic: (
        gatt_client.CharacteristicProxy[bytes] | None
    ) = None
    database_hash_characteristic: gatt_client.CharacteristicProxy[bytes] | None = None
    service_changed_characteristic: gatt_client.CharacteristicProxy[bytes] | None = None

    _CHARACTERISTICS = {
        gatt.GATT_CLIENT_SUPPORTED_FEATURES_CHARACTERISTIC: 'client_supported_features_characteristic',
        gatt.GATT_SERVER_SUPPORTED_FEATURES_CHARACTERISTIC: 'server_supported_features_characteristic',
        gatt.GATT_DATABASE_HASH_CHARACTERISTIC: 'database_hash_characteristic',
        gatt.GATT_SERVICE_CHANGED_CHARACTERISTIC: 'service_changed_characteristic',
    }

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        for uuid, attribute_name in self._CHARACTERISTICS.items():
            if characteristics := self.service_proxy.get_characteristics_by_uuid(uuid):
                setattr(self, attribute_name, characteristics[0])
