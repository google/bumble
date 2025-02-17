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

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import pytest

from . import test_utils

from bumble import device
from bumble import gatt
from bumble.profiles import gatt_service


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_database_hash():
    devices = await test_utils.TwoDevices.create_with_connection()
    devices[0].gatt_server.services.clear()
    devices[0].gatt_server.attributes.clear()
    devices[0].gatt_server.attributes_by_handle.clear()
    devices[0].add_service(
        gatt.Service(
            gatt.GATT_GENERIC_ACCESS_SERVICE,
            characteristics=[
                gatt.Characteristic(
                    gatt.GATT_DEVICE_NAME_CHARACTERISTIC,
                    (
                        gatt.Characteristic.Properties.READ
                        | gatt.Characteristic.Properties.WRITE
                    ),
                    gatt.Characteristic.Permissions.READ_REQUIRES_AUTHENTICATION,
                ),
                gatt.Characteristic(
                    gatt.GATT_APPEARANCE_CHARACTERISTIC,
                    gatt.Characteristic.Properties.READ,
                    gatt.Characteristic.Permissions.READ_REQUIRES_AUTHENTICATION,
                ),
            ],
        )
    )
    devices[0].add_service(
        gatt_service.GenericAttributeProfileService(
            server_supported_features=None,
            database_hash_enabled=True,
            service_change_enabled=True,
        )
    )
    devices[0].gatt_server.add_attribute(
        gatt.Service(gatt.GATT_GLUCOSE_SERVICE, characteristics=[])
    )
    # There is a special attribute order in the spec, so we need to add attribute one by
    # one here.
    battery_service = gatt.Service(
        gatt.GATT_BATTERY_SERVICE,
        characteristics=[
            gatt.Characteristic(
                gatt.GATT_BATTERY_LEVEL_CHARACTERISTIC,
                properties=gatt.Characteristic.Properties.READ,
                permissions=gatt.Characteristic.Permissions.READ_REQUIRES_AUTHENTICATION,
            )
        ],
        primary=False,
    )
    battery_service.handle = 0x0014
    battery_service.end_group_handle = 0x0016
    devices[0].gatt_server.add_attribute(
        gatt.IncludedServiceDeclaration(battery_service)
    )
    c = gatt.Characteristic(
        '2A18',
        properties=(
            gatt.Characteristic.Properties.READ
            | gatt.Characteristic.Properties.INDICATE
            | gatt.Characteristic.Properties.EXTENDED_PROPERTIES
        ),
        permissions=gatt.Characteristic.Permissions.READ_REQUIRES_AUTHENTICATION,
    )
    devices[0].gatt_server.add_attribute(
        gatt.CharacteristicDeclaration(c, devices[0].gatt_server.next_handle() + 1)
    )
    devices[0].gatt_server.add_attribute(c)
    devices[0].gatt_server.add_attribute(
        gatt.Descriptor(
            gatt.GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
            gatt.Descriptor.Permissions.READ_REQUIRES_AUTHENTICATION,
            b'\x02\x00',
        ),
    )
    devices[0].gatt_server.add_attribute(
        gatt.Descriptor(
            gatt.GATT_CHARACTERISTIC_EXTENDED_PROPERTIES_DESCRIPTOR,
            gatt.Descriptor.Permissions.READ_REQUIRES_AUTHENTICATION,
            b'\x00\x00',
        ),
    )
    devices[0].add_service(battery_service)

    peer = device.Peer(devices.connections[1])
    client = await peer.discover_service_and_create_proxy(
        gatt_service.GenericAttributeProfileServiceProxy
    )
    assert client.database_hash_characteristic
    assert await client.database_hash_characteristic.read_value() == bytes.fromhex(
        'F1CA2D48ECF58BAC8A8830BBB9FBA990'
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_changed():
    devices = await test_utils.TwoDevices.create_with_connection()
    assert (service := devices[0].gatt_service)

    peer = device.Peer(devices.connections[1])
    assert (
        client := await peer.discover_service_and_create_proxy(
            gatt_service.GenericAttributeProfileServiceProxy
        )
    )
    assert client.service_changed_characteristic
    indications = []
    await client.service_changed_characteristic.subscribe(
        indications.append, prefer_notify=False
    )
    await devices[0].indicate_subscribers(
        service.service_changed_characteristic, b'1234'
    )
    await test_utils.async_barrier()
    assert indications[0] == b'1234'
