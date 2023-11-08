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
import asyncio
import logging
import os
import pytest

from bumble.core import UUID, BT_L2CAP_PROTOCOL_ID, BT_RFCOMM_PROTOCOL_ID
from bumble.sdp import (
    DataElement,
    ServiceAttribute,
    Client,
    Server,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
)
from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
# pylint: disable=invalid-name
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
def basic_check(x: DataElement) -> None:
    serialized = bytes(x)
    if len(serialized) < 500:
        print('Original:', x)
        print('Serialized:', serialized.hex())
    parsed = DataElement.from_bytes(serialized)
    if len(serialized) < 500:
        print('Parsed:', parsed)
    parsed_bytes = bytes(parsed)
    if len(serialized) < 500:
        print('Parsed Bytes:', parsed_bytes.hex())
    assert parsed_bytes == serialized
    x_str = str(x)
    parsed_str = str(parsed)
    assert x_str == parsed_str


# -----------------------------------------------------------------------------
def test_data_elements() -> None:
    e = DataElement(DataElement.NIL, None)
    basic_check(e)

    e = DataElement(DataElement.UNSIGNED_INTEGER, 12, 1)
    basic_check(e)

    e = DataElement(DataElement.UNSIGNED_INTEGER, 1234, 2)
    basic_check(e)

    e = DataElement(DataElement.UNSIGNED_INTEGER, 0x123456, 4)
    basic_check(e)

    e = DataElement(DataElement.UNSIGNED_INTEGER, 0x123456789, 8)
    basic_check(e)

    e = DataElement(DataElement.UNSIGNED_INTEGER, 0x0000FFFF, value_size=4)
    basic_check(e)

    e = DataElement(DataElement.SIGNED_INTEGER, -12, 1)
    basic_check(e)

    e = DataElement(DataElement.SIGNED_INTEGER, -1234, 2)
    basic_check(e)

    e = DataElement(DataElement.SIGNED_INTEGER, -0x123456, 4)
    basic_check(e)

    e = DataElement(DataElement.SIGNED_INTEGER, -0x123456789, 8)
    basic_check(e)

    e = DataElement(DataElement.SIGNED_INTEGER, 0x0000FFFF, value_size=4)
    basic_check(e)

    e = DataElement(DataElement.UUID, UUID.from_16_bits(1234))
    basic_check(e)

    e = DataElement(DataElement.UUID, UUID.from_32_bits(123456789))
    basic_check(e)

    e = DataElement(DataElement.UUID, UUID('61A3512C-09BE-4DDC-A6A6-0B03667AAFC6'))
    basic_check(e)

    e = DataElement(DataElement.TEXT_STRING, b'hello')
    basic_check(e)

    e = DataElement(DataElement.TEXT_STRING, b'hello' * 60)
    basic_check(e)

    e = DataElement(DataElement.TEXT_STRING, b'hello' * 20000)
    basic_check(e)

    e = DataElement(DataElement.BOOLEAN, True)
    basic_check(e)

    e = DataElement(DataElement.BOOLEAN, False)
    basic_check(e)

    e = DataElement(DataElement.SEQUENCE, [DataElement(DataElement.BOOLEAN, True)])
    basic_check(e)

    e = DataElement(
        DataElement.SEQUENCE,
        [
            DataElement(DataElement.BOOLEAN, True),
            DataElement(DataElement.TEXT_STRING, b'hello'),
        ],
    )
    basic_check(e)

    e = DataElement(DataElement.ALTERNATIVE, [DataElement(DataElement.BOOLEAN, True)])
    basic_check(e)

    e = DataElement(
        DataElement.ALTERNATIVE,
        [
            DataElement(DataElement.BOOLEAN, True),
            DataElement(DataElement.TEXT_STRING, b'hello'),
        ],
    )
    basic_check(e)

    e = DataElement(DataElement.URL, 'http://example.com')

    e = DataElement.nil()

    e = DataElement.unsigned_integer(1234, 2)
    basic_check(e)

    e = DataElement.signed_integer(-1234, 2)
    basic_check(e)

    e = DataElement.uuid(UUID.from_16_bits(1234))
    basic_check(e)

    e = DataElement.text_string(b'hello')
    basic_check(e)

    e = DataElement.boolean(True)
    basic_check(e)

    e = DataElement.sequence(
        [DataElement.signed_integer(0, 1), DataElement.text_string(b'hello')]
    )
    basic_check(e)

    e = DataElement.alternative(
        [DataElement.signed_integer(0, 1), DataElement.text_string(b'hello')]
    )
    basic_check(e)

    e = DataElement.url('http://foobar.com')
    basic_check(e)


# -----------------------------------------------------------------------------
def sdp_records():
    return {
        0x00010001: [
            ServiceAttribute(
                SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                DataElement.unsigned_integer_32(0x00010001),
            ),
            ServiceAttribute(
                SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
                DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
            ),
            ServiceAttribute(
                SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [DataElement.uuid(UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE'))]
                ),
            ),
            ServiceAttribute(
                SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence([DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]),
                    ]
                ),
            ),
        ]
    }


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_search():
    # Setup connections
    devices = TwoDevices()
    await devices.setup_connection()
    assert devices.connections[0]
    assert devices.connections[1]

    # Register SDP service
    devices.devices[0].sdp_server.service_records.update(sdp_records())

    # Search for service
    client = Client(devices.connections[1])
    await client.connect()
    services = await client.search_services(
        [UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE')]
    )

    # Then
    assert services[0] == 0x00010001


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_attribute():
    # Setup connections
    devices = TwoDevices()
    await devices.setup_connection()

    # Register SDP service
    devices.devices[0].sdp_server.service_records.update(sdp_records())

    # Search for service
    client = Client(devices.connections[1])
    await client.connect()
    attributes = await client.get_attributes(
        0x00010001, [SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID]
    )

    # Then
    assert attributes[0].value.value == sdp_records()[0x00010001][0].value.value


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_search_attribute():
    # Setup connections
    devices = TwoDevices()
    await devices.setup_connection()

    # Register SDP service
    devices.devices[0].sdp_server.service_records.update(sdp_records())

    # Search for service
    client = Client(devices.connections[1])
    await client.connect()
    attributes = await client.search_attributes(
        [UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE')], [(0x0000FFFF, 8)]
    )

    # Then
    for expect, actual in zip(attributes, sdp_records().values()):
        assert expect.id == actual.id
        assert expect.value == actual.value


# -----------------------------------------------------------------------------
async def run():
    test_data_elements()
    await test_service_attribute()
    await test_service_search()
    await test_service_search_attribute()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
