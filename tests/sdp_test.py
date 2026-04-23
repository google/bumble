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
import re

import pytest

from bumble import sdp
from bumble.core import BT_L2CAP_PROTOCOL_ID, UUID
from bumble.sdp import (
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    Client,
    DataElement,
    ServiceAttribute,
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
def sdp_records(record_count=1):
    return {
        0x00010001
        + i: [
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
        for i in range(record_count)
    }


# -----------------------------------------------------------------------------
def test_pdu_parameter_length(caplog) -> None:
    caplog.set_level(logging.WARNING)
    pdu = sdp.SDP_ErrorResponse(
        transaction_id=0, error_code=sdp.ErrorCode.INVALID_SDP_VERSION
    )
    assert sdp.SDP_PDU.from_bytes(bytes(pdu)) == pdu
    assert not re.search("Expect \d+ bytes, got \d+", caplog.text)


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
    async with Client(devices.connections[1]) as client:
        services = await client.search_services(
            [UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AF')]
        )
        assert len(services) == 0

        services = await client.search_services(
            [UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE')]
        )
        assert len(services) == 1
        assert services[0] == 0x00010001

        services = await client.search_services(
            [BT_L2CAP_PROTOCOL_ID, SDP_PUBLIC_BROWSE_ROOT]
        )
        assert len(services) == 1
        assert services[0] == 0x00010001

        services = await client.search_services(
            [BT_L2CAP_PROTOCOL_ID, SDP_PUBLIC_BROWSE_ROOT]
        )
        assert len(services) == 1
        assert services[0] == 0x00010001


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_search_with_continuation():
    # Setup connections
    devices = TwoDevices()
    await devices.setup_connection()

    # Register SDP service
    records = sdp_records(100)
    devices.devices[0].sdp_server.service_records.update(records)

    # Search for service
    async with Client(devices.connections[1], mtu=48) as client:
        services = await client.search_services(
            [UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE')]
        )
        assert len(services) == len(records)
        for i in range(len(records)):
            assert services[i] == 0x00010001 + i


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_attributes():
    # Setup connections
    devices = TwoDevices()
    await devices.setup_connection()

    # Register SDP service
    devices.devices[0].sdp_server.service_records.update(sdp_records())

    # Get attributes
    async with Client(devices.connections[1]) as client:
        attributes = await client.get_attributes(0x00010001, [1234])
        assert len(attributes) == 0

        attributes = await client.get_attributes(
            0x00010001, [SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID]
        )
        assert len(attributes) == 1
        assert attributes[0].value.value == sdp_records()[0x00010001][0].value.value


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_attributes_with_continuation():
    # Setup connections
    devices = TwoDevices()
    await devices.setup_connection()

    # Register SDP service
    records = {
        0x00010001: [
            ServiceAttribute(
                x,
                DataElement.unsigned_integer_32(0x00010001),
            )
            for x in range(100)
        ]
    }
    devices.devices[0].sdp_server.service_records.update(records)

    # Get attributes
    async with Client(devices.connections[1], mtu=48) as client:
        attributes = await client.get_attributes(0x00010001, list(range(100)))
        assert len(attributes) == 100
        for i, attribute in enumerate(attributes):
            assert attribute.id == i


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_search_attribute():
    # Setup connections
    devices = TwoDevices()
    await devices.setup_connection()

    # Register SDP service
    records = {
        0x00010001: [
            ServiceAttribute(
                4,
                DataElement.sequence(
                    [DataElement.uuid(UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE'))]
                ),
            ),
            ServiceAttribute(
                3,
                DataElement.sequence(
                    [DataElement.uuid(UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE'))]
                ),
            ),
            ServiceAttribute(
                1,
                DataElement.sequence(
                    [DataElement.uuid(UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE'))]
                ),
            ),
        ]
    }

    devices.devices[0].sdp_server.service_records.update(records)

    # Search for service
    async with Client(devices.connections[1]) as client:
        attributes = await client.search_attributes(
            [UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE')], [(0, 0xFFFF)]
        )
        assert len(attributes) == 1
        assert len(attributes[0]) == 3
        assert attributes[0][0].id == 1
        assert attributes[0][1].id == 3
        assert attributes[0][2].id == 4

        attributes = await client.search_attributes(
            [UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE')], [1, 2, 3]
        )
        assert len(attributes) == 1
        assert len(attributes[0]) == 2
        assert attributes[0][0].id == 1
        assert attributes[0][1].id == 3


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_service_search_attribute_with_continuation():
    # Setup connections
    devices = TwoDevices()
    await devices.setup_connection()

    # Register SDP service
    records = {
        0x00010001: [
            ServiceAttribute(
                x,
                DataElement.sequence(
                    [DataElement.uuid(UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE'))]
                ),
            )
            for x in range(100)
        ]
    }
    devices.devices[0].sdp_server.service_records.update(records)

    # Search for service
    async with Client(devices.connections[1], mtu=48) as client:
        attributes = await client.search_attributes(
            [UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE')], [(0, 0xFFFF)]
        )
        assert len(attributes) == 1
        assert len(attributes[0]) == 100
        for i in range(100):
            assert attributes[0][i].id == i


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_client_async_context():
    devices = TwoDevices()
    await devices.setup_connection()

    client = Client(devices.connections[1])

    async with client:
        assert client.channel is not None

    assert client.channel is None


# -----------------------------------------------------------------------------
async def run():
    test_data_elements()
    await test_service_attributes()
    await test_service_attributes_with_continuation()
    await test_service_search()
    await test_service_search_with_continuation()
    await test_service_search_attribute()
    await test_service_search_attribute_with_continuation()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())


# -----------------------------------------------------------------------------
def test_nested_sequence_recursion_guard():
    """Regression test: deeply-nested SDP SEQUENCE/ALTERNATIVE must not crash
    the parser with RecursionError. Instead a ValueError is raised once the
    configured nesting limit is exceeded.

    Root cause: DataElement.from_bytes -> list_from_bytes -> (constructor
    dispatching back to list_from_bytes for SEQUENCE/ALTERNATIVE) recursed
    without a depth limit. A malicious SDP peer could craft a PDU exceeding
    Pythons default recursion limit (~1000 frames) and crash the host.
    """
    # Build nested SEQUENCE payload with tag 0x36 (SEQUENCE, 2-byte length).
    inner = b"\x35\x00"  # empty SEQUENCE terminator
    for _ in range(1500):
        size = len(inner)
        if size >= 65535:
            break
        inner = bytes([0x36, (size >> 8) & 0xFF, size & 0xFF]) + inner

    import pytest
    with pytest.raises(ValueError, match="nesting exceeds max depth"):
        DataElement.from_bytes(inner)


def test_nested_sequence_within_limit_still_works():
    """Nested-but-reasonable SDP SEQUENCEs must still parse correctly."""
    leaf = DataElement.unsigned_integer(1, value_size=2)
    payload = leaf
    for _ in range(16):  # under the 32-depth limit
        payload = DataElement.sequence([payload])
    raw = bytes(payload)
    parsed = DataElement.from_bytes(raw)
    # Walk back down to confirm structural integrity preserved
    cur = parsed
    for _ in range(16):
        assert cur.type == DataElement.SEQUENCE
        cur = cur.value[0]
    assert cur.type == DataElement.UNSIGNED_INTEGER
    assert cur.value == 1
