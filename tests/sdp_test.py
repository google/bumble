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
from bumble.core import UUID
from bumble.sdp import DataElement

# -----------------------------------------------------------------------------
# pylint: disable=invalid-name
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
def basic_check(x):
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
def test_data_elements():
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

    e = DataElement(DataElement.TEXT_STRING, 'hello')
    basic_check(e)

    e = DataElement(DataElement.TEXT_STRING, 'hello' * 60)
    basic_check(e)

    e = DataElement(DataElement.TEXT_STRING, 'hello' * 20000)
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
            DataElement(DataElement.TEXT_STRING, 'hello'),
        ],
    )
    basic_check(e)

    e = DataElement(DataElement.ALTERNATIVE, [DataElement(DataElement.BOOLEAN, True)])
    basic_check(e)

    e = DataElement(
        DataElement.ALTERNATIVE,
        [
            DataElement(DataElement.BOOLEAN, True),
            DataElement(DataElement.TEXT_STRING, 'hello'),
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

    e = DataElement.text_string('hello')
    basic_check(e)

    e = DataElement.boolean(True)
    basic_check(e)

    e = DataElement.sequence(
        [DataElement.signed_integer(0, 1), DataElement.text_string('hello')]
    )
    basic_check(e)

    e = DataElement.alternative(
        [DataElement.signed_integer(0, 1), DataElement.text_string('hello')]
    )
    basic_check(e)

    e = DataElement.url('http://foobar.com')
    basic_check(e)


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_data_elements()
