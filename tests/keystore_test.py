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
import json
import logging
import os
import pathlib
import tempfile
from unittest import mock

import pytest

from bumble.keys import JsonKeyStore, PairingKeys

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

JSON1 = """
        {
            "my_namespace": {
                "14:7D:DA:4E:53:A8/P": {
                    "address_type": 0,
                    "irk": {
                        "authenticated": false,
                        "value": "e7b2543b206e4e46b44f9e51dad22bd1"
                    },
                    "link_key": {
                        "authenticated": false,
                        "value": "0745dd9691e693d9dca740f7d8dfea75"
                    },
                    "ltk": {
                        "authenticated": false,
                        "value": "d1897ee10016eb1a08e4e037fd54c683"
                    }
                }
            }
        }
        """

JSON2 = """
        {
            "my_namespace1": {
            },
            "my_namespace2": {
            }
        }
        """

JSON3 = """
        {
            "my_namespace1": {
            },
            "__DEFAULT__": {
                "14:7D:DA:4E:53:A8/P": {
                    "address_type": 0,
                    "irk": {
                        "authenticated": false,
                        "value": "e7b2543b206e4e46b44f9e51dad22bd1"
                    }
                }
            }
        }
        """


# -----------------------------------------------------------------------------
@pytest.fixture
def temporary_file():
    file = tempfile.NamedTemporaryFile(delete=False)
    file.close()
    yield file.name
    pathlib.Path(file.name).unlink()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_basic(temporary_file):
    with open(temporary_file, mode='w', encoding='utf-8') as file:
        file.write("{}")
        file.flush()

    keystore = JsonKeyStore('my_namespace', temporary_file)

    keys = await keystore.get_all()
    assert len(keys) == 0

    keys = PairingKeys()
    await keystore.update('foo', keys)
    foo = await keystore.get('foo')
    assert foo is not None
    assert foo.ltk is None
    ltk = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    keys.ltk = PairingKeys.Key(ltk)
    await keystore.update('foo', keys)
    foo = await keystore.get('foo')
    assert foo is not None
    assert foo.ltk is not None
    assert foo.ltk.value == ltk

    with open(file.name, encoding="utf-8") as json_file:
        json_data = json.load(json_file)
        assert 'my_namespace' in json_data
        assert 'foo' in json_data['my_namespace']
        assert 'ltk' in json_data['my_namespace']['foo']


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_parsing(temporary_file):
    with open(temporary_file, mode='w', encoding='utf-8') as file:
        file.write(JSON1)
        file.flush()

    keystore = JsonKeyStore('my_namespace', file.name)
    foo = await keystore.get('14:7D:DA:4E:53:A8/P')
    assert foo is not None
    assert foo.ltk.value == bytes.fromhex('d1897ee10016eb1a08e4e037fd54c683')


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_default_namespace(temporary_file):
    with open(temporary_file, mode='w', encoding='utf-8') as file:
        file.write(JSON1)
        file.flush()

    keystore = JsonKeyStore(None, file.name)
    all_keys = await keystore.get_all()
    assert len(all_keys) == 1
    name, keys = all_keys[0]
    assert name == '14:7D:DA:4E:53:A8/P'
    assert keys.irk.value == bytes.fromhex('e7b2543b206e4e46b44f9e51dad22bd1')

    with open(temporary_file, mode='w', encoding='utf-8') as file:
        file.write(JSON2)
        file.flush()

    keystore = JsonKeyStore(None, file.name)
    keys = PairingKeys()
    ltk = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    keys.ltk = PairingKeys.Key(ltk)
    await keystore.update('foo', keys)
    with open(file.name, encoding="utf-8") as json_file:
        json_data = json.load(json_file)
        assert '__DEFAULT__' in json_data
        assert 'foo' in json_data['__DEFAULT__']
        assert 'ltk' in json_data['__DEFAULT__']['foo']

    with open(temporary_file, mode='w', encoding='utf-8') as file:
        file.write(JSON3)
        file.flush()

    keystore = JsonKeyStore(None, file.name)
    all_keys = await keystore.get_all()
    assert len(all_keys) == 1
    name, keys = all_keys[0]
    assert name == '14:7D:DA:4E:53:A8/P'
    assert keys.irk.value == bytes.fromhex('e7b2543b206e4e46b44f9e51dad22bd1')


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_no_filename(tmp_path):
    import platformdirs

    with mock.patch.object(platformdirs, 'user_data_path', return_value=tmp_path):
        # Case 1: no namespace, no filename
        keystore = JsonKeyStore(None, None)
        expected_directory = tmp_path / 'Pairing'
        expected_filename = expected_directory / 'keys.json'
        assert keystore.directory_name == expected_directory
        assert keystore.filename == expected_filename

        # Save some data
        keys = PairingKeys()
        ltk = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        keys.ltk = PairingKeys.Key(ltk)
        await keystore.update('foo', keys)
        assert expected_filename.exists()

        # Load back
        keystore2 = JsonKeyStore(None, None)
        foo = await keystore2.get('foo')
        assert foo is not None
        assert foo.ltk.value == ltk

        # Case 2: namespace, no filename
        keystore3 = JsonKeyStore('my:namespace', None)
        # safe_name = 'my-namespace' (lower is already 'my:namespace', then replace ':' with '-')
        expected_filename3 = expected_directory / 'my-namespace.json'
        assert keystore3.filename == expected_filename3

        # Save some data
        await keystore3.update('bar', keys)
        assert expected_filename3.exists()

        # Load back
        keystore4 = JsonKeyStore('my:namespace', None)
        bar = await keystore4.get('bar')
        assert bar is not None
        assert bar.ltk.value == ltk


# -----------------------------------------------------------------------------
async def run_tests():
    await test_basic()
    await test_parsing()
    await test_default_namespace()
    await test_no_filename()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run_tests())
