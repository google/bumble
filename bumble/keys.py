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
# Keys and Key Storage
#
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import asyncio
import logging
import os
import json
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from .colors import color
from .hci import Address

if TYPE_CHECKING:
    from .device import Device


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
class PairingKeys:
    class Key:
        def __init__(self, value, authenticated=False, ediv=None, rand=None):
            self.value = value
            self.authenticated = authenticated
            self.ediv = ediv
            self.rand = rand

        @classmethod
        def from_dict(cls, key_dict):
            value = bytes.fromhex(key_dict['value'])
            authenticated = key_dict.get('authenticated', False)
            ediv = key_dict.get('ediv')
            rand = key_dict.get('rand')
            if rand is not None:
                rand = bytes.fromhex(rand)

            return cls(value, authenticated, ediv, rand)

        def to_dict(self):
            key_dict = {'value': self.value.hex(), 'authenticated': self.authenticated}
            if self.ediv is not None:
                key_dict['ediv'] = self.ediv
            if self.rand is not None:
                key_dict['rand'] = self.rand.hex()

            return key_dict

    def __init__(self):
        self.address_type = None
        self.ltk = None
        self.ltk_central = None
        self.ltk_peripheral = None
        self.irk = None
        self.csrk = None
        self.link_key = None  # Classic

    @staticmethod
    def key_from_dict(keys_dict, key_name):
        key_dict = keys_dict.get(key_name)
        if key_dict is None:
            return None

        return PairingKeys.Key.from_dict(key_dict)

    @staticmethod
    def from_dict(keys_dict):
        keys = PairingKeys()

        keys.address_type = keys_dict.get('address_type')
        keys.ltk = PairingKeys.key_from_dict(keys_dict, 'ltk')
        keys.ltk_central = PairingKeys.key_from_dict(keys_dict, 'ltk_central')
        keys.ltk_peripheral = PairingKeys.key_from_dict(keys_dict, 'ltk_peripheral')
        keys.irk = PairingKeys.key_from_dict(keys_dict, 'irk')
        keys.csrk = PairingKeys.key_from_dict(keys_dict, 'csrk')
        keys.link_key = PairingKeys.key_from_dict(keys_dict, 'link_key')

        return keys

    def to_dict(self):
        keys = {}

        if self.address_type is not None:
            keys['address_type'] = self.address_type

        if self.ltk is not None:
            keys['ltk'] = self.ltk.to_dict()

        if self.ltk_central is not None:
            keys['ltk_central'] = self.ltk_central.to_dict()

        if self.ltk_peripheral is not None:
            keys['ltk_peripheral'] = self.ltk_peripheral.to_dict()

        if self.irk is not None:
            keys['irk'] = self.irk.to_dict()

        if self.csrk is not None:
            keys['csrk'] = self.csrk.to_dict()

        if self.link_key is not None:
            keys['link_key'] = self.link_key.to_dict()

        return keys

    def print(self, prefix=''):
        keys_dict = self.to_dict()
        for (container_property, value) in keys_dict.items():
            if isinstance(value, dict):
                print(f'{prefix}{color(container_property, "cyan")}:')
                for (key_property, key_value) in value.items():
                    print(f'{prefix}  {color(key_property, "green")}: {key_value}')
            else:
                print(f'{prefix}{color(container_property, "cyan")}: {value}')


# -----------------------------------------------------------------------------
class KeyStore:
    async def delete(self, name: str):
        pass

    async def update(self, name: str, keys: PairingKeys) -> None:
        pass

    async def get(self, _name: str) -> Optional[PairingKeys]:
        return None

    async def get_all(self) -> List[Tuple[str, PairingKeys]]:
        return []

    async def delete_all(self) -> None:
        all_keys = await self.get_all()
        await asyncio.gather(*(self.delete(name) for (name, _) in all_keys))

    async def get_resolving_keys(self):
        all_keys = await self.get_all()
        resolving_keys = []
        for (name, keys) in all_keys:
            if keys.irk is not None:
                if keys.address_type is None:
                    address_type = Address.RANDOM_DEVICE_ADDRESS
                else:
                    address_type = keys.address_type
                resolving_keys.append((keys.irk.value, Address(name, address_type)))

        return resolving_keys

    async def print(self, prefix=''):
        entries = await self.get_all()
        separator = ''
        for (name, keys) in entries:
            print(separator + prefix + color(name, 'yellow'))
            keys.print(prefix=prefix + '  ')
            separator = '\n'

    @staticmethod
    def create_for_device(device: Device) -> KeyStore:
        if device.config.keystore is None:
            return MemoryKeyStore()

        keystore_type = device.config.keystore.split(':', 1)[0]
        if keystore_type == 'JsonKeyStore':
            return JsonKeyStore.from_device(device)

        return MemoryKeyStore()


# -----------------------------------------------------------------------------
class JsonKeyStore(KeyStore):
    """
    KeyStore implementation that is backed by a JSON file.

    This implementation supports storing a hierarchy of key sets in a single file.
    A key set is a representation of a PairingKeys object. Each key set is stored
    in a map, with the address of paired peer as the key. Maps are themselves grouped
    into namespaces, grouping pairing keys by controller addresses.
    The JSON object model looks like:
    {
        "<namespace>": {
            "peer-address": {
                "address_type": <n>,
                "irk" : {
                    "authenticated": <true/false>,
                    "value": "hex-encoded-key"
                },
                ... other keys ...
            },
            ... other peers ...
        }
        ... other namespaces ...
    }

    A namespace is typically the BD_ADDR of a controller, since that is a convenient
    unique identifier, but it may be something else.
    A special namespace, called the "default" namespace, is used when instantiating this
    class without a namespace. With the default namespace, reading from a file will
    load an existing namespace if there is only one, which may be convenient for reading
    from a file with a single key set and for which the namespace isn't known. If the
    file does not include any existing key set, or if there are more than one and none
    has the default name, a new one will be created with the name "__DEFAULT__".
    """

    APP_NAME = 'Bumble'
    APP_AUTHOR = 'Google'
    KEYS_DIR = 'Pairing'
    DEFAULT_NAMESPACE = '__DEFAULT__'
    DEFAULT_BASE_NAME = "keys"

    def __init__(self, namespace, filename=None):
        self.namespace = namespace if namespace is not None else self.DEFAULT_NAMESPACE

        if filename is None:
            # Use a default for the current user

            # Import here because this may not exist on all platforms
            # pylint: disable=import-outside-toplevel
            import appdirs

            self.directory_name = os.path.join(
                appdirs.user_data_dir(self.APP_NAME, self.APP_AUTHOR), self.KEYS_DIR
            )
            base_name = self.DEFAULT_BASE_NAME if namespace is None else self.namespace
            json_filename = (
                f'{base_name}.json'.lower().replace(':', '-').replace('/p', '-p')
            )
            self.filename = os.path.join(self.directory_name, json_filename)
        else:
            self.filename = filename
            self.directory_name = os.path.dirname(os.path.abspath(self.filename))

        logger.debug(f'JSON keystore: {self.filename}')

    @staticmethod
    def from_device(device: Device, filename=None) -> Optional[JsonKeyStore]:
        if not filename:
            # Extract the filename from the config if there is one
            if device.config.keystore is not None:
                params = device.config.keystore.split(':', 1)[1:]
                if params:
                    filename = params[0]

        # Use a namespace based on the device address
        if device.public_address not in (Address.ANY, Address.ANY_RANDOM):
            namespace = str(device.public_address)
        elif device.random_address != Address.ANY_RANDOM:
            namespace = str(device.random_address)
        else:
            namespace = JsonKeyStore.DEFAULT_NAMESPACE

        return JsonKeyStore(namespace, filename)

    async def load(self):
        # Try to open the file, without failing. If the file does not exist, it
        # will be created upon saving.
        try:
            with open(self.filename, 'r', encoding='utf-8') as json_file:
                db = json.load(json_file)
        except FileNotFoundError:
            db = {}

        # First, look for a namespace match
        if self.namespace in db:
            return (db, db[self.namespace])

        # Then, if the namespace is the default namespace, and there's
        # only one entry in the db, use that
        if self.namespace == self.DEFAULT_NAMESPACE and len(db) == 1:
            return next(iter(db.items()))

        # Finally, just create an empty key map for the namespace
        key_map = {}
        db[self.namespace] = key_map
        return (db, key_map)

    async def save(self, db):
        # Create the directory if it doesn't exist
        if not os.path.exists(self.directory_name):
            os.makedirs(self.directory_name, exist_ok=True)

        # Save to a temporary file
        temp_filename = self.filename + '.tmp'
        with open(temp_filename, 'w', encoding='utf-8') as output:
            json.dump(db, output, sort_keys=True, indent=4)

        # Atomically replace the previous file
        os.replace(temp_filename, self.filename)

    async def delete(self, name: str) -> None:
        db, key_map = await self.load()
        del key_map[name]
        await self.save(db)

    async def update(self, name, keys):
        db, key_map = await self.load()
        key_map.setdefault(name, {}).update(keys.to_dict())
        await self.save(db)

    async def get_all(self):
        _, key_map = await self.load()
        return [(name, PairingKeys.from_dict(keys)) for (name, keys) in key_map.items()]

    async def delete_all(self):
        db, key_map = await self.load()
        key_map.clear()
        await self.save(db)

    async def get(self, name: str) -> Optional[PairingKeys]:
        _, key_map = await self.load()
        if name not in key_map:
            return None

        return PairingKeys.from_dict(key_map[name])


# -----------------------------------------------------------------------------
class MemoryKeyStore(KeyStore):
    all_keys: Dict[str, PairingKeys]

    def __init__(self) -> None:
        self.all_keys = {}

    async def delete(self, name: str) -> None:
        if name in self.all_keys:
            del self.all_keys[name]

    async def update(self, name: str, keys: PairingKeys) -> None:
        self.all_keys[name] = keys

    async def get(self, name: str) -> Optional[PairingKeys]:
        return self.all_keys.get(name)

    async def get_all(self) -> List[Tuple[str, PairingKeys]]:
        return list(self.all_keys.items())
