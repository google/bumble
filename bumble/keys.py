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
import asyncio
import logging
import os
import json
from typing import Optional

from .colors import color
from .hci import Address


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
    async def delete(self, name):
        pass

    async def update(self, name, keys):
        pass

    async def get(self, _name):
        return PairingKeys()

    async def get_all(self):
        return []

    async def delete_all(self):
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
    def create_for_device(device_config):
        if device_config.keystore is None:
            return None

        keystore_type = device_config.keystore.split(':', 1)[0]
        if keystore_type == 'JsonKeyStore':
            return JsonKeyStore.from_device_config(device_config)

        return None


# -----------------------------------------------------------------------------
class JsonKeyStore(KeyStore):
    APP_NAME = 'Bumble'
    APP_AUTHOR = 'Google'
    KEYS_DIR = 'Pairing'
    DEFAULT_NAMESPACE = '__DEFAULT__'

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
            json_filename = f'{self.namespace}.json'.lower().replace(':', '-')
            self.filename = os.path.join(self.directory_name, json_filename)
        else:
            self.filename = filename
            self.directory_name = os.path.dirname(os.path.abspath(self.filename))

        logger.debug(f'JSON keystore: {self.filename}')

    @staticmethod
    def from_device_config(device_config):
        params = device_config.keystore.split(':', 1)[1:]
        namespace = str(device_config.address)
        if params:
            filename = params[0]
        else:
            filename = None

        return JsonKeyStore(namespace, filename)

    async def load(self):
        try:
            with open(self.filename, 'r', encoding='utf-8') as json_file:
                return json.load(json_file)
        except FileNotFoundError:
            return {}

    async def save(self, db):
        # Create the directory if it doesn't exist
        if not os.path.exists(self.directory_name):
            os.makedirs(self.directory_name, exist_ok=True)

        # Save to a temporary file
        temp_filename = self.filename + '.tmp'
        with open(temp_filename, 'w', encoding='utf-8') as output:
            json.dump(db, output, sort_keys=True, indent=4)

        # Atomically replace the previous file
        os.rename(temp_filename, self.filename)

    async def delete(self, name: str) -> None:
        db = await self.load()

        namespace = db.get(self.namespace)
        if namespace is None:
            raise KeyError(name)

        del namespace[name]
        await self.save(db)

    async def update(self, name, keys):
        db = await self.load()

        namespace = db.setdefault(self.namespace, {})
        namespace[name] = keys.to_dict()

        await self.save(db)

    async def get_all(self):
        db = await self.load()

        namespace = db.get(self.namespace)
        if namespace is None:
            return []

        return [
            (name, PairingKeys.from_dict(keys)) for (name, keys) in namespace.items()
        ]

    async def delete_all(self):
        db = await self.load()

        db.pop(self.namespace, None)

        await self.save(db)

    async def get(self, name: str) -> Optional[PairingKeys]:
        db = await self.load()

        namespace = db.get(self.namespace)
        if namespace is None:
            return None

        keys = namespace.get(name)
        if keys is None:
            return None

        return PairingKeys.from_dict(keys)
