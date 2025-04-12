# Copyright 2025 Google LLC
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
# GATT - Type Adapters
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import struct
from typing import (
    Any,
    Callable,
    Generic,
    Iterable,
    Literal,
    Optional,
    Type,
    TypeVar,
)

from bumble.core import InvalidOperationError
from bumble.gatt import Characteristic
from bumble.gatt_client import CharacteristicProxy
from bumble import utils


# -----------------------------------------------------------------------------
# Typing
# -----------------------------------------------------------------------------
_T = TypeVar('_T')
_T2 = TypeVar('_T2', bound=utils.ByteSerializable)
_T3 = TypeVar('_T3', bound=utils.IntConvertible)


# -----------------------------------------------------------------------------
class CharacteristicAdapter(Characteristic, Generic[_T]):
    '''Base class for GATT Characteristic adapters.'''

    def __init__(self, characteristic: Characteristic) -> None:
        super().__init__(
            characteristic.uuid,
            characteristic.properties,
            characteristic.permissions,
            characteristic.value,
            characteristic.descriptors,
        )


# -----------------------------------------------------------------------------
class CharacteristicProxyAdapter(CharacteristicProxy[_T]):
    '''Base class for GATT CharacteristicProxy adapters.'''

    def __init__(self, characteristic_proxy: CharacteristicProxy):
        super().__init__(
            characteristic_proxy.client,
            characteristic_proxy.handle,
            characteristic_proxy.end_group_handle,
            characteristic_proxy.uuid,
            characteristic_proxy.properties,
        )


# -----------------------------------------------------------------------------
class DelegatedCharacteristicAdapter(CharacteristicAdapter[_T]):
    '''
    Adapter that converts bytes values using an encode and/or a decode function.
    '''

    def __init__(
        self,
        characteristic: Characteristic,
        encode: Optional[Callable[[_T], bytes]] = None,
        decode: Optional[Callable[[bytes], _T]] = None,
    ):
        super().__init__(characteristic)
        self.encode = encode
        self.decode = decode

    def encode_value(self, value: _T) -> bytes:
        if self.encode is None:
            raise InvalidOperationError('delegated adapter does not have an encoder')
        return self.encode(value)

    def decode_value(self, value: bytes) -> _T:
        if self.decode is None:
            raise InvalidOperationError('delegate adapter does not have a decoder')
        return self.decode(value)


# -----------------------------------------------------------------------------
class DelegatedCharacteristicProxyAdapter(CharacteristicProxyAdapter[_T]):
    '''
    Adapter that converts bytes values using an encode and a decode function.
    '''

    def __init__(
        self,
        characteristic_proxy: CharacteristicProxy,
        encode: Optional[Callable[[_T], bytes]] = None,
        decode: Optional[Callable[[bytes], _T]] = None,
    ):
        super().__init__(characteristic_proxy)
        self.encode = encode
        self.decode = decode

    def encode_value(self, value: _T) -> bytes:
        if self.encode is None:
            raise InvalidOperationError('delegated adapter does not have an encoder')
        return self.encode(value)

    def decode_value(self, value: bytes) -> _T:
        if self.decode is None:
            raise InvalidOperationError('delegate adapter does not have a decoder')
        return self.decode(value)


# -----------------------------------------------------------------------------
class PackedCharacteristicAdapter(CharacteristicAdapter):
    '''
    Adapter that packs/unpacks characteristic values according to a standard
    Python `struct` format.
    For formats with a single value, the adapted `read_value` and `write_value`
    methods return/accept single values. For formats with multiple values,
    they return/accept a tuple with the same number of elements as is required for
    the format.
    '''

    def __init__(self, characteristic: Characteristic, pack_format: str) -> None:
        super().__init__(characteristic)
        self.struct = struct.Struct(pack_format)

    def pack(self, *values) -> bytes:
        return self.struct.pack(*values)

    def unpack(self, buffer: bytes) -> tuple:
        return self.struct.unpack(buffer)

    def encode_value(self, value: Any) -> bytes:
        return self.pack(*value if isinstance(value, tuple) else (value,))

    def decode_value(self, value: bytes) -> Any:
        unpacked = self.unpack(value)
        return unpacked[0] if len(unpacked) == 1 else unpacked


# -----------------------------------------------------------------------------
class PackedCharacteristicProxyAdapter(CharacteristicProxyAdapter):
    '''
    Adapter that packs/unpacks characteristic values according to a standard
    Python `struct` format.
    For formats with a single value, the adapted `read_value` and `write_value`
    methods return/accept single values. For formats with multiple values,
    they return/accept a tuple with the same number of elements as is required for
    the format.
    '''

    def __init__(self, characteristic_proxy, pack_format):
        super().__init__(characteristic_proxy)
        self.struct = struct.Struct(pack_format)

    def pack(self, *values) -> bytes:
        return self.struct.pack(*values)

    def unpack(self, buffer: bytes) -> tuple:
        return self.struct.unpack(buffer)

    def encode_value(self, value: Any) -> bytes:
        return self.pack(*value if isinstance(value, tuple) else (value,))

    def decode_value(self, value: bytes) -> Any:
        unpacked = self.unpack(value)
        return unpacked[0] if len(unpacked) == 1 else unpacked


# -----------------------------------------------------------------------------
class MappedCharacteristicAdapter(PackedCharacteristicAdapter):
    '''
    Adapter that packs/unpacks characteristic values according to a standard
    Python `struct` format.
    The adapted `read_value` and `write_value` methods return/accept a dictionary which
    is packed/unpacked according to format, with the arguments extracted from the
    dictionary by key, in the same order as they occur in the `keys` parameter.
    '''

    def __init__(
        self, characteristic: Characteristic, pack_format: str, keys: Iterable[str]
    ) -> None:
        super().__init__(characteristic, pack_format)
        self.keys = keys

    # pylint: disable=arguments-differ
    def pack(self, values) -> bytes:
        return super().pack(*(values[key] for key in self.keys))

    def unpack(self, buffer: bytes) -> Any:
        return dict(zip(self.keys, super().unpack(buffer)))


# -----------------------------------------------------------------------------
class MappedCharacteristicProxyAdapter(PackedCharacteristicProxyAdapter):
    '''
    Adapter that packs/unpacks characteristic values according to a standard
    Python `struct` format.
    The adapted `read_value` and `write_value` methods return/accept a dictionary which
    is packed/unpacked according to format, with the arguments extracted from the
    dictionary by key, in the same order as they occur in the `keys` parameter.
    '''

    def __init__(
        self,
        characteristic_proxy: CharacteristicProxy,
        pack_format: str,
        keys: Iterable[str],
    ) -> None:
        super().__init__(characteristic_proxy, pack_format)
        self.keys = keys

    # pylint: disable=arguments-differ
    def pack(self, values) -> bytes:
        return super().pack(*(values[key] for key in self.keys))

    def unpack(self, buffer: bytes) -> Any:
        return dict(zip(self.keys, super().unpack(buffer)))


# -----------------------------------------------------------------------------
class UTF8CharacteristicAdapter(CharacteristicAdapter[str]):
    '''
    Adapter that converts strings to/from bytes using UTF-8 encoding
    '''

    def encode_value(self, value: str) -> bytes:
        return value.encode('utf-8')

    def decode_value(self, value: bytes) -> str:
        return value.decode('utf-8')


# -----------------------------------------------------------------------------
class UTF8CharacteristicProxyAdapter(CharacteristicProxyAdapter[str]):
    '''
    Adapter that converts strings to/from bytes using UTF-8 encoding
    '''

    def encode_value(self, value: str) -> bytes:
        return value.encode('utf-8')

    def decode_value(self, value: bytes) -> str:
        return value.decode('utf-8')


# -----------------------------------------------------------------------------
class SerializableCharacteristicAdapter(CharacteristicAdapter[_T2]):
    '''
    Adapter that converts any class to/from bytes using the class'
    `to_bytes` and `__bytes__` methods, respectively.
    '''

    def __init__(self, characteristic: Characteristic, cls: Type[_T2]) -> None:
        super().__init__(characteristic)
        self.cls = cls

    def encode_value(self, value: _T2) -> bytes:
        return bytes(value)

    def decode_value(self, value: bytes) -> _T2:
        return self.cls.from_bytes(value)


# -----------------------------------------------------------------------------
class SerializableCharacteristicProxyAdapter(CharacteristicProxyAdapter[_T2]):
    '''
    Adapter that converts any class to/from bytes using the class'
    `to_bytes` and `__bytes__` methods, respectively.
    '''

    def __init__(
        self, characteristic_proxy: CharacteristicProxy, cls: Type[_T2]
    ) -> None:
        super().__init__(characteristic_proxy)
        self.cls = cls

    def encode_value(self, value: _T2) -> bytes:
        return bytes(value)

    def decode_value(self, value: bytes) -> _T2:
        return self.cls.from_bytes(value)


# -----------------------------------------------------------------------------
class EnumCharacteristicAdapter(CharacteristicAdapter[_T3]):
    '''
    Adapter that converts int-enum-like classes to/from bytes using the class'
    `int().to_bytes()` and `from_bytes()` methods, respectively.
    '''

    def __init__(
        self,
        characteristic: Characteristic,
        cls: Type[_T3],
        length: int,
        byteorder: Literal['little', 'big'] = 'little',
    ):
        """
        Initialize an instance.

        Params:
          characteristic: the Characteristic to adapt to/from
          cls: the class to/from which to convert integer values
          length: number of bytes used to represent integer values
          byteorder: byte order of the byte representation of integers.
        """
        super().__init__(characteristic)
        self.cls = cls
        self.length = length
        self.byteorder = byteorder

    def encode_value(self, value: _T3) -> bytes:
        return int(value).to_bytes(self.length, self.byteorder)

    def decode_value(self, value: bytes) -> _T3:
        int_value = int.from_bytes(value, self.byteorder)
        return self.cls(int_value)


# -----------------------------------------------------------------------------
class EnumCharacteristicProxyAdapter(CharacteristicProxyAdapter[_T3]):
    '''
    Adapter that converts int-enum-like classes to/from bytes using the class'
    `int().to_bytes()` and `from_bytes()` methods, respectively.
    '''

    def __init__(
        self,
        characteristic_proxy: CharacteristicProxy,
        cls: Type[_T3],
        length: int,
        byteorder: Literal['little', 'big'] = 'little',
    ):
        """
        Initialize an instance.

        Params:
          characteristic_proxy: the CharacteristicProxy to adapt to/from
          cls: the class to/from which to convert integer values
          length: number of bytes used to represent integer values
          byteorder: byte order of the byte representation of integers.
        """
        super().__init__(characteristic_proxy)
        self.cls = cls
        self.length = length
        self.byteorder = byteorder

    def encode_value(self, value: _T3) -> bytes:
        return int(value).to_bytes(self.length, self.byteorder)

    def decode_value(self, value: bytes) -> _T3:
        int_value = int.from_bytes(value, self.byteorder)
        a = self.cls(int_value)
        return self.cls(int_value)
