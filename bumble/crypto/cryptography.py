# Copyright 2021-2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License")
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

import functools

from cryptography.hazmat.primitives import ciphers, cmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms, modes


def e(key: bytes, data: bytes) -> bytes:
    '''
    AES-128 ECB, expecting byte-swapped inputs and producing a byte-swapped output.

    See Bluetooth spec Vol 3, Part H - 2.2.1 Security function e
    '''

    cipher = ciphers.Cipher(algorithms.AES(key[::-1]), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data[::-1])[::-1]


class EccKey:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self.private_key = private_key

    @classmethod
    def generate(cls) -> EccKey:
        return EccKey(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_private_key_bytes(cls, d_bytes: bytes) -> EccKey:
        d = int.from_bytes(d_bytes, byteorder='big', signed=False)
        return EccKey(ec.derive_private_key(d, ec.SECP256R1()))

    @functools.cached_property
    def x(self) -> bytes:
        return (
            self.private_key.public_key()
            .public_numbers()
            .x.to_bytes(32, byteorder='big')
        )

    @functools.cached_property
    def y(self) -> bytes:
        return (
            self.private_key.public_key()
            .public_numbers()
            .y.to_bytes(32, byteorder='big')
        )

    def dh(self, public_key_x: bytes, public_key_y: bytes) -> bytes:
        x = int.from_bytes(public_key_x, byteorder='big', signed=False)
        y = int.from_bytes(public_key_y, byteorder='big', signed=False)
        return self.private_key.exchange(
            ec.ECDH(),
            ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(),
        )


def aes_cmac(m: bytes, k: bytes) -> bytes:
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.5 FunctionAES-CMAC

    NOTE: the input and output of this internal function are in big-endian byte order
    '''
    mac = cmac.CMAC(algorithms.AES(k))
    mac.update(m)
    return mac.finalize()
