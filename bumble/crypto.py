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
# Crypto support
#
# See Bluetooth spec Vol 3, Part H - 2.2 CRYPTOGRAPHIC TOOLBOX
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import logging
import operator

import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key,
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicNumbers,
    EllipticCurvePrivateNumbers,
    SECP256R1,
)
from cryptography.hazmat.primitives import cmac
from typing import Tuple


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class EccKey:
    def __init__(self, private_key: EllipticCurvePrivateKey) -> None:
        self.private_key = private_key

    @classmethod
    def generate(cls) -> EccKey:
        private_key = generate_private_key(SECP256R1())
        return cls(private_key)

    @classmethod
    def from_private_key_bytes(
        cls, d_bytes: bytes, x_bytes: bytes, y_bytes: bytes
    ) -> EccKey:
        d = int.from_bytes(d_bytes, byteorder='big', signed=False)
        x = int.from_bytes(x_bytes, byteorder='big', signed=False)
        y = int.from_bytes(y_bytes, byteorder='big', signed=False)
        private_key = EllipticCurvePrivateNumbers(
            d, EllipticCurvePublicNumbers(x, y, SECP256R1())
        ).private_key()
        return cls(private_key)

    @property
    def x(self) -> bytes:
        return (
            self.private_key.public_key()
            .public_numbers()
            .x.to_bytes(32, byteorder='big')
        )

    @property
    def y(self) -> bytes:
        return (
            self.private_key.public_key()
            .public_numbers()
            .y.to_bytes(32, byteorder='big')
        )

    def dh(self, public_key_x: bytes, public_key_y: bytes) -> bytes:
        x = int.from_bytes(public_key_x, byteorder='big', signed=False)
        y = int.from_bytes(public_key_y, byteorder='big', signed=False)
        public_key = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
        shared_key = self.private_key.exchange(ECDH(), public_key)

        return shared_key


# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
def xor(x: bytes, y: bytes) -> bytes:
    assert len(x) == len(y)
    return bytes(map(operator.xor, x, y))


# -----------------------------------------------------------------------------
def reverse(input: bytes) -> bytes:
    '''
    Returns bytes of input in reversed endianness.
    '''
    return input[::-1]


# -----------------------------------------------------------------------------
def r() -> bytes:
    '''
    Generate 16 bytes of random data
    '''
    return secrets.token_bytes(16)


# -----------------------------------------------------------------------------
def e(key: bytes, data: bytes) -> bytes:
    '''
    AES-128 ECB, expecting byte-swapped inputs and producing a byte-swapped output.

    See Bluetooth spec Vol 3, Part H - 2.2.1 Security function e
    '''

    cipher = Cipher(algorithms.AES(reverse(key)), modes.ECB())
    encryptor = cipher.encryptor()
    return reverse(encryptor.update(reverse(data)))


# -----------------------------------------------------------------------------
def ah(k: bytes, r: bytes) -> bytes:  # pylint: disable=redefined-outer-name
    '''
    See Bluetooth spec Vol 3, Part H - 2.2.2 Random Address Hash function ah
    '''

    padding = bytes(13)
    r_prime = r + padding
    return e(k, r_prime)[0:3]


# -----------------------------------------------------------------------------
def c1(
    k: bytes,
    r: bytes,
    preq: bytes,
    pres: bytes,
    iat: int,
    rat: int,
    ia: bytes,
    ra: bytes,
) -> bytes:  # pylint: disable=redefined-outer-name
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.3 Confirm value generation function c1 for
    LE Legacy Pairing
    '''

    p1 = bytes([iat, rat]) + preq + pres
    p2 = ra + ia + bytes([0, 0, 0, 0])
    return e(k, xor(e(k, xor(r, p1)), p2))


# -----------------------------------------------------------------------------
def s1(k: bytes, r1: bytes, r2: bytes) -> bytes:
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.4 Key generation function s1 for LE Legacy
    Pairing
    '''

    return e(k, r2[0:8] + r1[0:8])


# -----------------------------------------------------------------------------
def aes_cmac(m: bytes, k: bytes) -> bytes:
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.5 FunctionAES-CMAC

    NOTE: the input and output of this internal function are in big-endian byte order
    '''
    mac = cmac.CMAC(algorithms.AES(k))
    mac.update(m)
    return mac.finalize()


# -----------------------------------------------------------------------------
def f4(u: bytes, v: bytes, x: bytes, z: bytes) -> bytes:
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.6 LE Secure Connections Confirm Value
    Generation Function f4
    '''
    return reverse(aes_cmac(reverse(u) + reverse(v) + z, reverse(x)))


# -----------------------------------------------------------------------------
def f5(w: bytes, n1: bytes, n2: bytes, a1: bytes, a2: bytes) -> Tuple[bytes, bytes]:
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.7 LE Secure Connections Key Generation
    Function f5

    NOTE: this returns a tuple: (MacKey, LTK) in little-endian byte order
    '''
    salt = bytes.fromhex('6C888391AAF5A53860370BDB5A6083BE')
    t = aes_cmac(reverse(w), salt)
    key_id = bytes([0x62, 0x74, 0x6C, 0x65])
    return (
        reverse(
            aes_cmac(
                bytes([0])
                + key_id
                + reverse(n1)
                + reverse(n2)
                + reverse(a1)
                + reverse(a2)
                + bytes([1, 0]),
                t,
            )
        ),
        reverse(
            aes_cmac(
                bytes([1])
                + key_id
                + reverse(n1)
                + reverse(n2)
                + reverse(a1)
                + reverse(a2)
                + bytes([1, 0]),
                t,
            )
        ),
    )


# -----------------------------------------------------------------------------
def f6(
    w: bytes, n1: bytes, n2: bytes, r: bytes, io_cap: bytes, a1: bytes, a2: bytes
) -> bytes:  # pylint: disable=redefined-outer-name
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.8 LE Secure Connections Check Value
    Generation Function f6
    '''
    return reverse(
        aes_cmac(
            reverse(n1)
            + reverse(n2)
            + reverse(r)
            + reverse(io_cap)
            + reverse(a1)
            + reverse(a2),
            reverse(w),
        )
    )


# -----------------------------------------------------------------------------
def g2(u: bytes, v: bytes, x: bytes, y: bytes) -> int:
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.9 LE Secure Connections Numeric Comparison
    Value Generation Function g2
    '''
    return int.from_bytes(
        aes_cmac(
            reverse(u) + reverse(v) + reverse(y),
            reverse(x),
        )[-4:],
        byteorder='big',
    )


# -----------------------------------------------------------------------------
def h6(w: bytes, key_id: bytes) -> bytes:
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.10 Link key conversion function h6
    '''
    return reverse(aes_cmac(key_id, reverse(w)))


# -----------------------------------------------------------------------------
def h7(salt: bytes, w: bytes) -> bytes:
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.11 Link key conversion function h7
    '''
    return reverse(aes_cmac(reverse(w), salt))
