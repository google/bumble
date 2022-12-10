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
import logging
import operator
import platform

if platform.system() != 'Emscripten':
    import secrets
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key,
        ECDH,
        EllipticCurvePublicNumbers,
        EllipticCurvePrivateNumbers,
        SECP256R1,
    )
    from cryptography.hazmat.primitives import cmac
else:
    # TODO: implement stubs
    pass

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class EccKey:
    def __init__(self, private_key):
        self.private_key = private_key

    @classmethod
    def generate(cls):
        private_key = generate_private_key(SECP256R1())
        return cls(private_key)

    @classmethod
    def from_private_key_bytes(cls, d_bytes, x_bytes, y_bytes):
        d = int.from_bytes(d_bytes, byteorder='big', signed=False)
        x = int.from_bytes(x_bytes, byteorder='big', signed=False)
        y = int.from_bytes(y_bytes, byteorder='big', signed=False)
        private_key = EllipticCurvePrivateNumbers(
            d, EllipticCurvePublicNumbers(x, y, SECP256R1())
        ).private_key()
        return cls(private_key)

    @property
    def x(self):
        return (
            self.private_key.public_key()
            .public_numbers()
            .x.to_bytes(32, byteorder='big')
        )

    @property
    def y(self):
        return (
            self.private_key.public_key()
            .public_numbers()
            .y.to_bytes(32, byteorder='big')
        )

    def dh(self, public_key_x, public_key_y):
        x = int.from_bytes(public_key_x, byteorder='big', signed=False)
        y = int.from_bytes(public_key_y, byteorder='big', signed=False)
        public_key = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
        shared_key = self.private_key.exchange(ECDH(), public_key)

        return shared_key


# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
def xor(x, y):
    assert len(x) == len(y)
    return bytes(map(operator.xor, x, y))


# -----------------------------------------------------------------------------
def r():
    '''
    Generate 16 bytes of random data
    '''
    return secrets.token_bytes(16)


# -----------------------------------------------------------------------------
def e(key, data):
    '''
    AES-128 ECB, expecting byte-swapped inputs and producing a byte-swapped output.

    See Bluetooth spec Vol 3, Part H - 2.2.1 Security function e
    '''

    cipher = Cipher(algorithms.AES(bytes(reversed(key))), modes.ECB())
    encryptor = cipher.encryptor()
    return bytes(reversed(encryptor.update(bytes(reversed(data)))))


# -----------------------------------------------------------------------------
def ah(k, r):  # pylint: disable=redefined-outer-name
    '''
    See Bluetooth spec Vol 3, Part H - 2.2.2 Random Address Hash function ah
    '''

    padding = bytes(13)
    r_prime = r + padding
    return e(k, r_prime)[0:3]


# -----------------------------------------------------------------------------
def c1(k, r, preq, pres, iat, rat, ia, ra):  # pylint: disable=redefined-outer-name
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.3 Confirm value generation function c1 for
    LE Legacy Pairing
    '''

    p1 = bytes([iat, rat]) + preq + pres
    p2 = ra + ia + bytes([0, 0, 0, 0])
    return e(k, xor(e(k, xor(r, p1)), p2))


# -----------------------------------------------------------------------------
def s1(k, r1, r2):
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.4 Key generation function s1 for LE Legacy
    Pairing
    '''

    return e(k, r2[0:8] + r1[0:8])


# -----------------------------------------------------------------------------
def aes_cmac(m, k):
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.5 FunctionAES-CMAC

    NOTE: the input and output of this internal function are in big-endian byte order
    '''
    mac = cmac.CMAC(algorithms.AES(k))
    mac.update(m)
    return mac.finalize()


# -----------------------------------------------------------------------------
def f4(u, v, x, z):
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.6 LE Secure Connections Confirm Value
    Generation Function f4
    '''
    return bytes(
        reversed(
            aes_cmac(bytes(reversed(u)) + bytes(reversed(v)) + z, bytes(reversed(x)))
        )
    )


# -----------------------------------------------------------------------------
def f5(w, n1, n2, a1, a2):
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.7 LE Secure Connections Key Generation
    Function f5

    NOTE: this returns a tuple: (MacKey, LTK) in little-endian byte order
    '''
    salt = bytes.fromhex('6C888391AAF5A53860370BDB5A6083BE')
    t = aes_cmac(bytes(reversed(w)), salt)
    key_id = bytes([0x62, 0x74, 0x6C, 0x65])
    return (
        bytes(
            reversed(
                aes_cmac(
                    bytes([0])
                    + key_id
                    + bytes(reversed(n1))
                    + bytes(reversed(n2))
                    + bytes(reversed(a1))
                    + bytes(reversed(a2))
                    + bytes([1, 0]),
                    t,
                )
            )
        ),
        bytes(
            reversed(
                aes_cmac(
                    bytes([1])
                    + key_id
                    + bytes(reversed(n1))
                    + bytes(reversed(n2))
                    + bytes(reversed(a1))
                    + bytes(reversed(a2))
                    + bytes([1, 0]),
                    t,
                )
            )
        ),
    )


# -----------------------------------------------------------------------------
def f6(w, n1, n2, r, io_cap, a1, a2):  # pylint: disable=redefined-outer-name
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.8 LE Secure Connections Check Value
    Generation Function f6
    '''
    return bytes(
        reversed(
            aes_cmac(
                bytes(reversed(n1))
                + bytes(reversed(n2))
                + bytes(reversed(r))
                + bytes(reversed(io_cap))
                + bytes(reversed(a1))
                + bytes(reversed(a2)),
                bytes(reversed(w)),
            )
        )
    )


# -----------------------------------------------------------------------------
def g2(u, v, x, y):
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.9 LE Secure Connections Numeric Comparison
    Value Generation Function g2
    '''
    return int.from_bytes(
        aes_cmac(
            bytes(reversed(u)) + bytes(reversed(v)) + bytes(reversed(y)),
            bytes(reversed(x)),
        )[-4:],
        byteorder='big',
    )


# -----------------------------------------------------------------------------
def h6(w, key_id):
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.10 Link key conversion function h6
    '''
    return aes_cmac(key_id, w)


# -----------------------------------------------------------------------------
def h7(salt, w):
    '''
    See Bluetooth spec, Vol 3, Part H - 2.2.11 Link key conversion function h7
    '''
    return aes_cmac(w, salt)
