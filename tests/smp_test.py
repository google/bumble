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

import pytest

from bumble import smp
from bumble.crypto import EccKey, aes_cmac, ah, c1, f4, f5, f6, g2, h6, h7, s1
from bumble.pairing import OobData, OobSharedData, LeRole
from bumble.hci import Address
from bumble.core import AdvertisingData


# -----------------------------------------------------------------------------
# pylint: disable=invalid-name
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
def reversed_hex(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)[::-1]


# -----------------------------------------------------------------------------
def test_ecc():
    key = EccKey.generate()
    x = key.x
    y = key.y

    assert len(x) == 32
    assert len(y) == 32

    # Test DH with test vectors from the spec
    private_A = (
        '3f49f6d4 a3c55f38 74c9b3e3 d2103f50 4aff607b eb40b799 5899b8a6 cd3c1abd'
    )
    private_B = (
        '55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd'
    )
    public_A_x = (
        '20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6'
    )
    public_A_y = (
        'dc809c49 652aeb6d 63329abf 5a52155c 766345c2 8fed3024 741c8ed0 1589d28b'
    )
    public_B_x = (
        '1ea1f0f0 1faf1d96 09592284 f19e4c00 47b58afd 8615a69f 559077b2 2faaa190'
    )
    public_B_y = (
        '4c55f33e 429dad37 7356703a 9ab85160 472d1130 e28e3676 5f89aff9 15b1214a'
    )
    dhkey = 'ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698'

    key_a = EccKey.from_private_key_bytes(
        bytes.fromhex(private_A), bytes.fromhex(public_A_x), bytes.fromhex(public_A_y)
    )
    shared_key = key_a.dh(bytes.fromhex(public_B_x), bytes.fromhex(public_B_y))
    assert shared_key == bytes.fromhex(dhkey)

    key_b = EccKey.from_private_key_bytes(
        bytes.fromhex(private_B), bytes.fromhex(public_B_x), bytes.fromhex(public_B_y)
    )
    shared_key = key_b.dh(bytes.fromhex(public_A_x), bytes.fromhex(public_A_y))
    assert shared_key == bytes.fromhex(dhkey)


# -----------------------------------------------------------------------------
def test_c1():
    k = bytes(16)
    r = reversed_hex('5783D52156AD6F0E6388274EC6702EE0')
    pres = reversed_hex('05000800000302')
    preq = reversed_hex('07071000000101')
    iat = 1
    ia = reversed_hex('A1A2A3A4A5A6')
    rat = 0
    ra = reversed_hex('B1B2B3B4B5B6')
    result = c1(k, r, preq, pres, iat, rat, ia, ra)
    assert result == reversed_hex('1e1e3fef878988ead2a74dc5bef13b86')


# -----------------------------------------------------------------------------
def test_s1():
    k = bytes(16)
    r1 = reversed_hex('000F0E0D0C0B0A091122334455667788')
    r2 = reversed_hex('010203040506070899AABBCCDDEEFF00')
    result = s1(k, r1, r2)
    assert result == reversed_hex('9a1fe1f0e8b0f49b5b4216ae796da062')


# -----------------------------------------------------------------------------
def test_aes_cmac():
    m = b''
    k = bytes.fromhex('2b7e1516 28aed2a6 abf71588 09cf4f3c')
    cmac = aes_cmac(m, k)
    assert cmac == bytes.fromhex('bb1d6929 e9593728 7fa37d12 9b756746')

    m = bytes.fromhex('6bc1bee2 2e409f96 e93d7e11 7393172a')
    cmac = aes_cmac(m, k)
    assert cmac == bytes.fromhex('070a16b4 6b4d4144 f79bdd9d d04a287c')

    m = bytes.fromhex(
        '6bc1bee2 2e409f96 e93d7e11 7393172a'
        + 'ae2d8a57 1e03ac9c 9eb76fac 45af8e51'
        + '30c81c46 a35ce411'
    )
    cmac = aes_cmac(m, k)
    assert cmac == bytes.fromhex('dfa66747 de9ae630 30ca3261 1497c827')

    m = bytes.fromhex(
        '6bc1bee2 2e409f96 e93d7e11 7393172a'
        + 'ae2d8a57 1e03ac9c 9eb76fac 45af8e51'
        + '30c81c46 a35ce411 e5fbc119 1a0a52ef'
        + 'f69f2445 df4f9b17 ad2b417b e66c3710'
    )
    cmac = aes_cmac(m, k)
    assert cmac == bytes.fromhex('51f0bebf 7e3b9d92 fc497417 79363cfe')


# -----------------------------------------------------------------------------
def test_f4():
    u = reversed_hex(
        '20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6'
    )
    v = reversed_hex(
        '55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd'
    )
    x = reversed_hex('d5cb8454 d177733e ffffb2ec 712baeab')
    z = b'\0'
    value = f4(u, v, x, z)
    assert value == reversed_hex('f2c916f1 07a9bd1c f1eda1be a974872d')


# -----------------------------------------------------------------------------
def test_f5():
    w = reversed_hex(
        'ec0234a3 57c8ad05 341010a6 0a397d9b 99796b13 b4f866f1 868d34f3 73bfa698'
    )
    n1 = reversed_hex('d5cb8454 d177733e ffffb2ec 712baeab')
    n2 = reversed_hex('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf')
    a1 = reversed_hex('00561237 37bfce')
    a2 = reversed_hex('00a71370 2dcfc1')
    value = f5(w, n1, n2, a1, a2)
    assert value[0] == reversed_hex('2965f176 a1084a02 fd3f6a20 ce636e20')
    assert value[1] == reversed_hex('69867911 69d7cd23 980522b5 94750a38')


# -----------------------------------------------------------------------------
def test_f6():
    n1 = reversed_hex('d5cb8454 d177733e ffffb2ec 712baeab')
    n2 = reversed_hex('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf')
    mac_key = reversed_hex('2965f176 a1084a02 fd3f6a20 ce636e20')
    r = reversed_hex('12a3343b b453bb54 08da42d2 0c2d0fc8')
    io_cap = reversed_hex('010102')
    a1 = reversed_hex('00561237 37bfce')
    a2 = reversed_hex('00a71370 2dcfc1')
    value = f6(mac_key, n1, n2, r, io_cap, a1, a2)
    assert value == reversed_hex('e3c47398 9cd0e8c5 d26c0b09 da958f61')


# -----------------------------------------------------------------------------
def test_g2():
    u = reversed_hex(
        '20b003d2 f297be2c 5e2c83a7 e9f9a5b9 eff49111 acf4fddb cc030148 0e359de6'
    )
    v = reversed_hex(
        '55188b3d 32f6bb9a 900afcfb eed4e72a 59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd'
    )
    x = reversed_hex('d5cb8454 d177733e ffffb2ec 712baeab')
    y = reversed_hex('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf')
    value = g2(u, v, x, y)
    assert value == 0x2F9ED5BA


# -----------------------------------------------------------------------------
def test_h6():
    KEY = reversed_hex('ec0234a3 57c8ad05 341010a6 0a397d9b')
    KEY_ID = bytes.fromhex('6c656272')
    assert h6(KEY, KEY_ID) == reversed_hex('2d9ae102 e76dc91c e8d3a9e2 80b16399')


# -----------------------------------------------------------------------------
def test_h7():
    KEY = reversed_hex('ec0234a3 57c8ad05 341010a6 0a397d9b')
    SALT = bytes.fromhex('00000000 00000000 00000000 746D7031')
    assert h7(SALT, KEY) == reversed_hex('fb173597 c6a3c0ec d2998c2a 75a57011')


# -----------------------------------------------------------------------------
def test_ah():
    irk = reversed_hex('ec0234a3 57c8ad05 341010a6 0a397d9b')
    prand = reversed_hex('708194')
    value = ah(irk, prand)
    expected = reversed_hex('0dfbaa')
    assert value == expected


# -----------------------------------------------------------------------------
def test_oob_data():
    oob_data = OobData(
        address=Address("F0:F1:F2:F3:F4:F5"),
        role=LeRole.BOTH_PERIPHERAL_PREFERRED,
        shared_data=OobSharedData(c=b'12', r=b'34'),
    )
    oob_data_ad = oob_data.to_ad()
    oob_data_bytes = bytes(oob_data_ad)
    oob_data_ad_parsed = AdvertisingData.from_bytes(oob_data_bytes)
    oob_data_parsed = OobData.from_ad(oob_data_ad_parsed)
    assert oob_data_parsed.address == oob_data.address
    assert oob_data_parsed.role == oob_data.role
    assert oob_data_parsed.shared_data.c == oob_data.shared_data.c
    assert oob_data_parsed.shared_data.r == oob_data.shared_data.r


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'ct2, expected',
    [
        (False, 'bc1ca4ef 633fc1bd 0d8230af ee388fb0'),
        (True, '287ad379 dca40253 0a39f1f4 3047b835'),
    ],
)
def test_ltk_to_link_key(ct2: bool, expected: str):
    LTK = reversed_hex('368df9bc e3264b58 bd066c33 334fbf64')
    assert smp.Session.derive_link_key(LTK, ct2) == reversed_hex(expected)


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'ct2, expected',
    [
        (False, 'a813fb72 f1a3dfa1 8a2c9a43 f10d0a30'),
        (True, 'e85e09eb 5eccb3e2 69418a13 3211bc79'),
    ],
)
def test_link_key_to_ltk(ct2: bool, expected: str):
    LINK_KEY = reversed_hex('05040302 01000908 07060504 03020100')
    assert smp.Session.derive_ltk(LINK_KEY, ct2) == reversed_hex(expected)


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_ecc()
    test_c1()
    test_s1()
    test_aes_cmac()
    test_f4()
    test_f5()
    test_f6()
    test_g2()
    test_h6()
    test_h7()
    test_ah()
    test_oob_data()
