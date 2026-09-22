# Copyright 2021-2026 Google LLC
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

from typing import Any
from unittest import mock

import pytest

from bumble import crypto, pairing, smp
from bumble.core import AdvertisingData
from bumble.device import Device, DeviceConfiguration
from bumble.hci import Address
from bumble.pairing import LeRole, OobData, OobSharedData


# -----------------------------------------------------------------------------
# pylint: disable=invalid-name
# -----------------------------------------------------------------------------
@pytest.fixture(
    scope="session", params=["bumble.crypto.builtin", "bumble.crypto.cryptography"]
)
def crypto_backend(request):
    backend = pytest.importorskip(request.param)
    with (
        mock.patch.object(crypto, "e", backend.e),
        mock.patch.object(crypto, "aes_cmac", backend.aes_cmac),
        mock.patch.object(crypto, "EccKey", backend.EccKey),
    ):
        yield


# -----------------------------------------------------------------------------
def reversed_hex(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)[::-1]


# -----------------------------------------------------------------------------
def test_oob_data(crypto_backend):
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
def test_ltk_to_link_key(ct2: bool, expected: str, crypto_backend: Any):
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
def test_link_key_to_ltk(ct2: bool, expected: str, crypto_backend: Any):
    LINK_KEY = reversed_hex('05040302 01000908 07060504 03020100')
    assert smp.Session.derive_ltk(LINK_KEY, ct2) == reversed_hex(expected)


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'identity_address_type, public_address, random_address, expected_identity_address',
    [
        (
            None,
            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
        ),
        (
            None,
            Address.ANY,
            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
        ),
        (
            pairing.PairingConfig.AddressType.PUBLIC,
            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
        ),
        (
            pairing.PairingConfig.AddressType.RANDOM,
            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
        ),
    ],
)
@pytest.mark.asyncio
async def test_send_identity_address_command(
    identity_address_type: pairing.PairingConfig.AddressType | None,
    public_address: Address,
    random_address: Address,
    expected_identity_address: Address,
    crypto_backend: Any,
):
    device = Device()
    device.public_address = public_address
    device.static_address = random_address
    pairing_config = pairing.PairingConfig(identity_address_type=identity_address_type)
    session = smp.Session(device.smp_manager, mock.MagicMock(), pairing_config, True)

    with mock.patch.object(session, 'send_command') as mock_method:
        session.send_identity_address_command()

    actual_command = mock_method.call_args.args[0]
    assert actual_command.addr_type == expected_identity_address.address_type
    assert actual_command.bd_addr == expected_identity_address


@pytest.mark.asyncio
async def test_smp_debug_mode():
    config = DeviceConfiguration(smp_debug_mode=True)
    device = Device(config=config)

    assert device.smp_manager.ecc_key.x == smp.SMP_DEBUG_KEY_PUBLIC_X
    assert device.smp_manager.ecc_key.y == smp.SMP_DEBUG_KEY_PUBLIC_Y

    device.smp_manager.debug_mode = False

    assert not device.smp_manager.ecc_key.x == smp.SMP_DEBUG_KEY_PUBLIC_X
    assert not device.smp_manager.ecc_key.y == smp.SMP_DEBUG_KEY_PUBLIC_Y
