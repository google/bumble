# Copyright 2021-2023 Google LLC
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
from __future__ import annotations
import enum
from dataclasses import dataclass
from typing import Optional, Tuple

from .hci import (
    Address,
    HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY,
    HCI_DISPLAY_ONLY_IO_CAPABILITY,
    HCI_DISPLAY_YES_NO_IO_CAPABILITY,
    HCI_KEYBOARD_ONLY_IO_CAPABILITY,
)
from .smp import (
    SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY,
    SMP_KEYBOARD_ONLY_IO_CAPABILITY,
    SMP_DISPLAY_ONLY_IO_CAPABILITY,
    SMP_DISPLAY_YES_NO_IO_CAPABILITY,
    SMP_KEYBOARD_DISPLAY_IO_CAPABILITY,
    SMP_ENC_KEY_DISTRIBUTION_FLAG,
    SMP_ID_KEY_DISTRIBUTION_FLAG,
    SMP_SIGN_KEY_DISTRIBUTION_FLAG,
    SMP_LINK_KEY_DISTRIBUTION_FLAG,
    OobContext,
    OobLegacyContext,
    OobSharedData,
)
from .core import AdvertisingData, LeRole


# -----------------------------------------------------------------------------
@dataclass
class OobData:
    """OOB data that can be sent from one device to another."""

    address: Optional[Address] = None
    role: Optional[LeRole] = None
    shared_data: Optional[OobSharedData] = None
    legacy_context: Optional[OobLegacyContext] = None

    @classmethod
    def from_ad(cls, ad: AdvertisingData) -> OobData:
        instance = cls()
        shared_data_c: Optional[bytes] = None
        shared_data_r: Optional[bytes] = None
        for ad_type, ad_data in ad.ad_structures:
            if ad_type == AdvertisingData.LE_BLUETOOTH_DEVICE_ADDRESS:
                instance.address = Address(ad_data)
            elif ad_type == AdvertisingData.LE_ROLE:
                instance.role = LeRole(ad_data[0])
            elif ad_type == AdvertisingData.LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE:
                shared_data_c = ad_data
            elif ad_type == AdvertisingData.LE_SECURE_CONNECTIONS_RANDOM_VALUE:
                shared_data_r = ad_data
            elif ad_type == AdvertisingData.SECURITY_MANAGER_TK_VALUE:
                instance.legacy_context = OobLegacyContext(tk=ad_data)
        if shared_data_c and shared_data_r:
            instance.shared_data = OobSharedData(c=shared_data_c, r=shared_data_r)

        return instance

    def to_ad(self) -> AdvertisingData:
        ad_structures = []
        if self.address is not None:
            ad_structures.append(
                (AdvertisingData.LE_BLUETOOTH_DEVICE_ADDRESS, bytes(self.address))
            )
        if self.role is not None:
            ad_structures.append((AdvertisingData.LE_ROLE, bytes([self.role])))
        if self.shared_data is not None:
            ad_structures.extend(self.shared_data.to_ad().ad_structures)
        if self.legacy_context is not None:
            ad_structures.append(
                (AdvertisingData.SECURITY_MANAGER_TK_VALUE, self.legacy_context.tk)
            )

        return AdvertisingData(ad_structures)


# -----------------------------------------------------------------------------
class PairingDelegate:
    """Abstract base class for Pairing Delegates."""

    # I/O Capabilities.
    # These are defined abstractly, and can be mapped to specific Classic pairing
    # and/or SMP constants.
    class IoCapability(enum.IntEnum):
        NO_OUTPUT_NO_INPUT = SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY
        KEYBOARD_INPUT_ONLY = SMP_KEYBOARD_ONLY_IO_CAPABILITY
        DISPLAY_OUTPUT_ONLY = SMP_DISPLAY_ONLY_IO_CAPABILITY
        DISPLAY_OUTPUT_AND_YES_NO_INPUT = SMP_DISPLAY_YES_NO_IO_CAPABILITY
        DISPLAY_OUTPUT_AND_KEYBOARD_INPUT = SMP_KEYBOARD_DISPLAY_IO_CAPABILITY

    # Direct names for backward compatibility.
    NO_OUTPUT_NO_INPUT = IoCapability.NO_OUTPUT_NO_INPUT
    KEYBOARD_INPUT_ONLY = IoCapability.KEYBOARD_INPUT_ONLY
    DISPLAY_OUTPUT_ONLY = IoCapability.DISPLAY_OUTPUT_ONLY
    DISPLAY_OUTPUT_AND_YES_NO_INPUT = IoCapability.DISPLAY_OUTPUT_AND_YES_NO_INPUT
    DISPLAY_OUTPUT_AND_KEYBOARD_INPUT = IoCapability.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT

    # Key Distribution [LE only]
    class KeyDistribution(enum.IntFlag):
        DISTRIBUTE_ENCRYPTION_KEY = SMP_ENC_KEY_DISTRIBUTION_FLAG
        DISTRIBUTE_IDENTITY_KEY = SMP_ID_KEY_DISTRIBUTION_FLAG
        DISTRIBUTE_SIGNING_KEY = SMP_SIGN_KEY_DISTRIBUTION_FLAG
        DISTRIBUTE_LINK_KEY = SMP_LINK_KEY_DISTRIBUTION_FLAG

    DEFAULT_KEY_DISTRIBUTION: KeyDistribution = (
        KeyDistribution.DISTRIBUTE_ENCRYPTION_KEY
        | KeyDistribution.DISTRIBUTE_IDENTITY_KEY
    )

    # Default mapping from abstract to Classic I/O capabilities.
    # Subclasses may override this if they prefer a different mapping.
    CLASSIC_IO_CAPABILITIES_MAP = {
        NO_OUTPUT_NO_INPUT: HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY,
        KEYBOARD_INPUT_ONLY: HCI_KEYBOARD_ONLY_IO_CAPABILITY,
        DISPLAY_OUTPUT_ONLY: HCI_DISPLAY_ONLY_IO_CAPABILITY,
        DISPLAY_OUTPUT_AND_YES_NO_INPUT: HCI_DISPLAY_YES_NO_IO_CAPABILITY,
        DISPLAY_OUTPUT_AND_KEYBOARD_INPUT: HCI_DISPLAY_YES_NO_IO_CAPABILITY,
    }

    io_capability: IoCapability
    local_initiator_key_distribution: KeyDistribution
    local_responder_key_distribution: KeyDistribution

    def __init__(
        self,
        io_capability: IoCapability = NO_OUTPUT_NO_INPUT,
        local_initiator_key_distribution: KeyDistribution = DEFAULT_KEY_DISTRIBUTION,
        local_responder_key_distribution: KeyDistribution = DEFAULT_KEY_DISTRIBUTION,
    ) -> None:
        self.io_capability = io_capability
        self.local_initiator_key_distribution = local_initiator_key_distribution
        self.local_responder_key_distribution = local_responder_key_distribution

    @property
    def classic_io_capability(self) -> int:
        """Map the abstract I/O capability to a Classic constant."""

        # pylint: disable=line-too-long
        return self.CLASSIC_IO_CAPABILITIES_MAP.get(
            self.io_capability, HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY
        )

    @property
    def smp_io_capability(self) -> int:
        """Map the abstract I/O capability to an SMP constant."""

        # This is just a 1-1 direct mapping
        return self.io_capability

    async def accept(self) -> bool:
        """Accept or reject a Pairing request."""
        return True

    async def confirm(self, auto: bool = False) -> bool:
        """
        Respond yes or no to a Pairing confirmation question.
        The `auto` parameter stands for automatic confirmation.
        """
        return True

    # pylint: disable-next=unused-argument
    async def compare_numbers(self, number: int, digits: int) -> bool:
        """Compare two numbers."""
        return True

    async def get_number(self) -> Optional[int]:
        """
        Return an optional number as an answer to a passkey request.
        Returning `None` will result in a negative reply.
        """
        return 0

    async def get_string(self, max_length: int) -> Optional[str]:
        """
        Return a string whose utf-8 encoding is up to max_length bytes.
        """
        return None

    # pylint: disable-next=unused-argument
    async def display_number(self, number: int, digits: int) -> None:
        """Display a number."""

    # [LE only]
    async def key_distribution_response(
        self, peer_initiator_key_distribution: int, peer_responder_key_distribution: int
    ) -> Tuple[int, int]:
        """
        Return the key distribution response in an SMP protocol context.

        NOTE: since it is only used by the SMP protocol, this method's input and output
        are directly as integers, using the SMP constants, rather than the abstract
        KeyDistribution enums.
        """
        return (
            int(
                peer_initiator_key_distribution & self.local_initiator_key_distribution
            ),
            int(
                peer_responder_key_distribution & self.local_responder_key_distribution
            ),
        )


# -----------------------------------------------------------------------------
class PairingConfig:
    """Configuration for the Pairing protocol."""

    class AddressType(enum.IntEnum):
        PUBLIC = Address.PUBLIC_DEVICE_ADDRESS
        RANDOM = Address.RANDOM_DEVICE_ADDRESS

    @dataclass
    class OobConfig:
        """Config for OOB pairing."""

        our_context: Optional[OobContext]
        peer_data: Optional[OobSharedData]
        legacy_context: Optional[OobLegacyContext]

    def __init__(
        self,
        sc: bool = True,
        mitm: bool = True,
        bonding: bool = True,
        delegate: Optional[PairingDelegate] = None,
        identity_address_type: Optional[AddressType] = None,
        oob: Optional[OobConfig] = None,
    ) -> None:
        self.sc = sc
        self.mitm = mitm
        self.bonding = bonding
        self.delegate = delegate or PairingDelegate()
        self.identity_address_type = identity_address_type
        self.oob = oob

    def __str__(self) -> str:
        return (
            f'PairingConfig(sc={self.sc}, '
            f'mitm={self.mitm}, bonding={self.bonding}, '
            f'identity_address_type={self.identity_address_type}, '
            f'delegate[{self.delegate.io_capability}]), '
            f'oob[{self.oob}])'
        )
