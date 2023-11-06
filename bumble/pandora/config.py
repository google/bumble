# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations
from bumble.pairing import PairingConfig, PairingDelegate
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class Config:
    io_capability: PairingDelegate.IoCapability = PairingDelegate.NO_OUTPUT_NO_INPUT
    identity_address_type: PairingConfig.AddressType = PairingConfig.AddressType.RANDOM
    pairing_sc_enable: bool = True
    pairing_mitm_enable: bool = True
    pairing_bonding_enable: bool = True
    smp_local_initiator_key_distribution: PairingDelegate.KeyDistribution = (
        PairingDelegate.DEFAULT_KEY_DISTRIBUTION
    )
    smp_local_responder_key_distribution: PairingDelegate.KeyDistribution = (
        PairingDelegate.DEFAULT_KEY_DISTRIBUTION
    )

    def load_from_dict(self, config: Dict[str, Any]) -> None:
        io_capability_name: str = config.get(
            'io_capability', 'no_output_no_input'
        ).upper()
        self.io_capability = getattr(PairingDelegate, io_capability_name)
        identity_address_type_name: str = config.get(
            'identity_address_type', 'random'
        ).upper()
        self.identity_address_type = getattr(
            PairingConfig.AddressType, identity_address_type_name
        )
        self.pairing_sc_enable = config.get('pairing_sc_enable', True)
        self.pairing_mitm_enable = config.get('pairing_mitm_enable', True)
        self.pairing_bonding_enable = config.get('pairing_bonding_enable', True)
        self.smp_local_initiator_key_distribution = config.get(
            'smp_local_initiator_key_distribution',
            PairingDelegate.DEFAULT_KEY_DISTRIBUTION,
        )
        self.smp_local_responder_key_distribution = config.get(
            'smp_local_responder_key_distribution',
            PairingDelegate.DEFAULT_KEY_DISTRIBUTION,
        )
