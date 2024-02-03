# Copyright 2021-2024 Google LLC
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
import logging
import pytest

from bumble.controller import Controller
from bumble.host import Host
from bumble.transport import AsyncPipeSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'supported_commands, lmp_features',
    [
        (
            # Default commands
            '2000800000c000000000e4000000a822000000000000040000f7ffff7f000000'
            '30f0f9ff01008004000000000000000000000000000000000000000000000000',
            # Only LE LMP feature
            '0000000060000000',
        ),
        (
            # All commands
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
            # 3 pages of LMP features
            '000102030405060708090A0B0C0D0E0F011112131415161718191A1B1C1D1E1F',
        ),
    ],
)
async def test_reset(supported_commands: str, lmp_features: str):
    controller = Controller('C')
    controller.supported_commands = bytes.fromhex(supported_commands)
    controller.lmp_features = bytes.fromhex(lmp_features)
    host = Host(controller, AsyncPipeSink(controller))

    await host.reset()

    assert host.local_lmp_features == int.from_bytes(
        bytes.fromhex(lmp_features), 'little'
    )
