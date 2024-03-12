# Copyright 2024 Google LLC
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

from bumble.drivers import common
from bumble.hci import (
    hci_vendor_command_op_code,  # type: ignore
    HCI_Command,
    HCI_Reset_Command,
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# HCI Commands
# -----------------------------------------------------------------------------
HCI_INTEL_DDC_CONFIG_WRITE_COMMAND = hci_vendor_command_op_code(0xFC8B)  # type: ignore
HCI_INTEL_DDC_CONFIG_WRITE_PAYLOAD = [0x03, 0xE4, 0x02, 0x00]

HCI_Command.register_commands(globals())


@HCI_Command.command(  # type: ignore
    fields=[("params", "*")],
    return_parameters_fields=[
        ("params", "*"),
    ],
)
class Hci_Intel_DDC_Config_Write_Command(HCI_Command):
    pass


class Driver(common.Driver):
    def __init__(self, host):
        self.host = host

    @classmethod
    async def for_host(cls, host):  # type: ignore
        # Only instantiate this driver if explicitly selected
        if host.hci_metadata.get("driver") == "intel":
            return cls(host)

        return None

    async def init_controller(self):
        self.host.ready = True
        await self.host.send_command(HCI_Reset_Command(), check_result=True)
        await self.host.send_command(
            Hci_Intel_DDC_Config_Write_Command(
                params=HCI_INTEL_DDC_CONFIG_WRITE_PAYLOAD
            )
        )
