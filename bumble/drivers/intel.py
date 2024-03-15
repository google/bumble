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
# Constant
# -----------------------------------------------------------------------------

INTEL_USB_PRODUCTS = {
    # Intel AX210
    (0x8087, 0x0032),
    # Intel BE200
    (0x8087, 0x0036),
}

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

    @staticmethod
    def check(host):
        driver = host.hci_metadata.get("driver")
        if driver == "intel":
            return True

        vendor_id = host.hci_metadata.get("vendor_id")
        product_id = host.hci_metadata.get("product_id")

        if vendor_id is None or product_id is None:
            logger.debug("USB metadata not sufficient")
            return False

        if (vendor_id, product_id) not in INTEL_USB_PRODUCTS:
            logger.debug(
                f"USB device ({vendor_id:04X}, {product_id:04X}) " "not in known list"
            )
            return False

        return True

    @classmethod
    async def for_host(cls, host, force=False):  # type: ignore
        # Only instantiate this driver if explicitly selected
        if not force and not cls.check(host):
            return None

        return cls(host)

    async def init_controller(self):
        self.host.ready = True
        await self.host.send_command(HCI_Reset_Command(), check_result=True)
        await self.host.send_command(
            Hci_Intel_DDC_Config_Write_Command(
                params=HCI_INTEL_DDC_CONFIG_WRITE_PAYLOAD
            )
        )
