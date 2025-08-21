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
import asyncio
import sys

import bumble.logging
from bumble.device import Device
from bumble.gatt import Characteristic, Service
from bumble.pairing import PairingConfig, PairingDelegate
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
class FixedPinPairingDelegate(PairingDelegate):
    """
    A PairingDelegate that declares that the device only has the ability to display
    a passkey but not to enter or confirm one. When asked for the passkey to use for
    pairing, this delegate returns a fixed value (instead of the default, which  is
    to generate a random value each time). This is obviously not a secure way to do
    pairing, but it used here as an illustration of how a delegate can override the
    default passkey generation.
    """

    def __init__(self, passkey: int) -> None:
        super().__init__(io_capability=PairingDelegate.IoCapability.DISPLAY_OUTPUT_ONLY)
        self.passkey = passkey

    async def generate_passkey(self) -> int:
        return self.passkey


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_gatt_server_with_pairing_delegate.py <device-config> <transport-spec> '
        )
        print('example: run_gatt_server_with_pairing_delegate.py device1.json usb:0')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device to manage the host
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )

        # Add a service with a single characteristic.
        # The characteristic requires authentication, so reading it on a non-paired
        # connection will return an error.
        custom_service1 = Service(
            '50DB505C-8AC4-4738-8448-3B1D9CC09CC5',
            [
                Characteristic(
                    '486F64C6-4B5F-4B3B-8AFF-EDE134A8446A',
                    Characteristic.Properties.READ,
                    Characteristic.READABLE
                    | Characteristic.READ_REQUIRES_AUTHENTICATION,
                    bytes('hello', 'utf-8'),
                ),
            ],
        )
        device.add_services([custom_service1])

        # Debug print
        for attribute in device.gatt_server.attributes:
            print(attribute)

        # Setup pairing
        device.pairing_config_factory = lambda connection: PairingConfig(
            delegate=FixedPinPairingDelegate(123456)
        )

        # Get things going
        await device.power_on()

        # Connect to a peer
        if len(sys.argv) > 3:
            target_address = sys.argv[3]
            print(f'=== Connecting to {target_address}...')
            await device.connect(target_address)
        else:
            await device.start_advertising(auto_restart=True)

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
