# Copyright 2026 Google LLC
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
from collections.abc import Callable

import bumble.logging
from bumble.core import BaseError
from bumble.device import Connection, Device
from bumble.hci import Address, LeFeatureMask
from bumble.transport import open_transport

# -----------------------------------------------------------------------------
DEFAULT_CENTRAL_ADDRESS = Address("F0:F0:F0:F0:F0:F0")
DEFAULT_PERIPHERAL_ADDRESS = Address("F1:F1:F1:F1:F1:F1")


# -----------------------------------------------------------------------------
async def run_as_central(
    device: Device,
    scenario: Callable | None,
) -> None:
    # Connect to the peripheral
    print(f'=== Connecting to {DEFAULT_PERIPHERAL_ADDRESS}...')
    connection = await device.connect(DEFAULT_PERIPHERAL_ADDRESS)
    print("=== Connected")

    if scenario is not None:
        await asyncio.sleep(1)
        await scenario(connection)

    await asyncio.get_running_loop().create_future()


async def run_as_peripheral(device: Device, scenario: Callable | None) -> None:
    # Wait for a connection from the central
    print(f'=== Advertising as {DEFAULT_PERIPHERAL_ADDRESS}...')
    await device.start_advertising(auto_restart=True)

    async def on_connection(connection: Connection) -> None:
        assert scenario is not None
        await asyncio.sleep(1)
        await scenario(connection)

    if scenario is not None:
        device.on(Device.EVENT_CONNECTION, on_connection)

    await asyncio.get_running_loop().create_future()


async def change_parameters(
    connection: Connection,
    parameter_request_procedure_supported: bool,
    subrating_supported: bool,
    shorter_connection_intervals_supported: bool,
) -> None:
    if parameter_request_procedure_supported:
        try:
            print(">>> update_parameters(7.5, 200, 0, 4000)")
            await connection.update_parameters(7.5, 200, 0, 4000)
            await asyncio.sleep(3)
        except BaseError as error:
            print(f"Error: {error}")

    if subrating_supported:
        try:
            print(">>> update_subrate(1, 2, 2, 1, 4000)")
            await connection.update_subrate(1, 2, 2, 1, 4000)
            await asyncio.sleep(3)
        except BaseError as error:
            print(f"Error: {error}")

    if shorter_connection_intervals_supported:
        try:
            print(
                ">>> update_parameters_with_subrate(7.5, 200, 1, 1, 0, 0, 4000, 5, 1000)"
            )
            await connection.update_parameters_with_subrate(
                7.5, 200, 1, 1, 0, 0, 4000, 5, 1000
            )
            await asyncio.sleep(3)
        except BaseError as error:
            print(f"Error: {error}")

        try:
            print(
                ">>> update_parameters_with_subrate(0.750, 5, 1, 1, 0, 0, 4000, 0.125, 1000)"
            )
            await connection.update_parameters_with_subrate(
                0.750, 5, 1, 1, 0, 0, 4000, 0.125, 1000
            )
            await asyncio.sleep(3)
        except BaseError as error:
            print(f"Error: {error}")

    print(">>> done")


def on_connection(connection: Connection) -> None:
    print(f"+++ Connection established: {connection}")

    def on_le_remote_features_change() -> None:
        print(f'... LE Remote Features change: {connection.peer_le_features.name}')

    connection.on(
        connection.EVENT_LE_REMOTE_FEATURES_CHANGE, on_le_remote_features_change
    )

    def on_connection_parameters_change() -> None:
        print(f'... LE Connection Parameters change: {connection.parameters}')

    connection.on(
        connection.EVENT_CONNECTION_PARAMETERS_UPDATE, on_connection_parameters_change
    )


async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_connection_updates.py <transport-spec> '
            'central|peripheral initiator|responder'
        )
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[1]) as hci_transport:
        print('<<< connected')

        role = sys.argv[2]
        direction = sys.argv[3]
        device = Device.with_hci(
            role,
            (
                DEFAULT_CENTRAL_ADDRESS
                if role == "central"
                else DEFAULT_PERIPHERAL_ADDRESS
            ),
            hci_transport.source,
            hci_transport.sink,
        )
        device.le_subrate_enabled = True
        device.le_shorter_connection_intervals_enabled = True
        await device.power_on()

        parameter_request_procedure_supported = device.supports_le_features(
            LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE
        )
        print(
            "Parameters Request Procedure supported: "
            f"{parameter_request_procedure_supported}"
        )

        subrating_supported = device.supports_le_features(
            LeFeatureMask.CONNECTION_SUBRATING
        )
        print(f"Subrating supported: {subrating_supported}")

        shorter_connection_intervals_supported = device.supports_le_features(
            LeFeatureMask.SHORTER_CONNECTION_INTERVALS
        )
        print(
            "Shorter Connection Intervals supported: "
            f"{shorter_connection_intervals_supported}"
        )

        device.on(Device.EVENT_CONNECTION, on_connection)

        async def run(connection: Connection) -> None:
            await change_parameters(
                connection,
                parameter_request_procedure_supported,
                subrating_supported,
                shorter_connection_intervals_supported,
            )

        scenario = run if direction == "initiator" else None

        if role == "central":
            await run_as_central(device, scenario)
        else:
            await run_as_peripheral(device, scenario)


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
