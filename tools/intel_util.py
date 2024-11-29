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
import asyncio
import os
from typing import Any, Optional

import click

from bumble.colors import color
from bumble import transport
from bumble.drivers import intel
from bumble.host import Host

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def print_device_info(device_info: dict[intel.ValueType, Any]) -> None:
    if (mode := device_info.get(intel.ValueType.CURRENT_MODE_OF_OPERATION)) is not None:
        print(
            color("MODE:", "yellow"),
            mode.name,
        )
    print(color("DETAILS:", "yellow"))
    for key, value in device_info.items():
        print(f"  {color(key.name, 'green')}: {value}")


# -----------------------------------------------------------------------------
async def get_driver(host: Host, force: bool) -> Optional[intel.Driver]:
    # Create a driver
    driver = await intel.Driver.for_host(host, force)
    if driver is None:
        print("Device does not appear to be an Intel device")
        return None

    return driver


# -----------------------------------------------------------------------------
async def do_info(usb_transport, force):
    async with await transport.open_transport(usb_transport) as (
        hci_source,
        hci_sink,
    ):
        host = Host(hci_source, hci_sink)
        driver = await get_driver(host, force)
        if driver is None:
            return

        # Get and print the device info
        print_device_info(await driver.read_device_info())


# -----------------------------------------------------------------------------
async def do_load(usb_transport: str, force: bool) -> None:
    async with await transport.open_transport(usb_transport) as (
        hci_source,
        hci_sink,
    ):
        host = Host(hci_source, hci_sink)
        driver = await get_driver(host, force)
        if driver is None:
            return

        # Reboot in bootloader mode
        await driver.load_firmware()

        # Get and print the device info
        print_device_info(await driver.read_device_info())


# -----------------------------------------------------------------------------
async def do_bootloader(usb_transport: str, force: bool) -> None:
    async with await transport.open_transport(usb_transport) as (
        hci_source,
        hci_sink,
    ):
        host = Host(hci_source, hci_sink)
        driver = await get_driver(host, force)
        if driver is None:
            return

        # Reboot in bootloader mode
        await driver.reboot_bootloader()


# -----------------------------------------------------------------------------
@click.group()
def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())


@main.command
@click.argument("usb_transport")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Try to get the device info even if the USB info doesn't match",
)
def info(usb_transport, force):
    """Get the firmware info."""
    asyncio.run(do_info(usb_transport, force))


@main.command
@click.argument("usb_transport")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Load even if the USB info doesn't match",
)
def load(usb_transport, force):
    """Load a firmware image."""
    asyncio.run(do_load(usb_transport, force))


@main.command
@click.argument("usb_transport")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Attempt to reboot event if the USB info doesn't match",
)
def bootloader(usb_transport, force):
    """Reboot in bootloader mode."""
    asyncio.run(do_bootloader(usb_transport, force))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
