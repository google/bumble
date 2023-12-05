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
import asyncio
import logging
import click
import os

from bumble import transport as bumbleTransport
from bumble.host import Host
from bumble.drivers import intel

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def do_load(transport: str, force: bool):
    async with await bumbleTransport.open_transport(transport) as (
        hci_source,
        hci_sink,
    ):
        # Create a host to communicate with the device
        host = Host(hci_source, hci_sink)

        driver = await intel.Driver.for_host(host, force)
        if not driver:
            print("Firmware already loaded or no supported driver for this device.")
            return

        try:
            await driver.init_controller()
        except Exception as e:
            print(f"Unable to load firmware: {e}")
            return


# -----------------------------------------------------------------------------
async def do_info(transport: str, force: bool):
    async with await bumbleTransport.open_transport(transport) as (
        hci_source,
        hci_sink,
    ):
        # Create a host to communicate with the device
        host = Host(hci_source, hci_sink)  # type: ignore
        if not force and not intel.Driver.check(host):  # type: ignore
            print("Device not supported by this Intel driver")
            return

        version = await intel.fetch_intel_version(host)  # type: ignore
        if not version:
            print("Device not supported by this Intel driver")
            return
        try:
            (fw, fw_name) = intel.prepare_firmware(version)
            fw_path = intel.Driver.find_binary_path(fw_name)
            (boot_addr, fw_version) = intel.fetch_boot_addr(fw)
            print("Driver:")
            print(f"Firmware image: {fw_name}")
            print(f"Firmware path: {fw_path}")
            print(f"Firmware version: {fw_version}")
            print(f"Firmware boot address: {hex(boot_addr)}")
        except Exception as e:
            print(
                f"Firmware already loaded or no supported driver for this device: {e}"
            )


# -----------------------------------------------------------------------------
async def do_reboot_bootloader(transport: str, force: bool):
    async with await bumbleTransport.open_transport(transport) as (
        hci_source,
        hci_sink,
    ):
        # Create a host to communicate with the device
        host = Host(hci_source, hci_sink)  # type: ignore
        if not force and not intel.Driver.check(host):  # type: ignore
            print("Device not supported by this Intel driver")
            return

        await intel.reboot_bootloader(host)  # type: ignore


# -----------------------------------------------------------------------------
@click.group()
def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())


@main.command
@click.argument("transport")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Load the firmware even if the device info doesn't match",
)
def load(transport: str, force: bool):
    """Load a firmware image into the Bluetooth dongle"""
    asyncio.run(do_load(transport, force))


@main.command
@click.argument("transport")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Try to get the device info even if the USB info doesn't match",
)
def info(transport: str, force: bool):
    """Get the firmware info from a transport"""
    asyncio.run(do_info(transport, force))


@main.command
@click.argument("transport")
@click.option(
    "--force", is_flag=True, default=False, help="Force the reset in bootloader state"
)
def reboot_bootloader(transport: str, force: bool):
    """Reboot the device in bootloader state"""
    asyncio.run(do_reboot_bootloader(transport, force))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
