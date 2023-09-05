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
import logging
import asyncio
import os

import click

from bumble import transport
from bumble.host import Host
from bumble.drivers import rtk

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def do_parse(firmware_path):
    with open(firmware_path, 'rb') as firmware_file:
        firmware_data = firmware_file.read()
        firmware = rtk.Firmware(firmware_data)
        print(
            f"Firmware: version=0x{firmware.version:08X} "
            f"project_id=0x{firmware.project_id:04X}"
        )
        for patch in firmware.patches:
            print(
                f"  Patch: chip_id=0x{patch[0]:04X}, "
                f"{len(patch[1])} bytes, "
                f"SVN Version={patch[2]:08X}"
            )


# -----------------------------------------------------------------------------
async def do_load(usb_transport, force):
    async with await transport.open_transport_or_link(usb_transport) as (
        hci_source,
        hci_sink,
    ):
        # Create a host to communicate with the device
        host = Host(hci_source, hci_sink)
        await host.reset(driver_factory=None)

        # Get the driver.
        driver = await rtk.Driver.for_host(host, force)
        if driver is None:
            print("Firmware already loaded or no supported driver for this device.")
            return

        await driver.download_firmware()


# -----------------------------------------------------------------------------
async def do_drop(usb_transport):
    async with await transport.open_transport_or_link(usb_transport) as (
        hci_source,
        hci_sink,
    ):
        # Create a host to communicate with the device
        host = Host(hci_source, hci_sink)
        await host.reset(driver_factory=None)

        # Tell the device to reset/drop any loaded patch
        await rtk.Driver.drop_firmware(host)


# -----------------------------------------------------------------------------
async def do_info(usb_transport, force):
    async with await transport.open_transport(usb_transport) as (
        hci_source,
        hci_sink,
    ):
        # Create a host to communicate with the device
        host = Host(hci_source, hci_sink)
        await host.reset(driver_factory=None)

        # Check if this is a supported device.
        if not force and not rtk.Driver.check(host):
            print("USB device not supported by this RTK driver")
            return

        # Get the driver info.
        driver_info = await rtk.Driver.driver_info_for_host(host)
        if driver_info:
            print(
                "Driver:\n"
                f"  ROM:      {driver_info.rom:04X}\n"
                f"  Firmware: {driver_info.fw_name}\n"
                f"  Config:   {driver_info.config_name}\n"
            )
        else:
            print("Firmware already loaded or no supported driver for this device.")


# -----------------------------------------------------------------------------
@click.group()
def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())


@main.command
@click.argument("firmware_path")
def parse(firmware_path):
    """Parse a firmware image."""
    do_parse(firmware_path)


@main.command
@click.argument("usb_transport")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Load even if the USB info doesn't match",
)
def load(usb_transport, force):
    """Load a firmware image into the USB dongle."""
    asyncio.run(do_load(usb_transport, force))


@main.command
@click.argument("usb_transport")
def drop(usb_transport):
    """Drop a firmware image from the USB dongle."""
    asyncio.run(do_drop(usb_transport))


@main.command
@click.argument("usb_transport")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Try to get the device info even if the USB info doesn't match",
)
def info(usb_transport, force):
    """Get the firmware info from a USB dongle."""
    asyncio.run(do_info(usb_transport, force))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
