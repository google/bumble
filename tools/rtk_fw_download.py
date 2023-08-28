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
import pathlib
import urllib.request
import urllib.error

import click

from bumble.colors import color
from bumble.drivers import rtk
from bumble.tools import rtk_util


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
LINUX_KERNEL_GIT_SOURCE = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/rtl_bt",
    False,
)
REALTEK_OPENSOURCE_SOURCE = (
    "https://github.com/Realtek-OpenSource/android_hardware_realtek/raw/rtk1395/bt/rtkbt/Firmware/BT",
    True,
)
LINUX_FROM_SCRATCH_SOURCE = (
    "https://anduin.linuxfromscratch.org/sources/linux-firmware/rtl_bt",
    False,
)

# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
def download_file(base_url, name, remove_suffix):
    if remove_suffix:
        name = name.replace(".bin", "")

    url = f"{base_url}/{name}"
    with urllib.request.urlopen(url) as file:
        data = file.read()
        print(f"Downloaded {name}: {len(data)} bytes")
        return data


# -----------------------------------------------------------------------------
@click.command
@click.option(
    "--output-dir",
    default="",
    help="Output directory where the files will be saved. Defaults to the OS-specific"
    "app data dir, which the driver will check when trying to find firmware",
    show_default=True,
)
@click.option(
    "--source",
    type=click.Choice(["linux-kernel", "realtek-opensource", "linux-from-scratch"]),
    default="linux-kernel",
    show_default=True,
)
@click.option("--single", help="Only download a single image set, by its base name")
@click.option("--force", is_flag=True, help="Overwrite files if they already exist")
@click.option("--parse", is_flag=True, help="Parse the FW image after saving")
def main(output_dir, source, single, force, parse):
    """Download RTK firmware images and configs."""

    # Check that the output dir exists
    if output_dir == '':
        output_dir = rtk.rtk_firmware_dir()
    else:
        output_dir = pathlib.Path(output_dir)
    if not output_dir.is_dir():
        print("Output dir does not exist or is not a directory")
        return

    base_url, remove_suffix = {
        "linux-kernel": LINUX_KERNEL_GIT_SOURCE,
        "realtek-opensource": REALTEK_OPENSOURCE_SOURCE,
        "linux-from-scratch": LINUX_FROM_SCRATCH_SOURCE,
    }[source]

    print("Downloading")
    print(color("FROM:", "green"), base_url)
    print(color("TO:", "green"), output_dir)

    if single:
        images = [(f"{single}_fw.bin", f"{single}_config.bin", True)]
    else:
        images = [
            (driver_info.fw_name, driver_info.config_name, driver_info.config_needed)
            for driver_info in rtk.Driver.DRIVER_INFOS
        ]

    for (fw_name, config_name, config_needed) in images:
        print(color("---", "yellow"))
        fw_image_out = output_dir / fw_name
        if not force and fw_image_out.exists():
            print(color(f"{fw_image_out} already exists, skipping", "red"))
            continue
        if config_name:
            config_image_out = output_dir / config_name
            if not force and config_image_out.exists():
                print(color("f{config_out} already exists, skipping", "red"))
                continue

        try:
            fw_image = download_file(base_url, fw_name, remove_suffix)
        except urllib.error.HTTPError as error:
            print(f"Failed to download {fw_name}: {error}")
            continue

        config_image = None
        if config_name:
            try:
                config_image = download_file(base_url, config_name, remove_suffix)
            except urllib.error.HTTPError as error:
                if config_needed:
                    print(f"Failed to download {config_name}: {error}")
                    continue
                else:
                    print(f"No config available as {config_name}")

        fw_image_out.write_bytes(fw_image)
        if parse and config_name:
            print(color("Parsing:", "cyan"), fw_name)
            rtk_util.do_parse(fw_image_out)
        if config_image:
            config_image_out.write_bytes(config_image)


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
