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
import pathlib
import urllib.request
import urllib.error

import click

from bumble.colors import color
from bumble.drivers import intel


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
LINUX_KERNEL_GIT_SOURCE = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/intel"


# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
def download_file(base_url, name):
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
    type=click.Choice(["linux-kernel"]),
    default="linux-kernel",
    show_default=True,
)
@click.option("--single", help="Only download a single image set, by its base name")
@click.option("--force", is_flag=True, help="Overwrite files if they already exist")
def main(output_dir, source, single, force):
    """Download Intel firmware images and configs."""

    # Check that the output dir exists
    if output_dir == '':
        output_dir = intel.intel_firmware_dir()
    else:
        output_dir = pathlib.Path(output_dir)
    if not output_dir.is_dir():
        print("Output dir does not exist or is not a directory")
        return

    base_url = {
        "linux-kernel": LINUX_KERNEL_GIT_SOURCE,
    }[source]

    print("Downloading")
    print(color("FROM:", "green"), base_url)
    print(color("TO:", "green"), output_dir)

    if single:
        images = [(f"{single}.sfi", f"{single}.ddc")]
    else:
        images = [
            (f"{base_name}.sfi", f"{base_name}.ddc")
            for base_name in intel.INTEL_FW_IMAGE_NAMES
        ]

    for fw_name, config_name in images:
        print(color("---", "yellow"))
        fw_image_out = output_dir / fw_name
        if not force and fw_image_out.exists():
            print(color(f"{fw_image_out} already exists, skipping", "red"))
            continue
        if config_name:
            config_image_out = output_dir / config_name
            if not force and config_image_out.exists():
                print(color("f{config_image_out} already exists, skipping", "red"))
                continue

        try:
            fw_image = download_file(base_url, fw_name)
        except urllib.error.HTTPError as error:
            print(f"Failed to download {fw_name}: {error}")
            continue

        config_image = None
        if config_name:
            try:
                config_image = download_file(base_url, config_name)
            except urllib.error.HTTPError as error:
                print(f"Failed to download {config_name}: {error}")
                continue

        fw_image_out.write_bytes(fw_image)
        if config_image:
            config_image_out.write_bytes(config_image)


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
