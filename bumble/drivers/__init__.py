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
"""
Drivers that can be used to customize the interaction between a host and a controller,
like loading firmware after a cold start.
"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import logging
import pathlib
import platform
from collections.abc import Iterable
from typing import TYPE_CHECKING

from bumble.drivers import intel, rtk
from bumble.drivers.common import Driver

if TYPE_CHECKING:
    from bumble.host import Host

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
async def get_driver_for_host(host: Host) -> Driver | None:
    """Probe diver classes until one returns a valid instance for a host, or none is
    found.
    If a "driver" HCI metadata entry is present, only that driver class will be probed.
    """
    driver_classes: dict[str, type[Driver]] = {"rtk": rtk.Driver, "intel": intel.Driver}
    probe_list: Iterable[str]
    if driver_name := host.hci_metadata.get("driver"):
        # The "driver" metadata may include runtime options after a '/' (for example
        # "intel/ddc=..."). Keep only the base driver name (the portion before the
        # first slash) so it matches a key in driver_classes (e.g. "intel").
        driver_name = driver_name.split("/")[0]
        # Only probe a single driver
        probe_list = [driver_name]
    else:
        # Probe all drivers
        probe_list = driver_classes.keys()

    for driver_name in probe_list:
        if driver_class := driver_classes.get(driver_name):
            logger.debug(f"Probing driver class: {driver_name}")
            if driver := await driver_class.for_host(host):
                logger.debug(f"Instantiated {driver_name} driver")
                return driver
        else:
            logger.debug(f"Skipping unknown driver class: {driver_name}")

    return None


def project_data_dir() -> pathlib.Path:
    """
    Returns:
        A path to an OS-specific directory for bumble data. The directory is created if
         it doesn't exist.
    """
    import platformdirs

    if platform.system() == 'Darwin':
        # platformdirs doesn't handle macOS right: it doesn't assemble a bundle id
        # out of author & project
        return platformdirs.user_data_path(
            appname='com.google.bumble', ensure_exists=True
        )
    else:
        # windows and linux don't use the com qualifier
        return platformdirs.user_data_path(
            appname='bumble', appauthor='google', ensure_exists=True
        )
