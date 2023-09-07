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
import abc
import logging
import pathlib
import platform
from . import rtk


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class Driver(abc.ABC):
    """Base class for drivers."""

    @staticmethod
    async def for_host(_host):
        """Return a driver instance for a host.

        Args:
            host: Host object for which a driver should be created.

        Returns:
            A Driver instance if a driver should be instantiated for this host, or
            None if no driver instance of this class is needed.
        """
        return None

    @abc.abstractmethod
    async def init_controller(self):
        """Initialize the controller."""


# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
async def get_driver_for_host(host):
    """Probe all known diver classes until one returns a valid instance for a host,
    or none is found.
    """
    if driver := await rtk.Driver.for_host(host):
        logger.debug("Instantiated RTK driver")
        return driver

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
