# Copyright 2025 Google LLC
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
import functools
import logging
import os

from bumble import colors


# -----------------------------------------------------------------------------
class ColorFormatter(logging.Formatter):
    _colorizers = {
        logging.DEBUG: functools.partial(colors.color, fg="white"),
        logging.INFO: functools.partial(colors.color, fg="green"),
        logging.WARNING: functools.partial(colors.color, fg="yellow"),
        logging.ERROR: functools.partial(colors.color, fg="red"),
        logging.CRITICAL: functools.partial(colors.color, fg="black", bg="red"),
    }

    _formatters = {
        level: logging.Formatter(
            fmt=colorizer("{asctime}.{msecs:03.0f} {levelname:.1} {name}: ")
            + "{message}",
            datefmt="%H:%M:%S",
            style="{",
        )
        for level, colorizer in _colorizers.items()
    }

    def format(self, record: logging.LogRecord) -> str:
        return self._formatters[record.levelno].format(record)


def setup_basic_logging(default_level: str = "INFO") -> None:
    """
    Set up basic logging with logging.basicConfig, configured with a simple formatter
    that prints out the date and log level in color.
    If the BUMBLE_LOGLEVEL environment variable is set to the name of a log level, it
    is used. Otherwise the default_level argument is used.

    Args:
      default_level: default logging level

    """
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter())
    logging.basicConfig(
        level=os.environ.get("BUMBLE_LOGLEVEL", default_level).upper(),
        handlers=[handler],
    )
