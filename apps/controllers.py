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
import logging
import asyncio
import os

import click

from bumble.controller import Controller, Options
from bumble.link import LocalLink
from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def async_main(extended_advertising, transport_names):
    # Create a local link to attach the controllers to
    link = LocalLink()

    # Create a transport and controller for all requested names
    transports = []
    controllers = []
    options = Options(extended_advertising=extended_advertising)
    for index, transport_name in enumerate(transport_names):
        transport = await open_transport_or_link(transport_name)
        transports.append(transport)
        controller = Controller(
            f'C{index}',
            host_source=transport.source,
            host_sink=transport.sink,
            link=link,
            options=options,
        )
        controllers.append(controller)

    # Wait until the user interrupts
    await asyncio.get_running_loop().create_future()

    # Cleanup
    for transport in transports:
        transport.close()


# -----------------------------------------------------------------------------
@click.command()
@click.option(
    '--extended-advertising', is_flag=True, help="Enable extended advertising"
)
@click.argument('transports', nargs=-1, required=True)
def main(extended_advertising, transports):
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())
    asyncio.run(async_main(extended_advertising, transports))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
