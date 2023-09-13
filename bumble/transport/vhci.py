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

from typing import Optional

from .common import Transport
from .file import open_file_transport

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_vhci_transport(spec: Optional[str]) -> Transport:
    '''
    Open a VHCI transport (only available on some platforms).
    The parameter string is either empty (to use the default VHCI device
    path at /dev/vhci), or the path of a VHCI device
    '''

    HCI_VENDOR_PKT = 0xFF
    HCI_BREDR = 0x00  # Controller type

    # Open the VHCI device
    transport = await open_file_transport(spec or '/dev/vhci')

    # Override the source's `data_received` method so that we can
    # filter out the vendor packet that is received just after the
    # initial open
    def vhci_data_received(data: bytes) -> None:
        if len(data) > 0 and data[0] == HCI_VENDOR_PKT:
            if len(data) == 4:
                hci_index = data[2] << 8 | data[3]
                logger.info(f'HCI index {hci_index}')
        else:
            transport.source.parser.feed_data(data)  # type: ignore

    transport.source.data_received = vhci_data_received  # type: ignore

    # Write the initial config
    transport.sink.on_packet(bytes([HCI_VENDOR_PKT, HCI_BREDR]))

    return transport
