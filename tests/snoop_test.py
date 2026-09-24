# Copyright 2026 Google LLC
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
import io
import struct

from bumble import hci
from bumble.snoop import BtSnooper, Snooper


# -----------------------------------------------------------------------------
def test_btsnoop_packet_flags():
    output = io.BytesIO()
    snooper = BtSnooper(output)
    snooper.snoop(
        bytes([hci.HCI_COMMAND_PACKET, 0x03, 0x0C, 0x00]),
        Snooper.Direction.HOST_TO_CONTROLLER,
    )
    snooper.snoop(
        bytes([hci.HCI_EVENT_PACKET, 0x0E, 0x00]),
        Snooper.Direction.CONTROLLER_TO_HOST,
    )

    # Bit 0 is the direction, bit 1 is set for commands and events.
    data = output.getvalue()
    assert struct.unpack_from('>I', data, 16 + 8)[0] == 0x02
    assert struct.unpack_from('>I', data, 16 + 24 + 4 + 8)[0] == 0x03
