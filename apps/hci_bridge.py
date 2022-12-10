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
import sys

from bumble import hci, transport
from bumble.bridge import HCI_Bridge

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
async def async_main():
    if len(sys.argv) < 3:
        print(
            'Usage: hci_bridge.py <host-transport-spec> <controller-transport-spec> '
            '[command-short-circuit-list]'
        )
        print(
            'example: python hci_bridge.py udp:0.0.0.0:9000,127.0.0.1:9001 '
            'serial:/dev/tty.usbmodem0006839912171,1000000 '
            '0x3f:0x0070,0x3f:0x0074,0x3f:0x0077,0x3f:0x0078'
        )
        return

    print('>>> connecting to HCI...')
    async with await transport.open_transport_or_link(sys.argv[1]) as (
        hci_host_source,
        hci_host_sink,
    ):
        print('>>> connected')

        print('>>> connecting to HCI...')
        async with await transport.open_transport_or_link(sys.argv[2]) as (
            hci_controller_source,
            hci_controller_sink,
        ):
            print('>>> connected')

            command_short_circuits = []
            if len(sys.argv) >= 4:
                for op_code_str in sys.argv[3].split(','):
                    if ':' in op_code_str:
                        ogf, ocf = op_code_str.split(':')
                        command_short_circuits.append(
                            hci.hci_command_op_code(int(ogf, 16), int(ocf, 16))
                        )
                    else:
                        command_short_circuits.append(int(op_code_str, 16))

            def host_to_controller_filter(hci_packet):
                if (
                    hci_packet.hci_packet_type == hci.HCI_COMMAND_PACKET
                    and hci_packet.op_code in command_short_circuits
                ):
                    # Respond with a success response
                    logger.debug('short-circuiting packet')
                    response = hci.HCI_Command_Complete_Event(
                        num_hci_command_packets=1,
                        command_opcode=hci_packet.op_code,
                        return_parameters=bytes([hci.HCI_SUCCESS]),
                    )
                    # Return a packet with 'respond to sender' set to True
                    return (response.to_bytes(), True)

                return None

            _ = HCI_Bridge(
                hci_host_source,
                hci_host_sink,
                hci_controller_source,
                hci_controller_sink,
                host_to_controller_filter,
                None,
            )
            await asyncio.get_running_loop().create_future()


# -----------------------------------------------------------------------------
def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(async_main())


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
