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
import asyncio
import sys
import os
import logging

import bumble.core
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import (
    BT_BR_EDR_TRANSPORT,
)
from bumble import rfcomm, hfp
from bumble.hci import HCI_SynchronousDataPacket


logger = logging.getLogger(__name__)


def _default_configuration() -> hfp.AgConfiguration:
    return hfp.AgConfiguration(
        supported_ag_features=[
            hfp.AgFeature.HF_INDICATORS,
            hfp.AgFeature.IN_BAND_RING_TONE_CAPABILITY,
            hfp.AgFeature.REJECT_CALL,
            hfp.AgFeature.CODEC_NEGOTIATION,
            hfp.AgFeature.ESCO_S4_SETTINGS_SUPPORTED,
        ],
        supported_ag_indicators=[
            hfp.AgIndicatorState.call(),
            hfp.AgIndicatorState.service(),
            hfp.AgIndicatorState.callsetup(),
            hfp.AgIndicatorState.callsetup(),
            hfp.AgIndicatorState.signal(),
            hfp.AgIndicatorState.roam(),
            hfp.AgIndicatorState.battchg(),
        ],
        supported_hf_indicators=[
            hfp.HfIndicator.ENHANCED_SAFETY,
            hfp.HfIndicator.BATTERY_LEVEL,
        ],
        supported_ag_call_hold_operations=[],
        supported_audio_codecs=[hfp.AudioCodec.CVSD, hfp.AudioCodec.MSBC],
    )


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 4:
        print(
            'Usage: run_hfp_gateway.py <device-config> <transport-spec> '
            '<bluetooth-address>'
        )
        print(
            '  specifying a channel number, or "discover" to list all RFCOMM channels'
        )
        print('example: run_hfp_gateway.py hfp_gateway.json usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True
        await device.power_on()

        # Connect to a peer
        target_address = sys.argv[3]
        print(f'=== Connecting to {target_address}...')
        connection = await device.connect(target_address, transport=BT_BR_EDR_TRANSPORT)
        print(f'=== Connected to {connection.peer_address}!')

        # Get a list of all the Handsfree services (should only be 1)
        if not (hfp_record := await hfp.find_hf_sdp_record(connection)):
            print('!!! no service found')
            return

        # Pick the first one
        channel, version, hf_sdp_features = hfp_record
        print(f'HF version: {version}')
        print(f'HF features: {hf_sdp_features}')

        # Request authentication
        print('*** Authenticating...')
        await connection.authenticate()
        print('*** Authenticated')

        # Enable encryption
        print('*** Enabling encryption...')
        await connection.encrypt()
        print('*** Encryption on')

        # Create a client and start it
        print('@@@ Starting to RFCOMM client...')
        rfcomm_client = rfcomm.Client(connection)
        rfcomm_mux = await rfcomm_client.start()
        print('@@@ Started')

        print(f'### Opening session for channel {channel}...')
        try:
            session = await rfcomm_mux.open_dlc(channel)
            print('### Session open', session)
        except bumble.core.ConnectionError as error:
            print(f'### Session open failed: {error}')
            await rfcomm_mux.disconnect()
            print('@@@ Disconnected from RFCOMM server')
            return

        def on_sco(connection_handle: int, packet: HCI_SynchronousDataPacket):
            # Reset packet and loopback
            packet.packet_status = 0
            device.host.send_hci_packet(packet)

        device.host.on('sco_packet', on_sco)

        ag_protocol = hfp.AgProtocol(session, _default_configuration())

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
