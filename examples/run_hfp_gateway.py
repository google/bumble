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
import json
import sys
import os
import io
import logging
import websockets

from typing import Optional

import bumble.core
from bumble.device import Device, ScoLink
from bumble.transport import open_transport_or_link
from bumble.core import (
    BT_BR_EDR_TRANSPORT,
)
from bumble import hci, rfcomm, hfp


logger = logging.getLogger(__name__)

ws: Optional[websockets.WebSocketServerProtocol] = None
ag_protocol: Optional[hfp.AgProtocol] = None
source_file: Optional[io.BufferedReader] = None


def _default_configuration() -> hfp.AgConfiguration:
    return hfp.AgConfiguration(
        supported_ag_features=[
            hfp.AgFeature.HF_INDICATORS,
            hfp.AgFeature.IN_BAND_RING_TONE_CAPABILITY,
            hfp.AgFeature.REJECT_CALL,
            hfp.AgFeature.CODEC_NEGOTIATION,
            hfp.AgFeature.ESCO_S4_SETTINGS_SUPPORTED,
            hfp.AgFeature.ENHANCED_CALL_STATUS,
        ],
        supported_ag_indicators=[
            hfp.AgIndicatorState.call(),
            hfp.AgIndicatorState.callsetup(),
            hfp.AgIndicatorState.callheld(),
            hfp.AgIndicatorState.service(),
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


def send_message(type: str, **kwargs) -> None:
    if ws:
        asyncio.create_task(ws.send(json.dumps({'type': type, **kwargs})))


def on_speaker_volume(level: int):
    send_message(type='speaker_volume', level=level)


def on_microphone_volume(level: int):
    send_message(type='microphone_volume', level=level)


def on_sco_state_change(codec: int):
    if codec == hfp.AudioCodec.CVSD:
        sample_rate = 8000
    elif codec == hfp.AudioCodec.MSBC:
        sample_rate = 16000
    else:
        sample_rate = 0

    send_message(type='sco_state_change', sample_rate=sample_rate)


def on_sco_packet(packet: hci.HCI_SynchronousDataPacket):
    if ws:
        asyncio.create_task(ws.send(packet.data))
    if source_file and (pcm_data := source_file.read(packet.data_total_length)):
        assert ag_protocol
        host = ag_protocol.dlc.multiplexer.l2cap_channel.connection.device.host
        host.send_hci_packet(
            hci.HCI_SynchronousDataPacket(
                connection_handle=packet.connection_handle,
                packet_status=0,
                data_total_length=len(pcm_data),
                data=pcm_data,
            )
        )


def on_hfp_state_change(connected: bool):
    send_message(type='hfp_state_change', connected=connected)


async def ws_server(ws_client: websockets.WebSocketServerProtocol, path: str):
    del path
    global ws
    ws = ws_client

    async for message in ws_client:
        if not ag_protocol:
            continue

        json_message = json.loads(message)
        message_type = json_message['type']
        connection = ag_protocol.dlc.multiplexer.l2cap_channel.connection
        device = connection.device

        try:
            if message_type == 'at_response':
                ag_protocol.send_response(json_message['response'])
            elif message_type == 'ag_indicator':
                ag_protocol.update_ag_indicator(
                    hfp.AgIndicator(json_message['indicator']),
                    int(json_message['value']),
                )
            elif message_type == 'negotiate_codec':
                codec = hfp.AudioCodec(int(json_message['codec']))
                await ag_protocol.negotiate_codec(codec)
            elif message_type == 'connect_sco':
                if ag_protocol.active_codec == hfp.AudioCodec.CVSD:
                    esco_param = hfp.ESCO_PARAMETERS[
                        hfp.DefaultCodecParameters.ESCO_CVSD_S4
                    ]
                elif ag_protocol.active_codec == hfp.AudioCodec.MSBC:
                    esco_param = hfp.ESCO_PARAMETERS[
                        hfp.DefaultCodecParameters.ESCO_MSBC_T2
                    ]
                else:
                    raise ValueError(f'Unsupported codec {codec}')

                await device.send_command(
                    hci.HCI_Enhanced_Setup_Synchronous_Connection_Command(
                        connection_handle=connection.handle, **esco_param.asdict()
                    )
                )
            elif message_type == 'disconnect_sco':
                # Copy the values to avoid iteration error.
                for sco_link in list(device.sco_links.values()):
                    await sco_link.disconnect()
            elif message_type == 'update_calls':
                ag_protocol.calls = [
                    hfp.CallInfo(
                        index=int(call['index']),
                        direction=hfp.CallInfoDirection(int(call['direction'])),
                        status=hfp.CallInfoStatus(int(call['status'])),
                        number=call['number'],
                        multi_party=hfp.CallInfoMultiParty.NOT_IN_CONFERENCE,
                        mode=hfp.CallInfoMode.VOICE,
                    )
                    for call in json_message['calls']
                ]

        except Exception as e:
            send_message(type='error', message=e)


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_hfp_gateway.py <device-config> <transport-spec> '
            '[bluetooth-address] [wav-file-for-source]'
        )
        print(
            'example: run_hfp_gateway.py hfp_gateway.json usb:0 E1:CA:72:48:C4:E8 sample.wav'
        )
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

        rfcomm_server = rfcomm.Server(device)
        configuration = _default_configuration()

        def on_dlc(dlc: rfcomm.DLC):
            global ag_protocol
            ag_protocol = hfp.AgProtocol(dlc, configuration)
            ag_protocol.on('speaker_volume', on_speaker_volume)
            ag_protocol.on('microphone_volume', on_microphone_volume)
            on_hfp_state_change(True)
            dlc.multiplexer.l2cap_channel.on(
                'close', lambda: on_hfp_state_change(False)
            )

        channel = rfcomm_server.listen(on_dlc)
        device.sdp_service_records = {
            1: hfp.make_ag_sdp_records(1, channel, configuration)
        }

        def on_sco_connection(sco_link: ScoLink):
            assert ag_protocol
            on_sco_state_change(ag_protocol.active_codec)
            sco_link.on('disconnection', lambda _: on_sco_state_change(0))
            sco_link.sink = on_sco_packet

        device.on('sco_connection', on_sco_connection)
        if len(sys.argv) >= 4:
            # Connect to a peer
            target_address = sys.argv[3]
            print(f'=== Connecting to {target_address}...')
            connection = await device.connect(
                target_address, transport=BT_BR_EDR_TRANSPORT
            )
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

            on_dlc(session)

        await websockets.serve(ws_server, port=8888)

        if len(sys.argv) >= 5:
            global source_file
            source_file = open(sys.argv[4], 'rb')
            # Skip header
            source_file.seek(44)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
