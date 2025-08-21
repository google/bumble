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
import contextlib
import functools
import json
import sys
from typing import Optional

import websockets

import bumble.logging
from bumble import hci, hfp, rfcomm
from bumble.device import Connection, Device
from bumble.hfp import HfProtocol
from bumble.transport import open_transport

ws: Optional[websockets.WebSocketServerProtocol] = None
hf_protocol: Optional[HfProtocol] = None


# -----------------------------------------------------------------------------
def on_dlc(dlc: rfcomm.DLC, configuration: hfp.HfConfiguration):
    print('*** DLC connected', dlc)
    global hf_protocol
    hf_protocol = HfProtocol(dlc, configuration)
    asyncio.create_task(hf_protocol.run())

    def on_sco_request(connection: Connection, link_type: int, protocol: HfProtocol):
        if connection == protocol.dlc.multiplexer.l2cap_channel.connection:
            if link_type == hci.HCI_Connection_Complete_Event.LinkType.SCO:
                esco_parameters = hfp.ESCO_PARAMETERS[
                    hfp.DefaultCodecParameters.SCO_CVSD_D1
                ]
            elif protocol.active_codec == hfp.AudioCodec.MSBC:
                esco_parameters = hfp.ESCO_PARAMETERS[
                    hfp.DefaultCodecParameters.ESCO_MSBC_T2
                ]
            elif protocol.active_codec == hfp.AudioCodec.CVSD:
                esco_parameters = hfp.ESCO_PARAMETERS[
                    hfp.DefaultCodecParameters.ESCO_CVSD_S4
                ]
            else:
                raise RuntimeError("unknown active codec")

            connection.cancel_on_disconnection(
                connection.device.send_command(
                    hci.HCI_Enhanced_Accept_Synchronous_Connection_Request_Command(
                        bd_addr=connection.peer_address, **esco_parameters.asdict()
                    )
                )
            )

    handler = functools.partial(on_sco_request, protocol=hf_protocol)
    dlc.multiplexer.l2cap_channel.connection.device.on('sco_request', handler)
    dlc.multiplexer.l2cap_channel.once(
        'close',
        lambda: dlc.multiplexer.l2cap_channel.connection.device.remove_listener(
            'sco_request', handler
        ),
    )

    def on_ag_indicator(indicator):
        global ws
        if ws:
            asyncio.create_task(ws.send(str(indicator)))

    hf_protocol.on('ag_indicator', on_ag_indicator)


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: run_classic_hfp.py <device-config> <transport-spec>')
        print('example: run_classic_hfp.py classic2.json usb:04b4:f901')
        return

    print('<<< connecting to HCI...')
    async with await open_transport(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Hands-Free profile configuration.
        # TODO: load configuration from file.
        configuration = hfp.HfConfiguration(
            supported_hf_features=[
                hfp.HfFeature.THREE_WAY_CALLING,
                hfp.HfFeature.REMOTE_VOLUME_CONTROL,
                hfp.HfFeature.ENHANCED_CALL_STATUS,
                hfp.HfFeature.ENHANCED_CALL_CONTROL,
                hfp.HfFeature.CODEC_NEGOTIATION,
                hfp.HfFeature.HF_INDICATORS,
                hfp.HfFeature.ESCO_S4_SETTINGS_SUPPORTED,
            ],
            supported_hf_indicators=[
                hfp.HfIndicator.BATTERY_LEVEL,
            ],
            supported_audio_codecs=[
                hfp.AudioCodec.CVSD,
                hfp.AudioCodec.MSBC,
            ],
        )

        # Create a device
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.classic_enabled = True

        # Create and register a server
        rfcomm_server = rfcomm.Server(device)

        # Listen for incoming DLC connections
        channel_number = rfcomm_server.listen(lambda dlc: on_dlc(dlc, configuration))
        print(f'### Listening for connection on channel {channel_number}')

        # Advertise the HFP RFComm channel in the SDP
        device.sdp_service_records = {
            0x00010001: hfp.make_hf_sdp_records(
                0x00010001, channel_number, configuration
            )
        }

        # Let's go!
        await device.power_on()

        # Start being discoverable and connectable
        await device.set_discoverable(True)
        await device.set_connectable(True)

        # Start the UI websocket server to offer a few buttons and input boxes
        async def serve(websocket: websockets.WebSocketServerProtocol, _path):
            global ws
            ws = websocket
            async for message in websocket:
                with contextlib.suppress(websockets.exceptions.ConnectionClosedOK):
                    print('Received: ', str(message))

                    parsed = json.loads(message)
                    message_type = parsed['type']
                    if message_type == 'at_command':
                        if hf_protocol is not None:
                            response = str(
                                await hf_protocol.execute_command(
                                    parsed['command'],
                                    response_type=hfp.AtResponseType.MULTIPLE,
                                )
                            )
                            await websocket.send(response)
                    elif message_type == 'query_call':
                        if hf_protocol:
                            response = str(await hf_protocol.query_current_calls())
                            await websocket.send(response)

        await websockets.serve(serve, 'localhost', 8989)

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
