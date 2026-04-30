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
import wave

import websockets.asyncio.server

import bumble.logging
from bumble import hci, hfp, rfcomm
from bumble.device import Connection, Device, ScoLink
from bumble.hfp import HfProtocol
from bumble.transport import open_transport

# -----------------------------------------------------------------------------
ws: websockets.asyncio.server.ServerConnection | None = None
hf_protocol: HfProtocol | None = None
input_wav: wave.Wave_read | None = None
output_wav: wave.Wave_write | None = None


# -----------------------------------------------------------------------------
def on_audio_packet(packet: hci.HCI_SynchronousDataPacket) -> None:
    if (
        packet.packet_status
        == hci.HCI_SynchronousDataPacket.Status.CORRECTLY_RECEIVED_DATA
    ):
        if output_wav:
            # Save the PCM audio to the output
            output_wav.writeframes(packet.data)
    else:
        print('!!! discarding packet with status ', packet.packet_status.name)

    if input_wav and hf_protocol:
        # Send PCM audio from the input
        frame_count = len(packet.data) // 2
        while frame_count:
            # NOTE: we use a fixed number of frames here, this should likely be adjusted
            # based on the transport parameters (like the USB max packet size)
            chunk_size = min(frame_count, 16)
            if not (pcm_data := input_wav.readframes(chunk_size)):
                return
            frame_count -= chunk_size
            hf_protocol.dlc.multiplexer.l2cap_channel.connection.device.host.send_sco_sdu(
                connection_handle=packet.connection_handle,
                sdu=pcm_data,
            )


# -----------------------------------------------------------------------------
def on_sco_connection(link: ScoLink) -> None:
    print('### SCO connection established:', link)
    if link.air_mode == hci.CodecID.TRANSPARENT:
        print("@@@ The controller does not encode/decode voice")
        return

    link.sink = on_audio_packet


# -----------------------------------------------------------------------------
def on_sco_request(
    link_type: int, connection: Connection, protocol: HfProtocol
) -> None:
    if link_type == hci.HCI_Connection_Complete_Event.LinkType.SCO:
        esco_parameters = hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.SCO_CVSD_D1]
    elif protocol.active_codec == hfp.AudioCodec.MSBC:
        esco_parameters = hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.ESCO_MSBC_T2]
    elif protocol.active_codec == hfp.AudioCodec.CVSD:
        esco_parameters = hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.ESCO_CVSD_S4]
    else:
        raise RuntimeError("unknown active codec")

    if connection.device.host.supports_command(
        hci.HCI_ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND
    ):
        connection.cancel_on_disconnection(
            connection.device.send_async_command(
                hci.HCI_Enhanced_Accept_Synchronous_Connection_Request_Command(
                    bd_addr=connection.peer_address, **esco_parameters.asdict()
                )
            )
        )
    elif connection.device.host.supports_command(
        hci.HCI_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND
    ):
        connection.cancel_on_disconnection(
            connection.device.send_async_command(
                hci.HCI_Accept_Synchronous_Connection_Request_Command(
                    bd_addr=connection.peer_address,
                    transmit_bandwidth=esco_parameters.transmit_bandwidth,
                    receive_bandwidth=esco_parameters.receive_bandwidth,
                    max_latency=esco_parameters.max_latency,
                    voice_setting=int(
                        hci.VoiceSetting(
                            input_sample_size=hci.VoiceSetting.InputSampleSize.SIZE_16_BITS,
                            input_data_format=hci.VoiceSetting.InputDataFormat.TWOS_COMPLEMENT,
                        )
                    ),
                    retransmission_effort=esco_parameters.retransmission_effort,
                    packet_type=esco_parameters.packet_type,
                )
            )
        )
    else:
        print('!!! no supported command for SCO connection request')
        return

    connection.on('sco_connection', on_sco_connection)


# -----------------------------------------------------------------------------
def on_dlc(dlc: rfcomm.DLC, configuration: hfp.HfConfiguration):
    print('*** DLC connected', dlc)
    global hf_protocol
    hf_protocol = HfProtocol(dlc, configuration)
    asyncio.create_task(hf_protocol.run())

    connection = dlc.multiplexer.l2cap_channel.connection
    handler = functools.partial(
        on_sco_request,
        connection=connection,
        protocol=hf_protocol,
    )
    connection.on('sco_request', handler)
    dlc.multiplexer.l2cap_channel.once(
        'close',
        lambda: connection.remove_listener('sco_request', handler),
    )

    hf_protocol.on('ag_indicator', on_ag_indicator)
    hf_protocol.on('codec_negotiation', on_codec_negotiation)


# -----------------------------------------------------------------------------
def on_ag_indicator(indicator):
    global ws
    if ws:
        asyncio.create_task(ws.send(str(indicator)))


# -----------------------------------------------------------------------------
def on_codec_negotiation(codec: hfp.AudioCodec):
    print(f'### Negotiated codec: {codec.name}')
    global output_wav
    if output_wav:
        output_wav.setnchannels(1)
        output_wav.setsampwidth(2)
        match codec:
            case hfp.AudioCodec.CVSD:
                output_wav.setframerate(8000)
            case hfp.AudioCodec.MSBC:
                output_wav.setframerate(16000)


# -----------------------------------------------------------------------------
async def run(device: Device, codec: str | None) -> None:
    if codec is None:
        supported_audio_codecs = [hfp.AudioCodec.CVSD, hfp.AudioCodec.MSBC]
    else:
        if codec == 'cvsd':
            supported_audio_codecs = [hfp.AudioCodec.CVSD]
        elif codec == 'msbc':
            supported_audio_codecs = [hfp.AudioCodec.MSBC]
        else:
            print('Unknown codec: ', codec)
            return

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
        supported_audio_codecs=supported_audio_codecs,
    )

    # Create and register a server
    rfcomm_server = rfcomm.Server(device)

    # Listen for incoming DLC connections
    channel_number = rfcomm_server.listen(lambda dlc: on_dlc(dlc, configuration))
    print(f'### Listening for connection on channel {channel_number}')

    # Advertise the HFP RFComm channel in the SDP
    device.sdp_service_records = {
        0x00010001: hfp.make_hf_sdp_records(0x00010001, channel_number, configuration)
    }

    # Let's go!
    await device.power_on()

    # Start being discoverable and connectable
    await device.set_discoverable(True)
    await device.set_connectable(True)

    # Start the UI websocket server to offer a few buttons and input boxes
    async def serve(websocket: websockets.asyncio.server.ServerConnection):
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

    await websockets.asyncio.server.serve(serve, 'localhost', 8989)

    await asyncio.get_running_loop().create_future()  # run forever


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_hfp_handsfree.py <device-config> <transport-spec> '
            '[codec] [input] [output]'
        )
        print('example: run_hfp_handsfree.py classic2.json usb:0')
        return

    device_config = sys.argv[1]
    transport_spec = sys.argv[2]

    codec: str | None = None
    if len(sys.argv) >= 4:
        codec = sys.argv[3]

    input_file_name: str | None = None
    if len(sys.argv) >= 5:
        input_file_name = sys.argv[4]

    output_file_name: str | None = None
    if len(sys.argv) >= 6:
        output_file_name = sys.argv[5]

    global input_wav, output_wav
    input_cm: contextlib.AbstractContextManager[wave.Wave_read | None] = (
        wave.open(input_file_name, "rb")
        if input_file_name
        else contextlib.nullcontext(None)
    )
    output_cm: contextlib.AbstractContextManager[wave.Wave_write | None] = (
        wave.open(output_file_name, "wb")
        if output_file_name
        else contextlib.nullcontext(None)
    )
    with input_cm as input_wav, output_cm as output_wav:
        if input_wav and input_wav.getnchannels() != 1:
            print("Mono input required")
            return
        if input_wav and input_wav.getsampwidth() != 2:
            print("16-bit input required")
            return

        async with await open_transport(transport_spec) as transport:
            device = Device.from_config_file_with_hci(
                device_config, transport.source, transport.sink
            )
            device.classic_enabled = True
            await run(device, codec)


# -----------------------------------------------------------------------------
bumble.logging.setup_basic_logging('DEBUG')
asyncio.run(main())
