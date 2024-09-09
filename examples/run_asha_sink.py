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
import websockets

from typing import Optional

from bumble import decoder
from bumble import gatt
from bumble.core import AdvertisingData
from bumble.device import Device, AdvertisingParameters
from bumble.transport import open_transport_or_link
from bumble.profiles import asha

ws_connection: Optional[websockets.WebSocketServerProtocol] = None
g722_decoder = decoder.G722Decoder()


async def ws_server(ws_client: websockets.WebSocketServerProtocol, path: str):
    del path
    global ws_connection
    ws_connection = ws_client

    async for message in ws_client:
        print(message)


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) != 3:
        print('Usage: python run_asha_sink.py <device-config> <transport-spec>')
        print('example: python run_asha_sink.py device1.json usb:0')
        return

    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )

        def on_audio_packet(packet: bytes) -> None:
            global ws_connection
            if ws_connection:
                offset = 1
                while offset < len(packet):
                    pcm_data = g722_decoder.decode_frame(packet[offset : offset + 80])
                    offset += 80
                    asyncio.get_running_loop().create_task(ws_connection.send(pcm_data))
            else:
                logging.info("No active client")

        asha_service = asha.AshaService(
            capability=0,
            hisyncid=b'\x01\x02\x03\x04\x05\x06\x07\x08',
            device=device,
            audio_sink=on_audio_packet,
        )
        device.add_service(asha_service)

        # Set the advertising data
        advertising_data = (
            bytes(
                AdvertisingData(
                    [
                        (
                            AdvertisingData.COMPLETE_LOCAL_NAME,
                            bytes(device.name, 'utf-8'),
                        ),
                        (AdvertisingData.FLAGS, bytes([0x06])),
                        (
                            AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                            bytes(gatt.GATT_ASHA_SERVICE),
                        ),
                    ]
                )
            )
            + asha_service.get_advertising_data()
        )

        # Go!
        await device.power_on()
        await device.create_advertising_set(
            auto_restart=True,
            advertising_data=advertising_data,
            advertising_parameters=AdvertisingParameters(
                primary_advertising_interval_min=100,
                primary_advertising_interval_max=100,
            ),
        )

        await websockets.serve(ws_server, port=8888)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper(),
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
asyncio.run(main())
