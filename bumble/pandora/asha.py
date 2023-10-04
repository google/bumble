# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import grpc
import logging

from bumble.decoder import G722Decoder
from bumble.device import Connection, Device
from bumble.pandora import utils
from bumble.profiles import asha_service
from google.protobuf.empty_pb2 import Empty  # pytype: disable=pyi-error
from pandora.asha_grpc_aio import ASHAServicer
from pandora.asha_pb2 import CaptureAudioRequest, CaptureAudioResponse, RegisterRequest
from typing import AsyncGenerator, Optional


class AshaService(ASHAServicer):
    DECODE_FRAME_LENGTH = 80

    device: Device
    asha_service: Optional[asha_service.AshaService]

    def __init__(self, device: Device) -> None:
        self.log = utils.BumbleServerLoggerAdapter(
            logging.getLogger(), {"service_name": "Asha", "device": device}
        )
        self.device = device
        self.asha_service = None

    @utils.rpc
    async def Register(
        self, request: RegisterRequest, context: grpc.ServicerContext
    ) -> Empty:
        logging.info("Register")
        if self.asha_service:
            self.asha_service.capability = request.capability
            self.asha_service.hisyncid = request.hisyncid
        else:
            self.asha_service = asha_service.AshaService(
                request.capability, request.hisyncid, self.device
            )
            self.device.add_service(self.asha_service)  # type: ignore[no-untyped-call]
        return Empty()

    @utils.rpc
    async def CaptureAudio(
        self, request: CaptureAudioRequest, context: grpc.ServicerContext
    ) -> AsyncGenerator[CaptureAudioResponse, None]:
        connection_handle = int.from_bytes(request.connection.cookie.value, "big")
        logging.info(f"CaptureAudioData connection_handle:{connection_handle}")

        if not (connection := self.device.lookup_connection(connection_handle)):
            raise RuntimeError(
                f"Unknown connection for connection_handle:{connection_handle}"
            )

        decoder = G722Decoder()  # type: ignore
        queue: asyncio.Queue[bytes] = asyncio.Queue()

        def on_data(asha_connection: Connection, data: bytes) -> None:
            if asha_connection == connection:
                queue.put_nowait(data)

        self.asha_service.on("data", on_data)  # type: ignore

        try:
            while data := await queue.get():
                output_bytes = bytearray()
                # First byte is sequence number, last 160 bytes are audio payload.
                audio_payload = data[1:]
                data_length = int(len(audio_payload) / AshaService.DECODE_FRAME_LENGTH)
                for i in range(0, data_length):
                    input_data = audio_payload[
                        i
                        * AshaService.DECODE_FRAME_LENGTH : i
                        * AshaService.DECODE_FRAME_LENGTH
                        + AshaService.DECODE_FRAME_LENGTH
                    ]
                    decoded_data = decoder.decode_frame(input_data)
                    output_bytes.extend(decoded_data)

                yield CaptureAudioResponse(data=bytes(output_bytes))
        finally:
            self.asha_service.remove_listener("data", on_data)  # type: ignore
