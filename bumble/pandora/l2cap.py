# Copyright 2024 Google LLC
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
from __future__ import annotations
import asyncio
import grpc
import json
import logging

from asyncio import Queue as AsyncQueue, Future

from bumble.pandora import utils
from bumble.pandora.config import Config
from bumble.core import OutOfResourcesError, InvalidArgumentError
from bumble.device import Device
from bumble.l2cap import (
    ClassicChannel,
    ClassicChannelServer,
    ClassicChannelSpec,
    LeCreditBasedChannel,
    LeCreditBasedChannelServer,
    LeCreditBasedChannelSpec,
)
from google.protobuf import any_pb2, empty_pb2  # pytype: disable=pyi-error
from pandora.l2cap_grpc_aio import L2CAPServicer  # pytype: disable=pyi-error
from pandora.l2cap_pb2 import (  # pytype: disable=pyi-error
    COMMAND_NOT_UNDERSTOOD,
    INVALID_CID_IN_REQUEST,
    Channel as PandoraChannel,
    ConnectRequest,
    ConnectResponse,
    CreditBasedChannelRequest,
    DisconnectRequest,
    DisconnectResponse,
    ReceiveRequest,
    ReceiveResponse,
    SendRequest,
    SendResponse,
    WaitConnectionRequest,
    WaitConnectionResponse,
    WaitDisconnectionRequest,
    WaitDisconnectionResponse,
)
from typing import AsyncGenerator, Dict, Optional, Union
from dataclasses import dataclass

L2capChannel = Union[ClassicChannel, LeCreditBasedChannel]


@dataclass
class ChannelContext:
    close_future: Future
    sdu_queue: AsyncQueue


class L2CAPService(L2CAPServicer):
    def __init__(self, device: Device, config: Config) -> None:
        self.log = utils.BumbleServerLoggerAdapter(
            logging.getLogger(), {'service_name': 'L2CAP', 'device': device}
        )
        self.device = device
        self.config = config
        self.channels: Dict[bytes, ChannelContext] = {}

    def register_event(self, l2cap_channel: L2capChannel) -> ChannelContext:
        close_future = asyncio.get_running_loop().create_future()
        sdu_queue: AsyncQueue = AsyncQueue()

        def on_channel_sdu(sdu):
            sdu_queue.put_nowait(sdu)

        def on_close():
            close_future.set_result(None)

        l2cap_channel.sink = on_channel_sdu
        l2cap_channel.on('close', on_close)

        return ChannelContext(close_future, sdu_queue)

    @utils.rpc
    async def WaitConnection(
        self, request: WaitConnectionRequest, context: grpc.ServicerContext
    ) -> WaitConnectionResponse:
        self.log.debug('WaitConnection')
        if not request.connection:
            raise ValueError('A valid connection field must be set')

        # find connection on device based on connection cookie value
        connection_handle = int.from_bytes(request.connection.cookie.value, 'big')
        connection = self.device.lookup_connection(connection_handle)

        if not connection:
            raise ValueError('The connection specified is invalid.')

        oneof = request.WhichOneof('type')
        self.log.debug(f'WaitConnection channel request type: {oneof}.')
        channel_type = getattr(request, oneof)
        spec: Optional[Union[ClassicChannelSpec, LeCreditBasedChannelSpec]] = None
        l2cap_server: Optional[
            Union[ClassicChannelServer, LeCreditBasedChannelServer]
        ] = None
        if isinstance(channel_type, CreditBasedChannelRequest):
            spec = LeCreditBasedChannelSpec(
                psm=channel_type.spsm,
                max_credits=channel_type.initial_credit,
                mtu=channel_type.mtu,
                mps=channel_type.mps,
            )
            if channel_type.spsm in self.device.l2cap_channel_manager.le_coc_servers:
                l2cap_server = self.device.l2cap_channel_manager.le_coc_servers[
                    channel_type.spsm
                ]
        else:
            spec = ClassicChannelSpec(
                psm=channel_type.psm,
                mtu=channel_type.mtu,
            )
            if channel_type.psm in self.device.l2cap_channel_manager.servers:
                l2cap_server = self.device.l2cap_channel_manager.servers[
                    channel_type.psm
                ]

        self.log.info(f'Listening for L2CAP connection on PSM {spec.psm}')
        channel_future: Future[PandoraChannel] = (
            asyncio.get_running_loop().create_future()
        )

        def on_l2cap_channel(l2cap_channel: L2capChannel):
            try:
                channel_context = self.register_event(l2cap_channel)
                pandora_channel: PandoraChannel = self.craft_pandora_channel(
                    connection_handle, l2cap_channel
                )
                self.channels[pandora_channel.cookie.value] = channel_context
                channel_future.set_result(pandora_channel)
            except Exception as e:
                self.log.error(f'Failed to set channel future: {e}')

        if l2cap_server is None:
            l2cap_server = self.device.create_l2cap_server(
                spec=spec, handler=on_l2cap_channel
            )
        else:
            l2cap_server.on('connection', on_l2cap_channel)

        try:
            self.log.debug('Waiting for a channel connection.')
            pandora_channel: PandoraChannel = await channel_future

            return WaitConnectionResponse(channel=pandora_channel)
        except Exception as e:
            self.log.warning(f'Exception: {e}')

        return WaitConnectionResponse(error=COMMAND_NOT_UNDERSTOOD)

    @utils.rpc
    async def WaitDisconnection(
        self, request: WaitDisconnectionRequest, context: grpc.ServicerContext
    ) -> WaitDisconnectionResponse:
        try:
            self.log.debug('WaitDisconnection')

            await self.lookup_context(request.channel).close_future
            self.log.debug("return WaitDisconnectionResponse")
            return WaitDisconnectionResponse(success=empty_pb2.Empty())
        except KeyError as e:
            self.log.warning(f'WaitDisconnection: Unable to find the channel: {e}')
            return WaitDisconnectionResponse(error=INVALID_CID_IN_REQUEST)
        except Exception as e:
            self.log.exception(f'WaitDisonnection failed: {e}')
            return WaitDisconnectionResponse(error=COMMAND_NOT_UNDERSTOOD)

    @utils.rpc
    async def Receive(
        self, request: ReceiveRequest, context: grpc.ServicerContext
    ) -> AsyncGenerator[ReceiveResponse, None]:
        self.log.debug('Receive')
        oneof = request.WhichOneof('source')
        self.log.debug(f'Source: {oneof}.')
        pandora_channel = getattr(request, oneof)

        sdu_queue = self.lookup_context(pandora_channel).sdu_queue

        while sdu := await sdu_queue.get():
            self.log.debug(f'Receive: Received {len(sdu)} bytes -> {sdu.decode()}')
            response = ReceiveResponse(data=sdu)
            yield response

    @utils.rpc
    async def Connect(
        self, request: ConnectRequest, context: grpc.ServicerContext
    ) -> ConnectResponse:
        self.log.debug('Connect')

        if not request.connection:
            raise ValueError('A valid connection field must be set')

        # find connection on device based on connection cookie value
        connection_handle = int.from_bytes(request.connection.cookie.value, 'big')
        connection = self.device.lookup_connection(connection_handle)

        if not connection:
            raise ValueError('The connection specified is invalid.')

        oneof = request.WhichOneof('type')
        self.log.debug(f'Channel request type: {oneof}.')
        channel_type = getattr(request, oneof)
        spec: Optional[Union[ClassicChannelSpec, LeCreditBasedChannelSpec]] = None
        if isinstance(channel_type, CreditBasedChannelRequest):
            spec = LeCreditBasedChannelSpec(
                psm=channel_type.spsm,
                max_credits=channel_type.initial_credit,
                mtu=channel_type.mtu,
                mps=channel_type.mps,
            )
        else:
            spec = ClassicChannelSpec(
                psm=channel_type.psm,
                mtu=channel_type.mtu,
            )

        try:
            self.log.info(f'Opening L2CAP channel on PSM = {spec.psm}')
            l2cap_channel = await connection.create_l2cap_channel(spec=spec)
            channel_context = self.register_event(l2cap_channel)
            pandora_channel = self.craft_pandora_channel(
                connection_handle, l2cap_channel
            )
            self.channels[pandora_channel.cookie.value] = channel_context

            return ConnectResponse(channel=pandora_channel)

        except OutOfResourcesError as e:
            self.log.error(e)
            return ConnectResponse(error=INVALID_CID_IN_REQUEST)
        except InvalidArgumentError as e:
            self.log.error(e)
            return ConnectResponse(error=COMMAND_NOT_UNDERSTOOD)

    @utils.rpc
    async def Disconnect(
        self, request: DisconnectRequest, context: grpc.ServicerContext
    ) -> DisconnectResponse:
        try:
            self.log.debug('Disconnect')
            l2cap_channel = self.lookup_channel(request.channel)
            if not l2cap_channel:
                self.log.warning('Disconnect: Unable to find the channel')
                return DisconnectResponse(error=INVALID_CID_IN_REQUEST)

            await l2cap_channel.disconnect()
            return DisconnectResponse(success=empty_pb2.Empty())
        except Exception as e:
            self.log.exception(f'Disonnect failed: {e}')
            return DisconnectResponse(error=COMMAND_NOT_UNDERSTOOD)

    @utils.rpc
    async def Send(
        self, request: SendRequest, context: grpc.ServicerContext
    ) -> SendResponse:
        self.log.debug('Send')
        try:
            oneof = request.WhichOneof('sink')
            self.log.debug(f'Sink: {oneof}.')
            pandora_channel = getattr(request, oneof)

            l2cap_channel = self.lookup_channel(pandora_channel)
            if not l2cap_channel:
                return SendResponse(error=COMMAND_NOT_UNDERSTOOD)
            if isinstance(l2cap_channel, ClassicChannel):
                l2cap_channel.send_pdu(request.data)
            else:
                l2cap_channel.write(request.data)
            return SendResponse(success=empty_pb2.Empty())
        except Exception as e:
            self.log.exception(f'Disonnect failed: {e}')
            return SendResponse(error=COMMAND_NOT_UNDERSTOOD)

    def craft_pandora_channel(
        self,
        connection_handle: int,
        l2cap_channel: L2capChannel,
    ) -> PandoraChannel:
        parameters = {
            "connection_handle": connection_handle,
            "source_cid": l2cap_channel.source_cid,
        }
        cookie = any_pb2.Any()
        cookie.value = json.dumps(parameters).encode()
        return PandoraChannel(cookie=cookie)

    def lookup_channel(self, pandora_channel: PandoraChannel) -> L2capChannel:
        (connection_handle, source_cid) = json.loads(
            pandora_channel.cookie.value
        ).values()

        return self.device.l2cap_channel_manager.channels[connection_handle][source_cid]

    def lookup_context(self, pandora_channel: PandoraChannel) -> ChannelContext:
        return self.channels[pandora_channel.cookie.value]
