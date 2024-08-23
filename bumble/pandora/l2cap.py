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
import threading

from . import utils
from .config import Config
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
    Channel,
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
from typing import Any, AsyncGenerator, Dict, Optional, Union


class L2CAPService(L2CAPServicer):
    def __init__(self, device: Device, config: Config) -> None:
        self.log = utils.BumbleServerLoggerAdapter(
            logging.getLogger(), {'service_name': 'L2CAP', 'device': device}
        )
        self.device = device
        self.config = config
        self.sdu_queue: asyncio.Queue = asyncio.Queue()

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
        channel_future: asyncio.Future[Union[ClassicChannel, LeCreditBasedChannel]] = (
            asyncio.get_running_loop().create_future()
        )

        def on_l2cap_channel(
            l2cap_channel: Union[ClassicChannel, LeCreditBasedChannel]
        ):
            try:
                channel_future.set_result(l2cap_channel)
                self.log.debug(
                    f'Channel future set successfully with channel= {l2cap_channel}'
                )
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
            l2cap_channel = await channel_future
            channel = self.channel_to_proto(l2cap_channel)
            return WaitConnectionResponse(channel=channel)
        except Exception as e:
            self.log.warning(f'Exception: {e}')
        return WaitConnectionResponse(error=COMMAND_NOT_UNDERSTOOD)

    @utils.rpc
    async def WaitDisconnection(
        self, request: WaitDisconnectionRequest, context: grpc.ServicerContext
    ) -> WaitDisconnectionResponse:
        try:
            self.log.debug('WaitDisconnection')
            l2cap_channel = self.get_l2cap_channel(request.channel)
            if l2cap_channel is None:
                self.log.warn('WaitDisconnection: Unable to find the channel')
                return WaitDisconnectionResponse(error=INVALID_CID_IN_REQUEST)

            self.log.debug('WaitDisconnection: Sending a disconnection request')
            closed_event: asyncio.Event = asyncio.Event()

            def on_close():
                self.log.info('Received a close event')
                closed_event.set()

            l2cap_channel.on('close', on_close)
            await closed_event.wait()
            return WaitDisconnectionResponse(success=empty_pb2.Empty())
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
        channel = getattr(request, oneof)

        if not isinstance(channel, Channel):
            raise NotImplementedError(f'TODO: {type(channel)} not currently supported.')

        def on_channel_sdu(sdu):
            async def handle_sdu():
                await self.sdu_queue.put(sdu)

            asyncio.create_task(handle_sdu())

        l2cap_channel = self.get_l2cap_channel(channel)
        if l2cap_channel is None:
            raise ValueError('The channel in the request is not valid.')

        l2cap_channel.sink = on_channel_sdu
        while sdu := await self.sdu_queue.get():
            # Retrieve the next SDU from the queue
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
            self.log.info(f'L2CAP channel: {l2cap_channel}')
        except Exception as e:
            l2cap_channel = None
            self.log.exception(f'Connection failed: {e}')

        if not l2cap_channel:
            return ConnectResponse(error=COMMAND_NOT_UNDERSTOOD)

        channel = self.channel_to_proto(l2cap_channel)
        return ConnectResponse(channel=channel)

    @utils.rpc
    async def Disconnect(
        self, request: DisconnectRequest, context: grpc.ServicerContext
    ) -> DisconnectResponse:
        try:
            self.log.debug('Disconnect')
            l2cap_channel = self.get_l2cap_channel(request.channel)
            if not l2cap_channel:
                self.log.warn('Disconnect: Unable to find the channel')
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
            channel = getattr(request, oneof)

            if not isinstance(channel, Channel):
                raise NotImplementedError(
                    f'TODO: {type(channel)} not currently supported.'
                )
            l2cap_channel = self.get_l2cap_channel(channel)
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

    def get_l2cap_channel(
        self, channel: Channel
    ) -> Optional[Union[ClassicChannel, LeCreditBasedChannel]]:
        parameters = self.get_channel_parameters(channel)
        connection_handle = parameters.get('connection_handle', 0)
        destination_cid = parameters.get('destination_cid', 0)
        is_classic = parameters.get('is_classic', False)
        self.log.debug(
            f'get_l2cap_channel: Connection handle:{connection_handle}, cid:{destination_cid}'
        )
        l2cap_channel: Optional[Union[ClassicChannel, LeCreditBasedChannel]] = None
        if is_classic:
            l2cap_channel = self.device.l2cap_channel_manager.find_channel(
                connection_handle, destination_cid
            )
        else:
            l2cap_channel = self.device.l2cap_channel_manager.find_le_coc_channel(
                connection_handle, destination_cid
            )
        return l2cap_channel

    def channel_to_proto(
        self, l2cap_channel: Union[ClassicChannel, LeCreditBasedChannel]
    ) -> Channel:
        parameters = {
            "source_cid": l2cap_channel.source_cid,
            "destination_cid": l2cap_channel.destination_cid,
            "connection_handle": l2cap_channel.connection.handle,
            "is_classic": True if isinstance(l2cap_channel, ClassicChannel) else False,
        }
        self.log.info(f'Channel parameters: {parameters}')
        cookie = any_pb2.Any()
        cookie.value = json.dumps(parameters).encode()
        return Channel(cookie=cookie)

    def get_channel_parameters(self, channel: Channel) -> Dict['str', Any]:
        cookie_value = channel.cookie.value.decode()
        parameters = json.loads(cookie_value)
        self.log.info(f'Channel parameters: {parameters}')
        return parameters
