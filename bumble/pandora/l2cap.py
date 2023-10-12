# Copyright 2023 Google LLC
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

import abc
import asyncio
import collections
import dataclasses
import grpc
import logging
import struct

from bumble import device
from bumble import l2cap
from bumble.utils import EventWatcher
from bumble.pandora import config
from bumble.pandora import utils
from google.protobuf import any_pb2  # pytype: disable=pyi-error
from google.protobuf import empty_pb2  # pytype: disable=pyi-error
from pandora import l2cap_pb2
from pandora import l2cap_grpc_aio
from typing import AsyncGenerator, Dict, Union, Optional, DefaultDict


class ChannelProxy(abc.ABC):
    up_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def send(self, sdu: bytes) -> None:
        ...

    async def receive(self) -> bytes:
        return await self.up_queue.get()

    def on_data(self, pdu: bytes) -> None:
        self.up_queue.put_nowait(pdu)


class CocChannelProxy(ChannelProxy):
    def __init__(
        self, channel: Union[l2cap.ClassicChannel, l2cap.LeCreditBasedChannel]
    ) -> None:
        super().__init__()
        self.channel = channel
        channel.sink = self.on_data
        self.disconnection_result = asyncio.get_event_loop().create_future()

        @channel.once('close')
        def on_close() -> None:
            self.disconnection_result.set_result(None)

    def send(self, data: bytes) -> None:
        if isinstance(self.channel, l2cap.ClassicChannel):
            self.channel.send_pdu(data)
        else:
            self.channel.write(data)

    @property
    def closed(self):
        if isinstance(self.channel, l2cap.ClassicChannel):
            return self.channel.state == self.channel.State.CLOSED
        else:
            return self.channel.state == self.channel.State.DISCONNECTED

    async def disconnect(self) -> None:
        if self.closed:
            return

        await self.channel.disconnect()

    async def wait_disconnect(self) -> None:
        if self.closed:
            return

        await self.disconnection_result


@dataclasses.dataclass
class FixedChannelProxy(ChannelProxy):
    connection_handle: int
    cid: int
    device: device.Device

    def send(self, data: bytes) -> None:
        self.device.send_l2cap_pdu(self.connection_handle, self.cid, data)


class L2CAPService(l2cap_grpc_aio.L2CAPServicer):
    channels: DefaultDict[int, Dict[int, ChannelProxy]]

    def __init__(self, device: device.Device, config: config.Config) -> None:
        self.log = utils.BumbleServerLoggerAdapter(
            logging.getLogger(), {'service_name': 'L2CAP', 'device': device}
        )
        self.device = device
        self.config = config
        self.channels = collections.defaultdict(dict)
        self.device.on('connection', self.on_acl)

    def on_acl(self, connection: device.Connection) -> None:
        def on_disconnection(_reason) -> None:
            del self.channels[connection.handle]

        connection.once('disconnection', on_disconnection)

    def get_channel(self, channel: l2cap_pb2.Channel) -> ChannelProxy:
        connection_handle, cid = struct.unpack('>HH', channel.cookie.value)
        if cid not in self.channels[connection_handle]:
            raise RuntimeError('No valid cid or handle')
        return self.channels[connection_handle][cid]

    @utils.rpc
    async def Connect(
        self, request: l2cap_pb2.ConnectRequest, context: grpc.ServicerContext
    ) -> l2cap_pb2.ConnectResponse:
        self.log.debug('Connect')
        channel: Union[
            FixedChannelProxy, l2cap.ClassicChannel, l2cap.LeCreditBasedChannel
        ]
        connection_handle = int.from_bytes(request.connection.cookie.value, 'big')

        connection = self.device.lookup_connection(connection_handle)
        if connection is None:
            raise RuntimeError('Connection not exist')

        if request.type_variant() == 'fixed':
            # For fixed channel connection, do nothing because it's connectionless
            assert request.fixed
            cid = request.fixed.cid
            l2cap_cookie = any_pb2.Any(value=struct.pack('>HH', connection_handle, cid))
            self.channels[connection_handle][cid] = FixedChannelProxy(
                connection_handle=connection_handle,
                cid=cid,
                device=self.device,
            )

            def on_fixed_pdu(connection_handle: int, pdu: bytes) -> None:
                self.channels[connection_handle][cid].on_data(pdu)

            self.device.l2cap_channel_manager.register_fixed_channel(cid, on_fixed_pdu)
            return l2cap_pb2.ConnectResponse(
                channel=l2cap_pb2.Channel(cookie=l2cap_cookie)
            )

        if request.type_variant() == 'basic':
            assert request.basic
            channel = await connection.create_l2cap_channel(
                spec=l2cap.ClassicChannelSpec(
                    psm=request.basic.psm, mtu=request.basic.mtu
                )
            )
        elif request.type_variant() == 'le_credit_based':
            assert request.le_credit_based
            channel = await connection.create_l2cap_channel(
                spec=l2cap.LeCreditBasedChannelSpec(
                    psm=request.le_credit_based.spsm,
                    max_credits=request.le_credit_based.initial_credit,
                    mtu=request.le_credit_based.mtu,
                    mps=request.le_credit_based.mps,
                )
            )
        else:
            raise NotImplementedError()

        self.channels[connection_handle][channel.source_cid] = CocChannelProxy(channel)
        l2cap_cookie = any_pb2.Any(
            value=struct.pack('>HH', connection_handle, channel.source_cid)
        )
        return l2cap_pb2.ConnectResponse(channel=l2cap_pb2.Channel(cookie=l2cap_cookie))

    @utils.rpc
    async def OnConnection(
        self, request: l2cap_pb2.OnConnectionRequest, context: grpc.ServicerContext
    ) -> AsyncGenerator[l2cap_pb2.OnConnectionResponse, None]:
        self.log.debug('WaitConnection')

        queue: asyncio.Queue[l2cap_pb2.OnConnectionResponse] = asyncio.Queue()

        watcher = EventWatcher()
        server: Union[
            l2cap.ClassicChannelServer, l2cap.LeCreditBasedChannelServer, None
        ] = None
        fixed_cid: Optional[int] = None

        # Fixed channels are connectionless, so it should produce a response immediately.
        if request.type_variant() == 'fixed':
            assert request.fixed
            fixed_cid = request.fixed.cid

            def on_fixed_pdu(connection_handle: int, pdu: bytes) -> None:
                self.channels[connection_handle][fixed_cid].on_data(pdu)

                channel_proxy = FixedChannelProxy(
                    connection_handle=connection_handle,
                    cid=fixed_cid,
                    device=self.device,
                )
                self.channels[connection_handle][fixed_cid] = channel_proxy
                l2cap_cookie = any_pb2.Any(
                    value=struct.pack('>HH', connection_handle, fixed_cid)
                )

                queue.put_nowait(
                    l2cap_pb2.OnConnectionResponse(
                        channel=l2cap_pb2.Channel(cookie=l2cap_cookie)
                    )
                )

            # Register CID and callback
            self.device.l2cap_channel_manager.register_fixed_channel(
                fixed_cid, on_fixed_pdu
            )
        else:

            def on_connected(
                channel: Union[l2cap.ClassicChannel, l2cap.LeCreditBasedChannel]
            ) -> None:
                connection_handle = channel.connection.handle

                # Save channel instances
                cid = channel.source_cid
                self.channels[connection_handle][cid] = CocChannelProxy(channel)

                # Produce connection responses
                l2cap_cookie = any_pb2.Any(
                    value=struct.pack('>HH', connection_handle, cid)
                )
                queue.put_nowait(
                    l2cap_pb2.OnConnectionResponse(
                        channel=l2cap_pb2.Channel(cookie=l2cap_cookie)
                    )
                )

                # Listen disconnections
                @watcher.on(channel, 'close')
                def on_close():
                    del self.channels[connection_handle][cid]

            if request.type_variant() == 'basic':
                assert request.basic
                server = self.device.create_l2cap_server(
                    spec=l2cap.ClassicChannelSpec(psm=request.basic.psm),
                    handler=on_connected,
                )
            elif request.type_variant() == 'le_credit_based':
                assert request.le_credit_based
                server = self.device.create_l2cap_server(
                    spec=l2cap.LeCreditBasedChannelSpec(
                        psm=request.le_credit_based.spsm,
                        max_credits=request.le_credit_based.initial_credit,
                        mtu=request.le_credit_based.mtu,
                        mps=request.le_credit_based.mps,
                    ),
                    handler=on_connected,
                )
            else:
                raise NotImplementedError()

        try:
            # Produce event stream
            while event := await queue.get():
                yield event
        finally:
            watcher.close()
            if server:
                server.close()
            if fixed_cid:
                self.device.l2cap_channel_manager.deregister_fixed_channel(fixed_cid)

    @utils.rpc
    async def Disconnect(
        self, request: l2cap_pb2.DisconnectRequest, context: grpc.ServicerContext
    ) -> l2cap_pb2.DisconnectResponse:
        self.log.debug('Disconnect')
        channel = self.get_channel(request.channel)
        if isinstance(channel, FixedChannelProxy):
            raise ValueError('Fixed channel cannot be disconnected')

        assert isinstance(channel, CocChannelProxy)
        await channel.disconnect()
        return l2cap_pb2.DisconnectResponse(success=empty_pb2.Empty())

    @utils.rpc
    async def WaitDisconnection(
        self, request: l2cap_pb2.WaitDisconnectionRequest, context: grpc.ServicerContext
    ) -> l2cap_pb2.WaitDisconnectionResponse:
        self.log.debug('WaitDisconnection')
        channel = self.get_channel(request.channel)
        if isinstance(channel, FixedChannelProxy):
            raise RuntimeError('Fixed channel cannot be disconnected')

        assert isinstance(channel, CocChannelProxy)
        await channel.wait_disconnect()
        return l2cap_pb2.WaitDisconnectionResponse(success=empty_pb2.Empty())

    @utils.rpc
    async def Receive(
        self, request: l2cap_pb2.ReceiveRequest, context: grpc.ServicerContext
    ) -> AsyncGenerator[l2cap_pb2.ReceiveResponse, None]:
        self.log.debug('Receive')
        channel = self.get_channel(request.channel)

        while packet := await channel.receive():
            yield l2cap_pb2.ReceiveResponse(data=packet)

    @utils.rpc
    async def Send(
        self, request: l2cap_pb2.SendRequest, context: grpc.ServicerContext
    ) -> l2cap_pb2.SendResponse:
        self.log.debug('Send')
        channel = self.get_channel(request.channel)
        channel.send(request.data)
        return l2cap_pb2.SendResponse(success=empty_pb2.Empty())
