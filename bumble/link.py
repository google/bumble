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
from functools import partial

from bumble.core import BT_PERIPHERAL_ROLE, BT_BR_EDR_TRANSPORT, BT_LE_TRANSPORT
from bumble.colors import color
from bumble.hci import (
    Address,
    HCI_SUCCESS,
    HCI_CONNECTION_ACCEPT_TIMEOUT_ERROR,
    HCI_CONNECTION_TIMEOUT_ERROR,
    HCI_PAGE_TIMEOUT_ERROR,
    HCI_Connection_Complete_Event,
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def parse_parameters(params_str):
    result = {}
    for param_str in params_str.split(','):
        if '=' in param_str:
            key, value = param_str.split('=')
            result[key] = value
    return result


# -----------------------------------------------------------------------------
# TODO: add more support for various LL exchanges
# (see Vol 6, Part B - 2.4 DATA CHANNEL PDU)
# -----------------------------------------------------------------------------
class LocalLink:
    '''
    Link bus for controllers to communicate with each other
    '''

    def __init__(self):
        self.controllers = set()
        self.pending_connection = None
        self.pending_classic_connection = None

    ############################################################
    # Common utils
    ############################################################

    def add_controller(self, controller):
        logger.debug(f'new controller: {controller}')
        self.controllers.add(controller)

    def remove_controller(self, controller):
        self.controllers.remove(controller)

    def find_controller(self, address):
        for controller in self.controllers:
            if controller.random_address == address:
                return controller
        return None

    def find_classic_controller(self, address):
        for controller in self.controllers:
            if controller.public_address == address:
                return controller
        return None

    def get_pending_connection(self):
        return self.pending_connection

    ############################################################
    # LE handlers
    ############################################################

    def on_address_changed(self, controller):
        pass

    def send_advertising_data(self, sender_address, data):
        # Send the advertising data to all controllers, except the sender
        for controller in self.controllers:
            if controller.random_address != sender_address:
                controller.on_link_advertising_data(sender_address, data)

    def send_acl_data(self, sender_controller, destination_address, transport, data):
        # Send the data to the first controller with a matching address
        if transport == BT_LE_TRANSPORT:
            destination_controller = self.find_controller(destination_address)
            source_address = sender_controller.random_address
        elif transport == BT_BR_EDR_TRANSPORT:
            destination_controller = self.find_classic_controller(destination_address)
            source_address = sender_controller.public_address

        if destination_controller is not None:
            destination_controller.on_link_acl_data(source_address, transport, data)

    def on_connection_complete(self):
        # Check that we expect this call
        if not self.pending_connection:
            logger.warning('on_connection_complete with no pending connection')
            return

        central_address, le_create_connection_command = self.pending_connection
        self.pending_connection = None

        # Find the controller that initiated the connection
        if not (central_controller := self.find_controller(central_address)):
            logger.warning('!!! Initiating controller not found')
            return

        # Connect to the first controller with a matching address
        if peripheral_controller := self.find_controller(
            le_create_connection_command.peer_address
        ):
            central_controller.on_link_peripheral_connection_complete(
                le_create_connection_command, HCI_SUCCESS
            )
            peripheral_controller.on_link_central_connected(central_address)
            return

        # No peripheral found
        central_controller.on_link_peripheral_connection_complete(
            le_create_connection_command, HCI_CONNECTION_ACCEPT_TIMEOUT_ERROR
        )

    def connect(self, central_address, le_create_connection_command):
        logger.debug(
            f'$$$ CONNECTION {central_address} -> '
            f'{le_create_connection_command.peer_address}'
        )
        self.pending_connection = (central_address, le_create_connection_command)
        asyncio.get_running_loop().call_soon(self.on_connection_complete)

    def on_disconnection_complete(
        self, central_address, peripheral_address, disconnect_command
    ):
        # Find the controller that initiated the disconnection
        if not (central_controller := self.find_controller(central_address)):
            logger.warning('!!! Initiating controller not found')
            return

        # Disconnect from the first controller with a matching address
        if peripheral_controller := self.find_controller(peripheral_address):
            peripheral_controller.on_link_central_disconnected(
                central_address, disconnect_command.reason
            )

        central_controller.on_link_peripheral_disconnection_complete(
            disconnect_command, HCI_SUCCESS
        )

    def disconnect(self, central_address, peripheral_address, disconnect_command):
        logger.debug(
            f'$$$ DISCONNECTION {central_address} -> '
            f'{peripheral_address}: reason = {disconnect_command.reason}'
        )
        args = [central_address, peripheral_address, disconnect_command]
        asyncio.get_running_loop().call_soon(self.on_disconnection_complete, *args)

    # pylint: disable=too-many-arguments
    def on_connection_encrypted(
        self, central_address, peripheral_address, rand, ediv, ltk
    ):
        logger.debug(f'*** ENCRYPTION {central_address} -> {peripheral_address}')

        if central_controller := self.find_controller(central_address):
            central_controller.on_link_encrypted(peripheral_address, rand, ediv, ltk)

        if peripheral_controller := self.find_controller(peripheral_address):
            peripheral_controller.on_link_encrypted(central_address, rand, ediv, ltk)

    ############################################################
    # Classic handlers
    ############################################################

    def classic_connect(self, initiator_controller, responder_address):
        logger.debug(
            f'[Classic] {initiator_controller.public_address} connects to {responder_address}'
        )
        responder_controller = self.find_classic_controller(responder_address)
        if responder_controller is None:
            initiator_controller.on_classic_connection_complete(
                responder_address, HCI_PAGE_TIMEOUT_ERROR
            )
            return
        self.pending_classic_connection = (initiator_controller, responder_controller)

        responder_controller.on_classic_connection_request(
            initiator_controller.public_address,
            HCI_Connection_Complete_Event.ACL_LINK_TYPE,
        )

    def classic_accept_connection(
        self, responder_controller, initiator_address, responder_role
    ):
        logger.debug(
            f'[Classic] {responder_controller.public_address} accepts to connect {initiator_address}'
        )
        initiator_controller = self.find_classic_controller(initiator_address)
        if initiator_controller is None:
            responder_controller.on_classic_connection_complete(
                responder_controller.public_address, HCI_PAGE_TIMEOUT_ERROR
            )
            return

        async def task():
            if responder_role != BT_PERIPHERAL_ROLE:
                initiator_controller.on_classic_role_change(
                    responder_controller.public_address, int(not (responder_role))
                )
            initiator_controller.on_classic_connection_complete(
                responder_controller.public_address, HCI_SUCCESS
            )

        asyncio.create_task(task())
        responder_controller.on_classic_role_change(
            initiator_controller.public_address, responder_role
        )
        responder_controller.on_classic_connection_complete(
            initiator_controller.public_address, HCI_SUCCESS
        )
        self.pending_classic_connection = None

    def classic_disconnect(self, initiator_controller, responder_address, reason):
        logger.debug(
            f'[Classic] {initiator_controller.public_address} disconnects {responder_address}'
        )
        responder_controller = self.find_classic_controller(responder_address)

        async def task():
            initiator_controller.on_classic_disconnected(responder_address, reason)

        asyncio.create_task(task())
        responder_controller.on_classic_disconnected(
            initiator_controller.public_address, reason
        )

    def classic_switch_role(
        self, initiator_controller, responder_address, initiator_new_role
    ):
        responder_controller = self.find_classic_controller(responder_address)
        if responder_controller is None:
            return

        async def task():
            initiator_controller.on_classic_role_change(
                responder_address, initiator_new_role
            )

        asyncio.create_task(task())
        responder_controller.on_classic_role_change(
            initiator_controller.public_address, int(not (initiator_new_role))
        )


# -----------------------------------------------------------------------------
class RemoteLink:
    '''
    A Link implementation that communicates with other virtual controllers via a
    WebSocket relay
    '''

    def __init__(self, uri):
        self.controller = None
        self.uri = uri
        self.execution_queue = asyncio.Queue()
        self.websocket = asyncio.get_running_loop().create_future()
        self.rpc_result = None
        self.pending_connection = None
        self.central_connections = set()  # List of addresses that we have connected to
        self.peripheral_connections = (
            set()
        )  # List of addresses that have connected to us

        # Connect and run asynchronously
        asyncio.create_task(self.run_connection())
        asyncio.create_task(self.run_executor_loop())

    def add_controller(self, controller):
        if self.controller:
            raise ValueError('controller already set')
        self.controller = controller

    def remove_controller(self, controller):
        if self.controller != controller:
            raise ValueError('controller mismatch')
        self.controller = None

    def get_pending_connection(self):
        return self.pending_connection

    def get_pending_classic_connection(self):
        return self.pending_classic_connection

    async def wait_until_connected(self):
        await self.websocket

    def execute(self, async_function):
        self.execution_queue.put_nowait(async_function())

    async def run_executor_loop(self):
        logger.debug('executor loop starting')
        while True:
            item = await self.execution_queue.get()
            try:
                await item
            except Exception as error:
                logger.warning(
                    f'{color("!!! Exception in async handler:", "red")} {error}'
                )

    async def run_connection(self):
        import websockets  # lazy import

        # Connect to the relay
        logger.debug(f'connecting to {self.uri}')
        # pylint: disable-next=no-member
        websocket = await websockets.connect(self.uri)
        self.websocket.set_result(websocket)
        logger.debug(f'connected to {self.uri}')

        while True:
            message = await websocket.recv()
            logger.debug(f'received message: {message}')
            keyword, *payload = message.split(':', 1)

            handler_name = f'on_{keyword}_received'
            handler = getattr(self, handler_name, None)
            if handler:
                await handler(payload[0] if payload else None)

    def close(self):
        if self.websocket.done():
            logger.debug('closing websocket')
            websocket = self.websocket.result()
            asyncio.create_task(websocket.close())

    async def on_result_received(self, result):
        if self.rpc_result:
            self.rpc_result.set_result(result)

    async def on_left_received(self, address):
        if address in self.central_connections:
            self.controller.on_link_peripheral_disconnected(Address(address))
            self.central_connections.remove(address)

        if address in self.peripheral_connections:
            self.controller.on_link_central_disconnected(
                address, HCI_CONNECTION_TIMEOUT_ERROR
            )
            self.peripheral_connections.remove(address)

    async def on_unreachable_received(self, target):
        await self.on_left_received(target)

    async def on_message_received(self, message):
        sender, *payload = message.split('/', 1)
        if payload:
            keyword, *payload = payload[0].split(':', 1)
            handler_name = f'on_{keyword}_message_received'
            handler = getattr(self, handler_name, None)
            if handler:
                await handler(sender, payload[0] if payload else None)

    async def on_advertisement_message_received(self, sender, advertisement):
        try:
            self.controller.on_link_advertising_data(
                Address(sender), bytes.fromhex(advertisement)
            )
        except Exception:
            logger.exception('exception')

    async def on_acl_message_received(self, sender, acl_data):
        try:
            self.controller.on_link_acl_data(Address(sender), bytes.fromhex(acl_data))
        except Exception:
            logger.exception('exception')

    async def on_connect_message_received(self, sender, _):
        # Remember the connection
        self.peripheral_connections.add(sender)

        # Notify the controller
        logger.debug(f'connection from central {sender}')
        self.controller.on_link_central_connected(Address(sender))

        # Accept the connection by responding to it
        await self.send_targeted_message(sender, 'connected')

    async def on_connected_message_received(self, sender, _):
        if not self.pending_connection:
            logger.warning('received a connection ack, but no connection is pending')
            return

        # Remember the connection
        self.central_connections.add(sender)

        # Notify the controller
        logger.debug(f'connected to peripheral {self.pending_connection.peer_address}')
        self.controller.on_link_peripheral_connection_complete(
            self.pending_connection, HCI_SUCCESS
        )

    async def on_disconnect_message_received(self, sender, message):
        # Notify the controller
        params = parse_parameters(message)
        reason = int(params.get('reason', str(HCI_CONNECTION_TIMEOUT_ERROR)))
        self.controller.on_link_central_disconnected(Address(sender), reason)

        # Forget the connection
        if sender in self.peripheral_connections:
            self.peripheral_connections.remove(sender)

    async def on_encrypted_message_received(self, sender, _):
        # TODO parse params to get real args
        self.controller.on_link_encrypted(Address(sender), bytes(8), 0, bytes(16))

    async def send_rpc_command(self, command):
        # Ensure we have a connection
        websocket = await self.websocket

        # Create a future value to hold the eventual result
        assert self.rpc_result is None
        self.rpc_result = asyncio.get_running_loop().create_future()

        # Send the command
        await websocket.send(command)

        # Wait for the result
        rpc_result = await self.rpc_result
        self.rpc_result = None
        logger.debug(f'rpc_result: {rpc_result}')

        # TODO: parse the result

    async def send_targeted_message(self, target, message):
        # Ensure we have a connection
        websocket = await self.websocket

        # Send the message
        await websocket.send(f'@{target} {message}')

    async def notify_address_changed(self):
        await self.send_rpc_command(f'/set-address {self.controller.random_address}')

    def on_address_changed(self, controller):
        logger.info(f'address changed for {controller}: {controller.random_address}')

        # Notify the relay of the change
        self.execute(self.notify_address_changed)

    async def send_advertising_data_to_relay(self, data):
        await self.send_targeted_message('*', f'advertisement:{data.hex()}')

    def send_advertising_data(self, _, data):
        self.execute(partial(self.send_advertising_data_to_relay, data))

    async def send_acl_data_to_relay(self, peer_address, data):
        await self.send_targeted_message(peer_address, f'acl:{data.hex()}')

    def send_acl_data(self, _, peer_address, _transport, data):
        # TODO: handle different transport
        self.execute(partial(self.send_acl_data_to_relay, peer_address, data))

    async def send_connection_request_to_relay(self, peer_address):
        await self.send_targeted_message(peer_address, 'connect')

    def connect(self, _, le_create_connection_command):
        if self.pending_connection:
            logger.warning('connection already pending')
            return
        self.pending_connection = le_create_connection_command
        self.execute(
            partial(
                self.send_connection_request_to_relay,
                str(le_create_connection_command.peer_address),
            )
        )

    def on_disconnection_complete(self, disconnect_command):
        self.controller.on_link_peripheral_disconnection_complete(
            disconnect_command, HCI_SUCCESS
        )

    def disconnect(self, central_address, peripheral_address, disconnect_command):
        logger.debug(
            f'disconnect {central_address} -> '
            f'{peripheral_address}: reason = {disconnect_command.reason}'
        )
        self.execute(
            partial(
                self.send_targeted_message,
                peripheral_address,
                f'disconnect:reason={disconnect_command.reason}',
            )
        )
        asyncio.get_running_loop().call_soon(
            self.on_disconnection_complete, disconnect_command
        )

    def on_connection_encrypted(self, _, peripheral_address, rand, ediv, ltk):
        asyncio.get_running_loop().call_soon(
            self.controller.on_link_encrypted, peripheral_address, rand, ediv, ltk
        )
        self.execute(
            partial(
                self.send_targeted_message,
                peripheral_address,
                f'encrypted:ltk={ltk.hex()}',
            )
        )
