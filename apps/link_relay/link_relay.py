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

# ----------------------------------------------------------------------------
# Imports
# ----------------------------------------------------------------------------
import sys
import logging
import json
import asyncio
import argparse
import uuid
import os
from urllib.parse import urlparse
import websockets

from bumble.colors import color

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
DEFAULT_RELAY_PORT = 10723


# ----------------------------------------------------------------------------
# Utils
# ----------------------------------------------------------------------------
def error_to_json(error):
    return json.dumps({'error': error})


def error_to_result(error):
    return f'result:{error_to_json(error)}'


async def broadcast_message(message, connections):
    # Send to all the connections
    tasks = [connection.send_message(message) for connection in connections]
    if tasks:
        await asyncio.gather(*tasks)


# ----------------------------------------------------------------------------
# Connection class
# ----------------------------------------------------------------------------
class Connection:
    """
    A Connection represents a client connected to the relay over a websocket
    """

    def __init__(self, room, websocket):
        self.room = room
        self.websocket = websocket
        self.address = str(uuid.uuid4())

    async def send_message(self, message):
        try:
            logger.debug(color(f'->{self.address}: {message}', 'yellow'))
            return await self.websocket.send(message)
        except websockets.exceptions.WebSocketException as error:
            logger.info(f'! client "{self}" disconnected: {error}')
            await self.cleanup()

    async def send_error(self, error):
        return await self.send_message(f'result:{error_to_json(error)}')

    async def receive_message(self):
        try:
            message = await self.websocket.recv()
            logger.debug(color(f'<-{self.address}: {message}', 'blue'))
            return message
        except websockets.exceptions.WebSocketException as error:
            logger.info(color(f'! client "{self}" disconnected: {error}', 'red'))
            await self.cleanup()

    async def cleanup(self):
        if self.room:
            await self.room.remove_connection(self)

    def set_address(self, address):
        logger.info(f'Connection address changed: {self.address} -> {address}')
        self.address = address

    def __str__(self):
        return (
            f'Connection(address="{self.address}", '
            f'client={self.websocket.remote_address[0]}:'
            f'{self.websocket.remote_address[1]})'
        )


# ----------------------------------------------------------------------------
# Room class
# ----------------------------------------------------------------------------
class Room:
    """
    A Room is a collection of bridged connections
    """

    def __init__(self, relay, name):
        self.relay = relay
        self.name = name
        self.observers = []
        self.connections = []

    async def add_connection(self, connection):
        logger.info(f'New participant in {self.name}: {connection}')
        self.connections.append(connection)
        await self.broadcast_message(connection, f'joined:{connection.address}')

    async def remove_connection(self, connection):
        if connection in self.connections:
            self.connections.remove(connection)
            await self.broadcast_message(connection, f'left:{connection.address}')

    def find_connections_by_address(self, address):
        return [c for c in self.connections if c.address == address]

    async def bridge_connection(self, connection):
        while True:
            # Wait for a message
            message = await connection.receive_message()

            # Skip empty messages
            if message is None:
                return

            # Parse the message to decide how to handle it
            if message.startswith('@'):
                # This is a targeted message
                await self.on_targeted_message(connection, message)
            elif message.startswith('/'):
                # This is an RPC request
                await self.on_rpc_request(connection, message)
            else:
                await connection.send_message(
                    f'result:{error_to_json("error: invalid message")}'
                )

    async def broadcast_message(self, sender, message):
        '''
        Send to all connections in the room except back to the sender
        '''
        await broadcast_message(message, [c for c in self.connections if c != sender])

    async def on_rpc_request(self, connection, message):
        command, *params = message.split(' ', 1)
        if handler := getattr(
            self, f'on_{command[1:].lower().replace("-","_")}_command', None
        ):
            try:
                result = await handler(connection, params)
            except Exception as error:
                result = error_to_result(error)
        else:
            result = error_to_result('unknown command')

        await connection.send_message(result or 'result:{}')

    async def on_targeted_message(self, connection, message):
        target, *payload = message.split(' ', 1)
        if not payload:
            return error_to_json('missing arguments')
        payload = payload[0]
        target = target[1:]

        # Determine what targets to send to
        if target == '*':
            # Send to all connections in the room except the connection from which the
            # message was received
            connections = [c for c in self.connections if c != connection]
        else:
            connections = self.find_connections_by_address(target)
            if not connections:
                # Unicast with no recipient, let the sender know
                await connection.send_message(f'unreachable:{target}')

        # Send to targets
        await broadcast_message(f'message:{connection.address}/{payload}', connections)

    async def on_set_address_command(self, connection, params):
        if not params:
            return error_to_result('missing address')

        current_address = connection.address
        new_address = params[0]
        connection.set_address(new_address)
        await self.broadcast_message(
            connection, f'address-changed:from={current_address},to={new_address}'
        )


# ----------------------------------------------------------------------------
class Relay:
    """
    A relay accepts connections with the following url: ws://<hostname>/<room>.
    Participants in a room can communicate with each other
    """

    def __init__(self, port):
        self.port = port
        self.rooms = {}
        self.observers = []

    def start(self):
        logger.info(f'Starting Relay on port {self.port}')

        # pylint: disable-next=no-member
        return websockets.serve(self.serve, '0.0.0.0', self.port, ping_interval=None)

    async def serve_as_controller(self, connection):
        pass

    async def serve(self, websocket, path):
        logger.debug(f'New connection with path {path}')

        # Parse the path
        parsed = urlparse(path)

        # Check if this is a controller client
        if parsed.path == '/':
            return await self.serve_as_controller(Connection('', websocket))

        # Find or create a room for this connection
        room_name = parsed.path[1:].split('/')[0]
        if room_name not in self.rooms:
            self.rooms[room_name] = Room(self, room_name)
        room = self.rooms[room_name]

        # Add the connection to the room
        connection = Connection(room, websocket)
        await room.add_connection(connection)

        # Bridge until the connection is closed
        await room.bridge_connection(connection)


# ----------------------------------------------------------------------------
def main():
    # Check the Python version
    if sys.version_info < (3, 6, 1):
        print('ERROR: Python 3.6.1 or higher is required')
        sys.exit(1)

    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())

    # Parse arguments
    arg_parser = argparse.ArgumentParser(description='Bumble Link Relay')
    arg_parser.add_argument('--log-level', default='INFO', help='logger level')
    arg_parser.add_argument('--log-config', help='logger config file (YAML)')
    arg_parser.add_argument(
        '--port', type=int, default=DEFAULT_RELAY_PORT, help='Port to listen on'
    )
    args = arg_parser.parse_args()

    # Setup logger
    if args.log_config:
        from logging import config  # pylint: disable=import-outside-toplevel

        config.fileConfig(args.log_config)
    else:
        logging.basicConfig(level=getattr(logging, args.log_level.upper()))

    # Start a relay
    relay = Relay(args.port)
    asyncio.get_event_loop().run_until_complete(relay.start())
    asyncio.get_event_loop().run_forever()


# ----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
