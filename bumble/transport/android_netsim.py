# Copyright 2021-2023 Google LLC
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
import atexit
import logging
import os
import pathlib
import platform
import sys
from typing import Dict, Optional

import grpc.aio

import bumble
from bumble.transport.common import (
    ParserSource,
    PumpedTransport,
    PumpedPacketSource,
    PumpedPacketSink,
    Transport,
    TransportSpecError,
    TransportInitError,
)

# pylint: disable=no-name-in-module
from bumble.transport.grpc_protobuf.netsim.packet_streamer_pb2_grpc import (
    PacketStreamerStub,
    PacketStreamerServicer,
    add_PacketStreamerServicer_to_server,
)
from bumble.transport.grpc_protobuf.netsim.packet_streamer_pb2 import (
    PacketRequest,
    PacketResponse,
)
from bumble.transport.grpc_protobuf.netsim.hci_packet_pb2 import HCIPacket
from bumble.transport.grpc_protobuf.netsim.startup_pb2 import Chip, ChipInfo, DeviceInfo
from bumble.transport.grpc_protobuf.netsim.common_pb2 import ChipKind


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_NAME = 'bumble0'
DEFAULT_MANUFACTURER = 'Bumble'
DEFAULT_VARIANT = ''


# -----------------------------------------------------------------------------
def get_ini_dir() -> Optional[pathlib.Path]:
    if sys.platform == 'darwin':
        if tmpdir := os.getenv('TMPDIR', None):
            return pathlib.Path(tmpdir)
        if home := os.getenv('HOME', None):
            return pathlib.Path(home) / 'Library/Caches/TemporaryItems'
    elif sys.platform == 'linux':
        if xdg_runtime_dir := os.environ.get('XDG_RUNTIME_DIR', None):
            return pathlib.Path(xdg_runtime_dir)
        tmpdir = os.environ.get('TMPDIR', '/tmp')
        if pathlib.Path(tmpdir).is_dir():
            return pathlib.Path(tmpdir)
    elif sys.platform == 'win32':
        if local_app_data_dir := os.environ.get('LOCALAPPDATA', None):
            return pathlib.Path(local_app_data_dir) / 'Temp'

    return None


# -----------------------------------------------------------------------------
def ini_file_name(instance_number: int) -> str:
    suffix = f'_{instance_number}' if instance_number > 0 else ''
    return f'netsim{suffix}.ini'


# -----------------------------------------------------------------------------
def find_grpc_port(instance_number: int) -> int:
    if not (ini_dir := get_ini_dir()):
        logger.debug('no known directory for .ini file')
        return 0

    ini_file = ini_dir / ini_file_name(instance_number)
    logger.debug(f'Looking for .ini file at {ini_file}')
    if ini_file.is_file():
        with open(ini_file, 'r') as ini_file_data:
            for line in ini_file_data.readlines():
                if '=' in line:
                    key, value = line.split('=')
                    if key == 'grpc.port':
                        logger.debug(f'gRPC port = {value}')
                        return int(value)

        logger.debug('no grpc.port property found in .ini file')

    # Not found
    return 0


# -----------------------------------------------------------------------------
def publish_grpc_port(grpc_port: int, instance_number: int) -> bool:
    if not (ini_dir := get_ini_dir()):
        logger.debug('no known directory for .ini file')
        return False

    if not ini_dir.is_dir():
        logger.debug('ini directory does not exist')
        return False

    ini_file = ini_dir / ini_file_name(instance_number)
    try:
        ini_file.write_text(f'grpc.port={grpc_port}\n')
        logger.debug(f"published gRPC port at {ini_file}")

        def cleanup():
            logger.debug("removing .ini file")
            ini_file.unlink()

        atexit.register(cleanup)
        return True
    except OSError:
        logger.debug('failed to write to .ini file')
        return False


# -----------------------------------------------------------------------------
async def open_android_netsim_controller_transport(
    server_host: Optional[str], server_port: int, options: Dict[str, str]
) -> Transport:
    if not server_port:
        raise TransportSpecError('invalid port')
    if server_host == '_' or not server_host:
        server_host = 'localhost'

    instance_number = int(options.get('instance', "0"))
    if not publish_grpc_port(server_port, instance_number):
        logger.warning("unable to publish gRPC port")

    class HciDevice:
        def __init__(self, context, on_data_received):
            self.context = context
            self.on_data_received = on_data_received
            self.name = None
            self.loop = asyncio.get_running_loop()
            self.done = self.loop.create_future()
            self.task = self.loop.create_task(self.pump())

        async def pump(self):
            try:
                await self.pump_loop()
            except asyncio.CancelledError:
                logger.debug('Pump task canceled')
                self.done.set_result(None)

        async def pump_loop(self):
            while True:
                request = await self.context.read()
                if request == grpc.aio.EOF:
                    logger.debug('End of request stream')
                    self.done.set_result(None)
                    return

                # If we're not initialized yet, wait for a init packet.
                if self.name is None:
                    if request.WhichOneof('request_type') == 'initial_info':
                        logger.debug(f'Received initial info: {request}')

                        # We only accept BLUETOOTH
                        if request.initial_info.chip.kind != ChipKind.BLUETOOTH:
                            logger.warning('Unsupported chip type')
                            error = PacketResponse(error='Unsupported chip type')
                            await self.context.write(error)
                            return

                    self.name = request.initial_info.name
                    continue

                # Expect a data packet
                request_type = request.WhichOneof('request_type')
                if request_type != 'hci_packet':
                    logger.warning(f'Unexpected request type: {request_type}')
                    error = PacketResponse(error='Unexpected request type')
                    await self.context.write(error)
                    continue

                # Process the packet
                data = (
                    bytes([request.hci_packet.packet_type]) + request.hci_packet.packet
                )
                self.on_data_received(data)

        async def send_packet(self, data):
            return await self.context.write(
                PacketResponse(
                    hci_packet=HCIPacket(packet_type=data[0], packet=data[1:])
                )
            )

        def terminate(self):
            self.task.cancel()

        async def wait_for_termination(self):
            await self.done

    class Server(PacketStreamerServicer, ParserSource):
        def __init__(self):
            PacketStreamerServicer.__init__(self)
            ParserSource.__init__(self)
            self.device = None

            # Create a gRPC server with `so_reuseport=0` so that if there's already
            # a server listening on that port, we get an exception.
            self.grpc_server = grpc.aio.server(options=(('grpc.so_reuseport', 0),))
            add_PacketStreamerServicer_to_server(self, self.grpc_server)
            self.grpc_server.add_insecure_port(f'{server_host}:{server_port}')
            logger.debug(f'gRPC server listening on {server_host}:{server_port}')

        async def start(self):
            logger.debug('Starting gRPC server')
            await self.grpc_server.start()

        async def serve(self):
            # Keep serving until terminated.
            try:
                await self.grpc_server.wait_for_termination()
                logger.debug('gRPC server terminated')
            except asyncio.CancelledError:
                logger.debug('gRPC server cancelled')
                await self.grpc_server.stop(None)

        async def send_packet(self, packet):
            if not self.device:
                logger.debug('no device, dropping packet')
                return

            return await self.device.send_packet(packet)

        async def StreamPackets(self, _request_iterator, context):
            logger.debug('StreamPackets request')

            # Check that we don't already have a device
            if self.device:
                logger.debug('Busy, already serving a device')
                return PacketResponse(error='Busy')

            # Instantiate a new device
            self.device = HciDevice(context, self.parser.feed_data)

            # Wait for the device to terminate
            logger.debug('Waiting for device to terminate')
            try:
                await self.device.wait_for_termination()
            except asyncio.CancelledError:
                logger.debug('Request canceled')
                self.device.terminate()

            logger.debug('Device terminated')
            self.device = None

    server = Server()
    await server.start()
    asyncio.get_running_loop().create_task(server.serve())

    sink = PumpedPacketSink(server.send_packet)
    sink.start()
    return Transport(server, sink)


# -----------------------------------------------------------------------------
async def open_android_netsim_host_transport_with_address(
    server_host: Optional[str],
    server_port: int,
    options: Optional[Dict[str, str]] = None,
):
    if server_host == '_' or not server_host:
        server_host = 'localhost'

    if not server_port:
        # Look for the gRPC config in a .ini file
        instance_number = 0 if options is None else int(options.get('instance', '0'))
        server_port = find_grpc_port(instance_number)
        if not server_port:
            raise TransportInitError('gRPC server port not found')

    # Connect to the gRPC server
    server_address = f'{server_host}:{server_port}'
    logger.debug(f'Connecting to gRPC server at {server_address}')
    channel = grpc.aio.insecure_channel(server_address)

    return await open_android_netsim_host_transport_with_channel(
        channel,
        options,
    )


# -----------------------------------------------------------------------------
async def open_android_netsim_host_transport_with_channel(
    channel, options: Optional[Dict[str, str]] = None
):
    # Wrapper for I/O operations
    class HciDevice:
        def __init__(self, name, variant, manufacturer, hci_device):
            self.name = name
            self.variant = variant
            self.manufacturer = manufacturer
            self.hci_device = hci_device

        async def start(self):  # Send the startup info
            device_info = DeviceInfo(
                name=self.name,
                kind='BUMBLE',
                version=bumble.__version__,
                sdk_version=platform.python_version(),
                build_id=platform.platform(),
                arch=platform.machine(),
                variant=self.variant,
            )
            chip = Chip(kind=ChipKind.BLUETOOTH, manufacturer=self.manufacturer)
            chip_info = ChipInfo(name=self.name, chip=chip, device_info=device_info)
            logger.debug(f'Sending chip info to netsim: {chip_info}')
            await self.hci_device.write(PacketRequest(initial_info=chip_info))

        async def read(self):
            response = await self.hci_device.read()
            response_type = response.WhichOneof('response_type')

            if response_type == 'error':
                logger.warning(f'received error: {response.error}')
                raise TransportInitError(response.error)

            if response_type == 'hci_packet':
                return (
                    bytes([response.hci_packet.packet_type])
                    + response.hci_packet.packet
                )

            raise TransportSpecError('unsupported response type')

        async def write(self, packet):
            await self.hci_device.write(
                PacketRequest(
                    hci_packet=HCIPacket(packet_type=packet[0], packet=packet[1:])
                )
            )

    name = DEFAULT_NAME if options is None else options.get('name', DEFAULT_NAME)
    variant = (
        DEFAULT_VARIANT if options is None else options.get('variant', DEFAULT_VARIANT)
    )
    manufacturer = DEFAULT_MANUFACTURER

    # Connect as a host
    service = PacketStreamerStub(channel)
    hci_device = HciDevice(
        name=name,
        variant=variant,
        manufacturer=manufacturer,
        hci_device=service.StreamPackets(),
    )
    await hci_device.start()

    # Create the transport object
    class GrpcTransport(PumpedTransport):
        async def close(self):
            await super().close()
            await channel.close()

    transport = GrpcTransport(
        PumpedPacketSource(hci_device.read),
        PumpedPacketSink(hci_device.write),
    )
    transport.start()

    return transport


# -----------------------------------------------------------------------------
async def open_android_netsim_transport(spec: Optional[str]) -> Transport:
    '''
    Open a transport connection as a client or server, implementing Android's `netsim`
    simulator protocol over gRPC.
    The parameter string has this syntax:
    [<host>:<port>][<options>]
    Where <options> is a ','-separated list of <name>=<value> pairs.

    General options:
      mode=host|controller (default: host)
        Specifies whether the transport is used
        to connect *to* a netsim server (netsim is the controller), or accept
        connections *as* a netsim-compatible server.

      instance=<n>
        Specifies an instance number, with <n> > 0. This is used to determine which
        .init file to use. In `host` mode, it is ignored when the <host>:<port>
        specifier is present, since in that case no .ini file is used.

    In `host` mode:
      The <host>:<port> part is optional. When not specified, the transport
      looks for a netsim .ini file, from which it will read the `grpc.backend.port`
      property.
      Options for this mode are:
        name=<name>
          The "chip" name, used to identify the "chip" instance. This
          may be useful when several clients are connected, since each needs to use a
          different name.
        variant=<variant>
          The device info variant field, which may be used to convey a device or
          application type (ex: "virtual-speaker", or "keyboard")

    In `controller` mode:
      The <host>:<port> part is required. <host> may be the address of a local network
      interface, or '_' to accept connections on all local network interfaces.

    Examples:
    (empty string) --> connect to netsim on the port specified in the .ini file
    localhost:8555 --> connect to netsim on localhost:8555
    name=bumble1 --> connect to netsim, using `bumble1` as the "chip" name.
    localhost:8555,name=bumble1 --> connect to netsim on localhost:8555, using
    `bumble1` as the "chip" name.
    _:8877,mode=controller --> accept connections as a controller on any interface
    on port 8877.
    '''

    # Parse the parameters
    params = spec.split(',') if spec else []
    if params and ':' in params[0]:
        # Explicit <host>:<port>
        host, port_str = params[0].split(':')
        port = int(port_str)
        params_offset = 1
    else:
        host = None
        port = 0
        params_offset = 0

    options: Dict[str, str] = {}
    for param in params[params_offset:]:
        if '=' not in param:
            raise TransportSpecError('invalid parameter, expected <name>=<value>')
        option_name, option_value = param.split('=')
        options[option_name] = option_value

    mode = options.get('mode', 'host')
    if mode == 'host':
        return await open_android_netsim_host_transport_with_address(
            host, port, options
        )
    if mode == 'controller':
        if host is None:
            raise TransportSpecError('<host>:<port> missing')
        return await open_android_netsim_controller_transport(host, port, options)

    raise TransportSpecError('invalid mode option')
