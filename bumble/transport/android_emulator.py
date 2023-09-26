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
import logging
import grpc.aio

from typing import Optional, Union

from .common import PumpedTransport, PumpedPacketSource, PumpedPacketSink, Transport

# pylint: disable=no-name-in-module
from .grpc_protobuf.emulated_bluetooth_pb2_grpc import EmulatedBluetoothServiceStub
from .grpc_protobuf.emulated_bluetooth_packets_pb2 import HCIPacket
from .grpc_protobuf.emulated_bluetooth_vhci_pb2_grpc import VhciForwardingServiceStub


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_android_emulator_transport(spec: Optional[str]) -> Transport:
    '''
    Open a transport connection to an Android emulator via its gRPC interface.
    The parameter string has this syntax:
    [<remote-host>:<remote-port>][,mode=<host|controller>]
    The <remote-host>:<remote-port> part is optional, it defaults to localhost:8554
    The mode=<mode> part is optional, it defaults to mode=host
    When the mode is set to 'controller', the connection is for a controller (i.e the
    Android Bluetooth stack will use the connected endpoint as its controller). When
    the mode is set to 'host', the connection is to the 'Root Canal' virtual controller
    that runs as part of the emulator, and used by the Android Bluetooth stack.

    Examples:
    (empty string) --> connect as a host to the emulator on localhost:8554
    localhost:8555 --> connect as a host to the emulator on localhost:8555
    mode=controller --> connect as a controller to the emulator on localhost:8554
    '''

    # Wrapper for I/O operations
    class HciDevice:
        def __init__(self, hci_device):
            self.hci_device = hci_device

        async def read(self):
            packet = await self.hci_device.read()
            return bytes([packet.type]) + packet.packet

        async def write(self, packet):
            await self.hci_device.write(HCIPacket(type=packet[0], packet=packet[1:]))

    # Parse the parameters
    mode = 'host'
    server_host = 'localhost'
    server_port = '8554'
    if spec is not None:
        params = spec.split(',')
        for param in params:
            if param.startswith('mode='):
                mode = param.split('=')[1]
            elif ':' in param:
                server_host, server_port = param.split(':')
            else:
                raise ValueError('invalid parameter')

    # Connect to the gRPC server
    server_address = f'{server_host}:{server_port}'
    logger.debug(f'connecting to gRPC server at {server_address}')
    channel = grpc.aio.insecure_channel(server_address)

    service: Union[EmulatedBluetoothServiceStub, VhciForwardingServiceStub]
    if mode == 'host':
        # Connect as a host
        service = EmulatedBluetoothServiceStub(channel)
        hci_device = HciDevice(service.registerHCIDevice())
    elif mode == 'controller':
        # Connect as a controller
        service = VhciForwardingServiceStub(channel)
        hci_device = HciDevice(service.attachVhci())
    else:
        raise ValueError('invalid mode')

    # Create the transport object
    class EmulatorTransport(PumpedTransport):
        async def close(self):
            await super().close()
            await channel.close()

    transport = EmulatorTransport(
        PumpedPacketSource(hci_device.read), PumpedPacketSink(hci_device.write)
    )
    transport.start()

    return transport
