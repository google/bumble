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
import enum
import logging
import os
import struct
import time

import click

from bumble.core import (
    BT_BR_EDR_TRANSPORT,
    BT_LE_TRANSPORT,
    BT_L2CAP_PROTOCOL_ID,
    BT_RFCOMM_PROTOCOL_ID,
    UUID,
    CommandTimeoutError,
)
from bumble.colors import color
from bumble.device import Connection, ConnectionParametersPreferences, Device, Peer
from bumble.gatt import Characteristic, CharacteristicValue, Service
from bumble.hci import (
    HCI_LE_1M_PHY,
    HCI_LE_2M_PHY,
    HCI_LE_CODED_PHY,
    HCI_Constant,
    HCI_Error,
    HCI_StatusError,
)
from bumble.sdp import (
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    DataElement,
    ServiceAttribute,
)
from bumble.transport import open_transport_or_link
import bumble.rfcomm
import bumble.core
from bumble.utils import AsyncRunner


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
DEFAULT_CENTRAL_ADDRESS = 'F0:F0:F0:F0:F0:F0'
DEFAULT_CENTRAL_NAME = 'Speed Central'
DEFAULT_PERIPHERAL_ADDRESS = 'F1:F1:F1:F1:F1:F1'
DEFAULT_PERIPHERAL_NAME = 'Speed Peripheral'

SPEED_SERVICE_UUID = '50DB505C-8AC4-4738-8448-3B1D9CC09CC5'
SPEED_TX_UUID = 'E789C754-41A1-45F4-A948-A0A1A90DBA53'
SPEED_RX_UUID = '016A2CC7-E14B-4819-935F-1F56EAE4098D'

DEFAULT_L2CAP_PSM = 1234
DEFAULT_L2CAP_MAX_CREDITS = 128
DEFAULT_L2CAP_MTU = 1022
DEFAULT_L2CAP_MPS = 1024

DEFAULT_LINGER_TIME = 1.0

DEFAULT_RFCOMM_CHANNEL = 8

# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def parse_packet(packet):
    if len(packet) < 1:
        print(
            color(f'!!! Packet too short (got {len(packet)} bytes, need >= 1)', 'red')
        )
        raise ValueError('packet too short')

    try:
        packet_type = PacketType(packet[0])
    except ValueError:
        print(color(f'!!! Invalid packet type 0x{packet[0]:02X}', 'red'))
        raise

    return (packet_type, packet[1:])


def parse_packet_sequence(packet_data):
    if len(packet_data) < 5:
        print(
            color(
                f'!!!Packet too short (got {len(packet_data)} bytes, need >= 5)',
                'red',
            )
        )
        raise ValueError('packet too short')
    return struct.unpack_from('>bI', packet_data, 0)


def le_phy_name(phy_id):
    return {HCI_LE_1M_PHY: '1M', HCI_LE_2M_PHY: '2M', HCI_LE_CODED_PHY: 'CODED'}.get(
        phy_id, HCI_Constant.le_phy_name(phy_id)
    )


def print_connection(connection):
    if connection.transport == BT_LE_TRANSPORT:
        phy_state = (
            'PHY='
            f'RX:{le_phy_name(connection.phy.rx_phy)}/'
            f'TX:{le_phy_name(connection.phy.tx_phy)}'
        )

        data_length = f'DL={connection.data_length}'
        connection_parameters = (
            'Parameters='
            f'{connection.parameters.connection_interval * 1.25:.2f}/'
            f'{connection.parameters.peripheral_latency}/'
            f'{connection.parameters.supervision_timeout * 10} '
        )

    else:
        phy_state = ''
        data_length = ''
        connection_parameters = ''

    mtu = connection.att_mtu

    print(
        f'{color("@@@ Connection:", "yellow")} '
        f'{connection_parameters} '
        f'{data_length} '
        f'{phy_state} '
        f'MTU={mtu}'
    )


def make_sdp_records(channel):
    return {
        0x00010001: [
            ServiceAttribute(
                SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
                DataElement.unsigned_integer_32(0x00010001),
            ),
            ServiceAttribute(
                SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
                DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
            ),
            ServiceAttribute(
                SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [DataElement.uuid(UUID('E6D55659-C8B4-4B85-96BB-B1143AF6D3AE'))]
                ),
            ),
            ServiceAttribute(
                SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                DataElement.sequence(
                    [
                        DataElement.sequence([DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]),
                        DataElement.sequence(
                            [
                                DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                                DataElement.unsigned_integer_8(channel),
                            ]
                        ),
                    ]
                ),
            ),
        ]
    }


class PacketType(enum.IntEnum):
    RESET = 0
    SEQUENCE = 1
    ACK = 2


PACKET_FLAG_LAST = 1

# -----------------------------------------------------------------------------
# Sender
# -----------------------------------------------------------------------------
class Sender:
    def __init__(self, packet_io, start_delay, packet_size, packet_count):
        self.tx_start_delay = start_delay
        self.tx_packet_size = packet_size
        self.tx_packet_count = packet_count
        self.packet_io = packet_io
        self.packet_io.packet_listener = self
        self.start_time = 0
        self.bytes_sent = 0
        self.done = asyncio.Event()

    def reset(self):
        pass

    async def run(self):
        print(color('--- Waiting for I/O to be ready...', 'blue'))
        await self.packet_io.ready.wait()
        print(color('--- Go!', 'blue'))

        if self.tx_start_delay:
            print(color(f'*** Startup delay: {self.tx_start_delay}', 'blue'))
            await asyncio.sleep(self.tx_start_delay)  # FIXME

        print(color('=== Sending RESET', 'magenta'))
        await self.packet_io.send_packet(bytes([PacketType.RESET]))
        self.start_time = time.time()
        for tx_i in range(self.tx_packet_count):
            packet_flags = PACKET_FLAG_LAST if tx_i == self.tx_packet_count - 1 else 0
            packet = struct.pack(
                '>bbI',
                PacketType.SEQUENCE,
                packet_flags,
                tx_i,
            ) + bytes(self.tx_packet_size - 6)
            print(color(f'Sending packet {tx_i}: {len(packet)} bytes', 'yellow'))
            self.bytes_sent += len(packet)
            await self.packet_io.send_packet(packet)

        await self.done.wait()
        print(color('=== Done!', 'magenta'))

    def on_packet_received(self, packet):
        try:
            packet_type, _ = parse_packet(packet)
        except ValueError:
            return

        if packet_type == PacketType.ACK:
            elapsed = time.time() - self.start_time
            average_tx_speed = self.bytes_sent / elapsed
            print(
                color(
                    f'@@@ Received ACK. Speed: average={average_tx_speed:.4f}'
                    f' ({self.bytes_sent} bytes in {elapsed:.2f} seconds)',
                    'green',
                )
            )
            self.done.set()


# -----------------------------------------------------------------------------
# Receiver
# -----------------------------------------------------------------------------
class Receiver:
    def __init__(self, packet_io):
        self.reset()
        self.packet_io = packet_io
        self.packet_io.packet_listener = self
        self.done = asyncio.Event()

    def reset(self):
        self.expected_packet_index = 0
        self.start_timestamp = 0.0
        self.last_timestamp = 0.0
        self.bytes_received = 0

    def on_packet_received(self, packet):
        try:
            packet_type, packet_data = parse_packet(packet)
        except ValueError:
            return

        now = time.time()

        if packet_type == PacketType.RESET:
            print(color('=== Received RESET', 'magenta'))
            self.reset()
            self.start_timestamp = now
            return

        try:
            packet_flags, packet_index = parse_packet_sequence(packet_data)
        except ValueError:
            return
        print(
            f'<<< Received packet {packet_index}: '
            f'flags=0x{packet_flags:02X}, {len(packet)} bytes'
        )

        if packet_index != self.expected_packet_index:
            print(
                color(
                    f'!!! Unexpected packet, expected {self.expected_packet_index} '
                    f'but received {packet_index}'
                )
            )

        elapsed_since_start = now - self.start_timestamp
        elapsed_since_last = now - self.last_timestamp
        self.bytes_received += len(packet)
        instant_rx_speed = len(packet) / elapsed_since_last
        average_rx_speed = self.bytes_received / elapsed_since_start
        print(
            color(
                f'Speed: instant={instant_rx_speed:.4f}, average={average_rx_speed:.4f}',
                'yellow',
            )
        )

        self.last_timestamp = now
        self.expected_packet_index = packet_index + 1

        if packet_flags & PACKET_FLAG_LAST:
            AsyncRunner.spawn(
                self.packet_io.send_packet(
                    struct.pack('>bbI', PacketType.ACK, packet_flags, packet_index)
                )
            )
            print(color('@@@ Received last packet', 'green'))
            self.done.set()

    async def run(self):
        await self.done.wait()
        print(color('=== Done!', 'magenta'))


# -----------------------------------------------------------------------------
# Ping
# -----------------------------------------------------------------------------
class Ping:
    def __init__(self, packet_io, start_delay, packet_size, packet_count):
        self.tx_start_delay = start_delay
        self.tx_packet_size = packet_size
        self.tx_packet_count = packet_count
        self.packet_io = packet_io
        self.packet_io.packet_listener = self
        self.done = asyncio.Event()
        self.current_packet_index = 0
        self.ping_sent_time = 0.0
        self.latencies = []

    def reset(self):
        pass

    async def run(self):
        print(color('--- Waiting for I/O to be ready...', 'blue'))
        await self.packet_io.ready.wait()
        print(color('--- Go!', 'blue'))

        if self.tx_start_delay:
            print(color(f'*** Startup delay: {self.tx_start_delay}', 'blue'))
            await asyncio.sleep(self.tx_start_delay)  # FIXME

        print(color('=== Sending RESET', 'magenta'))
        await self.packet_io.send_packet(bytes([PacketType.RESET]))

        await self.send_next_ping()

        await self.done.wait()
        average_latency = sum(self.latencies) / len(self.latencies)
        print(color(f'@@@ Average latency: {average_latency:.2f}'))
        print(color('=== Done!', 'magenta'))

    async def send_next_ping(self):
        packet = struct.pack(
            '>bbI',
            PacketType.SEQUENCE,
            PACKET_FLAG_LAST
            if self.current_packet_index == self.tx_packet_count - 1
            else 0,
            self.current_packet_index,
        ) + bytes(self.tx_packet_size - 6)
        print(color(f'Sending packet {self.current_packet_index}', 'yellow'))
        self.ping_sent_time = time.time()
        await self.packet_io.send_packet(packet)

    def on_packet_received(self, packet):
        elapsed = time.time() - self.ping_sent_time

        try:
            packet_type, packet_data = parse_packet(packet)
        except ValueError:
            return

        try:
            packet_flags, packet_index = parse_packet_sequence(packet_data)
        except ValueError:
            return

        if packet_type == PacketType.ACK:
            latency = elapsed * 1000
            self.latencies.append(latency)
            print(
                color(
                    f'<<< Received ACK [{packet_index}], latency={latency:.2f}ms',
                    'green',
                )
            )

            if packet_index == self.current_packet_index:
                self.current_packet_index += 1
            else:
                print(
                    color(
                        f'!!! Unexpected packet, expected {self.current_packet_index} '
                        f'but received {packet_index}'
                    )
                )

        if packet_flags & PACKET_FLAG_LAST:
            self.done.set()
            return

        AsyncRunner.spawn(self.send_next_ping())


# -----------------------------------------------------------------------------
# Pong
# -----------------------------------------------------------------------------
class Pong:
    def __init__(self, packet_io):
        self.reset()
        self.packet_io = packet_io
        self.packet_io.packet_listener = self
        self.done = asyncio.Event()

    def reset(self):
        self.expected_packet_index = 0

    def on_packet_received(self, packet):
        try:
            packet_type, packet_data = parse_packet(packet)
        except ValueError:
            return

        if packet_type == PacketType.RESET:
            print(color('=== Received RESET', 'magenta'))
            self.reset()
            return

        try:
            packet_flags, packet_index = parse_packet_sequence(packet_data)
        except ValueError:
            return
        print(
            color(
                f'<<< Received packet {packet_index}: '
                f'flags=0x{packet_flags:02X}, {len(packet)} bytes',
                'green',
            )
        )

        if packet_index != self.expected_packet_index:
            print(
                color(
                    f'!!! Unexpected packet, expected {self.expected_packet_index} '
                    f'but received {packet_index}'
                )
            )

        self.expected_packet_index = packet_index + 1

        AsyncRunner.spawn(
            self.packet_io.send_packet(
                struct.pack('>bbI', PacketType.ACK, packet_flags, packet_index)
            )
        )

        if packet_flags & PACKET_FLAG_LAST:
            self.done.set()

    async def run(self):
        await self.done.wait()
        print(color('=== Done!', 'magenta'))


# -----------------------------------------------------------------------------
# GattClient
# -----------------------------------------------------------------------------
class GattClient:
    def __init__(self, _device, att_mtu=None):
        self.att_mtu = att_mtu
        self.speed_rx = None
        self.speed_tx = None
        self.packet_listener = None
        self.ready = asyncio.Event()

    async def on_connection(self, connection):
        peer = Peer(connection)

        if self.att_mtu:
            print(color(f'*** Requesting MTU update: {self.att_mtu}', 'blue'))
            await peer.request_mtu(self.att_mtu)

        print(color('*** Discovering services...', 'blue'))
        await peer.discover_services()

        speed_services = peer.get_services_by_uuid(SPEED_SERVICE_UUID)
        if not speed_services:
            print(color('!!! Speed Service not found', 'red'))
            return
        speed_service = speed_services[0]
        print(color('*** Discovering characteristics...', 'blue'))
        await speed_service.discover_characteristics()

        speed_txs = speed_service.get_characteristics_by_uuid(SPEED_TX_UUID)
        if not speed_txs:
            print(color('!!! Speed TX not found', 'red'))
            return
        self.speed_tx = speed_txs[0]

        speed_rxs = speed_service.get_characteristics_by_uuid(SPEED_RX_UUID)
        if not speed_rxs:
            print(color('!!! Speed RX not found', 'red'))
            return
        self.speed_rx = speed_rxs[0]

        print(color('*** Subscribing to RX', 'blue'))
        await self.speed_rx.subscribe(self.on_packet_received)

        print(color('*** Discovery complete', 'blue'))

        connection.on('disconnection', self.on_disconnection)
        self.ready.set()

    def on_disconnection(self, _):
        self.ready.clear()

    def on_packet_received(self, packet):
        if self.packet_listener:
            self.packet_listener.on_packet_received(packet)

    async def send_packet(self, packet):
        await self.speed_tx.write_value(packet)


# -----------------------------------------------------------------------------
# GattServer
# -----------------------------------------------------------------------------
class GattServer:
    def __init__(self, device):
        self.device = device
        self.packet_listener = None
        self.ready = asyncio.Event()

        # Setup the GATT service
        self.speed_tx = Characteristic(
            SPEED_TX_UUID,
            Characteristic.WRITE,
            Characteristic.WRITEABLE,
            CharacteristicValue(write=self.on_tx_write),
        )
        self.speed_rx = Characteristic(SPEED_RX_UUID, Characteristic.NOTIFY, 0)

        speed_service = Service(
            SPEED_SERVICE_UUID,
            [self.speed_tx, self.speed_rx],
        )
        device.add_services([speed_service])

        self.speed_rx.on('subscription', self.on_rx_subscription)

    async def on_connection(self, connection):
        connection.on('disconnection', self.on_disconnection)

    def on_disconnection(self, _):
        self.ready.clear()

    def on_rx_subscription(self, _connection, notify_enabled, _indicate_enabled):
        if notify_enabled:
            print(color('*** RX subscription', 'blue'))
            self.ready.set()
        else:
            print(color('*** RX un-subscription', 'blue'))
            self.ready.clear()

    def on_tx_write(self, _, value):
        if self.packet_listener:
            self.packet_listener.on_packet_received(value)

    async def send_packet(self, packet):
        await self.device.notify_subscribers(self.speed_rx, packet)


# -----------------------------------------------------------------------------
# StreamedPacketIO
# -----------------------------------------------------------------------------
class StreamedPacketIO:
    def __init__(self):
        self.packet_listener = None
        self.io_sink = None
        self.rx_packet = b''
        self.rx_packet_header = b''
        self.rx_packet_need = 0

    def on_packet(self, packet):
        while packet:
            if self.rx_packet_need:
                chunk = packet[: self.rx_packet_need]
                self.rx_packet += chunk
                packet = packet[len(chunk) :]
                self.rx_packet_need -= len(chunk)
                if not self.rx_packet_need:
                    # Packet completed
                    if self.packet_listener:
                        self.packet_listener.on_packet_received(self.rx_packet)

                    self.rx_packet = b''
                    self.rx_packet_header = b''
            else:
                # Expect the next packet
                header_bytes_needed = 2 - len(self.rx_packet_header)
                header_bytes = packet[:header_bytes_needed]
                self.rx_packet_header += header_bytes
                if len(self.rx_packet_header) != 2:
                    return
                packet = packet[len(header_bytes) :]
                self.rx_packet_need = struct.unpack('>H', self.rx_packet_header)[0]

    async def send_packet(self, packet):
        if not self.io_sink:
            print(color('!!! No sink, dropping packet', 'red'))
            return

        # pylint: disable-next=not-callable
        self.io_sink(struct.pack('>H', len(packet)) + packet)


# -----------------------------------------------------------------------------
# L2capClient
# -----------------------------------------------------------------------------
class L2capClient(StreamedPacketIO):
    def __init__(
        self,
        _device,
        psm=DEFAULT_L2CAP_PSM,
        max_credits=DEFAULT_L2CAP_MAX_CREDITS,
        mtu=DEFAULT_L2CAP_MTU,
        mps=DEFAULT_L2CAP_MPS,
    ):
        super().__init__()
        self.psm = psm
        self.max_credits = max_credits
        self.mtu = mtu
        self.mps = mps
        self.ready = asyncio.Event()

    async def on_connection(self, connection):
        connection.on('disconnection', self.on_disconnection)

        # Connect a new L2CAP channel
        print(color(f'>>> Opening L2CAP channel on PSM = {self.psm}', 'yellow'))
        try:
            l2cap_channel = await connection.open_l2cap_channel(
                psm=self.psm,
                max_credits=self.max_credits,
                mtu=self.mtu,
                mps=self.mps,
            )
            print(color('*** L2CAP channel:', 'cyan'), l2cap_channel)
        except Exception as error:
            print(color(f'!!! Connection failed: {error}', 'red'))
            return

        l2cap_channel.sink = self.on_packet
        l2cap_channel.on('close', self.on_l2cap_close)
        self.io_sink = l2cap_channel.write

        self.ready.set()

    def on_disconnection(self, _):
        pass

    def on_l2cap_close(self):
        print(color('*** L2CAP channel closed', 'red'))


# -----------------------------------------------------------------------------
# L2capServer
# -----------------------------------------------------------------------------
class L2capServer(StreamedPacketIO):
    def __init__(
        self,
        device,
        psm=DEFAULT_L2CAP_PSM,
        max_credits=DEFAULT_L2CAP_MAX_CREDITS,
        mtu=DEFAULT_L2CAP_MTU,
        mps=DEFAULT_L2CAP_MPS,
    ):
        super().__init__()
        self.l2cap_channel = None
        self.ready = asyncio.Event()

        # Listen for incoming L2CAP CoC connections
        device.register_l2cap_channel_server(
            psm=psm,
            server=self.on_l2cap_channel,
            max_credits=max_credits,
            mtu=mtu,
            mps=mps,
        )
        print(color(f'### Listening for CoC connection on PSM {psm}', 'yellow'))

    async def on_connection(self, connection):
        connection.on('disconnection', self.on_disconnection)

    def on_disconnection(self, _):
        pass

    def on_l2cap_channel(self, l2cap_channel):
        print(color('*** L2CAP channel:', 'cyan'), l2cap_channel)

        self.io_sink = l2cap_channel.write
        l2cap_channel.on('close', self.on_l2cap_close)
        l2cap_channel.sink = self.on_packet

        self.ready.set()

    def on_l2cap_close(self):
        print(color('*** L2CAP channel closed', 'red'))
        self.l2cap_channel = None


# -----------------------------------------------------------------------------
# RfcommClient
# -----------------------------------------------------------------------------
class RfcommClient(StreamedPacketIO):
    def __init__(self, device):
        super().__init__()
        self.device = device
        self.ready = asyncio.Event()

    async def on_connection(self, connection):
        connection.on('disconnection', self.on_disconnection)

        # Create a client and start it
        print(color('*** Starting RFCOMM client...', 'blue'))
        rfcomm_client = bumble.rfcomm.Client(self.device, connection)
        rfcomm_mux = await rfcomm_client.start()
        print(color('*** Started', 'blue'))

        channel = DEFAULT_RFCOMM_CHANNEL
        print(color(f'### Opening session for channel {channel}...', 'yellow'))
        try:
            rfcomm_session = await rfcomm_mux.open_dlc(channel)
            print(color('### Session open', 'yellow'), rfcomm_session)
        except bumble.core.ConnectionError as error:
            print(color(f'!!! Session open failed: {error}', 'red'))
            await rfcomm_mux.disconnect()
            return

        rfcomm_session.sink = self.on_packet
        self.io_sink = rfcomm_session.write

        self.ready.set()

    def on_disconnection(self, _):
        pass


# -----------------------------------------------------------------------------
# RfcommServer
# -----------------------------------------------------------------------------
class RfcommServer(StreamedPacketIO):
    def __init__(self, device):
        super().__init__()
        self.ready = asyncio.Event()

        # Create and register a server
        rfcomm_server = bumble.rfcomm.Server(device)

        # Listen for incoming DLC connections
        channel_number = rfcomm_server.listen(self.on_dlc, DEFAULT_RFCOMM_CHANNEL)

        # Setup the SDP to advertise this channel
        device.sdp_service_records = make_sdp_records(channel_number)

        print(
            color(
                f'### Listening for RFComm connection on channel {channel_number}',
                'yellow',
            )
        )

    async def on_connection(self, connection):
        connection.on('disconnection', self.on_disconnection)

    def on_disconnection(self, _):
        pass

    def on_dlc(self, dlc):
        print(color('*** DLC connected:', 'blue'), dlc)
        dlc.sink = self.on_packet
        self.io_sink = dlc.write


# -----------------------------------------------------------------------------
# Central
# -----------------------------------------------------------------------------
class Central(Connection.Listener):
    def __init__(
        self,
        transport,
        peripheral_address,
        classic,
        role_factory,
        mode_factory,
        connection_interval,
        phy,
    ):
        super().__init__()
        self.transport = transport
        self.peripheral_address = peripheral_address
        self.classic = classic
        self.role_factory = role_factory
        self.mode_factory = mode_factory
        self.device = None
        self.connection = None

        if phy:
            self.phy = {
                '1m': HCI_LE_1M_PHY,
                '2m': HCI_LE_2M_PHY,
                'coded': HCI_LE_CODED_PHY,
            }[phy]
        else:
            self.phy = None

        if connection_interval:
            connection_parameter_preferences = ConnectionParametersPreferences()
            connection_parameter_preferences.connection_interval_min = (
                connection_interval
            )
            connection_parameter_preferences.connection_interval_max = (
                connection_interval
            )

            # Preferences for the 1M PHY are always set.
            self.connection_parameter_preferences = {
                HCI_LE_1M_PHY: connection_parameter_preferences,
            }

            if self.phy not in (None, HCI_LE_1M_PHY):
                # Add an connections parameters entry for this PHY.
                self.connection_parameter_preferences[
                    self.phy
                ] = connection_parameter_preferences
        else:
            self.connection_parameter_preferences = None

    async def run(self):
        print(color('>>> Connecting to HCI...', 'green'))
        async with await open_transport_or_link(self.transport) as (
            hci_source,
            hci_sink,
        ):
            print(color('>>> Connected', 'green'))

            central_address = DEFAULT_CENTRAL_ADDRESS
            self.device = Device.with_hci(
                DEFAULT_CENTRAL_NAME, central_address, hci_source, hci_sink
            )
            mode = self.mode_factory(self.device)
            role = self.role_factory(mode)
            self.device.classic_enabled = self.classic

            await self.device.power_on()

            print(color(f'### Connecting to {self.peripheral_address}...', 'cyan'))
            try:
                self.connection = await self.device.connect(
                    self.peripheral_address,
                    connection_parameters_preferences=self.connection_parameter_preferences,
                    transport=BT_BR_EDR_TRANSPORT if self.classic else BT_LE_TRANSPORT,
                )
            except CommandTimeoutError:
                print(color('!!! Connection timed out', 'red'))
                return
            except bumble.core.ConnectionError as error:
                print(color(f'!!! Connection error: {error}', 'red'))
                return
            except HCI_StatusError as error:
                print(color(f'!!! Connection failed: {error.error_name}'))
                return
            print(color('### Connected', 'cyan'))
            self.connection.listener = self
            print_connection(self.connection)

            await mode.on_connection(self.connection)

            # Set the PHY if requested
            if self.phy is not None:
                try:
                    await self.connection.set_phy(
                        tx_phys=[self.phy], rx_phys=[self.phy]
                    )
                except HCI_Error as error:
                    print(
                        color(
                            f'!!! Unable to set the PHY: {error.error_name}', 'yellow'
                        )
                    )

            await role.run()
            await asyncio.sleep(DEFAULT_LINGER_TIME)

    def on_disconnection(self, reason):
        print(color(f'!!! Disconnection: reason={reason}', 'red'))
        self.connection = None

    def on_connection_parameters_update(self):
        print_connection(self.connection)

    def on_connection_phy_update(self):
        print_connection(self.connection)

    def on_connection_att_mtu_update(self):
        print_connection(self.connection)

    def on_connection_data_length_change(self):
        print_connection(self.connection)


# -----------------------------------------------------------------------------
# Peripheral
# -----------------------------------------------------------------------------
class Peripheral(Device.Listener, Connection.Listener):
    def __init__(self, transport, classic, role_factory, mode_factory):
        self.transport = transport
        self.classic = classic
        self.role_factory = role_factory
        self.role = None
        self.mode_factory = mode_factory
        self.mode = None
        self.device = None
        self.connection = None
        self.connected = asyncio.Event()

    async def run(self):
        print(color('>>> Connecting to HCI...', 'green'))
        async with await open_transport_or_link(self.transport) as (
            hci_source,
            hci_sink,
        ):
            print(color('>>> Connected', 'green'))

            peripheral_address = DEFAULT_PERIPHERAL_ADDRESS
            self.device = Device.with_hci(
                DEFAULT_PERIPHERAL_NAME, peripheral_address, hci_source, hci_sink
            )
            self.device.listener = self
            self.mode = self.mode_factory(self.device)
            self.role = self.role_factory(self.mode)
            self.device.classic_enabled = self.classic

            await self.device.power_on()

            if self.classic:
                await self.device.set_discoverable(True)
                await self.device.set_connectable(True)
            else:
                await self.device.start_advertising(auto_restart=True)

            if self.classic:
                print(
                    color(
                        '### Waiting for connection on'
                        f' {self.device.public_address}...',
                        'cyan',
                    )
                )
            else:
                print(
                    color(
                        f'### Waiting for connection on {peripheral_address}...',
                        'cyan',
                    )
                )
            await self.connected.wait()
            print(color('### Connected', 'cyan'))

            await self.mode.on_connection(self.connection)
            await self.role.run()
            await asyncio.sleep(DEFAULT_LINGER_TIME)

    def on_connection(self, connection):
        connection.listener = self
        self.connection = connection
        self.connected.set()

    def on_disconnection(self, reason):
        print(color(f'!!! Disconnection: reason={reason}', 'red'))
        self.connection = None
        self.role.reset()

    def on_connection_parameters_update(self):
        print_connection(self.connection)

    def on_connection_phy_update(self):
        print_connection(self.connection)

    def on_connection_att_mtu_update(self):
        print_connection(self.connection)

    def on_connection_data_length_change(self):
        print_connection(self.connection)


# -----------------------------------------------------------------------------
def create_mode_factory(ctx, default_mode):
    mode = ctx.obj['mode']
    if mode is None:
        mode = default_mode

    def create_mode(device):
        if mode == 'gatt-client':
            return GattClient(device, att_mtu=ctx.obj['att_mtu'])

        if mode == 'gatt-server':
            return GattServer(device)

        if mode == 'l2cap-client':
            return L2capClient(device)

        if mode == 'l2cap-server':
            return L2capServer(device)

        if mode == 'rfcomm-client':
            return RfcommClient(device)

        if mode == 'rfcomm-server':
            return RfcommServer(device)

        raise ValueError('invalid mode')

    return create_mode


# -----------------------------------------------------------------------------
def create_role_factory(ctx, default_role):
    role = ctx.obj['role']
    if role is None:
        role = default_role

    def create_role(packet_io):
        if role == 'sender':
            return Sender(
                packet_io,
                start_delay=ctx.obj['start_delay'],
                packet_size=ctx.obj['packet_size'],
                packet_count=ctx.obj['packet_count'],
            )

        if role == 'receiver':
            return Receiver(packet_io)

        if role == 'ping':
            return Ping(
                packet_io,
                start_delay=ctx.obj['start_delay'],
                packet_size=ctx.obj['packet_size'],
                packet_count=ctx.obj['packet_count'],
            )

        if role == 'pong':
            return Pong(packet_io)

        raise ValueError('invalid role')

    return create_role


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
@click.group()
@click.option('--device-config', metavar='FILENAME', help='Device configuration file')
@click.option('--role', type=click.Choice(['sender', 'receiver', 'ping', 'pong']))
@click.option(
    '--mode',
    type=click.Choice(
        [
            'gatt-client',
            'gatt-server',
            'l2cap-client',
            'l2cap-server',
            'rfcomm-client',
            'rfcomm-server',
        ]
    ),
)
@click.option(
    '--att-mtu',
    metavar='MTU',
    type=click.IntRange(23, 517),
    help='GATT MTU (gatt-client mode)',
)
@click.option(
    '--packet-size',
    '-s',
    metavar='SIZE',
    type=click.IntRange(8, 4096),
    default=500,
    help='Packet size (server role)',
)
@click.option(
    '--packet-count',
    '-c',
    metavar='COUNT',
    type=int,
    default=10,
    help='Packet count (server role)',
)
@click.option(
    '--start-delay',
    '-sd',
    metavar='SECONDS',
    type=int,
    default=1,
    help='Start delay (server role)',
)
@click.pass_context
def bench(
    ctx, device_config, role, mode, att_mtu, packet_size, packet_count, start_delay
):
    ctx.ensure_object(dict)
    ctx.obj['device_config'] = device_config
    ctx.obj['role'] = role
    ctx.obj['mode'] = mode
    ctx.obj['att_mtu'] = att_mtu
    ctx.obj['packet_size'] = packet_size
    ctx.obj['packet_count'] = packet_count
    ctx.obj['start_delay'] = start_delay

    ctx.obj['classic'] = mode in ('rfcomm-client', 'rfcomm-server')


@bench.command()
@click.argument('transport')
@click.option(
    '--peripheral',
    'peripheral_address',
    metavar='ADDRESS_OR_NAME',
    default=DEFAULT_PERIPHERAL_ADDRESS,
    help='Address or name to connect to',
)
@click.option(
    '--connection-interval',
    '--ci',
    metavar='CONNECTION_INTERVAL',
    type=int,
    help='Connection interval (in ms)',
)
@click.option('--phy', type=click.Choice(['1m', '2m', 'coded']), help='PHY to use')
@click.pass_context
def central(ctx, transport, peripheral_address, connection_interval, phy):
    """Run as a central (initiates the connection)"""
    role_factory = create_role_factory(ctx, 'sender')
    mode_factory = create_mode_factory(ctx, 'gatt-client')
    classic = ctx.obj['classic']

    asyncio.run(
        Central(
            transport,
            peripheral_address,
            classic,
            role_factory,
            mode_factory,
            connection_interval,
            phy,
        ).run()
    )


@bench.command()
@click.argument('transport')
@click.pass_context
def peripheral(ctx, transport):
    """Run as a peripheral (waits for a connection)"""
    role_factory = create_role_factory(ctx, 'receiver')
    mode_factory = create_mode_factory(ctx, 'gatt-server')

    asyncio.run(
        Peripheral(transport, ctx.obj['classic'], role_factory, mode_factory).run()
    )


def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    bench()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
