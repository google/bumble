# Copyright 2025 Google LLC
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
from __future__ import annotations

import asyncio
import collections
import contextlib
import dataclasses
import functools
import logging
import os
import struct
from typing import (
    Any,
    AsyncGenerator,
    Coroutine,
    Deque,
    Optional,
    Tuple,
)

import click

try:
    import lc3  # type: ignore  # pylint: disable=E0401
except ImportError as e:
    raise ImportError(
        "Try `python -m pip install \"git+https://github.com/google/liblc3.git\"`."
    ) from e

from bumble.audio import io as audio_io
from bumble.colors import color
from bumble import company_ids
from bumble import core
from bumble import gatt
from bumble import hci
from bumble.profiles import bap
from bumble.profiles import le_audio
from bumble.profiles import pbp
from bumble.profiles import bass
import bumble.device
import bumble.transport
import bumble.utils

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
AURACAST_DEFAULT_DEVICE_NAME = 'Bumble Auracast'
AURACAST_DEFAULT_DEVICE_ADDRESS = hci.Address('F0:F1:F2:F3:F4:F5')
AURACAST_DEFAULT_SYNC_TIMEOUT = 5.0
AURACAST_DEFAULT_ATT_MTU = 256
AURACAST_DEFAULT_FRAME_DURATION = 10000
AURACAST_DEFAULT_SAMPLE_RATE = 48000
AURACAST_DEFAULT_TRANSMIT_BITRATE = 80000


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def codec_config_string(
    codec_config: bap.CodecSpecificConfiguration, indent: str
) -> str:
    lines = []
    if codec_config.sampling_frequency is not None:
        lines.append(f'Sampling Frequency: {codec_config.sampling_frequency.hz} hz')
    if codec_config.frame_duration is not None:
        lines.append(f'Frame Duration:     {codec_config.frame_duration.us} µs')
    if codec_config.octets_per_codec_frame is not None:
        lines.append(f'Frame Size:         {codec_config.octets_per_codec_frame} bytes')
    if codec_config.codec_frames_per_sdu is not None:
        lines.append(f'Frames Per SDU:     {codec_config.codec_frames_per_sdu}')
    if codec_config.audio_channel_allocation is not None:
        lines.append(
            f'Audio Location:     {codec_config.audio_channel_allocation.name}'
        )
    return '\n'.join(indent + line for line in lines)


def broadcast_code_bytes(broadcast_code: str) -> bytes:
    """
    Convert a broadcast code string to a 16-byte value.

    If `broadcast_code` is `0x` followed by 32 hex characters, it is interpreted as a
    raw 16-byte raw broadcast code in big-endian byte order.
    Otherwise, `broadcast_code` is converted to a 16-byte value as specified in
    BLUETOOTH CORE SPECIFICATION Version 6.0 | Vol 3, Part C , section 3.2.6.3
    """
    if broadcast_code.startswith("0x") and len(broadcast_code) == 34:
        return bytes.fromhex(broadcast_code[2:])[::-1]

    broadcast_code_utf8 = broadcast_code.encode("utf-8")
    if len(broadcast_code_utf8) > 16:
        raise ValueError("broadcast code must be <= 16 bytes in utf-8 encoding")
    padding = bytes(16 - len(broadcast_code_utf8))
    return broadcast_code_utf8 + padding


# -----------------------------------------------------------------------------
# Scan For Broadcasts
# -----------------------------------------------------------------------------
class BroadcastScanner(bumble.utils.EventEmitter):
    @dataclasses.dataclass
    class Broadcast(bumble.utils.EventEmitter):
        name: str | None
        sync: bumble.device.PeriodicAdvertisingSync
        broadcast_id: int
        rssi: int = 0
        public_broadcast_announcement: Optional[pbp.PublicBroadcastAnnouncement] = None
        broadcast_audio_announcement: Optional[bap.BroadcastAudioAnnouncement] = None
        basic_audio_announcement: Optional[bap.BasicAudioAnnouncement] = None
        appearance: Optional[core.Appearance] = None
        biginfo: Optional[bumble.device.BIGInfoAdvertisement] = None
        manufacturer_data: Optional[Tuple[str, bytes]] = None

        def __post_init__(self) -> None:
            super().__init__()
            self.sync.on('establishment', self.on_sync_establishment)
            self.sync.on('loss', self.on_sync_loss)
            self.sync.on('periodic_advertisement', self.on_periodic_advertisement)
            self.sync.on('biginfo_advertisement', self.on_biginfo_advertisement)

        def update(self, advertisement: bumble.device.Advertisement) -> None:
            self.rssi = advertisement.rssi
            for service_data in advertisement.data.get_all(
                core.AdvertisingData.Type.SERVICE_DATA_16_BIT_UUID
            ):
                service_uuid, data = service_data

                if service_uuid == gatt.GATT_PUBLIC_BROADCAST_ANNOUNCEMENT_SERVICE:
                    self.public_broadcast_announcement = (
                        pbp.PublicBroadcastAnnouncement.from_bytes(data)
                    )
                    continue

                if service_uuid == gatt.GATT_BROADCAST_AUDIO_ANNOUNCEMENT_SERVICE:
                    self.broadcast_audio_announcement = (
                        bap.BroadcastAudioAnnouncement.from_bytes(data)
                    )
                    continue

            self.appearance = advertisement.data.get(
                core.AdvertisingData.Type.APPEARANCE
            )

            if manufacturer_data := advertisement.data.get(
                core.AdvertisingData.Type.MANUFACTURER_SPECIFIC_DATA
            ):
                company_id, data = manufacturer_data
                self.manufacturer_data = (
                    company_ids.COMPANY_IDENTIFIERS.get(
                        company_id, f'0x{company_id:04X}'
                    ),
                    data,
                )

            self.emit('update')

        def print(self) -> None:
            print(
                color('Broadcast:', 'yellow'),
                self.sync.advertiser_address,
                color(self.sync.state.name, 'green'),
            )
            if self.name is not None:
                print(f'  {color("Name", "cyan")}:         {self.name}')
            if self.appearance:
                print(f'  {color("Appearance", "cyan")}:   {str(self.appearance)}')
            print(f'  {color("RSSI", "cyan")}:         {self.rssi}')
            print(f'  {color("SID", "cyan")}:          {self.sync.sid}')

            if self.manufacturer_data:
                print(
                    f'  {color("Manufacturer Data", "cyan")}: '
                    f'{self.manufacturer_data[0]} -> {self.manufacturer_data[1].hex()}'
                )

            if self.broadcast_audio_announcement:
                print(
                    f'  {color("Broadcast ID", "cyan")}: '
                    f'{self.broadcast_audio_announcement.broadcast_id}'
                )

            if self.public_broadcast_announcement:
                print(
                    f'  {color("Features", "cyan")}:     '
                    f'{self.public_broadcast_announcement.features.name}'
                )
                print(f'  {color("Metadata", "cyan")}:')
                print(self.public_broadcast_announcement.metadata.pretty_print('    '))

            if self.basic_audio_announcement:
                print(color('  Audio:', 'cyan'))
                print(
                    color('    Presentation Delay:', 'magenta'),
                    self.basic_audio_announcement.presentation_delay,
                    "µs",
                )
                for subgroup in self.basic_audio_announcement.subgroups:
                    print(color('    Subgroup:', 'magenta'))
                    print(color('      Codec ID:', 'yellow'))
                    print(
                        color('        Coding Format:           ', 'green'),
                        subgroup.codec_id.codec_id.name,
                    )
                    print(
                        color('        Company ID:              ', 'green'),
                        subgroup.codec_id.company_id,
                    )
                    print(
                        color('        Vendor Specific Codec ID:', 'green'),
                        subgroup.codec_id.vendor_specific_codec_id,
                    )
                    print(color('      Codec Config:', 'yellow'))
                    print(
                        codec_config_string(
                            subgroup.codec_specific_configuration, '        '
                        ),
                    )
                    print(color('      Metadata:    ', 'yellow'))
                    print(subgroup.metadata.pretty_print('        '))

                    for bis in subgroup.bis:
                        print(color(f'      BIS [{bis.index}]:', 'yellow'))
                        print(color('       Codec Config:', 'green'))
                        print(
                            codec_config_string(
                                bis.codec_specific_configuration, '         '
                            ),
                        )

            if self.biginfo:
                print(color('  BIG:', 'cyan'))
                print(color('    Number of BIS:', 'magenta'), self.biginfo.num_bis)
                print(color('    ISO Interval: ', 'magenta'), self.biginfo.iso_interval)
                print(color('    Max PDU:      ', 'magenta'), self.biginfo.max_pdu)
                print(color('    SDU Interval: ', 'magenta'), self.biginfo.sdu_interval)
                print(color('    Max SDU:      ', 'magenta'), self.biginfo.max_sdu)
                print(color('    PHY:          ', 'magenta'), self.biginfo.phy.name)
                print(color('    Framed:       ', 'magenta'), self.biginfo.framed)
                print(color('    Encrypted:    ', 'magenta'), self.biginfo.encrypted)

        def on_sync_establishment(self) -> None:
            self.emit('sync_establishment')

        def on_sync_loss(self) -> None:
            self.basic_audio_announcement = None
            self.biginfo = None
            self.emit('sync_loss')

        def on_periodic_advertisement(
            self, advertisement: bumble.device.PeriodicAdvertisement
        ) -> None:
            if advertisement.data is None:
                return

            for service_data in advertisement.data.get_all(
                core.AdvertisingData.Type.SERVICE_DATA_16_BIT_UUID
            ):
                service_uuid, data = service_data

                if service_uuid == gatt.GATT_BASIC_AUDIO_ANNOUNCEMENT_SERVICE:
                    self.basic_audio_announcement = (
                        bap.BasicAudioAnnouncement.from_bytes(data)
                    )
                    break

            self.emit('change')

        def on_biginfo_advertisement(
            self, advertisement: bumble.device.BIGInfoAdvertisement
        ) -> None:
            self.biginfo = advertisement
            self.emit('change')

    def __init__(
        self,
        device: bumble.device.Device,
        filter_duplicates: bool,
        sync_timeout: float,
    ):
        super().__init__()
        self.device = device
        self.filter_duplicates = filter_duplicates
        self.sync_timeout = sync_timeout
        self.broadcasts = dict[hci.Address, BroadcastScanner.Broadcast]()
        device.on('advertisement', self.on_advertisement)

    async def start(self) -> None:
        await self.device.start_scanning(
            active=False,
            filter_duplicates=False,
        )

    async def stop(self) -> None:
        await self.device.stop_scanning()

    def on_advertisement(self, advertisement: bumble.device.Advertisement) -> None:
        if not (
            ads := advertisement.data.get_all(
                core.AdvertisingData.Type.SERVICE_DATA_16_BIT_UUID
            )
        ) or not (
            broadcast_audio_announcement := next(
                (
                    ad
                    for ad in ads
                    if ad[0] == gatt.GATT_BROADCAST_AUDIO_ANNOUNCEMENT_SERVICE
                ),
                None,
            )
        ):
            return

        broadcast_name = advertisement.data.get_all(
            core.AdvertisingData.Type.BROADCAST_NAME
        )

        if broadcast := self.broadcasts.get(advertisement.address):
            broadcast.update(advertisement)
            return

        bumble.utils.AsyncRunner.spawn(
            self.on_new_broadcast(
                broadcast_name[0] if broadcast_name else None,
                advertisement,
                bap.BroadcastAudioAnnouncement.from_bytes(
                    broadcast_audio_announcement[1]
                ).broadcast_id,
            )
        )

    async def on_new_broadcast(
        self,
        name: str | None,
        advertisement: bumble.device.Advertisement,
        broadcast_id: int,
    ) -> None:
        periodic_advertising_sync = await self.device.create_periodic_advertising_sync(
            advertiser_address=advertisement.address,
            sid=advertisement.sid,
            sync_timeout=self.sync_timeout,
            filter_duplicates=self.filter_duplicates,
        )
        broadcast = self.Broadcast(name, periodic_advertising_sync, broadcast_id)
        broadcast.update(advertisement)
        self.broadcasts[advertisement.address] = broadcast
        periodic_advertising_sync.on('loss', lambda: self.on_broadcast_loss(broadcast))
        self.emit('new_broadcast', broadcast)

    def on_broadcast_loss(self, broadcast: Broadcast) -> None:
        del self.broadcasts[broadcast.sync.advertiser_address]
        bumble.utils.AsyncRunner.spawn(broadcast.sync.terminate())
        self.emit('broadcast_loss', broadcast)


class PrintingBroadcastScanner(bumble.utils.EventEmitter):
    def __init__(
        self, device: bumble.device.Device, filter_duplicates: bool, sync_timeout: float
    ) -> None:
        super().__init__()
        self.scanner = BroadcastScanner(device, filter_duplicates, sync_timeout)
        self.scanner.on('new_broadcast', self.on_new_broadcast)
        self.scanner.on('broadcast_loss', self.on_broadcast_loss)
        self.scanner.on('update', self.refresh)
        self.status_message = ''

    async def start(self) -> None:
        self.status_message = color('Scanning...', 'green')
        await self.scanner.start()

    def on_new_broadcast(self, broadcast: BroadcastScanner.Broadcast) -> None:
        self.status_message = color(
            f'+Found {len(self.scanner.broadcasts)} broadcasts', 'green'
        )
        broadcast.on('change', self.refresh)
        broadcast.on('update', self.refresh)
        self.refresh()

    def on_broadcast_loss(self, broadcast: BroadcastScanner.Broadcast) -> None:
        self.status_message = color(
            f'-Found {len(self.scanner.broadcasts)} broadcasts', 'green'
        )
        self.refresh()

    def refresh(self) -> None:
        # Clear the screen from the top
        print('\033[H')
        print('\033[0J')
        print('\033[H')

        # Print the status message
        print(self.status_message)
        print("==========================================")

        # Print all broadcasts
        for broadcast in self.scanner.broadcasts.values():
            broadcast.print()
            print('------------------------------------------')

        # Clear the screen to the bottom
        print('\033[0J')


@contextlib.asynccontextmanager
async def create_device(transport: str) -> AsyncGenerator[bumble.device.Device, Any]:
    async with await bumble.transport.open_transport(transport) as (
        hci_source,
        hci_sink,
    ):
        device_config = bumble.device.DeviceConfiguration(
            name=AURACAST_DEFAULT_DEVICE_NAME,
            address=AURACAST_DEFAULT_DEVICE_ADDRESS,
            keystore='JsonKeyStore',
        )

        device = bumble.device.Device.from_config_with_hci(
            device_config,
            hci_source,
            hci_sink,
        )
        await device.power_on()

        yield device


async def find_broadcast_by_name(
    device: bumble.device.Device, name: Optional[str]
) -> BroadcastScanner.Broadcast:
    result = asyncio.get_running_loop().create_future()

    def on_broadcast_change(broadcast: BroadcastScanner.Broadcast) -> None:
        if broadcast.basic_audio_announcement and not result.done():
            print(color('Broadcast basic audio announcement received', 'green'))
            result.set_result(broadcast)

    def on_new_broadcast(broadcast: BroadcastScanner.Broadcast) -> None:
        if name is None or broadcast.name == name:
            print(color('Broadcast found:', 'green'), broadcast.name)
            broadcast.on('change', lambda: on_broadcast_change(broadcast))
            return

        print(color(f'Skipping broadcast {broadcast.name}'))

    scanner = BroadcastScanner(device, False, AURACAST_DEFAULT_SYNC_TIMEOUT)
    scanner.on('new_broadcast', on_new_broadcast)
    await scanner.start()

    broadcast = await result
    await scanner.stop()

    return broadcast


async def run_scan(
    filter_duplicates: bool, sync_timeout: float, transport: str
) -> None:
    async with create_device(transport) as device:
        if not device.supports_le_periodic_advertising:
            print(color('Periodic advertising not supported', 'red'))
            return

        scanner = PrintingBroadcastScanner(device, filter_duplicates, sync_timeout)
        await scanner.start()
        await asyncio.get_running_loop().create_future()


async def run_assist(
    broadcast_name: Optional[str],
    source_id: Optional[int],
    command: str,
    transport: str,
    address: str,
) -> None:
    async with create_device(transport) as device:
        if not device.supports_le_periodic_advertising:
            print(color('Periodic advertising not supported', 'red'))
            return

        # Connect to the server
        print(f'=== Connecting to {address}...')
        connection = await device.connect(address)
        peer = bumble.device.Peer(connection)
        print(f'=== Connected to {peer}')

        print("+++ Encrypting connection...")
        await peer.connection.encrypt()
        print("+++ Connection encrypted")

        # Request a larger MTU
        mtu = AURACAST_DEFAULT_ATT_MTU
        print(color(f'$$$ Requesting MTU={mtu}', 'yellow'))
        await peer.request_mtu(mtu)

        # Get the BASS service
        bass_client = await peer.discover_service_and_create_proxy(
            bass.BroadcastAudioScanServiceProxy
        )

        # Check that the service was found
        if not bass_client:
            print(color('!!! Broadcast Audio Scan Service not found', 'red'))
            return

        # Subscribe to and read the broadcast receive state characteristics
        def on_broadcast_receive_state_update(
            value: bass.BroadcastReceiveState, index: int
        ) -> None:
            print(
                f"{color(f'Broadcast Receive State Update [{index}]:', 'green')} {value}"
            )

        for i, broadcast_receive_state in enumerate(
            bass_client.broadcast_receive_states
        ):
            try:
                await broadcast_receive_state.subscribe(
                    functools.partial(on_broadcast_receive_state_update, index=i)
                )
            except core.ProtocolError as error:
                print(
                    color(
                        '!!! Failed to subscribe to Broadcast Receive State characteristic',
                        'red',
                    ),
                    error,
                )
            value = await broadcast_receive_state.read_value()
            print(
                f'{color(f"Initial Broadcast Receive State [{i}]:", "green")} {value}'
            )

        if command == 'monitor-state':
            await peer.sustain()
            return

        if command == 'add-source':
            # Find the requested broadcast
            await bass_client.remote_scan_started()
            if broadcast_name:
                print(color('Scanning for broadcast:', 'cyan'), broadcast_name)
            else:
                print(color('Scanning for any broadcast', 'cyan'))
            broadcast = await find_broadcast_by_name(device, broadcast_name)

            if broadcast.broadcast_audio_announcement is None:
                print(color('No broadcast audio announcement found', 'red'))
                return

            if (
                broadcast.basic_audio_announcement is None
                or not broadcast.basic_audio_announcement.subgroups
            ):
                print(color('No subgroups found', 'red'))
                return

            # Add the source
            print(color('Adding source:', 'blue'), broadcast.sync.advertiser_address)
            await bass_client.add_source(
                broadcast.sync.advertiser_address,
                broadcast.sync.sid,
                broadcast.broadcast_audio_announcement.broadcast_id,
                bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_AVAILABLE,
                0xFFFF,
                [
                    bass.SubgroupInfo(
                        bass.SubgroupInfo.ANY_BIS,
                        bytes(broadcast.basic_audio_announcement.subgroups[0].metadata),
                    )
                ],
            )

            # Initiate a PA Sync Transfer
            await broadcast.sync.transfer(peer.connection)

            # Notify the sink that we're done scanning.
            await bass_client.remote_scan_stopped()

            await peer.sustain()
            return

        if command == 'modify-source':
            if source_id is None:
                print(color('!!! modify-source requires --source-id'))
                return

            # Find the requested broadcast
            await bass_client.remote_scan_started()
            if broadcast_name:
                print(color('Scanning for broadcast:', 'cyan'), broadcast_name)
            else:
                print(color('Scanning for any broadcast', 'cyan'))
            broadcast = await find_broadcast_by_name(device, broadcast_name)

            if broadcast.broadcast_audio_announcement is None:
                print(color('No broadcast audio announcement found', 'red'))
                return

            if (
                broadcast.basic_audio_announcement is None
                or not broadcast.basic_audio_announcement.subgroups
            ):
                print(color('No subgroups found', 'red'))
                return

            # Modify the source
            print(
                color('Modifying source:', 'blue'),
                source_id,
            )
            await bass_client.modify_source(
                source_id,
                bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
                0xFFFF,
                [
                    bass.SubgroupInfo(
                        bass.SubgroupInfo.ANY_BIS,
                        bytes(broadcast.basic_audio_announcement.subgroups[0].metadata),
                    )
                ],
            )
            await peer.sustain()
            return

        if command == 'remove-source':
            if source_id is None:
                print(color('!!! remove-source requires --source-id'))
                return

            # Remove the source
            print(color('Removing source:', 'blue'), source_id)
            await bass_client.remove_source(source_id)
            await peer.sustain()
            return

        print(color(f'!!! invalid command {command}'))


async def run_pair(transport: str, address: str) -> None:
    async with create_device(transport) as device:

        # Connect to the server
        print(f'=== Connecting to {address}...')
        async with device.connect_as_gatt(address) as peer:
            print(f'=== Connected to {peer}')

            print("+++ Initiating pairing...")
            await peer.connection.pair()
            print("+++ Paired")


async def run_receive(
    transport: str,
    broadcast_id: Optional[int],
    output: str,
    broadcast_code: str | None,
    sync_timeout: float,
    subgroup_index: int,
) -> None:
    # Run a pre-flight check for the output.
    try:
        if not audio_io.check_audio_output(output):
            return
    except ValueError as error:
        print(error)
        return

    async with create_device(transport) as device:
        if not device.supports_le_periodic_advertising:
            print(color('Periodic advertising not supported', 'red'))
            return

        scanner = BroadcastScanner(device, False, sync_timeout)
        scan_result: asyncio.Future[BroadcastScanner.Broadcast] = (
            asyncio.get_running_loop().create_future()
        )

        def on_new_broadcast(broadcast: BroadcastScanner.Broadcast) -> None:
            if scan_result.done():
                return
            if broadcast_id is None or broadcast.broadcast_id == broadcast_id:
                scan_result.set_result(broadcast)

        scanner.on('new_broadcast', on_new_broadcast)
        await scanner.start()
        print('Start scanning...')
        broadcast = await scan_result
        print('Advertisement found:')
        broadcast.print()
        basic_audio_announcement_scanned = asyncio.Event()

        def on_change() -> None:
            if (
                broadcast.basic_audio_announcement and broadcast.biginfo
            ) and not basic_audio_announcement_scanned.is_set():
                basic_audio_announcement_scanned.set()

        broadcast.on('change', on_change)
        if not broadcast.basic_audio_announcement or not broadcast.biginfo:
            print('Wait for Basic Audio Announcement and BIG Info...')
            await basic_audio_announcement_scanned.wait()
        print('Basic Audio Announcement found')
        broadcast.print()
        print('Stop scanning')
        await scanner.stop()
        print('Start sync to BIG')

        assert broadcast.basic_audio_announcement
        subgroup = broadcast.basic_audio_announcement.subgroups[subgroup_index]
        configuration = subgroup.codec_specific_configuration
        assert configuration
        assert (sampling_frequency := configuration.sampling_frequency)
        assert (frame_duration := configuration.frame_duration)

        big_sync = await device.create_big_sync(
            broadcast.sync,
            bumble.device.BigSyncParameters(
                big_sync_timeout=0x4000,
                bis=[bis.index for bis in subgroup.bis],
                broadcast_code=(
                    broadcast_code_bytes(broadcast_code) if broadcast_code else None
                ),
            ),
        )
        num_bis = len(big_sync.bis_links)
        decoder = lc3.Decoder(
            frame_duration_us=frame_duration.us,
            sample_rate_hz=sampling_frequency.hz,
            num_channels=num_bis,
        )
        lc3_queues: list[Deque[bytes]] = [collections.deque() for i in range(num_bis)]
        packet_stats = [0, 0]

        audio_output = await audio_io.create_audio_output(output)
        # This try should be replaced with contextlib.aclosing() when python 3.9 is no
        # longer needed.
        try:
            await audio_output.open(
                audio_io.PcmFormat(
                    audio_io.PcmFormat.Endianness.LITTLE,
                    audio_io.PcmFormat.SampleType.FLOAT32,
                    sampling_frequency.hz,
                    num_bis,
                )
            )

            def sink(queue: Deque[bytes], packet: hci.HCI_IsoDataPacket):
                # TODO: re-assemble fragments and detect errors
                queue.append(packet.iso_sdu_fragment)

                while all(lc3_queues):
                    # This assumes SDUs contain one LC3 frame each, which may not
                    # be correct for all cases. TODO: revisit this assumption.
                    frame = b''.join([lc3_queue.popleft() for lc3_queue in lc3_queues])
                    if not frame:
                        print(color('!!! received empty frame', 'red'))
                        continue

                    packet_stats[0] += len(frame)
                    packet_stats[1] += 1
                    print(
                        f'\rRECEIVED: {packet_stats[0]} bytes in '
                        f'{packet_stats[1]} packets',
                        end='',
                    )

                    try:
                        pcm = decoder.decode(frame).tobytes()
                    except lc3.BaseError as error:
                        print(color(f'!!! LC3 decoding error: {error}'))
                        continue

                    audio_output.write(pcm)

            for i, bis_link in enumerate(big_sync.bis_links):
                print(f'Setup ISO for BIS {bis_link.handle}')
                bis_link.sink = functools.partial(sink, lc3_queues[i])
                await bis_link.setup_data_path(
                    direction=bis_link.Direction.CONTROLLER_TO_HOST
                )

            terminated = asyncio.Event()
            big_sync.on(big_sync.Event.TERMINATION, lambda _: terminated.set())
            await terminated.wait()
        finally:
            await audio_output.aclose()


async def run_transmit(
    transport: str,
    broadcast_id: int,
    broadcast_code: str | None,
    broadcast_name: str,
    bitrate: int,
    manufacturer_data: tuple[int, bytes] | None,
    input: str,
    input_format: str,
) -> None:
    # Run a pre-flight check for the input.
    try:
        if not audio_io.check_audio_input(input):
            return
    except ValueError as error:
        print(error)
        return

    async with create_device(transport) as device:
        if not device.supports_le_periodic_advertising:
            print(color('Periodic advertising not supported', 'red'))
            return

        basic_audio_announcement = bap.BasicAudioAnnouncement(
            presentation_delay=40000,
            subgroups=[
                bap.BasicAudioAnnouncement.Subgroup(
                    codec_id=hci.CodingFormat(codec_id=hci.CodecID.LC3),
                    codec_specific_configuration=bap.CodecSpecificConfiguration(
                        sampling_frequency=bap.SamplingFrequency.FREQ_48000,
                        frame_duration=bap.FrameDuration.DURATION_10000_US,
                        octets_per_codec_frame=100,
                    ),
                    metadata=le_audio.Metadata(
                        [
                            le_audio.Metadata.Entry(
                                tag=le_audio.Metadata.Tag.LANGUAGE, data=b'eng'
                            ),
                            le_audio.Metadata.Entry(
                                tag=le_audio.Metadata.Tag.PROGRAM_INFO, data=b'Disco'
                            ),
                        ]
                    ),
                    bis=[
                        bap.BasicAudioAnnouncement.BIS(
                            index=1,
                            codec_specific_configuration=bap.CodecSpecificConfiguration(
                                audio_channel_allocation=bap.AudioLocation.FRONT_LEFT
                            ),
                        ),
                        bap.BasicAudioAnnouncement.BIS(
                            index=2,
                            codec_specific_configuration=bap.CodecSpecificConfiguration(
                                audio_channel_allocation=bap.AudioLocation.FRONT_RIGHT
                            ),
                        ),
                    ],
                )
            ],
        )
        broadcast_audio_announcement = bap.BroadcastAudioAnnouncement(broadcast_id)

        advertising_manufacturer_data = (
            b''
            if manufacturer_data is None
            else bytes(
                core.AdvertisingData(
                    [
                        (
                            core.AdvertisingData.MANUFACTURER_SPECIFIC_DATA,
                            struct.pack('<H', manufacturer_data[0])
                            + manufacturer_data[1],
                        )
                    ]
                )
            )
        )

        advertising_set = await device.create_advertising_set(
            advertising_parameters=bumble.device.AdvertisingParameters(
                advertising_event_properties=bumble.device.AdvertisingEventProperties(
                    is_connectable=False
                ),
                primary_advertising_interval_min=100,
                primary_advertising_interval_max=200,
            ),
            advertising_data=(
                broadcast_audio_announcement.get_advertising_data()
                + bytes(
                    core.AdvertisingData(
                        [(core.AdvertisingData.BROADCAST_NAME, broadcast_name.encode())]
                    )
                )
                + advertising_manufacturer_data
            ),
            periodic_advertising_parameters=bumble.device.PeriodicAdvertisingParameters(
                periodic_advertising_interval_min=80,
                periodic_advertising_interval_max=160,
            ),
            periodic_advertising_data=basic_audio_announcement.get_advertising_data(),
            auto_restart=True,
            auto_start=True,
        )

        print('Start Periodic Advertising')
        await advertising_set.start_periodic()

        audio_input = await audio_io.create_audio_input(input, input_format)
        pcm_format = await audio_input.open()
        # This try should be replaced with contextlib.aclosing() when python 3.9 is no
        # longer needed.
        try:
            if pcm_format.channels != 2:
                print("Only 2 channels PCM configurations are supported")
                return
            if pcm_format.sample_type == audio_io.PcmFormat.SampleType.INT16:
                pcm_bit_depth = 16
            elif pcm_format.sample_type == audio_io.PcmFormat.SampleType.FLOAT32:
                pcm_bit_depth = None
            else:
                print("Only INT16 and FLOAT32 sample types are supported")
                return

            encoder = lc3.Encoder(
                frame_duration_us=AURACAST_DEFAULT_FRAME_DURATION,
                sample_rate_hz=AURACAST_DEFAULT_SAMPLE_RATE,
                num_channels=pcm_format.channels,
                input_sample_rate_hz=pcm_format.sample_rate,
            )
            lc3_frame_samples = encoder.get_frame_samples()
            lc3_frame_size = encoder.get_frame_bytes(bitrate)
            print(
                f'Encoding with {lc3_frame_samples} '
                f'PCM samples per {lc3_frame_size} byte frame'
            )

            print('Setup BIG')
            big = await device.create_big(
                advertising_set,
                parameters=bumble.device.BigParameters(
                    num_bis=pcm_format.channels,
                    sdu_interval=AURACAST_DEFAULT_FRAME_DURATION,
                    max_sdu=lc3_frame_size,
                    max_transport_latency=65,
                    rtn=4,
                    broadcast_code=(
                        broadcast_code_bytes(broadcast_code) if broadcast_code else None
                    ),
                ),
            )
            for bis_link in big.bis_links:
                print(f'Setup ISO for BIS {bis_link.handle}')
                await bis_link.setup_data_path(
                    direction=bis_link.Direction.HOST_TO_CONTROLLER
                )

            iso_queues = [
                bumble.device.IsoPacketStream(bis_link, 64)
                for bis_link in big.bis_links
            ]

            def on_flow():
                data_packet_queue = iso_queues[0].data_packet_queue
                print(
                    f'\rPACKETS: pending={data_packet_queue.pending}, '
                    f'queued={data_packet_queue.queued}, '
                    f'completed={data_packet_queue.completed}',
                    end='',
                )

            iso_queues[0].data_packet_queue.on('flow', on_flow)

            frame_count = 0
            async for pcm_frame in audio_input.frames(lc3_frame_samples):
                lc3_frame = encoder.encode(
                    pcm_frame, num_bytes=2 * lc3_frame_size, bit_depth=pcm_bit_depth
                )

                mid = len(lc3_frame) // 2
                await iso_queues[0].write(lc3_frame[:mid])
                await iso_queues[1].write(lc3_frame[mid:])

                frame_count += 1
        finally:
            await audio_input.aclose()


def run_async(async_command: Coroutine) -> None:
    try:
        asyncio.run(async_command)
    except core.ProtocolError as error:
        if error.error_namespace == 'att' and error.error_code in list(
            bass.ApplicationError
        ):
            message = bass.ApplicationError(error.error_code).name
        else:
            message = str(error)

        print(
            color('!!! An error occurred while executing the command:', 'red'), message
        )


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
@click.group()
@click.pass_context
def auracast(ctx):
    ctx.ensure_object(dict)


@auracast.command('scan')
@click.option(
    '--filter-duplicates', is_flag=True, default=False, help='Filter duplicates'
)
@click.option(
    '--sync-timeout',
    metavar='SYNC_TIMEOUT',
    type=float,
    default=AURACAST_DEFAULT_SYNC_TIMEOUT,
    help='Sync timeout (in seconds)',
)
@click.argument('transport')
@click.pass_context
def scan(ctx, filter_duplicates, sync_timeout, transport):
    """Scan for public broadcasts"""
    run_async(run_scan(filter_duplicates, sync_timeout, transport))


@auracast.command('assist')
@click.option(
    '--broadcast-name',
    metavar='BROADCAST_NAME',
    help='Broadcast Name to tune to',
)
@click.option(
    '--source-id',
    metavar='SOURCE_ID',
    type=int,
    help='Source ID (for remove-source command)',
)
@click.option(
    '--command',
    type=click.Choice(
        ['monitor-state', 'add-source', 'modify-source', 'remove-source']
    ),
    required=True,
)
@click.argument('transport')
@click.argument('address')
@click.pass_context
def assist(ctx, broadcast_name, source_id, command, transport, address):
    """Scan for broadcasts on behalf of an audio server"""
    run_async(run_assist(broadcast_name, source_id, command, transport, address))


@auracast.command('pair')
@click.argument('transport')
@click.argument('address')
@click.pass_context
def pair(ctx, transport, address):
    """Pair with an audio server"""
    run_async(run_pair(transport, address))


@auracast.command('receive')
@click.argument('transport')
@click.argument(
    'broadcast_id',
    type=int,
    required=False,
)
@click.option(
    '--output',
    default='device',
    help=(
        "Audio output. "
        "'device' -> use the host's default sound output device, "
        "'device:<DEVICE_ID>' -> use one of the  host's sound output device "
        "(specify 'device:?' to get a list of available sound output devices), "
        "'stdout' -> send audio to stdout, "
        "'file:<filename> -> write audio to a raw float32 PCM file, "
        "'ffplay' -> pipe the audio to ffplay"
    ),
)
@click.option(
    '--broadcast-code',
    metavar='BROADCAST_CODE',
    type=str,
    help='Broadcast encryption code (string or raw hex format prefixed with 0x)',
)
@click.option(
    '--sync-timeout',
    metavar='SYNC_TIMEOUT',
    type=float,
    default=AURACAST_DEFAULT_SYNC_TIMEOUT,
    help='Sync timeout (in seconds)',
)
@click.option(
    '--subgroup',
    metavar='SUBGROUP',
    type=int,
    default=0,
    help='Index of Subgroup',
)
@click.pass_context
def receive(
    ctx,
    transport,
    broadcast_id,
    output,
    broadcast_code,
    sync_timeout,
    subgroup,
):
    """Receive a broadcast source"""
    run_async(
        run_receive(
            transport,
            broadcast_id,
            output,
            broadcast_code,
            sync_timeout,
            subgroup,
        )
    )


@auracast.command('transmit')
@click.argument('transport')
@click.option(
    '--input',
    required=True,
    help=(
        "Audio input. "
        "'device' -> use the host's default sound input device, "
        "'device:<DEVICE_ID>' -> use one of the host's sound input devices "
        "(specify 'device:?' to get a list of available sound input devices), "
        "'stdin' -> receive audio from stdin as int16 PCM, "
        "'file:<filename> -> read audio from a .wav or raw int16 PCM file. "
        "(The file: prefix may be omitted if the file path does not start with "
        "the substring 'device:' or 'file:' and is not 'stdin')"
    ),
)
@click.option(
    '--input-format',
    metavar="FORMAT",
    default='auto',
    help=(
        "Audio input format. "
        "Use 'auto' for .wav files, or for the default setting with the devices. "
        "For other inputs, the format is specified as "
        "<sample-type>,<sample-rate>,<channels> (supported <sample-type>: 'int16le' "
        "for 16-bit signed integers with little-endian byte order or 'float32le' for "
        "32-bit floating point with little-endian byte order)"
    ),
)
@click.option(
    '--broadcast-id',
    metavar='BROADCAST_ID',
    type=int,
    default=123456,
    help='Broadcast ID',
)
@click.option(
    '--broadcast-code',
    metavar='BROADCAST_CODE',
    help='Broadcast encryption code in hex format',
)
@click.option(
    '--broadcast-name',
    metavar='BROADCAST_NAME',
    default='Bumble Auracast',
    help='Broadcast name',
)
@click.option(
    '--bitrate',
    type=int,
    default=AURACAST_DEFAULT_TRANSMIT_BITRATE,
    help='Bitrate, per channel, in bps',
)
@click.option(
    '--manufacturer-data',
    metavar='VENDOR-ID:DATA-HEX',
    help='Manufacturer data (specify as <vendor-id>:<data-hex>)',
)
@click.pass_context
def transmit(
    ctx,
    transport,
    broadcast_id,
    broadcast_code,
    manufacturer_data,
    broadcast_name,
    bitrate,
    input,
    input_format,
):
    """Transmit a broadcast source"""
    if manufacturer_data:
        vendor_id_str, data_hex = manufacturer_data.split(':')
        vendor_id = int(vendor_id_str)
        data = bytes.fromhex(data_hex)
        manufacturer_data_tuple = (vendor_id, data)
    else:
        manufacturer_data_tuple = None

    if (input == 'device' or input.startswith('device:')) and input_format == 'auto':
        # Use a default format for device inputs
        input_format = 'int16le,48000,1'

    run_async(
        run_transmit(
            transport=transport,
            broadcast_id=broadcast_id,
            broadcast_code=broadcast_code,
            broadcast_name=broadcast_name,
            bitrate=bitrate,
            manufacturer_data=manufacturer_data_tuple,
            input=input,
            input_format=input_format,
        )
    )


def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    auracast()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
