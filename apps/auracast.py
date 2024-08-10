# Copyright 2024 Google LLC
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
import contextlib
import dataclasses
import logging
import os
from typing import cast, Any, AsyncGenerator, Coroutine, Dict, Optional, Tuple

import click
import pyee

from bumble.colors import color
import bumble.company_ids
import bumble.core
import bumble.device
import bumble.gatt
import bumble.hci
import bumble.profiles.bap
import bumble.profiles.bass
import bumble.profiles.pbp
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
AURACAST_DEFAULT_DEVICE_ADDRESS = bumble.hci.Address('F0:F1:F2:F3:F4:F5')
AURACAST_DEFAULT_SYNC_TIMEOUT = 5.0
AURACAST_DEFAULT_ATT_MTU = 256


# -----------------------------------------------------------------------------
# Scan For Broadcasts
# -----------------------------------------------------------------------------
class BroadcastScanner(pyee.EventEmitter):
    @dataclasses.dataclass
    class Broadcast(pyee.EventEmitter):
        name: str
        sync: bumble.device.PeriodicAdvertisingSync
        rssi: int = 0
        public_broadcast_announcement: Optional[
            bumble.profiles.pbp.PublicBroadcastAnnouncement
        ] = None
        broadcast_audio_announcement: Optional[
            bumble.profiles.bap.BroadcastAudioAnnouncement
        ] = None
        basic_audio_announcement: Optional[
            bumble.profiles.bap.BasicAudioAnnouncement
        ] = None
        appearance: Optional[bumble.core.Appearance] = None
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
                bumble.core.AdvertisingData.SERVICE_DATA
            ):
                assert isinstance(service_data, tuple)
                service_uuid, data = service_data
                assert isinstance(data, bytes)

                if (
                    service_uuid
                    == bumble.gatt.GATT_PUBLIC_BROADCAST_ANNOUNCEMENT_SERVICE
                ):
                    self.public_broadcast_announcement = (
                        bumble.profiles.pbp.PublicBroadcastAnnouncement.from_bytes(data)
                    )
                    continue

                if (
                    service_uuid
                    == bumble.gatt.GATT_BROADCAST_AUDIO_ANNOUNCEMENT_SERVICE
                ):
                    self.broadcast_audio_announcement = (
                        bumble.profiles.bap.BroadcastAudioAnnouncement.from_bytes(data)
                    )
                    continue

            self.appearance = advertisement.data.get(  # type: ignore[assignment]
                bumble.core.AdvertisingData.APPEARANCE
            )

            if manufacturer_data := advertisement.data.get(
                bumble.core.AdvertisingData.MANUFACTURER_SPECIFIC_DATA
            ):
                assert isinstance(manufacturer_data, tuple)
                company_id = cast(int, manufacturer_data[0])
                data = cast(bytes, manufacturer_data[1])
                self.manufacturer_data = (
                    bumble.company_ids.COMPANY_IDENTIFIERS.get(
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
                    f'{self.public_broadcast_announcement.features}'
                )
                print(
                    f'  {color("Metadata", "cyan")}:     '
                    f'{self.public_broadcast_announcement.metadata}'
                )

            if self.basic_audio_announcement:
                print(color('  Audio:', 'cyan'))
                print(
                    color('    Presentation Delay:', 'magenta'),
                    self.basic_audio_announcement.presentation_delay,
                )
                for subgroup in self.basic_audio_announcement.subgroups:
                    print(color('    Subgroup:', 'magenta'))
                    print(color('      Codec ID:', 'yellow'))
                    print(
                        color('        Coding Format:           ', 'green'),
                        subgroup.codec_id.coding_format.name,
                    )
                    print(
                        color('        Company ID:              ', 'green'),
                        subgroup.codec_id.company_id,
                    )
                    print(
                        color('        Vendor Specific Codec ID:', 'green'),
                        subgroup.codec_id.vendor_specific_codec_id,
                    )
                    print(
                        color('      Codec Config:', 'yellow'),
                        subgroup.codec_specific_configuration,
                    )
                    print(color('      Metadata:    ', 'yellow'), subgroup.metadata)

                    for bis in subgroup.bis:
                        print(color(f'      BIS [{bis.index}]:', 'yellow'))
                        print(
                            color('       Codec Config:', 'green'),
                            bis.codec_specific_configuration,
                        )

            if self.biginfo:
                print(color('  BIG:', 'cyan'))
                print(
                    color('    Number of BIS:', 'magenta'),
                    self.biginfo.num_bis,
                )
                print(
                    color('    PHY:          ', 'magenta'),
                    self.biginfo.phy.name,
                )
                print(
                    color('    Framed:       ', 'magenta'),
                    self.biginfo.framed,
                )
                print(
                    color('    Encrypted:    ', 'magenta'),
                    self.biginfo.encrypted,
                )

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
                bumble.core.AdvertisingData.SERVICE_DATA
            ):
                assert isinstance(service_data, tuple)
                service_uuid, data = service_data
                assert isinstance(data, bytes)

                if service_uuid == bumble.gatt.GATT_BASIC_AUDIO_ANNOUNCEMENT_SERVICE:
                    self.basic_audio_announcement = (
                        bumble.profiles.bap.BasicAudioAnnouncement.from_bytes(data)
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
        self.broadcasts: Dict[bumble.hci.Address, BroadcastScanner.Broadcast] = {}
        device.on('advertisement', self.on_advertisement)

    async def start(self) -> None:
        await self.device.start_scanning(
            active=False,
            filter_duplicates=False,
        )

    async def stop(self) -> None:
        await self.device.stop_scanning()

    def on_advertisement(self, advertisement: bumble.device.Advertisement) -> None:
        if (
            broadcast_name := advertisement.data.get(
                bumble.core.AdvertisingData.BROADCAST_NAME
            )
        ) is None:
            return
        assert isinstance(broadcast_name, str)

        if broadcast := self.broadcasts.get(advertisement.address):
            broadcast.update(advertisement)
            return

        bumble.utils.AsyncRunner.spawn(
            self.on_new_broadcast(broadcast_name, advertisement)
        )

    async def on_new_broadcast(
        self, name: str, advertisement: bumble.device.Advertisement
    ) -> None:
        periodic_advertising_sync = await self.device.create_periodic_advertising_sync(
            advertiser_address=advertisement.address,
            sid=advertisement.sid,
            sync_timeout=self.sync_timeout,
            filter_duplicates=self.filter_duplicates,
        )
        broadcast = self.Broadcast(
            name,
            periodic_advertising_sync,
        )
        broadcast.update(advertisement)
        self.broadcasts[advertisement.address] = broadcast
        periodic_advertising_sync.on('loss', lambda: self.on_broadcast_loss(broadcast))
        self.emit('new_broadcast', broadcast)

    def on_broadcast_loss(self, broadcast: Broadcast) -> None:
        del self.broadcasts[broadcast.sync.advertiser_address]
        bumble.utils.AsyncRunner.spawn(broadcast.sync.terminate())
        self.emit('broadcast_loss', broadcast)


class PrintingBroadcastScanner:
    def __init__(
        self, device: bumble.device.Device, filter_duplicates: bool, sync_timeout: float
    ) -> None:
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
        bass = await peer.discover_service_and_create_proxy(
            bumble.profiles.bass.BroadcastAudioScanServiceProxy
        )

        # Check that the service was found
        if not bass:
            print(color('!!! Broadcast Audio Scan Service not found', 'red'))
            return

        # Subscribe to and read the broadcast receive state characteristics
        for i, broadcast_receive_state in enumerate(bass.broadcast_receive_states):
            try:
                await broadcast_receive_state.subscribe(
                    lambda value, i=i: print(
                        f"{color(f'Broadcast Receive State Update [{i}]:', 'green')} {value}"
                    )
                )
            except bumble.core.ProtocolError as error:
                print(
                    color(
                        f'!!! Failed to subscribe to Broadcast Receive State characteristic:',
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
            await bass.remote_scan_started()
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
            await bass.add_source(
                broadcast.sync.advertiser_address,
                broadcast.sync.sid,
                broadcast.broadcast_audio_announcement.broadcast_id,
                bumble.profiles.bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_AVAILABLE,
                0xFFFF,
                [
                    bumble.profiles.bass.SubgroupInfo(
                        bumble.profiles.bass.SubgroupInfo.ANY_BIS,
                        bytes(broadcast.basic_audio_announcement.subgroups[0].metadata),
                    )
                ],
            )

            # Initiate a PA Sync Transfer
            await broadcast.sync.transfer(peer.connection)

            # Notify the sink that we're done scanning.
            await bass.remote_scan_stopped()

            await peer.sustain()
            return

        if command == 'modify-source':
            if source_id is None:
                print(color('!!! modify-source requires --source-id'))
                return

            # Find the requested broadcast
            await bass.remote_scan_started()
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
            await bass.modify_source(
                source_id,
                bumble.profiles.bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
                0xFFFF,
                [
                    bumble.profiles.bass.SubgroupInfo(
                        bumble.profiles.bass.SubgroupInfo.ANY_BIS,
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
            await bass.remove_source(source_id)
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


def run_async(async_command: Coroutine) -> None:
    try:
        asyncio.run(async_command)
    except bumble.core.ProtocolError as error:
        if error.error_namespace == 'att' and error.error_code in list(
            bumble.profiles.bass.ApplicationError
        ):
            message = bumble.profiles.bass.ApplicationError(error.error_code).name
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
def auracast(
    ctx,
):
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
    """Scan for broadcasts on behalf of a audio server"""
    run_async(run_assist(broadcast_name, source_id, command, transport, address))


@auracast.command('pair')
@click.argument('transport')
@click.argument('address')
@click.pass_context
def pair(ctx, transport, address):
    """Pair with an audio server"""
    run_async(run_pair(transport, address))


def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    auracast()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
