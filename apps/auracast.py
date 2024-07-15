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
import dataclasses
import logging
import os
from typing import cast, Dict, Optional, Tuple

import click
import pyee

from bumble.colors import color
import bumble.company_ids
import bumble.core
import bumble.device
import bumble.gatt
import bumble.hci
import bumble.profiles.bap
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
AURACAST_DEFAULT_DEVICE_NAME = "Bumble Auracast"
AURACAST_DEFAULT_DEVICE_ADDRESS = bumble.hci.Address("F0:F1:F2:F3:F4:F5")


# -----------------------------------------------------------------------------
# Discover Broadcasts
# -----------------------------------------------------------------------------
class BroadcastDiscoverer:
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

            self.establishment_timeout_task = asyncio.create_task(
                self.wait_for_establishment()
            )

        async def wait_for_establishment(self) -> None:
            await asyncio.sleep(5.0)
            if self.sync.state == bumble.device.PeriodicAdvertisingSync.State.PENDING:
                print(
                    color(
                        '!!! Periodic advertisement sync not established in time, '
                        'canceling',
                        'red',
                    )
                )
                await self.sync.terminate()

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
            self.establishment_timeout_task.cancel()
            self.emit('change')

        def on_sync_loss(self) -> None:
            self.basic_audio_announcement = None
            self.biginfo = None
            self.emit('change')

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
        self.device = device
        self.filter_duplicates = filter_duplicates
        self.sync_timeout = sync_timeout
        self.broadcasts: Dict[bumble.hci.Address, BroadcastDiscoverer.Broadcast] = {}
        self.status_message = ''
        device.on('advertisement', self.on_advertisement)

    async def run(self) -> None:
        self.status_message = color('Scanning...', 'green')
        await self.device.start_scanning(
            active=False,
            filter_duplicates=False,
        )

    def refresh(self) -> None:
        # Clear the screen from the top
        print('\033[H')
        print('\033[0J')
        print('\033[H')

        # Print the status message
        print(self.status_message)
        print("==========================================")

        # Print all broadcasts
        for broadcast in self.broadcasts.values():
            broadcast.print()
            print('------------------------------------------')

        # Clear the screen to the bottom
        print('\033[0J')

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
            self.refresh()
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
        broadcast.on('change', self.refresh)
        broadcast.update(advertisement)
        self.broadcasts[advertisement.address] = broadcast
        periodic_advertising_sync.on('loss', lambda: self.on_broadcast_loss(broadcast))
        self.status_message = color(
            f'+Found {len(self.broadcasts)} broadcasts', 'green'
        )
        self.refresh()

    def on_broadcast_loss(self, broadcast: Broadcast) -> None:
        del self.broadcasts[broadcast.sync.advertiser_address]
        bumble.utils.AsyncRunner.spawn(broadcast.sync.terminate())
        self.status_message = color(
            f'-Found {len(self.broadcasts)} broadcasts', 'green'
        )
        self.refresh()


async def run_discover_broadcasts(
    filter_duplicates: bool, sync_timeout: float, transport: str
) -> None:
    async with await bumble.transport.open_transport(transport) as (
        hci_source,
        hci_sink,
    ):
        device = bumble.device.Device.with_hci(
            AURACAST_DEFAULT_DEVICE_NAME,
            AURACAST_DEFAULT_DEVICE_ADDRESS,
            hci_source,
            hci_sink,
        )
        await device.power_on()

        if not device.supports_le_periodic_advertising:
            print(color('Periodic advertising not supported', 'red'))
            return

        discoverer = BroadcastDiscoverer(device, filter_duplicates, sync_timeout)
        await discoverer.run()
        await hci_source.terminated


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
@click.group()
@click.pass_context
def auracast(
    ctx,
):
    ctx.ensure_object(dict)


@auracast.command('discover-broadcasts')
@click.option(
    '--filter-duplicates', is_flag=True, default=False, help='Filter duplicates'
)
@click.option(
    '--sync-timeout',
    metavar='SYNC_TIMEOUT',
    type=float,
    default=5.0,
    help='Sync timeout (in seconds)',
)
@click.argument('transport')
@click.pass_context
def discover_broadcasts(ctx, filter_duplicates, sync_timeout, transport):
    """Discover public broadcasts"""
    asyncio.run(run_discover_broadcasts(filter_duplicates, sync_timeout, transport))


def main():
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    auracast()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
