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
import asyncio
import os
import logging
import click

from bumble.colors import color
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.keys import JsonKeyStore
from bumble.smp import AddressResolver
from bumble.device import Advertisement
from bumble.hci import HCI_Constant, HCI_LE_1M_PHY, HCI_LE_CODED_PHY


# -----------------------------------------------------------------------------
def make_rssi_bar(rssi):
    DISPLAY_MIN_RSSI = -105
    DISPLAY_MAX_RSSI = -30
    DEFAULT_RSSI_BAR_WIDTH = 30

    blocks = ['', '▏', '▎', '▍', '▌', '▋', '▊', '▉']
    bar_width = (rssi - DISPLAY_MIN_RSSI) / (DISPLAY_MAX_RSSI - DISPLAY_MIN_RSSI)
    bar_width = min(max(bar_width, 0), 1)
    bar_ticks = int(bar_width * DEFAULT_RSSI_BAR_WIDTH * 8)
    return ('█' * int(bar_ticks / 8)) + blocks[bar_ticks % 8]


# -----------------------------------------------------------------------------
class AdvertisementPrinter:
    def __init__(self, min_rssi, resolver):
        self.min_rssi = min_rssi
        self.resolver = resolver

    def print_advertisement(self, advertisement):
        address = advertisement.address
        address_color = 'yellow' if advertisement.is_connectable else 'red'

        if self.min_rssi is not None and advertisement.rssi < self.min_rssi:
            return

        address_qualifier = ''
        resolution_qualifier = ''
        if self.resolver and advertisement.address.is_resolvable:
            resolved = self.resolver.resolve(advertisement.address)
            if resolved is not None:
                resolution_qualifier = f'(resolved from {advertisement.address})'
                address = resolved

        address_type_string = ('PUBLIC', 'RANDOM', 'PUBLIC_ID', 'RANDOM_ID')[
            address.address_type
        ]
        if address.is_public:
            type_color = 'cyan'
        else:
            if address.is_static:
                type_color = 'green'
                address_qualifier = '(static)'
            elif address.is_resolvable:
                type_color = 'magenta'
                address_qualifier = '(resolvable)'
            else:
                type_color = 'blue'
                address_qualifier = '(non-resolvable)'

        separator = '\n  '
        rssi_bar = make_rssi_bar(advertisement.rssi)
        if not advertisement.is_legacy:
            phy_info = (
                f'PHY: {HCI_Constant.le_phy_name(advertisement.primary_phy)}/'
                f'{HCI_Constant.le_phy_name(advertisement.secondary_phy)} '
                f'{separator}'
            )
        else:
            phy_info = ''

        print(
            f'>>> {color(address, address_color)} '
            f'[{color(address_type_string, type_color)}]{address_qualifier}'
            f'{resolution_qualifier}:{separator}'
            f'{phy_info}'
            f'RSSI:{advertisement.rssi:4} {rssi_bar}{separator}'
            f'{advertisement.data.to_string(separator)}\n'
        )

    def on_advertisement(self, advertisement):
        self.print_advertisement(advertisement)

    def on_advertising_report(self, report):
        print(f'{color("EVENT", "green")}: {report.event_type_string()}')
        self.print_advertisement(Advertisement.from_advertising_report(report))


# -----------------------------------------------------------------------------
async def scan(
    min_rssi,
    passive,
    scan_interval,
    scan_window,
    phy,
    filter_duplicates,
    raw,
    keystore_file,
    device_config,
    transport,
):
    print('<<< connecting to HCI...')
    async with await open_transport_or_link(transport) as (hci_source, hci_sink):
        print('<<< connected')

        if device_config:
            device = Device.from_config_file_with_hci(
                device_config, hci_source, hci_sink
            )
        else:
            device = Device.with_hci(
                'Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink
            )

        await device.power_on()

        if keystore_file:
            device.keystore = JsonKeyStore.from_device(device, filename=keystore_file)

        if device.keystore:
            resolving_keys = await device.keystore.get_resolving_keys()
            resolver = AddressResolver(resolving_keys)
        else:
            resolver = None

        printer = AdvertisementPrinter(min_rssi, resolver)
        if raw:
            device.host.on('advertising_report', printer.on_advertising_report)
        else:
            device.on('advertisement', printer.on_advertisement)

        if phy is None:
            scanning_phys = [HCI_LE_1M_PHY, HCI_LE_CODED_PHY]
        else:
            scanning_phys = [{'1m': HCI_LE_1M_PHY, 'coded': HCI_LE_CODED_PHY}[phy]]

        await device.start_scanning(
            active=(not passive),
            scan_interval=scan_interval,
            scan_window=scan_window,
            filter_duplicates=filter_duplicates,
            scanning_phys=scanning_phys,
        )

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
@click.command()
@click.option('--min-rssi', type=int, help='Minimum RSSI value')
@click.option('--passive', is_flag=True, default=False, help='Perform passive scanning')
@click.option('--scan-interval', type=int, default=60, help='Scan interval')
@click.option('--scan-window', type=int, default=60, help='Scan window')
@click.option(
    '--phy', type=click.Choice(['1m', 'coded']), help='Only scan on the specified PHY'
)
@click.option(
    '--filter-duplicates',
    type=bool,
    default=True,
    help='Filter duplicates at the controller level',
)
@click.option(
    '--raw',
    is_flag=True,
    default=False,
    help='Listen for raw advertising reports instead of processed ones',
)
@click.option('--keystore-file', help='Keystore file to use when resolving addresses')
@click.option('--device-config', help='Device config file for the scanning device')
@click.argument('transport')
def main(
    min_rssi,
    passive,
    scan_interval,
    scan_window,
    phy,
    filter_duplicates,
    raw,
    keystore_file,
    device_config,
    transport,
):
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'WARNING').upper())
    asyncio.run(
        scan(
            min_rssi,
            passive,
            scan_interval,
            scan_window,
            phy,
            filter_duplicates,
            raw,
            keystore_file,
            device_config,
            transport,
        )
    )


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
