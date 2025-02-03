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
from typing import Callable, Iterable, Optional

import click

from bumble.core import ProtocolError
from bumble.colors import color
from bumble.device import Device, Peer
from bumble.gatt import Service
from bumble.profiles.device_information_service import DeviceInformationServiceProxy
from bumble.profiles.battery_service import BatteryServiceProxy
from bumble.profiles.gap import GenericAccessServiceProxy
from bumble.profiles.pacs import PublishedAudioCapabilitiesServiceProxy
from bumble.profiles.tmap import TelephonyAndMediaAudioServiceProxy
from bumble.profiles.vcs import VolumeControlServiceProxy
from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def try_show(function: Callable, *args, **kwargs) -> None:
    try:
        await function(*args, **kwargs)
    except ProtocolError as error:
        print(color('ERROR:', 'red'), error)


# -----------------------------------------------------------------------------
def show_services(services: Iterable[Service]) -> None:
    for service in services:
        print(color(str(service), 'cyan'))

        for characteristic in service.characteristics:
            print(color('  ' + str(characteristic), 'magenta'))


# -----------------------------------------------------------------------------
async def show_gap_information(
    gap_service: GenericAccessServiceProxy,
):
    print(color('### Generic Access Profile', 'yellow'))

    if gap_service.device_name:
        print(
            color(' Device Name:', 'green'),
            await gap_service.device_name.read_value(),
        )

    if gap_service.appearance:
        print(
            color(' Appearance: ', 'green'),
            await gap_service.appearance.read_value(),
        )

    print()


# -----------------------------------------------------------------------------
async def show_device_information(
    device_information_service: DeviceInformationServiceProxy,
):
    print(color('### Device Information', 'yellow'))

    if device_information_service.manufacturer_name:
        print(
            color('  Manufacturer Name:', 'green'),
            await device_information_service.manufacturer_name.read_value(),
        )

    if device_information_service.model_number:
        print(
            color('  Model Number:     ', 'green'),
            await device_information_service.model_number.read_value(),
        )

    if device_information_service.serial_number:
        print(
            color('  Serial Number:    ', 'green'),
            await device_information_service.serial_number.read_value(),
        )

    if device_information_service.firmware_revision:
        print(
            color('  Firmware Revision:', 'green'),
            await device_information_service.firmware_revision.read_value(),
        )

    print()


# -----------------------------------------------------------------------------
async def show_battery_level(
    battery_service: BatteryServiceProxy,
):
    print(color('### Battery Information', 'yellow'))

    if battery_service.battery_level:
        print(
            color('  Battery Level:', 'green'),
            await battery_service.battery_level.read_value(),
        )

    print()


# -----------------------------------------------------------------------------
async def show_tmas(
    tmas: TelephonyAndMediaAudioServiceProxy,
):
    print(color('### Telephony And Media Audio Service', 'yellow'))

    if tmas.role:
        role = await tmas.role.read_value()
        print(color('  Role:', 'green'), role)

    print()


# -----------------------------------------------------------------------------
async def show_pacs(pacs: PublishedAudioCapabilitiesServiceProxy) -> None:
    print(color('### Published Audio Capabilities Service', 'yellow'))

    contexts = await pacs.available_audio_contexts.read_value()
    print(color('  Available Audio Contexts:', 'green'), contexts)

    contexts = await pacs.supported_audio_contexts.read_value()
    print(color('  Supported Audio Contexts:', 'green'), contexts)

    if pacs.sink_pac:
        pac = await pacs.sink_pac.read_value()
        print(color('  Sink PAC:                ', 'green'), pac)

    if pacs.sink_audio_locations:
        audio_locations = await pacs.sink_audio_locations.read_value()
        print(color('  Sink Audio Locations:    ', 'green'), audio_locations)

    if pacs.source_pac:
        pac = await pacs.source_pac.read_value()
        print(color('  Source PAC:              ', 'green'), pac)

    if pacs.source_audio_locations:
        audio_locations = await pacs.source_audio_locations.read_value()
        print(color('  Source Audio Locations:  ', 'green'), audio_locations)

    print()


# -----------------------------------------------------------------------------
async def show_vcs(vcs: VolumeControlServiceProxy) -> None:
    print(color('### Volume Control Service', 'yellow'))

    volume_state = await vcs.volume_state.read_value()
    print(color('  Volume State:', 'green'), volume_state)

    volume_flags = await vcs.volume_flags.read_value()
    print(color('  Volume Flags:', 'green'), volume_flags)


# -----------------------------------------------------------------------------
async def show_device_info(peer, done: Optional[asyncio.Future]) -> None:
    try:
        # Discover all services
        print(color('### Discovering Services and Characteristics', 'magenta'))
        await peer.discover_services()
        for service in peer.services:
            await service.discover_characteristics()

        print(color('=== Services ===', 'yellow'))
        show_services(peer.services)
        print()

        if gap_service := peer.create_service_proxy(GenericAccessServiceProxy):
            await try_show(show_gap_information, gap_service)

        if device_information_service := peer.create_service_proxy(
            DeviceInformationServiceProxy
        ):
            await try_show(show_device_information, device_information_service)

        if battery_service := peer.create_service_proxy(BatteryServiceProxy):
            await try_show(show_battery_level, battery_service)

        if tmas := peer.create_service_proxy(TelephonyAndMediaAudioServiceProxy):
            await try_show(show_tmas, tmas)

        if pacs := peer.create_service_proxy(PublishedAudioCapabilitiesServiceProxy):
            await try_show(show_pacs, pacs)

        if vcs := peer.create_service_proxy(VolumeControlServiceProxy):
            await try_show(show_vcs, vcs)

        if done is not None:
            done.set_result(None)
    except asyncio.CancelledError:
        print(color('!!! Operation canceled', 'red'))


# -----------------------------------------------------------------------------
async def async_main(device_config, encrypt, transport, address_or_name):
    async with await open_transport_or_link(transport) as (hci_source, hci_sink):

        # Create a device
        if device_config:
            device = Device.from_config_file_with_hci(
                device_config, hci_source, hci_sink
            )
        else:
            device = Device.with_hci(
                'Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink
            )
        await device.power_on()

        if address_or_name:
            # Connect to the target peer
            print(color('>>> Connecting...', 'green'))
            connection = await device.connect(address_or_name)
            print(color('>>> Connected', 'green'))

            # Encrypt the connection if required
            if encrypt:
                print(color('+++ Encrypting connection...', 'blue'))
                await connection.encrypt()
                print(color('+++ Encryption established', 'blue'))

            await show_device_info(Peer(connection), None)
        else:
            # Wait for a connection
            done = asyncio.get_running_loop().create_future()
            device.on(
                'connection',
                lambda connection: asyncio.create_task(
                    show_device_info(Peer(connection), done)
                ),
            )
            await device.start_advertising(auto_restart=True)

            print(color('### Waiting for connection...', 'blue'))
            await done


# -----------------------------------------------------------------------------
@click.command()
@click.option('--device-config', help='Device configuration', type=click.Path())
@click.option('--encrypt', help='Encrypt the connection', is_flag=True, default=False)
@click.argument('transport')
@click.argument('address-or-name', required=False)
def main(device_config, encrypt, transport, address_or_name):
    """
    Dump the GATT database on a remote device. If ADDRESS_OR_NAME is not specified,
    wait for an incoming connection.
    """
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(async_main(device_config, encrypt, transport, address_or_name))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
