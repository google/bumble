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
import sys
import os
import logging
import struct

from bumble.device import Device, Connection, AdvertisingData
from bumble.transport import open_transport_or_link
from bumble.gatt import (
    Characteristic,
    Service,
    GATT_AUDIO_STREAM_CONTROL_SERVICE,
    GATT_ASE_CONTROL_POINT_CHARACTERISTIC,
    GATT_COMMON_AUDIO_SERVICE,
    GATT_COORDINATED_SET_IDENTIFICATION_SERVICE,
    GATT_PUBLISHED_AUDIO_CAPABILITIES_SERVICE,
    GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC,
    GATT_SINK_ASE_CHARACTERISTIC,
)


# -----------------------------------------------------------------------------
class Listener(Device.Listener, Connection.Listener):
    def __init__(self, device):
        self.device = device

    def on_connection(self, connection):
        print(f'=== Connected to {connection}')
        connection.listener = self

    def on_disconnection(self, reason):
        print(f'### Disconnected, reason={reason}')

    def on_characteristic_subscription(
        self, connection, characteristic, notify_enabled, indicate_enabled
    ):
        print(
            f'$$$ Characteristic subscription for handle {characteristic.handle} '
            f'from {connection}: '
            f'notify {"enabled" if notify_enabled else "disabled"}, '
            f'indicate {"enabled" if indicate_enabled else "disabled"}'
        )


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: run_leaudio_unicast_sink.py <device-config> <transport-spec>')
        print('example: run_leaudio_unicast_sink.py adv_short_interval.json usb:0')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device to manage the host
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.listener = Listener(device)

        sirk = Characteristic(
            GATT_SET_IDENTITY_RESOLVING_KEY_CHARACTERISTIC,
            Characteristic.READ,
            Characteristic.READABLE,
            b'\x01' + b'\x01' * 16,
        )
        ase_control_point = Characteristic(
            GATT_ASE_CONTROL_POINT_CHARACTERISTIC,
            Characteristic.WRITE
            | Characteristic.WRITE_WITHOUT_RESPONSE
            | Characteristic.NOTIFY,
            Characteristic.WRITEABLE,
        )
        sink_ase = Characteristic(
            GATT_SINK_ASE_CHARACTERISTIC,
            Characteristic.READ | Characteristic.NOTIFY,
            Characteristic.READABLE,
        )
        ascs = Service(
            GATT_AUDIO_STREAM_CONTROL_SERVICE,
            [ase_control_point, sink_ase],
        )
        device.add_service(ascs)

        pacs = Service(GATT_PUBLISHED_AUDIO_CAPABILITIES_SERVICE, [])
        device.add_service(pacs)

        csis = Service(
            GATT_COORDINATED_SET_IDENTIFICATION_SERVICE,
            [sirk],
        )
        cas = Service(
            GATT_COMMON_AUDIO_SERVICE,
            characteristics=[],
            included_services=[csis],
        )
        device.add_service(cas)

        # Debug print
        for attribute in device.gatt_server.attributes:
            print(attribute)
        device.advertising_data = bytes(
            AdvertisingData(
                [
                    (AdvertisingData.COMPLETE_LOCAL_NAME, bytes(device.name, 'utf-8')),
                    (AdvertisingData.FLAGS, bytes([0x06])),
                ]
            )
        )

        # Get things going
        await device.power_on()

        # Connect to a peer
        if len(sys.argv) > 3:
            target_address = sys.argv[3]
            print(f'=== Connecting to {target_address}...')
            await device.connect(target_address)
        else:
            await device.start_advertising(auto_restart=True)

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
