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
from bumble.device import Device, Advertisement, Connection, Peer
from bumble.hci import Address, HCI_Reset_Command
from bumble.core import AdvertisingData
from bumble.gatt import (
    GATT_HEART_RATE_SERVICE,
    GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC,
)
from typing import Optional, Union

from bumble.utils import AsyncRunner
import asyncio
import datetime


# -----------------------------------------------------------------------------
class Treadmill:
    peer: Optional[Peer]

    class ScanEntry:
        def __init__(self, advertisement):
            self.address = advertisement.address.to_string(False)
            self.address_type = (
                'Public',
                'Random',
                'Public Identity',
                'Random Identity',
            )[advertisement.address.address_type]
            self.rssi = advertisement.rssi
            self.data = advertisement.data.to_string('\n')

    def __init__(self, hci_source, hci_sink):
        super().__init__()
        random_address = Address.generate_static_address()
        self.device = Device.with_hci('Bumbleton', random_address, hci_source, hci_sink)
        self.scan_entries = {}
        self.listeners = {}
        self.peer = None
        self.device.on('advertisement', self.on_advertisement)
        self.device.on('connection', self.on_connection)

    async def start(self):
        print('### Starting Scanner')
        self.scan_entries = {}
        self.emit_scanning_update()
        await self.device.power_on()
        await self.device.start_scanning()
        print('### Scanner started')

    async def stop(self):
        # TODO: replace this once a proper reset is implemented in the lib.
        await self.device.host.send_command(HCI_Reset_Command())
        await self.device.power_off()
        print('### Scanner stopped')

    def emit_scanning_update(self):
        if listener := self.listeners.get('scanning_updates'):
            listener(list(self.scan_entries.values()))

    def emit_hr_update(self, value: int, time: str):
        if listener := self.listeners.get('hr_updates'):
            listener({"value": value, "time": time})

    def emit_connection_updates(self, connection: Connection):
        if listener := self.listeners.get('connection_updates'):
            listener(
                {
                    'handle': connection.handle,
                    'role': connection.role_name,
                    'self_address': str(connection.self_address),
                    'peer_address': str(connection.peer_address),
                    'is_encrypted': "Yes" if connection.is_encrypted else "No",
                }
            )

    def emit_on_security_request(self):
        if listener := self.listeners.get('on_security_request'):
            listener()

    def on(self, event_name, listener):
        self.listeners[event_name] = listener

    def on_advertisement(self, advertisement: Advertisement):
        uuids = advertisement.data.get(
            AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
        )
        if not uuids:
            return
        if not GATT_HEART_RATE_SERVICE in uuids:
            return

        self.scan_entries[advertisement.address] = self.ScanEntry(advertisement)
        self.emit_scanning_update()

    @AsyncRunner.run_in_task()
    async def on_connection(self, connection: Connection):
        self.emit_connection_updates(connection)
        connection.listener = self
        connection.on('security_request', self.on_security_request)
        connection.on('pairing_failure', self.on_pairing_failure)
        connection.on('pairing', self.on_pairing)
        self.peer = Peer(connection)
        print(f'Connected to {self.peer}')
        print("Starting service discovery...")
        await self.peer.discover_all()
        print("Service discovery complete!")

        hr_measurement_characteristics = self.peer.get_characteristics_by_uuid(
            uuid=GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC,
            service=GATT_HEART_RATE_SERVICE,
        )
        hr_measurement_characteristic = hr_measurement_characteristics[0]
        print(
            f"HR measurement characteristic attribute: {hr_measurement_characteristic.handle}"
        )

        await hr_measurement_characteristic.subscribe(
            lambda value: self.emit_hr_update(
                value=int.from_bytes(value), time=str(datetime.datetime.now())
            )
        )

    async def do_connect(self, address: str):
        print(f'Connecting to {address}')
        if self.device.is_scanning:
            await self.device.stop_scanning()

        await self.device.connect(address)

    def on_security_request(self, _):
        print("Received security request!")
        self.emit_on_security_request()

    def do_security_request_response(self, value: bool):
        print(f"do_security_request_response {value}")
        if value:
            asyncio.create_task(self.peer.connection.pair())
        else:
            asyncio.create_task(
                self.device.smp_manager.send_command(
                    self.peer.connection,
                    SMP_Pairing_Failed_Command(reason=SMP_PAIRING_NOT_SUPPORTED_ERROR),
                )
            )

    def on_pairing_failure(self, reason):
        self.emit_connection_updates(self.peer.connection)
        print("Pairing failed for reason ", reason)

    def on_pairing(self, keys):
        self.emit_connection_updates(self.peer.connection)


# -----------------------------------------------------------------------------
def main(hci_source, hci_sink):
    return Treadmill(hci_source, hci_sink)
