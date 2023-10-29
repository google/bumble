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
from bumble.device import Device
from bumble.hci import HCI_Reset_Command


# -----------------------------------------------------------------------------
class Scanner:
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
        self.device = Device.with_hci(
            'Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink
        )
        self.scan_entries = {}
        self.listeners = {}
        self.device.on('advertisement', self.on_advertisement)

    async def start(self):
        print('### Starting Scanner')
        self.scan_entries = {}
        self.emit_update()
        await self.device.power_on()
        await self.device.start_scanning()
        print('### Scanner started')

    async def stop(self):
        # TODO: replace this once a proper reset is implemented in the lib.
        await self.device.host.send_command(HCI_Reset_Command())
        await self.device.power_off()
        print('### Scanner stopped')

    def emit_update(self):
        if listener := self.listeners.get('update'):
            listener(list(self.scan_entries.values()))

    def on(self, event_name, listener):
        self.listeners[event_name] = listener

    def on_advertisement(self, advertisement):
        self.scan_entries[advertisement.address] = self.ScanEntry(advertisement)
        self.emit_update()


# -----------------------------------------------------------------------------
def main(hci_source, hci_sink):
    return Scanner(hci_source, hci_sink)
