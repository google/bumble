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
import time

from bumble.device import Device


# -----------------------------------------------------------------------------
class ScanEntry:
    def __init__(self, advertisement):
        self.address = advertisement.address.to_string(False)
        self.address_type = ('Public', 'Random', 'Public Identity', 'Random Identity')[
            advertisement.address.address_type
        ]
        self.rssi = advertisement.rssi
        self.data = advertisement.data.to_string("\n")


# -----------------------------------------------------------------------------
class ScannerListener(Device.Listener):
    def __init__(self, callback):
        self.callback = callback
        self.entries = {}

    def on_advertisement(self, advertisement):
        self.entries[advertisement.address] = ScanEntry(advertisement)
        self.callback(list(self.entries.values()))


# -----------------------------------------------------------------------------
async def main(hci_source, hci_sink, callback):
    print('### Starting Scanner')
    device = Device.with_hci('Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
    device.listener = ScannerListener(callback)
    await device.power_on()
    await device.start_scanning()

    print('### Scanner started')
