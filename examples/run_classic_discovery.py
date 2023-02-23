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
import sys
import os
import logging
from bumble.colors import color

from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.core import DeviceClass


# -----------------------------------------------------------------------------
class DiscoveryListener(Device.Listener):
    def on_inquiry_result(self, address, class_of_device, data, rssi):
        (
            service_classes,
            major_device_class,
            minor_device_class,
        ) = DeviceClass.split_class_of_device(class_of_device)
        separator = '\n  '
        print(f'>>> {color(address, "yellow")}:')
        print(f'  Device Class (raw): {class_of_device:06X}')
        major_class_name = DeviceClass.major_device_class_name(major_device_class)
        print('  Device Major Class: ' f'{major_class_name}')
        minor_class_name = DeviceClass.minor_device_class_name(
            major_device_class, minor_device_class
        )
        print('  Device Minor Class: ' f'{minor_class_name}')
        print(
            '  Device Services: '
            f'{", ".join(DeviceClass.service_class_labels(service_classes))}'
        )
        print(f'  RSSI: {rssi}')
        if data.ad_structures:
            print(f'  {data.to_string(separator)}')


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 2:
        print('Usage: run_classic_discovery.py <transport-spec>')
        print('example: run_classic_discovery.py usb:04b4:f901')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[1]) as (hci_source, hci_sink):
        print('<<< connected')

        device = Device.with_hci('Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
        device.listener = DiscoveryListener()
        await device.power_on()
        await device.start_discovery()

        await hci_source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
