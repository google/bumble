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
import sys
import time
import math
import random
import struct
import logging
import asyncio
import os

from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.transport import open_transport_or_link
from bumble.profiles.device_information_service import DeviceInformationService
from bumble.profiles.heart_rate_service import HeartRateService
from bumble.utils import AsyncRunner


# -----------------------------------------------------------------------------
async def main():
    if len(sys.argv) != 3:
        print('Usage: python heart_rate_server.py <device-config> <transport-spec>')
        print('example: python heart_rate_server.py device1.json usb:0')
        return

    async with await open_transport_or_link(sys.argv[2]) as (hci_source, hci_sink):
        device = Device.from_config_file_with_hci(sys.argv[1], hci_source, hci_sink)

        # Keep track of accumulated expended energy
        energy_start_time = time.time()

        def reset_energy_expended():
            nonlocal energy_start_time
            energy_start_time = time.time()

        # Add a Device Information Service and Heart Rate Service to the GATT sever
        device_information_service = DeviceInformationService(
            manufacturer_name='ACME',
            model_number='HR-102',
            serial_number='7654321',
            hardware_revision='1.1.3',
            software_revision='2.5.6',
            system_id=(0x123456, 0x8877665544),
        )

        heart_rate_service = HeartRateService(
            read_heart_rate_measurement=lambda _: HeartRateService.HeartRateMeasurement(
                heart_rate=100 + int(50 * math.sin(time.time() * math.pi / 60)),
                sensor_contact_detected=random.choice((True, False, None)),
                energy_expended=random.choice(
                    (int((time.time() - energy_start_time) * 100), None)
                ),
                rr_intervals=random.choice(
                    (
                        (
                            random.randint(900, 1100) / 1000,
                            random.randint(900, 1100) / 1000,
                        ),
                        None,
                    )
                ),
            ),
            body_sensor_location=HeartRateService.BodySensorLocation.WRIST,
            reset_energy_expended=lambda _: reset_energy_expended(),
        )

        device.add_services([device_information_service, heart_rate_service])

        # Set the advertising data
        device.advertising_data = bytes(
            AdvertisingData(
                [
                    (
                        AdvertisingData.COMPLETE_LOCAL_NAME,
                        bytes('Bumble Heart', 'utf-8'),
                    ),
                    (
                        AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                        bytes(heart_rate_service.uuid),
                    ),
                    (AdvertisingData.APPEARANCE, struct.pack('<H', 0x0340)),
                ]
            )
        )

        # Notify subscribers of the current value as soon as they subscribe
        @heart_rate_service.heart_rate_measurement_characteristic.on('subscription')
        def on_subscription(connection, notify_enabled, indicate_enabled):
            if notify_enabled or indicate_enabled:
                AsyncRunner.spawn(
                    device.notify_subscriber(
                        connection,
                        heart_rate_service.heart_rate_measurement_characteristic,
                    )
                )

        # Go!
        await device.power_on()
        await device.start_advertising(auto_restart=True)

        # Notify every 3 seconds
        while True:
            await asyncio.sleep(3.0)
            await device.notify_subscribers(
                heart_rate_service.heart_rate_measurement_characteristic
            )


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
