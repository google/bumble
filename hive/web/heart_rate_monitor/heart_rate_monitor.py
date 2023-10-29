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
import struct

from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.hci import HCI_Reset_Command
from bumble.profiles.device_information_service import DeviceInformationService
from bumble.profiles.heart_rate_service import HeartRateService
from bumble.utils import AsyncRunner


# -----------------------------------------------------------------------------
class HeartRateMonitor:
    def __init__(self, hci_source, hci_sink):
        self.heart_rate = 60

        self.device = Device.with_hci(
            'Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink
        )

        device_information_service = DeviceInformationService(
            manufacturer_name='ACME',
            model_number='HR-102',
            serial_number='7654321',
            hardware_revision='1.1.3',
            software_revision='2.5.6',
            system_id=(0x123456, 0x8877665544),
        )

        self.heart_rate_service = HeartRateService(
            read_heart_rate_measurement=lambda _: HeartRateService.HeartRateMeasurement(
                heart_rate=self.heart_rate,
                sensor_contact_detected=True,
            ),
            body_sensor_location=HeartRateService.BodySensorLocation.WRIST,
            reset_energy_expended=self.reset_energy_expended,
        )

        # Notify subscribers of the current value as soon as they subscribe
        @self.heart_rate_service.heart_rate_measurement_characteristic.on(
            'subscription'
        )
        def on_subscription(_, notify_enabled, indicate_enabled):
            if notify_enabled or indicate_enabled:
                self.notify_heart_rate()

        self.device.add_services([device_information_service, self.heart_rate_service])

        self.device.advertising_data = bytes(
            AdvertisingData(
                [
                    (
                        AdvertisingData.FLAGS,
                        bytes(
                            [
                                AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG
                                | AdvertisingData.BR_EDR_NOT_SUPPORTED_FLAG
                            ]
                        ),
                    ),
                    (
                        AdvertisingData.COMPLETE_LOCAL_NAME,
                        bytes('Bumble Heart', 'utf-8'),
                    ),
                    (
                        AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                        bytes(self.heart_rate_service.uuid),
                    ),
                    (AdvertisingData.APPEARANCE, struct.pack('<H', 0x0340)),
                ]
            )
        )

    async def start(self):
        print('### Starting Monitor')
        await self.device.power_on()
        await self.device.start_advertising(auto_restart=True)
        print('### Monitor started')

    async def stop(self):
        # TODO: replace this once a proper reset is implemented in the lib.
        await self.device.host.send_command(HCI_Reset_Command())
        await self.device.power_off()
        print('### Monitor stopped')

    def notify_heart_rate(self):
        AsyncRunner.spawn(
            self.device.notify_subscribers(
                self.heart_rate_service.heart_rate_measurement_characteristic
            )
        )

    def set_heart_rate(self, heart_rate):
        self.heart_rate = heart_rate
        self.notify_heart_rate()

    def reset_energy_expended(self, _):
        print('<<< Reset Energy Expended')


# -----------------------------------------------------------------------------
def main(hci_source, hci_sink):
    return HeartRateMonitor(hci_source, hci_sink)
