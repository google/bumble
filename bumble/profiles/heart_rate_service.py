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
from enum import IntEnum
import struct

from ..gatt_client import ProfileServiceProxy
from ..att import ATT_Error
from ..gatt import (
    GATT_HEART_RATE_SERVICE,
    GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC,
    GATT_BODY_SENSOR_LOCATION_CHARACTERISTIC,
    GATT_HEART_RATE_CONTROL_POINT_CHARACTERISTIC,
    TemplateService,
    Characteristic,
    CharacteristicValue,
    DelegatedCharacteristicAdapter,
    PackedCharacteristicAdapter,
)


# -----------------------------------------------------------------------------
class HeartRateService(TemplateService):
    UUID = GATT_HEART_RATE_SERVICE
    HEART_RATE_CONTROL_POINT_FORMAT = 'B'
    CONTROL_POINT_NOT_SUPPORTED = 0x80
    RESET_ENERGY_EXPENDED = 0x01

    class BodySensorLocation(IntEnum):
        OTHER = 0
        CHEST = 1
        WRIST = 2
        FINGER = 3
        HAND = 4
        EAR_LOBE = 5
        FOOT = 6

    class HeartRateMeasurement:
        def __init__(
            self,
            heart_rate,
            sensor_contact_detected=None,
            energy_expended=None,
            rr_intervals=None,
        ):
            if heart_rate < 0 or heart_rate > 0xFFFF:
                raise ValueError('heart_rate out of range')

            if energy_expended is not None and (
                energy_expended < 0 or energy_expended > 0xFFFF
            ):
                raise ValueError('energy_expended out of range')

            if rr_intervals:
                for rr_interval in rr_intervals:
                    if rr_interval < 0 or rr_interval * 1024 > 0xFFFF:
                        raise ValueError('rr_intervals out of range')

            self.heart_rate = heart_rate
            self.sensor_contact_detected = sensor_contact_detected
            self.energy_expended = energy_expended
            self.rr_intervals = rr_intervals

        @classmethod
        def from_bytes(cls, data):
            flags = data[0]
            offset = 1

            if flags & 1:
                hr = struct.unpack_from('<H', data, offset)[0]
                offset += 2
            else:
                hr = struct.unpack_from('B', data, offset)[0]
                offset += 1

            if flags & (1 << 2):
                sensor_contact_detected = flags & (1 << 1) != 0
            else:
                sensor_contact_detected = None

            if flags & (1 << 3):
                energy_expended = struct.unpack_from('<H', data, offset)[0]
                offset += 2
            else:
                energy_expended = None

            if flags & (1 << 4):
                rr_intervals = tuple(
                    struct.unpack_from('<H', data, offset + i * 2)[0] / 1024
                    for i in range((len(data) - offset) // 2)
                )
            else:
                rr_intervals = ()

            return cls(hr, sensor_contact_detected, energy_expended, rr_intervals)

        def __bytes__(self):
            if self.heart_rate < 256:
                flags = 0
                data = struct.pack('B', self.heart_rate)
            else:
                flags = 1
                data = struct.pack('<H', self.heart_rate)

            if self.sensor_contact_detected is not None:
                flags |= ((1 if self.sensor_contact_detected else 0) << 1) | (1 << 2)

            if self.energy_expended is not None:
                flags |= 1 << 3
                data += struct.pack('<H', self.energy_expended)

            if self.rr_intervals:
                flags |= 1 << 4
                data += b''.join(
                    [
                        struct.pack('<H', int(rr_interval * 1024))
                        for rr_interval in self.rr_intervals
                    ]
                )

            return bytes([flags]) + data

        def __str__(self):
            return (
                f'HeartRateMeasurement(heart_rate={self.heart_rate},'
                f' sensor_contact_detected={self.sensor_contact_detected},'
                f' energy_expended={self.energy_expended},'
                f' rr_intervals={self.rr_intervals})'
            )

    def __init__(
        self,
        read_heart_rate_measurement,
        body_sensor_location=None,
        reset_energy_expended=None,
    ):
        self.heart_rate_measurement_characteristic = DelegatedCharacteristicAdapter(
            Characteristic(
                GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC,
                Characteristic.Properties.NOTIFY,
                0,
                CharacteristicValue(read=read_heart_rate_measurement),
            ),
            # pylint: disable=unnecessary-lambda
            encode=lambda value: bytes(value),
        )
        characteristics = [self.heart_rate_measurement_characteristic]

        if body_sensor_location is not None:
            self.body_sensor_location_characteristic = Characteristic(
                GATT_BODY_SENSOR_LOCATION_CHARACTERISTIC,
                Characteristic.Properties.READ,
                Characteristic.READABLE,
                bytes([int(body_sensor_location)]),
            )
            characteristics.append(self.body_sensor_location_characteristic)

        if reset_energy_expended:

            def write_heart_rate_control_point_value(connection, value):
                if value == self.RESET_ENERGY_EXPENDED:
                    if reset_energy_expended is not None:
                        reset_energy_expended(connection)
                else:
                    raise ATT_Error(self.CONTROL_POINT_NOT_SUPPORTED)

            self.heart_rate_control_point_characteristic = PackedCharacteristicAdapter(
                Characteristic(
                    GATT_HEART_RATE_CONTROL_POINT_CHARACTERISTIC,
                    Characteristic.Properties.WRITE,
                    Characteristic.WRITEABLE,
                    CharacteristicValue(write=write_heart_rate_control_point_value),
                ),
                pack_format=HeartRateService.HEART_RATE_CONTROL_POINT_FORMAT,
            )
            characteristics.append(self.heart_rate_control_point_characteristic)

        super().__init__(characteristics)


# -----------------------------------------------------------------------------
class HeartRateServiceProxy(ProfileServiceProxy):
    SERVICE_CLASS = HeartRateService

    def __init__(self, service_proxy):
        self.service_proxy = service_proxy

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC
        ):
            self.heart_rate_measurement = DelegatedCharacteristicAdapter(
                characteristics[0],
                decode=HeartRateService.HeartRateMeasurement.from_bytes,
            )
        else:
            self.heart_rate_measurement = None

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_BODY_SENSOR_LOCATION_CHARACTERISTIC
        ):
            self.body_sensor_location = DelegatedCharacteristicAdapter(
                characteristics[0],
                decode=lambda value: HeartRateService.BodySensorLocation(value[0]),
            )
        else:
            self.body_sensor_location = None

        if characteristics := service_proxy.get_characteristics_by_uuid(
            GATT_HEART_RATE_CONTROL_POINT_CHARACTERISTIC
        ):
            self.heart_rate_control_point = PackedCharacteristicAdapter(
                characteristics[0],
                pack_format=HeartRateService.HEART_RATE_CONTROL_POINT_FORMAT,
            )
        else:
            self.heart_rate_control_point = None

    async def reset_energy_expended(self):
        if self.heart_rate_control_point is not None:
            return await self.heart_rate_control_point.write_value(
                HeartRateService.RESET_ENERGY_EXPENDED
            )
