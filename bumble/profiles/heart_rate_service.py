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
from __future__ import annotations

import dataclasses
import enum
import struct
from collections.abc import Callable, Sequence
from typing import Any

from typing_extensions import Self

from bumble import att, core, device, gatt, gatt_adapters, gatt_client, utils


# -----------------------------------------------------------------------------
class HeartRateService(gatt.TemplateService):
    UUID = gatt.GATT_HEART_RATE_SERVICE

    HEART_RATE_CONTROL_POINT_FORMAT = 'B'
    CONTROL_POINT_NOT_SUPPORTED = 0x80
    RESET_ENERGY_EXPENDED = 0x01

    heart_rate_measurement_characteristic: gatt.Characteristic[HeartRateMeasurement]
    body_sensor_location_characteristic: gatt.Characteristic[BodySensorLocation]
    heart_rate_control_point_characteristic: gatt.Characteristic[int]

    class BodySensorLocation(utils.OpenIntEnum):
        OTHER = 0
        CHEST = 1
        WRIST = 2
        FINGER = 3
        HAND = 4
        EAR_LOBE = 5
        FOOT = 6

    @dataclasses.dataclass
    class HeartRateMeasurement:
        heart_rate: int
        sensor_contact_detected: bool | None = None
        energy_expended: int | None = None
        rr_intervals: Sequence[float] | None = None

        class Flag(enum.IntFlag):
            INT16_HEART_RATE = 1 << 0
            SENSOR_CONTACT_DETECTED = 1 << 1
            SENSOR_CONTACT_SUPPORTED = 1 << 2
            ENERGY_EXPENDED_STATUS = 1 << 3
            RR_INTERVAL = 1 << 4

        def __post_init__(self) -> None:
            if self.heart_rate < 0 or self.heart_rate > 0xFFFF:
                raise core.InvalidArgumentError('heart_rate out of range')

            if self.energy_expended is not None and (
                self.energy_expended < 0 or self.energy_expended > 0xFFFF
            ):
                raise core.InvalidArgumentError('energy_expended out of range')

            if self.rr_intervals:
                for rr_interval in self.rr_intervals:
                    if rr_interval < 0 or rr_interval * 1024 > 0xFFFF:
                        raise core.InvalidArgumentError('rr_intervals out of range')

        @classmethod
        def from_bytes(cls, data: bytes) -> Self:
            flags = data[0]
            offset = 1

            if flags & cls.Flag.INT16_HEART_RATE:
                heart_rate = struct.unpack_from('<H', data, offset)[0]
                offset += 2
            else:
                heart_rate = struct.unpack_from('B', data, offset)[0]
                offset += 1

            if flags & cls.Flag.SENSOR_CONTACT_SUPPORTED:
                sensor_contact_detected = flags & cls.Flag.SENSOR_CONTACT_DETECTED != 0
            else:
                sensor_contact_detected = None

            if flags & cls.Flag.ENERGY_EXPENDED_STATUS:
                energy_expended = struct.unpack_from('<H', data, offset)[0]
                offset += 2
            else:
                energy_expended = None

            rr_intervals: Sequence[float] | None = None
            if flags & cls.Flag.RR_INTERVAL:
                rr_intervals = tuple(
                    struct.unpack_from('<H', data, i)[0] / 1024
                    for i in range(offset, len(data), 2)
                )

            return cls(
                heart_rate=heart_rate,
                sensor_contact_detected=sensor_contact_detected,
                energy_expended=energy_expended,
                rr_intervals=rr_intervals,
            )

        def __bytes__(self) -> bytes:
            flags = 0
            if self.heart_rate < 256:
                data = struct.pack('B', self.heart_rate)
            else:
                flags |= self.Flag.INT16_HEART_RATE
                data = struct.pack('<H', self.heart_rate)

            if self.sensor_contact_detected is not None:
                flags |= self.Flag.SENSOR_CONTACT_SUPPORTED
                if self.sensor_contact_detected:
                    flags |= self.Flag.SENSOR_CONTACT_DETECTED

            if self.energy_expended is not None:
                flags |= self.Flag.ENERGY_EXPENDED_STATUS
                data += struct.pack('<H', self.energy_expended)

            if self.rr_intervals is not None:
                flags |= self.Flag.RR_INTERVAL
                data += b''.join(
                    [
                        struct.pack('<H', int(rr_interval * 1024))
                        for rr_interval in self.rr_intervals
                    ]
                )

            return bytes([flags]) + data

    def __init__(
        self,
        read_heart_rate_measurement: Callable[
            [device.Connection], HeartRateMeasurement
        ],
        body_sensor_location: HeartRateService.BodySensorLocation | None = None,
        reset_energy_expended: Callable[[device.Connection], Any] | None = None,
    ):
        self.heart_rate_measurement_characteristic = (
            gatt_adapters.SerializableCharacteristicAdapter(
                gatt.Characteristic(
                    uuid=gatt.GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC,
                    properties=gatt.Characteristic.Properties.NOTIFY,
                    permissions=gatt.Characteristic.Permissions(0),
                    value=gatt.CharacteristicValue(read=read_heart_rate_measurement),
                ),
                HeartRateService.HeartRateMeasurement,
            )
        )
        characteristics: list[gatt.Characteristic] = [
            self.heart_rate_measurement_characteristic
        ]

        if body_sensor_location is not None:
            self.body_sensor_location_characteristic = (
                gatt_adapters.EnumCharacteristicAdapter(
                    gatt.Characteristic(
                        uuid=gatt.GATT_BODY_SENSOR_LOCATION_CHARACTERISTIC,
                        properties=gatt.Characteristic.Properties.READ,
                        permissions=gatt.Characteristic.READABLE,
                        value=body_sensor_location,
                    ),
                    cls=self.BodySensorLocation,
                    length=1,
                )
            )
            characteristics.append(self.body_sensor_location_characteristic)

        if reset_energy_expended:

            def write_heart_rate_control_point_value(
                connection: device.Connection, value: bytes
            ) -> None:
                if value == self.RESET_ENERGY_EXPENDED:
                    if reset_energy_expended is not None:
                        reset_energy_expended(connection)
                else:
                    raise att.ATT_Error(self.CONTROL_POINT_NOT_SUPPORTED)

            self.heart_rate_control_point_characteristic = (
                gatt_adapters.PackedCharacteristicAdapter(
                    gatt.Characteristic(
                        uuid=gatt.GATT_HEART_RATE_CONTROL_POINT_CHARACTERISTIC,
                        properties=gatt.Characteristic.Properties.WRITE,
                        permissions=gatt.Characteristic.WRITEABLE,
                        value=gatt.CharacteristicValue(
                            write=write_heart_rate_control_point_value
                        ),
                    ),
                    pack_format=HeartRateService.HEART_RATE_CONTROL_POINT_FORMAT,
                )
            )
            characteristics.append(self.heart_rate_control_point_characteristic)

        super().__init__(characteristics)


# -----------------------------------------------------------------------------
class HeartRateServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = HeartRateService

    heart_rate_measurement: gatt_client.CharacteristicProxy[
        HeartRateService.HeartRateMeasurement
    ]
    body_sensor_location: (
        gatt_client.CharacteristicProxy[HeartRateService.BodySensorLocation] | None
    )
    heart_rate_control_point: gatt_client.CharacteristicProxy[int] | None

    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
        self.service_proxy = service_proxy

        self.heart_rate_measurement = (
            gatt_adapters.SerializableCharacteristicProxyAdapter(
                service_proxy.get_required_characteristic_by_uuid(
                    gatt.GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC
                ),
                HeartRateService.HeartRateMeasurement,
            )
        )

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_BODY_SENSOR_LOCATION_CHARACTERISTIC
        ):
            self.body_sensor_location = gatt_adapters.EnumCharacteristicProxyAdapter(
                characteristics[0], cls=HeartRateService.BodySensorLocation, length=1
            )
        else:
            self.body_sensor_location = None

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_HEART_RATE_CONTROL_POINT_CHARACTERISTIC
        ):
            self.heart_rate_control_point = (
                gatt_adapters.PackedCharacteristicProxyAdapter(
                    characteristics[0],
                    pack_format=HeartRateService.HEART_RATE_CONTROL_POINT_FORMAT,
                )
            )
        else:
            self.heart_rate_control_point = None

    async def reset_energy_expended(self) -> None:
        if self.heart_rate_control_point is not None:
            return await self.heart_rate_control_point.write_value(
                HeartRateService.RESET_ENERGY_EXPENDED
            )
