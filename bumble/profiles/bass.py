# Copyright 2024 Google LLC
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
# See the License for

"""LE Audio - Broadcast Audio Scan Service"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import logging
from typing import Optional

from bumble import device
from bumble import gatt
from bumble import gatt_client
from bumble import utils

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
class ApplicationError(utils.OpenIntEnum):
    OPCODE_NOT_SUPPORTED = 0x80
    INVALID_SOURCE_ID = 0x81


# -----------------------------------------------------------------------------
class BroadcastAudioScanService(gatt.TemplateService):
    UUID = gatt.GATT_BROADCAST_AUDIO_SCAN_SERVICE

    def __init__(self):
        self.broadcast_audio_scan_control_point_characteristic = gatt.Characteristic(
            gatt.GATT_BROADCAST_AUDIO_SCAN_CONTROL_POINT_CHARACTERISTIC,
            gatt.Characteristic.Properties.WRITE
            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            gatt.Characteristic.WRITEABLE,
            gatt.CharacteristicValue(
                write=self.on_broadcast_audio_scan_control_point_write
            ),
        )

        self.broadcast_receive_state_characteristic = gatt.Characteristic(
            gatt.GATT_BROADCAST_RECEIVE_STATE_CHARACTERISTIC,
            gatt.Characteristic.Properties.READ | gatt.Characteristic.Properties.NOTIFY,
            gatt.Characteristic.Permissions.READABLE
            | gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            b'12',  # TEST
        )

        super().__init__([self.battery_level_characteristic])

    def on_broadcast_audio_scan_control_point_write(
        self, connection: device.Connection, value: bytes
    ) -> None:
        pass


# -----------------------------------------------------------------------------
class BroadcastAudioScanServiceProxy(gatt_client.ProfileServiceProxy):
    SERVICE_CLASS = BroadcastAudioScanService

    broadcast_audio_scan_control_point: Optional[gatt_client.CharacteristicProxy]
    broadcast_receive_state: Optional[gatt_client.CharacteristicProxy]

    def __init__(self, service_proxy: gatt_client.ServiceProxy):
        self.service_proxy = service_proxy

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_BROADCAST_AUDIO_SCAN_CONTROL_POINT_CHARACTERISTIC
        ):
            self.broadcast_audio_scan_control_point = characteristics[0]
        else:
            self.broadcast_audio_scan_control_point = None

        if characteristics := service_proxy.get_characteristics_by_uuid(
            gatt.GATT_BROADCAST_RECEIVE_STATE_CHARACTERISTIC
        ):
            self.broadcast_receive_state = characteristics[0]
        else:
            self.broadcast_receive_state = None
