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
# See the License for the specific language governing permissions and
# limitations under the License.

"""Le Audio - Audio Input Control Service"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import enum
import logging

from bumble.gatt import (
    Characteristic,
    TemplateService,
    GATT_AUDIO_INPUT_CONTROL_SERVICE,
    GATT_AUDIO_INPUT_STATE_CHARACTERISTIC,
    GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC,
    GATT_AUDIO_INPUT_TYPE_CHARACTERISTIC,
    GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC,
    GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC,
    GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC,
)

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
class Mute(enum.IntEnum):
    '''
    Cf. 2.2.1.2 Mute Field
    '''

    NOT_MUTED = 0
    MUTED = 1
    DISABLED = 2


class GainMode(enum.IntEnum):
    '''
    Cf. 2.2.1.3 Gain Mode
    '''

    MANUAL_ONLY = 0
    AUTOMATIC_ONLY = 1
    MANUAL = 2
    AUTOMATIC = 3


# -----------------------------------------------------------------------------
class AudioInputState(Characteristic):
    '''
    Cf. 2.2.1 AudioInputState
    '''

    gain_settings: int
    mute: Mute
    gain_mode: int
    change_counter: int


class AicsService(TemplateService):
    UUID = GATT_AUDIO_INPUT_CONTROL_SERVICE

    def __init__(self):
        self.audio_input_state = Characteristic(
            uuid=GATT_AUDIO_INPUT_STATE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ
            | Characteristic.Properties.NOTIFY,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.gain_settings_properties = Characteristic(
            uuid=GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.gain_settings_properties = Characteristic(
            uuid=GATT_AUDIO_INPUT_TYPE_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.gain_settings_properties = Characteristic(
            uuid=GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC,
            properties=Characteristic.Properties.READ,
            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.gain_settings_properties = Characteristic(
            uuid=GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC,
            properties=Characteristic.Properties.WRITE,
            permissions=Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=b'',
        )
        self.gain_settings_properties = Characteristic(
            uuid=GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC,
            properties=Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
            permissions=Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
            value=b'',
        )
        super().__init__([self.audio_input_state])
