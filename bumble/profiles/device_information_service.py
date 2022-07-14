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
# DIS - Device Information Service
#
# See Bluetooth Document No. DIS_SPEC Revision: V11r00
#
# -----------------------------------------------------------------------------

from ..gatt import *


class GattDeviceInformationService(TemplateService):
    UUID = GATT_DEVICE_INFORMATION_SERVICE

    def __init__(self, manf_name=None, model_num=None,
                 serial_num=None, hw_rev=None, fw_rev=None, sw_rev=None):
        # TODO Support System ID
        # TODO Support IEEE 11073-20601 Regulatory Certification Data List
        # TODO Support PnP ID
        chars = []
        if manf_name is not None:
            chars.append(GattManufacturerNameStringCharacteristic(manf_name))

        if model_num is not None:
            chars.append(GattModelNumberStringCharacteristic(model_num))

        if serial_num is not None:
            chars.append(GattSerialNumberStringCharacteristic(serial_num))

        if hw_rev is not None:
            chars.append(GattHardwareRevisionStringCharacteristic(hw_rev))

        if fw_rev is not None:
            chars.append(GattFirmwareRevisionStringCharacteristic(fw_rev))

        if sw_rev is not None:
            chars.append(GattSoftwareRevisionStringCharacteristic(sw_rev))

        super().__init__(chars)


class GattManufacturerNameStringCharacteristic(UTF8Characteristic):
    UUID = GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC
    PROPERTIES = Characteristic.READ
    PERMISSIONS = Characteristic.READABLE


class GattModelNumberStringCharacteristic(UTF8Characteristic):
    UUID = GATT_MODEL_NUMBER_STRING_CHARACTERISTIC
    PROPERTIES = Characteristic.READ
    PERMISSIONS = Characteristic.READABLE


class GattSerialNumberStringCharacteristic(UTF8Characteristic):
    UUID = GATT_SERIAL_NUMBER_STRING_CHARACTERISTIC
    PROPERTIES = Characteristic.READ
    PERMISSIONS = Characteristic.READABLE


class GattHardwareRevisionStringCharacteristic(UTF8Characteristic):
    UUID = GATT_HARDWARE_REVISION_STRING_CHARACTERISTIC
    PROPERTIES = Characteristic.READ
    PERMISSIONS = Characteristic.READABLE


class GattFirmwareRevisionStringCharacteristic(UTF8Characteristic):
    UUID = GATT_FIRMWARE_REVISION_STRING_CHARACTERISTIC
    PROPERTIES = Characteristic.READ
    PERMISSIONS = Characteristic.READABLE


class GattSoftwareRevisionStringCharacteristic(UTF8Characteristic):
    UUID = GATT_SOFTWARE_REVISION_STRING_CHARACTERISTIC
    PROPERTIES = Characteristic.READ
    PERMISSIONS = Characteristic.READABLE
