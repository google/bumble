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
# GATT - Generic Attribute Profile
#
# See Bluetooth spec @ Vol 3, Part G
#
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import asyncio
import enum
import functools
import logging
import struct
from typing import Sequence
from colors import color

from .core import UUID, get_dict_key_by_value
from .att import Attribute


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

GATT_REQUEST_TIMEOUT = 30  # seconds

GATT_MAX_ATTRIBUTE_VALUE_SIZE = 512

# Services
GATT_GENERIC_ACCESS_SERVICE                 = UUID.from_16_bits(0x1800, 'Generic Access')
GATT_GENERIC_ATTRIBUTE_SERVICE              = UUID.from_16_bits(0x1801, 'Generic Attribute')
GATT_IMMEDIATE_ALERT_SERVICE                = UUID.from_16_bits(0x1802, 'Immediate Alert')
GATT_LINK_LOSS_SERVICE                      = UUID.from_16_bits(0x1803, 'Link Loss')
GATT_TX_POWER_SERVICE                       = UUID.from_16_bits(0x1804, 'TX Power')
GATT_CURRENT_TIME_SERVICE                   = UUID.from_16_bits(0x1805, 'Current Time')
GATT_REFERENCE_TIME_UPDATE_SERVICE          = UUID.from_16_bits(0x1806, 'Reference Time Update')
GATT_NEXT_DST_CHANGE_SERVICE                = UUID.from_16_bits(0x1807, 'Next DST Change')
GATT_GLUCOSE_SERVICE                        = UUID.from_16_bits(0x1808, 'Glucose')
GATT_HEALTH_THERMOMETER_SERVICE             = UUID.from_16_bits(0x1809, 'Health Thermometer')
GATT_DEVICE_INFORMATION_SERVICE             = UUID.from_16_bits(0x180A, 'Device Information')
GATT_HEART_RATE_SERVICE                     = UUID.from_16_bits(0x180D, 'Heart Rate')
GATT_PHONE_ALERT_STATUS_SERVICE             = UUID.from_16_bits(0x180E, 'Phone Alert Status')
GATT_BATTERY_SERVICE                        = UUID.from_16_bits(0x180F, 'Battery')
GATT_BLOOD_PRESSURE_SERVICE                 = UUID.from_16_bits(0x1810, 'Blood Pressure')
GATT_ALERT_NOTIFICATION_SERVICE             = UUID.from_16_bits(0x1811, 'Alert Notification')
GATT_HUMAN_INTERFACE_DEVICE_SERVICE         = UUID.from_16_bits(0x1812, 'Human Interface Device')
GATT_SCAN_PARAMETERS_SERVICE                = UUID.from_16_bits(0x1813, 'Scan Parameters')
GATT_RUNNING_SPEED_AND_CADENCE_SERVICE      = UUID.from_16_bits(0x1814, 'Running Speed and Cadence')
GATT_AUTOMATION_IO_SERVICE                  = UUID.from_16_bits(0x1815, 'Automation IO')
GATT_CYCLING_SPEED_AND_CADENCE_SERVICE      = UUID.from_16_bits(0x1816, 'Cycling Speed and Cadence')
GATT_CYCLING_POWER_SERVICE                  = UUID.from_16_bits(0x1818, 'Cycling Power')
GATT_LOCATION_AND_NAVIGATION_SERVICE        = UUID.from_16_bits(0x1819, 'Location and Navigation')
GATT_ENVIRONMENTAL_SENSING_SERVICE          = UUID.from_16_bits(0x181A, 'Environmental Sensing')
GATT_BODY_COMPOSITION_SERVICE               = UUID.from_16_bits(0x181B, 'Body Composition')
GATT_USER_DATA_SERVICE                      = UUID.from_16_bits(0x181C, 'User Data')
GATT_WEIGHT_SCALE_SERVICE                   = UUID.from_16_bits(0x181D, 'Weight Scale')
GATT_BOND_MANAGEMENT_SERVICE                = UUID.from_16_bits(0x181E, 'Bond Management')
GATT_CONTINUOUS_GLUCOSE_MONITORING_SERVICE  = UUID.from_16_bits(0x181F, 'Continuous Glucose Monitoring')
GATT_INTERNET_PROTOCOL_SUPPORT_SERVICE      = UUID.from_16_bits(0x1820, 'Internet Protocol Support')
GATT_INDOOR_POSITIONING_SERVICE             = UUID.from_16_bits(0x1821, 'Indoor Positioning')
GATT_PULSE_OXIMETER_SERVICE                 = UUID.from_16_bits(0x1822, 'Pulse Oximeter')
GATT_HTTP_PROXY_SERVICE                     = UUID.from_16_bits(0x1823, 'HTTP Proxy')
GATT_TRANSPORT_DISCOVERY_SERVICE            = UUID.from_16_bits(0x1824, 'Transport Discovery')
GATT_OBJECT_TRANSFER_SERVICE                = UUID.from_16_bits(0x1825, 'Object Transfer')
GATT_FITNESS_MACHINE_SERVICE                = UUID.from_16_bits(0x1826, 'Fitness Machine')
GATT_MESH_PROVISIONING_SERVICE              = UUID.from_16_bits(0x1827, 'Mesh Provisioning')
GATT_MESH_PROXY_SERVICE                     = UUID.from_16_bits(0x1828, 'Mesh Proxy')
GATT_RECONNECTION_CONFIGURATION_SERVICE     = UUID.from_16_bits(0x1829, 'Reconnection Configuration')
GATT_INSULIN_DELIVERY_SERVICE               = UUID.from_16_bits(0x183A, 'Insulin Delivery')
GATT_BINARY_SENSOR_SERVICE                  = UUID.from_16_bits(0x183B, 'Binary Sensor')
GATT_EMERGENCY_CONFIGURATION_SERVICE        = UUID.from_16_bits(0x183C, 'Emergency Configuration')
GATT_PHYSICAL_ACTIVITY_MONITOR_SERVICE      = UUID.from_16_bits(0x183E, 'Physical Activity Monitor')
GATT_AUDIO_INPUT_CONTROL_SERVICE            = UUID.from_16_bits(0x1843, 'Audio Input Control')
GATT_VOLUME_CONTROL_SERVICE                 = UUID.from_16_bits(0x1844, 'Volume Control')
GATT_VOLUME_OFFSET_CONTROL_SERVICE          = UUID.from_16_bits(0x1845, 'Volume Offset Control')
GATT_COORDINATED_SET_IDENTIFICATION_SERVICE = UUID.from_16_bits(0x1846, 'Coordinated Set Identification Service')
GATT_DEVICE_TIME_SERVICE                    = UUID.from_16_bits(0x1847, 'Device Time')
GATT_MEDIA_CONTROL_SERVICE                  = UUID.from_16_bits(0x1848, 'Media Control Service')
GATT_GENERIC_MEDIA_CONTROL_SERVICE          = UUID.from_16_bits(0x1849, 'Generic Media Control Service')
GATT_CONSTANT_TONE_EXTENSION_SERVICE        = UUID.from_16_bits(0x184A, 'Constant Tone Extension')
GATT_TELEPHONE_BEARER_SERVICE               = UUID.from_16_bits(0x184B, 'Telephone Bearer Service')
GATT_GENERIC_TELEPHONE_BEARER_SERVICE       = UUID.from_16_bits(0x184C, 'Generic Telephone Bearer Service')
GATT_MICROPHONE_CONTROL_SERVICE             = UUID.from_16_bits(0x184D, 'Microphone Control')

# Types
GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE   = UUID.from_16_bits(0x2800, 'Primary Service')
GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE = UUID.from_16_bits(0x2801, 'Secondary Service')
GATT_INCLUDE_ATTRIBUTE_TYPE           = UUID.from_16_bits(0x2802, 'Include')
GATT_CHARACTERISTIC_ATTRIBUTE_TYPE    = UUID.from_16_bits(0x2803, 'Characteristic')

# Descriptors
GATT_CHARACTERISTIC_EXTENDED_PROPERTIES_DESCRIPTOR   = UUID.from_16_bits(0x2900, 'Characteristic Extended Properties')
GATT_CHARACTERISTIC_USER_DESCRIPTION_DESCRIPTOR      = UUID.from_16_bits(0x2901, 'Characteristic User Description')
GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR  = UUID.from_16_bits(0x2902, 'Client Characteristic Configuration')
GATT_SERVER_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR  = UUID.from_16_bits(0x2903, 'Server Characteristic Configuration')
GATT_CHARACTERISTIC_PRESENTATION_FORMAT_DESCRIPTOR   = UUID.from_16_bits(0x2904, 'Characteristic Format')
GATT_CHARACTERISTIC_AGGREGATE_FORMAT_DESCRIPTOR      = UUID.from_16_bits(0x2905, 'Characteristic Aggregate Format')
GATT_VALID_RANGE_DESCRIPTOR                          = UUID.from_16_bits(0x2906, 'Valid Range')
GATT_EXTERNAL_REPORT_DESCRIPTOR                      = UUID.from_16_bits(0x2907, 'External Report')
GATT_REPORT_REFERENCE_DESCRIPTOR                     = UUID.from_16_bits(0x2908, 'Report Reference')
GATT_NUMBER_OF_DIGITALS_DESCRIPTOR                   = UUID.from_16_bits(0x2909, 'Number of Digitals')
GATT_VALUE_TRIGGER_SETTING_DESCRIPTOR                = UUID.from_16_bits(0x290A, 'Value Trigger Setting')
GATT_ENVIRONMENTAL_SENSING_CONFIGURATION_DESCRIPTOR  = UUID.from_16_bits(0x290B, 'Environmental Sensing Configuration')
GATT_ENVIRONMENTAL_SENSING_MEASUREMENT_DESCRIPTOR    = UUID.from_16_bits(0x290C, 'Environmental Sensing Measurement')
GATT_ENVIRONMENTAL_SENSING_TRIGGER_DESCRIPTOR        = UUID.from_16_bits(0x290D, 'Environmental Sensing Trigger Setting')
GATT_TIME_TRIGGER_DESCRIPTOR                         = UUID.from_16_bits(0x290E, 'Time Trigger Setting')
GATT_COMPLETE_BR_EDR_TRANSPORT_BLOCK_DATA_DESCRIPTOR = UUID.from_16_bits(0x290F, 'Complete BR-EDR Transport Block Data')

# Device Information Service
GATT_SYSTEM_ID_CHARACTERISTIC                          = UUID.from_16_bits(0x2A23, 'System ID')
GATT_MODEL_NUMBER_STRING_CHARACTERISTIC                = UUID.from_16_bits(0x2A24, 'Model Number String')
GATT_SERIAL_NUMBER_STRING_CHARACTERISTIC               = UUID.from_16_bits(0x2A25, 'Serial Number String')
GATT_FIRMWARE_REVISION_STRING_CHARACTERISTIC           = UUID.from_16_bits(0x2A26, 'Firmware Revision String')
GATT_HARDWARE_REVISION_STRING_CHARACTERISTIC           = UUID.from_16_bits(0x2A27, 'Hardware Revision String')
GATT_SOFTWARE_REVISION_STRING_CHARACTERISTIC           = UUID.from_16_bits(0x2A28, 'Software Revision String')
GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC           = UUID.from_16_bits(0x2A29, 'Manufacturer Name String')
GATT_REGULATORY_CERTIFICATION_DATA_LIST_CHARACTERISTIC = UUID.from_16_bits(0x2A2A, 'IEEE 11073-20601 Regulatory Certification Data List')
GATT_PNP_ID_CHARACTERISTIC                             = UUID.from_16_bits(0x2A50, 'PnP ID')

# Human Interface Device Service
GATT_HID_INFORMATION_CHARACTERISTIC   = UUID.from_16_bits(0x2A4A, 'HID Information')
GATT_REPORT_MAP_CHARACTERISTIC        = UUID.from_16_bits(0x2A4B, 'Report Map')
GATT_HID_CONTROL_POINT_CHARACTERISTIC = UUID.from_16_bits(0x2A4C, 'HID Control Point')
GATT_REPORT_CHARACTERISTIC            = UUID.from_16_bits(0x2A4D, 'Report')
GATT_PROTOCOL_MODE_CHARACTERISTIC     = UUID.from_16_bits(0x2A4E, 'Protocol Mode')

# Heart Rate Service
GATT_HEART_RATE_MEASUREMENT_CHARACTERISTIC   = UUID.from_16_bits(0x2A37, 'Heart Rate Measurement')
GATT_BODY_SENSOR_LOCATION_CHARACTERISTIC     = UUID.from_16_bits(0x2A38, 'Body Sensor Location')
GATT_HEART_RATE_CONTROL_POINT_CHARACTERISTIC = UUID.from_16_bits(0x2A39, 'Heart Rate Control Point')

# Battery Service
GATT_BATTERY_LEVEL_CHARACTERISTIC = UUID.from_16_bits(0x2A19, 'Battery Level')

# ASHA Service
GATT_ASHA_SERVICE                             = UUID.from_16_bits(0xFDF0, 'Audio Streaming for Hearing Aid')
GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC = UUID('6333651e-c481-4a3e-9169-7c902aad37bb', 'ReadOnlyProperties')
GATT_ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC  = UUID('f0d4de7e-4a88-476c-9d9f-1937b0996cc0', 'AudioControlPoint')
GATT_ASHA_AUDIO_STATUS_CHARACTERISTIC         = UUID('38663f1a-e711-4cac-b641-326b56404837', 'AudioStatus')
GATT_ASHA_VOLUME_CHARACTERISTIC               = UUID('00e4ca9e-ab14-41e4-8823-f9e70c7e91df', 'Volume')
GATT_ASHA_LE_PSM_OUT_CHARACTERISTIC           = UUID('2d410339-82b6-42aa-b34e-e2e01df8cc1a', 'LE_PSM_OUT')

# Misc
GATT_DEVICE_NAME_CHARACTERISTIC                                = UUID.from_16_bits(0x2A00, 'Device Name')
GATT_APPEARANCE_CHARACTERISTIC                                 = UUID.from_16_bits(0x2A01, 'Appearance')
GATT_PERIPHERAL_PRIVACY_FLAG_CHARACTERISTIC                    = UUID.from_16_bits(0x2A02, 'Peripheral Privacy Flag')
GATT_RECONNECTION_ADDRESS_CHARACTERISTIC                       = UUID.from_16_bits(0x2A03, 'Reconnection Address')
GATT_PERIPHERAL_PREFERRED_CONNECTION_PARAMETERS_CHARACTERISTIC = UUID.from_16_bits(0x2A04, 'Peripheral Preferred Connection Parameters')
GATT_SERVICE_CHANGED_CHARACTERISTIC                            = UUID.from_16_bits(0x2A05, 'Service Changed')
GATT_ALERT_LEVEL_CHARACTERISTIC                                = UUID.from_16_bits(0x2A06, 'Alert Level')
GATT_TX_POWER_LEVEL_CHARACTERISTIC                             = UUID.from_16_bits(0x2A07, 'Tx Power Level')
GATT_BOOT_KEYBOARD_INPUT_REPORT_CHARACTERISTIC                 = UUID.from_16_bits(0x2A22, 'Boot Keyboard Input Report')
GATT_CURRENT_TIME_CHARACTERISTIC                               = UUID.from_16_bits(0x2A2B, 'Current Time')
GATT_BOOT_KEYBOARD_OUTPUT_REPORT_CHARACTERISTIC                = UUID.from_16_bits(0x2A32, 'Boot Keyboard Output Report')
GATT_CENTRAL_ADDRESS_RESOLUTION__CHARACTERISTIC                = UUID.from_16_bits(0x2AA6, 'Central Address Resolution')

# fmt: on
# pylint: enable=line-too-long


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------


def show_services(services):
    for service in services:
        print(color(str(service), 'cyan'))

        for characteristic in service.characteristics:
            print(color('  ' + str(characteristic), 'magenta'))

            for descriptor in characteristic.descriptors:
                print(color('    ' + str(descriptor), 'green'))


# -----------------------------------------------------------------------------
class Service(Attribute):
    '''
    See Vol 3, Part G - 3.1 SERVICE DEFINITION
    '''

    def __init__(self, uuid, characteristics: list[Characteristic], primary=True):
        # Convert the uuid to a UUID object if it isn't already
        if isinstance(uuid, str):
            uuid = UUID(uuid)

        super().__init__(
            GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE
            if primary
            else GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE,
            Attribute.READABLE,
            uuid.to_pdu_bytes(),
        )
        self.uuid = uuid
        # self.included_services = []
        self.characteristics = characteristics[:]
        self.primary = primary

    def get_advertising_data(self):
        """
        Get Service specific advertising data
        Defined by each Service, default value is empty
        :return Service data for advertising
        """
        return None

    def __str__(self):
        return (
            f'Service(handle=0x{self.handle:04X}, '
            f'end=0x{self.end_group_handle:04X}, '
            f'uuid={self.uuid})'
            f'{"" if self.primary else "*"}'
        )


# -----------------------------------------------------------------------------
class TemplateService(Service):
    '''
    Convenience abstract class that can be used by profile-specific subclasses that want
    to expose their UUID as a class property
    '''

    UUID = None

    def __init__(self, characteristics, primary=True):
        super().__init__(self.UUID, characteristics, primary)


# -----------------------------------------------------------------------------
class Characteristic(Attribute):
    '''
    See Vol 3, Part G - 3.3 CHARACTERISTIC DEFINITION
    '''

    # Property flags
    BROADCAST = 0x01
    READ = 0x02
    WRITE_WITHOUT_RESPONSE = 0x04
    WRITE = 0x08
    NOTIFY = 0x10
    INDICATE = 0x20
    AUTHENTICATED_SIGNED_WRITES = 0x40
    EXTENDED_PROPERTIES = 0x80

    PROPERTY_NAMES = {
        BROADCAST: 'BROADCAST',
        READ: 'READ',
        WRITE_WITHOUT_RESPONSE: 'WRITE_WITHOUT_RESPONSE',
        WRITE: 'WRITE',
        NOTIFY: 'NOTIFY',
        INDICATE: 'INDICATE',
        AUTHENTICATED_SIGNED_WRITES: 'AUTHENTICATED_SIGNED_WRITES',
        EXTENDED_PROPERTIES: 'EXTENDED_PROPERTIES',
    }

    @staticmethod
    def property_name(property_int):
        return Characteristic.PROPERTY_NAMES.get(property_int, '')

    @staticmethod
    def properties_as_string(properties):
        return ','.join(
            [
                Characteristic.property_name(p)
                for p in Characteristic.PROPERTY_NAMES
                if properties & p
            ]
        )

    @staticmethod
    def string_to_properties(properties_str: str):
        return functools.reduce(
            lambda x, y: x | get_dict_key_by_value(Characteristic.PROPERTY_NAMES, y),
            properties_str.split(","),
            0,
        )

    def __init__(
        self,
        uuid,
        properties,
        permissions,
        value=b'',
        descriptors: Sequence[Descriptor] = (),
    ):
        super().__init__(uuid, permissions, value)
        self.uuid = self.type
        if isinstance(properties, str):
            self.properties = Characteristic.string_to_properties(properties)
        else:
            self.properties = properties
        self.descriptors = descriptors

    def get_descriptor(self, descriptor_type):
        for descriptor in self.descriptors:
            if descriptor.type == descriptor_type:
                return descriptor

        return None

    def __str__(self):
        return (
            f'Characteristic(handle=0x{self.handle:04X}, '
            f'end=0x{self.end_group_handle:04X}, '
            f'uuid={self.uuid}, '
            f'properties={Characteristic.properties_as_string(self.properties)})'
        )


# -----------------------------------------------------------------------------
class CharacteristicDeclaration(Attribute):
    '''
    See Vol 3, Part G - 3.3.1 CHARACTERISTIC DECLARATION
    '''

    def __init__(self, characteristic, value_handle):
        declaration_bytes = (
            struct.pack('<BH', characteristic.properties, value_handle)
            + characteristic.uuid.to_pdu_bytes()
        )
        super().__init__(
            GATT_CHARACTERISTIC_ATTRIBUTE_TYPE, Attribute.READABLE, declaration_bytes
        )
        self.value_handle = value_handle
        self.characteristic = characteristic

    def __str__(self):
        return (
            f'CharacteristicDeclaration(handle=0x{self.handle:04X}, '
            f'value_handle=0x{self.value_handle:04X}, '
            f'uuid={self.characteristic.uuid}, properties='
            f'{Characteristic.properties_as_string(self.characteristic.properties)})'
        )


# -----------------------------------------------------------------------------
class CharacteristicValue:
    '''
    Characteristic value where reading and/or writing is delegated to functions
    passed as arguments to the constructor.
    '''

    def __init__(self, read=None, write=None):
        self._read = read
        self._write = write

    def read(self, connection):
        return self._read(connection) if self._read else b''

    def write(self, connection, value):
        if self._write:
            self._write(connection, value)


# -----------------------------------------------------------------------------
class CharacteristicAdapter:
    '''
    An adapter that can adapt any object with `read_value` and `write_value`
    methods (like Characteristic and CharacteristicProxy objects) by wrapping
    those methods with ones that return/accept encoded/decoded values.
    Objects with async methods are considered proxies, so the adaptation is one
    where the return value of `read_value` is decoded and the value passed to
    `write_value` is encoded. Other objects are considered local characteristics
    so the adaptation is one where the return value of `read_value` is encoded
    and the value passed to `write_value` is decoded.
    If the characteristic has a `subscribe` method, it is wrapped with one where
    the values are decoded before being passed to the subscriber.
    '''

    def __init__(self, characteristic):
        self.wrapped_characteristic = characteristic
        self.subscribers = {}  # Map from subscriber to proxy subscriber

        if asyncio.iscoroutinefunction(
            characteristic.read_value
        ) and asyncio.iscoroutinefunction(characteristic.write_value):
            self.read_value = self.read_decoded_value
            self.write_value = self.write_decoded_value
        else:
            self.read_value = self.read_encoded_value
            self.write_value = self.write_encoded_value

        if hasattr(self.wrapped_characteristic, 'subscribe'):
            self.subscribe = self.wrapped_subscribe

        if hasattr(self.wrapped_characteristic, 'unsubscribe'):
            self.unsubscribe = self.wrapped_unsubscribe

    def __getattr__(self, name):
        return getattr(self.wrapped_characteristic, name)

    def __setattr__(self, name, value):
        if name in (
            'wrapped_characteristic',
            'subscribers',
            'read_value',
            'write_value',
            'subscribe',
            'unsubscribe',
        ):
            super().__setattr__(name, value)
        else:
            setattr(self.wrapped_characteristic, name, value)

    def read_encoded_value(self, connection):
        return self.encode_value(self.wrapped_characteristic.read_value(connection))

    def write_encoded_value(self, connection, value):
        return self.wrapped_characteristic.write_value(
            connection, self.decode_value(value)
        )

    async def read_decoded_value(self):
        return self.decode_value(await self.wrapped_characteristic.read_value())

    async def write_decoded_value(self, value, with_response=False):
        return await self.wrapped_characteristic.write_value(
            self.encode_value(value), with_response
        )

    def encode_value(self, value):
        return value

    def decode_value(self, value):
        return value

    def wrapped_subscribe(self, subscriber=None):
        if subscriber is not None:
            if subscriber in self.subscribers:
                # We already have a proxy subscriber
                subscriber = self.subscribers[subscriber]
            else:
                # Create and register a proxy that will decode the value
                original_subscriber = subscriber

                def on_change(value):
                    original_subscriber(self.decode_value(value))

                self.subscribers[subscriber] = on_change
                subscriber = on_change

        return self.wrapped_characteristic.subscribe(subscriber)

    def wrapped_unsubscribe(self, subscriber=None):
        if subscriber in self.subscribers:
            subscriber = self.subscribers.pop(subscriber)

        return self.wrapped_characteristic.unsubscribe(subscriber)

    def __str__(self):
        wrapped = str(self.wrapped_characteristic)
        return f'{self.__class__.__name__}({wrapped})'


# -----------------------------------------------------------------------------
class DelegatedCharacteristicAdapter(CharacteristicAdapter):
    '''
    Adapter that converts bytes values using an encode and a decode function.
    '''

    def __init__(self, characteristic, encode=None, decode=None):
        super().__init__(characteristic)
        self.encode = encode
        self.decode = decode

    def encode_value(self, value):
        return self.encode(value) if self.encode else value

    def decode_value(self, value):
        return self.decode(value) if self.decode else value


# -----------------------------------------------------------------------------
class PackedCharacteristicAdapter(CharacteristicAdapter):
    '''
    Adapter that packs/unpacks characteristic values according to a standard
    Python `struct` format.
    For formats with a single value, the adapted `read_value` and `write_value`
    methods return/accept single values. For formats with multiple values,
    they return/accept a tuple with the same number of elements as is required for
    the format.
    '''

    def __init__(self, characteristic, pack_format):
        super().__init__(characteristic)
        self.struct = struct.Struct(pack_format)

    def pack(self, *values):
        return self.struct.pack(*values)

    def unpack(self, buffer):
        return self.struct.unpack(buffer)

    def encode_value(self, value):
        return self.pack(*value if isinstance(value, tuple) else (value,))

    def decode_value(self, value):
        unpacked = self.unpack(value)
        return unpacked[0] if len(unpacked) == 1 else unpacked


# -----------------------------------------------------------------------------
class MappedCharacteristicAdapter(PackedCharacteristicAdapter):
    '''
    Adapter that packs/unpacks characteristic values according to a standard
    Python `struct` format.
    The adapted `read_value` and `write_value` methods return/accept aa dictionary which
    is packed/unpacked according to format, with the arguments extracted from the
    dictionary by key, in the same order as they occur in the `keys` parameter.
    '''

    def __init__(self, characteristic, pack_format, keys):
        super().__init__(characteristic, pack_format)
        self.keys = keys

    # pylint: disable=arguments-differ
    def pack(self, values):
        return super().pack(*(values[key] for key in self.keys))

    def unpack(self, buffer):
        return dict(zip(self.keys, super().unpack(buffer)))


# -----------------------------------------------------------------------------
class UTF8CharacteristicAdapter(CharacteristicAdapter):
    '''
    Adapter that converts strings to/from bytes using UTF-8 encoding
    '''

    def encode_value(self, value):
        return value.encode('utf-8')

    def decode_value(self, value):
        return value.decode('utf-8')


# -----------------------------------------------------------------------------
class Descriptor(Attribute):
    '''
    See Vol 3, Part G - 3.3.3 Characteristic Descriptor Declarations
    '''

    def __str__(self):
        return (
            f'Descriptor(handle=0x{self.handle:04X}, '
            f'type={self.type}, '
            f'value={self.read_value(None).hex()})'
        )


class ClientCharacteristicConfigurationBits(enum.IntFlag):
    '''
    See Vol 3, Part G - 3.3.3.3 - Table 3.11 Client Characteristic Configuration bit
    field definition
    '''

    DEFAULT = 0x0000
    NOTIFICATION = 0x0001
    INDICATION = 0x0002
