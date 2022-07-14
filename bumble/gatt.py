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
import logging
import struct
from colors import color

from .core import *
from .hci import *
from .att import *

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
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
GATT_DEVICE_HEART_RATE_SERVICE              = UUID.from_16_bits(0x180D, 'Heart Rate')
GATT_PHONE_ALTERT_STATUS_SERVICE            = UUID.from_16_bits(0x180E, 'Phone Alert Status')
GATT_DEVICE_BATTERY_SERVICE                 = UUID.from_16_bits(0x180F, 'Battery')
GATT_BLOOD_PRESSURE_SERVICE                 = UUID.from_16_bits(0x1810, 'Blood Pressure')
GATT_ALTERT_NOTIFICATION_SERVICE            = UUID.from_16_bits(0x1811, 'Alert Notification')
GATT_DEVICE_HUMAN_INTERFACE_DEVICE_SERVICE  = UUID.from_16_bits(0x1812, 'Human Interface Device')
GATT_DEVICE_SCAN_PARAMETERS_SERVICE         = UUID.from_16_bits(0x1813, 'Scan Parameters')
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
GATT_COMPLETE_BE_EDR_TRANSPORT_BLOCK_DATA_DESCRIPTOR = UUID.from_16_bits(0x290F, 'Complete BR-EDR Transport Block Data')

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

# Human Interface Device
GATT_HID_INFORMATION_CHARACTERISTIC   = UUID.from_16_bits(0x2A4A, 'HID Information')
GATT_REPORT_MAP_CHARACTERISTIC        = UUID.from_16_bits(0x2A4B, 'Report Map')
GATT_HID_CONTROL_POINT_CHARACTERISTIC = UUID.from_16_bits(0x2A4C, 'HID Control Point')
GATT_REPORT_CHARACTERISTIC            = UUID.from_16_bits(0x2A4D, 'Report')
GATT_PROTOCOL_MODE_CHARACTERISTIC     = UUID.from_16_bits(0x2A4E, 'Protocol Mode')

# Misc
GATT_DEVICE_NAME_CHARACTERISTIC                                  = UUID.from_16_bits(0x2A00, 'Device Name')
GATT_APPEARANCE_CHARACTERISTIC                                   = UUID.from_16_bits(0x2A01, 'Appearance')
GATT_PERIPHERAL_PRIVACY_FLAG_CHARACTERISTIC                      = UUID.from_16_bits(0x2A02, 'Peripheral Privacy Flag')
GATT_RECONNECTION_ADDRESS_CHARACTERISTIC                         = UUID.from_16_bits(0x2A03, 'Reconnection Address')
GATT_PERIPHERAL_PREFERRREED_CONNECTION_PARAMETERS_CHARACTERISTIC = UUID.from_16_bits(0x2A04, 'Peripheral Preferred Connection Parameters')
GATT_SERVICE_CHANGED_CHARACTERISTIC                              = UUID.from_16_bits(0x2A05, 'Service Changed')
GATT_ALERT_LEVEL_CHARACTERISTIC                                  = UUID.from_16_bits(0x2A06, 'Alert Level')
GATT_TX_POWER_LEVEL_CHARACTERISTIC                               = UUID.from_16_bits(0x2A07, 'Tx Power Level')
GATT_BATTERY_LEVEL_CHARACTERISTIC                                = UUID.from_16_bits(0x2A19, 'Battery Level')
GATT_BOOT_KEYBOARD_INPUT_REPORT_CHARACTERISTIC                   = UUID.from_16_bits(0x2A22, 'Boot Keyboard Input Report')
GATT_CURRENT_TIME_CHARACTERISTIC                                 = UUID.from_16_bits(0x2A2B, 'Current Time')
GATT_BOOT_KEYBOARD_OUTPUT_REPORT_CHARACTERISTIC                  = UUID.from_16_bits(0x2A32, 'Boot Keyboard Output Report')
GATT_CENTRAL_ADDRESS_RESOLUTION__CHARACTERISTIC                  = UUID.from_16_bits(0x2AA6, 'Central Address Resolution')


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

    def __init__(self, uuid, characteristics, primary=True):
        # Convert the uuid to a UUID object if it isn't already
        if type(uuid) is str:
            uuid = UUID(uuid)

        super().__init__(
            GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE if primary else GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE,
            Attribute.READABLE,
            uuid.to_pdu_bytes()
        )
        self.uuid              = uuid
        self.included_services = []
        self.characteristics   = characteristics[:]
        self.end_group_handle  = 0
        self.primary           = primary

    def __str__(self):
        return f'Service(handle=0x{self.handle:04X}, end=0x{self.end_group_handle:04X}, uuid={self.uuid}){"" if self.primary else "*"}'


class TemplateService(Service):
    UUID = None
    CHARACTERISTICS = []
    PRIMARY = True

    def __init__(self, characteristics=[]):
        if not characteristics:
            characteristics = [x() for x in self.CHARACTERISTICS]

        super().__init__(
            self.UUID,
            characteristics,
            self.PRIMARY
            )


# -----------------------------------------------------------------------------
class Characteristic(Attribute):
    '''
    See Vol 3, Part G - 3.3 CHARACTERISTIC DEFINITION
    '''

    # Property flags
    BROADCAST                   = 0x01
    READ                        = 0x02
    WRITE_WITHOUT_RESPONSE      = 0x04
    WRITE                       = 0x08
    NOTIFY                      = 0x10
    INDICATE                    = 0X20
    AUTHENTICATED_SIGNED_WRITES = 0X40
    EXTENDED_PROPERTIES         = 0X80

    PROPERTY_NAMES = {
        BROADCAST:                   'BROADCAST',
        READ:                        'READ',
        WRITE_WITHOUT_RESPONSE:      'WRITE_WITHOUT_RESPONSE',
        WRITE:                       'WRITE',
        NOTIFY:                      'NOTIFY',
        INDICATE:                    'INDICATE',
        AUTHENTICATED_SIGNED_WRITES: 'AUTHENTICATED_SIGNED_WRITES',
        EXTENDED_PROPERTIES:         'EXTENDED_PROPERTIES'
    }

    @staticmethod
    def property_name(property):
        return Characteristic.PROPERTY_NAMES.get(property, '')

    def __init__(self, uuid, properties, permissions, value = b'', descriptors = []):
        # Convert the uuid to a UUID object if it isn't already
        if type(uuid) is str:
            uuid = UUID(uuid)

        super().__init__(uuid, permissions, value)
        self.uuid                    = uuid
        self.properties              = properties
        self._descriptors            = descriptors
        self._descriptors_discovered = False
        self.end_group_handle        = 0
        self.attach_descriptors()

    def attach_descriptors(self):
        """ Let all the descriptors know they are attached to this characteristic """
        for descriptor in self._descriptors:
            descriptor.characteristic = self

    def add_descriptor(self, descriptor):
        descriptor.characteristic = self
        self.descriptors.append(descriptor)

    def get_descriptor(self, descriptor_type):
        for descriptor in self.descriptors:
            if descriptor.uuid == descriptor_type:
                return descriptor

    @property
    def descriptors(self):
        return self._descriptors

    @descriptors.setter
    def descriptors(self, value):
        self._descriptors = value
        self._descriptors_discovered = True
        self.attach_descriptors()

    @property
    def descriptors_discovered(self):
        return self._descriptors_discovered

    def get_properties_as_string(self):
        return ','.join([self.property_name(p) for p in self.PROPERTY_NAMES.keys() if self.properties & p])

    def __str__(self):
        return f'Characteristic(handle=0x{self.handle:04X}, end=0x{self.end_group_handle:04X}, uuid={self.uuid}, properties={self.get_properties_as_string()})'


class TemplateCharacteristic(Characteristic):
    UUID = None
    PROPERTIES = None
    PERMISSIONS = None
    VALUE = b''

    def __init__(self, value):
        if value is None:
            value = self.VALUE if type(self.VALUE) is bytes else self.VALUE()

        super().__init__(self.UUID, self.PROPERTIES, self.PERMISSIONS, value)


class UTF8Characteristic(TemplateCharacteristic):
    def __init__(self, value):
        super().__init__(UTF8CharacteristicValue(value=value))


# -----------------------------------------------------------------------------
class CharacteristicValue:
    def __init__(self, read=None, write=None, value=None):
        self._read = read
        self._write = write
        self._value = value

    def read(self, connection):
        if self._read:
            return self._read(connection)
        elif self._value is not None:
            return self._value
        else:
            return b''

    def write(self, connection, value):
        if self._write:
            self._write(connection, value)
        elif self._value is not None:
            self._value = value

class PackedCharacteristicValue(CharacteristicValue):
    def __init__(self, fmt, **kwargs):
        super().__init__(**kwargs)
        self.fmt = fmt
        self.struct = struct.Struct(fmt)

    def pack(self, *values):
        return self.struct.pack(*values)

    def unpack(self, buf):
        return self.struct.unpack(buf)

    def read(self, connection):
        return self.pack(super().read(connection))

    def write(self, connection, value):
        super().write(connection, self.unpack(value))

class MappedCharacteristicValue(PackedCharacteristicValue):
    def __init__(self, fmt, tags, **kwargs):
        super().__init__(fmt, **kwargs)
        self.tags = tags

    def pack(self, values):
        return super().pack(*iter(values[key] for key in self.tags))

    def unpack(self, buf):
        return {key:value for (key, value) in zip(self.tags, super().unpack(buf))}


class UTF8CharacteristicValue(PackedCharacteristicValue):
    def __init__(self, **kwargs):
        super().__init__('<s', **kwargs)

    def pack(self, value):
        return value.encode('UTF-8')

    def unpack(self, buf):
        return buf.decode()


# -----------------------------------------------------------------------------
class Descriptor(Attribute):
    '''
    See Vol 3, Part G - 3.3.3 Characteristic Descriptor Declarations
    '''

    def __init__(self, uuid, permissions, value = b''):
        # Convert the uuid to a UUID object if it isn't already
        if type(uuid) is str:
            uuid = UUID(uuid)

        super().__init__(uuid, permissions, value)
        self.uuid = uuid
        self.characteristic = None

    def __str__(self):
        return f'Descriptor(handle=0x{self.handle:04X}, uuid={self.uuid}, value={self.read_value(None).hex()})'
