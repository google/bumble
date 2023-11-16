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
import enum
import struct
from typing import List, Optional, Tuple, Union, cast, Dict

from .company_ids import COMPANY_IDENTIFIERS


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off

BT_CENTRAL_ROLE    = 0
BT_PERIPHERAL_ROLE = 1

BT_BR_EDR_TRANSPORT = 0
BT_LE_TRANSPORT     = 1


# fmt: on


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def bit_flags_to_strings(bits, bit_flag_names):
    names = []
    index = 0
    while bits != 0:
        if bits & 1:
            name = bit_flag_names[index] if index < len(bit_flag_names) else f'#{index}'
            names.append(name)
        bits >>= 1
        index += 1

    return names


def name_or_number(dictionary: Dict[int, str], number: int, width: int = 2) -> str:
    name = dictionary.get(number)
    if name is not None:
        return name
    return f'[0x{number:0{width}X}]'


def padded_bytes(buffer, size):
    padding_size = max(size - len(buffer), 0)
    return buffer + bytes(padding_size)


def get_dict_key_by_value(dictionary, value):
    for key, val in dictionary.items():
        if val == value:
            return key
    return None


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------
class BaseError(Exception):
    """Base class for errors with an error code, error name and namespace"""

    def __init__(
        self,
        error_code: Optional[int],
        error_namespace: str = '',
        error_name: str = '',
        details: str = '',
    ):
        super().__init__()
        self.error_code = error_code
        self.error_namespace = error_namespace
        self.error_name = error_name
        self.details = details

    def __str__(self):
        if self.error_namespace:
            namespace = f'{self.error_namespace}/'
        else:
            namespace = ''
        error_text = {
            (True, True): f'{self.error_name} [0x{self.error_code:X}]',
            (True, False): self.error_name,
            (False, True): f'0x{self.error_code:X}',
            (False, False): '',
        }[(self.error_name != '', self.error_code is not None)]

        return f'{type(self).__name__}({namespace}{error_text})'


class ProtocolError(BaseError):
    """Protocol Error"""


class TimeoutError(Exception):  # pylint: disable=redefined-builtin
    """Timeout Error"""


class CommandTimeoutError(Exception):
    """Command Timeout Error"""


class InvalidStateError(Exception):
    """Invalid State Error"""


class ConnectionError(BaseError):  # pylint: disable=redefined-builtin
    """Connection Error"""

    FAILURE = 0x01
    CONNECTION_REFUSED = 0x02

    def __init__(
        self,
        error_code,
        transport,
        peer_address,
        error_namespace='',
        error_name='',
        details='',
    ):
        super().__init__(error_code, error_namespace, error_name, details)
        self.transport = transport
        self.peer_address = peer_address


class ConnectionParameterUpdateError(BaseError):
    """Connection Parameter Update Error"""


# -----------------------------------------------------------------------------
# UUID
#
# NOTE: the internal byte representation is in little-endian byte order
#
# Base UUID: 00000000-0000-1000-8000- 00805F9B34FB
# -----------------------------------------------------------------------------
class UUID:
    '''
    See Bluetooth spec Vol 3, Part B - 2.5.1 UUID

    Note that this class expects and works in little-endian byte-order throughout.
    The exception is when interacting with strings, which are in big-endian byte-order.
    '''

    BASE_UUID = bytes.fromhex('00001000800000805F9B34FB')[::-1]  # little-endian
    UUIDS: List[UUID] = []  # Registry of all instances created

    uuid_bytes: bytes
    name: Optional[str]

    def __init__(
        self, uuid_str_or_int: Union[str, int], name: Optional[str] = None
    ) -> None:
        if isinstance(uuid_str_or_int, int):
            self.uuid_bytes = struct.pack('<H', uuid_str_or_int)
        else:
            if len(uuid_str_or_int) == 36:
                if (
                    uuid_str_or_int[8] != '-'
                    or uuid_str_or_int[13] != '-'
                    or uuid_str_or_int[18] != '-'
                    or uuid_str_or_int[23] != '-'
                ):
                    raise ValueError('invalid UUID format')
                uuid_str = uuid_str_or_int.replace('-', '')
            else:
                uuid_str = uuid_str_or_int
            if len(uuid_str) != 32 and len(uuid_str) != 8 and len(uuid_str) != 4:
                raise ValueError(f"invalid UUID format: {uuid_str}")
            self.uuid_bytes = bytes(reversed(bytes.fromhex(uuid_str)))
        self.name = name

    def register(self) -> UUID:
        # Register this object in the class registry, and update the entry's name if
        # it wasn't set already
        for uuid in self.UUIDS:
            if self == uuid:
                if uuid.name is None:
                    uuid.name = self.name
                return uuid

        self.UUIDS.append(self)
        return self

    @classmethod
    def from_bytes(cls, uuid_bytes: bytes, name: Optional[str] = None) -> UUID:
        if len(uuid_bytes) in (2, 4, 16):
            self = cls.__new__(cls)
            self.uuid_bytes = uuid_bytes
            self.name = name

            return self.register()

        raise ValueError('only 2, 4 and 16 bytes are allowed')

    @classmethod
    def from_16_bits(cls, uuid_16: int, name: Optional[str] = None) -> UUID:
        return cls.from_bytes(struct.pack('<H', uuid_16), name)

    @classmethod
    def from_32_bits(cls, uuid_32: int, name: Optional[str] = None) -> UUID:
        return cls.from_bytes(struct.pack('<I', uuid_32), name)

    @classmethod
    def parse_uuid(cls, uuid_as_bytes: bytes, offset: int) -> Tuple[int, UUID]:
        return len(uuid_as_bytes), cls.from_bytes(uuid_as_bytes[offset:])

    @classmethod
    def parse_uuid_2(cls, uuid_as_bytes: bytes, offset: int) -> Tuple[int, UUID]:
        return offset + 2, cls.from_bytes(uuid_as_bytes[offset : offset + 2])

    def to_bytes(self, force_128: bool = False) -> bytes:
        '''
        Serialize UUID in little-endian byte-order
        '''
        if not force_128:
            return self.uuid_bytes

        if len(self.uuid_bytes) == 2:
            return self.BASE_UUID + self.uuid_bytes + bytes([0, 0])
        elif len(self.uuid_bytes) == 4:
            return self.BASE_UUID + self.uuid_bytes
        elif len(self.uuid_bytes) == 16:
            return self.uuid_bytes
        else:
            assert False, "unreachable"

    def to_pdu_bytes(self) -> bytes:
        '''
        Convert to bytes for use in an ATT PDU.
        According to Vol 3, Part F - 3.2.1 Attribute Type:
        "All 32-bit Attribute UUIDs shall be converted to 128-bit UUIDs when the
         Attribute UUID is contained in an ATT PDU."
        '''
        return self.to_bytes(force_128=(len(self.uuid_bytes) == 4))

    def to_hex_str(self, separator: str = '') -> str:
        if len(self.uuid_bytes) == 2 or len(self.uuid_bytes) == 4:
            return bytes(reversed(self.uuid_bytes)).hex().upper()

        return separator.join(
            [
                bytes(reversed(self.uuid_bytes[12:16])).hex(),
                bytes(reversed(self.uuid_bytes[10:12])).hex(),
                bytes(reversed(self.uuid_bytes[8:10])).hex(),
                bytes(reversed(self.uuid_bytes[6:8])).hex(),
                bytes(reversed(self.uuid_bytes[0:6])).hex(),
            ]
        ).upper()

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UUID):
            return self.to_bytes(force_128=True) == other.to_bytes(force_128=True)

        if isinstance(other, str):
            return UUID(other) == self

        return False

    def __hash__(self) -> int:
        return hash(self.uuid_bytes)

    def __str__(self) -> str:
        result = self.to_hex_str(separator='-')
        if len(self.uuid_bytes) == 2:
            result = 'UUID-16:' + result
        elif len(self.uuid_bytes) == 4:
            result = 'UUID-32:' + result
        if self.name is not None:
            result += f' ({self.name})'
        return result


# -----------------------------------------------------------------------------
# Common UUID constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

# Protocol Identifiers
BT_SDP_PROTOCOL_ID                      = UUID.from_16_bits(0x0001, 'SDP')
BT_UDP_PROTOCOL_ID                      = UUID.from_16_bits(0x0002, 'UDP')
BT_RFCOMM_PROTOCOL_ID                   = UUID.from_16_bits(0x0003, 'RFCOMM')
BT_TCP_PROTOCOL_ID                      = UUID.from_16_bits(0x0004, 'TCP')
BT_TCS_BIN_PROTOCOL_ID                  = UUID.from_16_bits(0x0005, 'TCP-BIN')
BT_TCS_AT_PROTOCOL_ID                   = UUID.from_16_bits(0x0006, 'TCS-AT')
BT_ATT_PROTOCOL_ID                      = UUID.from_16_bits(0x0007, 'ATT')
BT_OBEX_PROTOCOL_ID                     = UUID.from_16_bits(0x0008, 'OBEX')
BT_IP_PROTOCOL_ID                       = UUID.from_16_bits(0x0009, 'IP')
BT_FTP_PROTOCOL_ID                      = UUID.from_16_bits(0x000A, 'FTP')
BT_HTTP_PROTOCOL_ID                     = UUID.from_16_bits(0x000C, 'HTTP')
BT_WSP_PROTOCOL_ID                      = UUID.from_16_bits(0x000E, 'WSP')
BT_BNEP_PROTOCOL_ID                     = UUID.from_16_bits(0x000F, 'BNEP')
BT_UPNP_PROTOCOL_ID                     = UUID.from_16_bits(0x0010, 'UPNP')
BT_HIDP_PROTOCOL_ID                     = UUID.from_16_bits(0x0011, 'HIDP')
BT_HARDCOPY_CONTROL_CHANNEL_PROTOCOL_ID = UUID.from_16_bits(0x0012, 'HardcopyControlChannel')
BT_HARDCOPY_DATA_CHANNEL_PROTOCOL_ID    = UUID.from_16_bits(0x0014, 'HardcopyDataChannel')
BT_HARDCOPY_NOTIFICATION_PROTOCOL_ID    = UUID.from_16_bits(0x0016, 'HardcopyNotification')
BT_AVTCP_PROTOCOL_ID                    = UUID.from_16_bits(0x0017, 'AVCTP')
BT_AVDTP_PROTOCOL_ID                    = UUID.from_16_bits(0x0019, 'AVDTP')
BT_CMTP_PROTOCOL_ID                     = UUID.from_16_bits(0x001B, 'CMTP')
BT_MCAP_CONTROL_CHANNEL_PROTOCOL_ID     = UUID.from_16_bits(0x001E, 'MCAPControlChannel')
BT_MCAP_DATA_CHANNEL_PROTOCOL_ID        = UUID.from_16_bits(0x001F, 'MCAPDataChannel')
BT_L2CAP_PROTOCOL_ID                    = UUID.from_16_bits(0x0100, 'L2CAP')

# Service Classes and Profiles
BT_SERVICE_DISCOVERY_SERVER_SERVICE_CLASS_ID_SERVICE = UUID.from_16_bits(0x1000, 'ServiceDiscoveryServerServiceClassID')
BT_BROWSE_GROUP_DESCRIPTOR_SERVICE_CLASS_ID_SERVICE  = UUID.from_16_bits(0x1001, 'BrowseGroupDescriptorServiceClassID')
BT_SERIAL_PORT_SERVICE                               = UUID.from_16_bits(0x1101, 'SerialPort')
BT_LAN_ACCESS_USING_PPP_SERVICE                      = UUID.from_16_bits(0x1102, 'LANAccessUsingPPP')
BT_DIALUP_NETWORKING_SERVICE                         = UUID.from_16_bits(0x1103, 'DialupNetworking')
BT_IR_MCSYNC_SERVICE                                 = UUID.from_16_bits(0x1104, 'IrMCSync')
BT_OBEX_OBJECT_PUSH_SERVICE                          = UUID.from_16_bits(0x1105, 'OBEXObjectPush')
BT_OBEX_FILE_TRANSFER_SERVICE                        = UUID.from_16_bits(0x1106, 'OBEXFileTransfer')
BT_IR_MCSYNC_COMMAND_SERVICE                         = UUID.from_16_bits(0x1107, 'IrMCSyncCommand')
BT_HEADSET_SERVICE                                   = UUID.from_16_bits(0x1108, 'Headset')
BT_CORDLESS_TELEPHONY_SERVICE                        = UUID.from_16_bits(0x1109, 'CordlessTelephony')
BT_AUDIO_SOURCE_SERVICE                              = UUID.from_16_bits(0x110A, 'AudioSource')
BT_AUDIO_SINK_SERVICE                                = UUID.from_16_bits(0x110B, 'AudioSink')
BT_AV_REMOTE_CONTROL_TARGET_SERVICE                  = UUID.from_16_bits(0x110C, 'A/V_RemoteControlTarget')
BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE               = UUID.from_16_bits(0x110D, 'AdvancedAudioDistribution')
BT_AV_REMOTE_CONTROL_SERVICE                         = UUID.from_16_bits(0x110E, 'A/V_RemoteControl')
BT_AV_REMOTE_CONTROL_CONTROLLER_SERVICE              = UUID.from_16_bits(0x110F, 'A/V_RemoteControlController')
BT_INTERCOM_SERVICE                                  = UUID.from_16_bits(0x1110, 'Intercom')
BT_FAX_SERVICE                                       = UUID.from_16_bits(0x1111, 'Fax')
BT_HEADSET_AUDIO_GATEWAY_SERVICE                     = UUID.from_16_bits(0x1112, 'Headset - Audio Gateway')
BT_WAP_SERVICE                                       = UUID.from_16_bits(0x1113, 'WAP')
BT_WAP_CLIENT_SERVICE                                = UUID.from_16_bits(0x1114, 'WAP_CLIENT')
BT_PANU_SERVICE                                      = UUID.from_16_bits(0x1115, 'PANU')
BT_NAP_SERVICE                                       = UUID.from_16_bits(0x1116, 'NAP')
BT_GN_SERVICE                                        = UUID.from_16_bits(0x1117, 'GN')
BT_DIRECT_PRINTING_SERVICE                           = UUID.from_16_bits(0x1118, 'DirectPrinting')
BT_REFERENCE_PRINTING_SERVICE                        = UUID.from_16_bits(0x1119, 'ReferencePrinting')
BT_BASIC_IMAGING_PROFILE_SERVICE                     = UUID.from_16_bits(0x111A, 'Basic Imaging Profile')
BT_IMAGING_RESPONDER_SERVICE                         = UUID.from_16_bits(0x111B, 'ImagingResponder')
BT_IMAGING_AUTOMATIC_ARCHIVE_SERVICE                 = UUID.from_16_bits(0x111C, 'ImagingAutomaticArchive')
BT_IMAGING_REFERENCED_OBJECTS_SERVICE                = UUID.from_16_bits(0x111D, 'ImagingReferencedObjects')
BT_HANDSFREE_SERVICE                                 = UUID.from_16_bits(0x111E, 'Handsfree')
BT_HANDSFREE_AUDIO_GATEWAY_SERVICE                   = UUID.from_16_bits(0x111F, 'HandsfreeAudioGateway')
BT_DIRECT_PRINTING_REFERENCE_OBJECTS_SERVICE         = UUID.from_16_bits(0x1120, 'DirectPrintingReferenceObjectsService')
BT_REFLECTED_UI_SERVICE                              = UUID.from_16_bits(0x1121, 'ReflectedUI')
BT_BASIC_PRINTING_SERVICE                            = UUID.from_16_bits(0x1122, 'BasicPrinting')
BT_PRINTING_STATUS_SERVICE                           = UUID.from_16_bits(0x1123, 'PrintingStatus')
BT_HUMAN_INTERFACE_DEVICE_SERVICE                    = UUID.from_16_bits(0x1124, 'HumanInterfaceDeviceService')
BT_HARDCOPY_CABLE_REPLACEMENT_SERVICE                = UUID.from_16_bits(0x1125, 'HardcopyCableReplacement')
BT_HCR_PRINT_SERVICE                                 = UUID.from_16_bits(0x1126, 'HCR_Print')
BT_HCR_SCAN_SERVICE                                  = UUID.from_16_bits(0x1127, 'HCR_Scan')
BT_COMMON_ISDN_ACCESS_SERVICE                        = UUID.from_16_bits(0x1128, 'Common_ISDN_Access')
BT_SIM_ACCESS_SERVICE                                = UUID.from_16_bits(0x112D, 'SIM_Access')
BT_PHONEBOOK_ACCESS_PCE_SERVICE                      = UUID.from_16_bits(0x112E, 'Phonebook Access - PCE')
BT_PHONEBOOK_ACCESS_PSE_SERVICE                      = UUID.from_16_bits(0x112F, 'Phonebook Access - PSE')
BT_PHONEBOOK_ACCESS_SERVICE                          = UUID.from_16_bits(0x1130, 'Phonebook Access')
BT_HEADSET_HS_SERVICE                                = UUID.from_16_bits(0x1131, 'Headset - HS')
BT_MESSAGE_ACCESS_SERVER_SERVICE                     = UUID.from_16_bits(0x1132, 'Message Access Server')
BT_MESSAGE_NOTIFICATION_SERVER_SERVICE               = UUID.from_16_bits(0x1133, 'Message Notification Server')
BT_MESSAGE_ACCESS_PROFILE_SERVICE                    = UUID.from_16_bits(0x1134, 'Message Access Profile')
BT_GNSS_SERVICE                                      = UUID.from_16_bits(0x1135, 'GNSS')
BT_GNSS_SERVER_SERVICE                               = UUID.from_16_bits(0x1136, 'GNSS_Server')
BT_3D_DISPLAY_SERVICE                                = UUID.from_16_bits(0x1137, '3D Display')
BT_3D_GLASSES_SERVICE                                = UUID.from_16_bits(0x1138, '3D Glasses')
BT_3D_SYNCHRONIZATION_SERVICE                        = UUID.from_16_bits(0x1139, '3D Synchronization')
BT_MPS_PROFILE_SERVICE                               = UUID.from_16_bits(0x113A, 'MPS Profile')
BT_MPS_SC_SERVICE                                    = UUID.from_16_bits(0x113B, 'MPS SC')
BT_ACCESS_SERVICE_SERVICE                            = UUID.from_16_bits(0x113C, 'CTN Access Service')
BT_CTN_NOTIFICATION_SERVICE_SERVICE                  = UUID.from_16_bits(0x113D, 'CTN Notification Service')
BT_CTN_PROFILE_SERVICE                               = UUID.from_16_bits(0x113E, 'CTN Profile')
BT_PNP_INFORMATION_SERVICE                           = UUID.from_16_bits(0x1200, 'PnPInformation')
BT_GENERIC_NETWORKING_SERVICE                        = UUID.from_16_bits(0x1201, 'GenericNetworking')
BT_GENERIC_FILE_TRANSFER_SERVICE                     = UUID.from_16_bits(0x1202, 'GenericFileTransfer')
BT_GENERIC_AUDIO_SERVICE                             = UUID.from_16_bits(0x1203, 'GenericAudio')
BT_GENERIC_TELEPHONY_SERVICE                         = UUID.from_16_bits(0x1204, 'GenericTelephony')
BT_UPNP_SERVICE                                      = UUID.from_16_bits(0x1205, 'UPNP_Service')
BT_UPNP_IP_SERVICE                                   = UUID.from_16_bits(0x1206, 'UPNP_IP_Service')
BT_ESDP_UPNP_IP_PAN_SERVICE                          = UUID.from_16_bits(0x1300, 'ESDP_UPNP_IP_PAN')
BT_ESDP_UPNP_IP_LAP_SERVICE                          = UUID.from_16_bits(0x1301, 'ESDP_UPNP_IP_LAP')
BT_ESDP_UPNP_L2CAP_SERVICE                           = UUID.from_16_bits(0x1302, 'ESDP_UPNP_L2CAP')
BT_VIDEO_SOURCE_SERVICE                              = UUID.from_16_bits(0x1303, 'VideoSource')
BT_VIDEO_SINK_SERVICE                                = UUID.from_16_bits(0x1304, 'VideoSink')
BT_VIDEO_DISTRIBUTION_SERVICE                        = UUID.from_16_bits(0x1305, 'VideoDistribution')
BT_HDP_SERVICE                                       = UUID.from_16_bits(0x1400, 'HDP')
BT_HDP_SOURCE_SERVICE                                = UUID.from_16_bits(0x1401, 'HDP Source')
BT_HDP_SINK_SERVICE                                  = UUID.from_16_bits(0x1402, 'HDP Sink')

# fmt: on
# pylint: enable=line-too-long


# -----------------------------------------------------------------------------
# DeviceClass
# -----------------------------------------------------------------------------
class DeviceClass:
    # fmt: off
    # pylint: disable=line-too-long

    # Major Service Classes (flags combined with OR)
    LIMITED_DISCOVERABLE_MODE_SERVICE_CLASS = (1 << 0)
    LE_AUDIO_SERVICE_CLASS                  = (1 << 1)
    RESERVED                                = (1 << 2)
    POSITIONING_SERVICE_CLASS               = (1 << 3)
    NETWORKING_SERVICE_CLASS                = (1 << 4)
    RENDERING_SERVICE_CLASS                 = (1 << 5)
    CAPTURING_SERVICE_CLASS                 = (1 << 6)
    OBJECT_TRANSFER_SERVICE_CLASS           = (1 << 7)
    AUDIO_SERVICE_CLASS                     = (1 << 8)
    TELEPHONY_SERVICE_CLASS                 = (1 << 9)
    INFORMATION_SERVICE_CLASS               = (1 << 10)

    SERVICE_CLASS_LABELS = [
        'Limited Discoverable Mode',
        'LE audio',
        '(reserved)',
        'Positioning',
        'Networking',
        'Rendering',
        'Capturing',
        'Object Transfer',
        'Audio',
        'Telephony',
        'Information'
    ]

    # Major Device Classes
    MISCELLANEOUS_MAJOR_DEVICE_CLASS            = 0x00
    COMPUTER_MAJOR_DEVICE_CLASS                 = 0x01
    PHONE_MAJOR_DEVICE_CLASS                    = 0x02
    LAN_NETWORK_ACCESS_POINT_MAJOR_DEVICE_CLASS = 0x03
    AUDIO_VIDEO_MAJOR_DEVICE_CLASS              = 0x04
    PERIPHERAL_MAJOR_DEVICE_CLASS               = 0x05
    IMAGING_MAJOR_DEVICE_CLASS                  = 0x06
    WEARABLE_MAJOR_DEVICE_CLASS                 = 0x07
    TOY_MAJOR_DEVICE_CLASS                      = 0x08
    HEALTH_MAJOR_DEVICE_CLASS                   = 0x09
    UNCATEGORIZED_MAJOR_DEVICE_CLASS            = 0x1F

    MAJOR_DEVICE_CLASS_NAMES = {
        MISCELLANEOUS_MAJOR_DEVICE_CLASS:            'Miscellaneous',
        COMPUTER_MAJOR_DEVICE_CLASS:                 'Computer',
        PHONE_MAJOR_DEVICE_CLASS:                    'Phone',
        LAN_NETWORK_ACCESS_POINT_MAJOR_DEVICE_CLASS: 'LAN/Network Access Point',
        AUDIO_VIDEO_MAJOR_DEVICE_CLASS:              'Audio/Video',
        PERIPHERAL_MAJOR_DEVICE_CLASS:               'Peripheral',
        IMAGING_MAJOR_DEVICE_CLASS:                  'Imaging',
        WEARABLE_MAJOR_DEVICE_CLASS:                 'Wearable',
        TOY_MAJOR_DEVICE_CLASS:                      'Toy',
        HEALTH_MAJOR_DEVICE_CLASS:                   'Health',
        UNCATEGORIZED_MAJOR_DEVICE_CLASS:            'Uncategorized'
    }

    COMPUTER_UNCATEGORIZED_MINOR_DEVICE_CLASS         = 0x00
    COMPUTER_DESKTOP_WORKSTATION_MINOR_DEVICE_CLASS   = 0x01
    COMPUTER_SERVER_CLASS_COMPUTER_MINOR_DEVICE_CLASS = 0x02
    COMPUTER_LAPTOP_COMPUTER_MINOR_DEVICE_CLASS       = 0x03
    COMPUTER_HANDHELD_PC_PDA_MINOR_DEVICE_CLASS       = 0x04
    COMPUTER_PALM_SIZE_PC_PDA_MINOR_DEVICE_CLASS      = 0x05
    COMPUTER_WEARABLE_COMPUTER_MINOR_DEVICE_CLASS     = 0x06
    COMPUTER_TABLET_MINOR_DEVICE_CLASS                = 0x07

    COMPUTER_MINOR_DEVICE_CLASS_NAMES = {
        COMPUTER_UNCATEGORIZED_MINOR_DEVICE_CLASS:         'Uncategorized',
        COMPUTER_DESKTOP_WORKSTATION_MINOR_DEVICE_CLASS:   'Desktop workstation',
        COMPUTER_SERVER_CLASS_COMPUTER_MINOR_DEVICE_CLASS: 'Server-class computer',
        COMPUTER_LAPTOP_COMPUTER_MINOR_DEVICE_CLASS:       'Laptop',
        COMPUTER_HANDHELD_PC_PDA_MINOR_DEVICE_CLASS:       'Handheld PC/PDA',
        COMPUTER_PALM_SIZE_PC_PDA_MINOR_DEVICE_CLASS:      'Palm-size PC/PDA',
        COMPUTER_WEARABLE_COMPUTER_MINOR_DEVICE_CLASS:     'Wearable computer',
        COMPUTER_TABLET_MINOR_DEVICE_CLASS:                'Tablet'
    }

    PHONE_UNCATEGORIZED_MINOR_DEVICE_CLASS                = 0x00
    PHONE_CELLULAR_MINOR_DEVICE_CLASS                     = 0x01
    PHONE_CORDLESS_MINOR_DEVICE_CLASS                     = 0x02
    PHONE_SMARTPHONE_MINOR_DEVICE_CLASS                   = 0x03
    PHONE_WIRED_MODEM_OR_VOICE_GATEWAY_MINOR_DEVICE_CLASS = 0x04
    PHONE_COMMON_ISDN_MINOR_DEVICE_CLASS                  = 0x05

    PHONE_MINOR_DEVICE_CLASS_NAMES = {
        PHONE_UNCATEGORIZED_MINOR_DEVICE_CLASS:                'Uncategorized',
        PHONE_CELLULAR_MINOR_DEVICE_CLASS:                     'Cellular',
        PHONE_CORDLESS_MINOR_DEVICE_CLASS:                     'Cordless',
        PHONE_SMARTPHONE_MINOR_DEVICE_CLASS:                   'Smartphone',
        PHONE_WIRED_MODEM_OR_VOICE_GATEWAY_MINOR_DEVICE_CLASS: 'Wired modem or voice gateway',
        PHONE_COMMON_ISDN_MINOR_DEVICE_CLASS:                  'Common ISDN access'
    }

    AUDIO_VIDEO_UNCATEGORIZED_MINOR_DEVICE_CLASS                 = 0x00
    AUDIO_VIDEO_WEARABLE_HEADSET_DEVICE_MINOR_DEVICE_CLASS       = 0x01
    AUDIO_VIDEO_HANDS_FREE_DEVICE_MINOR_DEVICE_CLASS             = 0x02
    # (RESERVED)                                                 = 0x03
    AUDIO_VIDEO_MICROPHONE_MINOR_DEVICE_CLASS                    = 0x04
    AUDIO_VIDEO_LOUDSPEAKER_MINOR_DEVICE_CLASS                   = 0x05
    AUDIO_VIDEO_HEADPHONES_MINOR_DEVICE_CLASS                    = 0x06
    AUDIO_VIDEO_PORTABLE_AUDIO_MINOR_DEVICE_CLASS                = 0x07
    AUDIO_VIDEO_CAR_AUDIO_MINOR_DEVICE_CLASS                     = 0x08
    AUDIO_VIDEO_SET_TOP_BOX_MINOR_DEVICE_CLASS                   = 0x09
    AUDIO_VIDEO_HIFI_AUDIO_DEVICE_MINOR_DEVICE_CLASS             = 0x0A
    AUDIO_VIDEO_VCR_MINOR_DEVICE_CLASS                           = 0x0B
    AUDIO_VIDEO_VIDEO_CAMERA_MINOR_DEVICE_CLASS                  = 0x0C
    AUDIO_VIDEO_CAMCORDER_MINOR_DEVICE_CLASS                     = 0x0D
    AUDIO_VIDEO_VIDEO_MONITOR_MINOR_DEVICE_CLASS                 = 0x0E
    AUDIO_VIDEO_VIDEO_DISPLAY_AND_LOUDSPEAKER_MINOR_DEVICE_CLASS = 0x0F
    AUDIO_VIDEO_VIDEO_CONFERENCING_MINOR_DEVICE_CLASS            = 0x10
    # (RESERVED)                                                 = 0x11
    AUDIO_VIDEO_GAMING_OR_TOY_MINOR_DEVICE_CLASS                 = 0x12

    AUDIO_VIDEO_MINOR_DEVICE_CLASS_NAMES = {
        AUDIO_VIDEO_UNCATEGORIZED_MINOR_DEVICE_CLASS:                 'Uncategorized',
        AUDIO_VIDEO_WEARABLE_HEADSET_DEVICE_MINOR_DEVICE_CLASS:       'Wearable Headset Device',
        AUDIO_VIDEO_HANDS_FREE_DEVICE_MINOR_DEVICE_CLASS:             'Hands-free Device',
        AUDIO_VIDEO_MICROPHONE_MINOR_DEVICE_CLASS:                    'Microphone',
        AUDIO_VIDEO_LOUDSPEAKER_MINOR_DEVICE_CLASS:                   'Loudspeaker',
        AUDIO_VIDEO_HEADPHONES_MINOR_DEVICE_CLASS:                    'Headphones',
        AUDIO_VIDEO_PORTABLE_AUDIO_MINOR_DEVICE_CLASS:                'Portable Audio',
        AUDIO_VIDEO_CAR_AUDIO_MINOR_DEVICE_CLASS:                     'Car audio',
        AUDIO_VIDEO_SET_TOP_BOX_MINOR_DEVICE_CLASS:                   'Set-top box',
        AUDIO_VIDEO_HIFI_AUDIO_DEVICE_MINOR_DEVICE_CLASS:             'HiFi Audio Device',
        AUDIO_VIDEO_VCR_MINOR_DEVICE_CLASS:                           'VCR',
        AUDIO_VIDEO_VIDEO_CAMERA_MINOR_DEVICE_CLASS:                  'Video Camera',
        AUDIO_VIDEO_CAMCORDER_MINOR_DEVICE_CLASS:                     'Camcorder',
        AUDIO_VIDEO_VIDEO_MONITOR_MINOR_DEVICE_CLASS:                 'Video Monitor',
        AUDIO_VIDEO_VIDEO_DISPLAY_AND_LOUDSPEAKER_MINOR_DEVICE_CLASS: 'Video Display and Loudspeaker',
        AUDIO_VIDEO_VIDEO_CONFERENCING_MINOR_DEVICE_CLASS:            'Video Conferencing',
        AUDIO_VIDEO_GAMING_OR_TOY_MINOR_DEVICE_CLASS:                 'Gaming/Toy'
    }

    PERIPHERAL_UNCATEGORIZED_MINOR_DEVICE_CLASS                  = 0x00
    PERIPHERAL_KEYBOARD_MINOR_DEVICE_CLASS                       = 0x10
    PERIPHERAL_POINTING_DEVICE_MINOR_DEVICE_CLASS                = 0x20
    PERIPHERAL_COMBO_KEYBOARD_POINTING_DEVICE_MINOR_DEVICE_CLASS = 0x30
    PERIPHERAL_JOYSTICK_MINOR_DEVICE_CLASS                       = 0x01
    PERIPHERAL_GAMEPAD_MINOR_DEVICE_CLASS                        = 0x02
    PERIPHERAL_REMOTE_CONTROL_MINOR_DEVICE_CLASS                 = 0x03
    PERIPHERAL_SENSING_DEVICE_MINOR_DEVICE_CLASS                 = 0x04
    PERIPHERAL_DIGITIZER_TABLET_MINOR_DEVICE_CLASS               = 0x05
    PERIPHERAL_CARD_READER_MINOR_DEVICE_CLASS                    = 0x06
    PERIPHERAL_DIGITAL_PEN_MINOR_DEVICE_CLASS                    = 0x07
    PERIPHERAL_HANDHELD_SCANNER_MINOR_DEVICE_CLASS               = 0x08
    PERIPHERAL_HANDHELD_GESTURAL_INPUT_DEVICE_MINOR_DEVICE_CLASS = 0x09

    PERIPHERAL_MINOR_DEVICE_CLASS_NAMES = {
        PERIPHERAL_UNCATEGORIZED_MINOR_DEVICE_CLASS:                  'Uncategorized',
        PERIPHERAL_KEYBOARD_MINOR_DEVICE_CLASS:                       'Keyboard',
        PERIPHERAL_POINTING_DEVICE_MINOR_DEVICE_CLASS:                'Pointing device',
        PERIPHERAL_COMBO_KEYBOARD_POINTING_DEVICE_MINOR_DEVICE_CLASS: 'Combo keyboard/pointing device',
        PERIPHERAL_JOYSTICK_MINOR_DEVICE_CLASS:                       'Joystick',
        PERIPHERAL_GAMEPAD_MINOR_DEVICE_CLASS:                        'Gamepad',
        PERIPHERAL_REMOTE_CONTROL_MINOR_DEVICE_CLASS:                 'Remote control',
        PERIPHERAL_SENSING_DEVICE_MINOR_DEVICE_CLASS:                 'Sensing device',
        PERIPHERAL_DIGITIZER_TABLET_MINOR_DEVICE_CLASS:               'Digitizer tablet',
        PERIPHERAL_CARD_READER_MINOR_DEVICE_CLASS:                    'Card Reader',
        PERIPHERAL_DIGITAL_PEN_MINOR_DEVICE_CLASS:                    'Digital Pen',
        PERIPHERAL_HANDHELD_SCANNER_MINOR_DEVICE_CLASS:               'Handheld scanner',
        PERIPHERAL_HANDHELD_GESTURAL_INPUT_DEVICE_MINOR_DEVICE_CLASS: 'Handheld gestural input device'
    }

    WEARABLE_UNCATEGORIZED_MINOR_DEVICE_CLASS = 0x00
    WEARABLE_WRISTWATCH_MINOR_DEVICE_CLASS    = 0x01
    WEARABLE_PAGER_MINOR_DEVICE_CLASS         = 0x02
    WEARABLE_JACKET_MINOR_DEVICE_CLASS        = 0x03
    WEARABLE_HELMET_MINOR_DEVICE_CLASS        = 0x04
    WEARABLE_GLASSES_MINOR_DEVICE_CLASS       = 0x05

    WEARABLE_MINOR_DEVICE_CLASS_NAMES = {
        WEARABLE_UNCATEGORIZED_MINOR_DEVICE_CLASS: 'Uncategorized',
        WEARABLE_WRISTWATCH_MINOR_DEVICE_CLASS:    'Wristwatch',
        WEARABLE_PAGER_MINOR_DEVICE_CLASS:         'Pager',
        WEARABLE_JACKET_MINOR_DEVICE_CLASS:        'Jacket',
        WEARABLE_HELMET_MINOR_DEVICE_CLASS:        'Helmet',
        WEARABLE_GLASSES_MINOR_DEVICE_CLASS:       'Glasses',
    }

    TOY_UNCATEGORIZED_MINOR_DEVICE_CLASS      = 0x00
    TOY_ROBOT_MINOR_DEVICE_CLASS              = 0x01
    TOY_VEHICLE_MINOR_DEVICE_CLASS            = 0x02
    TOY_DOLL_ACTION_FIGURE_MINOR_DEVICE_CLASS = 0x03
    TOY_CONTROLLER_MINOR_DEVICE_CLASS         = 0x04
    TOY_GAME_MINOR_DEVICE_CLASS               = 0x05

    TOY_MINOR_DEVICE_CLASS_NAMES = {
        TOY_UNCATEGORIZED_MINOR_DEVICE_CLASS:      'Uncategorized',
        TOY_ROBOT_MINOR_DEVICE_CLASS:              'Robot',
        TOY_VEHICLE_MINOR_DEVICE_CLASS:            'Vehicle',
        TOY_DOLL_ACTION_FIGURE_MINOR_DEVICE_CLASS: 'Doll/Action figure',
        TOY_CONTROLLER_MINOR_DEVICE_CLASS:         'Controller',
        TOY_GAME_MINOR_DEVICE_CLASS:               'Game',
    }

    HEALTH_UNDEFINED_MINOR_DEVICE_CLASS                 = 0x00
    HEALTH_BLOOD_PRESSURE_MONITOR_MINOR_DEVICE_CLASS    = 0x01
    HEALTH_THERMOMETER_MINOR_DEVICE_CLASS               = 0x02
    HEALTH_WEIGHING_SCALE_MINOR_DEVICE_CLASS            = 0x03
    HEALTH_GLUCOSE_METER_MINOR_DEVICE_CLASS             = 0x04
    HEALTH_PULSE_OXIMETER_MINOR_DEVICE_CLASS            = 0x05
    HEALTH_HEART_PULSE_RATE_MONITOR_MINOR_DEVICE_CLASS  = 0x06
    HEALTH_HEALTH_DATA_DISPLAY_MINOR_DEVICE_CLASS       = 0x07
    HEALTH_STEP_COUNTER_MINOR_DEVICE_CLASS              = 0x08
    HEALTH_BODY_COMPOSITION_ANALYZER_MINOR_DEVICE_CLASS = 0x09
    HEALTH_PEAK_FLOW_MONITOR_MINOR_DEVICE_CLASS         = 0x0A
    HEALTH_MEDICATION_MONITOR_MINOR_DEVICE_CLASS        = 0x0B
    HEALTH_KNEE_PROSTHESIS_MINOR_DEVICE_CLASS           = 0x0C
    HEALTH_ANKLE_PROSTHESIS_MINOR_DEVICE_CLASS          = 0x0D
    HEALTH_GENERIC_HEALTH_MANAGER_MINOR_DEVICE_CLASS    = 0x0E
    HEALTH_PERSONAL_MOBILITY_DEVICE_MINOR_DEVICE_CLASS  = 0x0F

    HEALTH_MINOR_DEVICE_CLASS_NAMES = {
        HEALTH_UNDEFINED_MINOR_DEVICE_CLASS:                 'Undefined',
        HEALTH_BLOOD_PRESSURE_MONITOR_MINOR_DEVICE_CLASS:    'Blood Pressure Monitor',
        HEALTH_THERMOMETER_MINOR_DEVICE_CLASS:               'Thermometer',
        HEALTH_WEIGHING_SCALE_MINOR_DEVICE_CLASS:            'Weighing Scale',
        HEALTH_GLUCOSE_METER_MINOR_DEVICE_CLASS:             'Glucose Meter',
        HEALTH_PULSE_OXIMETER_MINOR_DEVICE_CLASS:            'Pulse Oximeter',
        HEALTH_HEART_PULSE_RATE_MONITOR_MINOR_DEVICE_CLASS:  'Heart/Pulse Rate Monitor',
        HEALTH_HEALTH_DATA_DISPLAY_MINOR_DEVICE_CLASS:       'Health Data Display',
        HEALTH_STEP_COUNTER_MINOR_DEVICE_CLASS:              'Step Counter',
        HEALTH_BODY_COMPOSITION_ANALYZER_MINOR_DEVICE_CLASS: 'Body Composition Analyzer',
        HEALTH_PEAK_FLOW_MONITOR_MINOR_DEVICE_CLASS:         'Peak Flow Monitor',
        HEALTH_MEDICATION_MONITOR_MINOR_DEVICE_CLASS:        'Medication Monitor',
        HEALTH_KNEE_PROSTHESIS_MINOR_DEVICE_CLASS:           'Knee Prosthesis',
        HEALTH_ANKLE_PROSTHESIS_MINOR_DEVICE_CLASS:          'Ankle Prosthesis',
        HEALTH_GENERIC_HEALTH_MANAGER_MINOR_DEVICE_CLASS:    'Generic Health Manager',
        HEALTH_PERSONAL_MOBILITY_DEVICE_MINOR_DEVICE_CLASS:  'Personal Mobility Device',
    }

    MINOR_DEVICE_CLASS_NAMES = {
        COMPUTER_MAJOR_DEVICE_CLASS:    COMPUTER_MINOR_DEVICE_CLASS_NAMES,
        PHONE_MAJOR_DEVICE_CLASS:       PHONE_MINOR_DEVICE_CLASS_NAMES,
        AUDIO_VIDEO_MAJOR_DEVICE_CLASS: AUDIO_VIDEO_MINOR_DEVICE_CLASS_NAMES,
        PERIPHERAL_MAJOR_DEVICE_CLASS:  PERIPHERAL_MINOR_DEVICE_CLASS_NAMES,
        WEARABLE_MAJOR_DEVICE_CLASS:    WEARABLE_MINOR_DEVICE_CLASS_NAMES,
        TOY_MAJOR_DEVICE_CLASS:         TOY_MINOR_DEVICE_CLASS_NAMES,
        HEALTH_MAJOR_DEVICE_CLASS:      HEALTH_MINOR_DEVICE_CLASS_NAMES,
    }

    # fmt: on
    # pylint: enable=line-too-long

    @staticmethod
    def split_class_of_device(class_of_device):
        # Split the bit fields of the composite class of device value into:
        # (service_classes, major_device_class, minor_device_class)
        return (
            (class_of_device >> 13 & 0x7FF),
            (class_of_device >> 8 & 0x1F),
            (class_of_device >> 2 & 0x3F),
        )

    @staticmethod
    def pack_class_of_device(service_classes, major_device_class, minor_device_class):
        return service_classes << 13 | major_device_class << 8 | minor_device_class << 2

    @staticmethod
    def service_class_labels(service_class_flags):
        return bit_flags_to_strings(
            service_class_flags, DeviceClass.SERVICE_CLASS_LABELS
        )

    @staticmethod
    def major_device_class_name(device_class):
        return name_or_number(DeviceClass.MAJOR_DEVICE_CLASS_NAMES, device_class)

    @staticmethod
    def minor_device_class_name(major_device_class, minor_device_class):
        class_names = DeviceClass.MINOR_DEVICE_CLASS_NAMES.get(major_device_class)
        if class_names is None:
            return f'#{minor_device_class:02X}'
        return name_or_number(class_names, minor_device_class)


# -----------------------------------------------------------------------------
# Advertising Data
# -----------------------------------------------------------------------------
AdvertisingObject = Union[
    List[UUID], Tuple[UUID, bytes], bytes, str, int, Tuple[int, int], Tuple[int, bytes]
]


class AdvertisingData:
    # fmt: off
    # pylint: disable=line-too-long

    # This list is only partial, it still needs to be filled in from the spec
    FLAGS                                          = 0x01
    INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS  = 0x02
    COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS    = 0x03
    INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS  = 0x04
    COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS    = 0x05
    INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS = 0x06
    COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS   = 0x07
    SHORTENED_LOCAL_NAME                           = 0x08
    COMPLETE_LOCAL_NAME                            = 0x09
    TX_POWER_LEVEL                                 = 0x0A
    CLASS_OF_DEVICE                                = 0x0D
    SIMPLE_PAIRING_HASH_C                          = 0x0E
    SIMPLE_PAIRING_HASH_C_192                      = 0x0E
    SIMPLE_PAIRING_RANDOMIZER_R                    = 0x0F
    SIMPLE_PAIRING_RANDOMIZER_R_192                = 0x0F
    DEVICE_ID                                      = 0x10
    SECURITY_MANAGER_TK_VALUE                      = 0x10
    SECURITY_MANAGER_OUT_OF_BAND_FLAGS             = 0x11
    PERIPHERAL_CONNECTION_INTERVAL_RANGE           = 0x12
    LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS      = 0x14
    LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS     = 0x15
    SERVICE_DATA                                   = 0x16
    SERVICE_DATA_16_BIT_UUID                       = 0x16
    PUBLIC_TARGET_ADDRESS                          = 0x17
    RANDOM_TARGET_ADDRESS                          = 0x18
    APPEARANCE                                     = 0x19
    ADVERTISING_INTERVAL                           = 0x1A
    LE_BLUETOOTH_DEVICE_ADDRESS                    = 0x1B
    LE_ROLE                                        = 0x1C
    SIMPLE_PAIRING_HASH_C_256                      = 0x1D
    SIMPLE_PAIRING_RANDOMIZER_R_256                = 0x1E
    LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS      = 0x1F
    SERVICE_DATA_32_BIT_UUID                       = 0x20
    SERVICE_DATA_128_BIT_UUID                      = 0x21
    LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE       = 0x22
    LE_SECURE_CONNECTIONS_RANDOM_VALUE             = 0x23
    URI                                            = 0x24
    INDOOR_POSITIONING                             = 0x25
    TRANSPORT_DISCOVERY_DATA                       = 0x26
    LE_SUPPORTED_FEATURES                          = 0x27
    CHANNEL_MAP_UPDATE_INDICATION                  = 0x28
    PB_ADV                                         = 0x29
    MESH_MESSAGE                                   = 0x2A
    MESH_BEACON                                    = 0x2B
    BIGINFO                                        = 0x2C
    BROADCAST_CODE                                 = 0x2D
    RESOLVABLE_SET_IDENTIFIER                      = 0x2E
    ADVERTISING_INTERVAL_LONG                      = 0x2F
    THREE_D_INFORMATION_DATA                       = 0x3D
    MANUFACTURER_SPECIFIC_DATA                     = 0xFF

    AD_TYPE_NAMES = {
        FLAGS:                                          'FLAGS',
        INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:  'INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS',
        COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:    'COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS',
        INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:  'INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS',
        COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:    'COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS',
        INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS: 'INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS',
        COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:   'COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS',
        SHORTENED_LOCAL_NAME:                           'SHORTENED_LOCAL_NAME',
        COMPLETE_LOCAL_NAME:                            'COMPLETE_LOCAL_NAME',
        TX_POWER_LEVEL:                                 'TX_POWER_LEVEL',
        CLASS_OF_DEVICE:                                'CLASS_OF_DEVICE',
        SIMPLE_PAIRING_HASH_C:                          'SIMPLE_PAIRING_HASH_C',
        SIMPLE_PAIRING_HASH_C_192:                      'SIMPLE_PAIRING_HASH_C_192',
        SIMPLE_PAIRING_RANDOMIZER_R:                    'SIMPLE_PAIRING_RANDOMIZER_R',
        SIMPLE_PAIRING_RANDOMIZER_R_192:                'SIMPLE_PAIRING_RANDOMIZER_R_192',
        DEVICE_ID:                                      'DEVICE_ID',
        SECURITY_MANAGER_TK_VALUE:                      'SECURITY_MANAGER_TK_VALUE',
        SECURITY_MANAGER_OUT_OF_BAND_FLAGS:             'SECURITY_MANAGER_OUT_OF_BAND_FLAGS',
        PERIPHERAL_CONNECTION_INTERVAL_RANGE:           'PERIPHERAL_CONNECTION_INTERVAL_RANGE',
        LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS:      'LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS',
        LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS:     'LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS',
        SERVICE_DATA:                                   'SERVICE_DATA',
        SERVICE_DATA_16_BIT_UUID:                       'SERVICE_DATA_16_BIT_UUID',
        PUBLIC_TARGET_ADDRESS:                          'PUBLIC_TARGET_ADDRESS',
        RANDOM_TARGET_ADDRESS:                          'RANDOM_TARGET_ADDRESS',
        APPEARANCE:                                     'APPEARANCE',
        ADVERTISING_INTERVAL:                           'ADVERTISING_INTERVAL',
        LE_BLUETOOTH_DEVICE_ADDRESS:                    'LE_BLUETOOTH_DEVICE_ADDRESS',
        LE_ROLE:                                        'LE_ROLE',
        SIMPLE_PAIRING_HASH_C_256:                      'SIMPLE_PAIRING_HASH_C_256',
        SIMPLE_PAIRING_RANDOMIZER_R_256:                'SIMPLE_PAIRING_RANDOMIZER_R_256',
        LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS:      'LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS',
        SERVICE_DATA_32_BIT_UUID:                       'SERVICE_DATA_32_BIT_UUID',
        SERVICE_DATA_128_BIT_UUID:                      'SERVICE_DATA_128_BIT_UUID',
        LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE:       'LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE',
        LE_SECURE_CONNECTIONS_RANDOM_VALUE:             'LE_SECURE_CONNECTIONS_RANDOM_VALUE',
        URI:                                            'URI',
        INDOOR_POSITIONING:                             'INDOOR_POSITIONING',
        TRANSPORT_DISCOVERY_DATA:                       'TRANSPORT_DISCOVERY_DATA',
        LE_SUPPORTED_FEATURES:                          'LE_SUPPORTED_FEATURES',
        CHANNEL_MAP_UPDATE_INDICATION:                  'CHANNEL_MAP_UPDATE_INDICATION',
        PB_ADV:                                         'PB_ADV',
        MESH_MESSAGE:                                   'MESH_MESSAGE',
        MESH_BEACON:                                    'MESH_BEACON',
        BIGINFO:                                        'BIGINFO',
        BROADCAST_CODE:                                 'BROADCAST_CODE',
        RESOLVABLE_SET_IDENTIFIER:                      'RESOLVABLE_SET_IDENTIFIER',
        ADVERTISING_INTERVAL_LONG:                      'ADVERTISING_INTERVAL_LONG',
        THREE_D_INFORMATION_DATA:                       'THREE_D_INFORMATION_DATA',
        MANUFACTURER_SPECIFIC_DATA:                     'MANUFACTURER_SPECIFIC_DATA'
    }

    LE_LIMITED_DISCOVERABLE_MODE_FLAG = 0x01
    LE_GENERAL_DISCOVERABLE_MODE_FLAG = 0x02
    BR_EDR_NOT_SUPPORTED_FLAG         = 0x04
    BR_EDR_CONTROLLER_FLAG            = 0x08
    BR_EDR_HOST_FLAG                  = 0x10

    ad_structures: List[Tuple[int, bytes]]

    # fmt: on
    # pylint: enable=line-too-long

    def __init__(self, ad_structures: Optional[List[Tuple[int, bytes]]] = None) -> None:
        if ad_structures is None:
            ad_structures = []
        self.ad_structures = ad_structures[:]

    @staticmethod
    def from_bytes(data):
        instance = AdvertisingData()
        instance.append(data)
        return instance

    @staticmethod
    def flags_to_string(flags, short=False):
        flag_names = (
            ['LE Limited', 'LE General', 'No BR/EDR', 'BR/EDR C', 'BR/EDR H']
            if short
            else [
                'LE Limited Discoverable Mode',
                'LE General Discoverable Mode',
                'BR/EDR Not Supported',
                'Simultaneous LE and BR/EDR (Controller)',
                'Simultaneous LE and BR/EDR (Host)',
            ]
        )
        return ','.join(bit_flags_to_strings(flags, flag_names))

    @staticmethod
    def uuid_list_to_objects(ad_data: bytes, uuid_size: int) -> List[UUID]:
        uuids = []
        offset = 0
        while (offset + uuid_size) <= len(ad_data):
            uuids.append(UUID.from_bytes(ad_data[offset : offset + uuid_size]))
            offset += uuid_size
        return uuids

    @staticmethod
    def uuid_list_to_string(ad_data, uuid_size):
        return ', '.join(
            [
                str(uuid)
                for uuid in AdvertisingData.uuid_list_to_objects(ad_data, uuid_size)
            ]
        )

    @staticmethod
    def ad_data_to_string(ad_type, ad_data):
        if ad_type == AdvertisingData.FLAGS:
            ad_type_str = 'Flags'
            ad_data_str = AdvertisingData.flags_to_string(ad_data[0], short=True)
        elif ad_type == AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:
            ad_type_str = 'Complete List of 16-bit Service Class UUIDs'
            ad_data_str = AdvertisingData.uuid_list_to_string(ad_data, 2)
        elif ad_type == AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:
            ad_type_str = 'Incomplete List of 16-bit Service Class UUIDs'
            ad_data_str = AdvertisingData.uuid_list_to_string(ad_data, 2)
        elif ad_type == AdvertisingData.COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:
            ad_type_str = 'Complete List of 32-bit Service Class UUIDs'
            ad_data_str = AdvertisingData.uuid_list_to_string(ad_data, 4)
        elif ad_type == AdvertisingData.INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:
            ad_type_str = 'Incomplete List of 32-bit Service Class UUIDs'
            ad_data_str = AdvertisingData.uuid_list_to_string(ad_data, 4)
        elif ad_type == AdvertisingData.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:
            ad_type_str = 'Complete List of 128-bit Service Class UUIDs'
            ad_data_str = AdvertisingData.uuid_list_to_string(ad_data, 16)
        elif ad_type == AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:
            ad_type_str = 'Incomplete List of 128-bit Service Class UUIDs'
            ad_data_str = AdvertisingData.uuid_list_to_string(ad_data, 16)
        elif ad_type == AdvertisingData.SERVICE_DATA_16_BIT_UUID:
            ad_type_str = 'Service Data'
            uuid = UUID.from_bytes(ad_data[:2])
            ad_data_str = f'service={uuid}, data={ad_data[2:].hex()}'
        elif ad_type == AdvertisingData.SERVICE_DATA_32_BIT_UUID:
            ad_type_str = 'Service Data'
            uuid = UUID.from_bytes(ad_data[:4])
            ad_data_str = f'service={uuid}, data={ad_data[4:].hex()}'
        elif ad_type == AdvertisingData.SERVICE_DATA_128_BIT_UUID:
            ad_type_str = 'Service Data'
            uuid = UUID.from_bytes(ad_data[:16])
            ad_data_str = f'service={uuid}, data={ad_data[16:].hex()}'
        elif ad_type == AdvertisingData.SHORTENED_LOCAL_NAME:
            ad_type_str = 'Shortened Local Name'
            ad_data_str = f'"{ad_data.decode("utf-8")}"'
        elif ad_type == AdvertisingData.COMPLETE_LOCAL_NAME:
            ad_type_str = 'Complete Local Name'
            ad_data_str = f'"{ad_data.decode("utf-8")}"'
        elif ad_type == AdvertisingData.TX_POWER_LEVEL:
            ad_type_str = 'TX Power Level'
            ad_data_str = str(ad_data[0])
        elif ad_type == AdvertisingData.MANUFACTURER_SPECIFIC_DATA:
            ad_type_str = 'Manufacturer Specific Data'
            company_id = struct.unpack_from('<H', ad_data, 0)[0]
            company_name = COMPANY_IDENTIFIERS.get(company_id, f'0x{company_id:04X}')
            ad_data_str = f'company={company_name}, data={ad_data[2:].hex()}'
        elif ad_type == AdvertisingData.APPEARANCE:
            ad_type_str = 'Appearance'
            ad_data_str = ad_data.hex()
        else:
            ad_type_str = AdvertisingData.AD_TYPE_NAMES.get(ad_type, f'0x{ad_type:02X}')
            ad_data_str = ad_data.hex()

        return f'[{ad_type_str}]: {ad_data_str}'

    # pylint: disable=too-many-return-statements
    @staticmethod
    def ad_data_to_object(ad_type: int, ad_data: bytes) -> AdvertisingObject:
        if ad_type in (
            AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS,
        ):
            return AdvertisingData.uuid_list_to_objects(ad_data, 2)

        if ad_type in (
            AdvertisingData.COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS,
        ):
            return AdvertisingData.uuid_list_to_objects(ad_data, 4)

        if ad_type in (
            AdvertisingData.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS,
        ):
            return AdvertisingData.uuid_list_to_objects(ad_data, 16)

        if ad_type == AdvertisingData.SERVICE_DATA_16_BIT_UUID:
            return (UUID.from_bytes(ad_data[:2]), ad_data[2:])

        if ad_type == AdvertisingData.SERVICE_DATA_32_BIT_UUID:
            return (UUID.from_bytes(ad_data[:4]), ad_data[4:])

        if ad_type == AdvertisingData.SERVICE_DATA_128_BIT_UUID:
            return (UUID.from_bytes(ad_data[:16]), ad_data[16:])

        if ad_type in (
            AdvertisingData.SHORTENED_LOCAL_NAME,
            AdvertisingData.COMPLETE_LOCAL_NAME,
            AdvertisingData.URI,
        ):
            return ad_data.decode("utf-8")

        if ad_type in (AdvertisingData.TX_POWER_LEVEL, AdvertisingData.FLAGS):
            return cast(int, struct.unpack('B', ad_data)[0])

        if ad_type in (
            AdvertisingData.APPEARANCE,
            AdvertisingData.ADVERTISING_INTERVAL,
        ):
            return cast(int, struct.unpack('<H', ad_data)[0])

        if ad_type == AdvertisingData.CLASS_OF_DEVICE:
            return cast(int, struct.unpack('<I', bytes([*ad_data, 0]))[0])

        if ad_type == AdvertisingData.PERIPHERAL_CONNECTION_INTERVAL_RANGE:
            return cast(Tuple[int, int], struct.unpack('<HH', ad_data))

        if ad_type == AdvertisingData.MANUFACTURER_SPECIFIC_DATA:
            return (cast(int, struct.unpack_from('<H', ad_data, 0)[0]), ad_data[2:])

        return ad_data

    def append(self, data):
        offset = 0
        while offset + 1 < len(data):
            length = data[offset]
            offset += 1
            if length > 0:
                ad_type = data[offset]
                ad_data = data[offset + 1 : offset + length]
                self.ad_structures.append((ad_type, ad_data))
            offset += length

    def get_all(self, type_id: int, raw: bool = False) -> List[AdvertisingObject]:
        '''
        Get Advertising Data Structure(s) with a given type

        Returns a (possibly empty) list of matches.
        '''

        def process_ad_data(ad_data: bytes) -> AdvertisingObject:
            return ad_data if raw else self.ad_data_to_object(type_id, ad_data)

        return [process_ad_data(ad[1]) for ad in self.ad_structures if ad[0] == type_id]

    def get(self, type_id: int, raw: bool = False) -> Optional[AdvertisingObject]:
        '''
        Get Advertising Data Structure(s) with a given type

        Returns the first entry, or None if no structure matches.
        '''

        all = self.get_all(type_id, raw=raw)
        return all[0] if all else None

    def __bytes__(self):
        return b''.join(
            [bytes([len(x[1]) + 1, x[0]]) + x[1] for x in self.ad_structures]
        )

    def to_string(self, separator=', '):
        return separator.join(
            [AdvertisingData.ad_data_to_string(x[0], x[1]) for x in self.ad_structures]
        )

    def __str__(self):
        return self.to_string()


# -----------------------------------------------------------------------------
# Connection Parameters
# -----------------------------------------------------------------------------
class ConnectionParameters:
    def __init__(self, connection_interval, peripheral_latency, supervision_timeout):
        self.connection_interval = connection_interval
        self.peripheral_latency = peripheral_latency
        self.supervision_timeout = supervision_timeout

    def __str__(self):
        return (
            f'ConnectionParameters(connection_interval={self.connection_interval}, '
            f'peripheral_latency={self.peripheral_latency}, '
            f'supervision_timeout={self.supervision_timeout}'
        )


# -----------------------------------------------------------------------------
# Connection PHY
# -----------------------------------------------------------------------------
class ConnectionPHY:
    def __init__(self, tx_phy, rx_phy):
        self.tx_phy = tx_phy
        self.rx_phy = rx_phy

    def __str__(self):
        return f'ConnectionPHY(tx_phy={self.tx_phy}, rx_phy={self.rx_phy})'


# -----------------------------------------------------------------------------
# LE Role
# -----------------------------------------------------------------------------
class LeRole(enum.IntEnum):
    PERIPHERAL_ONLY = 0x00
    CENTRAL_ONLY = 0x01
    BOTH_PERIPHERAL_PREFERRED = 0x02
    BOTH_CENTRAL_PREFERRED = 0x03
