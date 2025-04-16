# Copyright 2021-2025 Google LLC
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
from typing import cast, overload, Literal, Union, Optional
from typing_extensions import Self

from bumble.company_ids import COMPANY_IDENTIFIERS
from bumble import utils


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off

class PhysicalTransport(enum.IntEnum):
    BR_EDR = 0
    LE     = 1

BT_BR_EDR_TRANSPORT = PhysicalTransport.BR_EDR
BT_LE_TRANSPORT     = PhysicalTransport.LE


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


def name_or_number(dictionary: dict[int, str], number: int, width: int = 2) -> str:
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


class BaseBumbleError(Exception):
    """Base Error raised by Bumble."""


class BaseError(BaseBumbleError):
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
        have_name = self.error_name != ''
        have_code = self.error_code is not None
        if have_name and have_code:
            error_text = f'{self.error_name} [0x{self.error_code:X}]'
        elif have_name and not have_code:
            error_text = self.error_name
        elif not have_name and have_code:
            error_text = f'0x{self.error_code:X}'
        else:
            error_text = '<unspecified>'

        return f'{type(self).__name__}({namespace}{error_text})'


class ProtocolError(BaseError):
    """Protocol Error"""


class TimeoutError(BaseBumbleError):  # pylint: disable=redefined-builtin
    """Timeout Error"""


class CommandTimeoutError(BaseBumbleError):
    """Command Timeout Error"""


class InvalidStateError(BaseBumbleError):
    """Invalid State Error"""


class InvalidArgumentError(BaseBumbleError, ValueError):
    """Invalid Argument Error"""


class InvalidPacketError(BaseBumbleError, ValueError):
    """Invalid Packet Error"""


class InvalidOperationError(BaseBumbleError, RuntimeError):
    """Invalid Operation Error"""


class NotSupportedError(BaseBumbleError, RuntimeError):
    """Not Supported"""


class OutOfResourcesError(BaseBumbleError, RuntimeError):
    """Out of Resources Error"""


class UnreachableError(BaseBumbleError):
    """The code path raising this error should be unreachable."""


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
    UUIDS: list[UUID] = []  # Registry of all instances created

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
                    raise InvalidArgumentError('invalid UUID format')
                uuid_str = uuid_str_or_int.replace('-', '')
            else:
                uuid_str = uuid_str_or_int
            if len(uuid_str) != 32 and len(uuid_str) != 8 and len(uuid_str) != 4:
                raise InvalidArgumentError(f"invalid UUID format: {uuid_str}")
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

        raise InvalidArgumentError('only 2, 4 and 16 bytes are allowed')

    @classmethod
    def from_16_bits(cls, uuid_16: int, name: Optional[str] = None) -> UUID:
        return cls.from_bytes(struct.pack('<H', uuid_16), name)

    @classmethod
    def from_32_bits(cls, uuid_32: int, name: Optional[str] = None) -> UUID:
        return cls.from_bytes(struct.pack('<I', uuid_32), name)

    @classmethod
    def parse_uuid(cls, uuid_as_bytes: bytes, offset: int) -> tuple[int, UUID]:
        return len(uuid_as_bytes), cls.from_bytes(uuid_as_bytes[offset:])

    @classmethod
    def parse_uuid_2(cls, uuid_as_bytes: bytes, offset: int) -> tuple[int, UUID]:
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
BT_AVCTP_PROTOCOL_ID                    = UUID.from_16_bits(0x0017, 'AVCTP')
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
# Appearance
# -----------------------------------------------------------------------------
class Appearance:
    class Category(utils.OpenIntEnum):
        UNKNOWN = 0x0000
        PHONE = 0x0001
        COMPUTER = 0x0002
        WATCH = 0x0003
        CLOCK = 0x0004
        DISPLAY = 0x0005
        REMOTE_CONTROL = 0x0006
        EYE_GLASSES = 0x0007
        TAG = 0x0008
        KEYRING = 0x0009
        MEDIA_PLAYER = 0x000A
        BARCODE_SCANNER = 0x000B
        THERMOMETER = 0x000C
        HEART_RATE_SENSOR = 0x000D
        BLOOD_PRESSURE = 0x000E
        HUMAN_INTERFACE_DEVICE = 0x000F
        GLUCOSE_METER = 0x0010
        RUNNING_WALKING_SENSOR = 0x0011
        CYCLING = 0x0012
        CONTROL_DEVICE = 0x0013
        NETWORK_DEVICE = 0x0014
        SENSOR = 0x0015
        LIGHT_FIXTURES = 0x0016
        FAN = 0x0017
        HVAC = 0x0018
        AIR_CONDITIONING = 0x0019
        HUMIDIFIER = 0x001A
        HEATING = 0x001B
        ACCESS_CONTROL = 0x001C
        MOTORIZED_DEVICE = 0x001D
        POWER_DEVICE = 0x001E
        LIGHT_SOURCE = 0x001F
        WINDOW_COVERING = 0x0020
        AUDIO_SINK = 0x0021
        AUDIO_SOURCE = 0x0022
        MOTORIZED_VEHICLE = 0x0023
        DOMESTIC_APPLIANCE = 0x0024
        WEARABLE_AUDIO_DEVICE = 0x0025
        AIRCRAFT = 0x0026
        AV_EQUIPMENT = 0x0027
        DISPLAY_EQUIPMENT = 0x0028
        HEARING_AID = 0x0029
        GAMING = 0x002A
        SIGNAGE = 0x002B
        PULSE_OXIMETER = 0x0031
        WEIGHT_SCALE = 0x0032
        PERSONAL_MOBILITY_DEVICE = 0x0033
        CONTINUOUS_GLUCOSE_MONITOR = 0x0034
        INSULIN_PUMP = 0x0035
        MEDICATION_DELIVERY = 0x0036
        SPIROMETER = 0x0037
        OUTDOOR_SPORTS_ACTIVITY = 0x0051

    class UnknownSubcategory(utils.OpenIntEnum):
        GENERIC_UNKNOWN = 0x00

    class PhoneSubcategory(utils.OpenIntEnum):
        GENERIC_PHONE = 0x00

    class ComputerSubcategory(utils.OpenIntEnum):
        GENERIC_COMPUTER = 0x00
        DESKTOP_WORKSTATION = 0x01
        SERVER_CLASS_COMPUTER = 0x02
        LAPTOP = 0x03
        HANDHELD_PC_PDA = 0x04
        PALM_SIZE_PC_PDA = 0x05
        WEARABLE_COMPUTER = 0x06
        TABLET = 0x07
        DOCKING_STATION = 0x08
        ALL_IN_ONE = 0x09
        BLADE_SERVER = 0x0A
        CONVERTIBLE = 0x0B
        DETACHABLE = 0x0C
        IOT_GATEWAY = 0x0D
        MINI_PC = 0x0E
        STICK_PC = 0x0F

    class WatchSubcategory(utils.OpenIntEnum):
        GENENERIC_WATCH = 0x00
        SPORTS_WATCH = 0x01
        SMARTWATCH = 0x02

    class ClockSubcategory(utils.OpenIntEnum):
        GENERIC_CLOCK = 0x00

    class DisplaySubcategory(utils.OpenIntEnum):
        GENERIC_DISPLAY = 0x00

    class RemoteControlSubcategory(utils.OpenIntEnum):
        GENERIC_REMOTE_CONTROL = 0x00

    class EyeglassesSubcategory(utils.OpenIntEnum):
        GENERIC_EYEGLASSES = 0x00

    class TagSubcategory(utils.OpenIntEnum):
        GENERIC_TAG = 0x00

    class KeyringSubcategory(utils.OpenIntEnum):
        GENERIC_KEYRING = 0x00

    class MediaPlayerSubcategory(utils.OpenIntEnum):
        GENERIC_MEDIA_PLAYER = 0x00

    class BarcodeScannerSubcategory(utils.OpenIntEnum):
        GENERIC_BARCODE_SCANNER = 0x00

    class ThermometerSubcategory(utils.OpenIntEnum):
        GENERIC_THERMOMETER = 0x00
        EAR_THERMOMETER = 0x01

    class HeartRateSensorSubcategory(utils.OpenIntEnum):
        GENERIC_HEART_RATE_SENSOR = 0x00
        HEART_RATE_BELT = 0x01

    class BloodPressureSubcategory(utils.OpenIntEnum):
        GENERIC_BLOOD_PRESSURE = 0x00
        ARM_BLOOD_PRESSURE = 0x01
        WRIST_BLOOD_PRESSURE = 0x02

    class HumanInterfaceDeviceSubcategory(utils.OpenIntEnum):
        GENERIC_HUMAN_INTERFACE_DEVICE = 0x00
        KEYBOARD = 0x01
        MOUSE = 0x02
        JOYSTICK = 0x03
        GAMEPAD = 0x04
        DIGITIZER_TABLET = 0x05
        CARD_READER = 0x06
        DIGITAL_PEN = 0x07
        BARCODE_SCANNER = 0x08
        TOUCHPAD = 0x09
        PRESENTATION_REMOTE = 0x0A

    class GlucoseMeterSubcategory(utils.OpenIntEnum):
        GENERIC_GLUCOSE_METER = 0x00

    class RunningWalkingSensorSubcategory(utils.OpenIntEnum):
        GENERIC_RUNNING_WALKING_SENSOR = 0x00
        IN_SHOE_RUNNING_WALKING_SENSOR = 0x01
        ON_SHOW_RUNNING_WALKING_SENSOR = 0x02
        ON_HIP_RUNNING_WALKING_SENSOR = 0x03

    class CyclingSubcategory(utils.OpenIntEnum):
        GENERIC_CYCLING = 0x00
        CYCLING_COMPUTER = 0x01
        SPEED_SENSOR = 0x02
        CADENCE_SENSOR = 0x03
        POWER_SENSOR = 0x04
        SPEED_AND_CADENCE_SENSOR = 0x05

    class ControlDeviceSubcategory(utils.OpenIntEnum):
        GENERIC_CONTROL_DEVICE = 0x00
        SWITCH = 0x01
        MULTI_SWITCH = 0x02
        BUTTON = 0x03
        SLIDER = 0x04
        ROTARY_SWITCH = 0x05
        TOUCH_PANEL = 0x06
        SINGLE_SWITCH = 0x07
        DOUBLE_SWITCH = 0x08
        TRIPLE_SWITCH = 0x09
        BATTERY_SWITCH = 0x0A
        ENERGY_HARVESTING_SWITCH = 0x0B
        PUSH_BUTTON = 0x0C

    class NetworkDeviceSubcategory(utils.OpenIntEnum):
        GENERIC_NETWORK_DEVICE = 0x00
        ACCESS_POINT = 0x01
        MESH_DEVICE = 0x02
        MESH_NETWORK_PROXY = 0x03

    class SensorSubcategory(utils.OpenIntEnum):
        GENERIC_SENSOR = 0x00
        MOTION_SENSOR = 0x01
        AIR_QUALITY_SENSOR = 0x02
        TEMPERATURE_SENSOR = 0x03
        HUMIDITY_SENSOR = 0x04
        LEAK_SENSOR = 0x05
        SMOKE_SENSOR = 0x06
        OCCUPANCY_SENSOR = 0x07
        CONTACT_SENSOR = 0x08
        CARBON_MONOXIDE_SENSOR = 0x09
        CARBON_DIOXIDE_SENSOR = 0x0A
        AMBIENT_LIGHT_SENSOR = 0x0B
        ENERGY_SENSOR = 0x0C
        COLOR_LIGHT_SENSOR = 0x0D
        RAIN_SENSOR = 0x0E
        FIRE_SENSOR = 0x0F
        WIND_SENSOR = 0x10
        PROXIMITY_SENSOR = 0x11
        MULTI_SENSOR = 0x12
        FLUSH_MOUNTED_SENSOR = 0x13
        CEILING_MOUNTED_SENSOR = 0x14
        WALL_MOUNTED_SENSOR = 0x15
        MULTISENSOR = 0x16
        ENERGY_METER = 0x17
        FLAME_DETECTOR = 0x18
        VEHICLE_TIRE_PRESSURE_SENSOR = 0x19

    class LightFixturesSubcategory(utils.OpenIntEnum):
        GENERIC_LIGHT_FIXTURES = 0x00
        WALL_LIGHT = 0x01
        CEILING_LIGHT = 0x02
        FLOOR_LIGHT = 0x03
        CABINET_LIGHT = 0x04
        DESK_LIGHT = 0x05
        TROFFER_LIGHT = 0x06
        PENDANT_LIGHT = 0x07
        IN_GROUND_LIGHT = 0x08
        FLOOD_LIGHT = 0x09
        UNDERWATER_LIGHT = 0x0A
        BOLLARD_WITH_LIGHT = 0x0B
        PATHWAY_LIGHT = 0x0C
        GARDEN_LIGHT = 0x0D
        POLE_TOP_LIGHT = 0x0E
        SPOTLIGHT = 0x0F
        LINEAR_LIGHT = 0x10
        STREET_LIGHT = 0x11
        SHELVES_LIGHT = 0x12
        BAY_LIGHT = 0x013
        EMERGENCY_EXIT_LIGHT = 0x14
        LIGHT_CONTROLLER = 0x15
        LIGHT_DRIVER = 0x16
        BULB = 0x17
        LOW_BAY_LIGHT = 0x18
        HIGH_BAY_LIGHT = 0x19

    class FanSubcategory(utils.OpenIntEnum):
        GENERIC_FAN = 0x00
        CEILING_FAN = 0x01
        AXIAL_FAN = 0x02
        EXHAUST_FAN = 0x03
        PEDESTAL_FAN = 0x04
        DESK_FAN = 0x05
        WALL_FAN = 0x06

    class HvacSubcategory(utils.OpenIntEnum):
        GENERIC_HVAC = 0x00
        THERMOSTAT = 0x01
        HUMIDIFIER = 0x02
        DEHUMIDIFIER = 0x03
        HEATER = 0x04
        RADIATOR = 0x05
        BOILER = 0x06
        HEAT_PUMP = 0x07
        INFRARED_HEATER = 0x08
        RADIANT_PANEL_HEATER = 0x09
        FAN_HEATER = 0x0A
        AIR_CURTAIN = 0x0B

    class AirConditioningSubcategory(utils.OpenIntEnum):
        GENERIC_AIR_CONDITIONING = 0x00

    class HumidifierSubcategory(utils.OpenIntEnum):
        GENERIC_HUMIDIFIER = 0x00

    class HeatingSubcategory(utils.OpenIntEnum):
        GENERIC_HEATING = 0x00
        RADIATOR = 0x01
        BOILER = 0x02
        HEAT_PUMP = 0x03
        INFRARED_HEATER = 0x04
        RADIANT_PANEL_HEATER = 0x05
        FAN_HEATER = 0x06
        AIR_CURTAIN = 0x07

    class AccessControlSubcategory(utils.OpenIntEnum):
        GENERIC_ACCESS_CONTROL = 0x00
        ACCESS_DOOR = 0x01
        GARAGE_DOOR = 0x02
        EMERGENCY_EXIT_DOOR = 0x03
        ACCESS_LOCK = 0x04
        ELEVATOR = 0x05
        WINDOW = 0x06
        ENTRANCE_GATE = 0x07
        DOOR_LOCK = 0x08
        LOCKER = 0x09

    class MotorizedDeviceSubcategory(utils.OpenIntEnum):
        GENERIC_MOTORIZED_DEVICE = 0x00
        MOTORIZED_GATE = 0x01
        AWNING = 0x02
        BLINDS_OR_SHADES = 0x03
        CURTAINS = 0x04
        SCREEN = 0x05

    class PowerDeviceSubcategory(utils.OpenIntEnum):
        GENERIC_POWER_DEVICE = 0x00
        POWER_OUTLET = 0x01
        POWER_STRIP = 0x02
        PLUG = 0x03
        POWER_SUPPLY = 0x04
        LED_DRIVER = 0x05
        FLUORESCENT_LAMP_GEAR = 0x06
        HID_LAMP_GEAR = 0x07
        CHARGE_CASE = 0x08
        POWER_BANK = 0x09

    class LightSourceSubcategory(utils.OpenIntEnum):
        GENERIC_LIGHT_SOURCE = 0x00
        INCANDESCENT_LIGHT_BULB = 0x01
        LED_LAMP = 0x02
        HID_LAMP = 0x03
        FLUORESCENT_LAMP = 0x04
        LED_ARRAY = 0x05
        MULTI_COLOR_LED_ARRAY = 0x06
        LOW_VOLTAGE_HALOGEN = 0x07
        ORGANIC_LIGHT_EMITTING_DIODE = 0x08

    class WindowCoveringSubcategory(utils.OpenIntEnum):
        GENERIC_WINDOW_COVERING = 0x00
        WINDOW_SHADES = 0x01
        WINDOW_BLINDS = 0x02
        WINDOW_AWNING = 0x03
        WINDOW_CURTAIN = 0x04
        EXTERIOR_SHUTTER = 0x05
        EXTERIOR_SCREEN = 0x06

    class AudioSinkSubcategory(utils.OpenIntEnum):
        GENERIC_AUDIO_SINK = 0x00
        STANDALONE_SPEAKER = 0x01
        SOUNDBAR = 0x02
        BOOKSHELF_SPEAKER = 0x03
        STANDMOUNTED_SPEAKER = 0x04
        SPEAKERPHONE = 0x05

    class AudioSourceSubcategory(utils.OpenIntEnum):
        GENERIC_AUDIO_SOURCE = 0x00
        MICROPHONE = 0x01
        ALARM = 0x02
        BELL = 0x03
        HORN = 0x04
        BROADCASTING_DEVICE = 0x05
        SERVICE_DESK = 0x06
        KIOSK = 0x07
        BROADCASTING_ROOM = 0x08
        AUDITORIUM = 0x09

    class MotorizedVehicleSubcategory(utils.OpenIntEnum):
        GENERIC_MOTORIZED_VEHICLE = 0x00
        CAR = 0x01
        LARGE_GOODS_VEHICLE = 0x02
        TWO_WHEELED_VEHICLE = 0x03
        MOTORBIKE = 0x04
        SCOOTER = 0x05
        MOPED = 0x06
        THREE_WHEELED_VEHICLE = 0x07
        LIGHT_VEHICLE = 0x08
        QUAD_BIKE = 0x09
        MINIBUS = 0x0A
        BUS = 0x0B
        TROLLEY = 0x0C
        AGRICULTURAL_VEHICLE = 0x0D
        CAMPER_CARAVAN = 0x0E
        RECREATIONAL_VEHICLE_MOTOR_HOME = 0x0F

    class DomesticApplianceSubcategory(utils.OpenIntEnum):
        GENERIC_DOMESTIC_APPLIANCE = 0x00
        REFRIGERATOR = 0x01
        FREEZER = 0x02
        OVEN = 0x03
        MICROWAVE = 0x04
        TOASTER = 0x05
        WASHING_MACHINE = 0x06
        DRYER = 0x07
        COFFEE_MAKER = 0x08
        CLOTHES_IRON = 0x09
        CURLING_IRON = 0x0A
        HAIR_DRYER = 0x0B
        VACUUM_CLEANER = 0x0C
        ROBOTIC_VACUUM_CLEANER = 0x0D
        RICE_COOKER = 0x0E
        CLOTHES_STEAMER = 0x0F

    class WearableAudioDeviceSubcategory(utils.OpenIntEnum):
        GENERIC_WEARABLE_AUDIO_DEVICE = 0x00
        EARBUD = 0x01
        HEADSET = 0x02
        HEADPHONES = 0x03
        NECK_BAND = 0x04

    class AircraftSubcategory(utils.OpenIntEnum):
        GENERIC_AIRCRAFT = 0x00
        LIGHT_AIRCRAFT = 0x01
        MICROLIGHT = 0x02
        PARAGLIDER = 0x03
        LARGE_PASSENGER_AIRCRAFT = 0x04

    class AvEquipmentSubcategory(utils.OpenIntEnum):
        GENERIC_AV_EQUIPMENT = 0x00
        AMPLIFIER = 0x01
        RECEIVER = 0x02
        RADIO = 0x03
        TUNER = 0x04
        TURNTABLE = 0x05
        CD_PLAYER = 0x06
        DVD_PLAYER = 0x07
        BLUERAY_PLAYER = 0x08
        OPTICAL_DISC_PLAYER = 0x09
        SET_TOP_BOX = 0x0A

    class DisplayEquipmentSubcategory(utils.OpenIntEnum):
        GENERIC_DISPLAY_EQUIPMENT = 0x00
        TELEVISION = 0x01
        MONITOR = 0x02
        PROJECTOR = 0x03

    class HearingAidSubcategory(utils.OpenIntEnum):
        GENERIC_HEARING_AID = 0x00
        IN_EAR_HEARING_AID = 0x01
        BEHIND_EAR_HEARING_AID = 0x02
        COCHLEAR_IMPLANT = 0x03

    class GamingSubcategory(utils.OpenIntEnum):
        GENERIC_GAMING = 0x00
        HOME_VIDEO_GAME_CONSOLE = 0x01
        PORTABLE_HANDHELD_CONSOLE = 0x02

    class SignageSubcategory(utils.OpenIntEnum):
        GENERIC_SIGNAGE = 0x00
        DIGITAL_SIGNAGE = 0x01
        ELECTRONIC_LABEL = 0x02

    class PulseOximeterSubcategory(utils.OpenIntEnum):
        GENERIC_PULSE_OXIMETER = 0x00
        FINGERTIP_PULSE_OXIMETER = 0x01
        WRIST_WORN_PULSE_OXIMETER = 0x02

    class WeightScaleSubcategory(utils.OpenIntEnum):
        GENERIC_WEIGHT_SCALE = 0x00

    class PersonalMobilityDeviceSubcategory(utils.OpenIntEnum):
        GENERIC_PERSONAL_MOBILITY_DEVICE = 0x00
        POWERED_WHEELCHAIR = 0x01
        MOBILITY_SCOOTER = 0x02

    class ContinuousGlucoseMonitorSubcategory(utils.OpenIntEnum):
        GENERIC_CONTINUOUS_GLUCOSE_MONITOR = 0x00

    class InsulinPumpSubcategory(utils.OpenIntEnum):
        GENERIC_INSULIN_PUMP = 0x00
        INSULIN_PUMP_DURABLE_PUMP = 0x01
        INSULIN_PUMP_PATCH_PUMP = 0x02
        INSULIN_PEN = 0x03

    class MedicationDeliverySubcategory(utils.OpenIntEnum):
        GENERIC_MEDICATION_DELIVERY = 0x00

    class SpirometerSubcategory(utils.OpenIntEnum):
        GENERIC_SPIROMETER = 0x00
        HANDHELD_SPIROMETER = 0x01

    class OutdoorSportsActivitySubcategory(utils.OpenIntEnum):
        GENERIC_OUTDOOR_SPORTS_ACTIVITY = 0x00
        LOCATION_DISPLAY = 0x01
        LOCATION_AND_NAVIGATION_DISPLAY = 0x02
        LOCATION_POD = 0x03
        LOCATION_AND_NAVIGATION_POD = 0x04

    class _OpenSubcategory(utils.OpenIntEnum):
        GENERIC = 0x00

    SUBCATEGORY_CLASSES = {
        Category.UNKNOWN: UnknownSubcategory,
        Category.PHONE: PhoneSubcategory,
        Category.COMPUTER: ComputerSubcategory,
        Category.WATCH: WatchSubcategory,
        Category.CLOCK: ClockSubcategory,
        Category.DISPLAY: DisplaySubcategory,
        Category.REMOTE_CONTROL: RemoteControlSubcategory,
        Category.EYE_GLASSES: EyeglassesSubcategory,
        Category.TAG: TagSubcategory,
        Category.KEYRING: KeyringSubcategory,
        Category.MEDIA_PLAYER: MediaPlayerSubcategory,
        Category.BARCODE_SCANNER: BarcodeScannerSubcategory,
        Category.THERMOMETER: ThermometerSubcategory,
        Category.HEART_RATE_SENSOR: HeartRateSensorSubcategory,
        Category.BLOOD_PRESSURE: BloodPressureSubcategory,
        Category.HUMAN_INTERFACE_DEVICE: HumanInterfaceDeviceSubcategory,
        Category.GLUCOSE_METER: GlucoseMeterSubcategory,
        Category.RUNNING_WALKING_SENSOR: RunningWalkingSensorSubcategory,
        Category.CYCLING: CyclingSubcategory,
        Category.CONTROL_DEVICE: ControlDeviceSubcategory,
        Category.NETWORK_DEVICE: NetworkDeviceSubcategory,
        Category.SENSOR: SensorSubcategory,
        Category.LIGHT_FIXTURES: LightFixturesSubcategory,
        Category.FAN: FanSubcategory,
        Category.HVAC: HvacSubcategory,
        Category.AIR_CONDITIONING: AirConditioningSubcategory,
        Category.HUMIDIFIER: HumidifierSubcategory,
        Category.HEATING: HeatingSubcategory,
        Category.ACCESS_CONTROL: AccessControlSubcategory,
        Category.MOTORIZED_DEVICE: MotorizedDeviceSubcategory,
        Category.POWER_DEVICE: PowerDeviceSubcategory,
        Category.LIGHT_SOURCE: LightSourceSubcategory,
        Category.WINDOW_COVERING: WindowCoveringSubcategory,
        Category.AUDIO_SINK: AudioSinkSubcategory,
        Category.AUDIO_SOURCE: AudioSourceSubcategory,
        Category.MOTORIZED_VEHICLE: MotorizedVehicleSubcategory,
        Category.DOMESTIC_APPLIANCE: DomesticApplianceSubcategory,
        Category.WEARABLE_AUDIO_DEVICE: WearableAudioDeviceSubcategory,
        Category.AIRCRAFT: AircraftSubcategory,
        Category.AV_EQUIPMENT: AvEquipmentSubcategory,
        Category.DISPLAY_EQUIPMENT: DisplayEquipmentSubcategory,
        Category.HEARING_AID: HearingAidSubcategory,
        Category.GAMING: GamingSubcategory,
        Category.SIGNAGE: SignageSubcategory,
        Category.PULSE_OXIMETER: PulseOximeterSubcategory,
        Category.WEIGHT_SCALE: WeightScaleSubcategory,
        Category.PERSONAL_MOBILITY_DEVICE: PersonalMobilityDeviceSubcategory,
        Category.CONTINUOUS_GLUCOSE_MONITOR: ContinuousGlucoseMonitorSubcategory,
        Category.INSULIN_PUMP: InsulinPumpSubcategory,
        Category.MEDICATION_DELIVERY: MedicationDeliverySubcategory,
        Category.SPIROMETER: SpirometerSubcategory,
        Category.OUTDOOR_SPORTS_ACTIVITY: OutdoorSportsActivitySubcategory,
    }

    category: Category
    subcategory: enum.IntEnum

    @classmethod
    def from_int(cls, appearance: int) -> Self:
        category = cls.Category(appearance >> 6)
        return cls(category, appearance & 0x3F)

    def __init__(self, category: Category, subcategory: int) -> None:
        self.category = category
        if subcategory_class := self.SUBCATEGORY_CLASSES.get(category):
            self.subcategory = subcategory_class(subcategory)
        else:
            self.subcategory = self._OpenSubcategory(subcategory)

    def __int__(self) -> int:
        return self.category << 6 | self.subcategory

    def __repr__(self) -> str:
        return (
            'Appearance('
            f'category={self.category.name}, '
            f'subcategory={self.subcategory.name}'
            ')'
        )

    def __str__(self) -> str:
        return f'{self.category.name}/{self.subcategory.name}'


# -----------------------------------------------------------------------------
# Advertising Data
# -----------------------------------------------------------------------------
AdvertisingDataObject = Union[
    list[UUID],
    tuple[UUID, bytes],
    bytes,
    str,
    int,
    tuple[int, int],
    tuple[int, bytes],
    Appearance,
]


class AdvertisingData:
    # fmt: off
    # pylint: disable=line-too-long

    class Type(utils.OpenIntEnum):
        FLAGS                                               = 0x01
        INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS       = 0x02
        COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS         = 0x03
        INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS       = 0x04
        COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS         = 0x05
        INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS      = 0x06
        COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS        = 0x07
        SHORTENED_LOCAL_NAME                                = 0x08
        COMPLETE_LOCAL_NAME                                 = 0x09
        TX_POWER_LEVEL                                      = 0x0A
        CLASS_OF_DEVICE                                     = 0x0D
        SIMPLE_PAIRING_HASH_C                               = 0x0E
        SIMPLE_PAIRING_HASH_C_192                           = 0x0E
        SIMPLE_PAIRING_RANDOMIZER_R                         = 0x0F
        SIMPLE_PAIRING_RANDOMIZER_R_192                     = 0x0F
        DEVICE_ID                                           = 0x10
        SECURITY_MANAGER_TK_VALUE                           = 0x10
        SECURITY_MANAGER_OUT_OF_BAND_FLAGS                  = 0x11
        PERIPHERAL_CONNECTION_INTERVAL_RANGE                = 0x12
        LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS           = 0x14
        LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS          = 0x15
        SERVICE_DATA_16_BIT_UUID                            = 0x16
        PUBLIC_TARGET_ADDRESS                               = 0x17
        RANDOM_TARGET_ADDRESS                               = 0x18
        APPEARANCE                                          = 0x19
        ADVERTISING_INTERVAL                                = 0x1A
        LE_BLUETOOTH_DEVICE_ADDRESS                         = 0x1B
        LE_ROLE                                             = 0x1C
        SIMPLE_PAIRING_HASH_C_256                           = 0x1D
        SIMPLE_PAIRING_RANDOMIZER_R_256                     = 0x1E
        LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS           = 0x1F
        SERVICE_DATA_32_BIT_UUID                            = 0x20
        SERVICE_DATA_128_BIT_UUID                           = 0x21
        LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE            = 0x22
        LE_SECURE_CONNECTIONS_RANDOM_VALUE                  = 0x23
        URI                                                 = 0x24
        INDOOR_POSITIONING                                  = 0x25
        TRANSPORT_DISCOVERY_DATA                            = 0x26
        LE_SUPPORTED_FEATURES                               = 0x27
        CHANNEL_MAP_UPDATE_INDICATION                       = 0x28
        PB_ADV                                              = 0x29
        MESH_MESSAGE                                        = 0x2A
        MESH_BEACON                                         = 0x2B
        BIGINFO                                             = 0x2C
        BROADCAST_CODE                                      = 0x2D
        RESOLVABLE_SET_IDENTIFIER                           = 0x2E
        ADVERTISING_INTERVAL_LONG                           = 0x2F
        BROADCAST_NAME                                      = 0x30
        ENCRYPTED_ADVERTISING_DATA                          = 0x31
        PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION    = 0x32
        ELECTRONIC_SHELF_LABEL                              = 0x34
        THREE_D_INFORMATION_DATA                            = 0x3D
        MANUFACTURER_SPECIFIC_DATA                          = 0xFF

    # For backward-compatibility
    FLAGS                                            = Type.FLAGS
    INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS    = Type.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS
    COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS      = Type.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS
    INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS    = Type.INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS
    COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS      = Type.COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS
    INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS   = Type.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS
    COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS     = Type.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS
    SHORTENED_LOCAL_NAME                             = Type.SHORTENED_LOCAL_NAME
    COMPLETE_LOCAL_NAME                              = Type.COMPLETE_LOCAL_NAME
    TX_POWER_LEVEL                                   = Type.TX_POWER_LEVEL
    CLASS_OF_DEVICE                                  = Type.CLASS_OF_DEVICE
    SIMPLE_PAIRING_HASH_C                            = Type.SIMPLE_PAIRING_HASH_C
    SIMPLE_PAIRING_HASH_C_192                        = Type.SIMPLE_PAIRING_HASH_C_192
    SIMPLE_PAIRING_RANDOMIZER_R                      = Type.SIMPLE_PAIRING_RANDOMIZER_R
    SIMPLE_PAIRING_RANDOMIZER_R_192                  = Type.SIMPLE_PAIRING_RANDOMIZER_R_192
    DEVICE_ID                                        = Type.DEVICE_ID
    SECURITY_MANAGER_TK_VALUE                        = Type.SECURITY_MANAGER_TK_VALUE
    SECURITY_MANAGER_OUT_OF_BAND_FLAGS               = Type.SECURITY_MANAGER_OUT_OF_BAND_FLAGS
    PERIPHERAL_CONNECTION_INTERVAL_RANGE             = Type.PERIPHERAL_CONNECTION_INTERVAL_RANGE
    LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS        = Type.LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS
    LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS       = Type.LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS
    SERVICE_DATA                                     = Type.SERVICE_DATA_16_BIT_UUID
    SERVICE_DATA_16_BIT_UUID                         = Type.SERVICE_DATA_16_BIT_UUID
    PUBLIC_TARGET_ADDRESS                            = Type.PUBLIC_TARGET_ADDRESS
    RANDOM_TARGET_ADDRESS                            = Type.RANDOM_TARGET_ADDRESS
    APPEARANCE                                       = Type.APPEARANCE
    ADVERTISING_INTERVAL                             = Type.ADVERTISING_INTERVAL
    LE_BLUETOOTH_DEVICE_ADDRESS                      = Type.LE_BLUETOOTH_DEVICE_ADDRESS
    LE_ROLE                                          = Type.LE_ROLE
    SIMPLE_PAIRING_HASH_C_256                        = Type.SIMPLE_PAIRING_HASH_C_256
    SIMPLE_PAIRING_RANDOMIZER_R_256                  = Type.SIMPLE_PAIRING_RANDOMIZER_R_256
    LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS        = Type.LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS
    SERVICE_DATA_32_BIT_UUID                         = Type.SERVICE_DATA_32_BIT_UUID
    SERVICE_DATA_128_BIT_UUID                        = Type.SERVICE_DATA_128_BIT_UUID
    LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE         = Type.LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE
    LE_SECURE_CONNECTIONS_RANDOM_VALUE               = Type.LE_SECURE_CONNECTIONS_RANDOM_VALUE
    URI                                              = Type.URI
    INDOOR_POSITIONING                               = Type.INDOOR_POSITIONING
    TRANSPORT_DISCOVERY_DATA                         = Type.TRANSPORT_DISCOVERY_DATA
    LE_SUPPORTED_FEATURES                            = Type.LE_SUPPORTED_FEATURES
    CHANNEL_MAP_UPDATE_INDICATION                    = Type.CHANNEL_MAP_UPDATE_INDICATION
    PB_ADV                                           = Type.PB_ADV
    MESH_MESSAGE                                     = Type.MESH_MESSAGE
    MESH_BEACON                                      = Type.MESH_BEACON
    BIGINFO                                          = Type.BIGINFO
    BROADCAST_CODE                                   = Type.BROADCAST_CODE
    RESOLVABLE_SET_IDENTIFIER                        = Type.RESOLVABLE_SET_IDENTIFIER
    ADVERTISING_INTERVAL_LONG                        = Type.ADVERTISING_INTERVAL_LONG
    BROADCAST_NAME                                   = Type.BROADCAST_NAME
    ENCRYPTED_ADVERTISING_DATA                       = Type.ENCRYPTED_ADVERTISING_DATA
    PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION = Type.PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION
    ELECTRONIC_SHELF_LABEL                           = Type.ELECTRONIC_SHELF_LABEL
    THREE_D_INFORMATION_DATA                         = Type.THREE_D_INFORMATION_DATA
    MANUFACTURER_SPECIFIC_DATA                       = Type.MANUFACTURER_SPECIFIC_DATA

    LE_LIMITED_DISCOVERABLE_MODE_FLAG = 0x01
    LE_GENERAL_DISCOVERABLE_MODE_FLAG = 0x02
    BR_EDR_NOT_SUPPORTED_FLAG         = 0x04
    BR_EDR_CONTROLLER_FLAG            = 0x08
    BR_EDR_HOST_FLAG                  = 0x10

    ad_structures: list[tuple[int, bytes]]

    # fmt: on
    # pylint: enable=line-too-long

    def __init__(self, ad_structures: Optional[list[tuple[int, bytes]]] = None) -> None:
        if ad_structures is None:
            ad_structures = []
        self.ad_structures = ad_structures[:]

    @classmethod
    def from_bytes(cls, data: bytes) -> AdvertisingData:
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
    def uuid_list_to_objects(ad_data: bytes, uuid_size: int) -> list[UUID]:
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

    @classmethod
    def ad_data_to_string(cls, ad_type: int, ad_data: bytes) -> str:
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
            try:
                ad_data_str = f'"{ad_data.decode("utf-8")}"'
            except UnicodeDecodeError:
                ad_data_str = ad_data.hex()
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
            appearance = Appearance.from_int(struct.unpack_from('<H', ad_data, 0)[0])
            ad_data_str = str(appearance)
        elif ad_type == AdvertisingData.BROADCAST_NAME:
            ad_type_str = 'Broadcast Name'
            ad_data_str = ad_data.decode('utf-8')
        else:
            ad_type_str = AdvertisingData.Type(ad_type).name
            ad_data_str = ad_data.hex()

        return f'[{ad_type_str}]: {ad_data_str}'

    # pylint: disable=too-many-return-statements
    @classmethod
    def ad_data_to_object(cls, ad_type: int, ad_data: bytes) -> AdvertisingDataObject:
        if ad_type in (
            AdvertisingData.Type.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS,
        ):
            return AdvertisingData.uuid_list_to_objects(ad_data, 2)

        if ad_type in (
            AdvertisingData.Type.COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS,
        ):
            return AdvertisingData.uuid_list_to_objects(ad_data, 4)

        if ad_type in (
            AdvertisingData.Type.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS,
        ):
            return AdvertisingData.uuid_list_to_objects(ad_data, 16)

        if ad_type == AdvertisingData.Type.SERVICE_DATA_16_BIT_UUID:
            return (UUID.from_bytes(ad_data[:2]), ad_data[2:])

        if ad_type == AdvertisingData.Type.SERVICE_DATA_32_BIT_UUID:
            return (UUID.from_bytes(ad_data[:4]), ad_data[4:])

        if ad_type == AdvertisingData.Type.SERVICE_DATA_128_BIT_UUID:
            return (UUID.from_bytes(ad_data[:16]), ad_data[16:])

        if ad_type in (
            AdvertisingData.Type.SHORTENED_LOCAL_NAME,
            AdvertisingData.Type.COMPLETE_LOCAL_NAME,
            AdvertisingData.Type.URI,
            AdvertisingData.Type.BROADCAST_NAME,
        ):
            return ad_data.decode("utf-8")

        if ad_type in (AdvertisingData.Type.TX_POWER_LEVEL, AdvertisingData.Type.FLAGS):
            return cast(int, struct.unpack('B', ad_data)[0])

        if ad_type in (AdvertisingData.Type.ADVERTISING_INTERVAL,):
            return cast(int, struct.unpack('<H', ad_data)[0])

        if ad_type == AdvertisingData.Type.CLASS_OF_DEVICE:
            return cast(int, struct.unpack('<I', bytes([*ad_data, 0]))[0])

        if ad_type == AdvertisingData.Type.PERIPHERAL_CONNECTION_INTERVAL_RANGE:
            return cast(tuple[int, int], struct.unpack('<HH', ad_data))

        if ad_type == AdvertisingData.Type.APPEARANCE:
            return Appearance.from_int(
                cast(int, struct.unpack_from('<H', ad_data, 0)[0])
            )

        if ad_type == AdvertisingData.Type.MANUFACTURER_SPECIFIC_DATA:
            return (cast(int, struct.unpack_from('<H', ad_data, 0)[0]), ad_data[2:])

        return ad_data

    def append(self, data: bytes) -> None:
        offset = 0
        while offset + 1 < len(data):
            length = data[offset]
            offset += 1
            if length > 0:
                ad_type = data[offset]
                ad_data = data[offset + 1 : offset + length]
                self.ad_structures.append((ad_type, ad_data))
            offset += length

    @overload
    def get_all(
        self,
        type_id: Literal[
            AdvertisingData.Type.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS,
            AdvertisingData.Type.COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS,
            AdvertisingData.Type.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS,
        ],
        raw: Literal[False] = False,
    ) -> list[list[UUID]]: ...
    @overload
    def get_all(
        self,
        type_id: Literal[
            AdvertisingData.Type.SERVICE_DATA_16_BIT_UUID,
            AdvertisingData.Type.SERVICE_DATA_32_BIT_UUID,
            AdvertisingData.Type.SERVICE_DATA_128_BIT_UUID,
        ],
        raw: Literal[False] = False,
    ) -> list[tuple[UUID, bytes]]: ...
    @overload
    def get_all(
        self,
        type_id: Literal[
            AdvertisingData.Type.SHORTENED_LOCAL_NAME,
            AdvertisingData.Type.COMPLETE_LOCAL_NAME,
            AdvertisingData.Type.URI,
            AdvertisingData.Type.BROADCAST_NAME,
        ],
        raw: Literal[False] = False,
    ) -> list[str]: ...
    @overload
    def get_all(
        self,
        type_id: Literal[
            AdvertisingData.Type.TX_POWER_LEVEL,
            AdvertisingData.Type.FLAGS,
            AdvertisingData.Type.ADVERTISING_INTERVAL,
            AdvertisingData.Type.CLASS_OF_DEVICE,
        ],
        raw: Literal[False] = False,
    ) -> list[int]: ...
    @overload
    def get_all(
        self,
        type_id: Literal[AdvertisingData.Type.PERIPHERAL_CONNECTION_INTERVAL_RANGE,],
        raw: Literal[False] = False,
    ) -> list[tuple[int, int]]: ...
    @overload
    def get_all(
        self,
        type_id: Literal[AdvertisingData.Type.MANUFACTURER_SPECIFIC_DATA,],
        raw: Literal[False] = False,
    ) -> list[tuple[int, bytes]]: ...
    @overload
    def get_all(
        self,
        type_id: Literal[AdvertisingData.Type.APPEARANCE,],
        raw: Literal[False] = False,
    ) -> list[Appearance]: ...
    @overload
    def get_all(self, type_id: int, raw: Literal[True]) -> list[bytes]: ...
    @overload
    def get_all(
        self, type_id: int, raw: bool = False
    ) -> list[AdvertisingDataObject]: ...

    def get_all(self, type_id: int, raw: bool = False) -> list[AdvertisingDataObject]:  # type: ignore[misc]
        '''
        Get Advertising Data Structure(s) with a given type

        Returns a (possibly empty) list of matches.
        '''

        def process_ad_data(ad_data: bytes) -> AdvertisingDataObject:
            return ad_data if raw else self.ad_data_to_object(type_id, ad_data)

        return [process_ad_data(ad[1]) for ad in self.ad_structures if ad[0] == type_id]

    @overload
    def get(
        self,
        type_id: Literal[
            AdvertisingData.Type.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS,
            AdvertisingData.Type.COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS,
            AdvertisingData.Type.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
            AdvertisingData.Type.LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS,
        ],
        raw: Literal[False] = False,
    ) -> Optional[list[UUID]]: ...
    @overload
    def get(
        self,
        type_id: Literal[
            AdvertisingData.Type.SERVICE_DATA_16_BIT_UUID,
            AdvertisingData.Type.SERVICE_DATA_32_BIT_UUID,
            AdvertisingData.Type.SERVICE_DATA_128_BIT_UUID,
        ],
        raw: Literal[False] = False,
    ) -> Optional[tuple[UUID, bytes]]: ...
    @overload
    def get(
        self,
        type_id: Literal[
            AdvertisingData.Type.SHORTENED_LOCAL_NAME,
            AdvertisingData.Type.COMPLETE_LOCAL_NAME,
            AdvertisingData.Type.URI,
            AdvertisingData.Type.BROADCAST_NAME,
        ],
        raw: Literal[False] = False,
    ) -> Optional[Optional[str]]: ...
    @overload
    def get(
        self,
        type_id: Literal[
            AdvertisingData.Type.TX_POWER_LEVEL,
            AdvertisingData.Type.FLAGS,
            AdvertisingData.Type.ADVERTISING_INTERVAL,
            AdvertisingData.Type.CLASS_OF_DEVICE,
        ],
        raw: Literal[False] = False,
    ) -> Optional[int]: ...
    @overload
    def get(
        self,
        type_id: Literal[AdvertisingData.Type.PERIPHERAL_CONNECTION_INTERVAL_RANGE,],
        raw: Literal[False] = False,
    ) -> Optional[tuple[int, int]]: ...
    @overload
    def get(
        self,
        type_id: Literal[AdvertisingData.Type.MANUFACTURER_SPECIFIC_DATA,],
        raw: Literal[False] = False,
    ) -> Optional[tuple[int, bytes]]: ...
    @overload
    def get(
        self,
        type_id: Literal[AdvertisingData.Type.APPEARANCE,],
        raw: Literal[False] = False,
    ) -> Optional[Appearance]: ...
    @overload
    def get(self, type_id: int, raw: Literal[True]) -> Optional[bytes]: ...
    @overload
    def get(
        self, type_id: int, raw: bool = False
    ) -> Optional[AdvertisingDataObject]: ...

    def get(self, type_id: int, raw: bool = False) -> Optional[AdvertisingDataObject]:
        '''
        Get Advertising Data Structure(s) with a given type

        Returns the first entry, or None if no structure matches.
        '''

        all_objects = self.get_all(type_id, raw=raw)
        return all_objects[0] if all_objects else None

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
