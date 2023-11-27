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
# SMP - Security Manager Protocol
#
# See Bluetooth spec @ Vol 3, Part H
#
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import logging
import asyncio
import enum
import secrets
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    cast,
)

from pyee import EventEmitter

from .colors import color
from .hci import (
    Address,
    HCI_LE_Enable_Encryption_Command,
    HCI_Object,
    key_with_value,
)
from .core import (
    BT_BR_EDR_TRANSPORT,
    BT_CENTRAL_ROLE,
    BT_LE_TRANSPORT,
    AdvertisingData,
    ProtocolError,
    name_or_number,
)
from .keys import PairingKeys
from . import crypto

if TYPE_CHECKING:
    from bumble.device import Connection, Device
    from bumble.pairing import PairingConfig


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

SMP_CID = 0x06
SMP_BR_CID = 0x07

SMP_PAIRING_REQUEST_COMMAND               = 0x01
SMP_PAIRING_RESPONSE_COMMAND              = 0x02
SMP_PAIRING_CONFIRM_COMMAND               = 0x03
SMP_PAIRING_RANDOM_COMMAND                = 0x04
SMP_PAIRING_FAILED_COMMAND                = 0x05
SMP_ENCRYPTION_INFORMATION_COMMAND        = 0x06
SMP_MASTER_IDENTIFICATION_COMMAND         = 0x07
SMP_IDENTITY_INFORMATION_COMMAND          = 0x08
SMP_IDENTITY_ADDRESS_INFORMATION_COMMAND  = 0x09
SMP_SIGNING_INFORMATION_COMMAND           = 0x0A
SMP_SECURITY_REQUEST_COMMAND              = 0x0B
SMP_PAIRING_PUBLIC_KEY_COMMAND            = 0x0C
SMP_PAIRING_DHKEY_CHECK_COMMAND           = 0x0D
SMP_PAIRING_KEYPRESS_NOTIFICATION_COMMAND = 0x0E

SMP_COMMAND_NAMES = {
    SMP_PAIRING_REQUEST_COMMAND:               'SMP_PAIRING_REQUEST_COMMAND',
    SMP_PAIRING_RESPONSE_COMMAND:              'SMP_PAIRING_RESPONSE_COMMAND',
    SMP_PAIRING_CONFIRM_COMMAND:               'SMP_PAIRING_CONFIRM_COMMAND',
    SMP_PAIRING_RANDOM_COMMAND:                'SMP_PAIRING_RANDOM_COMMAND',
    SMP_PAIRING_FAILED_COMMAND:                'SMP_PAIRING_FAILED_COMMAND',
    SMP_ENCRYPTION_INFORMATION_COMMAND:        'SMP_ENCRYPTION_INFORMATION_COMMAND',
    SMP_MASTER_IDENTIFICATION_COMMAND:         'SMP_MASTER_IDENTIFICATION_COMMAND',
    SMP_IDENTITY_INFORMATION_COMMAND:          'SMP_IDENTITY_INFORMATION_COMMAND',
    SMP_IDENTITY_ADDRESS_INFORMATION_COMMAND:  'SMP_IDENTITY_ADDRESS_INFORMATION_COMMAND',
    SMP_SIGNING_INFORMATION_COMMAND:           'SMP_SIGNING_INFORMATION_COMMAND',
    SMP_SECURITY_REQUEST_COMMAND:              'SMP_SECURITY_REQUEST_COMMAND',
    SMP_PAIRING_PUBLIC_KEY_COMMAND:            'SMP_PAIRING_PUBLIC_KEY_COMMAND',
    SMP_PAIRING_DHKEY_CHECK_COMMAND:           'SMP_PAIRING_DHKEY_CHECK_COMMAND',
    SMP_PAIRING_KEYPRESS_NOTIFICATION_COMMAND: 'SMP_PAIRING_KEYPRESS_NOTIFICATION_COMMAND'
}

SMP_DISPLAY_ONLY_IO_CAPABILITY       = 0x00
SMP_DISPLAY_YES_NO_IO_CAPABILITY     = 0x01
SMP_KEYBOARD_ONLY_IO_CAPABILITY      = 0x02
SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY = 0x03
SMP_KEYBOARD_DISPLAY_IO_CAPABILITY   = 0x04

SMP_IO_CAPABILITY_NAMES = {
    SMP_DISPLAY_ONLY_IO_CAPABILITY:       'SMP_DISPLAY_ONLY_IO_CAPABILITY',
    SMP_DISPLAY_YES_NO_IO_CAPABILITY:     'SMP_DISPLAY_YES_NO_IO_CAPABILITY',
    SMP_KEYBOARD_ONLY_IO_CAPABILITY:      'SMP_KEYBOARD_ONLY_IO_CAPABILITY',
    SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: 'SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY',
    SMP_KEYBOARD_DISPLAY_IO_CAPABILITY:   'SMP_KEYBOARD_DISPLAY_IO_CAPABILITY'
}

SMP_PASSKEY_ENTRY_FAILED_ERROR                       = 0x01
SMP_OOB_NOT_AVAILABLE_ERROR                          = 0x02
SMP_AUTHENTICATION_REQUIREMENTS_ERROR                = 0x03
SMP_CONFIRM_VALUE_FAILED_ERROR                       = 0x04
SMP_PAIRING_NOT_SUPPORTED_ERROR                      = 0x05
SMP_ENCRYPTION_KEY_SIZE_ERROR                        = 0x06
SMP_COMMAND_NOT_SUPPORTED_ERROR                      = 0x07
SMP_UNSPECIFIED_REASON_ERROR                         = 0x08
SMP_REPEATED_ATTEMPTS_ERROR                          = 0x09
SMP_INVALID_PARAMETERS_ERROR                         = 0x0A
SMP_DHKEY_CHECK_FAILED_ERROR                         = 0x0B
SMP_NUMERIC_COMPARISON_FAILED_ERROR                  = 0x0C
SMP_BD_EDR_PAIRING_IN_PROGRESS_ERROR                 = 0x0D
SMP_CROSS_TRANSPORT_KEY_DERIVATION_NOT_ALLOWED_ERROR = 0x0E

SMP_ERROR_NAMES = {
    SMP_PASSKEY_ENTRY_FAILED_ERROR:                       'SMP_PASSKEY_ENTRY_FAILED_ERROR',
    SMP_OOB_NOT_AVAILABLE_ERROR:                          'SMP_OOB_NOT_AVAILABLE_ERROR',
    SMP_AUTHENTICATION_REQUIREMENTS_ERROR:                'SMP_AUTHENTICATION_REQUIREMENTS_ERROR',
    SMP_CONFIRM_VALUE_FAILED_ERROR:                       'SMP_CONFIRM_VALUE_FAILED_ERROR',
    SMP_PAIRING_NOT_SUPPORTED_ERROR:                      'SMP_PAIRING_NOT_SUPPORTED_ERROR',
    SMP_ENCRYPTION_KEY_SIZE_ERROR:                        'SMP_ENCRYPTION_KEY_SIZE_ERROR',
    SMP_COMMAND_NOT_SUPPORTED_ERROR:                      'SMP_COMMAND_NOT_SUPPORTED_ERROR',
    SMP_UNSPECIFIED_REASON_ERROR:                         'SMP_UNSPECIFIED_REASON_ERROR',
    SMP_REPEATED_ATTEMPTS_ERROR:                          'SMP_REPEATED_ATTEMPTS_ERROR',
    SMP_INVALID_PARAMETERS_ERROR:                         'SMP_INVALID_PARAMETERS_ERROR',
    SMP_DHKEY_CHECK_FAILED_ERROR:                         'SMP_DHKEY_CHECK_FAILED_ERROR',
    SMP_NUMERIC_COMPARISON_FAILED_ERROR:                  'SMP_NUMERIC_COMPARISON_FAILED_ERROR',
    SMP_BD_EDR_PAIRING_IN_PROGRESS_ERROR:                 'SMP_BD_EDR_PAIRING_IN_PROGRESS_ERROR',
    SMP_CROSS_TRANSPORT_KEY_DERIVATION_NOT_ALLOWED_ERROR: 'SMP_CROSS_TRANSPORT_KEY_DERIVATION_NOT_ALLOWED_ERROR'
}

SMP_PASSKEY_ENTRY_STARTED_KEYPRESS_NOTIFICATION_TYPE   = 0
SMP_PASSKEY_DIGIT_ENTERED_KEYPRESS_NOTIFICATION_TYPE   = 1
SMP_PASSKEY_DIGIT_ERASED_KEYPRESS_NOTIFICATION_TYPE    = 2
SMP_PASSKEY_CLEARED_KEYPRESS_NOTIFICATION_TYPE         = 3
SMP_PASSKEY_ENTRY_COMPLETED_KEYPRESS_NOTIFICATION_TYPE = 4

SMP_KEYPRESS_NOTIFICATION_TYPE_NAMES = {
    SMP_PASSKEY_ENTRY_STARTED_KEYPRESS_NOTIFICATION_TYPE:   'SMP_PASSKEY_ENTRY_STARTED_KEYPRESS_NOTIFICATION_TYPE',
    SMP_PASSKEY_DIGIT_ENTERED_KEYPRESS_NOTIFICATION_TYPE:   'SMP_PASSKEY_DIGIT_ENTERED_KEYPRESS_NOTIFICATION_TYPE',
    SMP_PASSKEY_DIGIT_ERASED_KEYPRESS_NOTIFICATION_TYPE:    'SMP_PASSKEY_DIGIT_ERASED_KEYPRESS_NOTIFICATION_TYPE',
    SMP_PASSKEY_CLEARED_KEYPRESS_NOTIFICATION_TYPE:         'SMP_PASSKEY_CLEARED_KEYPRESS_NOTIFICATION_TYPE',
    SMP_PASSKEY_ENTRY_COMPLETED_KEYPRESS_NOTIFICATION_TYPE: 'SMP_PASSKEY_ENTRY_COMPLETED_KEYPRESS_NOTIFICATION_TYPE'
}

# Bit flags for key distribution/generation
SMP_ENC_KEY_DISTRIBUTION_FLAG  = 0b0001
SMP_ID_KEY_DISTRIBUTION_FLAG   = 0b0010
SMP_SIGN_KEY_DISTRIBUTION_FLAG = 0b0100
SMP_LINK_KEY_DISTRIBUTION_FLAG = 0b1000

# AuthReq fields
SMP_BONDING_AUTHREQ  = 0b00000001
SMP_MITM_AUTHREQ     = 0b00000100
SMP_SC_AUTHREQ       = 0b00001000
SMP_KEYPRESS_AUTHREQ = 0b00010000
SMP_CT2_AUTHREQ      = 0b00100000

# Crypto salt
SMP_CTKD_H7_LEBR_SALT = bytes.fromhex('000000000000000000000000746D7031')
SMP_CTKD_H7_BRLE_SALT = bytes.fromhex('000000000000000000000000746D7032')

# fmt: on
# pylint: enable=line-too-long
# pylint: disable=invalid-name


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def error_name(error_code: int) -> str:
    return name_or_number(SMP_ERROR_NAMES, error_code)


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class SMP_Command:
    '''
    See Bluetooth spec @ Vol 3, Part H - 3 SECURITY MANAGER PROTOCOL
    '''

    smp_classes: Dict[int, Type[SMP_Command]] = {}
    fields: Any
    code = 0
    name = ''

    @staticmethod
    def from_bytes(pdu: bytes) -> "SMP_Command":
        code = pdu[0]

        cls = SMP_Command.smp_classes.get(code)
        if cls is None:
            instance = SMP_Command(pdu)
            instance.name = SMP_Command.command_name(code)
            instance.code = code
            return instance
        self = cls.__new__(cls)
        SMP_Command.__init__(self, pdu)
        if hasattr(self, 'fields'):
            self.init_from_bytes(pdu, 1)
        return self

    @staticmethod
    def command_name(code: int) -> str:
        return name_or_number(SMP_COMMAND_NAMES, code)

    @staticmethod
    def auth_req_str(value: int) -> str:
        bonding_flags = value & 3
        mitm = (value >> 2) & 1
        sc = (value >> 3) & 1
        keypress = (value >> 4) & 1
        ct2 = (value >> 5) & 1

        return (
            f'bonding_flags={bonding_flags}, '
            f'MITM={mitm}, sc={sc}, keypress={keypress}, ct2={ct2}'
        )

    @staticmethod
    def io_capability_name(io_capability: int) -> str:
        return name_or_number(SMP_IO_CAPABILITY_NAMES, io_capability)

    @staticmethod
    def key_distribution_str(value: int) -> str:
        key_types: List[str] = []
        if value & SMP_ENC_KEY_DISTRIBUTION_FLAG:
            key_types.append('ENC')
        if value & SMP_ID_KEY_DISTRIBUTION_FLAG:
            key_types.append('ID')
        if value & SMP_SIGN_KEY_DISTRIBUTION_FLAG:
            key_types.append('SIGN')
        if value & SMP_LINK_KEY_DISTRIBUTION_FLAG:
            key_types.append('LINK')
        return ','.join(key_types)

    @staticmethod
    def keypress_notification_type_name(notification_type: int) -> str:
        return name_or_number(SMP_KEYPRESS_NOTIFICATION_TYPE_NAMES, notification_type)

    @staticmethod
    def subclass(fields):
        def inner(cls):
            cls.name = cls.__name__.upper()
            cls.code = key_with_value(SMP_COMMAND_NAMES, cls.name)
            if cls.code is None:
                raise KeyError(
                    f'Command name {cls.name} not found in SMP_COMMAND_NAMES'
                )
            cls.fields = fields

            # Register a factory for this class
            SMP_Command.smp_classes[cls.code] = cls

            return cls

        return inner

    def __init__(self, pdu: Optional[bytes] = None, **kwargs: Any) -> None:
        if hasattr(self, 'fields') and kwargs:
            HCI_Object.init_from_fields(self, self.fields, kwargs)
        if pdu is None:
            pdu = bytes([self.code]) + HCI_Object.dict_to_bytes(kwargs, self.fields)
        self.pdu = pdu

    def init_from_bytes(self, pdu: bytes, offset: int) -> None:
        return HCI_Object.init_from_bytes(self, pdu, offset, self.fields)

    def to_bytes(self):
        return self.pdu

    def __bytes__(self):
        return self.to_bytes()

    def __str__(self):
        result = color(self.name, 'yellow')
        if fields := getattr(self, 'fields', None):
            result += ':\n' + HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if len(self.pdu) > 1:
                result += f': {self.pdu.hex()}'
        return result


# -----------------------------------------------------------------------------
@SMP_Command.subclass(
    [
        ('io_capability', {'size': 1, 'mapper': SMP_Command.io_capability_name}),
        ('oob_data_flag', 1),
        ('auth_req', {'size': 1, 'mapper': SMP_Command.auth_req_str}),
        ('maximum_encryption_key_size', 1),
        (
            'initiator_key_distribution',
            {'size': 1, 'mapper': SMP_Command.key_distribution_str},
        ),
        (
            'responder_key_distribution',
            {'size': 1, 'mapper': SMP_Command.key_distribution_str},
        ),
    ]
)
class SMP_Pairing_Request_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.5.1 Pairing Request
    '''

    io_capability: int
    oob_data_flag: int
    auth_req: int
    maximum_encryption_key_size: int
    initiator_key_distribution: int
    responder_key_distribution: int


# -----------------------------------------------------------------------------
@SMP_Command.subclass(
    [
        ('io_capability', {'size': 1, 'mapper': SMP_Command.io_capability_name}),
        ('oob_data_flag', 1),
        ('auth_req', {'size': 1, 'mapper': SMP_Command.auth_req_str}),
        ('maximum_encryption_key_size', 1),
        (
            'initiator_key_distribution',
            {'size': 1, 'mapper': SMP_Command.key_distribution_str},
        ),
        (
            'responder_key_distribution',
            {'size': 1, 'mapper': SMP_Command.key_distribution_str},
        ),
    ]
)
class SMP_Pairing_Response_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.5.2 Pairing Response
    '''

    io_capability: int
    oob_data_flag: int
    auth_req: int
    maximum_encryption_key_size: int
    initiator_key_distribution: int
    responder_key_distribution: int


# -----------------------------------------------------------------------------
@SMP_Command.subclass([('confirm_value', 16)])
class SMP_Pairing_Confirm_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.5.3 Pairing Confirm
    '''

    confirm_value: bytes


# -----------------------------------------------------------------------------
@SMP_Command.subclass([('random_value', 16)])
class SMP_Pairing_Random_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.5.4 Pairing Random
    '''

    random_value: bytes


# -----------------------------------------------------------------------------
@SMP_Command.subclass([('reason', {'size': 1, 'mapper': error_name})])
class SMP_Pairing_Failed_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.5.5 Pairing Failed
    '''

    reason: int


# -----------------------------------------------------------------------------
@SMP_Command.subclass([('public_key_x', 32), ('public_key_y', 32)])
class SMP_Pairing_Public_Key_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.5.6 Pairing Public Key
    '''

    public_key_x: bytes
    public_key_y: bytes


# -----------------------------------------------------------------------------
@SMP_Command.subclass(
    [
        ('dhkey_check', 16),
    ]
)
class SMP_Pairing_DHKey_Check_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.5.7 Pairing DHKey Check
    '''

    dhkey_check: bytes


# -----------------------------------------------------------------------------
@SMP_Command.subclass(
    [
        (
            'notification_type',
            {'size': 1, 'mapper': SMP_Command.keypress_notification_type_name},
        ),
    ]
)
class SMP_Pairing_Keypress_Notification_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.5.8 Keypress Notification
    '''

    notification_type: int


# -----------------------------------------------------------------------------
@SMP_Command.subclass([('long_term_key', 16)])
class SMP_Encryption_Information_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.6.2 Encryption Information
    '''

    long_term_key: bytes


# -----------------------------------------------------------------------------
@SMP_Command.subclass([('ediv', 2), ('rand', 8)])
class SMP_Master_Identification_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.6.3 Master Identification
    '''

    ediv: int
    rand: bytes


# -----------------------------------------------------------------------------
@SMP_Command.subclass([('identity_resolving_key', 16)])
class SMP_Identity_Information_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.6.4 Identity Information
    '''

    identity_resolving_key: bytes


# -----------------------------------------------------------------------------
@SMP_Command.subclass(
    [
        ('addr_type', Address.ADDRESS_TYPE_SPEC),
        ('bd_addr', Address.parse_address_preceded_by_type),
    ]
)
class SMP_Identity_Address_Information_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.6.5 Identity Address Information
    '''

    addr_type: int
    bd_addr: Address


# -----------------------------------------------------------------------------
@SMP_Command.subclass([('signature_key', 16)])
class SMP_Signing_Information_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.6.6 Signing Information
    '''

    signature_key: bytes


# -----------------------------------------------------------------------------
@SMP_Command.subclass(
    [
        ('auth_req', {'size': 1, 'mapper': SMP_Command.auth_req_str}),
    ]
)
class SMP_Security_Request_Command(SMP_Command):
    '''
    See Bluetooth spec @ Vol 3, Part H - 3.6.7 Security Request
    '''

    auth_req: int


# -----------------------------------------------------------------------------
def smp_auth_req(bonding: bool, mitm: bool, sc: bool, keypress: bool, ct2: bool) -> int:
    value = 0
    if bonding:
        value |= SMP_BONDING_AUTHREQ
    if mitm:
        value |= SMP_MITM_AUTHREQ
    if sc:
        value |= SMP_SC_AUTHREQ
    if keypress:
        value |= SMP_KEYPRESS_AUTHREQ
    if ct2:
        value |= SMP_CT2_AUTHREQ
    return value


# -----------------------------------------------------------------------------
class AddressResolver:
    def __init__(self, resolving_keys):
        self.resolving_keys = resolving_keys

    def resolve(self, address):
        address_bytes = bytes(address)
        hash_part = address_bytes[0:3]
        prand = address_bytes[3:6]
        for irk, resolved_address in self.resolving_keys:
            local_hash = crypto.ah(irk, prand)
            if local_hash == hash_part:
                # Match!
                if resolved_address.address_type == Address.PUBLIC_DEVICE_ADDRESS:
                    resolved_address_type = Address.PUBLIC_IDENTITY_ADDRESS
                else:
                    resolved_address_type = Address.RANDOM_IDENTITY_ADDRESS
                return Address(
                    address=str(resolved_address), address_type=resolved_address_type
                )

        return None


# -----------------------------------------------------------------------------
class PairingMethod(enum.IntEnum):
    JUST_WORKS = 0
    NUMERIC_COMPARISON = 1
    PASSKEY = 2
    OOB = 3
    CTKD_OVER_CLASSIC = 4


# -----------------------------------------------------------------------------
class OobContext:
    """Cryptographic context for LE SC OOB pairing."""

    ecc_key: crypto.EccKey
    r: bytes

    def __init__(
        self, ecc_key: Optional[crypto.EccKey] = None, r: Optional[bytes] = None
    ) -> None:
        self.ecc_key = crypto.EccKey.generate() if ecc_key is None else ecc_key
        self.r = crypto.r() if r is None else r

    def share(self) -> OobSharedData:
        pkx = self.ecc_key.x[::-1]
        return OobSharedData(c=crypto.f4(pkx, pkx, self.r, bytes(1)), r=self.r)


# -----------------------------------------------------------------------------
class OobLegacyContext:
    """Cryptographic context for LE Legacy OOB pairing."""

    tk: bytes

    def __init__(self, tk: Optional[bytes] = None) -> None:
        self.tk = crypto.r() if tk is None else tk


# -----------------------------------------------------------------------------
@dataclass
class OobSharedData:
    """Shareable data for LE SC OOB pairing."""

    c: bytes
    r: bytes

    def to_ad(self) -> AdvertisingData:
        return AdvertisingData(
            [
                (AdvertisingData.LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE, self.c),
                (AdvertisingData.LE_SECURE_CONNECTIONS_RANDOM_VALUE, self.r),
            ]
        )

    def __str__(self) -> str:
        return f'OOB(C={self.c.hex()}, R={self.r.hex()})'


# -----------------------------------------------------------------------------
class Session:
    # I/O Capability to pairing method decision matrix
    #
    # See Bluetooth spec @ Vol 3, part H - Table 2.8: Mapping of IO Capabilities to Key
    # Generation Method
    #
    # Map: initiator -> responder -> <method>
    # where <method> may be a simple entry or a 2-element tuple, with the first element
    # for legacy pairing and the second  for secure connections, when the two are
    # different. Each entry is either a method name, or, for PASSKEY, a tuple:
    # (method, initiator_displays, responder_displays)
    # to specify if the initiator and responder should display (True) or input a code
    # (False).
    PAIRING_METHODS = {
        SMP_DISPLAY_ONLY_IO_CAPABILITY: {
            SMP_DISPLAY_ONLY_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_DISPLAY_YES_NO_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_KEYBOARD_ONLY_IO_CAPABILITY: (PairingMethod.PASSKEY, True, False),
            SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_KEYBOARD_DISPLAY_IO_CAPABILITY: (PairingMethod.PASSKEY, True, False),
        },
        SMP_DISPLAY_YES_NO_IO_CAPABILITY: {
            SMP_DISPLAY_ONLY_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_DISPLAY_YES_NO_IO_CAPABILITY: (
                PairingMethod.JUST_WORKS,
                PairingMethod.NUMERIC_COMPARISON,
            ),
            SMP_KEYBOARD_ONLY_IO_CAPABILITY: (PairingMethod.PASSKEY, True, False),
            SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_KEYBOARD_DISPLAY_IO_CAPABILITY: (
                (PairingMethod.PASSKEY, True, False),
                PairingMethod.NUMERIC_COMPARISON,
            ),
        },
        SMP_KEYBOARD_ONLY_IO_CAPABILITY: {
            SMP_DISPLAY_ONLY_IO_CAPABILITY: (PairingMethod.PASSKEY, False, True),
            SMP_DISPLAY_YES_NO_IO_CAPABILITY: (PairingMethod.PASSKEY, False, True),
            SMP_KEYBOARD_ONLY_IO_CAPABILITY: (PairingMethod.PASSKEY, False, False),
            SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_KEYBOARD_DISPLAY_IO_CAPABILITY: (PairingMethod.PASSKEY, False, True),
        },
        SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: {
            SMP_DISPLAY_ONLY_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_DISPLAY_YES_NO_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_KEYBOARD_ONLY_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_KEYBOARD_DISPLAY_IO_CAPABILITY: PairingMethod.JUST_WORKS,
        },
        SMP_KEYBOARD_DISPLAY_IO_CAPABILITY: {
            SMP_DISPLAY_ONLY_IO_CAPABILITY: (PairingMethod.PASSKEY, False, True),
            SMP_DISPLAY_YES_NO_IO_CAPABILITY: (
                (PairingMethod.PASSKEY, False, True),
                PairingMethod.NUMERIC_COMPARISON,
            ),
            SMP_KEYBOARD_ONLY_IO_CAPABILITY: (PairingMethod.PASSKEY, True, False),
            SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: PairingMethod.JUST_WORKS,
            SMP_KEYBOARD_DISPLAY_IO_CAPABILITY: (
                (PairingMethod.PASSKEY, True, False),
                PairingMethod.NUMERIC_COMPARISON,
            ),
        },
    }

    ea: bytes
    eb: bytes
    ltk: bytes
    preq: bytes
    pres: bytes
    tk: bytes

    def __init__(
        self,
        manager: Manager,
        connection: Connection,
        pairing_config: PairingConfig,
        is_initiator: bool,
    ) -> None:
        self.manager = manager
        self.connection = connection
        self.stk = None
        self.ltk_ediv = 0
        self.ltk_rand = bytes(8)
        self.link_key: Optional[bytes] = None
        self.initiator_key_distribution: int = 0
        self.responder_key_distribution: int = 0
        self.peer_random_value: Optional[bytes] = None
        self.peer_public_key_x: bytes = bytes(32)
        self.peer_public_key_y = bytes(32)
        self.peer_ltk = None
        self.peer_ediv = None
        self.peer_rand: Optional[bytes] = None
        self.peer_identity_resolving_key = None
        self.peer_bd_addr: Optional[Address] = None
        self.peer_signature_key = None
        self.peer_expected_distributions: List[Type[SMP_Command]] = []
        self.dh_key = b''
        self.confirm_value = None
        self.passkey: Optional[int] = None
        self.passkey_ready = asyncio.Event()
        self.passkey_step = 0
        self.passkey_display = False
        self.pairing_method: PairingMethod = PairingMethod.JUST_WORKS
        self.pairing_config = pairing_config
        self.wait_before_continuing: Optional[asyncio.Future[None]] = None
        self.completed = False
        self.ctkd_task: Optional[Awaitable[None]] = None

        # Decide if we're the initiator or the responder
        self.is_initiator = is_initiator
        self.is_responder = not self.is_initiator

        # Listen for connection events
        connection.on('disconnection', self.on_disconnection)
        connection.on(
            'connection_encryption_change', self.on_connection_encryption_change
        )
        connection.on(
            'connection_encryption_key_refresh',
            self.on_connection_encryption_key_refresh,
        )

        # Create a future that can be used to wait for the session to complete
        if self.is_initiator:
            self.pairing_result: Optional[
                asyncio.Future[None]
            ] = asyncio.get_running_loop().create_future()
        else:
            self.pairing_result = None

        # Key Distribution (default values before negotiation)
        self.initiator_key_distribution = (
            pairing_config.delegate.local_initiator_key_distribution
        )
        self.responder_key_distribution = (
            pairing_config.delegate.local_responder_key_distribution
        )

        # Authentication Requirements Flags - Vol 3, Part H, Figure 3.3
        self.bonding: bool = pairing_config.bonding
        self.sc: bool = pairing_config.sc
        self.mitm: bool = pairing_config.mitm
        self.keypress = False
        self.ct2: bool = False

        # I/O Capabilities
        self.io_capability = pairing_config.delegate.io_capability
        self.peer_io_capability = SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY

        # OOB
        self.oob_data_flag = 0 if pairing_config.oob is None else 1

        # Set up addresses
        self_address = connection.self_address
        peer_address = connection.peer_resolvable_address or connection.peer_address
        if self.is_initiator:
            self.ia = bytes(self_address)
            self.iat = 1 if self_address.is_random else 0
            self.ra = bytes(peer_address)
            self.rat = 1 if peer_address.is_random else 0
        else:
            self.ra = bytes(self_address)
            self.rat = 1 if self_address.is_random else 0
            self.ia = bytes(peer_address)
            self.iat = 1 if peer_address.is_random else 0

        # Select the ECC key, TK and r initial value
        if pairing_config.oob:
            self.peer_oob_data = pairing_config.oob.peer_data
            if pairing_config.sc:
                if pairing_config.oob.our_context is None:
                    raise ValueError(
                        "oob pairing config requires a context when sc is True"
                    )
                self.r = pairing_config.oob.our_context.r
                self.ecc_key = pairing_config.oob.our_context.ecc_key
                if pairing_config.oob.legacy_context is not None:
                    self.tk = pairing_config.oob.legacy_context.tk
            else:
                if pairing_config.oob.legacy_context is None:
                    raise ValueError(
                        "oob pairing config requires a legacy context when sc is False"
                    )
                self.r = bytes(16)
                self.ecc_key = manager.ecc_key
                self.tk = pairing_config.oob.legacy_context.tk
        else:
            self.peer_oob_data = None
            self.r = bytes(16)
            self.ecc_key = manager.ecc_key
            self.tk = bytes(16)

    @property
    def pkx(self) -> Tuple[bytes, bytes]:
        return (self.ecc_key.x[::-1], self.peer_public_key_x)

    @property
    def pka(self) -> bytes:
        return self.pkx[0 if self.is_initiator else 1]

    @property
    def pkb(self) -> bytes:
        return self.pkx[0 if self.is_responder else 1]

    @property
    def nx(self) -> Tuple[bytes, bytes]:
        assert self.peer_random_value
        return (self.r, self.peer_random_value)

    @property
    def na(self) -> bytes:
        return self.nx[0 if self.is_initiator else 1]

    @property
    def nb(self) -> bytes:
        return self.nx[0 if self.is_responder else 1]

    @property
    def auth_req(self) -> int:
        return smp_auth_req(self.bonding, self.mitm, self.sc, self.keypress, self.ct2)

    def get_long_term_key(self, rand: bytes, ediv: int) -> Optional[bytes]:
        if not self.sc and not self.completed:
            if rand == self.ltk_rand and ediv == self.ltk_ediv:
                return self.stk
        else:
            return self.ltk

        return None

    def decide_pairing_method(
        self,
        auth_req: int,
        initiator_io_capability: int,
        responder_io_capability: int,
    ) -> None:
        if self.connection.transport == BT_BR_EDR_TRANSPORT:
            self.pairing_method = PairingMethod.CTKD_OVER_CLASSIC
            return
        if (not self.mitm) and (auth_req & SMP_MITM_AUTHREQ == 0):
            self.pairing_method = PairingMethod.JUST_WORKS
            return

        details = self.PAIRING_METHODS[initiator_io_capability][responder_io_capability]  # type: ignore[index]
        if isinstance(details, tuple) and len(details) == 2:
            # One entry for legacy pairing and one for secure connections
            details = details[1 if self.sc else 0]
        if isinstance(details, PairingMethod):
            # Just a method ID
            self.pairing_method = details
        else:
            # PASSKEY method, with a method ID and display/input flags
            assert isinstance(details[0], PairingMethod)
            self.pairing_method = details[0]
            self.passkey_display = details[1 if self.is_initiator else 2]

    def check_expected_value(
        self, expected: bytes, received: bytes, error: int
    ) -> bool:
        logger.debug(f'expected={expected.hex()} got={received.hex()}')
        if expected != received:
            logger.info(color('pairing confirm/check mismatch', 'red'))
            self.send_pairing_failed(error)
            return False
        return True

    def prompt_user_for_confirmation(self, next_steps: Callable[[], None]) -> None:
        async def prompt() -> None:
            logger.debug('ask for confirmation')
            try:
                response = await self.pairing_config.delegate.confirm()
                if response:
                    next_steps()
                    return
            except Exception as error:
                logger.warning(f'exception while confirm: {error}')

            self.send_pairing_failed(SMP_CONFIRM_VALUE_FAILED_ERROR)

        self.connection.abort_on('disconnection', prompt())

    def prompt_user_for_numeric_comparison(
        self, code: int, next_steps: Callable[[], None]
    ) -> None:
        async def prompt() -> None:
            logger.debug(f'verification code: {code}')
            try:
                response = await self.pairing_config.delegate.compare_numbers(
                    code, digits=6
                )
                if response:
                    next_steps()
                    return
            except Exception as error:
                logger.warning(f'exception while prompting: {error}')

            self.send_pairing_failed(SMP_CONFIRM_VALUE_FAILED_ERROR)

        self.connection.abort_on('disconnection', prompt())

    def prompt_user_for_number(self, next_steps: Callable[[int], None]) -> None:
        async def prompt() -> None:
            logger.debug('prompting user for passkey')
            try:
                passkey = await self.pairing_config.delegate.get_number()
                if passkey is None:
                    logger.debug('Passkey request rejected')
                    self.send_pairing_failed(SMP_PASSKEY_ENTRY_FAILED_ERROR)
                    return
                logger.debug(f'user input: {passkey}')
                next_steps(passkey)
            except Exception as error:
                logger.warning(f'exception while prompting: {error}')
                self.send_pairing_failed(SMP_PASSKEY_ENTRY_FAILED_ERROR)

        self.connection.abort_on('disconnection', prompt())

    def display_passkey(self) -> None:
        # Generate random Passkey/PIN code
        self.passkey = secrets.randbelow(1000000)
        assert self.passkey is not None
        logger.debug(f'Pairing PIN CODE: {self.passkey:06}')
        self.passkey_ready.set()

        # The value of TK is computed from the PIN code
        if not self.sc:
            self.tk = self.passkey.to_bytes(16, byteorder='little')
            logger.debug(f'TK from passkey = {self.tk.hex()}')

        try:
            self.connection.abort_on(
                'disconnection',
                self.pairing_config.delegate.display_number(self.passkey, digits=6),
            )
        except Exception as error:
            logger.warning(f'exception while displaying number: {error}')

    def input_passkey(self, next_steps: Optional[Callable[[], None]] = None) -> None:
        # Prompt the user for the passkey displayed on the peer
        def after_input(passkey: int) -> None:
            self.passkey = passkey

            if not self.sc:
                self.tk = passkey.to_bytes(16, byteorder='little')
                logger.debug(f'TK from passkey = {self.tk.hex()}')

            self.passkey_ready.set()

            if next_steps is not None:
                next_steps()

        self.prompt_user_for_number(after_input)

    def display_or_input_passkey(
        self, next_steps: Optional[Callable[[], None]] = None
    ) -> None:
        if self.passkey_display:
            self.display_passkey()
            if next_steps is not None:
                next_steps()
        else:
            self.input_passkey(next_steps)

    def send_command(self, command: SMP_Command) -> None:
        self.manager.send_command(self.connection, command)

    def send_pairing_failed(self, error: int) -> None:
        self.send_command(SMP_Pairing_Failed_Command(reason=error))
        self.on_pairing_failure(error)

    def send_pairing_request_command(self) -> None:
        self.manager.on_session_start(self)

        command = SMP_Pairing_Request_Command(
            io_capability=self.io_capability,
            oob_data_flag=self.oob_data_flag,
            auth_req=self.auth_req,
            maximum_encryption_key_size=16,
            initiator_key_distribution=self.initiator_key_distribution,
            responder_key_distribution=self.responder_key_distribution,
        )
        self.preq = bytes(command)
        self.send_command(command)

    def send_pairing_response_command(self) -> None:
        response = SMP_Pairing_Response_Command(
            io_capability=self.io_capability,
            oob_data_flag=self.oob_data_flag,
            auth_req=self.auth_req,
            maximum_encryption_key_size=16,
            initiator_key_distribution=self.initiator_key_distribution,
            responder_key_distribution=self.responder_key_distribution,
        )
        self.pres = bytes(response)
        self.send_command(response)

    def send_pairing_confirm_command(self) -> None:
        self.r = crypto.r()
        logger.debug(f'generated random: {self.r.hex()}')

        if self.sc:

            async def next_steps() -> None:
                if self.pairing_method in (
                    PairingMethod.JUST_WORKS,
                    PairingMethod.NUMERIC_COMPARISON,
                ):
                    z = 0
                elif self.pairing_method == PairingMethod.PASSKEY:
                    # We need a passkey
                    await self.passkey_ready.wait()
                    assert self.passkey

                    z = 0x80 + ((self.passkey >> self.passkey_step) & 1)
                else:
                    return

                if self.is_initiator:
                    confirm_value = crypto.f4(self.pka, self.pkb, self.r, bytes([z]))
                else:
                    confirm_value = crypto.f4(self.pkb, self.pka, self.r, bytes([z]))

                self.send_command(
                    SMP_Pairing_Confirm_Command(confirm_value=confirm_value)
                )

            # Perform the next steps asynchronously in case we need to wait for input
            self.connection.abort_on('disconnection', next_steps())
        else:
            confirm_value = crypto.c1(
                self.tk,
                self.r,
                self.preq,
                self.pres,
                self.iat,
                self.rat,
                self.ia,
                self.ra,
            )

            self.send_command(SMP_Pairing_Confirm_Command(confirm_value=confirm_value))

    def send_pairing_random_command(self) -> None:
        self.send_command(SMP_Pairing_Random_Command(random_value=self.r))

    def send_public_key_command(self) -> None:
        self.send_command(
            SMP_Pairing_Public_Key_Command(
                public_key_x=self.ecc_key.x[::-1],
                public_key_y=self.ecc_key.y[::-1],
            )
        )

    def send_pairing_dhkey_check_command(self) -> None:
        self.send_command(
            SMP_Pairing_DHKey_Check_Command(
                dhkey_check=self.ea if self.is_initiator else self.eb
            )
        )

    def send_identity_address_command(self) -> None:
        identity_address = {
            None: self.connection.self_address,
            Address.PUBLIC_DEVICE_ADDRESS: self.manager.device.public_address,
            Address.RANDOM_DEVICE_ADDRESS: self.manager.device.random_address,
        }[self.pairing_config.identity_address_type]
        self.send_command(
            SMP_Identity_Address_Information_Command(
                addr_type=identity_address.address_type,
                bd_addr=identity_address,
            )
        )

    def start_encryption(self, key: bytes) -> None:
        # We can now encrypt the connection with the short term key, so that we can
        # distribute the long term and/or other keys over an encrypted connection
        self.manager.device.host.send_command_sync(
            HCI_LE_Enable_Encryption_Command(  # type: ignore[call-arg]
                connection_handle=self.connection.handle,
                random_number=bytes(8),
                encrypted_diversifier=0,
                long_term_key=key,
            )
        )

    @classmethod
    def derive_ltk(cls, link_key: bytes, ct2: bool) -> bytes:
        '''Derives Long Term Key from Link Key.

        Args:
            link_key: BR/EDR Link Key bytes in little-endian.
            ct2: whether ct2 is supported on both devices.
        Returns:
            LE Long Tern Key bytes in little-endian.
        '''
        ilk = (
            crypto.h7(salt=SMP_CTKD_H7_BRLE_SALT, w=link_key)
            if ct2
            else crypto.h6(link_key, b'tmp2')
        )
        return crypto.h6(ilk, b'brle')

    @classmethod
    def derive_link_key(cls, ltk: bytes, ct2: bool) -> bytes:
        '''Derives Link Key from Long Term Key.

        Args:
            ltk: LE Long Term Key bytes in little-endian.
            ct2: whether ct2 is supported on both devices.
        Returns:
            BR/EDR Link Key bytes in little-endian.
        '''
        ilk = (
            crypto.h7(salt=SMP_CTKD_H7_LEBR_SALT, w=ltk)
            if ct2
            else crypto.h6(ltk, b'tmp1')
        )
        return crypto.h6(ilk, b'lebr')

    async def get_link_key_and_derive_ltk(self) -> None:
        '''Retrieves BR/EDR Link Key from storage and derive it to LE LTK.'''
        link_key = await self.manager.device.get_link_key(self.connection.peer_address)
        if link_key is None:
            logging.warning(
                'Try to derive LTK but host does not have the LK. Send a SMP_PAIRING_FAILED but the procedure will not be paused!'
            )
            self.send_pairing_failed(
                SMP_CROSS_TRANSPORT_KEY_DERIVATION_NOT_ALLOWED_ERROR
            )
        else:
            self.ltk = self.derive_ltk(link_key, self.ct2)

    def distribute_keys(self) -> None:
        # Distribute the keys as required
        if self.is_initiator:
            # CTKD: Derive LTK from LinkKey
            if (
                self.connection.transport == BT_BR_EDR_TRANSPORT
                and self.initiator_key_distribution & SMP_ENC_KEY_DISTRIBUTION_FLAG
            ):
                self.ctkd_task = self.connection.abort_on(
                    'disconnection', self.get_link_key_and_derive_ltk()
                )
            elif not self.sc:
                # Distribute the LTK, EDIV and RAND
                if self.initiator_key_distribution & SMP_ENC_KEY_DISTRIBUTION_FLAG:
                    self.send_command(
                        SMP_Encryption_Information_Command(long_term_key=self.ltk)
                    )
                    self.send_command(
                        SMP_Master_Identification_Command(
                            ediv=self.ltk_ediv, rand=self.ltk_rand
                        )
                    )

            # Distribute IRK & BD ADDR
            if self.initiator_key_distribution & SMP_ID_KEY_DISTRIBUTION_FLAG:
                self.send_command(
                    SMP_Identity_Information_Command(
                        identity_resolving_key=self.manager.device.irk
                    )
                )
                self.send_identity_address_command()

            # Distribute CSRK
            csrk = bytes(16)  # FIXME: testing
            if self.initiator_key_distribution & SMP_SIGN_KEY_DISTRIBUTION_FLAG:
                self.send_command(SMP_Signing_Information_Command(signature_key=csrk))

            # CTKD, calculate BR/EDR link key
            if self.initiator_key_distribution & SMP_LINK_KEY_DISTRIBUTION_FLAG:
                self.link_key = self.derive_link_key(self.ltk, self.ct2)

        else:
            # CTKD: Derive LTK from LinkKey
            if (
                self.connection.transport == BT_BR_EDR_TRANSPORT
                and self.responder_key_distribution & SMP_ENC_KEY_DISTRIBUTION_FLAG
            ):
                self.ctkd_task = self.connection.abort_on(
                    'disconnection', self.get_link_key_and_derive_ltk()
                )
            # Distribute the LTK, EDIV and RAND
            elif not self.sc:
                if self.responder_key_distribution & SMP_ENC_KEY_DISTRIBUTION_FLAG:
                    self.send_command(
                        SMP_Encryption_Information_Command(long_term_key=self.ltk)
                    )
                    self.send_command(
                        SMP_Master_Identification_Command(
                            ediv=self.ltk_ediv, rand=self.ltk_rand
                        )
                    )

            # Distribute IRK & BD ADDR
            if self.responder_key_distribution & SMP_ID_KEY_DISTRIBUTION_FLAG:
                self.send_command(
                    SMP_Identity_Information_Command(
                        identity_resolving_key=self.manager.device.irk
                    )
                )
                self.send_identity_address_command()

            # Distribute CSRK
            csrk = bytes(16)  # FIXME: testing
            if self.responder_key_distribution & SMP_SIGN_KEY_DISTRIBUTION_FLAG:
                self.send_command(SMP_Signing_Information_Command(signature_key=csrk))

            # CTKD, calculate BR/EDR link key
            if self.responder_key_distribution & SMP_LINK_KEY_DISTRIBUTION_FLAG:
                self.link_key = self.derive_link_key(self.ltk, self.ct2)

    def compute_peer_expected_distributions(self, key_distribution_flags: int) -> None:
        # Set our expectations for what to wait for in the key distribution phase
        self.peer_expected_distributions = []
        if not self.sc and self.connection.transport == BT_LE_TRANSPORT:
            if key_distribution_flags & SMP_ENC_KEY_DISTRIBUTION_FLAG != 0:
                self.peer_expected_distributions.append(
                    SMP_Encryption_Information_Command
                )
                self.peer_expected_distributions.append(
                    SMP_Master_Identification_Command
                )
        if key_distribution_flags & SMP_ID_KEY_DISTRIBUTION_FLAG != 0:
            self.peer_expected_distributions.append(SMP_Identity_Information_Command)
            self.peer_expected_distributions.append(
                SMP_Identity_Address_Information_Command
            )
        if key_distribution_flags & SMP_SIGN_KEY_DISTRIBUTION_FLAG != 0:
            self.peer_expected_distributions.append(SMP_Signing_Information_Command)
        logger.debug(
            'expecting distributions: '
            f'{[c.__name__ for c in self.peer_expected_distributions]}'
        )

    def check_key_distribution(self, command_class: Type[SMP_Command]) -> None:
        # First, check that the connection is encrypted
        if not self.connection.is_encrypted:
            logger.warning(
                color('received key distribution on a non-encrypted connection', 'red')
            )
            self.send_pairing_failed(SMP_UNSPECIFIED_REASON_ERROR)
            return

        # Check that this command class is expected
        if command_class in self.peer_expected_distributions:
            self.peer_expected_distributions.remove(command_class)
            logger.debug(
                'remaining distributions: '
                f'{[c.__name__ for c in self.peer_expected_distributions]}'
            )
            if not self.peer_expected_distributions:
                self.on_peer_key_distribution_complete()
        else:
            logger.warning(
                color(
                    '!!! unexpected key distribution command: '
                    f'{command_class.__name__}',
                    'red',
                )
            )
            self.send_pairing_failed(SMP_UNSPECIFIED_REASON_ERROR)

    async def pair(self) -> None:
        # Start pairing as an initiator
        # TODO: check that this session isn't already active

        # Send the pairing request to start the process
        self.send_pairing_request_command()

        # Wait for the pairing process to finish
        assert self.pairing_result
        await self.connection.abort_on('disconnection', self.pairing_result)

    def on_disconnection(self, _: int) -> None:
        self.connection.remove_listener('disconnection', self.on_disconnection)
        self.connection.remove_listener(
            'connection_encryption_change', self.on_connection_encryption_change
        )
        self.connection.remove_listener(
            'connection_encryption_key_refresh',
            self.on_connection_encryption_key_refresh,
        )
        self.manager.on_session_end(self)

    def on_peer_key_distribution_complete(self) -> None:
        # The initiator can now send its keys
        if self.is_initiator:
            self.distribute_keys()

        self.connection.abort_on('disconnection', self.on_pairing())

    def on_connection_encryption_change(self) -> None:
        if self.connection.is_encrypted:
            if self.is_responder:
                # The responder distributes its keys first, the initiator later
                self.distribute_keys()

            # If we're not expecting key distributions from the peer, we're done
            if not self.peer_expected_distributions:
                self.on_peer_key_distribution_complete()

    def on_connection_encryption_key_refresh(self) -> None:
        # Do as if the connection had just been encrypted
        self.on_connection_encryption_change()

    async def on_pairing(self) -> None:
        logger.debug('pairing complete')

        if self.completed:
            return

        self.completed = True

        if self.pairing_result is not None and not self.pairing_result.done():
            self.pairing_result.set_result(None)

        # Use the peer address from the pairing protocol or the connection
        if self.peer_bd_addr is not None:
            peer_address = self.peer_bd_addr
        else:
            peer_address = self.connection.peer_address

        # Wait for link key fetch and key derivation
        if self.ctkd_task is not None:
            await self.ctkd_task
            self.ctkd_task = None

        # Create an object to hold the keys
        keys = PairingKeys()
        keys.address_type = peer_address.address_type
        authenticated = self.pairing_method != PairingMethod.JUST_WORKS
        if self.sc or self.connection.transport == BT_BR_EDR_TRANSPORT:
            keys.ltk = PairingKeys.Key(value=self.ltk, authenticated=authenticated)
        else:
            our_ltk_key = PairingKeys.Key(
                value=self.ltk,
                authenticated=authenticated,
                ediv=self.ltk_ediv,
                rand=self.ltk_rand,
            )
            peer_ltk_key = PairingKeys.Key(
                value=self.peer_ltk,
                authenticated=authenticated,
                ediv=self.peer_ediv,
                rand=self.peer_rand,
            )
            if self.is_initiator:
                keys.ltk_central = peer_ltk_key
                keys.ltk_peripheral = our_ltk_key
            else:
                keys.ltk_central = our_ltk_key
                keys.ltk_peripheral = peer_ltk_key
        if self.peer_identity_resolving_key is not None:
            keys.irk = PairingKeys.Key(
                value=self.peer_identity_resolving_key, authenticated=authenticated
            )
        if self.peer_signature_key is not None:
            keys.csrk = PairingKeys.Key(
                value=self.peer_signature_key, authenticated=authenticated
            )
        if self.link_key is not None:
            keys.link_key = PairingKeys.Key(
                value=self.link_key, authenticated=authenticated
            )
        await self.manager.on_pairing(self, peer_address, keys)

    def on_pairing_failure(self, reason: int) -> None:
        logger.warning(f'pairing failure ({error_name(reason)})')

        if self.completed:
            return

        self.completed = True

        error = ProtocolError(reason, 'smp', error_name(reason))
        if self.pairing_result is not None and not self.pairing_result.done():
            self.pairing_result.set_exception(error)
        self.manager.on_pairing_failure(self, reason)

    def on_smp_command(self, command: SMP_Command) -> None:
        # Find the handler method
        handler_name = f'on_{command.name.lower()}'
        handler = getattr(self, handler_name, None)
        if handler is not None:
            try:
                handler(command)
            except Exception as error:
                logger.exception(f'{color("!!! Exception in handler:", "red")} {error}')
                response = SMP_Pairing_Failed_Command(
                    reason=SMP_UNSPECIFIED_REASON_ERROR
                )
                self.send_command(response)
        else:
            logger.error(color('SMP command not handled???', 'red'))

    def on_smp_pairing_request_command(
        self, command: SMP_Pairing_Request_Command
    ) -> None:
        self.connection.abort_on(
            'disconnection', self.on_smp_pairing_request_command_async(command)
        )

    async def on_smp_pairing_request_command_async(
        self, command: SMP_Pairing_Request_Command
    ) -> None:
        # Check if the request should proceed
        try:
            accepted = await self.pairing_config.delegate.accept()
        except Exception as error:
            logger.warning(f'exception while accepting: {error}')
            accepted = False
        if not accepted:
            logger.debug('pairing rejected by delegate')
            self.send_pairing_failed(SMP_PAIRING_NOT_SUPPORTED_ERROR)
            return

        # Save the request
        self.preq = bytes(command)

        # Bonding and SC require both sides to request/support it
        self.bonding = self.bonding and (command.auth_req & SMP_BONDING_AUTHREQ != 0)
        self.sc = self.sc and (command.auth_req & SMP_SC_AUTHREQ != 0)
        self.ct2 = self.ct2 and (command.auth_req & SMP_CT2_AUTHREQ != 0)

        # Infer the pairing method
        if (self.sc and (self.oob_data_flag != 0 or command.oob_data_flag != 0)) or (
            not self.sc and (self.oob_data_flag != 0 and command.oob_data_flag != 0)
        ):
            # Use OOB
            self.pairing_method = PairingMethod.OOB
            if not self.sc and self.tk is None:
                # For legacy OOB, TK is required.
                logger.warning("legacy OOB without TK")
                self.send_pairing_failed(SMP_OOB_NOT_AVAILABLE_ERROR)
                return
            if command.oob_data_flag == 0:
                # The peer doesn't have OOB data, use r=0
                self.r = bytes(16)
        else:
            # Decide which pairing method to use from the IO capability
            self.decide_pairing_method(
                command.auth_req,
                command.io_capability,
                self.io_capability,
            )

        logger.debug(f'pairing method: {self.pairing_method.name}')

        # Key distribution
        (
            self.initiator_key_distribution,
            self.responder_key_distribution,
        ) = await self.pairing_config.delegate.key_distribution_response(
            command.initiator_key_distribution, command.responder_key_distribution
        )
        self.compute_peer_expected_distributions(self.initiator_key_distribution)

        # The pairing is now starting
        self.manager.on_session_start(self)

        # Display a passkey if we need to
        if not self.sc:
            if self.pairing_method == PairingMethod.PASSKEY and self.passkey_display:
                self.display_passkey()

        # Respond
        self.send_pairing_response_command()

        # Vol 3, Part C, 5.2.2.1.3
        # CTKD over BR/EDR should happen after the connection has been encrypted,
        # so when receiving pairing requests, responder should start distributing keys
        if (
            self.connection.transport == BT_BR_EDR_TRANSPORT
            and self.connection.is_encrypted
            and self.is_responder
            and accepted
        ):
            self.distribute_keys()

    def on_smp_pairing_response_command(
        self, command: SMP_Pairing_Response_Command
    ) -> None:
        if self.is_responder:
            logger.warning(color('received pairing response as a responder', 'red'))
            return

        # Save the response
        self.pres = bytes(command)
        self.peer_io_capability = command.io_capability

        # Bonding and SC require both sides to request/support it
        self.bonding = self.bonding and (command.auth_req & SMP_BONDING_AUTHREQ != 0)
        self.sc = self.sc and (command.auth_req & SMP_SC_AUTHREQ != 0)

        # Infer the pairing method
        if (self.sc and (self.oob_data_flag != 0 or command.oob_data_flag != 0)) or (
            not self.sc and (self.oob_data_flag != 0 and command.oob_data_flag != 0)
        ):
            # Use OOB
            self.pairing_method = PairingMethod.OOB
            if not self.sc and self.tk is None:
                # For legacy OOB, TK is required.
                logger.warning("legacy OOB without TK")
                self.send_pairing_failed(SMP_OOB_NOT_AVAILABLE_ERROR)
                return
            if command.oob_data_flag == 0:
                # The peer doesn't have OOB data, use r=0
                self.r = bytes(16)
        else:
            # Decide which pairing method to use from the IO capability
            self.decide_pairing_method(
                command.auth_req, self.io_capability, command.io_capability
            )

        logger.debug(f'pairing method: {self.pairing_method.name}')

        # Key distribution
        if (
            command.initiator_key_distribution & ~self.initiator_key_distribution != 0
        ) or (
            command.responder_key_distribution & ~self.responder_key_distribution != 0
        ):
            # The response isn't a subset of the request
            self.send_pairing_failed(SMP_INVALID_PARAMETERS_ERROR)
            return
        self.initiator_key_distribution = command.initiator_key_distribution
        self.responder_key_distribution = command.responder_key_distribution
        self.compute_peer_expected_distributions(self.responder_key_distribution)

        # Start phase 2
        if self.pairing_method == PairingMethod.CTKD_OVER_CLASSIC:
            # Authentication is already done in SMP, so remote shall start keys distribution immediately
            return
        elif self.sc:
            if self.pairing_method == PairingMethod.PASSKEY:
                self.display_or_input_passkey()

            self.send_public_key_command()
        else:
            if self.pairing_method == PairingMethod.PASSKEY:
                self.display_or_input_passkey(self.send_pairing_confirm_command)
            else:
                self.send_pairing_confirm_command()

    def on_smp_pairing_confirm_command_legacy(
        self, _: SMP_Pairing_Confirm_Command
    ) -> None:
        if self.is_initiator:
            self.send_pairing_random_command()
        else:
            # If the method is PASSKEY, now is the time to input the code
            if (
                self.pairing_method == PairingMethod.PASSKEY
                and not self.passkey_display
            ):
                self.input_passkey(self.send_pairing_confirm_command)
            else:
                self.send_pairing_confirm_command()

    def on_smp_pairing_confirm_command_secure_connections(
        self, _: SMP_Pairing_Confirm_Command
    ) -> None:
        if self.pairing_method in (
            PairingMethod.JUST_WORKS,
            PairingMethod.NUMERIC_COMPARISON,
        ):
            if self.is_initiator:
                self.r = crypto.r()
                self.send_pairing_random_command()
        elif self.pairing_method == PairingMethod.PASSKEY:
            if self.is_initiator:
                self.send_pairing_random_command()
            else:
                self.send_pairing_confirm_command()

    def on_smp_pairing_confirm_command(
        self, command: SMP_Pairing_Confirm_Command
    ) -> None:
        self.confirm_value = command.confirm_value
        if self.sc:
            self.on_smp_pairing_confirm_command_secure_connections(command)
        else:
            self.on_smp_pairing_confirm_command_legacy(command)

    def on_smp_pairing_random_command_legacy(
        self, command: SMP_Pairing_Random_Command
    ) -> None:
        # Check that the confirmation values match
        confirm_verifier = crypto.c1(
            self.tk,
            command.random_value,
            self.preq,
            self.pres,
            self.iat,
            self.rat,
            self.ia,
            self.ra,
        )
        assert self.confirm_value
        if not self.check_expected_value(
            self.confirm_value, confirm_verifier, SMP_CONFIRM_VALUE_FAILED_ERROR
        ):
            return

        # Compute STK
        if self.is_initiator:
            mrand = self.r
            srand = command.random_value
        else:
            srand = self.r
            mrand = command.random_value
        self.stk = crypto.s1(self.tk, srand, mrand)
        logger.debug(f'STK = {self.stk.hex()}')

        # Generate LTK
        self.ltk = crypto.r()

        if self.is_initiator:
            self.start_encryption(self.stk)
        else:
            self.send_pairing_random_command()

    def on_smp_pairing_random_command_secure_connections(
        self, command: SMP_Pairing_Random_Command
    ) -> None:
        if self.pairing_method == PairingMethod.PASSKEY and self.passkey is None:
            logger.warning('no passkey entered, ignoring command')
            return

        # pylint: disable=too-many-return-statements
        if self.is_initiator:
            if self.pairing_method in (
                PairingMethod.JUST_WORKS,
                PairingMethod.NUMERIC_COMPARISON,
            ):
                assert self.confirm_value
                # Check that the random value matches what was committed to earlier
                confirm_verifier = crypto.f4(
                    self.pkb, self.pka, command.random_value, bytes([0])
                )
                if not self.check_expected_value(
                    self.confirm_value, confirm_verifier, SMP_CONFIRM_VALUE_FAILED_ERROR
                ):
                    return
            elif self.pairing_method == PairingMethod.PASSKEY:
                assert self.passkey and self.confirm_value
                # Check that the random value matches what was committed to earlier
                confirm_verifier = crypto.f4(
                    self.pkb,
                    self.pka,
                    command.random_value,
                    bytes([0x80 + ((self.passkey >> self.passkey_step) & 1)]),
                )
                if not self.check_expected_value(
                    self.confirm_value, confirm_verifier, SMP_CONFIRM_VALUE_FAILED_ERROR
                ):
                    return

                # Move on to the next iteration
                self.passkey_step += 1
                logger.debug(f'passkey finished step {self.passkey_step} of 20')
                if self.passkey_step < 20:
                    self.send_pairing_confirm_command()
                    return
            elif self.pairing_method != PairingMethod.OOB:
                return
        else:
            if self.pairing_method in (
                PairingMethod.JUST_WORKS,
                PairingMethod.NUMERIC_COMPARISON,
                PairingMethod.OOB,
            ):
                self.send_pairing_random_command()
            elif self.pairing_method == PairingMethod.PASSKEY:
                assert self.passkey and self.confirm_value
                # Check that the random value matches what was committed to earlier
                confirm_verifier = crypto.f4(
                    self.pka,
                    self.pkb,
                    command.random_value,
                    bytes([0x80 + ((self.passkey >> self.passkey_step) & 1)]),
                )
                if not self.check_expected_value(
                    self.confirm_value, confirm_verifier, SMP_CONFIRM_VALUE_FAILED_ERROR
                ):
                    return

                self.send_pairing_random_command()

                # Move on to the next iteration
                self.passkey_step += 1
                logger.debug(f'passkey finished step {self.passkey_step} of 20')
                if self.passkey_step < 20:
                    self.r = crypto.r()
                    return
            else:
                return

        # Compute the MacKey and LTK
        a = self.ia + bytes([self.iat])
        b = self.ra + bytes([self.rat])
        (mac_key, self.ltk) = crypto.f5(self.dh_key, self.na, self.nb, a, b)

        # Compute the DH Key checks
        if self.pairing_method in (
            PairingMethod.JUST_WORKS,
            PairingMethod.NUMERIC_COMPARISON,
            PairingMethod.OOB,
        ):
            ra = bytes(16)
            rb = ra
        elif self.pairing_method == PairingMethod.PASSKEY:
            assert self.passkey
            ra = self.passkey.to_bytes(16, byteorder='little')
            rb = ra
        else:
            return

        assert self.preq and self.pres
        io_cap_a = self.preq[1:4]
        io_cap_b = self.pres[1:4]
        self.ea = crypto.f6(mac_key, self.na, self.nb, rb, io_cap_a, a, b)
        self.eb = crypto.f6(mac_key, self.nb, self.na, ra, io_cap_b, b, a)

        # Next steps to be performed after possible user confirmation
        def next_steps() -> None:
            # The initiator sends the DH Key check to the responder
            if self.is_initiator:
                self.send_pairing_dhkey_check_command()
            else:
                if self.wait_before_continuing:
                    self.wait_before_continuing.set_result(None)

        # Prompt the user for confirmation if needed
        if self.pairing_method in (
            PairingMethod.JUST_WORKS,
            PairingMethod.NUMERIC_COMPARISON,
        ):
            # Compute the 6-digit code
            code = crypto.g2(self.pka, self.pkb, self.na, self.nb) % 1000000

            # Ask for user confirmation
            self.wait_before_continuing = asyncio.get_running_loop().create_future()
            if self.pairing_method == PairingMethod.JUST_WORKS:
                self.prompt_user_for_confirmation(next_steps)
            else:
                self.prompt_user_for_numeric_comparison(code, next_steps)
        else:
            next_steps()

    def on_smp_pairing_random_command(
        self, command: SMP_Pairing_Random_Command
    ) -> None:
        self.peer_random_value = command.random_value
        if self.sc:
            self.on_smp_pairing_random_command_secure_connections(command)
        else:
            self.on_smp_pairing_random_command_legacy(command)

    def on_smp_pairing_public_key_command(
        self, command: SMP_Pairing_Public_Key_Command
    ) -> None:
        # Store the public key so that we can compute the confirmation value later
        self.peer_public_key_x = command.public_key_x
        self.peer_public_key_y = command.public_key_y

        # Compute the DH key
        self.dh_key = self.ecc_key.dh(
            command.public_key_x[::-1],
            command.public_key_y[::-1],
        )[::-1]
        logger.debug(f'DH key: {self.dh_key.hex()}')

        if self.pairing_method == PairingMethod.OOB:
            # Check against shared OOB data
            if self.peer_oob_data:
                confirm_verifier = crypto.f4(
                    self.peer_public_key_x,
                    self.peer_public_key_x,
                    self.peer_oob_data.r,
                    bytes(1),
                )
                if not self.check_expected_value(
                    self.peer_oob_data.c,
                    confirm_verifier,
                    SMP_CONFIRM_VALUE_FAILED_ERROR,
                ):
                    return

        if self.is_initiator:
            if self.pairing_method == PairingMethod.OOB:
                self.send_pairing_random_command()
            else:
                self.send_pairing_confirm_command()
        else:
            if self.pairing_method == PairingMethod.PASSKEY:
                self.display_or_input_passkey()

            # Send our public key back to the initiator
            self.send_public_key_command()

            if self.pairing_method in (
                PairingMethod.JUST_WORKS,
                PairingMethod.NUMERIC_COMPARISON,
                PairingMethod.OOB,
            ):
                # We can now send the confirmation value
                self.send_pairing_confirm_command()

    def on_smp_pairing_dhkey_check_command(
        self, command: SMP_Pairing_DHKey_Check_Command
    ) -> None:
        # Check that what we received matches what we computed earlier
        expected = self.eb if self.is_initiator else self.ea
        assert expected
        if not self.check_expected_value(
            expected, command.dhkey_check, SMP_DHKEY_CHECK_FAILED_ERROR
        ):
            return

        if self.is_responder:
            if self.wait_before_continuing is not None:

                async def next_steps() -> None:
                    assert self.wait_before_continuing
                    await self.wait_before_continuing
                    self.wait_before_continuing = None
                    self.send_pairing_dhkey_check_command()

                self.connection.abort_on('disconnection', next_steps())
            else:
                self.send_pairing_dhkey_check_command()
        else:
            self.start_encryption(self.ltk)

    def on_smp_pairing_failed_command(
        self, command: SMP_Pairing_Failed_Command
    ) -> None:
        self.on_pairing_failure(command.reason)

    def on_smp_encryption_information_command(
        self, command: SMP_Encryption_Information_Command
    ) -> None:
        self.peer_ltk = command.long_term_key
        self.check_key_distribution(SMP_Encryption_Information_Command)

    def on_smp_master_identification_command(
        self, command: SMP_Master_Identification_Command
    ) -> None:
        self.peer_ediv = command.ediv
        self.peer_rand = command.rand
        self.check_key_distribution(SMP_Master_Identification_Command)

    def on_smp_identity_information_command(
        self, command: SMP_Identity_Information_Command
    ) -> None:
        self.peer_identity_resolving_key = command.identity_resolving_key
        self.check_key_distribution(SMP_Identity_Information_Command)

    def on_smp_identity_address_information_command(
        self, command: SMP_Identity_Address_Information_Command
    ) -> None:
        self.peer_bd_addr = command.bd_addr
        self.check_key_distribution(SMP_Identity_Address_Information_Command)

    def on_smp_signing_information_command(
        self, command: SMP_Signing_Information_Command
    ) -> None:
        self.peer_signature_key = command.signature_key
        self.check_key_distribution(SMP_Signing_Information_Command)


# -----------------------------------------------------------------------------
class Manager(EventEmitter):
    '''
    Implements the Initiator and Responder roles of the Security Manager Protocol
    '''

    device: Device
    sessions: Dict[int, Session]
    pairing_config_factory: Callable[[Connection], PairingConfig]
    session_proxy: Type[Session]
    _ecc_key: Optional[crypto.EccKey]

    def __init__(
        self,
        device: Device,
        pairing_config_factory: Callable[[Connection], PairingConfig],
    ) -> None:
        super().__init__()
        self.device = device
        self.sessions = {}
        self._ecc_key = None
        self.pairing_config_factory = pairing_config_factory
        self.session_proxy = Session

    def send_command(self, connection: Connection, command: SMP_Command) -> None:
        logger.debug(
            f'>>> Sending SMP Command on connection [0x{connection.handle:04X}] '
            f'{connection.peer_address}: {command}'
        )
        cid = SMP_BR_CID if connection.transport == BT_BR_EDR_TRANSPORT else SMP_CID
        connection.send_l2cap_pdu(cid, command.to_bytes())

    def on_smp_security_request_command(
        self, connection: Connection, request: SMP_Security_Request_Command
    ) -> None:
        connection.emit('security_request', request.auth_req)

    def on_smp_pdu(self, connection: Connection, pdu: bytes) -> None:
        # Parse the L2CAP payload into an SMP Command object
        command = SMP_Command.from_bytes(pdu)
        logger.debug(
            f'<<< Received SMP Command on connection [0x{connection.handle:04X}] '
            f'{connection.peer_address}: {command}'
        )

        # Security request is more than just pairing, so let applications handle them
        if command.code == SMP_SECURITY_REQUEST_COMMAND:
            self.on_smp_security_request_command(
                connection, cast(SMP_Security_Request_Command, command)
            )
            return

        # Look for a session with this connection, and create one if none exists
        if not (session := self.sessions.get(connection.handle)):
            if connection.role == BT_CENTRAL_ROLE:
                logger.warning('Remote starts pairing as Peripheral!')
            pairing_config = self.pairing_config_factory(connection)
            session = self.session_proxy(
                self, connection, pairing_config, is_initiator=False
            )
            self.sessions[connection.handle] = session

        # Delegate the handling of the command to the session
        session.on_smp_command(command)

    @property
    def ecc_key(self) -> crypto.EccKey:
        if self._ecc_key is None:
            self._ecc_key = crypto.EccKey.generate()
        assert self._ecc_key
        return self._ecc_key

    async def pair(self, connection: Connection) -> None:
        # TODO: check if there's already a session for this connection
        if connection.role != BT_CENTRAL_ROLE:
            logger.warning('Start pairing as Peripheral!')
        pairing_config = self.pairing_config_factory(connection)
        session = self.session_proxy(
            self, connection, pairing_config, is_initiator=True
        )
        self.sessions[connection.handle] = session
        return await session.pair()

    def request_pairing(self, connection: Connection) -> None:
        pairing_config = self.pairing_config_factory(connection)
        if pairing_config:
            auth_req = smp_auth_req(
                pairing_config.bonding,
                pairing_config.mitm,
                pairing_config.sc,
                False,
                False,
            )
        else:
            auth_req = 0
        self.send_command(connection, SMP_Security_Request_Command(auth_req=auth_req))

    def on_session_start(self, session: Session) -> None:
        self.device.on_pairing_start(session.connection)

    async def on_pairing(
        self, session: Session, identity_address: Optional[Address], keys: PairingKeys
    ) -> None:
        # Store the keys in the key store
        if self.device.keystore and identity_address is not None:
            self.device.abort_on(
                'flush', self.device.update_keys(str(identity_address), keys)
            )

        # Notify the device
        self.device.on_pairing(session.connection, identity_address, keys, session.sc)

    def on_pairing_failure(self, session: Session, reason: int) -> None:
        self.device.on_pairing_failure(session.connection, reason)

    def on_session_end(self, session: Session) -> None:
        logger.debug(f'session end for connection 0x{session.connection.handle:04X}')
        if session.connection.handle in self.sessions:
            del self.sessions[session.connection.handle]

    def get_long_term_key(
        self, connection: Connection, rand: bytes, ediv: int
    ) -> Optional[bytes]:
        if session := self.sessions.get(connection.handle):
            return session.get_long_term_key(rand, ediv)

        return None
