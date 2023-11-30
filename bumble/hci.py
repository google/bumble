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
import collections
import enum
import functools
import logging
import struct
from typing import Any, Dict, Callable, Optional, Type, Union, List

from .colors import color
from .core import (
    BT_BR_EDR_TRANSPORT,
    AdvertisingData,
    DeviceClass,
    ProtocolError,
    bit_flags_to_strings,
    name_or_number,
    padded_bytes,
)


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------
def hci_command_op_code(ogf, ocf):
    return ogf << 10 | ocf


def hci_vendor_command_op_code(ocf):
    return hci_command_op_code(HCI_VENDOR_OGF, ocf)


def key_with_value(dictionary, target_value):
    for key, value in dictionary.items():
        if value == target_value:
            return key
    return None


def indent_lines(string):
    return '\n'.join(['  ' + line for line in string.split('\n')])


def map_null_terminated_utf8_string(utf8_bytes):
    try:
        terminator = utf8_bytes.find(0)
        if terminator < 0:
            terminator = len(utf8_bytes)
        return utf8_bytes[0:terminator].decode('utf8')
    except UnicodeDecodeError:
        return utf8_bytes


def map_class_of_device(class_of_device):
    (
        service_classes,
        major_device_class,
        minor_device_class,
    ) = DeviceClass.split_class_of_device(class_of_device)
    return (
        f'[{class_of_device:06X}] Services('
        f'{",".join(DeviceClass.service_class_labels(service_classes))}),'
        f'Class({DeviceClass.major_device_class_name(major_device_class)}|'
        f'{DeviceClass.minor_device_class_name(major_device_class, minor_device_class)}'
        ')'
    )


def phy_list_to_bits(phys):
    if phys is None:
        return 0

    phy_bits = 0
    for phy in phys:
        if phy not in HCI_LE_PHY_TYPE_TO_BIT:
            raise ValueError('invalid PHY')
        phy_bits |= 1 << HCI_LE_PHY_TYPE_TO_BIT[phy]
    return phy_bits


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

HCI_VENDOR_OGF = 0x3F

# HCI Version
HCI_VERSION_BLUETOOTH_CORE_1_0B    = 0
HCI_VERSION_BLUETOOTH_CORE_1_1     = 1
HCI_VERSION_BLUETOOTH_CORE_1_2     = 2
HCI_VERSION_BLUETOOTH_CORE_2_0_EDR = 3
HCI_VERSION_BLUETOOTH_CORE_2_1_EDR = 4
HCI_VERSION_BLUETOOTH_CORE_3_0_HS  = 5
HCI_VERSION_BLUETOOTH_CORE_4_0     = 6
HCI_VERSION_BLUETOOTH_CORE_4_1     = 7
HCI_VERSION_BLUETOOTH_CORE_4_2     = 8
HCI_VERSION_BLUETOOTH_CORE_5_0     = 9
HCI_VERSION_BLUETOOTH_CORE_5_1     = 10
HCI_VERSION_BLUETOOTH_CORE_5_2     = 11
HCI_VERSION_BLUETOOTH_CORE_5_3     = 12
HCI_VERSION_BLUETOOTH_CORE_5_4     = 13

HCI_VERSION_NAMES = {
    HCI_VERSION_BLUETOOTH_CORE_1_0B:    'HCI_VERSION_BLUETOOTH_CORE_1_0B',
    HCI_VERSION_BLUETOOTH_CORE_1_1:     'HCI_VERSION_BLUETOOTH_CORE_1_1',
    HCI_VERSION_BLUETOOTH_CORE_1_2:     'HCI_VERSION_BLUETOOTH_CORE_1_2',
    HCI_VERSION_BLUETOOTH_CORE_2_0_EDR: 'HCI_VERSION_BLUETOOTH_CORE_2_0_EDR',
    HCI_VERSION_BLUETOOTH_CORE_2_1_EDR: 'HCI_VERSION_BLUETOOTH_CORE_2_1_EDR',
    HCI_VERSION_BLUETOOTH_CORE_3_0_HS:  'HCI_VERSION_BLUETOOTH_CORE_3_0_HS',
    HCI_VERSION_BLUETOOTH_CORE_4_0:     'HCI_VERSION_BLUETOOTH_CORE_4_0',
    HCI_VERSION_BLUETOOTH_CORE_4_1:     'HCI_VERSION_BLUETOOTH_CORE_4_1',
    HCI_VERSION_BLUETOOTH_CORE_4_2:     'HCI_VERSION_BLUETOOTH_CORE_4_2',
    HCI_VERSION_BLUETOOTH_CORE_5_0:     'HCI_VERSION_BLUETOOTH_CORE_5_0',
    HCI_VERSION_BLUETOOTH_CORE_5_1:     'HCI_VERSION_BLUETOOTH_CORE_5_1',
    HCI_VERSION_BLUETOOTH_CORE_5_2:     'HCI_VERSION_BLUETOOTH_CORE_5_2',
    HCI_VERSION_BLUETOOTH_CORE_5_3:     'HCI_VERSION_BLUETOOTH_CORE_5_3',
    HCI_VERSION_BLUETOOTH_CORE_5_4:     'HCI_VERSION_BLUETOOTH_CORE_5_4',
}

# LMP Version
LMP_VERSION_NAMES = HCI_VERSION_NAMES

# HCI Packet types
HCI_COMMAND_PACKET          = 0x01
HCI_ACL_DATA_PACKET         = 0x02
HCI_SYNCHRONOUS_DATA_PACKET = 0x03
HCI_EVENT_PACKET            = 0x04
HCI_ISO_DATA_PACKET         = 0x05

# HCI Event Codes
HCI_INQUIRY_COMPLETE_EVENT                                       = 0x01
HCI_INQUIRY_RESULT_EVENT                                         = 0x02
HCI_CONNECTION_COMPLETE_EVENT                                    = 0x03
HCI_CONNECTION_REQUEST_EVENT                                     = 0x04
HCI_DISCONNECTION_COMPLETE_EVENT                                 = 0x05
HCI_AUTHENTICATION_COMPLETE_EVENT                                = 0x06
HCI_REMOTE_NAME_REQUEST_COMPLETE_EVENT                           = 0x07
HCI_ENCRYPTION_CHANGE_EVENT                                      = 0x08
HCI_CHANGE_CONNECTION_LINK_KEY_COMPLETE_EVENT                    = 0x09
HCI_LINK_KEY_TYPE_CHANGED_EVENT                                  = 0x0A
HCI_READ_REMOTE_SUPPORTED_FEATURES_COMPLETE_EVENT                = 0x0B
HCI_READ_REMOTE_VERSION_INFORMATION_COMPLETE_EVENT               = 0x0C
HCI_QOS_SETUP_COMPLETE_EVENT                                     = 0x0D
HCI_COMMAND_COMPLETE_EVENT                                       = 0x0E
HCI_COMMAND_STATUS_EVENT                                         = 0x0F
HCI_HARDWARE_ERROR_EVENT                                         = 0x10
HCI_FLUSH_OCCURRED_EVENT                                         = 0x11
HCI_ROLE_CHANGE_EVENT                                            = 0x12
HCI_NUMBER_OF_COMPLETED_PACKETS_EVENT                            = 0x13
HCI_MODE_CHANGE_EVENT                                            = 0x14
HCI_RETURN_LINK_KEYS_EVENT                                       = 0x15
HCI_PIN_CODE_REQUEST_EVENT                                       = 0x16
HCI_LINK_KEY_REQUEST_EVENT                                       = 0x17
HCI_LINK_KEY_NOTIFICATION_EVENT                                  = 0x18
HCI_LOOPBACK_COMMAND_EVENT                                       = 0x19
HCI_DATA_BUFFER_OVERFLOW_EVENT                                   = 0x1A
HCI_MAX_SLOTS_CHANGE_EVENT                                       = 0x1B
HCI_READ_CLOCK_OFFSET_COMPLETE_EVENT                             = 0x1C
HCI_CONNECTION_PACKET_TYPE_CHANGED_EVENT                         = 0x1D
HCI_QOS_VIOLATION_EVENT                                          = 0x1E
HCI_PAGE_SCAN_REPETITION_MODE_CHANGE_EVENT                       = 0x20
HCI_FLOW_SPECIFICATION_COMPLETE_EVENT                            = 0x21
HCI_INQUIRY_RESULT_WITH_RSSI_EVENT                               = 0x22
HCI_READ_REMOTE_EXTENDED_FEATURES_COMPLETE_EVENT                 = 0x23
HCI_SYNCHRONOUS_CONNECTION_COMPLETE_EVENT                        = 0x2C
HCI_SYNCHRONOUS_CONNECTION_CHANGED_EVENT                         = 0x2D
HCI_SNIFF_SUBRATING_EVENT                                        = 0x2E
HCI_EXTENDED_INQUIRY_RESULT_EVENT                                = 0x2F
HCI_ENCRYPTION_KEY_REFRESH_COMPLETE_EVENT                        = 0x30
HCI_IO_CAPABILITY_REQUEST_EVENT                                  = 0x31
HCI_IO_CAPABILITY_RESPONSE_EVENT                                 = 0x32
HCI_USER_CONFIRMATION_REQUEST_EVENT                              = 0x33
HCI_USER_PASSKEY_REQUEST_EVENT                                   = 0x34
HCI_REMOTE_OOB_DATA_REQUEST_EVENT                                = 0x35
HCI_SIMPLE_PAIRING_COMPLETE_EVENT                                = 0x36
HCI_LINK_SUPERVISION_TIMEOUT_CHANGED_EVENT                       = 0x38
HCI_ENHANCED_FLUSH_COMPLETE_EVENT                                = 0x39
HCI_USER_PASSKEY_NOTIFICATION_EVENT                              = 0x3B
HCI_KEYPRESS_NOTIFICATION_EVENT                                  = 0x3C
HCI_REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION_EVENT            = 0x3D
HCI_LE_META_EVENT                                                = 0x3E
HCI_NUMBER_OF_COMPLETED_DATA_BLOCKS_EVENT                        = 0x48
HCI_TRIGGERED_CLOCK_CAPTURE_EVENT                                = 0X4E
HCI_SYNCHRONIZATION_TRAIN_COMPLETE_EVENT                         = 0X4F
HCI_SYNCHRONIZATION_TRAIN_RECEIVED_EVENT                         = 0X50
HCI_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE_EVENT            = 0X51
HCI_CONNECTIONLESS_PERIPHERAL_BROADCAST_TIMEOUT_EVENT            = 0X52
HCI_TRUNCATED_PAGE_COMPLETE_EVENT                                = 0X53
HCI_PERIPHERAL_PAGE_RESPONSE_TIMEOUT_EVENT                       = 0X54
HCI_CONNECTIONLESS_PERIPHERAL_BROADCAST_CHANNEL_MAP_CHANGE_EVENT = 0X55
HCI_INQUIRY_RESPONSE_NOTIFICATION_EVENT                          = 0X56
HCI_AUTHENTICATED_PAYLOAD_TIMEOUT_EXPIRED_EVENT                  = 0X57
HCI_SAM_STATUS_CHANGE_EVENT                                      = 0X58

HCI_VENDOR_EVENT = 0xFF


# HCI Subevent Codes
HCI_LE_CONNECTION_COMPLETE_EVENT                         = 0x01
HCI_LE_ADVERTISING_REPORT_EVENT                          = 0x02
HCI_LE_CONNECTION_UPDATE_COMPLETE_EVENT                  = 0x03
HCI_LE_READ_REMOTE_FEATURES_COMPLETE_EVENT               = 0x04
HCI_LE_LONG_TERM_KEY_REQUEST_EVENT                       = 0x05
HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_EVENT         = 0x06
HCI_LE_DATA_LENGTH_CHANGE_EVENT                          = 0x07
HCI_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE_EVENT        = 0x08
HCI_LE_GENERATE_DHKEY_COMPLETE_EVENT                     = 0x09
HCI_LE_ENHANCED_CONNECTION_COMPLETE_EVENT                = 0x0A
HCI_LE_DIRECTED_ADVERTISING_REPORT_EVENT                 = 0x0B
HCI_LE_PHY_UPDATE_COMPLETE_EVENT                         = 0x0C
HCI_LE_EXTENDED_ADVERTISING_REPORT_EVENT                 = 0x0D
HCI_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_EVENT       = 0x0E
HCI_LE_PERIODIC_ADVERTISING_REPORT_EVENT                 = 0x0F
HCI_LE_PERIODIC_ADVERTISING_SYNC_LOST_EVENT              = 0x10
HCI_LE_SCAN_TIMEOUT_EVENT                                = 0x11
HCI_LE_ADVERTISING_SET_TERMINATED_EVENT                  = 0x12
HCI_LE_SCAN_REQUEST_RECEIVED_EVENT                       = 0x13
HCI_LE_CHANNEL_SELECTION_ALGORITHM_EVENT                 = 0x14
HCI_LE_CONNECTIONLESS_IQ_REPORT_EVENT                    = 0X15
HCI_LE_CONNECTION_IQ_REPORT_EVENT                        = 0X16
HCI_LE_CTE_REQUEST_FAILED_EVENT                          = 0X17
HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_EVENT = 0X18
HCI_LE_CIS_ESTABLISHED_EVENT                             = 0X19
HCI_LE_CIS_REQUEST_EVENT                                 = 0X1A
HCI_LE_CREATE_BIG_COMPLETE_EVENT                         = 0X1B
HCI_LE_TERMINATE_BIG_COMPLETE_EVENT                      = 0X1C
HCI_LE_BIG_SYNC_ESTABLISHED_EVENT                        = 0X1D
HCI_LE_BIG_SYNC_LOST_EVENT                               = 0X1E
HCI_LE_REQUEST_PEER_SCA_COMPLETE_EVENT                   = 0X1F
HCI_LE_PATH_LOSS_THRESHOLD_EVENT                         = 0X20
HCI_LE_TRANSMIT_POWER_REPORTING_EVENT                    = 0X21
HCI_LE_BIGINFO_ADVERTISING_REPORT_EVENT                  = 0X22
HCI_LE_SUBRATE_CHANGE_EVENT                              = 0X23


# HCI Command
HCI_INQUIRY_COMMAND                                                      = hci_command_op_code(0x01, 0x0001)
HCI_INQUIRY_CANCEL_COMMAND                                               = hci_command_op_code(0x01, 0x0002)
HCI_PERIODIC_INQUIRY_MODE_COMMAND                                        = hci_command_op_code(0x01, 0x0003)
HCI_EXIT_PERIODIC_INQUIRY_MODE_COMMAND                                   = hci_command_op_code(0x01, 0x0004)
HCI_CREATE_CONNECTION_COMMAND                                            = hci_command_op_code(0x01, 0x0005)
HCI_DISCONNECT_COMMAND                                                   = hci_command_op_code(0x01, 0x0006)
HCI_CREATE_CONNECTION_CANCEL_COMMAND                                     = hci_command_op_code(0x01, 0x0008)
HCI_ACCEPT_CONNECTION_REQUEST_COMMAND                                    = hci_command_op_code(0x01, 0x0009)
HCI_REJECT_CONNECTION_REQUEST_COMMAND                                    = hci_command_op_code(0x01, 0x000A)
HCI_LINK_KEY_REQUEST_REPLY_COMMAND                                       = hci_command_op_code(0x01, 0x000B)
HCI_LINK_KEY_REQUEST_NEGATIVE_REPLY_COMMAND                              = hci_command_op_code(0x01, 0x000C)
HCI_PIN_CODE_REQUEST_REPLY_COMMAND                                       = hci_command_op_code(0x01, 0x000D)
HCI_PIN_CODE_REQUEST_NEGATIVE_REPLY_COMMAND                              = hci_command_op_code(0x01, 0x000E)
HCI_CHANGE_CONNECTION_PACKET_TYPE_COMMAND                                = hci_command_op_code(0x01, 0x000F)
HCI_AUTHENTICATION_REQUESTED_COMMAND                                     = hci_command_op_code(0x01, 0x0011)
HCI_SET_CONNECTION_ENCRYPTION_COMMAND                                    = hci_command_op_code(0x01, 0x0013)
HCI_CHANGE_CONNECTION_LINK_KEY_COMMAND                                   = hci_command_op_code(0x01, 0x0015)
HCI_LINK_KEY_SELECTION_COMMAND                                           = hci_command_op_code(0x01, 0x0017)
HCI_REMOTE_NAME_REQUEST_COMMAND                                          = hci_command_op_code(0x01, 0x0019)
HCI_REMOTE_NAME_REQUEST_CANCEL_COMMAND                                   = hci_command_op_code(0x01, 0x001A)
HCI_READ_REMOTE_SUPPORTED_FEATURES_COMMAND                               = hci_command_op_code(0x01, 0x001B)
HCI_READ_REMOTE_EXTENDED_FEATURES_COMMAND                                = hci_command_op_code(0x01, 0x001C)
HCI_READ_REMOTE_VERSION_INFORMATION_COMMAND                              = hci_command_op_code(0x01, 0x001D)
HCI_READ_CLOCK_OFFSET_COMMAND                                            = hci_command_op_code(0x01, 0x001F)
HCI_READ_LMP_HANDLE_COMMAND                                              = hci_command_op_code(0x01, 0x0020)
HCI_SETUP_SYNCHRONOUS_CONNECTION_COMMAND                                 = hci_command_op_code(0x01, 0x0028)
HCI_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND                        = hci_command_op_code(0x01, 0x0029)
HCI_REJECT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND                        = hci_command_op_code(0x01, 0x002A)
HCI_IO_CAPABILITY_REQUEST_REPLY_COMMAND                                  = hci_command_op_code(0x01, 0x002B)
HCI_USER_CONFIRMATION_REQUEST_REPLY_COMMAND                              = hci_command_op_code(0x01, 0x002C)
HCI_USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY_COMMAND                     = hci_command_op_code(0x01, 0x002D)
HCI_USER_PASSKEY_REQUEST_REPLY_COMMAND                                   = hci_command_op_code(0x01, 0x002E)
HCI_USER_PASSKEY_REQUEST_NEGATIVE_REPLY_COMMAND                          = hci_command_op_code(0x01, 0x002F)
HCI_REMOTE_OOB_DATA_REQUEST_REPLY_COMMAND                                = hci_command_op_code(0x01, 0x0030)
HCI_REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY_COMMAND                       = hci_command_op_code(0x01, 0x0033)
HCI_IO_CAPABILITY_REQUEST_NEGATIVE_REPLY_COMMAND                         = hci_command_op_code(0x01, 0x0034)
HCI_ENHANCED_SETUP_SYNCHRONOUS_CONNECTION_COMMAND                        = hci_command_op_code(0x01, 0x003D)
HCI_ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND               = hci_command_op_code(0x01, 0x003E)
HCI_TRUNCATED_PAGE_COMMAND                                               = hci_command_op_code(0x01, 0x003F)
HCI_TRUNCATED_PAGE_CANCEL_COMMAND                                        = hci_command_op_code(0x01, 0x0040)
HCI_SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_COMMAND                      = hci_command_op_code(0x01, 0x0041)
HCI_SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE_COMMAND              = hci_command_op_code(0x01, 0x0042)
HCI_START_SYNCHRONIZATION_TRAIN_COMMAND                                  = hci_command_op_code(0x01, 0x0043)
HCI_RECEIVE_SYNCHRONIZATION_TRAIN_COMMAND                                = hci_command_op_code(0x01, 0x0044)
HCI_REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY_COMMAND                       = hci_command_op_code(0x01, 0x0045)
HCI_HOLD_MODE_COMMAND                                                    = hci_command_op_code(0x02, 0x0001)
HCI_SNIFF_MODE_COMMAND                                                   = hci_command_op_code(0x02, 0x0003)
HCI_EXIT_SNIFF_MODE_COMMAND                                              = hci_command_op_code(0x02, 0x0004)
HCI_QOS_SETUP_COMMAND                                                    = hci_command_op_code(0x02, 0x0007)
HCI_ROLE_DISCOVERY_COMMAND                                               = hci_command_op_code(0x02, 0x0009)
HCI_SWITCH_ROLE_COMMAND                                                  = hci_command_op_code(0x02, 0x000B)
HCI_READ_LINK_POLICY_SETTINGS_COMMAND                                    = hci_command_op_code(0x02, 0x000C)
HCI_WRITE_LINK_POLICY_SETTINGS_COMMAND                                   = hci_command_op_code(0x02, 0x000D)
HCI_READ_DEFAULT_LINK_POLICY_SETTINGS_COMMAND                            = hci_command_op_code(0x02, 0x000E)
HCI_WRITE_DEFAULT_LINK_POLICY_SETTINGS_COMMAND                           = hci_command_op_code(0x02, 0x000F)
HCI_FLOW_SPECIFICATION_COMMAND                                           = hci_command_op_code(0x02, 0x0010)
HCI_SNIFF_SUBRATING_COMMAND                                              = hci_command_op_code(0x02, 0x0011)
HCI_SET_EVENT_MASK_COMMAND                                               = hci_command_op_code(0x03, 0x0001)
HCI_RESET_COMMAND                                                        = hci_command_op_code(0x03, 0x0003)
HCI_SET_EVENT_FILTER_COMMAND                                             = hci_command_op_code(0x03, 0x0005)
HCI_FLUSH_COMMAND                                                        = hci_command_op_code(0x03, 0x0008)
HCI_READ_PIN_TYPE_COMMAND                                                = hci_command_op_code(0x03, 0x0009)
HCI_WRITE_PIN_TYPE_COMMAND                                               = hci_command_op_code(0x03, 0x000A)
HCI_READ_STORED_LINK_KEY_COMMAND                                         = hci_command_op_code(0x03, 0x000D)
HCI_WRITE_STORED_LINK_KEY_COMMAND                                        = hci_command_op_code(0x03, 0x0011)
HCI_DELETE_STORED_LINK_KEY_COMMAND                                       = hci_command_op_code(0x03, 0x0012)
HCI_WRITE_LOCAL_NAME_COMMAND                                             = hci_command_op_code(0x03, 0x0013)
HCI_READ_LOCAL_NAME_COMMAND                                              = hci_command_op_code(0x03, 0x0014)
HCI_READ_CONNECTION_ACCEPT_TIMEOUT_COMMAND                               = hci_command_op_code(0x03, 0x0015)
HCI_WRITE_CONNECTION_ACCEPT_TIMEOUT_COMMAND                              = hci_command_op_code(0x03, 0x0016)
HCI_READ_PAGE_TIMEOUT_COMMAND                                            = hci_command_op_code(0x03, 0x0017)
HCI_WRITE_PAGE_TIMEOUT_COMMAND                                           = hci_command_op_code(0x03, 0x0018)
HCI_READ_SCAN_ENABLE_COMMAND                                             = hci_command_op_code(0x03, 0x0019)
HCI_WRITE_SCAN_ENABLE_COMMAND                                            = hci_command_op_code(0x03, 0x001A)
HCI_READ_PAGE_SCAN_ACTIVITY_COMMAND                                      = hci_command_op_code(0x03, 0x001B)
HCI_WRITE_PAGE_SCAN_ACTIVITY_COMMAND                                     = hci_command_op_code(0x03, 0x001C)
HCI_READ_INQUIRY_SCAN_ACTIVITY_COMMAND                                   = hci_command_op_code(0x03, 0x001D)
HCI_WRITE_INQUIRY_SCAN_ACTIVITY_COMMAND                                  = hci_command_op_code(0x03, 0x001E)
HCI_READ_AUTHENTICATION_ENABLE_COMMAND                                   = hci_command_op_code(0x03, 0x001F)
HCI_WRITE_AUTHENTICATION_ENABLE_COMMAND                                  = hci_command_op_code(0x03, 0x0020)
HCI_READ_CLASS_OF_DEVICE_COMMAND                                         = hci_command_op_code(0x03, 0x0023)
HCI_WRITE_CLASS_OF_DEVICE_COMMAND                                        = hci_command_op_code(0x03, 0x0024)
HCI_READ_VOICE_SETTING_COMMAND                                           = hci_command_op_code(0x03, 0x0025)
HCI_WRITE_VOICE_SETTING_COMMAND                                          = hci_command_op_code(0x03, 0x0026)
HCI_READ_AUTOMATIC_FLUSH_TIMEOUT_COMMAND                                 = hci_command_op_code(0x03, 0x0027)
HCI_WRITE_AUTOMATIC_FLUSH_TIMEOUT_COMMAND                                = hci_command_op_code(0x03, 0x0028)
HCI_READ_NUM_BROADCAST_RETRANSMISSIONS_COMMAND                           = hci_command_op_code(0x03, 0x0029)
HCI_WRITE_NUM_BROADCAST_RETRANSMISSIONS_COMMAND                          = hci_command_op_code(0x03, 0x002A)
HCI_READ_HOLD_MODE_ACTIVITY_COMMAND                                      = hci_command_op_code(0x03, 0x002B)
HCI_WRITE_HOLD_MODE_ACTIVITY_COMMAND                                     = hci_command_op_code(0x03, 0x002C)
HCI_READ_TRANSMIT_POWER_LEVEL_COMMAND                                    = hci_command_op_code(0x03, 0x002D)
HCI_READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE_COMMAND                         = hci_command_op_code(0x03, 0x002E)
HCI_WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE_COMMAND                        = hci_command_op_code(0x03, 0x002F)
HCI_SET_CONTROLLER_TO_HOST_FLOW_CONTROL_COMMAND                          = hci_command_op_code(0x03, 0x0031)
HCI_HOST_BUFFER_SIZE_COMMAND                                             = hci_command_op_code(0x03, 0x0033)
HCI_HOST_NUMBER_OF_COMPLETED_PACKETS_COMMAND                             = hci_command_op_code(0x03, 0x0035)
HCI_READ_LINK_SUPERVISION_TIMEOUT_COMMAND                                = hci_command_op_code(0x03, 0x0036)
HCI_WRITE_LINK_SUPERVISION_TIMEOUT_COMMAND                               = hci_command_op_code(0x03, 0x0037)
HCI_READ_NUMBER_OF_SUPPORTED_IAC_COMMAND                                 = hci_command_op_code(0x03, 0x0038)
HCI_READ_CURRENT_IAC_LAP_COMMAND                                         = hci_command_op_code(0x03, 0x0039)
HCI_WRITE_CURRENT_IAC_LAP_COMMAND                                        = hci_command_op_code(0x03, 0x003A)
HCI_SET_AFH_HOST_CHANNEL_CLASSIFICATION_COMMAND                          = hci_command_op_code(0x03, 0x003F)
HCI_READ_INQUIRY_SCAN_TYPE_COMMAND                                       = hci_command_op_code(0x03, 0x0042)
HCI_WRITE_INQUIRY_SCAN_TYPE_COMMAND                                      = hci_command_op_code(0x03, 0x0043)
HCI_READ_INQUIRY_MODE_COMMAND                                            = hci_command_op_code(0x03, 0x0044)
HCI_WRITE_INQUIRY_MODE_COMMAND                                           = hci_command_op_code(0x03, 0x0045)
HCI_READ_PAGE_SCAN_TYPE_COMMAND                                          = hci_command_op_code(0x03, 0x0046)
HCI_WRITE_PAGE_SCAN_TYPE_COMMAND                                         = hci_command_op_code(0x03, 0x0047)
HCI_READ_AFH_CHANNEL_ASSESSMENT_MODE_COMMAND                             = hci_command_op_code(0x03, 0x0048)
HCI_WRITE_AFH_CHANNEL_ASSESSMENT_MODE_COMMAND                            = hci_command_op_code(0x03, 0x0049)
HCI_READ_EXTENDED_INQUIRY_RESPONSE_COMMAND                               = hci_command_op_code(0x03, 0x0051)
HCI_WRITE_EXTENDED_INQUIRY_RESPONSE_COMMAND                              = hci_command_op_code(0x03, 0x0052)
HCI_REFRESH_ENCRYPTION_KEY_COMMAND                                       = hci_command_op_code(0x03, 0x0053)
HCI_READ_SIMPLE_PAIRING_MODE_COMMAND                                     = hci_command_op_code(0x03, 0x0055)
HCI_WRITE_SIMPLE_PAIRING_MODE_COMMAND                                    = hci_command_op_code(0x03, 0x0056)
HCI_READ_LOCAL_OOB_DATA_COMMAND                                          = hci_command_op_code(0x03, 0x0057)
HCI_READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL_COMMAND                   = hci_command_op_code(0x03, 0x0058)
HCI_WRITE_INQUIRY_TRANSMIT_POWER_LEVEL_COMMAND                           = hci_command_op_code(0x03, 0x0059)
HCI_READ_DEFAULT_ERRONEOUS_DATA_REPORTING_COMMAND                        = hci_command_op_code(0x03, 0x005A)
HCI_WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING_COMMAND                       = hci_command_op_code(0x03, 0x005B)
HCI_ENHANCED_FLUSH_COMMAND                                               = hci_command_op_code(0x03, 0x005F)
HCI_SEND_KEYPRESS_NOTIFICATION_COMMAND                                   = hci_command_op_code(0x03, 0x0060)
HCI_SET_EVENT_MASK_PAGE_2_COMMAND                                        = hci_command_op_code(0x03, 0x0063)
HCI_READ_FLOW_CONTROL_MODE_COMMAND                                       = hci_command_op_code(0x03, 0x0066)
HCI_WRITE_FLOW_CONTROL_MODE_COMMAND                                      = hci_command_op_code(0x03, 0x0067)
HCI_READ_ENHANCED_TRANSMIT_POWER_LEVEL_COMMAND                           = hci_command_op_code(0x03, 0x0068)
HCI_READ_LE_HOST_SUPPORT_COMMAND                                         = hci_command_op_code(0x03, 0x006C)
HCI_WRITE_LE_HOST_SUPPORT_COMMAND                                        = hci_command_op_code(0x03, 0x006D)
HCI_SET_MWS_CHANNEL_PARAMETERS_COMMAND                                   = hci_command_op_code(0x03, 0x006E)
HCI_SET_EXTERNAL_FRAME_CONFIGURATION_COMMAND                             = hci_command_op_code(0x03, 0x006F)
HCI_SET_MWS_SIGNALING_COMMAND                                            = hci_command_op_code(0x03, 0x0070)
HCI_SET_MWS_TRANSPORT_LAYER_COMMAND                                      = hci_command_op_code(0x03, 0x0071)
HCI_SET_MWS_SCAN_FREQUENCY_TABLE_COMMAND                                 = hci_command_op_code(0x03, 0x0072)
HCI_SET_MWS_PATTERN_CONFIGURATION_COMMAND                                = hci_command_op_code(0x03, 0x0073)
HCI_SET_RESERVED_LT_ADDR_COMMAND                                         = hci_command_op_code(0x03, 0x0074)
HCI_DELETE_RESERVED_LT_ADDR_COMMAND                                      = hci_command_op_code(0x03, 0x0075)
HCI_SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA_COMMAND                 = hci_command_op_code(0x03, 0x0076)
HCI_READ_SYNCHRONIZATION_TRAIN_PARAMETERS_COMMAND                        = hci_command_op_code(0x03, 0x0077)
HCI_WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS_COMMAND                       = hci_command_op_code(0x03, 0x0078)
HCI_READ_SECURE_CONNECTIONS_HOST_SUPPORT_COMMAND                         = hci_command_op_code(0x03, 0x0079)
HCI_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT_COMMAND                        = hci_command_op_code(0x03, 0x007A)
HCI_READ_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND                           = hci_command_op_code(0x03, 0x007B)
HCI_WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND                          = hci_command_op_code(0x03, 0x007C)
HCI_READ_LOCAL_OOB_EXTENDED_DATA_COMMAND                                 = hci_command_op_code(0x03, 0x007D)
HCI_READ_EXTENDED_PAGE_TIMEOUT_COMMAND                                   = hci_command_op_code(0x03, 0x007E)
HCI_WRITE_EXTENDED_PAGE_TIMEOUT_COMMAND                                  = hci_command_op_code(0x03, 0x007F)
HCI_READ_EXTENDED_INQUIRY_LENGTH_COMMAND                                 = hci_command_op_code(0x03, 0x0080)
HCI_WRITE_EXTENDED_INQUIRY_LENGTH_COMMAND                                = hci_command_op_code(0x03, 0x0081)
HCI_SET_ECOSYSTEM_BASE_INTERVAL_COMMAND                                  = hci_command_op_code(0x03, 0x0082)
HCI_CONFIGURE_DATA_PATH_COMMAND                                          = hci_command_op_code(0x03, 0x0083)
HCI_SET_MIN_ENCRYPTION_KEY_SIZE_COMMAND                                  = hci_command_op_code(0x03, 0x0084)
HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND                               = hci_command_op_code(0x04, 0x0001)
HCI_READ_LOCAL_SUPPORTED_COMMANDS_COMMAND                                = hci_command_op_code(0x04, 0x0002)
HCI_READ_LOCAL_SUPPORTED_FEATURES_COMMAND                                = hci_command_op_code(0x04, 0x0003)
HCI_READ_LOCAL_EXTENDED_FEATURES_COMMAND                                 = hci_command_op_code(0x04, 0x0004)
HCI_READ_BUFFER_SIZE_COMMAND                                             = hci_command_op_code(0x04, 0x0005)
HCI_READ_BD_ADDR_COMMAND                                                 = hci_command_op_code(0x04, 0x0009)
HCI_READ_DATA_BLOCK_SIZE_COMMAND                                         = hci_command_op_code(0x04, 0x000A)
HCI_READ_LOCAL_SUPPORTED_CODECS_COMMAND                                  = hci_command_op_code(0x04, 0x000B)
HCI_READ_LOCAL_SIMPLE_PAIRING_OPTIONS_COMMAND                            = hci_command_op_code(0x04, 0x000C)
HCI_READ_LOCAL_SUPPORTED_CODECS_V2_COMMAND                               = hci_command_op_code(0x04, 0x000D)
HCI_READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES_COMMAND                      = hci_command_op_code(0x04, 0x000E)
HCI_READ_LOCAL_SUPPORTED_CONTROLLER_DELAY_COMMAND                        = hci_command_op_code(0x04, 0x000F)
HCI_READ_FAILED_CONTACT_COUNTER_COMMAND                                  = hci_command_op_code(0x05, 0x0001)
HCI_RESET_FAILED_CONTACT_COUNTER_COMMAND                                 = hci_command_op_code(0x05, 0x0002)
HCI_READ_LINK_QUALITY_COMMAND                                            = hci_command_op_code(0x05, 0x0003)
HCI_READ_RSSI_COMMAND                                                    = hci_command_op_code(0x05, 0x0005)
HCI_READ_AFH_CHANNEL_MAP_COMMAND                                         = hci_command_op_code(0x05, 0x0006)
HCI_READ_CLOCK_COMMAND                                                   = hci_command_op_code(0x05, 0x0007)
HCI_READ_ENCRYPTION_KEY_SIZE_COMMAND                                     = hci_command_op_code(0x05, 0x0008)
HCI_GET_MWS_TRANSPORT_LAYER_CONFIGURATION_COMMAND                        = hci_command_op_code(0x05, 0x000C)
HCI_SET_TRIGGERED_CLOCK_CAPTURE_COMMAND                                  = hci_command_op_code(0x05, 0x000D)
HCI_READ_LOOPBACK_MODE_COMMAND                                           = hci_command_op_code(0x06, 0x0001)
HCI_WRITE_LOOPBACK_MODE_COMMAND                                          = hci_command_op_code(0x06, 0x0002)
HCI_ENABLE_DEVICE_UNDER_TEST_MODE_COMMAND                                = hci_command_op_code(0x06, 0x0003)
HCI_WRITE_SIMPLE_PAIRING_DEBUG_MODE_COMMAND                              = hci_command_op_code(0x06, 0x0004)
HCI_WRITE_SECURE_CONNECTIONS_TEST_MODE_COMMAND                           = hci_command_op_code(0x06, 0x000A)
HCI_LE_SET_EVENT_MASK_COMMAND                                            = hci_command_op_code(0x08, 0x0001)
HCI_LE_READ_BUFFER_SIZE_COMMAND                                          = hci_command_op_code(0x08, 0x0002)
HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND                             = hci_command_op_code(0x08, 0x0003)
HCI_LE_SET_RANDOM_ADDRESS_COMMAND                                        = hci_command_op_code(0x08, 0x0005)
HCI_LE_SET_ADVERTISING_PARAMETERS_COMMAND                                = hci_command_op_code(0x08, 0x0006)
HCI_LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER_COMMAND                = hci_command_op_code(0x08, 0x0007)
HCI_LE_SET_ADVERTISING_DATA_COMMAND                                      = hci_command_op_code(0x08, 0x0008)
HCI_LE_SET_SCAN_RESPONSE_DATA_COMMAND                                    = hci_command_op_code(0x08, 0x0009)
HCI_LE_SET_ADVERTISING_ENABLE_COMMAND                                    = hci_command_op_code(0x08, 0x000A)
HCI_LE_SET_SCAN_PARAMETERS_COMMAND                                       = hci_command_op_code(0x08, 0x000B)
HCI_LE_SET_SCAN_ENABLE_COMMAND                                           = hci_command_op_code(0x08, 0x000C)
HCI_LE_CREATE_CONNECTION_COMMAND                                         = hci_command_op_code(0x08, 0x000D)
HCI_LE_CREATE_CONNECTION_CANCEL_COMMAND                                  = hci_command_op_code(0x08, 0x000E)
HCI_LE_READ_FILTER_ACCEPT_LIST_SIZE_COMMAND                              = hci_command_op_code(0x08, 0x000F)
HCI_LE_CLEAR_FILTER_ACCEPT_LIST_COMMAND                                  = hci_command_op_code(0x08, 0x0010)
HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST_COMMAND                          = hci_command_op_code(0x08, 0x0011)
HCI_LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST_COMMAND                     = hci_command_op_code(0x08, 0x0012)
HCI_LE_CONNECTION_UPDATE_COMMAND                                         = hci_command_op_code(0x08, 0x0013)
HCI_LE_SET_HOST_CHANNEL_CLASSIFICATION_COMMAND                           = hci_command_op_code(0x08, 0x0014)
HCI_LE_READ_CHANNEL_MAP_COMMAND                                          = hci_command_op_code(0x08, 0x0015)
HCI_LE_READ_REMOTE_FEATURES_COMMAND                                      = hci_command_op_code(0x08, 0x0016)
HCI_LE_ENCRYPT_COMMAND                                                   = hci_command_op_code(0x08, 0x0017)
HCI_LE_RAND_COMMAND                                                      = hci_command_op_code(0x08, 0x0018)
HCI_LE_ENABLE_ENCRYPTION_COMMAND                                         = hci_command_op_code(0x08, 0x0019)
HCI_LE_LONG_TERM_KEY_REQUEST_REPLY_COMMAND                               = hci_command_op_code(0x08, 0x001A)
HCI_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY_COMMAND                      = hci_command_op_code(0x08, 0x001B)
HCI_LE_READ_SUPPORTED_STATES_COMMAND                                     = hci_command_op_code(0x08, 0x001C)
HCI_LE_RECEIVER_TEST_COMMAND                                             = hci_command_op_code(0x08, 0x001D)
HCI_LE_TRANSMITTER_TEST_COMMAND                                          = hci_command_op_code(0x08, 0x001E)
HCI_LE_TEST_END_COMMAND                                                  = hci_command_op_code(0x08, 0x001F)
HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY_COMMAND                 = hci_command_op_code(0x08, 0x0020)
HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY_COMMAND        = hci_command_op_code(0x08, 0x0021)
HCI_LE_SET_DATA_LENGTH_COMMAND                                           = hci_command_op_code(0x08, 0x0022)
HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND                        = hci_command_op_code(0x08, 0x0023)
HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND                       = hci_command_op_code(0x08, 0x0024)
HCI_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMMAND                               = hci_command_op_code(0x08, 0x0025)
HCI_LE_GENERATE_DHKEY_COMMAND                                            = hci_command_op_code(0x08, 0x0026)
HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND                              = hci_command_op_code(0x08, 0x0027)
HCI_LE_REMOVE_DEVICE_FROM_RESOLVING_LIST_COMMAND                         = hci_command_op_code(0x08, 0x0028)
HCI_LE_CLEAR_RESOLVING_LIST_COMMAND                                      = hci_command_op_code(0x08, 0x0029)
HCI_LE_READ_RESOLVING_LIST_SIZE_COMMAND                                  = hci_command_op_code(0x08, 0x002A)
HCI_LE_READ_PEER_RESOLVABLE_ADDRESS_COMMAND                              = hci_command_op_code(0x08, 0x002B)
HCI_LE_READ_LOCAL_RESOLVABLE_ADDRESS_COMMAND                             = hci_command_op_code(0x08, 0x002C)
HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE_COMMAND                             = hci_command_op_code(0x08, 0x002D)
HCI_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT_COMMAND                    = hci_command_op_code(0x08, 0x002E)
HCI_LE_READ_MAXIMUM_DATA_LENGTH_COMMAND                                  = hci_command_op_code(0x08, 0x002F)
HCI_LE_READ_PHY_COMMAND                                                  = hci_command_op_code(0x08, 0x0030)
HCI_LE_SET_DEFAULT_PHY_COMMAND                                           = hci_command_op_code(0x08, 0x0031)
HCI_LE_SET_PHY_COMMAND                                                   = hci_command_op_code(0x08, 0x0032)
HCI_LE_RECEIVER_TEST_V2_COMMAND                                          = hci_command_op_code(0x08, 0x0033)
HCI_LE_TRANSMITTER_TEST_V2_COMMAND                                       = hci_command_op_code(0x08, 0x0034)
HCI_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_COMMAND                        = hci_command_op_code(0x08, 0x0035)
HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_COMMAND                       = hci_command_op_code(0x08, 0x0036)
HCI_LE_SET_EXTENDED_ADVERTISING_DATA_COMMAND                             = hci_command_op_code(0x08, 0x0037)
HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA_COMMAND                           = hci_command_op_code(0x08, 0x0038)
HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE_COMMAND                           = hci_command_op_code(0x08, 0x0039)
HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND                      = hci_command_op_code(0x08, 0x003A)
HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND                 = hci_command_op_code(0x08, 0x003B)
HCI_LE_REMOVE_ADVERTISING_SET_COMMAND                                    = hci_command_op_code(0x08, 0x003C)
HCI_LE_CLEAR_ADVERTISING_SETS_COMMAND                                    = hci_command_op_code(0x08, 0x003D)
HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_COMMAND                       = hci_command_op_code(0x08, 0x003E)
HCI_LE_SET_PERIODIC_ADVERTISING_DATA_COMMAND                             = hci_command_op_code(0x08, 0x003F)
HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE_COMMAND                           = hci_command_op_code(0x08, 0x0040)
HCI_LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND                              = hci_command_op_code(0x08, 0x0041)
HCI_LE_SET_EXTENDED_SCAN_ENABLE_COMMAND                                  = hci_command_op_code(0x08, 0x0042)
HCI_LE_EXTENDED_CREATE_CONNECTION_COMMAND                                = hci_command_op_code(0x08, 0x0043)
HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_COMMAND                          = hci_command_op_code(0x08, 0x0044)
HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL_COMMAND                   = hci_command_op_code(0x08, 0x0045)
HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC_COMMAND                       = hci_command_op_code(0x08, 0x0046)
HCI_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST_COMMAND                    = hci_command_op_code(0x08, 0x0047)
HCI_LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST_COMMAND               = hci_command_op_code(0x08, 0x0048)
HCI_LE_CLEAR_PERIODIC_ADVERTISER_LIST_COMMAND                            = hci_command_op_code(0x08, 0x0049)
HCI_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE_COMMAND                        = hci_command_op_code(0x08, 0x004A)
HCI_LE_READ_TRANSMIT_POWER_COMMAND                                       = hci_command_op_code(0x08, 0x004B)
HCI_LE_READ_RF_PATH_COMPENSATION_COMMAND                                 = hci_command_op_code(0x08, 0x004C)
HCI_LE_WRITE_RF_PATH_COMPENSATION_COMMAND                                = hci_command_op_code(0x08, 0x004D)
HCI_LE_SET_PRIVACY_MODE_COMMAND                                          = hci_command_op_code(0x08, 0x004E)
HCI_LE_RECEIVER_TEST_V3_COMMAND                                          = hci_command_op_code(0x08, 0x004F)
HCI_LE_TRANSMITTER_TEST_V3_COMMAND                                       = hci_command_op_code(0x08, 0x0050)
HCI_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS_COMMAND                = hci_command_op_code(0x08, 0x0051)
HCI_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE_COMMAND                    = hci_command_op_code(0x08, 0x0052)
HCI_LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE_COMMAND                     = hci_command_op_code(0x08, 0x0053)
HCI_LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS_COMMAND                     = hci_command_op_code(0x08, 0x0054)
HCI_LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS_COMMAND                    = hci_command_op_code(0x08, 0x0055)
HCI_LE_CONNECTION_CTE_REQUEST_ENABLE_COMMAND                             = hci_command_op_code(0x08, 0x0056)
HCI_LE_CONNECTION_CTE_RESPONSE_ENABLE_COMMAND                            = hci_command_op_code(0x08, 0x0057)
HCI_LE_READ_ANTENNA_INFORMATION_COMMAND                                  = hci_command_op_code(0x08, 0x0058)
HCI_LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE_COMMAND                   = hci_command_op_code(0x08, 0x0059)
HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_COMMAND                        = hci_command_op_code(0x08, 0x005A)
HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER_COMMAND                    = hci_command_op_code(0x08, 0x005B)
HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_COMMAND         = hci_command_op_code(0x08, 0x005C)
HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_COMMAND = hci_command_op_code(0x08, 0x005D)
HCI_LE_GENERATE_DHKEY_V2_COMMAND                                         = hci_command_op_code(0x08, 0x005E)
HCI_LE_MODIFY_SLEEP_CLOCK_ACCURACY_COMMAND                               = hci_command_op_code(0x08, 0x005F)
HCI_LE_READ_BUFFER_SIZE_V2_COMMAND                                       = hci_command_op_code(0x08, 0x0060)
HCI_LE_READ_ISO_TX_SYNC_COMMAND                                          = hci_command_op_code(0x08, 0x0061)
HCI_LE_SET_CIG_PARAMETERS_COMMAND                                        = hci_command_op_code(0x08, 0x0062)
HCI_LE_SET_CIG_PARAMETERS_TEST_COMMAND                                   = hci_command_op_code(0x08, 0x0063)
HCI_LE_CREATE_CIS_COMMAND                                                = hci_command_op_code(0x08, 0x0064)
HCI_LE_REMOVE_CIG_COMMAND                                                = hci_command_op_code(0x08, 0x0065)
HCI_LE_ACCEPT_CIS_REQUEST_COMMAND                                        = hci_command_op_code(0x08, 0x0066)
HCI_LE_REJECT_CIS_REQUEST_COMMAND                                        = hci_command_op_code(0x08, 0x0067)
HCI_LE_CREATE_BIG_COMMAND                                                = hci_command_op_code(0x08, 0x0068)
HCI_LE_CREATE_BIG_TEST_COMMAND                                           = hci_command_op_code(0x08, 0x0069)
HCI_LE_TERMINATE_BIG_COMMAND                                             = hci_command_op_code(0x08, 0x006A)
HCI_LE_BIG_CREATE_SYNC_COMMAND                                           = hci_command_op_code(0x08, 0x006B)
HCI_LE_BIG_TERMINATE_SYNC_COMMAND                                        = hci_command_op_code(0x08, 0x006C)
HCI_LE_REQUEST_PEER_SCA_COMMAND                                          = hci_command_op_code(0x08, 0x006D)
HCI_LE_SETUP_ISO_DATA_PATH_COMMAND                                       = hci_command_op_code(0x08, 0x006E)
HCI_LE_REMOVE_ISO_DATA_PATH_COMMAND                                      = hci_command_op_code(0x08, 0x006F)
HCI_LE_ISO_TRANSMIT_TEST_COMMAND                                         = hci_command_op_code(0x08, 0x0070)
HCI_LE_ISO_RECEIVE_TEST_COMMAND                                          = hci_command_op_code(0x08, 0x0071)
HCI_LE_ISO_READ_TEST_COUNTERS_COMMAND                                    = hci_command_op_code(0x08, 0x0072)
HCI_LE_ISO_TEST_END_COMMAND                                              = hci_command_op_code(0x08, 0x0073)
HCI_LE_SET_HOST_FEATURE_COMMAND                                          = hci_command_op_code(0x08, 0x0074)
HCI_LE_READ_ISO_LINK_QUALITY_COMMAND                                     = hci_command_op_code(0x08, 0x0075)
HCI_LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL_COMMAND                        = hci_command_op_code(0x08, 0x0076)
HCI_LE_READ_REMOTE_TRANSMIT_POWER_LEVEL_COMMAND                          = hci_command_op_code(0x08, 0x0077)
HCI_LE_SET_PATH_LOSS_REPORTING_PARAMETERS_COMMAND                        = hci_command_op_code(0x08, 0x0078)
HCI_LE_SET_PATH_LOSS_REPORTING_ENABLE_COMMAND                            = hci_command_op_code(0x08, 0x0079)
HCI_LE_SET_TRANSMIT_POWER_REPORTING_ENABLE_COMMAND                       = hci_command_op_code(0x08, 0x007A)
HCI_LE_TRANSMITTER_TEST_V4_COMMAND                                       = hci_command_op_code(0x08, 0x007B)
HCI_LE_SET_DATA_RELATED_ADDRESS_CHANGES_COMMAND                          = hci_command_op_code(0x08, 0x007C)
HCI_LE_SET_DEFAULT_SUBRATE_COMMAND                                       = hci_command_op_code(0x08, 0x007D)
HCI_LE_SUBRATE_REQUEST_COMMAND                                           = hci_command_op_code(0x08, 0x007E)


# HCI Error Codes
# See Bluetooth spec Vol 2, Part D - 1.3 LIST OF ERROR CODES
HCI_SUCCESS                                                                            = 0x00
HCI_UNKNOWN_HCI_COMMAND_ERROR                                                          = 0x01
HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERROR                                                = 0x02
HCI_HARDWARE_FAILURE_ERROR                                                             = 0x03
HCI_PAGE_TIMEOUT_ERROR                                                                 = 0x04
HCI_AUTHENTICATION_FAILURE_ERROR                                                       = 0x05
HCI_PIN_OR_KEY_MISSING_ERROR                                                           = 0x06
HCI_MEMORY_CAPACITY_EXCEEDED_ERROR                                                     = 0x07
HCI_CONNECTION_TIMEOUT_ERROR                                                           = 0x08
HCI_CONNECTION_LIMIT_EXCEEDED_ERROR                                                    = 0x09
HCI_SYNCHRONOUS_CONNECTION_LIMIT_TO_A_DEVICE_EXCEEDED_ERROR                            = 0x0A
HCI_CONNECTION_ALREADY_EXISTS_ERROR                                                    = 0x0B
HCI_COMMAND_DISALLOWED_ERROR                                                           = 0x0C
HCI_CONNECTION_REJECTED_DUE_TO_LIMITED_RESOURCES_ERROR                                 = 0x0D
HCI_CONNECTION_REJECTED_DUE_TO_SECURITY_REASONS_ERROR                                  = 0x0E
HCI_CONNECTION_REJECTED_DUE_TO_UNACCEPTABLE_BD_ADDR_ERROR                              = 0x0F
HCI_CONNECTION_ACCEPT_TIMEOUT_ERROR                                                    = 0x10
HCI_UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR                                       = 0x11
HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR                                               = 0x12
HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR                                            = 0x13
HCI_REMOTE_DEVICE_TERMINATED_CONNECTION_DUE_TO_LOW_RESOURCES_ERROR                     = 0x14
HCI_REMOTE_DEVICE_TERMINATED_CONNECTION_DUE_TO_POWER_OFF_ERROR                         = 0x15
HCI_CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR                                          = 0x16
HCI_REPEATED_ATTEMPTS_ERROR                                                            = 0X17
HCI_PAIRING_NOT_ALLOWED_ERROR                                                          = 0X18
HCI_UNKNOWN_LMP_PDU_ERROR                                                              = 0X19
HCI_UNSUPPORTED_REMOTE_FEATURE_ERROR                                                   = 0X1A
HCI_SCO_OFFSET_REJECTED_ERROR                                                          = 0X1B
HCI_SCO_INTERVAL_REJECTED_ERROR                                                        = 0X1C
HCI_SCO_AIR_MODE_REJECTED_ERROR                                                        = 0X1D
HCI_INVALID_LMP_OR_LL_PARAMETERS_ERROR                                                 = 0X1E
HCI_UNSPECIFIED_ERROR_ERROR                                                            = 0X1F
HCI_UNSUPPORTED_LMP_OR_LL_PARAMETER_VALUE_ERROR                                        = 0X20
HCI_ROLE_CHANGE_NOT_ALLOWED_ERROR                                                      = 0X21
HCI_LMP_OR_LL_RESPONSE_TIMEOUT_ERROR                                                   = 0X22
HCI_LMP_ERROR_TRANSACTION_COLLISION_OR_LL_PROCEDURE_COLLISION_ERROR                    = 0X23
HCI_LMP_PDU_NOT_ALLOWED_ERROR                                                          = 0X24
HCI_ENCRYPTION_MODE_NOT_ACCEPTABLE_ERROR                                               = 0X25
HCI_LINK_KEY_CANNOT_BE_CHANGED_ERROR                                                   = 0X26
HCI_REQUESTED_QOS_NOT_SUPPORTED_ERROR                                                  = 0X27
HCI_INSTANT_PASSED_ERROR                                                               = 0X28
HCI_PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED_ERROR                                          = 0X29
HCI_DIFFERENT_TRANSACTION_COLLISION_ERROR                                              = 0X2A
HCI_RESERVED_FOR_FUTURE_USE                                                            = 0X2B
HCI_QOS_UNACCEPTABLE_PARAMETER_ERROR                                                   = 0X2C
HCI_QOS_REJECTED_ERROR                                                                 = 0X2D
HCI_CHANNEL_CLASSIFICATION_NOT_SUPPORTED_ERROR                                         = 0X2E
HCI_INSUFFICIENT_SECURITY_ERROR                                                        = 0X2F
HCI_PARAMETER_OUT_OF_MANDATORY_RANGE_ERROR                                             = 0X30
HCI_ROLE_SWITCH_PENDING_ERROR                                                          = 0X32
HCI_RESERVED_SLOT_VIOLATION_ERROR                                                      = 0X34
HCI_ROLE_SWITCH_FAILED_ERROR                                                           = 0X35
HCI_EXTENDED_INQUIRY_RESPONSE_TOO_LARGE_ERROR                                          = 0X36
HCI_SECURE_SIMPLE_PAIRING_NOT_SUPPORTED_BY_HOST_ERROR                                  = 0X37
HCI_HOST_BUSY_PAIRING_ERROR                                                            = 0X38
HCI_CONNECTION_REJECTED_DUE_TO_NO_SUITABLE_CHANNEL_FOUND_ERROR                         = 0X39
HCI_CONTROLLER_BUSY_ERROR                                                              = 0X3A
HCI_UNACCEPTABLE_CONNECTION_PARAMETERS_ERROR                                           = 0X3B
HCI_ADVERTISING_TIMEOUT_ERROR                                                          = 0X3C
HCI_CONNECTION_TERMINATED_DUE_TO_MIC_FAILURE_ERROR                                     = 0X3D
HCI_CONNECTION_FAILED_TO_BE_ESTABLISHED_ERROR                                          = 0X3E
HCI_COARSE_CLOCK_ADJUSTMENT_REJECTED_BUT_WILL_TRY_TO_ADJUST_USING_CLOCK_DRAGGING_ERROR = 0X40
HCI_TYPE0_SUBMAP_NOT_DEFINED_ERROR                                                     = 0X41
HCI_UNKNOWN_ADVERTISING_IDENTIFIER_ERROR                                               = 0X42
HCI_LIMIT_REACHED_ERROR                                                                = 0X43
HCI_OPERATION_CANCELLED_BY_HOST_ERROR                                                  = 0X44
HCI_PACKET_TOO_LONG_ERROR                                                              = 0X45

HCI_ERROR_NAMES = {
    error_code: error_name for (error_name, error_code) in globals().items()
    if error_name.startswith('HCI_') and error_name.endswith('_ERROR')
}
HCI_ERROR_NAMES[HCI_SUCCESS] = 'HCI_SUCCESS'

# Command Status codes
HCI_COMMAND_STATUS_PENDING = 0

# LE Event Masks
HCI_LE_CONNECTION_COMPLETE_EVENT_MASK                         = (1 << 0)
HCI_LE_ADVERTISING_REPORT_EVENT_MASK                          = (1 << 1)
HCI_LE_CONNECTION_UPDATE_COMPLETE_EVENT_MASK                  = (1 << 2)
HCI_LE_READ_REMOTE_FEATURES_COMPLETE_EVENT_MASK               = (1 << 3)
HCI_LE_LONG_TERM_KEY_REQUEST_EVENT_MASK                       = (1 << 4)
HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_EVENT_MASK         = (1 << 5)
HCI_LE_DATA_LENGTH_CHANGE_EVENT_MASK                          = (1 << 6)
HCI_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE_EVENT_MASK        = (1 << 7)
HCI_LE_GENERATE_DHKEY_COMPLETE_EVENT_MASK                     = (1 << 8)
HCI_LE_ENHANCED_CONNECTION_COMPLETE_EVENT_MASK                = (1 << 9)
HCI_LE_DIRECTED_ADVERTISING_REPORT_EVENT_MASK                 = (1 << 10)
HCI_LE_PHY_UPDATE_COMPLETE_EVENT_MASK                         = (1 << 11)
HCI_LE_EXTENDED_ADVERTISING_REPORT_EVENT_MASK                 = (1 << 12)
HCI_LE_PERIODIC_ADVERTISING_SYNC_ESTABLISHED_EVENT_MASK       = (1 << 13)
HCI_LE_PERIODIC_ADVERTISING_REPORT_EVENT_MASK                 = (1 << 14)
HCI_LE_PERIODIC_ADVERTISING_SYNC_LOST_EVENT_MASK              = (1 << 15)
HCI_LE_EXTENDED_SCAN_TIMEOUT_EVENT_MASK                       = (1 << 16)
HCI_LE_EXTENDED_ADVERTISING_SET_TERMINATED_EVENT_MASK         = (1 << 17)
HCI_LE_SCAN_REQUEST_RECEIVED_EVENT_MASK                       = (1 << 18)
HCI_LE_CHANNEL_SELECTION_ALGORITHM_EVENT_MASK                 = (1 << 19)
HCI_LE_CONNECTIONLESS_IQ_REPORT_EVENT_MASK                    = (1 << 20)
HCI_LE_CONNECTION_IQ_REPORT_EVENT_MASK                        = (1 << 21)
HCI_LE_CTE_REQUEST_FAILED_EVENT_MASK                          = (1 << 22)
HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_EVENT_MASK = (1 << 23)
HCI_LE_CIS_ESTABLISHED_EVENT_MASK                             = (1 << 24)
HCI_LE_CIS_REQUEST_EVENT_MASK                                 = (1 << 25)
HCI_LE_CREATE_BIG_COMPLETE_EVENT_MASK                         = (1 << 26)
HCI_LE_TERMINATE_BIG_COMPLETE_EVENT_MASK                      = (1 << 27)
HCI_LE_BIG_SYNC_ESTABLISHED_EVENT_MASK                        = (1 << 28)
HCI_LE_BIG_SYNC_LOST_EVENT_MASK                               = (1 << 29)
HCI_LE_REQUEST_PEER_SCA_COMPLETE_EVENT_MASK                   = (1 << 30)
HCI_LE_PATH_LOSS_THRESHOLD_EVENT_MASK                         = (1 << 31)
HCI_LE_TRANSMIT_POWER_REPORTING_EVENT_MASK                    = (1 << 32)
HCI_LE_BIGINFO_ADVERTISING_REPORT_EVENT_MASK                  = (1 << 33)
HCI_LE_SUBRATE_CHANGE_EVENT_MASK                              = (1 << 34)

HCI_LE_EVENT_MASK_NAMES = {
    mask: mask_name for (mask_name, mask) in globals().items()
    if mask_name.startswith('HCI_LE_') and mask_name.endswith('_EVENT_MASK')
}

# ACL
HCI_ACL_PB_FIRST_NON_FLUSHABLE = 0
HCI_ACL_PB_CONTINUATION        = 1
HCI_ACL_PB_FIRST_FLUSHABLE     = 2
HCI_ACK_PB_COMPLETE_L2CAP      = 3

# Roles
HCI_CENTRAL_ROLE    = 0
HCI_PERIPHERAL_ROLE = 1

HCI_ROLE_NAMES = {
    HCI_CENTRAL_ROLE:    'CENTRAL',
    HCI_PERIPHERAL_ROLE: 'PERIPHERAL'
}

# LE PHY Types
HCI_LE_1M_PHY    = 1
HCI_LE_2M_PHY    = 2
HCI_LE_CODED_PHY = 3

HCI_LE_PHY_NAMES = {
    HCI_LE_1M_PHY:    'LE 1M',
    HCI_LE_2M_PHY:    'LE 2M',
    HCI_LE_CODED_PHY: 'LE Coded'
}

HCI_LE_1M_PHY_BIT    = 0
HCI_LE_2M_PHY_BIT    = 1
HCI_LE_CODED_PHY_BIT = 2

HCI_LE_PHY_BIT_NAMES = ['LE_1M_PHY', 'LE_2M_PHY', 'LE_CODED_PHY']

HCI_LE_PHY_TYPE_TO_BIT = {
    HCI_LE_1M_PHY:    HCI_LE_1M_PHY_BIT,
    HCI_LE_2M_PHY:    HCI_LE_2M_PHY_BIT,
    HCI_LE_CODED_PHY: HCI_LE_CODED_PHY_BIT
}

# Connection Parameters
HCI_CONNECTION_INTERVAL_MS_PER_UNIT = 1.25
HCI_CONNECTION_LATENCY_MS_PER_UNIT  = 1.25
HCI_SUPERVISION_TIMEOUT_MS_PER_UNIT = 10

# Inquiry LAP
HCI_LIMITED_DEDICATED_INQUIRY_LAP = 0x9E8B00
HCI_GENERAL_INQUIRY_LAP           = 0x9E8B33
HCI_INQUIRY_LAP_NAMES = {
    HCI_LIMITED_DEDICATED_INQUIRY_LAP: 'Limited Dedicated Inquiry',
    HCI_GENERAL_INQUIRY_LAP:           'General Inquiry'
}

# Inquiry Mode
HCI_STANDARD_INQUIRY_MODE  = 0x00
HCI_INQUIRY_WITH_RSSI_MODE = 0x01
HCI_EXTENDED_INQUIRY_MODE  = 0x02

# Page Scan Repetition Mode
HCI_R0_PAGE_SCAN_REPETITION_MODE = 0x00
HCI_R1_PAGE_SCAN_REPETITION_MODE = 0x01
HCI_R2_PAGE_SCAN_REPETITION_MODE = 0x02

# IO Capability
HCI_DISPLAY_ONLY_IO_CAPABILITY       = 0x00
HCI_DISPLAY_YES_NO_IO_CAPABILITY     = 0x01
HCI_KEYBOARD_ONLY_IO_CAPABILITY      = 0x02
HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY = 0x03

HCI_IO_CAPABILITY_NAMES = {
    HCI_DISPLAY_ONLY_IO_CAPABILITY:       'HCI_DISPLAY_ONLY_IO_CAPABILITY',
    HCI_DISPLAY_YES_NO_IO_CAPABILITY:     'HCI_DISPLAY_YES_NO_IO_CAPABILITY',
    HCI_KEYBOARD_ONLY_IO_CAPABILITY:      'HCI_KEYBOARD_ONLY_IO_CAPABILITY',
    HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: 'HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY'
}

# Authentication Requirements
HCI_MITM_NOT_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS        = 0x00
HCI_MITM_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS            = 0x01
HCI_MITM_NOT_REQUIRED_DEDICATED_BONDING_AUTHENTICATION_REQUIREMENTS = 0x02
HCI_MITM_REQUIRED_DEDICATED_BONDING_AUTHENTICATION_REQUIREMENTS     = 0x03
HCI_MITM_NOT_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS   = 0x04
HCI_MITM_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS       = 0x05

HCI_AUTHENTICATION_REQUIREMENTS_NAMES = {
    HCI_MITM_NOT_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS:        'HCI_MITM_NOT_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS',
    HCI_MITM_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS:            'HCI_MITM_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS',
    HCI_MITM_NOT_REQUIRED_DEDICATED_BONDING_AUTHENTICATION_REQUIREMENTS: 'HCI_MITM_NOT_REQUIRED_DEDICATED_BONDING_AUTHENTICATION_REQUIREMENTS',
    HCI_MITM_REQUIRED_DEDICATED_BONDING_AUTHENTICATION_REQUIREMENTS:     'HCI_MITM_REQUIRED_DEDICATED_BONDING_AUTHENTICATION_REQUIREMENTS',
    HCI_MITM_NOT_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS:   'HCI_MITM_NOT_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS',
    HCI_MITM_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS:       'HCI_MITM_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS'
}

# Link Key Types
HCI_COMBINATION_KEY_TYPE                                      = 0X00
HCI_LOCAL_UNIT_KEY_TYPE                                       = 0X01
HCI_REMOTE_UNIT_KEY_TYPE                                      = 0X02
HCI_DEBUG_COMBINATION_KEY_TYPE                                = 0X03
HCI_UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE = 0X04
HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE   = 0X05
HCI_CHANGED_COMBINATION_KEY_TYPE                              = 0X06
HCI_UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE = 0X07
HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE   = 0X08

HCI_LINK_TYPE_NAMES = {
    HCI_COMBINATION_KEY_TYPE:                                      'HCI_COMBINATION_KEY_TYPE',
    HCI_LOCAL_UNIT_KEY_TYPE:                                       'HCI_LOCAL_UNIT_KEY_TYPE',
    HCI_REMOTE_UNIT_KEY_TYPE:                                      'HCI_REMOTE_UNIT_KEY_TYPE',
    HCI_DEBUG_COMBINATION_KEY_TYPE:                                'HCI_DEBUG_COMBINATION_KEY_TYPE',
    HCI_UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE: 'HCI_UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE',
    HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE:   'HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE',
    HCI_CHANGED_COMBINATION_KEY_TYPE:                              'HCI_CHANGED_COMBINATION_KEY_TYPE',
    HCI_UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE: 'HCI_UNAUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE',
    HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE:   'HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE'
}

# Address types
HCI_PUBLIC_DEVICE_ADDRESS_TYPE   = 0x00
HCI_RANDOM_DEVICE_ADDRESS_TYPE   = 0x01
HCI_PUBLIC_IDENTITY_ADDRESS_TYPE = 0x02
HCI_RANDOM_IDENTITY_ADDRESS_TYPE = 0x03

# Supported Commands Flags
# See Bluetooth spec @ 6.27 SUPPORTED COMMANDS
HCI_SUPPORTED_COMMANDS_FLAGS = (
    # Octet 0
    (
        HCI_INQUIRY_COMMAND,
        HCI_INQUIRY_CANCEL_COMMAND,
        HCI_PERIODIC_INQUIRY_MODE_COMMAND,
        HCI_EXIT_PERIODIC_INQUIRY_MODE_COMMAND,
        HCI_CREATE_CONNECTION_COMMAND,
        HCI_DISCONNECT_COMMAND,
        None,
        HCI_CREATE_CONNECTION_CANCEL_COMMAND
    ),
    # Octet 1
    (
        HCI_ACCEPT_CONNECTION_REQUEST_COMMAND,
        HCI_REJECT_CONNECTION_REQUEST_COMMAND,
        HCI_LINK_KEY_REQUEST_REPLY_COMMAND,
        HCI_LINK_KEY_REQUEST_NEGATIVE_REPLY_COMMAND,
        HCI_PIN_CODE_REQUEST_REPLY_COMMAND,
        HCI_PIN_CODE_REQUEST_NEGATIVE_REPLY_COMMAND,
        HCI_CHANGE_CONNECTION_PACKET_TYPE_COMMAND,
        HCI_AUTHENTICATION_REQUESTED_COMMAND
    ),
    # Octet 2
    (
        HCI_SET_CONNECTION_ENCRYPTION_COMMAND,
        HCI_CHANGE_CONNECTION_LINK_KEY_COMMAND,
        HCI_LINK_KEY_SELECTION_COMMAND,
        HCI_REMOTE_NAME_REQUEST_COMMAND,
        HCI_REMOTE_NAME_REQUEST_CANCEL_COMMAND,
        HCI_READ_REMOTE_SUPPORTED_FEATURES_COMMAND,
        HCI_READ_REMOTE_EXTENDED_FEATURES_COMMAND,
        HCI_READ_REMOTE_VERSION_INFORMATION_COMMAND
    ),
    # Octet 3
    (
        HCI_READ_CLOCK_OFFSET_COMMAND,
        HCI_READ_LMP_HANDLE_COMMAND,
        None,
        None,
        None,
        None,
        None,
        None
    ),
    # Octet 4
    (
        None,
        HCI_HOLD_MODE_COMMAND,
        HCI_SNIFF_MODE_COMMAND,
        HCI_EXIT_SNIFF_MODE_COMMAND,
        None,
        None,
        HCI_QOS_SETUP_COMMAND,
        HCI_ROLE_DISCOVERY_COMMAND
    ),
    # Octet 5
    (
        HCI_SWITCH_ROLE_COMMAND,
        HCI_READ_LINK_POLICY_SETTINGS_COMMAND,
        HCI_WRITE_LINK_POLICY_SETTINGS_COMMAND,
        HCI_READ_DEFAULT_LINK_POLICY_SETTINGS_COMMAND,
        HCI_WRITE_DEFAULT_LINK_POLICY_SETTINGS_COMMAND,
        HCI_FLOW_SPECIFICATION_COMMAND,
        HCI_SET_EVENT_MASK_COMMAND,
        HCI_RESET_COMMAND
    ),
    # Octet 6
    (
        HCI_SET_EVENT_FILTER_COMMAND,
        HCI_FLUSH_COMMAND,
        HCI_READ_PIN_TYPE_COMMAND,
        HCI_WRITE_PIN_TYPE_COMMAND,
        None,
        HCI_READ_STORED_LINK_KEY_COMMAND,
        HCI_WRITE_STORED_LINK_KEY_COMMAND,
        HCI_DELETE_STORED_LINK_KEY_COMMAND
    ),
    # Octet 7
    (
        HCI_WRITE_LOCAL_NAME_COMMAND,
        HCI_READ_LOCAL_NAME_COMMAND,
        HCI_READ_CONNECTION_ACCEPT_TIMEOUT_COMMAND,
        HCI_WRITE_CONNECTION_ACCEPT_TIMEOUT_COMMAND,
        HCI_READ_PAGE_TIMEOUT_COMMAND,
        HCI_WRITE_PAGE_TIMEOUT_COMMAND,
        HCI_READ_SCAN_ENABLE_COMMAND,
        HCI_WRITE_SCAN_ENABLE_COMMAND
    ),
    # Octet 8
    (
        HCI_READ_PAGE_SCAN_ACTIVITY_COMMAND,
        HCI_WRITE_PAGE_SCAN_ACTIVITY_COMMAND,
        HCI_READ_INQUIRY_SCAN_ACTIVITY_COMMAND,
        HCI_WRITE_INQUIRY_SCAN_ACTIVITY_COMMAND,
        HCI_READ_AUTHENTICATION_ENABLE_COMMAND,
        HCI_WRITE_AUTHENTICATION_ENABLE_COMMAND,
        None,
        None
    ),
    # Octet 9
    (
        HCI_READ_CLASS_OF_DEVICE_COMMAND,
        HCI_WRITE_CLASS_OF_DEVICE_COMMAND,
        HCI_READ_VOICE_SETTING_COMMAND,
        HCI_WRITE_VOICE_SETTING_COMMAND,
        HCI_READ_AUTOMATIC_FLUSH_TIMEOUT_COMMAND,
        HCI_WRITE_AUTOMATIC_FLUSH_TIMEOUT_COMMAND,
        HCI_READ_NUM_BROADCAST_RETRANSMISSIONS_COMMAND,
        HCI_WRITE_NUM_BROADCAST_RETRANSMISSIONS_COMMAND
    ),
    # Octet 10
    (
        HCI_READ_HOLD_MODE_ACTIVITY_COMMAND,
        HCI_WRITE_HOLD_MODE_ACTIVITY_COMMAND,
        HCI_READ_TRANSMIT_POWER_LEVEL_COMMAND,
        HCI_READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE_COMMAND,
        HCI_WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE_COMMAND,
        HCI_SET_CONTROLLER_TO_HOST_FLOW_CONTROL_COMMAND,
        HCI_HOST_BUFFER_SIZE_COMMAND,
        HCI_HOST_NUMBER_OF_COMPLETED_PACKETS_COMMAND
    ),
    # Octet 11
    (
        HCI_READ_LINK_SUPERVISION_TIMEOUT_COMMAND,
        HCI_WRITE_LINK_SUPERVISION_TIMEOUT_COMMAND,
        HCI_READ_NUMBER_OF_SUPPORTED_IAC_COMMAND,
        HCI_READ_CURRENT_IAC_LAP_COMMAND,
        HCI_WRITE_CURRENT_IAC_LAP_COMMAND,
        None,
        None,
        None
    ),
    # Octet 12
    (
        None,
        HCI_SET_AFH_HOST_CHANNEL_CLASSIFICATION_COMMAND,
        None,
        None,
        HCI_READ_INQUIRY_SCAN_TYPE_COMMAND,
        HCI_WRITE_INQUIRY_SCAN_TYPE_COMMAND,
        HCI_READ_INQUIRY_MODE_COMMAND,
        HCI_WRITE_INQUIRY_MODE_COMMAND
    ),
    # Octet 13
    (
        HCI_READ_PAGE_SCAN_TYPE_COMMAND,
        HCI_WRITE_PAGE_SCAN_TYPE_COMMAND,
        HCI_READ_AFH_CHANNEL_ASSESSMENT_MODE_COMMAND,
        HCI_WRITE_AFH_CHANNEL_ASSESSMENT_MODE_COMMAND,
        None,
        None,
        None,
        None,
    ),
    # Octet 14
    (
        None,
        None,
        None,
        HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND,
        None,
        HCI_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
        HCI_READ_LOCAL_EXTENDED_FEATURES_COMMAND,
        HCI_READ_BUFFER_SIZE_COMMAND
    ),
    # Octet 15
    (
        None,
        HCI_READ_BD_ADDR_COMMAND,
        HCI_READ_FAILED_CONTACT_COUNTER_COMMAND,
        HCI_RESET_FAILED_CONTACT_COUNTER_COMMAND,
        HCI_READ_LINK_QUALITY_COMMAND,
        HCI_READ_RSSI_COMMAND,
        HCI_READ_AFH_CHANNEL_MAP_COMMAND,
        HCI_READ_CLOCK_COMMAND
    ),
    # Octet  16
    (
        HCI_READ_LOOPBACK_MODE_COMMAND,
        HCI_WRITE_LOOPBACK_MODE_COMMAND,
        HCI_ENABLE_DEVICE_UNDER_TEST_MODE_COMMAND,
        HCI_SETUP_SYNCHRONOUS_CONNECTION_COMMAND,
        HCI_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND,
        HCI_REJECT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND,
        None,
        None,
    ),
    # Octet 17
    (
        HCI_READ_EXTENDED_INQUIRY_RESPONSE_COMMAND,
        HCI_WRITE_EXTENDED_INQUIRY_RESPONSE_COMMAND,
        HCI_REFRESH_ENCRYPTION_KEY_COMMAND,
        None,
        HCI_SNIFF_SUBRATING_COMMAND,
        HCI_READ_SIMPLE_PAIRING_MODE_COMMAND,
        HCI_WRITE_SIMPLE_PAIRING_MODE_COMMAND,
        HCI_READ_LOCAL_OOB_DATA_COMMAND
    ),
    # Octet 18
    (
        HCI_READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL_COMMAND,
        HCI_WRITE_INQUIRY_TRANSMIT_POWER_LEVEL_COMMAND,
        HCI_READ_DEFAULT_ERRONEOUS_DATA_REPORTING_COMMAND,
        HCI_WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING_COMMAND,
        None,
        None,
        None,
        HCI_IO_CAPABILITY_REQUEST_REPLY_COMMAND
    ),
    # Octet 19
    (
        HCI_USER_CONFIRMATION_REQUEST_REPLY_COMMAND,
        HCI_USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY_COMMAND,
        HCI_USER_PASSKEY_REQUEST_REPLY_COMMAND,
        HCI_USER_PASSKEY_REQUEST_NEGATIVE_REPLY_COMMAND,
        HCI_REMOTE_OOB_DATA_REQUEST_REPLY_COMMAND,
        HCI_WRITE_SIMPLE_PAIRING_DEBUG_MODE_COMMAND,
        HCI_ENHANCED_FLUSH_COMMAND,
        HCI_REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY_COMMAND
    ),
    # Octet 20
    (
        None,
        None,
        HCI_SEND_KEYPRESS_NOTIFICATION_COMMAND,
        HCI_IO_CAPABILITY_REQUEST_NEGATIVE_REPLY_COMMAND,
        HCI_READ_ENCRYPTION_KEY_SIZE_COMMAND,
        None,
        None,
        None,
    ),
    # Octet 21
    (
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ),
    # Octet 22
    (
        None,
        None,
        HCI_SET_EVENT_MASK_PAGE_2_COMMAND,
        None,
        None,
        None,
        None,
        None,
    ),
    # Octet 23
    (
        HCI_READ_FLOW_CONTROL_MODE_COMMAND,
        HCI_WRITE_FLOW_CONTROL_MODE_COMMAND,
        HCI_READ_DATA_BLOCK_SIZE_COMMAND,
        None,
        None,
        None,
        None,
        None,
    ),
    # Octet 24
    (
        HCI_READ_ENHANCED_TRANSMIT_POWER_LEVEL_COMMAND,
        None,
        None,
        None,
        None,
        HCI_READ_LE_HOST_SUPPORT_COMMAND,
        HCI_WRITE_LE_HOST_SUPPORT_COMMAND,
        None,
    ),
    # Octet 25
    (
        HCI_LE_SET_EVENT_MASK_COMMAND,
        HCI_LE_READ_BUFFER_SIZE_COMMAND,
        HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
        None,
        HCI_LE_SET_RANDOM_ADDRESS_COMMAND,
        HCI_LE_SET_ADVERTISING_PARAMETERS_COMMAND,
        HCI_LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER_COMMAND,
        HCI_LE_SET_ADVERTISING_DATA_COMMAND,
    ),
    # Octet 26
    (
        HCI_LE_SET_SCAN_RESPONSE_DATA_COMMAND,
        HCI_LE_SET_ADVERTISING_ENABLE_COMMAND,
        HCI_LE_SET_SCAN_PARAMETERS_COMMAND,
        HCI_LE_SET_SCAN_ENABLE_COMMAND,
        HCI_LE_CREATE_CONNECTION_COMMAND,
        HCI_LE_CREATE_CONNECTION_CANCEL_COMMAND,
        HCI_LE_READ_FILTER_ACCEPT_LIST_SIZE_COMMAND,
        HCI_LE_CLEAR_FILTER_ACCEPT_LIST_COMMAND
    ),
    # Octet 27
    (
        HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST_COMMAND,
        HCI_LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST_COMMAND,
        HCI_LE_CONNECTION_UPDATE_COMMAND,
        HCI_LE_SET_HOST_CHANNEL_CLASSIFICATION_COMMAND,
        HCI_LE_READ_CHANNEL_MAP_COMMAND,
        HCI_LE_READ_REMOTE_FEATURES_COMMAND,
        HCI_LE_ENCRYPT_COMMAND,
        HCI_LE_RAND_COMMAND
    ),
    # Octet 28
    (
        HCI_LE_ENABLE_ENCRYPTION_COMMAND,
        HCI_LE_LONG_TERM_KEY_REQUEST_REPLY_COMMAND,
        HCI_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY_COMMAND,
        HCI_LE_READ_SUPPORTED_STATES_COMMAND,
        HCI_LE_RECEIVER_TEST_COMMAND,
        HCI_LE_TRANSMITTER_TEST_COMMAND,
        HCI_LE_TEST_END_COMMAND,
        None,
    ),
    # Octet 29
    (
        None,
        None,
        None,
        HCI_ENHANCED_SETUP_SYNCHRONOUS_CONNECTION_COMMAND,
        HCI_ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND,
        HCI_READ_LOCAL_SUPPORTED_CODECS_COMMAND,
        HCI_SET_MWS_CHANNEL_PARAMETERS_COMMAND,
        HCI_SET_EXTERNAL_FRAME_CONFIGURATION_COMMAND
    ),
    # Octet 30
    (
        HCI_SET_MWS_SIGNALING_COMMAND,
        HCI_SET_MWS_TRANSPORT_LAYER_COMMAND,
        HCI_SET_MWS_SCAN_FREQUENCY_TABLE_COMMAND,
        HCI_GET_MWS_TRANSPORT_LAYER_CONFIGURATION_COMMAND,
        HCI_SET_MWS_PATTERN_CONFIGURATION_COMMAND,
        HCI_SET_TRIGGERED_CLOCK_CAPTURE_COMMAND,
        HCI_TRUNCATED_PAGE_COMMAND,
        HCI_TRUNCATED_PAGE_CANCEL_COMMAND
    ),
    # Octet 31
    (
        HCI_SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_COMMAND,
        HCI_SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE_COMMAND,
        HCI_START_SYNCHRONIZATION_TRAIN_COMMAND,
        HCI_RECEIVE_SYNCHRONIZATION_TRAIN_COMMAND,
        HCI_SET_RESERVED_LT_ADDR_COMMAND,
        HCI_DELETE_RESERVED_LT_ADDR_COMMAND,
        HCI_SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA_COMMAND,
        HCI_READ_SYNCHRONIZATION_TRAIN_PARAMETERS_COMMAND
    ),
    # Octet 32
    (
        HCI_WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS_COMMAND,
        HCI_REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY_COMMAND,
        HCI_READ_SECURE_CONNECTIONS_HOST_SUPPORT_COMMAND,
        HCI_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT_COMMAND,
        HCI_READ_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND,
        HCI_WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND,
        HCI_READ_LOCAL_OOB_EXTENDED_DATA_COMMAND,
        HCI_WRITE_SECURE_CONNECTIONS_TEST_MODE_COMMAND
    ),
    # Octet 33
    (
        HCI_READ_EXTENDED_PAGE_TIMEOUT_COMMAND,
        HCI_WRITE_EXTENDED_PAGE_TIMEOUT_COMMAND,
        HCI_READ_EXTENDED_INQUIRY_LENGTH_COMMAND,
        HCI_WRITE_EXTENDED_INQUIRY_LENGTH_COMMAND,
        HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY_COMMAND,
        HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY_COMMAND,
        HCI_LE_SET_DATA_LENGTH_COMMAND,
        HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND
    ),
    # Octet 34
    (
        HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
        HCI_LE_READ_LOCAL_P_256_PUBLIC_KEY_COMMAND,
        HCI_LE_GENERATE_DHKEY_COMMAND,
        HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND,
        HCI_LE_REMOVE_DEVICE_FROM_RESOLVING_LIST_COMMAND,
        HCI_LE_CLEAR_RESOLVING_LIST_COMMAND,
        HCI_LE_READ_RESOLVING_LIST_SIZE_COMMAND,
        HCI_LE_READ_PEER_RESOLVABLE_ADDRESS_COMMAND
    ),
    # Octet 35
    (
        HCI_LE_READ_LOCAL_RESOLVABLE_ADDRESS_COMMAND,
        HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE_COMMAND,
        HCI_LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT_COMMAND,
        HCI_LE_READ_MAXIMUM_DATA_LENGTH_COMMAND,
        HCI_LE_READ_PHY_COMMAND,
        HCI_LE_SET_DEFAULT_PHY_COMMAND,
        HCI_LE_SET_PHY_COMMAND,
        HCI_LE_RECEIVER_TEST_V2_COMMAND
    ),
    # Octet 36
    (
        HCI_LE_TRANSMITTER_TEST_V2_COMMAND,
        HCI_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_COMMAND,
        HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_COMMAND,
        HCI_LE_SET_EXTENDED_ADVERTISING_DATA_COMMAND,
        HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA_COMMAND,
        HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE_COMMAND,
        HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND,
        HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND,
    ),
    # Octet 37
    (
        HCI_LE_REMOVE_ADVERTISING_SET_COMMAND,
        HCI_LE_CLEAR_ADVERTISING_SETS_COMMAND,
        HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_COMMAND,
        HCI_LE_SET_PERIODIC_ADVERTISING_DATA_COMMAND,
        HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE_COMMAND,
        HCI_LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND,
        HCI_LE_SET_EXTENDED_SCAN_ENABLE_COMMAND,
        HCI_LE_EXTENDED_CREATE_CONNECTION_COMMAND
    ),
    # Octet 38
    (
        HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_COMMAND,
        HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL_COMMAND,
        HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC_COMMAND,
        HCI_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST_COMMAND,
        HCI_LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST_COMMAND,
        HCI_LE_CLEAR_PERIODIC_ADVERTISER_LIST_COMMAND,
        HCI_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE_COMMAND,
        HCI_LE_READ_TRANSMIT_POWER_COMMAND
    ),
    # Octet 39
    (
        HCI_LE_READ_RF_PATH_COMPENSATION_COMMAND,
        HCI_LE_WRITE_RF_PATH_COMPENSATION_COMMAND,
        HCI_LE_SET_PRIVACY_MODE_COMMAND,
        HCI_LE_RECEIVER_TEST_V3_COMMAND,
        HCI_LE_TRANSMITTER_TEST_V3_COMMAND,
        HCI_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS_COMMAND,
        HCI_LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE_COMMAND,
        HCI_LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE_COMMAND,
    ),
    # Octet 40
    (
        HCI_LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS_COMMAND,
        HCI_LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS_COMMAND,
        HCI_LE_CONNECTION_CTE_REQUEST_ENABLE_COMMAND,
        HCI_LE_CONNECTION_CTE_RESPONSE_ENABLE_COMMAND,
        HCI_LE_READ_ANTENNA_INFORMATION_COMMAND,
        HCI_LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE_COMMAND,
        HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_COMMAND,
        HCI_LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER_COMMAND
    ),
    # Octet 41
    (
        HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_COMMAND,
        HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_COMMAND,
        HCI_LE_GENERATE_DHKEY_V2_COMMAND,
        HCI_READ_LOCAL_SIMPLE_PAIRING_OPTIONS_COMMAND,
        HCI_LE_MODIFY_SLEEP_CLOCK_ACCURACY_COMMAND,
        HCI_LE_READ_BUFFER_SIZE_V2_COMMAND,
        HCI_LE_READ_ISO_TX_SYNC_COMMAND,
        HCI_LE_SET_CIG_PARAMETERS_COMMAND
    ),
    # Octet 42
    (
        HCI_LE_SET_CIG_PARAMETERS_TEST_COMMAND,
        HCI_LE_CREATE_CIS_COMMAND,
        HCI_LE_REMOVE_CIG_COMMAND,
        HCI_LE_ACCEPT_CIS_REQUEST_COMMAND,
        HCI_LE_REJECT_CIS_REQUEST_COMMAND,
        HCI_LE_CREATE_BIG_COMMAND,
        HCI_LE_CREATE_BIG_TEST_COMMAND,
        HCI_LE_TERMINATE_BIG_COMMAND,
    ),
    # Octet 43
    (
        HCI_LE_BIG_CREATE_SYNC_COMMAND,
        HCI_LE_BIG_TERMINATE_SYNC_COMMAND,
        HCI_LE_REQUEST_PEER_SCA_COMMAND,
        HCI_LE_SETUP_ISO_DATA_PATH_COMMAND,
        HCI_LE_REMOVE_ISO_DATA_PATH_COMMAND,
        HCI_LE_ISO_TRANSMIT_TEST_COMMAND,
        HCI_LE_ISO_RECEIVE_TEST_COMMAND,
        HCI_LE_ISO_READ_TEST_COUNTERS_COMMAND
    ),
    # Octet 44
    (
        HCI_LE_ISO_TEST_END_COMMAND,
        HCI_LE_SET_HOST_FEATURE_COMMAND,
        HCI_LE_READ_ISO_LINK_QUALITY_COMMAND,
        HCI_LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL_COMMAND,
        HCI_LE_READ_REMOTE_TRANSMIT_POWER_LEVEL_COMMAND,
        HCI_LE_SET_PATH_LOSS_REPORTING_PARAMETERS_COMMAND,
        HCI_LE_SET_PATH_LOSS_REPORTING_ENABLE_COMMAND,
        HCI_LE_SET_TRANSMIT_POWER_REPORTING_ENABLE_COMMAND
    ),
    # Octet 45
    (
        HCI_LE_TRANSMITTER_TEST_V4_COMMAND,
        HCI_SET_ECOSYSTEM_BASE_INTERVAL_COMMAND,
        HCI_READ_LOCAL_SUPPORTED_CODECS_V2_COMMAND,
        HCI_READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES_COMMAND,
        HCI_READ_LOCAL_SUPPORTED_CONTROLLER_DELAY_COMMAND,
        HCI_CONFIGURE_DATA_PATH_COMMAND,
        HCI_LE_SET_DATA_RELATED_ADDRESS_CHANGES_COMMAND,
        HCI_SET_MIN_ENCRYPTION_KEY_SIZE_COMMAND
    ),
    # Octet 46
    (
        HCI_LE_SET_DEFAULT_SUBRATE_COMMAND,
        HCI_LE_SUBRATE_REQUEST_COMMAND,
        None,
        None,
        None,
        None,
        None,
        None
    )
)

# LE Supported Features
HCI_LE_ENCRYPTION_LE_SUPPORTED_FEATURE                                = 0
HCI_CONNECTION_PARAMETERS_REQUEST_PROCEDURE_LE_SUPPORTED_FEATURE      = 1
HCI_EXTENDED_REJECT_INDICATION_LE_SUPPORTED_FEATURE                   = 2
HCI_PERIPHERAL_INITIATED_FEATURE_EXCHANGE_LE_SUPPORTED_FEATURE        = 3
HCI_LE_PING_LE_SUPPORTED_FEATURE                                      = 4
HCI_LE_DATA_PACKET_LENGTH_EXTENSION_LE_SUPPORTED_FEATURE              = 5
HCI_LL_PRIVACY_LE_SUPPORTED_FEATURE                                   = 6
HCI_EXTENDED_SCANNER_FILTER_POLICIES_LE_SUPPORTED_FEATURE             = 7
HCI_LE_2M_PHY_LE_SUPPORTED_FEATURE                                    = 8
HCI_STABLE_MODULATION_INDEX_TRANSMITTER_LE_SUPPORTED_FEATURE          = 9
HCI_STABLE_MODULATION_INDEX_RECEIVER_LE_SUPPORTED_FEATURE             = 10
HCI_LE_CODED_PHY_LE_SUPPORTED_FEATURE                                 = 11
HCI_LE_EXTENDED_ADVERTISING_LE_SUPPORTED_FEATURE                      = 12
HCI_LE_PERIODIC_ADVERTISING_LE_SUPPORTED_FEATURE                      = 13
HCI_CHANNEL_SELECTION_ALGORITHM_2_LE_SUPPORTED_FEATURE                = 14
HCI_LE_POWER_CLASS_1_LE_SUPPORTED_FEATURE                             = 15
HCI_MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE_LE_SUPPORTED_FEATURE    = 16
HCI_CONNECTION_CTE_REQUEST_LE_SUPPORTED_FEATURE                       = 17
HCI_CONNECTION_CTE_RESPONSE_LE_SUPPORTED_FEATURE                      = 18
HCI_CONNECTIONLESS_CTE_TRANSMITTER_LE_SUPPORTED_FEATURE               = 19
HCI_CONNECTIONLESS_CTR_RECEIVER_LE_SUPPORTED_FEATURE                  = 20
HCI_ANTENNA_SWITCHING_DURING_CTE_TRANSMISSION_LE_SUPPORTED_FEATURE    = 21
HCI_ANTENNA_SWITCHING_DURING_CTE_RECEPTION_LE_SUPPORTED_FEATURE       = 22
HCI_RECEIVING_CONSTANT_TONE_EXTENSIONS_LE_SUPPORTED_FEATURE           = 23
HCI_PERIODIC_ADVERTISING_SYNC_TRANSFER_SENDER_LE_SUPPORTED_FEATURE    = 24
HCI_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECIPIENT_LE_SUPPORTED_FEATURE = 25
HCI_SLEEP_CLOCK_ACCURACY_UPDATES_LE_SUPPORTED_FEATURE                 = 26
HCI_REMOTE_PUBLIC_KEY_VALIDATION_LE_SUPPORTED_FEATURE                 = 27
HCI_CONNECTED_ISOCHRONOUS_STREAM_CENTRAL_LE_SUPPORTED_FEATURE         = 28
HCI_CONNECTED_ISOCHRONOUS_STREAM_PERIPHERAL_LE_SUPPORTED_FEATURE      = 29
HCI_ISOCHRONOUS_BROADCASTER_LE_SUPPORTED_FEATURE                      = 30
HCI_SYNCHRONIZED_RECEIVER_LE_SUPPORTED_FEATURE                        = 31
HCI_CONNECTED_ISOCHRONOUS_STREAM_LE_SUPPORTED_FEATURE                 = 32
HCI_LE_POWER_CONTROL_REQUEST_LE_SUPPORTED_FEATURE                     = 33
HCI_LE_POWER_CONTROL_REQUEST_DUP_LE_SUPPORTED_FEATURE                 = 34
HCI_LE_PATH_LOSS_MONITORING_LE_SUPPORTED_FEATURE                      = 35
HCI_PERIODIC_ADVERTISING_ADI_SUPPORT_LE_SUPPORTED_FEATURE             = 36
HCI_CONNECTION_SUBRATING_LE_SUPPORTED_FEATURE                         = 37
HCI_CONNECTION_SUBRATING_HOST_SUPPORT_LE_SUPPORTED_FEATURE            = 38
HCI_CHANNEL_CLASSIFICATION_LE_SUPPORTED_FEATURE                       = 39

HCI_LE_SUPPORTED_FEATURES_NAMES = {
    flag: feature_name for (feature_name, flag) in globals().items()
    if feature_name.startswith('HCI_') and feature_name.endswith('_LE_SUPPORTED_FEATURE')
}


# fmt: on
# pylint: enable=line-too-long
# pylint: disable=invalid-name

# -----------------------------------------------------------------------------
# pylint: disable-next=unnecessary-lambda
STATUS_SPEC = {'size': 1, 'mapper': lambda x: HCI_Constant.status_name(x)}


# -----------------------------------------------------------------------------
class HCI_Constant:
    @staticmethod
    def status_name(status):
        return HCI_ERROR_NAMES.get(status, f'0x{status:02X}')

    @staticmethod
    def error_name(status):
        return HCI_ERROR_NAMES.get(status, f'0x{status:02X}')

    @staticmethod
    def role_name(role):
        return HCI_ROLE_NAMES.get(role, str(role))

    @staticmethod
    def le_phy_name(phy):
        return HCI_LE_PHY_NAMES.get(phy, str(phy))

    @staticmethod
    def inquiry_lap_name(lap):
        return HCI_INQUIRY_LAP_NAMES.get(lap, f'0x{lap:06X}')

    @staticmethod
    def io_capability_name(io_capability):
        return HCI_IO_CAPABILITY_NAMES.get(io_capability, f'0x{io_capability:02X}')

    @staticmethod
    def authentication_requirements_name(authentication_requirements):
        return HCI_AUTHENTICATION_REQUIREMENTS_NAMES.get(
            authentication_requirements, f'0x{authentication_requirements:02X}'
        )

    @staticmethod
    def link_key_type_name(link_key_type):
        return HCI_LINK_TYPE_NAMES.get(link_key_type, f'0x{link_key_type:02X}')


# -----------------------------------------------------------------------------
class HCI_Error(ProtocolError):
    def __init__(self, error_code):
        super().__init__(
            error_code,
            error_namespace='hci',
            error_name=HCI_Constant.error_name(error_code),
        )


# -----------------------------------------------------------------------------
class HCI_StatusError(ProtocolError):
    def __init__(self, response):
        super().__init__(
            response.status,
            error_namespace=HCI_Command.command_name(response.command_opcode),
            error_name=HCI_Constant.status_name(response.status),
        )


# -----------------------------------------------------------------------------
# Generic HCI object
# -----------------------------------------------------------------------------
class HCI_Object:
    @staticmethod
    def init_from_fields(hci_object, fields, values):
        if isinstance(values, dict):
            for field in fields:
                if isinstance(field, list):
                    # The field is an array, up-level the array field names
                    for sub_field_name, _ in field:
                        setattr(hci_object, sub_field_name, values[sub_field_name])
                else:
                    field_name = field[0]
                    setattr(hci_object, field_name, values[field_name])
        else:
            for field_name, field_value in zip(fields, values):
                setattr(hci_object, field_name, field_value)

    @staticmethod
    def init_from_bytes(hci_object, data, offset, fields):
        parsed = HCI_Object.dict_from_bytes(data, offset, fields)
        HCI_Object.init_from_fields(hci_object, parsed.keys(), parsed.values())

    @staticmethod
    def parse_field(data, offset, field_type):
        # The field_type may be a dictionary with a mapper, parser, and/or size
        if isinstance(field_type, dict):
            if 'size' in field_type:
                field_type = field_type['size']
            elif 'parser' in field_type:
                field_type = field_type['parser']

        # Parse the field
        if field_type == '*':
            # The rest of the bytes
            field_value = data[offset:]
            return (field_value, len(field_value))
        if field_type == 1:
            # 8-bit unsigned
            return (data[offset], 1)
        if field_type == -1:
            # 8-bit signed
            return (struct.unpack_from('b', data, offset)[0], 1)
        if field_type == 2:
            # 16-bit unsigned
            return (struct.unpack_from('<H', data, offset)[0], 2)
        if field_type == '>2':
            # 16-bit unsigned big-endian
            return (struct.unpack_from('>H', data, offset)[0], 2)
        if field_type == -2:
            # 16-bit signed
            return (struct.unpack_from('<h', data, offset)[0], 2)
        if field_type == 3:
            # 24-bit unsigned
            padded = data[offset : offset + 3] + bytes([0])
            return (struct.unpack('<I', padded)[0], 3)
        if field_type == 4:
            # 32-bit unsigned
            return (struct.unpack_from('<I', data, offset)[0], 4)
        if field_type == '>4':
            # 32-bit unsigned big-endian
            return (struct.unpack_from('>I', data, offset)[0], 4)
        if isinstance(field_type, int) and 4 < field_type <= 256:
            # Byte array (from 5 up to 256 bytes)
            return (data[offset : offset + field_type], field_type)
        if callable(field_type):
            new_offset, field_value = field_type(data, offset)
            return (field_value, new_offset - offset)

        raise ValueError(f'unknown field type {field_type}')

    @staticmethod
    def dict_from_bytes(data, offset, fields):
        result = collections.OrderedDict()
        for field in fields:
            if isinstance(field, list):
                # This is an array field, starting with a 1-byte item count.
                item_count = data[offset]
                offset += 1
                for _ in range(item_count):
                    for sub_field_name, sub_field_type in field:
                        value, size = HCI_Object.parse_field(
                            data, offset, sub_field_type
                        )
                        result.setdefault(sub_field_name, []).append(value)
                        offset += size
                continue

            field_name, field_type = field
            field_value, field_size = HCI_Object.parse_field(data, offset, field_type)
            result[field_name] = field_value
            offset += field_size

        return result

    @staticmethod
    def serialize_field(field_value, field_type):
        # The field_type may be a dictionary with a mapper, parser, serializer,
        # and/or size
        serializer = None
        if isinstance(field_type, dict):
            if 'serializer' in field_type:
                serializer = field_type['serializer']
            if 'size' in field_type:
                field_type = field_type['size']

        # Serialize the field
        if serializer:
            field_bytes = serializer(field_value)
        elif field_type == 1:
            # 8-bit unsigned
            field_bytes = bytes([field_value])
        elif field_type == -1:
            # 8-bit signed
            field_bytes = struct.pack('b', field_value)
        elif field_type == 2:
            # 16-bit unsigned
            field_bytes = struct.pack('<H', field_value)
        elif field_type == '>2':
            # 16-bit unsigned big-endian
            field_bytes = struct.pack('>H', field_value)
        elif field_type == -2:
            # 16-bit signed
            field_bytes = struct.pack('<h', field_value)
        elif field_type == 3:
            # 24-bit unsigned
            field_bytes = struct.pack('<I', field_value)[0:3]
        elif field_type == 4:
            # 32-bit unsigned
            field_bytes = struct.pack('<I', field_value)
        elif field_type == '>4':
            # 32-bit unsigned big-endian
            field_bytes = struct.pack('>I', field_value)
        elif field_type == '*':
            if isinstance(field_value, int):
                if 0 <= field_value <= 255:
                    field_bytes = bytes([field_value])
                else:
                    raise ValueError('value too large for *-typed field')
            else:
                field_bytes = bytes(field_value)
        elif isinstance(field_value, (bytes, bytearray)) or hasattr(
            field_value, 'to_bytes'
        ):
            field_bytes = bytes(field_value)
            if isinstance(field_type, int) and 4 < field_type <= 256:
                # Truncate or pad with zeros if the field is too long or too short
                if len(field_bytes) < field_type:
                    field_bytes += bytes(field_type - len(field_bytes))
                elif len(field_bytes) > field_type:
                    field_bytes = field_bytes[:field_type]
        else:
            raise ValueError(f"don't know how to serialize type {type(field_value)}")

        return field_bytes

    @staticmethod
    def dict_to_bytes(hci_object, fields):
        result = bytearray()
        for field in fields:
            if isinstance(field, list):
                # The field is an array. The serialized form starts with a 1-byte
                # item count. We use the length of the first array field as the
                # array count, since all array fields have the same number of items.
                item_count = len(hci_object[field[0][0]])
                result += bytes([item_count]) + b''.join(
                    b''.join(
                        HCI_Object.serialize_field(
                            hci_object[sub_field_name][i], sub_field_type
                        )
                        for sub_field_name, sub_field_type in field
                    )
                    for i in range(item_count)
                )
                continue

            (field_name, field_type) = field
            result += HCI_Object.serialize_field(hci_object[field_name], field_type)

        return bytes(result)

    @classmethod
    def from_bytes(cls, data, offset, fields):
        return cls(fields, **cls.dict_from_bytes(data, offset, fields))

    def to_bytes(self):
        return HCI_Object.dict_to_bytes(self.__dict__, self.fields)

    @staticmethod
    def parse_length_prefixed_bytes(data, offset):
        length = data[offset]
        return offset + 1 + length, data[offset + 1 : offset + 1 + length]

    @staticmethod
    def serialize_length_prefixed_bytes(data, padded_size=0):
        prefixed_size = 1 + len(data)
        padding = (
            bytes(padded_size - prefixed_size) if prefixed_size < padded_size else b''
        )
        return bytes([len(data)]) + data + padding

    @staticmethod
    def format_field_value(value, indentation):
        if isinstance(value, bytes):
            return value.hex()

        if isinstance(value, HCI_Object):
            return '\n' + value.to_string(indentation)

        return str(value)

    @staticmethod
    def stringify_field(
        field_name, field_type, field_value, indentation, value_mappers
    ):
        value_mapper = None
        if isinstance(field_type, dict):
            # Get the value mapper from the specifier
            value_mapper = field_type.get('mapper')

        # Check if there's a matching mapper passed
        if value_mappers:
            value_mapper = value_mappers.get(field_name, value_mapper)

        # Map the value if we have a mapper
        if value_mapper is not None:
            field_value = value_mapper(field_value)

        # Get the string representation of the value
        return HCI_Object.format_field_value(
            field_value, indentation=indentation + '  '
        )

    @staticmethod
    def format_fields(hci_object, fields, indentation='', value_mappers=None):
        if not fields:
            return ''

        # Build array of formatted key:value pairs
        field_strings = []
        for field in fields:
            if isinstance(field, list):
                for sub_field in field:
                    sub_field_name, sub_field_type = sub_field
                    item_count = len(hci_object[sub_field_name])
                    for i in range(item_count):
                        field_strings.append(
                            (
                                f'{sub_field_name}[{i}]',
                                HCI_Object.stringify_field(
                                    sub_field_name,
                                    sub_field_type,
                                    hci_object[sub_field_name][i],
                                    indentation,
                                    value_mappers,
                                ),
                            ),
                        )
                continue

            field_name, field_type = field
            field_value = hci_object[field_name]
            field_strings.append(
                (
                    field_name,
                    HCI_Object.stringify_field(
                        field_name, field_type, field_value, indentation, value_mappers
                    ),
                ),
            )

        # Measure the widest field name
        max_field_name_length = max(len(s[0]) for s in field_strings)
        sep = ':'
        return '\n'.join(
            f'{indentation}'
            f'{color(f"{field_name + sep:{1 + max_field_name_length}}", "cyan")} {field_value}'
            for field_name, field_value in field_strings
        )

    def __bytes__(self):
        return self.to_bytes()

    def __init__(self, fields, **kwargs):
        self.fields = fields
        self.init_from_fields(self, fields, kwargs)

    def to_string(self, indentation='', value_mappers=None):
        return HCI_Object.format_fields(
            self.__dict__, self.fields, indentation, value_mappers
        )

    def __str__(self):
        return self.to_string()


# -----------------------------------------------------------------------------
# Bluetooth Address
# -----------------------------------------------------------------------------
class Address:
    '''
    Bluetooth Address (see Bluetooth spec Vol 6, Part B - 1.3 DEVICE ADDRESS)
    NOTE: the address bytes are stored in little-endian byte order here, so
    address[0] is the LSB of the address, address[5] is the MSB.
    '''

    PUBLIC_DEVICE_ADDRESS = 0x00
    RANDOM_DEVICE_ADDRESS = 0x01
    PUBLIC_IDENTITY_ADDRESS = 0x02
    RANDOM_IDENTITY_ADDRESS = 0x03

    ADDRESS_TYPE_NAMES = {
        PUBLIC_DEVICE_ADDRESS: 'PUBLIC_DEVICE_ADDRESS',
        RANDOM_DEVICE_ADDRESS: 'RANDOM_DEVICE_ADDRESS',
        PUBLIC_IDENTITY_ADDRESS: 'PUBLIC_IDENTITY_ADDRESS',
        RANDOM_IDENTITY_ADDRESS: 'RANDOM_IDENTITY_ADDRESS',
    }

    # Type declarations
    NIL: Address
    ANY: Address
    ANY_RANDOM: Address

    # pylint: disable-next=unnecessary-lambda
    ADDRESS_TYPE_SPEC = {'size': 1, 'mapper': lambda x: Address.address_type_name(x)}

    @staticmethod
    def address_type_name(address_type):
        return name_or_number(Address.ADDRESS_TYPE_NAMES, address_type)

    @staticmethod
    def from_string_for_transport(string, transport):
        if transport == BT_BR_EDR_TRANSPORT:
            address_type = Address.PUBLIC_DEVICE_ADDRESS
        else:
            address_type = Address.RANDOM_DEVICE_ADDRESS
        return Address(string, address_type)

    @staticmethod
    def parse_address(data, offset):
        # Fix the type to a default value. This is used for parsing type-less Classic
        # addresses
        return Address.parse_address_with_type(
            data, offset, Address.PUBLIC_DEVICE_ADDRESS
        )

    @staticmethod
    def parse_address_with_type(data, offset, address_type):
        return offset + 6, Address(data[offset : offset + 6], address_type)

    @staticmethod
    def parse_address_preceded_by_type(data, offset):
        address_type = data[offset - 1]
        return Address.parse_address_with_type(data, offset, address_type)

    def __init__(
        self, address: Union[bytes, str], address_type: int = RANDOM_DEVICE_ADDRESS
    ):
        '''
        Initialize an instance. `address` may be a byte array in little-endian
        format, or a hex string in big-endian format (with optional ':'
        separators between the bytes).
        If the address is a string suffixed with '/P', `address_type` is ignored and
        the type is set to PUBLIC_DEVICE_ADDRESS.
        '''
        if isinstance(address, bytes):
            self.address_bytes = address
        else:
            # Check if there's a '/P' type specifier
            if address.endswith('P'):
                address_type = Address.PUBLIC_DEVICE_ADDRESS
                address = address[:-2]

            if len(address) == 12 + 5:
                # Form with ':' separators
                address = address.replace(':', '')
            self.address_bytes = bytes(reversed(bytes.fromhex(address)))

        if len(self.address_bytes) != 6:
            raise ValueError('invalid address length')

        self.address_type = address_type

    def clone(self):
        return Address(self.address_bytes, self.address_type)

    @property
    def is_public(self):
        return self.address_type in (
            self.PUBLIC_DEVICE_ADDRESS,
            self.PUBLIC_IDENTITY_ADDRESS,
        )

    @property
    def is_random(self):
        return not self.is_public

    @property
    def is_resolved(self):
        return self.address_type in (
            self.PUBLIC_IDENTITY_ADDRESS,
            self.RANDOM_IDENTITY_ADDRESS,
        )

    @property
    def is_resolvable(self):
        return self.address_type == self.RANDOM_DEVICE_ADDRESS and (
            self.address_bytes[5] >> 6 == 1
        )

    @property
    def is_static(self):
        return self.is_random and (self.address_bytes[5] >> 6 == 3)

    def to_bytes(self):
        return self.address_bytes

    def to_string(self, with_type_qualifier=True):
        '''
        String representation of the address, MSB first, with an optional type
        qualifier.
        '''
        result = ':'.join([f'{x:02X}' for x in reversed(self.address_bytes)])
        if not with_type_qualifier or not self.is_public:
            return result
        return result + '/P'

    def __bytes__(self):
        return self.to_bytes()

    def __hash__(self):
        return hash(self.address_bytes)

    def __eq__(self, other):
        return (
            self.address_bytes == other.address_bytes
            and self.is_public == other.is_public
        )

    def __str__(self):
        return self.to_string()


# Predefined address values
Address.NIL = Address(b"\xff\xff\xff\xff\xff\xff", Address.PUBLIC_DEVICE_ADDRESS)
Address.ANY = Address(b"\x00\x00\x00\x00\x00\x00", Address.PUBLIC_DEVICE_ADDRESS)
Address.ANY_RANDOM = Address(b"\x00\x00\x00\x00\x00\x00", Address.RANDOM_DEVICE_ADDRESS)

# -----------------------------------------------------------------------------
class OwnAddressType:
    PUBLIC = 0
    RANDOM = 1
    RESOLVABLE_OR_PUBLIC = 2
    RESOLVABLE_OR_RANDOM = 3

    TYPE_NAMES = {
        PUBLIC: 'PUBLIC',
        RANDOM: 'RANDOM',
        RESOLVABLE_OR_PUBLIC: 'RESOLVABLE_OR_PUBLIC',
        RESOLVABLE_OR_RANDOM: 'RESOLVABLE_OR_RANDOM',
    }

    @staticmethod
    def type_name(type_id):
        return name_or_number(OwnAddressType.TYPE_NAMES, type_id)

    # pylint: disable-next=unnecessary-lambda
    TYPE_SPEC = {'size': 1, 'mapper': lambda x: OwnAddressType.type_name(x)}


# -----------------------------------------------------------------------------
class HCI_Packet:
    '''
    Abstract Base class for HCI packets
    '''

    hci_packet_type: int

    @staticmethod
    def from_bytes(packet: bytes) -> HCI_Packet:
        packet_type = packet[0]

        if packet_type == HCI_COMMAND_PACKET:
            return HCI_Command.from_bytes(packet)

        if packet_type == HCI_ACL_DATA_PACKET:
            return HCI_AclDataPacket.from_bytes(packet)

        if packet_type == HCI_SYNCHRONOUS_DATA_PACKET:
            return HCI_SynchronousDataPacket.from_bytes(packet)

        if packet_type == HCI_EVENT_PACKET:
            return HCI_Event.from_bytes(packet)

        return HCI_CustomPacket(packet)

    def __init__(self, name):
        self.name = name

    def __bytes__(self) -> bytes:
        raise NotImplementedError

    def __repr__(self) -> str:
        return self.name


# -----------------------------------------------------------------------------
class HCI_CustomPacket(HCI_Packet):
    def __init__(self, payload):
        super().__init__('HCI_CUSTOM_PACKET')
        self.hci_packet_type = payload[0]
        self.payload = payload

    def __bytes__(self) -> bytes:
        return self.payload


# -----------------------------------------------------------------------------
class HCI_Command(HCI_Packet):
    '''
    See Bluetooth spec @ Vol 2, Part E - 5.4.1 HCI Command Packet
    '''

    hci_packet_type = HCI_COMMAND_PACKET
    command_names: Dict[int, str] = {}
    command_classes: Dict[int, Type[HCI_Command]] = {}

    @staticmethod
    def command(fields=(), return_parameters_fields=()):
        '''
        Decorator used to declare and register subclasses
        '''

        def inner(cls):
            cls.name = cls.__name__.upper()
            cls.op_code = key_with_value(cls.command_names, cls.name)
            if cls.op_code is None:
                raise KeyError(f'command {cls.name} not found in command_names')
            cls.fields = fields
            cls.return_parameters_fields = return_parameters_fields

            # Patch the __init__ method to fix the op_code
            if fields is not None:

                def init(self, parameters=None, **kwargs):
                    return HCI_Command.__init__(self, cls.op_code, parameters, **kwargs)

                cls.__init__ = init

            # Register a factory for this class
            HCI_Command.command_classes[cls.op_code] = cls

            return cls

        return inner

    @staticmethod
    def command_map(symbols: Dict[str, Any]) -> Dict[int, str]:
        return {
            command_code: command_name
            for (command_name, command_code) in symbols.items()
            if command_name.startswith('HCI_') and command_name.endswith('_COMMAND')
        }

    @classmethod
    def register_commands(cls, symbols: Dict[str, Any]) -> None:
        cls.command_names.update(cls.command_map(symbols))

    @staticmethod
    def from_bytes(packet: bytes) -> HCI_Command:
        op_code, length = struct.unpack_from('<HB', packet, 1)
        parameters = packet[4:]
        if len(parameters) != length:
            raise ValueError('invalid packet length')

        # Look for a registered class
        cls = HCI_Command.command_classes.get(op_code)
        if cls is None:
            # No class registered, just use a generic instance
            return HCI_Command(op_code, parameters)

        # Create a new instance
        if (fields := getattr(cls, 'fields', None)) is not None:
            self = cls.__new__(cls)
            HCI_Command.__init__(self, op_code, parameters)
            HCI_Object.init_from_bytes(self, parameters, 0, fields)
            return self

        return cls.from_parameters(parameters)  # type: ignore

    @staticmethod
    def command_name(op_code):
        name = HCI_Command.command_names.get(op_code)
        if name is not None:
            return name
        return f'[OGF=0x{op_code >> 10:02x}, OCF=0x{op_code & 0x3FF:04x}]'

    @classmethod
    def create_return_parameters(cls, **kwargs):
        return HCI_Object(cls.return_parameters_fields, **kwargs)

    @classmethod
    def parse_return_parameters(cls, parameters):
        if not cls.return_parameters_fields:
            return None
        return_parameters = HCI_Object.from_bytes(
            parameters, 0, cls.return_parameters_fields
        )
        return_parameters.fields = cls.return_parameters_fields
        return return_parameters

    def __init__(self, op_code, parameters=None, **kwargs):
        super().__init__(HCI_Command.command_name(op_code))
        if (fields := getattr(self, 'fields', None)) and kwargs:
            HCI_Object.init_from_fields(self, fields, kwargs)
            if parameters is None:
                parameters = HCI_Object.dict_to_bytes(kwargs, fields)
        self.op_code = op_code
        self.parameters = parameters

    def to_bytes(self):
        parameters = b'' if self.parameters is None else self.parameters
        return (
            struct.pack('<BHB', HCI_COMMAND_PACKET, self.op_code, len(parameters))
            + parameters
        )

    def __bytes__(self):
        return self.to_bytes()

    def __str__(self):
        result = color(self.name, 'green')
        if fields := getattr(self, 'fields', None):
            result += ':\n' + HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if self.parameters:
                result += f': {self.parameters.hex()}'
        return result


HCI_Command.register_commands(globals())


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('lap', {'size': 3, 'mapper': HCI_Constant.inquiry_lap_name}),
        ('inquiry_length', 1),
        ('num_responses', 1),
    ]
)
class HCI_Inquiry_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.1 Inquiry Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_Inquiry_Cancel_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.2 Inquiry Cancel Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('bd_addr', Address.parse_address),
        ('packet_type', 2),
        ('page_scan_repetition_mode', 1),
        ('reserved', 1),
        ('clock_offset', 2),
        ('allow_role_switch', 1),
    ]
)
class HCI_Create_Connection_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.5 Create Connection Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        ('reason', {'size': 1, 'mapper': HCI_Constant.error_name}),
    ]
)
class HCI_Disconnect_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.6 Disconnect Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_Create_Connection_Cancel_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.7 Create Connection Cancel Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('bd_addr', Address.parse_address), ('role', 1)])
class HCI_Accept_Connection_Request_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.8 Accept Connection Request Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('bd_addr', Address.parse_address),
        ('reason', {'size': 1, 'mapper': HCI_Constant.error_name}),
    ]
)
class HCI_Reject_Connection_Request_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.9 Reject Connection Request Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('bd_addr', Address.parse_address), ('link_key', 16)])
class HCI_Link_Key_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.10 Link Key Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_Link_Key_Request_Negative_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.11 Link Key Request Negative Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('bd_addr', Address.parse_address),
        ('pin_code_length', 1),
        ('pin_code', 16),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_PIN_Code_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.12 PIN Code Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_PIN_Code_Request_Negative_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.13 PIN Code Request Negative Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2), ('packet_type', 2)])
class HCI_Change_Connection_Packet_Type_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.14 Change Connection Packet Type Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2)])
class HCI_Authentication_Requested_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.15 Authentication Requested Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2), ('encryption_enable', 1)])
class HCI_Set_Connection_Encryption_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.16 Set Connection Encryption Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('bd_addr', Address.parse_address),
        ('page_scan_repetition_mode', 1),
        ('reserved', 1),
        ('clock_offset', 2),
    ]
)
class HCI_Remote_Name_Request_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.19 Remote Name Request Command
    '''

    R0 = 0x00
    R1 = 0x01
    R2 = 0x02


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2)])
class HCI_Read_Remote_Supported_Features_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.21 Read Remote Supported Features Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2), ('page_number', 1)])
class HCI_Read_Remote_Extended_Features_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.22 Read Remote Extended Features Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2)])
class HCI_Read_Remote_Version_Information_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.23 Read Remote Version Information Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2)])
class HCI_Read_Clock_Offset_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.23 Read Clock Offset Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('bd_addr', Address.parse_address),
        ('reason', {'size': 1, 'mapper': HCI_Constant.error_name}),
    ],
)
class HCI_Reject_Synchronous_Connection_Request_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.28 Reject Synchronous Connection Request Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('bd_addr', Address.parse_address),
        ('io_capability', {'size': 1, 'mapper': HCI_Constant.io_capability_name}),
        ('oob_data_present', 1),
        (
            'authentication_requirements',
            {'size': 1, 'mapper': HCI_Constant.authentication_requirements_name},
        ),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_IO_Capability_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.29 IO Capability Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_User_Confirmation_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.30 User Confirmation Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_User_Confirmation_Request_Negative_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.31 User Confirmation Request Negative Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address), ('numeric_value', 4)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_User_Passkey_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.32 User Passkey Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_User_Passkey_Request_Negative_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.33 User Passkey Request Negative Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('bd_addr', Address.parse_address),
        ('c', 16),
        ('r', 16),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_Remote_OOB_Data_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.34 Remote OOB Data Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_Remote_OOB_Data_Request_Negative_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.35 Remote OOB Data Request Negative Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('bd_addr', Address.parse_address),
        ('reason', 1),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_IO_Capability_Request_Negative_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.36 IO Capability Request Negative Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        ('transmit_bandwidth', 4),
        ('receive_bandwidth', 4),
        ('transmit_coding_format', 5),
        ('receive_coding_format', 5),
        ('transmit_codec_frame_size', 2),
        ('receive_codec_frame_size', 2),
        ('input_bandwidth', 4),
        ('output_bandwidth', 4),
        ('input_coding_format', 5),
        ('output_coding_format', 5),
        ('input_coded_data_size', 2),
        ('output_coded_data_size', 2),
        ('input_pcm_data_format', 1),
        ('output_pcm_data_format', 1),
        ('input_pcm_sample_payload_msb_position', 1),
        ('output_pcm_sample_payload_msb_position', 1),
        ('input_data_path', 1),
        ('output_data_path', 1),
        ('input_transport_unit_size', 1),
        ('output_transport_unit_size', 1),
        ('max_latency', 2),
        ('packet_type', 2),
        ('retransmission_effort', 1),
    ]
)
class HCI_Enhanced_Setup_Synchronous_Connection_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.45 Enhanced Setup Synchronous Connection Command
    '''

    class CodingFormat(enum.IntEnum):
        U_LOG = 0x00
        A_LOG = 0x01
        CVSD = 0x02
        TRANSPARENT = 0x03
        PCM = 0x04
        MSBC = 0x05
        LC3 = 0x06
        G729A = 0x07

        def to_bytes(self):
            return self.value.to_bytes(5, 'little')

        def __bytes__(self):
            return self.to_bytes()

    class PcmDataFormat(enum.IntEnum):
        NA = 0x00
        ONES_COMPLEMENT = 0x01
        TWOS_COMPLEMENT = 0x02
        SIGN_MAGNITUDE = 0x03
        UNSIGNED = 0x04

    class DataPath(enum.IntEnum):
        HCI = 0x00
        PCM = 0x01

    class RetransmissionEffort(enum.IntEnum):
        NO_RETRANSMISSION = 0x00
        OPTIMIZE_FOR_POWER = 0x01
        OPTIMIZE_FOR_QUALITY = 0x02
        DONT_CARE = 0xFF

    class PacketType(enum.IntFlag):
        HV1 = 0x0001
        HV2 = 0x0002
        HV3 = 0x0004
        EV3 = 0x0008
        EV4 = 0x0010
        EV5 = 0x0020
        NO_2_EV3 = 0x0040
        NO_3_EV3 = 0x0080
        NO_2_EV5 = 0x0100
        NO_3_EV5 = 0x0200


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('bd_addr', Address.parse_address),
        ('transmit_bandwidth', 4),
        ('receive_bandwidth', 4),
        ('transmit_coding_format', 5),
        ('receive_coding_format', 5),
        ('transmit_codec_frame_size', 2),
        ('receive_codec_frame_size', 2),
        ('input_bandwidth', 4),
        ('output_bandwidth', 4),
        ('input_coding_format', 5),
        ('output_coding_format', 5),
        ('input_coded_data_size', 2),
        ('output_coded_data_size', 2),
        ('input_pcm_data_format', 1),
        ('output_pcm_data_format', 1),
        ('input_pcm_sample_payload_msb_position', 1),
        ('output_pcm_sample_payload_msb_position', 1),
        ('input_data_path', 1),
        ('output_data_path', 1),
        ('input_transport_unit_size', 1),
        ('output_transport_unit_size', 1),
        ('max_latency', 2),
        ('packet_type', 2),
        ('retransmission_effort', 1),
    ]
)
class HCI_Enhanced_Accept_Synchronous_Connection_Request_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.46 Enhanced Accept Synchronous Connection Request Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('bd_addr', Address.parse_address),
        ('page_scan_repetition_mode', 1),
        ('clock_offset', 2),
    ]
)
class HCI_Truncated_Page_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.47 Truncated Page Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_Truncated_Page_Cancel_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.48 Truncated Page Cancel Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('enable', 1),
        ('lt_addr', 1),
        ('lpo_allowed', 1),
        ('packet_type', 2),
        ('interval_min', 2),
        ('interval_max', 2),
        ('supervision_timeout', 2),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('lt_addr', 1),
        ('interval', 2),
    ],
)
class HCI_Set_Connectionless_Peripheral_Broadcast_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.49 Set Connectionless Peripheral Broadcast Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('enable', 1),
        ('bd_addr', Address.parse_address),
        ('lt_addr', 1),
        ('interval', 2),
        ('clock_offset', 4),
        ('next_connectionless_peripheral_broadcast_clock', 4),
        ('supervision_timeout', 2),
        ('remote_timing_accuracy', 1),
        ('skip', 1),
        ('packet_type', 2),
        ('afh_channel_map', 10),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
        ('lt_addr', 1),
    ],
)
class HCI_Set_Connectionless_Peripheral_Broadcast_Receive_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.50 Set Connectionless Peripheral Broadcast Receive Command
    '''


# -----------------------------------------------------------------------------
class HCI_Start_Synchronization_Train_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.51 Start Synchronization Train Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('bd_addr', Address.parse_address),
        ('sync_scan_timeout', 2),
        ('sync_scan_window', 2),
        ('sync_scan_interval', 2),
    ],
)
class HCI_Receive_Synchronization_Train_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.52 Receive Synchronization Train Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('bd_addr', Address.parse_address),
        ('c_192', 16),
        ('r_192', 16),
        ('c_256', 16),
        ('r_256', 16),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ],
)
class HCI_Remote_OOB_Extended_Data_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.1.53 Remote OOB Extended Data Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        ('sniff_max_interval', 2),
        ('sniff_min_interval', 2),
        ('sniff_attempt', 2),
        ('sniff_timeout', 2),
    ]
)
class HCI_Sniff_Mode_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.2.2 Sniff Mode Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2)])
class HCI_Exit_Sniff_Mode_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.2.3 Exit Sniff Mode Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('bd_addr', Address.parse_address),
        ('role', {'size': 1, 'mapper': HCI_Constant.role_name}),
    ]
)
class HCI_Switch_Role_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.2.8 Switch Role Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2), ('link_policy_settings', 2)])
class HCI_Write_Link_Policy_Settings_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.2.10 Write Link Policy Settings Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('default_link_policy_settings', 2)])
class HCI_Write_Default_Link_Policy_Settings_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.2.12 Write Default Link Policy Settings Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        ('maximum_latency', 2),
        ('minimum_remote_timeout', 2),
        ('minimum_local_timeout', 2),
    ]
)
class HCI_Sniff_Subrating_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.2.14 Sniff Subrating Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('event_mask', 8)])
class HCI_Set_Event_Mask_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.1 Set Event Mask Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_Reset_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.2 Reset Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('filter_type', 1),
        ('filter_condition', '*'),
    ]
)
class HCI_Set_Event_Filter_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.3 Set Event Filter Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address), ('read_all_flag', 1)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('max_num_keys', 2),
        ('num_keys_read', 2),
    ],
)
class HCI_Read_Stored_Link_Key_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.8 Read Stored Link Key Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('bd_addr', Address.parse_address), ('delete_all_flag', 1)],
    return_parameters_fields=[('status', STATUS_SPEC), ('num_keys_deleted', 2)],
)
class HCI_Delete_Stored_Link_Key_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.10 Delete Stored Link Key Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [('local_name', {'size': 248, 'mapper': map_null_terminated_utf8_string})]
)
class HCI_Write_Local_Name_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.11 Write Local Name Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('local_name', {'size': 248, 'mapper': map_null_terminated_utf8_string}),
    ]
)
class HCI_Read_Local_Name_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.12 Read Local Name Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_accept_timeout', 2)])
class HCI_Write_Connection_Accept_Timeout_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.14 Write Connection Accept Timeout Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('page_timeout', 2)])
class HCI_Write_Page_Timeout_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.16 Write Page Timeout Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('scan_enable', 1)])
class HCI_Write_Scan_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.18 Write Scan Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('page_scan_interval', 2),
        ('page_scan_window', 2),
    ]
)
class HCI_Read_Page_Scan_Activity_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.19 Read Page Scan Activity Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('page_scan_interval', 2), ('page_scan_window', 2)])
class HCI_Write_Page_Scan_Activity_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.20 Write Page Scan Activity Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('inquiry_scan_interval', 2), ('inquiry_scan_window', 2)])
class HCI_Write_Inquiry_Scan_Activity_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.22 Write Inquiry Scan Activity Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('class_of_device', {'size': 3, 'mapper': map_class_of_device}),
    ]
)
class HCI_Read_Class_Of_Device_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.25 Read Class of Device Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('class_of_device', {'size': 3, 'mapper': map_class_of_device})])
class HCI_Write_Class_Of_Device_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.26 Write Class of Device Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[('status', STATUS_SPEC), ('voice_setting', 2)]
)
class HCI_Read_Voice_Setting_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.27 Read Voice Setting Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('voice_setting', 2)])
class HCI_Write_Voice_Setting_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.28 Write Voice Setting Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_Read_Synchronous_Flow_Control_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.36 Read Synchronous Flow Control Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('synchronous_flow_control_enable', 1)])
class HCI_Write_Synchronous_Flow_Control_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.37 Write Synchronous Flow Control Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('host_acl_data_packet_length', 2),
        ('host_synchronous_data_packet_length', 1),
        ('host_total_num_acl_data_packets', 2),
        ('host_total_num_synchronous_data_packets', 2),
    ]
)
class HCI_Host_Buffer_Size_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.39 Host Buffer Size Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('handle', 2), ('link_supervision_timeout', 2)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('handle', 2),
    ],
)
class HCI_Write_Link_Supervision_Timeout_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.42 Write Link Supervision Timeout Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[('status', STATUS_SPEC), ('num_support_iac', 1)]
)
class HCI_Read_Number_Of_Supported_IAC_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.43 Read Number Of Supported IAC Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('num_current_iac', 1),
        ('iac_lap', '*'),  # TODO: this should be parsed as an array
    ]
)
class HCI_Read_Current_IAC_LAP_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.44 Read Current IAC LAP Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('scan_type', 1)])
class HCI_Write_Inquiry_Scan_Type_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.48 Write Inquiry Scan Type Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('inquiry_mode', 1)])
class HCI_Write_Inquiry_Mode_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.50 Write Inquiry Mode Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[('status', STATUS_SPEC), ('page_scan_type', 1)]
)
class HCI_Read_Page_Scan_Type_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.51 Read Page Scan Type Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('page_scan_type', 1)])
class HCI_Write_Page_Scan_Type_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.52 Write Page Scan Type Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('fec_required', 1),
        (
            'extended_inquiry_response',
            {'size': 240, 'serializer': lambda x: padded_bytes(x, 240)},
        ),
    ]
)
class HCI_Write_Extended_Inquiry_Response_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.56 Write Extended Inquiry Response Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('simple_pairing_mode', 1)])
class HCI_Write_Simple_Pairing_Mode_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.59 Write Simple Pairing Mode Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('c', 16),
        ('r', 16),
    ]
)
class HCI_Read_Local_OOB_Data_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.60 Read Local OOB Data Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[('status', STATUS_SPEC), ('tx_power', -1)]
)
class HCI_Read_Inquiry_Response_Transmit_Power_Level_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.61 Read Inquiry Response Transmit Power Level Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[('status', STATUS_SPEC), ('erroneous_data_reporting', 1)]
)
class HCI_Read_Default_Erroneous_Data_Reporting_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.64 Read Default Erroneous Data Reporting Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('event_mask_page_2', 8)])
class HCI_Set_Event_Mask_Page_2_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.69 Set Event Mask Page 2 Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_Read_LE_Host_Support_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.78 Read LE Host Support Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('le_supported_host', 1), ('simultaneous_le_host', 1)])
class HCI_Write_LE_Host_Support_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.79 Write LE Host Support Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('secure_connections_host_support', 1)])
class HCI_Write_Secure_Connections_Host_Support_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.92 Write Secure Connections Host Support Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2), ('authenticated_payload_timeout', 2)])
class HCI_Write_Authenticated_Payload_Timeout_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.94 Write Authenticated Payload Timeout Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('c_192', 16),
        ('r_192', 16),
        ('c_256', 16),
        ('r_256', 16),
    ]
)
class HCI_Read_Local_OOB_Extended_Data_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.3.95 Read Local OOB Extended Data Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('hci_version', 1),
        ('hci_subversion', 2),
        ('lmp_version', 1),
        ('company_identifier', 2),
        ('lmp_subversion', 2),
    ]
)
class HCI_Read_Local_Version_Information_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.4.1 Read Local Version Information Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[('status', STATUS_SPEC), ('supported_commands', 64)]
)
class HCI_Read_Local_Supported_Commands_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.4.2 Read Local Supported Commands Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_Read_Local_Supported_Features_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.4.3 Read Local Supported Features Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('page_number', 1)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('page_number', 1),
        ('maximum_page_number', 1),
        ('extended_lmp_features', 8),
    ],
)
class HCI_Read_Local_Extended_Features_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.4.4 Read Local Extended Features Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('hc_acl_data_packet_length', 2),
        ('hc_synchronous_data_packet_length', 1),
        ('hc_total_num_acl_data_packets', 2),
        ('hc_total_num_synchronous_data_packets', 2),
    ]
)
class HCI_Read_Buffer_Size_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.4.5 Read Buffer Size Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
    ]
)
class HCI_Read_BD_ADDR_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.4.6 Read BD_ADDR Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_Read_Local_Supported_Codecs_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.4.8 Read Local Supported Codecs Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('handle', 2)],
    return_parameters_fields=[('status', STATUS_SPEC), ('handle', 2), ('rssi', -1)],
)
class HCI_Read_RSSI_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.5.4 Read RSSI Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('connection_handle', 2)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('key_size', 1),
    ],
)
class HCI_Read_Encryption_Key_Size_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.5.7 Read Encryption Key Size Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('le_event_mask', 8)])
class HCI_LE_Set_Event_Mask_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.1 LE Set Event Mask Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('hc_le_acl_data_packet_length', 2),
        ('hc_total_num_le_acl_data_packets', 1),
    ]
)
class HCI_LE_Read_Buffer_Size_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.2 LE Read Buffer Size Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[('status', STATUS_SPEC), ('le_features', 8)]
)
class HCI_LE_Read_Local_Supported_Features_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.3 LE Read Local Supported Features Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        (
            'random_address',
            lambda data, offset: Address.parse_address_with_type(
                data, offset, Address.RANDOM_DEVICE_ADDRESS
            ),
        )
    ]
)
class HCI_LE_Set_Random_Address_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.4 LE Set Random Address Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    # pylint: disable=line-too-long,unnecessary-lambda
    [
        ('advertising_interval_min', 2),
        ('advertising_interval_max', 2),
        (
            'advertising_type',
            {
                'size': 1,
                'mapper': lambda x: HCI_LE_Set_Advertising_Parameters_Command.advertising_type_name(
                    x
                ),
            },
        ),
        ('own_address_type', OwnAddressType.TYPE_SPEC),
        ('peer_address_type', Address.ADDRESS_TYPE_SPEC),
        ('peer_address', Address.parse_address_preceded_by_type),
        ('advertising_channel_map', 1),
        ('advertising_filter_policy', 1),
    ]
)
class HCI_LE_Set_Advertising_Parameters_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.5 LE Set Advertising Parameters Command
    '''

    ADV_IND = 0x00
    ADV_DIRECT_IND = 0x01
    ADV_SCAN_IND = 0x02
    ADV_NONCONN_IND = 0x03
    ADV_DIRECT_IND_LOW_DUTY = 0x04

    ADVERTISING_TYPE_NAMES = {
        ADV_IND: 'ADV_IND',
        ADV_DIRECT_IND: 'ADV_DIRECT_IND',
        ADV_SCAN_IND: 'ADV_SCAN_IND',
        ADV_NONCONN_IND: 'ADV_NONCONN_IND',
        ADV_DIRECT_IND_LOW_DUTY: 'ADV_DIRECT_IND_LOW_DUTY',
    }

    @classmethod
    def advertising_type_name(cls, advertising_type):
        return name_or_number(cls.ADVERTISING_TYPE_NAMES, advertising_type)


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.6 LE Read Advertising Physical Channel Tx Power Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        (
            'advertising_data',
            {
                'parser': HCI_Object.parse_length_prefixed_bytes,
                'serializer': functools.partial(
                    HCI_Object.serialize_length_prefixed_bytes, padded_size=32
                ),
            },
        )
    ]
)
class HCI_LE_Set_Advertising_Data_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.7 LE Set Advertising Data Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        (
            'scan_response_data',
            {
                'parser': HCI_Object.parse_length_prefixed_bytes,
                'serializer': functools.partial(
                    HCI_Object.serialize_length_prefixed_bytes, padded_size=32
                ),
            },
        )
    ]
)
class HCI_LE_Set_Scan_Response_Data_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.8 LE Set Scan Response Data Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('advertising_enable', 1)])
class HCI_LE_Set_Advertising_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.9 LE Set Advertising Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('le_scan_type', 1),
        ('le_scan_interval', 2),
        ('le_scan_window', 2),
        ('own_address_type', OwnAddressType.TYPE_SPEC),
        ('scanning_filter_policy', 1),
    ]
)
class HCI_LE_Set_Scan_Parameters_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.10 LE Set Scan Parameters Command
    '''

    PASSIVE_SCANNING = 0
    ACTIVE_SCANNING = 1

    BASIC_UNFILTERED_POLICY = 0x00
    BASIC_FILTERED_POLICY = 0x01
    EXTENDED_UNFILTERED_POLICY = 0x02
    EXTENDED_FILTERED_POLICY = 0x03


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('le_scan_enable', 1),
        ('filter_duplicates', 1),
    ]
)
class HCI_LE_Set_Scan_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.11 LE Set Scan Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('le_scan_interval', 2),
        ('le_scan_window', 2),
        ('initiator_filter_policy', 1),
        ('peer_address_type', Address.ADDRESS_TYPE_SPEC),
        ('peer_address', Address.parse_address_preceded_by_type),
        ('own_address_type', OwnAddressType.TYPE_SPEC),
        ('connection_interval_min', 2),
        ('connection_interval_max', 2),
        ('max_latency', 2),
        ('supervision_timeout', 2),
        ('min_ce_length', 2),
        ('max_ce_length', 2),
    ]
)
class HCI_LE_Create_Connection_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.12 LE Create Connection Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_LE_Create_Connection_Cancel_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.13 LE Create Connection Cancel Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_LE_Read_Filter_Accept_List_Size_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.14 LE Read Filter Accept List Size Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_LE_Clear_Filter_Accept_List_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.15 LE Clear Filter Accept List Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('address_type', Address.ADDRESS_TYPE_SPEC),
        ('address', Address.parse_address_preceded_by_type),
    ]
)
class HCI_LE_Add_Device_To_Filter_Accept_List_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.16 LE Add Device To Filter Accept List Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('address_type', Address.ADDRESS_TYPE_SPEC),
        ('address', Address.parse_address_preceded_by_type),
    ]
)
class HCI_LE_Remove_Device_From_Filter_Accept_List_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.17 LE Remove Device From Filter Accept List Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        ('connection_interval_min', 2),
        ('connection_interval_max', 2),
        ('max_latency', 2),
        ('supervision_timeout', 2),
        ('min_ce_length', 2),
        ('max_ce_length', 2),
    ]
)
class HCI_LE_Connection_Update_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.18 LE Connection Update Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2)])
class HCI_LE_Read_Remote_Features_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.21 LE Read Remote Features Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[("status", STATUS_SPEC), ("random_number", 8)]
)
class HCI_LE_Rand_Command(HCI_Command):
    """
    See Bluetooth spec @ 7.8.23 LE Rand Command
    """


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        ('random_number', 8),
        ('encrypted_diversifier', 2),
        ('long_term_key', 16),
    ]
)
class HCI_LE_Enable_Encryption_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.24 LE Enable Encryption Command
    (renamed from "LE Start Encryption Command" in version prior to 5.2 of the
    specification)
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2), ('long_term_key', 16)])
class HCI_LE_Long_Term_Key_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.25 LE Long Term Key Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('connection_handle', 2)])
class HCI_LE_Long_Term_Key_Request_Negative_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.26 LE Long Term Key Request Negative Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_LE_Read_Supported_States_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.27 LE Read Supported States Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        ('interval_min', 2),
        ('interval_max', 2),
        ('max_latency', 2),
        ('timeout', 2),
        ('min_ce_length', 2),
        ('max_ce_length', 2),
    ]
)
class HCI_LE_Remote_Connection_Parameter_Request_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.31 LE Remote Connection Parameter Request Reply Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        ('reason', {'size': 1, 'mapper': HCI_Constant.error_name}),
    ]
)
class HCI_LE_Remote_Connection_Parameter_Request_Negative_Reply_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.32 LE Remote Connection Parameter Request Negative Reply
    Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('connection_handle', 2),
        ('tx_octets', 2),
        ('tx_time', 2),
    ],
    return_parameters_fields=[('status', STATUS_SPEC), ('connection_handle', 2)],
)
class HCI_LE_Set_Data_Length_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.33 LE Set Data Length Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('suggested_max_tx_octets', 2),
        ('suggested_max_tx_time', 2),
    ]
)
class HCI_LE_Read_Suggested_Default_Data_Length_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.34 LE Read Suggested Default Data Length Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('suggested_max_tx_octets', 2), ('suggested_max_tx_time', 2)])
class HCI_LE_Write_Suggested_Default_Data_Length_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.35 LE Write Suggested Default Data Length Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('peer_identity_address_type', Address.ADDRESS_TYPE_SPEC),
        ('peer_identity_address', Address.parse_address_preceded_by_type),
        ('peer_irk', 16),
        ('local_irk', 16),
    ]
)
class HCI_LE_Add_Device_To_Resolving_List_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.38 LE Add Device To Resolving List Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_LE_Clear_Resolving_List_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.40 LE Clear Resolving List Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('address_resolution_enable', 1)])
class HCI_LE_Set_Address_Resolution_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.44 LE Set Address Resolution Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('rpa_timeout', 2)])
class HCI_LE_Set_Resolvable_Private_Address_Timeout_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.45 LE Set Resolvable Private Address Timeout Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('supported_max_tx_octets', 2),
        ('supported_max_tx_time', 2),
        ('supported_max_rx_octets', 2),
        ('supported_max_rx_time', 2),
    ]
)
class HCI_LE_Read_Maximum_Data_Length_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.46 LE Read Maximum Data Length Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('connection_handle', 2)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('tx_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
        ('rx_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
    ],
)
class HCI_LE_Read_PHY_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.47 LE Read PHY Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        (
            'all_phys',
            {
                'size': 1,
                'mapper': lambda x: bit_flags_to_strings(
                    x, HCI_LE_Set_Default_PHY_Command.ANY_PHY_BIT_NAMES
                ),
            },
        ),
        (
            'tx_phys',
            {
                'size': 1,
                'mapper': lambda x: bit_flags_to_strings(x, HCI_LE_PHY_BIT_NAMES),
            },
        ),
        (
            'rx_phys',
            {
                'size': 1,
                'mapper': lambda x: bit_flags_to_strings(x, HCI_LE_PHY_BIT_NAMES),
            },
        ),
    ]
)
class HCI_LE_Set_Default_PHY_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.48 LE Set Default PHY Command
    '''

    ANY_TX_PHY_BIT = 0
    ANY_RX_PHY_BIT = 1

    ANY_PHY_BIT_NAMES = ['Any TX', 'Any RX']


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('connection_handle', 2),
        (
            'all_phys',
            {
                'size': 1,
                'mapper': lambda x: bit_flags_to_strings(
                    x, HCI_LE_Set_PHY_Command.ANY_PHY_BIT_NAMES
                ),
            },
        ),
        (
            'tx_phys',
            {
                'size': 1,
                'mapper': lambda x: bit_flags_to_strings(x, HCI_LE_PHY_BIT_NAMES),
            },
        ),
        (
            'rx_phys',
            {
                'size': 1,
                'mapper': lambda x: bit_flags_to_strings(x, HCI_LE_PHY_BIT_NAMES),
            },
        ),
        ('phy_options', 2),
    ]
)
class HCI_LE_Set_PHY_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.49 LE Set PHY Command
    '''

    ANY_TX_PHY_BIT = 0
    ANY_RX_PHY_BIT = 1

    ANY_PHY_BIT_NAMES = ['Any TX', 'Any RX']


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('advertising_handle', 1),
        (
            'random_address',
            lambda data, offset: Address.parse_address_with_type(
                data, offset, Address.RANDOM_DEVICE_ADDRESS
            ),
        ),
    ]
)
class HCI_LE_Set_Advertising_Set_Random_Address_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.52 LE Set Advertising Set Random Address Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    # pylint: disable=line-too-long,unnecessary-lambda
    fields=[
        ('advertising_handle', 1),
        (
            'advertising_event_properties',
            {
                'size': 2,
                'mapper': lambda x: str(
                    HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties(
                        x
                    )
                ),
            },
        ),
        ('primary_advertising_interval_min', 3),
        ('primary_advertising_interval_max', 3),
        (
            'primary_advertising_channel_map',
            {
                'size': 1,
                'mapper': lambda x: str(
                    HCI_LE_Set_Extended_Advertising_Parameters_Command.ChannelMap(x)
                ),
            },
        ),
        ('own_address_type', OwnAddressType.TYPE_SPEC),
        ('peer_address_type', Address.ADDRESS_TYPE_SPEC),
        ('peer_address', Address.parse_address_preceded_by_type),
        ('advertising_filter_policy', 1),
        ('advertising_tx_power', 1),
        ('primary_advertising_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
        ('secondary_advertising_max_skip', 1),
        ('secondary_advertising_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
        ('advertising_sid', 1),
        ('scan_request_notification_enable', 1),
    ],
    return_parameters_fields=[('status', STATUS_SPEC), ('selected_tx__power', 1)],
)
class HCI_LE_Set_Extended_Advertising_Parameters_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.53 LE Set Extended Advertising Parameters Command
    '''

    class AdvertisingProperties(enum.IntFlag):
        CONNECTABLE_ADVERTISING = 1 << 0
        SCANNABLE_ADVERTISING = 1 << 1
        DIRECTED_ADVERTISING = 1 << 2
        HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING = 1 << 3
        USE_LEGACY_ADVERTISING_PDUS = 1 << 4
        ANONYMOUS_ADVERTISING = 1 << 5
        INCLUDE_TX_POWER = 1 << 6

        def __str__(self) -> str:
            return '|'.join(
                flag.name
                for flag in HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties
                if self.value & flag.value and flag.name is not None
            )

    class ChannelMap(enum.IntFlag):
        CHANNEL_37 = 1 << 0
        CHANNEL_38 = 1 << 1
        CHANNEL_39 = 1 << 2

        def __str__(self) -> str:
            return '|'.join(
                flag.name
                for flag in HCI_LE_Set_Extended_Advertising_Parameters_Command.ChannelMap
                if self.value & flag.value and flag.name is not None
            )


# -----------------------------------------------------------------------------
@HCI_Command.command(
    # pylint: disable=line-too-long,unnecessary-lambda
    [
        ('advertising_handle', 1),
        (
            'operation',
            {
                'size': 1,
                'mapper': lambda x: HCI_LE_Set_Extended_Advertising_Data_Command.Operation(
                    x
                ).name,
            },
        ),
        ('fragment_preference', 1),
        (
            'advertising_data',
            {
                'parser': HCI_Object.parse_length_prefixed_bytes,
                'serializer': HCI_Object.serialize_length_prefixed_bytes,
            },
        ),
    ]
)
class HCI_LE_Set_Extended_Advertising_Data_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.54 LE Set Extended Advertising Data Command
    '''

    class Operation(enum.IntEnum):
        INTERMEDIATE_FRAGMENT = 0x00
        FIRST_FRAGMENT = 0x01
        LAST_FRAGMENT = 0x02
        COMPLETE_DATA = 0x03
        UNCHANGED_DATA = 0x04


# -----------------------------------------------------------------------------
@HCI_Command.command(
    # pylint: disable=line-too-long,unnecessary-lambda
    [
        ('advertising_handle', 1),
        (
            'operation',
            {
                'size': 1,
                'mapper': lambda x: HCI_LE_Set_Extended_Advertising_Data_Command.Operation(
                    x
                ).name,
            },
        ),
        ('fragment_preference', 1),
        (
            'scan_response_data',
            {
                'parser': HCI_Object.parse_length_prefixed_bytes,
                'serializer': HCI_Object.serialize_length_prefixed_bytes,
            },
        ),
    ]
)
class HCI_LE_Set_Extended_Scan_Response_Data_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.55 LE Set Extended Scan Response Data Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('enable', 1),
        [
            ('advertising_handles', 1),
            ('durations', 2),
            ('max_extended_advertising_events', 1),
        ],
    ]
)
class HCI_LE_Set_Extended_Advertising_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.56 LE Set Extended Advertising Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('max_advertising_data_length', 2),
    ]
)
class HCI_LE_Read_Maximum_Advertising_Data_Length_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.57 LE Read Maximum Advertising Data Length Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('num_supported_advertising_sets', 1),
    ]
)
class HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.58 LE Read Number of Supported Advertising Sets Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('advertising_handle', 1)])
class HCI_LE_Remove_Advertising_Set_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.59 LE Remove Advertising Set Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command()
class HCI_LE_Clear_Advertising_Sets_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.60 LE Clear Advertising Sets Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command([('enable', 1), ('advertising_handle', 1)])
class HCI_LE_Set_Periodic_Advertising_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.63 LE Set Periodic Advertising Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(fields=None)
class HCI_LE_Set_Extended_Scan_Parameters_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.64 LE Set Extended Scan Parameters Command
    '''

    PASSIVE_SCANNING = 0
    ACTIVE_SCANNING = 1

    BASIC_UNFILTERED_POLICY = 0x00
    BASIC_FILTERED_POLICY = 0x01
    EXTENDED_UNFILTERED_POLICY = 0x02
    EXTENDED_FILTERED_POLICY = 0x03

    @classmethod
    def from_parameters(cls, parameters):
        own_address_type = parameters[0]
        scanning_filter_policy = parameters[1]
        scanning_phys = parameters[2]

        phy_bits_set = bin(scanning_phys).count('1')
        scan_types = []
        scan_intervals = []
        scan_windows = []
        for i in range(phy_bits_set):
            scan_types.append(parameters[3 + (5 * i)])
            scan_intervals.append(
                struct.unpack_from('<H', parameters, 3 + (5 * i) + 1)[0]
            )
            scan_windows.append(
                struct.unpack_from('<H', parameters, 3 + (5 * i) + 3)[0]
            )

        return cls(
            own_address_type=own_address_type,
            scanning_filter_policy=scanning_filter_policy,
            scanning_phys=scanning_phys,
            scan_types=scan_types,
            scan_intervals=scan_intervals,
            scan_windows=scan_windows,
        )

    def __init__(
        self,
        own_address_type,
        scanning_filter_policy,
        scanning_phys,
        scan_types,
        scan_intervals,
        scan_windows,
    ):
        super().__init__(HCI_LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND)
        self.own_address_type = own_address_type
        self.scanning_filter_policy = scanning_filter_policy
        self.scanning_phys = scanning_phys
        self.scan_types = scan_types
        self.scan_intervals = scan_intervals
        self.scan_windows = scan_windows

        self.parameters = bytes(
            [own_address_type, scanning_filter_policy, scanning_phys]
        )
        phy_bits_set = bin(scanning_phys).count('1')
        for i in range(phy_bits_set):
            self.parameters += struct.pack(
                '<BHH', scan_types[i], scan_intervals[i], scan_windows[i]
            )

    def __str__(self):
        scanning_phys_strs = bit_flags_to_strings(
            self.scanning_phys, HCI_LE_PHY_BIT_NAMES
        )
        fields = [
            (
                'own_address_type:      ',
                Address.address_type_name(self.own_address_type),
            ),
            ('scanning_filter_policy:', self.scanning_filter_policy),
            ('scanning_phys:         ', ','.join(scanning_phys_strs)),
        ]
        for (i, scanning_phy_str) in enumerate(scanning_phys_strs):
            fields.append(
                (
                    f'{scanning_phy_str}.scan_type:    ',
                    'PASSIVE'
                    if self.scan_types[i] == self.PASSIVE_SCANNING
                    else 'ACTIVE',
                )
            )
            fields.append(
                (f'{scanning_phy_str}.scan_interval:', self.scan_intervals[i])
            )
            fields.append((f'{scanning_phy_str}.scan_window:  ', self.scan_windows[i]))

        return (
            color(self.name, 'green')
            + ':\n'
            + '\n'.join(
                [
                    color('  ' + field[0], 'cyan') + ' ' + str(field[1])
                    for field in fields
                ]
            )
        )


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [('enable', 1), ('filter_duplicates', 1), ('duration', 2), ('period', 2)]
)
class HCI_LE_Set_Extended_Scan_Enable_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.65 LE Set Extended Scan Enable Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(fields=None)
class HCI_LE_Extended_Create_Connection_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.66 LE Extended Create Connection Command
    '''

    @classmethod
    def from_parameters(cls, parameters):
        initiator_filter_policy = parameters[0]
        own_address_type = parameters[1]
        peer_address_type = parameters[2]
        peer_address = Address.parse_address_preceded_by_type(parameters, 3)[1]
        initiating_phys = parameters[9]

        phy_bits_set = bin(initiating_phys).count('1')

        def read_parameter_list(offset):
            return [
                struct.unpack_from('<H', parameters, offset + 16 * i)[0]
                for i in range(phy_bits_set)
            ]

        return cls(
            initiator_filter_policy=initiator_filter_policy,
            own_address_type=own_address_type,
            peer_address_type=peer_address_type,
            peer_address=peer_address,
            initiating_phys=initiating_phys,
            scan_intervals=read_parameter_list(10),
            scan_windows=read_parameter_list(12),
            connection_interval_mins=read_parameter_list(14),
            connection_interval_maxs=read_parameter_list(16),
            max_latencies=read_parameter_list(18),
            supervision_timeouts=read_parameter_list(20),
            min_ce_lengths=read_parameter_list(22),
            max_ce_lengths=read_parameter_list(24),
        )

    def __init__(
        self,
        initiator_filter_policy,
        own_address_type,
        peer_address_type,
        peer_address,
        initiating_phys,
        scan_intervals,
        scan_windows,
        connection_interval_mins,
        connection_interval_maxs,
        max_latencies,
        supervision_timeouts,
        min_ce_lengths,
        max_ce_lengths,
    ):
        super().__init__(HCI_LE_EXTENDED_CREATE_CONNECTION_COMMAND)
        self.initiator_filter_policy = initiator_filter_policy
        self.own_address_type = own_address_type
        self.peer_address_type = peer_address_type
        self.peer_address = peer_address
        self.initiating_phys = initiating_phys
        self.scan_intervals = scan_intervals
        self.scan_windows = scan_windows
        self.connection_interval_mins = connection_interval_mins
        self.connection_interval_maxs = connection_interval_maxs
        self.max_latencies = max_latencies
        self.supervision_timeouts = supervision_timeouts
        self.min_ce_lengths = min_ce_lengths
        self.max_ce_lengths = max_ce_lengths

        self.parameters = (
            bytes([initiator_filter_policy, own_address_type, peer_address_type])
            + bytes(peer_address)
            + bytes([initiating_phys])
        )

        phy_bits_set = bin(initiating_phys).count('1')
        for i in range(phy_bits_set):
            self.parameters += struct.pack(
                '<HHHHHHHH',
                scan_intervals[i],
                scan_windows[i],
                connection_interval_mins[i],
                connection_interval_maxs[i],
                max_latencies[i],
                supervision_timeouts[i],
                min_ce_lengths[i],
                max_ce_lengths[i],
            )

    def __str__(self):
        initiating_phys_strs = bit_flags_to_strings(
            self.initiating_phys, HCI_LE_PHY_BIT_NAMES
        )
        fields = [
            ('initiator_filter_policy:', self.initiator_filter_policy),
            (
                'own_address_type:       ',
                OwnAddressType.type_name(self.own_address_type),
            ),
            (
                'peer_address_type:      ',
                Address.address_type_name(self.peer_address_type),
            ),
            ('peer_address:           ', str(self.peer_address)),
            ('initiating_phys:        ', ','.join(initiating_phys_strs)),
        ]
        for (i, initiating_phys_str) in enumerate(initiating_phys_strs):
            fields.append(
                (
                    f'{initiating_phys_str}.scan_interval:          ',
                    self.scan_intervals[i],
                )
            )
            fields.append(
                (
                    f'{initiating_phys_str}.scan_window:            ',
                    self.scan_windows[i],
                )
            )
            fields.append(
                (
                    f'{initiating_phys_str}.connection_interval_min:',
                    self.connection_interval_mins[i],
                )
            )
            fields.append(
                (
                    f'{initiating_phys_str}.connection_interval_max:',
                    self.connection_interval_maxs[i],
                )
            )
            fields.append(
                (
                    f'{initiating_phys_str}.max_latency:            ',
                    self.max_latencies[i],
                )
            )
            fields.append(
                (
                    f'{initiating_phys_str}.supervision_timeout:    ',
                    self.supervision_timeouts[i],
                )
            )
            fields.append(
                (
                    f'{initiating_phys_str}.min_ce_length:          ',
                    self.min_ce_lengths[i],
                )
            )
            fields.append(
                (
                    f'{initiating_phys_str}.max_ce_length:          ',
                    self.max_ce_lengths[i],
                )
            )

        return (
            color(self.name, 'green')
            + ':\n'
            + '\n'.join(
                [
                    color('  ' + field[0], 'cyan') + ' ' + str(field[1])
                    for field in fields
                ]
            )
        )


# -----------------------------------------------------------------------------
@HCI_Command.command(
    [
        ('peer_identity_address_type', Address.ADDRESS_TYPE_SPEC),
        ('peer_identity_address', Address.parse_address_preceded_by_type),
        (
            'privacy_mode',
            {
                'size': 1,
                # pylint: disable-next=unnecessary-lambda
                'mapper': lambda x: HCI_LE_Set_Privacy_Mode_Command.privacy_mode_name(
                    x
                ),
            },
        ),
    ]
)
class HCI_LE_Set_Privacy_Mode_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.77 LE Set Privacy Mode Command
    '''

    NETWORK_PRIVACY_MODE = 0x00
    DEVICE_PRIVACY_MODE = 0x01

    PRIVACY_MODE_NAMES = {
        NETWORK_PRIVACY_MODE: 'NETWORK_PRIVACY_MODE',
        DEVICE_PRIVACY_MODE: 'DEVICE_PRIVACY_MODE',
    }

    @classmethod
    def privacy_mode_name(cls, privacy_mode):
        return name_or_number(cls.PRIVACY_MODE_NAMES, privacy_mode)


# -----------------------------------------------------------------------------
@HCI_Command.command([('bit_number', 1), ('bit_value', 1)])
class HCI_LE_Set_Host_Feature_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.115 LE Set Host Feature Command
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('cig_id', 1),
        ('sdu_interval_c_to_p', 3),
        ('sdu_interval_p_to_c', 3),
        ('worst_case_sca', 1),
        ('packing', 1),
        ('framing', 1),
        ('max_transport_latency_c_to_p', 2),
        ('max_transport_latency_p_to_c', 2),
        [
            ('cis_id', 1),
            ('max_sdu_c_to_p', 2),
            ('max_sdu_p_to_c', 2),
            ('phy_c_to_p', 1),
            ('phy_p_to_c', 1),
            ('rtn_c_to_p', 1),
            ('rtn_p_to_c', 1),
        ],
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('cig_id', 1),
        [('connection_handle', 2)],
    ],
)
class HCI_LE_Set_CIG_Parameters_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.97 LE Set CIG Parameters Command
    '''

    cig_id: int
    sdu_interval_c_to_p: int
    sdu_interval_p_to_c: int
    worst_case_sca: int
    packing: int
    framing: int
    max_transport_latency_c_to_p: int
    max_transport_latency_p_to_c: int
    cis_id: List[int]
    max_sdu_c_to_p: List[int]
    max_sdu_p_to_c: List[int]
    phy_c_to_p: List[int]
    phy_p_to_c: List[int]
    rtn_c_to_p: List[int]
    rtn_p_to_c: List[int]


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        [
            ('cis_connection_handle', 2),
            ('acl_connection_handle', 2),
        ],
    ],
)
class HCI_LE_Create_CIS_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.99 LE Create CIS command
    '''

    cis_connection_handle: List[int]
    acl_connection_handle: List[int]


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('cig_id', 1)],
    return_parameters_fields=[('status', STATUS_SPEC), ('cig_id', 1)],
)
class HCI_LE_Remove_CIG_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.100 LE Remove CIG command
    '''

    cig_id: int


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('connection_handle', 2)],
)
class HCI_LE_Accept_CIS_Request_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.101 LE Accept CIS Request command
    '''

    connection_handle: int


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('connection_handle', 2)],
)
class HCI_LE_Reject_CIS_Request_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.102 LE Reject CIS Request command
    '''

    connection_handle: int


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('connection_handle', 2),
        ('data_path_direction', 1),
        ('data_path_id', 1),
        ('codec_id', 5),
        ('controller_delay', 3),
        ('codec_configuration', '*'),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
    ],
)
class HCI_LE_Setup_ISO_Data_Path_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.109 LE Setup ISO Data Path command
    '''

    connection_handle: int
    data_path_direction: int
    data_path_id: int
    codec_id: int
    controller_delay: int
    codec_configuration: int


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        ('connection_handle', 2),
        ('data_path_direction', 1),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
    ],
)
class HCI_LE_Remove_ISO_Data_Path_Command(HCI_Command):
    '''
    See Bluetooth spec @ 7.8.110 LE Remove ISO Data Path command
    '''

    connection_handle: int
    data_path_direction: int


# -----------------------------------------------------------------------------
# HCI Events
# -----------------------------------------------------------------------------
class HCI_Event(HCI_Packet):
    '''
    See Bluetooth spec @ Vol 2, Part E - 5.4.4 HCI Event Packet
    '''

    hci_packet_type = HCI_EVENT_PACKET
    event_names: Dict[int, str] = {}
    event_classes: Dict[int, Type[HCI_Event]] = {}

    @staticmethod
    def event(fields=()):
        '''
        Decorator used to declare and register subclasses
        '''

        def inner(cls):
            cls.name = cls.__name__.upper()
            cls.event_code = key_with_value(cls.event_names, cls.name)
            if cls.event_code is None:
                raise KeyError(f'event {cls.name} not found in event_names')
            cls.fields = fields

            # Patch the __init__ method to fix the event_code
            def init(self, parameters=None, **kwargs):
                return HCI_Event.__init__(self, cls.event_code, parameters, **kwargs)

            cls.__init__ = init

            # Register a factory for this class
            HCI_Event.event_classes[cls.event_code] = cls

            return cls

        return inner

    @staticmethod
    def event_map(symbols: Dict[str, Any]) -> Dict[int, str]:
        return {
            event_code: event_name
            for (event_name, event_code) in symbols.items()
            if event_name.startswith('HCI_')
            and not event_name.startswith('HCI_LE_')
            and event_name.endswith('_EVENT')
        }

    @staticmethod
    def event_name(event_code):
        return name_or_number(HCI_Event.event_names, event_code)

    @staticmethod
    def register_events(symbols: Dict[str, Any]) -> None:
        HCI_Event.event_names.update(HCI_Event.event_map(symbols))

    @staticmethod
    def registered(event_class):
        event_class.name = event_class.__name__.upper()
        event_class.event_code = key_with_value(HCI_Event.event_names, event_class.name)
        if event_class.event_code is None:
            raise KeyError(f'event {event_class.name} not found in event_names')

        # Register a factory for this class
        HCI_Event.event_classes[event_class.event_code] = event_class

        return event_class

    @staticmethod
    def from_bytes(packet: bytes) -> HCI_Event:
        event_code = packet[1]
        length = packet[2]
        parameters = packet[3:]
        if len(parameters) != length:
            raise ValueError('invalid packet length')

        cls: Any
        if event_code == HCI_LE_META_EVENT:
            # We do this dispatch here and not in the subclass in order to avoid call
            # loops
            subevent_code = parameters[0]
            cls = HCI_LE_Meta_Event.subevent_classes.get(subevent_code)
            if cls is None:
                # No class registered, just use a generic class instance
                return HCI_LE_Meta_Event(subevent_code, parameters)
        elif event_code == HCI_VENDOR_EVENT:
            subevent_code = parameters[0]
            cls = HCI_Vendor_Event.subevent_classes.get(subevent_code)
            if cls is None:
                # No class registered, just use a generic class instance
                return HCI_Vendor_Event(subevent_code, parameters)
        else:
            cls = HCI_Event.event_classes.get(event_code)
            if cls is None:
                # No class registered, just use a generic class instance
                return HCI_Event(event_code, parameters)

        # Invoke the factory to create a new instance
        return cls.from_parameters(parameters)  # type: ignore

    @classmethod
    def from_parameters(cls, parameters):
        self = cls.__new__(cls)
        HCI_Event.__init__(self, self.event_code, parameters)
        if fields := getattr(self, 'fields', None):
            HCI_Object.init_from_bytes(self, parameters, 0, fields)
        return self

    def __init__(self, event_code, parameters=None, **kwargs):
        super().__init__(HCI_Event.event_name(event_code))
        if (fields := getattr(self, 'fields', None)) and kwargs:
            HCI_Object.init_from_fields(self, fields, kwargs)
            if parameters is None:
                parameters = HCI_Object.dict_to_bytes(kwargs, fields)
        self.event_code = event_code
        self.parameters = parameters

    def to_bytes(self):
        parameters = b'' if self.parameters is None else self.parameters
        return bytes([HCI_EVENT_PACKET, self.event_code, len(parameters)]) + parameters

    def __bytes__(self):
        return self.to_bytes()

    def __str__(self):
        result = color(self.name, 'magenta')
        if fields := getattr(self, 'fields', None):
            result += ':\n' + HCI_Object.format_fields(self.__dict__, fields, '  ')
        else:
            if self.parameters:
                result += f': {self.parameters.hex()}'
        return result


HCI_Event.register_events(globals())


# -----------------------------------------------------------------------------
class HCI_Extended_Event(HCI_Event):
    '''
    HCI_Event subclass for events that has a subevent code.
    '''

    subevent_names: Dict[int, str] = {}
    subevent_classes: Dict[int, Type[HCI_Extended_Event]]

    @classmethod
    def event(cls, fields=()):
        '''
        Decorator used to declare and register subclasses
        '''

        def inner(cls):
            cls.name = cls.__name__.upper()
            cls.subevent_code = key_with_value(cls.subevent_names, cls.name)
            if cls.subevent_code is None:
                raise KeyError(f'subevent {cls.name} not found in subevent_names')
            cls.fields = fields

            # Patch the __init__ method to fix the subevent_code
            original_init = cls.__init__

            def init(self, parameters=None, **kwargs):
                return original_init(self, cls.subevent_code, parameters, **kwargs)

            cls.__init__ = init

            # Register a factory for this class
            cls.subevent_classes[cls.subevent_code] = cls

            return cls

        return inner

    @classmethod
    def subevent_name(cls, subevent_code):
        subevent_name = cls.subevent_names.get(subevent_code)
        if subevent_name is not None:
            return subevent_name

        return f'{cls.__name__.upper()}[0x{subevent_code:02X}]'

    @staticmethod
    def subevent_map(symbols: Dict[str, Any]) -> Dict[int, str]:
        return {
            subevent_code: subevent_name
            for (subevent_name, subevent_code) in symbols.items()
            if subevent_name.startswith('HCI_') and subevent_name.endswith('_EVENT')
        }

    @classmethod
    def register_subevents(cls, symbols: Dict[str, Any]) -> None:
        cls.subevent_names.update(cls.subevent_map(symbols))

    @classmethod
    def from_parameters(cls, parameters):
        self = cls.__new__(cls)
        HCI_Extended_Event.__init__(self, self.subevent_code, parameters)
        if fields := getattr(self, 'fields', None):
            HCI_Object.init_from_bytes(self, parameters, 1, fields)
        return self

    def __init__(self, subevent_code, parameters, **kwargs):
        self.subevent_code = subevent_code
        if parameters is None and (fields := getattr(self, 'fields', None)) and kwargs:
            parameters = bytes([subevent_code]) + HCI_Object.dict_to_bytes(
                kwargs, fields
            )
        super().__init__(self.event_code, parameters, **kwargs)

        # Override the name in order to adopt the subevent name instead
        self.name = self.subevent_name(subevent_code)


# -----------------------------------------------------------------------------
class HCI_LE_Meta_Event(HCI_Extended_Event):
    '''
    See Bluetooth spec @ 7.7.65 LE Meta Event
    '''

    event_code: int = HCI_LE_META_EVENT
    subevent_classes = {}

    @staticmethod
    def subevent_map(symbols: Dict[str, Any]) -> Dict[int, str]:
        return {
            subevent_code: subevent_name
            for (subevent_name, subevent_code) in symbols.items()
            if subevent_name.startswith('HCI_LE_') and subevent_name.endswith('_EVENT')
        }


HCI_LE_Meta_Event.register_subevents(globals())


# -----------------------------------------------------------------------------
class HCI_Vendor_Event(HCI_Extended_Event):
    event_code: int = HCI_VENDOR_EVENT
    subevent_classes = {}


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        (
            'role',
            {'size': 1, 'mapper': lambda x: 'CENTRAL' if x == 0 else 'PERIPHERAL'},
        ),
        ('peer_address_type', Address.ADDRESS_TYPE_SPEC),
        ('peer_address', Address.parse_address_preceded_by_type),
        ('connection_interval', 2),
        ('peripheral_latency', 2),
        ('supervision_timeout', 2),
        ('central_clock_accuracy', 1),
    ]
)
class HCI_LE_Connection_Complete_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.1 LE Connection Complete Event
    '''


# -----------------------------------------------------------------------------
class HCI_LE_Advertising_Report_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.2 LE Advertising Report Event
    '''

    subevent_code = HCI_LE_ADVERTISING_REPORT_EVENT

    # Event Types
    ADV_IND = 0x00
    ADV_DIRECT_IND = 0x01
    ADV_SCAN_IND = 0x02
    ADV_NONCONN_IND = 0x03
    SCAN_RSP = 0x04

    EVENT_TYPE_NAMES = {
        ADV_IND: 'ADV_IND',  # Connectable and scannable undirected advertising
        ADV_DIRECT_IND: 'ADV_DIRECT_IND',  # Connectable directed advertising
        ADV_SCAN_IND: 'ADV_SCAN_IND',  # Scannable undirected advertising
        ADV_NONCONN_IND: 'ADV_NONCONN_IND',  # Non connectable undirected advertising
        SCAN_RSP: 'SCAN_RSP',  # Scan Response
    }

    class Report(HCI_Object):
        FIELDS = [
            ('event_type', 1),
            ('address_type', Address.ADDRESS_TYPE_SPEC),
            ('address', Address.parse_address_preceded_by_type),
            (
                'data',
                {
                    'parser': HCI_Object.parse_length_prefixed_bytes,
                    'serializer': HCI_Object.serialize_length_prefixed_bytes,
                },
            ),
            ('rssi', -1),
        ]

        @classmethod
        def from_parameters(cls, parameters, offset):
            return cls.from_bytes(parameters, offset, cls.FIELDS)

        def event_type_string(self):
            return HCI_LE_Advertising_Report_Event.event_type_name(self.event_type)

        def to_string(self, indentation='', _=None):
            return super().to_string(
                indentation,
                {
                    'event_type': HCI_LE_Advertising_Report_Event.event_type_name,
                    'address_type': Address.address_type_name,
                    'data': lambda x: str(AdvertisingData.from_bytes(x)),
                },
            )

    @classmethod
    def event_type_name(cls, event_type):
        return name_or_number(cls.EVENT_TYPE_NAMES, event_type)

    @classmethod
    def from_parameters(cls, parameters):
        num_reports = parameters[1]
        reports = []
        offset = 2
        for _ in range(num_reports):
            report = cls.Report.from_parameters(parameters, offset)
            offset += 10 + len(report.data)
            reports.append(report)

        return cls(reports)

    def __init__(self, reports):
        self.reports = reports[:]

        # Serialize the fields
        parameters = bytes([HCI_LE_ADVERTISING_REPORT_EVENT, len(reports)]) + b''.join(
            [bytes(report) for report in reports]
        )

        super().__init__(self.subevent_code, parameters)

    def __str__(self):
        reports = '\n'.join(
            [f'{i}:\n{report.to_string("  ")}' for i, report in enumerate(self.reports)]
        )
        return f'{color(self.subevent_name(self.subevent_code), "magenta")}:\n{reports}'


HCI_LE_Meta_Event.subevent_classes[
    HCI_LE_ADVERTISING_REPORT_EVENT
] = HCI_LE_Advertising_Report_Event


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('connection_interval', 2),
        ('peripheral_latency', 2),
        ('supervision_timeout', 2),
    ]
)
class HCI_LE_Connection_Update_Complete_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.3 LE Connection Update Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [('status', STATUS_SPEC), ('connection_handle', 2), ('le_features', 8)]
)
class HCI_LE_Read_Remote_Features_Complete_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.4 LE Read Remote Features Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [('connection_handle', 2), ('random_number', 8), ('encryption_diversifier', 2)]
)
class HCI_LE_Long_Term_Key_Request_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.5 LE Long Term Key Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [
        ('connection_handle', 2),
        ('interval_min', 2),
        ('interval_max', 2),
        ('max_latency', 2),
        ('timeout', 2),
    ]
)
class HCI_LE_Remote_Connection_Parameter_Request_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.6 LE Remote Connection Parameter Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [
        ('connection_handle', 2),
        ('max_tx_octets', 2),
        ('max_tx_time', 2),
        ('max_rx_octets', 2),
        ('max_rx_time', 2),
    ]
)
class HCI_LE_Data_Length_Change_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.7 LE Data Length Change Event
    '''


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        (
            'role',
            {'size': 1, 'mapper': lambda x: 'CENTRAL' if x == 0 else 'PERIPHERAL'},
        ),
        ('peer_address_type', Address.ADDRESS_TYPE_SPEC),
        ('peer_address', Address.parse_address_preceded_by_type),
        ('local_resolvable_private_address', Address.parse_address),
        ('peer_resolvable_private_address', Address.parse_address),
        ('connection_interval', 2),
        ('peripheral_latency', 2),
        ('supervision_timeout', 2),
        ('central_clock_accuracy', 1),
    ]
)
class HCI_LE_Enhanced_Connection_Complete_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.10 LE Enhanced Connection Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('tx_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
        ('rx_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
    ]
)
class HCI_LE_PHY_Update_Complete_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.12 LE PHY Update Complete Event
    '''


# -----------------------------------------------------------------------------
class HCI_LE_Extended_Advertising_Report_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.13 LE Extended Advertising Report Event
    '''

    subevent_code = HCI_LE_EXTENDED_ADVERTISING_REPORT_EVENT

    # Event types flags
    CONNECTABLE_ADVERTISING = 0
    SCANNABLE_ADVERTISING = 1
    DIRECTED_ADVERTISING = 2
    SCAN_RESPONSE = 3
    LEGACY_ADVERTISING_PDU_USED = 4

    DATA_COMPLETE = 0x00
    DATA_INCOMPLETE_MORE_TO_COME = 0x01
    DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME = 0x02

    EVENT_TYPE_FLAG_NAMES = (
        'CONNECTABLE_ADVERTISING',
        'SCANNABLE_ADVERTISING',
        'DIRECTED_ADVERTISING',
        'SCAN_RESPONSE',
        'LEGACY_ADVERTISING_PDU_USED',
    )

    LEGACY_PDU_TYPE_MAP = {
        0b0011: HCI_LE_Advertising_Report_Event.ADV_IND,
        0b0101: HCI_LE_Advertising_Report_Event.ADV_DIRECT_IND,
        0b0010: HCI_LE_Advertising_Report_Event.ADV_SCAN_IND,
        0b0000: HCI_LE_Advertising_Report_Event.ADV_NONCONN_IND,
        0b1011: HCI_LE_Advertising_Report_Event.SCAN_RSP,
        0b1010: HCI_LE_Advertising_Report_Event.SCAN_RSP,
    }

    NO_ADI_FIELD_PROVIDED = 0xFF
    TX_POWER_INFORMATION_NOT_AVAILABLE = 0x7F
    RSSI_NOT_AVAILABLE = 0x7F
    ANONYMOUS_ADDRESS_TYPE = 0xFF
    UNRESOLVED_RESOLVABLE_ADDRESS_TYPE = 0xFE

    class Report(HCI_Object):
        FIELDS = [
            ('event_type', 2),
            ('address_type', Address.ADDRESS_TYPE_SPEC),
            ('address', Address.parse_address_preceded_by_type),
            ('primary_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
            ('secondary_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
            ('advertising_sid', 1),
            ('tx_power', 1),
            ('rssi', -1),
            ('periodic_advertising_interval', 2),
            ('direct_address_type', Address.ADDRESS_TYPE_SPEC),
            ('direct_address', Address.parse_address_preceded_by_type),
            (
                'data',
                {
                    'parser': HCI_Object.parse_length_prefixed_bytes,
                    'serializer': HCI_Object.serialize_length_prefixed_bytes,
                },
            ),
        ]

        @classmethod
        def from_parameters(cls, parameters, offset):
            return cls.from_bytes(parameters, offset, cls.FIELDS)

        def event_type_string(self):
            return HCI_LE_Extended_Advertising_Report_Event.event_type_string(
                self.event_type
            )

        def to_string(self, indentation='', _=None):
            # pylint: disable=line-too-long
            return super().to_string(
                indentation,
                {
                    'event_type': HCI_LE_Extended_Advertising_Report_Event.event_type_string,
                    'address_type': Address.address_type_name,
                    'data': lambda x: str(AdvertisingData.from_bytes(x)),
                },
            )

    @staticmethod
    def event_type_string(event_type):
        event_type_flags = bit_flags_to_strings(
            event_type & 0x1F,
            HCI_LE_Extended_Advertising_Report_Event.EVENT_TYPE_FLAG_NAMES,
        )
        event_type_flags.append(
            ('COMPLETE', 'INCOMPLETE+', 'INCOMPLETE#', '?')[(event_type >> 5) & 3]
        )

        if event_type & (
            1 << HCI_LE_Extended_Advertising_Report_Event.LEGACY_ADVERTISING_PDU_USED
        ):
            legacy_pdu_type = (
                HCI_LE_Extended_Advertising_Report_Event.LEGACY_PDU_TYPE_MAP.get(
                    event_type & 0x0F
                )
            )
            if legacy_pdu_type is not None:
                # pylint: disable=line-too-long
                legacy_info_string = f'({HCI_LE_Advertising_Report_Event.event_type_name(legacy_pdu_type)})'
            else:
                legacy_info_string = ''
        else:
            legacy_info_string = ''

        return f'0x{event_type:04X} [{",".join(event_type_flags)}]{legacy_info_string}'

    @classmethod
    def from_parameters(cls, parameters):
        num_reports = parameters[1]
        reports = []
        offset = 2
        for _ in range(num_reports):
            report = cls.Report.from_parameters(parameters, offset)
            offset += 24 + len(report.data)
            reports.append(report)

        return cls(reports)

    def __init__(self, reports):
        self.reports = reports[:]

        # Serialize the fields
        parameters = bytes(
            [HCI_LE_EXTENDED_ADVERTISING_REPORT_EVENT, len(reports)]
        ) + b''.join([bytes(report) for report in reports])

        super().__init__(self.subevent_code, parameters)

    def __str__(self):
        reports = '\n'.join(
            [f'{i}:\n{report.to_string("  ")}' for i, report in enumerate(self.reports)]
        )
        return f'{color(self.subevent_name(self.subevent_code), "magenta")}:\n{reports}'


HCI_LE_Meta_Event.subevent_classes[
    HCI_LE_EXTENDED_ADVERTISING_REPORT_EVENT
] = HCI_LE_Extended_Advertising_Report_Event


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event([('connection_handle', 2), ('channel_selection_algorithm', 1)])
class HCI_LE_Channel_Selection_Algorithm_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.20 LE Channel Selection Algorithm Event
    '''


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('cig_sync_delay', 3),
        ('cis_sync_delay', 3),
        ('transport_latency_c_to_p', 3),
        ('transport_latency_p_to_c', 3),
        ('phy_c_to_p', 1),
        ('phy_p_to_c', 1),
        ('nse', 1),
        ('bn_c_to_p', 1),
        ('bn_p_to_c', 1),
        ('ft_c_to_p', 1),
        ('ft_p_to_c', 1),
        ('max_pdu_c_to_p', 2),
        ('max_pdu_p_to_c', 2),
        ('iso_interval', 2),
    ]
)
class HCI_LE_CIS_Established_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.25 LE CIS Established Event
    '''


# -----------------------------------------------------------------------------
@HCI_LE_Meta_Event.event(
    [
        ('acl_connection_handle', 2),
        ('cis_connection_handle', 2),
        ('cig_id', 1),
        ('cis_id', 1),
    ]
)
class HCI_LE_CIS_Request_Event(HCI_LE_Meta_Event):
    '''
    See Bluetooth spec @ 7.7.65.26 LE CIS Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('status', STATUS_SPEC)])
class HCI_Inquiry_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.1 Inquiry Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.registered
class HCI_Inquiry_Result_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.2 Inquiry Result Event
    '''

    RESPONSE_FIELDS = [
        ('bd_addr', Address.parse_address),
        ('page_scan_repetition_mode', 1),
        ('reserved', 1),
        ('reserved', 1),
        ('class_of_device', {'size': 3, 'mapper': map_class_of_device}),
        ('clock_offset', 2),
    ]

    @staticmethod
    def from_parameters(parameters):
        num_responses = parameters[0]
        responses = []
        offset = 1
        for _ in range(num_responses):
            response = HCI_Object.from_bytes(
                parameters, offset, HCI_Inquiry_Result_Event.RESPONSE_FIELDS
            )
            offset += 14
            responses.append(response)

        return HCI_Inquiry_Result_Event(responses)

    def __init__(self, responses):
        self.responses = responses[:]

        # Serialize the fields
        parameters = bytes([HCI_INQUIRY_RESULT_EVENT, len(responses)]) + b''.join(
            [bytes(response) for response in responses]
        )

        super().__init__(HCI_INQUIRY_RESULT_EVENT, parameters)

    def __str__(self):
        responses = '\n'.join(
            [response.to_string(indentation='  ') for response in self.responses]
        )
        return f'{color("HCI_INQUIRY_RESULT_EVENT", "magenta")}:\n{responses}'


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('bd_addr', Address.parse_address),
        (
            'link_type',
            {
                'size': 1,
                # pylint: disable-next=unnecessary-lambda
                'mapper': lambda x: HCI_Connection_Complete_Event.link_type_name(x),
            },
        ),
        ('encryption_enabled', 1),
    ]
)
class HCI_Connection_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.3 Connection Complete Event
    '''

    SCO_LINK_TYPE = 0x00
    ACL_LINK_TYPE = 0x01
    ESCO_LINK_TYPE = 0x02

    LINK_TYPE_NAMES = {
        SCO_LINK_TYPE: 'SCO',
        ACL_LINK_TYPE: 'ACL',
        ESCO_LINK_TYPE: 'eSCO',
    }

    @staticmethod
    def link_type_name(link_type):
        return name_or_number(HCI_Connection_Complete_Event.LINK_TYPE_NAMES, link_type)


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('bd_addr', Address.parse_address),
        ('class_of_device', 3),
        (
            'link_type',
            {
                'size': 1,
                # pylint: disable-next=unnecessary-lambda
                'mapper': lambda x: HCI_Connection_Complete_Event.link_type_name(x),
            },
        ),
    ]
)
class HCI_Connection_Request_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.4 Connection Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('reason', {'size': 1, 'mapper': HCI_Constant.error_name}),
    ]
)
class HCI_Disconnection_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.5 Disconnection Complete Event
    '''

    status: int
    connection_handle: int
    reason: int


# -----------------------------------------------------------------------------
@HCI_Event.event([('status', STATUS_SPEC), ('connection_handle', 2)])
class HCI_Authentication_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.6 Authentication Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
        ('remote_name', {'size': 248, 'mapper': map_null_terminated_utf8_string}),
    ]
)
class HCI_Remote_Name_Request_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.7 Remote Name Request Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        (
            'encryption_enabled',
            {
                'size': 1,
                # pylint: disable-next=unnecessary-lambda
                'mapper': lambda x: HCI_Encryption_Change_Event.encryption_enabled_name(
                    x
                ),
            },
        ),
    ]
)
class HCI_Encryption_Change_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.8 Encryption Change Event
    '''

    OFF = 0x00
    E0_OR_AES_CCM = 0x01
    AES_CCM = 0x02

    ENCRYPTION_ENABLED_NAMES = {
        OFF: 'OFF',
        E0_OR_AES_CCM: 'E0_OR_AES_CCM',
        AES_CCM: 'AES_CCM',
    }

    @staticmethod
    def encryption_enabled_name(encryption_enabled):
        return name_or_number(
            HCI_Encryption_Change_Event.ENCRYPTION_ENABLED_NAMES, encryption_enabled
        )


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [('status', STATUS_SPEC), ('connection_handle', 2), ('lmp_features', 8)]
)
class HCI_Read_Remote_Supported_Features_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.11 Read Remote Supported Features Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('version', 1),
        ('manufacturer_name', 2),
        ('subversion', 2),
    ]
)
class HCI_Read_Remote_Version_Information_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.12 Read Remote Version Information Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('num_hci_command_packets', 1),
        ('command_opcode', {'size': 2, 'mapper': HCI_Command.command_name}),
        ('return_parameters', '*'),
    ]
)
class HCI_Command_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.14 Command Complete Event
    '''

    return_parameters = b''
    command_opcode: int

    def map_return_parameters(self, return_parameters):
        '''Map simple 'status' return parameters to their named constant form'''

        if isinstance(return_parameters, bytes) and len(return_parameters) == 1:
            # Byte-array form
            return HCI_Constant.status_name(return_parameters[0])

        if isinstance(return_parameters, int):
            # Already converted to an integer status code
            return HCI_Constant.status_name(return_parameters)

        return return_parameters

    @staticmethod
    def from_parameters(parameters):
        self = HCI_Command_Complete_Event.__new__(HCI_Command_Complete_Event)
        HCI_Event.__init__(self, self.event_code, parameters)
        HCI_Object.init_from_bytes(
            self, parameters, 0, HCI_Command_Complete_Event.fields
        )

        # Parse the return parameters
        if (
            isinstance(self.return_parameters, bytes)
            and len(self.return_parameters) == 1
        ):
            # All commands with 1-byte return parameters return a 'status' field,
            # convert it to an integer
            self.return_parameters = self.return_parameters[0]
        else:
            cls = HCI_Command.command_classes.get(self.command_opcode)
            if cls:
                # Try to parse the return parameters bytes into an object.
                return_parameters = cls.parse_return_parameters(self.return_parameters)
                if return_parameters is not None:
                    self.return_parameters = return_parameters

        return self

    def __str__(self):
        return f'{color(self.name, "magenta")}:\n' + HCI_Object.format_fields(
            self.__dict__,
            self.fields,
            '  ',
            {'return_parameters': self.map_return_parameters},
        )


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        (
            'status',
            # pylint: disable-next=unnecessary-lambda
            {'size': 1, 'mapper': lambda x: HCI_Command_Status_Event.status_name(x)},
        ),
        ('num_hci_command_packets', 1),
        ('command_opcode', {'size': 2, 'mapper': HCI_Command.command_name}),
    ]
)
class HCI_Command_Status_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.15 Command Complete Event
    '''

    PENDING = 0

    @staticmethod
    def status_name(status):
        if status == HCI_Command_Status_Event.PENDING:
            return 'PENDING'

        return HCI_Constant.error_name(status)


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('bd_addr', Address.parse_address),
        ('new_role', {'size': 1, 'mapper': HCI_Constant.role_name}),
    ]
)
class HCI_Role_Change_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.18 Role Change Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.registered
class HCI_Number_Of_Completed_Packets_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.19 Number Of Completed Packets Event
    '''

    @classmethod
    def from_parameters(cls, parameters):
        self = cls.__new__(cls)
        self.parameters = parameters
        num_handles = parameters[0]
        self.connection_handles = []
        self.num_completed_packets = []
        for i in range(num_handles):
            self.connection_handles.append(
                struct.unpack_from('<H', parameters, 1 + i * 4)[0]
            )
            self.num_completed_packets.append(
                struct.unpack_from('<H', parameters, 1 + i * 4 + 2)[0]
            )

        return self

    def __init__(self, connection_handle_and_completed_packets_list):
        self.connection_handles = []
        self.num_completed_packets = []
        parameters = bytes([len(connection_handle_and_completed_packets_list)])
        for handle, completed_packets in connection_handle_and_completed_packets_list:
            self.connection_handles.append(handle)
            self.num_completed_packets.append(completed_packets)
            parameters += struct.pack('<H', handle)
            parameters += struct.pack('<H', completed_packets)
        super().__init__(HCI_NUMBER_OF_COMPLETED_PACKETS_EVENT, parameters)

    def __str__(self):
        lines = [
            color(self.name, 'magenta') + ':',
            color('  number_of_handles:        ', 'cyan')
            + f'{len(self.connection_handles)}',
        ]
        for i, connection_handle in enumerate(self.connection_handles):
            lines.append(
                color(f'  connection_handle[{i}]:     ', 'cyan')
                + f'{connection_handle}'
            )
            lines.append(
                color(f'  num_completed_packets[{i}]: ', 'cyan')
                + f'{self.num_completed_packets[i]}'
            )
        return '\n'.join(lines)


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        (
            'current_mode',
            # pylint: disable-next=unnecessary-lambda
            {'size': 1, 'mapper': lambda x: HCI_Mode_Change_Event.mode_name(x)},
        ),
        ('interval', 2),
    ]
)
class HCI_Mode_Change_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.20 Mode Change Event
    '''

    ACTIVE_MODE = 0x00
    HOLD_MODE = 0x01
    SNIFF_MODE = 0x02

    MODE_NAMES = {
        ACTIVE_MODE: 'ACTIVE_MODE',
        HOLD_MODE: 'HOLD_MODE',
        SNIFF_MODE: 'SNIFF_MODE',
    }

    @staticmethod
    def mode_name(mode):
        return name_or_number(HCI_Mode_Change_Event.MODE_NAMES, mode)


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address)])
class HCI_PIN_Code_Request_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.22 PIN Code Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address)])
class HCI_Link_Key_Request_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.24 7.7.23 Link Key Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('bd_addr', Address.parse_address),
        ('link_key', 16),
        ('key_type', {'size': 1, 'mapper': HCI_Constant.link_key_type_name}),
    ]
)
class HCI_Link_Key_Notification_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.24 Link Key Notification Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('connection_handle', 2), ('lmp_max_slots', 1)])
class HCI_Max_Slots_Change_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.27 Max Slots Change Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [('status', STATUS_SPEC), ('connection_handle', 2), ('clock_offset', 2)]
)
class HCI_Read_Clock_Offset_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.28 Read Clock Offset Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [('status', STATUS_SPEC), ('connection_handle', 2), ('packet_type', 2)]
)
class HCI_Connection_Packet_Type_Changed_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.29 Connection Packet Type Changed Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address), ('page_scan_repetition_mode', 1)])
class HCI_Page_Scan_Repetition_Mode_Change_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.31 Page Scan Repetition Mode Change Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.registered
class HCI_Inquiry_Result_With_RSSI_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.33 Inquiry Result with RSSI Event
    '''

    RESPONSE_FIELDS = [
        ('bd_addr', Address.parse_address),
        ('page_scan_repetition_mode', 1),
        ('reserved', 1),
        ('class_of_device', {'size': 3, 'mapper': map_class_of_device}),
        ('clock_offset', 2),
        ('rssi', -1),
    ]

    @staticmethod
    def from_parameters(parameters):
        num_responses = parameters[0]
        responses = []
        offset = 1
        for _ in range(num_responses):
            response = HCI_Object.from_bytes(
                parameters, offset, HCI_Inquiry_Result_With_RSSI_Event.RESPONSE_FIELDS
            )
            offset += 14
            responses.append(response)

        return HCI_Inquiry_Result_With_RSSI_Event(responses)

    def __init__(self, responses):
        self.responses = responses[:]

        # Serialize the fields
        parameters = bytes(
            [HCI_INQUIRY_RESULT_WITH_RSSI_EVENT, len(responses)]
        ) + b''.join([bytes(response) for response in responses])

        super().__init__(HCI_INQUIRY_RESULT_WITH_RSSI_EVENT, parameters)

    def __str__(self):
        responses = '\n'.join(
            [response.to_string(indentation='  ') for response in self.responses]
        )
        return f'{color("HCI_INQUIRY_RESULT_WITH_RSSI_EVENT", "magenta")}:\n{responses}'


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('page_number', 1),
        ('maximum_page_number', 1),
        ('extended_lmp_features', 8),
    ]
)
class HCI_Read_Remote_Extended_Features_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.34 Read Remote Extended Features Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    # pylint: disable=line-too-long
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('bd_addr', Address.parse_address),
        (
            'link_type',
            {
                'size': 1,
                # pylint: disable-next=unnecessary-lambda
                'mapper': lambda x: HCI_Synchronous_Connection_Complete_Event.link_type_name(
                    x
                ),
            },
        ),
        ('transmission_interval', 1),
        ('retransmission_window', 1),
        ('rx_packet_length', 2),
        ('tx_packet_length', 2),
        (
            'air_mode',
            {
                'size': 1,
                # pylint: disable-next=unnecessary-lambda
                'mapper': lambda x: HCI_Synchronous_Connection_Complete_Event.air_mode_name(
                    x
                ),
            },
        ),
    ]
)
class HCI_Synchronous_Connection_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.35 Synchronous Connection Complete Event
    '''

    SCO_CONNECTION_LINK_TYPE = 0x00
    ESCO_CONNECTION_LINK_TYPE = 0x02

    LINK_TYPE_NAMES = {
        SCO_CONNECTION_LINK_TYPE: 'SCO',
        ESCO_CONNECTION_LINK_TYPE: 'eSCO',
    }

    U_LAW_LOG_AIR_MODE = 0x00
    A_LAW_LOG_AIR_MORE = 0x01
    CVSD_AIR_MODE = 0x02
    TRANSPARENT_DATA_AIR_MODE = 0x03

    AIR_MODE_NAMES = {
        U_LAW_LOG_AIR_MODE: 'u-law log',
        A_LAW_LOG_AIR_MORE: 'A-law log',
        CVSD_AIR_MODE: 'CVSD',
        TRANSPARENT_DATA_AIR_MODE: 'Transparent Data',
    }

    @staticmethod
    def link_type_name(link_type):
        return name_or_number(
            HCI_Synchronous_Connection_Complete_Event.LINK_TYPE_NAMES, link_type
        )

    @staticmethod
    def air_mode_name(air_mode):
        return name_or_number(
            HCI_Synchronous_Connection_Complete_Event.AIR_MODE_NAMES, air_mode
        )


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('status', STATUS_SPEC),
        ('connection_handle', 2),
        ('transmission_interval', 1),
        ('retransmission_window', 1),
        ('rx_packet_length', 2),
        ('tx_packet_length', 2),
    ]
)
class HCI_Synchronous_Connection_Changed_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.36 Synchronous Connection Changed Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('num_responses', 1),
        ('bd_addr', Address.parse_address),
        ('page_scan_repetition_mode', 1),
        ('reserved', 1),
        ('class_of_device', {'size': 3, 'mapper': map_class_of_device}),
        ('clock_offset', 2),
        ('rssi', -1),
        ('extended_inquiry_response', 240),
    ]
)
class HCI_Extended_Inquiry_Result_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.38 Extended Inquiry Result Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('status', STATUS_SPEC), ('connection_handle', 2)])
class HCI_Encryption_Key_Refresh_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.39 Encryption Key Refresh Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address)])
class HCI_IO_Capability_Request_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.40 IO Capability Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event(
    [
        ('bd_addr', Address.parse_address),
        ('io_capability', {'size': 1, 'mapper': HCI_Constant.io_capability_name}),
        ('oob_data_present', 1),
        (
            'authentication_requirements',
            {'size': 1, 'mapper': HCI_Constant.authentication_requirements_name},
        ),
    ]
)
class HCI_IO_Capability_Response_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.41 IO Capability Response Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address), ('numeric_value', 4)])
class HCI_User_Confirmation_Request_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.42 User Confirmation Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address)])
class HCI_User_Passkey_Request_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.43 User Passkey Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address)])
class HCI_Remote_OOB_Data_Request_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.44 Remote OOB Data Request Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('status', STATUS_SPEC), ('bd_addr', Address.parse_address)])
class HCI_Simple_Pairing_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.45 Simple Pairing Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('connection_handle', 2), ('link_supervision_timeout', 2)])
class HCI_Link_Supervision_Timeout_Changed_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.46 Link Supervision Timeout Changed Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('handle', 2)])
class HCI_Enhanced_Flush_Complete_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.47 Enhanced Flush Complete Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address), ('passkey', 4)])
class HCI_User_Passkey_Notification_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.48 User Passkey Notification Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address), ('notification_type', 1)])
class HCI_Keypress_Notification_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.49 Keypress Notification Event
    '''


# -----------------------------------------------------------------------------
@HCI_Event.event([('bd_addr', Address.parse_address), ('host_supported_features', 8)])
class HCI_Remote_Host_Supported_Features_Notification_Event(HCI_Event):
    '''
    See Bluetooth spec @ 7.7.50 Remote Host Supported Features Notification Event
    '''


# -----------------------------------------------------------------------------
class HCI_AclDataPacket(HCI_Packet):
    '''
    See Bluetooth spec @ 5.4.2 HCI ACL Data Packets
    '''

    hci_packet_type = HCI_ACL_DATA_PACKET

    @staticmethod
    def from_bytes(packet: bytes) -> HCI_AclDataPacket:
        # Read the header
        h, data_total_length = struct.unpack_from('<HH', packet, 1)
        connection_handle = h & 0xFFF
        pb_flag = (h >> 12) & 3
        bc_flag = (h >> 14) & 3
        data = packet[5:]
        if len(data) != data_total_length:
            raise ValueError('invalid packet length')
        return HCI_AclDataPacket(
            connection_handle, pb_flag, bc_flag, data_total_length, data
        )

    def to_bytes(self):
        h = (self.pb_flag << 12) | (self.bc_flag << 14) | self.connection_handle
        return (
            struct.pack('<BHH', HCI_ACL_DATA_PACKET, h, self.data_total_length)
            + self.data
        )

    def __init__(self, connection_handle, pb_flag, bc_flag, data_total_length, data):
        self.connection_handle = connection_handle
        self.pb_flag = pb_flag
        self.bc_flag = bc_flag
        self.data_total_length = data_total_length
        self.data = data

    def __bytes__(self):
        return self.to_bytes()

    def __str__(self):
        return (
            f'{color("ACL", "blue")}: '
            f'handle=0x{self.connection_handle:04x}, '
            f'pb={self.pb_flag}, bc={self.bc_flag}, '
            f'data_total_length={self.data_total_length}, '
            f'data={self.data.hex()}'
        )


# -----------------------------------------------------------------------------
class HCI_SynchronousDataPacket(HCI_Packet):
    '''
    See Bluetooth spec @ 5.4.3 HCI SCO Data Packets
    '''

    hci_packet_type = HCI_SYNCHRONOUS_DATA_PACKET

    @staticmethod
    def from_bytes(packet: bytes) -> HCI_SynchronousDataPacket:
        # Read the header
        h, data_total_length = struct.unpack_from('<HB', packet, 1)
        connection_handle = h & 0xFFF
        packet_status = (h >> 12) & 0b11
        data = packet[4:]
        if len(data) != data_total_length:
            raise ValueError(
                f'invalid packet length {len(data)} != {data_total_length}'
            )
        return HCI_SynchronousDataPacket(
            connection_handle, packet_status, data_total_length, data
        )

    def to_bytes(self) -> bytes:
        h = (self.packet_status << 12) | self.connection_handle
        return (
            struct.pack('<BHB', HCI_SYNCHRONOUS_DATA_PACKET, h, self.data_total_length)
            + self.data
        )

    def __init__(
        self,
        connection_handle: int,
        packet_status: int,
        data_total_length: int,
        data: bytes,
    ) -> None:
        self.connection_handle = connection_handle
        self.packet_status = packet_status
        self.data_total_length = data_total_length
        self.data = data

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def __str__(self) -> str:
        return (
            f'{color("SCO", "blue")}: '
            f'handle=0x{self.connection_handle:04x}, '
            f'ps={self.packet_status}, '
            f'data_total_length={self.data_total_length}, '
            f'data={self.data.hex()}'
        )


# -----------------------------------------------------------------------------
class HCI_IsoDataPacket(HCI_Packet):
    '''
    See Bluetooth spec @ 5.4.5 HCI ISO Data Packets
    '''

    hci_packet_type = HCI_ISO_DATA_PACKET

    @staticmethod
    def from_bytes(packet: bytes) -> HCI_IsoDataPacket:
        time_stamp: Optional[int] = None
        packet_sequence_number: Optional[int] = None
        iso_sdu_length: Optional[int] = None
        packet_status_flag: Optional[int] = None

        pos = 1
        pdu_info, data_total_length = struct.unpack_from('<HH', packet, pos)
        connection_handle = pdu_info & 0xFFF
        pb_flag = (pdu_info >> 12) & 0b11
        ts_flag = (pdu_info >> 14) & 0b01
        pos += 4

        # pb_flag in (0b00, 0b10) but faster
        should_include_sdu_info = not (pb_flag & 0b01)

        if ts_flag:
            if not should_include_sdu_info:
                logger.warn(f'Timestamp included when pb_flag={bin(pb_flag)}')
            time_stamp, _ = struct.unpack_from('<I', packet, pos)
            pos += 4

        if should_include_sdu_info:
            packet_sequence_number, sdu_info = struct.unpack_from('<HH', packet, pos)
            iso_sdu_length = sdu_info & 0xFFF
            packet_status_flag = sdu_info >> 14
            pos += 4

        iso_sdu_fragment = packet[pos:]
        return HCI_IsoDataPacket(
            connection_handle=connection_handle,
            pb_flag=pb_flag,
            ts_flag=ts_flag,
            data_total_length=data_total_length,
            time_stamp=time_stamp,
            packet_sequence_number=packet_sequence_number,
            iso_sdu_length=iso_sdu_length,
            packet_status_flag=packet_status_flag,
            iso_sdu_fragment=iso_sdu_fragment,
        )

    def __init__(
        self,
        connection_handle: int,
        pb_flag: int,
        ts_flag: int,
        data_total_length: int,
        time_stamp: Optional[int],
        packet_sequence_number: Optional[int],
        iso_sdu_length: Optional[int],
        packet_status_flag: Optional[int],
        iso_sdu_fragment: bytes,
    ) -> None:
        self.connection_handle = connection_handle
        self.pb_flag = pb_flag
        self.ts_flag = ts_flag
        self.data_total_length = data_total_length
        self.time_stamp = time_stamp
        self.packet_sequence_number = packet_sequence_number
        self.iso_sdu_length = iso_sdu_length
        self.packet_status_flag = packet_status_flag
        self.iso_sdu_fragment = iso_sdu_fragment

    def __bytes__(self) -> bytes:
        return self.to_bytes()

    def to_bytes(self) -> bytes:
        fmt = '<BHH'
        args = [
            HCI_ISO_DATA_PACKET,
            self.ts_flag << 14 | self.pb_flag << 12 | self.connection_handle,
            self.data_total_length,
        ]
        if self.time_stamp is not None:
            fmt += 'I'
            args.append(self.time_stamp)
        if (
            self.packet_sequence_number is not None
            and self.iso_sdu_length is not None
            and self.packet_status_flag is not None
        ):
            fmt += 'HH'
            args += [
                self.packet_sequence_number,
                self.iso_sdu_length | self.packet_status_flag << 14,
            ]
        return struct.pack(fmt, args) + self.iso_sdu_fragment

    def __str__(self) -> str:
        return (
            f'{color("ISO", "blue")}: '
            f'handle=0x{self.connection_handle:04x}, '
            f'ps={self.packet_status_flag}, '
            f'data_total_length={self.data_total_length}, '
            f'sdu={self.iso_sdu_fragment.hex()}'
        )


# -----------------------------------------------------------------------------
class HCI_AclDataPacketAssembler:
    current_data: Optional[bytes]

    def __init__(self, callback: Callable[[bytes], Any]) -> None:
        self.callback = callback
        self.current_data = None
        self.l2cap_pdu_length = 0

    def feed_packet(self, packet: HCI_AclDataPacket) -> None:
        if packet.pb_flag in (
            HCI_ACL_PB_FIRST_NON_FLUSHABLE,
            HCI_ACL_PB_FIRST_FLUSHABLE,
        ):
            (l2cap_pdu_length,) = struct.unpack_from('<H', packet.data, 0)
            self.current_data = packet.data
            self.l2cap_pdu_length = l2cap_pdu_length
        elif packet.pb_flag == HCI_ACL_PB_CONTINUATION:
            if self.current_data is None:
                logger.warning('!!! ACL continuation without start')
                return
            self.current_data += packet.data

        assert self.current_data is not None
        if len(self.current_data) == self.l2cap_pdu_length + 4:
            # The packet is complete, invoke the callback
            logger.debug(f'<<< ACL PDU: {self.current_data.hex()}')
            self.callback(self.current_data)

            # Reset
            self.current_data = None
            self.l2cap_pdu_length = 0
        else:
            # Sanity check
            if len(self.current_data) > self.l2cap_pdu_length + 4:
                logger.warning('!!! ACL data exceeds L2CAP PDU')
                self.current_data = None
                self.l2cap_pdu_length = 0
