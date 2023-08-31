# Copyright 2021-2023 Google LLC
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
import struct

from bumble.hci import (
    name_or_number,
    hci_vendor_command_op_code,
    Address,
    HCI_Constant,
    HCI_Object,
    HCI_Command,
    HCI_Vendor_Event,
    STATUS_SPEC,
)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Android Vendor Specific Commands and Events.
# Only a subset of the commands are implemented here currently.
#
# pylint: disable-next=line-too-long
# See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#chip-capabilities-and-configuration
HCI_LE_GET_VENDOR_CAPABILITIES_COMMAND = hci_vendor_command_op_code(0x153)
HCI_LE_APCF_COMMAND = hci_vendor_command_op_code(0x157)
HCI_GET_CONTROLLER_ACTIVITY_ENERGY_INFO_COMMAND = hci_vendor_command_op_code(0x159)
HCI_A2DP_HARDWARE_OFFLOAD_COMMAND = hci_vendor_command_op_code(0x15D)
HCI_BLUETOOTH_QUALITY_REPORT_COMMAND = hci_vendor_command_op_code(0x15E)
HCI_DYNAMIC_AUDIO_BUFFER_COMMAND = hci_vendor_command_op_code(0x15F)

HCI_BLUETOOTH_QUALITY_REPORT_EVENT = 0x58

HCI_Command.register_commands(globals())
HCI_Vendor_Event.register_subevents(globals())


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('max_advt_instances', 1),
        ('offloaded_resolution_of_private_address', 1),
        ('total_scan_results_storage', 2),
        ('max_irk_list_sz', 1),
        ('filtering_support', 1),
        ('max_filter', 1),
        ('activity_energy_info_support', 1),
        ('version_supported', 2),
        ('total_num_of_advt_tracked', 2),
        ('extended_scan_support', 1),
        ('debug_logging_supported', 1),
        ('le_address_generation_offloading_support', 1),
        ('a2dp_source_offload_capability_mask', 4),
        ('bluetooth_quality_report_support', 1),
        ('dynamic_audio_buffer_support', 4),
    ]
)
class HCI_LE_Get_Vendor_Capabilities_Command(HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#vendor-specific-capabilities
    '''

    @classmethod
    def parse_return_parameters(cls, parameters):
        # There are many versions of this data structure, so we need to parse until
        # there are no more bytes to parse, and leave un-signal parameters set to
        # None (older versions)
        nones = {field: None for field, _ in cls.return_parameters_fields}
        return_parameters = HCI_Object(cls.return_parameters_fields, **nones)

        try:
            offset = 0
            for field in cls.return_parameters_fields:
                field_name, field_type = field
                field_value, field_size = HCI_Object.parse_field(
                    parameters, offset, field_type
                )
                setattr(return_parameters, field_name, field_value)
                offset += field_size
        except struct.error:
            pass

        return return_parameters


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        (
            'opcode',
            {
                'size': 1,
                'mapper': lambda x: HCI_LE_APCF_Command.opcode_name(x),
            },
        ),
        ('payload', '*'),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        (
            'opcode',
            {
                'size': 1,
                'mapper': lambda x: HCI_LE_APCF_Command.opcode_name(x),
            },
        ),
        ('payload', '*'),
    ],
)
class HCI_LE_APCF_Command(HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#le_apcf_command

    NOTE: the subcommand-specific payloads are left as opaque byte arrays in this
    implementation. A future enhancement may define subcommand-specific data structures.
    '''

    # APCF Subcommands
    # TODO: use the OpenIntEnum class (when upcoming PR is merged)
    APCF_ENABLE = 0x00
    APCF_SET_FILTERING_PARAMETERS = 0x01
    APCF_BROADCASTER_ADDRESS = 0x02
    APCF_SERVICE_UUID = 0x03
    APCF_SERVICE_SOLICITATION_UUID = 0x04
    APCF_LOCAL_NAME = 0x05
    APCF_MANUFACTURER_DATA = 0x06
    APCF_SERVICE_DATA = 0x07
    APCF_TRANSPORT_DISCOVERY_SERVICE = 0x08
    APCF_AD_TYPE_FILTER = 0x09
    APCF_READ_EXTENDED_FEATURES = 0xFF

    OPCODE_NAMES = {
        APCF_ENABLE: 'APCF_ENABLE',
        APCF_SET_FILTERING_PARAMETERS: 'APCF_SET_FILTERING_PARAMETERS',
        APCF_BROADCASTER_ADDRESS: 'APCF_BROADCASTER_ADDRESS',
        APCF_SERVICE_UUID: 'APCF_SERVICE_UUID',
        APCF_SERVICE_SOLICITATION_UUID: 'APCF_SERVICE_SOLICITATION_UUID',
        APCF_LOCAL_NAME: 'APCF_LOCAL_NAME',
        APCF_MANUFACTURER_DATA: 'APCF_MANUFACTURER_DATA',
        APCF_SERVICE_DATA: 'APCF_SERVICE_DATA',
        APCF_TRANSPORT_DISCOVERY_SERVICE: 'APCF_TRANSPORT_DISCOVERY_SERVICE',
        APCF_AD_TYPE_FILTER: 'APCF_AD_TYPE_FILTER',
        APCF_READ_EXTENDED_FEATURES: 'APCF_READ_EXTENDED_FEATURES',
    }

    @classmethod
    def opcode_name(cls, opcode):
        return name_or_number(cls.OPCODE_NAMES, opcode)


# -----------------------------------------------------------------------------
@HCI_Command.command(
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('total_tx_time_ms', 4),
        ('total_rx_time_ms', 4),
        ('total_idle_time_ms', 4),
        ('total_energy_used', 4),
    ],
)
class HCI_Get_Controller_Activity_Energy_Info_Command(HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#le_get_controller_activity_energy_info
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        (
            'opcode',
            {
                'size': 1,
                'mapper': lambda x: HCI_A2DP_Hardware_Offload_Command.opcode_name(x),
            },
        ),
        ('payload', '*'),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        (
            'opcode',
            {
                'size': 1,
                'mapper': lambda x: HCI_A2DP_Hardware_Offload_Command.opcode_name(x),
            },
        ),
        ('payload', '*'),
    ],
)
class HCI_A2DP_Hardware_Offload_Command(HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#a2dp-hardware-offload-support

    NOTE: the subcommand-specific payloads are left as opaque byte arrays in this
    implementation. A future enhancement may define subcommand-specific data structures.
    '''

    # A2DP Hardware Offload Subcommands
    # TODO: use the OpenIntEnum class (when upcoming PR is merged)
    START_A2DP_OFFLOAD = 0x01
    STOP_A2DP_OFFLOAD = 0x02

    OPCODE_NAMES = {
        START_A2DP_OFFLOAD: 'START_A2DP_OFFLOAD',
        STOP_A2DP_OFFLOAD: 'STOP_A2DP_OFFLOAD',
    }

    @classmethod
    def opcode_name(cls, opcode):
        return name_or_number(cls.OPCODE_NAMES, opcode)


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[
        (
            'opcode',
            {
                'size': 1,
                'mapper': lambda x: HCI_Dynamic_Audio_Buffer_Command.opcode_name(x),
            },
        ),
        ('payload', '*'),
    ],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        (
            'opcode',
            {
                'size': 1,
                'mapper': lambda x: HCI_Dynamic_Audio_Buffer_Command.opcode_name(x),
            },
        ),
        ('payload', '*'),
    ],
)
class HCI_Dynamic_Audio_Buffer_Command(HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#dynamic-audio-buffer-command

    NOTE: the subcommand-specific payloads are left as opaque byte arrays in this
    implementation. A future enhancement may define subcommand-specific data structures.
    '''

    # Dynamic Audio Buffer Subcommands
    # TODO: use the OpenIntEnum class (when upcoming PR is merged)
    GET_AUDIO_BUFFER_TIME_CAPABILITY = 0x01

    OPCODE_NAMES = {
        GET_AUDIO_BUFFER_TIME_CAPABILITY: 'GET_AUDIO_BUFFER_TIME_CAPABILITY',
    }

    @classmethod
    def opcode_name(cls, opcode):
        return name_or_number(cls.OPCODE_NAMES, opcode)


# -----------------------------------------------------------------------------
@HCI_Vendor_Event.event(
    fields=[
        ('quality_report_id', 1),
        ('packet_types', 1),
        ('connection_handle', 2),
        ('connection_role', {'size': 1, 'mapper': HCI_Constant.role_name}),
        ('tx_power_level', -1),
        ('rssi', -1),
        ('snr', 1),
        ('unused_afh_channel_count', 1),
        ('afh_select_unideal_channel_count', 1),
        ('lsto', 2),
        ('connection_piconet_clock', 4),
        ('retransmission_count', 4),
        ('no_rx_count', 4),
        ('nak_count', 4),
        ('last_tx_ack_timestamp', 4),
        ('flow_off_count', 4),
        ('last_flow_on_timestamp', 4),
        ('buffer_overflow_bytes', 4),
        ('buffer_underflow_bytes', 4),
        ('bdaddr', Address.parse_address),
        ('cal_failed_item_count', 1),
        ('tx_total_packets', 4),
        ('tx_unacked_packets', 4),
        ('tx_flushed_packets', 4),
        ('tx_last_subevent_packets', 4),
        ('crc_error_packets', 4),
        ('rx_duplicate_packets', 4),
        ('vendor_specific_parameters', '*'),
    ]
)
class HCI_Bluetooth_Quality_Report_Event(HCI_Vendor_Event):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#bluetooth-quality-report-sub-event
    '''
