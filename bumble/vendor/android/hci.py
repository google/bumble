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
import dataclasses
import struct
from dataclasses import field

from bumble import hci

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Android Vendor Specific Commands and Events.
# Only a subset of the commands are implemented here currently.
#
# pylint: disable-next=line-too-long
# See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#chip-capabilities-and-configuration
HCI_LE_GET_VENDOR_CAPABILITIES_COMMAND = hci.hci_vendor_command_op_code(0x153)
HCI_LE_APCF_COMMAND = hci.hci_vendor_command_op_code(0x157)
HCI_GET_CONTROLLER_ACTIVITY_ENERGY_INFO_COMMAND = hci.hci_vendor_command_op_code(0x159)
HCI_A2DP_HARDWARE_OFFLOAD_COMMAND = hci.hci_vendor_command_op_code(0x15D)
HCI_BLUETOOTH_QUALITY_REPORT_COMMAND = hci.hci_vendor_command_op_code(0x15E)
HCI_DYNAMIC_AUDIO_BUFFER_COMMAND = hci.hci_vendor_command_op_code(0x15F)

HCI_BLUETOOTH_QUALITY_REPORT_EVENT = 0x58

hci.HCI_Command.register_commands(globals())


# -----------------------------------------------------------------------------
@hci.HCI_Command.command
@dataclasses.dataclass
class HCI_LE_Get_Vendor_Capabilities_Command(hci.HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#vendor-specific-capabilities
    '''

    return_parameters_fields = [
        ('status', hci.STATUS_SPEC),
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

    @classmethod
    def parse_return_parameters(cls, parameters):
        # There are many versions of this data structure, so we need to parse until
        # there are no more bytes to parse, and leave un-signal parameters set to
        # None (older versions)
        nones = {field: None for field, _ in cls.return_parameters_fields}
        return_parameters = hci.HCI_Object(cls.return_parameters_fields, **nones)

        try:
            offset = 0
            for field in cls.return_parameters_fields:
                field_name, field_type = field
                field_value, field_size = hci.HCI_Object.parse_field(
                    parameters, offset, field_type
                )
                setattr(return_parameters, field_name, field_value)
                offset += field_size
        except struct.error:
            pass

        return return_parameters


# -----------------------------------------------------------------------------
@hci.HCI_Command.command
@dataclasses.dataclass
class HCI_LE_APCF_Command(hci.HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#le_apcf_command

    NOTE: the subcommand-specific payloads are left as opaque byte arrays in this
    implementation. A future enhancement may define subcommand-specific data structures.
    '''

    # APCF Subcommands
    class Opcode(hci.SpecableEnum):
        ENABLE = 0x00
        SET_FILTERING_PARAMETERS = 0x01
        BROADCASTER_ADDRESS = 0x02
        SERVICE_UUID = 0x03
        SERVICE_SOLICITATION_UUID = 0x04
        LOCAL_NAME = 0x05
        MANUFACTURER_DATA = 0x06
        SERVICE_DATA = 0x07
        TRANSPORT_DISCOVERY_SERVICE = 0x08
        AD_TYPE_FILTER = 0x09
        READ_EXTENDED_FEATURES = 0xFF

    opcode: int = dataclasses.field(metadata=Opcode.type_metadata(1))
    payload: bytes = dataclasses.field(metadata=hci.metadata("*"))

    return_parameters_fields = [
        ('status', hci.STATUS_SPEC),
        ('opcode', Opcode.type_spec(1)),
        ('payload', '*'),
    ]


# -----------------------------------------------------------------------------
@hci.HCI_Command.command
@dataclasses.dataclass
class HCI_Get_Controller_Activity_Energy_Info_Command(hci.HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#le_get_controller_activity_energy_info
    '''

    return_parameters_fields = [
        ('status', hci.STATUS_SPEC),
        ('total_tx_time_ms', 4),
        ('total_rx_time_ms', 4),
        ('total_idle_time_ms', 4),
        ('total_energy_used', 4),
    ]


# -----------------------------------------------------------------------------
@hci.HCI_Command.command
@dataclasses.dataclass
class HCI_A2DP_Hardware_Offload_Command(hci.HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#a2dp-hardware-offload-support

    NOTE: the subcommand-specific payloads are left as opaque byte arrays in this
    implementation. A future enhancement may define subcommand-specific data structures.
    '''

    # A2DP Hardware Offload Subcommands
    class Opcode(hci.SpecableEnum):
        START_A2DP_OFFLOAD = 0x01
        STOP_A2DP_OFFLOAD = 0x02

    opcode: int = dataclasses.field(metadata=Opcode.type_metadata(1))
    payload: bytes = dataclasses.field(metadata=hci.metadata("*"))

    return_parameters_fields = [
        ('status', hci.STATUS_SPEC),
        ('opcode', Opcode.type_spec(1)),
        ('payload', '*'),
    ]


# -----------------------------------------------------------------------------
@hci.HCI_Command.command
@dataclasses.dataclass
class HCI_Dynamic_Audio_Buffer_Command(hci.HCI_Command):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#dynamic-audio-buffer-command

    NOTE: the subcommand-specific payloads are left as opaque byte arrays in this
    implementation. A future enhancement may define subcommand-specific data structures.
    '''

    # Dynamic Audio Buffer Subcommands
    class Opcode(hci.SpecableEnum):
        GET_AUDIO_BUFFER_TIME_CAPABILITY = 0x01

    opcode: int = dataclasses.field(metadata=Opcode.type_metadata(1))
    payload: bytes = dataclasses.field(metadata=hci.metadata("*"))

    return_parameters_fields = [
        ('status', hci.STATUS_SPEC),
        ('opcode', Opcode.type_spec(1)),
        ('payload', '*'),
    ]


# -----------------------------------------------------------------------------
class HCI_Android_Vendor_Event(hci.HCI_Extended_Event):
    event_code: int = hci.HCI_VENDOR_EVENT
    subevent_classes: dict[int, type[hci.HCI_Extended_Event]] = {}

    @classmethod
    def subclass_from_parameters(
        cls, parameters: bytes
    ) -> hci.HCI_Extended_Event | None:
        subevent_code = parameters[0]
        if subevent_code == HCI_BLUETOOTH_QUALITY_REPORT_EVENT:
            quality_report_id = parameters[1]
            if quality_report_id in (0x01, 0x02, 0x03, 0x04, 0x07, 0x08, 0x09):
                return HCI_Bluetooth_Quality_Report_Event.from_parameters(parameters)

        return None


HCI_Android_Vendor_Event.register_subevents(globals())
hci.HCI_Event.add_vendor_factory(HCI_Android_Vendor_Event.subclass_from_parameters)


# -----------------------------------------------------------------------------
@hci.HCI_Extended_Event.event
@dataclasses.dataclass
class HCI_Bluetooth_Quality_Report_Event(HCI_Android_Vendor_Event):
    # pylint: disable=line-too-long
    '''
    See https://source.android.com/docs/core/connect/bluetooth/hci_requirements#bluetooth-quality-report-sub-event
    '''

    quality_report_id: int = field(metadata=hci.metadata(1))
    packet_types: int = field(metadata=hci.metadata(1))
    connection_handle: int = field(metadata=hci.metadata(2))
    connection_role: int = field(metadata=hci.Role.type_metadata(1))
    tx_power_level: int = field(metadata=hci.metadata(-1))
    rssi: int = field(metadata=hci.metadata(-1))
    snr: int = field(metadata=hci.metadata(1))
    unused_afh_channel_count: int = field(metadata=hci.metadata(1))
    afh_select_unideal_channel_count: int = field(metadata=hci.metadata(1))
    lsto: int = field(metadata=hci.metadata(2))
    connection_piconet_clock: int = field(metadata=hci.metadata(4))
    retransmission_count: int = field(metadata=hci.metadata(4))
    no_rx_count: int = field(metadata=hci.metadata(4))
    nak_count: int = field(metadata=hci.metadata(4))
    last_tx_ack_timestamp: int = field(metadata=hci.metadata(4))
    flow_off_count: int = field(metadata=hci.metadata(4))
    last_flow_on_timestamp: int = field(metadata=hci.metadata(4))
    buffer_overflow_bytes: int = field(metadata=hci.metadata(4))
    buffer_underflow_bytes: int = field(metadata=hci.metadata(4))
    bdaddr: hci.Address = field(metadata=hci.metadata(hci.Address.parse_address))
    cal_failed_item_count: int = field(metadata=hci.metadata(1))
    tx_total_packets: int = field(metadata=hci.metadata(4))
    tx_unacked_packets: int = field(metadata=hci.metadata(4))
    tx_flushed_packets: int = field(metadata=hci.metadata(4))
    tx_last_subevent_packets: int = field(metadata=hci.metadata(4))
    crc_error_packets: int = field(metadata=hci.metadata(4))
    rx_duplicate_packets: int = field(metadata=hci.metadata(4))
    rx_unreceived_packets: int = field(metadata=hci.metadata(4))
    vendor_specific_parameters: bytes = field(metadata=hci.metadata('*'))
