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
from bumble.hci import (
    hci_vendor_command_op_code,
    HCI_Command,
    STATUS_SPEC,
)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Zephyr RTOS Vendor Specific Commands and Events.
# Only a subset of the commands are implemented here currently.
#
# pylint: disable-next=line-too-long
# See https://github.com/zephyrproject-rtos/zephyr/blob/main/include/zephyr/bluetooth/hci_vs.h
HCI_WRITE_TX_POWER_LEVEL_COMMAND = hci_vendor_command_op_code(0x000E)
HCI_READ_TX_POWER_LEVEL_COMMAND = hci_vendor_command_op_code(0x000F)

HCI_Command.register_commands(globals())


# -----------------------------------------------------------------------------
class TX_Power_Level_Command:
    '''
    Base class for read and write TX power level HCI commands
    '''

    TX_POWER_HANDLE_TYPE_ADV = 0x00
    TX_POWER_HANDLE_TYPE_SCAN = 0x01
    TX_POWER_HANDLE_TYPE_CONN = 0x02


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('handle_type', 1), ('connection_handle', 2), ('tx_power_level', -1)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('handle_type', 1),
        ('connection_handle', 2),
        ('selected_tx_power_level', -1),
    ],
)
class HCI_Write_Tx_Power_Level_Command(HCI_Command, TX_Power_Level_Command):
    '''
    Write TX power level. See BT_HCI_OP_VS_WRITE_TX_POWER_LEVEL in
    https://github.com/zephyrproject-rtos/zephyr/blob/main/include/zephyr/bluetooth/hci_vs.h

    Power level is in dB. Connection handle for TX_POWER_HANDLE_TYPE_ADV and
    TX_POWER_HANDLE_TYPE_SCAN should be zero.
    '''


# -----------------------------------------------------------------------------
@HCI_Command.command(
    fields=[('handle_type', 1), ('connection_handle', 2)],
    return_parameters_fields=[
        ('status', STATUS_SPEC),
        ('handle_type', 1),
        ('connection_handle', 2),
        ('tx_power_level', -1),
    ],
)
class HCI_Read_Tx_Power_Level_Command(HCI_Command, TX_Power_Level_Command):
    '''
    Read TX power level. See BT_HCI_OP_VS_READ_TX_POWER_LEVEL in
    https://github.com/zephyrproject-rtos/zephyr/blob/main/include/zephyr/bluetooth/hci_vs.h

    Power level is in dB. Connection handle for TX_POWER_HANDLE_TYPE_ADV and
    TX_POWER_HANDLE_TYPE_SCAN should be zero.
    '''
