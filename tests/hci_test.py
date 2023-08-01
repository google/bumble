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

from bumble.hci import (
    HCI_DISCONNECT_COMMAND,
    HCI_LE_1M_PHY_BIT,
    HCI_LE_CODED_PHY_BIT,
    HCI_LE_READ_BUFFER_SIZE_COMMAND,
    HCI_RESET_COMMAND,
    HCI_SUCCESS,
    Address,
    HCI_Command,
    HCI_Command_Complete_Event,
    HCI_Command_Status_Event,
    HCI_CustomPacket,
    HCI_Disconnect_Command,
    HCI_Event,
    HCI_LE_Add_Device_To_Filter_Accept_List_Command,
    HCI_LE_Advertising_Report_Event,
    HCI_LE_Channel_Selection_Algorithm_Event,
    HCI_LE_Connection_Complete_Event,
    HCI_LE_Connection_Update_Command,
    HCI_LE_Connection_Update_Complete_Event,
    HCI_LE_Create_Connection_Command,
    HCI_LE_Extended_Create_Connection_Command,
    HCI_LE_Read_Buffer_Size_Command,
    HCI_LE_Read_Remote_Features_Command,
    HCI_LE_Read_Remote_Features_Complete_Event,
    HCI_LE_Remove_Device_From_Filter_Accept_List_Command,
    HCI_LE_Set_Advertising_Data_Command,
    HCI_LE_Set_Advertising_Parameters_Command,
    HCI_LE_Set_Default_PHY_Command,
    HCI_LE_Set_Event_Mask_Command,
    HCI_LE_Set_Extended_Advertising_Enable_Command,
    HCI_LE_Set_Extended_Scan_Parameters_Command,
    HCI_LE_Set_Random_Address_Command,
    HCI_LE_Set_Scan_Enable_Command,
    HCI_LE_Set_Scan_Parameters_Command,
    HCI_Number_Of_Completed_Packets_Event,
    HCI_Packet,
    HCI_PIN_Code_Request_Reply_Command,
    HCI_Read_Local_Supported_Commands_Command,
    HCI_Read_Local_Supported_Features_Command,
    HCI_Read_Local_Version_Information_Command,
    HCI_Reset_Command,
    HCI_Set_Event_Mask_Command,
)


# -----------------------------------------------------------------------------
# pylint: disable=invalid-name


def basic_check(x):
    packet = x.to_bytes()
    print(packet.hex())
    parsed = HCI_Packet.from_bytes(packet)
    x_str = str(x)
    parsed_str = str(parsed)
    print(x_str)
    parsed_bytes = parsed.to_bytes()
    assert x_str == parsed_str
    assert packet == parsed_bytes


# -----------------------------------------------------------------------------
def test_HCI_Event():
    event = HCI_Event(0xF9)
    basic_check(event)

    event = HCI_Event(0xF8, bytes.fromhex('AABBCC'))
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Connection_Complete_Event():
    address = Address('00:11:22:33:44:55')
    event = HCI_LE_Connection_Complete_Event(
        status=HCI_SUCCESS,
        connection_handle=1,
        role=1,
        peer_address_type=1,
        peer_address=address,
        connection_interval=3,
        peripheral_latency=4,
        supervision_timeout=5,
        central_clock_accuracy=6,
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Advertising_Report_Event():
    address = Address('00:11:22:33:44:55/P')
    report = HCI_LE_Advertising_Report_Event.Report(
        HCI_LE_Advertising_Report_Event.Report.FIELDS,
        event_type=HCI_LE_Advertising_Report_Event.ADV_IND,
        address_type=Address.PUBLIC_DEVICE_ADDRESS,
        address=address,
        data=bytes.fromhex(
            '0201061106ba5689a6fabfa2bd01467d6e00fbabad08160a181604659b03'
        ),
        rssi=100,
    )
    event = HCI_LE_Advertising_Report_Event([report])
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Read_Remote_Features_Complete_Event():
    event = HCI_LE_Read_Remote_Features_Complete_Event(
        status=HCI_SUCCESS,
        connection_handle=0x007,
        le_features=bytes.fromhex('0011223344556677'),
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Connection_Update_Complete_Event():
    event = HCI_LE_Connection_Update_Complete_Event(
        status=HCI_SUCCESS,
        connection_handle=0x007,
        connection_interval=10,
        peripheral_latency=3,
        supervision_timeout=5,
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Channel_Selection_Algorithm_Event():
    event = HCI_LE_Channel_Selection_Algorithm_Event(
        connection_handle=7, channel_selection_algorithm=1
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_Command_Complete_Event():
    # With a serializable object
    event = HCI_Command_Complete_Event(
        num_hci_command_packets=34,
        command_opcode=HCI_LE_READ_BUFFER_SIZE_COMMAND,
        return_parameters=HCI_LE_Read_Buffer_Size_Command.create_return_parameters(
            status=0,
            hc_le_acl_data_packet_length=1234,
            hc_total_num_le_acl_data_packets=56,
        ),
    )
    basic_check(event)

    # With an arbitrary byte array
    event = HCI_Command_Complete_Event(
        num_hci_command_packets=1,
        command_opcode=HCI_RESET_COMMAND,
        return_parameters=bytes([1, 2, 3, 4]),
    )
    basic_check(event)

    # With a simple status as a 1-byte array
    event = HCI_Command_Complete_Event(
        num_hci_command_packets=1,
        command_opcode=HCI_RESET_COMMAND,
        return_parameters=bytes([7]),
    )
    basic_check(event)
    event = HCI_Packet.from_bytes(event.to_bytes())
    assert event.return_parameters == 7

    # With a simple status as an integer status
    event = HCI_Command_Complete_Event(
        num_hci_command_packets=1, command_opcode=HCI_RESET_COMMAND, return_parameters=9
    )
    basic_check(event)
    assert event.return_parameters == 9


# -----------------------------------------------------------------------------
def test_HCI_Command_Status_Event():
    event = HCI_Command_Status_Event(
        status=0, num_hci_command_packets=37, command_opcode=HCI_DISCONNECT_COMMAND
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_Number_Of_Completed_Packets_Event():
    event = HCI_Number_Of_Completed_Packets_Event([(1, 2), (3, 4)])
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_Command():
    command = HCI_Command(0x5566)
    basic_check(command)

    command = HCI_Command(0x5566, bytes.fromhex('AABBCC'))
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_PIN_Code_Request_Reply_Command():
    pin_code = b'1234'
    pin_code_length = len(pin_code)
    # here to make the test pass, we need to
    # pad pin_code, as HCI_Object.format_fields
    # does not do it for us
    padded_pin_code = pin_code + bytes(16 - pin_code_length)
    command = HCI_PIN_Code_Request_Reply_Command(
        bd_addr=Address(
            '00:11:22:33:44:55', address_type=Address.PUBLIC_DEVICE_ADDRESS
        ),
        pin_code_length=pin_code_length,
        pin_code=padded_pin_code,
    )
    basic_check(command)


def test_HCI_Reset_Command():
    command = HCI_Reset_Command()
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Read_Local_Version_Information_Command():
    command = HCI_Read_Local_Version_Information_Command()
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Read_Local_Supported_Commands_Command():
    command = HCI_Read_Local_Supported_Commands_Command()
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Read_Local_Supported_Features_Command():
    command = HCI_Read_Local_Supported_Features_Command()
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Disconnect_Command():
    command = HCI_Disconnect_Command(connection_handle=123, reason=0x11)
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Set_Event_Mask_Command():
    command = HCI_Set_Event_Mask_Command(event_mask=bytes.fromhex('0011223344556677'))
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Event_Mask_Command():
    command = HCI_LE_Set_Event_Mask_Command(
        le_event_mask=bytes.fromhex('0011223344556677')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Random_Address_Command():
    command = HCI_LE_Set_Random_Address_Command(
        random_address=Address('00:11:22:33:44:55')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Advertising_Parameters_Command():
    command = HCI_LE_Set_Advertising_Parameters_Command(
        advertising_interval_min=20,
        advertising_interval_max=30,
        advertising_type=HCI_LE_Set_Advertising_Parameters_Command.ADV_NONCONN_IND,
        own_address_type=Address.PUBLIC_DEVICE_ADDRESS,
        peer_address_type=Address.RANDOM_DEVICE_ADDRESS,
        peer_address=Address('00:11:22:33:44:55'),
        advertising_channel_map=0x03,
        advertising_filter_policy=1,
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Advertising_Data_Command():
    command = HCI_LE_Set_Advertising_Data_Command(
        advertising_data=bytes.fromhex('AABBCC')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Scan_Parameters_Command():
    command = HCI_LE_Set_Scan_Parameters_Command(
        le_scan_type=1,
        le_scan_interval=20,
        le_scan_window=10,
        own_address_type=1,
        scanning_filter_policy=0,
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Scan_Enable_Command():
    command = HCI_LE_Set_Scan_Enable_Command(le_scan_enable=1, filter_duplicates=0)
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Create_Connection_Command():
    command = HCI_LE_Create_Connection_Command(
        le_scan_interval=4,
        le_scan_window=5,
        initiator_filter_policy=1,
        peer_address_type=1,
        peer_address=Address('00:11:22:33:44:55'),
        own_address_type=2,
        connection_interval_min=7,
        connection_interval_max=8,
        max_latency=9,
        supervision_timeout=10,
        min_ce_length=11,
        max_ce_length=12,
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Extended_Create_Connection_Command():
    command = HCI_LE_Extended_Create_Connection_Command(
        initiator_filter_policy=0,
        own_address_type=0,
        peer_address_type=1,
        peer_address=Address('00:11:22:33:44:55'),
        initiating_phys=3,
        scan_intervals=(10, 11),
        scan_windows=(12, 13),
        connection_interval_mins=(14, 15),
        connection_interval_maxs=(16, 17),
        max_latencies=(18, 19),
        supervision_timeouts=(20, 21),
        min_ce_lengths=(100, 101),
        max_ce_lengths=(102, 103),
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Add_Device_To_Filter_Accept_List_Command():
    command = HCI_LE_Add_Device_To_Filter_Accept_List_Command(
        address_type=1, address=Address('00:11:22:33:44:55')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Remove_Device_From_Filter_Accept_List_Command():
    command = HCI_LE_Remove_Device_From_Filter_Accept_List_Command(
        address_type=1, address=Address('00:11:22:33:44:55')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Connection_Update_Command():
    command = HCI_LE_Connection_Update_Command(
        connection_handle=0x0002,
        connection_interval_min=10,
        connection_interval_max=20,
        max_latency=7,
        supervision_timeout=3,
        min_ce_length=100,
        max_ce_length=200,
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Read_Remote_Features_Command():
    command = HCI_LE_Read_Remote_Features_Command(connection_handle=0x0002)
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Default_PHY_Command():
    command = HCI_LE_Set_Default_PHY_Command(all_phys=0, tx_phys=1, rx_phys=1)
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Extended_Scan_Parameters_Command():
    command = HCI_LE_Set_Extended_Scan_Parameters_Command(
        own_address_type=Address.RANDOM_DEVICE_ADDRESS,
        # pylint: disable-next=line-too-long
        scanning_filter_policy=HCI_LE_Set_Extended_Scan_Parameters_Command.BASIC_FILTERED_POLICY,
        scanning_phys=(1 << HCI_LE_1M_PHY_BIT | 1 << HCI_LE_CODED_PHY_BIT | 1 << 4),
        scan_types=[
            HCI_LE_Set_Extended_Scan_Parameters_Command.ACTIVE_SCANNING,
            HCI_LE_Set_Extended_Scan_Parameters_Command.ACTIVE_SCANNING,
            HCI_LE_Set_Extended_Scan_Parameters_Command.PASSIVE_SCANNING,
        ],
        scan_intervals=[1, 2, 3],
        scan_windows=[4, 5, 6],
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Extended_Advertising_Enable_Command():
    command = HCI_Packet.from_bytes(
        bytes.fromhex('0139200e010301050008020600090307000a')
    )
    assert command.enable == 1
    assert command.advertising_handles == [1, 2, 3]
    assert command.durations == [5, 6, 7]
    assert command.max_extended_advertising_events == [8, 9, 10]

    command = HCI_LE_Set_Extended_Advertising_Enable_Command(
        enable=1,
        advertising_handles=[1, 2, 3],
        durations=[5, 6, 7],
        max_extended_advertising_events=[8, 9, 10],
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_address():
    a = Address('C4:F2:17:1A:1D:BB')
    assert not a.is_public
    assert a.is_random
    assert a.address_type == Address.RANDOM_DEVICE_ADDRESS
    assert not a.is_resolvable
    assert not a.is_resolved
    assert a.is_static


# -----------------------------------------------------------------------------
def test_custom():
    data = bytes([0x77, 0x02, 0x01, 0x03])
    packet = HCI_CustomPacket(data)
    assert packet.hci_packet_type == 0x77
    assert packet.payload == data


# -----------------------------------------------------------------------------
def run_test_events():
    test_HCI_Event()
    test_HCI_LE_Connection_Complete_Event()
    test_HCI_LE_Advertising_Report_Event()
    test_HCI_LE_Connection_Update_Complete_Event()
    test_HCI_LE_Read_Remote_Features_Complete_Event()
    test_HCI_LE_Channel_Selection_Algorithm_Event()
    test_HCI_Command_Complete_Event()
    test_HCI_Command_Status_Event()
    test_HCI_Number_Of_Completed_Packets_Event()


# -----------------------------------------------------------------------------
def run_test_commands():
    test_HCI_Command()
    test_HCI_Reset_Command()
    test_HCI_PIN_Code_Request_Reply_Command()
    test_HCI_Read_Local_Version_Information_Command()
    test_HCI_Read_Local_Supported_Commands_Command()
    test_HCI_Read_Local_Supported_Features_Command()
    test_HCI_Disconnect_Command()
    test_HCI_Set_Event_Mask_Command()
    test_HCI_LE_Set_Event_Mask_Command()
    test_HCI_LE_Set_Random_Address_Command()
    test_HCI_LE_Set_Advertising_Parameters_Command()
    test_HCI_LE_Set_Advertising_Data_Command()
    test_HCI_LE_Set_Scan_Parameters_Command()
    test_HCI_LE_Set_Scan_Enable_Command()
    test_HCI_LE_Create_Connection_Command()
    test_HCI_LE_Extended_Create_Connection_Command()
    test_HCI_LE_Add_Device_To_Filter_Accept_List_Command()
    test_HCI_LE_Remove_Device_From_Filter_Accept_List_Command()
    test_HCI_LE_Connection_Update_Command()
    test_HCI_LE_Read_Remote_Features_Command()
    test_HCI_LE_Set_Default_PHY_Command()
    test_HCI_LE_Set_Extended_Scan_Parameters_Command()
    test_HCI_LE_Set_Extended_Advertising_Enable_Command()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    run_test_events()
    run_test_commands()
    test_address()
    test_custom()
