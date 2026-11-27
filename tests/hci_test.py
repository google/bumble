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
import dataclasses
import inspect
import struct

import pytest

from bumble import hci, utils

# -----------------------------------------------------------------------------
# pylint: disable=invalid-name


def basic_check(x):
    packet = bytes(x)
    print(packet.hex())
    parsed = hci.HCI_Packet.from_bytes(packet)
    x_str = str(x)
    parsed_str = str(parsed)
    print(x_str)
    parsed_bytes = bytes(parsed)
    assert x_str == parsed_str
    assert packet == parsed_bytes


# -----------------------------------------------------------------------------
def test_HCI_Event():
    event = hci.HCI_Event(event_code=0xF9)
    basic_check(event)

    event = hci.HCI_Event(event_code=0xF8, parameters=bytes.fromhex('AABBCC'))
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Connection_Complete_Event():
    address = hci.Address('00:11:22:33:44:55')
    event = hci.HCI_LE_Connection_Complete_Event(
        status=hci.HCI_SUCCESS,
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
    address = hci.Address('00:11:22:33:44:55/P')
    report = hci.HCI_LE_Advertising_Report_Event.Report(
        event_type=hci.HCI_LE_Advertising_Report_Event.EventType.ADV_IND,
        address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
        address=address,
        data=bytes.fromhex(
            '0201061106ba5689a6fabfa2bd01467d6e00fbabad08160a181604659b03'
        ),
        rssi=100,
    )
    event = hci.HCI_LE_Advertising_Report_Event([report])
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Extended_Advertising_Report_Event():
    address = hci.Address('00:11:22:33:44:55/P')
    report = hci.HCI_LE_Extended_Advertising_Report_Event.Report(
        event_type=hci.HCI_LE_Extended_Advertising_Report_Event.EventType.CONNECTABLE_ADVERTISING,
        address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
        address=address,
        data=bytes.fromhex(
            '0201061106ba5689a6fabfa2bd01467d6e00fbabad08160a181604659b03'
        ),
        rssi=100,
        primary_phy=hci.HCI_LE_1M_PHY,
        secondary_phy=hci.HCI_LE_CODED_PHY,
        advertising_sid=0,
        tx_power=10,
        periodic_advertising_interval=2,
        direct_address=hci.Address('00:11:22:33:44:55/P'),
        direct_address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
    )
    event = hci.HCI_LE_Extended_Advertising_Report_Event([report])
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Read_Remote_Features_Complete_Event():
    event = hci.HCI_LE_Read_Remote_Features_Complete_Event(
        status=hci.HCI_SUCCESS,
        connection_handle=0x007,
        le_features=bytes.fromhex('0011223344556677'),
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Connection_Update_Complete_Event():
    event = hci.HCI_LE_Connection_Update_Complete_Event(
        status=hci.HCI_SUCCESS,
        connection_handle=0x007,
        connection_interval=10,
        peripheral_latency=3,
        supervision_timeout=5,
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_LE_Channel_Selection_Algorithm_Event():
    event = hci.HCI_LE_Channel_Selection_Algorithm_Event(
        connection_handle=7, channel_selection_algorithm=1
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_Command_Complete_Event():
    # With a serializable object
    event1 = hci.HCI_Command_Complete_Event(
        num_hci_command_packets=34,
        command_opcode=hci.HCI_LE_READ_BUFFER_SIZE_COMMAND,
        return_parameters=hci.HCI_LE_Read_Buffer_Size_Command.return_parameters_class(
            status=0,
            le_acl_data_packet_length=1234,
            total_num_le_acl_data_packets=56,
        ),
    )
    basic_check(event1)

    # With a simple status as an integer status
    event3 = hci.HCI_Command_Complete_Event(
        num_hci_command_packets=1,
        command_opcode=hci.HCI_RESET_COMMAND,
        return_parameters=hci.HCI_StatusReturnParameters(hci.HCI_ErrorCode(9)),
    )
    basic_check(event3)
    assert event3.return_parameters.status == 9


# -----------------------------------------------------------------------------
def test_HCI_Command_Status_Event():
    event = hci.HCI_Command_Status_Event(
        status=0, num_hci_command_packets=37, command_opcode=hci.HCI_DISCONNECT_COMMAND
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_Number_Of_Completed_Packets_Event():
    event = hci.HCI_Number_Of_Completed_Packets_Event(
        connection_handles=(1, 2),
        num_completed_packets=(3, 4),
    )
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_Number_Of_Completed_Packets_Event_with_no_handles():
    wire = bytes.fromhex('04130100')
    event = hci.HCI_Packet.from_bytes(wire)

    assert isinstance(event, hci.HCI_Number_Of_Completed_Packets_Event)
    assert event.connection_handles == []
    assert event.num_completed_packets == []
    assert bytes(event) == wire
    basic_check(event)


# -----------------------------------------------------------------------------
def test_HCI_Vendor_Event():
    data = bytes.fromhex('01020304')
    event = hci.HCI_Vendor_Event(data=data)
    event_bytes = bytes(event)
    parsed = hci.HCI_Packet.from_bytes(event_bytes)
    assert isinstance(parsed, hci.HCI_Vendor_Event)
    assert parsed.data == data

    class HCI_Custom_Event(hci.HCI_Event):
        def __init__(self, blabla):
            super().__init__(
                event_code=hci.HCI_VENDOR_EVENT, parameters=struct.pack("<I", blabla)
            )
            self.name = 'HCI_CUSTOM_EVENT'
            self.blabla = blabla

    def create_event(payload):
        if payload[0] == 1:
            return HCI_Custom_Event(blabla=struct.unpack('<I', payload)[0])
        return None

    hci.HCI_Event.add_vendor_factory(create_event)
    parsed = hci.HCI_Packet.from_bytes(event_bytes)
    assert isinstance(parsed, HCI_Custom_Event)
    assert parsed.blabla == 0x04030201
    event_bytes2 = event_bytes[:3] + bytes([7]) + event_bytes[4:]
    parsed = hci.HCI_Packet.from_bytes(event_bytes2)
    assert not isinstance(parsed, HCI_Custom_Event)
    assert isinstance(parsed, hci.HCI_Vendor_Event)
    hci.HCI_Event.remove_vendor_factory(create_event)

    parsed = hci.HCI_Packet.from_bytes(event_bytes)
    assert not isinstance(parsed, HCI_Custom_Event)
    assert isinstance(parsed, hci.HCI_Vendor_Event)


# -----------------------------------------------------------------------------
def test_return_parameters() -> None:
    params = hci.HCI_Reset_Command.parse_return_parameters(bytes.fromhex('3C'))
    assert params.status == hci.HCI_ErrorCode.ADVERTISING_TIMEOUT_ERROR
    assert isinstance(params.status, utils.OpenIntEnum)

    params = hci.HCI_Read_BD_ADDR_Command.parse_return_parameters(
        bytes.fromhex('00001122334455')
    )
    assert params.status == hci.HCI_ErrorCode.SUCCESS
    assert isinstance(params.status, utils.OpenIntEnum)
    assert isinstance(params.bd_addr, hci.Address)

    params = hci.HCI_Read_Local_Name_Command.parse_return_parameters(
        bytes.fromhex('0068656c6c6f') + bytes(248 - 5)
    )
    assert params.status == hci.HCI_ErrorCode.SUCCESS
    assert isinstance(params.local_name, bytes)
    assert len(params.local_name) == 248
    assert hci.map_null_terminated_utf8_string(params.local_name) == 'hello'

    # Some return parameters may be shorter than the full length
    # (for Command Complete events with errors)
    params = hci.HCI_Read_BD_ADDR_Command.parse_return_parameters(
        bytes.fromhex('010011223344')
    )
    assert isinstance(params, hci.HCI_StatusReturnParameters)
    assert params.status == hci.HCI_ErrorCode.UNKNOWN_HCI_COMMAND_ERROR


# -----------------------------------------------------------------------------
def test_HCI_Command():
    command = hci.HCI_Command(op_code=0x5566)
    basic_check(command)

    command = hci.HCI_Command(op_code=0x5566, parameters=bytes.fromhex('AABBCC'))
    basic_check(command)


# -----------------------------------------------------------------------------
def test_custom_command():
    @hci.HCI_Command.command
    class CustomCommand(hci.HCI_Command):
        op_code = 0x7788
        name = 'Custom Command'

    command = CustomCommand()
    basic_check(command)
    parsed = hci.HCI_Packet.from_bytes(bytes(command))
    assert isinstance(parsed, CustomCommand)
    assert parsed.op_code == 0x7788
    assert parsed.name == 'Custom Command'


# -----------------------------------------------------------------------------
def test_custom_event():
    @hci.HCI_Event.event
    class CustomEvent(hci.HCI_Event):
        event_code = 0x99
        name = 'Custom Event'

    event = CustomEvent()
    basic_check(event)
    parsed = hci.HCI_Packet.from_bytes(bytes(event))
    assert isinstance(parsed, CustomEvent)
    assert parsed.event_code == 0x99
    assert parsed.name == 'Custom Event'


# -----------------------------------------------------------------------------
def test_custom_le_meta_event():
    @hci.HCI_LE_Meta_Event.event
    class CustomEvent(hci.HCI_LE_Meta_Event):
        subevent_code = 0xFF
        name = 'Custom Extended Event'

    event = CustomEvent()
    basic_check(event)
    parsed = hci.HCI_Packet.from_bytes(bytes(event))
    assert isinstance(parsed, CustomEvent)
    assert parsed.subevent_code == 0xFF
    assert parsed.name == 'Custom Extended Event'


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "clazz",
    [
        clazz[1]
        for clazz in inspect.getmembers(hci)
        if isinstance(clazz[1], type)
        and issubclass(clazz[1], hci.HCI_Command)
        and clazz[1] not in (hci.HCI_Command, hci.HCI_SyncCommand, hci.HCI_AsyncCommand)
    ],
)
def test_hci_command_subclasses_op_code(clazz: type[hci.HCI_Command]):
    assert clazz.op_code > 0
    assert isinstance(clazz.name, str)


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "clazz",
    [
        clazz[1]
        for clazz in inspect.getmembers(hci)
        if isinstance(clazz[1], type)
        and clazz[1] is not hci.HCI_Event
        and issubclass(clazz[1], hci.HCI_Event)
        and not issubclass(clazz[1], hci.HCI_Extended_Event)
    ],
)
def test_hci_event_subclasses_event_code(clazz: type[hci.HCI_Event]):
    assert clazz.event_code > 0
    assert isinstance(clazz.name, str)


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "clazz",
    [
        clazz[1]
        for clazz in inspect.getmembers(hci)
        if isinstance(clazz[1], type)
        and issubclass(clazz[1], hci.HCI_Extended_Event)
        and clazz[1] not in (hci.HCI_Extended_Event, hci.HCI_LE_Meta_Event)
    ],
)
def test_hci_extended_event_subclasses_event_code(clazz: type[hci.HCI_Extended_Event]):
    assert clazz.event_code > 0
    assert clazz.subevent_code > 0
    assert isinstance(clazz.name, str)


# -----------------------------------------------------------------------------
def test_HCI_PIN_Code_Request_Reply_Command():
    pin_code = b'1234'
    pin_code_length = len(pin_code)
    # here to make the test pass, we need to
    # pad pin_code, as hci.HCI_Object.format_fields
    # does not do it for us
    padded_pin_code = pin_code + bytes(16 - pin_code_length)
    command = hci.HCI_PIN_Code_Request_Reply_Command(
        bd_addr=hci.Address(
            '00:11:22:33:44:55', address_type=hci.Address.PUBLIC_DEVICE_ADDRESS
        ),
        pin_code_length=pin_code_length,
        pin_code=padded_pin_code,
    )
    basic_check(command)


def test_HCI_Reset_Command():
    command = hci.HCI_Reset_Command()
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Read_Local_Version_Information_Command():
    command = hci.HCI_Read_Local_Version_Information_Command()
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Read_Local_Supported_Commands_Command():
    command = hci.HCI_Read_Local_Supported_Commands_Command()
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Read_Local_Supported_Features_Command():
    command = hci.HCI_Read_Local_Supported_Features_Command()
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Disconnect_Command():
    command = hci.HCI_Disconnect_Command(connection_handle=123, reason=0x11)
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Set_Event_Mask_Command():
    command = hci.HCI_Set_Event_Mask_Command(
        event_mask=bytes.fromhex('0011223344556677')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Event_Mask_Command():
    command = hci.HCI_LE_Set_Event_Mask_Command(
        le_event_mask=hci.HCI_LE_Set_Event_Mask_Command.mask(
            [
                hci.HCI_LE_CONNECTION_COMPLETE_EVENT,
                hci.HCI_LE_ENHANCED_CONNECTION_COMPLETE_V2_EVENT,
            ]
        )
    )
    assert command.le_event_mask == bytes.fromhex('0100000000010000')
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Random_Address_Command():
    command = hci.HCI_LE_Set_Random_Address_Command(
        random_address=hci.Address('00:11:22:33:44:55')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Advertising_Parameters_Command():
    command = hci.HCI_LE_Set_Advertising_Parameters_Command(
        advertising_interval_min=20,
        advertising_interval_max=30,
        advertising_type=hci.HCI_LE_Set_Advertising_Parameters_Command.AdvertisingType.ADV_NONCONN_IND,
        own_address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
        peer_address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
        peer_address=hci.Address('00:11:22:33:44:55'),
        advertising_channel_map=0x03,
        advertising_filter_policy=1,
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Advertising_Data_Command():
    command = hci.HCI_LE_Set_Advertising_Data_Command(
        advertising_data=bytes.fromhex('AABBCC')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Scan_Parameters_Command():
    command = hci.HCI_LE_Set_Scan_Parameters_Command(
        le_scan_type=1,
        le_scan_interval=20,
        le_scan_window=10,
        own_address_type=1,
        scanning_filter_policy=0,
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Scan_Enable_Command():
    command = hci.HCI_LE_Set_Scan_Enable_Command(le_scan_enable=1, filter_duplicates=0)
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Create_Connection_Command():
    command = hci.HCI_LE_Create_Connection_Command(
        le_scan_interval=4,
        le_scan_window=5,
        initiator_filter_policy=1,
        peer_address_type=1,
        peer_address=hci.Address('00:11:22:33:44:55'),
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
    command = hci.HCI_LE_Extended_Create_Connection_Command(
        initiator_filter_policy=0,
        own_address_type=0,
        peer_address_type=1,
        peer_address=hci.Address('00:11:22:33:44:55'),
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
    command = hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(
        address_type=1, address=hci.Address('00:11:22:33:44:55')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Remove_Device_From_Filter_Accept_List_Command():
    command = hci.HCI_LE_Remove_Device_From_Filter_Accept_List_Command(
        address_type=1, address=hci.Address('00:11:22:33:44:55')
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Connection_Update_Command():
    command = hci.HCI_LE_Connection_Update_Command(
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
    command = hci.HCI_LE_Read_Remote_Features_Command(connection_handle=0x0002)
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Default_PHY_Command():
    command = hci.HCI_LE_Set_Default_PHY_Command(all_phys=0, tx_phys=1, rx_phys=1)
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Extended_Scan_Parameters_Command():
    command = hci.HCI_LE_Set_Extended_Scan_Parameters_Command(
        own_address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
        # pylint: disable-next=line-too-long
        scanning_filter_policy=hci.HCI_LE_Set_Extended_Scan_Parameters_Command.BASIC_FILTERED_POLICY,
        scanning_phys=(
            1 << hci.HCI_LE_1M_PHY_BIT | 1 << hci.HCI_LE_CODED_PHY_BIT | 1 << 4
        ),
        scan_types=[
            hci.HCI_LE_Set_Extended_Scan_Parameters_Command.ACTIVE_SCANNING,
            hci.HCI_LE_Set_Extended_Scan_Parameters_Command.ACTIVE_SCANNING,
            hci.HCI_LE_Set_Extended_Scan_Parameters_Command.PASSIVE_SCANNING,
        ],
        scan_intervals=[1, 2, 3],
        scan_windows=[4, 5, 6],
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_LE_Set_Extended_Advertising_Enable_Command():
    command = hci.HCI_Packet.from_bytes(
        bytes.fromhex('0139200e010301050008020600090307000a')
    )
    assert command.enable == 1
    assert command.advertising_handles == [1, 2, 3]
    assert command.durations == [5, 6, 7]
    assert command.max_extended_advertising_events == [8, 9, 10]

    command = hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
        enable=1,
        advertising_handles=[1, 2, 3],
        durations=[5, 6, 7],
        max_extended_advertising_events=[8, 9, 10],
    )
    basic_check(command)


# -----------------------------------------------------------------------------
def test_HCI_Setup_Synchronous_Connection_Command():
    # A legacy Setup Synchronous Connection command with a 16-bit CVSD voice setting
    # and eSCO packet types (Core Spec Vol 4, Part E - 7.1.26).
    command = hci.HCI_Setup_Synchronous_Connection_Command(
        connection_handle=0x0060,
        transmit_bandwidth=8000,
        receive_bandwidth=8000,
        max_latency=10,
        voice_setting=0x0060,
        retransmission_effort=1,
        packet_type=0x0388,
    )
    basic_check(command)

    parsed = hci.HCI_Packet.from_bytes(bytes(command))
    assert parsed.connection_handle == 0x0060
    assert parsed.voice_setting == 0x0060
    assert (
        parsed.packet_type
        & hci.HCI_Setup_Synchronous_Connection_Command.ESCO_PACKET_TYPES
    )
    assert not (
        parsed.packet_type
        & hci.HCI_Setup_Synchronous_Connection_Command.SCO_PACKET_TYPES
    )

    # A SCO link, with an 8-bit voice setting
    sco_command = hci.HCI_Setup_Synchronous_Connection_Command(
        connection_handle=0x0060,
        transmit_bandwidth=8000,
        receive_bandwidth=8000,
        max_latency=10,
        voice_setting=0x0000,
        retransmission_effort=1,
        packet_type=hci.HCI_Setup_Synchronous_Connection_Command.PacketType.HV3,
    )
    basic_check(sco_command)
    assert (
        sco_command.packet_type
        & hci.HCI_Setup_Synchronous_Connection_Command.SCO_PACKET_TYPES
    )
    assert not (
        sco_command.packet_type
        & hci.HCI_Setup_Synchronous_Connection_Command.ESCO_PACKET_TYPES
    )


# -----------------------------------------------------------------------------
def test_voice_setting_codec_id():
    # The Air_Coding_Format of a voice setting uses a different numbering than the air
    # mode (codec ID) reported by the Synchronous Connection Complete event.
    assert hci.VoiceSetting.from_int(0x0060).codec_id() == hci.CodecID.CVSD
    assert hci.VoiceSetting.from_int(0x0063).codec_id() == hci.CodecID.TRANSPARENT
    assert (
        hci.VoiceSetting(
            air_coding_format=hci.VoiceSetting.AirCodingFormat.U_LAW
        ).codec_id()
        == hci.CodecID.U_LOG
    )
    assert (
        hci.VoiceSetting(
            air_coding_format=hci.VoiceSetting.AirCodingFormat.A_LAW
        ).codec_id()
        == hci.CodecID.A_LOG
    )


# -----------------------------------------------------------------------------
def test_HCI_LE_Setup_ISO_Data_Path_Command():
    command = hci.HCI_Packet.from_bytes(
        bytes.fromhex('016e200d60000001030000000000000000')
    )

    assert command.connection_handle == 0x0060
    assert command.data_path_direction == 0x00
    assert command.data_path_id == 0x01
    assert command.codec_id == hci.CodingFormat(hci.CodecID.TRANSPARENT)
    assert command.controller_delay == 0
    assert command.codec_configuration == b''

    command = hci.HCI_LE_Setup_ISO_Data_Path_Command(
        connection_handle=0x0060,
        data_path_direction=0x00,
        data_path_id=0x01,
        codec_id=hci.CodingFormat(hci.CodecID.TRANSPARENT),
        controller_delay=0x00,
        codec_configuration=b'',
    )
    basic_check(command)


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ('packet', 'wire'),
    [
        pytest.param(
            hci.HCI_Read_Authenticated_Payload_Timeout_Command(
                connection_handle=0x0123
            ),
            '017b0c022301',
            id='read-authenticated-payload-timeout',
        ),
        pytest.param(
            hci.HCI_LE_Set_Host_Channel_Classification_Command(
                channel_map=bytes.fromhex('0102030405')
            ),
            '011420050102030405',
            id='set-host-channel-classification',
        ),
        pytest.param(
            hci.HCI_LE_Read_Channel_Map_Command(connection_handle=0x0123),
            '011520022301',
            id='read-channel-map',
        ),
        pytest.param(
            hci.HCI_LE_Encrypt_Command(
                key=bytes(range(16)), plaintext_data=bytes(range(16, 32))
            ),
            '01172020'
            '000102030405060708090a0b0c0d0e0f'
            '101112131415161718191a1b1c1d1e1f',
            id='encrypt',
        ),
        pytest.param(
            hci.HCI_LE_Add_Device_To_Periodic_Advertiser_List_Command(
                advertiser_address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
                advertiser_address=hci.Address('11:22:33:44:55:66'),
                advertising_sid=0x07,
            ),
            '014720080166554433221107',
            id='add-periodic-advertiser',
        ),
        pytest.param(
            hci.HCI_LE_Remove_Device_From_Periodic_Advertiser_List_Command(
                advertiser_address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
                advertiser_address=hci.Address('11:22:33:44:55:66'),
                advertising_sid=0x07,
            ),
            '014820080166554433221107',
            id='remove-periodic-advertiser',
        ),
        pytest.param(
            hci.HCI_LE_Clear_Periodic_Advertiser_List_Command(),
            '01492000',
            id='clear-periodic-advertisers',
        ),
        pytest.param(
            hci.HCI_LE_Read_Periodic_Advertiser_List_Size_Command(),
            '014a2000',
            id='read-periodic-advertiser-list-size',
        ),
    ],
)
def test_hci_command_wire_vectors(packet, wire: str) -> None:
    encoded = bytes.fromhex(wire)
    assert bytes(packet) == encoded

    parsed = hci.HCI_Packet.from_bytes(encoded)
    assert type(parsed) is type(packet)
    for field_name, _ in packet.fields:
        assert getattr(parsed, field_name) == getattr(packet, field_name)
    assert bytes(parsed) == encoded


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ('event', 'wire'),
    [
        pytest.param(
            hci.HCI_LE_Scan_Timeout_Event(),
            '043e0111',
            id='scan-timeout',
        ),
        pytest.param(
            hci.HCI_LE_Scan_Request_Received_Event(
                advertising_handle=0x03,
                scanner_address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
                scanner_address=hci.Address('11:22:33:44:55:66'),
            ),
            '043e09130301665544332211',
            id='scan-request-received',
        ),
        pytest.param(
            hci.HCI_Authenticated_Payload_Timeout_Expired_Event(
                connection_handle=0x0123
            ),
            '0457022301',
            id='authenticated-payload-timeout-expired',
        ),
    ],
)
def test_hci_event_wire_vectors(event, wire: str) -> None:
    encoded = bytes.fromhex(wire)
    assert bytes(event) == encoded

    parsed = hci.HCI_Packet.from_bytes(encoded)
    assert type(parsed) is type(event)
    for field_name, _ in event.fields:
        assert getattr(parsed, field_name) == getattr(event, field_name)
    assert bytes(parsed) == encoded


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ('command_class', 'parameters', 'expected_fields'),
    [
        pytest.param(
            hci.HCI_Read_Authenticated_Payload_Timeout_Command,
            '0023013412',
            {'connection_handle': 0x0123, 'authenticated_payload_timeout': 0x1234},
            id='read-authenticated-payload-timeout',
        ),
        pytest.param(
            hci.HCI_LE_Read_Channel_Map_Command,
            '0023010102030405',
            {'connection_handle': 0x0123, 'channel_map': bytes.fromhex('0102030405')},
            id='read-channel-map',
        ),
        pytest.param(
            hci.HCI_LE_Encrypt_Command,
            '00000102030405060708090a0b0c0d0e0f',
            {'encrypted_data': bytes(range(16))},
            id='encrypt',
        ),
        pytest.param(
            hci.HCI_LE_Read_Periodic_Advertiser_List_Size_Command,
            '0008',
            {'periodic_advertiser_list_size': 8},
            id='read-periodic-advertiser-list-size',
        ),
    ],
)
def test_hci_command_return_parameters(
    command_class, parameters: str, expected_fields: dict
) -> None:
    result = command_class.parse_return_parameters(bytes.fromhex(parameters))

    assert result.status == hci.HCI_SUCCESS
    for name, value in expected_fields.items():
        assert getattr(result, name) == value


# -----------------------------------------------------------------------------
def test_HCI_Read_Local_Supported_Codecs_Command_Complete():
    returned_parameters = (
        hci.HCI_Read_Local_Supported_Codecs_Command.parse_return_parameters(
            bytes(
                [
                    hci.HCI_SUCCESS,
                    3,
                    hci.CodecID.A_LOG,
                    hci.CodecID.CVSD,
                    hci.CodecID.LINEAR_PCM,
                    0,
                ]
            )
        )
    )
    assert returned_parameters.standard_codec_ids == [
        hci.CodecID.A_LOG,
        hci.CodecID.CVSD,
        hci.CodecID.LINEAR_PCM,
    ]


# -----------------------------------------------------------------------------
def test_HCI_Read_Local_Supported_Codecs_V2_Command_Complete():
    returned_parameters = hci.HCI_Read_Local_Supported_Codecs_V2_Command.parse_return_parameters(
        bytes(
            [
                hci.HCI_SUCCESS,
                3,
                hci.CodecID.A_LOG,
                hci.HCI_Read_Local_Supported_Codecs_V2_ReturnParameters.Transport.BR_EDR_ACL,
                hci.CodecID.CVSD,
                hci.HCI_Read_Local_Supported_Codecs_V2_ReturnParameters.Transport.BR_EDR_SCO,
                hci.CodecID.LINEAR_PCM,
                hci.HCI_Read_Local_Supported_Codecs_V2_ReturnParameters.Transport.LE_CIS,
                0,
            ]
        )
    )
    assert returned_parameters.standard_codec_ids == [
        hci.CodecID.A_LOG,
        hci.CodecID.CVSD,
        hci.CodecID.LINEAR_PCM,
    ]
    assert returned_parameters.standard_codec_transports == [
        hci.HCI_Read_Local_Supported_Codecs_V2_ReturnParameters.Transport.BR_EDR_ACL,
        hci.HCI_Read_Local_Supported_Codecs_V2_ReturnParameters.Transport.BR_EDR_SCO,
        hci.HCI_Read_Local_Supported_Codecs_V2_ReturnParameters.Transport.LE_CIS,
    ]


# -----------------------------------------------------------------------------
def test_address():
    a = hci.Address('C4:F2:17:1A:1D:BB')
    assert not a.is_public
    assert a.is_random
    assert a.address_type == hci.Address.RANDOM_DEVICE_ADDRESS
    assert not a.is_resolvable
    assert not a.is_resolved
    assert a.is_static


# -----------------------------------------------------------------------------
def test_custom():
    data = bytes([0x77, 0x02, 0x01, 0x03])
    packet = hci.HCI_CustomPacket(data)
    assert packet.hci_packet_type == 0x77
    assert packet.payload == data


# -----------------------------------------------------------------------------
def test_iso_data_packet():
    data = bytes.fromhex(
        '05616044002ac9f0a193003c00e83b477b00eba8d41dc018bf1a980f0290afe1e7c37652096697'
        '52b6a535a8df61e22931ef5a36281bc77ed6a3206d984bcdabee6be831c699cb50e2'
    )
    packet = hci.HCI_IsoDataPacket.from_bytes(data)
    assert packet.connection_handle == 0x0061
    assert packet.packet_status_flag == 0
    assert packet.pb_flag == 0x02
    assert packet.ts_flag == 0x01
    assert packet.data_total_length == 68
    assert packet.time_stamp == 2716911914
    assert packet.packet_sequence_number == 147
    assert packet.iso_sdu_length == 60
    assert packet.iso_sdu_fragment == bytes.fromhex(
        'e83b477b00eba8d41dc018bf1a980f0290afe1e7c3765209669752b6a535a8df61e22931ef5a3'
        '6281bc77ed6a3206d984bcdabee6be831c699cb50e2'
    )

    assert bytes(packet) == data


# -----------------------------------------------------------------------------
def test_iso_data_packet_too_short():
    # A truncated ISO data packet must raise InvalidPacketError, not the raw
    # struct.error from unpack_from. Here pb_flag=0b00 asks for 4 bytes of SDU
    # info at offset 5, but the packet ends at offset 5.
    data = bytes.fromhex('0561000000')  # type + pdu_info(0x0061) + len(0) = 5 bytes
    with pytest.raises(hci.InvalidPacketError):
        hci.HCI_IsoDataPacket.from_bytes(data)


# -----------------------------------------------------------------------------
def test_signed_tx_power_fields():
    # LE Set Extended Advertising Parameters (7.8.53): advertising_tx_power is int8.
    ext_adv_cmd = hci.HCI_LE_Set_Extended_Advertising_Parameters_Command(
        advertising_handle=1,
        advertising_event_properties=0,
        primary_advertising_interval_min=0x20,
        primary_advertising_interval_max=0x40,
        primary_advertising_channel_map=0x07,
        own_address_type=hci.OwnAddressType.RANDOM,
        peer_address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
        peer_address=hci.Address.ANY,
        advertising_filter_policy=0,
        advertising_tx_power=-20,
        primary_advertising_phy=hci.Phy.LE_1M,
        secondary_advertising_max_skip=0,
        secondary_advertising_phy=hci.Phy.LE_1M,
        advertising_sid=0,
        scan_request_notification_enable=0,
    )
    parsed_ext_adv = hci.HCI_Command.from_bytes(bytes(ext_adv_cmd))
    assert isinstance(
        parsed_ext_adv, hci.HCI_LE_Set_Extended_Advertising_Parameters_Command
    )
    assert parsed_ext_adv.advertising_tx_power == -20
    assert bytes(parsed_ext_adv) == bytes(ext_adv_cmd)

    # LE Read Transmit Power Return Parameters (7.8.74): min/max_tx_power are int8.
    tx_power_rp = hci.HCI_LE_Read_Transmit_Power_ReturnParameters(
        status=hci.HCI_ErrorCode.SUCCESS,
        min_tx_power=-30,
        max_tx_power=10,
    )
    tx_power_evt = hci.HCI_Command_Complete_Event(
        num_hci_command_packets=1,
        command_opcode=hci.HCI_LE_READ_TRANSMIT_POWER_COMMAND,
        return_parameters=tx_power_rp,
    )
    parsed_tx_power_evt = hci.HCI_Event.from_bytes(bytes(tx_power_evt))
    assert isinstance(parsed_tx_power_evt, hci.HCI_Command_Complete_Event)
    parsed_tx_power_rp = parsed_tx_power_evt.return_parameters
    assert isinstance(
        parsed_tx_power_rp, hci.HCI_LE_Read_Transmit_Power_ReturnParameters
    )
    assert parsed_tx_power_rp.min_tx_power == -30
    assert parsed_tx_power_rp.max_tx_power == 10

    # LE CS Set Default Settings (7.8.133): max_tx_power is int8.
    cs_default_cmd = hci.HCI_LE_CS_Set_Default_Settings_Command(
        connection_handle=0x0040,
        role_enable=hci.CsRoleMask.INITIATOR,
        cs_sync_antenna_selection=0x01,
        max_tx_power=-15,
    )
    parsed_cs_default = hci.HCI_Command.from_bytes(bytes(cs_default_cmd))
    assert isinstance(parsed_cs_default, hci.HCI_LE_CS_Set_Default_Settings_Command)
    assert parsed_cs_default.max_tx_power == -15

    # LE CS Set Procedure Parameters (7.8.140): tx_power_delta is int8.
    cs_proc_cmd = hci.HCI_LE_CS_Set_Procedure_Parameters_Command(
        connection_handle=0x0040,
        config_id=0,
        max_procedure_len=10,
        min_procedure_interval=10,
        max_procedure_interval=20,
        max_procedure_count=1,
        min_subevent_len=1250,
        max_subevent_len=2500,
        tone_antenna_config_selection=0,
        phy=hci.Phy.LE_1M,
        tx_power_delta=-12,
        preferred_peer_antenna=1,
        snr_control_initiator=hci.CsSnr.NOT_APPLIED,
        snr_control_reflector=hci.CsSnr.NOT_APPLIED,
    )
    parsed_cs_proc = hci.HCI_Command.from_bytes(bytes(cs_proc_cmd))
    assert isinstance(parsed_cs_proc, hci.HCI_LE_CS_Set_Procedure_Parameters_Command)
    assert parsed_cs_proc.tx_power_delta == -12

    # LE CS Test (7.8.142): transmit_power_level is int8.
    cs_test_cmd = hci.HCI_LE_CS_Test_Command(
        main_mode_type=1,
        sub_mode_type=0,
        main_mode_repetition=0,
        mode_0_steps=1,
        role=hci.CsRole.INITIATOR,
        rtt_type=hci.RttType.AA_ONLY,
        cs_sync_phy=hci.CsSyncPhy.LE_1M,
        cs_sync_antenna_selection=1,
        subevent_len=1250,
        subevent_interval=10,
        max_num_subevents=1,
        transmit_power_level=-10,
        t_ip1_time=10,
        t_ip2_time=10,
        t_fcs_time=10,
        t_pm_time=10,
        t_sw_time=10,
        tone_antenna_config_selection=0,
        reserved=0,
        snr_control_initiator=hci.CsSnr.NOT_APPLIED,
        snr_control_reflector=hci.CsSnr.NOT_APPLIED,
        drbg_nonce=0,
        channel_map_repetition=1,
        override_config=0,
        override_parameters_data=b'',
    )
    parsed_cs_test = hci.HCI_Command.from_bytes(bytes(cs_test_cmd))
    assert isinstance(parsed_cs_test, hci.HCI_LE_CS_Test_Command)
    assert parsed_cs_test.transmit_power_level == -10

    # LE Extended Advertising Report (7.7.65.13): tx_power is int8.
    ext_adv_report = hci.HCI_LE_Extended_Advertising_Report_Event(
        reports=[
            hci.HCI_LE_Extended_Advertising_Report_Event.Report(
                event_type=0,
                address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
                address=hci.Address(
                    'C1:02:03:04:05:06', hci.Address.RANDOM_DEVICE_ADDRESS
                ),
                primary_phy=hci.Phy.LE_1M,
                secondary_phy=hci.Phy.LE_1M,
                advertising_sid=0,
                tx_power=-25,
                rssi=-60,
                periodic_advertising_interval=0,
                direct_address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
                direct_address=hci.Address.ANY,
                data=b'',
            )
        ]
    )
    parsed_ext_adv_report = hci.HCI_Event.from_bytes(bytes(ext_adv_report))
    assert isinstance(
        parsed_ext_adv_report, hci.HCI_LE_Extended_Advertising_Report_Event
    )
    assert parsed_ext_adv_report.reports[0].tx_power == -25
    assert parsed_ext_adv_report.reports[0].rssi == -60


# -----------------------------------------------------------------------------
def test_le_read_all_local_supported_features_command_and_random_address_commands():
    assert dataclasses.is_dataclass(
        hci.HCI_LE_Read_All_Local_Supported_Features_Command
    )
    cmd = hci.HCI_LE_Read_All_Local_Supported_Features_Command()
    parsed = hci.HCI_Command.from_bytes(bytes(cmd))
    assert parsed == cmd

    addr = hci.Address('C1:02:03:04:05:06', hci.Address.RANDOM_DEVICE_ADDRESS)
    adv_rand_cmd = hci.HCI_LE_Set_Advertising_Set_Random_Address_Command(
        advertising_handle=2,
        random_address=addr,
    )
    parsed_adv_rand = hci.HCI_Command.from_bytes(bytes(adv_rand_cmd))
    assert isinstance(
        parsed_adv_rand, hci.HCI_LE_Set_Advertising_Set_Random_Address_Command
    )
    assert parsed_adv_rand.random_address == addr
    assert (
        parsed_adv_rand.random_address.address_type == hci.Address.RANDOM_DEVICE_ADDRESS
    )


# -----------------------------------------------------------------------------
def test_new_le_commands_round_trip():
    pub_addr = hci.Address('01:02:03:04:05:06', hci.Address.PUBLIC_DEVICE_ADDRESS)
    rand_addr = hci.Address('C1:02:03:04:05:06', hci.Address.RANDOM_DEVICE_ADDRESS)

    commands = [
        hci.HCI_LE_Receiver_Test_Command(rx_channel=10),
        hci.HCI_LE_Transmitter_Test_Command(
            tx_channel=10, test_data_length=37, packet_payload=0
        ),
        hci.HCI_LE_Test_End_Command(),
        hci.HCI_LE_Generate_DHKey_Command(
            key_x_coordinate=bytes(range(32)),
            key_y_coordinate=bytes(range(32, 64)),
        ),
        hci.HCI_LE_Generate_DHKey_V2_Command(
            key_x_coordinate=bytes(range(32)),
            key_y_coordinate=bytes(range(32, 64)),
            key_type=0,
        ),
        hci.HCI_LE_Remove_Device_From_Resolving_List_Command(
            peer_identity_address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
            peer_identity_address=pub_addr,
        ),
        hci.HCI_LE_Read_Peer_Resolvable_Address_Command(
            peer_identity_address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
            peer_identity_address=pub_addr,
        ),
        hci.HCI_LE_Read_Local_Resolvable_Address_Command(
            peer_identity_address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
            peer_identity_address=rand_addr,
        ),
        hci.HCI_LE_Receiver_Test_V2_Command(
            rx_channel=5, phy=hci.Phy.LE_2M, modulation_index=0
        ),
        hci.HCI_LE_Transmitter_Test_V2_Command(
            tx_channel=5, test_data_length=20, packet_payload=1, phy=2
        ),
        hci.HCI_LE_Receiver_Test_V3_Command(
            rx_channel=5,
            phy=hci.Phy.LE_2M,
            modulation_index=0,
            expected_cte_length=10,
            expected_cte_type=0,
            slot_durations=1,
            antenna_ids=[0, 1, 2],
        ),
        hci.HCI_LE_Transmitter_Test_V3_Command(
            tx_channel=5,
            test_data_length=20,
            packet_payload=1,
            phy=2,
            cte_length=10,
            cte_type=1,
            antenna_ids=[0, 1],
        ),
        hci.HCI_LE_Transmitter_Test_V4_Command(
            tx_channel=5,
            test_data_length=20,
            packet_payload=1,
            phy=2,
            cte_length=10,
            cte_type=1,
            antenna_ids=[0, 1],
            tx_power_level=-15,
        ),
        hci.HCI_LE_Set_Extended_Advertising_Parameters_V2_Command(
            advertising_handle=1,
            advertising_event_properties=0,
            primary_advertising_interval_min=0x20,
            primary_advertising_interval_max=0x40,
            primary_advertising_channel_map=0x07,
            own_address_type=hci.OwnAddressType.RANDOM,
            peer_address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
            peer_address=pub_addr,
            advertising_filter_policy=0,
            advertising_tx_power=-10,
            primary_advertising_phy=hci.Phy.LE_1M,
            secondary_advertising_max_skip=0,
            secondary_advertising_phy=hci.Phy.LE_2M,
            advertising_sid=1,
            scan_request_notification_enable=0,
            primary_advertising_phy_options=0,
            secondary_advertising_phy_options=0,
        ),
        hci.HCI_LE_Set_Periodic_Advertising_Parameters_V2_Command(
            advertising_handle=1,
            periodic_advertising_interval_min=0x10,
            periodic_advertising_interval_max=0x20,
            periodic_advertising_properties=0,
            num_subevents=4,
            subevent_interval=0x10,
            response_slot_delay=0x05,
            response_slot_spacing=0x04,
            num_response_slots=2,
        ),
        hci.HCI_LE_Set_Periodic_Advertising_Subevent_Data_Command(
            advertising_handle=1,
            subevents=[
                hci.HCI_LE_Set_Periodic_Advertising_Subevent_Data_Command.SubeventData(
                    subevent=0,
                    response_slot_start=0,
                    response_slot_count=2,
                    subevent_data=b'\x01\x02\x03',
                )
            ],
        ),
        hci.HCI_LE_Set_Periodic_Advertising_Response_Data_Command(
            sync_handle=0x0010,
            request_event=100,
            request_subevent=0,
            response_subevent=0,
            response_slot=1,
            response_data=b'\xaa\xbb',
        ),
        hci.HCI_LE_Set_Periodic_Sync_Subevent_Command(
            sync_handle=0x0010,
            periodic_advertising_properties=0,
            subevents=[0, 1, 2],
        ),
        hci.HCI_LE_Read_RF_Path_Compensation_Command(),
        hci.HCI_LE_Write_RF_Path_Compensation_Command(
            rf_tx_path_compensation_value=-125,
            rf_rx_path_compensation_value=50,
        ),
        hci.HCI_LE_Set_Data_Related_Address_Changes_Command(
            advertising_handle=1, change_reasons=0x03
        ),
        hci.HCI_LE_Set_Connectionless_CTE_Transmit_Parameters_Command(
            advertising_handle=1,
            cte_length=10,
            cte_type=0,
            cte_count=1,
            antenna_ids=[0, 1],
        ),
        hci.HCI_LE_Set_Connectionless_CTE_Transmit_Enable_Command(
            advertising_handle=1, cte_enable=1
        ),
        hci.HCI_LE_Set_Connectionless_IQ_Sampling_Enable_Command(
            sync_handle=0x0010,
            sampling_enable=1,
            slot_durations=1,
            max_sampled_ctes=2,
            antenna_ids=[0, 1],
        ),
        hci.HCI_LE_Set_Connection_CTE_Receive_Parameters_Command(
            connection_handle=0x0040,
            sampling_enable=1,
            slot_durations=1,
            antenna_ids=[0, 1],
        ),
        hci.HCI_LE_Set_Connection_CTE_Transmit_Parameters_Command(
            connection_handle=0x0040, cte_types=0x03, antenna_ids=[0, 1]
        ),
        hci.HCI_LE_Connection_CTE_Request_Enable_Command(
            connection_handle=0x0040,
            enable=1,
            cte_request_interval=10,
            requested_cte_length=10,
            requested_cte_type=0,
        ),
        hci.HCI_LE_Connection_CTE_Response_Enable_Command(
            connection_handle=0x0040, enable=1
        ),
        hci.HCI_LE_Read_Antenna_Information_Command(),
        hci.HCI_LE_Modify_Sleep_Clock_Accuracy_Command(action=1),
        hci.HCI_LE_Set_CIG_Parameters_Test_Command(
            cig_id=1,
            sdu_interval_c_to_p=10000,
            sdu_interval_p_to_c=10000,
            ft_c_to_p=1,
            ft_p_to_c=1,
            iso_interval=8,
            worst_case_sca=0,
            packing=0,
            framing=0,
            cis_id=[1],
            nse=[2],
            max_sdu_c_to_p=[40],
            max_sdu_p_to_c=[40],
            max_pdu_c_to_p=[40],
            max_pdu_p_to_c=[40],
            phy_c_to_p=[2],
            phy_p_to_c=[2],
            bn_c_to_p=[1],
            bn_p_to_c=[1],
        ),
        hci.HCI_LE_Create_BIG_Test_Command(
            big_handle=1,
            advertising_handle=1,
            num_bis=2,
            sdu_interval=10000,
            iso_interval=8,
            nse=2,
            max_sdu=40,
            max_pdu=40,
            phy=2,
            packing=0,
            framing=0,
            bn=1,
            irc=1,
            pto=0,
            encryption=0,
            broadcast_code=bytes(16),
        ),
        hci.HCI_LE_Request_Peer_SCA_Command(connection_handle=0x0040),
        hci.HCI_LE_ISO_Transmit_Test_Command(connection_handle=0x0050, payload_type=0),
        hci.HCI_LE_ISO_Receive_Test_Command(connection_handle=0x0050, payload_type=0),
        hci.HCI_LE_ISO_Read_Test_Counters_Command(connection_handle=0x0050),
        hci.HCI_LE_ISO_Test_End_Command(connection_handle=0x0050),
        hci.HCI_LE_Read_ISO_Link_Quality_Command(connection_handle=0x0050),
        hci.HCI_LE_Enhanced_Read_Transmit_Power_Level_Command(
            connection_handle=0x0040, phy=1
        ),
        hci.HCI_LE_Read_Remote_Transmit_Power_Level_Command(
            connection_handle=0x0040, phy=1
        ),
        hci.HCI_LE_Set_Path_Loss_Reporting_Parameters_Command(
            connection_handle=0x0040,
            high_threshold=80,
            high_hysteresis=5,
            low_threshold=40,
            low_hysteresis=5,
            min_time_spent=10,
        ),
        hci.HCI_LE_Set_Path_Loss_Reporting_Enable_Command(
            connection_handle=0x0040, enable=1
        ),
        hci.HCI_LE_Set_Transmit_Power_Reporting_Enable_Command(
            connection_handle=0x0040, local_enable=1, remote_enable=1
        ),
        hci.HCI_LE_CS_Write_Cached_Remote_Supported_Capabilities_V2_Command(
            connection_handle=0x0040,
            num_config_supported=1,
            max_consecutive_procedures_supported=1,
            num_antennas_supported=1,
            max_antenna_paths_supported=1,
            roles_supported=1,
            modes_supported=1,
            rtt_capability=0,
            rtt_aa_only_n=1,
            rtt_sounding_n=1,
            rtt_random_sequence_n=1,
            nadm_sounding_capability=0,
            nadm_random_capability=0,
            cs_sync_phys_supported=1,
            subfeatures_supported=0,
            t_ip1_times_supported=0,
            t_ip2_times_supported=0,
            t_fcs_times_supported=0,
            t_pm_times_supported=0,
            t_sw_time_supported=0,
            tx_snr_capability=0,
            t_ip2_ipt_times_supported=0,
            t_sw_ipt_times_supported=0,
            rtt_2m_aa_only_n=1,
            rtt_2m_sounding_n=1,
            rtt_2m_random_sequence_n=1,
        ),
    ]

    for cmd in commands:
        raw = bytes(cmd)
        parsed = hci.HCI_Command.from_bytes(raw)
        assert type(parsed) is type(cmd)
        assert parsed == cmd
        assert bytes(parsed) == raw

    # Non-dataclass LE Extended Create Connection [v2]
    ext_conn_v2 = hci.HCI_LE_Extended_Create_Connection_V2_Command(
        advertising_handle=1,
        subevent=2,
        initiator_filter_policy=0,
        own_address_type=hci.OwnAddressType.RANDOM,
        peer_address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
        peer_address=rand_addr,
        initiating_phys=0b001,
        scan_intervals=[0x60],
        scan_windows=[0x30],
        connection_interval_mins=[0x18],
        connection_interval_maxs=[0x28],
        max_latencies=[0],
        supervision_timeouts=[0x0190],
        min_ce_lengths=[0],
        max_ce_lengths=[0],
    )
    parsed_v2 = hci.HCI_Command.from_bytes(bytes(ext_conn_v2))
    assert isinstance(parsed_v2, hci.HCI_LE_Extended_Create_Connection_V2_Command)
    assert parsed_v2.advertising_handle == 1
    assert parsed_v2.subevent == 2
    assert parsed_v2.peer_address == rand_addr
    assert bytes(parsed_v2) == bytes(ext_conn_v2)


# -----------------------------------------------------------------------------
def test_new_le_return_parameters_round_trip():
    rpa = hci.Address('41:02:03:04:05:06', hci.Address.RANDOM_DEVICE_ADDRESS)
    cases = [
        (
            hci.HCI_LE_TEST_END_COMMAND,
            hci.HCI_LE_Test_End_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS, number_of_packets=42
            ),
        ),
        (
            hci.HCI_LE_READ_PEER_RESOLVABLE_ADDRESS_COMMAND,
            hci.HCI_LE_Read_Peer_Resolvable_Address_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS, peer_resolvable_address=rpa
            ),
        ),
        (
            hci.HCI_LE_READ_LOCAL_RESOLVABLE_ADDRESS_COMMAND,
            hci.HCI_LE_Read_Local_Resolvable_Address_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS, local_resolvable_address=rpa
            ),
        ),
        (
            hci.HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2_COMMAND,
            hci.HCI_LE_Set_Periodic_Advertising_Parameters_V2_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS, advertising_handle=1
            ),
        ),
        (
            hci.HCI_LE_SET_PERIODIC_ADVERTISING_SUBEVENT_DATA_COMMAND,
            hci.HCI_LE_Set_Periodic_Advertising_Subevent_Data_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS, advertising_handle=1
            ),
        ),
        (
            hci.HCI_LE_SET_PERIODIC_ADVERTISING_RESPONSE_DATA_COMMAND,
            hci.HCI_LE_Set_Periodic_Advertising_Response_Data_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS, sync_handle=0x0010
            ),
        ),
        (
            hci.HCI_LE_SET_PERIODIC_SYNC_SUBEVENT_COMMAND,
            hci.HCI_LE_Set_Periodic_Sync_Subevent_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS, sync_handle=0x0010
            ),
        ),
        (
            hci.HCI_LE_READ_RF_PATH_COMPENSATION_COMMAND,
            hci.HCI_LE_Read_RF_Path_Compensation_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS,
                rf_tx_path_compensation_value=-120,
                rf_rx_path_compensation_value=45,
            ),
        ),
        (
            hci.HCI_LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE_COMMAND,
            hci.HCI_LE_Set_Connectionless_IQ_Sampling_Enable_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS, sync_handle=0x0010
            ),
        ),
        (
            hci.HCI_LE_READ_ANTENNA_INFORMATION_COMMAND,
            hci.HCI_LE_Read_Antenna_Information_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS,
                supported_switching_sampling_rates=0x07,
                num_antennae=4,
                max_switching_pattern_length=16,
                max_cte_length=20,
            ),
        ),
        (
            hci.HCI_LE_ISO_READ_TEST_COUNTERS_COMMAND,
            hci.HCI_LE_ISO_Read_Test_Counters_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS,
                connection_handle=0x0050,
                received_sdu_count=100,
                missed_sdu_count=2,
                failed_sdu_count=1,
            ),
        ),
        (
            hci.HCI_LE_ISO_TEST_END_COMMAND,
            hci.HCI_LE_ISO_Test_End_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS,
                connection_handle=0x0050,
                received_sdu_count=100,
                missed_sdu_count=2,
                failed_sdu_count=1,
            ),
        ),
        (
            hci.HCI_LE_READ_ISO_LINK_QUALITY_COMMAND,
            hci.HCI_LE_Read_ISO_Link_Quality_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS,
                connection_handle=0x0050,
                tx_unacked_packets=1,
                tx_flushed_packets=2,
                tx_last_subevent_packets=3,
                retransmitted_packets=4,
                crc_error_packets=5,
                rx_unreceived_packets=6,
                duplicate_packets=7,
            ),
        ),
        (
            hci.HCI_LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL_COMMAND,
            hci.HCI_LE_Enhanced_Read_Transmit_Power_Level_ReturnParameters(
                status=hci.HCI_ErrorCode.SUCCESS,
                connection_handle=0x0040,
                phy=1,
                current_tx_power_level=-12,
                max_tx_power_level=10,
            ),
        ),
    ]

    for op_code, rp in cases:
        evt = hci.HCI_Command_Complete_Event(
            num_hci_command_packets=1,
            command_opcode=op_code,
            return_parameters=rp,
        )
        parsed = hci.HCI_Event.from_bytes(bytes(evt))
        assert isinstance(parsed, hci.HCI_Command_Complete_Event)
        assert parsed.return_parameters == rp


# -----------------------------------------------------------------------------
def test_new_le_meta_events_round_trip():
    pub_addr = hci.Address('01:02:03:04:05:06', hci.Address.PUBLIC_DEVICE_ADDRESS)
    rand_addr = hci.Address('C1:02:03:04:05:06', hci.Address.RANDOM_DEVICE_ADDRESS)

    events = [
        hci.HCI_LE_Read_Local_P_256_Public_Key_Complete_Event(
            status=hci.HCI_ErrorCode.SUCCESS,
            key_x_coordinate=bytes(range(32)),
            key_y_coordinate=bytes(range(32, 64)),
        ),
        hci.HCI_LE_Generate_DHKey_Complete_Event(
            status=hci.HCI_ErrorCode.SUCCESS,
            dhkey=bytes(range(32)),
        ),
        hci.HCI_LE_Directed_Advertising_Report_Event(
            reports=[
                hci.HCI_LE_Directed_Advertising_Report_Event.Report(
                    event_type=0x01,
                    address_type=hci.Address.RANDOM_DEVICE_ADDRESS,
                    address=rand_addr,
                    direct_address_type=hci.Address.PUBLIC_DEVICE_ADDRESS,
                    direct_address=pub_addr,
                    rssi=-55,
                )
            ]
        ),
        hci.HCI_LE_Periodic_Advertising_Subevent_Data_Request_Event(
            advertising_handle=1, subevent_start=0, subevent_data_count=4
        ),
        hci.HCI_LE_Periodic_Advertising_Response_Report_Event(
            advertising_handle=1,
            subevent=0,
            tx_status=0,
            responses=[
                hci.HCI_LE_Periodic_Advertising_Response_Report_Event.Response(
                    tx_power=-5,
                    rssi=-60,
                    cte_type=0xFF,
                    response_slot=0,
                    data_status=0,
                    data=b'\x01\x02',
                )
            ],
        ),
        hci.HCI_LE_Connectionless_IQ_Report_Event(
            sync_handle=0x0010,
            channel_index=10,
            rssi=-650,
            rssi_antenna_id=0,
            cte_type=0,
            slot_durations=1,
            packet_status=0,
            periodic_event_counter=5,
            i_sample=[-10, 20],
            q_sample=[15, -25],
        ),
        hci.HCI_LE_Connection_IQ_Report_Event(
            connection_handle=0x0040,
            rx_phy=hci.Phy.LE_2M,
            data_channel_index=12,
            rssi=-500,
            rssi_antenna_id=1,
            cte_type=1,
            slot_durations=2,
            packet_status=0,
            connection_event_counter=7,
            i_sample=[-1, 2],
            q_sample=[3, -4],
        ),
        hci.HCI_LE_CTE_Request_Failed_Event(
            status=hci.HCI_ErrorCode.SUCCESS, connection_handle=0x0040
        ),
        hci.HCI_LE_Request_Peer_SCA_Complete_Event(
            status=hci.HCI_ErrorCode.SUCCESS,
            connection_handle=0x0040,
            peer_clock_accuracy=2,
        ),
        hci.HCI_LE_Path_Loss_Threshold_Event(
            connection_handle=0x0040, current_path_loss=65, zone_entered=1
        ),
        hci.HCI_LE_Transmit_Power_Reporting_Event(
            status=hci.HCI_ErrorCode.SUCCESS,
            connection_handle=0x0040,
            reason=0,
            phy=1,
            tx_power_level=-10,
            tx_power_level_flag=0,
            delta=-2,
        ),
        hci.HCI_LE_Frame_Space_Update_Complete_Event(
            status=hci.HCI_ErrorCode.SUCCESS,
            connection_handle=0x0040,
            initiator=0,
            frame_space=150,
            phys=0x03,
            spacing_types=0x0001,
        ),
    ]

    for evt in events:
        raw = bytes(evt)
        parsed = hci.HCI_Event.from_bytes(raw)
        assert type(parsed) is type(evt)
        assert parsed == evt
        assert bytes(parsed) == raw


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
    test_HCI_Vendor_Event()


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
    test_HCI_LE_Setup_ISO_Data_Path_Command()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    run_test_events()
    run_test_commands()
    test_return_parameters()
    test_address()
    test_custom()
    test_iso_data_packet()
