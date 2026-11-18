# Copyright 2021-2026 Google LLC
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
# Tests for Bluetooth Core 7.0 LE High Data Throughput (HDT).
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import asyncio
from unittest import mock

import pytest

from bumble import hci
from bumble.core import ConnectionPHY
from bumble.device import Connection
from bumble.keys import MemoryKeyStore, PairingKeys
from bumble.testing.test_utils import TwoDevices, async_barrier

_TIMEOUT = 1.0


# -----------------------------------------------------------------------------
def check_round_trip(packet: hci.HCI_Packet, expected_hex: str | None = None) -> None:
    packet_bytes = bytes(packet)
    if expected_hex is not None:
        assert packet_bytes.hex() == expected_hex
    parsed = hci.HCI_Packet.from_bytes(packet_bytes)
    assert type(parsed) is type(packet)
    assert bytes(parsed) == packet_bytes


# -----------------------------------------------------------------------------
def test_specification_version() -> None:
    assert hci.SpecificationVersion.BLUETOOTH_CORE_6_3 == 0x11
    assert hci.SpecificationVersion.BLUETOOTH_CORE_7_0 == 0x12


# -----------------------------------------------------------------------------
def test_phy() -> None:
    assert hci.Phy.LE_HDT == 0x05
    assert hci.PhyBit.LE_HDT == 0x10
    assert hci.phy_list_to_bits([hci.Phy.LE_1M, hci.Phy.LE_HDT]) == 0x11
    assert hci.HCI_Constant.le_phy_name(hci.Phy.LE_HDT) == 'LE HDT'


# -----------------------------------------------------------------------------
def test_le_features() -> None:
    assert hci.LeFeature.ENCRYPTION_KEY_SCHEDULE == 76
    assert hci.LeFeature.HIGH_DATA_THROUGHPUT == 77
    assert hci.LeFeature.RECEIVE_HDT6_RATE == 78
    assert hci.LeFeature.TRANSMIT_HDT6_RATE == 79
    assert hci.LeFeature.RECEIVE_HDT7_5_RATE == 80
    assert hci.LeFeature.TRANSMIT_HDT7_5_RATE == 81
    assert hci.LeFeature.HDT_PACKET_FORMAT_1 == 82
    assert hci.LeFeature.LINK_QUALITY_FEEDBACK == 83
    assert hci.LeFeature.ISOCHRONOUS_BROADCASTER_ON_LE_HDT_PHY == 84
    assert hci.LeFeature.SYNCHRONIZED_RECEIVER_ON_LE_HDT_PHY == 85
    assert hci.LeFeature.OPPORTUNISTIC_ENCRYPTION_HOST_SUPPORT == 90
    assert hci.LeFeatureMask.HIGH_DATA_THROUGHPUT == 1 << 77


# -----------------------------------------------------------------------------
def test_phy_options() -> None:
    options = hci.PhyOptions.from_hdt_preferences(
        rates=hci.HdtRate.HDT6 | hci.HdtRate.HDT7_5,
        mic_length=hci.HdtMicLength.MIC_64_BITS,
        packet_format=hci.HdtPacketFormat.FORMAT_1,
    )
    assert int(options) == (0b11000 << 2) | (1 << 7) | (2 << 8)
    assert options.hdt_rates == hci.HdtRate.HDT6 | hci.HdtRate.HDT7_5
    assert options.hdt_mic_length == hci.HdtMicLength.MIC_64_BITS
    assert options.hdt_packet_format == hci.HdtPacketFormat.FORMAT_1

    # Defaults of HCI_LE_Set_HDT_Default_Parameters
    options = hci.PhyOptions.from_hdt_preferences(rates=hci.HdtRate.ALL)
    assert int(options) == 0x1F << 2
    assert options.hdt_mic_length == hci.HdtMicLength.MIC_128_BITS
    assert options.hdt_packet_format == hci.HdtPacketFormat.ANY


# -----------------------------------------------------------------------------
def test_supported_commands_masks() -> None:
    masks = hci.HCI_SUPPORTED_COMMANDS_MASKS
    assert masks[hci.HCI_LE_SET_HDT_DEFAULT_PARAMETERS_COMMAND] == 1 << (52 * 8 + 1)
    assert masks[hci.HCI_LE_SET_HDT_PARAMETERS_TEST_COMMAND] == 1 << (52 * 8 + 2)
    assert masks[hci.HCI_LE_SET_DATA_LENGTH_V2_COMMAND] == 1 << (52 * 8 + 3)
    assert masks[hci.HCI_LE_ENABLE_ENCRYPTION_V2_COMMAND] == 1 << (50 * 8 + 4)
    assert masks[hci.HCI_LE_SET_CIG_PARAMETERS_V2_COMMAND] == 1 << (51 * 8 + 0)
    assert masks[hci.HCI_LE_REMOVE_CIG_CONFIGURATION_COMMAND] == 1 << (53 * 8 + 3)


# -----------------------------------------------------------------------------
def test_le_event_mask_v2() -> None:
    mask = int.from_bytes(
        hci.HCI_LE_Set_Event_Mask_V2_Command.mask(
            [
                hci.HCI_LE_CONNECTION_COMPLETE_EVENT,
                hci.HCI_LE_CREATE_BIG_COMPLETE_V2_EVENT,
                hci.HCI_LE_TEST_REPORT_HDT_LINK_QUALITY_EVENT,
                hci.HCI_LE_UPDATE_CIG_PERIPHERAL_REQUEST_EVENT,
            ]
        ),
        'little',
    )
    assert mask == (1 << 0) | (1 << 58) | (1 << 64) | (1 << 66)

    page_2_mask = int.from_bytes(
        hci.HCI_Set_Event_Mask_Page_2_Command.mask(
            [
                hci.HCI_ENCRYPTION_CHANGE_V3_EVENT,
                hci.HCI_ENCRYPTION_KEY_REFRESH_COMPLETE_V2_EVENT,
            ]
        ),
        'little',
    )
    assert page_2_mask == (1 << 26) | (1 << 27)


# -----------------------------------------------------------------------------
def test_commands() -> None:
    check_round_trip(
        hci.HCI_LE_Set_HDT_Default_Parameters_Command(
            preferred_mic_length=hci.HdtMicLength.MIC_128_BITS,
            preferred_packet_format=hci.HdtPacketFormat.ANY,
            preferred_acl_rates=hci.HdtRate.ALL,
        ),
        '01bc200402001f00',
    )
    check_round_trip(
        hci.HCI_LE_Set_HDT_Parameters_Test_Command(
            connection_handle=0x0040,
            mic_length=hci.HdtMicLength.MIC_64_BITS,
            packet_format=hci.HdtPacketFormat.FORMAT_1,
            blocks_per_payload=4,
            tx_rate=hci.HdtRate.HDT6,
        ),
        '01bd20074000010204' '0800',
    )
    check_round_trip(
        hci.HCI_Refresh_Encryption_Key_V2_Command(
            connection_handle=0x0040, hdt_mic_length=hci.HdtMicLength.MIC_64_BITS
        ),
        '01540c03400001',
    )
    check_round_trip(
        hci.HCI_LE_Enable_Encryption_V2_Command(
            connection_handle=0x0040,
            random_number=bytes(8),
            encrypted_diversifier=0,
            long_term_key=bytes(range(16)),
            hdt_mic_length=hci.HdtMicLength.MIC_128_BITS,
            encryption_type=hci.EncryptionType.LONG_TERM_KEY,
        ),
        '01af201e4000' + '00' * 10 + bytes(range(16)).hex() + '0200',
    )
    check_round_trip(
        hci.HCI_LE_Read_All_Remote_Features_Command(
            connection_handle=0x0040, pages_requested=10
        ),
        '018820034000' '0a',
    )
    check_round_trip(
        hci.HCI_LE_Set_Data_Length_V2_Command(
            connection_handle=0x0040,
            tx_octets=0x1FEF,
            tx_time=0x4290,
            phys=hci.DataLengthPhys.LE_HDT,
        ),
        '01aa20074000ef1f904201',
    )
    check_round_trip(
        hci.HCI_LE_Read_Suggested_Default_Data_Length_V2_Command(
            phys=hci.DataLengthPhys.LE_HDT
        ),
        '01b1200101',
    )
    check_round_trip(
        hci.HCI_LE_Write_Suggested_Default_Data_Length_V2_Command(
            suggested_max_tx_octets=0x00FB,
            suggested_max_tx_time=0x0848,
            phys=hci.DataLengthPhys.GFSK,
        ),
        '01b22005fb00480800',
    )
    check_round_trip(
        hci.HCI_LE_Read_Maximum_Data_Length_V2_Command(phy=hci.Phy.LE_HDT),
        '01b0200105',
    )
    check_round_trip(
        hci.HCI_LE_Set_CIG_Parameters_V2_Command(
            cig_id=1,
            sdu_interval_c_to_p=10000,
            sdu_interval_p_to_c=10000,
            worst_case_sca=0,
            packing=0,
            framing=0,
            max_transport_latency_c_to_p=10,
            max_transport_latency_p_to_c=10,
            cis_id=[2],
            max_sdu_c_to_p=[100],
            max_sdu_p_to_c=[100],
            phy_c_to_p=[hci.PhyBit.LE_HDT],
            phy_p_to_c=[hci.PhyBit.LE_HDT],
            rtn_c_to_p=[2],
            rtn_p_to_c=[2],
            coded_rates_c_to_p=[hci.CodedRate.S8 | hci.CodedRate.S2],
            coded_rates_p_to_c=[hci.CodedRate.S8 | hci.CodedRate.S2],
            hdt_rates_c_to_p=[hci.HdtRate.ALL],
            hdt_rates_p_to_c=[hci.HdtRate.ALL],
            hdt_mic_length=[hci.HdtMicLength.MIC_128_BITS],
            hdt_packet_format=[hci.HdtPacketFormat.ANY],
        ),
        '01b32020'
        '011027001027000000000a000a00'
        '01'
        '02640064001010020203031f001f000200',
    )
    check_round_trip(
        hci.HCI_LE_Create_CIS_V2_Command(
            config_id=1, cis_connection_handle=[0x0041], acl_connection_handle=[0x0040]
        ),
        '01b5200601014100' '4000',
    )
    check_round_trip(
        hci.HCI_LE_Create_BIG_V2_Command(
            big_handle=0,
            advertising_handle=1,
            num_bis=2,
            sdu_interval=10000,
            max_sdu=100,
            max_transport_latency=10,
            rtn=2,
            phy=hci.PhyBit.LE_HDT,
            packing=0,
            framing=0,
            encryption=0,
            broadcast_code=bytes(16),
            coded_rates=3,
            hdt_rates=hci.HdtRate.ALL,
            hdt_mic_length=hci.HdtMicLength.MIC_128_BITS,
            hdt_packet_format=hci.HdtPacketFormat.ANY,
        ),
        '01b62024' '0001021027006400' '0a000210000000' + '00' * 16 + '031f000200',
    )
    check_round_trip(
        hci.HCI_LE_Set_Event_Mask_V2_Command(
            le_event_mask=hci.HCI_LE_Set_Event_Mask_V2_Command.mask(
                [hci.HCI_LE_TEST_REPORT_HDT_LINK_QUALITY_EVENT]
            )
        ),
        '01a420ff' + '00' * 8 + '01' + '00' * 246,
    )


# -----------------------------------------------------------------------------
def test_events() -> None:
    check_round_trip(
        hci.HCI_LE_Data_Length_Change_V2_Event(
            connection_handle=0x0040,
            max_tx_octets=0x1FEF,
            max_tx_time=0x4290,
            max_rx_octets=0x1FEF,
            max_rx_time=0x4290,
            phys=hci.DataLengthPhys.LE_HDT,
        ),
        '043e0c394000ef1f9042ef1f904201',
    )
    check_round_trip(
        hci.HCI_LE_CIS_Established_V3_Event(
            status=hci.HCI_SUCCESS,
            connection_handle=0x0041,
            cig_sync_delay=1,
            cis_sync_delay=2,
            transport_latency_c_to_p=3,
            transport_latency_p_to_c=4,
            phy_c_to_p=hci.Phy.LE_HDT,
            phy_p_to_c=hci.Phy.LE_HDT,
            nse=1,
            bn_c_to_p=1,
            bn_p_to_c=1,
            ft_c_to_p=1,
            ft_p_to_c=1,
            max_pdu_c_to_p=100,
            max_pdu_p_to_c=100,
            iso_interval=8,
            sub_interval=5,
            max_sdu_c_to_p=100,
            max_sdu_p_to_c=100,
            sdu_interval_c_to_p=10000,
            sdu_interval_p_to_c=10000,
            framing=0,
            rates_c_to_p=hci.HdtRate.HDT4,
            rates_p_to_c=hci.HdtRate.HDT4,
            config_id=0,
            tl_group_id=0,
            encryption_enabled=1,
            mic_length=hci.HdtMicLength.MIC_64_BITS,
        ),
    )
    check_round_trip(
        hci.HCI_LE_CIS_Established_V2_Event(
            status=hci.HCI_SUCCESS,
            connection_handle=0x0041,
            cig_sync_delay=1,
            cis_sync_delay=2,
            transport_latency_c_to_p=3,
            transport_latency_p_to_c=4,
            phy_c_to_p=hci.Phy.LE_2M,
            phy_p_to_c=hci.Phy.LE_2M,
            nse=1,
            bn_c_to_p=1,
            bn_p_to_c=1,
            ft_c_to_p=1,
            ft_p_to_c=1,
            max_pdu_c_to_p=100,
            max_pdu_p_to_c=100,
            iso_interval=8,
            sub_interval=5,
            max_sdu_c_to_p=100,
            max_sdu_p_to_c=100,
            sdu_interval_c_to_p=10000,
            sdu_interval_p_to_c=10000,
            framing=0,
        ),
    )
    event_bytes = bytes(
        hci.HCI_LE_CIS_Established_V3_Event(
            status=0,
            connection_handle=0,
            cig_sync_delay=0,
            cis_sync_delay=0,
            transport_latency_c_to_p=0,
            transport_latency_p_to_c=0,
            phy_c_to_p=0,
            phy_p_to_c=0,
            nse=0,
            bn_c_to_p=0,
            bn_p_to_c=0,
            ft_c_to_p=0,
            ft_p_to_c=0,
            max_pdu_c_to_p=0,
            max_pdu_p_to_c=0,
            iso_interval=0,
            sub_interval=0,
            max_sdu_c_to_p=0,
            max_sdu_p_to_c=0,
            sdu_interval_c_to_p=0,
            sdu_interval_p_to_c=0,
            framing=0,
            rates_c_to_p=0,
            rates_p_to_c=0,
            config_id=0,
            tl_group_id=0,
            encryption_enabled=0,
            mic_length=0,
        )
    )
    # Event code, parameter length, subevent code
    assert event_bytes[1:4] == bytes([0x3E, 0x33, 0x3A])

    check_round_trip(
        hci.HCI_LE_Create_BIG_Complete_V2_Event(
            status=hci.HCI_SUCCESS,
            big_handle=0,
            big_sync_delay=1,
            transport_latency_big=2,
            phy=hci.Phy.LE_HDT,
            nse=1,
            bn=1,
            pto=0,
            irc=1,
            max_pdu=100,
            iso_interval=8,
            rates=hci.HdtRate.HDT2,
            encryption_enabled=0,
            mic_length=hci.HdtMicLength.MIC_128_BITS,
            connection_handle=[0x0100, 0x0101],
        ),
        '043e1b3b000001000002000005010100016400080001000002020001' '0101',
    )
    check_round_trip(
        hci.HCI_LE_Read_All_Remote_Features_Complete_Event(
            status=hci.HCI_SUCCESS,
            connection_handle=0x0040,
            max_remote_page=1,
            max_valid_page=1,
            le_features=bytes(248),
        ),
        '043efe2b00400001' '01' + '00' * 248,
    )
    check_round_trip(
        hci.HCI_LE_Test_Report_HDT_Link_Quality_Event(
            channel_index=3,
            report_status=hci.HCI_LE_Test_Report_HDT_Link_Quality_Event.ReportStatus.FINAL_REPORT,
            rssi=[
                -50,
                hci.HCI_LE_Test_Report_HDT_Link_Quality_Event.RSSI_NOT_AVAILABLE,
            ],
            snr=[20, hci.HCI_LE_Test_Report_HDT_Link_Quality_Event.SNR_NOT_AVAILABLE],
        ),
        '043e083c030002ce147f1f',
    )
    check_round_trip(
        hci.HCI_Encryption_Change_V3_Event(
            status=hci.HCI_SUCCESS,
            connection_handle=0x0040,
            encryption_enabled=1,
            encryption_key_size=16,
            mic_length=hci.HdtMicLength.MIC_64_BITS,
            key_schedule_enabled=hci.KeyScheduleEnabled.NOT_USED,
            key_schedule_debug_flag=0,
        ),
        '045a0800400001100100' '00',
    )
    check_round_trip(
        hci.HCI_Encryption_Key_Refresh_Complete_V2_Event(
            status=hci.HCI_SUCCESS,
            connection_handle=0x0040,
            mic_length=hci.HdtMicLength.MIC_128_BITS,
            key_schedule_enabled=hci.KeyScheduleEnabled.NOT_USED,
            key_schedule_debug_flag=0,
        ),
        '045b0600400002' '0000',
    )


# -----------------------------------------------------------------------------
def test_read_maximum_data_length_v2_return_parameters() -> None:
    event = hci.HCI_Command_Complete_Event(
        num_hci_command_packets=1,
        command_opcode=hci.HCI_LE_READ_MAXIMUM_DATA_LENGTH_V2_COMMAND,
        return_parameters=hci.HCI_LE_Read_Maximum_Data_Length_V2_ReturnParameters(
            status=hci.HCI_ErrorCode.SUCCESS,
            supported_max_tx_octets=0x1FEF,
            supported_max_tx_time=0x4290,
            supported_max_rx_octets=0x1FEF,
            supported_max_rx_time=0x4290,
            supported_max_tx_payload_window_size=2,
            supported_max_rx_payload_window_size=3,
            supported_max_rx_octets_per_packet=0x1FEF,
        ),
    )
    parsed = hci.HCI_Packet.from_bytes(bytes(event))
    assert isinstance(parsed, hci.HCI_Command_Complete_Event)
    assert parsed.return_parameters == event.return_parameters


# -----------------------------------------------------------------------------
def _set_no_phy_preference(devices: TwoDevices) -> None:
    # Equivalent to the hosts issuing HCI_LE_Set_Default_PHY with All_PHYs = 0x03,
    # before connecting.
    for controller in devices.controllers:
        controller.default_phy['all_phys'] = 0x03


# -----------------------------------------------------------------------------
async def _wait_for_phy_update(connection: Connection) -> asyncio.Future:
    future = asyncio.get_running_loop().create_future()
    connection.once(connection.EVENT_CONNECTION_PHY_UPDATE, future.set_result)
    return future


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_host_unmasks_hdt_events() -> None:
    devices = TwoDevices()
    await devices.setup_connection()
    controller = devices.controllers[0]

    for subevent_code in (
        hci.HCI_LE_DATA_LENGTH_CHANGE_V2_EVENT,
        hci.HCI_LE_CIS_ESTABLISHED_V3_EVENT,
        hci.HCI_LE_CREATE_BIG_COMPLETE_V2_EVENT,
        hci.HCI_LE_TEST_REPORT_HDT_LINK_QUALITY_EVENT,
    ):
        assert controller.is_le_event_unmasked(subevent_code)
    assert controller.is_event_page_2_unmasked(hci.HCI_ENCRYPTION_CHANGE_V3_EVENT)
    assert controller.is_event_page_2_unmasked(
        hci.HCI_ENCRYPTION_KEY_REFRESH_COMPLETE_V2_EVENT
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_read_all_local_and_remote_features() -> None:
    devices = TwoDevices()
    await devices.setup_connection()

    assert devices[0].supports_le_phy(hci.Phy.LE_HDT)
    assert devices[0].host.local_le_features == devices.controllers[0].le_features

    response = await devices[0].send_sync_command(
        hci.HCI_LE_Read_All_Local_Supported_Features_Command()
    )
    assert response.max_page == 1

    # Read all the pages
    assert (
        await devices.connections[0].get_remote_le_features()
    ) == devices.controllers[1].le_features
    assert devices.connections[0].peer_le_features & (
        hci.LeFeatureMask.HIGH_DATA_THROUGHPUT
    )

    # Only read page 0
    events = []
    devices[0].host.on(
        'le_remote_features', lambda handle, features: events.append(features)
    )
    await devices[0].send_async_command(
        hci.HCI_LE_Read_All_Remote_Features_Command(
            connection_handle=devices.connections[0].handle, pages_requested=0
        )
    )
    await async_barrier()
    assert events == [
        hci.LeFeatureMask(devices.controllers[1].le_features.value & 0xFFFFFFFFFFFFFFFF)
    ]


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_default_hdt_parameters() -> None:
    devices = TwoDevices()
    await devices.setup_connection()
    controller = devices.controllers[0]

    await devices[0].set_default_hdt_parameters(
        mic_length=hci.HdtMicLength.MIC_64_BITS,
        packet_format=hci.HdtPacketFormat.FORMAT_1,
        acl_rates=hci.HdtRate.HDT2 | hci.HdtRate.HDT3,
    )
    assert controller.hdt_preferred_mic_length == hci.HdtMicLength.MIC_64_BITS
    assert controller.hdt_preferred_packet_format == hci.HdtPacketFormat.FORMAT_1
    assert controller.hdt_preferred_acl_rates == hci.HdtRate.HDT2 | hci.HdtRate.HDT3

    # Reserved values
    with pytest.raises(hci.HCI_Error) as error:
        await devices[0].set_default_hdt_parameters(
            mic_length=hci.HdtMicLength.MIC_32_BITS
        )
    assert error.value.error_code == hci.HCI_ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR

    # Controller without HDT
    controller.le_features &= ~hci.LeFeatureMask.HIGH_DATA_THROUGHPUT
    with pytest.raises(hci.HCI_Error) as error:
        await devices[0].set_default_hdt_parameters()
    assert error.value.error_code == hci.HCI_ErrorCode.UNKNOWN_HCI_COMMAND_ERROR


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_hdt_parameters_test() -> None:
    devices = TwoDevices()
    await devices.setup_connection()
    connection = devices.connections[0]

    response = await devices[0].send_sync_command(
        hci.HCI_LE_Set_HDT_Parameters_Test_Command(
            connection_handle=connection.handle,
            mic_length=hci.HdtMicLength.MIC_64_BITS,
            packet_format=hci.HdtPacketFormat.FORMAT_1,
            blocks_per_payload=4,
            tx_rate=hci.HdtRate.HDT6,
        )
    )
    assert response.connection_handle == connection.handle

    # Only one bit shall be set in TX_Rate.
    event = await devices[0].send_sync_command_raw(
        hci.HCI_LE_Set_HDT_Parameters_Test_Command(
            connection_handle=connection.handle,
            mic_length=hci.HdtMicLength.MIC_64_BITS,
            packet_format=hci.HdtPacketFormat.FORMAT_1,
            blocks_per_payload=4,
            tx_rate=hci.HdtRate.HDT6 | hci.HdtRate.HDT2,
        )
    )
    assert (
        event.return_parameters.status
        == hci.HCI_ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_phy_hdt() -> None:
    devices = TwoDevices()
    _set_no_phy_preference(devices)
    await devices.setup_connection()
    central, peripheral = devices.connections[0], devices.connections[1]

    central_update = await _wait_for_phy_update(central)
    peripheral_update = await _wait_for_phy_update(peripheral)
    await central.set_phy(tx_phys=[hci.Phy.LE_HDT], rx_phys=[hci.Phy.LE_HDT])
    hdt = ConnectionPHY(hci.Phy.LE_HDT, hci.Phy.LE_HDT)
    assert await asyncio.wait_for(central_update, _TIMEOUT) == hdt
    assert await asyncio.wait_for(peripheral_update, _TIMEOUT) == hdt
    assert await central.get_phy() == hdt
    assert await peripheral.get_phy() == hdt


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_phy_hdt_asymmetric() -> None:
    devices = TwoDevices()
    _set_no_phy_preference(devices)
    await devices.setup_connection()
    central, peripheral = devices.connections[0], devices.connections[1]

    # Asymmetric PHYs, initiated by the peripheral.
    central_update = await _wait_for_phy_update(central)
    peripheral_update = await _wait_for_phy_update(peripheral)
    await peripheral.set_phy(tx_phys=[hci.Phy.LE_2M], rx_phys=[hci.Phy.LE_HDT])
    assert await asyncio.wait_for(peripheral_update, _TIMEOUT) == ConnectionPHY(
        hci.Phy.LE_2M, hci.Phy.LE_HDT
    )
    assert await asyncio.wait_for(central_update, _TIMEOUT) == ConnectionPHY(
        hci.Phy.LE_HDT, hci.Phy.LE_2M
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_phy_hdt_with_peer_without_hdt() -> None:
    devices = TwoDevices()
    devices.controllers[1].le_features &= ~hci.LeFeatureMask.HIGH_DATA_THROUGHPUT
    _set_no_phy_preference(devices)
    await devices.setup_connection()
    central = devices.connections[0]

    central_update = await _wait_for_phy_update(central)
    await central.set_phy(
        tx_phys=[hci.Phy.LE_HDT, hci.Phy.LE_2M],
        rx_phys=[hci.Phy.LE_HDT, hci.Phy.LE_2M],
    )
    assert await asyncio.wait_for(central_update, _TIMEOUT) == ConnectionPHY(
        hci.Phy.LE_2M, hci.Phy.LE_2M
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_set_phy_hdt_unsupported() -> None:
    devices = TwoDevices()
    devices.controllers[0].le_features &= ~hci.LeFeatureMask.HIGH_DATA_THROUGHPUT
    await devices.setup_connection()

    assert not devices[0].supports_le_phy(hci.Phy.LE_HDT)
    with pytest.raises(hci.HCI_Error) as error:
        await devices.connections[0].set_phy(
            tx_phys=[hci.Phy.LE_HDT], rx_phys=[hci.Phy.LE_HDT]
        )
    assert (
        error.value.error_code
        == hci.HCI_ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_hdt_data_length() -> None:
    devices = TwoDevices()
    await devices.setup_connection()
    central, peripheral = devices.connections[0], devices.connections[1]

    response = await devices[0].send_sync_command(
        hci.HCI_LE_Read_Maximum_Data_Length_V2_Command(phy=hci.Phy.LE_HDT)
    )
    assert response.supported_max_tx_octets == 0x1FEF
    assert response.supported_max_rx_octets == 0x1FEF
    assert response.supported_max_tx_payload_window_size == 1
    assert response.supported_max_rx_payload_window_size == 1
    assert response.supported_max_rx_octets_per_packet == 0x1FEF

    response = await devices[0].send_sync_command(
        hci.HCI_LE_Read_Maximum_Data_Length_V2_Command(phy=hci.Phy.LE_1M)
    )
    assert (
        response.supported_max_tx_octets
        == devices.controllers[0].supported_max_tx_octets
    )

    await devices[0].send_sync_command(
        hci.HCI_LE_Write_Suggested_Default_Data_Length_V2_Command(
            suggested_max_tx_octets=1000,
            suggested_max_tx_time=0x2000,
            phys=hci.DataLengthPhys.LE_HDT,
        )
    )
    suggested = await devices[0].send_sync_command(
        hci.HCI_LE_Read_Suggested_Default_Data_Length_V2_Command(
            phys=hci.DataLengthPhys.LE_HDT
        )
    )
    assert suggested.suggested_max_tx_octets == 1000
    assert suggested.suggested_max_tx_time == 0x2000

    central_change = asyncio.get_running_loop().create_future()
    peripheral_change = asyncio.get_running_loop().create_future()
    central.once(
        central.EVENT_CONNECTION_HDT_DATA_LENGTH_CHANGE,
        lambda: central_change.set_result(None),
    )
    peripheral.once(
        peripheral.EVENT_CONNECTION_HDT_DATA_LENGTH_CHANGE,
        lambda: peripheral_change.set_result(None),
    )
    await devices[0].set_data_length(
        central, 4000, 0x3000, phys=hci.DataLengthPhys.LE_HDT
    )
    await asyncio.wait_for(central_change, _TIMEOUT)
    await asyncio.wait_for(peripheral_change, _TIMEOUT)
    assert central.hdt_data_length == Connection.LeDataLength(
        max_tx_octets=4000, max_tx_time=0x3000, max_rx_octets=0x1FEF, max_rx_time=0x4290
    )
    assert peripheral.hdt_data_length == Connection.LeDataLength(
        max_tx_octets=0x1FEF, max_tx_time=0x4290, max_rx_octets=4000, max_rx_time=0x3000
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_encryption_mic_length() -> None:
    devices = TwoDevices()
    _set_no_phy_preference(devices)
    await devices.setup_connection()
    central, peripheral = devices.connections[0], devices.connections[1]

    ltk = bytes(range(16))
    devices[0].keystore = MemoryKeyStore()
    await devices[0].keystore.update(
        str(central.peer_address), PairingKeys(ltk=PairingKeys.Key(value=ltk))
    )

    async def long_term_key_provider(_connection_handle, _rand, _ediv):
        return ltk

    devices[1].host.long_term_key_provider = long_term_key_provider

    # Encryption on a GFSK PHY uses a 32-bit MIC.
    await central.encrypt()
    await async_barrier()
    assert central.is_encrypted
    assert peripheral.is_encrypted
    assert central.encryption_key_size == 16
    assert central.encryption_mic_length == hci.HdtMicLength.MIC_32_BITS
    assert peripheral.encryption_mic_length == hci.HdtMicLength.MIC_32_BITS

    # Move to the LE HDT PHY, preferring a 64-bit MIC.
    central_update = await _wait_for_phy_update(central)
    await central.set_phy(
        tx_phys=[hci.Phy.LE_HDT],
        rx_phys=[hci.Phy.LE_HDT],
        phy_options=hci.PhyOptions.PREFER_HDT_64_BIT_MIC,
    )
    await asyncio.wait_for(central_update, _TIMEOUT)

    # Refresh the key.
    key_refresh = asyncio.get_running_loop().create_future()
    central.once(
        central.EVENT_CONNECTION_ENCRYPTION_KEY_REFRESH,
        lambda: key_refresh.set_result(None),
    )
    await devices[0].send_async_command(
        hci.HCI_Refresh_Encryption_Key_V2_Command(
            connection_handle=central.handle,
            hdt_mic_length=hci.HdtMicLength.MIC_64_BITS,
        )
    )
    await asyncio.wait_for(key_refresh, _TIMEOUT)
    await async_barrier()
    assert central.encryption_mic_length == hci.HdtMicLength.MIC_64_BITS

    # Encrypting an encrypted connection refreshes the key.
    await central.encrypt()
    assert central.is_encrypted


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_refresh_encryption_key_without_encryption() -> None:
    devices = TwoDevices()
    await devices.setup_connection()

    with pytest.raises(hci.HCI_Error) as error:
        await devices[0].send_async_command(
            hci.HCI_Refresh_Encryption_Key_V2_Command(
                connection_handle=devices.connections[0].handle,
                hdt_mic_length=hci.HdtMicLength.MIC_128_BITS,
            )
        )
    assert error.value.error_code == hci.HCI_ErrorCode.INSUFFICIENT_SECURITY_ERROR


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_create_big_v2() -> None:
    devices = TwoDevices()
    await devices.setup_connection()

    with mock.patch.object(
        devices[0].host, 'on_hci_le_create_big_complete_v2_event'
    ) as handler:
        await devices[0].send_async_command(
            hci.HCI_LE_Create_BIG_V2_Command(
                big_handle=0,
                advertising_handle=1,
                num_bis=2,
                sdu_interval=10000,
                max_sdu=100,
                max_transport_latency=10,
                rtn=2,
                phy=hci.PhyBit.LE_2M,
                packing=0,
                framing=0,
                encryption=0,
                broadcast_code=bytes(16),
                coded_rates=3,
                hdt_rates=hci.HdtRate.ALL,
                hdt_mic_length=hci.HdtMicLength.MIC_128_BITS,
                hdt_packet_format=hci.HdtPacketFormat.ANY,
            )
        )
        await async_barrier()
    handler.assert_called_once()
    event = handler.call_args.args[0]
    assert isinstance(event, hci.HCI_LE_Create_BIG_Complete_V2_Event)
    assert event.phy == hci.Phy.LE_2M
    assert event.connection_handle == [0x0100, 0x0101]

    # Isochronous Broadcaster on the LE HDT PHY is not supported.
    with pytest.raises(hci.HCI_Error) as error:
        await devices[0].send_async_command(
            hci.HCI_LE_Create_BIG_V2_Command(
                big_handle=1,
                advertising_handle=1,
                num_bis=1,
                sdu_interval=10000,
                max_sdu=100,
                max_transport_latency=10,
                rtn=2,
                phy=hci.PhyBit.LE_HDT,
                packing=0,
                framing=0,
                encryption=0,
                broadcast_code=bytes(16),
                coded_rates=3,
                hdt_rates=hci.HdtRate.ALL,
                hdt_mic_length=hci.HdtMicLength.MIC_128_BITS,
                hdt_packet_format=hci.HdtPacketFormat.ANY,
            )
        )
    assert (
        error.value.error_code
        == hci.HCI_ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR
    )
