# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.6: Controller Information."""

import pytest

from bumble import hci
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.peer import establish
from tests.radio_controller.qualification.tester import LOWER_PERIPHERAL_PUBLIC_ADDRESS

ErrorCode = hci.HCI_ErrorCode
RADIO_CASES = {'HCI/CIN/BV-14-C'}

# Independent ICS/IXIT declaration of this test DUT; never read from the backend.
EXPECTED_COMMANDS = frozenset(
    {
        hci.HCI_DISCONNECT_COMMAND,
        hci.HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST_COMMAND,
        hci.HCI_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST_COMMAND,
        hci.HCI_LE_CLEAR_ADVERTISING_SETS_COMMAND,
        hci.HCI_LE_CLEAR_FILTER_ACCEPT_LIST_COMMAND,
        hci.HCI_LE_CLEAR_PERIODIC_ADVERTISER_LIST_COMMAND,
        hci.HCI_LE_CONNECTION_UPDATE_COMMAND,
        hci.HCI_LE_CREATE_CONNECTION_CANCEL_COMMAND,
        hci.HCI_LE_CREATE_CONNECTION_COMMAND,
        hci.HCI_LE_ENABLE_ENCRYPTION_COMMAND,
        hci.HCI_LE_ENCRYPT_COMMAND,
        hci.HCI_LE_EXTENDED_CREATE_CONNECTION_COMMAND,
        hci.HCI_LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY_COMMAND,
        hci.HCI_LE_LONG_TERM_KEY_REQUEST_REPLY_COMMAND,
        hci.HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL_COMMAND,
        hci.HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_COMMAND,
        hci.HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC_COMMAND,
        hci.HCI_LE_RAND_COMMAND,
        hci.HCI_LE_READ_BUFFER_SIZE_COMMAND,
        hci.HCI_LE_READ_CHANNEL_MAP_COMMAND,
        hci.HCI_LE_READ_FILTER_ACCEPT_LIST_SIZE_COMMAND,
        hci.HCI_LE_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
        hci.HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND,
        hci.HCI_LE_READ_MAXIMUM_DATA_LENGTH_COMMAND,
        hci.HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND,
        hci.HCI_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE_COMMAND,
        hci.HCI_LE_READ_PHY_COMMAND,
        hci.HCI_LE_READ_REMOTE_FEATURES_COMMAND,
        hci.HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
        hci.HCI_LE_READ_SUPPORTED_STATES_COMMAND,
        hci.HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY_COMMAND,
        hci.HCI_LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY_COMMAND,
        hci.HCI_LE_REMOVE_ADVERTISING_SET_COMMAND,
        hci.HCI_LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST_COMMAND,
        hci.HCI_LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST_COMMAND,
        hci.HCI_LE_SET_ADVERTISING_DATA_COMMAND,
        hci.HCI_LE_SET_ADVERTISING_ENABLE_COMMAND,
        hci.HCI_LE_SET_ADVERTISING_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_COMMAND,
        hci.HCI_LE_SET_DATA_LENGTH_COMMAND,
        hci.HCI_LE_SET_DEFAULT_PHY_COMMAND,
        hci.HCI_LE_SET_EVENT_MASK_COMMAND,
        hci.HCI_LE_SET_EXTENDED_ADVERTISING_DATA_COMMAND,
        hci.HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE_COMMAND,
        hci.HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_EXTENDED_SCAN_ENABLE_COMMAND,
        hci.HCI_LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA_COMMAND,
        hci.HCI_LE_SET_HOST_CHANNEL_CLASSIFICATION_COMMAND,
        hci.HCI_LE_SET_PERIODIC_ADVERTISING_DATA_COMMAND,
        hci.HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE_COMMAND,
        hci.HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE_COMMAND,
        hci.HCI_LE_SET_PHY_COMMAND,
        hci.HCI_LE_SET_RANDOM_ADDRESS_COMMAND,
        hci.HCI_LE_SET_SCAN_ENABLE_COMMAND,
        hci.HCI_LE_SET_SCAN_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_SCAN_RESPONSE_DATA_COMMAND,
        hci.HCI_LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
        hci.HCI_READ_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND,
        hci.HCI_READ_BD_ADDR_COMMAND,
        hci.HCI_READ_LOCAL_SUPPORTED_COMMANDS_COMMAND,
        hci.HCI_READ_LOCAL_SUPPORTED_FEATURES_COMMAND,
        hci.HCI_READ_LOCAL_VERSION_INFORMATION_COMMAND,
        hci.HCI_READ_REMOTE_VERSION_INFORMATION_COMMAND,
        hci.HCI_READ_RSSI_COMMAND,
        hci.HCI_RESET_COMMAND,
        hci.HCI_SET_EVENT_MASK_COMMAND,
        hci.HCI_SET_EVENT_MASK_PAGE_2_COMMAND,
        hci.HCI_WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT_COMMAND,
    }
)
EXPECTED_LOCAL_VERSION = (
    hci.HCI_VERSION_BLUETOOTH_CORE_5_0,
    0,
    hci.HCI_VERSION_BLUETOOTH_CORE_5_0,
    0xFFFF,
    0,
)


# Expected capability declarations of the configured DUT, not implementation imports.
EXPECTED_LE_FEATURES = int(
    hci.LeFeatureMask.LE_ENCRYPTION
    | hci.LeFeatureMask.LE_PING
    | hci.LeFeatureMask.LE_EXTENDED_ADVERTISING
    | hci.LeFeatureMask.LE_PERIODIC_ADVERTISING
    | hci.LeFeatureMask.CHANNEL_SELECTION_ALGORITHM_2
    | hci.LeFeatureMask.CONNECTION_PARAMETERS_REQUEST_PROCEDURE
    | hci.LeFeatureMask.EXTENDED_REJECT_INDICATION
    | hci.LeFeatureMask.LE_2M_PHY
    | hci.LeFeatureMask.LE_CODED_PHY
    | hci.LeFeatureMask.LE_DATA_PACKET_LENGTH_EXTENSION
    | hci.LeFeatureMask.PERIPHERAL_INITIATED_FEATURE_EXCHANGE
    | hci.LeFeatureMask.MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE
).to_bytes(8, 'little')


async def read_local_supported_commands(tester):
    """Read Local Supported Commands command.

    Initial Condition:
        No LL connection exists. EXPECTED_COMMANDS declares this LE Controller's
        supported commands independently of the returned bitmap or backend.

    Test Steps:
        1. Send Read Local Supported Commands [v1], as selected by Table 4.10.
        2. Receive successful Command Complete with the matching opcode,
           one command credit and Supported_Commands.

    Expected Outcome:
        Pass verdict:
            All 64 returned octets exactly match the independently declared
            command set mapped through the standard Supported Commands bit table.
            Unsupported and undefined command bits are zero.

    Reference:
        HCI.TS.p39.pdf, Section 4.6.1, HCI/CIN/BV-03-C, Table 4.10 and Figure 4.17;
        PDF/printed pages 49-50; source [1] 7.4.2 and [2] LE Command Tables.
    """
    result = await tester.command(hci.HCI_Read_Local_Supported_Commands_Command())
    # Read Local Supported Commands itself has no bit assigned in this bitmap.
    mapped = EXPECTED_COMMANDS - {hci.HCI_READ_LOCAL_SUPPORTED_COMMANDS_COMMAND}
    expected = sum(hci.HCI_SUPPORTED_COMMANDS_MASKS[op] for op in mapped)
    assert result.supported_commands == expected.to_bytes(64, 'little')


async def read_local_version_information(tester):
    """Read Local Version Information Command.

    Initial Condition:
        No LL connection exists. EXPECTED_LOCAL_VERSION declares HCI 5.0,
        revision zero, LMP 5.0, manufacturer 0xFFFF and subversion zero.

    Test Steps:
        The source procedure is the unnumbered MSC in Figure 4.18:
        - Send Read Local Version Information.
        - Receive successful Command Complete with the matching opcode and
          one command credit. Read all five version/manufacturer fields.

    Expected Outcome:
        Pass verdict:
            HCI Version and LMP Version use the declared Assigned Numbers values.
            HCI Revision, Manufacturer Name and LMP Subversion exactly match
            the independent declaration.

    Reference:
        HCI.TS.p39.pdf, standalone HCI/CIN/BV-04-C, Figure 4.18;
        PDF/printed pages 50-51; source [1] HCI 7.4.1.
    """
    result = await tester.command(hci.HCI_Read_Local_Version_Information_Command())
    assert (
        result.hci_version,
        result.hci_subversion,
        result.lmp_version,
        result.company_identifier,
        result.lmp_subversion,
    ) == EXPECTED_LOCAL_VERSION


async def read_local_le_features(tester):
    """LE Read Local Supported Features Page 0 Command.

    Initial Condition:
        The IUT has no Lower Tester connection. EXPECTED_LE_FEATURES declares
        the selected DUT capabilities independently of the Controller's code.

    Test Steps:
        The source uses the unnumbered MSC in Figure 4.22:
        - The Upper Tester sends LE Read Local Supported Features Page 0.
        - The IUT returns Command Complete with Status = Success (0x00),
          the corresponding opcode, a command credit and LE_Features.
        Compare the feature field against EXPECTED_LE_FEATURES, the independent
        declaration of this DUT's supported LL capabilities.

    Expected Outcome:
        Pass verdict: the Features field contains exactly the supported features
        mapped from LL ICS by the source's referenced Table 2.1.

    Reference:
        HCI.TS.p39.pdf, Section 4.6, independently titled procedure
        HCI/CIN/BV-12-C; PDF/printed page 56, Figure 4.22.
        Source reference [1], Section 7.8.3; [20], Table 2.1 (LL ICS mapping).
    """
    result = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    assert result.le_features == EXPECTED_LE_FEATURES


async def accept_list_capacity(tester):
    """Filter Accept List Size.

    Initial Condition:
        The IUT is not connected to the Lower Tester.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Upper Tester sends LE Clear Filter Accept List.
        - Read Filter Accept List Size; require successful Command Complete
          and a size of at least one.
        - Add distinct addresses until the reported number of entries is filled;
          require successful Command Complete for each addition.
        - Add one more address and require Command Complete with Status =
          Memory Capacity Exceeded (0x07).
        - Remove one inserted address and require successful Command Complete.
        - Add another address and require successful Command Complete.
        This implementation uses distinct public addresses for all additions.

    Expected Outcome:
        Pass verdict: the reported capacity is at least one; all commands return
        matching Command Complete events with one command credit. Insertions
        succeed while space exists, fail with 0x07 when full, and succeed again
        after a successful removal.

    Reference:
        HCI.TS.p39.pdf, Section 4.6, independently titled procedure
        HCI/CIN/BV-06-C, Figure 4.19; PDF/printed pages 51-52.
        Source reference [8], Section 7.8.17.
    """
    await tester.command(hci.HCI_LE_Clear_Filter_Accept_List_Command())
    size = (
        await tester.command(hci.HCI_LE_Read_Filter_Accept_List_Size_Command())
    ).filter_accept_list_size
    assert size > 0
    for index in range(size + 1):
        address = hci.Address((index + 1).to_bytes(6, 'little'), 0)
        await tester.command(
            hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(0, address),
            (
                ErrorCode.SUCCESS
                if index < size
                else ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR
            ),
        )
    await tester.command(
        hci.HCI_LE_Remove_Device_From_Filter_Accept_List_Command(
            0, hci.Address(size.to_bytes(6, 'little'), 0)
        )
    )
    await tester.command(
        hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command(
            0, hci.Address((size + 2).to_bytes(6, 'little'), 0)
        )
    )


async def read_rssi(tester):
    """Read RSSI Value.

    Initial Condition:
        An ACL is established with the independent Lower Tester; either role is
        permitted. This implementation selects the Peripheral role and LE 1M.

    Test Steps:
        1. The Upper Tester sends Read RSSI with Handle equal to the current
           ACL's Connection_Handle.
        2. The IUT returns successful Command Complete with Handle equal to
           the value from step 1 and a valid RSSI.

    Observation Setup:
        Establish the ACL to satisfy the initial condition before step 1.
        Check the opcode, command credit and LE RSSI range as well as Status
        and Handle. Disconnect after step 2; teardown is not a source step.

    Expected Outcome:
        Pass verdict: status is Success, Handle equals the submitted connection
        handle and RSSI is within the LE measurement range -127 through +20 dBm,
        not the unavailable sentinel 127.

    Reference:
        HCI.TS.p39.pdf, Section 4.6.3, HCI/CIN/BV-14-C;
        PDF/printed pages 57-58, steps 1-2 and Figure 4.24.
        Source reference [12], Section 7.5.4; Table 4.13 selects LE PHY.
    """
    link = await establish(tester, peer_address=LOWER_PERIPHERAL_PUBLIC_ADDRESS)
    result = await tester.command(hci.HCI_Read_RSSI_Command(link.handle))
    assert result.handle == link.handle and -127 <= result.rssi <= 20
    await link.disconnect()


PROCEDURES: ProcedureMap = {}

# Verify the v1 Supported_Commands bitmap against the independently declared commands,
# including zero bits for unsupported or undefined commands.
PROCEDURES |= procedure_cases(
    read_local_supported_commands,
    {
        'HCI/CIN/BV-03-C': (
            'Read Local Supported Commands [v1] command',
            {},
        ),
    },
)

# Verify every returned version and manufacturer field against the declared IXIT values,
# rather than comparing two Controller self-reports.
PROCEDURES |= procedure_cases(
    read_local_version_information,
    {
        'HCI/CIN/BV-04-C': (
            'Read Local Version Information Command',
            {},
        ),
    },
)

# Verify that the reported Filter Accept List size equals the available address-list
# entries; check insertion, overflow and reuse after removal.
PROCEDURES |= procedure_cases(
    accept_list_capacity,
    {
        'HCI/CIN/BV-06-C': (
            'Filter Accept List Size',
            {},
        ),
    },
)

# Verify that the returned LE feature bits match the declared LL capabilities.
PROCEDURES |= procedure_cases(
    read_local_le_features,
    {
        'HCI/CIN/BV-12-C': (
            'LE Read Local Supported Features Page 0 Command',
            {},
        ),
    },
)

# Verify that Read RSSI returns a valid measurement for the selected ACL.
PROCEDURES |= procedure_cases(
    read_rssi,
    {
        'HCI/CIN/BV-14-C': (
            'Read RSSI Value, LE PHY',
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES, radio_cases=RADIO_CASES),
)
async def test_controller_information_commands(
    hci_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(hci_dut, identifier, description, procedure, parameters, marks)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES, radio_cases=RADIO_CASES, radio=True),
)
async def test_controller_information_radio(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
