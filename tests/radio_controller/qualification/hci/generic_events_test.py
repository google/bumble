# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.3: Generic Events."""

import random

import pytest

from bumble import hci
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.hci.controller_information_test import (
    EXPECTED_COMMANDS,
)
from tests.radio_controller.qualification.tester import (
    create_connection,
    create_sync,
    extended_enable,
    extended_parameters,
    legacy_parameters,
    scan_parameters,
)

ErrorCode = hci.HCI_ErrorCode
Properties = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties
)
Operation = hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation
SYNC_TRANSFER_PARAMETERS_OPCODE = (
    hci.HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_COMMAND
)


def _check_unknown_command(event, opcode):
    assert isinstance(
        event, (hci.HCI_Command_Complete_Event, hci.HCI_Command_Status_Event)
    )
    assert event.command_opcode == opcode and event.num_hci_command_packets == 1
    if isinstance(event, hci.HCI_Command_Status_Event):
        status = event.status
    else:
        parameters = event.return_parameters
        status = (
            parameters.data[0]
            if isinstance(parameters, hci.HCI_GenericReturnParameters)
            else parameters[0] if isinstance(parameters, bytes) else parameters.status
        )
    allowed = (
        (
            ErrorCode.UNKNOWN_HCI_COMMAND_ERROR,
            ErrorCode.UNSPECIFIED_ERROR_ERROR,
            ErrorCode.COMMAND_DISALLOWED_ERROR,
        )
        if opcode == hci.HCI_REMOTE_NAME_REQUEST_CANCEL_COMMAND
        else (ErrorCode.UNKNOWN_HCI_COMMAND_ERROR,)
    )
    assert status in allowed, (opcode, status)


async def unsupported_commands_on_each_supported_controller(tester):
    """Unsupported Commands on each supported controller.

    Initial Condition:
        The IUT has no Lower Tester connection. EXPECTED_COMMANDS is its independent
        ICS declaration; do not derive exclusions from the reported command bitmap.
        BR/EDR and AMP Controller variants do not apply to this LE-only IUT.

    Test Steps:
        The source uses an unnumbered repeated procedure:
        - For each standard opcode defined by the HCI codec but absent from the
          independent capability declaration, send that unsupported command.
          Use zero parameters: an unsupported opcode has no parameter schema
          at this Controller. Vendor-specific opcodes are outside this table.
        - Receive Command Complete or Command Status. Verify the matching
          opcode, one command credit and Unknown HCI Command (0x01).
        - Apply the source note's Remote Name Request Cancel exception only
          to that opcode: Unspecified Error or Command Disallowed is also allowed.

    Expected Outcome:
        Pass verdict:
            Every unsupported command produces one of the specified responses.
            A reported bitmap cannot remove a declared-unsupported opcode from
            the sweep. Unknown opcodes, rather than malformed parameters, are
            the subject of this test; RFU OGF is covered by HCI/GEV/BI-01-C.

    Reference:
        HCI.TS.p39.pdf, standalone HCI/GEV/BV-01-C, Figure 4.1 and Notes;
        PDF/printed page 26; source [1] 7.7.14 and Core HCI Unknown HCI Command.
    """
    opcodes = sorted(
        opcode
        for opcode in hci.HCI_Command.command_names
        if opcode not in EXPECTED_COMMANDS and opcode >> 10 != hci.HCI_VENDOR_OGF
    )
    assert opcodes, 'no unsupported commands in the declared test matrix'
    for opcode in opcodes:
        tester.send(bytes(hci.HCI_Command(b'', op_code=opcode)))
        event = await tester.expect(
            lambda event: isinstance(
                event, (hci.HCI_Command_Complete_Event, hci.HCI_Command_Status_Event)
            )
            and event.command_opcode == opcode
        )
        _check_unknown_command(event, opcode)


async def _reject_mixed_command_families(tester, legacy, extended):
    """Execute both directions of a section's complete supported-command tables."""
    supported = int.from_bytes(
        (
            await tester.command(hci.HCI_Read_Local_Supported_Commands_Command())
        ).supported_commands,
        'little',
    )
    for first, rejected in ((legacy[0], extended), (extended[0], legacy)):
        await tester.command(hci.HCI_Reset_Command())
        await tester.command(first)
        for command in rejected:
            if supported & hci.HCI_SUPPORTED_COMMANDS_MASKS[command.op_code]:
                status = (
                    (
                        ErrorCode.COMMAND_DISALLOWED_ERROR,
                        ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                    )
                    if command.op_code == SYNC_TRANSFER_PARAMETERS_OPCODE
                    else ErrorCode.COMMAND_DISALLOWED_ERROR
                )
                await tester.command(command, status)
    # A reset must allow either family again.
    await tester.command(hci.HCI_Reset_Command())
    await tester.command(legacy[0])


async def disallow_mixed_advertising_commands(tester):
    """Disallow Mixing Legacy and Extended Advertising Commands.

    Initial Condition:
        No separate Initial Condition block is specified. The procedure begins
        with Reset; the reported Supported Commands mask selects table rows.
        Periodic Advertising Sync Transfer is not supported by this DUT.

    Test Steps:
        1. The Upper Tester powers the IUT off and on, or sends Reset. This
           implementation uses Reset.
        2. Send LE Set Advertising Parameters and require Command Complete
           with Status = Success (0x00).
        3. Send each supported command in Table 4.2 (13 rows), requiring
           Command Complete with the status specified in that table: Command
           Disallowed (0x0C), or alternatively Unknown Connection Identifier
           (0x02) for Periodic Advertising Sync Transfer Parameters.
        4. Power the IUT off and on, or send Reset.
        5. Send LE Set Extended Advertising Parameters and require Command
           Complete with Status = Success (0x00).
        6. Send each supported command in Table 4.3: Set Advertising Parameters,
           Read Advertising Channel Tx Power, Set Advertising Data, Set Scan
           Response Data and Set Advertising Enable. Require Command Complete
           with Status = Command Disallowed (0x0C) for each command.

    Additional Check:
        After the six source steps, reset and verify that legacy parameters
        can be selected again. This is not an additional source step.

    Expected Outcome:
        Pass verdict: every supported command from the opposite family returns
        Command Complete with matching opcode, a command credit and status 0x0C.
        Table 4.2 permits 0x02 for its per-connection Sync Transfer Parameters
        row; this DUT does not support that row or the default-transfer row.

    Reference:
        HCI.TS.p39.pdf, Section 4.3, independently titled procedure
        HCI/GEV/BV-02-C, Tables 4.2 and 4.3; PDF/printed pages 27-28.
        Source reference [9], Section 3.19.1.
        Section 4.3.1 is the preceding event-alternatives subsection, not the
        numeric identifier of this independently titled procedure.
    """
    legacy = [
        legacy_parameters(),
        hci.HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_Command(),
        hci.HCI_LE_Set_Advertising_Data_Command(b''),
        hci.HCI_LE_Set_Scan_Response_Data_Command(b''),
        hci.HCI_LE_Set_Advertising_Enable_Command(0),
    ]
    extended = [
        extended_parameters(),
        hci.HCI_LE_Set_Extended_Advertising_Data_Command(
            0, Operation.COMPLETE_DATA, 0, b''
        ),
        hci.HCI_LE_Set_Extended_Scan_Response_Data_Command(
            0, Operation.COMPLETE_DATA, 0, b''
        ),
        extended_enable(0),
        hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command(),
        hci.HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command(),
        hci.HCI_LE_Remove_Advertising_Set_Command(0),
        hci.HCI_LE_Clear_Advertising_Sets_Command(),
        hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(0, 40, 40, 0),
        hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
            0, Operation.COMPLETE_DATA, b''
        ),
        hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(0, 0),
        hci.HCI_LE_Set_Periodic_Advertising_Sync_Transfer_Parameters_Command(
            0, 0, 0, 10, 0
        ),
        hci.HCI_LE_Set_Default_Periodic_Advertising_Sync_Transfer_Parameters_Command(
            0, 0, 10, 0
        ),
    ]
    await _reject_mixed_command_families(tester, legacy, extended)


async def disallow_mixed_scanning_commands(tester):
    """Disallow Mixing Legacy and Extended Scanning Commands.

    Initial Condition:
        No separate Initial Condition block is specified. Reset establishes the
        initial state; supported commands are selected from the reported mask.

    Test Steps:
        1. The Upper Tester powers the IUT off and on, or sends Reset. This
           implementation uses Reset.
        2. Send LE Set Scan Parameters and require Command Complete with
           Status = Success (0x00).
        3. Send each supported command from the ten rows of Table 4.4: Extended Scan
           Parameters/Enable, Extended Create Connection, Create Sync,
           Create Sync Cancel, Terminate Sync and all four Periodic Advertiser
           List commands; require status 0x0C in the prescribed event.
        4. Power the IUT off and on, or send Reset.
        5. Send LE Set Extended Scan Parameters and require Command Complete
           with Status = Success (0x00).
        6. Send each supported command in Table 4.5: Scan Parameters,
           Scan Enable and Create Connection; require status 0x0C in the
           prescribed event.

    Additional Check:
        After the six source steps, reset and verify that legacy parameters
        can be selected again. This is not an additional source step.

    Expected Outcome:
        Pass verdict: every opposite-family command returns Command Disallowed,
        with matching opcode and one command credit. Create Connection and
        Create Sync commands return Command Status; other rows return Command
        Complete, as prescribed by Tables 4.4 and 4.5.

    Reference:
        HCI.TS.p39.pdf, Section 4.3, independently titled procedure
        HCI/GEV/BV-03-C, Tables 4.4 and 4.5; PDF/printed pages 28-30.
        Source reference [9], Section 3.19.1.
    """
    legacy = [
        scan_parameters(),
        hci.HCI_LE_Set_Scan_Enable_Command(0, 0),
        create_connection(),
    ]
    extended = [
        scan_parameters(extended=True),
        hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0),
        create_connection(extended=True),
        create_sync(),
        hci.HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command(),
        hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(0),
        hci.HCI_LE_Add_Device_To_Periodic_Advertiser_List_Command(
            0, hci.Address.ANY, 0
        ),
        hci.HCI_LE_Remove_Device_From_Periodic_Advertiser_List_Command(
            0, hci.Address.ANY, 0
        ),
        hci.HCI_LE_Clear_Periodic_Advertiser_List_Command(),
        hci.HCI_LE_Read_Periodic_Advertiser_List_Size_Command(),
    ]
    await _reject_mixed_command_families(tester, legacy, extended)


async def extended_advertising_without_scan_response_data(tester):
    """Extended Advertising Commands Without Scan Response Data.

    Initial Condition:
        No separate Initial Condition block is specified; step 1 resets the IUT.

    Test Steps:
        1. The Upper Tester powers the IUT off and on, or sends Reset. This
           implementation uses Reset.
        2. Send LE Set Extended Advertising Parameters with the scannable
           property set; require Command Complete with Status = Success (0x00).
        3. Send LE Set Extended Scan Response Data without response data;
           require Command Complete with Status = Success (0x00).
        4. Send LE Set Extended Advertising Enable without response data;
           require Command Complete with Status = Command Disallowed (0x0C).

    Expected Outcome:
        Pass verdict: the data command completes with status 0x00 and enable
        completes with status 0x0C; opcode and command credit must match.

    Reference:
        HCI.TS.p39.pdf, Section 4.3, independently titled procedure
        HCI/GEV/BV-04-C; PDF/printed page 30, steps 1-4.
        Source reference [9], Sections 7.8.55 and 7.8.56.
    """
    await tester.command(hci.HCI_Reset_Command())
    await tester.command(
        extended_parameters(
            advertising_event_properties=Properties.SCANNABLE_ADVERTISING
        )
    )
    await tester.command(
        hci.HCI_LE_Set_Extended_Scan_Response_Data_Command(
            0, Operation.COMPLETE_DATA, 0, b''
        )
    )
    await tester.command(extended_enable(), ErrorCode.COMMAND_DISALLOWED_ERROR)


async def rfu_commands(tester):
    """HCI Command with RFU OGF.

    Initial Condition:
        No separate Initial Condition is specified. A fresh IUT receives commands
        through the Upper Tester's serialized HCI interface.

    Test Steps:
        Repeat steps 1 and 2 for OCF values 0x000-0x00F, 0x3F0-0x3FF,
        and twenty random values between 0x010 and 0x3EF. This implementation
        seeds its local generator and selects twenty distinct random values.
        1. The Upper Tester sends an HCI command with OGF = 0x3E and the
           selected OCF to the IUT.
        2. The IUT returns Command Complete with Status = Unknown HCI Command
           (0x01). Check the matching opcode and one command credit as well.

    Expected Outcome:
        Pass verdict: all 52 commands return Unknown HCI Command through Command
        Complete; an unrelated opcode or Command Status cannot satisfy the test.

    Reference:
        HCI.TS.p39.pdf, Section 4.3, independently titled procedure
        HCI/GEV/BI-01-C; PDF/printed page 31.
        Source reference [9], Section 5.4.1.
    """
    rfu_ogf = 0x3E
    opcodes = [*range(0x010), *range(0x3F0, 0x400)]
    opcodes += random.Random(0).sample(range(0x010, 0x3F0), 20)
    for ocf in opcodes:
        await tester.command(
            hci.HCI_Command(b'', op_code=hci.hci_command_op_code(rfu_ogf, ocf)),
            ErrorCode.UNKNOWN_HCI_COMMAND_ERROR,
        )


PROCEDURES: ProcedureMap = {}

# Verify that every standard HCI opcode declared unsupported by this LE-only Controller
# returns Unknown HCI Command through either allowed event.
PROCEDURES |= procedure_cases(
    unsupported_commands_on_each_supported_controller,
    {
        'HCI/GEV/BV-01-C': (
            'Unsupported Commands on each supported controller',
            {},
        ),
    },
)

# Verify that every supported command from the other advertising family is rejected with
# Command Disallowed until the Controller is reset.
PROCEDURES |= procedure_cases(
    disallow_mixed_advertising_commands,
    {
        'HCI/GEV/BV-02-C': (
            'Disallow Mixing Legacy and Extended Advertising Commands',
            {},
        ),
    },
)

# Verify rejection of every supported legacy or extended scanning command after a
# command from the other family, until Reset.
PROCEDURES |= procedure_cases(
    disallow_mixed_scanning_commands,
    {
        'HCI/GEV/BV-03-C': (
            'Disallow Mixing Legacy and Extended Scanning Commands',
            {},
        ),
    },
)

# Verify that submitting empty scan-response data succeeds, but enabling a scannable
# extended advertiser without response data is disallowed.
PROCEDURES |= procedure_cases(
    extended_advertising_without_scan_response_data,
    {
        'HCI/GEV/BV-04-C': (
            'Extended Advertising Commands Without Scan Response Data',
            {},
        ),
    },
)

# Verify Unknown HCI Command for a command with RFU OGF 0x3E.
PROCEDURES |= procedure_cases(
    rfu_commands,
    {
        'HCI/GEV/BI-01-C': (
            'HCI Command with RFU OGF',
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_generic_events(
    hci_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(hci_dut, identifier, description, procedure, parameters, marks)
