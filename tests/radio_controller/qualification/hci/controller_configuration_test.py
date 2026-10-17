# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.10: Controller Configuration."""

import random
import struct

import pytest

from bumble import hci
from bumble.ll import (
    PDU_DATA_PAYLOAD_SIZE_MAX,
    PDU_DATA_PAYLOAD_SIZE_MIN,
    PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
    PDU_DATA_PAYLOAD_TIME_MIN_US,
    ControlPdu,
    LlId,
)
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.peer import establish
from tests.radio_controller.qualification.tester import (
    create_connection,
    extended_parameters,
)

ErrorCode = hci.HCI_ErrorCode
Opcode = ControlPdu.Opcode

# Capacity declared for this DUT configuration, not read from its implementation.
EXPECTED_PERIODIC_ADVERTISER_LIST_SIZE = 8


def _periodic_parameters(**changes):
    values = {
        'advertising_handle': 0,
        'periodic_advertising_interval_min': 40,
        'periodic_advertising_interval_max': 40,
        'periodic_advertising_properties': 0,
    }
    return hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(**(values | changes))


async def bredr_not_supported(tester):
    """BR/EDR Not Supported.

    Initial Condition:
        The LE-only IUT is in standby.

    Test Steps:
        The source describes an unnumbered procedure: the Upper Tester sends
        HCI Inquiry and receives either Command Complete or Command Status
        with Status = Unknown HCI Command (0x01). Check the corresponding
        opcode and one command credit in either event alternative.

    Expected Outcome:
        Pass verdict: either permitted event reports status 0x01 for Inquiry.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BV-07-C;
        PDF/printed pages 154-155, Figure 4.83.
        Source reference [1], Section 3.2.
    """
    command = hci.HCI_Inquiry_Command(0x9E8B00, 1, 1)
    tester.send(bytes(command))
    event = await tester.expect(
        lambda event: (
            isinstance(
                event, (hci.HCI_Command_Complete_Event, hci.HCI_Command_Status_Event)
            )
            and event.command_opcode == command.op_code
        )
    )
    assert event.num_hci_command_packets == 1
    if isinstance(event, hci.HCI_Command_Status_Event):
        status = event.status
    else:
        # The status is the first return-parameter octet, also for unknown commands.
        status = event.parameters[3]
    assert status == ErrorCode.UNKNOWN_HCI_COMMAND_ERROR


async def set_data_length(tester):
    """LE Set Data Length.

    Initial Condition:
        Establish an ACL with the IUT as Central and a DLE-capable Lower Tester.
        The initial effective data length is 27 octets.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Upper Tester sends LE Set Data Length with the current connection
          handle and permissible TxOctets/TxTime values.
        - The IUT returns Command Complete for that command.
        - If the command changes the maximum transmission packet size or time,
          the IUT sends LE Data Length Change with the updated values.

    Observation Setup:
        Establish the ACL and exchange DLE support before the source procedure.
        Select TxOctets = 60 and TxTime = 592 us. Answer LL_LENGTH_REQ with peer
        receive/transmit limits of 60 octets and 592 us, then check the resulting
        change event against both endpoints' negotiated limits. This vector
        changes the initial effective length, so the conditional event is
        required here. Disconnect in a separate postamble.

    Expected Outcome:
        Pass verdict: the command succeeds for the selected handle. Because the
        selected vector changes effective limits, Data Length Change must report
        60 octets and 592 us in both directions for that same connection.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BV-09-C;
        PDF/printed page 156, Figure 4.84.
        Source reference [2], Section 7.8.33.
    """
    link = await establish(tester, central=True)
    await link.control(
        Opcode.LL_FEATURE_RSP,
        bytes([Opcode.LL_PERIPHERAL_FEATURE_REQ])
        + int(hci.LeFeatureMask.LE_DATA_PACKET_LENGTH_EXTENSION).to_bytes(8, 'little'),
    )
    octets, time_us = 60, 592
    result = await tester.command(
        hci.HCI_LE_Set_Data_Length_Command(link.handle, octets, time_us)
    )
    assert result.connection_handle == link.handle
    request = await link.control(Opcode.LL_LENGTH_REQ)
    max_rx_octets, max_rx_time, max_tx_octets, max_tx_time = struct.unpack(
        '<HHHH', request[1:]
    )
    assert max_rx_octets >= PDU_DATA_PAYLOAD_SIZE_MIN
    assert max_rx_time >= PDU_DATA_PAYLOAD_TIME_MIN_US
    assert (max_tx_octets, max_tx_time) == (octets, time_us)
    await link.exchange(
        bytes([Opcode.LL_LENGTH_RSP])
        + struct.pack('<HHHH', octets, time_us, octets, time_us),
        llid=LlId.CONTROL,
    )
    event = await tester.event(hci.HCI_LE_Data_Length_Change_Event)
    assert event.connection_handle == link.handle
    assert (
        event.max_tx_octets,
        event.max_tx_time,
        event.max_rx_octets,
        event.max_rx_time,
    ) == (
        min(octets, max_tx_octets),
        min(time_us, max_tx_time),
        min(octets, max_rx_octets),
        min(time_us, max_rx_time),
    )
    await link.disconnect(local=True)


async def read_suggested_data_length(tester):
    """LE Read Suggested Default Data Length Command.

    Initial Condition:
        The IUT has just been reset and is in standby.

    Test Steps:
        The source describes an unnumbered procedure: the Upper Tester sends
        LE Read Suggested Default Data Length and receives Command Complete.

    Observation Setup:
        Reset before the procedure to establish the initial condition. Check
        Success, the matching opcode, command credit and both returned values.

    Expected Outcome:
        Pass verdict: SuggestedMaxTxOctets is 27 and SuggestedMaxTxTime is 328 us.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BV-10-C;
        PDF/printed page 157, Figure 4.85.
        Source reference [8], Section 7.8.34.
    """
    await tester.command(hci.HCI_Reset_Command())
    result = await tester.command(
        hci.HCI_LE_Read_Suggested_Default_Data_Length_Command()
    )
    assert result.suggested_max_tx_octets == PDU_DATA_PAYLOAD_SIZE_MIN
    assert result.suggested_max_tx_time == PDU_DATA_PAYLOAD_TIME_MIN_US


async def write_suggested_data_length(tester):
    """LE Write Suggested Default Data Length Command.

    Initial Condition:
        The IUT is in standby.

    Test Steps:
        The source describes an unnumbered procedure for every Table 4.33 row:
        - Send LE Write Suggested Default Data Length with that row's TxOctets
          and TxTime, and receive Command Complete.
        - Send LE Read Suggested Default Data Length and receive Command
          Complete with both stored values.

    Test Case Configuration:
        Rounds 1-9 use the ordered Cartesian product TxOctets = 0x001B, 0x00FB,
        0x0080 and, for each, TxTime = 0x0148, 0x4290, 0x2000. Rounds 10-20
        choose each value randomly in the inclusive ranges 0x001B..0x00FB and
        0x0148..0x4290. A locally seeded generator makes those stimuli repeatable.

    Expected Outcome:
        Pass verdict: all twenty writes and reads succeed with matching opcode
        and credit; each read returns the exact pair most recently written.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BV-11-C;
        PDF/printed pages 157-159, Table 4.33 and Figure 4.86.
        Source reference [8], Section 7.8.35.
    """
    pairs = [
        (octets, time_us)
        for octets in (PDU_DATA_PAYLOAD_SIZE_MIN, PDU_DATA_PAYLOAD_SIZE_MAX, 128)
        for time_us in (
            PDU_DATA_PAYLOAD_TIME_MIN_US,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
            0x2000,
        )
    ]
    generator = random.Random(0)
    pairs += [
        (
            generator.randint(PDU_DATA_PAYLOAD_SIZE_MIN, PDU_DATA_PAYLOAD_SIZE_MAX),
            generator.randint(
                PDU_DATA_PAYLOAD_TIME_MIN_US, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
            ),
        )
        for _ in range(11)
    ]
    for octets, time_us in pairs:
        await tester.command(
            hci.HCI_LE_Write_Suggested_Default_Data_Length_Command(octets, time_us)
        )
        result = await tester.command(
            hci.HCI_LE_Read_Suggested_Default_Data_Length_Command()
        )
        assert (result.suggested_max_tx_octets, result.suggested_max_tx_time) == (
            octets,
            time_us,
        )


async def set_default_phy(tester):
    """LE Set Default PHY Command.

    Initial Condition:
        The IUT is in standby.

    Test Steps:
        The source describes an unnumbered procedure: the Upper Tester sends
        LE Set Default PHY with ALL_PHYS = 0x03 and TX_PHYS = RX_PHYS = 0
        (no preferences), then receives Command Complete.
        Check Success, the matching opcode and one command credit.

    Expected Outcome:
        Pass verdict: Command Complete returns Success.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BV-15-C;
        PDF/printed pages 161-162, Figure 4.90.
        Source reference [8], Section 7.8.48.
    """
    await tester.command(
        hci.HCI_LE_Set_Default_PHY_Command(
            hci.HCI_LE_ALL_PHYS_TX_MASK | hci.HCI_LE_ALL_PHYS_RX_MASK, 0, 0
        )
    )


async def read_periodic_list_size(tester):
    """LE Read Periodic Advertiser List Size Command.

    Initial Condition:
        The IUT is in standby. This DUT declares an eight-entry list.

    Test Steps:
        The source describes an unnumbered procedure: the Upper Tester sends
        LE Read Periodic Advertiser List Size and receives Command Complete
        containing the list size. Check Success, the corresponding opcode,
        command credit and the independently declared capacity of eight.

    Expected Outcome:
        Pass verdict: the command succeeds and reports eight entries. No minimum
        capacity is inferred from the needs of a different test procedure.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BV-16-C;
        PDF/printed pages 162-163, Figure 4.91.
        Source reference [9], Section 7.8.73.
    """
    result = await tester.command(
        hci.HCI_LE_Read_Periodic_Advertiser_List_Size_Command()
    )
    assert (
        result.periodic_advertiser_list_size == EXPECTED_PERIODIC_ADVERTISER_LIST_SIZE
    )


async def periodic_list_commands(tester):
    """LE Add/Remove/Clear Periodic Advertiser List Commands.

    Initial Condition:
        The IUT is in standby with an empty Periodic Advertiser List.

    Test Steps:
        1. Send LE Clear Periodic Advertiser List; require Command Complete
           with Status = Success (0x00).
        2. Add an arbitrarily chosen valid address, address type and SID;
           require successful Command Complete.
        3. Remove the step-2 identity; require successful Command Complete.
        4. Remove it again; require Command Complete with Unknown Advertising
           Identifier (0x42).
        5. Add the step-2 identity again; require successful Command Complete.
        6. Clear the list; require successful Command Complete.
        7. Add the step-2 identity again; require successful Command Complete.
        8. Add the identical entry again; require Command Complete with Invalid
           HCI Command Parameters (0x12).
        9. Add the same address and type but a different SID; require successful
           Command Complete.
        10. Add the same address and SID as step 2 but a different address type;
            require successful Command Complete.

    Expected Outcome:
        Pass verdict: all ten ordered commands succeed except the second remove
        (Unknown Advertising Identifier, 0x42) and duplicate add (0x12).
        Each completion has the matching opcode and one command credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BV-17-C;
        PDF/printed pages 163-165, steps 1-10 and Figure 4.92.
        Source reference [9], Sections 7.8.70, 7.8.71 and 7.8.72.
    """
    address = hci.Address('C0:34:56:78:9A:BC', hci.AddressType.PUBLIC_DEVICE)
    add = hci.HCI_LE_Add_Device_To_Periodic_Advertiser_List_Command
    remove = hci.HCI_LE_Remove_Device_From_Periodic_Advertiser_List_Command
    clear = hci.HCI_LE_Clear_Periodic_Advertiser_List_Command
    await tester.command(clear())
    await tester.command(add(address.address_type, address, 3))
    await tester.command(remove(address.address_type, address, 3))
    await tester.command(
        remove(address.address_type, address, 3),
        ErrorCode.UNKNOWN_ADVERTISING_IDENTIFIER_ERROR,
    )
    await tester.command(add(address.address_type, address, 3))
    await tester.command(clear())
    await tester.command(add(address.address_type, address, 3))
    await tester.command(
        add(address.address_type, address, 3),
        ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
    )
    await tester.command(add(address.address_type, address, 4))
    random_address = hci.Address(bytes(address), hci.AddressType.RANDOM_DEVICE)
    await tester.command(add(random_address.address_type, random_address, 3))


async def periodic_adi_not_supported(tester):
    """Invalid LE Set Periodic Advertising Enable Parameters, Periodic Advertising ADI
    Not Supported.

    Initial Condition:
        The IUT is in standby with compatible extended and periodic parameters.
        Its reported feature mask does not advertise periodic ADI support.

    Test Steps:
        1. Send LE Set Periodic Advertising Enable with Enable bits 0 and 1 set.
        2. Require Command Complete with a valid error status.
        3. Send the same command with Enable bit 0 clear and bit 1 set.
        4. Require Command Complete with a valid error status.

    Observation Setup:
        Verify the absent ADI feature and configure compatible extended and
        periodic parameters on handle zero before step 1, establishing the
        initial condition. Keep that handle in both enable commands.

    Expected Outcome:
        Pass verdict: both completions report valid nonzero errors with matching
        opcode and credit. The source does not prescribe one particular error.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BI-34-C;
        PDF/printed page 185, steps 1-4.
        Source reference [13], Section 7.8.63.
    """
    features = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    assert (
        not int.from_bytes(features.le_features, 'little')
        & hci.LeFeatureMask.PERIODIC_ADVERTISING_ADI_SUPPORT
    )
    await tester.command(extended_parameters())
    await tester.command(_periodic_parameters())
    errors = tuple(
        code
        for code in ErrorCode
        if code not in (ErrorCode.SUCCESS, ErrorCode.RESERVED_FOR_FUTURE_USE)
    )
    for enable in (0b11, 0b10):
        await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(enable, 0), errors
        )


async def invalid_data_length(tester):
    """LE Set Data Length, Invalid Parameters.

    Initial Condition:
        An ACL exists with the IUT in either role; select Central and a valid handle.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Upper Tester sends LE Set Data Length with TxTime = 17041 us.
        - The IUT returns Command Complete with Invalid Parameters (0x12).

    Observation Setup:
        Establish the ACL before the procedure and use its valid handle and
        permissible TxOctets = 27. Check the opcode, command credit, error
        status and returned handle shown in Figure 4.105, then disconnect
        in a separate postamble.

    Expected Outcome:
        Pass verdict: Command Complete returns 0x12, the submitted handle,
        matching command opcode and one command credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BI-40-C;
        PDF/printed page 190, Figure 4.105.
        Source reference [2], Section 7.8.33.
    """
    link = await establish(tester, central=True)
    command = hci.HCI_LE_Set_Data_Length_Command(
        link.handle, PDU_DATA_PAYLOAD_SIZE_MIN, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US + 1
    )
    await tester.wait(0)
    tester.send(bytes(command))
    event = await tester.expect(
        lambda event: (
            isinstance(event, hci.HCI_Command_Complete_Event)
            and event.command_opcode == command.op_code
        )
    )
    assert event.num_hci_command_packets == 1
    # The generic HCI decoder exposes only status for errors; inspect the wire handle.
    assert event.parameters[3:] == struct.pack(
        '<BH', ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR, link.handle
    )
    await link.disconnect(local=True)


async def invalid_channel_map_handle(tester):
    """LE Read Channel Map \u2013 Reject Invalid Handle.

    Initial Condition:
        Establish one valid ACL; either IUT role is permitted. Select Central.

    Test Steps:
        1. Send LE Read Channel Map with a Connection_Handle different from
           the established connection's handle.
        2. Require Command Complete with Unknown Connection Identifier (0x02).

    Observation Setup:
        Establish one ACL and retain its handle before step 1; select an unused
        handle for the command. Disconnect the valid ACL after step 2, not as
        part of the source procedure.

    Expected Outcome:
        Pass verdict: Command Complete returns 0x02, matching opcode and credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BI-43-C;
        PDF/printed pages 191-192, Figure 4.106.
        Source reference [13], Section 7.8.20.
    """
    link = await establish(tester, central=True)
    await tester.command(
        hci.HCI_LE_Read_Channel_Map_Command(link.handle + 1),
        ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
    )
    await link.disconnect(local=True)


async def invalid_periodic_parameters(tester):
    """LE Set Periodic Advertising Parameters, Invalid Parameters.

    Initial Condition:
        A valid advertising set is configured, without periodic advertising enabled.

    Test Steps:
        Repeat steps 1 and 2 for the rounds selected by Table 4.56:
        1. Send the selected Set Periodic Advertising Parameters command with
           the parameters of the Table 4.57 round.
        2. Require Command Complete with that round's prescribed status.

    Test Case Configuration:
        BI-64 selects v1, rounds 1 and 2 only: unknown handle with other values
        valid returns 0x42; Min greater than Max with other values valid returns
        0x12. Configure valid handle zero before the rounds; use unknown handle
        one in round 1, then handle zero with Min = 41, Max = 40 in round 2.
        The unselected BI-65 uses v2 and all Table 4.57 rounds.

    Expected Outcome:
        Pass verdict: Table 4.57 rounds 1 and 2 return 0x42 and 0x12 respectively,
        with matching opcode and credit. Table 4.56 assigns only these rows to v1.

    Source Correction:
        The shared Test Purpose mentions only v2, but Table 4.56 explicitly
        assigns BI-64 to v1 rounds 1-2. Follow that case-specific selection.
        Amber confirms the table/prose mismatch; no adopted erratum is claimed.

    Reference:
        HCI.TS.p39.pdf, Section 4.10.15, HCI/CCO/BI-64-C;
        PDF/printed pages 207-208, Tables 4.56 and 4.57.
        Source reference [17], Section 7.8.61.
    """
    await tester.command(extended_parameters())
    await tester.command(
        _periodic_parameters(advertising_handle=1),
        ErrorCode.UNKNOWN_ADVERTISING_IDENTIFIER_ERROR,
    )
    await tester.command(
        _periodic_parameters(periodic_advertising_interval_min=41),
        ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
    )


async def invalid_initiator_filter_policy(tester):
    """Reject LE Extended Create Connection with Invalid Initiator_Filter_Policy
    Parameters.

    Initial Condition:
        The IUT is not scanning, has no pending initiation, and does not declare
        Decision-based Advertising Filtering support.

    Test Steps:
        1. Send LE Extended Create Connection with Initiator_Filter_Policy
           different from 0x00 and 0x01; all other parameters are valid.
        2. Require Unsupported Feature or Parameter Value (0x11) for that command.

    Observation Setup:
        Verify the feature prerequisite through HCI before the source steps.
        Repeat both steps for policies 2, 3 and 255. The source does not prescribe
        separate numbered steps or additional requirements for those vectors.

    Expected Outcome:
        Pass verdict: Command Status with status 0x11, matching opcode and
        one command credit is required for every selected negative vector.

    Source Correction:
        Step 2 and the verdict name Command Complete, but Core Vol 4, Part E,
        Section 7.8.66 specifies Command Status for Extended Create Connection,
        including this unsupported-policy error. Amber confirms this event-name
        inconsistency; no adopted SIG erratum is claimed.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BI-72-C;
        PDF/printed page 214, steps 1-2; source reference [18], Section 7.8.66.
    """
    features = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    assert (
        not int.from_bytes(features.le_features, 'little')
        & hci.LeFeatureMask.DECISION_BASED_ADVERTISING_FILTERING
    )
    for policy in (2, 3, 255):
        await tester.command(
            create_connection(extended=True, initiator_filter_policy=policy),
            ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR,
        )


async def invalid_connection_event_lengths(tester):
    """LE Create Connection, Invalid Parameters.

    Initial Condition:
        The IUT is already initiating. No advertiser is present to complete it.

    Test Steps:
        1. Send LE Create Connection with Min_CE_Length greater than
           Max_CE_Length and all other parameters valid.
        2. Require Command Status with Invalid HCI Command Parameters (0x12).

    Observation Setup:
        Start a valid pending attempt before step 1 to establish the required
        Initiating state. For the invalid command, select Min_CE_Length = 1 and
        Max_CE_Length = 0. Cancel the original attempt after step 2 as a separate
        postamble, not as an additional source step.

    Expected Outcome:
        Pass verdict: the second command returns Command Status with 0x12,
        matching opcode and one available command credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.10, HCI/CCO/BI-134-C;
        PDF/printed pages 247-248, steps 1-2.
        Source reference [17], Section 7.8.12.
    """
    await tester.command(create_connection())
    await tester.command(
        create_connection(min_ce_length=1), ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR
    )
    await tester.command(hci.HCI_LE_Create_Connection_Cancel_Command())


PROCEDURES: ProcedureMap = {}

# Verify that an LE-only IUT rejects a BR/EDR Inquiry command.
PROCEDURES |= procedure_cases(
    bredr_not_supported,
    {
        'HCI/CCO/BV-07-C': (
            'BR/EDR Not Supported',
            {},
        ),
    },
)

# Verify successful Set Data Length and notification of changed limits.
PROCEDURES |= procedure_cases(
    set_data_length,
    {
        'HCI/CCO/BV-09-C': (
            'LE Set Data Length',
            {},
        ),
    },
)

# Verify the reset values reported by Read Suggested Default Data Length.
PROCEDURES |= procedure_cases(
    read_suggested_data_length,
    {
        'HCI/CCO/BV-10-C': (
            'LE Read Suggested Default Data Length Command',
            {},
        ),
    },
)

# Verify storage and readback of all prescribed default-data-length pairs.
PROCEDURES |= procedure_cases(
    write_suggested_data_length,
    {
        'HCI/CCO/BV-11-C': (
            'LE Write Suggested Default Data Length Command',
            {},
        ),
    },
)

# Verify that Set Default PHY accepts no-preference selections.
PROCEDURES |= procedure_cases(
    set_default_phy,
    {
        'HCI/CCO/BV-15-C': (
            'LE Set Default PHY Command',
            {},
        ),
    },
)

# Verify that Read Periodic Advertiser List Size returns the declared capacity.
PROCEDURES |= procedure_cases(
    read_periodic_list_size,
    {
        'HCI/CCO/BV-16-C': (
            'LE Read Periodic Advertiser List Size Command',
            {},
        ),
    },
)

# Verify add, remove and clear operations and address-type/SID identity.
PROCEDURES |= procedure_cases(
    periodic_list_commands,
    {
        'HCI/CCO/BV-17-C': (
            'LE Add/Remove/Clear Periodic Advertiser List Commands',
            {},
        ),
    },
)

# Verify rejection of both ADI-requesting Enable values when ADI is unsupported.
PROCEDURES |= procedure_cases(
    periodic_adi_not_supported,
    {
        'HCI/CCO/BI-34-C': (
            (
                'Invalid LE Set Periodic Advertising Enable Parameters, '
                'Periodic Advertising ADI Not Supported'
            ),
            {},
        ),
    },
)

# Verify rejection of TxTime one microsecond above its maximum.
PROCEDURES |= procedure_cases(
    invalid_data_length,
    {
        'HCI/CCO/BI-40-C': (
            'LE Set Data Length, Invalid Parameters',
            {},
        ),
    },
)

# Verify rejection of Read Channel Map for an unassigned ACL handle.
PROCEDURES |= procedure_cases(
    invalid_channel_map_handle,
    {
        'HCI/CCO/BI-43-C': (
            'LE Read Channel Map – Reject Invalid Handle',
            {},
        ),
    },
)

# Verify invalid-handle and reversed-interval errors for the selected v1 command.
PROCEDURES |= procedure_cases(
    invalid_periodic_parameters,
    {
        'HCI/CCO/BI-64-C': (
            (
                'LE Set Periodic Advertising Parameters, Invalid '
                'Parameters, HCI_LE_Set_Periodic_Advertising_Parameters '
                '[v1]'
            ),
            {},
        ),
    },
)

# Verify rejection of decision-based initiation when the feature is unsupported.
PROCEDURES |= procedure_cases(
    invalid_initiator_filter_policy,
    {
        'HCI/CCO/BI-72-C': (
            (
                'Reject LE Extended Create Connection with Invalid '
                'Initiator_Filter_Policy Parameters'
            ),
            {},
        ),
    },
)

# Verify rejection of Min_CE_Length greater than Max_CE_Length.
PROCEDURES |= procedure_cases(
    invalid_connection_event_lengths,
    {
        'HCI/CCO/BI-134-C': (
            'LE Create Connection, Invalid Parameters',
            {},
        ),
    },
)
RADIO_CASES = ('HCI/CCO/BV-09-C', 'HCI/CCO/BI-40-C', 'HCI/CCO/BI-43-C')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES, radio_cases=RADIO_CASES),
)
async def test_controller_configuration_commands(
    hci_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(hci_dut, identifier, description, procedure, parameters, marks)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES, radio_cases=RADIO_CASES, radio=True),
)
async def test_controller_configuration_radio(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
