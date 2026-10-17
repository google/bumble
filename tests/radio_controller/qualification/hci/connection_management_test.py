# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.13: LE Connection Management."""

import pytest

from bumble import hci
from bumble.ll import LL_ADV_PRIMARY_CHANNELS
from bumble.radio_controller.radio import Phy
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.peer import establish
from tests.radio_controller.qualification.tester import (
    PEER_ADDRESS,
    adv_pdu,
    create_connection,
)

ErrorCode = hci.HCI_ErrorCode
PUBLIC_PEER = hci.Address(bytes(PEER_ADDRESS), hci.AddressType.PUBLIC_DEVICE)


async def read_phy(tester):
    """LE Read PHY Command.

    Initial Condition:
        Establish an LE 1M ACL with the Lower Tester; either IUT role is allowed.
        This vector selects the IUT as Peripheral.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Upper Tester sends LE Read PHY with the current connection handle.
        - The IUT returns Command Complete containing that handle and TX_PHY /
          RX_PHY values matching the active connection.

    Observation Setup:
        Establish the LE 1M Peripheral ACL before the procedure. Check Success,
        matching opcode, command credit, handle and both PHY fields. Disconnect
        in a separate postamble, not an additional source step.

    Expected Outcome:
        Pass verdict: the command succeeds, returns the submitted handle, and
        reports LE 1M for TX and RX, matching the established link.

    Reference:
        HCI.TS.p39.pdf, Section 4.13, HCI/CM/BV-03-C;
        PDF/printed page 281, Figure 4.135.
        Source reference [9], Section 7.8.47.
    """
    link = await establish(tester)
    result = await tester.command(hci.HCI_LE_Read_PHY_Command(link.handle))
    assert result.connection_handle == link.handle
    assert result.tx_phy == result.rx_phy == Phy.LE_1M
    await link.disconnect()


async def unsupported_initiating_phys(tester):
    """LE Extended Create Connection With Unsupported PHY.

    Initial Condition:
        The IUT has no connection or pending initiation. It declares support for
        LE 1M, LE 2M and LE Coded; the other five mask bits are RFU.

    Test Steps:
        The source describes an unnumbered repeated procedure. For each RFU
        or unsupported Initiating_PHYs bit, send Extended Create Connection
        with only that bit set and otherwise valid parameters, and receive
        an error response. This implementation covers all eight bit positions,
        excluding the declared supported 1M, 2M and Coded bits.

    Expected Outcome:
        Pass verdict: every unsupported bit is rejected with 0x11, the matching
        opcode and one credit in Command Status. The source explicitly passes
        without stimuli if all eight bits are supported; that branch does not
        apply to this DUT.

    Source Correction:
        The prose, Figure 4.139 and verdict name Command Complete. Core Vol 4,
        Part E, Section 7.8.66 defines Command Status for this command, including
        unsupported PHY rejection. Amber supports that event-name correction;
        it is not claimed as adopted SIG errata.

    Reference:
        HCI.TS.p39.pdf, Section 4.13, HCI/CM/BI-01-C;
        PDF/printed page 287, Figure 4.139; source reference [9], Section 7.8.66.
    """
    supported = hci.PhyBit.LE_1M | hci.PhyBit.LE_2M | hci.PhyBit.LE_CODED
    for bit in range(8):
        if not supported & (1 << bit):
            await tester.command(
                create_connection(extended=True, initiating_phys=1 << bit),
                ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR,
            )


async def cancel_without_pending_attempt(tester, *, extended=False):
    """LE Create Connection Cancel, Command Disallowed.

    Initial Condition:
        No IUT initiation is pending. The Lower Tester uses a public address
        and advertises ADV_IND on all supported primary channels until connected.

    Test Steps:
        1. Send LE Create Connection Cancel.
        2. Require Command Complete with Command Disallowed (0x0C).
        3. Send the Table 4.87 connect command with Peer_Address_Type = 0x00
           and the Lower Tester's public address; require successful Command
           Status. BI-02 selects legacy, BI-03 selects Extended Create Connection.
        4. The Lower Tester begins sending ADV_IND on supported primary channels.
        5. Receive the IUT's CONNECT_IND following an ADV_IND.
        6. Receive connection completion with the public peer's address/type.
        7. Send LE Create Connection Cancel again.
        8. Require Command Complete with Command Disallowed (0x0C).

    Observation Setup:
        Before step 1, enable the connection-complete subevent selected by the
        command contract: legacy for BI-02, enhanced for BI-03. Require that
        exact event type during establishment. Disconnect after step 8.

    Expected Outcome:
        Pass verdict: both Cancel commands return Command Complete with 0x0C,
        matching opcode and credit. Creation succeeds with the public peer.

    Source Correction:
        The verdict's steps 3 and 8 mean steps 2 and 8: step 3 is successful
        command submission, not a failed Cancel response. Step 6's legacy event
        name applies to BI-02; for Extended Create Connection in BI-03, use
        Enhanced Connection Complete per Core Vol 4, Part E, Section 7.8.66.
        Amber supports these Core-consistent readings, not adopted errata.

    Reference:
        HCI.TS.p39.pdf, Section 4.13.1, HCI/CM/BI-02-C and HCI/CM/BI-03-C;
        PDF/printed pages 289-290, Table 4.87 and Figure 4.141, steps 1-8.
        Source reference [11], Section 7.8.13.
    """
    complete = (
        hci.HCI_LE_Enhanced_Connection_Complete_Event
        if extended
        else hci.HCI_LE_Connection_Complete_Event
    )
    await tester.masks(le=1 << (complete.subevent_code - 1))
    await tester.command(
        hci.HCI_LE_Create_Connection_Cancel_Command(),
        ErrorCode.COMMAND_DISALLOWED_ERROR,
    )
    link = await establish(
        tester,
        central=True,
        extended=extended,
        peer_address=PUBLIC_PEER,
        advertising_channels=LL_ADV_PRIMARY_CHANNELS,
        connection_complete_event=complete,
    )
    await tester.command(
        hci.HCI_LE_Create_Connection_Cancel_Command(),
        ErrorCode.COMMAND_DISALLOWED_ERROR,
    )
    await link.disconnect(local=True)


async def reject_connected_peer(tester, *, extended=False):
    """Connection Attempt Rejected When Connected to the Peer.

    Initial Condition:
        The Lower Tester advertises ADV_IND with a public address on all primary
        channels and continues advertising after the first connection.

    Test Steps:
        1. Send the Table 4.88 connect command with Peer_Address_Type = 0x00
           and the Lower Tester's public address; require successful Command Status.
        2. The Lower Tester begins sending ADV_IND on supported primary channels.
        3. Receive the IUT's CONNECT_IND following an ADV_IND.
        4. Receive the Table 4.88 connection-complete event with the public peer's
           address/type: legacy for BI-04, enhanced for BI-05.
        5. The Lower Tester continues sending ADV_IND.
        6. Send the same Table 4.88 command with the same public peer address/type.
        7. Select the IUT's response alternative:
           7A.1. Command Status returns Connection Already Exists (0x0B).
           7B.1. Alternatively, receive successful Command Status.
           7B.2. Then require the Table 4.88 connection-complete event with
                 Status = Connection Already Exists (0x0B).

    Observation Setup:
        Enable the exact Table 4.88 completion subevent before step 1, rather
        than treating legacy and enhanced events as interchangeable. Advertise
        on all supported primary channels. After step 7, verify the original
        ACL still exchanges data, then disconnect in a separate postamble.

    Expected Outcome:
        Pass verdict: alternative 7A returns Command Status with 0x0B, or
        alternative 7B returns successful status followed by connection completion
        with 0x0B. The original connection is not replaced or corrupted.

    Reference:
        HCI.TS.p39.pdf, Section 4.13.2, HCI/CM/BI-04-C and HCI/CM/BI-05-C;
        PDF/printed pages 290-292, Table 4.88 and Figure 4.142.
        Source reference [11], Sections 7.8.12 and 7.8.66.
    """
    complete = (
        hci.HCI_LE_Enhanced_Connection_Complete_Event
        if extended
        else hci.HCI_LE_Connection_Complete_Event
    )
    await tester.masks(le=1 << (complete.subevent_code - 1))
    link = await establish(
        tester,
        central=True,
        extended=extended,
        peer_address=PUBLIC_PEER,
        advertising_channels=LL_ADV_PRIMARY_CHANNELS,
        connection_complete_event=complete,
    )
    for channel in LL_ADV_PRIMARY_CHANNELS:
        await tester.transmit(channel, adv_pdu(address=PUBLIC_PEER))
    result = await tester.command(
        create_connection(
            extended=extended,
            peer_address=PUBLIC_PEER,
            peer_address_type=PUBLIC_PEER.address_type,
        ),
        (ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR, ErrorCode.SUCCESS),
    )
    if result.status == ErrorCode.SUCCESS:
        event = await tester.event(complete)
        assert type(event) is complete
        assert event.status == ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR
    await link.exchange()
    await link.disconnect(local=True)


PROCEDURES: ProcedureMap = {}

# Verify the connection handle and current transmit/receive PHY from Read PHY.
PROCEDURES |= procedure_cases(
    read_phy,
    {
        'HCI/CM/BV-03-C': (
            'LE Read PHY Command',
            {},
        ),
    },
)

# Verify rejection of each unsupported or RFU Initiating_PHYs bit.
PROCEDURES |= procedure_cases(
    unsupported_initiating_phys,
    {
        'HCI/CM/BI-01-C': (
            'LE Extended Create Connection With Unsupported PHY',
            {},
        ),
    },
)

# Verify Cancel rejection when no legacy or extended creation is pending.
PROCEDURES |= procedure_cases(
    cancel_without_pending_attempt,
    {
        'HCI/CM/BI-02-C': (
            'LE Create Connection Cancel, Command Disallowed',
            {},
        ),
        'HCI/CM/BI-03-C': (
            'LE Create Connection Cancel, Command Disallowed',
            {'extended': True},
        ),
    },
)

# Verify rejection of a second connection attempt to an already connected peer.
PROCEDURES |= procedure_cases(
    reject_connected_peer,
    {
        'HCI/CM/BI-04-C': (
            'Connection Attempt Rejected When Connected to the Peer',
            {},
        ),
        'HCI/CM/BI-05-C': (
            'Connection Attempt Rejected When Connected to the Peer',
            {'extended': True},
        ),
    },
)
RADIO_CASES = tuple(
    identifier for identifier in PROCEDURES if identifier != 'HCI/CM/BI-01-C'
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES, radio_cases=RADIO_CASES),
)
async def test_connection_management_commands(
    hci_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(hci_dut, identifier, description, procedure, parameters, marks)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES, radio_cases=RADIO_CASES, radio=True),
)
async def test_connection_management_radio(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
