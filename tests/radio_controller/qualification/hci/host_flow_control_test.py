# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.8: Host Flow Control."""

import pytest

from bumble import hci
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.tester import (
    PEER_ADDRESS,
    adv_pdu,
    scan_parameters,
)


async def scanning_event_mask(tester):
    """LE Set Event Mask \u2013 Scanning state.

    Initial Condition:
        No LL connection exists. The Lower Tester is ready to advertise; the IUT
        is configured for passive scanning with duplicate filtering disabled.

    Test Steps:
        1. Send Set Event Mask with general event bits 4, 7, 11, 15, 16, 47 and
           61 set; require successful Command Complete.
        2. Send the Table 4.25 LE Set Event Mask version with all bits set except
           bits 1 and 12; require successful Command Complete. BV-04 selects v1.
        3. Send LE Set Scan Enable with Scan_Enable = 0x01 and
           Filter_Duplicates = 0x00; require successful Command Complete.
        4. The Lower Tester begins advertising.
        5. After at least twenty advertisements, send the selected LE Set Event
           Mask command with bit 1 set; require successful Command Complete.
        6. The IUT sends at least two LE Advertising Report events.

    Observation Setup:
        Configure passive scan parameters before step 1. Inject twenty ADV_IND
        packets, verify that neither legacy nor extended reports are present
        before step 5, then inject two further advertisements to collect the
        required reports. Check their addresses and data as well. Disable
        scanning in a separate postamble after step 6.

    Expected Outcome:
        Pass verdict: all commands complete successfully with matching opcode
        and command credit. Reports are absent before step 5 and at least two
        reports are received afterward, with the Lower Tester's address and data.

    Reference:
        HCI.TS.p39.pdf, Section 4.8.1, Table 4.25 and Figure 4.57;
        HCI/HFC/BV-04-C, PDF/printed pages 120-122. Table 4.25 selects v1.
        Source reference [8], Sections 7.3.1 and 7.8.1.
    """
    report_types = (
        hci.HCI_LE_Advertising_Report_Event,
        hci.HCI_LE_Extended_Advertising_Report_Event,
    )
    await tester.command(scan_parameters())
    await tester.masks(
        general=sum(1 << bit for bit in (4, 7, 11, 15, 16, 47, 61)),
        le=((1 << 64) - 1)
        & ~(1 << (hci.HCI_LE_ADVERTISING_REPORT_EVENT - 1))
        & ~(1 << (hci.HCI_LE_EXTENDED_ADVERTISING_REPORT_EVENT - 1)),
    )
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))
    tester.events.clear()
    for _ in range(20):
        await tester.transmit(37, adv_pdu())
    await tester.wait(1000)
    assert not any(isinstance(event, report_types) for event in tester.events)
    await tester.command(
        hci.HCI_LE_Set_Event_Mask_Command(
            (1 << (hci.HCI_LE_ADVERTISING_REPORT_EVENT - 1)).to_bytes(8, 'little')
        )
    )
    for _ in range(2):
        await tester.transmit(37, adv_pdu())
        event = await tester.event(hci.HCI_LE_Advertising_Report_Event)
        assert len(event.reports) == 1
        assert event.reports[0].address == PEER_ADDRESS
        assert event.reports[0].data == b'test'
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))


PROCEDURES: ProcedureMap = {}

# Verify that LE Set Event Mask controls advertising reports while scanning.
PROCEDURES |= procedure_cases(
    scanning_event_mask,
    {
        'HCI/HFC/BV-04-C': (
            'LE Set Event Mask – Scanning state, v1',
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_host_flow_control(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
