# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.4: Device Setup."""

import pytest

from bumble import hci
from bumble.ll import (
    LL_CONN_INTERVAL_UNIT_US,
    LL_EVENT_COUNTER_MASK,
    LL_SUPERVISION_TIMEOUT_UNIT_US,
    AdvertisingPduType,
    LlId,
)
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.peer import establish, host_send, peer_send
from tests.radio_controller.qualification.tester import (
    adv_pdu,
    create_connection,
    legacy_parameters,
    scan_parameters,
)

# Local observation periods; the source does not prescribe these durations.
ADVERTISING_OBSERVATION_US = 200_000
POST_PACKET_OBSERVATION_US = 1000
OBSERVATION_PACKETS = 5


async def reset_in_advertising_state(tester):
    """Reset in Advertising State.

    Initial Condition:
        The IUT is advertising connectable undirected ADV_IND packets. The
        independent Lower Tester listens on enabled primary channel 37.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Lower Tester receives ADV_IND packets from the advertising IUT.
        - The Upper Tester sends Reset and receives Command Complete with
          Status = Success.
        - The Lower Tester receives no further ADV_IND packets from the IUT.

    Observation Setup:
        Configure and enable advertising to establish the initial condition.
        Receive five packets, checking packet type, length and CRC. After Reset,
        listen for 200 ms, longer than the configured interval plus advDelay.
        These counts and durations are local choices, not source requirements.

    Expected Outcome:
        Pass verdict: Reset completes with Success, matching opcode and one
        command credit; no further ADV_IND is transmitted after completion.
        The observation period and packet count are local test choices, not
        additional numerical requirements from the source.

    Reference:
        HCI.TS.p39.pdf, Section 4.4, independently titled procedure
        HCI/DSU/BV-02-C, Figure 4.5; PDF/printed page 33.
        Source reference [1], Section 7.3.2.
    """
    await tester.command(legacy_parameters())
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    for _ in range(OBSERVATION_PACKETS):
        await tester.expect_pdu(kind=AdvertisingPduType.ADV_IND)
    await tester.command(hci.HCI_Reset_Command())
    assert await tester.receive(37, duration_us=ADVERTISING_OBSERVATION_US) is None


async def _observe_reset_connection(tester, link):
    """Observe each original connection anchor until its supervision timeout."""
    await tester.command(hci.HCI_Reset_Command())
    deadline = (
        tester.radio.now_us + link.parameters.timeout * LL_SUPERVISION_TIMEOUT_UNIT_US
    )
    while link.anchor < deadline:
        channel = link.channel
        if not link.central:
            # The independent Central continues sending despite the reset.
            await link._send(channel, b'', LlId.CONTINUATION, link.anchor)
        assert (
            await tester.receive(
                channel,
                start_us=max(tester.radio.now_us + 1, link.anchor - 1),
                duration_us=max(
                    POST_PACKET_OBSERVATION_US,
                    link.anchor - tester.radio.now_us + POST_PACKET_OBSERVATION_US,
                ),
                **link.radio_parameters,
            )
            is None
        )
        link.anchor += link.parameters.interval * LL_CONN_INTERVAL_UNIT_US
        link.counter = (link.counter + 1) & LL_EVENT_COUNTER_MASK


async def reset_to_peripheral(tester):
    """Reset to Peripheral.

    Initial Condition:
        An LE ACL exists; the IUT is Peripheral and the independent Lower
        Tester is Central.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Lower Tester sends data to the IUT and receives confirmation.
        - The Upper Tester sends Reset and receives Command Complete with
          Status = Success.
        - The Lower Tester continues sending data and receives no IUT packets
          until the connection timeout expires.

    Observation Setup:
        Establish the ACL for the initial condition and retain its channel and
        timer state. Verify LL acknowledgement and exact HCI ACL delivery before
        Reset. Then send empty data PDUs and listen at the original anchors
        through the supervision timeout. The source MSC permits an optional
        LL_TERMINATE_IND before Command Complete, not after it.

    Expected Outcome:
        Pass verdict: Reset returns Success with matching opcode and one credit;
        no IUT data packets occur after its completion through the timeout.
        A termination before completion is optional in the source MSC.

    Reference:
        HCI.TS.p39.pdf, Section 4.4, independently titled procedure
        HCI/DSU/BV-03-C, Figure 4.6; PDF/printed page 34.
        Source reference [1], Section 7.3.2.
    """
    link = await establish(tester, central=False)
    await peer_send(tester, link, b'data')
    await _observe_reset_connection(tester, link)


async def reset_in_scanning_state(tester):
    """Reset in Scanning State.

    Initial Condition:
        The IUT passively scans; the independent Lower Tester sends ADV_IND.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Upper Tester receives LE Advertising Report from the scanning IUT.
        - The Upper Tester sends Reset and receives Command Complete with
          Status = Success.
        - The Upper Tester receives no further LE Advertising Reports.

    Observation Setup:
        Enable passive scanning and inject five advertisements, requiring a
        report for each. After Reset, restore event masks so mask suppression
        cannot hide continued scanning. Send five more advertisements and
        inspect HCI events after each packet and a 1 ms observation period.
        Mask restoration, counts and durations are local observation choices.

    Expected Outcome:
        Pass verdict: Reset completes successfully with matching opcode and one
        credit, and the IUT emits no further LE Advertising Report events.
        Re-enabling masks is an additional observation safeguard.

    Reference:
        HCI.TS.p39.pdf, Section 4.4, independently titled procedure
        HCI/DSU/BV-04-C, Figure 4.7; PDF/printed page 35.
        Source reference [1], Section 7.3.2.
    """
    await tester.command(scan_parameters())
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))
    for _ in range(OBSERVATION_PACKETS):
        await tester.transmit(37, adv_pdu())
        await tester.event(hci.HCI_LE_Advertising_Report_Event)
    await tester.command(hci.HCI_Reset_Command())
    tester.events.clear()
    await tester.masks()
    for _ in range(OBSERVATION_PACKETS):
        await tester.transmit(37, adv_pdu())
        await tester.wait(POST_PACKET_OBSERVATION_US)
        assert not any(
            isinstance(event, hci.HCI_LE_Advertising_Report_Event)
            for event in tester.events
        )


async def reset_in_initiating_state(tester):
    """Reset in Initiating State.

    Initial Condition:
        The independent Lower Tester is idle. The IUT enters Initiating with
        LE Create Connection targeting that Lower Tester's address.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Upper Tester sends LE Create Connection and receives Command
          Status with Status = Success.
        - The Upper Tester sends Reset and receives Command Complete with
          Status = Success.
        - After that completion, the Lower Tester sends ADV_IND packets and
          receives no CONNECT_REQ packets from the IUT.

    Observation Setup:
        Restore event masks after Reset so suppression cannot hide a connection
        completion. Send five advertisements, listening for CONNECT_IND and
        checking HCI events after each. CONNECT_REQ is the source's name for
        the legacy connection-request PDU represented as CONNECT_IND here.
        The extra event-mask commands and packet count are local safeguards.

    Expected Outcome:
        Pass verdict: Reset returns Success with matching opcode and one credit.
        No CONNECT_IND or LE Connection Complete is generated after completion;
        the enhanced completion event is also forbidden.

    Reference:
        HCI.TS.p39.pdf, Section 4.4, independently titled procedure
        HCI/DSU/BV-05-C, Figure 4.8; PDF/printed pages 36-37.
        Source reference [1], Section 7.3.2.
    """
    await tester.command(create_connection())
    await tester.command(hci.HCI_Reset_Command())
    tester.events.clear()
    await tester.masks()
    for _ in range(OBSERVATION_PACKETS):
        await tester.transmit(37, adv_pdu())
        assert await tester.receive(37, duration_us=POST_PACKET_OBSERVATION_US) is None
        assert not any(
            isinstance(
                event,
                (
                    hci.HCI_LE_Connection_Complete_Event,
                    hci.HCI_LE_Enhanced_Connection_Complete_Event,
                ),
            )
            for event in tester.events
        )


async def reset_to_central(tester):
    """Reset to Central.

    Initial Condition:
        An LE ACL exists; the IUT is Central and the independent Lower Tester
        is Peripheral.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Lower Tester receives IUT data packets and sends confirmation.
        - The Upper Tester sends Reset and receives Command Complete with
          Status = Success.
        - The Lower Tester receives no IUT packets until the connection timeout
          expires.

    Observation Setup:
        Establish the ACL for the initial condition. Submit Host data and verify
        exact on-air delivery, LL acknowledgement and the HCI completed-packet
        credit before Reset. Listen on every original connection anchor through
        the supervision timeout. The source MSC permits an optional
        LL_TERMINATE_IND before Command Complete, not after it.

    Expected Outcome:
        Pass verdict: Reset returns Success with matching opcode and one credit;
        the IUT sends no further data packets after completion through timeout.
        A termination before completion is optional in the source MSC.

    Reference:
        HCI.TS.p39.pdf, Section 4.4, independently titled procedure
        HCI/DSU/BV-06-C, Figure 4.9; PDF/printed pages 37-38.
        Source reference [1], Section 7.3.2.
    """
    link = await establish(tester, central=True)
    await host_send(tester, link, b'data')
    await _observe_reset_connection(tester, link)


PROCEDURES: ProcedureMap = {}

# Verify that Reset moves an advertising LE Controller to Standby.
PROCEDURES |= procedure_cases(
    reset_in_advertising_state,
    {
        'HCI/DSU/BV-02-C': (
            'Reset in advertising state',
            {},
        ),
    },
)

# Verify that Reset moves an LE Peripheral to Standby and loses its ACL.
PROCEDURES |= procedure_cases(
    reset_to_peripheral,
    {
        'HCI/DSU/BV-03-C': (
            'Reset to Peripheral',
            {},
        ),
    },
)

# Verify that Reset stops LE Advertising Report events from a scanning IUT.
PROCEDURES |= procedure_cases(
    reset_in_scanning_state,
    {
        'HCI/DSU/BV-04-C': (
            'Reset in scanning state',
            {},
        ),
    },
)

# Verify that Reset stops initiation without establishing a connection.
PROCEDURES |= procedure_cases(
    reset_in_initiating_state,
    {
        'HCI/DSU/BV-05-C': (
            'Reset in initiating state',
            {},
        ),
    },
)

# Verify that Reset moves an LE Central to Standby and loses its ACL.
PROCEDURES |= procedure_cases(
    reset_to_central,
    {
        'HCI/DSU/BV-06-C': (
            'Reset to Central',
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_device_setup(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
