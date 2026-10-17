# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.17: Event Versioning."""

import pytest

from bumble import hci
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.hci.device_discovery_test import (
    _start_scanning,
)
from tests.radio_controller.qualification.ll import security_test as security
from tests.radio_controller.qualification.peer import host_send
from tests.radio_controller.qualification.tester import create_connection, create_sync

ErrorCode = hci.HCI_ErrorCode
ReportDataStatus = hci.HCI_LE_Periodic_Advertising_Report_Event.DataStatus
# Core Vol 4, Part E, 7.3.69: explicit Page 2 mask position, not event code - 1.
ENCRYPTION_CHANGE_V2_MASK = 1 << 25
# HCI.TS.p39, 4.17.4: observe a masked report for at least 50 periodic events.
MASK_SETTLING_EVENTS = 50
ENCRYPTION_EVENTS = (
    hci.HCI_Encryption_Change_Event,
    hci.HCI_Encryption_Change_V2_Event,
)
SYNC_EVENTS = (
    hci.HCI_LE_Periodic_Advertising_Sync_Established_Event,
    hci.HCI_LE_Periodic_Advertising_Sync_Established_V2_Event,
)
REPORT_EVENTS = (
    hci.HCI_LE_Periodic_Advertising_Report_Event,
    hci.HCI_LE_Periodic_Advertising_Report_V2_Event,
)
CONNECTION_EVENTS = (
    hci.HCI_LE_Connection_Complete_Event,
    hci.HCI_LE_Enhanced_Connection_Complete_Event,
    hci.HCI_LE_Enhanced_Connection_Complete_V2_Event,
)


def _version_events(tester, family):
    events = []
    while (event := tester.take(lambda event: isinstance(event, family))) is not None:
        events.append(event)
    return events


def _version_result(tester, family, expected):
    """Reject wrong versions, duplicates and events from a fully masked family."""
    events = _version_events(tester, family)
    if expected is None:
        assert not events, 'masked event was delivered'
        return None
    assert len(events) == 1, 'expected exactly one event from the versioned family'
    assert type(events[0]) is expected, 'incorrect event version'
    return events[0]


def _periodic_reports(tester, handle, sent, *, enabled):
    """Validate all pending reports; the source permits more than one report."""
    events = _version_events(tester, REPORT_EVENTS)
    assert enabled or not events, 'masked periodic report was delivered'
    for report in events:
        assert type(report) is REPORT_EVENTS[0], 'incorrect periodic report version'
        assert report.sync_handle == handle
        assert report.data_status == ReportDataStatus.DATA_COMPLETE
        assert report.data in sent
    return bool(events)


async def _le_versions(tester, family, *, v1, v2):
    mask = (1 << 64) - 1
    for enabled, event_type in zip((v1, v2), family):
        mask &= ~(1 << (event_type.subevent_code - 1))
        if enabled:
            mask |= 1 << (event_type.subevent_code - 1)
    await tester.command(hci.HCI_LE_Set_Event_Mask_Command(mask.to_bytes(8, 'little')))


async def encryption_change_versions(tester, *, central):
    """Check correct handling of HCI Encryption Change event with two
    versions, LE.

    Initial Condition:
        Table 4.121 alternative A. HCI/EVV/BV-03-C selects Peripheral and
        LL/SEC/PER/BV-01-C; HCI/EVV/BV-05-C selects Central and
        LL/SEC/CEN/BV-01-C. Establish the selected role using the common public
        addresses, key preamble and encryption feature exchange.

    Test Steps:
        1. Enable both Encryption Change v1 and v2 event masks.
        2. Execute the selected LL Encryption Mode Setup through its Encryption
           Change event: deliver 1000 zero octets in ten-octet HCI ACL packets,
           exchange SKD/IV, supply the LTK and complete the encrypted handshake.
        3. Select alternative 3A: receive exactly one Encryption Change v1.
        4. The Lower Tester terminates the connection; establish a new one in
           the same role.
        5. Enable Encryption Change v2 and mask v1.
        6. Execute the same LL procedure through Encryption Change.
        7. Select alternative 7A: receive no Encryption Change event.
        8. The Lower Tester terminates the connection; establish a new one in
           the same role.
        9. Enable Encryption Change v1 and mask v2.
        10. Execute the same LL procedure through Encryption Change.
        11. Receive exactly one Encryption Change v1.

    Expected Outcome:
        Pass verdict:
            Steps 3A.1 and 11 report successful v1 with the established handle
            and encryption enabled. Step 7A.1 emits neither version. The
            independently encrypted peer verifies the LL handshake and MICs.

    Source Correction:
        Steps 1, 5 and 9 incorrectly name LE Set Event Mask. Encryption Change
        is not an LE Meta subevent. Use Set Event Mask bit 7 for v1 and Set
        Event Mask Page 2 bit 25 for v2, per Core Vol 4 Part E 7.3.1/7.3.69.
        Amber confirms this local correction, not an adopted specification erratum.

    Reference:
        HCI.TS.p39.pdf, 4.17.2, Table 4.121, Steps 1-11 and alternative A;
        PDF/printed 374-375; source [17] 7.7.8. Referenced LL procedures:
        LL.TS.p28, 4.8.6/4.8.7, through Encryption Change, not their later
        encrypted-data, termination and random-address repetition steps.
    """
    for v1, v2 in ((True, True), (False, True), (True, False)):
        link = await security._security_link(tester, central)
        general = (1 << 64) - 1
        if not v1:
            general &= ~(1 << (hci.HCI_ENCRYPTION_CHANGE_EVENT - 1))
        await tester.command(
            hci.HCI_Set_Event_Mask_Command(general.to_bytes(8, 'little'))
        )
        await tester.command(
            hci.HCI_Set_Event_Mask_Page_2_Command(
                (ENCRYPTION_CHANGE_V2_MASK if v2 else 0).to_bytes(8, 'little')
            )
        )
        await security._feature_exchange(link, ping=False)
        for _ in range(
            security.MODE_SETUP_TOTAL_OCTETS // security.MODE_SETUP_DATA_SIZE
        ):
            await host_send(tester, link, bytes(security.MODE_SETUP_DATA_SIZE))
        await security._begin(tester, link)
        await security._finish(tester, link, check_event=False)
        event = _version_result(
            tester,
            ENCRYPTION_EVENTS,
            hci.HCI_Encryption_Change_Event if v1 else None,
        )
        if event is not None:
            assert event.status == ErrorCode.SUCCESS
            assert event.connection_handle == link.handle
            assert event.encryption_enabled == (
                hci.HCI_Encryption_Change_Event.Enabled.E0_OR_AES_CCM
            )
        await link.disconnect(local=False)
        _version_result(tester, ENCRYPTION_EVENTS, None)


async def periodic_sync_established_versions(tester):
    """Check correct handling of LE Periodic Advertising Sync Established
    event with two versions.

    Initial Condition:
        The IUT scans. Table 4.122 alternative A: only v1 is supported.

    Test Steps:
        1. Begin ongoing ADV_EXT_IND/AUX_ADV_IND announcements. AuxPtr points
           to the secondary PDU, whose AdvA identifies the Lower Tester and
           whose SyncInfo points to AUX_SYNC_IND packets that are never sent.
        2. Require an Extended Advertising Report with a nonzero periodic
           interval and complete Data Status.
        3. Enable both Sync Established v1 and v2 in LE Event Mask.
        4. Send Create Sync; require successful Command Status.
        5. Send Create Sync Cancel; require successful Command Complete.
        6. Select alternative 6A.1: receive Sync Established v1.
        7. Enable Sync Established v2 and mask v1.
        8. Send Create Sync; require successful Command Status.
        9. Send Create Sync Cancel; require successful Command Complete.
        10. Select alternative 10A.1: receive no Sync Established event.
        11. Enable Sync Established v1 and mask v2.
        12. Send Create Sync; require successful Command Status.
        13. Send Create Sync Cancel; require successful Command Complete.
        14. Receive Sync Established v1 with the cancellation status.

    Expected Outcome:
        Pass verdict:
            Steps 6A.1 and 14 deliver v1 with Operation Cancelled by Host;
            Step 10A.1 emits neither version. Every command returns its
            expected event type, opcode, command credit and success status.

    Source Correction:
        Step 14 says 0x3E although Step 13 successfully cancels the request.
        Use 0x44 per Core Vol 4 Part E 7.8.68; 0x3E belongs to synchronization
        timeout under 7.8.67. The pass verdict's final event reference is
        Step 14, not command Step 12. Amber confirms these Core-backed local
        corrections; they are not claimed as adopted specification errata.

    Coverage Note:
        Continue the associated announcements without transmitting any periodic
        PDU. A selected 10-ms post-cancel observation interval gives the masked
        family additional execution opportunities before inspecting its queue.

    Reference:
        HCI.TS.p39.pdf, 4.17.3, HCI/EVV/BV-07-C, Table 4.122, Steps 1-14
        and alternative A; PDF/printed 375-376; source [17] 7.7.65.14.
    """
    train = await _start_scanning(tester)
    for v1, v2 in ((True, True), (False, True), (True, False)):
        await _le_versions(tester, SYNC_EVENTS, v1=v1, v2=v2)
        await tester.command(create_sync(sync_timeout=200))
        await tester.command(
            hci.HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command()
        )
        await train.announce(tester)
        await tester.wait(10_000)
        event = _version_result(tester, SYNC_EVENTS, SYNC_EVENTS[0] if v1 else None)
        if event is not None:
            assert event.status == ErrorCode.OPERATION_CANCELLED_BY_HOST_ERROR
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def periodic_report_versions(tester):
    """Check correct handling of LE Periodic Advertising Report event with
    two versions.

    Initial Condition:
        The IUT scans and is synchronized to the Lower Tester's ongoing
        periodic advertising. Table 4.123 alternative A: only v1 is supported.

    Test Steps:
        1. Enable both Periodic Advertising Report v1 and v2 in LE Event Mask.
        2. Select alternative 2A.1: receive at least one v1 periodic report.
        3. Enable Periodic Advertising Report v2 and mask v1.
        4. Select alternative 4A.1: observe at least 50 periodic events and
           require no Periodic Advertising Report event of either version.
        5. Enable Periodic Advertising Report v1 and mask v2.
        6. Continue periodic events for at least 50 events or until a v1
           report is received. Require the v1 report.

    Expected Outcome:
        Pass verdict:
            Steps 2A.1 and 6 return v1 reports with the selected sync handle
            and exact transmitted data. Step 4A.1 emits neither version.

    Coverage Note:
        Establish synchronization before Step 1. The setup report is consumed
        separately; it cannot satisfy Step 2. Inject one complete periodic PDU
        per event. The source note's 'periodic connection events' refers to
        periodic advertising events in this unconnected synchronization test.
        Allow 50 events for the v1 mask to settle before the separate 50-event
        no-report observation. Transient v1 reports in that selected grace
        window cannot fail the mask transition; v2 reports are never accepted.

    Reference:
        HCI.TS.p39.pdf, 4.17.4, HCI/EVV/BV-09-C, Table 4.123, Steps 1-6
        and settling note; PDF/printed 376-377; source [17] 7.7.65.15.
    """
    train = await _start_scanning(tester)
    await tester.command(create_sync(sync_timeout=200))
    await train.announce(tester)
    await train.transmit(tester, b'setup')
    sync = await tester.event(hci.HCI_LE_Periodic_Advertising_Sync_Established_Event)
    assert sync.status == ErrorCode.SUCCESS
    report = _version_result(tester, REPORT_EVENTS, REPORT_EVENTS[0])
    assert report.sync_handle == sync.sync_handle and report.data == b'setup'
    sent = {b'setup'}
    for v1, v2 in ((True, True), (False, True), (True, False)):
        await _le_versions(tester, REPORT_EVENTS, v1=v1, v2=v2)
        if not v1:
            for _ in range(MASK_SETTLING_EVENTS):
                sent.add(b'settling')
                await train.transmit(tester, b'settling')
                _periodic_reports(tester, sync.sync_handle, sent, enabled=True)
        seen = False
        for index in range(MASK_SETTLING_EVENTS):
            data = bytes([v1, v2, index])
            sent.add(data)
            await train.transmit(tester, data)
            seen = _periodic_reports(tester, sync.sync_handle, sent, enabled=v1)
            if seen:
                break
        assert seen == v1, 'no v1 report within the periodic observation window'
    await tester.command(
        hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(sync.sync_handle)
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def central_connection_complete_versions(tester):
    """Check correct handling of LE Enhanced Connection Complete Event
    with two versions and legacy LE Connection Complete Event, Central.

    Initial Condition:
        Standby. Table 4.125 alternative B; no advertiser can complete the
        pending connection before its explicit Host cancellation.

    Test Steps:
        1. Enable legacy Connection Complete and Enhanced Connection Complete
           v1 and v2 with LE Set Event Mask.
        2. Send legacy Create Connection; require successful Command Status.
        3. Send Create Connection Cancel; require successful Command Complete.
        4. Select alternative 4B.1: receive Enhanced Connection Complete v1
           with a valid failure status.
        5. Disable legacy completion, enable enhanced v2 and mask enhanced v1.
        6. Send Create Connection; require successful Command Status.
        7. Send Create Connection Cancel; require successful Command Complete.
        8. Select alternative 8B.1: receive no legacy or enhanced completion.
        9. Disable legacy completion, enable enhanced v1 and mask enhanced v2.
        10. Send Create Connection; require successful Command Status.
        11. Send Create Connection Cancel; require successful Command Complete.
        12. Select alternative 12B.1: receive Enhanced Connection Complete v1
            with a valid failure status.
        13. Enable legacy completion and mask both enhanced versions.
        14. Send Create Connection; require successful Command Status.
        15. Send Create Connection Cancel; require successful Command Complete.
        16. Receive legacy Connection Complete with a valid failure status.

    Expected Outcome:
        Pass verdict:
            Steps 4B.1 and 12B.1 select enhanced v1, Step 8B.1 emits no version,
            and Step 16 selects legacy. All emitted events carry the failed
            establishment status specified for Create Connection cancellation.

    Reference:
        HCI.TS.p39.pdf, 4.17.6, HCI/EVV/BV-14-C, Table 4.125,
        Steps 1-16 and alternative B; PDF/printed 379-381; source [17] 7.7.65.1.
        Core Vol 4 Part E 7.8.13 defines the cancellation result status.
    """
    legacy, v1, v2 = CONNECTION_EVENTS
    for enabled, expected in (
        ((legacy, v1, v2), v1),
        ((v2,), None),
        ((v1,), v1),
        ((legacy,), legacy),
    ):
        mask = sum(1 << (kind.subevent_code - 1) for kind in enabled)
        await tester.command(
            hci.HCI_LE_Set_Event_Mask_Command(mask.to_bytes(8, 'little'))
        )
        await tester.command(create_connection())
        await tester.command(hci.HCI_LE_Create_Connection_Cancel_Command())
        event = _version_result(tester, CONNECTION_EVENTS, expected)
        if event is not None:
            assert event.status == ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR


PROCEDURES: ProcedureMap = {}

# Verify Encryption Change event-version selection under both-enabled, v2-only and
# v1-only masks for an LE Controller supporting only v1.
PROCEDURES |= procedure_cases(
    encryption_change_versions,
    {
        'HCI/EVV/BV-03-C': (
            (
                'Check correct handling of HCI Encryption Change event with'
                ' two versions, LE'
            ),
            {'central': False},
        ),
        'HCI/EVV/BV-05-C': (
            (
                'Check correct handling of HCI Encryption Change event with'
                ' two versions, LE'
            ),
            {'central': True},
        ),
    },
)

# Verify periodic report-version selection for both-enabled, v2-only and v1-only event
# masks, including the mask-settling observation period.
PROCEDURES |= procedure_cases(
    periodic_report_versions,
    {
        'HCI/EVV/BV-09-C': (
            (
                'Check correct handling of LE Periodic Advertising Report '
                'event with two versions'
            ),
            {},
        ),
    },
)

# Verify Sync Established version selection under both-enabled, v2-only and v1-only LE
# event masks.
PROCEDURES |= procedure_cases(
    periodic_sync_established_versions,
    {
        'HCI/EVV/BV-07-C': (
            (
                'Check correct handling of LE Periodic Advertising Sync '
                'Established event with two versions'
            ),
            {},
        ),
    },
)

# Verify selection between legacy and enhanced v1/v2 connection-complete events for a
# Central supporting enhanced v1 but not v2.
PROCEDURES |= procedure_cases(
    central_connection_complete_versions,
    {
        'HCI/EVV/BV-14-C': (
            (
                'Check correct handling of LE Enhanced Connection Complete '
                'Event with two versions and legacy LE Connection Complete '
                'Event, Central'
            ),
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_event_versioning(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
