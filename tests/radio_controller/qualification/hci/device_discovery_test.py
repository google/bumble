# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.7: Device Discovery."""

import random
import warnings

import pytest

from bumble import hci
from bumble.ll import (
    LL_ADV_PRIMARY_CHANNELS,
    LL_PERIODIC_INTERVAL_MAX,
    LL_PERIODIC_INTERVAL_MIN,
    AdvertisingPduType,
)
from bumble.radio_controller.radio import Phy
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.periodic import (
    PeriodicAdvertiser,
    PeriodicTrain,
)
from tests.radio_controller.qualification.tester import (
    PEER_ADDRESS,
    LinkParameters,
    adv_pdu,
    create_sync,
    extended_enable,
    extended_parameters,
    legacy_parameters,
    receive_extended,
    scan_parameters,
)

ErrorCode = hci.HCI_ErrorCode
Properties = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties
)
AdvType = hci.HCI_LE_Set_Advertising_Parameters_Command.AdvertisingType
Operation = hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation


def _advertising_parameters(properties=0, **changes):
    return extended_parameters(
        advertising_event_properties=properties,
        peer_address_type=hci.AddressType.PUBLIC_DEVICE,
        peer_address=hci.Address(bytes(PEER_ADDRESS), hci.AddressType.PUBLIC_DEVICE),
        **changes,
    )


def _periodic_parameters(**changes):
    values = {
        'advertising_handle': 0,
        'periodic_advertising_interval_min': 40,
        'periodic_advertising_interval_max': 40,
        'periodic_advertising_properties': 0,
    }
    return hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(**(values | changes))


async def _configure_periodic_set(tester, *, with_data=False):
    """Create a compatible set in standby for a periodic command procedure."""
    await tester.command(_advertising_parameters())
    await tester.command(_periodic_parameters())
    if with_data:
        await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
                0, Operation.COMPLETE_DATA, random.Random(0).randbytes(1)
            )
        )


async def _start_scanning(tester):
    await tester.command(scan_parameters(extended=True))
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    train = PeriodicTrain(tester.radio.now_us + 100_000)
    await train.announce(tester)
    event = await tester.event(hci.HCI_LE_Extended_Advertising_Report_Event)
    (report,) = event.reports
    assert report.address == PEER_ADDRESS and report.advertising_sid == 3
    assert report.periodic_advertising_interval == train.interval
    assert (report.event_type >> hci.HCI_LE_EXT_ADV_REPORT_DATA_STATUS_SHIFT) == 0
    return train


async def advertising_disable(tester):
    """Set Advertising Enable.

    Initial Condition:
        The IUT is advertising connectable undirected ADV_IND on the enabled primary
        channel.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Lower Tester receives ADV_IND packets from the advertising IUT.
        - The Upper Tester sends LE Set Advertising Enable with Enable = Disabled
          and receives Command Complete with Status = Success.
        - The Lower Tester receives no further ADV_IND packets from the IUT.

    Observation Setup:
        Configure and enable advertising to establish the initial condition.
        Receive five valid ADV_IND packets before disabling, then listen for
        200 ms, longer than the configured interval plus advDelay. These counts
        and durations are local choices, not source requirements.

    Expected Outcome:
        Pass verdict: matching Command Complete returns Success and one credit; no
        ADV_IND follows completion.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, HCI/DDI/BV-03-C, Figure 4.27; PDF/printed page 61.
        Source reference [8], Section 7.8.10.
    """
    await tester.command(legacy_parameters())
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(1))
    for _ in range(5):
        await tester.expect_pdu(kind=AdvertisingPduType.ADV_IND)
    await tester.command(hci.HCI_LE_Set_Advertising_Enable_Command(0))
    assert await tester.receive(37, duration_us=200_000) is None


async def scanning_disable(tester):
    """Set Scan Enable.

    Initial Condition:
        The IUT passively scans; the independent Lower Tester advertises ADV_IND.

    Test Steps:
        The source describes an unnumbered procedure:
        - The Upper Tester receives LE Advertising Report from the scanning IUT.
        - The Upper Tester sends LE Set Scan Enable with Scan Enable = Disabled
          and receives Command Complete with Status = Success.
        - The Upper Tester receives no further LE Advertising Reports after
          that command completion.

    Observation Setup:
        Establish passive scanning and require reports for five advertisements
        before disabling. Then send five more advertisements without changing
        event masks, checking HCI after each transmission and a 1 ms observation
        period. These counts and durations are local observation choices.

    Expected Outcome:
        Pass verdict: the disabling command returns Success with matching opcode and one
        credit; no further Advertising Report follows completion.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, HCI/DDI/BV-04-C, Figure 4.28; PDF/printed pages
        62-63.
        Source reference [8], Section 7.8.12.
    """
    await tester.command(scan_parameters())
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(1, 0))
    for _ in range(5):
        await tester.transmit(37, adv_pdu(), start_us=tester.radio.now_us + 100)
        await tester.event(hci.HCI_LE_Advertising_Report_Event)
    await tester.command(hci.HCI_LE_Set_Scan_Enable_Command(0, 0))
    tester.events.clear()
    for _ in range(5):
        await tester.transmit(37, adv_pdu())
        await tester.wait(1000)
        assert not any(
            isinstance(event, hci.HCI_LE_Advertising_Report_Event)
            for event in tester.events
        )


async def extended_interval_bounds(tester):
    """Reject Invalid Extended Advertising Parameters.

    Initial Condition:
        The IUT is not advertising. The declared interval range is 0x000020 through
        0xFFFFFF, with nonconnectable, non-scannable legacy properties.

    Test Steps:
        The source describes an unnumbered procedure:
        - Send Extended Advertising Parameters with the declared legacy event
          properties, Min = IXIT minimum minus two, Max = IXIT minimum minus one.
        - If the declared maximum is 0xFFFFFF, end with Pass after checking the
          response. This is the selected branch for this full-range DUT.
        - Otherwise send Min = IXIT maximum plus one; set Max to that same value
          if IXIT maximum is 0xFFFFFE, or to IXIT maximum plus two otherwise.
          This branch is not applicable to this DUT's declared maximum.

    Expected Outcome:
        Pass verdict: below-0x20 parameters return Unsupported Feature or Invalid
        Parameters, matching opcode and one command credit.
        The source requires 0x11 for rejected IXIT values that remain within
        the protocol's encodable interval range; below 0x20 it permits 0x11 or
        0x12, as exercised here.

    Source Correction:
        Figure 4.29's 0xFFFFE boundary omits an F. Use 0xFFFFFE from the source
        prose, consistent with the 24-bit fields in Core Vol 4, Part E,
        Section 7.8.53. Amber supports this reading, not an adopted erratum.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, HCI/DDI/BI-01-C, Figure 4.29; PDF/printed pages
        63-64.
        Source reference [9], Section 7.8.53.
    """
    await tester.command(
        _advertising_parameters(
            Properties.USE_LEGACY_ADVERTISING_PDUS,
            primary_advertising_interval_min=hci.HCI_LE_ADV_INTERVAL_MIN - 2,
            primary_advertising_interval_max=hci.HCI_LE_ADV_INTERVAL_MIN - 1,
        ),
        (
            ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
            ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR,
        ),
    )


async def invalid_parameters(tester):
    """Reject Invalid Advertising Parameters.

    Initial Condition:
        Standby; declared legacy intervals are 0x0020 through 0x4000.

    Test Steps:
        The source describes an unnumbered two-command procedure:
        - Send Set Advertising Parameters with Advertising_Type = 0x03
          (ADV_NONCONN_IND), Min = IXIT minimum minus two and Max = IXIT minimum
          minus one.
        - Send the same command and type with Min = IXIT maximum plus one and
          Max = IXIT maximum plus two, applying the source correction below.

    Expected Outcome:
        Pass verdict: both out-of-range commands are rejected with correct opcodes and
        one command credit. For either field outside 0x0020 through 0x4000, the
        source permits 0x11 or 0x12; otherwise it requires 0x11 for an interval
        outside a narrower manufacturer's IXIT range. Both rounds here are
        outside the full protocol range, so either allowed error is accepted.

    Source Correction:
        The second command repeats Advertising_Interval_Max for both fields.
        Interpret it as Min = IXIT maximum plus one, Max = IXIT maximum plus
        two. Core Vol 4, Part E, Section 7.8.5 defines the distinct fields and
        Min <= Max. Amber supports this interpretation as a clerical field-name
        duplication; no adopted SIG erratum is claimed.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, HCI/DDI/BI-02-C; PDF/printed page 65.
        Source reference [9], Section 7.8.5.
    """
    for minimum, maximum in (
        (hci.HCI_LE_ADV_INTERVAL_MIN - 2, hci.HCI_LE_ADV_INTERVAL_MIN - 1),
        (hci.HCI_LE_ADV_INTERVAL_MAX + 1, hci.HCI_LE_ADV_INTERVAL_MAX + 2),
    ):
        await tester.command(
            legacy_parameters(
                advertising_type=AdvType.ADV_NONCONN_IND,
                advertising_interval_min=minimum,
                advertising_interval_max=maximum,
            ),
            (
                ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
                ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR,
            ),
        )


async def periodic_interval_bounds(tester):
    """Reject Invalid Periodic Advertising Parameters.

    Initial Condition:
        Periodic advertising is disabled and a valid default extended set exists.
        This DUT declares the supported periodic range 0x0006 through 0xFFFF.

    Test Steps:
        The source describes an unnumbered procedure:
        - Send Set Periodic Advertising Parameters with Min = IXIT minimum
          minus two and Max = IXIT minimum minus one.
        - If the declared maximum is 0xFFFF, end with Pass after checking the
          response. This is the selected branch for this full-range DUT.
        - Otherwise send Min = IXIT maximum plus one; set Max to that same value
          if IXIT maximum is 0xFFFE, or to IXIT maximum plus two otherwise.
          This branch is not applicable to this DUT's declared maximum.

    Observation Setup:
        Configure the default extended set before the source procedure to
        establish the initial condition. Do not enable periodic advertising.

    Expected Outcome:
        Pass verdict: the below-0x0006 command completes with status 0x11 or
        0x12, matching opcode and credit. No overflowing HCI value is transmitted.
        For rejected IXIT values not below 0x0006, the source requires 0x11.

    Source Correction:
        The pass verdict calls these Primary_Advertising_Interval fields.
        Use Periodic_Advertising_Interval_Min/Max, the parameters of the tested
        command in Core Vol 4, Part E, Section 7.8.61. Amber confirms this
        command/field mismatch; no adopted SIG erratum is claimed.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled HCI/DDI/BI-67-C;
        PDF/printed pages 65-67, Figure 4.30.
        Source reference [9], Section 7.8.61.
    """
    await tester.command(_advertising_parameters())
    assert LL_PERIODIC_INTERVAL_MAX == 0xFFFF
    await tester.command(
        _periodic_parameters(
            periodic_advertising_interval_min=LL_PERIODIC_INTERVAL_MIN - 2,
            periodic_advertising_interval_max=LL_PERIODIC_INTERVAL_MIN - 1,
        ),
        (
            ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR,
            ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
        ),
    )


async def duplicate_periodic_sync(tester):
    """Reject LE Periodic Advertising Create Sync Command to a Synchronized Advertising
    Set.

    Initial Condition:
        The IUT scans three trains sharing address/type, with SIDs 3/4/3 and distinct
        Access Addresses and CRC initializers; it receives SyncInfo for all three.

    Test Steps:
        1. The Upper Tester sends Periodic Advertising Create Sync for the first
           train's address, address type and SID, with Options bit 0 = 0.
        2. Require Command Status with Status = Success (0x00).
        3. Wait for LE Periodic Advertising Sync Established.
        4. Send Create Sync again with the first train's identity and bit 0 = 0.
        5. Require Command Status with Connection Already Exists (0x0B).
        6. Send Create Sync for the second train's identity and bit 0 = 0.
        7. Require Command Status with Success; Memory Capacity Exceeded
           (0x07) makes the result Inconclusive.
        8. Wait for Sync Established; Memory Capacity Exceeded makes the
           result Inconclusive.
        9. The Lower Tester stops the first periodic train and continues the
           second and third trains.
        10. Send Create Sync for the first train's identity and bit 0 = 0.
        11. Require Command Status with Connection Already Exists (0x0B) or
            Memory Capacity Exceeded (0x07).
        12. Send Terminate Sync with the first train's Sync_Handle from step 3.
        13. Require Command Complete with Status = Success (0x00).
        14. Send Create Sync with the first train's identity and bit 0 = 0.
        15. Require Command Status with Success; Memory Capacity Exceeded
            makes the result Inconclusive.
        16. Wait for Sync Established; Memory Capacity Exceeded makes the
            result Inconclusive. The third train now has the requested identity
            because it shares the first train's address, address type and SID.

    Observation Setup:
        Establish the initial condition by announcing all three trains and
        checking their reports before step 1. Accepted synchronizations must
        report the expected address, SID and periodic data. Distinct active
        identities must retain distinct handles. Continue the remaining two
        trains and validate their independent reports after step 16, then
        terminate both handles. These extra checks are not source steps.

    Expected Outcome:
        Pass verdict: each Create Sync returns the prescribed Command Status and, when
        accepted, successful Sync Established with correct identity. A stopped train
        retains its identity reservation until explicit termination, without replacing
        another handle.
        Inconclusive verdict: Memory Capacity Exceeded in steps 7, 8, 15 or 16;
        this implementation reports that branch as a pytest skip, never Pass.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, HCI/DDI/BI-04-C, Figure 4.32, steps 1-16;
        PDF/printed pages 69-71.
        Source reference [12], Section 7.8.67.
    """
    await tester.command(scan_parameters(extended=True))
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    now = tester.radio.now_us
    trains = [
        PeriodicTrain(
            now + offset, access_address=0x9A328370 ^ index, crc_init=0x123456 ^ index
        )
        for index, offset in enumerate((40_000, 70_000, 100_000))
    ]
    sids = (3, 4, 3)

    async def announce(indices, *, observe=False):
        for index in indices:
            while tester.take(
                lambda event: isinstance(
                    event, hci.HCI_LE_Extended_Advertising_Report_Event
                )
            ):
                pass
            for channel in LL_ADV_PRIMARY_CHANNELS:
                await trains[index].announce(
                    tester, sid=sids[index], primary_channel=channel
                )
            if observe:
                event = await tester.event(hci.HCI_LE_Extended_Advertising_Report_Event)
                assert event.reports
                for report in event.reports:
                    assert report.address == PEER_ADDRESS
                    assert report.address_type == PEER_ADDRESS.address_type
                    assert report.advertising_sid == sids[index]
                    assert (
                        report.periodic_advertising_interval == trains[index].interval
                    )

    # Establish the source precondition before any Create Sync command.
    await announce(range(3), observe=True)
    handles = []
    for index, sid in enumerate(sids):
        allowed = (
            (ErrorCode.SUCCESS,)
            if index == 0
            else (ErrorCode.SUCCESS, ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR)
        )
        result = await tester.command(
            create_sync(advertising_sid=sid, sync_timeout=200), allowed
        )
        if result.status == ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR:
            pytest.skip('Inconclusive: insufficient periodic synchronization capacity')
        await announce(range(3) if index < 2 else (1, 2))
        await trains[index].transmit(tester, bytes([sid]))
        event = await tester.event(
            hci.HCI_LE_Periodic_Advertising_Sync_Established_Event
        )
        if index and event.status == ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR:
            pytest.skip('Inconclusive: insufficient periodic synchronization capacity')
        assert event.status == ErrorCode.SUCCESS and event.advertising_sid == sid
        assert event.advertiser_address == PEER_ADDRESS
        handles.append(event.sync_handle)
        report = await tester.event(hci.HCI_LE_Periodic_Advertising_Report_Event)
        assert report.sync_handle == event.sync_handle and report.data == bytes([sid])
        if index == 0:
            await tester.command(
                create_sync(advertising_sid=3, sync_timeout=200),
                ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR,
            )
        if index == 1:
            assert handles[0] != handles[1]
            # Stop train zero. Send the other trains in chronological order.
            await announce((1, 2))
            for active in sorted((1, 2), key=lambda item: trains[item].anchor):
                await trains[active].transmit(tester, bytes([sids[active]]))
                if active == 1:
                    report = await tester.event(
                        hci.HCI_LE_Periodic_Advertising_Report_Event
                    )
                    assert report.sync_handle == handles[1]
                    assert report.data == bytes([sids[1]])
            await tester.command(
                create_sync(advertising_sid=3, sync_timeout=200),
                (
                    ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR,
                    ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR,
                ),
            )
            await tester.command(
                hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handles[0])
            )
    assert handles[1] != handles[2]
    for index in sorted((1, 2), key=lambda item: trains[item].anchor):
        await trains[index].transmit(tester, bytes([index]))
        report = await tester.event(hci.HCI_LE_Periodic_Advertising_Report_Event)
        assert report.sync_handle == handles[index] and report.data == bytes([index])
    for handle in handles[1:]:
        await tester.command(
            hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle)
        )


async def periodic_advertiser_list_identity(tester):
    """Connect to one periodic advertising train, Periodic Advertiser List.

    Initial Condition:
        Three ongoing periodic trains share the same address, type and SID.
        Their intervals are 20, 25 and 30 ms; first PA2 and PA3 are offset
        from PA1 by 2 and 5 ms respectively. The IUT scans extended advertising
        and receives SyncInfo for all three. Distinct Access Addresses and CRC
        initializers distinguish the RF trains without changing their identity.

    Test Steps:
        1. Add the shared advertiser identity to the Periodic Advertiser List;
           require successful Command Complete.
        2. Add the same address/type with a different SID; require success.
        3. Continue all three trains with their initial address, type and SID.
        4. At a reproducibly randomized time, send Create Sync with Options
           bit 0 set; require successful Command Status.
        5. Require successful Sync Established. Its periodic interval
           identifies which of the three trains was selected.
        6. Stop advertising the selected train.
        7. Send Create Sync again with Options bit 0 set; require success.
        8. For at least 3000 ms, continue the remaining trains and require no
           Sync Established event and no loss of the original synchronization.
        9. Stop one remaining periodic advertiser.
        10. Change that advertiser's SID to the alternate SID added in Step 2.
        11. Resume advertising that train with its new SID.
        12. Require successful Sync Established with the changed train's
            interval, address/type and new SID.

    Expected Outcome:
        Pass verdict:
            Step 5 synchronizes to one original train. Step 8 does not create
            another synchronization to the occupied identity. Step 12 creates
            a distinct synchronization for the changed SID, with the expected
            train interval. Every HCI command has the required response.

    Source Correction:
        Step 3 says the trains have different addresses/SIDs, contradicting
        the initial condition, purpose and later SID change. Preserve the
        shared identity, consistent with Core Vol 6 Part B 4.4.5.1 and
        Vol 4 Part E 7.8.67. Use a selected 10-second Sync_Timeout so that
        Step 8 observes duplicate suppression, not legitimate loss of sync.
        Amber supports this local clarification, not an adopted erratum.

    Coverage Note:
        Drive the independent periodic transmitters and their announcements
        chronologically. Identify the selected train from the actual HCI
        interval rather than assuming which train wins. No synchronization is
        terminated until after Step 12; the changed SID must use another handle.

    Reference:
        HCI.TS.p39.pdf, standalone HCI/DDI/BV-12-C, Figure 4.53,
        Steps 1-12; PDF/printed 114-116; source [12] 7.8.67.
    """
    events = (
        hci.HCI_LE_Periodic_Advertising_Sync_Established_Event,
        hci.HCI_LE_Periodic_Advertising_Sync_Established_V2_Event,
    )
    await tester.command(scan_parameters(extended=True))
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0))
    base = tester.radio.now_us + 100_000
    advertisers = [
        PeriodicAdvertiser(
            PeriodicTrain(
                base + offset,
                interval=interval,
                access_address=LinkParameters.access_address ^ index,
                crc_init=LinkParameters.crc_init ^ index,
            ),
            next_advertisement=tester.radio.now_us + 100,
            advertising_interval_us=20_000,
            address=PEER_ADDRESS,
        )
        for index, (interval, offset) in enumerate(((16, 0), (20, 2000), (24, 5000)))
    ]
    for advertiser in advertisers:
        for channel in LL_ADV_PRIMARY_CHANNELS:
            await advertiser.train.announce(tester, primary_channel=channel)
        event = await tester.event(hci.HCI_LE_Extended_Advertising_Report_Event)
        assert event.reports
        for report in event.reports:
            assert report.address == PEER_ADDRESS
            assert report.address_type == PEER_ADDRESS.address_type
            assert report.advertising_sid == advertiser.sid
            assert report.periodic_advertising_interval == advertiser.train.interval
        while tester.take(lambda item: isinstance(item, type(event))) is not None:
            pass

    for sid in (3, 4):
        await tester.command(
            hci.HCI_LE_Add_Device_To_Periodic_Advertiser_List_Command(
                PEER_ADDRESS.address_type, PEER_ADDRESS, sid
            )
        )
    active = set(range(len(advertisers)))
    generator = random.Random(0)

    async def transmit_next():
        index = min(active, key=lambda index: advertisers[index].train.anchor)
        await advertisers[index].transmit(tester, bytes([index]))

    async def synchronized():
        deadline = tester.radio.now_us + 1_000_000
        while tester.radio.now_us < deadline:
            await transmit_next()
            if (
                event := tester.take(lambda item: isinstance(item, events))
            ) is not None:
                assert type(event) is events[0]
                assert event.status == ErrorCode.SUCCESS
                assert event.advertiser_address == PEER_ADDRESS
                assert event.advertiser_address_type == PEER_ADDRESS.address_type
                return event
        raise AssertionError('no synchronization within the selected tester budget')

    await tester.wait(generator.randrange(2000))
    await tester.command(create_sync(options=1, sync_timeout=1000))
    first = await synchronized()
    assert first.advertising_sid == 3
    selected = next(
        index
        for index, advertiser in enumerate(advertisers)
        if advertiser.train.interval == first.periodic_advertising_interval
    )
    active.remove(selected)
    await tester.command(create_sync(options=1, sync_timeout=1000))
    until = tester.radio.now_us + 3_000_000
    while tester.radio.now_us < until:
        await transmit_next()
        assert tester.take(lambda item: isinstance(item, events)) is None
        assert (
            tester.take(
                lambda item: isinstance(
                    item, hci.HCI_LE_Periodic_Advertising_Sync_Lost_Event
                )
            )
            is None
        )
    changed = generator.choice(sorted(active))
    advertisers[changed].sid = 4
    second = await synchronized()
    assert second.advertising_sid == 4
    assert second.periodic_advertising_interval == advertisers[changed].train.interval
    assert second.sync_handle != first.sync_handle
    for handle in (first.sync_handle, second.sync_handle):
        await tester.command(
            hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(handle)
        )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def unsupported_scan_phys(tester):
    """LE Set Extended Scan Parameters With Unsupported PHY.

    Initial Condition:
        The IUT is not scanning; its declared scanning PHYs are LE 1M and LE Coded.

    Test Steps:
        The source describes an unnumbered repeated procedure. For each RFU bit
        or unsupported PHY bit in Scanning_PHYs:
        - Send LE Set Extended Scan Parameters with only that bit set and all
          other parameters valid.
        - Receive Command Complete with an error status.
        This implementation enumerates all eight one-bit values and supplies
        one parameter block for each selected bit.

    Expected Outcome:
        Pass verdict: every unsupported selection returns 0x11, matching opcode and one
        credit; supported PHYs are excluded from the negative vectors.
        The source explicitly passes without stimuli if all eight PHY bits
        are supported. That branch does not apply to this DUT's 1M/Coded mask.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, HCI/DDI/BI-05-C, Figure 4.33; PDF/printed page 72.
        Source reference [9], Section 7.8.64.
    """
    supported = hci.PhyBit.LE_1M | hci.PhyBit.LE_CODED
    for bit in range(8):
        if supported & (1 << bit):
            continue
        await tester.command(
            scan_parameters(extended=True, scanning_phys=1 << bit),
            ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR,
        )


async def invalid_extended_advertising_enable(tester):
    """Reject Invalid Extended Advertising Enable Command.

    Initial Condition:
        The IUT is in standby with a configured scannable extended set and no
        scan-response data for its handle.

    Test Steps:
        1. Send LE Set Extended Advertising Enable with Enable = 0x01,
           Number_Of_Sets = 0x01 and the existing Advertising_Handle; all other
           parameters are valid.
        2. Require Command Complete with Command Disallowed (0x0C).
        3. Send LE Set Extended Advertising Enable with Enable = 0x01 and
           Number_Of_Sets = 0x00, with all other applicable parameters valid.
        4. Require Command Complete with Invalid HCI Command Parameters (0x12).

    Observation Setup:
        Configure the scannable set without scan-response data to establish
        the initial condition before step 1.

    Source Correction:
        Step 3 also mentions an existing Advertising_Handle, but zero sets
        means no handle/duration/event-count array entries on the wire. Send
        only Enable = 1 and Number_Of_Sets = 0, not an undeclared handle entry.
        Core Vol 4, Part E, Section 7.8.56 defines this format and 0x12 result;
        Amber confirms the copied-field inconsistency, not an adopted erratum.

    Expected Outcome:
        Pass verdict: the two enable commands return Command Complete with
        status 0x0C and 0x12 respectively, matching opcode and one command credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled procedure
        HCI/DDI/BI-12-C; PDF/printed pages 74-75, steps 1-4.
        Source reference [9], Section 7.8.56; Figure 4.35.
    """
    await tester.command(
        extended_parameters(
            advertising_event_properties=Properties.SCANNABLE_ADVERTISING
        )
    )
    await tester.command(extended_enable(), ErrorCode.COMMAND_DISALLOWED_ERROR)
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Enable_Command(1, [], [], []),
        ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
    )


async def invalid_periodic_advertising_enable(tester):
    """Reject Invalid Periodic Advertising Enable Command.

    Initial Condition:
        Standby, with compatible extended and periodic parameters on one handle.

    Test Steps:
        1. Send LE Set Periodic Advertising Data with Operation = FIRST_FRAGMENT
           (0x01) and nonzero Advertising_Data_Length.
        2. Require Command Complete with Status = Success (0x00).
        3. Send LE Set Periodic Advertising Enable with Enable = 0x01 and
           Advertising_Handle equal to the existing handle.
        4. Require Command Complete with Command Disallowed (0x0C).

    Observation Setup:
        Configure compatible extended and periodic parameters before step 1
        to establish the source initial condition; do not enable advertising.

    Expected Outcome:
        Pass verdict: the incomplete data is accepted, but enable returns
        status 0x0C with matching opcode and a command credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled procedure
        HCI/DDI/BI-13-C; PDF/printed page 75, steps 1-4.
        Source reference [9], Section 7.8.63.
    """
    await tester.command(extended_parameters())
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(0, 40, 40, 0)
    )
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
            0, Operation.FIRST_FRAGMENT, b'test'
        )
    )
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0),
        ErrorCode.COMMAND_DISALLOWED_ERROR,
    )


async def periodic_fragments_while_enabled(tester):
    """Reject LE Set Periodic Advertising Data setting the fragment when periodic
    advertising is enabled.

    Initial Condition:
        The IUT is advertising with periodic advertisements. Configure one set
        with complete data and enable its associated and periodic advertising.

    Test Steps:
        Repeat steps 1 and 2 for all three Table 4.15 rounds: Operation = 0x00
        (intermediate fragment), 0x01 (first fragment), 0x02 (last fragment).
        1. Send LE Set Periodic Advertising Data with the selected Operation.
        2. Require Command Complete with Command Disallowed (0x0C).

    Observation Setup:
        Configure compatible extended/periodic parameters, provide complete
        periodic data and enable associated and periodic advertising before
        the first round. Retain the same advertising handle in every round.

    Expected Outcome:
        Pass verdict: all three fragmentation commands return status 0x0C,
        matching command opcode and one command credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled procedure
        HCI/DDI/BI-14-C; PDF/printed pages 75-76, Table 4.15.
        Source reference [13], Section 7.8.62.
    """
    await tester.command(extended_parameters())
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(0, 40, 40, 0)
    )
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
            0, Operation.COMPLETE_DATA, b'test'
        )
    )
    await tester.command(extended_enable())
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0))
    for operation in (
        Operation.INTERMEDIATE_FRAGMENT,
        Operation.FIRST_FRAGMENT,
        Operation.LAST_FRAGMENT,
    ):
        await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Data_Command(0, operation, b'test'),
            ErrorCode.COMMAND_DISALLOWED_ERROR,
        )


async def incompatible_parameters_during_periodic_advertising(tester, *, properties):
    """Reject Set Extended Advertising Parameters Command using a Periodic Advertising
    Set and Incompatible Advertising is Specified.

    Initial Condition:
        An advertising set exists with at most 31 data octets. Use handle zero
        with initially compatible extended properties and one periodic data octet.

    Test Steps:
        1. Send LE Set Extended Advertising Parameters with a valid handle and
           Advertising_Event_Properties = 0x00.
        2. Require Command Complete with Status = Success (0x00).
        3. Send LE Set Periodic Advertising Parameters with the handle from step 1.
        4. Require Command Complete with Status = Success (0x00).
        5. Send LE Set Periodic Advertising Data with that handle and the
           specified data. This implementation selects one complete data octet.
        6. Require Command Complete with Status = Success (0x00).
        7. Send LE Set Periodic Advertising Enable with Enable = 1.
        8. Require Command Complete with Status = Success (0x00).
        9. Send LE Set Extended Advertising Parameters with the same handle and
           the advertising properties selected by Table 4.16.
        10. Require Command Complete with Invalid HCI Command Parameters (0x12).

    Test Case Configuration:
        Table 4.16 selects BI-15 through BI-25 in this mask order: 0x20, 0x24,
        0x13, 0x15, 0x1D, 0x12, 0x10, 0x01, 0x05, 0x02, 0x06. The registered
        case's properties parameter selects one row, not multiple procedures.

    Expected Outcome:
        Pass verdict: the final command returns status 0x12 for each selected
        Table 4.16 row. Every completion identifies the command and returns a credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.7.2, Table 4.16, steps 1-10;
        HCI/DDI/BI-15-C through HCI/DDI/BI-25-C; PDF/printed pages 76-78.
        Source reference [12], Section 7.8.53; Figure 4.36.
    """
    await _configure_periodic_set(tester, with_data=True)
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0))
    await tester.command(
        _advertising_parameters(properties), ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR
    )


async def incompatible_periodic_parameters(tester, *, properties):
    """Reject Set Periodic Advertising Parameters Command when the Associated Handle
    Specifies Incompatible Advertising.

    Initial Condition:
        An advertising set with no more than 31 data octets exists where the
        selected advertising type requires one. Advertising remains disabled.

    Test Steps:
        1. Set Extended Advertising Parameters with the Table 4.17 property mask
           selected by the case, using the specified advertising set if required.
        2. Require successful Command Complete.
        3. Send Set Periodic Advertising Parameters with the handle from step 1.
        4. Require Command Complete with Invalid HCI Command Parameters (0x12).

    Test Case Configuration:
        Table 4.17 selects BI-26 through BI-36 in this mask order: 0x20, 0x24,
        0x13, 0x15, 0x1D, 0x12, 0x10, 0x01, 0x05, 0x02, 0x06. The initial
        advertising data is empty, satisfying the at-most-31-octet condition.

    Expected Outcome:
        Pass verdict: each Table 4.17 row is rejected with status 0x12, matching
        opcode and a command credit. Initial extended parameters must succeed.

    Reference:
        HCI.TS.p39.pdf, Section 4.7.3, Table 4.17, steps 1-4;
        HCI/DDI/BI-26-C through HCI/DDI/BI-36-C; PDF/printed pages 78-79.
        Source reference [12], Section 7.8.61; Figure 4.37.
    """
    await tester.command(_advertising_parameters(properties))
    await tester.command(
        _periodic_parameters(), ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR
    )


async def incompatible_periodic_enable(tester, *, properties):
    """Reject Set Periodic Advertising Enable Command when the Associated Handle
    Specifies Incompatible Advertising.

    Initial Condition:
        An advertising set exists with no more than 31 data octets where needed;
        both associated advertising and periodic advertising are disabled.

    Test Steps:
        1. Send LE Set Extended Advertising Parameters with a valid handle and
           Advertising_Event_Properties = 0x00.
        2. Require successful Command Complete.
        3. Send LE Set Periodic Advertising Parameters with the handle from step 1.
        4. Require Command Complete with Status = Success (0x00).
        5. Send LE Set Extended Advertising Parameters with the same handle and
           advertising type selected by Table 4.18.
        6. Require successful Command Complete.
        7. Send LE Set Periodic Advertising Enable with the handle from step 5
           and Enable = 1.
        8. Require Command Complete with Command Disallowed (0x0C).

    Test Case Configuration:
        Table 4.18 selects BI-37 through BI-47 in this mask order: 0x20, 0x24,
        0x13, 0x15, 0x1D, 0x12, 0x10, 0x01, 0x05, 0x02, 0x06. The initial
        advertising data is empty, satisfying the at-most-31-octet condition.

    Expected Outcome:
        Pass verdict: each Table 4.18 row returns status 0x0C for periodic enable,
        matching opcode and a credit; all preceding commands must succeed.

    Reference:
        HCI.TS.p39.pdf, Section 4.7.4, Table 4.18, steps 1-8;
        HCI/DDI/BI-37-C through HCI/DDI/BI-47-C; PDF/printed pages 79-81.
        Source reference [13], Section 7.8.63; Figure 4.38.
    """
    await _configure_periodic_set(tester)
    await tester.command(_advertising_parameters(properties))
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0),
        ErrorCode.COMMAND_DISALLOWED_ERROR,
    )


async def default_extended_scan_enable(tester):
    """Default Extended Scan Enable Command.

    Initial Condition:
        Standby after Reset; Set Extended Scan Parameters has not been executed.

    Test Steps:
        1. Send LE Set Extended Scan Enable with Enable = 0x01 and all other
           parameters valid.
        2. Receive Command Complete with Command Disallowed (0x0C), ending the
           test, or Success (0x00), in which case the IUT starts scanning.
        3. On Success in step 2, send LE Set Extended Scan Parameters with a
           supported PHY (LE 1M here), passive Scan_Type[0] = 0x00,
           Scan_Interval[0] = Scan_Window[0] = 0x0010, Own_Address_Type = 0x00
           and Scanning_Filter_Policy = 0x00 (accept all).
        4. Require Command Complete with Command Disallowed (0x0C).

    Postamble:
        If scanning was enabled, disable it after step 4. This cleanup command
        is not part of the source's step 4.

    Expected Outcome:
        Pass verdict: enable returns either 0x0C, or 0x00 followed by 0x0C for
        Set Extended Scan Parameters. Each event has the matching opcode/credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled HCI/DDI/BV-06-C;
        PDF/printed pages 82-83, steps 1-4, Figure 4.39.
        Source reference [9], Section 7.8.65.
    """
    result = await tester.command(
        hci.HCI_LE_Set_Extended_Scan_Enable_Command(1, 0, 0, 0),
        (ErrorCode.SUCCESS, ErrorCode.COMMAND_DISALLOWED_ERROR),
    )
    if result.status == ErrorCode.COMMAND_DISALLOWED_ERROR:
        return
    await tester.command(
        scan_parameters(extended=True, scan_intervals=[16], scan_windows=[16]),
        ErrorCode.COMMAND_DISALLOWED_ERROR,
    )
    await tester.command(hci.HCI_LE_Set_Extended_Scan_Enable_Command(0, 0, 0, 0))


async def periodic_enable_before_parameters(tester):
    """Set Periodic Advertising Before Periodic Advertising Parameters Command.

    Initial Condition:
        Standby with no extended parameters configured for the selected handle.

    Test Steps:
        1. Send LE Set Extended Advertising Parameters; require successful
           Command Complete.
        2. Send LE Set Periodic Advertising Enable with Enable = 0x01 and
           Advertising_Handle equal to that existing handle.
        3. Select alternative 3A or 3B from the enable result:
           3A.1. Without vendor-specific defaults, receive Command Complete
                 with Command Disallowed (0x0C).
           3A.2. The Upper Tester sends LE Set Periodic Advertising Parameters.
           3A.3. Receive successful Command Complete.
           3B.1. With vendor-specific defaults, receive Command Complete with
                 Status = Success (0x00).
           3B.2. The Upper Tester sends LE Set Periodic Advertising Parameters.
           3B.3. Receive Command Complete with Command Disallowed (0x0C).

    Expected Outcome:
        Pass verdict: either 3A or 3B completes with the paired statuses above,
        matching opcodes and command credits.

    Postamble:
        Disable any train enabled through alternative 3B after its observations.

    Source Correction:
        Step 3A.2 names the IUT as both command sender and receiver; the sender
        is the Upper Tester, as in Figure 4.40 and step 3B.2. The verdict's
        reference to a Command Complete in 3B.2 means 3B.3, its response step.
        Amber supports both readings. These are local source corrections,
        not adopted SIG errata.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled HCI/DDI/BV-07-C;
        PDF/printed pages 83-84, Figure 4.40 and alternatives 3A/3B.
        Source reference [13], Section 7.8.63.
    """
    await tester.command(_advertising_parameters())
    result = await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0),
        (ErrorCode.COMMAND_DISALLOWED_ERROR, ErrorCode.SUCCESS),
    )
    await tester.command(
        _periodic_parameters(),
        (
            ErrorCode.SUCCESS
            if result.status != ErrorCode.SUCCESS
            else ErrorCode.COMMAND_DISALLOWED_ERROR
        ),
    )
    if result.status == ErrorCode.SUCCESS:
        await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(0, 0))


async def invalid_sync_options(tester):
    """Reject LE Periodic Advertising Create Sync Command With Disallowed Reporting
    Options, Periodic Advertising ADI not supported.

    Initial Condition:
        An independent peer announces an extended/periodic train. The scanning IUT has
        received its address/type and SID. Periodic Advertising ADI is not declared.

    Test Steps:
        1. Send LE Periodic Advertising Create Sync for the peer with Options =
           0x04 (do not use list, reporting enabled, duplicate filtering enabled).
        2. Select the returned event's alternative:
           2A.1. The IUT returns successful Command Status.
           2A.2. The IUT returns Sync Established with a valid error status.
           2B.1. Alternatively, Command Status itself returns a valid error.
        3. Send Create Sync with Options = 0x05 (use list, reporting enabled,
           duplicate filtering enabled).
        4. Select the returned event's alternative:
           4A.1. The IUT returns successful Command Status.
           4A.2. The IUT returns Sync Established with a valid error status.
           4B.1. Alternatively, Command Status itself returns a valid error.

    Observation Setup:
        Read local features to verify that Periodic Advertising ADI is absent.
        Establish extended scanning, announce the periodic train and check its
        complete HCI report before step 1. This realizes the initial condition
        rather than adding a source procedure step.

    Expected Outcome:
        Pass verdict: both requests end in a valid nonzero error through a permitted
        event path. The source allows other valid errors besides 0x11; final Success is
        forbidden.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, HCI/DDI/BI-49-C, Figure 4.41; PDF/printed pages
        84-86.
        Source reference [13], Section 7.8.67.
    """
    features = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    assert not (
        int.from_bytes(features.le_features, 'little')
        & hci.LeFeatureMask.PERIODIC_ADVERTISING_ADI_SUPPORT
    )
    await _start_scanning(tester)
    valid_errors = tuple(
        error
        for error in ErrorCode
        if error not in (ErrorCode.SUCCESS, ErrorCode.RESERVED_FOR_FUTURE_USE)
    )
    for options in (4, 5):
        result = await tester.command(
            create_sync(options=options), (ErrorCode.SUCCESS, *valid_errors)
        )
        if result.status == ErrorCode.SUCCESS:
            event = await tester.event(
                hci.HCI_LE_Periodic_Advertising_Sync_Established_Event
            )
            assert event.status in valid_errors


async def interval_too_short(tester, *, phy=Phy.LE_1M):
    """Reject Set Periodic Advertising Parameters Command when Advertising Data Too
    Long.

    Initial Condition:
        Standby; minimum supported periodic interval is 7.5 ms. Storage below 755 octets
        on 1M or 500 octets on Coded makes the source Inconclusive.

    Test Steps:
        1. Send LE Read Maximum Advertising Data Length.
        2. Require successful Command Complete with the maximum data length.
        3. Send valid Extended Advertising Parameters and require successful
           Command Complete. Select the Table 4.20 PHY: LE 1M for BI-50 or
           LE Coded for BI-51, used on both primary and secondary channels.
        4. Set Periodic Advertising Parameters on that handle with Min = Max =
           0x0050 (100 ms); require successful Command Complete.
        5. Set Periodic Advertising Data with that handle, Operation = 0x01,
           Length = 250 and 250 random octets in 1..254; require Success.
        6. Set another 250 random octets in 1..254 on that handle; use Operation
           from Table 4.20 (0x00 for 1M, 0x02 for Coded); require Success.
        7. For 1M, repeat step 6 once. For Coded, go to step 9.
        8. For 1M, set five random octets in 1..254 with Operation = 0x02 on
           that handle; require successful Command Complete.
        9. Enable extended advertising with Enable = 1, Num_Sets = 1, that
           handle and Duration = 0x0000; require successful Command Complete.
        10. Enable periodic advertising with Enable = 1; require Success.
        11. Immediately after three periodic advertising events, disable
            periodic advertising with Enable = 0; require Success.
        12. Set Periodic Advertising Parameters on the same handle with
            Min = Max = 0x0006 (7.5 ms).
        13. Require Command Complete with Packet Too Long (0x45).
        14. Re-enable periodic advertising with Enable = 1; require successful
            Command Complete.
        15. The IUT resumes periodic advertising.

    Expected Outcome:
        Pass verdict: interval reconfiguration returns 0x45 with correct opcode and
        credit in step 13; re-enable succeeds in step 14 and the original train
        resumes in step 15.
        Inconclusive verdict: advertised storage below 755 octets on 1M or
        500 octets on Coded, or an IXIT minimum interval greater than 0x0006.

    Observation Setup:
        The local seeded generator reproduces random payloads. Decode SyncInfo
        and reassemble each of the three periodic events, checking exact data.
        After re-enable, verify the unchanged 100-ms interval and data, then
        disable periodic and associated advertising as a separate postamble.

    Source Correction:
        The verdict's Packet Too Long reference to step 14 means step 13;
        step 14 explicitly requires successful re-enable. Step 11's three
        advertising events are the periodic events labeled in Figure 4.45.
        Amber supports the step-number correction and this figure-based
        clarification; neither is claimed as adopted SIG errata.

    Reference:
        HCI.TS.p39.pdf, Section 4.7.5, Table 4.20, Figures 4.44-4.45; HCI/DDI/BI-50-C
        and HCI/DDI/BI-51-C; PDF/printed pages 89-92.
        Source reference [12], Section 7.8.61.
    """
    coded = phy == Phy.LE_CODED
    size = 500 if coded else 755
    capacity = await tester.command(
        hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command()
    )
    if capacity.max_advertising_data_length < size:
        pytest.skip(f'Inconclusive: periodic PHY variant requires {size} data octets')
    await tester.command(
        _advertising_parameters(
            primary_advertising_interval_min=160,
            primary_advertising_interval_max=160,
            primary_advertising_phy=phy,
            secondary_advertising_phy=phy,
        )
    )
    await tester.command(
        _periodic_parameters(
            periodic_advertising_interval_min=80, periodic_advertising_interval_max=80
        )
    )
    generator = random.Random(0)
    data = bytes(generator.randint(1, 254) for _ in range(size))
    chunks = (
        (Operation.FIRST_FRAGMENT, data[:250]),
        (
            Operation.LAST_FRAGMENT if coded else Operation.INTERMEDIATE_FRAGMENT,
            data[250:500],
        ),
    )
    if not coded:
        chunks += (
            (Operation.INTERMEDIATE_FRAGMENT, data[500:750]),
            (Operation.LAST_FRAGMENT, data[750:]),
        )
    for operation, fragment in chunks:
        await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Data_Command(0, operation, fragment)
        )
    await tester.command(extended_enable())
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0))
    _, packet, fields = await receive_extended(tester, phy=phy, primary_phy=phy)
    train = PeriodicTrain.from_advertisement(packet, fields)
    assert train.interval == 80
    for _ in range(3):
        assert await train.receive(tester) == data
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(0, 0))
    await tester.command(
        _periodic_parameters(
            periodic_advertising_interval_min=LL_PERIODIC_INTERVAL_MIN,
            periodic_advertising_interval_max=LL_PERIODIC_INTERVAL_MIN,
        ),
        ErrorCode.PACKET_TOO_LONG_ERROR,
    )
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0))
    _, packet, fields = await receive_extended(tester, phy=phy, primary_phy=phy)
    train = PeriodicTrain.from_advertisement(packet, fields)
    assert train.interval == 80 and await train.receive(tester) == data
    await tester.command(hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(0, 0))
    await tester.command(extended_enable(0))


async def periodic_packet_too_long(tester):
    """Reject Set Periodic Advertising Data Command when Advertising Data Too Long.

    Initial Condition:
        Standby; this DUT declares at least 755 data octets and a supported
        minimum periodic interval of 0x0006 (7.5 ms).

    Test Steps:
        1. Send LE Read Maximum Advertising Data Length.
        2. Receive successful Command Complete with the maximum data length.
        3. Send Extended Advertising Parameters with Secondary_PHY = LE 1M and
           other valid parameters; require successful Command Complete.
        4. Set Periodic Advertising Parameters with that handle and Min = Max =
           0x0006 (7.5 ms); require successful Command Complete.
        5. Send Set Periodic Advertising Data with that handle, Operation = 0x01,
           Length = 250 and 250 random octets in 1..254.
        6. Select the returned Command Complete alternative:
           6A.1. On Success, continue to step 7.
           6B.1. Alternatively, receive Packet Too Long (0x45).
           6B.2. End with Pass.
        7. Perform steps 8 and 9 twice unless the test ends in step 9B.2.
        8. Send Set Periodic Advertising Data with that handle, Operation = 0x00,
           Length = 250 and 250 random octets in 1..254.
        9. Select the returned Command Complete alternative:
           9A.1. On Success, continue the prescribed repetitions/procedure.
           9B.1. Alternatively, receive Packet Too Long (0x45).
           9B.2. End with Pass.
        10. Send Set Periodic Advertising Data with that handle, Operation =
            0x02, Length = 5 and five random octets in 1..254.
        11. Receive Command Complete with Packet Too Long (0x45).

    Expected Outcome:
        Pass verdict: Command Complete reports Packet Too Long (0x45) on the
        first/intermediate fragment or the final five-octet fragment. Every
        preceding accepted fragment has status Success and matching opcode/credit.
        Insufficient storage or no 7.5-ms interval makes the source Inconclusive.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled HCI/DDI/BI-52-C;
        PDF/printed pages 93-96, steps 1-11 and Figure 4.46.
        Source reference [12], Section 7.8.62.
    """
    result = await tester.command(
        hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command()
    )
    if result.max_advertising_data_length < 755:
        pytest.skip('Inconclusive: HCI/DDI/BI-52-C requires capacity >=755 octets')
    await tester.command(_advertising_parameters())
    await tester.command(
        _periodic_parameters(
            periodic_advertising_interval_min=LL_PERIODIC_INTERVAL_MIN,
            periodic_advertising_interval_max=LL_PERIODIC_INTERVAL_MIN,
        )
    )
    generator = random.Random(0)
    for operation, size in (
        (Operation.FIRST_FRAGMENT, 250),
        (Operation.INTERMEDIATE_FRAGMENT, 250),
        (Operation.INTERMEDIATE_FRAGMENT, 250),
        (Operation.LAST_FRAGMENT, 5),
    ):
        result = await tester.command(
            hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
                0, operation, bytes(generator.randint(1, 254) for _ in range(size))
            ),
            (ErrorCode.SUCCESS, ErrorCode.PACKET_TOO_LONG_ERROR),
        )
        if result.status == ErrorCode.PACKET_TOO_LONG_ERROR:
            return
    raise AssertionError(
        '755 octets were accepted despite the 7.5-ms periodic interval'
    )


async def incompatible_periodic_enable_with_advertising(tester, *, properties):
    """Reject LE Set Periodic Advertising Enable Command, Legacy Packet.

    Initial Condition:
        The IUT is in standby. Use one valid handle and seeded random one-octet
        data for the periodic payload and, when needed, the scan response.

    Test Steps:
        1. Send Extended Advertising Parameters with a valid handle and
           Properties = 0 (nonconnectable/nonscannable extended advertising);
           require successful Command Complete.
        2. Set Periodic Advertising Parameters on the same handle; require
           successful Command Complete.
        3. Set Periodic Advertising Data on that handle with Length = 1 and
           one random octet; require successful Command Complete.
        4. Set Extended Advertising Parameters on that handle with properties
           selected by Table 4.21; require successful Command Complete.
        5. If the scannable bit is unset, skip to step 6. Otherwise set Extended
           Scan Response Data on the same handle with Length = 1 and one random
           octet; require successful Command Complete.
        6. Enable extended advertising with Enable = 0x01; require successful
           Command Complete.
        7. Send Set Periodic Advertising Enable with Enable = 0x01.
        8. Require Command Complete with Command Disallowed (0x0C).

    Test Case Configuration:
        Table 4.21 selects BI-53 through BI-61 in this mask order: 0x20, 0x24,
        0x13, 0x12, 0x10, 0x01, 0x05, 0x02, 0x06. One method receives the
        registered row's properties parameter; it retains one handle throughout.

    Expected Outcome:
        Pass verdict: step 8 returns status 0x0C, matching opcode and a credit.
        All prerequisite configuration and associated-advertising enable commands
        succeed. The section title also covers non-legacy rows in Table 4.21.

    Reference:
        HCI.TS.p39.pdf, Section 4.7.6, Table 4.21, steps 1-8;
        HCI/DDI/BI-53-C through HCI/DDI/BI-61-C; PDF/printed pages 96-98.
        Source reference [12], Section 7.8.63; Figure 4.47.
    """
    await _configure_periodic_set(tester, with_data=True)
    await tester.command(_advertising_parameters(properties))
    if properties & Properties.SCANNABLE_ADVERTISING:
        await tester.command(
            hci.HCI_LE_Set_Extended_Scan_Response_Data_Command(
                0, Operation.COMPLETE_DATA, 0, random.Random(0).randbytes(1)
            )
        )
    await tester.command(extended_enable())
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0),
        ErrorCode.COMMAND_DISALLOWED_ERROR,
    )


async def coded_packet_too_long(tester):
    """Reject Set Extended Advertising Parameters Command, Packet Too Long, LE Coded.

    Initial Condition:
        Standby; maximum advertising-data capacity is at least 251 octets.

    Test Steps:
        1. Send LE Read Maximum Advertising Data Length.
        2. Receive successful Command Complete with the maximum data length.
        3. Set Extended Advertising Parameters with Min = Max = 0x30 (30 ms),
           Properties = 0 (nonconnectable/nonscannable), and both primary and
           secondary PHY = LE Coded; require successful Command Complete.
        4. Set Extended Advertising Data to 251 random octets in 1..255;
           require successful Command Complete.
        5. Set Extended Advertising Parameters with Min = Max = 0x20 (20 ms),
           Properties = 0 and Secondary_Advertising_Max_Skip = 0.
        6. Require Command Complete with Packet Too Long (0x45).

    Expected Outcome:
        Pass verdict: the interval-change command returns Command Complete with
        status 0x45, matching opcode and a command credit. Initial configuration
        and data commands succeed. Capacity below 251 octets is Inconclusive.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled HCI/DDI/BI-62-C;
        PDF/printed pages 98-100, steps 1-6 and Figure 4.48.
        Source reference [12], Sections 7.8.53 and 7.8.54.
    """
    result = await tester.command(
        hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command()
    )
    if result.max_advertising_data_length < 251:
        pytest.skip('Inconclusive: HCI/DDI/BI-62-C requires capacity >=251 octets')
    values = {
        'primary_advertising_phy': hci.Phy.LE_CODED,
        'secondary_advertising_phy': hci.Phy.LE_CODED,
    }
    await tester.command(
        _advertising_parameters(
            primary_advertising_interval_min=48,
            primary_advertising_interval_max=48,
            **values,
        )
    )
    generator = random.Random(0)
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Data_Command(
            0,
            Operation.COMPLETE_DATA,
            0,
            bytes(generator.randint(1, 255) for _ in range(251)),
        )
    )
    await tester.command(
        _advertising_parameters(
            primary_advertising_interval_min=32,
            primary_advertising_interval_max=32,
            secondary_advertising_max_skip=0,
            **values,
        ),
        ErrorCode.PACKET_TOO_LONG_ERROR,
    )


async def oversized_data(tester, *, response=False, phy=hci.Phy.LE_1M):
    """Reject Set Extended Advertising Data Commands, Data Too Long.

    Initial Condition:
        Standby. Table 4.22 selects advertising data (properties zero) for BI-63/64
        or scan-response data (Scannable property) for BI-65/66; primary PHY
        is LE 1M for BI-63/65 and Coded for BI-64/66.

    Test Steps:
        1. Send LE Read Maximum Advertising Data Length.
        2. Receive successful Command Complete with the maximum data length.
        3. Set Extended Advertising Parameters with Min = Max = 0x140 (200 ms)
           and Table 4.22's PHY/properties; require successful Command Complete.
        4. Perform steps 5 and 6 seven times, sending a total of maximum length
           minus one octets in the seven commands.
        5. Send the command selected by Table 4.22 with random payload octets.
           Use Operation = 0x01 for the first instance, 0x00 thereafter.
        6. Require successful Command Complete.
        7. Send the selected command with two random octets and Operation = 0x00.
        8. Receive Command Complete.
        9. If Status = Memory Capacity Exceeded (0x07), end with Pass. If Status
           is not Success (0x00), end with Fail. On Success, continue.
        10. Send the selected command with one random octet and Operation = 0x02.
        11. Require Command Complete with Memory Capacity Exceeded (0x07).

    Expected Outcome:
        Pass verdict: all seven initial fragments succeed and the overflow is
        rejected with Memory Capacity Exceeded in step 9 or 11, with matching
        Command Complete opcodes and credits.
        Fail verdict: an error other than Success or Memory Capacity Exceeded
        is not accepted; all seven step-6 responses must succeed.

    Source Correction:
        Figure 4.49 gives interval 0x20, conflicting with step 3's explicit
        0x140; use the ordered step's 200-ms interval. Its caption says periodic
        data, but the commands are extended advertising/scan-response data from
        Table 4.22. These annotations identify the local interpretation, not
        adopted SIG errata. Amber supports following the ordered step/table;
        this is storage exhaustion (0x07), not an airtime failure (0x45).

    Reference:
        HCI.TS.p39.pdf, Section 4.7.7, Table 4.22, steps 1-11;
        HCI/DDI/BI-63-C through HCI/DDI/BI-66-C; PDF/printed pages 100-102.
        Source reference [12], Sections 7.8.54 and 7.8.55; Figure 4.49.
    """
    capacity = (
        await tester.command(hci.HCI_LE_Read_Maximum_Advertising_Data_Length_Command())
    ).max_advertising_data_length
    await tester.command(
        extended_parameters(
            advertising_event_properties=(
                Properties.SCANNABLE_ADVERTISING if response else 0
            ),
            primary_advertising_interval_min=320,
            primary_advertising_interval_max=320,
            primary_advertising_phy=phy,
        )
    )
    command = (
        hci.HCI_LE_Set_Extended_Scan_Response_Data_Command
        if response
        else hci.HCI_LE_Set_Extended_Advertising_Data_Command
    )
    size = (capacity - 1 + 6) // 7
    remaining = capacity - 1
    generator = random.Random(0)
    for index in range(7):
        fragment = generator.randbytes(min(size, remaining))
        await tester.command(
            command(
                0,
                (
                    Operation.FIRST_FRAGMENT
                    if index == 0
                    else Operation.INTERMEDIATE_FRAGMENT
                ),
                0,
                fragment,
            )
        )
        remaining -= len(fragment)
    assert remaining == 0
    result = await tester.command(
        command(0, Operation.INTERMEDIATE_FRAGMENT, 0, generator.randbytes(2)),
        (ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR, ErrorCode.SUCCESS),
    )
    if result.status == ErrorCode.SUCCESS:
        await tester.command(
            command(0, Operation.LAST_FRAGMENT, 0, generator.randbytes(1)),
            ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR,
        )


async def invalid_decision_scan_parameters(tester):
    """Reject LE Set Extended Scan Parameters with Invalid Scan_Filter_Policy
    Parameters.

    Initial Condition:
        The IUT is not scanning and does not declare Decision-based Advertising
        Filtering support. Check the reported feature mask before the procedure.

    Test Steps:
        1. Send valid Extended Scan Parameters with Scan_Filter_Policy bits
           2 and 3 set to a value other than 0b00.
        2. Require Command Complete with nonzero Status. If Status differs from
           Unsupported Feature or Parameter Value (0x11), issue a warning.

    Observation Setup:
        Check the reported feature mask before the source steps. Exercise all
        three nonzero choices of the two bits (01, 10, 11), retaining valid PHY,
        timing and address parameters. The source does not number those choices
        as separate steps; this implementation repeats steps 1 and 2 for each.

    Expected Outcome:
        Pass verdict: each command returns a nonzero status, matching opcode
        and credit. The source prefers 0x11 but explicitly allows other errors.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled HCI/DDI/BI-68-C;
        PDF/printed page 102, steps 1-2.
        Source reference [18], Section 7.8.64.
    """
    features = await tester.command(hci.HCI_LE_Read_Local_Supported_Features_Command())
    assert (
        not int.from_bytes(features.le_features, 'little')
        & hci.LeFeatureMask.DECISION_BASED_ADVERTISING_FILTERING
    )
    for policy in (0b0100, 0b1000, 0b1100):
        result = await tester.command(
            scan_parameters(extended=True, scanning_filter_policy=policy),
            tuple(
                code
                for code in ErrorCode
                if code not in (ErrorCode.SUCCESS, ErrorCode.RESERVED_FOR_FUTURE_USE)
            ),
        )
        if result.status != ErrorCode.UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERROR:
            warnings.warn(
                (
                    f'HCI/DDI/BI-68-C: expected preferred status 0x11, received '
                    f'{result.status:#04x}'
                ),
                stacklevel=2,
            )


async def invalid_decision_advertising_parameters(tester):
    """LE Set Extended Advertising Parameters, Invalid Decision Parameters.

    Initial Condition:
        The IUT is not scanning. Use valid extended parameters on LE 1M.

    Test Steps:
        1. Send Extended Advertising Parameters with Primary_PHY = LE 1M,
           Directed and Use Decision PDUs bits 2/7 set, and Include AdvA/ADI
           bits 8/9 clear; other parameters are valid.
        2. Require Command Complete with Invalid HCI Command Parameters (0x12).
        3. Send Extended Advertising Parameters with Primary_PHY = LE 1M,
           bits 7/9 clear and Include AdvA bit 8 set; other parameters are valid.
        4. Require Command Complete with Invalid HCI Command Parameters (0x12).
        5. Send Extended Advertising Parameters with Primary_PHY = LE 1M,
           bits 7/8 clear and Include ADI bit 9 set; other parameters are valid.
        6. Require Command Complete with Invalid HCI Command Parameters (0x12).

    Expected Outcome:
        Pass verdict: all three Command Complete events have status 0x12,
        matching opcode and a credit. The PDF places this verdict directly
        below step 6 rather than under a separate Expected Outcome heading.

    Reference:
        HCI.TS.p39.pdf, Section 4.7, independently titled HCI/DDI/BI-69-C;
        PDF/printed pages 102-103, steps 1-6 and following Pass verdict.
        Source reference [18], Section 7.8.53.
    """
    for properties in (
        Properties.DIRECTED_ADVERTISING | Properties.USE_DECISION_PDUS,
        Properties.INCLUDE_ADVA_IN_DECISION_PDUS,
        Properties.INCLUDE_ADI_IN_DECISION_PDUS,
    ):
        await tester.command(
            _advertising_parameters(properties),
            ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
        )


async def periodic_data_before_parameters(tester):
    """Reject Set Periodic Advertising Data Command, Not Configured for Periodic
    Advertising.

    Initial Condition:
        Advertising data exists and has at most 31 octets. The selected v1
        periodic-data command is supported; no periodic parameters are configured.

    Test Steps:
        1. Send Extended Advertising Parameters with a valid handle,
           Properties = 0x0000, Primary_PHY = Secondary_PHY = LE 1M (0x01).
        2. Require successful Command Complete.
        3. Select the Table 4.23 command's alternative:
           3A.1. For BI-70, send Periodic Advertising Data on the same handle
                 with Operation = 0x03 (complete), Length = 1 and one random
                 octet, without having set periodic parameters.
           3B.1. The unselected BI-71 variant instead sends Periodic Advertising
                 Subevent Data with Num_Subevents_With_Data = 1, Length = 1 and
                 one random octet. It is not executed by the selected BI-70 case.
        4. Require Command Complete with Command Disallowed (0x0C).

    Observation Setup:
        After creating the handle, set three ordinary advertising data octets
        before step 3, satisfying the source's existing-data condition. No
        periodic parameter command is sent; this extra setup is not step 3A.1.

    Expected Outcome:
        Pass verdict: periodic data returns status 0x0C, matching opcode and a
        command credit. The unselected PAwR subevent-data alternative is not
        required by HCI/DDI/BI-70-C.

    Reference:
        HCI.TS.p39.pdf, Section 4.7.8, HCI/DDI/BI-70-C;
        PDF/printed pages 103-104, alternative 3A, steps 1-4.
        Source reference [12], Section 7.8.62; Table 4.23 and Figure 4.50.
    """
    await tester.command(_advertising_parameters())
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Data_Command(
            0, Operation.COMPLETE_DATA, 0, b'\x02\x01\x06'
        )
    )
    await tester.command(
        hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
            0, Operation.COMPLETE_DATA, random.Random(0).randbytes(1)
        ),
        ErrorCode.COMMAND_DISALLOWED_ERROR,
    )


PERIODIC_INCOMPATIBLE_PROPERTIES = (
    Properties.ANONYMOUS_ADVERTISING,
    Properties.ANONYMOUS_ADVERTISING | Properties.DIRECTED_ADVERTISING,
    Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.CONNECTABLE_ADVERTISING
    | Properties.SCANNABLE_ADVERTISING,
    Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.CONNECTABLE_ADVERTISING
    | Properties.DIRECTED_ADVERTISING,
    Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.CONNECTABLE_ADVERTISING
    | Properties.DIRECTED_ADVERTISING
    | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING,
    Properties.USE_LEGACY_ADVERTISING_PDUS | Properties.SCANNABLE_ADVERTISING,
    Properties.USE_LEGACY_ADVERTISING_PDUS,
    Properties.CONNECTABLE_ADVERTISING,
    Properties.CONNECTABLE_ADVERTISING | Properties.DIRECTED_ADVERTISING,
    Properties.SCANNABLE_ADVERTISING,
    Properties.SCANNABLE_ADVERTISING | Properties.DIRECTED_ADVERTISING,
)

PROCEDURES: ProcedureMap = {}

# Verify that disabling advertising stops subsequent ADV_IND transmissions.
PROCEDURES |= procedure_cases(
    advertising_disable,
    {
        'HCI/DDI/BV-03-C': (
            'Set Advertising Enable',
            {},
        ),
    },
)

# Verify that disabling passive scanning stops subsequent LE Advertising Reports.
PROCEDURES |= procedure_cases(
    scanning_disable,
    {
        'HCI/DDI/BV-04-C': (
            'Set Scan Enable',
            {},
        ),
    },
)

# Verify rejection of extended advertising intervals outside the declared IXIT range.
PROCEDURES |= procedure_cases(
    extended_interval_bounds,
    {
        'HCI/DDI/BI-01-C': (
            'Reject Invalid Extended Advertising Parameters',
            {},
        ),
    },
)

# Verify rejection of legacy nonconnectable intervals outside the declared IXIT range.
PROCEDURES |= procedure_cases(
    invalid_parameters,
    {
        'HCI/DDI/BI-02-C': (
            'Reject Invalid Advertising Parameters',
            {},
        ),
    },
)

# Verify rejection of periodic intervals outside the manufacturer's IXIT range.
PROCEDURES |= procedure_cases(
    periodic_interval_bounds,
    {
        'HCI/DDI/BI-67-C': (
            'Reject Invalid Periodic Advertising Parameters',
            {},
        ),
    },
)

# Verify duplicate periodic identity rejection until the existing synchronization is
# terminated.
PROCEDURES |= procedure_cases(
    duplicate_periodic_sync,
    {
        'HCI/DDI/BI-04-C': (
            (
                'Reject LE Periodic Advertising Create Sync Command to a '
                'Synchronized Advertising Set'
            ),
            {},
        ),
    },
)

# Verify individual rejection of every unsupported or RFU scanning PHY bit.
PROCEDURES |= procedure_cases(
    unsupported_scan_phys,
    {
        'HCI/DDI/BI-05-C': (
            'LE Set Extended Scan Parameters With Unsupported PHY',
            {},
        ),
    },
)

# Verify both prescribed errors for Extended Advertising Enable when a scannable set has
# no scan-response data, or no sets are specified.
PROCEDURES |= procedure_cases(
    invalid_extended_advertising_enable,
    {
        'HCI/DDI/BI-12-C': (
            'Reject Invalid Extended Advertising Enable Command',
            {},
        ),
    },
)

# Verify rejection of periodic enable while the advertising data is incomplete.
PROCEDURES |= procedure_cases(
    invalid_periodic_advertising_enable,
    {
        'HCI/DDI/BI-13-C': (
            'Reject Invalid Periodic Advertising Enable Command',
            {},
        ),
    },
)

# Verify rejection of periodic-data fragmentation operations during an enabled periodic
# advertising train.
PROCEDURES |= procedure_cases(
    periodic_fragments_while_enabled,
    {
        'HCI/DDI/BI-14-C': (
            (
                'Reject LE Set Periodic Advertising Data setting the '
                'fragment when periodic advertising is enabled'
            ),
            {},
        ),
    },
)

# Reject a change to scannable, connectable, legacy or anonymous properties while
# periodic advertising is enabled for the same set.
PROCEDURES |= procedure_cases(
    incompatible_parameters_during_periodic_advertising,
    {
        'HCI/DDI/BI-15-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {'properties': Properties.ANONYMOUS_ADVERTISING},
        ),
        'HCI/DDI/BI-16-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {
                'properties': Properties.DIRECTED_ADVERTISING
                | Properties.ANONYMOUS_ADVERTISING
            },
        ),
        'HCI/DDI/BI-17-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.SCANNABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-18-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-19-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
                | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-20-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {
                'properties': Properties.SCANNABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-21-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {'properties': Properties.USE_LEGACY_ADVERTISING_PDUS},
        ),
        'HCI/DDI/BI-22-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {'properties': Properties.CONNECTABLE_ADVERTISING},
        ),
        'HCI/DDI/BI-23-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
            },
        ),
        'HCI/DDI/BI-24-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {'properties': Properties.SCANNABLE_ADVERTISING},
        ),
        'HCI/DDI/BI-25-C': (
            (
                'Reject Set Extended Advertising Parameters Command using a'
                ' Periodic Advertising Set and Incompatible Advertising is '
                'Specified'
            ),
            {
                'properties': Properties.SCANNABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
            },
        ),
    },
)

# Reject periodic parameters when the associated advertising set specifies scannable,
# connectable, legacy or anonymous advertising.
PROCEDURES |= procedure_cases(
    incompatible_periodic_parameters,
    {
        'HCI/DDI/BI-26-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {'properties': Properties.ANONYMOUS_ADVERTISING},
        ),
        'HCI/DDI/BI-27-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.DIRECTED_ADVERTISING
                | Properties.ANONYMOUS_ADVERTISING
            },
        ),
        'HCI/DDI/BI-28-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.SCANNABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-29-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-30-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
                | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-31-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.SCANNABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-32-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {'properties': Properties.USE_LEGACY_ADVERTISING_PDUS},
        ),
        'HCI/DDI/BI-33-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {'properties': Properties.CONNECTABLE_ADVERTISING},
        ),
        'HCI/DDI/BI-34-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
            },
        ),
        'HCI/DDI/BI-35-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {'properties': Properties.SCANNABLE_ADVERTISING},
        ),
        'HCI/DDI/BI-36-C': (
            (
                'Reject Set Periodic Advertising Parameters Command when '
                'the Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.SCANNABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
            },
        ),
    },
)

# Reject periodic enable after an initially compatible advertising set changes to
# scannable, connectable, legacy or anonymous advertising.
PROCEDURES |= procedure_cases(
    incompatible_periodic_enable,
    {
        'HCI/DDI/BI-37-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {'properties': Properties.ANONYMOUS_ADVERTISING},
        ),
        'HCI/DDI/BI-38-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.DIRECTED_ADVERTISING
                | Properties.ANONYMOUS_ADVERTISING
            },
        ),
        'HCI/DDI/BI-39-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.SCANNABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-40-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-41-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
                | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-42-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.SCANNABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-43-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {'properties': Properties.USE_LEGACY_ADVERTISING_PDUS},
        ),
        'HCI/DDI/BI-44-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {'properties': Properties.CONNECTABLE_ADVERTISING},
        ),
        'HCI/DDI/BI-45-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
            },
        ),
        'HCI/DDI/BI-46-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {'properties': Properties.SCANNABLE_ADVERTISING},
        ),
        'HCI/DDI/BI-47-C': (
            (
                'Reject Set Periodic Advertising Enable Command when the '
                'Associated Handle Specifies Incompatible Advertising'
            ),
            {
                'properties': Properties.SCANNABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
            },
        ),
    },
)

# Verify enable without explicit scanning parameters, including the allowed
# vendor-default scanning branch and its parameter-change rejection.
PROCEDURES |= procedure_cases(
    default_extended_scan_enable,
    {
        'HCI/DDI/BV-06-C': (
            'Default Extended Scan Enable Command',
            {},
        ),
    },
)

# Verify periodic enable before setting periodic parameters, including both the
# vendor-default and no-vendor-default alternatives.
PROCEDURES |= procedure_cases(
    periodic_enable_before_parameters,
    {
        'HCI/DDI/BV-07-C': (
            (
                'Set Periodic Advertising Before Periodic Advertising '
                'Parameters Command'
            ),
            {},
        ),
    },
)

# Verify invalid duplicate-filtering reporting options without Periodic Advertising ADI
# support.
PROCEDURES |= procedure_cases(
    invalid_sync_options,
    {
        'HCI/DDI/BI-49-C': (
            (
                'Reject LE Periodic Advertising Create Sync Command With '
                'Disallowed Reporting Options, Periodic Advertising ADI not'
                ' supported'
            ),
            {},
        ),
    },
)

# Verify interval-change rejection for stored data that cannot fit, retaining the
# original periodic train.
PROCEDURES |= procedure_cases(
    interval_too_short,
    {
        'HCI/DDI/BI-50-C': (
            (
                'LE Set Periodic Advertising Parameters, Reject, Data Too '
                'Long, LE 1M PHY'
            ),
            {},
        ),
        'HCI/DDI/BI-51-C': (
            (
                'LE Set Periodic Advertising Parameters, Reject, Data Too '
                'Long, LE Coded PHY'
            ),
            {'phy': Phy.LE_CODED},
        ),
    },
)

# Reject periodic data that cannot be transmitted within the configured interval.
PROCEDURES |= procedure_cases(
    periodic_packet_too_long,
    {
        'HCI/DDI/BI-52-C': (
            (
                'Reject Set Periodic Advertising Data Command when '
                'Advertising Data Too Long'
            ),
            {},
        ),
    },
)

# Reject periodic enable when the running associated advertising set has scannable,
# connectable, legacy or anonymous properties.
PROCEDURES |= procedure_cases(
    incompatible_periodic_enable_with_advertising,
    {
        'HCI/DDI/BI-53-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Anonymous, undirected'
            ),
            {'properties': Properties.ANONYMOUS_ADVERTISING},
        ),
        'HCI/DDI/BI-54-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Anonymous, directed'
            ),
            {
                'properties': Properties.DIRECTED_ADVERTISING
                | Properties.ANONYMOUS_ADVERTISING
            },
        ),
        'HCI/DDI/BI-55-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Connectable and scannable undirected'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.SCANNABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-56-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Scannable undirected'
            ),
            {
                'properties': Properties.SCANNABLE_ADVERTISING
                | Properties.USE_LEGACY_ADVERTISING_PDUS
            },
        ),
        'HCI/DDI/BI-57-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Non-connectable and non-scannable, undirected'
            ),
            {'properties': Properties.USE_LEGACY_ADVERTISING_PDUS},
        ),
        'HCI/DDI/BI-58-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Connectable undirected'
            ),
            {'properties': Properties.CONNECTABLE_ADVERTISING},
        ),
        'HCI/DDI/BI-59-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Connectable directed'
            ),
            {
                'properties': Properties.CONNECTABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
            },
        ),
        'HCI/DDI/BI-60-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Scannable undirected'
            ),
            {'properties': Properties.SCANNABLE_ADVERTISING},
        ),
        'HCI/DDI/BI-61-C': (
            (
                'LE Set Extended Advertising Parameters Command, Reject, '
                'Scannable directed'
            ),
            {
                'properties': Properties.SCANNABLE_ADVERTISING
                | Properties.DIRECTED_ADVERTISING
            },
        ),
    },
)

# Reject a Coded advertising interval too short for the previously stored data.
PROCEDURES |= procedure_cases(
    coded_packet_too_long,
    {
        'HCI/DDI/BI-62-C': (
            (
                'Reject Set Extended Advertising Parameters Command, Packet'
                ' Too Long, LE Coded'
            ),
            {},
        ),
    },
)

# Verify rejection of extended advertising or scan-response data beyond the Controller's
# reported storage capacity.
PROCEDURES |= procedure_cases(
    oversized_data,
    {
        'HCI/DDI/BI-63-C': (
            'Reject Set Extended Advertising Data Command, Data Too Long, LE 1M PHY',
            {},
        ),
        'HCI/DDI/BI-64-C': (
            (
                'Reject Set Extended Advertising Data Command, Data Too '
                'Long, LE Coded PHY'
            ),
            {'phy': Phy.LE_CODED},
        ),
        'HCI/DDI/BI-65-C': (
            (
                'Reject Set Extended Scan Response Data Command, Data Too '
                'Long, LE 1M PHY'
            ),
            {'response': True},
        ),
        'HCI/DDI/BI-66-C': (
            (
                'Reject Set Extended Scan Response Data Command, Data Too '
                'Long, LE Coded PHY'
            ),
            {'response': True, 'phy': Phy.LE_CODED},
        ),
    },
)

# Reject Decision-based Advertising filtering policies when unsupported.
PROCEDURES |= procedure_cases(
    invalid_decision_scan_parameters,
    {
        'HCI/DDI/BI-68-C': (
            (
                'Reject LE Set Extended Scan Parameters with Invalid '
                'Scan_Filter_Policy Parameters'
            ),
            {},
        ),
    },
)

# Verify rejection of the three invalid Decision PDU property combinations.
PROCEDURES |= procedure_cases(
    invalid_decision_advertising_parameters,
    {
        'HCI/DDI/BI-69-C': (
            'LE Set Extended Advertising Parameters, Invalid Decision Parameters',
            {},
        ),
    },
)

# Reject setting periodic data before periodic parameters have been configured.
PROCEDURES |= procedure_cases(
    periodic_data_before_parameters,
    {
        'HCI/DDI/BI-70-C': (
            'HCI_LE_Set_Periodic_Advertising_Data',
            {},
        ),
    },
)

# Verify that the IUT synchronizes to at most one periodic advertising train for each
# advertiser address, address type and Advertising SID.
PROCEDURES |= procedure_cases(
    periodic_advertiser_list_identity,
    {
        'HCI/DDI/BV-12-C': (
            'Connect to one periodic advertising train, Periodic Advertiser List',
            {},
        ),
    },
)

# Verify rejection of disallowed reporting options in LE Periodic Advertising Create
# Sync.
PROCEDURES |= procedure_cases(
    None,
    {
        'HCI/DDI/BI-03-C': pytest.param(
            (
                'Reject LE Periodic Advertising Create Sync Command With '
                'Disallowed Reporting Options'
            ),
            {},
            marks=[
                pytest.mark.skip(
                    reason=(
                        'Not applicable: ICS requires no LE Set Periodic '
                        'Advertising Receive Enable support (HCI6/30 AND '
                        'NOT6/37); this DUT supports the command and initially'
                        ' disabled reporting.'
                    ),
                ),
            ],
        ),
    },
)

RADIO_CASES = [
    "HCI/DDI/BV-12-C",
    "HCI/DDI/BV-03-C",
    "HCI/DDI/BV-04-C",
    "HCI/DDI/BI-04-C",
    "HCI/DDI/BI-49-C",
    "HCI/DDI/BI-50-C",
    "HCI/DDI/BI-51-C",
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES, radio_cases=RADIO_CASES),
)
async def test_device_discovery_commands(
    hci_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(hci_dut, identifier, description, procedure, parameters, marks)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(
        PROCEDURES,
        radio_cases=RADIO_CASES,
        radio=True,
    ),
)
async def test_device_discovery_radio(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
