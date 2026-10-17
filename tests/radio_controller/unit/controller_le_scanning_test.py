# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Synchronization slot ownership, cancellation and advertiser-list capacity."""

import pytest

from bumble import hci
from bumble.radio_controller.radio_discovery import PeriodicSync
from tests.radio_controller.unit.helpers import PEER_ADDRESS, create_sync

ErrorCode = hci.HCI_ErrorCode

Add = hci.HCI_LE_Add_Device_To_Periodic_Advertiser_List_Command

Remove = hci.HCI_LE_Remove_Device_From_Periodic_Advertiser_List_Command

Options = hci.HCI_LE_Periodic_Advertising_Create_Sync_Command.Options

Clear = hci.HCI_LE_Clear_Periodic_Advertiser_List_Command


@pytest.mark.asyncio
async def test_periodic_list_capacity_errors_and_reset(hci_dut):
    tester = hci_dut
    capacity = (
        await tester.command(hci.HCI_LE_Read_Periodic_Advertiser_List_Size_Command())
    ).periodic_advertiser_list_size
    assert capacity > 0
    addresses = [
        hci.Address(
            (0x123456789A00 + index).to_bytes(6, 'little'),
            hci.AddressType.PUBLIC_DEVICE,
        )
        for index in range(capacity + 1)
    ]
    for address in addresses[:-1]:
        await tester.command(Add(address.address_type, address, 0))
    await tester.command(
        Add(addresses[0].address_type, addresses[0], 0),
        ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
    )
    await tester.command(
        Add(addresses[-1].address_type, addresses[-1], 0),
        ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR,
    )
    await tester.command(Remove(addresses[0].address_type, addresses[0], 0))
    await tester.command(Add(addresses[-1].address_type, addresses[-1], 0))
    await tester.command(
        Add(hci.AddressType.PUBLIC_IDENTITY, PEER_ADDRESS, 0),
        ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
    )
    await tester.command(
        Add(PEER_ADDRESS.address_type, PEER_ADDRESS, 16),
        ErrorCode.INVALID_COMMAND_PARAMETERS_ERROR,
    )
    await tester.command(hci.HCI_Reset_Command())
    await tester.command(
        Remove(addresses[-1].address_type, addresses[-1], 0),
        ErrorCode.UNKNOWN_ADVERTISING_IDENTIFIER_ERROR,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('use_list', [False, True])
async def test_periodic_list_is_immutable_during_pending_sync(hci_dut, use_list):
    tester = hci_dut
    await tester.masks()
    await tester.command(Add(PEER_ADDRESS.address_type, PEER_ADDRESS, 3))
    await tester.command(
        create_sync(
            options=int(Options.USE_PERIODIC_ADVERTISER_LIST) if use_list else 0
        )
    )
    for command in (
        Add(PEER_ADDRESS.address_type, PEER_ADDRESS, 4),
        Remove(PEER_ADDRESS.address_type, PEER_ADDRESS, 3),
        Clear(),
    ):
        await tester.command(command, ErrorCode.COMMAND_DISALLOWED_ERROR)
    await tester.command(hci.HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command())
    await tester.event(hci.HCI_LE_Periodic_Advertising_Sync_Established_Event)
    await tester.command(Clear())


async def test_sync_capacity_cancel_and_reset_preserve_other_handles(hci_dut):
    tester = hci_dut
    await tester.masks()
    link = tester.input.backend.link
    for index in range(8):
        link.syncs[index + 1] = PeriodicSync(
            PEER_ADDRESS, index, 100_000, 100_000, established=True, handle=index + 1
        )
    await tester.command(
        create_sync(advertising_sid=3), ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR
    )
    await tester.command(
        create_sync(advertising_sid=8), ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR
    )
    await tester.command(hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(4))
    await tester.command(create_sync(advertising_sid=8))
    assert link.sync.handle == 4
    await tester.command(hci.HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command())
    cancelled = await tester.event(
        hci.HCI_LE_Periodic_Advertising_Sync_Established_Event
    )
    assert cancelled.status == ErrorCode.OPERATION_CANCELLED_BY_HOST_ERROR
    assert link.sync is None and len(link.syncs) == 7
    await tester.command(hci.HCI_Reset_Command())
    assert not link.syncs and link.sync is None
