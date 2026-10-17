# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Advertising fragment transactions, event budgets and atomic enable."""

from types import SimpleNamespace

import pytest

from bumble import hci
from bumble.controller import AdvertisingSet, Controller
from bumble.hci import HCI_LE_ADV_DATA_SIZE_MAX
from bumble.radio_controller.controller_backend import RadioBackend
from bumble.radio_controller.radio import RADIO_ADVERTISING_SET_COUNT, Phy
from bumble.radio_controller.radio_discovery import Advertising
from bumble.radio_controller.radio_extended import advertising_time_us, periodic_time_us
from tests.radio_controller.unit.helpers import extended_parameters

ErrorCode = hci.HCI_ErrorCode

DataOperation = hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation

ADDRESS = hci.Address('F0:F1:F2:F3:F4:01', hci.AddressType.PUBLIC_DEVICE)


def radio_backend():
    return RadioBackend(SimpleNamespace(now_us=0))


@pytest.mark.parametrize('phy', list(Phy))
def test_periodic_maximum_chain_budget(connection, phy):
    p = connection.link.listener
    item = Advertising(
        p.controller.public_address,
        extended=True,
        secondary_phy=phy,
        periodic_interval=400,
    )
    p.link.advertisers[0] = item
    for index in range(0, HCI_LE_ADV_DATA_SIZE_MAX, 250):
        operation = (
            DataOperation.FIRST_FRAGMENT
            if index == 0
            else (
                DataOperation.LAST_FRAGMENT
                if index + 250 >= HCI_LE_ADV_DATA_SIZE_MAX
                else DataOperation.INTERMEDIATE_FRAGMENT
            )
        )
        assert (
            p._set_data(
                0,
                operation,
                bytes(min(250, HCI_LE_ADV_DATA_SIZE_MAX - index)),
                'periodic_data',
            ).status
            == ErrorCode.SUCCESS
        )
    assert len(item.periodic_data) == HCI_LE_ADV_DATA_SIZE_MAX
    assert 0 < periodic_time_us(item) < 500_000
    assert (
        p.on_hci_le_set_periodic_advertising_enable_command(
            hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0)
        ).status
        == ErrorCode.SUCCESS
    )


def test_active_data_update_discards_data_when_event_would_not_fit(connection):
    procedures = connection.link.listener
    item = Advertising(
        procedures.controller.public_address,
        extended=True,
        enabled=True,
        primary_phy=Phy.LE_CODED,
        secondary_phy=Phy.LE_CODED,
        interval_us=20_000,
        interval_max_us=20_000,
        data=b'old',
    )
    procedures.link.advertisers[0] = item
    result = procedures._set_data(0, 3, bytes(250), 'data')
    assert result.status == ErrorCode.PACKET_TOO_LONG_ERROR
    assert not item.data and item.did == 0
    assert not procedures.fragments


def test_enable_selects_interval_that_fits_data_within_host_range(connection):
    procedures = connection.link.listener
    item = Advertising(
        procedures.controller.public_address,
        extended=True,
        primary_phy=Phy.LE_CODED,
        secondary_phy=Phy.LE_CODED,
        interval_us=20_000,
        interval_max_us=100_000,
    )
    procedures.link.advertisers[0] = item
    result = procedures._set_data(0, 3, bytes(250), 'data')
    assert result.status == ErrorCode.SUCCESS
    procedures.link.connections.clear()
    result = procedures.on_hci_le_set_extended_advertising_enable_command(
        hci.HCI_LE_Set_Extended_Advertising_Enable_Command(1, [0], [0], [0])
    )
    assert result.status == ErrorCode.SUCCESS
    assert 20_000 < advertising_time_us(item) <= item.interval_us <= 100_000
    assert item.interval_us % 625 == 0


def test_periodic_enable_rejects_combination_without_radio_time(connection):
    procedures = connection.link.listener
    item = Advertising(
        procedures.controller.public_address,
        extended=True,
        secondary_phy=Phy.LE_CODED,
        periodic_interval=6,
        data=bytes(191),
    )
    procedures.link.advertisers[0] = item
    result = procedures.on_hci_le_set_periodic_advertising_enable_command(
        hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(1, 0)
    )
    assert result.status == ErrorCode.COMMAND_DISALLOWED_ERROR
    assert not item.periodic_enabled


def test_periodic_data_update_rejects_unavailable_radio_budget(connection):
    procedures = connection.link.listener
    item = Advertising(
        procedures.controller.public_address,
        extended=True,
        secondary_phy=Phy.LE_CODED,
        periodic_interval=6,
        periodic_enabled=True,
        periodic_data=b'old',
    )
    procedures.link.advertisers[0] = item
    result = procedures._set_data(0, 3, bytes(191), 'periodic_data')
    assert result.status == ErrorCode.PACKET_TOO_LONG_ERROR
    assert not item.periodic_data


@pytest.mark.asyncio
async def test_radio_advertising_uses_controller_owned_set_records():
    backend = radio_backend()
    controller = Controller('radio', backend=backend, public_address=ADDRESS)
    procedures = controller.le_procedures
    assert procedures is not None
    backend.link.advertisers[0] = Advertising(ADDRESS, extended=True)
    controller.advertising_sets[0] = AdvertisingSet(controller, 0)
    assert procedures._set_data(0, 1, b'first', 'data').status == ErrorCode.SUCCESS
    assert not controller.advertising_sets[0].data
    assert procedures._set_data(0, 2, b'last', 'data').status == ErrorCode.SUCCESS
    assert controller.advertising_sets[0].data == b'firstlast'
    assert backend.link.advertisers[0].data == b'firstlast'
    assert not procedures.fragments
    assert (
        procedures._set_data(0, 2, b'bad', 'data').status
        == ErrorCode.COMMAND_DISALLOWED_ERROR
    )
    assert (
        procedures._set_data(0, 3, bytes(HCI_LE_ADV_DATA_SIZE_MAX + 1), 'data').status
        == ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR
    )
    assert not controller.advertising_sets[0].data
    assert not backend.link.advertisers[0].data
    assert (
        procedures.on_hci_le_remove_advertising_set_command(
            hci.HCI_LE_Remove_Advertising_Set_Command(0)
        ).status
        == ErrorCode.SUCCESS
    )
    assert not controller.advertising_sets and not backend.link.advertisers


async def test_advertising_capacity_and_atomic_enable(hci_dut):
    tester = hci_dut
    result = await tester.command(
        hci.HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command()
    )
    assert result.num_supported_advertising_sets == RADIO_ADVERTISING_SET_COUNT
    for handle in range(result.num_supported_advertising_sets):
        await tester.command(extended_parameters(advertising_handle=handle))
    await tester.command(
        extended_parameters(advertising_handle=result.num_supported_advertising_sets),
        ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR,
    )
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Enable_Command(1, [0, 254], [0, 0], [0, 0]),
        ErrorCode.UNKNOWN_ADVERTISING_IDENTIFIER_ERROR,
    )
    assert not any(
        item.enabled for item in tester.input.backend.link.advertisers.values()
    )
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Enable_Command(1, [0, 1], [0, 0], [0, 0])
    )
    assert all(
        tester.input.backend.link.advertisers[handle].enabled for handle in (0, 1)
    )
    await tester.command(
        hci.HCI_LE_Set_Extended_Advertising_Enable_Command(0, [], [], [])
    )
    await tester.command(hci.HCI_LE_Clear_Advertising_Sets_Command())


def test_random_address_update_is_atomic_and_preserves_address_selection(controller):
    commands = controller.le_procedures
    new_address = hci.Address('C0:12:34:56:78:9A')
    for handle, own in enumerate(
        (hci.OwnAddressType.PUBLIC, hci.OwnAddressType.RANDOM)
    ):
        assert (
            commands.on_hci_le_set_extended_advertising_parameters_command(
                extended_parameters(advertising_handle=handle, own_address_type=own)
            ).status
            == ErrorCode.SUCCESS
        )
        item = controller.backend.link.advertisers[handle]
        original_address = item.address
        command = hci.HCI_LE_Set_Advertising_Set_Random_Address_Command(
            handle, new_address
        )
        item.enabled = True
        assert (
            commands.on_hci_le_set_advertising_set_random_address_command(
                command
            ).status
            == ErrorCode.COMMAND_DISALLOWED_ERROR
        )
        assert item.address == original_address and item.random_address is None
        item.enabled = False
        assert (
            commands.on_hci_le_set_advertising_set_random_address_command(
                command
            ).status
            == ErrorCode.SUCCESS
        )
        assert controller.advertising_sets[handle].random_address == new_address
        assert item.address == (
            new_address if own == hci.OwnAddressType.RANDOM else original_address
        )
    assert (
        commands.on_hci_le_set_advertising_set_random_address_command(
            hci.HCI_LE_Set_Advertising_Set_Random_Address_Command(99, new_address)
        ).status
        == ErrorCode.UNKNOWN_ADVERTISING_IDENTIFIER_ERROR
    )
