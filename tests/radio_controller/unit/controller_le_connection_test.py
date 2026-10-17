# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Command failure atomicity and connection-specific routing."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from bumble import hci
from bumble.controller import Controller
from bumble.ll import PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
from bumble.radio_controller.controller_backend import RadioBackend
from bumble.radio_controller.radio import (
    RADIO_CONNECTION_COUNT,
    RADIO_RSSI_NOT_AVAILABLE,
    Received,
)
from bumble.radio_controller.radio_control import InstantUpdate
from tests.radio_controller.unit.helpers import add_connection, create_connection

ErrorCode = hci.HCI_ErrorCode

ADDRESS = hci.Address('F0:F1:F2:F3:F4:01', hci.AddressType.PUBLIC_DEVICE)


def radio_backend():
    return RadioBackend(SimpleNamespace(now_us=0))


@pytest.mark.asyncio
@pytest.mark.parametrize('initiating', [False, True])
async def test_radio_random_address_change_is_atomic_during_initiation(initiating):
    controller = Controller('radio', backend=radio_backend(), public_address=ADDRESS)
    old_address = controller.random_address
    new_address = hci.Address('C0:12:34:56:78:9A')
    if initiating:
        controller.le_procedures.link.initiating = SimpleNamespace()
    packets = []
    controller.send_hci_packet = packets.append
    controller.on_packet(bytes(hci.HCI_LE_Set_Random_Address_Command(new_address)))
    assert len(packets) == 1
    event = packets[0]
    assert isinstance(event, hci.HCI_Command_Complete_Event)
    assert event.command_opcode == hci.HCI_LE_SET_RANDOM_ADDRESS_COMMAND
    assert event.return_parameters.status == (
        ErrorCode.COMMAND_DISALLOWED_ERROR if initiating else ErrorCode.SUCCESS
    )
    assert controller.random_address == (old_address if initiating else new_address)


def test_read_rssi_uses_received_strength_and_distinguishes_unknown_handle(connection):
    connection.report_created()
    listener = connection.link.listener
    command = hci.HCI_Read_RSSI_Command(connection.handle)
    assert listener.on_hci_read_rssi_command(command).rssi == RADIO_RSSI_NOT_AVAILABLE
    connection.radio.incoming.append(Received(b'\x01\x00', -53.4, 1300, 1380, True))
    asyncio.run(connection.receive(7, 2000))
    result = listener.on_hci_read_rssi_command(command)
    assert result.status == ErrorCode.SUCCESS and result.rssi == -53
    connection.radio.incoming.append(Received(b'\x01\x00', -80, 2300, 2380, False))
    asyncio.run(connection.receive(7, 2500))
    assert listener.on_hci_read_rssi_command(command).rssi == -53
    assert (
        listener.on_hci_read_rssi_command(
            hci.HCI_Read_RSSI_Command(connection.handle + 1)
        ).status
        == ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
    )


def test_hci_acl_and_disconnect_route_to_only_the_selected_handle(connection):
    second = add_connection(connection, 1)
    listener = connection.link.listener
    packet = hci.HCI_AclDataPacket(
        second.handle, hci.HCI_ACL_PB_FIRST_FLUSHABLE, 0, 6, b'second'
    )
    listener.on_hci_acl_data_packet(packet)
    assert not connection.queue and second.queue[-1].payload == b'second'
    listener.on_hci_disconnect_command(
        hci.HCI_Disconnect_Command(
            second.handle, ErrorCode.REMOTE_USER_TERMINATED_CONNECTION_ERROR
        )
    )
    assert not connection.queue and len(second.queue) == 2
    second.complete(ErrorCode.CONNECTION_TERMINATED_BY_LOCAL_HOST_ERROR)
    assert connection.link.connections == {connection.handle: connection}
    assert (
        listener.controller.find_le_connection_by_handle(connection.handle) is not None
    )
    assert listener.controller.find_le_connection_by_handle(second.handle) is None


def test_peer_duplicates_and_shared_connection_capacity(connection):
    connection.report_created()
    listener = connection.link.listener
    listener.on_hci_le_create_connection_command(
        create_connection(peer_address=connection.peer)
    )
    assert (
        listener.controller.events[-1].status
        == ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR
    )
    for index in range(1, RADIO_CONNECTION_COUNT):
        add_connection(connection, index, hci.Role(index % 2))
    listener.on_hci_le_create_connection_command(create_connection())
    assert (
        listener.controller.events[-1].status
        == ErrorCode.CONNECTION_LIMIT_EXCEEDED_ERROR
    )
    assert len(connection.link.connections) == RADIO_CONNECTION_COUNT


@pytest.mark.parametrize('existing_extended', [False, True])
def test_rejected_initiating_command_preserves_pending_context(
    connection, existing_extended
):
    listener = connection.link.listener
    if existing_extended:
        listener.on_hci_le_extended_create_connection_command(
            create_connection(extended=True)
        )
    else:
        listener.on_hci_le_create_connection_command(create_connection())
    attempt = connection.link.initiating
    assert attempt is not None
    before = replace(attempt)
    random_state = connection.link.random.getstate()
    command = create_connection(extended=True, initiating_phys=hci.PhyBit.LE_CODED)
    listener.on_hci_le_extended_create_connection_command(command)
    assert listener.controller.events[-1].status == ErrorCode.COMMAND_DISALLOWED_ERROR
    assert listener.controller.events[-1].command_opcode == command.op_code
    assert connection.link.initiating is attempt and attempt == before
    assert connection.link.random.getstate() == random_state


@pytest.mark.parametrize('extended', [False, True])
def test_initiating_templates_do_not_allocate_wire_identity(connection, extended):
    link = connection.link
    random_state = link.random.getstate()
    command = create_connection(extended=extended)
    handler = (
        link.listener.on_hci_le_extended_create_connection_command
        if extended
        else link.listener.on_hci_le_create_connection_command
    )
    handler(command)
    assert link.initiating is not None
    for parameters in link.initiating.phy_parameters.values():
        assert (parameters.access_address, parameters.crc_init, parameters.hop) == (
            0,
            0,
            0,
        )
    assert link.random.getstate() == random_state


def test_host_channel_classification_is_atomic_and_only_targets_centrals(connection):
    connection.role = hci.Role.CENTRAL
    second = add_connection(connection, 1)
    peripheral = add_connection(connection, 2, hci.Role.PERIPHERAL)
    channel_map = (1 << 2) | (1 << 8)
    second.controls.pending = InstantUpdate(6, channel_map=channel_map)
    command = hci.HCI_LE_Set_Host_Channel_Classification_Command(
        channel_map.to_bytes(5, 'little')
    )
    listener = connection.link.listener
    assert (
        listener.on_hci_le_set_host_channel_classification_command(command).status
        == ErrorCode.COMMAND_DISALLOWED_ERROR
    )
    assert connection.controls.pending is None
    second.controls.pending = None
    assert (
        listener.on_hci_le_set_host_channel_classification_command(command).status
        == ErrorCode.SUCCESS
    )
    assert (
        connection.controls.pending.channel_map
        == second.controls.pending.channel_map
        == channel_map
    )
    assert peripheral.controls.pending is None


def test_hci_busy_or_known_unsupported_peer(connection):
    connection.establish()
    p = connection.link.listener
    command = hci.HCI_LE_Set_Data_Length_Command(
        connection.handle, PDU_DATA_PAYLOAD_SIZE_MAX, PDU_DATA_PAYLOAD_TIME_CODED_MAX_US
    )
    connection.peer_features = 0
    assert (
        p.on_hci_le_set_data_length_command(command).status
        == ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
    )
    connection.peer_features = int(hci.LeFeatureMask.LE_DATA_PACKET_LENGTH_EXTENSION)
    assert p.on_hci_le_set_data_length_command(command).status == ErrorCode.SUCCESS
    assert (
        p.on_hci_le_set_data_length_command(command).status
        == ErrorCode.COMMAND_DISALLOWED_ERROR
    )
