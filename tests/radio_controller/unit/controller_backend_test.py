# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI decoding, backend isolation and binding ownership."""

from types import SimpleNamespace

import pytest

from bumble import hci
from bumble.controller import Controller
from bumble.link import LocalLink
from bumble.radio_controller.controller_backend import RadioBackend
from bumble.radio_controller.radio import RADIO_HCI_ACL_BUFFER_SIZE

ErrorCode = hci.HCI_ErrorCode

ADDRESS = hci.Address('F0:F1:F2:F3:F4:01', hci.AddressType.PUBLIC_DEVICE)


def radio_backend():
    return RadioBackend(SimpleNamespace(now_us=0))


@pytest.mark.asyncio
async def test_controller_default_link_keeps_original_unregistered_behavior():
    controller = Controller('local')
    assert isinstance(controller.link, LocalLink)
    assert controller not in controller.link.controllers
    assert controller.le_procedures is None


@pytest.mark.asyncio
async def test_existing_link_constructor_keeps_local_behavior():
    link = LocalLink()
    controller = Controller('local', link=link)
    assert controller.link is link
    assert controller in link.controllers
    assert controller.le_procedures is None


@pytest.mark.asyncio
@pytest.mark.parametrize('use_radio', [False, True])
async def test_same_controller_decodes_hci_and_builds_command_complete(use_radio):
    controller = Controller(
        'test', backend=radio_backend() if use_radio else None, public_address=ADDRESS
    )
    packets = []
    controller.send_hci_packet = packets.append
    controller.on_packet(bytes(hci.HCI_Read_BD_ADDR_Command()))
    assert len(packets) == 1
    event = packets[0]
    assert isinstance(event, hci.HCI_Command_Complete_Event)
    assert event.command_opcode == hci.HCI_READ_BD_ADDR_COMMAND
    assert event.return_parameters.status == ErrorCode.SUCCESS
    assert event.return_parameters.bd_addr == ADDRESS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'opcode,parameters',
    [
        (hci.HCI_READ_LOCAL_EXTENDED_FEATURES_COMMAND, b''),
        (hci.HCI_READ_LOCAL_EXTENDED_FEATURES_COMMAND, bytes(255)),
        (hci.HCI_CREATE_CONNECTION_COMMAND, b'\xff'),
    ],
)
async def test_unsupported_command_is_rejected_before_parameter_decoding(
    opcode, parameters
):
    controller = Controller('radio', backend=radio_backend())
    packets = []
    controller.send_hci_packet = packets.append
    controller.on_packet(bytes(hci.HCI_Command(parameters, op_code=opcode)))
    assert len(packets) == 1
    event = packets[0]
    assert event.command_opcode == opcode and event.num_hci_command_packets == 1
    if isinstance(event, hci.HCI_Command_Status_Event):
        assert event.status == ErrorCode.UNKNOWN_HCI_COMMAND_ERROR
    else:
        assert isinstance(event, hci.HCI_Command_Complete_Event)
        assert event.return_parameters.status == ErrorCode.UNKNOWN_HCI_COMMAND_ERROR


@pytest.mark.asyncio
async def test_unsupported_opcode_does_not_bypass_hci_frame_length_validation():
    from bumble.core import InvalidPacketError

    controller = Controller('radio', backend=radio_backend())
    packets = []
    controller.send_hci_packet = packets.append
    packet = bytearray(bytes(hci.HCI_Command(b'', op_code=hci.HCI_INQUIRY_COMMAND)))
    packet[3] = 1
    with pytest.raises(InvalidPacketError):
        controller.on_packet(packet)
    assert not packets


@pytest.mark.asyncio
async def test_backend_capabilities_do_not_change_other_controllers():
    local = Controller('local')
    supported = local.supported_commands.copy()
    radio = Controller('radio', backend=radio_backend())
    assert radio.le_features & hci.LeFeatureMask.LE_PERIODIC_ADVERTISING
    assert radio.le_features & hci.LeFeatureMask.LE_ENCRYPTION
    assert (
        radio.le_features & hci.LeFeatureMask.MINIMUM_NUMBER_OF_USED_CHANNELS_PROCEDURE
    )
    assert radio.le_acl_data_packet_length == RADIO_HCI_ACL_BUFFER_SIZE
    assert local.le_features & hci.LeFeatureMask.LE_ENCRYPTION
    assert local.supported_commands == supported


@pytest.mark.asyncio
async def test_radio_never_falls_back_to_local_encryption():
    controller = Controller('radio', backend=radio_backend())
    packets = []
    controller.send_hci_packet = packets.append
    controller.on_packet(
        bytes(
            hci.HCI_LE_Enable_Encryption_Command(
                connection_handle=1,
                random_number=bytes(8),
                encrypted_diversifier=0,
                long_term_key=bytes(16),
            )
        )
    )
    assert isinstance(packets[0], hci.HCI_Command_Status_Event)
    assert packets[0].status == ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
    assert controller.link is None


@pytest.mark.asyncio
async def test_link_and_backend_are_mutually_exclusive():
    with pytest.raises(ValueError, match='either link or backend'):
        Controller('test', link=LocalLink(), backend=radio_backend())


@pytest.mark.asyncio
async def test_backend_cannot_be_shared_by_controller_instances():
    backend = radio_backend()
    Controller('first', backend=backend)
    with pytest.raises(ValueError, match='one Controller'):
        Controller('second', backend=backend)
