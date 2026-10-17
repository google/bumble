# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""HCI.TS.p39, Section 4.5: Controller Flow Control."""

import struct

import pytest

from bumble import hci
from bumble.l2cap import L2CAP_LE_U_DYNAMIC_CID_RANGE_START
from bumble.ll import PDU_DATA_PAYLOAD_SIZE_MAX
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.peer import establish, host_send

# The configured DUT declares eight 251-octet HCI ACL buffers.
EXPECTED_HCI_ACL_LENGTH = PDU_DATA_PAYLOAD_SIZE_MAX
EXPECTED_HCI_ACL_BUFFERS = 8
L2CAP_BASIC_HEADER_SIZE = struct.calcsize('<HH')
PACKETS_PER_LENGTH = 5


async def buffer_size(tester):
    """Buffer Size.

    Initial Condition:
        No LL connection exists. The test configuration declares eight
        251-octet HCI ACL buffers independently of the Controller implementation.

    Test Steps:
        The source describes an unnumbered procedure and Figure 4.12:
        - Before connecting, send LE Read Buffer Size and require successful
          Command Complete; retain the returned packet length N and count.
        - Establish an LE ACL with the independent Lower Tester.
        - Repeat the complete pair in the MSC five times: send one valid L2CAP
          packet with one data octet and a four-octet header (HCI length 5),
          observe RF delivery and one completed-packet response; then send one
          buffer-sized L2CAP packet (HCI length N, payload N-4), observe RF
          delivery and one completed-packet response.

    Observation Setup:
        Check both capacity fields against this DUT's declared configuration.
        Reassemble each packet's RF fragments and verify exact contents, LL
        boundary flags, acknowledgement and one HCI completion credit.
        Disconnect after all five pairs; teardown is not a source step.

    Expected Outcome:
        Pass verdict: Command Complete has Success, matching opcode, one command
        credit and correct packet-length/count fields. Each packet in both
        five repeated pairs produces exactly one Number Of Completed Packets credit.

    Reference:
        HCI.TS.p39.pdf, Section 4.5, independently titled procedure
        HCI/CFC/BV-02-C, Figure 4.12 and L2CAP note; PDF/printed pages 42-43.
        Source reference [8], Section 7.8.2.
    """
    result = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
    length = result.le_acl_data_packet_length
    assert length == EXPECTED_HCI_ACL_LENGTH
    assert result.total_num_le_acl_data_packets == EXPECTED_HCI_ACL_BUFFERS
    link = await establish(tester, central=True)
    for index in range(PACKETS_PER_LENGTH):
        for size in (1, length - L2CAP_BASIC_HEADER_SIZE):
            payload = struct.pack('<HH', size, L2CAP_LE_U_DYNAMIC_CID_RANGE_START)
            payload += bytes([index + 1]) * size
            await host_send(tester, link, payload)
    await link.disconnect(local=True)


PROCEDURES: ProcedureMap = {}

# Verify the reported LE Controller buffer size and completed-packet flow control for
# single-data-octet and buffer-sized L2CAP packets.
PROCEDURES |= procedure_cases(
    buffer_size,
    {
        'HCI/CFC/BV-02-C': (
            'Buffer Size',
            {},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_controller_flow_control(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
