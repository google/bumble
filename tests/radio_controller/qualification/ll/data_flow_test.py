# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LL.TS.p28, Section 4.9."""

import struct

import pytest

from bumble import hci
from bumble.l2cap import L2CAP_LE_U_DYNAMIC_CID_RANGE_START
from bumble.ll import PDU_DATA_LLID_MASK, PDU_DATA_SN_MASK, PDU_HEADER_SIZE, LlId
from tests.radio_controller.qualification.cases import (
    ProcedureMap,
    collect_cases,
    procedure_cases,
    verify_case,
)
from tests.radio_controller.qualification.peer import establish, peer_send
from tests.radio_controller.qualification.tester import (
    LOWER_CENTRAL_PUBLIC_ADDRESS,
    LOWER_PERIPHERAL_PUBLIC_ADDRESS,
)


class _FrameReceiver:
    """One L2CAP PDU's bytes and boundary, independent of transport fragmentation."""

    def __init__(self, expected):
        self.expected = expected
        self.data = bytearray()
        self.started = False

    def feed(self, data, *, start):
        if start:
            assert not self.started, 'unexpected second L2CAP start'
            self.started = True
        else:
            assert self.started, 'continuation before L2CAP start'
        self.data.extend(data)
        assert self.expected.startswith(self.data), 'L2CAP frame bytes changed'

    @property
    def complete(self):
        return self.started and self.data == self.expected


class _HostReceiver(_FrameReceiver):
    def __init__(self, tester, link, expected):
        super().__init__(expected)
        self.tester, self.link = tester, link

    def poll(self):
        while (
            packet := self.tester.take(lambda p: isinstance(p, hci.HCI_AclDataPacket))
        ) is not None:
            assert packet.connection_handle == self.link.handle
            assert packet.bc_flag == 0 and packet.data_total_length == len(packet.data)
            assert packet.pb_flag in (
                hci.HCI_ACL_PB_FIRST_FLUSHABLE,
                hci.HCI_ACL_PB_CONTINUATION,
            )
            self.feed(
                packet.data, start=packet.pb_flag == hci.HCI_ACL_PB_FIRST_FLUSHABLE
            )


def _completed_packets(tester, handle):
    completed = 0
    while (
        event := tester.take(
            lambda p: isinstance(p, hci.HCI_Number_Of_Completed_Packets_Event)
        )
    ) is not None:
        assert len(event.connection_handles) == len(event.num_completed_packets)
        for reported_handle, count in zip(
            event.connection_handles, event.num_completed_packets
        ):
            assert reported_handle == handle and count >= 0
            completed += count
    return completed


async def _transmit_frame(tester, link, frame, first_length, maximum, slots):
    fragments = [frame[:first_length]] + [
        frame[offset : offset + maximum]
        for offset in range(first_length, len(frame), maximum)
    ]
    receiver = _FrameReceiver(frame)
    submitted = completed = 0
    previous = None
    settled = False
    # Local instrument watchdog; the source imposes no per-fragment delivery deadline.
    for _ in range(128):
        await tester.wait(0)
        completed += _completed_packets(tester, link.handle)
        assert completed <= submitted, 'too many HCI completion credits'
        while submitted < len(fragments) and submitted - completed < slots:
            data = fragments[submitted]
            boundary = (
                hci.HCI_ACL_PB_FIRST_NON_FLUSHABLE
                if not submitted
                else hci.HCI_ACL_PB_CONTINUATION
            )
            tester.send(
                bytes(hci.HCI_AclDataPacket(link.handle, boundary, 0, len(data), data))
            )
            submitted += 1
        expected_sn = link.nesn
        packet = await link.exchange()
        llid, payload = packet.pdu[0] & PDU_DATA_LLID_MASK, packet.pdu[PDU_HEADER_SIZE:]
        if llid != LlId.CONTROL:
            assert llid in (LlId.START, LlId.CONTINUATION)
            assert payload or llid != LlId.START, 'zero-length LLID START on air'
            if payload:
                if int(bool(packet.pdu[0] & PDU_DATA_SN_MASK)) == expected_sn:
                    receiver.feed(payload, start=llid == LlId.START)
                    previous = llid, payload
                else:
                    assert (llid, payload) == previous, 'changed retransmission'
        completed += _completed_packets(tester, link.handle)
        assert completed <= submitted, 'too many HCI completion credits'
        if receiver.complete and completed == submitted == len(fragments):
            if settled:
                return
            settled = True
    raise AssertionError('fragmented L2CAP frame did not complete')


async def _fragmented_header(tester, *, central=False, receive=False):
    """Preserve the complete 28-octet frame in every prescribed header-split round."""
    link = await establish(
        tester,
        central=central,
        peer_address=(
            LOWER_PERIPHERAL_PUBLIC_ADDRESS if central else LOWER_CENTRAL_PUBLIC_ADDRESS
        ),
    )
    payload = bytes(range(24))
    frame = (
        struct.pack('<HH', len(payload), L2CAP_LE_U_DYNAMIC_CID_RANGE_START) + payload
    )
    if not receive:
        buffers = await tester.command(hci.HCI_LE_Read_Buffer_Size_Command())
        maximum, slots = (
            buffers.le_acl_data_packet_length,
            buffers.total_num_le_acl_data_packets,
        )
        if not slots:
            shared = await tester.command(hci.HCI_Read_Buffer_Size_Command())
            maximum, slots = (
                shared.hc_acl_data_packet_length,
                shared.hc_total_num_acl_data_packets,
            )
        if maximum < 5 or slots < 1:
            pytest.skip('HCI buffers cannot carry the source-required start fragments')
    for first_length in range(1 if receive else 0, 6):
        if receive:
            receiver = _HostReceiver(tester, link, frame)
            await peer_send(tester, link, frame[:first_length], receiver=receiver)
            await peer_send(
                tester, link, frame[first_length:], continuation=True, receiver=receiver
            )
            for _ in range(128):
                receiver.poll()
                if receiver.complete:
                    break
                await link.exchange()
            assert receiver.complete, 'fragmented L2CAP frame not delivered through HCI'
        else:
            await _transmit_frame(tester, link, frame, first_length, maximum, slots)
    await link.disconnect()


async def transmit_fragmented_l2cap_header(tester, *, central):
    """Transmit Fragmented L2CAP Header.

    Initial Condition:
        Connected to the Lower Tester in the Table 4.9-1 role, with any scan
        interval/window, public peer address, Lower Tester address, supported
        own-address type, common interval, Peripheral latency and timeout.
        Select public IUT address, 30-ms interval, zero latency and one-second
        supervision timeout. Build one 28-octet frame: a four-octet L2CAP header
        with length 24 and a dynamic LE CID, then 24 deterministic data octets.
        Read HCI buffer size/credits, using shared buffers if LE has none.

    Test Steps:
        Repeat Steps 1/2 for every Table 4.9-2 round, with start-fragment lengths
        0, 1, 2, 3, 4 and 5 octets respectively.
        1. Submit the 28-octet L2CAP frame through HCI: one start fragment of
           the selected length, followed by one or more continuation packets
           containing the remaining bytes. Respect the reported HCI payload
           limit and outstanding-packet credits. Do not wait for RF delivery of
           each individual input fragment before submitting its continuation.
        2. Receive the frame unaltered over the air. Accept legal coalescing or
           re-fragmentation, not only the input boundaries. Independently collect
           exactly one LLID START and subsequent continuations, checking all
           bytes, SN/retransmissions and complete HCI credit return. Ignore
           ordinary empty LLID CONTINUATION packets, but reject LLID START with
           zero length; the zero-octet HCI start is not a legal empty air start.

    Expected Outcome:
        Pass verdict:
            The Lower Tester receives exactly the original 28 frame octets in
            every round, with the L2CAP boundary preserved regardless of legal
            changes to fragment boundaries.

    Postamble:
        Acknowledge the final packet, drain completion credits, then terminate
        after all six rounds. This is not another numbered source step.

    Reference:
        LL.TS.p28, Section 4.9.2.1, LL/DFL/CEN/BV-01-C and LL/DFL/PER/BV-01-C;
        PDF 1293-1294, printed 4.9-2..3; Tables 4.9-1/2 and Figure 4.9-1.
        Source references [11], HCI Section 5.4.2, and [12], L2CAP Section 7.2.1.
        Boundary rules: Core Vol 1 Part A Section 5.3 and Vol 6 Part B
        Section 2.4.1. Amber confirms independent fragmentation and the
        zero-length LLID START prohibition.
    """
    await _fragmented_header(tester, receive=False, central=central)


async def receive_fragmented_l2cap_header(tester, *, central):
    """Receive Fragmented L2CAP Header.

    Initial Condition:
        Connected to the Lower Tester in the Table 4.9-3 role, with any scan
        interval/window, public peer address, Lower Tester address, supported
        own-address type, common interval, Peripheral latency and timeout.
        Select public IUT address, 30-ms interval, zero latency and one-second
        supervision timeout. Build a 28-octet L2CAP frame with a four-octet
        length/CID header and 24 deterministic data octets.

    Test Steps:
        Repeat Steps 1/2 for every Table 4.9-4 round, with start-fragment lengths
        1, 2, 3, 4 and 5 octets respectively.
        1. Send one LLID START containing the selected number of frame octets,
           followed by a single LLID CONTINUATION containing all remaining
           bytes. Preserve sequence/acknowledgement rules; do not await HCI
           delivery of the first fragment before transmitting the continuation.
        2. Receive the frame unaltered through HCI, allowing legal coalescing or
           re-fragmentation. Collect one start and subsequent continuations with
           matching handle, zero BC and consistent lengths; verify all 28 bytes
           without requiring the input split to reappear in HCI packets.

    Expected Outcome:
        Pass verdict:
            The Upper Tester receives exactly the original frame in all five
            rounds, irrespective of legal changes to fragment boundaries.

    Postamble:
        Terminate after all rounds and verify HCI disconnection. This cleanup
        is outside the two numbered source steps.

    Reference:
        LL.TS.p28, Section 4.9.2.2, LL/DFL/CEN/BV-02-C and LL/DFL/PER/BV-02-C;
        PDF 1295-1296, printed 4.9-4..5; Tables 4.9-3/4 and Figure 4.9-2.
        Source references [11], HCI Section 5.4.2, and [12], L2CAP Section 7.2.1.
        Independent boundary mapping: Core Vol 1 Part A Section 5.3, confirmed
        by Amber and explicitly allowed by the source's Step 2.
    """
    await _fragmented_header(tester, receive=True, central=central)


PROCEDURES: ProcedureMap = {}

# Verify correct transmission of an L2CAP frame when its header is split across HCI ACL
# packets, including a zero-octet HCI start fragment.
PROCEDURES |= procedure_cases(
    transmit_fragmented_l2cap_header,
    {
        'LL/DFL/CEN/BV-01-C': (
            'Transmit Fragmented L2CAP Header',
            {'central': True},
        ),
        'LL/DFL/PER/BV-01-C': (
            'Transmit Fragmented L2CAP Header',
            {'central': False},
        ),
    },
)

# Verify correct reception of an L2CAP frame whose header is split across received LL
# DATA packets, allowing different fragmentation at HCI output.
PROCEDURES |= procedure_cases(
    receive_fragmented_l2cap_header,
    {
        'LL/DFL/CEN/BV-02-C': (
            'Receive Fragmented L2CAP Header',
            {'central': True},
        ),
        'LL/DFL/PER/BV-02-C': (
            'Receive Fragmented L2CAP Header',
            {'central': False},
        ),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'identifier,description,procedure,parameters,marks',
    collect_cases(PROCEDURES),
)
async def test_data_flow(
    air_dut, identifier, description, procedure, parameters, marks
):
    await verify_case(air_dut, identifier, description, procedure, parameters, marks)
