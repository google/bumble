# Copyright 2021-2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import asyncio
import logging
import unittest
import unittest.mock

import pytest

from bumble import controller, hci
from bumble.controller import Controller
from bumble.hci import (
    HCI_AclDataPacket,
    HCI_Command_Complete_Event,
    HCI_Command_Status_Event,
    HCI_CommandStatus,
    HCI_Disconnect_Command,
    HCI_Error,
    HCI_ErrorCode,
    HCI_Event,
    HCI_GenericReturnParameters,
    HCI_LE_Terminate_BIG_Command,
    HCI_Reset_Command,
    HCI_StatusReturnParameters,
)
from bumble.host import DataPacketQueue, Host, IsoLink, IsoSdu, IsoSduAssembler
from bumble.transport.common import AsyncPipeSink, TransportSink

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'supported_commands, max_lmp_features_page_number',
    [
        (controller.Controller.supported_commands, 0),
        (
            # All commands
            set(hci.HCI_Command.command_names.keys()),
            # 3 pages of LMP features
            2,
        ),
    ],
)
async def test_reset(supported_commands: set[int], max_lmp_features_page_number: int):
    controller = Controller('C')
    controller.supported_commands = supported_commands
    controller.lmp_features_max_page_number = max_lmp_features_page_number
    host = Host(controller, AsyncPipeSink(controller))

    await host.reset()

    assert host.local_lmp_features == (
        controller.lmp_features & ~(1 << (64 * max_lmp_features_page_number + 1))
    )


@pytest.mark.asyncio
async def test_reset_enables_number_of_completed_packets_event() -> None:
    controller = Controller('C')
    controller.total_num_le_acl_data_packets = 3
    host = Host(controller, AsyncPipeSink(controller))

    await host.reset()

    completed_packets_event_bit = 1 << (hci.HCI_NUMBER_OF_COMPLETED_PACKETS_EVENT - 1)
    assert controller.event_mask & completed_packets_event_bit
    assert host.le_acl_packet_queue is not None
    assert host.le_acl_packet_queue.max_in_flight == 3


# -----------------------------------------------------------------------------
def test_data_packet_queue():
    controller = unittest.mock.Mock()
    queue = DataPacketQueue(10, 2, controller.send)
    assert queue.queued == 0
    assert queue.completed == 0
    packet = HCI_AclDataPacket(
        connection_handle=123, pb_flag=0, bc_flag=0, data_total_length=0, data=b''
    )

    queue.enqueue(packet, packet.connection_handle)
    assert queue.queued == 1
    assert queue.completed == 0
    assert controller.send.call_count == 1

    queue.enqueue(packet, packet.connection_handle)
    assert queue.queued == 2
    assert queue.completed == 0
    assert controller.send.call_count == 2

    queue.enqueue(packet, packet.connection_handle)
    assert queue.queued == 3
    assert queue.completed == 0
    assert controller.send.call_count == 2

    queue.on_packets_completed(1, 8000)
    assert queue.queued == 3
    assert queue.completed == 0
    assert controller.send.call_count == 2

    queue.on_packets_completed(1, 123)
    assert queue.queued == 3
    assert queue.completed == 1
    assert controller.send.call_count == 3

    queue.enqueue(packet, packet.connection_handle)
    assert queue.queued == 4
    assert queue.completed == 1
    assert controller.send.call_count == 3

    queue.on_packets_completed(2, 123)
    assert queue.queued == 4
    assert queue.completed == 3
    assert controller.send.call_count == 4

    queue.on_packets_completed(1, 123)
    assert queue.queued == 4
    assert queue.completed == 4
    assert controller.send.call_count == 4

    queue.enqueue(packet, 123)
    queue.enqueue(packet, 123)
    queue.enqueue(packet, 123)
    queue.enqueue(packet, 124)
    queue.enqueue(packet, 124)
    queue.enqueue(packet, 124)
    queue.on_packets_completed(1, 123)
    assert queue.queued == 10
    assert queue.completed == 5
    queue.flush(123)
    queue.flush(124)
    assert queue.queued == 10
    assert queue.completed == 10

    queue.enqueue(packet, 123)
    queue.on_packets_completed(1, 124)
    assert queue.queued == 11
    assert queue.completed == 10
    queue.on_packets_completed(1000, 123)
    assert queue.queued == 11
    assert queue.completed == 11

    drain_listener = unittest.mock.Mock()
    queue.on('flow', drain_listener.on_flow)
    queue.enqueue(packet, 123)
    assert drain_listener.on_flow.call_count == 0
    queue.on_packets_completed(1, 123)
    assert drain_listener.on_flow.call_count == 1
    queue.enqueue(packet, 123)
    queue.enqueue(packet, 123)
    queue.enqueue(packet, 123)
    queue.flush(123)
    assert drain_listener.on_flow.call_count == 1
    assert queue.queued == 15
    assert queue.completed == 15


# -----------------------------------------------------------------------------
class Source:
    terminated: asyncio.Future[None]
    sink: TransportSink

    def set_packet_sink(self, sink: TransportSink) -> None:
        self.sink = sink


class Sink:
    response: HCI_Event | None

    def __init__(self, source: Source, response: HCI_Event | None) -> None:
        self.source = source
        self.response = response

    def on_packet(self, packet: bytes) -> None:
        if self.response is not None:
            self.source.sink.on_packet(bytes(self.response))


@pytest.mark.asyncio
async def test_send_sync_command() -> None:
    source = Source()
    sink = Sink(
        source,
        HCI_Command_Complete_Event(
            1,
            HCI_Reset_Command.op_code,
            HCI_StatusReturnParameters(status=HCI_ErrorCode.SUCCESS),
        ),
    )

    host = Host(source, sink)
    host.ready = True

    # Sync command with success
    response1 = await host.send_sync_command(HCI_Reset_Command())
    assert response1.status == HCI_ErrorCode.SUCCESS

    # Sync command with error status should raise
    error_response = HCI_Command_Complete_Event(
        1,
        HCI_Reset_Command.op_code,
        HCI_StatusReturnParameters(status=HCI_ErrorCode.COMMAND_DISALLOWED_ERROR),
    )
    sink.response = error_response
    with pytest.raises(HCI_Error) as excinfo:
        await host.send_sync_command(HCI_Reset_Command())

    assert excinfo.value.error_code == error_response.return_parameters.status

    # Sync command with raw result
    response2 = await host.send_sync_command_raw(HCI_Reset_Command())
    assert response2.return_parameters.status == HCI_ErrorCode.COMMAND_DISALLOWED_ERROR

    # Sync command with a command that's not an HCI_SyncCommand
    # (here, for convenience, we use an HCI_AsyncCommand instance)
    command = HCI_Disconnect_Command(connection_handle=0x1234, reason=0x13)
    sink.response = HCI_Command_Complete_Event(
        1,
        command.op_code,
        HCI_GenericReturnParameters(data=bytes.fromhex("00112233")),
    )
    response3 = await host.send_sync_command_raw(command)  # type: ignore
    assert isinstance(response3.return_parameters, HCI_GenericReturnParameters)


@pytest.mark.asyncio
async def test_send_sync_command_timeout() -> None:
    source = Source()
    sink = Sink(source, None)

    host = Host(source, sink)
    host.ready = True

    with pytest.raises(asyncio.TimeoutError):
        await host.send_sync_command(HCI_Reset_Command(), response_timeout=0.01)

    # The sending semaphore should have been released, so this should not block
    # indefinitely
    with pytest.raises(asyncio.TimeoutError):
        await host.send_sync_command(hci.HCI_Reset_Command(), response_timeout=0.01)


@pytest.mark.asyncio
async def test_send_async_command() -> None:
    source = Source()
    sink = Sink(
        source,
        HCI_Command_Status_Event(
            HCI_CommandStatus.PENDING,
            1,
            HCI_Reset_Command.op_code,
        ),
    )

    host = Host(source, sink)
    host.ready = True

    # Normal pending status
    response = await host.send_async_command(
        HCI_LE_Terminate_BIG_Command(big_handle=0, reason=0)
    )
    assert response == HCI_CommandStatus.PENDING

    # Unknown HCI command result returned as a Command Status
    sink.response = HCI_Command_Status_Event(
        HCI_ErrorCode.UNKNOWN_HCI_COMMAND_ERROR,
        1,
        HCI_LE_Terminate_BIG_Command.op_code,
    )
    response = await host.send_async_command(
        HCI_LE_Terminate_BIG_Command(big_handle=0, reason=0), check_status=False
    )
    assert response == HCI_ErrorCode.UNKNOWN_HCI_COMMAND_ERROR

    # Unknown HCI command result returned as a Command Complete
    sink.response = HCI_Command_Complete_Event(
        1,
        HCI_LE_Terminate_BIG_Command.op_code,
        HCI_StatusReturnParameters(HCI_ErrorCode.UNKNOWN_HCI_COMMAND_ERROR),
    )
    response = await host.send_async_command(
        HCI_LE_Terminate_BIG_Command(big_handle=0, reason=0), check_status=False
    )
    assert response == HCI_ErrorCode.UNKNOWN_HCI_COMMAND_ERROR


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'iso_packet',
    [
        # Complete SDU, no Time_Stamp.
        hci.HCI_IsoDataPacket(
            connection_handle=0x60,
            data_total_length=4 + 240,
            iso_sdu_fragment=bytes(range(240)),
            pb_flag=0b10,
            packet_sequence_number=7,
            iso_sdu_length=240,
            packet_status_flag=0,
        ),
        # Empty SDU reported as lost data, no Time_Stamp.
        hci.HCI_IsoDataPacket(
            connection_handle=0x60,
            data_total_length=4,
            iso_sdu_fragment=b'',
            pb_flag=0b10,
            packet_sequence_number=8,
            iso_sdu_length=0,
            packet_status_flag=hci.HCI_IsoDataPacket.PacketStatus.LOST_DATA,
        ),
        # Complete SDU, with Time_Stamp.
        hci.HCI_IsoDataPacket(
            connection_handle=0x60,
            data_total_length=8 + 120,
            iso_sdu_fragment=bytes(120),
            pb_flag=0b10,
            time_stamp=0x12345678,
            packet_sequence_number=9,
            iso_sdu_length=120,
            packet_status_flag=0,
        ),
        # First fragment of a fragmented SDU.
        hci.HCI_IsoDataPacket(
            connection_handle=0x60,
            data_total_length=4 + 120,
            iso_sdu_fragment=bytes([1] * 120),
            pb_flag=0b00,
            packet_sequence_number=10,
            iso_sdu_length=240,
            packet_status_flag=0,
        ),
        # Last fragment of a fragmented SDU (no SDU header).
        hci.HCI_IsoDataPacket(
            connection_handle=0x60,
            data_total_length=120,
            iso_sdu_fragment=bytes([2] * 120),
            pb_flag=0b11,
        ),
    ],
)
def test_iso_data_wrapped_in_acl_packet(iso_packet: hci.HCI_IsoDataPacket) -> None:
    host = Host()
    host.cis_links[0x60] = unittest.mock.MagicMock()
    # Controllers sending ISO data over the USB Bulk endpoint deliver it as ACL data.
    raw_iso_packet = bytes(iso_packet)
    with unittest.mock.patch.object(host, 'on_hci_iso_data_packet') as handler:
        host.on_hci_acl_data_packet(
            HCI_AclDataPacket.from_bytes(
                bytes([hci.HCI_ACL_DATA_PACKET]) + raw_iso_packet[1:]
            )
        )

    received = [call.args[0] for call in handler.call_args_list]
    assert len(received) == 1
    assert bytes(received[0]) == raw_iso_packet
    assert received[0].pb_flag == iso_packet.pb_flag
    assert received[0].time_stamp == iso_packet.time_stamp
    assert received[0].iso_sdu_length == iso_packet.iso_sdu_length
    assert received[0].iso_sdu_fragment == iso_packet.iso_sdu_fragment


# -----------------------------------------------------------------------------
def _iso_fragments(
    sdu: bytes,
    fragment_size: int,
    time_stamp: int | None = None,
    packet_sequence_number: int = 0,
    packet_status_flag: int = 0,
    connection_handle: int = 0x60,
) -> list[hci.HCI_IsoDataPacket]:
    chunks = [sdu[i : i + fragment_size] for i in range(0, len(sdu), fragment_size)]
    chunks = chunks or [b'']
    packets = []
    for index, chunk in enumerate(chunks):
        is_first = index == 0
        is_last = index == len(chunks) - 1
        if is_first:
            packets.append(
                hci.HCI_IsoDataPacket(
                    connection_handle=connection_handle,
                    data_total_length=(4 if time_stamp is not None else 0)
                    + 4
                    + len(chunk),
                    iso_sdu_fragment=chunk,
                    pb_flag=0b10 if is_last else 0b00,
                    time_stamp=time_stamp,
                    packet_sequence_number=packet_sequence_number,
                    iso_sdu_length=len(sdu),
                    packet_status_flag=packet_status_flag,
                )
            )
        else:
            packets.append(
                hci.HCI_IsoDataPacket(
                    connection_handle=connection_handle,
                    data_total_length=len(chunk),
                    iso_sdu_fragment=chunk,
                    pb_flag=0b11 if is_last else 0b01,
                )
            )
    return packets


def _feed(
    assembler: IsoSduAssembler, packets: list[hci.HCI_IsoDataPacket]
) -> list[IsoSdu]:
    return [
        sdu for packet in packets if (sdu := assembler.feed_packet(packet)) is not None
    ]


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'sdu_length,fragment_size,time_stamp',
    [
        (0, 10, None),
        (100, 100, None),
        (100, 100, 0x12345678),
        (100, 40, None),
        (240, 60, 0xAABBCCDD),
        (200, 100, None),
    ],
)
def test_iso_sdu_assembler(
    sdu_length: int, fragment_size: int, time_stamp: int | None
) -> None:
    data = bytes(i & 0xFF for i in range(sdu_length))
    # Round-trip through bytes to exercise the parser as well.
    packets = [
        hci.HCI_IsoDataPacket.from_bytes(bytes(packet))
        for packet in _iso_fragments(data, fragment_size, time_stamp, 42)
    ]

    assert _feed(IsoSduAssembler(), packets) == [
        IsoSdu(data=data, packet_sequence_number=42, time_stamp=time_stamp)
    ]


# -----------------------------------------------------------------------------
@pytest.mark.parametrize('packet_status', list(hci.HCI_IsoDataPacket.PacketStatus))
def test_iso_sdu_assembler_packet_status(
    packet_status: hci.HCI_IsoDataPacket.PacketStatus,
) -> None:
    packets = [
        hci.HCI_IsoDataPacket.from_bytes(bytes(packet))
        for packet in _iso_fragments(bytes(10), 10, packet_status_flag=packet_status)
    ]
    (sdu,) = _feed(IsoSduAssembler(), packets)
    assert sdu.packet_status == packet_status


# -----------------------------------------------------------------------------
def test_iso_sdu_assembler_multiple_sdus() -> None:
    assembler = IsoSduAssembler()
    sdus = [bytes([n]) * (50 + n * 30) for n in range(5)]
    received = []
    for psn, sdu in enumerate(sdus):
        received += _feed(
            assembler, _iso_fragments(sdu, 40, packet_sequence_number=psn)
        )

    assert [sdu.data for sdu in received] == sdus
    assert [sdu.packet_sequence_number for sdu in received] == list(range(5))


# -----------------------------------------------------------------------------
def test_iso_sdu_assembler_continuation_without_start() -> None:
    assembler = IsoSduAssembler()

    # Drop the first fragment: continuation and last must be discarded.
    assert not _feed(assembler, _iso_fragments(bytes(100), 40)[1:])

    # The assembler recovers on the next SDU.
    received = _feed(assembler, _iso_fragments(bytes(range(80)), 40))
    assert [sdu.data for sdu in received] == [bytes(range(80))]


# -----------------------------------------------------------------------------
def test_iso_sdu_assembler_new_start_discards_partial() -> None:
    assembler = IsoSduAssembler()

    # Feed only the first fragment of an SDU, then a complete new SDU.
    assert not _feed(assembler, _iso_fragments(bytes(100), 40)[:1])
    received = _feed(
        assembler, _iso_fragments(bytes([7]) * 90, 40, packet_sequence_number=1)
    )

    assert [(sdu.data, sdu.packet_sequence_number) for sdu in received] == [
        (bytes([7]) * 90, 1)
    ]


# -----------------------------------------------------------------------------
def test_iso_sdu_assembler_length_mismatch() -> None:
    assembler = IsoSduAssembler()

    # Data exceeding ISO_SDU_Length is dropped.
    fragments = _iso_fragments(bytes(100), 40)
    fragments[1].iso_sdu_fragment = bytes(80)
    assert not _feed(assembler, fragments)
    assert assembler.first_packet is None

    # Last fragment arriving before ISO_SDU_Length is reached is dropped.
    fragments = _iso_fragments(bytes(100), 40)
    fragments[2].iso_sdu_fragment = bytes(5)
    assert not _feed(assembler, fragments)
    assert assembler.first_packet is None

    # Complete SDU whose payload does not match ISO_SDU_Length is dropped.
    (packet,) = _iso_fragments(bytes(20), 40)
    packet.iso_sdu_length = 30
    assert not _feed(assembler, [packet])
    assert assembler.first_packet is None


# -----------------------------------------------------------------------------
def test_host_emits_iso_sdu() -> None:
    host = Host()
    host.cis_links[0x60] = IsoLink(handle=0x60, packet_queue=unittest.mock.Mock())
    host.bis_links[0x61] = IsoLink(handle=0x61, packet_queue=unittest.mock.Mock())
    received: list[tuple[int, IsoSdu]] = []
    host.on('iso_sdu', lambda handle, sdu: received.append((handle, sdu)))

    # Interleave fragments of two links: each link has its own assembler.
    cis_packets = _iso_fragments(bytes([1]) * 100, 40, connection_handle=0x60)
    bis_packets = _iso_fragments(bytes([2]) * 70, 40, connection_handle=0x61)
    for index in range(max(len(cis_packets), len(bis_packets))):
        for packets in (cis_packets, bis_packets):
            if index < len(packets):
                host.on_hci_iso_data_packet(packets[index])

    # Data for unknown handles is ignored.
    for packet in _iso_fragments(bytes(10), 40, connection_handle=0x70):
        host.on_hci_iso_data_packet(packet)

    assert received == [
        (0x61, IsoSdu(data=bytes([2]) * 70, packet_sequence_number=0)),
        (0x60, IsoSdu(data=bytes([1]) * 100, packet_sequence_number=0)),
    ]
