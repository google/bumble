# Copyright 2021-2022 Google LLC
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
import itertools
import logging
import os
import random
from collections.abc import Sequence
from unittest import mock

import pytest

from bumble import core, l2cap
from bumble.testing.test_utils import TwoDevices, async_barrier

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
def test_helpers():
    psm = l2cap.L2CAP_Connection_Request.serialize_psm(0x01)
    assert psm == bytes([0x01, 0x00])

    psm = l2cap.L2CAP_Connection_Request.serialize_psm(0x1023)
    assert psm == bytes([0x23, 0x10])

    psm = l2cap.L2CAP_Connection_Request.serialize_psm(0x242311)
    assert psm == bytes([0x11, 0x23, 0x24])

    offset, psm = l2cap.L2CAP_Connection_Request.parse_psm(
        bytes([0x00, 0x01, 0x00, 0x44]), 1
    )
    assert offset == 3
    assert psm == 0x01

    offset, psm = l2cap.L2CAP_Connection_Request.parse_psm(
        bytes([0x00, 0x23, 0x10, 0x44]), 1
    )
    assert offset == 3
    assert psm == 0x1023

    offset, psm = l2cap.L2CAP_Connection_Request.parse_psm(
        bytes([0x00, 0x11, 0x23, 0x24, 0x44]), 1
    )
    assert offset == 4
    assert psm == 0x242311

    rq = l2cap.L2CAP_Connection_Request(psm=0x01, source_cid=0x44, identifier=0x88)
    brq = bytes(rq)
    srq = l2cap.L2CAP_Connection_Request.from_bytes(brq)
    assert isinstance(srq, l2cap.L2CAP_Connection_Request)
    assert srq.psm == rq.psm
    assert srq.source_cid == rq.source_cid
    assert srq.identifier == rq.identifier


# -----------------------------------------------------------------------------
def test_l2cap_credit_based_connection_request() -> None:
    frame = l2cap.L2CAP_Credit_Based_Connection_Request(
        identifier=1, spsm=2, mtu=3, mps=4, initial_credits=5, source_cid=[6, 7, 8]
    )

    parsed = l2cap.L2CAP_Control_Frame.from_bytes(bytes(frame))
    assert parsed == frame


# -----------------------------------------------------------------------------
def test_l2cap_credit_based_connection_response() -> None:
    frame = l2cap.L2CAP_Credit_Based_Connection_Response(
        identifier=1,
        mtu=2,
        mps=3,
        initial_credits=4,
        result=l2cap.L2CAP_Credit_Based_Connection_Response.Result.ALL_CONNECTIONS_PENDING_AUTHENTICATION_PENDING,
        destination_cid=[6, 7, 8],
    )

    parsed = l2cap.L2CAP_Control_Frame.from_bytes(bytes(frame))
    assert parsed == frame


# -----------------------------------------------------------------------------
def test_l2cap_credit_based_reconfigure_request() -> None:
    frame = l2cap.L2CAP_Credit_Based_Reconfigure_Request(
        identifier=1,
        mtu=2,
        mps=3,
        destination_cid=[6, 7, 8],
    )

    parsed = l2cap.L2CAP_Control_Frame.from_bytes(bytes(frame))
    assert parsed == frame


# -----------------------------------------------------------------------------
def test_l2cap_credit_based_reconfigure_response() -> None:
    frame = l2cap.L2CAP_Credit_Based_Reconfigure_Response(
        identifier=1,
        result=l2cap.L2CAP_Credit_Based_Reconfigure_Response.Result.RECONFIGURATION_FAILED_OTHER_UNACCEPTABLE_PARAMETERS,
    )

    parsed = l2cap.L2CAP_Control_Frame.from_bytes(bytes(frame))
    assert parsed == frame


# -----------------------------------------------------------------------------
def test_unimplemented_control_frame():
    frame = l2cap.L2CAP_Control_Frame(identifier=1)
    frame.code = 0xFF
    frame.payload = b'123456'

    parsed = l2cap.L2CAP_Control_Frame.from_bytes(bytes(frame))
    assert parsed.code == 0xFF
    assert parsed.payload == b'123456'


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_basic_connection():
    devices = TwoDevices()
    await devices.setup_connection()
    psm = 1234

    # Check that if there's no one listening, we can't connect
    with pytest.raises(core.ProtocolError):
        l2cap_channel = await devices.connections[0].create_l2cap_channel(
            spec=l2cap.LeCreditBasedChannelSpec(psm)
        )

    # Now add a listener
    incoming_channel = None
    received = []

    def on_coc(channel):
        nonlocal incoming_channel
        incoming_channel = channel

        def on_data(data):
            received.append(data)

        channel.sink = on_data

    devices.devices[1].create_l2cap_server(
        spec=l2cap.LeCreditBasedChannelSpec(psm=1234), handler=on_coc
    )
    l2cap_channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.LeCreditBasedChannelSpec(psm)
    )

    messages = (bytes([1, 2, 3]), bytes([4, 5, 6]), bytes(10000))
    for message in messages:
        l2cap_channel.write(message)
        await asyncio.sleep(0)

    await l2cap_channel.drain()

    # Test closing
    closed = [False, False]
    closed_event = asyncio.Event()

    def on_close(which, event):
        closed[which] = True
        if event:
            event.set()

    l2cap_channel.on('close', lambda: on_close(0, None))
    incoming_channel.on('close', lambda: on_close(1, closed_event))
    await l2cap_channel.disconnect()
    assert closed == [True, True]
    await closed_event.wait()

    sent_bytes = b''.join(messages)
    received_bytes = b''.join(received)
    assert sent_bytes == received_bytes


# -----------------------------------------------------------------------------
@pytest.mark.parametrize("info_type", list(l2cap.L2CAP_Information_Request.InfoType))
async def test_l2cap_information_request(monkeypatch, info_type):
    # TODO: Replace handlers with API when implemented
    devices = await TwoDevices.create_with_connection()

    # Register handlers
    info_rsp = list[l2cap.L2CAP_Information_Response]()

    def on_l2cap_information_response(connection, cid, frame):
        info_rsp.append(frame)

    assert (connection := devices.connections[0])
    channel_manager = devices[0].l2cap_channel_manager
    monkeypatch.setattr(
        channel_manager,
        'on_l2cap_information_response',
        on_l2cap_information_response,
        raising=False,
    )

    channel_manager.send_control_frame(
        connection,
        l2cap.L2CAP_LE_SIGNALING_CID,
        l2cap.L2CAP_Information_Request(
            identifier=channel_manager.next_identifier(connection),
            info_type=info_type,
        ),
    )

    await async_barrier()
    response = info_rsp[0]
    assert response.result == l2cap.L2CAP_Information_Response.Result.SUCCESS


# -----------------------------------------------------------------------------
async def transfer_payload(
    channels: Sequence[l2cap.ClassicChannel | l2cap.LeCreditBasedChannel],
):
    received = asyncio.Queue[bytes]()
    channels[1].sink = received.put_nowait
    sdu_lengths = (21, 70, 700, 5523)

    messages = [bytes([i % 8 for i in range(sdu_length)]) for sdu_length in sdu_lengths]
    for message in messages:
        channels[0].write(message)
        if isinstance(channels[0], l2cap.LeCreditBasedChannel):
            if random.randint(0, 5) == 1:
                await channels[0].drain()

    if isinstance(channels[0], l2cap.LeCreditBasedChannel):
        await channels[0].drain()

    sent_bytes = b''.join(messages)
    received_bytes = b''
    while len(received_bytes) < len(sent_bytes):
        received_bytes += await received.get()
    assert sent_bytes == received_bytes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "max_credits, mtu, mps",
    itertools.product((1, 10, 100, 10000), (50, 255, 256, 1000), (50, 255, 256, 1000)),
)
async def test_transfer(max_credits: int, mtu: int, mps: int):
    devices = await TwoDevices.create_with_connection()

    server_channels = asyncio.Queue[l2cap.LeCreditBasedChannel]()
    server = devices[1].create_l2cap_server(
        spec=l2cap.LeCreditBasedChannelSpec(max_credits=max_credits, mtu=mtu, mps=mps),
        handler=server_channels.put_nowait,
    )
    assert (connection := devices.connections[0])
    client = await connection.create_l2cap_channel(
        spec=l2cap.LeCreditBasedChannelSpec(server.psm)
    )
    server_channel = await server_channels.get()
    await transfer_payload((client, server_channel))
    await client.disconnect()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_bidirectional_transfer():
    devices = TwoDevices()
    await devices.setup_connection()

    server_channels = asyncio.Queue[l2cap.LeCreditBasedChannel]()
    server = devices.devices[1].create_l2cap_server(
        spec=l2cap.LeCreditBasedChannelSpec(),
        handler=server_channels.put_nowait,
    )
    client = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.LeCreditBasedChannelSpec(server.psm)
    )
    server_channel = await server_channels.get()
    await transfer_payload((client, server_channel))
    await transfer_payload((server_channel, client))
    await client.disconnect()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_mtu():
    devices = TwoDevices()
    await devices.setup_connection()

    def on_channel_open(channel):
        assert channel.peer_mtu == 456

    def on_channel(channel):
        channel.on('open', lambda: on_channel_open(channel))

    server = devices.devices[1].create_l2cap_server(
        spec=l2cap.ClassicChannelSpec(mtu=345), handler=on_channel
    )
    client_channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.ClassicChannelSpec(server.psm, mtu=456)
    )
    assert client_channel.peer_mtu == 345


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("mtu", (50, 255, 256, 1000))
async def test_enhanced_retransmission_mode(mtu: int):
    devices = TwoDevices()
    await devices.setup_connection()

    server_channels = asyncio.Queue[l2cap.ClassicChannel]()
    server = devices.devices[1].create_l2cap_server(
        spec=l2cap.ClassicChannelSpec(
            mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION,
            mtu=mtu,
            mps=256,
        ),
        handler=server_channels.put_nowait,
    )
    client_channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.ClassicChannelSpec(
            server.psm,
            mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION,
            mtu=mtu,
            mps=1024,
        )
    )
    server_channel = await server_channels.get()

    await transfer_payload((client_channel, server_channel))
    await transfer_payload((server_channel, client_channel))


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'server_mode, client_mode',
    [
        (l2cap.TransmissionMode.BASIC, l2cap.TransmissionMode.ENHANCED_RETRANSMISSION),
        (l2cap.TransmissionMode.ENHANCED_RETRANSMISSION, l2cap.TransmissionMode.BASIC),
    ],
)
@pytest.mark.asyncio
async def test_mode_mismatching(server_mode, client_mode):
    devices = TwoDevices()
    await devices.setup_connection()
    server = devices.devices[1].create_l2cap_server(
        spec=l2cap.ClassicChannelSpec(mode=server_mode)
    )

    with pytest.raises(l2cap.L2capError):
        await devices.connections[0].create_l2cap_channel(
            spec=l2cap.ClassicChannelSpec(psm=server.psm, mode=client_mode)
        )


# -----------------------------------------------------------------------------
def test_enhanced_control_fields():
    # I-frame: final must default to 0 (Core Spec Vol 3, Part A, 3.3.2).
    i_field = l2cap.InformationEnhancedControlField(
        tx_seq=42,
        req_seq=17,
        sar=l2cap.ControlField.SegmentationAndReassembly.START,
    )
    assert i_field.final == 0
    raw_i = bytes(i_field)
    assert raw_i[0] == (0 | (42 << 1) | (0 << 7))
    assert raw_i[1] == (17 | (1 << 6))
    assert l2cap.EnhancedControlField.from_bytes(raw_i) == i_field

    # S-frame: poll is bit 4, final is bit 7, req_seq is 6 bits.
    s_poll = l2cap.SupervisoryEnhancedControlField(
        supervision_function=l2cap.ControlField.SupervisoryFunction.RR,
        poll=1,
        final=0,
        req_seq=63,
    )
    raw_s_poll = bytes(s_poll)
    assert raw_s_poll == bytes([0x01 | (1 << 4), 63])
    assert l2cap.EnhancedControlField.from_bytes(raw_s_poll) == s_poll

    s_rej_final = l2cap.SupervisoryEnhancedControlField(
        supervision_function=l2cap.ControlField.SupervisoryFunction.REJ,
        poll=0,
        final=1,
        req_seq=5,
    )
    raw_s_rej = bytes(s_rej_final)
    assert raw_s_rej == bytes([0x01 | (1 << 2) | (1 << 7), 5])
    assert l2cap.EnhancedControlField.from_bytes(raw_s_rej) == s_rej_final

    # Reserved bits 14-15 in S-frame must be masked out when decoding req_seq.
    decoded = l2cap.SupervisoryEnhancedControlField.from_bytes(bytes([0x01, 0xC5]))
    assert decoded.req_seq == 5


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    'extra_options',
    [
        # Flush Timeout (200 ms, as sent by iOS A2DP)
        [
            (
                l2cap.L2CAP_Configure_Request.ParameterType.FLUSH_TIMEOUT,
                (200).to_bytes(2, 'little'),
            )
        ],
        # QoS Best Effort (service_type = 0x01)
        [
            (
                l2cap.L2CAP_Configure_Request.ParameterType.QOS,
                bytes([0x00, 0x01]) + bytes(20),
            )
        ],
        # QoS No Traffic (service_type = 0x00)
        [
            (
                l2cap.L2CAP_Configure_Request.ParameterType.QOS,
                bytes([0x00, 0x00]) + bytes(20),
            )
        ],
        # Unknown Hint option (MSB set = 0x80 | 0x2A) must be ignored
        [(0xAA, b'\x01\x02')],
        # Flush Timeout with Hint bit set
        [
            (
                0x80 | l2cap.L2CAP_Configure_Request.ParameterType.FLUSH_TIMEOUT,
                (200).to_bytes(2, 'little'),
            )
        ],
    ],
)
async def test_classic_configure_request_accepts_standard_and_hint_options(
    monkeypatch, extra_options
):
    devices = TwoDevices()
    await devices.setup_connection()

    original_send = l2cap.ClassicChannel.send_control_frame

    def patched_send(self, frame):
        if (
            isinstance(frame, l2cap.L2CAP_Configure_Request)
            and self.connection.device is devices.devices[0]
        ):
            options = l2cap.L2CAP_Control_Frame.decode_configuration_options(
                frame.options
            )
            options.extend(extra_options)
            frame = l2cap.L2CAP_Configure_Request(
                identifier=frame.identifier,
                destination_cid=frame.destination_cid,
                flags=frame.flags,
                options=l2cap.L2CAP_Control_Frame.encode_configuration_options(options),
            )
        return original_send(self, frame)

    monkeypatch.setattr(l2cap.ClassicChannel, 'send_control_frame', patched_send)

    server_channels = asyncio.Queue[l2cap.ClassicChannel]()
    server = devices.devices[1].create_l2cap_server(
        spec=l2cap.ClassicChannelSpec(), handler=server_channels.put_nowait
    )
    client_channel = await asyncio.wait_for(
        devices.connections[0].create_l2cap_channel(
            spec=l2cap.ClassicChannelSpec(psm=server.psm)
        ),
        timeout=5.0,
    )
    server_channel = await asyncio.wait_for(server_channels.get(), timeout=5.0)
    assert client_channel.state == l2cap.ClassicChannel.State.OPEN
    assert server_channel.state == l2cap.ClassicChannel.State.OPEN


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_enhanced_retransmission_fcs_and_corrupted_frame():
    devices = TwoDevices()
    await devices.setup_connection()

    server_channels = asyncio.Queue[l2cap.ClassicChannel]()
    # Server requests FCS=True while client leaves fcs_enabled=False;
    # per Core Spec 5.5, both sides must use 16-bit FCS.
    server = devices.devices[1].create_l2cap_server(
        spec=l2cap.ClassicChannelSpec(
            mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION,
            fcs_enabled=True,
            mps=64,
        ),
        handler=server_channels.put_nowait,
    )
    client_channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.ClassicChannelSpec(
            server.psm,
            mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION,
            fcs_enabled=False,
            mps=64,
        )
    )
    server_channel = await server_channels.get()
    assert client_channel.fcs_enabled is True
    assert server_channel.fcs_enabled is True

    # Normal transfer with FCS enabled works.
    await transfer_payload((client_channel, server_channel))

    # Corrupted FCS frame must be dropped and not delivered to sink.
    received = []
    server_channel.sink = received.append
    valid_pdu = l2cap.L2CAP_PDU(
        server_channel.source_cid,
        bytes(l2cap.InformationEnhancedControlField(tx_seq=0, req_seq=0, sar=0))
        + b'bad',
    ).to_bytes(with_fcs=True)
    # Strip 4-byte L2CAP header and flip last byte of FCS.
    corrupted_payload = valid_pdu[4:-1] + bytes([valid_pdu[-1] ^ 0xFF])
    server_channel.on_pdu(corrupted_payload)
    assert not received

    await client_channel.disconnect()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_enhanced_retransmission_mps_start_segment_limit():
    devices = TwoDevices()
    await devices.setup_connection()

    server_channels = asyncio.Queue[l2cap.ClassicChannel]()
    server = devices.devices[1].create_l2cap_server(
        spec=l2cap.ClassicChannelSpec(
            mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION,
            mps=20,
        ),
        handler=server_channels.put_nowait,
    )
    client_channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.ClassicChannelSpec(
            server.psm,
            mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION,
            mps=20,
        )
    )
    server_channel = await server_channels.get()

    sent_pdus: list[bytes] = []
    original_send_pdu = client_channel.send_pdu

    def spy_send_pdu(pdu):
        sent_pdus.append(bytes(pdu))
        original_send_pdu(pdu)

    client_channel.send_pdu = spy_send_pdu

    received = asyncio.Queue[bytes]()
    server_channel.sink = received.put_nowait

    sdu = bytes(range(50))
    client_channel.write(sdu)
    assert await asyncio.wait_for(received.get(), timeout=2.0) == sdu

    # Every I-frame payload (excluding 2-byte Enhanced Control Field) must be
    # <= MPS (20).
    i_frames = [p for p in sent_pdus if (p[0] & 0x01) == 0]
    assert len(i_frames) == 3  # 18 + 20 + 12 = 50
    for frame in i_frames:
        assert len(frame) - 2 <= 20

    await client_channel.disconnect()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_enhanced_retransmission_recovery_on_drop_and_rej_and_rnr():
    devices = TwoDevices()
    await devices.setup_connection()

    server_channels = asyncio.Queue[l2cap.ClassicChannel]()
    server = devices.devices[1].create_l2cap_server(
        spec=l2cap.ClassicChannelSpec(
            mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION,
            retransmission_timeout=0.05,
            monitor_timeout=0.1,
            max_retransmission=3,
        ),
        handler=server_channels.put_nowait,
    )
    client_channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.ClassicChannelSpec(
            server.psm,
            mode=l2cap.TransmissionMode.ENHANCED_RETRANSMISSION,
            retransmission_timeout=0.05,
            monitor_timeout=0.1,
            max_retransmission=3,
        )
    )
    server_channel = await server_channels.get()

    received = asyncio.Queue[bytes]()
    server_channel.sink = received.put_nowait

    # 1) Drop the first I-frame once -> recovered via Poll/Final retransmission.
    dropped_once = False
    original_server_on_pdu = server_channel.on_pdu

    def drop_first_i_frame(pdu: bytes) -> None:
        nonlocal dropped_once
        if not dropped_once and (pdu[0] & 0x01) == 0:
            dropped_once = True
            return
        original_server_on_pdu(pdu)

    server_channel.on_pdu = drop_first_i_frame
    client_channel.write(b'hello-poll-recovery')
    assert await asyncio.wait_for(received.get(), timeout=2.0) == b'hello-poll-recovery'

    # 2) Drop tx_seq=1 while tx_seq=2 arrives -> REJ triggers retransmission of 1 & 2.
    dropped_seq1 = False

    def drop_seq1_once(pdu: bytes) -> None:
        nonlocal dropped_seq1
        if not dropped_seq1 and (pdu[0] & 0x01) == 0 and ((pdu[0] >> 1) & 0x3F) == 1:
            dropped_seq1 = True
            return
        original_server_on_pdu(pdu)

    server_channel.on_pdu = drop_seq1_once
    client_channel.write(b'msg-1')
    client_channel.write(b'msg-2')
    assert await asyncio.wait_for(received.get(), timeout=2.0) == b'msg-1'
    assert await asyncio.wait_for(received.get(), timeout=2.0) == b'msg-2'

    # 3) RNR pauses client TX, RR resumes it immediately.
    # Drain any in-flight RR from step 2 before injecting RNR.
    await async_barrier()
    server_channel.on_pdu = original_server_on_pdu
    client_channel.on_pdu(
        bytes(
            l2cap.SupervisoryEnhancedControlField(
                supervision_function=l2cap.ControlField.SupervisoryFunction.RNR,
                req_seq=3,
            )
        )
    )
    client_channel.write(b'after-rnr')
    await async_barrier()
    assert received.empty()

    client_channel.on_pdu(
        bytes(
            l2cap.SupervisoryEnhancedControlField(
                supervision_function=l2cap.ControlField.SupervisoryFunction.RR,
                req_seq=3,
            )
        )
    )
    assert await asyncio.wait_for(received.get(), timeout=2.0) == b'after-rnr'

    # 4) SREJ selectively retransmits only the requested I-frame.
    await async_barrier()
    retransmitted_seqs: list[int] = []
    original_client_send_pdu = client_channel.send_pdu

    def drop_seq4_and_record(pdu):
        raw = bytes(pdu)
        if (raw[0] & 0x01) == 0:
            retransmitted_seqs.append((raw[0] >> 1) & 0x3F)
        original_client_send_pdu(pdu)

    client_channel.send_pdu = drop_seq4_and_record
    # Pause server RX so tx_seq=4 stays in client _tx_window.
    server_channel.on_pdu = lambda _pdu: None
    client_channel.write(b'srej-target')
    await async_barrier()
    retransmitted_seqs.clear()
    server_channel.on_pdu = original_server_on_pdu
    client_channel.on_pdu(
        bytes(
            l2cap.SupervisoryEnhancedControlField(
                supervision_function=l2cap.ControlField.SupervisoryFunction.SREJ,
                poll=0,
                req_seq=4,
            )
        )
    )
    assert await asyncio.wait_for(received.get(), timeout=2.0) == b'srej-target'
    assert retransmitted_seqs == [4]

    # 5) Disconnecting cancels timers cleanly.
    await client_channel.disconnect()
    assert isinstance(client_channel.processor, l2cap.EnhancedRetransmissionProcessor)
    assert client_channel.processor._monitor_handle is None
    assert client_channel.processor._receiver_ready_poll_handle is None


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_enhanced_credit_based_flow_control_connection():
    devices = await TwoDevices.create_with_connection()
    server_channels = asyncio.Queue[l2cap.LeCreditBasedChannel]()
    server = devices[1].create_l2cap_server(
        spec=l2cap.LeCreditBasedChannelSpec(), handler=server_channels.put_nowait
    )

    client_channels = await devices[
        0
    ].l2cap_channel_manager.create_enhanced_credit_based_channels(
        devices.connections[0], l2cap.LeCreditBasedChannelSpec(psm=server.psm), count=5
    )
    assert len(client_channels) == 5

    for client_channel in client_channels:
        server_channel = await server_channels.get()
        await transfer_payload((client_channel, server_channel))
        await transfer_payload((server_channel, client_channel))


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_enhanced_credit_based_flow_control_connection_failure_no_psm():
    devices = await TwoDevices.create_with_connection()

    with pytest.raises(l2cap.L2capError):
        await devices[0].l2cap_channel_manager.create_enhanced_credit_based_channels(
            devices.connections[0], l2cap.LeCreditBasedChannelSpec(psm=12345), count=5
        )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_enhanced_credit_based_flow_control_connection_failure_insufficient_resource_client_side():
    devices = await TwoDevices.create_with_connection()
    server = devices[1].create_l2cap_server(spec=l2cap.LeCreditBasedChannelSpec())

    with pytest.raises(core.OutOfResourcesError):
        await devices[0].l2cap_channel_manager.create_enhanced_credit_based_channels(
            devices.connections[0],
            l2cap.LeCreditBasedChannelSpec(server.psm),
            count=(
                l2cap.L2CAP_LE_U_DYNAMIC_CID_RANGE_END
                - l2cap.L2CAP_LE_U_DYNAMIC_CID_RANGE_START
            )
            * 2,
        )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_enhanced_credit_based_flow_control_connection_failure_insufficient_resource_server_side():
    devices = await TwoDevices.create_with_connection()
    server = devices[1].create_l2cap_server(spec=l2cap.LeCreditBasedChannelSpec())
    # Simulate that the server side has no available CID.
    channels = {
        cid: mock.Mock()
        for cid in range(
            l2cap.L2CAP_LE_U_DYNAMIC_CID_RANGE_START,
            l2cap.L2CAP_LE_U_DYNAMIC_CID_RANGE_END + 1,
        )
    }
    devices[1].l2cap_channel_manager.channels[devices.connections[1].handle] = channels

    with pytest.raises(l2cap.L2capError):
        await devices[0].l2cap_channel_manager.create_enhanced_credit_based_channels(
            devices.connections[0], l2cap.LeCreditBasedChannelSpec(server.psm), count=1
        )


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'cid, payload, expected',
    [
        (0x0040, '020000010203040506070809', '0E0040000200000102030405060708093861'),
        (0x0040, '0101', '040040000101D414'),
    ],
)
def test_fcs(cid: int, payload: str, expected: str):
    '''Core Spec 6.1, Vol 3, Part A, 3.3.5. Frame Check Sequence.'''
    pdu = l2cap.L2CAP_PDU(cid, bytes.fromhex(payload))
    assert pdu.to_bytes(with_fcs=True) == bytes.fromhex(expected)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_abort_while_disconnecting():
    # Setup client and server channels
    devices = TwoDevices()
    await devices.setup_connection()
    psm = 1234

    server_channels = asyncio.Queue[l2cap.LeCreditBasedChannel]()
    devices.devices[1].create_l2cap_server(
        spec=l2cap.LeCreditBasedChannelSpec(psm=psm),
        handler=server_channels.put_nowait,
    )
    client_channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.LeCreditBasedChannelSpec(psm)
    )
    server_channel = await server_channels.get()

    # Stub the server's request handler to ignore the disconnection request.
    # This keeps the client channel in the DISCONNECTING state, waiting for a response,
    # so we can simulate calling abort() during an active disconnection.
    server_channel.on_disconnection_request = lambda request: None

    # Intercept state change to DISCONNECTING and call abort()
    original_change_state = client_channel._change_state
    abort_called = False

    def intercept_change_state_and_abort(new_state):
        nonlocal abort_called
        original_change_state(new_state)
        if (
            new_state == l2cap.LeCreditBasedChannel.State.DISCONNECTING
            and not abort_called
        ):
            abort_called = True
            client_channel.abort()

    client_channel._change_state = intercept_change_state_and_abort

    # Start disconnection and wait with a timeout. It should resolve immediately due to the abort.
    await asyncio.wait_for(client_channel.disconnect(), timeout=1.0)
    assert client_channel.state == l2cap.LeCreditBasedChannel.State.DISCONNECTED


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_disconnection_collision():
    # Setup client and server channels
    devices = TwoDevices()
    await devices.setup_connection()
    psm = 1234

    server_channels = asyncio.Queue[l2cap.LeCreditBasedChannel]()
    devices.devices[1].create_l2cap_server(
        spec=l2cap.LeCreditBasedChannelSpec(psm=psm),
        handler=server_channels.put_nowait,
    )
    client_channel = await devices.connections[0].create_l2cap_channel(
        spec=l2cap.LeCreditBasedChannelSpec(psm)
    )
    server_channel = await server_channels.get()

    # Trigger disconnection from both sides concurrently to cause a collision.
    # Both channels will transition to DISCONNECTING and send DISCONNECTION_REQUESTs.
    # When each side receives the peer's request, it will handle it and resolve the
    # disconnection_result future.
    await asyncio.gather(
        client_channel.disconnect(),
        server_channel.disconnect(),
    )

    assert client_channel.state == l2cap.LeCreditBasedChannel.State.DISCONNECTED
    assert server_channel.state == l2cap.LeCreditBasedChannel.State.DISCONNECTED


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_zero_length_sdu():
    devices = await TwoDevices.create_with_connection()

    server_channels = asyncio.Queue[l2cap.LeCreditBasedChannel]()
    server = devices[1].create_l2cap_server(
        spec=l2cap.LeCreditBasedChannelSpec(),
        handler=server_channels.put_nowait,
    )
    assert (connection := devices.connections[0])
    client = await connection.create_l2cap_channel(
        spec=l2cap.LeCreditBasedChannelSpec(server.psm)
    )
    server_channel = await server_channels.get()
    received = asyncio.Queue[bytes]()
    server_channel.sink = received.put_nowait

    # A zero-length SDU must not hold up the SDUs that follow it
    client.send_pdu(bytes(2))
    client.write(b'hello')
    assert await asyncio.wait_for(received.get(), timeout=1.0) == b''
    assert await asyncio.wait_for(received.get(), timeout=1.0) == b'hello'
    await client.disconnect()


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sdu_length, payload_length",
    (
        (101, 0),  # SDU length larger than the MTU
        (0, 48),  # More payload than the SDU length
        (10, 11),
    ),
)
async def test_invalid_sdu_length(sdu_length: int, payload_length: int):
    devices = await TwoDevices.create_with_connection()

    server_channels = asyncio.Queue[l2cap.LeCreditBasedChannel]()
    server = devices[1].create_l2cap_server(
        spec=l2cap.LeCreditBasedChannelSpec(mtu=100),
        handler=server_channels.put_nowait,
    )
    assert (connection := devices.connections[0])
    client = await connection.create_l2cap_channel(
        spec=l2cap.LeCreditBasedChannelSpec(server.psm)
    )
    server_channel = await server_channels.get()
    server_channel.sink = mock.Mock()
    closed = asyncio.Event()
    server_channel.once(server_channel.EVENT_CLOSE, closed.set)

    # The receiver must disconnect the channel rather than buffer or deliver
    client.send_pdu(sdu_length.to_bytes(2, 'little') + bytes(payload_length))
    await asyncio.wait_for(closed.wait(), timeout=1.0)

    server_channel.sink.assert_not_called()
    assert server_channel.in_sdu is None
    assert client.state == l2cap.LeCreditBasedChannel.State.DISCONNECTED


# -----------------------------------------------------------------------------
async def run():
    test_helpers()
    await test_basic_connection()
    await test_transfer()
    await test_bidirectional_transfer()
    await test_mtu()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
