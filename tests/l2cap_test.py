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

from .test_utils import TwoDevices, async_barrier

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

    (offset, psm) = l2cap.L2CAP_Connection_Request.parse_psm(
        bytes([0x00, 0x01, 0x00, 0x44]), 1
    )
    assert offset == 3
    assert psm == 0x01

    (offset, psm) = l2cap.L2CAP_Connection_Request.parse_psm(
        bytes([0x00, 0x23, 0x10, 0x44]), 1
    )
    assert offset == 3
    assert psm == 0x1023

    (offset, psm) = l2cap.L2CAP_Connection_Request.parse_psm(
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
@pytest.mark.parametrize("info_type,", list(l2cap.L2CAP_Information_Request.InfoType))
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
@pytest.mark.parametrize("mtu,", (50, 255, 256, 1000))
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
