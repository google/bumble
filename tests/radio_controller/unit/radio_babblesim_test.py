# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""FIFO framing, PHY acknowledgements and endpoint/session cleanup."""

import asyncio
import os
import select
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from bumble.ll import PDU_ADV_ACCESS_ADDRESS, PDU_HEADER_SIZE
from bumble.radio_controller.radio import (
    PHY_1M_ADDRESS_TIME_US,
    PHY_1M_BITRATE_BPS,
    PHY_1M_OCTET_TIME_US,
    PHY_ADV_CHANNEL_FREQUENCIES_MHZ,
    RADIO_SWITCH_TIME_US,
    Phy,
    crc24,
)
from bumble.radio_controller.radio_asyncio import ControllerEventLoop
from bumble.radio_controller.radio_babblesim import (
    BSIM_FREQUENCY_BASE_MHZ,
    BSIM_FREQUENCY_SCALE,
    BSIM_RSSI_SCALE,
    BSIM_RX_SYNC_THRESHOLD,
    DISCONNECT,
    HEADER,
    MODULATION_LE_1M,
    NEVER,
    RX,
    RX_ADDRESS,
    RX_CONTINUE,
    RX_DONE,
    RX_END,
    RX_REQUEST,
    RX_STATUS_CRC_ERROR,
    RX_STATUS_HEADER_ERROR,
    RX_STATUS_IN_PROGRESS,
    RX_STATUS_NO_SYNC,
    RX_STATUS_OK,
    TIME,
    TX,
    TX_END,
    TX_REQUEST,
    WAIT,
    WAIT_END,
    BabbleSimClock,
    BabbleSimRadio,
    BabbleSimSession,
    PhyConnection,
)

requires_runner = pytest.mark.skipif(
    not hasattr(asyncio, 'Runner'), reason='Controller loops require Python 3.11'
)

requires_pipe2 = pytest.mark.skipif(
    not hasattr(os, 'pipe2'), reason='FIFO tests require os.pipe2'
)


@pytest.fixture
def endpoints(tmp_path):
    if not hasattr(os, 'pipe2'):
        pytest.skip('FIFO tests require os.pipe2')
    read_request, write_request = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    read_response, write_response = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    device = PhyConnection(tmp_path, 0)
    device.read_fd, device.write_fd = read_response, write_request
    phy = PhyConnection(tmp_path, 0)
    phy.read_fd, phy.write_fd = read_request, write_response
    try:
        yield device, phy
    finally:
        for fd in (read_request, write_request, read_response, write_response):
            os.close(fd)


@pytest.mark.asyncio
async def test_session_can_use_existing_host_loop_without_its_own_clock():
    worker = SimpleNamespace(start=AsyncMock(), close=AsyncMock())
    loop = asyncio.get_running_loop()
    async with BabbleSimSession('test', [(0, worker)]) as session:
        assert asyncio.get_running_loop() is loop
        assert session.clock is None and session.loop is None
        worker.start.assert_awaited_once_with('test', 0)
    worker.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_standalone_session_binds_clock_after_startup_barrier(monkeypatch):
    events = []
    worker = SimpleNamespace(
        start=AsyncMock(side_effect=lambda *args: events.append('start')),
        close=AsyncMock(side_effect=lambda: events.append('stop')),
        check=lambda: None,
    )
    session = BabbleSimSession('test', [(0, worker)], clock_dev_id=1)
    session.clock.connection.connect = AsyncMock(
        side_effect=lambda: events.append('connect')
    )
    session.clock.connection.wait_sync = lambda *args: events.append('barrier')
    session.clock.connection.close = lambda: events.append('disconnect')
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(
        loop, 'bind_clock', lambda clock: events.append('bind'), raising=False
    )
    monkeypatch.setattr(
        loop, 'unbind_clock', lambda: events.append('unbind'), raising=False
    )
    async with session:
        assert session.loop is loop
        assert events == ['start', 'connect', 'barrier', 'bind']
    assert events == [
        'start',
        'connect',
        'barrier',
        'bind',
        'unbind',
        'stop',
        'disconnect',
    ]


@pytest.mark.asyncio
async def test_session_start_failure_closes_started_and_unstarted_workers():
    first = SimpleNamespace(start=AsyncMock(), close=AsyncMock())
    second = SimpleNamespace(
        start=AsyncMock(side_effect=RuntimeError('broken worker')), close=AsyncMock()
    )
    session = BabbleSimSession('test', [(0, first), (1, second)])
    with pytest.raises(RuntimeError, match='broken worker'):
        await session.__aenter__()
    first.close.assert_awaited_once()
    second.close.assert_awaited_once()


def test_session_requires_at_least_one_controller():
    with pytest.raises(ValueError, match='at least one'):
        BabbleSimSession('test', [])


@pytest.mark.asyncio
async def test_session_stops_all_workers_before_releasing_host_grant():
    events = []

    async def close(name, fail=False):
        events.append(name)
        if fail:
            raise RuntimeError('broken worker')

    workers = [
        SimpleNamespace(close=lambda: close('first', True)),
        SimpleNamespace(close=lambda: close('second')),
    ]
    session = BabbleSimSession('test', list(enumerate(workers)), clock_dev_id=2)
    session.loop = SimpleNamespace(unbind_clock=lambda: events.append('unbind'))
    session.clock.connection.close = lambda: events.append('release')
    with pytest.raises(RuntimeError, match='broken worker'):
        await session.__aexit__(None, None, None)
    assert events == ['unbind', 'first', 'second', 'release']


@requires_runner
@pytest.mark.parametrize('buffered', [False, True])
def test_controller_drains_callbacks_before_wait_and_blocks_until_ack(
    endpoints, buffered
):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device
    events = []
    if buffered:
        os.write(phy.write_fd, HEADER.pack(WAIT_END))

    with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
        loop = runner.get_loop()
        radio.bind_loop(loop)
        send = device.send

        async def submit(packet):
            loop.call_soon(events.append, 'io')
            await send(packet)

        device.send = submit

        def respond():
            assert select.select([phy.read_fd], [], [], 5)[0]
            assert os.read(phy.read_fd, 12) == HEADER.pack(WAIT) + TIME.pack(1000)
            assert events[:9] == list(range(8, -1, -1))
            if not buffered:
                # A callback submitted during the wait cannot execute before ACK.
                assert 'io' not in events
                for byte in HEADER.pack(WAIT_END):
                    os.write(phy.write_fd, bytes([byte]))

        def nested(depth):
            events.append(depth)
            if depth:
                loop.call_soon(nested, depth - 1)

        async def exercise():
            loop.call_soon(nested, 8)
            assert await radio.advance_to_us(1000) == 1000
            events.append('ack')
            await loop.before_phy_request()
            assert events == [*range(8, -1, -1), 'ack', 'io']
            loop.unbind_clock()

        with ThreadPoolExecutor(max_workers=1) as executor:
            response = executor.submit(respond)
            runner.run(exercise())
            response.result(timeout=5)


@requires_runner
@pytest.mark.parametrize('blocking_wait', [False, True])
def test_controller_shutdown_interrupts_pending_phy_request(endpoints, blocking_wait):
    device, phy = endpoints
    with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
        loop = runner.get_loop()
        device.controller_loop = loop

        def interrupt():
            assert select.select([phy.read_fd], [], [], 5)[0]
            assert os.read(phy.read_fd, 12) == HEADER.pack(WAIT) + TIME.pack(1000)
            loop.interrupt()

        async def exercise():
            with pytest.raises(asyncio.CancelledError):
                if blocking_wait:
                    device.wait_sync(1000, 5)
                else:
                    await device.wait(1000)
            assert not device._busy

        with ThreadPoolExecutor(max_workers=1) as executor:
            response = executor.submit(interrupt)
            runner.run(exercise())
            response.result(timeout=5)


def test_failed_blocking_wait_cannot_reuse_a_late_ack(endpoints):
    device, phy = endpoints
    with pytest.raises(TimeoutError, match='waiting for BabbleSim PHY'):
        device.wait_sync(1000, 0)
    assert device.read_fd is None and device.write_fd is None and not device._busy
    with pytest.raises(RuntimeError, match='not connected'):
        device.wait_sync(0, 5)
    assert os.read(phy.read_fd, 64) == (
        HEADER.pack(WAIT) + TIME.pack(1000) + HEADER.pack(DISCONNECT)
    )


@requires_runner
def test_controller_timer_shortens_wait_on_same_radio_endpoint(endpoints):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device
    fired = []
    targets = []
    with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
        loop = runner.get_loop()
        radio.bind_loop(loop)

        def respond():
            for _ in range(2):
                assert select.select([phy.read_fd], [], [], 5)[0]
                request = os.read(phy.read_fd, 12)
                assert request[:4] == HEADER.pack(WAIT)
                targets.append(TIME.unpack(request[4:])[0])
                os.write(phy.write_fd, HEADER.pack(WAIT_END))

        async def exercise():
            loop.call_later(0.002, lambda: fired.append(radio.now_us))
            assert await radio.advance_to_us(5000) == pytest.approx(2000, abs=1)
            assert await radio.advance_to_us(5000) == 5000
            assert fired == [pytest.approx(2000, abs=1)]
            assert targets == [pytest.approx(2000, abs=1), 5000]
            loop.unbind_clock()

        with ThreadPoolExecutor(max_workers=1) as executor:
            response = executor.submit(respond)
            runner.run(exercise())
            response.result(timeout=5)


@requires_runner
def test_controller_timer_precedes_scheduled_tx_without_changing_rf_time(endpoints):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device
    fired = []
    with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
        loop = runner.get_loop()
        radio.bind_loop(loop)

        def respond():
            while True:
                assert select.select([phy.read_fd], [], [], 5)[0]
                header = os.read(phy.read_fd, HEADER.size)
                if header == HEADER.pack(WAIT):
                    target = TIME.unpack(os.read(phy.read_fd, TIME.size))[0]
                    assert target <= 2001
                    os.write(phy.write_fd, HEADER.pack(WAIT_END))
                else:
                    assert header == HEADER.pack(TX_REQUEST)
                    request = TX.unpack(os.read(phy.read_fd, TX.size))
                    assert request[:PDU_HEADER_SIZE] == (3000, 3079)
                    assert fired == [pytest.approx(2000, abs=1)]
                    assert os.read(phy.read_fd, 5) == b'\x02\x00' + crc24(b'\x02\x00')
                    os.write(phy.write_fd, HEADER.pack(TX_END) + TIME.pack(3079))
                    return

        async def exercise():
            loop.call_later(0.002, lambda: fired.append(radio.now_us))
            assert await radio.transmit(37, b'\x02\x00', start_us=3000) == 3080
            assert radio.now_us == 3079
            loop.unbind_clock()

        with ThreadPoolExecutor(max_workers=1) as executor:
            response = executor.submit(respond)
            runner.run(exercise())
            response.result(timeout=5)


@requires_runner
def test_controller_timer_cannot_interrupt_active_radio_reception(endpoints):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device
    fired = []
    with asyncio.Runner(loop_factory=ControllerEventLoop) as runner:
        loop = runner.get_loop()
        radio.bind_loop(loop)

        def respond():
            assert select.select([phy.read_fd], [], [], 5)[0]
            assert os.read(phy.read_fd, HEADER.size) == HEADER.pack(RX_REQUEST)
            assert RX.unpack(os.read(phy.read_fd, RX.size))[:2] == (1, 999)
            assert fired == []
            os.write(
                phy.write_fd, HEADER.pack(RX_END) + RX_DONE.pack(4, 0, 1000, 1000, 0)
            )

        async def exercise():
            loop.call_later(0.00005, lambda: fired.append(radio.now_us))
            assert await radio.receive(37, 1000) is None
            assert fired == []
            await loop.before_phy_request()
            assert fired == [1000]
            loop.unbind_clock()

        with ThreadPoolExecutor(max_workers=1) as executor:
            response = executor.submit(respond)
            runner.run(exercise())
            response.result(timeout=5)


@pytest.mark.asyncio
async def test_wait_packet_and_fragmented_ack(endpoints):
    device, phy = endpoints

    async def respond():
        assert await phy.receive(12) == HEADER.pack(WAIT) + TIME.pack(1234)
        for byte in HEADER.pack(WAIT_END):
            await phy.send(bytes([byte]))
            await asyncio.sleep(0)

    await asyncio.gather(device.wait(1234), respond())


@pytest.mark.asyncio
async def test_blocking_clock_handles_fragmented_ack(endpoints):
    device, phy = endpoints

    async def respond():
        assert await phy.receive(12) == HEADER.pack(WAIT) + TIME.pack(1234)
        for byte in HEADER.pack(WAIT_END):
            await phy.send(bytes([byte]))
            await asyncio.sleep(0)

    await asyncio.gather(asyncio.to_thread(device.wait_sync, 1234, 5), respond())


def test_blocking_clock_has_wall_watchdog_and_releases_request_state(endpoints):
    device, _ = endpoints
    with pytest.raises(TimeoutError, match='waiting for BabbleSim'):
        device.wait_sync(1234, 0.01)
    assert not device._busy


@pytest.mark.parametrize('header', [DISCONNECT, 0x1234])
def test_blocking_clock_rejects_disconnect_or_invalid_ack(endpoints, header):
    device, phy = endpoints
    os.write(phy.write_fd, HEADER.pack(header))
    with pytest.raises(RuntimeError):
        device.wait_sync(1234, 5)


@requires_pipe2
def test_blocking_clock_detects_eof(tmp_path):
    request_read, request_write = os.pipe2(os.O_NONBLOCK)
    response_read, response_write = os.pipe2(os.O_NONBLOCK)
    device = PhyConnection(tmp_path, 0)
    device.write_fd, device.read_fd = request_write, response_read
    os.close(response_write)
    try:
        with pytest.raises(RuntimeError, match='disconnected'):
            device.wait_sync(1234, 5)
    finally:
        for fd in (request_read, request_write, response_read):
            os.close(fd)


@pytest.mark.asyncio
async def test_host_clock_changes_only_after_its_own_ack(endpoints):
    device, phy = endpoints
    clock = BabbleSimClock(device)

    async def respond():
        assert await phy.receive(12) == HEADER.pack(WAIT) + TIME.pack(1234)
        assert clock.now_us == 0
        await phy.send(HEADER.pack(WAIT_END))

    result, _ = await asyncio.gather(
        asyncio.to_thread(clock.advance_to_us, 1234), respond()
    )
    assert result == clock.now_us == 1234
    for invalid in (1233, NEVER, -1):
        with pytest.raises(ValueError, match='nondecreasing'):
            clock.advance_to_us(invalid)


@pytest.mark.asyncio
async def test_tx_packet_layout_crc_and_completion_time(endpoints):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device
    pdu = b'\x02\x00'
    packet = pdu + crc24(pdu)

    async def respond():
        assert await phy.receive(HEADER.size) == HEADER.pack(TX_REQUEST)
        request = TX.unpack(await phy.receive(TX.size))
        assert request == (
            1,
            80,
            NEVER,
            NEVER,
            PDU_ADV_ACCESS_ADDRESS,
            MODULATION_LE_1M,
            (PHY_ADV_CHANNEL_FREQUENCIES_MHZ[37] - BSIM_FREQUENCY_BASE_MHZ)
            * BSIM_FREQUENCY_SCALE,
            0,
            len(packet),
        )
        assert await phy.receive(len(packet)) == packet
        await phy.send(HEADER.pack(TX_END) + TIME.pack(80))

    end, _ = await asyncio.gather(radio.transmit(37, pdu), respond())
    assert radio.now_us == 80 and end == 81


@pytest.mark.asyncio
async def test_tx_switching_rejects_early_start_before_submitting_phy(endpoints):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device
    radio.now_us = 99
    radio.switch.complete(37, Phy.LE_1M, transmit=True, end_us=100)
    with pytest.raises(ValueError, match='before the radio is ready'):
        await radio.transmit(38, b'\x02\x00', start_us=100 + RADIO_SWITCH_TIME_US - 1)
    assert not select.select([phy.read_fd], [], [], 0)[0]
    assert radio.switch.state == (37, Phy.LE_1M, True)


@pytest.mark.asyncio
@pytest.mark.parametrize('start_us', [None, 100])
@pytest.mark.parametrize('switch_time_us', [0, RADIO_SWITCH_TIME_US])
async def test_rx_switching_prevents_reception_before_radio_is_ready(
    endpoints, start_us, switch_time_us
):
    device, phy = endpoints
    radio = BabbleSimRadio(switch_time_us=switch_time_us)
    radio.connection = device
    radio.now_us = 99
    radio.switch.complete(37, Phy.LE_1M, transmit=True, end_us=100)
    ready_us = 100 + switch_time_us

    async def respond():
        assert await phy.receive(HEADER.size) == HEADER.pack(RX_REQUEST)
        request = RX.unpack(await phy.receive(RX.size))
        assert request[:2] == (ready_us, 1000 - ready_us)
        await phy.send(
            HEADER.pack(RX_END) + RX_DONE.pack(RX_STATUS_NO_SYNC, 0, 1000, 1000, 0)
        )

    result, _ = await asyncio.gather(
        radio.receive(37, 1000, start_us=start_us), respond()
    )
    assert result is None


@pytest.mark.asyncio
async def test_zero_switch_time_submits_back_to_back_tx_on_different_channels(
    endpoints,
):
    device, phy = endpoints
    radio = BabbleSimRadio(switch_time_us=0)
    radio.connection = device
    pdu = b'\x02\x00'
    duration = Phy.LE_1M.airtime_us(len(pdu))

    async def respond():
        for start in (1, 1 + duration):
            assert await phy.receive(HEADER.size) == HEADER.pack(TX_REQUEST)
            request = TX.unpack(await phy.receive(TX.size))
            assert request[:2] == (start, start + duration - 1)
            assert await phy.receive(request[-1]) == pdu + crc24(pdu)
            await phy.send(HEADER.pack(TX_END) + TIME.pack(request[1]))

    async def transmit():
        await radio.transmit(37, pdu)
        return await radio.transmit(38, pdu)

    end, _ = await asyncio.gather(transmit(), respond())
    assert end == 1 + 2 * duration


@pytest.mark.asyncio
async def test_rx_window_inside_switching_interval_submits_only_wait(endpoints):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device
    radio.now_us = 99
    radio.switch.complete(37, Phy.LE_1M, transmit=True, end_us=100)
    until = 100 + RADIO_SWITCH_TIME_US

    async def respond():
        assert await phy.receive(HEADER.size) == HEADER.pack(WAIT)
        assert TIME.unpack(await phy.receive(TIME.size))[0] == until
        await phy.send(HEADER.pack(WAIT_END))

    result, _ = await asyncio.gather(radio.receive(37, until), respond())
    assert result is None
    assert radio.switch.state == (37, Phy.LE_1M, True)


@pytest.mark.asyncio
@pytest.mark.parametrize('search_until_us', [140, 1000])
@pytest.mark.parametrize(
    'status,accept_bad_crc,received',
    [
        (RX_STATUS_OK, False, True),
        (RX_STATUS_CRC_ERROR, False, False),
        (RX_STATUS_CRC_ERROR, True, True),
    ],
)
async def test_rx_address_handshake_and_crc(
    endpoints, status, accept_bad_crc, received, search_until_us
):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device
    pdu = b'\x02\x00'
    packet = pdu + crc24(pdu)
    done = RX_DONE.pack(status, len(packet), 139, 179, -45 * BSIM_RSSI_SCALE)
    acquired = RX_DONE.pack(
        RX_STATUS_IN_PROGRESS, len(packet), 139, 139, -45 * BSIM_RSSI_SCALE
    )

    async def respond():
        assert await phy.receive(HEADER.size) == HEADER.pack(RX_REQUEST)
        request = RX.unpack(await phy.receive(RX.size))
        assert request == (
            1,
            search_until_us - 1,
            PDU_ADV_ACCESS_ADDRESS,
            MODULATION_LE_1M,
            (PHY_ADV_CHANNEL_FREQUENCIES_MHZ[37] - BSIM_FREQUENCY_BASE_MHZ)
            * BSIM_FREQUENCY_SCALE,
            0,
            BSIM_RX_SYNC_THRESHOLD,
            0,
            PHY_1M_ADDRESS_TIME_US,
            PDU_HEADER_SIZE * PHY_1M_OCTET_TIME_US,
            PHY_1M_BITRATE_BPS,
            NEVER,
            NEVER,
        )
        for chunk in (
            HEADER.pack(RX_ADDRESS),
            acquired[:7],
            acquired[7:],
            packet[:1],
            packet[1:],
        ):
            await phy.send(chunk)
            await asyncio.sleep(0)
        assert await phy.receive(HEADER.size) == HEADER.pack(RX_CONTINUE)
        assert radio.now_us == 139
        await phy.send(HEADER.pack(RX_END) + done)

    result, _ = await asyncio.gather(
        radio.receive(37, search_until_us, accept_bad_crc=accept_bad_crc), respond()
    )
    assert radio.now_us == 179
    assert (result is not None) == received
    if result is not None:
        assert (result.pdu, result.rssi, result.start_us, result.end_us) == (
            pdu,
            -45,
            100,
            180,
        )
        assert result.valid_crc == (status == RX_STATUS_OK)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'status',
    [
        RX_STATUS_CRC_ERROR,
        RX_STATUS_HEADER_ERROR,
        RX_STATUS_NO_SYNC,
    ],
)
async def test_rx_failure_has_no_packet_payload(endpoints, status):
    device, phy = endpoints
    radio = BabbleSimRadio()
    radio.connection = device

    async def respond():
        await phy.receive(HEADER.size + RX.size)
        await phy.send(HEADER.pack(RX_END) + RX_DONE.pack(status, 0, 1000, 1000, 0))

    result, _ = await asyncio.gather(radio.receive(37, 1000), respond())
    assert result is None and radio.now_us == 1000


@pytest.mark.asyncio
async def test_pending_request_does_not_block_loop_and_rejects_overlap(endpoints):
    device, phy = endpoints
    pending = asyncio.create_task(device.wait(100))
    assert await phy.receive(12) == HEADER.pack(WAIT) + TIME.pack(100)
    assert not pending.done()
    with pytest.raises(RuntimeError, match='one pending request'):
        await device.wait(200)
    await phy.send(HEADER.pack(WAIT_END))
    await pending


@pytest.mark.asyncio
@pytest.mark.parametrize('header', [DISCONNECT, 0x1234])
async def test_unexpected_response_raises_python_exception(endpoints, header):
    device, phy = endpoints

    async def respond():
        await phy.receive(12)
        await phy.send(HEADER.pack(header))

    with pytest.raises(RuntimeError):
        await asyncio.gather(device.wait(100), respond())


@pytest.mark.skipif(sys.platform != 'linux', reason='PHY registration requires Linux')
@pytest.mark.asyncio
async def test_connect_timeout_removes_owned_registration(tmp_path):
    connection = PhyConnection(tmp_path, 0)
    with pytest.raises(TimeoutError, match='did not connect'):
        await connection.connect(timeout=0)
    assert not Path(f'{connection.prefix}.lock').exists()
    assert connection.read_fd is None and connection.write_fd is None


@pytest.mark.asyncio
async def test_duplicate_registration_does_not_remove_other_device_lock(tmp_path):
    lock = tmp_path / '2G4.d0.lock'
    lock.write_text('existing device')
    connection = PhyConnection(tmp_path, 0)
    with pytest.raises(FileExistsError):
        await connection.connect()
    assert lock.read_text() == 'existing device'


def test_session_rejects_duplicate_controller_or_clock_identity():
    with pytest.raises(ValueError, match='distinct'):
        BabbleSimSession('test', [(0, None), (0, None)], clock_dev_id=2)
    with pytest.raises(ValueError, match='distinct'):
        BabbleSimSession('test', [(0, None)], clock_dev_id=0)


@pytest.mark.parametrize(
    'channel,mhz',
    [(37, 2402), (38, 2426), (39, 2480), (10, 2424), (11, 2428), (36, 2478)],
)
def test_radio_channel(channel, mhz):
    assert BabbleSimRadio.params(channel) == (
        MODULATION_LE_1M,
        (mhz - BSIM_FREQUENCY_BASE_MHZ) * BSIM_FREQUENCY_SCALE,
    )


def test_negative_radio_switch_time_is_rejected():
    with pytest.raises(ValueError, match='nonnegative'):
        BabbleSimRadio(switch_time_us=-1)


@pytest.mark.asyncio
@pytest.mark.parametrize('switch_time_us', [0, RADIO_SWITCH_TIME_US])
async def test_connect_resets_radio_state_but_preserves_switch_time(
    monkeypatch, switch_time_us
):
    from bumble.radio_controller.radio_babblesim import PhyConnection

    async def connect(connection):
        pass

    monkeypatch.setattr(PhyConnection, 'connect', connect)
    radio = BabbleSimRadio(switch_time_us=switch_time_us)
    radio.switch.complete(37, Phy.LE_1M, transmit=True, end_us=100)
    await radio.connect('test_radio_switch_config', 0)
    try:
        assert radio.switch.switch_time_us == switch_time_us
        assert radio.switch.state is None and radio.switch.end_us == 0
    finally:
        radio.close()
