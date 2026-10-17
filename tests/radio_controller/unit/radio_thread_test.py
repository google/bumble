# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Controller-thread ownership, deferred HCI delivery and worker lifecycle."""

import asyncio
import socket
import time
from threading import Event, get_ident
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from bumble.controller import Controller
from bumble.radio_controller.radio_thread import RadioControllerWorker


@pytest.mark.asyncio
@pytest.mark.parametrize('max_step_us', [1000, 250])
async def test_hci_runs_in_owner_thread_only_after_phy_ack(monkeypatch, max_step_us):
    host_thread = get_ident()
    entered = Event()
    read, write = socket.socketpair()
    read.setblocking(False)
    handled = []
    delivered = []
    radio = SimpleNamespace(now_us=0, bind_loop=Mock(), close=Mock())

    async def connect(sim, dev):
        assert get_ident() != host_thread
        assert (sim, dev) == ('test', 0)

    async def advance(target):
        await asyncio.get_running_loop().before_phy_request()
        entered.set()
        asyncio.get_running_loop().wait_for_phy_io(
            read.fileno(), write=False, deadline=time.monotonic() + 5
        )
        assert read.recv(1) == b'a'
        radio.now_us = target
        return target

    radio.connect, radio.advance_to_us = connect, advance
    monkeypatch.setattr(
        'bumble.radio_controller.radio_thread.BabbleSimRadio', lambda: radio
    )
    original = Controller.on_packet

    def on_packet(controller, packet):
        handled.append((get_ident(), radio.now_us))
        original(controller, packet)

    monkeypatch.setattr(Controller, 'on_packet', on_packet)
    received = asyncio.Event()

    def receive(packet):
        delivered.append((get_ident(), packet))
        received.set()

    worker = RadioControllerWorker('test', max_step_us=max_step_us)
    worker.set_packet_sink(SimpleNamespace(on_packet=receive))
    try:
        await worker.start('test', 0)
        assert worker._loop.radio_selector.max_step_us == max_step_us
        assert not worker.terminated.done()
        assert await asyncio.to_thread(entered.wait, 5)
        worker.on_packet(bytes.fromhex('01030c00'))
        assert not handled and not delivered
        write.sendall(b'a')
        await asyncio.wait_for(received.wait(), 5)
        assert handled == [(worker._thread.ident, max_step_us)]
        assert delivered == [(host_thread, bytes.fromhex('040e0401030c00'))]
        with pytest.raises(RuntimeError, match='attach the Host'):
            worker.set_packet_sink(None)
    finally:
        await worker.close()
        read.close()
        write.close()
    assert not worker._thread.is_alive()
    assert worker.terminated.done()
    radio.close.assert_called_once()
    with pytest.raises(RuntimeError, match='stopped'):
        worker.on_packet(b'packet')


@pytest.mark.asyncio
async def test_deferred_hci_notifications_precede_next_phy_request(monkeypatch):
    entered = Event()
    events = []

    def on_packet(controller, packet):
        events.append('command')
        asyncio.get_running_loop().call_soon(events.append, 'notification')

    async def advance(target):
        await asyncio.get_running_loop().before_phy_request()
        assert events == ['command', 'notification']
        entered.set()
        await asyncio.Future()

    radio = SimpleNamespace(
        now_us=0,
        connect=AsyncMock(),
        bind_loop=Mock(),
        advance_to_us=advance,
        close=Mock(),
    )
    monkeypatch.setattr(
        'bumble.radio_controller.radio_thread.BabbleSimRadio', lambda: radio
    )
    monkeypatch.setattr(Controller, 'on_packet', on_packet)
    worker = RadioControllerWorker('test')
    worker.on_packet(bytes.fromhex('01030c00'))
    try:
        await worker.start('test', 0)
        assert await asyncio.to_thread(entered.wait, 5)
        worker.check()
    finally:
        await worker.close()


@pytest.mark.asyncio
async def test_worker_start_failure_is_reported_and_thread_joined(monkeypatch):
    radio = SimpleNamespace(
        connect=AsyncMock(side_effect=RuntimeError('broken radio')), close=Mock()
    )
    monkeypatch.setattr(
        'bumble.radio_controller.radio_thread.BabbleSimRadio', lambda: radio
    )
    worker = RadioControllerWorker('test')
    with pytest.raises(RuntimeError, match='broken radio'):
        await worker.start('test', 0)
    with pytest.raises(RuntimeError, match='broken radio'):
        await worker.close()
    assert not worker._thread.is_alive()
    assert worker.terminated.done()
    radio.close.assert_called_once()


@pytest.mark.asyncio
async def test_cancelled_start_releases_connecting_worker(monkeypatch):
    entered = Event()

    async def connect(sim, dev):
        entered.set()
        await asyncio.Future()

    radio = SimpleNamespace(connect=connect, close=Mock())
    monkeypatch.setattr(
        'bumble.radio_controller.radio_thread.BabbleSimRadio', lambda: radio
    )
    worker = RadioControllerWorker('test')
    start = asyncio.create_task(worker.start('test', 0))
    assert await asyncio.to_thread(entered.wait, 5)
    start.cancel()
    with pytest.raises(asyncio.CancelledError):
        await start
    await worker.close()
    assert not worker._thread.is_alive()
    assert worker.terminated.done()
    radio.close.assert_called_once()


def test_worker_step_must_be_positive():
    with pytest.raises(ValueError, match='positive'):
        RadioControllerWorker('test', max_step_us=0)
