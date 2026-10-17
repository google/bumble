# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import os
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio

from bumble import hci
from bumble.controller import Controller
from bumble.radio_controller.controller_backend import RadioBackend
from bumble.radio_controller.radio_babblesim import BabbleSimRadio
from bumble.radio_controller.radio_thread import RadioControllerWorker
from tests.radio_controller.qualification.tester import (
    DUT_ADDRESS,
    AirTester,
    HciProbe,
    MultiAirTester,
)


def pytest_configure(config):
    config.addinivalue_line(
        'markers', 'radio_peers(count, factory): independent lower-tester radios'
    )
    config.addinivalue_line(
        'markers', 'limited: sub-microsecond timing approximated at 1-us resolution'
    )
    config.addinivalue_line(
        'markers',
        'source_conflict: unresolved source procedure or verdict requirements',
    )


@pytest_asyncio.fixture
async def hci_dut(tmp_path, request):
    with (tmp_path / 'protocol.log').open('w') as trace:
        trace.write(f'TEST {request.node.nodeid}\n')
        probe = HciProbe(trace)
        probe.input = Controller(
            'dut',
            public_address=DUT_ADDRESS,
            host_sink=probe,
            backend=RadioBackend(SimpleNamespace(now_us=0)),
        )
        yield probe


@pytest_asyncio.fixture
async def air_dut(tmp_path, request, controller_log):
    value = os.environ.get('BSIM_OUT_PATH')
    if value is None:
        pytest.skip('set BSIM_OUT_PATH to run real-PHY Controller behavior tests')
    out = Path(value).resolve()
    binary = out / 'bin/bs_2G4_phy_v1'
    assert binary.is_file(), f'BabbleSim PHY missing: {binary}'
    scan_max_coded_range_m = int(os.environ.get('BSIM_SCAN_MAX_CODED_RANGE_M', '0'))
    assert scan_max_coded_range_m >= 0
    sim_id = f'bumble_ll_{uuid.uuid4().hex[:12]}'
    (tmp_path / 'sim_id.txt').write_text(sim_id)
    worker = RadioControllerWorker('dut', public_address=str(DUT_ADDRESS).split('/')[0])
    # The lower tester injects/observes RF without modeling DUT hardware delays.
    radio = BabbleSimRadio(switch_time_us=0)
    peer_config = request.node.get_closest_marker('radio_peers')
    peers = [
        BabbleSimRadio(switch_time_us=0)
        for _ in range(peer_config.args[0] if peer_config else 0)
    ]
    peer_tasks = []
    with (
        (tmp_path / 'phy.log').open('wb') as log,
        (tmp_path / 'protocol.log').open('w') as trace,
    ):
        phy = await asyncio.create_subprocess_exec(
            binary,
            f'-s={sim_id}',
            f'-D={2 + len(peers)}',
            '-defmodem=BLE_simple',
            '-channel=multiatt',
            '-argschannel',
            '-at=45',
            '-argsmain',
            '-dump',
            '-dump_imm',
            '-crcerr_data',
            cwd=out / 'bin',
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        tester = (MultiAirTester if peers else AirTester)(radio, worker, trace)
        tester.phy_results = out / 'results' / sim_id
        # The default simulated path has colocated endpoints and no range delay.
        tester.scan_max_coded_range_m = scan_max_coded_range_m
        trace.write(f'TEST {request.node.nodeid}\n')
        trace.write(
            f'IXIT TSPX_scan_max_coded_range={tester.scan_max_coded_range_m} m\n'
        )
        worker.set_packet_sink(tester)
        try:
            await worker.start(sim_id, 0)
            await radio.connect(sim_id, 1)
            tester.peers = []
            for dev_id, peer_radio in enumerate(peers, 2):
                await peer_radio.connect(sim_id, dev_id)
                peer = peer_config.kwargs['factory'](peer_radio, dev_id - 1, trace)
                tester.peers.append(peer)
                peer_tasks.append(asyncio.create_task(peer.run()))
            await asyncio.wait_for(radio.connection.wait(0), 5)
            await tester.command(hci.HCI_Reset_Command())
            await tester.masks()
            yield tester
            # Let the PHY complete the last grant and dump before stopping the DUT.
            if radio.connection.read_fd is not None:
                await tester.wait(0)
        finally:
            try:
                await worker.close()
            finally:
                for task in peer_tasks:
                    task.cancel()
                peer_results = await asyncio.gather(*peer_tasks, return_exceptions=True)
                for peer_radio in peers:
                    peer_radio.close()
                radio.close()
                try:
                    await asyncio.wait_for(phy.wait(), 5)
                except asyncio.TimeoutError:
                    phy.kill()
                    await asyncio.wait_for(phy.wait(), 5)
                    raise
                assert phy.returncode == 0, f'PHY exited with status {phy.returncode}'
                for result in peer_results:
                    if isinstance(result, BaseException) and not isinstance(
                        result, asyncio.CancelledError
                    ):
                        raise result


@pytest.fixture
def controller_log(tmp_path):
    logger = logging.getLogger('bumble.controller')
    previous_level = logger.level
    handler = logging.FileHandler(tmp_path / 'controller.log')
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        handler.close()
