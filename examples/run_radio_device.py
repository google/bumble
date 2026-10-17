# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Run complete Bumble Host scenarios over BabbleSim-backed Controllers."""

import argparse
import asyncio
import logging
import os
import subprocess
import uuid
from contextlib import ExitStack
from pathlib import Path

from bumble import hci
from bumble.core import AdvertisingData
from bumble.device import (
    AdvertisingEventProperties,
    AdvertisingParameters,
    AdvertisingType,
    ConnectionParametersPreferences,
    Device,
    Peer,
    PeriodicAdvertisingParameters,
    PeriodicAdvertisingSync,
)
from bumble.gatt import Characteristic, Service
from bumble.host import Host
from bumble.radio_controller.radio_asyncio import RadioEventLoop
from bumble.radio_controller.radio_babblesim import BabbleSimSession
from bumble.radio_controller.radio_thread import RadioControllerWorker

SERVICE_UUID = 'A8120000-0000-4000-8000-000000000001'
VALUE_UUID = 'A8120001-0000-4000-8000-000000000001'
PHYS = {'1m': hci.Phy.LE_1M, '2m': hci.Phy.LE_2M, 'coded': hci.Phy.LE_CODED}


class PacketTrace:
    def __init__(self, sink, output, direction):
        self.sink, self.output, self.direction = sink, output, direction

    def on_packet(self, packet):
        self.output.write(f'{self.direction} {packet.hex()}\n')
        self.sink.on_packet(packet)


def advertising_data(device):
    return bytes(
        AdvertisingData([(AdvertisingData.COMPLETE_LOCAL_NAME, device.name.encode())])
    )


async def advertise(device, *, connectable=True):
    await device.start_advertising(
        advertising_type=(
            AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE
            if connectable
            else AdvertisingType.UNDIRECTED
        ),
        own_address_type=hci.OwnAddressType.PUBLIC,
        advertising_data=advertising_data(device),
        advertising_interval_min=100,
        advertising_interval_max=100,
    )


async def observe(device, advertisers):
    pending = {peer.public_address: advertising_data(peer) for peer in advertisers}
    complete = asyncio.get_running_loop().create_future()

    def report(advertisement):
        expected = pending.get(advertisement.address)
        if expected is None or complete.done():
            return
        if bytes(advertisement.data) != expected:
            complete.set_exception(
                ValueError(f'Unexpected data from {advertisement.address}')
            )
            return
        print(f'ADVERTISEMENT {advertisement.address} {expected.hex()}', flush=True)
        del pending[advertisement.address]
        if not pending:
            complete.set_result(None)

    device.on('advertisement', report)
    try:
        await device.start_scanning(
            active=False,
            scan_interval=30,
            scan_window=30,
            own_address_type=hci.OwnAddressType.PUBLIC,
        )
        await asyncio.wait_for(complete, 5)
    finally:
        device.remove_listener('advertisement', report)
        await device.stop_scanning()


async def connect(central, peripheral):
    connection = await central.connect(
        peripheral.public_address,
        own_address_type=hci.OwnAddressType.PUBLIC,
        timeout=10,
        connection_parameters_preferences={
            hci.Phy.LE_1M: ConnectionParametersPreferences(
                connection_interval_min=60,
                connection_interval_max=60,
                supervision_timeout=2000,
            )
        },
    )
    assert connection.peer_address == peripheral.public_address
    print(f'CONNECTED {central.name} -> {peripheral.name}', flush=True)
    return connection


async def read_gatt(connection, expected, *, count=1):
    peer = Peer(connection)
    assert await peer.request_mtu(64) == 64
    service = next(
        item
        for item in await peer.discover_services()
        if str(item.uuid) == SERVICE_UUID
    )
    characteristic = next(
        item
        for item in await peer.discover_characteristics(service=service)
        if str(item.uuid) == VALUE_UUID
    )
    for _ in range(count):
        assert await characteristic.read_value() == expected
    print(
        (
            f'GATT READ {connection.peer_address}: {count} x {len(expected)} bytes '
            f'verified'
        ),
        flush=True,
    )


async def start_periodic(device, sid, phy):
    advertising_set = await device.create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            advertising_event_properties=AdvertisingEventProperties(
                is_connectable=False,
                is_scannable=False,
            ),
            own_address_type=hci.OwnAddressType.PUBLIC,
            secondary_advertising_phy=phy,
            advertising_sid=sid,
            primary_advertising_interval_min=100,
            primary_advertising_interval_max=100,
        ),
        advertising_data=advertising_data(device),
        periodic_advertising_parameters=PeriodicAdvertisingParameters(
            periodic_advertising_interval_min=40,
            periodic_advertising_interval_max=40,
        ),
        periodic_advertising_data=advertising_data(device),
    )
    await advertising_set.start_periodic()
    return advertising_set


async def receive_periodic(device, advertiser, sid):
    sync = await device.create_periodic_advertising_sync(
        advertiser.public_address,
        sid=sid,
        sync_timeout=2,
    )
    complete = asyncio.get_running_loop().create_future()
    reports = 0

    def report(advertisement):
        nonlocal reports
        if complete.done():
            return
        if bytes(advertisement.data) != advertising_data(advertiser):
            complete.set_exception(ValueError('Unexpected periodic advertising data'))
            return
        reports += 1
        if reports == 5:
            complete.set_result(None)

    sync.on(PeriodicAdvertisingSync.EVENT_PERIODIC_ADVERTISEMENT, report)
    try:
        await asyncio.wait_for(complete, 10)
        assert sync.state == PeriodicAdvertisingSync.State.ESTABLISHED
        print(
            f'PERIODIC SYNC {device.name} <- {advertiser.name}: 5 valid reports',
            flush=True,
        )
        return sync
    finally:
        sync.remove_listener(
            PeriodicAdvertisingSync.EVENT_PERIODIC_ADVERTISEMENT, report
        )


async def advertising(devices, args):
    advertisers, observer = devices[:-1], devices[-1]
    for device in advertisers:
        await advertise(device, connectable=False)
    await observe(observer, advertisers)
    for device in advertisers:
        await device.stop_advertising()


async def connection(devices, args):
    peripheral, central = devices
    await advertise(peripheral)
    link = await connect(central, peripheral)
    await read_gatt(link, bytes([0]) * 60)
    await link.disconnect()
    assert not peripheral.connections and not central.connections


async def periodic(devices, args):
    advertiser, observer = devices
    advertising_set = await start_periodic(advertiser, 1, PHYS[args.phy])
    await observer.start_scanning(
        active=False, own_address_type=hci.OwnAddressType.PUBLIC
    )
    sync = await receive_periodic(observer, advertiser, 1)
    await sync.terminate()
    await observer.stop_scanning()
    await advertising_set.stop_periodic()
    await advertising_set.stop()


async def coexistence(devices, args):
    hub, count = devices[0], args.links_per_role
    hub_periodic = await start_periodic(hub, 1, PHYS[args.phy])
    await hub.start_scanning(
        active=True,
        scan_interval=30,
        scan_window=30,
        own_address_type=hci.OwnAddressType.PUBLIC,
    )
    central_links, peripheral_links = [], []
    for device in devices[1 : count + 1]:
        await advertise(device)
        central_links.append(await connect(hub, device))
    for device in devices[count + 1 :]:
        await advertise(hub)
        peripheral_links.append(await connect(device, hub))
    assert sorted(link.role for link in hub.connections.values()) == (
        [hci.Role.CENTRAL] * count + [hci.Role.PERIPHERAL] * count
    )
    assert len({link.handle for link in hub.connections.values()}) == 2 * count
    print(
        (
            f'COEXISTENCE: {count} Central + {count} Peripheral ACLs, scanning and '
            f'periodic TX'
        ),
        flush=True,
    )

    remote_periodic = await start_periodic(devices[1], 2, PHYS[args.phy])
    await devices[2].start_scanning(
        active=False, own_address_type=hci.OwnAddressType.PUBLIC
    )
    *_, hub_sync, peer_sync = await asyncio.wait_for(
        asyncio.gather(
            *(
                read_gatt(link, bytes([index + 1]) * 60, count=10)
                for index, link in enumerate(central_links)
            ),
            *(read_gatt(link, bytes([0]) * 60, count=10) for link in peripheral_links),
            receive_periodic(hub, devices[1], 2),
            receive_periodic(devices[2], hub, 1),
        ),
        20,
    )
    assert len(hub.connections) == 2 * count
    await central_links[0].disconnect()
    assert len(hub.connections) == 2 * count - 1
    await read_gatt(central_links[1], bytes([2]) * 60)
    assert hub_periodic.periodic_enabled
    assert (
        hub_sync.state == peer_sync.state == PeriodicAdvertisingSync.State.ESTABLISHED
    )
    print(
        'SELECTIVE DISCONNECT: other ACLs and periodic synchronization remain active',
        flush=True,
    )

    await hub_sync.terminate()
    await peer_sync.terminate()
    await devices[2].stop_scanning()
    await hub.stop_scanning()
    for advertising_set in (hub_periodic, remote_periodic):
        await advertising_set.stop_periodic()
        await advertising_set.stop()
    await asyncio.gather(
        *(link.disconnect() for link in central_links[1:]),
        *(link.disconnect() for link in peripheral_links),
    )
    assert not hub.connections


SCENARIOS = {
    'advertising': advertising,
    'connection': connection,
    'periodic': periodic,
    'coexistence': coexistence,
}


async def run(args, stack, device_count):
    workers, devices = [], []
    for index in range(device_count):
        address = f'F0:F1:F2:F3:F4:{index + 1:02X}'
        worker = RadioControllerWorker(f'node{index}', public_address=address)
        trace = stack.enter_context(
            (args.log_dir / f'hci{index}.log').open('w', buffering=1)
        )
        host = Host(
            controller_source=worker, controller_sink=PacketTrace(worker, trace, 'TX')
        )
        worker.set_packet_sink(PacketTrace(host, trace, 'RX'))
        device = Device(name=f'Radio {index}', address=hci.Address(address), host=host)
        if args.scenario in ('connection', 'coexistence'):
            device.add_service(
                Service(
                    SERVICE_UUID,
                    [
                        Characteristic(
                            VALUE_UUID,
                            Characteristic.Properties.READ,
                            Characteristic.READABLE,
                            bytes([index]) * 60,
                        )
                    ],
                )
            )
        workers.append((index, worker))
        devices.append(device)
    async with BabbleSimSession(
        args.sim_id, workers, clock_dev_id=device_count
    ) as session:
        for device in devices:
            await device.power_on()
        await SCENARIOS[args.scenario](devices, args)
        completed_us = session.clock.now_us
    return completed_us


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', choices=SCENARIOS)
    parser.add_argument(
        '-s', '--sim-id', default=f'bumble_demo_{uuid.uuid4().hex[:12]}'
    )
    parser.add_argument('--log-dir', type=Path)
    parser.add_argument(
        '--advertisers',
        type=int,
        default=1,
        help='advertising scenario: number of transmitters',
    )
    parser.add_argument(
        '--links-per-role',
        type=int,
        choices=(2, 4),
        default=2,
        help='coexistence scenario: ACLs of each role on the hub',
    )
    parser.add_argument(
        '--phy',
        choices=PHYS,
        default='1m',
        help='periodic/coexistence: secondary and periodic PHY',
    )
    args = parser.parse_args()
    if not 1 <= args.advertisers <= 254:
        parser.error('--advertisers must be between 1 and 254')
    if args.advertisers != 1 and args.scenario != 'advertising':
        parser.error('--advertisers applies only to advertising')
    if args.links_per_role != 2 and args.scenario != 'coexistence':
        parser.error('--links-per-role applies only to coexistence')
    if args.phy != '1m' and args.scenario not in ('periodic', 'coexistence'):
        parser.error('--phy applies only to periodic and coexistence')
    out = os.environ.get('BSIM_OUT_PATH')
    if not out:
        parser.error('export BSIM_OUT_PATH to a built BabbleSim workspace')
    binary = Path(out).resolve() / 'bin/bs_2G4_phy_v1'
    if not binary.is_file():
        parser.error(f'BabbleSim PHY missing: {binary}')
    args.log_dir = (args.log_dir or Path('out/radio') / args.sim_id).resolve()
    args.log_dir.mkdir(parents=True, exist_ok=False)
    device_count = (
        args.advertisers + 1
        if args.scenario == 'advertising'
        else 2 * args.links_per_role + 1 if args.scenario == 'coexistence' else 2
    )
    print(
        (
            f'LOGS {args.log_dir}\nPHY {args.sim_id}: {device_count} Controllers + '
            f'1 Host clock'
        ),
        flush=True,
    )
    with ExitStack() as stack:
        output = stack.enter_context((args.log_dir / 'phy.log').open('wb'))
        handler = logging.FileHandler(args.log_dir / 'devices.log')
        stack.callback(handler.close)
        handler.setFormatter(logging.Formatter('%(name)s %(message)s'))
        logger = logging.getLogger('bumble')
        previous_level = logger.level
        stack.callback(logger.setLevel, previous_level)
        stack.callback(setattr, logger, 'propagate', logger.propagate)
        stack.callback(logger.removeHandler, handler)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        phy = subprocess.Popen(
            [
                str(binary),
                f'-s={args.sim_id}',
                f'-D={device_count + 1}',
                '-defmodem=BLE_simple',
                '-channel=multiatt',
                '-argschannel',
                '-at=45',
                '-argsmain',
                '-dump',
                '-dump_imm',
            ],
            cwd=binary.parent,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        try:
            with asyncio.Runner(loop_factory=RadioEventLoop) as runner:
                completed_us = runner.run(run(args, stack, device_count))
        finally:
            try:
                phy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                phy.kill()
                phy.wait()
        if phy.returncode != 0:
            raise RuntimeError(
                f'PHY exited with status {phy.returncode}; see '
                f'{args.log_dir / "phy.log"}'
            )
    print(f'COMPLETED {args.scenario} at {completed_us} us', flush=True)
    print(f'RADIO DUMPS {binary.parent.parent / "results" / args.sim_id}', flush=True)


if __name__ == '__main__':
    main()
