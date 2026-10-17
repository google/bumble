# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Async Python client for the BabbleSim base and 2G4 v1 FIFO protocols.

Wire layouts follow bs_pc_base_types.h and bs_pc_2G4_types.h. No native
libraries or process-global communication state are used.
"""

from __future__ import annotations

import asyncio
import errno
import getpass
import os
import select
import stat
import struct
import time
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING

from bumble.ll import (
    LL_DATA_CHANNEL_COUNT,
    PDU_ADV_ACCESS_ADDRESS,
    PDU_ADV_CRC_INIT,
    PDU_ADV_EXT_PAYLOAD_SIZE_MAX,
    PDU_CRC_SIZE,
    PDU_HEADER_SIZE,
)
from bumble.radio_controller.radio import (
    PHY_1M_BITRATE_BPS,
    PHY_1M_OCTET_TIME_US,
    PHY_2M_BITRATE_BPS,
    PHY_2M_OCTET_TIME_US,
    PHY_ADV_CHANNEL_FREQUENCIES_MHZ,
    PHY_CODED_ADDRESS_TIME_US,
    PHY_CODED_FEC1_TIME_US,
    PHY_CODED_S2_FACTOR,
    PHY_CODED_S8_FACTOR,
    PHY_DATA_CHANNEL_BASE_MHZ,
    PHY_DATA_CHANNEL_GAP_INDEX,
    PHY_DATA_CHANNEL_SPACING_MHZ,
    RADIO_SWITCH_TIME_US,
    RADIO_TX_POWER_MAX_DBM,
    RADIO_TX_POWER_MIN_DBM,
    Phy,
    RadioSwitch,
    Received,
    crc24,
)

if TYPE_CHECKING:
    from bumble.radio_controller.radio_asyncio import ControllerEventLoop
    from bumble.radio_controller.radio_thread import RadioControllerWorker

NEVER = (1 << 64) - 1
HEADER = struct.Struct('=I')
TIME = struct.Struct('=Q')
TX = struct.Struct('=QQQQIHhhH')
RX = struct.Struct('=QIIHhhHHHHIQQ')
RX_DONE = struct.Struct('=HHQQi')
# The v2 extension carries coding rate and the prelocked FEC2 continuation.
TX_V2 = struct.Struct('=QQQQQQQHhhHH')
RX_V2 = struct.Struct('=QQQIIIHhhHHHHHHBBB')
RX_V2_DONE = struct.Struct('=QQQHiHH')
WAIT, WAIT_END, DISCONNECT = 0x01, 0x81, 0xFFFF
TX_REQUEST, TX_END = 0x02, 0x100
RX_REQUEST, RX_CONTINUE, RX_ADDRESS, RX_END = 0x11, 0x12, 0x102, 0x103
TX_V2_REQUEST = 0x22
RX_V2_REQUEST, RX_V2_CONTINUE, RX_V2_ADDRESS, RX_V2_END = 0x31, 0x16, 0x112, 0x113
RX_STATUS_OK = 1
RX_STATUS_CRC_ERROR = 2
# Native RX status values from bs_pc_2G4_types.h.
RX_STATUS_HEADER_ERROR = 3
RX_STATUS_NO_SYNC = 4
# Address acquired; reception is still in progress.
RX_STATUS_IN_PROGRESS = 5
MODULATION_LE_1M = 0x10
MODULATION_LE_2M = 0x20
MODULATION_LE_CODED = 0x50

# Native 2G4 radio parameters: bs_pc_2G4_types.h.
# Carrier frequency is Q8 MHz relative to 2400 MHz.
BSIM_FREQUENCY_BASE_MHZ = 2400
BSIM_FREQUENCY_SCALE = 1 << 8
# Transmit power uses Q8 dBm; measured RSSI uses Q16 dBm.
BSIM_POWER_SCALE = 1 << 8
BSIM_RSSI_SCALE = 1 << 16
# Receiver model tolerances; these are not Bluetooth protocol bounds.
BSIM_RX_SYNC_THRESHOLD = 2
BSIM_RX_ERROR_THRESHOLD_MAX = 0xFFFF
BSIM_RX_FORCED_DURATION_FOLLOW_TX = 0xFFFFFFFF
# Native packets include the LL header and CRC, but no preamble/Access Address.
BSIM_PACKET_SIZE_MIN = PDU_HEADER_SIZE + PDU_CRC_SIZE
BSIM_PACKET_SIZE_MAX = BSIM_PACKET_SIZE_MIN + PDU_ADV_EXT_PAYLOAD_SIZE_MAX
# LE Coded Coding Indicator wire encodings.
BSIM_CODED_CI_S8 = b'\x00'
BSIM_CODED_CI_S2 = b'\x01'
# Wall-clock watchdogs apply only to transport setup and stalled PHY I/O.
BSIM_CONNECT_TIMEOUT_SECONDS = 30.0
BSIM_CONNECT_RETRY_SECONDS = 0.01
BSIM_IO_TIMEOUT_SECONDS = 180.0
# /proc/<pid>/stat field 22 after removing fields 1 and 2 (pid and comm).
BSIM_PROC_START_TIME_INDEX = 19


class PhyConnection:
    """One device's FIFO descriptors and native registration lock."""

    def __init__(self, sim_dir: Path, dev_id: int, phy_id: str = '2G4'):
        if dev_id < 0:
            raise ValueError('device id must be nonnegative')
        self.prefix = sim_dir / f'{phy_id}.d{dev_id}'
        self.read_fd: int | None = None
        self.write_fd: int | None = None
        self._resources = ExitStack()
        self._busy = False
        self.controller_loop: ControllerEventLoop | None = None
        self._io_deadline = 0.0

    async def connect(self, timeout: float = BSIM_CONNECT_TIMEOUT_SECONDS) -> None:
        if self.write_fd is not None:
            return
        deadline = time.monotonic() + timeout
        try:
            self._register()
            while True:
                try:
                    if self.read_fd is None:
                        self.read_fd = self._open_fifo('.ptd', os.O_RDONLY)
                    self.write_fd = self._open_fifo('.dtp', os.O_WRONLY)
                    return
                except OSError as error:
                    if error.errno not in (errno.ENOENT, errno.ENXIO):
                        raise
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f'BabbleSim device did not connect: {self.prefix}'
                    )
                await asyncio.sleep(BSIM_CONNECT_RETRY_SECONDS)
        except BaseException:
            self.close()
            raise

    def _register(self) -> None:
        self.prefix.parent.mkdir(parents=True, exist_ok=True)
        lock_path = Path(f'{self.prefix}.lock')
        with lock_path.open('x') as lock:
            self._resources.callback(lock_path.unlink, missing_ok=True)
            start = (
                Path('/proc/self/stat')
                .read_text()
                .rsplit(')', 1)[1]
                .split()[BSIM_PROC_START_TIME_INDEX]
            )
            lock.write(f'{os.getpid()}\n{start}\n')

    def _open_fifo(self, suffix: str, flags: int) -> int:
        fd = os.open(f'{self.prefix}{suffix}', flags | os.O_NONBLOCK | os.O_CLOEXEC)
        self._resources.callback(os.close, fd)
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise RuntimeError(
                f'BabbleSim communication path is not a FIFO: {self.prefix}{suffix}'
            )
        return fd

    async def _ready(self, fd: int, *, write: bool = False) -> None:
        if self.controller_loop is not None and self._busy:
            self.controller_loop.wait_for_phy_io(
                fd, write=write, deadline=self._io_deadline
            )
            return
        loop = asyncio.get_running_loop()
        ready = loop.create_future()

        def notify() -> None:
            if not ready.done():
                ready.set_result(None)

        register = loop.add_writer if write else loop.add_reader
        unregister = loop.remove_writer if write else loop.remove_reader
        register(fd, notify)
        try:
            await ready
        finally:
            unregister(fd)

    async def send(self, packet: bytes) -> None:
        if self.write_fd is None:
            raise RuntimeError('BabbleSim device is not connected')
        while packet:
            try:
                written = os.write(self.write_fd, packet)
            except BlockingIOError:
                await self._ready(self.write_fd, write=True)
                continue
            if written == 0:
                raise RuntimeError('BabbleSim request write made no progress')
            packet = packet[written:]

    async def receive(self, size: int) -> bytes:
        if self.read_fd is None:
            raise RuntimeError('BabbleSim device is not connected')
        packet = bytearray()
        while len(packet) < size:
            try:
                chunk = os.read(self.read_fd, size - len(packet))
            except BlockingIOError:
                await self._ready(self.read_fd)
                continue
            if not chunk:
                raise RuntimeError('BabbleSim PHY disconnected')
            packet.extend(chunk)
        return bytes(packet)

    async def response(self, expected: int) -> None:
        header = HEADER.unpack(await self.receive(HEADER.size))[0]
        if header == DISCONNECT:
            raise RuntimeError('BabbleSim PHY disconnected')
        if header != expected:
            raise RuntimeError(
                f'unexpected BabbleSim response: {header:#x}, expected {expected:#x}'
            )

    async def wait(self, target_us: int) -> int:
        limit = await self.start_request()
        if limit is not None:
            target_us = min(target_us, limit)
        try:
            await self.send(HEADER.pack(WAIT) + TIME.pack(target_us))
            await self.response(WAIT_END)
            return target_us
        finally:
            self.end_request()

    def wait_sync(self, target_us: int, timeout: float) -> None:
        """Block the owning loop until this endpoint receives its WAIT_END."""
        if self.read_fd is None or self.write_fd is None:
            raise RuntimeError('BabbleSim device is not connected')
        self.begin_request()
        deadline = time.monotonic() + timeout

        def ready(fd, write=False):
            if self.controller_loop is not None:
                self.controller_loop.wait_for_phy_io(fd, write=write, deadline=deadline)
                return
            readable, writable, _ = select.select(
                [] if write else [fd],
                [fd] if write else [],
                [],
                max(0, deadline - time.monotonic()),
            )
            if not readable and not writable:
                raise TimeoutError('timed out waiting for BabbleSim PHY')

        try:
            packet = HEADER.pack(WAIT) + TIME.pack(target_us)
            while packet:
                ready(self.write_fd, write=True)
                try:
                    size = os.write(self.write_fd, packet)
                except BlockingIOError:
                    continue
                if size == 0:
                    raise RuntimeError('BabbleSim request write made no progress')
                packet = packet[size:]
            response = bytearray()
            while len(response) < HEADER.size:
                ready(self.read_fd)
                try:
                    chunk = os.read(self.read_fd, HEADER.size - len(response))
                except BlockingIOError:
                    continue
                if not chunk:
                    raise RuntimeError('BabbleSim PHY disconnected')
                response.extend(chunk)
            header = HEADER.unpack(response)[0]
            if header == DISCONNECT:
                raise RuntimeError('BabbleSim PHY disconnected')
            if header != WAIT_END:
                raise RuntimeError(f'unexpected BabbleSim WAIT response: {header:#x}')
        except BaseException:
            # A late ACK cannot be matched to a new request after this failure.
            self.close()
            raise
        finally:
            self.end_request()

    def begin_request(self) -> None:
        if self._busy:
            raise RuntimeError('a BabbleSim device can have only one pending request')
        self._busy = True

    async def start_request(self, start_us: int = 0) -> int | None:
        if self._busy:
            raise RuntimeError('a BabbleSim device can have only one pending request')
        limit = (
            await self.controller_loop.before_phy_request(start_us)
            if self.controller_loop is not None
            else None
        )
        self.begin_request()
        self._io_deadline = time.monotonic() + BSIM_IO_TIMEOUT_SECONDS
        return limit

    def end_request(self) -> None:
        self._busy = False

    def close(self) -> None:
        if self.write_fd is not None:
            try:
                os.write(self.write_fd, HEADER.pack(DISCONNECT))
            except OSError:
                pass
        self._resources.close()
        self.read_fd = self.write_fd = None


def simulation_directory(sim_id: str) -> Path:
    if not sim_id or Path(sim_id).name != sim_id or sim_id in ('.', '..'):
        raise ValueError('simulation id must be a nonempty path component')
    return Path('/tmp') / f'bs_{getpass.getuser()}' / sim_id


class BabbleSimClock:
    """The Host's blocking time endpoint, independent of Controller threads."""

    def __init__(
        self, connection: PhyConnection, step_timeout: float = BSIM_IO_TIMEOUT_SECONDS
    ):
        self.connection = connection
        self.now_us = 0
        self.step_timeout = step_timeout
        self.workers: list[RadioControllerWorker] = []

    def advance_to_us(self, target_us: int) -> int:
        for worker in self.workers:
            worker.check()
        if not self.now_us <= target_us < NEVER:
            raise ValueError('clock target must be a finite, nondecreasing uint64 time')
        self.connection.wait_sync(target_us, self.step_timeout)
        self.now_us = target_us
        return target_us


class BabbleSimSession:
    """Own radio worker threads and optionally bind a standalone Host clock."""

    def __init__(
        self,
        sim_id: str,
        controllers: list[tuple[int, RadioControllerWorker]],
        *,
        clock_dev_id: int | None = None,
    ):
        ids = [dev_id for dev_id, _ in controllers]
        if not ids:
            raise ValueError('a session requires at least one Controller')
        all_ids = ids + ([clock_dev_id] if clock_dev_id is not None else [])
        if len(set(all_ids)) != len(all_ids):
            raise ValueError('Controller and clock device ids must be distinct')
        self.sim_id = sim_id
        self.controllers = list(controllers)
        self.clock = (
            BabbleSimClock(PhyConnection(simulation_directory(sim_id), clock_dev_id))
            if clock_dev_id is not None
            else None
        )
        if self.clock is not None:
            self.clock.workers = [worker for _, worker in controllers]
        self.loop = None

    async def __aenter__(self):
        loop = asyncio.get_running_loop()
        try:
            for dev_id, worker in self.controllers:
                await worker.start(self.sim_id, dev_id)
            if self.clock is not None:
                await self.clock.connection.connect()
                self.clock.advance_to_us(0)
                loop.bind_clock(self.clock)
                self.loop = loop
            return self
        except BaseException as error:
            await self.__aexit__(type(error), error, error.__traceback__)
            raise

    async def __aexit__(self, exc_type, exc, traceback):
        if self.loop is not None:
            self.loop.unbind_clock()
            self.loop = None
        try:
            results = await asyncio.gather(
                *(worker.close() for _, worker in self.controllers),
                return_exceptions=True,
            )
        finally:
            # Keep the Host's PHY grant until every radio has stopped submitting work.
            if self.clock is not None:
                self.clock.connection.close()
        for result in results:
            if isinstance(result, Exception):
                raise result


class BabbleSimRadio:
    """Independent LE endpoint with optional Controller idle/ACK boundaries."""

    def __init__(self, *, switch_time_us: int = RADIO_SWITCH_TIME_US):
        self.connection: PhyConnection | None = None
        self.now_us = 0
        self.switch = RadioSwitch(switch_time_us=switch_time_us)

    async def connect(self, sim_id: str, dev_id: int) -> None:
        if self.connection is not None:
            raise RuntimeError('radio is already connected')
        connection = PhyConnection(simulation_directory(sim_id), dev_id)
        await connection.connect()
        self.connection = connection
        self.now_us = 0
        self.switch = RadioSwitch(switch_time_us=self.switch.switch_time_us)

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def _connection(self) -> PhyConnection:
        if self.connection is None:
            raise RuntimeError('radio is not connected')
        return self.connection

    def bind_loop(self, loop: ControllerEventLoop) -> None:
        self._connection().controller_loop = loop
        loop.bind_clock(_ControllerClock(self))

    @staticmethod
    def params(channel: int, phy: Phy = Phy.LE_1M) -> tuple[int, int]:
        if channel in PHY_ADV_CHANNEL_FREQUENCIES_MHZ:
            mhz = PHY_ADV_CHANNEL_FREQUENCIES_MHZ[channel]
        elif 0 <= channel <= LL_DATA_CHANNEL_COUNT - 1:
            mhz = (
                PHY_DATA_CHANNEL_BASE_MHZ
                + channel * PHY_DATA_CHANNEL_SPACING_MHZ
                + (
                    PHY_DATA_CHANNEL_SPACING_MHZ
                    if channel >= PHY_DATA_CHANNEL_GAP_INDEX
                    else 0
                )
            )
        else:
            raise ValueError(f'invalid Bluetooth LE channel: {channel}')
        return {
            Phy.LE_1M: MODULATION_LE_1M,
            Phy.LE_2M: MODULATION_LE_2M,
            Phy.LE_CODED: MODULATION_LE_CODED,
        }[Phy(phy)], (mhz - BSIM_FREQUENCY_BASE_MHZ) * BSIM_FREQUENCY_SCALE

    async def advance_to_us(self, target_us: int) -> int:
        if not 0 <= target_us < NEVER:
            raise ValueError('target must be a finite uint64 time')
        if target_us > self.now_us:
            self.now_us = await self._connection().wait(target_us)
        return self.now_us

    def earliest_start_us(self, channel: int, phy: Phy, *, transmit: bool) -> int:
        return self.switch.earliest_start_us(
            self.now_us, channel, phy, transmit=transmit
        )

    async def transmit(
        self,
        channel: int,
        pdu: bytes,
        *,
        start_us: int | None = None,
        access_address: int = PDU_ADV_ACCESS_ADDRESS,
        crc_init: int = PDU_ADV_CRC_INIT,
        phy: Phy = Phy.LE_1M,
        coding: int = PHY_CODED_S8_FACTOR,
        power_dbm: int = 0,
    ) -> int:
        phy = Phy(phy)
        packet = pdu + crc24(pdu, crc_init)
        duration_us = phy.airtime_us(len(pdu), coding)
        if not RADIO_TX_POWER_MIN_DBM <= power_dbm <= RADIO_TX_POWER_MAX_DBM:
            raise ValueError('invalid LE transmit power')
        ready_us = self.earliest_start_us(channel, phy, transmit=True)
        start_us = ready_us if start_us is None else start_us
        if start_us < ready_us:
            raise ValueError('transmission starts before the radio is ready')
        connection = self._connection()
        request = TX.pack(
            start_us,
            start_us + duration_us - 1,
            NEVER,
            NEVER,
            access_address,
            *self.params(channel, phy),
            power_dbm * BSIM_POWER_SCALE,
            len(packet),
        )
        await connection.start_request(start_us)
        try:
            if phy == Phy.LE_CODED:
                # Nordic's radio model also splits Coded at TERM1: CI is always
                # S=8; the prelocked second transaction uses the indicated rate.
                await self._transmit_coded_part(
                    channel,
                    (
                        BSIM_CODED_CI_S2
                        if coding == PHY_CODED_S2_FACTOR
                        else BSIM_CODED_CI_S8
                    ),
                    start_us,
                    PHY_CODED_FEC1_TIME_US,
                    access_address,
                    PHY_CODED_S8_FACTOR,
                    power_dbm,
                )
                await self._transmit_coded_part(
                    channel,
                    packet,
                    start_us + PHY_CODED_FEC1_TIME_US,
                    duration_us - PHY_CODED_FEC1_TIME_US,
                    access_address,
                    coding,
                    power_dbm,
                )
                return self.now_us + 1
            await connection.send(HEADER.pack(TX_REQUEST) + request + packet)
            await connection.response(TX_END)
            self.now_us = TIME.unpack(await connection.receive(TIME.size))[0]
            return self.now_us + 1
        finally:
            connection.end_request()
            self.switch.complete(channel, phy, transmit=True, end_us=self.now_us + 1)

    async def _transmit_coded_part(
        self, channel, packet, start, duration, address, coding, power_dbm
    ):
        # PHY end times identify the last occupied microsecond, not the boundary.
        end = start + duration - 1
        request = TX_V2.pack(
            start,
            end,
            start,
            end,
            address,
            NEVER,
            NEVER,
            *self.params(channel, Phy.LE_CODED),
            power_dbm * BSIM_POWER_SCALE,
            coding,
            len(packet),
        )
        connection = self._connection()
        await connection.send(HEADER.pack(TX_V2_REQUEST) + request + packet)
        await connection.response(TX_END)
        self.now_us = TIME.unpack(await connection.receive(TIME.size))[0]

    async def receive(
        self,
        channel: int,
        until_us: int,
        *,
        start_us: int | None = None,
        access_address: int = PDU_ADV_ACCESS_ADDRESS,
        crc_init: int = PDU_ADV_CRC_INIT,
        accept_bad_crc: bool = False,
        phy: Phy = Phy.LE_1M,
    ) -> Received | None:
        phy = Phy(phy)
        start_us = self.now_us + 1 if start_us is None else start_us
        if start_us <= self.now_us:
            raise ValueError('reception must start after the current PHY time')
        start_us = max(start_us, self.earliest_start_us(channel, phy, transmit=False))
        if start_us >= until_us:
            await self.advance_to_us(until_us)
            return None
        connection = self._connection()
        request = RX.pack(
            start_us,
            until_us - start_us,
            access_address,
            *self.params(channel, phy),
            0,
            BSIM_RX_SYNC_THRESHOLD,
            0,
            phy.address_us,
            PDU_HEADER_SIZE
            * (PHY_2M_OCTET_TIME_US if phy == Phy.LE_2M else PHY_1M_OCTET_TIME_US),
            PHY_2M_BITRATE_BPS if phy == Phy.LE_2M else PHY_1M_BITRATE_BPS,
            NEVER,
            NEVER,
        )
        await connection.start_request(start_us)
        try:
            if phy == Phy.LE_CODED:
                return await self._receive_coded(
                    channel,
                    start_us,
                    until_us,
                    access_address,
                    crc_init,
                    accept_bad_crc,
                )
            await connection.send(HEADER.pack(RX_REQUEST) + request)
            header = HEADER.unpack(await connection.receive(HEADER.size))[0]
            packet = b''
            if header == RX_ADDRESS:
                _, size, _, address_end_us, _ = RX_DONE.unpack(
                    await connection.receive(RX_DONE.size)
                )
                self.now_us = address_end_us
                if not BSIM_PACKET_SIZE_MIN <= size <= BSIM_PACKET_SIZE_MAX:
                    raise RuntimeError(f'invalid BabbleSim packet size: {size}')
                packet = await connection.receive(size)
                await connection.send(HEADER.pack(RX_CONTINUE))
                await connection.response(RX_END)
            elif header != RX_END:
                raise RuntimeError(f'unexpected BabbleSim RX response: {header:#x}')
            status, size, address_us, end_us, rssi = RX_DONE.unpack(
                await connection.receive(RX_DONE.size)
            )
            self.now_us = end_us
            # Without -crcerr_data, PHY clears packet_size on CRC failure.
            if status not in (RX_STATUS_OK, RX_STATUS_CRC_ERROR) or size == 0:
                return None
            if len(packet) != size:
                raise RuntimeError('BabbleSim RX packet size changed')
            valid_crc = status == RX_STATUS_OK and packet[-PDU_CRC_SIZE:] == crc24(
                packet[:-PDU_CRC_SIZE], crc_init
            )
            if not valid_crc and not accept_bad_crc:
                return None
            return Received(
                # The v1 PHY timestamps the last preamble/address microsecond.
                packet[:-PDU_CRC_SIZE],
                rssi / BSIM_RSSI_SCALE,
                address_us - (phy.address_us - 1),
                end_us + 1,
                valid_crc,
                phy,
            )
        finally:
            connection.end_request()
            self.switch.complete(channel, phy, transmit=False, end_us=self.now_us + 1)

    async def _receive_coded_part(
        self, channel, start, until, address, coding, prelocked
    ):
        connection = self._connection()
        request = RX_V2.pack(
            start,
            NEVER,
            NEVER,
            1 if prelocked else until - start,
            BSIM_RX_FORCED_DURATION_FOLLOW_TX,
            PHY_1M_BITRATE_BPS // coding,
            *self.params(channel, Phy.LE_CODED),
            0,
            coding,
            0 if prelocked else PHY_CODED_ADDRESS_TIME_US,
            PDU_HEADER_SIZE * PHY_1M_OCTET_TIME_US * (coding if prelocked else 1),
            0,
            BSIM_RX_ERROR_THRESHOLD_MAX if prelocked else BSIM_RX_SYNC_THRESHOLD,
            0 if prelocked else BSIM_RX_ERROR_THRESHOLD_MAX,
            int(prelocked),
            0,
            int(not prelocked),
        )
        await connection.send(
            HEADER.pack(RX_V2_REQUEST)
            + request
            + (b'' if prelocked else TIME.pack(address))
        )
        header = HEADER.unpack(await connection.receive(HEADER.size))[0]
        packet = b''
        if header == RX_V2_ADDRESS:
            _, _, _, _, _, _, size = RX_V2_DONE.unpack(
                await connection.receive(RX_V2_DONE.size)
            )
            if not 1 <= size <= BSIM_PACKET_SIZE_MAX:
                raise RuntimeError(f'invalid BabbleSim Coded packet size: {size}')
            packet = await connection.receive(size)
            await connection.send(
                HEADER.pack(RX_V2_CONTINUE) + TIME.pack(NEVER) + TIME.pack(NEVER)
            )
            await connection.response(RX_V2_END)
        elif header != RX_V2_END:
            raise RuntimeError(f'unexpected BabbleSim Coded response: {header:#x}')
        result = RX_V2_DONE.unpack(await connection.receive(RX_V2_DONE.size))
        self.now_us = result[1]
        return packet, result

    async def _receive_coded(
        self, channel, start, until, address, crc_init, accept_bad_crc
    ):
        ci, first = await self._receive_coded_part(
            channel, start, until, address, PHY_CODED_S8_FACTOR, False
        )
        address_end_us, ci_end_us, _, _, _, ci_status, _ = first
        if ci_status != RX_STATUS_OK or ci not in (BSIM_CODED_CI_S8, BSIM_CODED_CI_S2):
            return None
        coding = PHY_CODED_S2_FACTOR if ci == BSIM_CODED_CI_S2 else PHY_CODED_S8_FACTOR
        packet, result = await self._receive_coded_part(
            channel, ci_end_us + 1, until, address, coding, True
        )
        _, end, _, _, rssi, status, size = result
        if (
            status not in (RX_STATUS_OK, RX_STATUS_CRC_ERROR)
            or size < BSIM_PACKET_SIZE_MIN
            or size != len(packet)
        ):
            return None
        valid = status == RX_STATUS_OK and packet[-PDU_CRC_SIZE:] == crc24(
            packet[:-PDU_CRC_SIZE], crc_init
        )
        if not valid and not accept_bad_crc:
            return None
        return Received(
            packet[:-PDU_CRC_SIZE],
            rssi / BSIM_RSSI_SCALE,
            address_end_us - (PHY_CODED_ADDRESS_TIME_US - 1),
            end + 1,
            valid,
            Phy.LE_CODED,
            coding,
        )


class _ControllerClock:
    """Software timers share the radio's identity and time, not another PHY device."""

    def __init__(self, radio: BabbleSimRadio):
        self.radio = radio

    @property
    def now_us(self) -> int:
        return self.radio.now_us

    def advance_to_us(self, target_us: int) -> int:
        self.radio._connection().wait_sync(target_us, BSIM_IO_TIMEOUT_SECONDS)
        self.radio.now_us = target_us
        return target_us
