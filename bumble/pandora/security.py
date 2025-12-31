# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from typing import Any

import grpc
from google.protobuf import (
    any_pb2,  # pytype: disable=pyi-error
    empty_pb2,  # pytype: disable=pyi-error
    wrappers_pb2,  # pytype: disable=pyi-error
)
from pandora.host_pb2 import Connection
from pandora.security_grpc_aio import SecurityServicer, SecurityStorageServicer
from pandora.security_pb2 import (
    LE_LEVEL1,
    LE_LEVEL2,
    LE_LEVEL3,
    LE_LEVEL4,
    LEVEL0,
    LEVEL1,
    LEVEL2,
    LEVEL3,
    LEVEL4,
    DeleteBondRequest,
    IsBondedRequest,
    LESecurityLevel,
    PairingEvent,
    PairingEventAnswer,
    SecureRequest,
    SecureResponse,
    SecurityLevel,
    WaitSecurityRequest,
    WaitSecurityResponse,
)

import bumble.utils
from bumble import hci
from bumble.core import InvalidArgumentError, PhysicalTransport, ProtocolError
from bumble.device import Connection as BumbleConnection
from bumble.device import Device
from bumble.hci import HCI_Error, Role
from bumble.pairing import PairingConfig
from bumble.pairing import PairingDelegate as BasePairingDelegate
from bumble.pandora import utils
from bumble.pandora.config import Config


class PairingDelegate(BasePairingDelegate):
    def __init__(
        self,
        connection: BumbleConnection,
        service: SecurityService,
        io_capability: BasePairingDelegate.IoCapability = BasePairingDelegate.NO_OUTPUT_NO_INPUT,
        local_initiator_key_distribution: BasePairingDelegate.KeyDistribution = BasePairingDelegate.DEFAULT_KEY_DISTRIBUTION,
        local_responder_key_distribution: BasePairingDelegate.KeyDistribution = BasePairingDelegate.DEFAULT_KEY_DISTRIBUTION,
    ) -> None:
        self.log = utils.BumbleServerLoggerAdapter(
            logging.getLogger(),
            {'service_name': 'Security', 'device': connection.device},
        )
        self.connection = connection
        self.service = service
        super().__init__(
            io_capability,
            local_initiator_key_distribution,
            local_responder_key_distribution,
        )

    async def accept(self) -> bool:
        return True

    def add_origin(self, ev: PairingEvent) -> PairingEvent:
        if not self.connection.is_incomplete:
            assert ev.connection
            ev.connection.CopyFrom(
                Connection(
                    cookie=any_pb2.Any(value=self.connection.handle.to_bytes(4, 'big'))
                )
            )
        else:
            # In BR/EDR, connection may not be complete,
            # use address instead
            assert self.connection.transport == PhysicalTransport.BR_EDR
            ev.address = bytes(reversed(bytes(self.connection.peer_address)))

        return ev

    async def confirm(self, auto: bool = False) -> bool:
        self.log.debug(
            f"Pairing event: `just_works` (io_capability: {self.io_capability})"
        )

        if self.service.event_queue is None or self.service.event_answer is None:
            return True

        event = self.add_origin(PairingEvent(just_works=empty_pb2.Empty()))
        self.service.event_queue.put_nowait(event)
        answer = await anext(self.service.event_answer)  # type: ignore
        assert answer.event == event
        assert answer.answer_variant() == 'confirm' and answer.confirm is not None
        return answer.confirm

    async def compare_numbers(self, number: int, digits: int = 6) -> bool:
        self.log.debug(
            f"Pairing event: `numeric_comparison` (io_capability: {self.io_capability})"
        )

        if self.service.event_queue is None or self.service.event_answer is None:
            raise RuntimeError('security: unhandled number comparison request')

        event = self.add_origin(PairingEvent(numeric_comparison=number))
        self.service.event_queue.put_nowait(event)
        answer = await anext(self.service.event_answer)  # type: ignore
        assert answer.event == event
        assert answer.answer_variant() == 'confirm' and answer.confirm is not None
        return answer.confirm

    async def get_number(self) -> int | None:
        self.log.debug(
            f"Pairing event: `passkey_entry_request` (io_capability: {self.io_capability})"
        )

        if self.service.event_queue is None or self.service.event_answer is None:
            raise RuntimeError('security: unhandled number request')

        event = self.add_origin(PairingEvent(passkey_entry_request=empty_pb2.Empty()))
        self.service.event_queue.put_nowait(event)
        answer = await anext(self.service.event_answer)  # type: ignore
        assert answer.event == event
        if answer.answer_variant() is None:
            return None
        assert answer.answer_variant() == 'passkey'
        return answer.passkey

    async def get_string(self, max_length: int) -> str | None:
        self.log.debug(
            f"Pairing event: `pin_code_request` (io_capability: {self.io_capability})"
        )

        if self.service.event_queue is None or self.service.event_answer is None:
            raise RuntimeError('security: unhandled pin_code request')

        event = self.add_origin(PairingEvent(pin_code_request=empty_pb2.Empty()))
        self.service.event_queue.put_nowait(event)
        answer = await anext(self.service.event_answer)  # type: ignore
        assert answer.event == event
        if answer.answer_variant() is None:
            return None
        assert answer.answer_variant() == 'pin'

        if answer.pin is None:
            return None

        pin = answer.pin.decode('utf-8')
        if not pin or len(pin) > max_length:
            raise ValueError(f'Pin must be utf-8 encoded up to {max_length} bytes')

        return pin

    async def display_number(self, number: int, digits: int = 6) -> None:
        if (
            self.connection.transport == PhysicalTransport.BR_EDR
            and self.io_capability == BasePairingDelegate.DISPLAY_OUTPUT_ONLY
        ):
            return

        self.log.debug(
            f"Pairing event: `passkey_entry_notification` (io_capability: {self.io_capability})"
        )

        if self.service.event_queue is None:
            raise RuntimeError('security: unhandled number display request')

        event = self.add_origin(PairingEvent(passkey_entry_notification=number))
        self.service.event_queue.put_nowait(event)


class SecurityService(SecurityServicer):
    def __init__(self, device: Device, config: Config) -> None:
        self.log = utils.BumbleServerLoggerAdapter(
            logging.getLogger(), {'service_name': 'Security', 'device': device}
        )
        self.event_queue: asyncio.Queue[PairingEvent] | None = None
        self.event_answer: AsyncIterator[PairingEventAnswer] | None = None
        self.device = device
        self.config = config

        def pairing_config_factory(connection: BumbleConnection) -> PairingConfig:
            return PairingConfig(
                sc=config.pairing_sc_enable,
                mitm=config.pairing_mitm_enable,
                bonding=config.pairing_bonding_enable,
                identity_address_type=(
                    PairingConfig.AddressType.PUBLIC
                    if connection.self_address.is_public
                    else config.identity_address_type
                ),
                delegate=PairingDelegate(
                    connection,
                    self,
                    io_capability=config.io_capability,
                    local_initiator_key_distribution=config.smp_local_initiator_key_distribution,
                    local_responder_key_distribution=config.smp_local_responder_key_distribution,
                ),
            )

        self.device.pairing_config_factory = pairing_config_factory

    async def _classic_level_reached(
        self, level: SecurityLevel, connection: BumbleConnection
    ) -> bool:
        if level == LEVEL0:
            return True
        if level == LEVEL1:
            return connection.encryption == 0 or connection.authenticated
        if level == LEVEL2:
            return connection.encryption != 0 and connection.authenticated

        link_key_type: int | None = None
        if (keystore := connection.device.keystore) and (
            keys := await keystore.get(str(connection.peer_address))
        ):
            link_key_type = keys.link_key_type
        self.log.debug("link_key_type: %d", link_key_type)

        if level == LEVEL3:
            return (
                connection.encryption != 0
                and connection.authenticated
                and link_key_type
                in (
                    hci.LinkKeyType.AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192,
                    hci.LinkKeyType.AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256,
                )
            )
        if level == LEVEL4:
            return (
                connection.encryption == hci.HCI_Encryption_Change_Event.Enabled.AES_CCM
                and connection.authenticated
                and link_key_type
                == hci.LinkKeyType.AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256
            )
        raise InvalidArgumentError(f"Unexpected level {level}")

    def _le_level_reached(
        self, level: LESecurityLevel, connection: BumbleConnection
    ) -> bool:
        if level == LE_LEVEL1:
            return True
        if level == LE_LEVEL2:
            return connection.encryption != 0
        if level == LE_LEVEL3:
            return connection.encryption != 0 and connection.authenticated
        if level == LE_LEVEL4:
            return (
                connection.encryption != 0
                and connection.authenticated
                and connection.sc
            )
        raise InvalidArgumentError(f"Unexpected level {level}")

    @utils.rpc
    async def OnPairing(
        self, request: AsyncIterator[PairingEventAnswer], context: grpc.ServicerContext
    ) -> AsyncGenerator[PairingEvent, None]:
        self.log.debug('OnPairing')

        if self.event_queue is not None:
            raise RuntimeError('already streaming pairing events')

        if len(self.device.connections):
            raise RuntimeError(
                'the `OnPairing` method shall be initiated before establishing any connections.'
            )

        self.event_queue = asyncio.Queue()
        self.event_answer = request

        try:
            while event := await self.event_queue.get():
                yield event

        finally:
            self.event_queue = None
            self.event_answer = None

    @utils.rpc
    async def Secure(
        self, request: SecureRequest, context: grpc.ServicerContext
    ) -> SecureResponse:
        connection_handle = int.from_bytes(request.connection.cookie.value, 'big')
        self.log.debug(f"Secure: {connection_handle}")

        connection = self.device.lookup_connection(connection_handle)
        assert connection

        oneof = request.WhichOneof('level')
        level = getattr(request, oneof)
        assert {PhysicalTransport.BR_EDR: 'classic', PhysicalTransport.LE: 'le'}[
            connection.transport
        ] == oneof

        # security level already reached
        if await self.reached_security_level(connection, level):
            return SecureResponse(success=empty_pb2.Empty())

        # trigger pairing if needed
        if self.need_pairing(connection, level):
            try:
                self.log.debug('Pair...')

                security_result = asyncio.get_running_loop().create_future()

                with contextlib.closing(bumble.utils.EventWatcher()) as watcher:

                    @watcher.on(connection, connection.EVENT_PAIRING)
                    def on_pairing(*_: Any) -> None:
                        security_result.set_result('success')

                    @watcher.on(connection, connection.EVENT_PAIRING_FAILURE)
                    def on_pairing_failure(*_: Any) -> None:
                        security_result.set_result('pairing_failure')

                    @watcher.on(connection, connection.EVENT_DISCONNECTION)
                    def on_disconnection(*_: Any) -> None:
                        security_result.set_result('connection_died')

                    if (
                        connection.transport == PhysicalTransport.LE
                        and connection.role == Role.PERIPHERAL
                    ):
                        connection.request_pairing()
                    else:
                        await connection.pair()

                    result = await security_result

                self.log.debug(f'Pairing session complete, status={result}')
                if result != 'success':
                    return SecureResponse(**{result: empty_pb2.Empty()})
            except asyncio.CancelledError:
                self.log.warning("Connection died during encryption")
                return SecureResponse(connection_died=empty_pb2.Empty())
            except (HCI_Error, ProtocolError) as e:
                self.log.warning(f"Pairing failure: {e}")
                return SecureResponse(pairing_failure=empty_pb2.Empty())

        # trigger authentication if needed
        if self.need_authentication(connection, level):
            try:
                self.log.debug('Authenticate...')
                await connection.authenticate()
                self.log.debug('Authenticated')
            except asyncio.CancelledError:
                self.log.warning("Connection died during authentication")
                return SecureResponse(connection_died=empty_pb2.Empty())
            except (HCI_Error, ProtocolError) as e:
                self.log.warning(f"Authentication failure: {e}")
                return SecureResponse(authentication_failure=empty_pb2.Empty())

        # trigger encryption if needed
        if self.need_encryption(connection, level):
            try:
                self.log.debug('Encrypt...')
                await connection.encrypt()
                self.log.debug('Encrypted')
            except asyncio.CancelledError:
                self.log.warning("Connection died during encryption")
                return SecureResponse(connection_died=empty_pb2.Empty())
            except (HCI_Error, ProtocolError) as e:
                self.log.warning(f"Encryption failure: {e}")
                return SecureResponse(encryption_failure=empty_pb2.Empty())

        # security level has been reached ?
        if await self.reached_security_level(connection, level):
            return SecureResponse(success=empty_pb2.Empty())
        return SecureResponse(not_reached=empty_pb2.Empty())

    @utils.rpc
    async def WaitSecurity(
        self, request: WaitSecurityRequest, context: grpc.ServicerContext
    ) -> WaitSecurityResponse:
        connection_handle = int.from_bytes(request.connection.cookie.value, 'big')
        self.log.debug(f"WaitSecurity: {connection_handle}")

        connection = self.device.lookup_connection(connection_handle)
        assert connection

        assert request.level
        level = request.level
        assert {PhysicalTransport.BR_EDR: 'classic', PhysicalTransport.LE: 'le'}[
            connection.transport
        ] == request.level_variant()

        wait_for_security: asyncio.Future[str] = (
            asyncio.get_running_loop().create_future()
        )
        authenticate_task: asyncio.Future[None] | None = None
        pair_task: asyncio.Future[None] | None = None

        async def authenticate() -> None:
            if (encryption := connection.encryption) != 0:
                self.log.debug('Disable encryption...')
                with contextlib.suppress(Exception):
                    await connection.encrypt(enable=False)
                self.log.debug('Disable encryption: done')

            self.log.debug('Authenticate...')
            await connection.authenticate()
            self.log.debug('Authenticate: done')

            if encryption != 0 and connection.encryption != encryption:
                self.log.debug('Re-enable encryption...')
                await connection.encrypt()
                self.log.debug('Re-enable encryption: done')

        def set_failure(name: str) -> Callable[..., None]:
            def wrapper(*args: Any) -> None:
                self.log.debug(f'Wait for security: error `{name}`: {args}')
                wait_for_security.set_result(name)

            return wrapper

        async def try_set_success(*_: Any) -> None:
            if await self.reached_security_level(connection, level):
                self.log.debug('Wait for security: done')
                wait_for_security.set_result('success')

        async def on_encryption_change(*_: Any) -> None:
            if await self.reached_security_level(connection, level):
                self.log.debug('Wait for security: done')
                wait_for_security.set_result('success')
            elif (
                connection.transport == PhysicalTransport.BR_EDR
                and self.need_authentication(connection, level)
            ):
                nonlocal authenticate_task
                if authenticate_task is None:
                    authenticate_task = asyncio.create_task(authenticate())

        def pair(*_: Any) -> None:
            if self.need_pairing(connection, level):
                bumble.utils.AsyncRunner.spawn(connection.pair())

        listeners: dict[str, Callable[..., None | Awaitable[None]]] = {
            'disconnection': set_failure('connection_died'),
            'pairing_failure': set_failure('pairing_failure'),
            'connection_authentication_failure': set_failure('authentication_failure'),
            'connection_encryption_failure': set_failure('encryption_failure'),
            'pairing': try_set_success,
            'connection_authentication': try_set_success,
            'connection_encryption_change': on_encryption_change,
            'classic_pairing': try_set_success,
            'classic_pairing_failure': set_failure('pairing_failure'),
            'security_request': pair,
        }

        with contextlib.closing(bumble.utils.EventWatcher()) as watcher:
            # register event handlers
            for event, listener in listeners.items():
                watcher.on(connection, event, listener)

            # security level already reached
            if await self.reached_security_level(connection, level):
                return WaitSecurityResponse(success=empty_pb2.Empty())

            self.log.debug('Wait for security...')
            kwargs = {}
            kwargs[await wait_for_security] = empty_pb2.Empty()

        # wait for `authenticate` to finish if any
        if authenticate_task is not None:
            self.log.debug('Wait for authentication...')
            with contextlib.suppress(Exception):
                await authenticate_task  # type: ignore
            self.log.debug('Authenticated')

        # wait for `pair` to finish if any
        if pair_task is not None:
            self.log.debug('Wait for authentication...')
            with contextlib.suppress(Exception):
                await pair_task  # type: ignore
            self.log.debug('paired')

        return WaitSecurityResponse(**kwargs)

    async def reached_security_level(
        self, connection: BumbleConnection, level: SecurityLevel | LESecurityLevel
    ) -> bool:
        self.log.debug(
            str(
                {
                    'level': level,
                    'encryption': connection.encryption,
                    'authenticated': connection.authenticated,
                    'sc': connection.sc,
                }
            )
        )

        if isinstance(level, LESecurityLevel):
            return self._le_level_reached(level, connection)

        return await self._classic_level_reached(level, connection)

    def need_pairing(self, connection: BumbleConnection, level: int) -> bool:
        if connection.transport == PhysicalTransport.LE:
            return level >= LE_LEVEL3 and not connection.authenticated
        return False

    def need_authentication(self, connection: BumbleConnection, level: int) -> bool:
        if connection.transport == PhysicalTransport.LE:
            return False
        if level == LEVEL2 and connection.encryption != 0:
            return not connection.authenticated
        return level >= LEVEL2 and not connection.authenticated

    def need_encryption(self, connection: BumbleConnection, level: int) -> bool:
        # TODO(abel): need to support MITM
        if connection.transport == PhysicalTransport.LE:
            return level == LE_LEVEL2 and not connection.encryption
        return level >= LEVEL2 and not connection.encryption


class SecurityStorageService(SecurityStorageServicer):
    def __init__(self, device: Device, config: Config) -> None:
        self.log = utils.BumbleServerLoggerAdapter(
            logging.getLogger(), {'service_name': 'SecurityStorage', 'device': device}
        )
        self.device = device
        self.config = config

    @utils.rpc
    async def IsBonded(
        self, request: IsBondedRequest, context: grpc.ServicerContext
    ) -> wrappers_pb2.BoolValue:
        address = utils.address_from_request(request, request.WhichOneof("address"))
        self.log.debug(f"IsBonded: {address}")

        if self.device.keystore is not None:
            is_bonded = await self.device.keystore.get(str(address)) is not None
        else:
            is_bonded = False

        return wrappers_pb2.BoolValue(value=is_bonded)

    @utils.rpc
    async def DeleteBond(
        self, request: DeleteBondRequest, context: grpc.ServicerContext
    ) -> empty_pb2.Empty:
        address = utils.address_from_request(request, request.WhichOneof("address"))
        self.log.debug(f"DeleteBond: {address}")

        if self.device.keystore is not None:
            with contextlib.suppress(KeyError):
                await self.device.keystore.delete(str(address))

        return empty_pb2.Empty()
