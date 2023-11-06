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
import grpc
import logging

from . import utils
from .config import Config
from bumble import hci
from bumble.core import (
    BT_BR_EDR_TRANSPORT,
    BT_LE_TRANSPORT,
    BT_PERIPHERAL_ROLE,
    ProtocolError,
)
from bumble.device import Connection as BumbleConnection, Device
from bumble.hci import HCI_Error
from bumble.utils import EventWatcher
from bumble.pairing import PairingConfig, PairingDelegate as BasePairingDelegate
from google.protobuf import any_pb2  # pytype: disable=pyi-error
from google.protobuf import empty_pb2  # pytype: disable=pyi-error
from google.protobuf import wrappers_pb2  # pytype: disable=pyi-error
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
from typing import Any, AsyncGenerator, AsyncIterator, Callable, Dict, Optional, Union


class PairingDelegate(BasePairingDelegate):
    def __init__(
        self,
        connection: BumbleConnection,
        service: "SecurityService",
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
            assert self.connection.transport == BT_BR_EDR_TRANSPORT
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
        answer = await anext(self.service.event_answer)  # pytype: disable=name-error
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
        answer = await anext(self.service.event_answer)  # pytype: disable=name-error
        assert answer.event == event
        assert answer.answer_variant() == 'confirm' and answer.confirm is not None
        return answer.confirm

    async def get_number(self) -> Optional[int]:
        self.log.debug(
            f"Pairing event: `passkey_entry_request` (io_capability: {self.io_capability})"
        )

        if self.service.event_queue is None or self.service.event_answer is None:
            raise RuntimeError('security: unhandled number request')

        event = self.add_origin(PairingEvent(passkey_entry_request=empty_pb2.Empty()))
        self.service.event_queue.put_nowait(event)
        answer = await anext(self.service.event_answer)  # pytype: disable=name-error
        assert answer.event == event
        if answer.answer_variant() is None:
            return None
        assert answer.answer_variant() == 'passkey'
        return answer.passkey

    async def get_string(self, max_length: int) -> Optional[str]:
        self.log.debug(
            f"Pairing event: `pin_code_request` (io_capability: {self.io_capability})"
        )

        if self.service.event_queue is None or self.service.event_answer is None:
            raise RuntimeError('security: unhandled pin_code request')

        event = self.add_origin(PairingEvent(pin_code_request=empty_pb2.Empty()))
        self.service.event_queue.put_nowait(event)
        answer = await anext(self.service.event_answer)  # pytype: disable=name-error
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
            self.connection.transport == BT_BR_EDR_TRANSPORT
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


BR_LEVEL_REACHED: Dict[SecurityLevel, Callable[[BumbleConnection], bool]] = {
    LEVEL0: lambda connection: True,
    LEVEL1: lambda connection: connection.encryption == 0 or connection.authenticated,
    LEVEL2: lambda connection: connection.encryption != 0 and connection.authenticated,
    LEVEL3: lambda connection: connection.encryption != 0
    and connection.authenticated
    and connection.link_key_type
    in (
        hci.HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE,
        hci.HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE,
    ),
    LEVEL4: lambda connection: connection.encryption
    == hci.HCI_Encryption_Change_Event.AES_CCM
    and connection.authenticated
    and connection.link_key_type
    == hci.HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE,
}

LE_LEVEL_REACHED: Dict[LESecurityLevel, Callable[[BumbleConnection], bool]] = {
    LE_LEVEL1: lambda connection: True,
    LE_LEVEL2: lambda connection: connection.encryption != 0,
    LE_LEVEL3: lambda connection: connection.encryption != 0
    and connection.authenticated,
    LE_LEVEL4: lambda connection: connection.encryption != 0
    and connection.authenticated
    and connection.sc,
}


class SecurityService(SecurityServicer):
    def __init__(self, device: Device, config: Config) -> None:
        self.log = utils.BumbleServerLoggerAdapter(
            logging.getLogger(), {'service_name': 'Security', 'device': device}
        )
        self.event_queue: Optional[asyncio.Queue[PairingEvent]] = None
        self.event_answer: Optional[AsyncIterator[PairingEventAnswer]] = None
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
        assert {BT_BR_EDR_TRANSPORT: 'classic', BT_LE_TRANSPORT: 'le'}[
            connection.transport
        ] == oneof

        # security level already reached
        if self.reached_security_level(connection, level):
            return SecureResponse(success=empty_pb2.Empty())

        # trigger pairing if needed
        if self.need_pairing(connection, level):
            try:
                self.log.debug('Pair...')

                security_result = asyncio.get_running_loop().create_future()

                with contextlib.closing(EventWatcher()) as watcher:

                    @watcher.on(connection, 'pairing')
                    def on_pairing(*_: Any) -> None:
                        security_result.set_result('success')

                    @watcher.on(connection, 'pairing_failure')
                    def on_pairing_failure(*_: Any) -> None:
                        security_result.set_result('pairing_failure')

                    @watcher.on(connection, 'disconnection')
                    def on_disconnection(*_: Any) -> None:
                        security_result.set_result('connection_died')

                    if (
                        connection.transport == BT_LE_TRANSPORT
                        and connection.role == BT_PERIPHERAL_ROLE
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
        if self.reached_security_level(connection, level):
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
        assert {BT_BR_EDR_TRANSPORT: 'classic', BT_LE_TRANSPORT: 'le'}[
            connection.transport
        ] == request.level_variant()

        wait_for_security: asyncio.Future[
            str
        ] = asyncio.get_running_loop().create_future()
        authenticate_task: Optional[asyncio.Future[None]] = None
        pair_task: Optional[asyncio.Future[None]] = None

        async def authenticate() -> None:
            assert connection
            if (encryption := connection.encryption) != 0:
                self.log.debug('Disable encryption...')
                try:
                    await connection.encrypt(enable=False)
                except:
                    pass
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

        def try_set_success(*_: Any) -> None:
            assert connection
            if self.reached_security_level(connection, level):
                self.log.debug('Wait for security: done')
                wait_for_security.set_result('success')

        def on_encryption_change(*_: Any) -> None:
            assert connection
            if self.reached_security_level(connection, level):
                self.log.debug('Wait for security: done')
                wait_for_security.set_result('success')
            elif (
                connection.transport == BT_BR_EDR_TRANSPORT
                and self.need_authentication(connection, level)
            ):
                nonlocal authenticate_task
                if authenticate_task is None:
                    authenticate_task = asyncio.create_task(authenticate())

        def pair(*_: Any) -> None:
            if self.need_pairing(connection, level):
                pair_task = asyncio.create_task(connection.pair())

        listeners: Dict[str, Callable[..., None]] = {
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

        with contextlib.closing(EventWatcher()) as watcher:
            # register event handlers
            for event, listener in listeners.items():
                watcher.on(connection, event, listener)

            # security level already reached
            if self.reached_security_level(connection, level):
                return WaitSecurityResponse(success=empty_pb2.Empty())

            self.log.debug('Wait for security...')
            kwargs = {}
            kwargs[await wait_for_security] = empty_pb2.Empty()

        # wait for `authenticate` to finish if any
        if authenticate_task is not None:
            self.log.debug('Wait for authentication...')
            try:
                await authenticate_task  # type: ignore
            except:
                pass
            self.log.debug('Authenticated')

        # wait for `pair` to finish if any
        if pair_task is not None:
            self.log.debug('Wait for authentication...')
            try:
                await pair_task  # type: ignore
            except:
                pass
            self.log.debug('paired')

        return WaitSecurityResponse(**kwargs)

    def reached_security_level(
        self, connection: BumbleConnection, level: Union[SecurityLevel, LESecurityLevel]
    ) -> bool:
        self.log.debug(
            str(
                {
                    'level': level,
                    'encryption': connection.encryption,
                    'authenticated': connection.authenticated,
                    'sc': connection.sc,
                    'link_key_type': connection.link_key_type,
                }
            )
        )

        if isinstance(level, LESecurityLevel):
            return LE_LEVEL_REACHED[level](connection)

        return BR_LEVEL_REACHED[level](connection)

    def need_pairing(self, connection: BumbleConnection, level: int) -> bool:
        if connection.transport == BT_LE_TRANSPORT:
            return level >= LE_LEVEL3 and not connection.authenticated
        return False

    def need_authentication(self, connection: BumbleConnection, level: int) -> bool:
        if connection.transport == BT_LE_TRANSPORT:
            return False
        if level == LEVEL2 and connection.encryption != 0:
            return not connection.authenticated
        return level >= LEVEL2 and not connection.authenticated

    def need_encryption(self, connection: BumbleConnection, level: int) -> bool:
        # TODO(abel): need to support MITM
        if connection.transport == BT_LE_TRANSPORT:
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
