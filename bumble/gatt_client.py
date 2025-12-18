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
# GATT - Generic Attribute Profile
# Client
#
# See Bluetooth spec @ Vol 3, Part G
#
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations

import asyncio
import functools
import logging
import struct
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import (
    TYPE_CHECKING,
    Any,
    Generic,
    TypeVar,
    overload,
)

from bumble import att, core, l2cap, utils
from bumble.colors import color
from bumble.core import UUID, InvalidStateError
from bumble.gatt import (
    GATT_CHARACTERISTIC_ATTRIBUTE_TYPE,
    GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
    GATT_INCLUDE_ATTRIBUTE_TYPE,
    GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE,
    GATT_REQUEST_TIMEOUT,
    GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE,
    Characteristic,
    ClientCharacteristicConfigurationBits,
    InvalidServiceError,
    TemplateService,
)
from bumble.hci import HCI_Constant

if TYPE_CHECKING:
    from bumble import device as device_module

# -----------------------------------------------------------------------------
# Typing
# -----------------------------------------------------------------------------
_T = TypeVar('_T')

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------


def show_services(services: Iterable[ServiceProxy]) -> None:
    for service in services:
        print(color(str(service), 'cyan'))

        for characteristic in service.characteristics:
            print(color('  ' + str(characteristic), 'magenta'))

            for descriptor in characteristic.descriptors:
                print(color('    ' + str(descriptor), 'green'))


# -----------------------------------------------------------------------------
# Proxies
# -----------------------------------------------------------------------------
class AttributeProxy(utils.EventEmitter, Generic[_T]):
    def __init__(
        self, client: Client, handle: int, end_group_handle: int, attribute_type: UUID
    ) -> None:
        utils.EventEmitter.__init__(self)
        self.client = client
        self.handle = handle
        self.end_group_handle = end_group_handle
        self.type = attribute_type

    async def read_value(self, no_long_read: bool = False) -> _T:
        return self.decode_value(
            await self.client.read_value(self.handle, no_long_read)
        )

    async def write_value(self, value: _T, with_response=False):
        return await self.client.write_value(
            self.handle, self.encode_value(value), with_response
        )

    def encode_value(self, value: _T) -> bytes:
        return value  # type: ignore

    def decode_value(self, value: bytes) -> _T:
        return value  # type: ignore

    def __str__(self) -> str:
        return f'Attribute(handle=0x{self.handle:04X}, type={self.type})'


class ServiceProxy(AttributeProxy):
    uuid: UUID
    characteristics: list[CharacteristicProxy[bytes]]
    included_services: list[ServiceProxy]

    @staticmethod
    def from_client(service_class, client: Client, service_uuid: UUID):
        # The service and its characteristics are considered to have already been
        # discovered
        services = client.get_services_by_uuid(service_uuid)
        service = services[0] if services else None
        return service_class(service) if service else None

    def __init__(self, client, handle, end_group_handle, uuid, primary=True):
        attribute_type = (
            GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE
            if primary
            else GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE
        )
        super().__init__(client, handle, end_group_handle, attribute_type)
        self.uuid = uuid
        self.characteristics = []

    async def discover_characteristics(
        self, uuids=()
    ) -> list[CharacteristicProxy[bytes]]:
        return await self.client.discover_characteristics(uuids, self)

    def get_characteristics_by_uuid(
        self, uuid: UUID
    ) -> list[CharacteristicProxy[bytes]]:
        """Get all the characteristics with a specified UUID."""
        return self.client.get_characteristics_by_uuid(uuid, self)

    def get_required_characteristic_by_uuid(
        self, uuid: UUID
    ) -> CharacteristicProxy[bytes]:
        """
        Get the first characteristic with a specified UUID.

        If no characteristic with that UUID is found, an InvalidServiceError is raised.
        """
        if not (characteristics := self.get_characteristics_by_uuid(uuid)):
            raise InvalidServiceError(f'{uuid} characteristic not found')
        return characteristics[0]

    def __str__(self) -> str:
        return f'Service(handle=0x{self.handle:04X}, uuid={self.uuid})'


class CharacteristicProxy(AttributeProxy[_T]):
    properties: Characteristic.Properties
    descriptors: list[DescriptorProxy]
    subscribers: dict[Any, Callable[[_T], Any]]

    EVENT_UPDATE = "update"

    def __init__(
        self,
        client: Client,
        handle: int,
        end_group_handle: int,
        uuid: UUID,
        properties: int,
    ) -> None:
        super().__init__(client, handle, end_group_handle, uuid)
        self.uuid = uuid
        self.properties = Characteristic.Properties(properties)
        self.descriptors = []
        self.descriptors_discovered = False
        self.subscribers = {}  # Map from subscriber to proxy subscriber

    def get_descriptor(self, descriptor_type: UUID) -> DescriptorProxy | None:
        for descriptor in self.descriptors:
            if descriptor.type == descriptor_type:
                return descriptor

        return None

    async def discover_descriptors(self) -> list[DescriptorProxy]:
        return await self.client.discover_descriptors(self)

    async def subscribe(
        self,
        subscriber: Callable[[_T], Any] | None = None,
        prefer_notify: bool = True,
    ) -> None:
        if subscriber is not None:
            if subscriber in self.subscribers:
                # We already have a proxy subscriber
                subscriber = self.subscribers[subscriber]
            else:
                # Create and register a proxy that will decode the value
                original_subscriber = subscriber

                def on_change(value):
                    original_subscriber(self.decode_value(value))

                self.subscribers[subscriber] = on_change
                subscriber = on_change

        await self.client.subscribe(self, subscriber, prefer_notify)

    async def unsubscribe(self, subscriber=None, force=False) -> None:
        if subscriber in self.subscribers:
            subscriber = self.subscribers.pop(subscriber)

        await self.client.unsubscribe(self, subscriber, force)

    def __str__(self) -> str:
        return (
            f'Characteristic(handle=0x{self.handle:04X}, '
            f'uuid={self.uuid}, '
            f'{self.properties!s})'
        )


class DescriptorProxy(AttributeProxy[bytes]):
    def __init__(self, client: Client, handle: int, descriptor_type: UUID) -> None:
        super().__init__(client, handle, 0, descriptor_type)

    def __str__(self) -> str:
        return f'Descriptor(handle=0x{self.handle:04X}, type={self.type})'


class ProfileServiceProxy:
    '''
    Base class for profile-specific service proxies
    '''

    SERVICE_CLASS: type[TemplateService]

    @classmethod
    def from_client(cls, client: Client) -> ProfileServiceProxy | None:
        return ServiceProxy.from_client(cls, client, cls.SERVICE_CLASS.UUID)


# -----------------------------------------------------------------------------
# GATT Client
# -----------------------------------------------------------------------------
class Client:
    services: list[ServiceProxy]
    cached_values: dict[int, tuple[datetime, bytes]]
    notification_subscribers: dict[
        int, set[CharacteristicProxy | Callable[[bytes], Any]]
    ]
    indication_subscribers: dict[int, set[CharacteristicProxy | Callable[[bytes], Any]]]
    pending_response: asyncio.futures.Future[att.ATT_PDU] | None
    pending_request: att.ATT_PDU | None

    def __init__(self, bearer: att.Bearer) -> None:
        self.bearer = bearer
        self.mtu_exchange_done = False
        self.request_semaphore = asyncio.Semaphore(1)
        self.pending_request = None
        self.pending_response = None
        self.notification_subscribers = {}  # Subscriber set, by attribute handle
        self.indication_subscribers = {}  # Subscriber set, by attribute handle
        self.services = []
        self.cached_values = {}

        if att.is_enhanced_bearer(bearer):
            bearer.on(bearer.EVENT_CLOSE, self.on_disconnection)
            self._bearer_id = (
                f'[0x{bearer.connection.handle:04X}|CID=0x{bearer.source_cid:04X}]'
            )
            # Fill the mtu.
            bearer.on_att_mtu_update(att.ATT_DEFAULT_MTU)
            self.connection = bearer.connection
        else:
            bearer.on(bearer.EVENT_DISCONNECTION, self.on_disconnection)
            self._bearer_id = f'[0x{bearer.handle:04X}]'
            self.connection = bearer

    @overload
    @classmethod
    async def connect_eatt(
        cls,
        connection: device_module.Connection,
        spec: l2cap.LeCreditBasedChannelSpec | None = None,
    ) -> Client: ...

    @overload
    @classmethod
    async def connect_eatt(
        cls,
        connection: device_module.Connection,
        spec: l2cap.LeCreditBasedChannelSpec | None = None,
        count: int = 1,
    ) -> list[Client]: ...

    @classmethod
    async def connect_eatt(
        cls,
        connection: device_module.Connection,
        spec: l2cap.LeCreditBasedChannelSpec | None = None,
        count: int = 1,
    ) -> list[Client] | Client:
        channels = await connection.device.l2cap_channel_manager.create_enhanced_credit_based_channels(
            connection,
            spec or l2cap.LeCreditBasedChannelSpec(psm=att.EATT_PSM),
            count,
        )

        def on_pdu(client: Client, pdu: bytes):
            client.on_gatt_pdu(att.ATT_PDU.from_bytes(pdu))

        clients = [cls(channel) for channel in channels]
        for channel, client in zip(channels, clients):
            channel.sink = functools.partial(on_pdu, client)
            channel.att_mtu = att.ATT_DEFAULT_MTU
        return clients[0] if count == 1 else clients

    @property
    def mtu(self) -> int:
        return self.bearer.att_mtu

    @mtu.setter
    def mtu(self, value: int) -> None:
        self.bearer.on_att_mtu_update(value)

    def send_gatt_pdu(self, pdu: bytes) -> None:
        if att.is_enhanced_bearer(self.bearer):
            self.bearer.write(pdu)
        else:
            self.bearer.send_l2cap_pdu(att.ATT_CID, pdu)

    async def send_command(self, command: att.ATT_PDU) -> None:
        logger.debug(f'GATT Command from client: {self._bearer_id} {command}')
        self.send_gatt_pdu(bytes(command))

    async def send_request(self, request: att.ATT_PDU):
        logger.debug(f'GATT Request from client: {self._bearer_id} {request}')

        # Wait until we can send (only one pending command at a time for the connection)
        response = None
        async with self.request_semaphore:
            assert self.pending_request is None
            assert self.pending_response is None

            # Create a future value to hold the eventual response
            self.pending_response = asyncio.get_running_loop().create_future()
            self.pending_request = request

            try:
                self.send_gatt_pdu(bytes(request))
                response = await asyncio.wait_for(
                    self.pending_response, GATT_REQUEST_TIMEOUT
                )
            except asyncio.TimeoutError as error:
                logger.warning(color('!!! GATT Request timeout', 'red'))
                raise core.TimeoutError(f'GATT timeout for {request.name}') from error
            finally:
                self.pending_request = None
                self.pending_response = None

        return response

    def send_confirmation(
        self, confirmation: att.ATT_Handle_Value_Confirmation
    ) -> None:
        logger.debug(f'GATT Confirmation from client: {self._bearer_id} {confirmation}')
        self.send_gatt_pdu(bytes(confirmation))

    async def request_mtu(self, mtu: int) -> int:
        # Check the range
        if mtu < att.ATT_DEFAULT_MTU:
            raise core.InvalidArgumentError(f'MTU must be >= {att.ATT_DEFAULT_MTU}')
        if mtu > 0xFFFF:
            raise core.InvalidArgumentError('MTU must be <= 0xFFFF')

        # We can only send one request per connection
        if self.mtu_exchange_done:
            return self.mtu

        # Send the request
        self.mtu_exchange_done = True
        response = await self.send_request(
            att.ATT_Exchange_MTU_Request(client_rx_mtu=mtu)
        )
        if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
            raise att.ATT_Error(error_code=response.error_code, message=response)

        # Compute the final MTU
        self.mtu = min(mtu, response.server_rx_mtu)

        return self.mtu

    def get_services_by_uuid(self, uuid: UUID) -> list[ServiceProxy]:
        return [service for service in self.services if service.uuid == uuid]

    def get_characteristics_by_uuid(
        self, uuid: UUID, service: ServiceProxy | None = None
    ) -> list[CharacteristicProxy[bytes]]:
        services = [service] if service else self.services
        return [
            c
            for c in [c for s in services for c in s.characteristics]
            if c.uuid == uuid
        ]

    def get_attribute_grouping(
        self, attribute_handle: int
    ) -> (
        ServiceProxy
        | tuple[ServiceProxy, CharacteristicProxy]
        | tuple[ServiceProxy, CharacteristicProxy, DescriptorProxy]
        | None
    ):
        """
        Get the attribute(s) associated with an attribute handle
        """
        for service in self.services:
            if service.handle == attribute_handle:
                return service
            if service.handle <= attribute_handle <= service.end_group_handle:
                for characteristic in service.characteristics:
                    if characteristic.handle == attribute_handle:
                        return (service, characteristic)
                    if (
                        characteristic.handle
                        <= attribute_handle
                        <= characteristic.end_group_handle
                    ):
                        for descriptor in characteristic.descriptors:
                            if descriptor.handle == attribute_handle:
                                return (service, characteristic, descriptor)
        return None

    def on_service_discovered(self, service):
        '''Add a service to the service list if it wasn't already there'''
        already_known = False
        for existing_service in self.services:
            if existing_service.handle == service.handle:
                already_known = True
                break
        if not already_known:
            self.services.append(service)

    async def discover_services(self, uuids: Iterable[UUID] = ()) -> list[ServiceProxy]:
        '''
        See Vol 3, Part G - 4.4.1 Discover All Primary Services
        '''
        starting_handle = 0x0001
        services = []
        while starting_handle < 0xFFFF:
            response = await self.send_request(
                att.ATT_Read_By_Group_Type_Request(
                    starting_handle=starting_handle,
                    ending_handle=0xFFFF,
                    attribute_group_type=GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE,
                )
            )
            if response is None:
                # TODO raise appropriate exception
                return []

            # Check if we reached the end of the iteration
            if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                if response.error_code != att.ATT_ATTRIBUTE_NOT_FOUND_ERROR:
                    # Unexpected end
                    logger.warning(
                        '!!! unexpected error while discovering services: '
                        f'{HCI_Constant.error_name(response.error_code)}'
                    )
                    raise att.ATT_Error(
                        error_code=response.error_code,
                        message='Unexpected error while discovering services',
                    )
                break

            for (
                attribute_handle,
                end_group_handle,
                attribute_value,
            ) in response.attributes:
                if (
                    attribute_handle < starting_handle
                    or end_group_handle < attribute_handle
                ):
                    # Something's not right
                    logger.warning(
                        f'bogus handle values: {attribute_handle} {end_group_handle}'
                    )
                    return []

                # Create a service proxy for this service
                service = ServiceProxy(
                    self,
                    attribute_handle,
                    end_group_handle,
                    UUID.from_bytes(attribute_value),
                    True,
                )

                # Filter out returned services based on the given uuids list
                if (not uuids) or (service.uuid in uuids):
                    services.append(service)

                # Add the service to the peer's service list
                self.on_service_discovered(service)

            # Stop if for some reason the list was empty
            if not response.attributes:
                break

            # Move on to the next chunk
            starting_handle = response.attributes[-1][1] + 1

        return services

    async def discover_service(self, uuid: str | UUID) -> list[ServiceProxy]:
        '''
        See Vol 3, Part G - 4.4.2 Discover Primary Service by Service UUID
        '''

        # Force uuid to be a UUID object
        if isinstance(uuid, str):
            uuid = UUID(uuid)

        starting_handle = 0x0001
        services = []
        while starting_handle < 0xFFFF:
            response = await self.send_request(
                att.ATT_Find_By_Type_Value_Request(
                    starting_handle=starting_handle,
                    ending_handle=0xFFFF,
                    attribute_type=GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE,
                    attribute_value=uuid.to_pdu_bytes(),
                )
            )
            if response is None:
                # TODO raise appropriate exception
                return []

            # Check if we reached the end of the iteration
            if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                if response.error_code != att.ATT_ATTRIBUTE_NOT_FOUND_ERROR:
                    # Unexpected end
                    logger.warning(
                        '!!! unexpected error while discovering services: '
                        f'{HCI_Constant.error_name(response.error_code)}'
                    )
                    # TODO raise appropriate exception
                    return []
                break

            for attribute_handle, end_group_handle in response.handles_information:
                if (
                    attribute_handle < starting_handle
                    or end_group_handle < attribute_handle
                ):
                    # Something's not right
                    logger.warning(
                        f'bogus handle values: {attribute_handle} {end_group_handle}'
                    )
                    return []

                # Create a service proxy for this service
                service = ServiceProxy(
                    self, attribute_handle, end_group_handle, uuid, True
                )

                # Add the service to the peer's service list
                services.append(service)
                self.on_service_discovered(service)

                # Check if we've reached the end already
                if end_group_handle == 0xFFFF:
                    break

            # Stop if for some reason the list was empty
            if not response.handles_information:
                break

            # Move on to the next chunk
            starting_handle = response.handles_information[-1][1] + 1

        return services

    async def discover_included_services(
        self, service: ServiceProxy
    ) -> list[ServiceProxy]:
        '''
        See Vol 3, Part G - 4.5.1 Find Included Services
        '''

        starting_handle = service.handle
        ending_handle = service.end_group_handle

        included_services: list[ServiceProxy] = []
        while starting_handle <= ending_handle:
            response = await self.send_request(
                att.ATT_Read_By_Type_Request(
                    starting_handle=starting_handle,
                    ending_handle=ending_handle,
                    attribute_type=GATT_INCLUDE_ATTRIBUTE_TYPE,
                )
            )
            if response is None:
                # TODO raise appropriate exception
                return []

            # Check if we reached the end of the iteration
            if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                if response.error_code != att.ATT_ATTRIBUTE_NOT_FOUND_ERROR:
                    # Unexpected end
                    logger.warning(
                        '!!! unexpected error while discovering included services: '
                        f'{HCI_Constant.error_name(response.error_code)}'
                    )
                    raise att.ATT_Error(
                        error_code=response.error_code,
                        message='Unexpected error while discovering included services',
                    )
                break

            # Stop if for some reason the list was empty
            if not response.attributes:
                break

            # Process all included services returned in this iteration
            for attribute_handle, attribute_value in response.attributes:
                if attribute_handle < starting_handle:
                    # Something's not right
                    logger.warning(f'bogus handle value: {attribute_handle}')
                    return []

                group_starting_handle, group_ending_handle = struct.unpack_from(
                    '<HH', attribute_value
                )
                service_uuid = UUID.from_bytes(attribute_value[4:])
                included_service = ServiceProxy(
                    self, group_starting_handle, group_ending_handle, service_uuid, True
                )

                included_services.append(included_service)

            # Move on to the next included services
            starting_handle = response.attributes[-1][0] + 1

        service.included_services = included_services
        return included_services

    async def discover_characteristics(
        self, uuids, service: ServiceProxy | None
    ) -> list[CharacteristicProxy[bytes]]:
        '''
        See Vol 3, Part G - 4.6.1 Discover All Characteristics of a Service and 4.6.2
        Discover Characteristics by UUID
        '''

        # Cast the UUIDs type from string to object if needed
        uuids = [UUID(uuid) if isinstance(uuid, str) else uuid for uuid in uuids]

        # Decide which services to discover for
        services = [service] if service else self.services

        # Perform characteristic discovery for each service
        discovered_characteristics: list[CharacteristicProxy[bytes]] = []
        for service in services:
            starting_handle = service.handle
            ending_handle = service.end_group_handle

            characteristics: list[CharacteristicProxy[bytes]] = []
            while starting_handle <= ending_handle:
                response = await self.send_request(
                    att.ATT_Read_By_Type_Request(
                        starting_handle=starting_handle,
                        ending_handle=ending_handle,
                        attribute_type=GATT_CHARACTERISTIC_ATTRIBUTE_TYPE,
                    )
                )
                if response is None:
                    # TODO raise appropriate exception
                    return []

                # Check if we reached the end of the iteration
                if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                    if response.error_code != att.ATT_ATTRIBUTE_NOT_FOUND_ERROR:
                        # Unexpected end
                        logger.warning(
                            '!!! unexpected error while discovering characteristics: '
                            f'{HCI_Constant.error_name(response.error_code)}'
                        )
                        raise att.ATT_Error(
                            error_code=response.error_code,
                            message='Unexpected error while discovering characteristics',
                        )
                    break

                # Stop if for some reason the list was empty
                if not response.attributes:
                    break

                # Process all characteristics returned in this iteration
                for attribute_handle, attribute_value in response.attributes:
                    if attribute_handle < starting_handle:
                        # Something's not right
                        logger.warning(f'bogus handle value: {attribute_handle}')
                        return []

                    properties, handle = struct.unpack_from('<BH', attribute_value)
                    characteristic_uuid = UUID.from_bytes(attribute_value[3:])
                    characteristic = CharacteristicProxy[bytes](
                        self, handle, 0, characteristic_uuid, properties
                    )

                    # Set the previous characteristic's end handle
                    if characteristics:
                        characteristics[-1].end_group_handle = attribute_handle - 1

                    characteristics.append(characteristic)

                # Move on to the next characteristics
                starting_handle = response.attributes[-1][0] + 1

            # Set the end handle for the last characteristic
            if characteristics:
                characteristics[-1].end_group_handle = service.end_group_handle

            # Set the service's characteristics
            characteristics = [
                c for c in characteristics if not uuids or c.uuid in uuids
            ]
            service.characteristics = characteristics
            discovered_characteristics.extend(characteristics)

        return discovered_characteristics

    async def discover_descriptors(
        self,
        characteristic: CharacteristicProxy | None = None,
        start_handle: int | None = None,
        end_handle: int | None = None,
    ) -> list[DescriptorProxy]:
        '''
        See Vol 3, Part G - 4.7.1 Discover All Characteristic Descriptors
        '''
        if characteristic:
            starting_handle = characteristic.handle + 1
            ending_handle = characteristic.end_group_handle
        elif start_handle and end_handle:
            starting_handle = start_handle
            ending_handle = end_handle
        else:
            return []

        descriptors: list[DescriptorProxy] = []
        while starting_handle <= ending_handle:
            response = await self.send_request(
                att.ATT_Find_Information_Request(
                    starting_handle=starting_handle, ending_handle=ending_handle
                )
            )
            if response is None:
                # TODO raise appropriate exception
                return []

            # Check if we reached the end of the iteration
            if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                if response.error_code != att.ATT_ATTRIBUTE_NOT_FOUND_ERROR:
                    # Unexpected end
                    logger.warning(
                        '!!! unexpected error while discovering descriptors: '
                        f'{HCI_Constant.error_name(response.error_code)}'
                    )
                    # TODO raise appropriate exception
                    return []
                break

            # Stop if for some reason the list was empty
            if not response.information:
                break

            # Process all descriptors returned in this iteration
            for attribute_handle, attribute_uuid in response.information:
                if attribute_handle < starting_handle:
                    # Something's not right
                    logger.warning(f'bogus handle value: {attribute_handle}')
                    return []

                descriptor = DescriptorProxy(
                    self, attribute_handle, UUID.from_bytes(attribute_uuid)
                )
                descriptors.append(descriptor)
                # TODO: read descriptor value

            # Move on to the next descriptor
            starting_handle = response.information[-1][0] + 1

        # Set the characteristic's descriptors
        if characteristic:
            characteristic.descriptors = descriptors

        return descriptors

    async def discover_attributes(self) -> list[AttributeProxy[bytes]]:
        '''
        Discover all attributes, regardless of type
        '''
        starting_handle = 0x0001
        ending_handle = 0xFFFF
        attributes = []
        while True:
            response = await self.send_request(
                att.ATT_Find_Information_Request(
                    starting_handle=starting_handle, ending_handle=ending_handle
                )
            )
            if response is None:
                return []

            # Check if we reached the end of the iteration
            if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                if response.error_code != att.ATT_ATTRIBUTE_NOT_FOUND_ERROR:
                    # Unexpected end
                    logger.warning(
                        '!!! unexpected error while discovering attributes: '
                        f'{HCI_Constant.error_name(response.error_code)}'
                    )
                    return []
                break

            for attribute_handle, attribute_uuid in response.information:
                if attribute_handle < starting_handle:
                    # Something's not right
                    logger.warning(f'bogus handle value: {attribute_handle}')
                    return []

                attribute = AttributeProxy[bytes](
                    self, attribute_handle, 0, UUID.from_bytes(attribute_uuid)
                )
                attributes.append(attribute)

            # Move on to the next attributes
            starting_handle = attributes[-1].handle + 1

        return attributes

    async def subscribe(
        self,
        characteristic: CharacteristicProxy,
        subscriber: Callable[[Any], Any] | None = None,
        prefer_notify: bool = True,
    ) -> None:
        # If we haven't already discovered the descriptors for this characteristic,
        # do it now
        if not characteristic.descriptors_discovered:
            await self.discover_descriptors(characteristic)

        # Look for the CCCD descriptor
        cccd = characteristic.get_descriptor(
            GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
        )
        if not cccd:
            logger.warning('subscribing to characteristic with no CCCD descriptor')
            return

        if (
            characteristic.properties & Characteristic.Properties.NOTIFY
            and characteristic.properties & Characteristic.Properties.INDICATE
        ):
            if prefer_notify:
                bits = ClientCharacteristicConfigurationBits.NOTIFICATION
                subscribers = self.notification_subscribers
            else:
                bits = ClientCharacteristicConfigurationBits.INDICATION
                subscribers = self.indication_subscribers
        elif characteristic.properties & Characteristic.Properties.NOTIFY:
            bits = ClientCharacteristicConfigurationBits.NOTIFICATION
            subscribers = self.notification_subscribers
        elif characteristic.properties & Characteristic.Properties.INDICATE:
            bits = ClientCharacteristicConfigurationBits.INDICATION
            subscribers = self.indication_subscribers
        else:
            raise InvalidStateError("characteristic is not notify or indicate")

        # Add subscribers to the sets
        subscriber_set = subscribers.setdefault(characteristic.handle, set())
        if subscriber is not None:
            subscriber_set.add(subscriber)

        # Add the characteristic as a subscriber, which will result in the
        # characteristic emitting an 'update' event when a notification or indication
        # is received
        subscriber_set.add(characteristic)

        await self.write_value(cccd, struct.pack('<H', bits), with_response=True)

    async def unsubscribe(
        self,
        characteristic: CharacteristicProxy,
        subscriber: Callable[[Any], Any] | None = None,
        force: bool = False,
    ) -> None:
        '''
        Unsubscribe from a characteristic.

        If `force` is True, this will write zeros to the CCCD when there are no
        subscribers left, even if there were already no registered subscribers.
        '''
        # If we haven't already discovered the descriptors for this characteristic,
        # do it now
        if not characteristic.descriptors_discovered:
            await self.discover_descriptors(characteristic)

        # Look for the CCCD descriptor
        cccd = characteristic.get_descriptor(
            GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
        )
        if not cccd:
            logger.warning('unsubscribing from characteristic with no CCCD descriptor')
            return

        # Check if the characteristic has subscribers
        if not (
            characteristic.handle in self.notification_subscribers
            or characteristic.handle in self.indication_subscribers
        ):
            if not force:
                return

        # Remove the subscriber(s)
        if subscriber is not None:
            # Remove matching subscriber from subscriber sets
            for subscriber_set in (
                self.notification_subscribers,
                self.indication_subscribers,
            ):
                if (
                    subscribers := subscriber_set.get(characteristic.handle)
                ) and subscriber in subscribers:
                    subscribers.remove(subscriber)

                    # The characteristic itself is added as subscriber. If it is the
                    # last remaining subscriber, we remove it, such that the clean up
                    # works correctly. Otherwise the CCCD never is set back to 0.
                    if len(subscribers) == 1 and characteristic in subscribers:
                        subscribers.remove(characteristic)

                    # Cleanup if we removed the last one
                    if not subscribers:
                        del subscriber_set[characteristic.handle]
        else:
            # Remove all subscribers for this attribute from the sets
            self.notification_subscribers.pop(characteristic.handle, None)
            self.indication_subscribers.pop(characteristic.handle, None)

        # Update the CCCD
        if not (
            characteristic.handle in self.notification_subscribers
            or characteristic.handle in self.indication_subscribers
        ):
            # No more subscribers left
            await self.write_value(cccd, b'\x00\x00', with_response=True)

    async def read_value(
        self, attribute: int | AttributeProxy, no_long_read: bool = False
    ) -> bytes:
        '''
        See Vol 3, Part G - 4.8.1 Read Characteristic Value

        `attribute` can be an Attribute object, or a handle value
        '''

        # Send a request to read
        attribute_handle = attribute if isinstance(attribute, int) else attribute.handle
        response = await self.send_request(
            att.ATT_Read_Request(attribute_handle=attribute_handle)
        )
        if response is None:
            raise TimeoutError('read timeout')
        if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
            raise att.ATT_Error(error_code=response.error_code, message=response)

        # If the value is the max size for the MTU, try to read more unless the caller
        # specifically asked not to do that
        attribute_value = response.attribute_value
        if not no_long_read and len(attribute_value) == self.mtu - 1:
            logger.debug('using READ BLOB to get the rest of the value')
            offset = len(attribute_value)
            while True:
                response = await self.send_request(
                    att.ATT_Read_Blob_Request(
                        attribute_handle=attribute_handle, value_offset=offset
                    )
                )
                if response is None:
                    raise TimeoutError('read timeout')
                if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                    if response.error_code in (
                        att.ATT_ATTRIBUTE_NOT_LONG_ERROR,
                        att.ATT_INVALID_OFFSET_ERROR,
                    ):
                        break
                    raise att.ATT_Error(
                        error_code=response.error_code, message=response
                    )

                part = response.part_attribute_value
                attribute_value += part

                if len(part) < self.mtu - 1:
                    break

                offset += len(part)

        self.cache_value(attribute_handle, attribute_value)
        # Return the value as bytes
        return attribute_value

    async def read_characteristics_by_uuid(
        self, uuid: UUID, service: ServiceProxy | None
    ) -> list[bytes]:
        '''
        See Vol 3, Part G - 4.8.2 Read Using Characteristic UUID
        '''

        if service is None:
            starting_handle = 0x0001
            ending_handle = 0xFFFF
        else:
            starting_handle = service.handle
            ending_handle = service.end_group_handle

        characteristics_values = []
        while starting_handle <= ending_handle:
            response = await self.send_request(
                att.ATT_Read_By_Type_Request(
                    starting_handle=starting_handle,
                    ending_handle=ending_handle,
                    attribute_type=uuid,
                )
            )
            if response is None:
                # TODO raise appropriate exception
                return []

            # Check if we reached the end of the iteration
            if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                if response.error_code != att.ATT_ATTRIBUTE_NOT_FOUND_ERROR:
                    # Unexpected end
                    logger.warning(
                        '!!! unexpected error while reading characteristics: '
                        f'{HCI_Constant.error_name(response.error_code)}'
                    )
                    # TODO raise appropriate exception
                    return []
                break

            # Stop if for some reason the list was empty
            if not response.attributes:
                break

            # Process all characteristics returned in this iteration
            for attribute_handle, attribute_value in response.attributes:
                if attribute_handle < starting_handle:
                    # Something's not right
                    logger.warning(f'bogus handle value: {attribute_handle}')
                    return []

                characteristics_values.append(attribute_value)

            # Move on to the next characteristics
            starting_handle = response.attributes[-1][0] + 1

        return characteristics_values

    async def write_value(
        self,
        attribute: int | AttributeProxy,
        value: bytes,
        with_response: bool = False,
    ) -> None:
        '''
        See Vol 3, Part G - 4.9.1 Write Without Response & 4.9.3 Write Characteristic
        Value

        `attribute` can be an Attribute object, or a handle value
        '''

        # Send a request or command to write
        attribute_handle = attribute if isinstance(attribute, int) else attribute.handle
        if with_response:
            response = await self.send_request(
                att.ATT_Write_Request(
                    attribute_handle=attribute_handle, attribute_value=value
                )
            )
            if response.op_code == att.Opcode.ATT_ERROR_RESPONSE:
                raise att.ATT_Error(error_code=response.error_code, message=response)
        else:
            await self.send_command(
                att.ATT_Write_Command(
                    attribute_handle=attribute_handle, attribute_value=value
                )
            )

    def on_disconnection(self, *args) -> None:
        del args  # unused.
        if self.pending_response and not self.pending_response.done():
            self.pending_response.cancel()

    def on_gatt_pdu(self, att_pdu: att.ATT_PDU) -> None:
        logger.debug(f'GATT Response to client: {self._bearer_id} {att_pdu}')
        if att_pdu.op_code in att.ATT_RESPONSES:
            if self.pending_request is None:
                # Not expected!
                logger.warning('!!! unexpected response, there is no pending request')
                return

            # The response should match the pending request unless it is
            # an error response
            if att_pdu.op_code != att.Opcode.ATT_ERROR_RESPONSE:
                expected_response_name = self.pending_request.name.replace(
                    '_REQUEST', '_RESPONSE'
                )
                if att_pdu.name != expected_response_name:
                    logger.warning(
                        f'!!! mismatched response: expected {expected_response_name}'
                    )
                    return

            # Return the response to the coroutine that is waiting for it
            assert self.pending_response is not None
            self.pending_response.set_result(att_pdu)
        else:
            handler_name = f'on_{att_pdu.name.lower()}'
            handler = getattr(self, handler_name, None)
            if handler is not None:
                handler(att_pdu)
            else:
                logger.warning(
                    color(
                        '--- Ignoring GATT Response from ' f'{self._bearer_id}: ',
                        'red',
                    )
                    + str(att_pdu)
                )

    def on_att_handle_value_notification(
        self, notification: att.ATT_Handle_Value_Notification
    ):
        # Call all subscribers
        subscribers = self.notification_subscribers.get(
            notification.attribute_handle, set()
        )
        if not subscribers:
            logger.warning('!!! received notification with no subscriber')

        self.cache_value(notification.attribute_handle, notification.attribute_value)
        for subscriber in subscribers:
            if callable(subscriber):
                subscriber(notification.attribute_value)
            else:
                subscriber.emit(subscriber.EVENT_UPDATE, notification.attribute_value)

    def on_att_handle_value_indication(
        self, indication: att.ATT_Handle_Value_Indication
    ):
        # Call all subscribers
        subscribers = self.indication_subscribers.get(
            indication.attribute_handle, set()
        )
        if not subscribers:
            logger.warning('!!! received indication with no subscriber')

        self.cache_value(indication.attribute_handle, indication.attribute_value)
        for subscriber in subscribers:
            if callable(subscriber):
                subscriber(indication.attribute_value)
            else:
                subscriber.emit(subscriber.EVENT_UPDATE, indication.attribute_value)

        # Confirm that we received the indication
        self.send_confirmation(att.ATT_Handle_Value_Confirmation())

    def cache_value(self, attribute_handle: int, value: bytes) -> None:
        self.cached_values[attribute_handle] = (
            datetime.now(),
            value,
        )
