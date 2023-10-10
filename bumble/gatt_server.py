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
# Server
#
# See Bluetooth spec @ Vol 3, Part G
#
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from __future__ import annotations
import asyncio
import logging
from collections import defaultdict
import struct
from typing import List, Tuple, Optional, TypeVar, Type, Dict, Iterable, TYPE_CHECKING
from pyee import EventEmitter

from .colors import color
from .core import UUID
from .att import (
    ATT_ATTRIBUTE_NOT_FOUND_ERROR,
    ATT_ATTRIBUTE_NOT_LONG_ERROR,
    ATT_CID,
    ATT_DEFAULT_MTU,
    ATT_INVALID_ATTRIBUTE_LENGTH_ERROR,
    ATT_INVALID_HANDLE_ERROR,
    ATT_INVALID_OFFSET_ERROR,
    ATT_REQUEST_NOT_SUPPORTED_ERROR,
    ATT_REQUESTS,
    ATT_PDU,
    ATT_UNLIKELY_ERROR_ERROR,
    ATT_UNSUPPORTED_GROUP_TYPE_ERROR,
    ATT_Error,
    ATT_Error_Response,
    ATT_Exchange_MTU_Response,
    ATT_Find_By_Type_Value_Response,
    ATT_Find_Information_Response,
    ATT_Handle_Value_Indication,
    ATT_Handle_Value_Notification,
    ATT_Read_Blob_Response,
    ATT_Read_By_Group_Type_Response,
    ATT_Read_By_Type_Response,
    ATT_Read_Response,
    ATT_Write_Response,
    Attribute,
)
from .gatt import (
    GATT_CHARACTERISTIC_ATTRIBUTE_TYPE,
    GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
    GATT_MAX_ATTRIBUTE_VALUE_SIZE,
    GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE,
    GATT_REQUEST_TIMEOUT,
    GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE,
    Characteristic,
    CharacteristicDeclaration,
    CharacteristicValue,
    IncludedServiceDeclaration,
    Descriptor,
    Service,
)

if TYPE_CHECKING:
    from bumble.device import Device, Connection

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
GATT_SERVER_DEFAULT_MAX_MTU = 517


# -----------------------------------------------------------------------------
# GATT Server
# -----------------------------------------------------------------------------
class Server(EventEmitter):
    attributes: List[Attribute]
    services: List[Service]
    attributes_by_handle: Dict[int, Attribute]
    subscribers: Dict[int, Dict[int, bytes]]
    indication_semaphores: defaultdict[int, asyncio.Semaphore]
    pending_confirmations: defaultdict[int, Optional[asyncio.futures.Future]]

    def __init__(self, device: Device) -> None:
        super().__init__()
        self.device = device
        self.services = []
        self.attributes = []  # Attributes, ordered by increasing handle values
        self.attributes_by_handle = {}  # Map for fast attribute access by handle
        self.max_mtu = (
            GATT_SERVER_DEFAULT_MAX_MTU  # The max MTU we're willing to negotiate
        )
        self.subscribers = (
            {}
        )  # Map of subscriber states by connection handle and attribute handle
        self.indication_semaphores = defaultdict(lambda: asyncio.Semaphore(1))
        self.pending_confirmations = defaultdict(lambda: None)

    def __str__(self) -> str:
        return "\n".join(map(str, self.attributes))

    def send_gatt_pdu(self, connection_handle: int, pdu: bytes) -> None:
        self.device.send_l2cap_pdu(connection_handle, ATT_CID, pdu)

    def next_handle(self) -> int:
        return 1 + len(self.attributes)

    def get_advertising_service_data(self) -> Dict[Attribute, bytes]:
        return {
            attribute: data
            for attribute in self.attributes
            if isinstance(attribute, Service)
            and (data := attribute.get_advertising_data())
        }

    def get_attribute(self, handle: int) -> Optional[Attribute]:
        attribute = self.attributes_by_handle.get(handle)
        if attribute:
            return attribute

        # Not in the cached map, perform a linear lookup
        for attribute in self.attributes:
            if attribute.handle == handle:
                # Store in cached map
                self.attributes_by_handle[handle] = attribute
                return attribute
        return None

    AttributeGroupType = TypeVar('AttributeGroupType', Service, Characteristic)

    def get_attribute_group(
        self, handle: int, group_type: Type[AttributeGroupType]
    ) -> Optional[AttributeGroupType]:
        return next(
            (
                attribute
                for attribute in self.attributes
                if isinstance(attribute, group_type)
                and attribute.handle <= handle <= attribute.end_group_handle
            ),
            None,
        )

    def get_service_attribute(self, service_uuid: UUID) -> Optional[Service]:
        return next(
            (
                attribute
                for attribute in self.attributes
                if attribute.type == GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE
                and isinstance(attribute, Service)
                and attribute.uuid == service_uuid
            ),
            None,
        )

    def get_characteristic_attributes(
        self, service_uuid: UUID, characteristic_uuid: UUID
    ) -> Optional[Tuple[CharacteristicDeclaration, Characteristic]]:
        service_handle = self.get_service_attribute(service_uuid)
        if not service_handle:
            return None

        return next(
            (
                (
                    attribute,
                    self.get_attribute(attribute.characteristic.handle),
                )  # type: ignore
                for attribute in map(
                    self.get_attribute,
                    range(service_handle.handle, service_handle.end_group_handle + 1),
                )
                if attribute is not None
                and attribute.type == GATT_CHARACTERISTIC_ATTRIBUTE_TYPE
                and isinstance(attribute, CharacteristicDeclaration)
                and attribute.characteristic.uuid == characteristic_uuid
            ),
            None,
        )

    def get_descriptor_attribute(
        self, service_uuid: UUID, characteristic_uuid: UUID, descriptor_uuid: UUID
    ) -> Optional[Descriptor]:
        characteristics = self.get_characteristic_attributes(
            service_uuid, characteristic_uuid
        )
        if not characteristics:
            return None

        (_, characteristic_value) = characteristics

        return next(
            (
                attribute  # type: ignore
                for attribute in map(
                    self.get_attribute,
                    range(
                        characteristic_value.handle + 1,
                        characteristic_value.end_group_handle + 1,
                    ),
                )
                if attribute is not None and attribute.type == descriptor_uuid
            ),
            None,
        )

    def add_attribute(self, attribute: Attribute) -> None:
        # Assign a handle to this attribute
        attribute.handle = self.next_handle()
        attribute.end_group_handle = (
            attribute.handle
        )  # TODO: keep track of descriptors in the group

        # Add this attribute to the list
        self.attributes.append(attribute)

    def add_service(self, service: Service) -> None:
        # Add the service attribute to the DB
        self.add_attribute(service)

        # Add all included service
        for included_service in service.included_services:
            # Not registered yet, register the included service first.
            if included_service not in self.services:
                self.add_service(included_service)
                # TODO: Handle circular service reference
            include_declaration = IncludedServiceDeclaration(included_service)
            self.add_attribute(include_declaration)

        # Add all characteristics
        for characteristic in service.characteristics:
            # Add a Characteristic Declaration
            characteristic_declaration = CharacteristicDeclaration(
                characteristic, self.next_handle() + 1
            )
            self.add_attribute(characteristic_declaration)

            # Add the characteristic value
            self.add_attribute(characteristic)

            # Add the descriptors
            for descriptor in characteristic.descriptors:
                self.add_attribute(descriptor)

            # If the characteristic supports subscriptions, add a CCCD descriptor
            # unless there is one already
            if (
                characteristic.properties
                & (
                    Characteristic.Properties.NOTIFY
                    | Characteristic.Properties.INDICATE
                )
                and characteristic.get_descriptor(
                    GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR
                )
                is None
            ):
                self.add_attribute(
                    # pylint: disable=line-too-long
                    Descriptor(
                        GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
                        Attribute.READABLE | Attribute.WRITEABLE,
                        CharacteristicValue(
                            read=lambda connection, characteristic=characteristic: self.read_cccd(
                                connection, characteristic
                            ),
                            write=lambda connection, value, characteristic=characteristic: self.write_cccd(
                                connection, characteristic, value
                            ),
                        ),
                    )
                )

            # Update the service and characteristic group ends
            characteristic_declaration.end_group_handle = self.attributes[-1].handle
            characteristic.end_group_handle = self.attributes[-1].handle

        # Update the service group end
        service.end_group_handle = self.attributes[-1].handle
        self.services.append(service)

    def add_services(self, services: Iterable[Service]) -> None:
        for service in services:
            self.add_service(service)

    def read_cccd(
        self, connection: Optional[Connection], characteristic: Characteristic
    ) -> bytes:
        if connection is None:
            return bytes([0, 0])

        subscribers = self.subscribers.get(connection.handle)
        cccd = None
        if subscribers:
            cccd = subscribers.get(characteristic.handle)

        return cccd or bytes([0, 0])

    def write_cccd(
        self,
        connection: Connection,
        characteristic: Characteristic,
        value: bytes,
    ) -> None:
        logger.debug(
            f'Subscription update for connection=0x{connection.handle:04X}, '
            f'handle=0x{characteristic.handle:04X}: {value.hex()}'
        )

        # Sanity check
        if len(value) != 2:
            logger.warning('CCCD value not 2 bytes long')
            return

        cccds = self.subscribers.setdefault(connection.handle, {})
        cccds[characteristic.handle] = value
        logger.debug(f'CCCDs: {cccds}')
        notify_enabled = value[0] & 0x01 != 0
        indicate_enabled = value[0] & 0x02 != 0
        characteristic.emit(
            'subscription', connection, notify_enabled, indicate_enabled
        )
        self.emit(
            'characteristic_subscription',
            connection,
            characteristic,
            notify_enabled,
            indicate_enabled,
        )

    def send_response(self, connection: Connection, response: ATT_PDU) -> None:
        logger.debug(
            f'GATT Response from server: [0x{connection.handle:04X}] {response}'
        )
        self.send_gatt_pdu(connection.handle, response.to_bytes())

    async def notify_subscriber(
        self,
        connection: Connection,
        attribute: Attribute,
        value: Optional[bytes] = None,
        force: bool = False,
    ) -> None:
        # Check if there's a subscriber
        if not force:
            subscribers = self.subscribers.get(connection.handle)
            if not subscribers:
                logger.debug('not notifying, no subscribers')
                return
            cccd = subscribers.get(attribute.handle)
            if not cccd:
                logger.debug(
                    f'not notifying, no subscribers for handle {attribute.handle:04X}'
                )
                return
            if len(cccd) != 2 or (cccd[0] & 0x01 == 0):
                logger.debug(f'not notifying, cccd={cccd.hex()}')
                return

        # Get or encode the value
        value = (
            attribute.read_value(connection)
            if value is None
            else attribute.encode_value(value)
        )

        # Truncate if needed
        if len(value) > connection.att_mtu - 3:
            value = value[: connection.att_mtu - 3]

        # Notify
        notification = ATT_Handle_Value_Notification(
            attribute_handle=attribute.handle, attribute_value=value
        )
        logger.debug(
            f'GATT Notify from server: [0x{connection.handle:04X}] {notification}'
        )
        self.send_gatt_pdu(connection.handle, bytes(notification))

    async def indicate_subscriber(
        self,
        connection: Connection,
        attribute: Attribute,
        value: Optional[bytes] = None,
        force: bool = False,
    ) -> None:
        # Check if there's a subscriber
        if not force:
            subscribers = self.subscribers.get(connection.handle)
            if not subscribers:
                logger.debug('not indicating, no subscribers')
                return
            cccd = subscribers.get(attribute.handle)
            if not cccd:
                logger.debug(
                    f'not indicating, no subscribers for handle {attribute.handle:04X}'
                )
                return
            if len(cccd) != 2 or (cccd[0] & 0x02 == 0):
                logger.debug(f'not indicating, cccd={cccd.hex()}')
                return

        # Get or encode the value
        value = (
            attribute.read_value(connection)
            if value is None
            else attribute.encode_value(value)
        )

        # Truncate if needed
        if len(value) > connection.att_mtu - 3:
            value = value[: connection.att_mtu - 3]

        # Indicate
        indication = ATT_Handle_Value_Indication(
            attribute_handle=attribute.handle, attribute_value=value
        )
        logger.debug(
            f'GATT Indicate from server: [0x{connection.handle:04X}] {indication}'
        )

        # Wait until we can send (only one pending indication at a time per connection)
        async with self.indication_semaphores[connection.handle]:
            assert self.pending_confirmations[connection.handle] is None

            # Create a future value to hold the eventual response
            pending_confirmation = self.pending_confirmations[
                connection.handle
            ] = asyncio.get_running_loop().create_future()

            try:
                self.send_gatt_pdu(connection.handle, indication.to_bytes())
                await asyncio.wait_for(pending_confirmation, GATT_REQUEST_TIMEOUT)
            except asyncio.TimeoutError as error:
                logger.warning(color('!!! GATT Indicate timeout', 'red'))
                raise TimeoutError(f'GATT timeout for {indication.name}') from error
            finally:
                self.pending_confirmations[connection.handle] = None

    async def notify_or_indicate_subscribers(
        self,
        indicate: bool,
        attribute: Attribute,
        value: Optional[bytes] = None,
        force: bool = False,
    ) -> None:
        # Get all the connections for which there's at least one subscription
        connections = [
            connection
            for connection in [
                self.device.lookup_connection(connection_handle)
                for (connection_handle, subscribers) in self.subscribers.items()
                if force or subscribers.get(attribute.handle)
            ]
            if connection is not None
        ]

        # Indicate or notify for each connection
        if connections:
            coroutine = self.indicate_subscriber if indicate else self.notify_subscriber
            await asyncio.wait(
                [
                    asyncio.create_task(coroutine(connection, attribute, value, force))
                    for connection in connections
                ]
            )

    async def notify_subscribers(
        self,
        attribute: Attribute,
        value: Optional[bytes] = None,
        force: bool = False,
    ):
        return await self.notify_or_indicate_subscribers(False, attribute, value, force)

    async def indicate_subscribers(
        self,
        attribute: Attribute,
        value: Optional[bytes] = None,
        force: bool = False,
    ):
        return await self.notify_or_indicate_subscribers(True, attribute, value, force)

    def on_disconnection(self, connection: Connection) -> None:
        if connection.handle in self.subscribers:
            del self.subscribers[connection.handle]
        if connection.handle in self.indication_semaphores:
            del self.indication_semaphores[connection.handle]
        if connection.handle in self.pending_confirmations:
            del self.pending_confirmations[connection.handle]

    def on_gatt_pdu(self, connection: Connection, att_pdu: ATT_PDU) -> None:
        logger.debug(f'GATT Request to server: [0x{connection.handle:04X}] {att_pdu}')
        handler_name = f'on_{att_pdu.name.lower()}'
        handler = getattr(self, handler_name, None)
        if handler is not None:
            try:
                handler(connection, att_pdu)
            except ATT_Error as error:
                logger.debug(f'normal exception returned by handler: {error}')
                response = ATT_Error_Response(
                    request_opcode_in_error=att_pdu.op_code,
                    attribute_handle_in_error=error.att_handle,
                    error_code=error.error_code,
                )
                self.send_response(connection, response)
            except Exception as error:
                logger.warning(f'{color("!!! Exception in handler:", "red")} {error}')
                response = ATT_Error_Response(
                    request_opcode_in_error=att_pdu.op_code,
                    attribute_handle_in_error=0x0000,
                    error_code=ATT_UNLIKELY_ERROR_ERROR,
                )
                self.send_response(connection, response)
                raise error
        else:
            # No specific handler registered
            if att_pdu.op_code in ATT_REQUESTS:
                # Invoke the generic handler
                self.on_att_request(connection, att_pdu)
            else:
                # Just ignore
                logger.warning(
                    color(
                        f'--- Ignoring GATT Request from [0x{connection.handle:04X}]: ',
                        'red',
                    )
                    + str(att_pdu)
                )

    #######################################################
    # ATT handlers
    #######################################################
    def on_att_request(self, connection: Connection, pdu: ATT_PDU) -> None:
        '''
        Handler for requests without a more specific handler
        '''
        logger.warning(
            color(
                f'--- Unsupported ATT Request from [0x{connection.handle:04X}]: ', 'red'
            )
            + str(pdu)
        )
        response = ATT_Error_Response(
            request_opcode_in_error=pdu.op_code,
            attribute_handle_in_error=0x0000,
            error_code=ATT_REQUEST_NOT_SUPPORTED_ERROR,
        )
        self.send_response(connection, response)

    def on_att_exchange_mtu_request(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.2.1 Exchange MTU Request
        '''
        self.send_response(
            connection, ATT_Exchange_MTU_Response(server_rx_mtu=self.max_mtu)
        )

        # Compute the final MTU
        if request.client_rx_mtu >= ATT_DEFAULT_MTU:
            mtu = min(self.max_mtu, request.client_rx_mtu)

            # Notify the device
            self.device.on_connection_att_mtu_update(connection.handle, mtu)
        else:
            logger.warning('invalid client_rx_mtu received, MTU not changed')

    def on_att_find_information_request(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.3.1 Find Information Request
        '''

        # Check the request parameters
        if (
            request.starting_handle == 0
            or request.starting_handle > request.ending_handle
        ):
            self.send_response(
                connection,
                ATT_Error_Response(
                    request_opcode_in_error=request.op_code,
                    attribute_handle_in_error=request.starting_handle,
                    error_code=ATT_INVALID_HANDLE_ERROR,
                ),
            )
            return

        # Build list of returned attributes
        pdu_space_available = connection.att_mtu - 2
        attributes = []
        uuid_size = 0
        for attribute in (
            attribute
            for attribute in self.attributes
            if attribute.handle >= request.starting_handle
            and attribute.handle <= request.ending_handle
        ):
            this_uuid_size = len(attribute.type.to_pdu_bytes())

            if attributes:
                # Check if this attribute has the same type size as the previous one
                if this_uuid_size != uuid_size:
                    break

            # Check if there's enough space for one more entry
            uuid_size = this_uuid_size
            if pdu_space_available < 2 + uuid_size:
                break

            # Add the attribute to the list
            attributes.append(attribute)
            pdu_space_available -= 2 + uuid_size

        # Return the list of attributes
        if attributes:
            information_data_list = [
                struct.pack('<H', attribute.handle) + attribute.type.to_pdu_bytes()
                for attribute in attributes
            ]
            response = ATT_Find_Information_Response(
                format=1 if len(attributes[0].type.to_pdu_bytes()) == 2 else 2,
                information_data=b''.join(information_data_list),
            )
        else:
            response = ATT_Error_Response(
                request_opcode_in_error=request.op_code,
                attribute_handle_in_error=request.starting_handle,
                error_code=ATT_ATTRIBUTE_NOT_FOUND_ERROR,
            )

        self.send_response(connection, response)

    def on_att_find_by_type_value_request(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.3.3 Find By Type Value Request
        '''

        # Build list of returned attributes
        pdu_space_available = connection.att_mtu - 2
        attributes = []
        for attribute in (
            attribute
            for attribute in self.attributes
            if attribute.handle >= request.starting_handle
            and attribute.handle <= request.ending_handle
            and attribute.type == request.attribute_type
            and attribute.read_value(connection) == request.attribute_value
            and pdu_space_available >= 4
        ):
            # TODO: check permissions

            # Add the attribute to the list
            attributes.append(attribute)
            pdu_space_available -= 4

        # Return the list of attributes
        if attributes:
            handles_information_list = []
            for attribute in attributes:
                if attribute.type in (
                    GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE,
                    GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE,
                    GATT_CHARACTERISTIC_ATTRIBUTE_TYPE,
                ):
                    # Part of a group
                    group_end_handle = attribute.end_group_handle
                else:
                    # Not part of a group
                    group_end_handle = attribute.handle
                handles_information_list.append(
                    struct.pack('<HH', attribute.handle, group_end_handle)
                )
            response = ATT_Find_By_Type_Value_Response(
                handles_information_list=b''.join(handles_information_list)
            )
        else:
            response = ATT_Error_Response(
                request_opcode_in_error=request.op_code,
                attribute_handle_in_error=request.starting_handle,
                error_code=ATT_ATTRIBUTE_NOT_FOUND_ERROR,
            )

        self.send_response(connection, response)

    def on_att_read_by_type_request(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.4.1 Read By Type Request
        '''

        pdu_space_available = connection.att_mtu - 2

        response = ATT_Error_Response(
            request_opcode_in_error=request.op_code,
            attribute_handle_in_error=request.starting_handle,
            error_code=ATT_ATTRIBUTE_NOT_FOUND_ERROR,
        )

        attributes = []
        for attribute in (
            attribute
            for attribute in self.attributes
            if attribute.type == request.attribute_type
            and attribute.handle >= request.starting_handle
            and attribute.handle <= request.ending_handle
            and pdu_space_available
        ):
            try:
                attribute_value = attribute.read_value(connection)
            except ATT_Error as error:
                # If the first attribute is unreadable, return an error
                # Otherwise return attributes up to this point
                if not attributes:
                    response = ATT_Error_Response(
                        request_opcode_in_error=request.op_code,
                        attribute_handle_in_error=attribute.handle,
                        error_code=error.error_code,
                    )
                break

            # Check the attribute value size
            max_attribute_size = min(connection.att_mtu - 4, 253)
            if len(attribute_value) > max_attribute_size:
                # We need to truncate
                attribute_value = attribute_value[:max_attribute_size]
            if attributes and len(attributes[0][1]) != len(attribute_value):
                # Not the same size as previous attribute, stop here
                break

            # Check if there is enough space
            entry_size = 2 + len(attribute_value)
            if pdu_space_available < entry_size:
                break

            # Add the attribute to the list
            attributes.append((attribute.handle, attribute_value))
            pdu_space_available -= entry_size

        if attributes:
            attribute_data_list = [
                struct.pack('<H', handle) + value for handle, value in attributes
            ]
            response = ATT_Read_By_Type_Response(
                length=entry_size, attribute_data_list=b''.join(attribute_data_list)
            )
        else:
            logging.debug(f"not found {request}")

        self.send_response(connection, response)

    def on_att_read_request(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.4.3 Read Request
        '''

        if attribute := self.get_attribute(request.attribute_handle):
            try:
                value = attribute.read_value(connection)
            except ATT_Error as error:
                response = ATT_Error_Response(
                    request_opcode_in_error=request.op_code,
                    attribute_handle_in_error=request.attribute_handle,
                    error_code=error.error_code,
                )
            else:
                value_size = min(connection.att_mtu - 1, len(value))
                response = ATT_Read_Response(attribute_value=value[:value_size])
        else:
            response = ATT_Error_Response(
                request_opcode_in_error=request.op_code,
                attribute_handle_in_error=request.attribute_handle,
                error_code=ATT_INVALID_HANDLE_ERROR,
            )
        self.send_response(connection, response)

    def on_att_read_blob_request(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.4.5 Read Blob Request
        '''

        if attribute := self.get_attribute(request.attribute_handle):
            try:
                value = attribute.read_value(connection)
            except ATT_Error as error:
                response = ATT_Error_Response(
                    request_opcode_in_error=request.op_code,
                    attribute_handle_in_error=request.attribute_handle,
                    error_code=error.error_code,
                )
            else:
                if request.value_offset > len(value):
                    response = ATT_Error_Response(
                        request_opcode_in_error=request.op_code,
                        attribute_handle_in_error=request.attribute_handle,
                        error_code=ATT_INVALID_OFFSET_ERROR,
                    )
                elif len(value) <= connection.att_mtu - 1:
                    response = ATT_Error_Response(
                        request_opcode_in_error=request.op_code,
                        attribute_handle_in_error=request.attribute_handle,
                        error_code=ATT_ATTRIBUTE_NOT_LONG_ERROR,
                    )
                else:
                    part_size = min(
                        connection.att_mtu - 1, len(value) - request.value_offset
                    )
                    response = ATT_Read_Blob_Response(
                        part_attribute_value=value[
                            request.value_offset : request.value_offset + part_size
                        ]
                    )
        else:
            response = ATT_Error_Response(
                request_opcode_in_error=request.op_code,
                attribute_handle_in_error=request.attribute_handle,
                error_code=ATT_INVALID_HANDLE_ERROR,
            )
        self.send_response(connection, response)

    def on_att_read_by_group_type_request(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.4.9 Read by Group Type Request
        '''
        if request.attribute_group_type not in (
            GATT_PRIMARY_SERVICE_ATTRIBUTE_TYPE,
            GATT_SECONDARY_SERVICE_ATTRIBUTE_TYPE,
        ):
            response = ATT_Error_Response(
                request_opcode_in_error=request.op_code,
                attribute_handle_in_error=request.starting_handle,
                error_code=ATT_UNSUPPORTED_GROUP_TYPE_ERROR,
            )
            self.send_response(connection, response)
            return

        pdu_space_available = connection.att_mtu - 2
        attributes = []
        for attribute in (
            attribute
            for attribute in self.attributes
            if attribute.type == request.attribute_group_type
            and attribute.handle >= request.starting_handle
            and attribute.handle <= request.ending_handle
            and pdu_space_available
        ):
            # No need to catch permission errors here, since these attributes
            # must all be world-readable
            attribute_value = attribute.read_value(connection)
            # Check the attribute value size
            max_attribute_size = min(connection.att_mtu - 6, 251)
            if len(attribute_value) > max_attribute_size:
                # We need to truncate
                attribute_value = attribute_value[:max_attribute_size]
            if attributes and len(attributes[0][2]) != len(attribute_value):
                # Not the same size as previous attributes, stop here
                break

            # Check if there is enough space
            entry_size = 4 + len(attribute_value)
            if pdu_space_available < entry_size:
                break

            # Add the attribute to the list
            attributes.append(
                (attribute.handle, attribute.end_group_handle, attribute_value)
            )
            pdu_space_available -= entry_size

        if attributes:
            attribute_data_list = [
                struct.pack('<HH', handle, end_group_handle) + value
                for handle, end_group_handle, value in attributes
            ]
            response = ATT_Read_By_Group_Type_Response(
                length=len(attribute_data_list[0]),
                attribute_data_list=b''.join(attribute_data_list),
            )
        else:
            response = ATT_Error_Response(
                request_opcode_in_error=request.op_code,
                attribute_handle_in_error=request.starting_handle,
                error_code=ATT_ATTRIBUTE_NOT_FOUND_ERROR,
            )

        self.send_response(connection, response)

    def on_att_write_request(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.5.1 Write Request
        '''

        # Check  that the attribute exists
        attribute = self.get_attribute(request.attribute_handle)
        if attribute is None:
            self.send_response(
                connection,
                ATT_Error_Response(
                    request_opcode_in_error=request.op_code,
                    attribute_handle_in_error=request.attribute_handle,
                    error_code=ATT_INVALID_HANDLE_ERROR,
                ),
            )
            return

        # TODO: check permissions

        # Check the request parameters
        if len(request.attribute_value) > GATT_MAX_ATTRIBUTE_VALUE_SIZE:
            self.send_response(
                connection,
                ATT_Error_Response(
                    request_opcode_in_error=request.op_code,
                    attribute_handle_in_error=request.attribute_handle,
                    error_code=ATT_INVALID_ATTRIBUTE_LENGTH_ERROR,
                ),
            )
            return

        # Accept the value
        attribute.write_value(connection, request.attribute_value)

        # Done
        self.send_response(connection, ATT_Write_Response())

    def on_att_write_command(self, connection, request):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.5.3 Write Command
        '''

        # Check that the attribute exists
        attribute = self.get_attribute(request.attribute_handle)
        if attribute is None:
            return

        # TODO: check permissions

        # Check the request parameters
        if len(request.attribute_value) > GATT_MAX_ATTRIBUTE_VALUE_SIZE:
            return

        # Accept the value
        try:
            attribute.write_value(connection, request.attribute_value)
        except Exception as error:
            logger.warning(f'!!! ignoring exception: {error}')

    def on_att_handle_value_confirmation(self, connection, _confirmation):
        '''
        See Bluetooth spec Vol 3, Part F - 3.4.7.3 Handle Value Confirmation
        '''
        if self.pending_confirmations[connection.handle] is None:
            # Not expected!
            logger.warning(
                '!!! unexpected confirmation, there is no pending indication'
            )
            return

        self.pending_confirmations[connection.handle].set_result(None)
