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
from __future__ import annotations

import asyncio
import enum
import logging
import time
import warnings
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import (
    Any,
    ClassVar,
    SupportsBytes,
    TypeVar,
    cast,
)

from typing_extensions import override

from bumble import a2dp, device, hci, l2cap, sdp, utils
from bumble.colors import color
from bumble.core import (
    BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE,
    InvalidStateError,
    ProtocolError,
)
from bumble.rtp import MediaPacket

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

AVDTP_PSM = 0x0019

AVDTP_DEFAULT_RTX_SIG_TIMER = 5  # Seconds

# Signal Identifiers (AVDTP spec - 8.5 Signal Command Set)
class SignalIdentifier(hci.SpecableEnum):
    DISCOVER             = 0x01
    GET_CAPABILITIES     = 0x02
    SET_CONFIGURATION    = 0x03
    GET_CONFIGURATION    = 0x04
    RECONFIGURE          = 0x05
    OPEN                 = 0x06
    START                = 0x07
    CLOSE                = 0x08
    SUSPEND              = 0x09
    ABORT                = 0x0A
    SECURITY_CONTROL     = 0x0B
    GET_ALL_CAPABILITIES = 0x0C
    DELAYREPORT          = 0x0D

AVDTP_DISCOVER             = SignalIdentifier.DISCOVER
AVDTP_GET_CAPABILITIES     = SignalIdentifier.GET_CAPABILITIES
AVDTP_SET_CONFIGURATION    = SignalIdentifier.SET_CONFIGURATION
AVDTP_GET_CONFIGURATION    = SignalIdentifier.GET_CONFIGURATION
AVDTP_RECONFIGURE          = SignalIdentifier.RECONFIGURE
AVDTP_OPEN                 = SignalIdentifier.OPEN
AVDTP_START                = SignalIdentifier.START
AVDTP_CLOSE                = SignalIdentifier.CLOSE
AVDTP_SUSPEND              = SignalIdentifier.SUSPEND
AVDTP_ABORT                = SignalIdentifier.ABORT
AVDTP_SECURITY_CONTROL     = SignalIdentifier.SECURITY_CONTROL
AVDTP_GET_ALL_CAPABILITIES = SignalIdentifier.GET_ALL_CAPABILITIES
AVDTP_DELAYREPORT          = SignalIdentifier.DELAYREPORT

class ErrorCode(hci.SpecableEnum):
    '''Error codes (AVDTP spec - 8.20.6.2 ERROR_CODE tables)'''
    BAD_HEADER_FORMAT          = 0x01
    BAD_LENGTH                 = 0x11
    BAD_ACP_SEID               = 0x12
    SEP_IN_USE                 = 0x13
    SEP_NOT_IN_USE             = 0x14
    BAD_SERV_CATEGORY          = 0x17
    BAD_PAYLOAD_FORMAT         = 0x18
    NOT_SUPPORTED_COMMAND      = 0x19
    INVALID_CAPABILITIES       = 0x1A
    BAD_RECOVERY_TYPE          = 0x22
    BAD_MEDIA_TRANSPORT_FORMAT = 0x23
    BAD_RECOVERY_FORMAT        = 0x25
    BAD_ROHC_FORMAT            = 0x26
    BAD_CP_FORMAT              = 0x27
    BAD_MULTIPLEXING_FORMAT    = 0x28
    UNSUPPORTED_CONFIGURATION  = 0x29
    BAD_STATE                  = 0x31

AVDTP_BAD_HEADER_FORMAT_ERROR          = ErrorCode.BAD_HEADER_FORMAT
AVDTP_BAD_LENGTH_ERROR                 = ErrorCode.BAD_LENGTH
AVDTP_BAD_ACP_SEID_ERROR               = ErrorCode.BAD_ACP_SEID
AVDTP_SEP_IN_USE_ERROR                 = ErrorCode.SEP_IN_USE
AVDTP_SEP_NOT_IN_USE_ERROR             = ErrorCode.SEP_NOT_IN_USE
AVDTP_BAD_SERV_CATEGORY_ERROR          = ErrorCode.BAD_SERV_CATEGORY
AVDTP_BAD_PAYLOAD_FORMAT_ERROR         = ErrorCode.BAD_PAYLOAD_FORMAT
AVDTP_NOT_SUPPORTED_COMMAND_ERROR      = ErrorCode.NOT_SUPPORTED_COMMAND
AVDTP_INVALID_CAPABILITIES_ERROR       = ErrorCode.INVALID_CAPABILITIES
AVDTP_BAD_RECOVERY_TYPE_ERROR          = ErrorCode.BAD_RECOVERY_TYPE
AVDTP_BAD_MEDIA_TRANSPORT_FORMAT_ERROR = ErrorCode.BAD_MEDIA_TRANSPORT_FORMAT
AVDTP_BAD_RECOVERY_FORMAT_ERROR        = ErrorCode.BAD_RECOVERY_FORMAT
AVDTP_BAD_ROHC_FORMAT_ERROR            = ErrorCode.BAD_ROHC_FORMAT
AVDTP_BAD_CP_FORMAT_ERROR              = ErrorCode.BAD_CP_FORMAT
AVDTP_BAD_MULTIPLEXING_FORMAT_ERROR    = ErrorCode.BAD_MULTIPLEXING_FORMAT
AVDTP_UNSUPPORTED_CONFIGURATION_ERROR  = ErrorCode.UNSUPPORTED_CONFIGURATION
AVDTP_BAD_STATE_ERROR                  = ErrorCode.BAD_STATE

class MediaType(utils.OpenIntEnum):
    AUDIO      = 0x00
    VIDEO      = 0x01
    MULTIMEDIA = 0x02

AVDTP_AUDIO_MEDIA_TYPE      = MediaType.AUDIO
AVDTP_VIDEO_MEDIA_TYPE      = MediaType.VIDEO
AVDTP_MULTIMEDIA_MEDIA_TYPE = MediaType.MULTIMEDIA

class StreamEndPointType(utils.OpenIntEnum):
    '''TSEP (AVDTP spec - 8.20.3 Stream End-point Type, Source or Sink (TSEP)).'''
    SRC = 0x00
    SNK = 0x01

AVDTP_TSEP_SRC = StreamEndPointType.SRC
AVDTP_TSEP_SNK = StreamEndPointType.SNK

class ServiceCategory(hci.SpecableEnum):
    '''Service Categories (AVDTP spec - Table 8.47: Service Category information element field values).'''
    MEDIA_TRANSPORT    = 0x01
    REPORTING          = 0x02
    RECOVERY           = 0x03
    CONTENT_PROTECTION = 0x04
    HEADER_COMPRESSION = 0x05
    MULTIPLEXING       = 0x06
    MEDIA_CODEC        = 0x07
    DELAY_REPORTING    = 0x08

AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY    = ServiceCategory.MEDIA_TRANSPORT
AVDTP_REPORTING_SERVICE_CATEGORY          = ServiceCategory.REPORTING
AVDTP_RECOVERY_SERVICE_CATEGORY           = ServiceCategory.RECOVERY
AVDTP_CONTENT_PROTECTION_SERVICE_CATEGORY = ServiceCategory.CONTENT_PROTECTION
AVDTP_HEADER_COMPRESSION_SERVICE_CATEGORY = ServiceCategory.HEADER_COMPRESSION
AVDTP_MULTIPLEXING_SERVICE_CATEGORY       = ServiceCategory.MULTIPLEXING
AVDTP_MEDIA_CODEC_SERVICE_CATEGORY        = ServiceCategory.MEDIA_CODEC
AVDTP_DELAY_REPORTING_SERVICE_CATEGORY    = ServiceCategory.DELAY_REPORTING

class State(utils.OpenIntEnum):
    '''States (AVDTP spec - 9.1 State Definitions)'''
    IDLE       = 0x00
    CONFIGURED = 0x01
    OPEN       = 0x02
    STREAMING  = 0x03
    CLOSING    = 0x04
    ABORTING   = 0x05

# fmt: on
# pylint: enable=line-too-long
# pylint: disable=invalid-name


# -----------------------------------------------------------------------------
async def find_avdtp_service_with_sdp_client(
    sdp_client: sdp.Client,
) -> tuple[int, int] | None:
    '''
    Find an AVDTP service, using a connected SDP client, and return its version,
    or None if none is found
    '''

    # Search for services with an Audio Sink service class
    search_result = await sdp_client.search_attributes(
        [BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE],
        [sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID],
    )
    for attribute_list in search_result:
        profile_descriptor_list = sdp.ServiceAttribute.find_attribute_in_list(
            attribute_list, sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID
        )
        if profile_descriptor_list:
            for profile_descriptor in profile_descriptor_list.value:
                if (
                    profile_descriptor.type == sdp.DataElement.SEQUENCE
                    and len(profile_descriptor.value) >= 2
                ):
                    avdtp_version_major = profile_descriptor.value[1].value >> 8
                    avdtp_version_minor = profile_descriptor.value[1].value & 0xFF
                    return (avdtp_version_major, avdtp_version_minor)
    return None


# -----------------------------------------------------------------------------
async def find_avdtp_service_with_connection(
    connection: device.Connection,
) -> tuple[int, int] | None:
    '''
    Find an AVDTP service, for a connection, and return its version,
    or None if none is found
    '''

    sdp_client = sdp.Client(connection)
    await sdp_client.connect()
    service_version = await find_avdtp_service_with_sdp_client(sdp_client)
    await sdp_client.disconnect()

    return service_version


# -----------------------------------------------------------------------------
class RealtimeClock:
    def now(self) -> float:
        return time.time()

    async def sleep(self, duration: float) -> None:
        await asyncio.sleep(duration)


# -----------------------------------------------------------------------------
class MediaPacketPump:
    pump_task: asyncio.Task | None

    def __init__(
        self, packets: AsyncGenerator, clock: RealtimeClock = RealtimeClock()
    ) -> None:
        self.packets = packets
        self.clock = clock
        self.pump_task = None
        self.completed = asyncio.Event()

    async def start(self, rtp_channel: l2cap.ClassicChannel) -> None:
        async def pump_packets():
            start_time = 0
            start_timestamp = 0

            try:
                logger.debug('pump starting')
                async for packet in self.packets:
                    # Capture the timestamp of the first packet
                    if start_time == 0:
                        start_time = self.clock.now()
                        start_timestamp = packet.timestamp_seconds

                    # Wait until we can send
                    when = start_time + (packet.timestamp_seconds - start_timestamp)
                    now = self.clock.now()
                    if when > now:
                        delay = when - now
                        logger.debug(f'waiting for {delay}')
                        await self.clock.sleep(delay)

                    # Emit
                    rtp_channel.write(bytes(packet))
                    logger.debug(
                        f'{color(">>> sending RTP packet:", "green")} {packet}'
                    )
            except asyncio.exceptions.CancelledError:
                logger.debug('pump canceled')
            finally:
                self.completed.set()

        # Pump packets
        self.pump_task = asyncio.create_task(pump_packets())

    async def stop(self) -> None:
        # Stop the pump
        if self.pump_task:
            self.pump_task.cancel()
            await self.pump_task
            self.pump_task = None

    async def wait_for_completion(self) -> None:
        await self.completed.wait()


# -----------------------------------------------------------------------------
class MessageAssembler:
    message: bytes | None
    signal_identifier: SignalIdentifier

    def __init__(self, callback: Callable[[int, Message], Any]) -> None:
        self.callback = callback
        self.reset()

    def reset(self) -> None:
        self.transaction_label = 0
        self.message = None
        self.message_type = Message.MessageType.COMMAND
        self.signal_identifier = SignalIdentifier(0)
        self.number_of_signal_packets = 0
        self.packet_count = 0

    def on_pdu(self, pdu: bytes) -> None:
        self.packet_count += 1

        transaction_label = pdu[0] >> 4
        packet_type = Protocol.PacketType((pdu[0] >> 2) & 3)
        message_type = Message.MessageType(pdu[0] & 3)

        logger.debug(
            f'transaction_label={transaction_label}, '
            f'packet_type={packet_type.name}, '
            f'message_type={message_type.name}'
        )
        if packet_type in (
            Protocol.PacketType.SINGLE_PACKET,
            Protocol.PacketType.START_PACKET,
        ):
            if self.message is not None:
                # The previous message has not been terminated
                logger.warning(
                    'received a start or single packet when expecting an end or '
                    'continuation'
                )
                self.reset()

            self.transaction_label = transaction_label
            self.signal_identifier = SignalIdentifier(pdu[1] & 0x3F)
            self.message_type = message_type

            if packet_type == Protocol.PacketType.SINGLE_PACKET:
                self.message = pdu[2:]
                self.on_message_complete()
            else:
                self.number_of_signal_packets = pdu[2]
                self.message = pdu[3:]
        elif packet_type in (
            Protocol.PacketType.CONTINUE_PACKET,
            Protocol.PacketType.END_PACKET,
        ):
            if self.packet_count == 0:
                logger.warning('unexpected continuation')
                return

            if transaction_label != self.transaction_label:
                logger.warning(
                    f'transaction label mismatch: expected {self.transaction_label}, '
                    f'received {transaction_label}'
                )
                return

            if message_type != self.message_type:
                logger.warning(
                    f'message type mismatch: expected {self.message_type}, '
                    f'received {message_type}'
                )
                return

            self.message = (self.message or b'') + pdu[1:]

            if packet_type == Protocol.PacketType.END_PACKET:
                if self.packet_count != self.number_of_signal_packets:
                    logger.warning(
                        'incomplete fragmented message: '
                        f'expected {self.number_of_signal_packets} packets, '
                        f'received {self.packet_count}'
                    )
                    self.reset()
                    return

                self.on_message_complete()
            else:
                if self.packet_count > self.number_of_signal_packets:
                    logger.warning(
                        'too many packets: '
                        f'expected {self.number_of_signal_packets}, '
                        f'received {self.packet_count}'
                    )
                    self.reset()
                    return

    def on_message_complete(self) -> None:
        message = Message.create(
            self.signal_identifier,
            self.message_type,
            self.message or b'',
        )
        try:
            self.callback(self.transaction_label, message)
        except Exception:
            logger.exception(color('!!! exception in callback', 'red'))

        self.reset()


# -----------------------------------------------------------------------------
@dataclass
class ServiceCapabilities:
    METADATA = hci.metadata(
        {
            'parser': lambda data, offset: (
                len(data),
                ServiceCapabilities.parse_capabilities(data[offset:]),
            ),
            'serializer': lambda capabilities: ServiceCapabilities.serialize_capabilities(
                capabilities
            ),
        }
    )
    service_category: int
    service_capabilities_bytes: bytes = b''

    @classmethod
    def create(
        cls, service_category: int, service_capabilities_bytes: bytes
    ) -> ServiceCapabilities:
        # Select the appropriate subclass
        if service_category == AVDTP_MEDIA_CODEC_SERVICE_CATEGORY:
            return MediaCodecCapabilities.from_bytes(service_capabilities_bytes)
        return ServiceCapabilities(
            service_category=service_category,
            service_capabilities_bytes=service_capabilities_bytes,
        )

    @classmethod
    def parse_capabilities(cls, payload: bytes) -> list[ServiceCapabilities]:
        capabilities = []
        offset = 0
        while offset < len(payload):
            service_category = payload[offset]
            length_of_service_capabilities = payload[offset + 1]
            service_capabilities_bytes = payload[
                offset + 2 : offset + 2 + length_of_service_capabilities
            ]
            capabilities.append(
                ServiceCapabilities.create(service_category, service_capabilities_bytes)
            )
            offset += 2 + length_of_service_capabilities

        return capabilities

    @classmethod
    def serialize_capabilities(
        cls, capabilities: Iterable[ServiceCapabilities]
    ) -> bytes:
        return b''.join(
            bytes([item.service_category, len(item.service_capabilities_bytes)])
            + item.service_capabilities_bytes
            for item in capabilities
        )


# -----------------------------------------------------------------------------
@dataclass(init=False)
class MediaCodecCapabilities(ServiceCapabilities):
    service_category = AVDTP_MEDIA_CODEC_SERVICE_CATEGORY
    # Redeclare this attribute to suppress inheritance error.
    service_capabilities_bytes: bytes

    media_type: MediaType
    media_codec_type: a2dp.CodecType
    media_codec_information: bytes | SupportsBytes

    # Override init to allow passing service_capabilities_bytes.
    def __init__(
        self,
        media_type: MediaType,
        media_codec_type: a2dp.CodecType,
        media_codec_information: bytes | SupportsBytes,
        service_capabilities_bytes: bytes | None = None,
    ) -> None:
        self.media_type = media_type
        self.media_codec_type = media_codec_type

        if isinstance(media_codec_information, bytes):
            self.media_codec_information = a2dp.MediaCodecInformation.create(
                media_codec_type, media_codec_information
            )
        else:
            self.media_codec_information = media_codec_information

        if service_capabilities_bytes is not None:
            self.service_capabilities_bytes = service_capabilities_bytes
        else:
            self.service_capabilities_bytes = bytes(
                [self.media_type, self.media_codec_type]
            ) + bytes(self.media_codec_information)

    @classmethod
    def from_bytes(cls, data: bytes) -> ServiceCapabilities:
        media_type = MediaType(data[0])
        media_codec_type = a2dp.CodecType(data[1])
        return cls(
            media_type=media_type,
            media_codec_type=media_codec_type,
            media_codec_information=a2dp.MediaCodecInformation.create(
                media_codec_type, data[2:]
            ),
        )


# -----------------------------------------------------------------------------
@dataclass
class EndPointInfo:
    seid: int
    in_use: int
    media_type: MediaType
    tsep: StreamEndPointType

    @classmethod
    def from_bytes(cls, payload: bytes) -> EndPointInfo:
        return cls(
            seid=payload[0] >> 2,
            in_use=payload[0] >> 1 & 1,
            media_type=MediaType(payload[1] >> 4),
            tsep=StreamEndPointType(payload[1] >> 3 & 1),
        )

    def __bytes__(self) -> bytes:
        return bytes(
            [self.seid << 2 | self.in_use << 1, self.media_type << 4 | self.tsep << 3]
        )


# -----------------------------------------------------------------------------
class Message:
    class MessageType(enum.IntEnum):
        COMMAND = 0
        GENERAL_REJECT = 1
        RESPONSE_ACCEPT = 2
        RESPONSE_REJECT = 3

    SEID_METADATA = hci.metadata(
        {
            'serializer': lambda seid: bytes([seid << 2]),
            'parser': lambda data, offset: (offset + 1, data[offset] >> 2),
        }
    )

    # Subclasses, by signal identifier and message type
    subclasses: ClassVar[dict[int, dict[int, type[Message]]]] = {}

    message_type: MessageType
    signal_identifier: SignalIdentifier
    _payload: bytes | None = None
    fields: ClassVar[hci.Fields] = ()

    @property
    def payload(self) -> bytes:
        if self._payload is None:
            self._payload = hci.HCI_Object.dict_to_bytes(self.__dict__, self.fields)
        return self._payload

    @payload.setter
    def payload(self, payload: bytes) -> None:
        self._payload = payload

    _Message = TypeVar("_Message", bound="Message")

    @classmethod
    def subclass(cls, subclass: type[_Message]) -> type[_Message]:
        cls.subclasses.setdefault(subclass.signal_identifier, {})[
            subclass.message_type
        ] = subclass
        subclass.fields = hci.HCI_Object.fields_from_dataclass(subclass)
        return subclass

    # Factory method to create a subclass based on the signal identifier and message
    # type
    @classmethod
    def create(
        cls,
        signal_identifier: SignalIdentifier,
        message_type: MessageType,
        payload: bytes,
    ) -> Message:
        instance: Message
        # Look for a registered subclass
        if (subclasses := Message.subclasses.get(signal_identifier)) and (
            subclass := subclasses.get(message_type)
        ):
            instance = subclass(
                **hci.HCI_Object.dict_from_bytes(payload, 0, subclass.fields),
            )
            instance.payload = payload
            return instance

        # Instantiate the appropriate class based on the message type
        if message_type == Message.MessageType.RESPONSE_REJECT:
            # Assume a simple reject message
            instance = Simple_Reject(ErrorCode(payload[0]))
        else:
            instance = Message()
            instance.payload = payload
            instance.message_type = message_type
        instance.signal_identifier = signal_identifier
        return instance

    def to_string(self, details: str | Iterable[str]) -> str:
        base = color(
            f'{self.signal_identifier.name}_{self.message_type.name}',
            'yellow',
        )

        if details:
            if isinstance(details, str):
                return f'{base}: {details}'

            return (
                base
                + ':\n'
                + '\n'.join(['  ' + color(detail, 'cyan') for detail in details])
            )

        return base

    def __str__(self) -> str:
        return self.to_string(self.payload.hex())


# -----------------------------------------------------------------------------
@dataclass
class Simple_Command(Message):
    '''
    Command message with just one seid
    '''

    message_type = Message.MessageType.COMMAND

    acp_seid: int = field(metadata=Message.SEID_METADATA)

    def __str__(self) -> str:
        return self.to_string([f'ACP SEID: {self.acp_seid}'])


# -----------------------------------------------------------------------------
@dataclass
class Simple_Reject(Message):
    '''
    Reject messages with just an error code
    '''

    message_type = Message.MessageType.RESPONSE_REJECT

    error_code: ErrorCode = field(metadata=ErrorCode.type_metadata(1))

    def __str__(self) -> str:
        details = [f'error_code: {self.error_code.name}']
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Discover_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.6.1 Stream End Point Discovery Command
    '''

    signal_identifier = AVDTP_DISCOVER
    message_type = Message.MessageType.COMMAND


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Discover_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.6.2 Stream End Point Discovery Response
    '''

    signal_identifier = AVDTP_DISCOVER
    message_type = Message.MessageType.RESPONSE_ACCEPT

    @classmethod
    def parse_endpoints(
        cls, data: bytes, offset: int
    ) -> tuple[int, list[EndPointInfo]]:
        return len(data), [
            EndPointInfo.from_bytes(data[i * 2 : (i + 1) * 2])
            for i in range(offset, len(data) // 2)
        ]

    @classmethod
    def serialize_endpoints(cls, endpoints: Iterable[EndPointInfo]) -> bytes:
        return b''.join([bytes(endpoint) for endpoint in endpoints])

    endpoints: Iterable[EndPointInfo] = field(
        metadata=hci.metadata(
            {
                'parser': lambda data, offset: Discover_Response.parse_endpoints(
                    data, offset
                ),
                'serializer': lambda endpoints: Discover_Response.serialize_endpoints(
                    endpoints
                ),
            }
        )
    )

    def __str__(self) -> str:
        details = []
        for endpoint in self.endpoints:
            details.extend(
                # pylint: disable=line-too-long
                [
                    f'ACP SEID: {endpoint.seid}',
                    f'  in_use:     {endpoint.in_use}',
                    f'  media_type: {endpoint.media_type.name}',
                    f'  tsep:       {endpoint.tsep.name}',
                ]
            )
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_Capabilities_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.7.1 Get Capabilities Command
    '''

    signal_identifier = AVDTP_GET_CAPABILITIES
    message_type = Message.MessageType.COMMAND


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_Capabilities_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.7.2 Get All Capabilities Response
    '''

    signal_identifier = AVDTP_GET_CAPABILITIES
    message_type = Message.MessageType.RESPONSE_ACCEPT

    capabilities: Iterable[ServiceCapabilities] = field(
        metadata=ServiceCapabilities.METADATA
    )

    def __str__(self) -> str:
        details = [str(capability) for capability in self.capabilities]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_Capabilities_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.7.3 Get Capabilities Reject
    '''

    signal_identifier = AVDTP_GET_CAPABILITIES
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_All_Capabilities_Command(Get_Capabilities_Command):
    '''
    See Bluetooth AVDTP spec - 8.8.1 Get All Capabilities Command
    '''

    signal_identifier = AVDTP_GET_ALL_CAPABILITIES
    message_type = Message.MessageType.COMMAND


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_All_Capabilities_Response(Get_Capabilities_Response):
    '''
    See Bluetooth AVDTP spec - 8.8.2 Get All Capabilities Response
    '''

    signal_identifier = AVDTP_GET_ALL_CAPABILITIES
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_All_Capabilities_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.8.3 Get All Capabilities Reject
    '''

    signal_identifier = AVDTP_GET_ALL_CAPABILITIES
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Set_Configuration_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.9.1 Set Configuration Command
    '''

    signal_identifier = AVDTP_SET_CONFIGURATION
    message_type = Message.MessageType.COMMAND

    acp_seid: int = field(metadata=Message.SEID_METADATA)
    int_seid: int = field(metadata=Message.SEID_METADATA)
    capabilities: Iterable[ServiceCapabilities] = field(
        metadata=ServiceCapabilities.METADATA
    )

    def __str__(self) -> str:
        details = [f'ACP SEID: {self.acp_seid}', f'INT SEID: {self.int_seid}'] + [
            str(capability) for capability in self.capabilities
        ]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Set_Configuration_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.9.2 Set Configuration Response
    '''

    signal_identifier = AVDTP_SET_CONFIGURATION
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Set_Configuration_Reject(Message):
    '''
    See Bluetooth AVDTP spec - 8.9.3 Set Configuration Reject
    '''

    signal_identifier = AVDTP_SET_CONFIGURATION
    message_type = Message.MessageType.RESPONSE_REJECT

    service_category: ServiceCategory = field(
        metadata=ServiceCategory.type_metadata(1), default=ServiceCategory(0)
    )
    error_code: ErrorCode = field(
        metadata=ErrorCode.type_metadata(1), default=ErrorCode(0)
    )

    def __str__(self) -> str:
        details = [
            (f'service_category: {self.service_category.name}'),
            (f'error_code:       {self.error_code.name}'),
        ]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_Configuration_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.10.1 Get Configuration Command
    '''

    signal_identifier = AVDTP_GET_CONFIGURATION
    message_type = Message.MessageType.COMMAND


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_Configuration_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.10.2 Get Configuration Response
    '''

    signal_identifier = AVDTP_GET_CONFIGURATION
    message_type = Message.MessageType.RESPONSE_ACCEPT

    capabilities: Iterable[ServiceCapabilities] = field(
        metadata=ServiceCapabilities.METADATA
    )

    def __str__(self) -> str:
        details = [str(capability) for capability in self.capabilities]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Get_Configuration_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.10.3 Get Configuration Reject
    '''

    signal_identifier = AVDTP_GET_CONFIGURATION
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Reconfigure_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.11.1 Reconfigure Command
    '''

    signal_identifier = AVDTP_RECONFIGURE
    message_type = Message.MessageType.COMMAND

    acp_seid: int = field(metadata=Message.SEID_METADATA)
    capabilities: Iterable[ServiceCapabilities] = field(
        metadata=ServiceCapabilities.METADATA
    )

    def __str__(self) -> str:
        details = [
            f'ACP SEID: {self.acp_seid}',
        ] + [str(capability) for capability in self.capabilities]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Reconfigure_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.11.2 Reconfigure Response
    '''

    signal_identifier = AVDTP_RECONFIGURE
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Reconfigure_Reject(Set_Configuration_Reject):
    '''
    See Bluetooth AVDTP spec - 8.11.3 Reconfigure Reject
    '''

    signal_identifier = AVDTP_RECONFIGURE
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Open_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.12.1 Open Stream Command
    '''

    signal_identifier = AVDTP_OPEN
    message_type = Message.MessageType.COMMAND


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Open_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.12.2 Open Stream Response
    '''

    signal_identifier = AVDTP_OPEN
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Open_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.12.3 Open Stream Reject
    '''

    signal_identifier = AVDTP_OPEN
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Start_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.13.1 Start Stream Command
    '''

    signal_identifier = AVDTP_START
    message_type = Message.MessageType.COMMAND

    acp_seids: Iterable[int] = field(
        metadata=hci.metadata(
            {
                'serializer': lambda seids: bytes([seid << 2 for seid in seids]),
                'parser': lambda data, offset: (
                    len(data),
                    [x >> 2 for x in data[offset:]],
                ),
            }
        )
    )

    def __str__(self) -> str:
        return self.to_string([f'ACP SEIDs: {self.acp_seids}'])


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Start_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.13.2 Start Stream Response
    '''

    signal_identifier = AVDTP_START
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Start_Reject(Message):
    '''
    See Bluetooth AVDTP spec - 8.13.3 Set Configuration Reject
    '''

    signal_identifier = AVDTP_START
    message_type = Message.MessageType.RESPONSE_REJECT

    acp_seid: int = field(metadata=Message.SEID_METADATA)
    error_code: ErrorCode = field(metadata=ErrorCode.type_metadata(1))

    def __str__(self) -> str:
        details = [
            f'acp_seid:   {self.acp_seid}',
            f'error_code: {self.error_code.name}',
        ]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Close_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.14.1 Close Stream Command
    '''

    signal_identifier = AVDTP_CLOSE
    message_type = Message.MessageType.COMMAND


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Close_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.14.2 Close Stream Response
    '''

    signal_identifier = AVDTP_CLOSE
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Close_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.14.3 Close Stream Reject
    '''

    signal_identifier = AVDTP_CLOSE
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Suspend_Command(Start_Command):
    '''
    See Bluetooth AVDTP spec - 8.15.1 Suspend Command
    '''

    signal_identifier = AVDTP_SUSPEND
    message_type = Message.MessageType.COMMAND


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Suspend_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.15.2 Suspend Response
    '''

    signal_identifier = AVDTP_SUSPEND
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Suspend_Reject(Start_Reject):
    '''
    See Bluetooth AVDTP spec - 8.15.3 Suspend Reject
    '''

    signal_identifier = AVDTP_SUSPEND
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Abort_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.16.1 Abort Command
    '''

    signal_identifier = AVDTP_ABORT
    message_type = Message.MessageType.COMMAND


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Abort_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.16.2 Abort Response
    '''

    signal_identifier = AVDTP_ABORT
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Security_Control_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.17.1 Security Control Command
    '''

    signal_identifier = AVDTP_SECURITY_CONTROL
    message_type = Message.MessageType.COMMAND

    acp_seid: int = field(metadata=Message.SEID_METADATA)
    data: bytes = field(metadata=hci.metadata('*'))

    def __str__(self) -> str:
        return self.to_string(
            [f'ACP_SEID: {self.acp_seid}', f'data:    {self.data.hex()}']
        )


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Security_Control_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.17.2 Security Control Response
    '''

    signal_identifier = AVDTP_SECURITY_CONTROL
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class Security_Control_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.17.3 Security Control Reject
    '''

    signal_identifier = AVDTP_SECURITY_CONTROL
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class General_Reject(Message):
    '''
    See Bluetooth AVDTP spec - 8.18 General Reject
    '''

    signal_identifier = SignalIdentifier(0)
    message_type = Message.MessageType.GENERAL_REJECT

    def to_string(self, details):
        return color('GENERAL_REJECT', 'yellow')


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class DelayReport_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.19.1 Delay Report Command
    '''

    signal_identifier = AVDTP_DELAYREPORT
    message_type = Message.MessageType.COMMAND

    DELAY_METADATA = hci.metadata(
        {
            'serializer': lambda delay: bytes([delay >> 8, delay & 0xFF]),
            'parser': lambda data, offset: (
                offset + 2,
                (data[offset] << 8) | (data[offset + 1]),
            ),
        }
    )

    acp_seid: int = field(metadata=Message.SEID_METADATA)
    delay: int = field(metadata=DELAY_METADATA)

    def __str__(self) -> str:
        return self.to_string([f'ACP_SEID: {self.acp_seid}', f'delay:    {self.delay}'])


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class DelayReport_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.19.2 Delay Report Response
    '''

    signal_identifier = AVDTP_DELAYREPORT
    message_type = Message.MessageType.RESPONSE_ACCEPT


# -----------------------------------------------------------------------------
@Message.subclass
@dataclass
class DelayReport_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.19.3 Delay Report Reject
    '''

    signal_identifier = AVDTP_DELAYREPORT
    message_type = Message.MessageType.RESPONSE_REJECT


# -----------------------------------------------------------------------------
class Protocol(utils.EventEmitter):
    local_endpoints: list[LocalStreamEndPoint]
    remote_endpoints: dict[int, DiscoveredStreamEndPoint]
    streams: dict[int, Stream]
    transaction_results: list[asyncio.Future[Message] | None]
    channel_connector: Callable[[], Awaitable[l2cap.ClassicChannel]]
    channel_acceptor: Stream | None

    EVENT_OPEN = "open"
    EVENT_CLOSE = "close"

    class PacketType(enum.IntEnum):
        SINGLE_PACKET = 0
        START_PACKET = 1
        CONTINUE_PACKET = 2
        END_PACKET = 3

    @staticmethod
    async def connect(
        connection: device.Connection, version: tuple[int, int] = (1, 3)
    ) -> Protocol:
        channel = await connection.create_l2cap_channel(
            spec=l2cap.ClassicChannelSpec(psm=AVDTP_PSM)
        )
        protocol = Protocol(channel, version)

        return protocol

    def __init__(
        self, l2cap_channel: l2cap.ClassicChannel, version: tuple[int, int] = (1, 3)
    ) -> None:
        super().__init__()
        self.l2cap_channel = l2cap_channel
        self.version = version
        self.rtx_sig_timer = AVDTP_DEFAULT_RTX_SIG_TIMER
        self.message_assembler = MessageAssembler(self.on_message)
        self.transaction_results = [None] * 16  # Futures for up to 16 transactions
        self.transaction_semaphore = asyncio.Semaphore(16)
        self.transaction_count = 0
        self.channel_acceptor = None
        self.local_endpoints = []  # Local endpoints, with contiguous seid values
        self.remote_endpoints = {}  # Remote stream endpoints, by seid
        self.streams = {}  # Streams, by seid

        # Register to receive PDUs from the channel
        l2cap_channel.sink = self.on_pdu
        l2cap_channel.on(l2cap_channel.EVENT_OPEN, self.on_l2cap_channel_open)
        l2cap_channel.on(l2cap_channel.EVENT_CLOSE, self.on_l2cap_channel_close)

    def get_local_endpoint_by_seid(self, seid: int) -> LocalStreamEndPoint | None:
        if 0 < seid <= len(self.local_endpoints):
            return self.local_endpoints[seid - 1]

        return None

    def add_source(
        self,
        codec_capabilities: MediaCodecCapabilities,
        packet_pump: MediaPacketPump,
        delay_reporting: bool = False,
    ) -> LocalSource:
        seid = len(self.local_endpoints) + 1
        service_capabilities = (
            [ServiceCapabilities(AVDTP_DELAY_REPORTING_SERVICE_CATEGORY)]
            if delay_reporting
            else []
        )
        source = LocalSource(
            self, seid, codec_capabilities, service_capabilities, packet_pump
        )
        self.local_endpoints.append(source)

        return source

    def add_sink(self, codec_capabilities: MediaCodecCapabilities) -> LocalSink:
        seid = len(self.local_endpoints) + 1
        sink = LocalSink(self, seid, codec_capabilities)
        self.local_endpoints.append(sink)

        return sink

    async def create_stream(
        self, source: LocalStreamEndPoint, sink: StreamEndPointProxy
    ) -> Stream:
        # Check that the source isn't already used in a stream
        if source.in_use:
            raise InvalidStateError('source already in use')

        # Create or reuse a new stream to associate the source and the sink
        if source.seid in self.streams:
            stream = self.streams[source.seid]
        else:
            stream = Stream(self, source, sink)
            self.streams[source.seid] = stream

        # The stream can now be configured
        await stream.configure()

        return stream

    async def discover_remote_endpoints(self) -> Iterable[DiscoveredStreamEndPoint]:
        self.remote_endpoints = {}

        response: Discover_Response = await self.send_command(Discover_Command())
        for endpoint_entry in response.endpoints:
            logger.debug(
                f'getting endpoint capabilities for endpoint {endpoint_entry.seid}'
            )
            get_capabilities_response = await self.get_capabilities(endpoint_entry.seid)
            endpoint = DiscoveredStreamEndPoint(
                self,
                endpoint_entry.seid,
                endpoint_entry.media_type,
                endpoint_entry.tsep,
                endpoint_entry.in_use,
                get_capabilities_response.capabilities,
            )
            self.remote_endpoints[endpoint_entry.seid] = endpoint

        return self.remote_endpoints.values()

    def find_remote_sink_by_codec(
        self, media_type: int, codec_type: int, vendor_id: int = 0, codec_id: int = 0
    ) -> DiscoveredStreamEndPoint | None:
        for endpoint in self.remote_endpoints.values():
            if (
                not endpoint.in_use
                and endpoint.media_type == media_type
                and endpoint.tsep == AVDTP_TSEP_SNK
            ):
                has_media_transport = False
                has_codec = False
                for capabilities in endpoint.capabilities:
                    if (
                        capabilities.service_category
                        == AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY
                    ):
                        has_media_transport = True
                    elif (
                        capabilities.service_category
                        == AVDTP_MEDIA_CODEC_SERVICE_CATEGORY
                    ):
                        codec_capabilities = cast(MediaCodecCapabilities, capabilities)
                        if (
                            codec_capabilities.media_type == AVDTP_AUDIO_MEDIA_TYPE
                            and codec_capabilities.media_codec_type == codec_type
                        ):
                            if isinstance(
                                codec_capabilities.media_codec_information,
                                a2dp.VendorSpecificMediaCodecInformation,
                            ):
                                if (
                                    codec_capabilities.media_codec_information.vendor_id
                                    == vendor_id
                                    and codec_capabilities.media_codec_information.codec_id
                                    == codec_id
                                ):
                                    has_codec = True
                            else:
                                has_codec = True
                if has_media_transport and has_codec:
                    return endpoint

        return None

    def on_pdu(self, pdu: bytes) -> None:
        self.message_assembler.on_pdu(pdu)

    def on_message(self, transaction_label: int, message: Message) -> None:
        logger.debug(
            f'{color("<<< Received AVDTP message", "magenta")}: '
            f'[{transaction_label}] {message}'
        )

        # Check that the identifier is not reserved
        if message.signal_identifier == 0:
            logger.warning('!!! reserved signal identifier')
            return

        # Check that the identifier is valid
        if (
            message.signal_identifier < 0
            or message.signal_identifier > AVDTP_DELAYREPORT
        ):
            logger.warning('!!! invalid signal identifier')
            self.send_message(transaction_label, General_Reject())

        if message.message_type == Message.MessageType.COMMAND:
            # Command
            signal_name = message.signal_identifier.name.lower()
            handler_name = f'on_{signal_name}_command'
            handler = getattr(self, handler_name, None)
            if handler:
                try:
                    response = handler(message)
                    self.send_message(transaction_label, response)
                except Exception:
                    logger.exception(color("!!! Exception in handler:", "red"))
            else:
                logger.warning('unhandled command')
        else:
            # Response, look for a pending transaction with the same label
            transaction_result = self.transaction_results[transaction_label]
            if transaction_result is None:
                logger.warning(color('!!! no pending transaction for label', 'red'))
                return

            transaction_result.set_result(message)
            self.transaction_results[transaction_label] = None
            self.transaction_semaphore.release()

    def on_l2cap_connection(self, channel: l2cap.ClassicChannel) -> None:
        # Forward the channel to the endpoint that's expecting it
        if self.channel_acceptor is None:
            logger.warning(color('!!! l2cap connection with no acceptor', 'red'))
            return
        self.channel_acceptor.on_l2cap_connection(channel)

    def on_l2cap_channel_open(self) -> None:
        logger.debug(color('<<< L2CAP channel open', 'magenta'))
        self.emit(self.EVENT_OPEN)

    def on_l2cap_channel_close(self) -> None:
        logger.debug(color('<<< L2CAP channel close', 'magenta'))
        self.emit(self.EVENT_CLOSE)

    def send_message(self, transaction_label: int, message: Message) -> None:
        logger.debug(
            f'{color(">>> Sending AVDTP message", "magenta")}: '
            f'[{transaction_label}] {message}'
        )
        max_fragment_size = (
            self.l2cap_channel.peer_mtu - 3
        )  # Enough space for a 3-byte start packet header
        payload = message.payload
        if len(payload) + 2 <= self.l2cap_channel.peer_mtu:
            # Fits in a single packet
            packet_type = self.PacketType.SINGLE_PACKET
        else:
            packet_type = self.PacketType.START_PACKET

        done = False
        while not done:
            first_header_byte = (
                transaction_label << 4 | packet_type << 2 | message.message_type
            )

            if packet_type == self.PacketType.SINGLE_PACKET:
                header = bytes([first_header_byte, message.signal_identifier])
            elif packet_type == self.PacketType.START_PACKET:
                packet_count = (
                    max_fragment_size - 1 + len(payload)
                ) // max_fragment_size
                header = bytes(
                    [first_header_byte, message.signal_identifier, packet_count]
                )
            else:
                header = bytes([first_header_byte])

            # Send one packet
            self.l2cap_channel.write(header + payload[:max_fragment_size])

            # Prepare for the next packet
            payload = payload[max_fragment_size:]
            if payload:
                packet_type = (
                    self.PacketType.CONTINUE_PACKET
                    if len(payload) > max_fragment_size
                    else self.PacketType.END_PACKET
                )
            else:
                done = True

    async def send_command(self, command: Message):
        # TODO: support timeouts
        # Send the command
        (transaction_label, transaction_result) = await self.start_transaction()
        self.send_message(transaction_label, command)

        # Wait for the response
        response = await transaction_result

        # Check for errors
        if response.message_type in (
            Message.MessageType.GENERAL_REJECT,
            Message.MessageType.RESPONSE_REJECT,
        ):
            assert hasattr(response, 'error_code')
            raise ProtocolError(response.error_code, 'avdtp')

        return response

    async def start_transaction(self) -> tuple[int, asyncio.Future[Message]]:
        # Wait until we can start a new transaction
        await self.transaction_semaphore.acquire()

        # Look for the next free entry to store the transaction result
        for i in range(16):
            transaction_label = (self.transaction_count + i) % 16
            if self.transaction_results[transaction_label] is None:
                transaction_result = asyncio.get_running_loop().create_future()
                self.transaction_results[transaction_label] = transaction_result
                self.transaction_count += 1
                return (transaction_label, transaction_result)

        assert False  # Should never reach this

    async def get_capabilities(
        self, seid: int
    ) -> Get_Capabilities_Response | Get_All_Capabilities_Response:
        if self.version > (1, 2):
            return await self.send_command(Get_All_Capabilities_Command(seid))

        return await self.send_command(Get_Capabilities_Command(seid))

    async def set_configuration(
        self, acp_seid: int, int_seid: int, capabilities: Iterable[ServiceCapabilities]
    ) -> Set_Configuration_Response:
        return await self.send_command(
            Set_Configuration_Command(acp_seid, int_seid, capabilities)
        )

    async def get_configuration(self, seid: int) -> Get_Configuration_Response:
        response = await self.send_command(Get_Configuration_Command(seid))
        return response.capabilities

    async def open(self, seid: int) -> Open_Response:
        return await self.send_command(Open_Command(seid))

    async def start(self, seids: Iterable[int]) -> Start_Response:
        return await self.send_command(Start_Command(seids))

    async def suspend(self, seids: Iterable[int]) -> Suspend_Response:
        return await self.send_command(Suspend_Command(seids))

    async def close(self, seid: int) -> Close_Response:
        return await self.send_command(Close_Command(seid))

    async def abort(self, seid: int) -> Abort_Response:
        return await self.send_command(Abort_Command(seid))

    def on_discover_command(self, command: Discover_Command) -> Message | None:
        endpoint_infos = [
            EndPointInfo(endpoint.seid, 0, endpoint.media_type, endpoint.tsep)
            for endpoint in self.local_endpoints
        ]
        return Discover_Response(endpoint_infos)

    def on_get_capabilities_command(
        self, command: Get_Capabilities_Command
    ) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Get_Capabilities_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        return Get_Capabilities_Response(endpoint.capabilities)

    def on_get_all_capabilities_command(
        self, command: Get_All_Capabilities_Command
    ) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Get_All_Capabilities_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        return Get_All_Capabilities_Response(endpoint.capabilities)

    def on_set_configuration_command(
        self, command: Set_Configuration_Command
    ) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Set_Configuration_Reject(error_code=AVDTP_BAD_ACP_SEID_ERROR)

        # Check that the local endpoint isn't in use
        if endpoint.in_use:
            return Set_Configuration_Reject(error_code=AVDTP_SEP_IN_USE_ERROR)

        # Create a stream object for the pair of endpoints
        stream = Stream(self, endpoint, StreamEndPointProxy(self, command.int_seid))
        self.streams[command.acp_seid] = stream

        result = stream.on_set_configuration_command(command.capabilities)
        return result or Set_Configuration_Response()

    def on_get_configuration_command(
        self, command: Get_Configuration_Command
    ) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Get_Configuration_Reject(AVDTP_BAD_ACP_SEID_ERROR)
        if endpoint.stream is None:
            return Get_Configuration_Reject(AVDTP_BAD_STATE_ERROR)

        return endpoint.stream.on_get_configuration_command()

    def on_reconfigure_command(self, command: Reconfigure_Command) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Reconfigure_Reject(error_code=AVDTP_BAD_ACP_SEID_ERROR)
        if endpoint.stream is None:
            return Reconfigure_Reject(error_code=AVDTP_BAD_STATE_ERROR)

        result = endpoint.stream.on_reconfigure_command(command.capabilities)
        return result or Reconfigure_Response()

    def on_open_command(self, command: Open_Command) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Open_Reject(AVDTP_BAD_ACP_SEID_ERROR)
        if endpoint.stream is None:
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = endpoint.stream.on_open_command()
        return result or Open_Response()

    def on_start_command(self, command: Start_Command) -> Message | None:
        for seid in command.acp_seids:
            endpoint = self.get_local_endpoint_by_seid(seid)
            if endpoint is None:
                return Start_Reject(seid, AVDTP_BAD_ACP_SEID_ERROR)
            if endpoint.stream is None:
                return Start_Reject(seid, AVDTP_BAD_STATE_ERROR)

        # Start all streams
        # TODO: deal with partial failures
        for seid in command.acp_seids:
            endpoint = self.get_local_endpoint_by_seid(seid)
            if not endpoint or not endpoint.stream:
                raise InvalidStateError("Should already be checked!")
            if (result := endpoint.stream.on_start_command()) is not None:
                return result

        return Start_Response()

    def on_suspend_command(self, command: Suspend_Command) -> Message | None:
        for seid in command.acp_seids:
            endpoint = self.get_local_endpoint_by_seid(seid)
            if endpoint is None:
                return Suspend_Reject(seid, AVDTP_BAD_ACP_SEID_ERROR)
            if endpoint.stream is None:
                return Suspend_Reject(seid, AVDTP_BAD_STATE_ERROR)

        # Suspend all streams
        # TODO: deal with partial failures
        for seid in command.acp_seids:
            endpoint = self.get_local_endpoint_by_seid(seid)
            if not endpoint or not endpoint.stream:
                raise InvalidStateError("Should already be checked!")
            if (result := endpoint.stream.on_suspend_command()) is not None:
                return result

        return Suspend_Response()

    def on_close_command(self, command: Close_Command) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Close_Reject(AVDTP_BAD_ACP_SEID_ERROR)
        if endpoint.stream is None:
            return Close_Reject(AVDTP_BAD_STATE_ERROR)

        result = endpoint.stream.on_close_command()
        return result or Close_Response()

    def on_abort_command(self, command: Abort_Command) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None or endpoint.stream is None:
            return Abort_Response()

        endpoint.stream.on_abort_command()
        return Abort_Response()

    def on_security_control_command(
        self, command: Security_Control_Command
    ) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Security_Control_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        result = endpoint.on_security_control_command(command.data)
        return result or Security_Control_Response()

    def on_delayreport_command(self, command: DelayReport_Command) -> Message | None:
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return DelayReport_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        result = endpoint.on_delayreport_command(command.delay)
        return result or DelayReport_Response()


# -----------------------------------------------------------------------------
class Listener(utils.EventEmitter):
    servers: dict[int, Protocol]

    EVENT_CONNECTION = "connection"

    @staticmethod
    def create_registrar(device: device.Device):
        warnings.warn("Please use Listener.for_device()", DeprecationWarning)

        def wrapper(handler: Callable[[l2cap.ClassicChannel], None]) -> None:
            device.create_l2cap_server(l2cap.ClassicChannelSpec(psm=AVDTP_PSM), handler)

        return wrapper

    def set_server(self, connection: device.Connection, server: Protocol) -> None:
        self.servers[connection.handle] = server

    def remove_server(self, connection: device.Connection) -> None:
        if connection.handle in self.servers:
            del self.servers[connection.handle]

    def __init__(self, registrar=None, version=(1, 3)):
        super().__init__()
        self.version = version
        self.servers = {}  # Servers, by connection handle

        # Listen for incoming L2CAP connections
        if registrar:
            warnings.warn("Please use Listener.for_device()", DeprecationWarning)
            registrar(self.on_l2cap_connection)

    @classmethod
    def for_device(
        cls, device: device.Device, version: tuple[int, int] = (1, 3)
    ) -> Listener:
        listener = Listener(registrar=None, version=version)
        l2cap_server = device.create_l2cap_server(
            spec=l2cap.ClassicChannelSpec(psm=AVDTP_PSM)
        )
        l2cap_server.on(l2cap_server.EVENT_CONNECTION, listener.on_l2cap_connection)
        return listener

    def on_l2cap_connection(self, channel: l2cap.ClassicChannel) -> None:
        logger.debug(f'{color("<<< incoming L2CAP connection:", "magenta")} {channel}')

        if channel.connection.handle in self.servers:
            # This is a channel for a stream endpoint
            server = self.servers[channel.connection.handle]
            server.on_l2cap_connection(channel)
        else:
            # This is a new command/response channel
            def on_channel_open():
                logger.debug('setting up new Protocol for the connection')
                server = Protocol(channel, self.version)
                self.set_server(channel.connection, server)
                self.emit(self.EVENT_CONNECTION, server)

            def on_channel_close():
                logger.debug('removing Protocol for the connection')
                self.remove_server(channel.connection)

            channel.on(channel.EVENT_OPEN, on_channel_open)
            channel.on(channel.EVENT_CLOSE, on_channel_close)


# -----------------------------------------------------------------------------
class Stream:
    '''
    Pair of a local and a remote stream endpoint that can stream from one to the other
    '''

    rtp_channel: l2cap.ClassicChannel | None

    def change_state(self, state: State) -> None:
        logger.debug(f'{self} state change -> {color(state.name, "cyan")}')
        self.state = state

    def send_media_packet(self, packet: MediaPacket) -> None:
        assert self.rtp_channel
        self.rtp_channel.write(bytes(packet))

    async def configure(self) -> None:
        if self.state != State.IDLE:
            raise InvalidStateError('current state is not IDLE')

        await self.remote_endpoint.set_configuration(
            self.local_endpoint.seid, self.local_endpoint.configuration
        )
        self.change_state(State.CONFIGURED)

    async def open(self) -> None:
        if self.state != State.CONFIGURED:
            raise InvalidStateError('current state is not CONFIGURED')

        logger.debug('opening remote endpoint')
        await self.remote_endpoint.open()

        self.change_state(State.OPEN)

        # Create a channel for RTP packets
        self.rtp_channel = (
            await self.protocol.l2cap_channel.connection.create_l2cap_channel(
                l2cap.ClassicChannelSpec(psm=AVDTP_PSM)
            )
        )

    async def start(self) -> None:
        """[Source] Start streaming."""
        # Auto-open if needed
        if self.state == State.CONFIGURED:
            await self.open()

        if self.state != State.OPEN:
            raise InvalidStateError('current state is not OPEN')

        logger.debug('starting remote endpoint')
        await self.remote_endpoint.start()

        logger.debug('starting local endpoint')
        await self.local_endpoint.start()

        self.change_state(State.STREAMING)

    async def stop(self) -> None:
        """[Source] Stop streaming and transit to OPEN state."""
        if self.state != State.STREAMING:
            raise InvalidStateError('current state is not STREAMING')

        logger.debug('stopping local endpoint')
        await self.local_endpoint.stop()

        logger.debug('stopping remote endpoint')
        await self.remote_endpoint.stop()

        self.change_state(State.OPEN)

    async def close(self) -> None:
        """[Source] Close channel and transit to IDLE state."""
        if self.state not in (State.OPEN, State.STREAMING):
            raise InvalidStateError('current state is not OPEN or STREAMING')

        logger.debug('closing local endpoint')
        await self.local_endpoint.close()

        logger.debug('closing remote endpoint')
        await self.remote_endpoint.close()

        # Release any channels we may have created
        self.change_state(State.CLOSING)
        if self.rtp_channel:
            await self.rtp_channel.disconnect()
            self.rtp_channel = None

        # Release the endpoint
        self.local_endpoint.in_use = 0

        self.change_state(State.IDLE)

    def on_set_configuration_command(
        self, configuration: Iterable[ServiceCapabilities]
    ) -> Message | None:
        if self.state != State.IDLE:
            return Set_Configuration_Reject(error_code=AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_set_configuration_command(configuration)
        if result is not None:
            return result

        self.change_state(State.CONFIGURED)
        return None

    def on_get_configuration_command(self) -> Message | None:
        if self.state not in (
            State.CONFIGURED,
            State.OPEN,
            State.STREAMING,
        ):
            return Get_Configuration_Reject(error_code=AVDTP_BAD_STATE_ERROR)

        return self.local_endpoint.on_get_configuration_command()

    def on_reconfigure_command(
        self, configuration: Iterable[ServiceCapabilities]
    ) -> Message | None:
        if self.state != State.OPEN:
            return Reconfigure_Reject(error_code=AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_reconfigure_command(configuration)
        if result is not None:
            return result

        return None

    def on_open_command(self) -> Message | None:
        if self.state != State.CONFIGURED:
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_open_command()
        if result is not None:
            return result

        # Register to accept the next channel
        self.protocol.channel_acceptor = self

        self.change_state(State.OPEN)
        return None

    def on_start_command(self) -> Message | None:
        if self.state != State.OPEN:
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        # Check that we have an RTP channel
        if self.rtp_channel is None:
            logger.warning('received start command before RTP channel establishment')
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_start_command()
        if result is not None:
            return result

        self.change_state(State.STREAMING)
        return None

    def on_suspend_command(self) -> Message | None:
        if self.state != State.STREAMING:
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_suspend_command()
        if result is not None:
            return result

        self.change_state(State.OPEN)
        return None

    def on_close_command(self) -> Message | None:
        if self.state not in (State.OPEN, State.STREAMING):
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_close_command()
        if result is not None:
            return result

        self.change_state(State.CLOSING)

        if self.rtp_channel is None:
            # No channel to release, we're done
            self.change_state(State.IDLE)
        else:
            # TODO: set a timer as we wait for the RTP channel to be closed
            pass

        return None

    def on_abort_command(self) -> Message | None:
        if self.rtp_channel is None:
            # No need to wait
            self.change_state(State.IDLE)
        else:
            # Wait for the RTP channel to be closed
            self.change_state(State.ABORTING)
        return None

    def on_l2cap_connection(self, channel: l2cap.ClassicChannel) -> None:
        logger.debug(color('<<< stream channel connected', 'magenta'))
        self.rtp_channel = channel
        channel.on(channel.EVENT_OPEN, self.on_l2cap_channel_open)
        channel.on(channel.EVENT_CLOSE, self.on_l2cap_channel_close)

        # We don't need more channels
        self.protocol.channel_acceptor = None

    def on_l2cap_channel_open(self) -> None:
        logger.debug(color('<<< stream channel open', 'magenta'))
        self.local_endpoint.on_rtp_channel_open()

    def on_l2cap_channel_close(self) -> None:
        logger.debug(color('<<< stream channel closed', 'magenta'))
        self.local_endpoint.on_rtp_channel_close()
        self.local_endpoint.in_use = 0
        self.rtp_channel = None

        if self.state in (State.CLOSING, State.ABORTING):
            self.change_state(State.IDLE)
        else:
            logger.warning('unexpected channel close while not CLOSING or ABORTING')

    def __init__(
        self,
        protocol: Protocol,
        local_endpoint: LocalStreamEndPoint,
        remote_endpoint: StreamEndPointProxy,
    ) -> None:
        '''
        remote_endpoint must be a subclass of StreamEndPointProxy

        '''
        self.protocol = protocol
        self.local_endpoint = local_endpoint
        self.remote_endpoint = remote_endpoint
        self.rtp_channel = None
        self.state = State.IDLE

        local_endpoint.stream = self
        local_endpoint.in_use = 1

    def __str__(self) -> str:
        return (
            f'Stream({self.local_endpoint.seid} -> '
            f'{self.remote_endpoint.seid} {self.state.name})'
        )


# -----------------------------------------------------------------------------
@dataclass
class StreamEndPoint:
    seid: int
    media_type: MediaType
    tsep: StreamEndPointType
    in_use: int
    capabilities: Iterable[ServiceCapabilities]


# -----------------------------------------------------------------------------
class StreamEndPointProxy:
    def __init__(self, protocol: Protocol, seid: int) -> None:
        self.seid = seid
        self.protocol = protocol

    async def set_configuration(
        self, int_seid: int, configuration: Iterable[ServiceCapabilities]
    ) -> Set_Configuration_Response:
        return await self.protocol.set_configuration(self.seid, int_seid, configuration)

    async def open(self) -> Open_Response:
        return await self.protocol.open(self.seid)

    async def start(self) -> Start_Response:
        return await self.protocol.start([self.seid])

    async def stop(self) -> Suspend_Response:
        return await self.protocol.suspend([self.seid])

    async def close(self) -> Close_Response:
        return await self.protocol.close(self.seid)

    async def abort(self) -> Abort_Response:
        return await self.protocol.abort(self.seid)


# -----------------------------------------------------------------------------
class DiscoveredStreamEndPoint(StreamEndPoint, StreamEndPointProxy):
    def __init__(
        self,
        protocol: Protocol,
        seid: int,
        media_type: MediaType,
        tsep: StreamEndPointType,
        in_use: int,
        capabilities: Iterable[ServiceCapabilities],
    ) -> None:
        StreamEndPoint.__init__(self, seid, media_type, tsep, in_use, capabilities)
        StreamEndPointProxy.__init__(self, protocol, seid)


# -----------------------------------------------------------------------------
class LocalStreamEndPoint(StreamEndPoint, utils.EventEmitter):
    stream: Stream | None

    EVENT_CONFIGURATION = "configuration"
    EVENT_OPEN = "open"
    EVENT_START = "start"
    EVENT_STOP = "stop"
    EVENT_RTP_PACKET = "rtp_packet"
    EVENT_SUSPEND = "suspend"
    EVENT_CLOSE = "close"
    EVENT_ABORT = "abort"
    EVENT_DELAY_REPORT = "delay_report"
    EVENT_SECURITY_CONTROL = "security_control"
    EVENT_RTP_CHANNEL_OPEN = "rtp_channel_open"
    EVENT_RTP_CHANNEL_CLOSE = "rtp_channel_close"

    def __init__(
        self,
        protocol: Protocol,
        seid: int,
        media_type: MediaType,
        tsep: StreamEndPointType,
        capabilities: Iterable[ServiceCapabilities],
        configuration: Iterable[ServiceCapabilities] | None = None,
    ):
        StreamEndPoint.__init__(self, seid, media_type, tsep, 0, capabilities)
        utils.EventEmitter.__init__(self)
        self.protocol = protocol
        self.configuration = configuration if configuration is not None else []
        self.stream = None

    async def start(self) -> None:
        """[Source Only] Handles when receiving start command."""

    async def stop(self) -> None:
        """[Source Only] Handles when receiving stop command."""

    async def close(self) -> None:
        """[Source Only] Handles when receiving close command."""

    def on_reconfigure_command(
        self, command: Iterable[ServiceCapabilities]
    ) -> Message | None:
        del command  # unused.
        return None

    def on_set_configuration_command(
        self, configuration: Iterable[ServiceCapabilities]
    ) -> Message | None:
        logger.debug(
            '<<< received configuration: '
            f'{",".join([str(capability) for capability in configuration])}'
        )
        self.configuration = configuration
        self.emit(self.EVENT_CONFIGURATION)
        return None

    def on_get_configuration_command(self) -> Message | None:
        return Get_Configuration_Response(self.configuration)

    def on_open_command(self) -> Message | None:
        self.emit(self.EVENT_OPEN)
        return None

    def on_start_command(self) -> Message | None:
        self.emit(self.EVENT_START)
        return None

    def on_suspend_command(self) -> Message | None:
        self.emit(self.EVENT_SUSPEND)
        return None

    def on_close_command(self) -> Message | None:
        self.emit(self.EVENT_CLOSE)
        return None

    def on_abort_command(self) -> Message | None:
        self.emit(self.EVENT_ABORT)
        return None

    def on_delayreport_command(self, delay: int) -> Message | None:
        self.emit(self.EVENT_DELAY_REPORT, delay)
        return None

    def on_security_control_command(self, data: bytes) -> Message | None:
        self.emit(self.EVENT_SECURITY_CONTROL, data)
        return None

    def on_rtp_channel_open(self) -> None:
        self.emit(self.EVENT_RTP_CHANNEL_OPEN)
        return None

    def on_rtp_channel_close(self) -> None:
        self.emit(self.EVENT_RTP_CHANNEL_CLOSE)
        return None


# -----------------------------------------------------------------------------
class LocalSource(LocalStreamEndPoint):
    def __init__(
        self,
        protocol: Protocol,
        seid: int,
        codec_capabilities: MediaCodecCapabilities,
        other_capabilities: Iterable[ServiceCapabilities],
        packet_pump: MediaPacketPump,
    ) -> None:
        capabilities = [
            ServiceCapabilities(AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY),
            codec_capabilities,
        ] + list(other_capabilities)
        super().__init__(
            protocol,
            seid,
            codec_capabilities.media_type,
            AVDTP_TSEP_SRC,
            capabilities,
            capabilities,
        )
        self.packet_pump = packet_pump

    @override
    async def start(self) -> None:
        if self.packet_pump and self.stream and self.stream.rtp_channel:
            return await self.packet_pump.start(self.stream.rtp_channel)

        self.emit(self.EVENT_START)

    @override
    async def stop(self) -> None:
        if self.packet_pump:
            return await self.packet_pump.stop()

        self.emit(self.EVENT_STOP)

    @override
    def on_start_command(self) -> Message | None:
        asyncio.create_task(self.start())
        return None

    @override
    def on_suspend_command(self) -> Message | None:
        asyncio.create_task(self.stop())
        return None


# -----------------------------------------------------------------------------
class LocalSink(LocalStreamEndPoint):
    def __init__(
        self, protocol: Protocol, seid: int, codec_capabilities: MediaCodecCapabilities
    ) -> None:
        capabilities = [
            ServiceCapabilities(AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY),
            codec_capabilities,
        ]
        super().__init__(
            protocol,
            seid,
            codec_capabilities.media_type,
            AVDTP_TSEP_SNK,
            capabilities,
        )

    def on_rtp_channel_open(self) -> None:
        logger.debug(color('<<< RTP channel open', 'magenta'))
        if not self.stream:
            raise InvalidStateError('Stream is None')
        if not self.stream.rtp_channel:
            raise InvalidStateError('RTP channel is None')
        self.stream.rtp_channel.sink = self.on_avdtp_packet
        super().on_rtp_channel_open()

    def on_rtp_channel_close(self) -> None:
        logger.debug(color('<<< RTP channel close', 'magenta'))
        super().on_rtp_channel_close()

    def on_avdtp_packet(self, packet: bytes) -> None:
        rtp_packet = MediaPacket.from_bytes(packet)
        logger.debug(
            f'{color("<<< RTP Packet:", "green")} '
            f'{rtp_packet} {rtp_packet.payload[:16].hex()}'
        )
        self.emit(self.EVENT_RTP_PACKET, rtp_packet)
