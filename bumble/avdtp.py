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
import struct
import time
import logging
from colors import color
from pyee import EventEmitter
from typing import Dict, Type

from .core import (
    BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE,
    InvalidStateError,
    ProtocolError,
    name_or_number,
)
from .a2dp import (
    A2DP_CODEC_TYPE_NAMES,
    A2DP_MPEG_2_4_AAC_CODEC_TYPE,
    A2DP_NON_A2DP_CODEC_TYPE,
    A2DP_SBC_CODEC_TYPE,
    AacMediaCodecInformation,
    SbcMediaCodecInformation,
    VendorSpecificMediaCodecInformation,
)
from . import sdp

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
AVDTP_DISCOVER             = 0x01
AVDTP_GET_CAPABILITIES     = 0x02
AVDTP_SET_CONFIGURATION    = 0x03
AVDTP_GET_CONFIGURATION    = 0x04
AVDTP_RECONFIGURE          = 0x05
AVDTP_OPEN                 = 0x06
AVDTP_START                = 0x07
AVDTP_CLOSE                = 0x08
AVDTP_SUSPEND              = 0x09
AVDTP_ABORT                = 0x0A
AVDTP_SECURITY_CONTROL     = 0x0B
AVDTP_GET_ALL_CAPABILITIES = 0x0C
AVDTP_DELAYREPORT          = 0x0D

AVDTP_SIGNAL_NAMES = {
    AVDTP_DISCOVER:             'AVDTP_DISCOVER',
    AVDTP_GET_CAPABILITIES:     'AVDTP_GET_CAPABILITIES',
    AVDTP_SET_CONFIGURATION:    'AVDTP_SET_CONFIGURATION',
    AVDTP_GET_CONFIGURATION:    'AVDTP_GET_CONFIGURATION',
    AVDTP_RECONFIGURE:          'AVDTP_RECONFIGURE',
    AVDTP_OPEN:                 'AVDTP_OPEN',
    AVDTP_START:                'AVDTP_START',
    AVDTP_CLOSE:                'AVDTP_CLOSE',
    AVDTP_SUSPEND:              'AVDTP_SUSPEND',
    AVDTP_ABORT:                'AVDTP_ABORT',
    AVDTP_SECURITY_CONTROL:     'AVDTP_SECURITY_CONTROL',
    AVDTP_GET_ALL_CAPABILITIES: 'AVDTP_GET_ALL_CAPABILITIES',
    AVDTP_DELAYREPORT:          'AVDTP_DELAYREPORT'
}

AVDTP_SIGNAL_IDENTIFIERS = {
    'AVDTP_DISCOVER':             AVDTP_DISCOVER,
    'AVDTP_GET_CAPABILITIES':     AVDTP_GET_CAPABILITIES,
    'AVDTP_SET_CONFIGURATION':    AVDTP_SET_CONFIGURATION,
    'AVDTP_GET_CONFIGURATION':    AVDTP_GET_CONFIGURATION,
    'AVDTP_RECONFIGURE':          AVDTP_RECONFIGURE,
    'AVDTP_OPEN':                 AVDTP_OPEN,
    'AVDTP_START':                AVDTP_START,
    'AVDTP_CLOSE':                AVDTP_CLOSE,
    'AVDTP_SUSPEND':              AVDTP_SUSPEND,
    'AVDTP_ABORT':                AVDTP_ABORT,
    'AVDTP_SECURITY_CONTROL':     AVDTP_SECURITY_CONTROL,
    'AVDTP_GET_ALL_CAPABILITIES': AVDTP_GET_ALL_CAPABILITIES,
    'AVDTP_DELAYREPORT':          AVDTP_DELAYREPORT
}

# Error codes (AVDTP spec - 8.20.6.2 ERROR_CODE tables)
AVDTP_BAD_HEADER_FORMAT_ERROR          = 0x01
AVDTP_BAD_LENGTH_ERROR                 = 0x11
AVDTP_BAD_ACP_SEID_ERROR               = 0x12
AVDTP_SEP_IN_USE_ERROR                 = 0x13
AVDTP_SEP_NOT_IN_USE_ERROR             = 0x14
AVDTP_BAD_SERV_CATEGORY_ERROR          = 0x17
AVDTP_BAD_PAYLOAD_FORMAT_ERROR         = 0x18
AVDTP_NOT_SUPPORTED_COMMAND_ERROR      = 0x19
AVDTP_INVALID_CAPABILITIES_ERROR       = 0x1A
AVDTP_BAD_RECOVERY_TYPE_ERROR          = 0x22
AVDTP_BAD_MEDIA_TRANSPORT_FORMAT_ERROR = 0x23
AVDTP_BAD_RECOVERY_FORMAT_ERROR        = 0x25
AVDTP_BAD_ROHC_FORMAT_ERROR            = 0x26
AVDTP_BAD_CP_FORMAT_ERROR              = 0x27
AVDTP_BAD_MULTIPLEXING_FORMAT_ERROR    = 0x28
AVDTP_UNSUPPORTED_CONFIGURATION_ERROR  = 0x29
AVDTP_BAD_STATE_ERROR                  = 0x31

AVDTP_ERROR_NAMES = {
    AVDTP_BAD_HEADER_FORMAT_ERROR:          'AVDTP_BAD_HEADER_FORMAT_ERROR',
    AVDTP_BAD_LENGTH_ERROR:                 'AVDTP_BAD_LENGTH_ERROR',
    AVDTP_BAD_ACP_SEID_ERROR:               'AVDTP_BAD_ACP_SEID_ERROR',
    AVDTP_SEP_IN_USE_ERROR:                 'AVDTP_SEP_IN_USE_ERROR',
    AVDTP_SEP_NOT_IN_USE_ERROR:             'AVDTP_SEP_NOT_IN_USE_ERROR',
    AVDTP_BAD_SERV_CATEGORY_ERROR:          'AVDTP_BAD_SERV_CATEGORY_ERROR',
    AVDTP_BAD_PAYLOAD_FORMAT_ERROR:         'AVDTP_BAD_PAYLOAD_FORMAT_ERROR',
    AVDTP_NOT_SUPPORTED_COMMAND_ERROR:      'AVDTP_NOT_SUPPORTED_COMMAND_ERROR',
    AVDTP_INVALID_CAPABILITIES_ERROR:       'AVDTP_INVALID_CAPABILITIES_ERROR',
    AVDTP_BAD_RECOVERY_TYPE_ERROR:          'AVDTP_BAD_RECOVERY_TYPE_ERROR',
    AVDTP_BAD_MEDIA_TRANSPORT_FORMAT_ERROR: 'AVDTP_BAD_MEDIA_TRANSPORT_FORMAT_ERROR',
    AVDTP_BAD_RECOVERY_FORMAT_ERROR:        'AVDTP_BAD_RECOVERY_FORMAT_ERROR',
    AVDTP_BAD_ROHC_FORMAT_ERROR:            'AVDTP_BAD_ROHC_FORMAT_ERROR',
    AVDTP_BAD_CP_FORMAT_ERROR:              'AVDTP_BAD_CP_FORMAT_ERROR',
    AVDTP_BAD_MULTIPLEXING_FORMAT_ERROR:    'AVDTP_BAD_MULTIPLEXING_FORMAT_ERROR',
    AVDTP_UNSUPPORTED_CONFIGURATION_ERROR:  'AVDTP_UNSUPPORTED_CONFIGURATION_ERROR',
    AVDTP_BAD_STATE_ERROR:                  'AVDTP_BAD_STATE_ERROR'
}

AVDTP_AUDIO_MEDIA_TYPE      = 0x00
AVDTP_VIDEO_MEDIA_TYPE      = 0x01
AVDTP_MULTIMEDIA_MEDIA_TYPE = 0x02

AVDTP_MEDIA_TYPE_NAMES = {
    AVDTP_AUDIO_MEDIA_TYPE:      'AVDTP_AUDIO_MEDIA_TYPE',
    AVDTP_VIDEO_MEDIA_TYPE:      'AVDTP_VIDEO_MEDIA_TYPE',
    AVDTP_MULTIMEDIA_MEDIA_TYPE: 'AVDTP_MULTIMEDIA_MEDIA_TYPE'
}

# TSEP (AVDTP spec - 8.20.3 Stream End-point Type, Source or Sink (TSEP))
AVDTP_TSEP_SRC = 0x00
AVDTP_TSEP_SNK = 0x01

AVDTP_TSEP_NAMES = {
    AVDTP_TSEP_SRC: 'AVDTP_TSEP_SRC',
    AVDTP_TSEP_SNK: 'AVDTP_TSEP_SNK'
}

# Service Categories (AVDTP spec - Table 8.47: Service Category information element field values)
AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY    = 0x01
AVDTP_REPORTING_SERVICE_CATEGORY          = 0x02
AVDTP_RECOVERY_SERVICE_CATEGORY           = 0x03
AVDTP_CONTENT_PROTECTION_SERVICE_CATEGORY = 0x04
AVDTP_HEADER_COMPRESSION_SERVICE_CATEGORY = 0x05
AVDTP_MULTIPLEXING_SERVICE_CATEGORY       = 0x06
AVDTP_MEDIA_CODEC_SERVICE_CATEGORY        = 0x07
AVDTP_DELAY_REPORTING_SERVICE_CATEGORY    = 0x08

AVDTP_SERVICE_CATEGORY_NAMES = {
    AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY:    'AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY',
    AVDTP_REPORTING_SERVICE_CATEGORY:          'AVDTP_REPORTING_SERVICE_CATEGORY',
    AVDTP_RECOVERY_SERVICE_CATEGORY:           'AVDTP_RECOVERY_SERVICE_CATEGORY',
    AVDTP_CONTENT_PROTECTION_SERVICE_CATEGORY: 'AVDTP_CONTENT_PROTECTION_SERVICE_CATEGORY',
    AVDTP_HEADER_COMPRESSION_SERVICE_CATEGORY: 'AVDTP_HEADER_COMPRESSION_SERVICE_CATEGORY',
    AVDTP_MULTIPLEXING_SERVICE_CATEGORY:       'AVDTP_MULTIPLEXING_SERVICE_CATEGORY',
    AVDTP_MEDIA_CODEC_SERVICE_CATEGORY:        'AVDTP_MEDIA_CODEC_SERVICE_CATEGORY',
    AVDTP_DELAY_REPORTING_SERVICE_CATEGORY:    'AVDTP_DELAY_REPORTING_SERVICE_CATEGORY'
}

# States (AVDTP spec - 9.1 State Definitions)
AVDTP_IDLE_STATE       = 0x00
AVDTP_CONFIGURED_STATE = 0x01
AVDTP_OPEN_STATE       = 0x02
AVDTP_STREAMING_STATE  = 0x03
AVDTP_CLOSING_STATE    = 0x04
AVDTP_ABORTING_STATE   = 0x05

AVDTP_STATE_NAMES = {
    AVDTP_IDLE_STATE:       'AVDTP_IDLE_STATE',
    AVDTP_CONFIGURED_STATE: 'AVDTP_CONFIGURED_STATE',
    AVDTP_OPEN_STATE:       'AVDTP_OPEN_STATE',
    AVDTP_STREAMING_STATE:  'AVDTP_STREAMING_STATE',
    AVDTP_CLOSING_STATE:    'AVDTP_CLOSING_STATE',
    AVDTP_ABORTING_STATE:   'AVDTP_ABORTING_STATE'
}

# fmt: on
# pylint: enable=line-too-long
# pylint: disable=invalid-name


# -----------------------------------------------------------------------------
async def find_avdtp_service_with_sdp_client(sdp_client):
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
                if len(profile_descriptor.value) >= 2:
                    avdtp_version_major = profile_descriptor.value[1].value >> 8
                    avdtp_version_minor = profile_descriptor.value[1].value & 0xFF
                    return (avdtp_version_major, avdtp_version_minor)


# -----------------------------------------------------------------------------
async def find_avdtp_service_with_connection(device, connection):
    '''
    Find an AVDTP service, for a connection, and return its version,
    or None if none is found
    '''

    sdp_client = sdp.Client(device)
    await sdp_client.connect(connection)
    service_version = await find_avdtp_service_with_sdp_client(sdp_client)
    await sdp_client.disconnect()

    return service_version


# -----------------------------------------------------------------------------
class RealtimeClock:
    def now(self):
        return time.time()

    async def sleep(self, duration):
        await asyncio.sleep(duration)


# -----------------------------------------------------------------------------
class MediaPacket:
    @staticmethod
    def from_bytes(data):
        version = (data[0] >> 6) & 0x03
        padding = (data[0] >> 5) & 0x01
        extension = (data[0] >> 4) & 0x01
        csrc_count = data[0] & 0x0F
        marker = (data[1] >> 7) & 0x01
        payload_type = data[1] & 0x7F
        sequence_number = struct.unpack_from('>H', data, 2)[0]
        timestamp = struct.unpack_from('>I', data, 4)[0]
        ssrc = struct.unpack_from('>I', data, 8)[0]
        csrc_list = [
            struct.unpack_from('>I', data, 12 + i)[0] for i in range(csrc_count)
        ]
        payload = data[12 + csrc_count * 4 :]

        return MediaPacket(
            version,
            padding,
            extension,
            marker,
            sequence_number,
            timestamp,
            ssrc,
            csrc_list,
            payload_type,
            payload,
        )

    def __init__(
        self,
        version,
        padding,
        extension,
        marker,
        sequence_number,
        timestamp,
        ssrc,
        csrc_list,
        payload_type,
        payload,
    ):
        self.version = version
        self.padding = padding
        self.extension = extension
        self.marker = marker
        self.sequence_number = sequence_number
        self.timestamp = timestamp
        self.ssrc = ssrc
        self.csrc_list = csrc_list
        self.payload_type = payload_type
        self.payload = payload

    def __bytes__(self):
        header = bytes(
            [
                self.version << 6
                | self.padding << 5
                | self.extension << 4
                | len(self.csrc_list),
                self.marker << 7 | self.payload_type,
            ]
        ) + struct.pack('>HII', self.sequence_number, self.timestamp, self.ssrc)
        for csrc in self.csrc_list:
            header += struct.pack('>I', csrc)
        return header + self.payload

    def __str__(self):
        return (
            f'RTP(v={self.version},'
            f'p={self.padding},'
            f'x={self.extension},'
            f'm={self.marker},'
            f'pt={self.payload_type},'
            f'sn={self.sequence_number},'
            f'ts={self.timestamp},'
            f'ssrc={self.ssrc},'
            f'csrcs={self.csrc_list},'
            f'payload_size={len(self.payload)})'
        )


# -----------------------------------------------------------------------------
class MediaPacketPump:
    def __init__(self, packets, clock=RealtimeClock()):
        self.packets = packets
        self.clock = clock
        self.pump_task = None

    async def start(self, rtp_channel):
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
                    rtp_channel.send_pdu(bytes(packet))
                    logger.debug(
                        f'{color(">>> sending RTP packet:", "green")} {packet}'
                    )
            except asyncio.exceptions.CancelledError:
                logger.debug('pump canceled')

        # Pump packets
        self.pump_task = asyncio.create_task(pump_packets())

    async def stop(self):
        # Stop the pump
        if self.pump_task:
            self.pump_task.cancel()
            await self.pump_task
            self.pump_task = None


# -----------------------------------------------------------------------------
class MessageAssembler:  # pylint: disable=attribute-defined-outside-init
    def __init__(self, callback):
        self.callback = callback
        self.reset()

    def reset(self):
        self.transaction_label = 0
        self.message = None
        self.message_type = 0
        self.signal_identifier = 0
        self.number_of_signal_packets = 0
        self.packet_count = 0

    def on_pdu(self, pdu):
        self.packet_count += 1

        transaction_label = pdu[0] >> 4
        packet_type = (pdu[0] >> 2) & 3
        message_type = pdu[0] & 3

        logger.debug(
            f'transaction_label={transaction_label}, '
            f'packet_type={Protocol.packet_type_name(packet_type)}, '
            f'message_type={Message.message_type_name(message_type)}'
        )
        if packet_type in (Protocol.SINGLE_PACKET, Protocol.START_PACKET):
            if self.message is not None:
                # The previous message has not been terminated
                logger.warning(
                    'received a start or single packet when expecting an end or '
                    'continuation'
                )
                self.reset()

            self.transaction_label = transaction_label
            self.signal_identifier = pdu[1] & 0x3F
            self.message_type = message_type

            if packet_type == Protocol.SINGLE_PACKET:
                self.message = pdu[2:]
                self.on_message_complete()
            else:
                self.number_of_signal_packets = pdu[2]
                self.message = pdu[3:]
        elif packet_type in (Protocol.CONTINUE_PACKET, Protocol.END_PACKET):
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

            self.message += pdu[1:]

            if packet_type == Protocol.END_PACKET:
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

    def on_message_complete(self):
        message = Message.create(
            self.signal_identifier, self.message_type, self.message
        )

        try:
            self.callback(self.transaction_label, message)
        except Exception as error:
            logger.warning(color(f'!!! exception in callback: {error}'))

        self.reset()


# -----------------------------------------------------------------------------
class ServiceCapabilities:
    @staticmethod
    def create(service_category, service_capabilities_bytes):
        # Select the appropriate subclass
        if service_category == AVDTP_MEDIA_CODEC_SERVICE_CATEGORY:
            cls = MediaCodecCapabilities
        else:
            cls = ServiceCapabilities

        # Create an instance and initialize it
        instance = cls.__new__(cls)
        instance.service_category = service_category
        instance.service_capabilities_bytes = service_capabilities_bytes
        instance.init_from_bytes()

        return instance

    @staticmethod
    def parse_capabilities(payload):
        capabilities = []
        while payload:
            service_category = payload[0]
            length_of_service_capabilities = payload[1]
            service_capabilities_bytes = payload[2 : 2 + length_of_service_capabilities]
            capabilities.append(
                ServiceCapabilities.create(service_category, service_capabilities_bytes)
            )

            payload = payload[2 + length_of_service_capabilities :]

        return capabilities

    @staticmethod
    def serialize_capabilities(capabilities):
        serialized = b''
        for item in capabilities:
            serialized += (
                bytes([item.service_category, len(item.service_capabilities_bytes)])
                + item.service_capabilities_bytes
            )
        return serialized

    def init_from_bytes(self):
        pass

    def __init__(self, service_category, service_capabilities_bytes=b''):
        self.service_category = service_category
        self.service_capabilities_bytes = service_capabilities_bytes

    def to_string(self, details=[]):  # pylint: disable=dangerous-default-value
        attributes = ','.join(
            [name_or_number(AVDTP_SERVICE_CATEGORY_NAMES, self.service_category)]
            + details
        )
        return f'ServiceCapabilities({attributes})'

    def __str__(self):
        if self.service_capabilities_bytes:
            details = [self.service_capabilities_bytes.hex()]
        else:
            details = []
        return self.to_string(details)


# -----------------------------------------------------------------------------
class MediaCodecCapabilities(ServiceCapabilities):
    def init_from_bytes(self):
        self.media_type = self.service_capabilities_bytes[0]
        self.media_codec_type = self.service_capabilities_bytes[1]
        self.media_codec_information = self.service_capabilities_bytes[2:]

        if self.media_codec_type == A2DP_SBC_CODEC_TYPE:
            self.media_codec_information = SbcMediaCodecInformation.from_bytes(
                self.media_codec_information
            )
        elif self.media_codec_type == A2DP_MPEG_2_4_AAC_CODEC_TYPE:
            self.media_codec_information = AacMediaCodecInformation.from_bytes(
                self.media_codec_information
            )
        elif self.media_codec_type == A2DP_NON_A2DP_CODEC_TYPE:
            self.media_codec_information = (
                VendorSpecificMediaCodecInformation.from_bytes(
                    self.media_codec_information
                )
            )

    def __init__(self, media_type, media_codec_type, media_codec_information):
        super().__init__(
            AVDTP_MEDIA_CODEC_SERVICE_CATEGORY,
            bytes([media_type, media_codec_type]) + bytes(media_codec_information),
        )
        self.media_type = media_type
        self.media_codec_type = media_codec_type
        self.media_codec_information = media_codec_information

    def __str__(self):
        codec_info = (
            self.media_codec_information.hex()
            if isinstance(self.media_codec_information, bytes)
            else str(self.media_codec_information)
        )

        details = [
            f'media_type={name_or_number(AVDTP_MEDIA_TYPE_NAMES, self.media_type)}',
            f'codec={name_or_number(A2DP_CODEC_TYPE_NAMES, self.media_codec_type)}',
            f'codec_info={codec_info}',
        ]
        return self.to_string(details)


# -----------------------------------------------------------------------------
class EndPointInfo:
    @staticmethod
    def from_bytes(payload):
        return EndPointInfo(
            payload[0] >> 2, payload[0] >> 1 & 1, payload[1] >> 4, payload[1] >> 3 & 1
        )

    def __bytes__(self):
        return bytes(
            [self.seid << 2 | self.in_use << 1, self.media_type << 4 | self.tsep << 3]
        )

    def __init__(self, seid, in_use, media_type, tsep):
        self.seid = seid
        self.in_use = in_use
        self.media_type = media_type
        self.tsep = tsep


# -----------------------------------------------------------------------------
class Message:  # pylint:disable=attribute-defined-outside-init
    COMMAND = 0
    GENERAL_REJECT = 1
    RESPONSE_ACCEPT = 2
    RESPONSE_REJECT = 3

    MESSAGE_TYPE_NAMES = {
        COMMAND: 'COMMAND',
        GENERAL_REJECT: 'GENERAL_REJECT',
        RESPONSE_ACCEPT: 'RESPONSE_ACCEPT',
        RESPONSE_REJECT: 'RESPONSE_REJECT',
    }

    # Subclasses, by signal identifier and message type
    subclasses: Dict[int, Dict[int, Type[Message]]] = {}

    @staticmethod
    def message_type_name(message_type):
        return name_or_number(Message.MESSAGE_TYPE_NAMES, message_type)

    @staticmethod
    def subclass(subclass):
        # Infer the signal identifier and message subtype from the class name
        name = subclass.__name__
        if name == 'General_Reject':
            subclass.signal_identifier = 0
            signal_identifier_str = None
            message_type = Message.COMMAND
        elif name.endswith('_Command'):
            signal_identifier_str = name[:-8]
            message_type = Message.COMMAND
        elif name.endswith('_Response'):
            signal_identifier_str = name[:-9]
            message_type = Message.RESPONSE_ACCEPT
        elif name.endswith('_Reject'):
            signal_identifier_str = name[:-7]
            message_type = Message.RESPONSE_REJECT
        else:
            raise ValueError('invalid class name')

        subclass.message_type = message_type

        if signal_identifier_str is not None:
            for (name, signal_identifier) in AVDTP_SIGNAL_IDENTIFIERS.items():
                if name.lower().endswith(signal_identifier_str.lower()):
                    subclass.signal_identifier = signal_identifier
                    break

            # Register the subclass
            Message.subclasses.setdefault(subclass.signal_identifier, {})[
                subclass.message_type
            ] = subclass

        return subclass

    # Factory method to create a subclass based on the signal identifier and message
    # type
    @staticmethod
    def create(signal_identifier, message_type, payload):
        # Look for a registered subclass
        subclasses = Message.subclasses.get(signal_identifier)
        if subclasses:
            subclass = subclasses.get(message_type)
            if subclass:
                instance = subclass.__new__(subclass)
                instance.payload = payload
                instance.init_from_payload()
                return instance

        # Instantiate the appropriate class based on the message type
        if message_type == Message.RESPONSE_REJECT:
            # Assume a simple reject message
            instance = Simple_Reject(payload)
            instance.init_from_payload()
        else:
            instance = Message(payload)
        instance.signal_identifier = signal_identifier
        instance.message_type = message_type
        return instance

    def init_from_payload(self):
        pass

    def __init__(self, payload=b''):
        self.payload = payload

    def to_string(self, details):
        base = color(
            f'{name_or_number(AVDTP_SIGNAL_NAMES, self.signal_identifier)}_'
            f'{Message.message_type_name(self.message_type)}',
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

    def __str__(self):
        return self.to_string(self.payload.hex())


# -----------------------------------------------------------------------------
class Simple_Command(Message):
    '''
    Command message with just one seid
    '''

    def init_from_payload(self):
        self.acp_seid = self.payload[0] >> 2

    def __init__(self, seid):
        super().__init__(payload=bytes([seid << 2]))
        self.acp_seid = seid

    def __str__(self):
        return self.to_string([f'ACP SEID: {self.acp_seid}'])


# -----------------------------------------------------------------------------
class Simple_Reject(Message):
    '''
    Reject messages with just an error code
    '''

    def init_from_payload(self):
        self.error_code = self.payload[0]

    def __init__(self, error_code):
        super().__init__(payload=bytes([error_code]))
        self.error_code = error_code

    def __str__(self):
        details = [f'error_code: {name_or_number(AVDTP_ERROR_NAMES, self.error_code)}']
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
class Discover_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.6.1 Stream End Point Discovery Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Discover_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.6.2 Stream End Point Discovery Response
    '''

    def init_from_payload(self):
        self.endpoints = []
        endpoint_count = len(self.payload) // 2
        for i in range(endpoint_count):
            self.endpoints.append(
                EndPointInfo.from_bytes(self.payload[i * 2 : (i + 1) * 2])
            )

    def __init__(self, endpoints):
        super().__init__(payload=b''.join([bytes(endpoint) for endpoint in endpoints]))
        self.endpoints = endpoints

    def __str__(self):
        details = []
        for endpoint in self.endpoints:
            details.extend(
                # pylint: disable=line-too-long
                [
                    f'ACP SEID: {endpoint.seid}',
                    f'  in_use:     {endpoint.in_use}',
                    f'  media_type: {name_or_number(AVDTP_MEDIA_TYPE_NAMES, endpoint.media_type)}',
                    f'  tsep:       {name_or_number(AVDTP_TSEP_NAMES, endpoint.tsep)}',
                ]
            )
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
class Get_Capabilities_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.7.1 Get Capabilities Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Get_Capabilities_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.7.2 Get All Capabilities Response
    '''

    def init_from_payload(self):
        self.capabilities = ServiceCapabilities.parse_capabilities(self.payload)

    def __init__(self, capabilities):
        super().__init__(
            payload=ServiceCapabilities.serialize_capabilities(capabilities)
        )
        self.capabilities = capabilities

    def __str__(self):
        details = [str(capability) for capability in self.capabilities]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
class Get_Capabilities_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.7.3 Get Capabilities Reject
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Get_All_Capabilities_Command(Get_Capabilities_Command):
    '''
    See Bluetooth AVDTP spec - 8.8.1 Get All Capabilities Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Get_All_Capabilities_Response(Get_Capabilities_Response):
    '''
    See Bluetooth AVDTP spec - 8.8.2 Get All Capabilities Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Get_All_Capabilities_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.8.3 Get All Capabilities Reject
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Set_Configuration_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.9.1 Set Configuration Command
    '''

    def init_from_payload(self):
        self.acp_seid = self.payload[0] >> 2
        self.int_seid = self.payload[1] >> 2
        self.capabilities = ServiceCapabilities.parse_capabilities(self.payload[2:])

    def __init__(self, acp_seid, int_seid, capabilities):
        super().__init__(
            payload=bytes([acp_seid << 2, int_seid << 2])
            + ServiceCapabilities.serialize_capabilities(capabilities)
        )
        self.acp_seid = acp_seid
        self.int_seid = int_seid
        self.capabilities = capabilities

    def __str__(self):
        details = [f'ACP SEID: {self.acp_seid}', f'INT SEID: {self.int_seid}'] + [
            str(capability) for capability in self.capabilities
        ]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
class Set_Configuration_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.9.2 Set Configuration Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Set_Configuration_Reject(Message):
    '''
    See Bluetooth AVDTP spec - 8.9.3 Set Configuration Reject
    '''

    def init_from_payload(self):
        self.service_category = self.payload[0]
        self.error_code = self.payload[1]

    def __init__(self, service_category, error_code):
        super().__init__(payload=bytes([service_category, error_code]))
        self.service_category = service_category
        self.error_code = error_code

    def __str__(self):
        details = [
            (
                'service_category: '
                f'{name_or_number(AVDTP_SERVICE_CATEGORY_NAMES, self.service_category)}'
            ),
            (
                'error_code:       '
                f'{name_or_number(AVDTP_ERROR_NAMES, self.error_code)}'
            ),
        ]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
class Get_Configuration_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.10.1 Get Configuration Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Get_Configuration_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.10.2 Get Configuration Response
    '''

    def init_from_payload(self):
        self.capabilities = ServiceCapabilities.parse_capabilities(self.payload)

    def __init__(self, capabilities):
        super().__init__(
            payload=ServiceCapabilities.serialize_capabilities(capabilities)
        )
        self.capabilities = capabilities

    def __str__(self):
        details = [str(capability) for capability in self.capabilities]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
class Get_Configuration_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.10.3 Get Configuration Reject
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Reconfigure_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.11.1 Reconfigure Command
    '''

    def init_from_payload(self):
        # pylint: disable=attribute-defined-outside-init
        self.acp_seid = self.payload[0] >> 2
        self.capabilities = ServiceCapabilities.parse_capabilities(self.payload[1:])

    def __str__(self):
        details = [
            f'ACP SEID: {self.acp_seid}',
        ] + [str(capability) for capability in self.capabilities]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
class Reconfigure_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.11.2 Reconfigure Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Reconfigure_Reject(Set_Configuration_Reject):
    '''
    See Bluetooth AVDTP spec - 8.11.3 Reconfigure Reject
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Open_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.12.1 Open Stream Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Open_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.12.2 Open Stream Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Open_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.12.3 Open Stream Reject
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Start_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.13.1 Start Stream Command
    '''

    def init_from_payload(self):
        self.acp_seids = [x >> 2 for x in self.payload]

    def __init__(self, seids):
        super().__init__(payload=bytes([seid << 2 for seid in seids]))
        self.acp_seids = seids

    def __str__(self):
        return self.to_string([f'ACP SEIDs: {self.acp_seids}'])


# -----------------------------------------------------------------------------
@Message.subclass
class Start_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.13.2 Start Stream Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Start_Reject(Message):
    '''
    See Bluetooth AVDTP spec - 8.13.3 Set Configuration Reject
    '''

    def init_from_payload(self):
        self.acp_seid = self.payload[0] >> 2
        self.error_code = self.payload[1]

    def __init__(self, acp_seid, error_code):
        super().__init__(payload=bytes([acp_seid << 2, error_code]))
        self.acp_seid = acp_seid
        self.error_code = error_code

    def __str__(self):
        details = [
            f'acp_seid:   {self.acp_seid}',
            f'error_code: {name_or_number(AVDTP_ERROR_NAMES, self.error_code)}',
        ]
        return self.to_string(details)


# -----------------------------------------------------------------------------
@Message.subclass
class Close_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.14.1 Close Stream Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Close_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.14.2 Close Stream Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Close_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.14.3 Close Stream Reject
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Suspend_Command(Start_Command):
    '''
    See Bluetooth AVDTP spec - 8.15.1 Suspend Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Suspend_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.15.2 Suspend Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Suspend_Reject(Start_Reject):
    '''
    See Bluetooth AVDTP spec - 8.15.3 Suspend Reject
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Abort_Command(Simple_Command):
    '''
    See Bluetooth AVDTP spec - 8.16.1 Abort Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Abort_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.16.2 Abort Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Security_Control_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.17.1 Security Control Command
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Security_Control_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.17.2 Security Control Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class Security_Control_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.17.3 Security Control Reject
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class General_Reject(Message):
    '''
    See Bluetooth AVDTP spec - 8.18 General Reject
    '''

    def to_string(self, details):
        return color('GENERAL_REJECT', 'yellow')


# -----------------------------------------------------------------------------
@Message.subclass
class DelayReport_Command(Message):
    '''
    See Bluetooth AVDTP spec - 8.19.1 Delay Report Command
    '''

    def init_from_payload(self):
        # pylint: disable=attribute-defined-outside-init
        self.acp_seid = self.payload[0] >> 2
        self.delay = (self.payload[1] << 8) | (self.payload[2])

    def __str__(self):
        return self.to_string([f'ACP_SEID: {self.acp_seid}', f'delay:    {self.delay}'])


# -----------------------------------------------------------------------------
@Message.subclass
class DelayReport_Response(Message):
    '''
    See Bluetooth AVDTP spec - 8.19.2 Delay Report Response
    '''


# -----------------------------------------------------------------------------
@Message.subclass
class DelayReport_Reject(Simple_Reject):
    '''
    See Bluetooth AVDTP spec - 8.19.3 Delay Report Reject
    '''


# -----------------------------------------------------------------------------
class Protocol:
    SINGLE_PACKET = 0
    START_PACKET = 1
    CONTINUE_PACKET = 2
    END_PACKET = 3

    PACKET_TYPE_NAMES = {
        SINGLE_PACKET: 'SINGLE_PACKET',
        START_PACKET: 'START_PACKET',
        CONTINUE_PACKET: 'CONTINUE_PACKET',
        END_PACKET: 'END_PACKET',
    }

    @staticmethod
    def packet_type_name(packet_type):
        return name_or_number(Protocol.PACKET_TYPE_NAMES, packet_type)

    @staticmethod
    async def connect(connection, version=(1, 3)):
        connector = connection.create_l2cap_connector(AVDTP_PSM)
        channel = await connector()
        protocol = Protocol(channel, version)
        protocol.channel_connector = connector

        return protocol

    def __init__(self, l2cap_channel, version=(1, 3)):
        self.l2cap_channel = l2cap_channel
        self.version = version
        self.rtx_sig_timer = AVDTP_DEFAULT_RTX_SIG_TIMER
        self.message_assembler = MessageAssembler(self.on_message)
        self.transaction_results = [None] * 16  # Futures for up to 16 transactions
        self.transaction_semaphore = asyncio.Semaphore(16)
        self.transaction_count = 0
        self.channel_acceptor = None
        self.channel_connector = None
        self.local_endpoints = []  # Local endpoints, with contiguous seid values
        self.remote_endpoints = {}  # Remote stream endpoints, by seid
        self.streams = {}  # Streams, by seid

        # Register to receive PDUs from the channel
        l2cap_channel.sink = self.on_pdu
        l2cap_channel.on('open', self.on_l2cap_channel_open)

    def get_local_endpoint_by_seid(self, seid):
        if 0 < seid <= len(self.local_endpoints):
            return self.local_endpoints[seid - 1]

        return None

    def add_source(self, codec_capabilities, packet_pump):
        seid = len(self.local_endpoints) + 1
        source = LocalSource(self, seid, codec_capabilities, packet_pump)
        self.local_endpoints.append(source)

        return source

    def add_sink(self, codec_capabilities):
        seid = len(self.local_endpoints) + 1
        sink = LocalSink(self, seid, codec_capabilities)
        self.local_endpoints.append(sink)

        return sink

    async def create_stream(self, source, sink):
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

    async def discover_remote_endpoints(self):
        self.remote_endpoints = {}

        response = await self.send_command(Discover_Command())
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

    def find_remote_sink_by_codec(self, media_type, codec_type):
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
                        if (
                            capabilities.media_type == AVDTP_AUDIO_MEDIA_TYPE
                            and capabilities.media_codec_type == codec_type
                        ):
                            has_codec = True
                if has_media_transport and has_codec:
                    return endpoint

        return None

    def on_pdu(self, pdu):
        self.message_assembler.on_pdu(pdu)

    def on_message(self, transaction_label, message):
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

        if message.message_type == Message.COMMAND:
            # Command
            signal_name = (
                AVDTP_SIGNAL_NAMES.get(message.signal_identifier, "")
                .replace("AVDTP_", "")
                .lower()
            )
            handler_name = f'on_{signal_name}_command'
            handler = getattr(self, handler_name, None)
            if handler:
                try:
                    response = handler(message)
                    self.send_message(transaction_label, response)
                except Exception as error:
                    logger.warning(
                        f'{color("!!! Exception in handler:", "red")} {error}'
                    )
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

    def on_l2cap_connection(self, channel):
        # Forward the channel to the endpoint that's expecting it
        if self.channel_acceptor:
            self.channel_acceptor.on_l2cap_connection(channel)

    def on_l2cap_channel_open(self):
        logger.debug(color('<<< L2CAP channel open', 'magenta'))

    def send_message(self, transaction_label, message):
        logger.debug(
            f'{color(">>> Sending AVDTP message", "magenta")}: '
            f'[{transaction_label}] {message}'
        )
        max_fragment_size = (
            self.l2cap_channel.mtu - 3
        )  # Enough space for a 3-byte start packet header
        payload = message.payload
        if len(payload) + 2 <= self.l2cap_channel.mtu:
            # Fits in a single packet
            packet_type = self.SINGLE_PACKET
        else:
            packet_type = self.START_PACKET

        done = False
        while not done:
            first_header_byte = (
                transaction_label << 4 | packet_type << 2 | message.message_type
            )

            if packet_type == self.SINGLE_PACKET:
                header = bytes([first_header_byte, message.signal_identifier])
            elif packet_type == self.START_PACKET:
                packet_count = (
                    max_fragment_size - 1 + len(payload)
                ) // max_fragment_size
                header = bytes(
                    [first_header_byte, message.signal_identifier, packet_count]
                )
            else:
                header = bytes([first_header_byte])

            # Send one packet
            self.l2cap_channel.send_pdu(header + payload[:max_fragment_size])

            # Prepare for the next packet
            payload = payload[max_fragment_size:]
            if payload:
                packet_type = (
                    self.CONTINUE_PACKET
                    if payload > max_fragment_size
                    else self.END_PACKET
                )
            else:
                done = True

    async def send_command(self, command):
        # TODO: support timeouts
        # Send the command
        (transaction_label, transaction_result) = await self.start_transaction()
        self.send_message(transaction_label, command)

        # Wait for the response
        response = await transaction_result

        # Check for errors
        if response.message_type in (Message.GENERAL_REJECT, Message.RESPONSE_REJECT):
            raise ProtocolError(response.error_code, 'avdtp')

        return response

    async def start_transaction(self):
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

    async def get_capabilities(self, seid):
        if self.version > (1, 2):
            return await self.send_command(Get_All_Capabilities_Command(seid))

        return await self.send_command(Get_Capabilities_Command(seid))

    async def set_configuration(self, acp_seid, int_seid, capabilities):
        return await self.send_command(
            Set_Configuration_Command(acp_seid, int_seid, capabilities)
        )

    async def get_configuration(self, seid):
        response = await self.send_command(Get_Configuration_Command(seid))
        return response.capabilities

    async def open(self, seid):
        return await self.send_command(Open_Command(seid))

    async def start(self, seids):
        return await self.send_command(Start_Command(seids))

    async def suspend(self, seids):
        return await self.send_command(Suspend_Command(seids))

    async def close(self, seid):
        return await self.send_command(Close_Command(seid))

    async def abort(self, seid):
        return await self.send_command(Abort_Command(seid))

    def on_discover_command(self, _command):
        endpoint_infos = [
            EndPointInfo(endpoint.seid, 0, endpoint.media_type, endpoint.tsep)
            for endpoint in self.local_endpoints
        ]
        return Discover_Response(endpoint_infos)

    def on_get_capabilities_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Get_Capabilities_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        return Get_Capabilities_Response(endpoint.capabilities)

    def on_get_all_capabilities_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Get_All_Capabilities_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        return Get_All_Capabilities_Response(endpoint.capabilities)

    def on_set_configuration_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Set_Configuration_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        # Check that the local endpoint isn't in use
        if endpoint.in_use:
            return Set_Configuration_Reject(AVDTP_SEP_IN_USE_ERROR)

        # Create a stream object for the pair of endpoints
        stream = Stream(self, endpoint, StreamEndPointProxy(self, command.int_seid))
        self.streams[command.acp_seid] = stream

        result = stream.on_set_configuration_command(command.capabilities)
        return result or Set_Configuration_Response()

    def on_get_configuration_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Get_Configuration_Reject(AVDTP_BAD_ACP_SEID_ERROR)
        if endpoint.stream is None:
            return Get_Configuration_Reject(AVDTP_BAD_STATE_ERROR)

        return endpoint.stream.on_get_configuration_command()

    def on_reconfigure_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Reconfigure_Reject(0, AVDTP_BAD_ACP_SEID_ERROR)
        if endpoint.stream is None:
            return Reconfigure_Reject(0, AVDTP_BAD_STATE_ERROR)

        result = endpoint.stream.on_reconfigure_command(command.capabilities)
        return result or Reconfigure_Response()

    def on_open_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Open_Reject(AVDTP_BAD_ACP_SEID_ERROR)
        if endpoint.stream is None:
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = endpoint.stream.on_open_command()
        return result or Open_Response()

    def on_start_command(self, command):
        for seid in command.acp_seids:
            endpoint = self.get_local_endpoint_by_seid(seid)
            if endpoint is None:
                return Start_Reject(seid, AVDTP_BAD_ACP_SEID_ERROR)
            if endpoint.stream is None:
                return Start_Reject(AVDTP_BAD_STATE_ERROR)

        # Start all streams
        # TODO: deal with partial failures
        for seid in command.acp_seids:
            endpoint = self.get_local_endpoint_by_seid(seid)
            result = endpoint.stream.on_start_command()
            if result is not None:
                return result

        return Start_Response()

    def on_suspend_command(self, command):
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
            result = endpoint.stream.on_suspend_command()
            if result is not None:
                return result

        return Suspend_Response()

    def on_close_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Close_Reject(AVDTP_BAD_ACP_SEID_ERROR)
        if endpoint.stream is None:
            return Close_Reject(AVDTP_BAD_STATE_ERROR)

        result = endpoint.stream.on_close_command()
        return result or Close_Response()

    def on_abort_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None or endpoint.stream is None:
            return Abort_Response()

        endpoint.stream.on_abort_command()
        return Abort_Response()

    def on_security_control_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return Security_Control_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        result = endpoint.on_security_control_command(command.payload)
        return result or Security_Control_Response()

    def on_delayreport_command(self, command):
        endpoint = self.get_local_endpoint_by_seid(command.acp_seid)
        if endpoint is None:
            return DelayReport_Reject(AVDTP_BAD_ACP_SEID_ERROR)

        result = endpoint.on_delayreport_command(command.delay)
        return result or DelayReport_Response()


# -----------------------------------------------------------------------------
class Listener(EventEmitter):
    @staticmethod
    def create_registrar(device):
        return device.create_l2cap_registrar(AVDTP_PSM)

    def set_server(self, connection, server):
        self.servers[connection.handle] = server

    def __init__(self, registrar, version=(1, 3)):
        super().__init__()
        self.version = version
        self.servers = {}  # Servers, by connection handle

        # Listen for incoming L2CAP connections
        registrar(self.on_l2cap_connection)

    def on_l2cap_connection(self, channel):
        logger.debug(f'{color("<<< incoming L2CAP connection:", "magenta")} {channel}')

        if channel.connection.handle in self.servers:
            # This is a channel for a stream endpoint
            server = self.servers[channel.connection.handle]
            server.on_l2cap_connection(channel)
        else:
            # This is a new command/response channel
            def on_channel_open():
                server = Protocol(channel, self.version)
                self.set_server(channel.connection, server)
                self.emit('connection', server)

            channel.on('open', on_channel_open)


# -----------------------------------------------------------------------------
class Stream:
    '''
    Pair of a local and a remote stream endpoint that can stream from one to the other
    '''

    @staticmethod
    def state_name(state):
        return name_or_number(AVDTP_STATE_NAMES, state)

    def change_state(self, state):
        logger.debug(f'{self} state change -> {color(self.state_name(state), "cyan")}')
        self.state = state

    def send_media_packet(self, packet):
        self.rtp_channel.send_pdu(bytes(packet))

    async def configure(self):
        if self.state != AVDTP_IDLE_STATE:
            raise InvalidStateError('current state is not IDLE')

        await self.remote_endpoint.set_configuration(
            self.local_endpoint.seid, self.local_endpoint.configuration
        )
        self.change_state(AVDTP_CONFIGURED_STATE)

    async def open(self):
        if self.state != AVDTP_CONFIGURED_STATE:
            raise InvalidStateError('current state is not CONFIGURED')

        logger.debug('opening remote endpoint')
        await self.remote_endpoint.open()

        self.change_state(AVDTP_OPEN_STATE)

        # Create a channel for RTP packets
        self.rtp_channel = await self.protocol.channel_connector()

    async def start(self):
        # Auto-open if needed
        if self.state == AVDTP_CONFIGURED_STATE:
            await self.open()

        if self.state != AVDTP_OPEN_STATE:
            raise InvalidStateError('current state is not OPEN')

        logger.debug('starting remote endpoint')
        await self.remote_endpoint.start()

        logger.debug('starting local endpoint')
        await self.local_endpoint.start()

        self.change_state(AVDTP_STREAMING_STATE)

    async def stop(self):
        if self.state != AVDTP_STREAMING_STATE:
            raise InvalidStateError('current state is not STREAMING')

        logger.debug('stopping local endpoint')
        await self.local_endpoint.stop()

        logger.debug('stopping remote endpoint')
        await self.remote_endpoint.stop()

        self.change_state(AVDTP_OPEN_STATE)

    async def close(self):
        if self.state not in (AVDTP_OPEN_STATE, AVDTP_STREAMING_STATE):
            raise InvalidStateError('current state is not OPEN or STREAMING')

        logger.debug('closing local endpoint')
        await self.local_endpoint.close()

        logger.debug('closing remote endpoint')
        await self.remote_endpoint.close()

        # Release any channels we may have created
        self.change_state(AVDTP_CLOSING_STATE)
        if self.rtp_channel:
            await self.rtp_channel.disconnect()
            self.rtp_channel = None

        # Release the endpoint
        self.local_endpoint.in_use = 0

        self.change_state(AVDTP_IDLE_STATE)

    def on_set_configuration_command(self, configuration):
        if self.state != AVDTP_IDLE_STATE:
            return Set_Configuration_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_set_configuration_command(configuration)
        if result is not None:
            return result

        self.change_state(AVDTP_CONFIGURED_STATE)
        return None

    def on_get_configuration_command(self, configuration):
        if self.state not in (
            AVDTP_CONFIGURED_STATE,
            AVDTP_OPEN_STATE,
            AVDTP_STREAMING_STATE,
        ):
            return Get_Configuration_Reject(AVDTP_BAD_STATE_ERROR)

        return self.local_endpoint.on_get_configuration_command(configuration)

    def on_reconfigure_command(self, configuration):
        if self.state != AVDTP_OPEN_STATE:
            return Reconfigure_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_reconfigure_command(configuration)
        if result is not None:
            return result

        return None

    def on_open_command(self):
        if self.state != AVDTP_CONFIGURED_STATE:
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_open_command()
        if result is not None:
            return result

        # Register to accept the next channel
        self.protocol.channel_acceptor = self

        self.change_state(AVDTP_OPEN_STATE)
        return None

    def on_start_command(self):
        if self.state != AVDTP_OPEN_STATE:
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        # Check that we have an RTP channel
        if self.rtp_channel is None:
            logger.warning('received start command before RTP channel establishment')
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_start_command()
        if result is not None:
            return result

        self.change_state(AVDTP_STREAMING_STATE)
        return None

    def on_suspend_command(self):
        if self.state != AVDTP_STREAMING_STATE:
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_suspend_command()
        if result is not None:
            return result

        self.change_state(AVDTP_OPEN_STATE)
        return None

    def on_close_command(self):
        if self.state not in (AVDTP_OPEN_STATE, AVDTP_STREAMING_STATE):
            return Open_Reject(AVDTP_BAD_STATE_ERROR)

        result = self.local_endpoint.on_close_command()
        if result is not None:
            return result

        self.change_state(AVDTP_CLOSING_STATE)

        if self.rtp_channel is None:
            # No channel to release, we're done
            self.change_state(AVDTP_IDLE_STATE)
        else:
            # TODO: set a timer as we wait for the RTP channel to be closed
            pass

        return None

    def on_abort_command(self):
        if self.rtp_channel is None:
            # No need to wait
            self.change_state(AVDTP_IDLE_STATE)
        else:
            # Wait for the RTP channel to be closed
            self.change_state(AVDTP_ABORTING_STATE)

    def on_l2cap_connection(self, channel):
        logger.debug(color('<<< stream channel connected', 'magenta'))
        self.rtp_channel = channel
        channel.on('open', self.on_l2cap_channel_open)
        channel.on('close', self.on_l2cap_channel_close)

        # We don't need more channels
        self.protocol.channel_acceptor = None

    def on_l2cap_channel_open(self):
        logger.debug(color('<<< stream channel open', 'magenta'))
        self.local_endpoint.on_rtp_channel_open()

    def on_l2cap_channel_close(self):
        logger.debug(color('<<< stream channel closed', 'magenta'))
        self.local_endpoint.on_rtp_channel_close()
        self.local_endpoint.in_use = 0
        self.rtp_channel = None

        if self.state in (AVDTP_CLOSING_STATE, AVDTP_ABORTING_STATE):
            self.change_state(AVDTP_IDLE_STATE)
        else:
            logger.warning('unexpected channel close while not CLOSING or ABORTING')

    def __init__(self, protocol, local_endpoint, remote_endpoint):
        '''
        remote_endpoint must be a subclass of StreamEndPointProxy

        '''
        self.protocol = protocol
        self.local_endpoint = local_endpoint
        self.remote_endpoint = remote_endpoint
        self.rtp_channel = None
        self.state = AVDTP_IDLE_STATE

        local_endpoint.stream = self
        local_endpoint.in_use = 1

    def __str__(self):
        return (
            f'Stream({self.local_endpoint.seid} -> '
            f'{self.remote_endpoint.seid} {self.state_name(self.state)})'
        )


# -----------------------------------------------------------------------------
class StreamEndPoint:
    def __init__(self, seid, media_type, tsep, in_use, capabilities):
        self.seid = seid
        self.media_type = media_type
        self.tsep = tsep
        self.in_use = in_use
        self.capabilities = capabilities

    def __str__(self):
        media_type = f'{name_or_number(AVDTP_MEDIA_TYPE_NAMES, self.media_type)}'
        tsep = f'{name_or_number(AVDTP_TSEP_NAMES, self.tsep)}'
        return '\n'.join(
            [
                'SEP(',
                f'  seid={self.seid}',
                f'  media_type={media_type}',
                f'  tsep={tsep}',
                f'  in_use={self.in_use}',
                '  capabilities=[',
                '\n'.join([f'    {x}' for x in self.capabilities]),
                '  ]',
                ')',
            ]
        )


# -----------------------------------------------------------------------------
class StreamEndPointProxy:
    def __init__(self, protocol, seid):
        self.seid = seid
        self.protocol = protocol

    async def set_configuration(self, int_seid, configuration):
        return await self.protocol.set_configuration(self.seid, int_seid, configuration)

    async def open(self):
        return await self.protocol.open(self.seid)

    async def start(self):
        return await self.protocol.start([self.seid])

    async def stop(self):
        return await self.protocol.suspend([self.seid])

    async def close(self):
        return await self.protocol.close(self.seid)

    async def abort(self):
        return await self.protocol.abort(self.seid)


# -----------------------------------------------------------------------------
class DiscoveredStreamEndPoint(StreamEndPoint, StreamEndPointProxy):
    def __init__(self, protocol, seid, media_type, tsep, in_use, capabilities):
        StreamEndPoint.__init__(self, seid, media_type, tsep, in_use, capabilities)
        StreamEndPointProxy.__init__(self, protocol, seid)


# -----------------------------------------------------------------------------
class LocalStreamEndPoint(StreamEndPoint):
    def __init__(
        self, protocol, seid, media_type, tsep, capabilities, configuration=None
    ):
        super().__init__(seid, media_type, tsep, 0, capabilities)
        self.protocol = protocol
        self.configuration = configuration if configuration is not None else []
        self.stream = None

    async def start(self):
        pass

    async def stop(self):
        pass

    async def close(self):
        pass

    def on_reconfigure_command(self, command):
        pass

    def on_get_configuration_command(self):
        return Get_Configuration_Response(self.configuration)

    def on_open_command(self):
        pass

    def on_start_command(self):
        pass

    def on_suspend_command(self):
        pass

    def on_close_command(self):
        pass

    def on_abort_command(self):
        pass

    def on_rtp_channel_open(self):
        pass

    def on_rtp_channel_close(self):
        pass


# -----------------------------------------------------------------------------
class LocalSource(LocalStreamEndPoint, EventEmitter):
    def __init__(self, protocol, seid, codec_capabilities, packet_pump):
        capabilities = [
            ServiceCapabilities(AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY),
            codec_capabilities,
        ]
        LocalStreamEndPoint.__init__(
            self,
            protocol,
            seid,
            codec_capabilities.media_type,
            AVDTP_TSEP_SRC,
            capabilities,
            capabilities,
        )
        EventEmitter.__init__(self)
        self.packet_pump = packet_pump

    async def start(self):
        if self.packet_pump:
            return await self.packet_pump.start(self.stream.rtp_channel)

        self.emit('start', self.stream.rtp_channel)

    async def stop(self):
        if self.packet_pump:
            return await self.packet_pump.stop()

        self.emit('stop')

    def on_set_configuration_command(self, configuration):
        # For now, blindly accept the configuration
        logger.debug(f'<<< received source configuration: {configuration}')
        self.configuration = configuration

    def on_start_command(self):
        asyncio.create_task(self.start())

    def on_suspend_command(self):
        asyncio.create_task(self.stop())


# -----------------------------------------------------------------------------
class LocalSink(LocalStreamEndPoint, EventEmitter):
    def __init__(self, protocol, seid, codec_capabilities):
        capabilities = [
            ServiceCapabilities(AVDTP_MEDIA_TRANSPORT_SERVICE_CATEGORY),
            codec_capabilities,
        ]
        LocalStreamEndPoint.__init__(
            self,
            protocol,
            seid,
            codec_capabilities.media_type,
            AVDTP_TSEP_SNK,
            capabilities,
        )
        EventEmitter.__init__(self)

    def on_set_configuration_command(self, configuration):
        # For now, blindly accept the configuration
        logger.debug(f'<<< received sink configuration: {configuration}')
        self.configuration = configuration

    def on_rtp_channel_open(self):
        logger.debug(color('<<< RTP channel open', 'magenta'))
        self.stream.rtp_channel.sink = self.on_avdtp_packet

    def on_avdtp_packet(self, packet):
        rtp_packet = MediaPacket.from_bytes(packet)
        logger.debug(
            f'{color("<<< RTP Packet:", "green")} '
            f'{rtp_packet} {rtp_packet.payload[:16].hex()}'
        )
        self.emit('rtp_packet', rtp_packet)
