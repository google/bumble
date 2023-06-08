# Copyright 2023 Google LLC
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
import collections.abc
import logging
import asyncio
import dataclasses
import enum
import traceback
import warnings
from typing import Dict, List, Union, Set, TYPE_CHECKING

from . import at
from . import rfcomm

from bumble.colors import color
from bumble.core import (
    ProtocolError,
    BT_GENERIC_AUDIO_SERVICE,
    BT_HANDSFREE_SERVICE,
    BT_L2CAP_PROTOCOL_ID,
    BT_RFCOMM_PROTOCOL_ID,
)
from bumble.hci import HCI_Enhanced_Setup_Synchronous_Connection_Command
from bumble.sdp import (
    DataElement,
    ServiceAttribute,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
)


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Error
# -----------------------------------------------------------------------------


class HfpProtocolError(ProtocolError):
    def __init__(self, error_name: str = '', details: str = ''):
        super().__init__(None, 'hfp', error_name, details)


# -----------------------------------------------------------------------------
# Protocol Support
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
class HfpProtocol:
    dlc: rfcomm.DLC
    buffer: str
    lines: collections.deque
    lines_available: asyncio.Event

    def __init__(self, dlc: rfcomm.DLC) -> None:
        warnings.warn("See HfProtocol", DeprecationWarning)
        self.dlc = dlc
        self.buffer = ''
        self.lines = collections.deque()
        self.lines_available = asyncio.Event()

        dlc.sink = self.feed

    def feed(self, data: Union[bytes, str]) -> None:
        # Convert the data to a string if needed
        if isinstance(data, bytes):
            data = data.decode('utf-8')

        logger.debug(f'<<< Data received: {data}')

        # Add to the buffer and look for lines
        self.buffer += data
        while (separator := self.buffer.find('\r')) >= 0:
            line = self.buffer[:separator].strip()
            self.buffer = self.buffer[separator + 1 :]
            if len(line) > 0:
                self.on_line(line)

    def on_line(self, line: str) -> None:
        self.lines.append(line)
        self.lines_available.set()

    def send_command_line(self, line: str) -> None:
        logger.debug(color(f'>>> {line}', 'yellow'))
        self.dlc.write(line + '\r')

    def send_response_line(self, line: str) -> None:
        logger.debug(color(f'>>> {line}', 'yellow'))
        self.dlc.write('\r\n' + line + '\r\n')

    async def next_line(self) -> str:
        await self.lines_available.wait()
        line = self.lines.popleft()
        if not self.lines:
            self.lines_available.clear()
        logger.debug(color(f'<<< {line}', 'green'))
        return line


# -----------------------------------------------------------------------------
# Normative protocol definitions
# -----------------------------------------------------------------------------


# HF supported features (AT+BRSF=) (normative).
# Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07
# and 3GPP 27.007
class HfFeature(enum.IntFlag):
    EC_NR = 0x001  # Echo Cancel & Noise reduction
    THREE_WAY_CALLING = 0x002
    CLI_PRESENTATION_CAPABILITY = 0x004
    VOICE_RECOGNITION_ACTIVATION = 0x008
    REMOTE_VOLUME_CONTROL = 0x010
    ENHANCED_CALL_STATUS = 0x020
    ENHANCED_CALL_CONTROL = 0x040
    CODEC_NEGOTIATION = 0x080
    HF_INDICATORS = 0x100
    ESCO_S4_SETTINGS_SUPPORTED = 0x200
    ENHANCED_VOICE_RECOGNITION_STATUS = 0x400
    VOICE_RECOGNITION_TEST = 0x800


# AG supported features (+BRSF:) (normative).
# Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07
# and 3GPP 27.007
class AgFeature(enum.IntFlag):
    THREE_WAY_CALLING = 0x001
    EC_NR = 0x002  # Echo Cancel & Noise reduction
    VOICE_RECOGNITION_FUNCTION = 0x004
    IN_BAND_RING_TONE_CAPABILITY = 0x008
    VOICE_TAG = 0x010  # Attach a number to voice tag
    REJECT_CALL = 0x020  # Ability to reject a call
    ENHANCED_CALL_STATUS = 0x040
    ENHANCED_CALL_CONTROL = 0x080
    EXTENDED_ERROR_RESULT_CODES = 0x100
    CODEC_NEGOTIATION = 0x200
    HF_INDICATORS = 0x400
    ESCO_S4_SETTINGS_SUPPORTED = 0x800
    ENHANCED_VOICE_RECOGNITION_STATUS = 0x1000
    VOICE_RECOGNITION_TEST = 0x2000


# Audio Codec IDs (normative).
# Hands-Free Profile v1.8, 10 Appendix B
class AudioCodec(enum.IntEnum):
    CVSD = 0x01  # Support for CVSD audio codec
    MSBC = 0x02  # Support for mSBC audio codec


# HF Indicators (normative).
# Bluetooth Assigned Numbers, 6.10.1 HF Indicators
class HfIndicator(enum.IntEnum):
    ENHANCED_SAFETY = 0x01  # Enhanced safety feature
    BATTERY_LEVEL = 0x02  # Battery level feature


# Call Hold supported operations (normative).
# AT Commands Reference Guide, 3.5.2.3.12 +CHLD - Call Holding Services
class CallHoldOperation(enum.IntEnum):
    RELEASE_ALL_HELD_CALLS = 0  # Release all held calls
    RELEASE_ALL_ACTIVE_CALLS = 1  # Release all active calls, accept other
    HOLD_ALL_ACTIVE_CALLS = 2  # Place all active calls on hold, accept other
    ADD_HELD_CALL = 3  # Adds a held call to conversation


# Response Hold status (normative).
# Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07
# and 3GPP 27.007
class ResponseHoldStatus(enum.IntEnum):
    INC_CALL_HELD = 0  # Put incoming call on hold
    HELD_CALL_ACC = 1  # Accept a held incoming call
    HELD_CALL_REJ = 2  # Reject a held incoming call


# Values for the Call Setup AG indicator (normative).
# Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07
# and 3GPP 27.007
class CallSetupAgIndicator(enum.IntEnum):
    NOT_IN_CALL_SETUP = 0
    INCOMING_CALL_PROCESS = 1
    OUTGOING_CALL_SETUP = 2
    REMOTE_ALERTED = 3  # Remote party alerted in an outgoing call


# Values for the Call Held AG indicator (normative).
# Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07
# and 3GPP 27.007
class CallHeldAgIndicator(enum.IntEnum):
    NO_CALLS_HELD = 0
    # Call is placed on hold or active/held calls swapped
    # (The AG has both an active AND a held call)
    CALL_ON_HOLD_AND_ACTIVE_CALL = 1
    CALL_ON_HOLD_NO_ACTIVE_CALL = 2  # Call on hold, no active call


# Call Info direction (normative).
# AT Commands Reference Guide, 3.5.2.3.15 +CLCC - List Current Calls
class CallInfoDirection(enum.IntEnum):
    MOBILE_ORIGINATED_CALL = 0
    MOBILE_TERMINATED_CALL = 1


# Call Info status (normative).
# AT Commands Reference Guide, 3.5.2.3.15 +CLCC - List Current Calls
class CallInfoStatus(enum.IntEnum):
    ACTIVE = 0
    HELD = 1
    DIALING = 2
    ALERTING = 3
    INCOMING = 4
    WAITING = 5


# Call Info mode (normative).
# AT Commands Reference Guide, 3.5.2.3.15 +CLCC - List Current Calls
class CallInfoMode(enum.IntEnum):
    VOICE = 0
    DATA = 1
    FAX = 2
    UNKNOWN = 9


# -----------------------------------------------------------------------------
# Hands-Free Control Interoperability Requirements
# -----------------------------------------------------------------------------

# Response codes.
RESPONSE_CODES = [
    "+APLSIRI",
    "+BAC",
    "+BCC",
    "+BCS",
    "+BIA",
    "+BIEV",
    "+BIND",
    "+BINP",
    "+BLDN",
    "+BRSF",
    "+BTRH",
    "+BVRA",
    "+CCWA",
    "+CHLD",
    "+CHUP",
    "+CIND",
    "+CLCC",
    "+CLIP",
    "+CMEE",
    "+CMER",
    "+CNUM",
    "+COPS",
    "+IPHONEACCEV",
    "+NREC",
    "+VGM",
    "+VGS",
    "+VTS",
    "+XAPL",
    "A",
    "D",
]

# Unsolicited responses and statuses.
UNSOLICITED_CODES = [
    "+APLSIRI",
    "+BCS",
    "+BIND",
    "+BSIR",
    "+BTRH",
    "+BVRA",
    "+CCWA",
    "+CIEV",
    "+CLIP",
    "+VGM",
    "+VGS",
    "BLACKLISTED",
    "BUSY",
    "DELAYED",
    "NO ANSWER",
    "NO CARRIER",
    "RING",
]

# Status codes
STATUS_CODES = [
    "+CME ERROR",
    "BLACKLISTED",
    "BUSY",
    "DELAYED",
    "ERROR",
    "NO ANSWER",
    "NO CARRIER",
    "OK",
]


@dataclasses.dataclass
class Configuration:
    supported_hf_features: List[HfFeature]
    supported_hf_indicators: List[HfIndicator]
    supported_audio_codecs: List[AudioCodec]


class AtResponseType(enum.Enum):
    """Indicate if a response is expected from an AT command, and if multiple
    responses are accepted."""

    NONE = 0
    SINGLE = 1
    MULTIPLE = 2


class AtResponse:
    code: str
    parameters: list

    def __init__(self, response: bytearray):
        code_and_parameters = response.split(b':')
        parameters = (
            code_and_parameters[1] if len(code_and_parameters) > 1 else bytearray()
        )
        self.code = code_and_parameters[0].decode()
        self.parameters = at.parse_parameters(parameters)


@dataclasses.dataclass
class AgIndicatorState:
    description: str
    index: int
    supported_values: Set[int]
    current_status: int


@dataclasses.dataclass
class HfIndicatorState:
    supported: bool = False
    enabled: bool = False


class HfProtocol:
    """Implementation for the Hands-Free side of the Hands-Free profile.
    Reference specification Hands-Free Profile v1.8"""

    supported_hf_features: int
    supported_audio_codecs: List[AudioCodec]

    supported_ag_features: int
    supported_ag_call_hold_operations: List[CallHoldOperation]

    ag_indicators: List[AgIndicatorState]
    hf_indicators: Dict[HfIndicator, HfIndicatorState]

    dlc: rfcomm.DLC
    command_lock: asyncio.Lock
    if TYPE_CHECKING:
        response_queue: asyncio.Queue[AtResponse]
        unsolicited_queue: asyncio.Queue[AtResponse]
    else:
        response_queue: asyncio.Queue
        unsolicited_queue: asyncio.Queue
    read_buffer: bytearray

    def __init__(self, dlc: rfcomm.DLC, configuration: Configuration):
        # Configure internal state.
        self.dlc = dlc
        self.command_lock = asyncio.Lock()
        self.response_queue = asyncio.Queue()
        self.unsolicited_queue = asyncio.Queue()
        self.read_buffer = bytearray()

        # Build local features.
        self.supported_hf_features = sum(configuration.supported_hf_features)
        self.supported_audio_codecs = configuration.supported_audio_codecs

        self.hf_indicators = {
            indicator: HfIndicatorState()
            for indicator in configuration.supported_hf_indicators
        }

        # Clear remote features.
        self.supported_ag_features = 0
        self.supported_ag_call_hold_operations = []
        self.ag_indicators = []

        # Bind the AT reader to the RFCOMM channel.
        self.dlc.sink = self._read_at

    def supports_hf_feature(self, feature: HfFeature) -> bool:
        return (self.supported_hf_features & feature) != 0

    def supports_ag_feature(self, feature: AgFeature) -> bool:
        return (self.supported_ag_features & feature) != 0

    # Read AT messages from the RFCOMM channel.
    # Enqueue AT commands, responses, unsolicited responses to their
    # respective queues, and set the corresponding event.
    def _read_at(self, data: bytes):
        # Append to the read buffer.
        self.read_buffer.extend(data)

        # Locate header and trailer.
        header = self.read_buffer.find(b'\r\n')
        trailer = self.read_buffer.find(b'\r\n', header + 2)
        if header == -1 or trailer == -1:
            return

        # Isolate the AT response code and parameters.
        raw_response = self.read_buffer[header + 2 : trailer]
        response = AtResponse(raw_response)
        logger.debug(f"<<< {raw_response.decode()}")

        # Consume the response bytes.
        self.read_buffer = self.read_buffer[trailer + 2 :]

        # Forward the received code to the correct queue.
        if self.command_lock.locked() and (
            response.code in STATUS_CODES or response.code in RESPONSE_CODES
        ):
            self.response_queue.put_nowait(response)
        elif response.code in UNSOLICITED_CODES:
            self.unsolicited_queue.put_nowait(response)
        else:
            logger.warning(f"dropping unexpected response with code '{response.code}'")

    # Send an AT command and wait for the peer response.
    # Wait for the AT responses sent by the peer, to the status code.
    # Raises asyncio.TimeoutError if the status is not received
    # after a timeout (default 1 second).
    # Raises ProtocolError if the status is not OK.
    async def execute_command(
        self,
        cmd: str,
        timeout: float = 1.0,
        response_type: AtResponseType = AtResponseType.NONE,
    ) -> Union[None, AtResponse, List[AtResponse]]:
        async with self.command_lock:
            logger.debug(f">>> {cmd}")
            self.dlc.write(cmd + '\r')
            responses: List[AtResponse] = []

            while True:
                result = await asyncio.wait_for(
                    self.response_queue.get(), timeout=timeout
                )
                if result.code == 'OK':
                    if response_type == AtResponseType.SINGLE and len(responses) != 1:
                        raise HfpProtocolError("NO ANSWER")

                    if response_type == AtResponseType.MULTIPLE:
                        return responses
                    if response_type == AtResponseType.SINGLE:
                        return responses[0]
                    return None
                if result.code in STATUS_CODES:
                    raise HfpProtocolError(result.code)
                responses.append(result)

    # 4.2.1 Service Level Connection Initialization.
    async def initiate_slc(self):
        # 4.2.1.1 Supported features exchange
        # First, in the initialization procedure, the HF shall send the
        # AT+BRSF=<HF supported features> command to the AG to both notify
        # the AG of the supported features in the HF, as well as to retrieve the
        # supported features in the AG using the +BRSF result code.
        response = await self.execute_command(
            f"AT+BRSF={self.supported_hf_features}", response_type=AtResponseType.SINGLE
        )

        self.supported_ag_features = int(response.parameters[0])
        logger.info(f"supported AG features: {self.supported_ag_features}")
        for feature in AgFeature:
            if self.supports_ag_feature(feature):
                logger.info(f"  - {feature.name}")

        # 4.2.1.2 Codec Negotiation
        # Secondly, in the initialization procedure, if the HF supports the
        # Codec Negotiation feature, it shall check if the AT+BRSF command
        # response from the AG has indicated that it supports the Codec
        # Negotiation feature.
        if self.supports_hf_feature(
            HfFeature.CODEC_NEGOTIATION
        ) and self.supports_ag_feature(AgFeature.CODEC_NEGOTIATION):
            # If both the HF and AG do support the Codec Negotiation feature
            # then the HF shall send the AT+BAC=<HF available codecs> command to
            # the AG to notify the AG of the available codecs in the HF.
            codecs = [str(c) for c in self.supported_audio_codecs]
            await self.execute_command(f"AT+BAC={','.join(codecs)}")

        # 4.2.1.3 AG Indicators
        # After having retrieved the supported features in the AG, the HF shall
        # determine which indicators are supported by the AG, as well as the
        # ordering of the supported indicators. This is because, according to
        # the 3GPP 27.007 specification [2], the AG may support additional
        # indicators not provided for by the Hands-Free Profile, and because the
        # ordering of the indicators is implementation specific. The HF uses
        # the AT+CIND=? Test command to retrieve information about the supported
        # indicators and their ordering.
        response = await self.execute_command(
            "AT+CIND=?", response_type=AtResponseType.SINGLE
        )

        self.ag_indicators = []
        for index, indicator in enumerate(response.parameters):
            description = indicator[0].decode()
            supported_values = []
            for value in indicator[1]:
                value = value.split(b'-')
                value = [int(v) for v in value]
                value_min = value[0]
                value_max = value[1] if len(value) > 1 else value[0]
                supported_values.extend([v for v in range(value_min, value_max + 1)])

            self.ag_indicators.append(
                AgIndicatorState(description, index, set(supported_values), 0)
            )

        # Once the HF has the necessary supported indicator and ordering
        # information, it shall retrieve the current status of the indicators
        # in the AG using the AT+CIND? Read command.
        response = await self.execute_command(
            "AT+CIND?", response_type=AtResponseType.SINGLE
        )

        for index, indicator in enumerate(response.parameters):
            self.ag_indicators[index].current_status = int(indicator)

        # After having retrieved the status of the indicators in the AG, the HF
        # shall then enable the "Indicators status update" function in the AG by
        # issuing the AT+CMER command, to which the AG shall respond with OK.
        await self.execute_command("AT+CMER=3,,,1")

        if self.supports_hf_feature(
            HfFeature.THREE_WAY_CALLING
        ) and self.supports_ag_feature(HfFeature.THREE_WAY_CALLING):
            # After the HF has enabled the “Indicators status update” function in
            # the AG, and if the “Call waiting and 3-way calling” bit was set in the
            # supported features bitmap by both the HF and the AG, the HF shall
            # issue the AT+CHLD=? test command to retrieve the information about how
            # the call hold and multiparty services are supported in the AG. The HF
            # shall not issue the AT+CHLD=? test command in case either the HF or
            # the AG does not support the "Three-way calling" feature.
            response = await self.execute_command(
                "AT+CHLD=?", response_type=AtResponseType.SINGLE
            )

            self.supported_ag_call_hold_operations = [
                CallHoldOperation(int(operation))
                for operation in response.parameters[0]
                if not b'x' in operation
            ]

        # 4.2.1.4 HF Indicators
        # If the HF supports the HF indicator feature, it shall check the +BRSF
        # response to see if the AG also supports the HF Indicator feature.
        if self.supports_hf_feature(
            HfFeature.HF_INDICATORS
        ) and self.supports_ag_feature(AgFeature.HF_INDICATORS):
            # If both the HF and AG support the HF Indicator feature, then the HF
            # shall send the AT+BIND=<HF supported HF indicators> command to the AG
            # to notify the AG of the supported indicators’ assigned numbers in the
            # HF. The AG shall respond with OK
            indicators = [str(i) for i in self.hf_indicators.keys()]
            await self.execute_command(f"AT+BIND={','.join(indicators)}")

            # After having provided the AG with the HF indicators it supports,
            # the HF shall send the AT+BIND=? to request HF indicators supported
            # by the AG. The AG shall reply with the +BIND response listing all
            # HF indicators that it supports followed by an OK.
            response = await self.execute_command(
                "AT+BIND=?", response_type=AtResponseType.SINGLE
            )

            logger.info("supported HF indicators:")
            for indicator in response.parameters[0]:
                indicator = HfIndicator(int(indicator))
                logger.info(f"  - {indicator.name}")
                if indicator in self.hf_indicators:
                    self.hf_indicators[indicator].supported = True

            # Once the HF receives the supported HF indicators list from the AG,
            # the HF shall send the AT+BIND? command to determine which HF
            # indicators are enabled. The AG shall respond with one or more
            # +BIND responses. The AG shall terminate the list with OK.
            # (See Section 4.36.1.3).
            responses = await self.execute_command(
                "AT+BIND?", response_type=AtResponseType.MULTIPLE
            )

            logger.info("enabled HF indicators:")
            for response in responses:
                indicator = HfIndicator(int(response.parameters[0]))
                enabled = int(response.parameters[1]) != 0
                logger.info(f"  - {indicator.name}: {enabled}")
                if indicator in self.hf_indicators:
                    self.hf_indicators[indicator].enabled = True

        logger.info("SLC setup completed")

    # 4.11.2 Audio Connection Setup by HF
    async def setup_audio_connection(self):
        # When the HF triggers the establishment of the Codec Connection it
        # shall send the AT command AT+BCC to the AG. The AG shall respond with
        # OK if it will start the Codec Connection procedure, and with ERROR
        # if it cannot start the Codec Connection procedure.
        await self.execute_command("AT+BCC")

    # 4.11.3 Codec Connection Setup
    async def setup_codec_connection(self, codec_id: int):
        # The AG shall send a +BCS=<Codec ID> unsolicited response to the HF.
        # The HF shall then respond to the incoming unsolicited response with
        # the AT command AT+BCS=<Codec ID>. The ID shall be the same as in the
        # unsolicited response code as long as the ID is supported.
        # If the received ID is not available, the HF shall respond with
        # AT+BAC with its available codecs.
        if codec_id not in self.supported_audio_codecs:
            codecs = [str(c) for c in self.supported_audio_codecs]
            await self.execute_command(f"AT+BAC={','.join(codecs)}")
            return

        await self.execute_command(f"AT+BCS={codec_id}")

        # After sending the OK response, the AG shall open the
        # Synchronous Connection with the settings that are determined by the
        # ID. The HF shall be ready to accept the synchronous connection
        # establishment as soon as it has sent the AT commands AT+BCS=<Codec ID>.

        logger.info("codec connection setup completed")

    # 4.13.1 Answer Incoming Call from the HF – In-Band Ringing
    async def answer_incoming_call(self):
        # The user accepts the incoming voice call by using the proper means
        # provided by the HF. The HF shall then send the ATA command
        # (see Section 4.34) to the AG. The AG shall then begin the procedure for
        # accepting the incoming call.
        await self.execute_command("ATA")

    # 4.14.1 Reject an Incoming Call from the HF
    async def reject_incoming_call(self):
        # The user rejects the incoming call by using the User Interface on the
        # Hands-Free unit. The HF shall then send the AT+CHUP command
        # (see Section 4.34) to the AG. This may happen at any time during the
        # procedures described in Sections 4.13.1 and 4.13.2.
        await self.execute_command("AT+CHUP")

    # 4.15.1 Terminate a Call Process from the HF
    async def terminate_call(self):
        # The user may abort the ongoing call process using whatever means
        # provided by the Hands-Free unit. The HF shall send AT+CHUP command
        # (see Section 4.34) to the AG, and the AG shall then start the
        # procedure to terminate or interrupt the current call procedure.
        # The AG shall then send the OK indication followed by the +CIEV result
        # code, with the value indicating (call=0).
        await self.execute_command("AT+CHUP")

    async def update_ag_indicator(self, index: int, value: int):
        self.ag_indicators[index].current_status = value
        logger.info(
            f"AG indicator updated: {self.ag_indicators[index].description}, {value}"
        )

    async def handle_unsolicited(self):
        """Handle unsolicited result codes sent by the audio gateway."""
        result = await self.unsolicited_queue.get()
        if result.code == "+BCS":
            await self.setup_codec_connection(int(result.parameters[0]))
        elif result.code == "+CIEV":
            await self.update_ag_indicator(
                int(result.parameters[0]), int(result.parameters[1])
            )
        else:
            logging.info(f"unhandled unsolicited response {result.code}")

    async def run(self):
        """Main rountine for the Hands-Free side of the HFP protocol.
        Initiates the service level connection then loops handling
        unsolicited AG responses."""

        try:
            await self.initiate_slc()
            while True:
                await self.handle_unsolicited()
        except Exception:
            logger.error("HFP-HF protocol failed with the following error:")
            logger.error(traceback.format_exc())


# -----------------------------------------------------------------------------
# Normative SDP definitions
# -----------------------------------------------------------------------------


# Profile version (normative).
# Hands-Free Profile v1.8, 5.3 SDP Interoperability Requirements
class ProfileVersion(enum.IntEnum):
    V1_5 = 0x0105
    V1_6 = 0x0106
    V1_7 = 0x0107
    V1_8 = 0x0108
    V1_9 = 0x0109


# HF supported features (normative).
# Hands-Free Profile v1.8, 5.3 SDP Interoperability Requirements
class HfSdpFeature(enum.IntFlag):
    EC_NR = 0x01  # Echo Cancel & Noise reduction
    THREE_WAY_CALLING = 0x02
    CLI_PRESENTATION_CAPABILITY = 0x04
    VOICE_RECOGNITION_ACTIVATION = 0x08
    REMOTE_VOLUME_CONTROL = 0x10
    WIDE_BAND = 0x20  # Wide band speech
    ENHANCED_VOICE_RECOGNITION_STATUS = 0x40
    VOICE_RECOGNITION_TEST = 0x80


# AG supported features (normative).
# Hands-Free Profile v1.8, 5.3 SDP Interoperability Requirements
class AgSdpFeature(enum.IntFlag):
    THREE_WAY_CALLING = 0x01
    EC_NR = 0x02  # Echo Cancel & Noise reduction
    VOICE_RECOGNITION_FUNCTION = 0x04
    IN_BAND_RING_TONE_CAPABILITY = 0x08
    VOICE_TAG = 0x10  # Attach a number to voice tag
    WIDE_BAND = 0x20  # Wide band speech
    ENHANCED_VOICE_RECOGNITION_STATUS = 0x40
    VOICE_RECOGNITION_TEST = 0x80


def sdp_records(
    service_record_handle: int, rfcomm_channel: int, configuration: Configuration
) -> List[ServiceAttribute]:
    """Generate the SDP record for HFP Hands-Free support.
    The record exposes the features supported in the input configuration,
    and the allocated RFCOMM channel."""

    hf_supported_features = 0

    if HfFeature.EC_NR in configuration.supported_hf_features:
        hf_supported_features |= HfSdpFeature.EC_NR
    if HfFeature.THREE_WAY_CALLING in configuration.supported_hf_features:
        hf_supported_features |= HfSdpFeature.THREE_WAY_CALLING
    if HfFeature.CLI_PRESENTATION_CAPABILITY in configuration.supported_hf_features:
        hf_supported_features |= HfSdpFeature.CLI_PRESENTATION_CAPABILITY
    if HfFeature.VOICE_RECOGNITION_ACTIVATION in configuration.supported_hf_features:
        hf_supported_features |= HfSdpFeature.VOICE_RECOGNITION_ACTIVATION
    if HfFeature.REMOTE_VOLUME_CONTROL in configuration.supported_hf_features:
        hf_supported_features |= HfSdpFeature.REMOTE_VOLUME_CONTROL
    if (
        HfFeature.ENHANCED_VOICE_RECOGNITION_STATUS
        in configuration.supported_hf_features
    ):
        hf_supported_features |= HfSdpFeature.ENHANCED_VOICE_RECOGNITION_STATUS
    if HfFeature.VOICE_RECOGNITION_TEST in configuration.supported_hf_features:
        hf_supported_features |= HfSdpFeature.VOICE_RECOGNITION_TEST

    if AudioCodec.MSBC in configuration.supported_audio_codecs:
        hf_supported_features |= HfSdpFeature.WIDE_BAND

    return [
        ServiceAttribute(
            SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            DataElement.unsigned_integer_32(service_record_handle),
        ),
        ServiceAttribute(
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.uuid(BT_HANDSFREE_SERVICE),
                    DataElement.uuid(BT_GENERIC_AUDIO_SERVICE),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence([DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                            DataElement.unsigned_integer_8(rfcomm_channel),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_HANDSFREE_SERVICE),
                            DataElement.unsigned_integer_16(ProfileVersion.V1_8),
                        ]
                    )
                ]
            ),
        ),
        ServiceAttribute(
            SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            DataElement.unsigned_integer_16(hf_supported_features),
        ),
    ]


# -----------------------------------------------------------------------------
# ESCO Codec Default Parameters
# -----------------------------------------------------------------------------


# Hands-Free Profile v1.8, 5.7 Codec Interoperability Requirements
class DefaultCodecParameters(enum.IntEnum):
    SCO_CVSD_D0 = enum.auto()
    SCO_CVSD_D1 = enum.auto()
    ESCO_CVSD_S1 = enum.auto()
    ESCO_CVSD_S2 = enum.auto()
    ESCO_CVSD_S3 = enum.auto()
    ESCO_CVSD_S4 = enum.auto()
    ESCO_MSBC_T1 = enum.auto()
    ESCO_MSBC_T2 = enum.auto()


@dataclasses.dataclass
class EscoParameters:
    # Codec specific
    transmit_coding_format: HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat
    receive_coding_format: HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat
    packet_type: HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType
    retransmission_effort: HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort
    max_latency: int

    # Common
    input_coding_format: HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat = (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.TRANSPARENT
    )
    output_coding_format: HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat = (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.TRANSPARENT
    )
    input_coded_data_size: int = 16
    output_coded_data_size: int = 16
    input_pcm_data_format: HCI_Enhanced_Setup_Synchronous_Connection_Command.PcmDataFormat = (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PcmDataFormat.TWOS_COMPLEMENT
    )
    output_pcm_data_format: HCI_Enhanced_Setup_Synchronous_Connection_Command.PcmDataFormat = (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PcmDataFormat.TWOS_COMPLEMENT
    )
    input_pcm_sample_payload_msb_position: int = 0
    output_pcm_sample_payload_msb_position: int = 0
    input_data_path: HCI_Enhanced_Setup_Synchronous_Connection_Command.DataPath = (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.DataPath.HCI
    )
    output_data_path: HCI_Enhanced_Setup_Synchronous_Connection_Command.DataPath = (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.DataPath.HCI
    )
    input_transport_unit_size: int = 0
    output_transport_unit_size: int = 0
    input_bandwidth: int = 16000
    output_bandwidth: int = 16000
    transmit_bandwidth: int = 8000
    receive_bandwidth: int = 8000
    transmit_codec_frame_size: int = 60
    receive_codec_frame_size: int = 60


_ESCO_PARAMETERS_CVSD_D0 = EscoParameters(
    transmit_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    receive_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    max_latency=0xFFFF,
    packet_type=HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.HV1,
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.NO_RETRANSMISSION,
)

_ESCO_PARAMETERS_CVSD_D1 = EscoParameters(
    transmit_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    receive_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    max_latency=0xFFFF,
    packet_type=HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.HV3,
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.NO_RETRANSMISSION,
)

_ESCO_PARAMETERS_CVSD_S1 = EscoParameters(
    transmit_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    receive_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    max_latency=0x0007,
    packet_type=(
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV5
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV5
    ),
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.OPTIMIZE_FOR_POWER,
)

_ESCO_PARAMETERS_CVSD_S2 = EscoParameters(
    transmit_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    receive_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    max_latency=0x0007,
    packet_type=(
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV5
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV5
    ),
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.OPTIMIZE_FOR_POWER,
)

_ESCO_PARAMETERS_CVSD_S3 = EscoParameters(
    transmit_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    receive_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    max_latency=0x000A,
    packet_type=(
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV5
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV5
    ),
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.OPTIMIZE_FOR_POWER,
)

_ESCO_PARAMETERS_CVSD_S4 = EscoParameters(
    transmit_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    receive_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.CVSD,
    max_latency=0x000C,
    packet_type=(
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV5
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV5
    ),
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.OPTIMIZE_FOR_QUALITY,
)

_ESCO_PARAMETERS_MSBC_T1 = EscoParameters(
    transmit_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.MSBC,
    receive_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.MSBC,
    max_latency=0x0008,
    packet_type=(
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV5
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV5
    ),
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.OPTIMIZE_FOR_QUALITY,
)

_ESCO_PARAMETERS_MSBC_T2 = EscoParameters(
    transmit_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.MSBC,
    receive_coding_format=HCI_Enhanced_Setup_Synchronous_Connection_Command.CodingFormat.MSBC,
    max_latency=0x000D,
    packet_type=(
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV5
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV5
    ),
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.OPTIMIZE_FOR_QUALITY,
)

ESCO_PERAMETERS = {
    DefaultCodecParameters.SCO_CVSD_D0: _ESCO_PARAMETERS_CVSD_D0,
    DefaultCodecParameters.SCO_CVSD_D1: _ESCO_PARAMETERS_CVSD_D1,
    DefaultCodecParameters.ESCO_CVSD_S1: _ESCO_PARAMETERS_CVSD_S1,
    DefaultCodecParameters.ESCO_CVSD_S2: _ESCO_PARAMETERS_CVSD_S2,
    DefaultCodecParameters.ESCO_CVSD_S3: _ESCO_PARAMETERS_CVSD_S3,
    DefaultCodecParameters.ESCO_CVSD_S4: _ESCO_PARAMETERS_CVSD_S4,
    DefaultCodecParameters.ESCO_MSBC_T1: _ESCO_PARAMETERS_MSBC_T1,
    DefaultCodecParameters.ESCO_MSBC_T2: _ESCO_PARAMETERS_MSBC_T2,
}
