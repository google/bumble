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
from __future__ import annotations

import collections
import collections.abc
import logging
import asyncio
import dataclasses
import enum
import traceback
import pyee
import re
from typing import (
    Dict,
    List,
    Union,
    Set,
    Any,
    Optional,
    Type,
    Tuple,
    ClassVar,
    Iterable,
    TYPE_CHECKING,
)
from typing_extensions import Self

from bumble import at
from bumble import device
from bumble import rfcomm
from bumble import sdp
from bumble.colors import color
from bumble.core import (
    ProtocolError,
    BT_GENERIC_AUDIO_SERVICE,
    BT_HANDSFREE_SERVICE,
    BT_HANDSFREE_AUDIO_GATEWAY_SERVICE,
    BT_L2CAP_PROTOCOL_ID,
    BT_RFCOMM_PROTOCOL_ID,
)
from bumble.hci import (
    HCI_Enhanced_Setup_Synchronous_Connection_Command,
    CodingFormat,
    CodecID,
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


class HfFeature(enum.IntFlag):
    """
    HF supported features (AT+BRSF=) (normative).

    Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07 and 3GPP 27.007.
    """

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


class AgFeature(enum.IntFlag):
    """
    AG supported features (+BRSF:) (normative).

    Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07 and 3GPP 27.007.
    """

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


class AudioCodec(enum.IntEnum):
    """
    Audio Codec IDs (normative).

    Hands-Free Profile v1.9, 11 Appendix B
    """

    CVSD = 0x01  # Support for CVSD audio codec
    MSBC = 0x02  # Support for mSBC audio codec
    LC3_SWB = 0x03  # Support for LC3-SWB audio codec


class HfIndicator(enum.IntEnum):
    """
    HF Indicators (normative).

    Bluetooth Assigned Numbers, 6.10.1 HF Indicators.
    """

    ENHANCED_SAFETY = 0x01  # Enhanced safety feature
    BATTERY_LEVEL = 0x02  # Battery level feature


class CallHoldOperation(enum.Enum):
    """
    Call Hold supported operations (normative).

    AT Commands Reference Guide, 3.5.2.3.12 +CHLD - Call Holding Services.
    """

    RELEASE_ALL_HELD_CALLS = "0"  # Release all held calls
    RELEASE_ALL_ACTIVE_CALLS = "1"  # Release all active calls, accept other
    RELEASE_SPECIFIC_CALL = "1x"  # Release a specific call X
    HOLD_ALL_ACTIVE_CALLS = "2"  # Place all active calls on hold, accept other
    HOLD_ALL_CALLS_EXCEPT = "2x"  # Place all active calls except call X
    ADD_HELD_CALL = "3"  # Adds a held call to conversation
    CONNECT_TWO_CALLS = (
        "4"  # Connects the two calls and disconnects the subscriber from both calls
    )


class ResponseHoldStatus(enum.IntEnum):
    """
    Response Hold status (normative).

    Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07 and 3GPP 27.007.
    """

    INC_CALL_HELD = 0  # Put incoming call on hold
    HELD_CALL_ACC = 1  # Accept a held incoming call
    HELD_CALL_REJ = 2  # Reject a held incoming call


class AgIndicator(enum.Enum):
    """
    Values for the AG indicator (normative).

    Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07 and 3GPP 27.007.
    """

    SERVICE = 'service'
    CALL = 'call'
    CALL_SETUP = 'callsetup'
    CALL_HELD = 'callheld'
    SIGNAL = 'signal'
    ROAM = 'roam'
    BATTERY_CHARGE = 'battchg'


class CallSetupAgIndicator(enum.IntEnum):
    """
    Values for the Call Setup AG indicator (normative).

    Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07 and 3GPP 27.007.
    """

    NOT_IN_CALL_SETUP = 0
    INCOMING_CALL_PROCESS = 1
    OUTGOING_CALL_SETUP = 2
    REMOTE_ALERTED = 3  # Remote party alerted in an outgoing call


class CallHeldAgIndicator(enum.IntEnum):
    """
    Values for the Call Held AG indicator (normative).

    Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07 and 3GPP 27.007.
    """

    NO_CALLS_HELD = 0
    # Call is placed on hold or active/held calls swapped
    # (The AG has both an active AND a held call)
    CALL_ON_HOLD_AND_ACTIVE_CALL = 1
    CALL_ON_HOLD_NO_ACTIVE_CALL = 2  # Call on hold, no active call


class CallInfoDirection(enum.IntEnum):
    """
    Call Info direction (normative).

    AT Commands Reference Guide, 3.5.2.3.15 +CLCC - List Current Calls.
    """

    MOBILE_ORIGINATED_CALL = 0
    MOBILE_TERMINATED_CALL = 1


class CallInfoStatus(enum.IntEnum):
    """
    Call Info status (normative).

    AT Commands Reference Guide, 3.5.2.3.15 +CLCC - List Current Calls.
    """

    ACTIVE = 0
    HELD = 1
    DIALING = 2
    ALERTING = 3
    INCOMING = 4
    WAITING = 5


class CallInfoMode(enum.IntEnum):
    """
    Call Info mode (normative).

    AT Commands Reference Guide, 3.5.2.3.15 +CLCC - List Current Calls.
    """

    VOICE = 0
    DATA = 1
    FAX = 2
    UNKNOWN = 9


class CallInfoMultiParty(enum.IntEnum):
    """
    Call Info Multi-Party state (normative).

    AT Commands Reference Guide, 3.5.2.3.15 +CLCC - List Current Calls.
    """

    NOT_IN_CONFERENCE = 0
    IN_CONFERENCE = 1


@dataclasses.dataclass
class CallInfo:
    """
    Enhanced call status.

    AT Commands Reference Guide, 3.5.2.3.15 +CLCC - List Current Calls.
    """

    index: int
    direction: CallInfoDirection
    status: CallInfoStatus
    mode: CallInfoMode
    multi_party: CallInfoMultiParty
    number: Optional[str] = None
    type: Optional[int] = None


@dataclasses.dataclass
class CallLineIdentification:
    """
    Calling Line Identification notification.

    TS 127 007 - V6.8.0, 7.6 Calling line identification presentation +CLIP, but only
    number, type and alpha are meaningful in HFP.

    Attributes:
        number: String type phone number of format specified by `type`.
        type: Type of address octet in integer format (refer TS 24.008 [8] subclause
        10.5.4.7).
        subaddr: String type subaddress of format specified by `satype`.
        satype: Type of subaddress octet in integer format (refer TS 24.008 [8]
        subclause 10.5.4.8).
        alpha: Optional string type alphanumeric representation of number corresponding
        to the entry found in phonebook; used character set should be the one selected
        with command Select TE Character Set +CSCS.
        cli_validity: 0 CLI valid, 1 CLI has been withheld by the originator, 2 CLI is
        not available due to interworking problems or limitations of originating
        network.
    """

    number: str
    type: int
    subaddr: Optional[str] = None
    satype: Optional[int] = None
    alpha: Optional[str] = None
    cli_validity: Optional[int] = None

    @classmethod
    def parse_from(cls: Type[Self], parameters: List[bytes]) -> Self:
        return cls(
            number=parameters[0].decode(),
            type=int(parameters[1]),
            subaddr=parameters[2].decode() if len(parameters) >= 3 else None,
            satype=(
                int(parameters[3]) if len(parameters) >= 4 and parameters[3] else None
            ),
            alpha=parameters[4].decode() if len(parameters) >= 5 else None,
            cli_validity=(
                int(parameters[5]) if len(parameters) >= 6 and parameters[5] else None
            ),
        )

    def to_clip_string(self) -> str:
        return ','.join(
            str(arg) if arg else ''
            for arg in [
                self.number,
                self.type,
                self.subaddr,
                self.satype,
                self.alpha,
                self.cli_validity,
            ]
        )


class VoiceRecognitionState(enum.IntEnum):
    """
    vrec values provided in AT+BVRA command.

    Hands-Free Profile v1.8, 4.34.2, AT Capabilities Re-Used from GSM 07.07 and 3GPP 27.007.
    """

    DISABLE = 0
    ENABLE = 1
    # (Enhanced Voice Recognition Status only) HF is ready to accept audio.
    ENHANCED_READY = 2


class CmeError(enum.IntEnum):
    """
    CME ERROR codes (partial listed).

    TS 127 007 - V6.8.0, 9.2.1 General errors
    """

    PHONE_FAILURE = 0
    OPERATION_NOT_ALLOWED = 3
    OPERATION_NOT_SUPPORTED = 4
    MEMORY_FULL = 20
    INVALID_INDEX = 21
    NOT_FOUND = 22


# -----------------------------------------------------------------------------
# Hands-Free Control Interoperability Requirements
# -----------------------------------------------------------------------------

# Response codes.
RESPONSE_CODES = {
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
}

# Unsolicited responses and statuses.
UNSOLICITED_CODES = {
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
}

# Status codes
STATUS_CODES = {
    "+CME ERROR",
    "BLACKLISTED",
    "BUSY",
    "DELAYED",
    "ERROR",
    "NO ANSWER",
    "NO CARRIER",
    "OK",
}


@dataclasses.dataclass
class HfConfiguration:
    supported_hf_features: List[HfFeature]
    supported_hf_indicators: List[HfIndicator]
    supported_audio_codecs: List[AudioCodec]


@dataclasses.dataclass
class AgConfiguration:
    supported_ag_features: Iterable[AgFeature]
    supported_ag_indicators: collections.abc.Sequence[AgIndicatorState]
    supported_hf_indicators: Iterable[HfIndicator]
    supported_ag_call_hold_operations: Iterable[CallHoldOperation]
    supported_audio_codecs: Iterable[AudioCodec]


class AtResponseType(enum.Enum):
    """
    Indicates if a response is expected from an AT command, and if multiple responses are accepted.
    """

    NONE = 0
    SINGLE = 1
    MULTIPLE = 2


@dataclasses.dataclass
class AtResponse:
    code: str
    parameters: list

    @classmethod
    def parse_from(cls: Type[Self], buffer: bytearray) -> Self:
        code_and_parameters = buffer.split(b':')
        parameters = (
            code_and_parameters[1] if len(code_and_parameters) > 1 else bytearray()
        )
        return cls(
            code=code_and_parameters[0].decode(),
            parameters=at.parse_parameters(parameters),
        )


@dataclasses.dataclass
class AtCommand:
    class SubCode(str, enum.Enum):
        NONE = ''
        SET = '='
        TEST = '=?'
        READ = '?'

    code: str
    sub_code: SubCode
    parameters: list

    _PARSE_PATTERN: ClassVar[re.Pattern] = re.compile(
        r'AT\+(?P<code>[A-Z]+)(?P<sub_code>=\?|=|\?)?(?P<parameters>.*)'
    )

    @classmethod
    def parse_from(cls: Type[Self], buffer: bytearray) -> Self:
        if not (match := cls._PARSE_PATTERN.fullmatch(buffer.decode())):
            if buffer.startswith(b'ATA'):
                return cls(code='A', sub_code=AtCommand.SubCode.NONE, parameters=[])
            if buffer.startswith(b'ATD'):
                return cls(
                    code='D', sub_code=AtCommand.SubCode.NONE, parameters=[buffer[3:]]
                )
            raise HfpProtocolError('Invalid command')

        parameters = []
        if parameters_text := match.group('parameters'):
            parameters = at.parse_parameters(parameters_text.encode())

        return cls(
            code=match.group('code'),
            sub_code=AtCommand.SubCode(match.group('sub_code') or ''),
            parameters=parameters,
        )


@dataclasses.dataclass
class AgIndicatorState:
    """State wrapper of AG indicator.

    Attributes:
        indicator: Indicator of this indicator state.
        supported_values: Supported values of this indicator.
        current_status: Current status of this indicator.
        index: (HF only) Index of this indicator.
        enabled: (AG only) Whether this indicator is enabled to report.
        on_test_text: Text message reported in AT+CIND=? of this indicator.
    """

    indicator: AgIndicator
    supported_values: Set[int]
    current_status: int
    index: Optional[int] = None
    enabled: bool = True

    @property
    def on_test_text(self) -> str:
        min_value = min(self.supported_values)
        max_value = max(self.supported_values)
        if len(self.supported_values) == (max_value - min_value + 1):
            supported_values_text = f'({min_value}-{max_value})'
        else:
            supported_values_text = (
                f'({",".join(str(v) for v in self.supported_values)})'
            )
        return f'(\"{self.indicator.value}\",{supported_values_text})'

    @classmethod
    def call(cls: Type[Self]) -> Self:
        """Default call indicator state."""
        return cls(
            indicator=AgIndicator.CALL, supported_values={0, 1}, current_status=0
        )

    @classmethod
    def callsetup(cls: Type[Self]) -> Self:
        """Default callsetup indicator state."""
        return cls(
            indicator=AgIndicator.CALL_SETUP,
            supported_values={0, 1, 2, 3},
            current_status=0,
        )

    @classmethod
    def callheld(cls: Type[Self]) -> Self:
        """Default call indicator state."""
        return cls(
            indicator=AgIndicator.CALL_HELD,
            supported_values={0, 1, 2},
            current_status=0,
        )

    @classmethod
    def service(cls: Type[Self]) -> Self:
        """Default service indicator state."""
        return cls(
            indicator=AgIndicator.SERVICE, supported_values={0, 1}, current_status=0
        )

    @classmethod
    def signal(cls: Type[Self]) -> Self:
        """Default signal indicator state."""
        return cls(
            indicator=AgIndicator.SIGNAL,
            supported_values={0, 1, 2, 3, 4, 5},
            current_status=0,
        )

    @classmethod
    def roam(cls: Type[Self]) -> Self:
        """Default roam indicator state."""
        return cls(
            indicator=AgIndicator.CALL, supported_values={0, 1}, current_status=0
        )

    @classmethod
    def battchg(cls: Type[Self]) -> Self:
        """Default battery charge indicator state."""
        return cls(
            indicator=AgIndicator.BATTERY_CHARGE,
            supported_values={0, 1, 2, 3, 4, 5},
            current_status=0,
        )


@dataclasses.dataclass
class HfIndicatorState:
    """State wrapper of HF indicator.

    Attributes:
        indicator: Indicator of this indicator state.
        supported: Whether this indicator is supported.
        enabled: Whether this indicator is enabled.
        current_status: Current (last-reported) status value of this indicaotr.
    """

    indicator: HfIndicator
    supported: bool = False
    enabled: bool = False
    current_status: int = 0


class HfProtocol(pyee.EventEmitter):
    """
    Implementation for the Hands-Free side of the Hands-Free profile.

    Reference specification Hands-Free Profile v1.8.

    Emitted events:
        codec_negotiation: When codec is renegotiated, notify the new codec.
            Args:
                active_codec: AudioCodec
        ag_indicator: When AG update their indicators, notify the new state.
            Args:
                ag_indicator: AgIndicator
        speaker_volume: Emitted when AG update speaker volume autonomously.
            Args:
                volume: Int
        microphone_volume: Emitted when AG update microphone volume autonomously.
            Args:
                volume: Int
        microphone_volume: Emitted when AG sends a ringtone request.
            Args:
                None
        cli_notification: Emitted when notify the call metadata on line.
            Args:
                cli_notification: CallLineIdentification
        voice_recognition: Emitted when AG starts voice recognition autonomously.
            Args:
                vrec: VoiceRecognitionState
    """

    class HfLoopTermination(HfpProtocolError):
        """Termination signal for run() loop."""

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
        unsolicited_queue: asyncio.Queue[Optional[AtResponse]]
    else:
        response_queue: asyncio.Queue
        unsolicited_queue: asyncio.Queue
    read_buffer: bytearray
    active_codec: AudioCodec

    def __init__(
        self,
        dlc: rfcomm.DLC,
        configuration: HfConfiguration,
    ) -> None:
        super().__init__()

        # Configure internal state.
        self.dlc = dlc
        self.command_lock = asyncio.Lock()
        self.response_queue = asyncio.Queue()
        self.unsolicited_queue = asyncio.Queue()
        self.read_buffer = bytearray()
        self.active_codec = AudioCodec.CVSD
        self._slc_initialized = False

        # Build local features.
        self.supported_hf_features = sum(configuration.supported_hf_features)
        self.supported_audio_codecs = configuration.supported_audio_codecs

        self.hf_indicators = {
            indicator: HfIndicatorState(indicator=indicator)
            for indicator in configuration.supported_hf_indicators
        }

        # Clear remote features.
        self.supported_ag_features = 0
        self.supported_ag_call_hold_operations = []
        self.ag_indicators = []

        # Bind the AT reader to the RFCOMM channel.
        self.dlc.sink = self._read_at
        # Stop the run() loop when L2CAP is closed.
        self.dlc.multiplexer.l2cap_channel.on(
            'close', lambda: self.unsolicited_queue.put_nowait(None)
        )

    def supports_hf_feature(self, feature: HfFeature) -> bool:
        return (self.supported_hf_features & feature) != 0

    def supports_ag_feature(self, feature: AgFeature) -> bool:
        return (self.supported_ag_features & feature) != 0

    def _read_at(self, data: bytes):
        """
        Reads AT messages from the RFCOMM channel.

        Enqueues AT commands, responses, unsolicited responses to their respective queues, and set the corresponding event.
        """
        # Append to the read buffer.
        self.read_buffer.extend(data)

        # Locate header and trailer.
        header = self.read_buffer.find(b'\r\n')
        trailer = self.read_buffer.find(b'\r\n', header + 2)
        if header == -1 or trailer == -1:
            return

        # Isolate the AT response code and parameters.
        raw_response = self.read_buffer[header + 2 : trailer]
        response = AtResponse.parse_from(raw_response)
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

    async def execute_command(
        self,
        cmd: str,
        timeout: float = 1.0,
        response_type: AtResponseType = AtResponseType.NONE,
    ) -> Union[None, AtResponse, List[AtResponse]]:
        """
        Sends an AT command and wait for the peer response.
        Wait for the AT responses sent by the peer, to the status code.

        Args:
            cmd: the AT command in string to execute.
            timeout: timeout in float seconds.
            response_type: type of response.

        Raises:
            asyncio.TimeoutError: the status is not received after a timeout (default 1 second).
            ProtocolError: the status is not OK.
        """
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

    async def initiate_slc(self):
        """4.2.1 Service Level Connection Initialization."""

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
            codecs = [str(c.value) for c in self.supported_audio_codecs]
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
            description = AgIndicator(indicator[0].decode())
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
        ) and self.supports_ag_feature(AgFeature.THREE_WAY_CALLING):
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
                CallHoldOperation(operation.decode())
                for operation in response.parameters[0]
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
            indicators = [str(i.value) for i in self.hf_indicators]
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
        self._slc_initialized = True

    async def setup_audio_connection(self):
        """4.11.2 Audio Connection Setup by HF."""

        # When the HF triggers the establishment of the Codec Connection it
        # shall send the AT command AT+BCC to the AG. The AG shall respond with
        # OK if it will start the Codec Connection procedure, and with ERROR
        # if it cannot start the Codec Connection procedure.
        await self.execute_command("AT+BCC")

    async def setup_codec_connection(self, codec_id: int):
        """4.11.3 Codec Connection Setup."""
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
        self.active_codec = AudioCodec(codec_id)
        self.emit('codec_negotiation', self.active_codec)

        logger.info("codec connection setup completed")

    async def answer_incoming_call(self):
        """4.13.1 Answer Incoming Call from the HF - In-Band Ringing."""
        # The user accepts the incoming voice call by using the proper means
        # provided by the HF. The HF shall then send the ATA command
        # (see Section 4.34) to the AG. The AG shall then begin the procedure for
        # accepting the incoming call.
        await self.execute_command("ATA")

    async def reject_incoming_call(self):
        """4.14.1 Reject an Incoming Call from the HF."""
        # The user rejects the incoming call by using the User Interface on the
        # Hands-Free unit. The HF shall then send the AT+CHUP command
        # (see Section 4.34) to the AG. This may happen at any time during the
        # procedures described in Sections 4.13.1 and 4.13.2.
        await self.execute_command("AT+CHUP")

    async def terminate_call(self):
        """4.15.1 Terminate a Call Process from the HF."""
        # The user may abort the ongoing call process using whatever means
        # provided by the Hands-Free unit. The HF shall send AT+CHUP command
        # (see Section 4.34) to the AG, and the AG shall then start the
        # procedure to terminate or interrupt the current call procedure.
        # The AG shall then send the OK indication followed by the +CIEV result
        # code, with the value indicating (call=0).
        await self.execute_command("AT+CHUP")

    async def query_current_calls(self) -> List[CallInfo]:
        """4.32.1 Query List of Current Calls in AG.

        Return:
            List of current calls in AG.
        """
        responses = await self.execute_command(
            "AT+CLCC", response_type=AtResponseType.MULTIPLE
        )
        assert isinstance(responses, list)

        calls = []
        for response in responses:
            call_info = CallInfo(
                index=int(response.parameters[0]),
                direction=CallInfoDirection(int(response.parameters[1])),
                status=CallInfoStatus(int(response.parameters[2])),
                mode=CallInfoMode(int(response.parameters[3])),
                multi_party=CallInfoMultiParty(int(response.parameters[4])),
            )
            if len(response.parameters) >= 6:
                call_info.number = response.parameters[5].decode()
            if len(response.parameters) >= 7:
                call_info.type = int(response.parameters[6])
            calls.append(call_info)
        return calls

    async def update_ag_indicator(self, index: int, value: int):
        # CIEV is in 1-index, while ag_indicators is in 0-index.
        ag_indicator = self.ag_indicators[index - 1]
        ag_indicator.current_status = value
        self.emit('ag_indicator', ag_indicator)
        logger.info(f"AG indicator updated: {ag_indicator.indicator}, {value}")

    async def handle_unsolicited(self):
        """Handle unsolicited result codes sent by the audio gateway."""
        result = await self.unsolicited_queue.get()
        if not result:
            raise HfProtocol.HfLoopTermination()
        if result.code == "+BCS":
            await self.setup_codec_connection(int(result.parameters[0]))
        elif result.code == "+CIEV":
            await self.update_ag_indicator(
                int(result.parameters[0]), int(result.parameters[1])
            )
        elif result.code == "+VGS":
            self.emit('speaker_volume', int(result.parameters[0]))
        elif result.code == "+VGM":
            self.emit('microphone_volume', int(result.parameters[0]))
        elif result.code == "RING":
            self.emit('ring')
        elif result.code == "+CLIP":
            self.emit(
                'cli_notification', CallLineIdentification.parse_from(result.parameters)
            )
        elif result.code == "+BVRA":
            # TODO: Support Enhanced Voice Recognition.
            self.emit(
                'voice_recognition', VoiceRecognitionState(int(result.parameters[0]))
            )
        else:
            logging.info(f"unhandled unsolicited response {result.code}")

    async def run(self):
        """
        Main routine for the Hands-Free side of the HFP protocol.

        Initiates the service level connection then loops handling unsolicited AG responses.
        """

        try:
            if not self._slc_initialized:
                await self.initiate_slc()
            while True:
                await self.handle_unsolicited()
        except HfProtocol.HfLoopTermination:
            logger.info('Loop terminated')
        except Exception:
            logger.error("HFP-HF protocol failed with the following error:")
            logger.error(traceback.format_exc())


class AgProtocol(pyee.EventEmitter):
    """
    Implementation for the Audio-Gateway side of the Hands-Free profile.

    Reference specification Hands-Free Profile v1.8.

    Emitted events:
        slc_complete: Emit when SLC procedure is completed.
        codec_negotiation: When codec is renegotiated, notify the new codec.
            Args:
                active_codec: AudioCodec
        hf_indicator: When HF update their indicators, notify the new state.
            Args:
                hf_indicator: HfIndicatorState
        codec_connection_request: Emit when HF sends AT+BCC to request codec connection.
        answer: Emit when HF sends ATA to answer phone call.
        hang_up: Emit when HF sends AT+CHUP to hang up phone call.
        dial: Emit when HF sends ATD to dial phone call.
        voice_recognition: Emit when HF requests voice recognition state.
            Args:
                vrec: VoiceRecognitionState
        call_hold: Emit when HF requests call hold operation.
            Args:
                operation: CallHoldOperation
                call_index: Optional[int]
        speaker_volume: Emitted when AG update speaker volume autonomously.
            Args:
                volume: Int
        microphone_volume: Emitted when AG update microphone volume autonomously.
            Args:
                volume: Int
    """

    supported_hf_features: int
    supported_hf_indicators: Set[HfIndicator]
    supported_audio_codecs: List[AudioCodec]

    supported_ag_features: int
    supported_ag_call_hold_operations: List[CallHoldOperation]

    ag_indicators: List[AgIndicatorState]
    hf_indicators: collections.OrderedDict[HfIndicator, HfIndicatorState]

    dlc: rfcomm.DLC

    read_buffer: bytearray
    active_codec: AudioCodec
    calls: List[CallInfo]

    indicator_report_enabled: bool
    inband_ringtone_enabled: bool
    cme_error_enabled: bool
    cli_notification_enabled: bool
    call_waiting_enabled: bool
    _remained_slc_setup_features: Set[HfFeature]

    def __init__(self, dlc: rfcomm.DLC, configuration: AgConfiguration) -> None:
        super().__init__()

        # Configure internal state.
        self.dlc = dlc
        self.read_buffer = bytearray()
        self.active_codec = AudioCodec.CVSD
        self.calls = []

        # Build local features.
        self.supported_ag_features = sum(configuration.supported_ag_features)
        self.supported_ag_call_hold_operations = list(
            configuration.supported_ag_call_hold_operations
        )
        self.ag_indicators = list(configuration.supported_ag_indicators)
        self.supported_hf_indicators = set(configuration.supported_hf_indicators)
        self.inband_ringtone_enabled = True
        self._remained_slc_setup_features = set()

        # Clear remote features.
        self.supported_hf_features = 0
        self.supported_audio_codecs = []
        self.indicator_report_enabled = False
        self.cme_error_enabled = False
        self.cli_notification_enabled = False
        self.call_waiting_enabled = False

        self.hf_indicators = collections.OrderedDict()

        # Bind the AT reader to the RFCOMM channel.
        self.dlc.sink = self._read_at

    def supports_hf_feature(self, feature: HfFeature) -> bool:
        return (self.supported_hf_features & feature) != 0

    def supports_ag_feature(self, feature: AgFeature) -> bool:
        return (self.supported_ag_features & feature) != 0

    def _read_at(self, data: bytes):
        """
        Reads AT messages from the RFCOMM channel.
        """
        # Append to the read buffer.
        self.read_buffer.extend(data)

        # Locate the trailer.
        trailer = self.read_buffer.find(b'\r')
        if trailer == -1:
            return

        # Isolate the AT response code and parameters.
        raw_command = self.read_buffer[:trailer]
        command = AtCommand.parse_from(raw_command)
        logger.debug(f"<<< {raw_command.decode()}")

        # Consume the response bytes.
        self.read_buffer = self.read_buffer[trailer + 1 :]

        if command.sub_code == AtCommand.SubCode.TEST:
            handler_name = f'_on_{command.code.lower()}_test'
        elif command.sub_code == AtCommand.SubCode.READ:
            handler_name = f'_on_{command.code.lower()}_read'
        else:
            handler_name = f'_on_{command.code.lower()}'

        if handler := getattr(self, handler_name, None):
            handler(*command.parameters)
        else:
            logger.warning('Handler %s not found', handler_name)
            self.send_response('ERROR')

    def send_response(self, response: str) -> None:
        """Sends an AT response."""
        self.dlc.write(f'\r\n{response}\r\n')

    def send_cme_error(self, error_code: CmeError) -> None:
        """Sends an CME ERROR response.

        If CME Error is not enabled by HF, sends ERROR instead.
        """
        if self.cme_error_enabled:
            self.send_response(f'+CME ERROR: {error_code.value}')
        else:
            self.send_error()

    def send_ok(self) -> None:
        """Sends an OK response."""
        self.send_response('OK')

    def send_error(self) -> None:
        """Sends an ERROR response."""
        self.send_response('ERROR')

    def set_inband_ringtone_enabled(self, enabled: bool) -> None:
        """Enables or disables in-band ringtone."""

        self.inband_ringtone_enabled = enabled
        self.send_response(f'+BSIR: {1 if enabled else 0}')

    def set_speaker_volume(self, level: int) -> None:
        """Reports speaker volume."""

        self.send_response(f'+VGS: {level}')

    def set_microphone_volume(self, level: int) -> None:
        """Reports microphone volume."""

        self.send_response(f'+VGM: {level}')

    def send_ring(self) -> None:
        """Sends RING command to trigger ringtone on HF."""

        self.send_response('RING')

    def update_ag_indicator(self, indicator: AgIndicator, value: int) -> None:
        """Updates AG indicator.

        Args:
            indicator: Name of the indicator.
            value: new value of the indicator.
        """

        search_result = next(
            (
                (index, state)
                for index, state in enumerate(self.ag_indicators)
                if state.indicator == indicator
            ),
            None,
        )
        if not search_result:
            raise KeyError(f'{indicator} is not supported.')

        index, indicator_state = search_result
        if not self.indicator_report_enabled:
            logger.warning('AG indicator report is disabled')
        if not indicator_state.enabled:
            logger.warning(f'AG indicator {indicator} is disabled')

        indicator_state.current_status = value
        self.send_response(f'+CIEV: {index+1},{value}')

    async def negotiate_codec(self, codec: AudioCodec) -> None:
        """Starts codec negotiation."""

        if not self.supports_ag_feature(AgFeature.CODEC_NEGOTIATION):
            logger.warning('Local does not support Codec Negotiation')
        if not self.supports_hf_feature(HfFeature.CODEC_NEGOTIATION):
            logger.warning('Peer does not support Codec Negotiation')
        if codec not in self.supported_audio_codecs:
            logger.warning(f'{codec} is not supported by peer')

        at_bcs_future = asyncio.get_running_loop().create_future()
        self.once('codec_negotiation', at_bcs_future.set_result)
        self.send_response(f'+BCS: {codec.value}')
        if (new_codec := await at_bcs_future) != codec:
            raise HfpProtocolError(f'Expect codec: {codec}, but get {new_codec}')

    def send_cli_notification(self, cli: CallLineIdentification) -> None:
        """Sends +CLIP CLI notification."""

        if not self.cli_notification_enabled:
            logger.warning('Try to send CLIP while CLI notification is not enabled')

        self.send_response(f'+CLIP: {cli.to_clip_string()}')

    def _check_remained_slc_commands(self) -> None:
        if not self._remained_slc_setup_features:
            self.emit('slc_complete')

    def _on_brsf(self, hf_features: bytes) -> None:
        self.supported_hf_features = int(hf_features)
        self.send_response(f'+BRSF: {self.supported_ag_features}')
        self.send_ok()

        if self.supports_hf_feature(
            HfFeature.HF_INDICATORS
        ) and self.supports_ag_feature(AgFeature.HF_INDICATORS):
            self._remained_slc_setup_features.add(HfFeature.HF_INDICATORS)

        if self.supports_hf_feature(
            HfFeature.THREE_WAY_CALLING
        ) and self.supports_ag_feature(AgFeature.THREE_WAY_CALLING):
            self._remained_slc_setup_features.add(HfFeature.THREE_WAY_CALLING)

    def _on_bac(self, *args) -> None:
        self.supported_audio_codecs = [AudioCodec(int(value)) for value in args]
        self.send_ok()

    def _on_bcs(self, codec: bytes) -> None:
        self.active_codec = AudioCodec(int(codec))
        self.send_ok()
        self.emit('codec_negotiation', self.active_codec)

    def _on_bvra(self, vrec: bytes) -> None:
        self.send_ok()
        self.emit('voice_recognition', VoiceRecognitionState(int(vrec)))

    def _on_chld(self, operation_code: bytes) -> None:
        call_index: Optional[int] = None
        if len(operation_code) > 1:
            call_index = int(operation_code[1:])
            operation_code = operation_code[:1] + b'x'
        try:
            operation = CallHoldOperation(operation_code.decode())
        except:
            logger.error(f'Invalid operation: {operation_code.decode()}')
            self.send_cme_error(CmeError.OPERATION_NOT_SUPPORTED)
            return

        if operation not in self.supported_ag_call_hold_operations:
            logger.error(f'Unsupported operation: {operation_code.decode()}')
            self.send_cme_error(CmeError.OPERATION_NOT_SUPPORTED)

        if call_index is not None and not any(
            call.index == call_index for call in self.calls
        ):
            logger.error(f'No matching call {call_index}')
            self.send_cme_error(CmeError.INVALID_INDEX)

        # Real three-way calls have more complicated situations, but this is not a popular issue - let users to handle the remaining :)

        self.send_ok()
        self.emit('call_hold', operation, call_index)

    def _on_chld_test(self) -> None:
        if not self.supports_ag_feature(AgFeature.THREE_WAY_CALLING):
            self.send_error()
            return

        self.send_response(
            '+CHLD: ({})'.format(
                ','.join(
                    operation.value
                    for operation in self.supported_ag_call_hold_operations
                )
            )
        )
        self.send_ok()
        self._remained_slc_setup_features.remove(HfFeature.THREE_WAY_CALLING)
        self._check_remained_slc_commands()

    def _on_cind_test(self) -> None:
        if not self.ag_indicators:
            self.send_cme_error(CmeError.NOT_FOUND)
            return

        indicator_list_str = ",".join(
            indicator.on_test_text for indicator in self.ag_indicators
        )
        self.send_response(f'+CIND: {indicator_list_str}')
        self.send_ok()

    def _on_cind_read(self) -> None:
        if not self.ag_indicators:
            self.send_cme_error(CmeError.NOT_FOUND)
            return

        indicator_list_str = ",".join(
            str(indicator.current_status) for indicator in self.ag_indicators
        )
        self.send_response(f'+CIND: {indicator_list_str}')
        self.send_ok()

        self._check_remained_slc_commands()

    def _on_cmer(
        self,
        mode: bytes,
        keypad: Optional[bytes] = None,
        display: Optional[bytes] = None,
        indicator: bytes = b'',
    ) -> None:
        if (
            int(mode) != 3
            or (keypad and int(keypad))
            or (display and int(display))
            or int(indicator) not in (0, 1)
        ):
            logger.error(
                f'Unexpected values: mode={mode!r}, keypad={keypad!r}, '
                f'display={display!r}, indicator={indicator!r}'
            )
            self.send_cme_error(CmeError.INVALID_INDEX)

        self.indicator_report_enabled = bool(int(indicator))
        self.send_ok()

    def _on_cmee(self, enabled: bytes) -> None:
        self.cme_error_enabled = bool(int(enabled))
        self.send_ok()

    def _on_ccwa(self, enabled: bytes) -> None:
        self.call_waiting_enabled = bool(int(enabled))
        self.send_ok()

    def _on_bind(self, *args) -> None:
        if not self.supports_ag_feature(AgFeature.HF_INDICATORS):
            self.send_error()
            return

        peer_supported_indicators = set(
            HfIndicator(int(indicator)) for indicator in args
        )
        self.hf_indicators = collections.OrderedDict(
            {
                indicator: HfIndicatorState(indicator=indicator)
                for indicator in self.supported_hf_indicators.intersection(
                    peer_supported_indicators
                )
            }
        )
        self.send_ok()

    def _on_bind_test(self) -> None:
        if not self.supports_ag_feature(AgFeature.HF_INDICATORS):
            self.send_error()
            return

        hf_indicator_list_str = ",".join(
            str(indicator.value) for indicator in self.supported_hf_indicators
        )
        self.send_response(f'+BIND: ({hf_indicator_list_str})')
        self.send_ok()

    def _on_bind_read(self) -> None:
        if not self.supports_ag_feature(AgFeature.HF_INDICATORS):
            self.send_error()
            return

        for indicator in self.hf_indicators:
            self.send_response(f'+BIND: {indicator.value},1')

        self.send_ok()

        self._remained_slc_setup_features.remove(HfFeature.HF_INDICATORS)
        self._check_remained_slc_commands()

    def _on_biev(self, index_bytes: bytes, value_bytes: bytes) -> None:
        if not self.supports_ag_feature(AgFeature.HF_INDICATORS):
            self.send_error()
            return

        index = HfIndicator(int(index_bytes))
        if index not in self.hf_indicators:
            self.send_error()
            return

        self.hf_indicators[index].current_status = int(value_bytes)
        self.emit('hf_indicator', self.hf_indicators[index])
        self.send_ok()

    def _on_bia(self, *args) -> None:
        for enabled, state in zip(args, self.ag_indicators):
            state.enabled = bool(int(enabled))
        self.send_ok()

    def _on_bcc(self) -> None:
        self.emit('codec_connection_request')
        self.send_ok()

    def _on_a(self) -> None:
        """ATA handler."""
        self.emit('answer')
        self.send_ok()

    def _on_d(self, number: bytes) -> None:
        """ATD handler."""
        self.emit('dial', number.decode())
        self.send_ok()

    def _on_chup(self) -> None:
        self.emit('hang_up')
        self.send_ok()

    def _on_clcc(self) -> None:
        for call in self.calls:
            number_text = f',\"{call.number}\"' if call.number is not None else ''
            type_text = f',{call.type}' if call.type is not None else ''
            response = (
                f'+CLCC: {call.index}'
                f',{call.direction.value}'
                f',{call.status.value}'
                f',{call.mode.value}'
                f',{call.multi_party.value}'
                f'{number_text}'
                f'{type_text}'
            )
            self.send_response(response)
        self.send_ok()

    def _on_clip(self, enabled: bytes) -> None:
        if not self.supports_hf_feature(HfFeature.CLI_PRESENTATION_CAPABILITY):
            logger.error('Remote doesn not support CLI but sends AT+CLIP')
        self.cli_notification_enabled = True if enabled == b'1' else False
        self.send_ok()

    def _on_vgs(self, level: bytes) -> None:
        self.emit('speaker_volume', int(level))
        self.send_ok()

    def _on_vgm(self, level: bytes) -> None:
        self.emit('microphone_volume', int(level))
        self.send_ok()


# -----------------------------------------------------------------------------
# Normative SDP definitions
# -----------------------------------------------------------------------------


class ProfileVersion(enum.IntEnum):
    """
    Profile version (normative).

    Hands-Free Profile v1.8, 5.3 SDP Interoperability Requirements.
    """

    V1_5 = 0x0105
    V1_6 = 0x0106
    V1_7 = 0x0107
    V1_8 = 0x0108
    V1_9 = 0x0109


class HfSdpFeature(enum.IntFlag):
    """
    HF supported features (normative).

    Hands-Free Profile v1.8, 5.3 SDP Interoperability Requirements.
    """

    EC_NR = 0x01  # Echo Cancel & Noise reduction
    THREE_WAY_CALLING = 0x02
    CLI_PRESENTATION_CAPABILITY = 0x04
    VOICE_RECOGNITION_ACTIVATION = 0x08
    REMOTE_VOLUME_CONTROL = 0x10
    WIDE_BAND = 0x20  # Wide band speech
    ENHANCED_VOICE_RECOGNITION_STATUS = 0x40
    VOICE_RECOGNITION_TEST = 0x80


class AgSdpFeature(enum.IntFlag):
    """
    AG supported features (normative).

    Hands-Free Profile v1.8, 5.3 SDP Interoperability Requirements.
    """

    THREE_WAY_CALLING = 0x01
    EC_NR = 0x02  # Echo Cancel & Noise reduction
    VOICE_RECOGNITION_FUNCTION = 0x04
    IN_BAND_RING_TONE_CAPABILITY = 0x08
    VOICE_TAG = 0x10  # Attach a number to voice tag
    WIDE_BAND = 0x20  # Wide band speech
    ENHANCED_VOICE_RECOGNITION_STATUS = 0x40
    VOICE_RECOGNITION_TEST = 0x80


def make_hf_sdp_records(
    service_record_handle: int,
    rfcomm_channel: int,
    configuration: HfConfiguration,
    version: ProfileVersion = ProfileVersion.V1_8,
) -> List[sdp.ServiceAttribute]:
    """
    Generates the SDP record for HFP Hands-Free support.

    The record exposes the features supported in the input configuration,
    and the allocated RFCOMM channel.
    """

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
        sdp.ServiceAttribute(
            sdp.SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            sdp.DataElement.unsigned_integer_32(service_record_handle),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.uuid(BT_HANDSFREE_SERVICE),
                    sdp.DataElement.uuid(BT_GENERIC_AUDIO_SERVICE),
                ]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.sequence(
                        [sdp.DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]
                    ),
                    sdp.DataElement.sequence(
                        [
                            sdp.DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                            sdp.DataElement.unsigned_integer_8(rfcomm_channel),
                        ]
                    ),
                ]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.sequence(
                        [
                            sdp.DataElement.uuid(BT_HANDSFREE_SERVICE),
                            sdp.DataElement.unsigned_integer_16(version),
                        ]
                    )
                ]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            sdp.DataElement.unsigned_integer_16(hf_supported_features),
        ),
    ]


def make_ag_sdp_records(
    service_record_handle: int,
    rfcomm_channel: int,
    configuration: AgConfiguration,
    version: ProfileVersion = ProfileVersion.V1_8,
) -> List[sdp.ServiceAttribute]:
    """
    Generates the SDP record for HFP Audio-Gateway support.

    The record exposes the features supported in the input configuration,
    and the allocated RFCOMM channel.
    """

    ag_supported_features = 0

    if AgFeature.EC_NR in configuration.supported_ag_features:
        ag_supported_features |= AgSdpFeature.EC_NR
    if AgFeature.THREE_WAY_CALLING in configuration.supported_ag_features:
        ag_supported_features |= AgSdpFeature.THREE_WAY_CALLING
    if (
        AgFeature.ENHANCED_VOICE_RECOGNITION_STATUS
        in configuration.supported_ag_features
    ):
        ag_supported_features |= AgSdpFeature.ENHANCED_VOICE_RECOGNITION_STATUS
    if AgFeature.VOICE_RECOGNITION_TEST in configuration.supported_ag_features:
        ag_supported_features |= AgSdpFeature.VOICE_RECOGNITION_TEST
    if AgFeature.IN_BAND_RING_TONE_CAPABILITY in configuration.supported_ag_features:
        ag_supported_features |= AgSdpFeature.IN_BAND_RING_TONE_CAPABILITY
    if AgFeature.VOICE_RECOGNITION_FUNCTION in configuration.supported_ag_features:
        ag_supported_features |= AgSdpFeature.VOICE_RECOGNITION_FUNCTION
    if AudioCodec.MSBC in configuration.supported_audio_codecs:
        ag_supported_features |= AgSdpFeature.WIDE_BAND

    return [
        sdp.ServiceAttribute(
            sdp.SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            sdp.DataElement.unsigned_integer_32(service_record_handle),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.uuid(BT_HANDSFREE_AUDIO_GATEWAY_SERVICE),
                    sdp.DataElement.uuid(BT_GENERIC_AUDIO_SERVICE),
                ]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.sequence(
                        [sdp.DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]
                    ),
                    sdp.DataElement.sequence(
                        [
                            sdp.DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                            sdp.DataElement.unsigned_integer_8(rfcomm_channel),
                        ]
                    ),
                ]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            sdp.DataElement.sequence(
                [
                    sdp.DataElement.sequence(
                        [
                            sdp.DataElement.uuid(BT_HANDSFREE_AUDIO_GATEWAY_SERVICE),
                            sdp.DataElement.unsigned_integer_16(version),
                        ]
                    )
                ]
            ),
        ),
        sdp.ServiceAttribute(
            sdp.SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            sdp.DataElement.unsigned_integer_16(ag_supported_features),
        ),
    ]


async def find_hf_sdp_record(
    connection: device.Connection,
) -> Optional[Tuple[int, ProfileVersion, HfSdpFeature]]:
    """Searches a Hands-Free SDP record from remote device.

    Args:
        connection: ACL connection to make SDP search.

    Returns:
        Tuple of (<RFCOMM channel>, <Profile Version>, <HF SDP features>)
    """
    async with sdp.Client(connection) as sdp_client:
        search_result = await sdp_client.search_attributes(
            uuids=[BT_HANDSFREE_SERVICE],
            attribute_ids=[
                sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
                sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            ],
        )
        for attribute_lists in search_result:
            channel: Optional[int] = None
            version: Optional[ProfileVersion] = None
            features: Optional[HfSdpFeature] = None
            for attribute in attribute_lists:
                # The layout is [[L2CAP_PROTOCOL], [RFCOMM_PROTOCOL, RFCOMM_CHANNEL]].
                if attribute.id == sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                    protocol_descriptor_list = attribute.value.value
                    channel = protocol_descriptor_list[1].value[1].value
                elif (
                    attribute.id
                    == sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID
                ):
                    profile_descriptor_list = attribute.value.value
                    version = ProfileVersion(profile_descriptor_list[0].value[1].value)
                elif attribute.id == sdp.SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID:
                    features = HfSdpFeature(attribute.value.value)
                elif attribute.id == sdp.SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID:
                    class_id_list = attribute.value.value
                    uuid = class_id_list[0].value
                    # AG record may also contain HF UUID in its profile descriptor list.
                    # If found, skip this record.
                    if uuid == BT_HANDSFREE_AUDIO_GATEWAY_SERVICE:
                        channel, version, features = (None, None, None)
                        break

            if channel is not None and version is not None and features is not None:
                return (channel, version, features)
    return None


async def find_ag_sdp_record(
    connection: device.Connection,
) -> Optional[Tuple[int, ProfileVersion, AgSdpFeature]]:
    """Searches an Audio-Gateway SDP record from remote device.

    Args:
        connection: ACL connection to make SDP search.

    Returns:
        Tuple of (<RFCOMM channel>, <Profile Version>, <AG SDP features>)
    """
    async with sdp.Client(connection) as sdp_client:
        search_result = await sdp_client.search_attributes(
            uuids=[BT_HANDSFREE_AUDIO_GATEWAY_SERVICE],
            attribute_ids=[
                sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
                sdp.SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID,
            ],
        )
        for attribute_lists in search_result:
            channel: Optional[int] = None
            version: Optional[ProfileVersion] = None
            features: Optional[AgSdpFeature] = None
            for attribute in attribute_lists:
                # The layout is [[L2CAP_PROTOCOL], [RFCOMM_PROTOCOL, RFCOMM_CHANNEL]].
                if attribute.id == sdp.SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID:
                    protocol_descriptor_list = attribute.value.value
                    channel = protocol_descriptor_list[1].value[1].value
                elif (
                    attribute.id
                    == sdp.SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID
                ):
                    profile_descriptor_list = attribute.value.value
                    version = ProfileVersion(profile_descriptor_list[0].value[1].value)
                elif attribute.id == sdp.SDP_SUPPORTED_FEATURES_ATTRIBUTE_ID:
                    features = AgSdpFeature(attribute.value.value)
            if not channel or not version or features is None:
                logger.warning(f"Bad result {attribute_lists}.")
                return None
            return (channel, version, features)
    return None


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
    transmit_coding_format: CodingFormat
    receive_coding_format: CodingFormat
    packet_type: HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType
    retransmission_effort: (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort
    )
    max_latency: int

    # Common
    input_coding_format: CodingFormat = CodingFormat(CodecID.LINEAR_PCM)
    output_coding_format: CodingFormat = CodingFormat(CodecID.LINEAR_PCM)
    input_coded_data_size: int = 16
    output_coded_data_size: int = 16
    input_pcm_data_format: (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PcmDataFormat
    ) = HCI_Enhanced_Setup_Synchronous_Connection_Command.PcmDataFormat.TWOS_COMPLEMENT
    output_pcm_data_format: (
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PcmDataFormat
    ) = HCI_Enhanced_Setup_Synchronous_Connection_Command.PcmDataFormat.TWOS_COMPLEMENT
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

    def asdict(self) -> Dict[str, Any]:
        # dataclasses.asdict() will recursively deep-copy the entire object,
        # which is expensive and breaks CodingFormat object, so let it simply copy here.
        return self.__dict__


_ESCO_PARAMETERS_CVSD_D0 = EscoParameters(
    transmit_coding_format=CodingFormat(CodecID.CVSD),
    receive_coding_format=CodingFormat(CodecID.CVSD),
    max_latency=0xFFFF,
    packet_type=HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.HV1,
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.NO_RETRANSMISSION,
)

_ESCO_PARAMETERS_CVSD_D1 = EscoParameters(
    transmit_coding_format=CodingFormat(CodecID.CVSD),
    receive_coding_format=CodingFormat(CodecID.CVSD),
    max_latency=0xFFFF,
    packet_type=HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.HV3,
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.NO_RETRANSMISSION,
)

_ESCO_PARAMETERS_CVSD_S1 = EscoParameters(
    transmit_coding_format=CodingFormat(CodecID.CVSD),
    receive_coding_format=CodingFormat(CodecID.CVSD),
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
    transmit_coding_format=CodingFormat(CodecID.CVSD),
    receive_coding_format=CodingFormat(CodecID.CVSD),
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
    transmit_coding_format=CodingFormat(CodecID.CVSD),
    receive_coding_format=CodingFormat(CodecID.CVSD),
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
    transmit_coding_format=CodingFormat(CodecID.CVSD),
    receive_coding_format=CodingFormat(CodecID.CVSD),
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
    transmit_coding_format=CodingFormat(CodecID.MSBC),
    receive_coding_format=CodingFormat(CodecID.MSBC),
    max_latency=0x0008,
    packet_type=(
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV5
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV5
    ),
    input_bandwidth=32000,
    output_bandwidth=32000,
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.OPTIMIZE_FOR_QUALITY,
)

_ESCO_PARAMETERS_MSBC_T2 = EscoParameters(
    transmit_coding_format=CodingFormat(CodecID.MSBC),
    receive_coding_format=CodingFormat(CodecID.MSBC),
    max_latency=0x000D,
    packet_type=(
        HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV3
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_2_EV5
        | HCI_Enhanced_Setup_Synchronous_Connection_Command.PacketType.NO_3_EV5
    ),
    input_bandwidth=32000,
    output_bandwidth=32000,
    retransmission_effort=HCI_Enhanced_Setup_Synchronous_Connection_Command.RetransmissionEffort.OPTIMIZE_FOR_QUALITY,
)

ESCO_PARAMETERS = {
    DefaultCodecParameters.SCO_CVSD_D0: _ESCO_PARAMETERS_CVSD_D0,
    DefaultCodecParameters.SCO_CVSD_D1: _ESCO_PARAMETERS_CVSD_D1,
    DefaultCodecParameters.ESCO_CVSD_S1: _ESCO_PARAMETERS_CVSD_S1,
    DefaultCodecParameters.ESCO_CVSD_S2: _ESCO_PARAMETERS_CVSD_S2,
    DefaultCodecParameters.ESCO_CVSD_S3: _ESCO_PARAMETERS_CVSD_S3,
    DefaultCodecParameters.ESCO_CVSD_S4: _ESCO_PARAMETERS_CVSD_S4,
    DefaultCodecParameters.ESCO_MSBC_T1: _ESCO_PARAMETERS_MSBC_T1,
    DefaultCodecParameters.ESCO_MSBC_T2: _ESCO_PARAMETERS_MSBC_T2,
}
