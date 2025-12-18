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
import collections
import copy
import functools
import itertools
import json
import logging
import secrets
from collections.abc import Awaitable, Callable, Iterable, Sequence
from contextlib import AsyncExitStack, asynccontextmanager, closing
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    TypeVar,
    cast,
    overload,
)

from typing_extensions import Self

from bumble import (
    att,
    core,
    data_types,
    gatt,
    gatt_client,
    gatt_server,
    hci,
    l2cap,
    pairing,
    sdp,
    smp,
    utils,
)
from bumble.colors import color
from bumble.core import (
    AdvertisingData,
    BaseBumbleError,
    CommandTimeoutError,
    ConnectionParameterUpdateError,
    ConnectionPHY,
    InvalidArgumentError,
    InvalidOperationError,
    InvalidStateError,
    NotSupportedError,
    OutOfResourcesError,
    PhysicalTransport,
    UnreachableError,
)
from bumble.gatt import Attribute, Characteristic, Descriptor, Service
from bumble.host import DataPacketQueue, Host
from bumble.keys import KeyStore, PairingKeys
from bumble.profiles import gatt_service
from bumble.profiles.gap import GenericAccessService

if TYPE_CHECKING:
    from bumble.transport.common import TransportSink, TransportSource

_T = TypeVar('_T')

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

DEVICE_MIN_SCAN_INTERVAL                      = 2.5
DEVICE_MAX_SCAN_INTERVAL                      = 10240
DEVICE_MIN_SCAN_WINDOW                        = 2.5
DEVICE_MAX_SCAN_WINDOW                        = 10240
DEVICE_MIN_LE_RSSI                            = -127
DEVICE_MAX_LE_RSSI                            = 20
DEVICE_MIN_EXTENDED_ADVERTISING_SET_HANDLE    = 0x00
DEVICE_MAX_EXTENDED_ADVERTISING_SET_HANDLE    = 0xEF
DEVICE_MIN_BIG_HANDLE                         = 0x00
DEVICE_MAX_BIG_HANDLE                         = 0xEF
DEVICE_MIN_CS_CONFIG_ID                       = 0x00
DEVICE_MAX_CS_CONFIG_ID                       = 0x03

DEVICE_DEFAULT_ADDRESS                        = '00:00:00:00:00:00'
DEVICE_DEFAULT_ADVERTISING_INTERVAL           = 1000  # ms
DEVICE_DEFAULT_ADVERTISING_DATA               = ''
DEVICE_DEFAULT_NAME                           = 'Bumble'
DEVICE_DEFAULT_INQUIRY_LENGTH                 = 8  # 10.24 seconds
DEVICE_DEFAULT_CLASS_OF_DEVICE                = 0
DEVICE_DEFAULT_SCAN_RESPONSE_DATA             = b''
DEVICE_DEFAULT_DATA_LENGTH                    = (27, 328, 27, 328)
DEVICE_DEFAULT_SCAN_INTERVAL                  = 60  # ms
DEVICE_DEFAULT_SCAN_WINDOW                    = 60  # ms
DEVICE_DEFAULT_CONNECT_TIMEOUT                = None  # No timeout
DEVICE_DEFAULT_CONNECT_SCAN_INTERVAL          = 60  # ms
DEVICE_DEFAULT_CONNECT_SCAN_WINDOW            = 60  # ms
DEVICE_DEFAULT_CONNECTION_INTERVAL_MIN        = 15  # ms
DEVICE_DEFAULT_CONNECTION_INTERVAL_MAX        = 30  # ms
DEVICE_DEFAULT_CONNECTION_MAX_LATENCY         = 0
DEVICE_DEFAULT_CONNECTION_SUPERVISION_TIMEOUT = 720  # ms
DEVICE_DEFAULT_CONNECTION_MIN_CE_LENGTH       = 0   # ms
DEVICE_DEFAULT_CONNECTION_MAX_CE_LENGTH       = 0   # ms
DEVICE_DEFAULT_L2CAP_COC_MTU                  = l2cap.L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MTU
DEVICE_DEFAULT_L2CAP_COC_MPS                  = l2cap.L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_MPS
DEVICE_DEFAULT_L2CAP_COC_MAX_CREDITS          = l2cap.L2CAP_LE_CREDIT_BASED_CONNECTION_DEFAULT_INITIAL_CREDITS
DEVICE_DEFAULT_ADVERTISING_TX_POWER           = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.TX_POWER_NO_PREFERENCE
)
DEVICE_DEFAULT_PERIODIC_ADVERTISING_SYNC_SKIP = 0
DEVICE_DEFAULT_PERIODIC_ADVERTISING_SYNC_TIMEOUT = 5.0
DEVICE_DEFAULT_LE_RPA_TIMEOUT                 = 15 * 60 # 15 minutes (in seconds)
DEVICE_DEFAULT_ISO_CIS_MAX_SDU                = 251
DEVICE_DEFAULT_ISO_CIS_RTN                    = 10
DEVICE_DEFAULT_ISO_CIS_MAX_TRANSPORT_LATENCY  = 100

# fmt: on
# pylint: enable=line-too-long

# As specified in 7.8.56 LE Set Extended Advertising Enable command
DEVICE_MAX_HIGH_DUTY_CYCLE_CONNECTABLE_DIRECTED_ADVERTISING_DURATION = 1.28


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class ObjectLookupError(BaseBumbleError):
    """Error raised when failed to lookup an object."""


# -----------------------------------------------------------------------------
@dataclass
class Advertisement:
    # Attributes
    address: hci.Address
    rssi: int = hci.HCI_LE_Extended_Advertising_Report_Event.RSSI_NOT_AVAILABLE
    is_legacy: bool = False
    is_anonymous: bool = False
    is_connectable: bool = False
    is_directed: bool = False
    is_scannable: bool = False
    is_scan_response: bool = False
    is_complete: bool = True
    is_truncated: bool = False
    primary_phy: int = 0
    secondary_phy: int = 0
    tx_power: int = (
        hci.HCI_LE_Extended_Advertising_Report_Event.TX_POWER_INFORMATION_NOT_AVAILABLE
    )
    sid: int = 0
    data_bytes: bytes = b''

    # Constants
    TX_POWER_NOT_AVAILABLE: ClassVar[int] = (
        hci.HCI_LE_Extended_Advertising_Report_Event.TX_POWER_INFORMATION_NOT_AVAILABLE
    )
    RSSI_NOT_AVAILABLE: ClassVar[int] = (
        hci.HCI_LE_Extended_Advertising_Report_Event.RSSI_NOT_AVAILABLE
    )

    def __post_init__(self) -> None:
        self.data = AdvertisingData.from_bytes(self.data_bytes)

    @classmethod
    def from_advertising_report(cls, report) -> Advertisement | None:
        if isinstance(report, hci.HCI_LE_Advertising_Report_Event.Report):
            return LegacyAdvertisement.from_advertising_report(report)

        if isinstance(report, hci.HCI_LE_Extended_Advertising_Report_Event.Report):
            return ExtendedAdvertisement.from_advertising_report(report)

        return None


# -----------------------------------------------------------------------------
class LegacyAdvertisement(Advertisement):
    @classmethod
    def from_advertising_report(
        cls, report: hci.HCI_LE_Advertising_Report_Event.Report
    ) -> Self:
        return cls(
            address=report.address,
            rssi=report.rssi,
            is_legacy=True,
            is_connectable=(
                report.event_type
                in (
                    hci.HCI_LE_Advertising_Report_Event.EventType.ADV_IND,
                    hci.HCI_LE_Advertising_Report_Event.EventType.ADV_DIRECT_IND,
                )
            ),
            is_directed=(
                report.event_type
                == hci.HCI_LE_Advertising_Report_Event.EventType.ADV_DIRECT_IND
            ),
            is_scannable=(
                report.event_type
                in (
                    hci.HCI_LE_Advertising_Report_Event.EventType.ADV_IND,
                    hci.HCI_LE_Advertising_Report_Event.EventType.ADV_SCAN_IND,
                )
            ),
            is_scan_response=(
                report.event_type
                == hci.HCI_LE_Advertising_Report_Event.EventType.SCAN_RSP
            ),
            data_bytes=report.data,
        )


# -----------------------------------------------------------------------------
class ExtendedAdvertisement(Advertisement):
    @classmethod
    def from_advertising_report(
        cls, report: hci.HCI_LE_Extended_Advertising_Report_Event.Report
    ) -> Self:
        # fmt: off
        # pylint: disable=line-too-long
        return cls(
            address          = report.address,
            rssi             = report.rssi,
            is_legacy        = (report.event_type & hci.HCI_LE_Extended_Advertising_Report_Event.EventType.LEGACY_ADVERTISING_PDU_USED) != 0,
            is_anonymous     = report.address.address_type == hci.HCI_LE_Extended_Advertising_Report_Event.ANONYMOUS_ADDRESS_TYPE,
            is_connectable   = (report.event_type & hci.HCI_LE_Extended_Advertising_Report_Event.EventType.CONNECTABLE_ADVERTISING) != 0,
            is_directed      = (report.event_type & hci.HCI_LE_Extended_Advertising_Report_Event.EventType.DIRECTED_ADVERTISING) != 0,
            is_scannable     = (report.event_type & hci.HCI_LE_Extended_Advertising_Report_Event.EventType.SCANNABLE_ADVERTISING) != 0,
            is_scan_response = (report.event_type & hci.HCI_LE_Extended_Advertising_Report_Event.EventType.SCAN_RESPONSE) != 0,
            is_complete      = (report.event_type >> 5 & 3)  == hci.HCI_LE_Extended_Advertising_Report_Event.DATA_COMPLETE,
            is_truncated     = (report.event_type >> 5 & 3)  == hci.HCI_LE_Extended_Advertising_Report_Event.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME,
            primary_phy      = report.primary_phy,
            secondary_phy    = report.secondary_phy,
            tx_power         = report.tx_power,
            sid              = report.advertising_sid,
            data_bytes       = report.data,
        )
        # fmt: on


# -----------------------------------------------------------------------------
class AdvertisementDataAccumulator:
    last_advertisement: Advertisement | None
    last_data: bytes
    passive: bool

    def __init__(self, passive: bool = False):
        self.passive = passive
        self.last_advertisement = None
        self.last_data = b''

    def update(
        self,
        report: (
            hci.HCI_LE_Advertising_Report_Event.Report
            | hci.HCI_LE_Extended_Advertising_Report_Event.Report
        ),
    ) -> Advertisement | None:
        advertisement = Advertisement.from_advertising_report(report)
        if advertisement is None:
            return None

        result = None

        if advertisement.is_scan_response:
            if (
                self.last_advertisement is not None
                and not self.last_advertisement.is_scan_response
            ):
                # This is the response to a scannable advertisement
                if result := Advertisement.from_advertising_report(report):
                    result.is_connectable = self.last_advertisement.is_connectable
                    result.is_scannable = True
                    result.data = AdvertisingData.from_bytes(
                        self.last_data + report.data
                    )
            self.last_data = b''
        else:
            if (
                self.passive
                or (not advertisement.is_scannable)
                or (
                    self.last_advertisement is not None
                    and not self.last_advertisement.is_scan_response
                )
            ):
                # Don't wait for a scan response
                result = Advertisement.from_advertising_report(report)

            self.last_data = report.data

        self.last_advertisement = advertisement

        return result


# -----------------------------------------------------------------------------
class AdvertisingType(IntEnum):
    # fmt: off
    # pylint: disable=line-too-long
    UNDIRECTED_CONNECTABLE_SCANNABLE = 0x00  # Undirected, connectable,     scannable
    DIRECTED_CONNECTABLE_HIGH_DUTY   = 0x01  # Directed,   connectable,     non-scannable
    UNDIRECTED_SCANNABLE             = 0x02  # Undirected, non-connectable, scannable
    UNDIRECTED                       = 0x03  # Undirected, non-connectable, non-scannable
    DIRECTED_CONNECTABLE_LOW_DUTY    = 0x04  # Directed,   connectable,     non-scannable
    # fmt: on

    @property
    def has_data(self) -> bool:
        return self in (
            AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE,
            AdvertisingType.UNDIRECTED_SCANNABLE,
            AdvertisingType.UNDIRECTED,
        )

    @property
    def is_connectable(self) -> bool:
        return self in (
            AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE,
            AdvertisingType.DIRECTED_CONNECTABLE_HIGH_DUTY,
            AdvertisingType.DIRECTED_CONNECTABLE_LOW_DUTY,
        )

    @property
    def is_scannable(self) -> bool:
        return self in (
            AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE,
            AdvertisingType.UNDIRECTED_SCANNABLE,
        )

    @property
    def is_directed(self) -> bool:
        return self in (
            AdvertisingType.DIRECTED_CONNECTABLE_HIGH_DUTY,
            AdvertisingType.DIRECTED_CONNECTABLE_LOW_DUTY,
        )

    @property
    def is_high_duty_cycle_directed_connectable(self):
        return self == AdvertisingType.DIRECTED_CONNECTABLE_HIGH_DUTY


# -----------------------------------------------------------------------------
@dataclass
class LegacyAdvertiser:
    device: Device
    advertising_type: AdvertisingType
    own_address_type: hci.OwnAddressType
    peer_address: hci.Address
    auto_restart: bool

    async def start(self) -> None:
        # Set/update the advertising data if the advertising type allows it
        if self.advertising_type.has_data:
            await self.device.send_command(
                hci.HCI_LE_Set_Advertising_Data_Command(
                    advertising_data=self.device.advertising_data
                ),
                check_result=True,
            )

        # Set/update the scan response data if the advertising is scannable
        if self.advertising_type.is_scannable:
            await self.device.send_command(
                hci.HCI_LE_Set_Scan_Response_Data_Command(
                    scan_response_data=self.device.scan_response_data
                ),
                check_result=True,
            )

        # Set the advertising parameters
        await self.device.send_command(
            hci.HCI_LE_Set_Advertising_Parameters_Command(
                advertising_interval_min=int(
                    self.device.advertising_interval_min / 0.625
                ),
                advertising_interval_max=int(
                    self.device.advertising_interval_max / 0.625
                ),
                advertising_type=int(self.advertising_type),
                own_address_type=self.own_address_type,
                peer_address_type=self.peer_address.address_type,
                peer_address=self.peer_address,
                advertising_channel_map=7,
                advertising_filter_policy=0,
            ),
            check_result=True,
        )

        # Enable advertising
        await self.device.send_command(
            hci.HCI_LE_Set_Advertising_Enable_Command(advertising_enable=1),
            check_result=True,
        )

    async def stop(self) -> None:
        # Disable advertising
        await self.device.send_command(
            hci.HCI_LE_Set_Advertising_Enable_Command(advertising_enable=0),
            check_result=True,
        )


# -----------------------------------------------------------------------------
@dataclass
class AdvertisingEventProperties:
    is_connectable: bool = True
    is_scannable: bool = False
    is_directed: bool = False
    is_high_duty_cycle_directed_connectable: bool = False
    is_legacy: bool = False
    is_anonymous: bool = False
    include_tx_power: bool = False

    def __int__(self) -> int:
        properties = hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties(
            0
        )
        if self.is_connectable:
            properties |= properties.CONNECTABLE_ADVERTISING
        if self.is_scannable:
            properties |= properties.SCANNABLE_ADVERTISING
        if self.is_directed:
            properties |= properties.DIRECTED_ADVERTISING
        if self.is_high_duty_cycle_directed_connectable:
            properties |= properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
        if self.is_legacy:
            properties |= properties.USE_LEGACY_ADVERTISING_PDUS
        if self.is_anonymous:
            properties |= properties.ANONYMOUS_ADVERTISING
        if self.include_tx_power:
            properties |= properties.INCLUDE_TX_POWER

        return int(properties)

    @classmethod
    def from_advertising_type(
        cls: type[AdvertisingEventProperties],
        advertising_type: AdvertisingType,
    ) -> AdvertisingEventProperties:
        return cls(
            is_connectable=advertising_type.is_connectable,
            is_scannable=advertising_type.is_scannable,
            is_directed=advertising_type.is_directed,
            is_high_duty_cycle_directed_connectable=advertising_type.is_high_duty_cycle_directed_connectable,
            is_legacy=True,
            is_anonymous=False,
            include_tx_power=False,
        )


# -----------------------------------------------------------------------------
@dataclass
class PeriodicAdvertisement:
    address: hci.Address
    sid: int
    tx_power: int = (
        hci.HCI_LE_Periodic_Advertising_Report_Event.TX_POWER_INFORMATION_NOT_AVAILABLE
    )
    rssi: int = hci.HCI_LE_Periodic_Advertising_Report_Event.RSSI_NOT_AVAILABLE
    is_truncated: bool = False
    data_bytes: bytes = b''

    # Constants
    TX_POWER_NOT_AVAILABLE: ClassVar[int] = (
        hci.HCI_LE_Periodic_Advertising_Report_Event.TX_POWER_INFORMATION_NOT_AVAILABLE
    )
    RSSI_NOT_AVAILABLE: ClassVar[int] = (
        hci.HCI_LE_Periodic_Advertising_Report_Event.RSSI_NOT_AVAILABLE
    )

    def __post_init__(self) -> None:
        self.data = (
            None if self.is_truncated else AdvertisingData.from_bytes(self.data_bytes)
        )


# -----------------------------------------------------------------------------
@dataclass
class BigInfoAdvertisement:
    class Framing(utils.OpenIntEnum):
        # fmt: off
        UNFRAMED                = 0X00
        FRAMED_SEGMENTABLE_MODE = 0X01
        FRAMED_UNSEGMENTED_MODE = 0X02

    class Encryption(utils.OpenIntEnum):
        # fmt: off
        UNENCRYPTED = 0x00
        ENCRYPTED   = 0x01

    address: hci.Address
    sid: int
    num_bis: int
    nse: int
    iso_interval: float
    bn: int
    pto: int
    irc: int
    max_pdu: int
    sdu_interval: int
    max_sdu: int
    phy: hci.Phy
    framing: Framing
    encryption: Encryption

    @classmethod
    def from_report(cls, address: hci.Address, sid: int, report) -> Self:
        return cls(
            address,
            sid,
            report.num_bis,
            report.nse,
            report.iso_interval * 1.25,
            report.bn,
            report.pto,
            report.irc,
            report.max_pdu,
            report.sdu_interval,
            report.max_sdu,
            hci.Phy(report.phy),
            cls.Framing(report.framing),
            cls.Encryption(report.encryption),
        )


# -----------------------------------------------------------------------------
# TODO: replace with typing.TypeAlias when the code base is all Python >= 3.10
AdvertisingChannelMap = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.ChannelMap
)


# -----------------------------------------------------------------------------
@dataclass
class AdvertisingParameters:
    # pylint: disable=line-too-long
    advertising_event_properties: AdvertisingEventProperties = field(
        default_factory=AdvertisingEventProperties
    )
    primary_advertising_interval_min: float = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    primary_advertising_interval_max: float = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    primary_advertising_channel_map: (
        hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.ChannelMap
    ) = (
        AdvertisingChannelMap.CHANNEL_37
        | AdvertisingChannelMap.CHANNEL_38
        | AdvertisingChannelMap.CHANNEL_39
    )
    own_address_type: hci.OwnAddressType = hci.OwnAddressType.RANDOM
    peer_address: hci.Address = hci.Address.ANY
    advertising_filter_policy: int = 0
    advertising_tx_power: int = DEVICE_DEFAULT_ADVERTISING_TX_POWER
    primary_advertising_phy: hci.Phy = hci.Phy.LE_1M
    secondary_advertising_max_skip: int = 0
    secondary_advertising_phy: hci.Phy = hci.Phy.LE_1M
    advertising_sid: int = 0
    enable_scan_request_notifications: bool = False
    primary_advertising_phy_options: int = 0
    secondary_advertising_phy_options: int = 0


# -----------------------------------------------------------------------------
@dataclass
class PeriodicAdvertisingParameters:
    periodic_advertising_interval_min: float = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    periodic_advertising_interval_max: float = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    periodic_advertising_properties: (
        hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command.Properties
    ) = field(
        default_factory=lambda: hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command.Properties(
            0
        )
    )


# -----------------------------------------------------------------------------
@dataclass
class AdvertisingSet(utils.EventEmitter):
    device: Device
    advertising_handle: int
    auto_restart: bool
    random_address: hci.Address | None
    advertising_parameters: AdvertisingParameters
    advertising_data: bytes
    scan_response_data: bytes
    periodic_advertising_parameters: PeriodicAdvertisingParameters | None
    periodic_advertising_data: bytes
    selected_tx_power: int = 0
    enabled: bool = False
    periodic_enabled: bool = False

    EVENT_START = "start"
    EVENT_STOP = "stop"
    EVENT_START_PERIODIC = "start_periodic"
    EVENT_STOP_PERIODIC = "stop_periodic"
    EVENT_TERMINATION = "termination"

    def __post_init__(self) -> None:
        super().__init__()

    async def set_advertising_parameters(
        self, advertising_parameters: AdvertisingParameters
    ) -> None:
        # Compliance check
        if (
            not advertising_parameters.advertising_event_properties.is_legacy
            and advertising_parameters.advertising_event_properties.is_connectable
            and advertising_parameters.advertising_event_properties.is_scannable
        ):
            logger.warning(
                "non-legacy extended advertising event properties may not be both "
                "connectable and scannable"
            )

        response = await self.device.send_command(
            hci.HCI_LE_Set_Extended_Advertising_Parameters_Command(
                advertising_handle=self.advertising_handle,
                advertising_event_properties=int(
                    advertising_parameters.advertising_event_properties
                ),
                primary_advertising_interval_min=(
                    int(advertising_parameters.primary_advertising_interval_min / 0.625)
                ),
                primary_advertising_interval_max=(
                    int(advertising_parameters.primary_advertising_interval_max / 0.625)
                ),
                primary_advertising_channel_map=int(
                    advertising_parameters.primary_advertising_channel_map
                ),
                own_address_type=advertising_parameters.own_address_type,
                peer_address_type=advertising_parameters.peer_address.address_type,
                peer_address=advertising_parameters.peer_address,
                advertising_tx_power=advertising_parameters.advertising_tx_power,
                advertising_filter_policy=(
                    advertising_parameters.advertising_filter_policy
                ),
                primary_advertising_phy=advertising_parameters.primary_advertising_phy,
                secondary_advertising_max_skip=(
                    advertising_parameters.secondary_advertising_max_skip
                ),
                secondary_advertising_phy=(
                    advertising_parameters.secondary_advertising_phy
                ),
                advertising_sid=advertising_parameters.advertising_sid,
                scan_request_notification_enable=(
                    1 if advertising_parameters.enable_scan_request_notifications else 0
                ),
            ),
            check_result=True,
        )
        self.selected_tx_power = response.return_parameters.selected_tx_power
        self.advertising_parameters = advertising_parameters

    async def set_advertising_data(self, advertising_data: bytes) -> None:
        # pylint: disable=line-too-long
        await self.device.send_command(
            hci.HCI_LE_Set_Extended_Advertising_Data_Command(
                advertising_handle=self.advertising_handle,
                operation=hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation.COMPLETE_DATA,
                fragment_preference=hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.SHOULD_NOT_FRAGMENT,
                advertising_data=advertising_data,
            ),
            check_result=True,
        )
        self.advertising_data = advertising_data

    async def set_scan_response_data(self, scan_response_data: bytes) -> None:
        # pylint: disable=line-too-long
        if (
            scan_response_data
            and not self.advertising_parameters.advertising_event_properties.is_scannable
        ):
            logger.warning(
                "ignoring attempt to set non-empty scan response data on non-scannable "
                "advertising set"
            )
            return

        await self.device.send_command(
            hci.HCI_LE_Set_Extended_Scan_Response_Data_Command(
                advertising_handle=self.advertising_handle,
                operation=hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation.COMPLETE_DATA,
                fragment_preference=hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.SHOULD_NOT_FRAGMENT,
                scan_response_data=scan_response_data,
            ),
            check_result=True,
        )
        self.scan_response_data = scan_response_data

    async def set_periodic_advertising_parameters(
        self, advertising_parameters: PeriodicAdvertisingParameters
    ) -> None:
        await self.device.send_command(
            hci.HCI_LE_Set_Periodic_Advertising_Parameters_Command(
                advertising_handle=self.advertising_handle,
                periodic_advertising_interval_min=int(
                    advertising_parameters.periodic_advertising_interval_min / 1.25
                ),
                periodic_advertising_interval_max=int(
                    advertising_parameters.periodic_advertising_interval_max / 1.25
                ),
                periodic_advertising_properties=advertising_parameters.periodic_advertising_properties,
            ),
            check_result=True,
        )
        self.periodic_advertising_parameters = advertising_parameters

    async def set_periodic_advertising_data(self, advertising_data: bytes) -> None:
        await self.device.send_command(
            hci.HCI_LE_Set_Periodic_Advertising_Data_Command(
                advertising_handle=self.advertising_handle,
                operation=hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation.COMPLETE_DATA,
                advertising_data=advertising_data,
            ),
            check_result=True,
        )
        self.periodic_advertising_data = advertising_data

    async def set_random_address(self, random_address: hci.Address) -> None:
        await self.device.send_command(
            hci.HCI_LE_Set_Advertising_Set_Random_Address_Command(
                advertising_handle=self.advertising_handle,
                random_address=(random_address or self.device.random_address),
            ),
            check_result=True,
        )

    async def start(
        self, duration: float = 0.0, max_advertising_events: int = 0
    ) -> None:
        """
        Start advertising.

        Args:
          duration: How long to advertise for, in seconds. Use 0 (the default) for
          an unlimited duration, unless this advertising set is a High Duty Cycle
          Directed Advertisement type.
          max_advertising_events: Maximum number of events to advertise for. Use 0
          (the default) for an unlimited number of advertisements.
        """
        await self.device.send_command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
                enable=1,
                advertising_handles=[self.advertising_handle],
                durations=[round(duration * 100)],
                max_extended_advertising_events=[max_advertising_events],
            ),
            check_result=True,
        )
        self.enabled = True

        self.emit(self.EVENT_START)

    async def stop(self) -> None:
        await self.device.send_command(
            hci.HCI_LE_Set_Extended_Advertising_Enable_Command(
                enable=0,
                advertising_handles=[self.advertising_handle],
                durations=[0],
                max_extended_advertising_events=[0],
            ),
            check_result=True,
        )
        self.enabled = False

        self.emit(self.EVENT_STOP)

    async def start_periodic(self, include_adi: bool = False) -> None:
        if self.periodic_enabled:
            return
        await self.device.send_command(
            hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(
                enable=1 | (2 if include_adi else 0),
                advertising_handle=self.advertising_handle,
            ),
            check_result=True,
        )
        self.periodic_enabled = True

        self.emit(self.EVENT_START_PERIODIC)

    async def stop_periodic(self) -> None:
        if not self.periodic_enabled:
            return
        await self.device.send_command(
            hci.HCI_LE_Set_Periodic_Advertising_Enable_Command(
                enable=0,
                advertising_handle=self.advertising_handle,
            ),
            check_result=True,
        )
        self.periodic_enabled = False

        self.emit(self.EVENT_STOP_PERIODIC)

    async def remove(self) -> None:
        await self.device.send_command(
            hci.HCI_LE_Remove_Advertising_Set_Command(
                advertising_handle=self.advertising_handle
            ),
            check_result=True,
        )
        del self.device.extended_advertising_sets[self.advertising_handle]

    async def transfer_periodic_info(
        self, connection: Connection, service_data: int = 0
    ) -> None:
        if not self.periodic_enabled:
            raise core.InvalidStateError(
                f"Periodic Advertising is not enabled on Advertising Set 0x{self.advertising_handle:02X}"
            )
        await connection.transfer_periodic_set_info(
            self.advertising_handle, service_data
        )

    def on_termination(self, status: int) -> None:
        self.enabled = False
        self.emit(self.EVENT_TERMINATION, status)


# -----------------------------------------------------------------------------
class PeriodicAdvertisingSync(utils.EventEmitter):
    class State(Enum):
        INIT = 0
        PENDING = 1
        ESTABLISHED = 2
        CANCELLED = 3
        ERROR = 4
        LOST = 5
        TERMINATED = 6

    _state: State
    sync_handle: int | None
    advertiser_address: hci.Address
    sid: int
    skip: int
    sync_timeout: float  # Sync timeout, in seconds
    filter_duplicates: bool
    status: int
    advertiser_phy: int
    periodic_advertising_interval: float  # Advertising interval, in milliseconds
    advertiser_clock_accuracy: int

    EVENT_STATE_CHANGE = "state_change"
    EVENT_ESTABLISHMENT = "establishment"
    EVENT_CANCELLATION = "cancellation"
    EVENT_ERROR = "error"
    EVENT_LOSS = "loss"
    EVENT_PERIODIC_ADVERTISEMENT = "periodic_advertisement"
    EVENT_BIGINFO_ADVERTISEMENT = "biginfo_advertisement"

    def __init__(
        self,
        device: Device,
        advertiser_address: hci.Address,
        sid: int,
        skip: int,
        sync_timeout: float,
        filter_duplicates: bool,
    ) -> None:
        super().__init__()
        self._state = self.State.INIT
        self.sync_handle = None
        self.device = device
        self.advertiser_address = advertiser_address
        self.sid = sid
        self.skip = skip
        self.sync_timeout = sync_timeout
        self.filter_duplicates = filter_duplicates
        self.status = hci.HCI_SUCCESS
        self.advertiser_phy = 0
        self.periodic_advertising_interval = 0
        self.advertiser_clock_accuracy = 0
        self.data_accumulator = b''

    @property
    def state(self) -> State:
        return self._state

    @state.setter
    def state(self, state: State) -> None:
        logger.debug(f'{self} -> {state.name}')
        self._state = state
        self.emit(self.EVENT_STATE_CHANGE)

    async def establish(self) -> None:
        if self.state != self.State.INIT:
            raise InvalidStateError('sync not in init state')

        options = hci.HCI_LE_Periodic_Advertising_Create_Sync_Command.Options(0)
        if self.filter_duplicates:
            options |= (
                hci.HCI_LE_Periodic_Advertising_Create_Sync_Command.Options.DUPLICATE_FILTERING_INITIALLY_ENABLED
            )

        await self.device.send_command(
            hci.HCI_LE_Periodic_Advertising_Create_Sync_Command(
                options=options,
                advertising_sid=self.sid,
                advertiser_address_type=self.advertiser_address.address_type,
                advertiser_address=self.advertiser_address,
                skip=self.skip,
                sync_timeout=int(self.sync_timeout * 100),
                sync_cte_type=0,
            ),
            check_result=True,
        )

        self.state = self.State.PENDING

    async def terminate(self) -> None:
        if self.state in (self.State.INIT, self.State.CANCELLED, self.State.TERMINATED):
            return

        if self.state == self.State.PENDING:
            self.state = self.State.CANCELLED
            response = await self.device.send_command(
                hci.HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command(),
            )
            if response.return_parameters == hci.HCI_SUCCESS:
                if self in self.device.periodic_advertising_syncs:
                    self.device.periodic_advertising_syncs.remove(self)
            return

        if self.state in (self.State.ESTABLISHED, self.State.ERROR, self.State.LOST):
            self.state = self.State.TERMINATED
            if self.sync_handle is not None:
                await self.device.send_command(
                    hci.HCI_LE_Periodic_Advertising_Terminate_Sync_Command(
                        sync_handle=self.sync_handle
                    )
                )
            self.device.periodic_advertising_syncs.remove(self)

    async def transfer(self, connection: Connection, service_data: int = 0) -> None:
        if self.sync_handle is not None:
            await connection.transfer_periodic_sync(self.sync_handle, service_data)

    def on_establishment(
        self,
        status: int,
        sync_handle: int,
        advertiser_phy: int,
        periodic_advertising_interval: int,
        advertiser_clock_accuracy: int,
    ) -> None:
        self.status = status

        if self.state == self.State.CANCELLED:
            # Somehow, we receive an established event after trying to cancel, most
            # likely because the cancel command was sent too late, when the sync was
            # already established, but before the established event was sent.
            # We need to automatically terminate.
            logger.debug(
                "received established event for cancelled sync, will terminate"
            )
            self.state = self.State.ESTABLISHED
            utils.AsyncRunner.spawn(self.terminate())
            return

        if status == hci.HCI_SUCCESS:
            self.sync_handle = sync_handle
            self.advertiser_phy = advertiser_phy
            self.periodic_advertising_interval = periodic_advertising_interval * 1.25
            self.advertiser_clock_accuracy = advertiser_clock_accuracy
            self.state = self.State.ESTABLISHED
            self.emit(self.EVENT_ESTABLISHMENT)
            return

        # We don't need to keep a reference anymore
        if self in self.device.periodic_advertising_syncs:
            self.device.periodic_advertising_syncs.remove(self)

        if status == hci.HCI_OPERATION_CANCELLED_BY_HOST_ERROR:
            self.state = self.State.CANCELLED
            self.emit(self.EVENT_CANCELLATION)
            return

        self.state = self.State.ERROR
        self.emit(self.EVENT_ERROR)

    def on_loss(self):
        self.state = self.State.LOST
        self.emit(self.EVENT_LOSS)

    def on_periodic_advertising_report(self, report) -> None:
        self.data_accumulator += report.data
        if (
            report.data_status
            == hci.HCI_LE_Periodic_Advertising_Report_Event.DataStatus.DATA_INCOMPLETE_MORE_TO_COME
        ):
            return

        self.emit(
            self.EVENT_PERIODIC_ADVERTISEMENT,
            PeriodicAdvertisement(
                self.advertiser_address,
                self.sid,
                report.tx_power,
                report.rssi,
                is_truncated=(
                    report.data_status
                    == hci.HCI_LE_Periodic_Advertising_Report_Event.DataStatus.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME
                ),
                data_bytes=self.data_accumulator,
            ),
        )
        self.data_accumulator = b''

    def on_biginfo_advertising_report(self, report) -> None:
        self.emit(
            self.EVENT_BIGINFO_ADVERTISEMENT,
            BigInfoAdvertisement.from_report(self.advertiser_address, self.sid, report),
        )

    def __str__(self) -> str:
        return (
            'PeriodicAdvertisingSync('
            f'state={self.state.name}, '
            f'sync_handle={self.sync_handle}, '
            f'sid={self.sid}, '
            f'skip={self.skip}, '
            f'filter_duplicates={self.filter_duplicates}'
            ')'
        )


# -----------------------------------------------------------------------------
@dataclass
class BigParameters:
    class Packing(utils.OpenIntEnum):
        # fmt: off
        SEQUENTIAL = 0x00
        INTERLEAVED = 0x01

    class Framing(utils.OpenIntEnum):
        # fmt: off
        UNFRAMED = 0x00
        FRAMED   = 0x01

    num_bis: int
    sdu_interval: int  # SDU interval, in microseconds
    max_sdu: int
    max_transport_latency: int  # Max transport latency, in milliseconds
    rtn: int
    phy: hci.PhyBit = hci.PhyBit.LE_2M
    packing: Packing = Packing.SEQUENTIAL
    framing: Framing = Framing.UNFRAMED
    broadcast_code: bytes | None = None


# -----------------------------------------------------------------------------
@dataclass
class Big(utils.EventEmitter):
    class State(IntEnum):
        PENDING = 0
        ACTIVE = 1
        TERMINATED = 2

    class Event(str, Enum):
        ESTABLISHMENT = 'establishment'
        ESTABLISHMENT_FAILURE = 'establishment_failure'
        TERMINATION = 'termination'

    big_handle: int
    advertising_set: AdvertisingSet
    parameters: BigParameters
    state: State = State.PENDING

    # Attributes provided by BIG Create Complete event
    big_sync_delay: int = 0  # Sync delay, in microseconds
    transport_latency_big: int = 0  # Transport latency, in microseconds
    phy: hci.Phy = hci.Phy.LE_1M
    nse: int = 0
    bn: int = 0
    pto: int = 0
    irc: int = 0
    max_pdu: int = 0
    iso_interval: float = 0.0  # ISO interval, in milliseconds
    bis_links: Sequence[BisLink] = ()

    def __post_init__(self) -> None:
        super().__init__()
        self.device = self.advertising_set.device

    async def terminate(
        self,
        reason: int = hci.HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
    ) -> None:
        if self.state != Big.State.ACTIVE:
            logger.error('BIG %d is not active.', self.big_handle)
            return

        with closing(utils.EventWatcher()) as watcher:
            terminated = asyncio.Event()
            watcher.once(self, Big.Event.TERMINATION, lambda _: terminated.set())
            await self.device.send_command(
                hci.HCI_LE_Terminate_BIG_Command(
                    big_handle=self.big_handle, reason=reason
                ),
                check_result=True,
            )
            await terminated.wait()


# -----------------------------------------------------------------------------
@dataclass
class BigSyncParameters:
    big_sync_timeout: int
    bis: Sequence[int]
    mse: int = 0
    broadcast_code: bytes | None = None


# -----------------------------------------------------------------------------
@dataclass
class BigSync(utils.EventEmitter):
    class State(IntEnum):
        PENDING = 0
        ACTIVE = 1
        TERMINATED = 2

    class Event(str, Enum):
        ESTABLISHMENT = 'establishment'
        ESTABLISHMENT_FAILURE = 'establishment_failure'
        TERMINATION = 'termination'

    big_handle: int
    pa_sync: PeriodicAdvertisingSync
    parameters: BigSyncParameters
    state: State = State.PENDING

    # Attributes provided by BIG Create Sync Complete event
    transport_latency_big: int = 0
    nse: int = 0
    bn: int = 0
    pto: int = 0
    irc: int = 0
    max_pdu: int = 0
    iso_interval: float = 0.0
    bis_links: Sequence[BisLink] = ()

    def __post_init__(self) -> None:
        super().__init__()
        self.device = self.pa_sync.device

    async def terminate(self) -> None:
        if self.state != BigSync.State.ACTIVE:
            logger.error('BIG Sync %d is not active.', self.big_handle)
            return

        await self.device.send_command(
            hci.HCI_LE_BIG_Terminate_Sync_Command(big_handle=self.big_handle),
            check_result=True,
        )
        self.state = BigSync.State.TERMINATED


# -----------------------------------------------------------------------------
@dataclass
class ChannelSoundingCapabilities:
    num_config_supported: int
    max_consecutive_procedures_supported: int
    num_antennas_supported: int
    max_antenna_paths_supported: int
    roles_supported: int
    modes_supported: int
    rtt_capability: int
    rtt_aa_only_n: int
    rtt_sounding_n: int
    rtt_random_payload_n: int
    nadm_sounding_capability: int
    nadm_random_capability: int
    cs_sync_phys_supported: int
    subfeatures_supported: int
    t_ip1_times_supported: int
    t_ip2_times_supported: int
    t_fcs_times_supported: int
    t_pm_times_supported: int
    t_sw_time_supported: int
    tx_snr_capability: int


# -----------------------------------------------------------------------------
@dataclass
class ChannelSoundingConfig:
    config_id: int
    main_mode_type: int
    sub_mode_type: int
    min_main_mode_steps: int
    max_main_mode_steps: int
    main_mode_repetition: int
    mode_0_steps: int
    role: int
    rtt_type: int
    cs_sync_phy: int
    channel_map: bytes
    channel_map_repetition: int
    channel_selection_type: int
    ch3c_shape: int
    ch3c_jump: int
    reserved: int
    t_ip1_time: int
    t_ip2_time: int
    t_fcs_time: int
    t_pm_time: int


# -----------------------------------------------------------------------------
@dataclass
class ChannelSoundingProcedure:
    config_id: int
    state: int
    tone_antenna_config_selection: int
    selected_tx_power: int
    subevent_len: int
    subevents_per_event: int
    subevent_interval: float  # milliseconds.
    event_interval: int
    procedure_interval: int
    procedure_count: int
    max_procedure_len: float  # milliseconds.


# -----------------------------------------------------------------------------
class LePhyOptions:
    # Coded PHY preference
    ANY_CODED_PHY = 0
    PREFER_S_2_CODED_PHY = 1
    PREFER_S_8_CODED_PHY = 2

    def __init__(self, coded_phy_preference: int = 0):
        self.coded_phy_preference = coded_phy_preference

    def __int__(self):
        return self.coded_phy_preference & 3


# -----------------------------------------------------------------------------
_PROXY_CLASS = TypeVar('_PROXY_CLASS', bound=gatt_client.ProfileServiceProxy)


class Peer:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection

        # Shortcut to the connection's GATT client
        self.gatt_client = connection.gatt_client

    @property
    def services(self) -> list[gatt_client.ServiceProxy]:
        return self.gatt_client.services

    async def request_mtu(self, mtu: int) -> int:
        mtu = await self.gatt_client.request_mtu(mtu)
        self.connection.emit(self.connection.EVENT_CONNECTION_ATT_MTU_UPDATE)
        return mtu

    async def discover_service(
        self, uuid: core.UUID | str
    ) -> list[gatt_client.ServiceProxy]:
        return await self.gatt_client.discover_service(uuid)

    async def discover_services(
        self, uuids: Iterable[core.UUID] = ()
    ) -> list[gatt_client.ServiceProxy]:
        return await self.gatt_client.discover_services(uuids)

    async def discover_included_services(
        self, service: gatt_client.ServiceProxy
    ) -> list[gatt_client.ServiceProxy]:
        return await self.gatt_client.discover_included_services(service)

    async def discover_characteristics(
        self,
        uuids: Iterable[core.UUID | str] = (),
        service: gatt_client.ServiceProxy | None = None,
    ) -> list[gatt_client.CharacteristicProxy[bytes]]:
        return await self.gatt_client.discover_characteristics(
            uuids=uuids, service=service
        )

    async def discover_descriptors(
        self,
        characteristic: gatt_client.CharacteristicProxy | None = None,
        start_handle: int | None = None,
        end_handle: int | None = None,
    ):
        return await self.gatt_client.discover_descriptors(
            characteristic, start_handle, end_handle
        )

    async def discover_attributes(self) -> list[gatt_client.AttributeProxy[bytes]]:
        return await self.gatt_client.discover_attributes()

    async def discover_all(self):
        await self.discover_services()
        for service in self.services:
            await self.discover_characteristics(service=service)

        for service in self.services:
            for characteristic in service.characteristics:
                await self.discover_descriptors(characteristic=characteristic)

    async def subscribe(
        self,
        characteristic: gatt_client.CharacteristicProxy,
        subscriber: Callable[[bytes], Any] | None = None,
        prefer_notify: bool = True,
    ) -> None:
        return await self.gatt_client.subscribe(
            characteristic, subscriber, prefer_notify
        )

    async def unsubscribe(
        self,
        characteristic: gatt_client.CharacteristicProxy,
        subscriber: Callable[[bytes], Any] | None = None,
    ) -> None:
        return await self.gatt_client.unsubscribe(characteristic, subscriber)

    async def read_value(self, attribute: int | gatt_client.AttributeProxy) -> bytes:
        return await self.gatt_client.read_value(attribute)

    async def write_value(
        self,
        attribute: int | gatt_client.AttributeProxy,
        value: bytes,
        with_response: bool = False,
    ) -> None:
        return await self.gatt_client.write_value(attribute, value, with_response)

    async def read_characteristics_by_uuid(
        self, uuid: core.UUID, service: gatt_client.ServiceProxy | None = None
    ) -> list[bytes]:
        return await self.gatt_client.read_characteristics_by_uuid(uuid, service)

    def get_services_by_uuid(self, uuid: core.UUID) -> list[gatt_client.ServiceProxy]:
        return self.gatt_client.get_services_by_uuid(uuid)

    def get_characteristics_by_uuid(
        self,
        uuid: core.UUID,
        service: gatt_client.ServiceProxy | core.UUID | None = None,
    ) -> list[gatt_client.CharacteristicProxy[bytes]]:
        if isinstance(service, core.UUID):
            return list(
                itertools.chain(
                    *[
                        self.get_characteristics_by_uuid(uuid, s)
                        for s in self.get_services_by_uuid(service)
                    ]
                )
            )

        return self.gatt_client.get_characteristics_by_uuid(uuid, service)

    def create_service_proxy(
        self, proxy_class: type[_PROXY_CLASS]
    ) -> _PROXY_CLASS | None:
        if proxy := proxy_class.from_client(self.gatt_client):
            return cast(_PROXY_CLASS, proxy)

        return None

    async def discover_service_and_create_proxy(
        self, proxy_class: type[_PROXY_CLASS]
    ) -> _PROXY_CLASS | None:
        # Discover the first matching service and its characteristics
        services = await self.discover_service(proxy_class.SERVICE_CLASS.UUID)
        if services:
            service = services[0]
            await service.discover_characteristics()
            return self.create_service_proxy(proxy_class)
        return None

    async def sustain(self, timeout: float | None = None) -> None:
        await self.connection.sustain(timeout)

    # [Classic only]
    async def request_name(self) -> str:
        return await self.connection.request_remote_name()

    async def __aenter__(self):
        await self.discover_services()
        for service in self.services:
            await service.discover_characteristics()

        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass

    def __str__(self) -> str:
        return f'{self.connection.peer_address} as {self.connection.role_name}'


# -----------------------------------------------------------------------------
@dataclass
class ConnectionParametersPreferences:
    default: ClassVar[ConnectionParametersPreferences]
    connection_interval_min: float = DEVICE_DEFAULT_CONNECTION_INTERVAL_MIN
    connection_interval_max: float = DEVICE_DEFAULT_CONNECTION_INTERVAL_MAX
    max_latency: int = DEVICE_DEFAULT_CONNECTION_MAX_LATENCY
    supervision_timeout: int = DEVICE_DEFAULT_CONNECTION_SUPERVISION_TIMEOUT
    min_ce_length: int = DEVICE_DEFAULT_CONNECTION_MIN_CE_LENGTH
    max_ce_length: int = DEVICE_DEFAULT_CONNECTION_MAX_CE_LENGTH


ConnectionParametersPreferences.default = ConnectionParametersPreferences()


# -----------------------------------------------------------------------------
@dataclass
class ScoLink(utils.CompositeEventEmitter):
    device: Device
    acl_connection: Connection
    handle: int
    link_type: int
    sink: Callable[[hci.HCI_SynchronousDataPacket], Any] | None = None

    EVENT_DISCONNECTION: ClassVar[str] = "disconnection"
    EVENT_DISCONNECTION_FAILURE: ClassVar[str] = "disconnection_failure"

    def __post_init__(self) -> None:
        super().__init__()

    async def disconnect(
        self, reason: int = hci.HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR
    ) -> None:
        await self.device.disconnect(self, reason)


# -----------------------------------------------------------------------------
class _IsoLink:
    handle: int
    device: Device
    sink: Callable[[hci.HCI_IsoDataPacket], Any] | None = None
    data_paths: set[_IsoLink.Direction]
    _data_path_lock: asyncio.Lock

    class Direction(IntEnum):
        HOST_TO_CONTROLLER = (
            hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.HOST_TO_CONTROLLER
        )
        CONTROLLER_TO_HOST = (
            hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.CONTROLLER_TO_HOST
        )

    def __init__(self) -> None:
        self._data_path_lock = asyncio.Lock()
        self.data_paths = set()

    async def setup_data_path(
        self,
        direction: _IsoLink.Direction,
        data_path_id: int = 0,
        codec_id: hci.CodingFormat | None = None,
        controller_delay: int = 0,
        codec_configuration: bytes = b'',
    ) -> None:
        """Create a data path between controller and given entry.

        Args:
            direction: Direction of data path.
            data_path_id: ID of data path. Default is 0 (HCI).
            codec_id: Codec ID. Default is Transparent.
            controller_delay: Controller delay in microseconds. Default is 0.
            codec_configuration: Codec-specific configuration.

        Raises:
            HCI_Error: When command complete status is not HCI_SUCCESS.
        """
        async with self._data_path_lock:
            if direction in self.data_paths:
                return
            await self.device.send_command(
                hci.HCI_LE_Setup_ISO_Data_Path_Command(
                    connection_handle=self.handle,
                    data_path_direction=direction,
                    data_path_id=data_path_id,
                    codec_id=codec_id or hci.CodingFormat(hci.CodecID.TRANSPARENT),
                    controller_delay=controller_delay,
                    codec_configuration=codec_configuration,
                ),
                check_result=True,
            )
            self.data_paths.add(direction)

    async def remove_data_path(self, directions: Iterable[_IsoLink.Direction]) -> None:
        """Remove a data path with controller on given direction.

        Args:
            direction: Direction of data path.

        Raises:
            HCI_Error: When command complete status is not HCI_SUCCESS.
        """
        async with self._data_path_lock:
            directions_to_remove = set(directions).intersection(self.data_paths)
            if not directions_to_remove:
                return
            await self.device.send_command(
                hci.HCI_LE_Remove_ISO_Data_Path_Command(
                    connection_handle=self.handle,
                    data_path_direction=sum(
                        1 << direction for direction in directions_to_remove
                    ),
                ),
                check_result=True,
            )
            self.data_paths.difference_update(directions_to_remove)

    def write(self, sdu: bytes) -> None:
        """Write an ISO SDU."""
        self.device.host.send_iso_sdu(connection_handle=self.handle, sdu=sdu)

    async def get_tx_time_stamp(self) -> tuple[int, int, int]:
        response = await self.device.host.send_command(
            hci.HCI_LE_Read_ISO_TX_Sync_Command(connection_handle=self.handle),
            check_result=True,
        )
        return (
            response.return_parameters.packet_sequence_number,
            response.return_parameters.tx_time_stamp,
            response.return_parameters.time_offset,
        )

    @property
    def data_packet_queue(self) -> DataPacketQueue | None:
        return self.device.host.get_data_packet_queue(self.handle)

    async def drain(self) -> None:
        if data_packet_queue := self.data_packet_queue:
            await data_packet_queue.drain(self.handle)


# -----------------------------------------------------------------------------
@dataclass
class CigParameters:
    class WorstCaseSca(utils.OpenIntEnum):
        # fmt: off
        SCA_251_TO_500_PPM = 0x00
        SCA_151_TO_250_PPM = 0x01
        SCA_101_TO_150_PPM = 0x02
        SCA_76_TO_100_PPM  = 0x03
        SCA_51_TO_75_PPM   = 0x04
        SCA_31_TO_50_PPM   = 0x05
        SCA_21_TO_30_PPM   = 0x06
        SCA_0_TO_20_PPM    = 0x07

    class Packing(utils.OpenIntEnum):
        # fmt: off
        SEQUENTIAL = 0x00
        INTERLEAVED = 0x01

    class Framing(utils.OpenIntEnum):
        # fmt: off
        UNFRAMED = 0x00
        FRAMED   = 0x01

    @dataclass
    class CisParameters:
        cis_id: int
        max_sdu_c_to_p: int = DEVICE_DEFAULT_ISO_CIS_MAX_SDU
        max_sdu_p_to_c: int = DEVICE_DEFAULT_ISO_CIS_MAX_SDU
        phy_c_to_p: hci.PhyBit = hci.PhyBit.LE_2M
        phy_p_to_c: hci.PhyBit = hci.PhyBit.LE_2M
        rtn_c_to_p: int = DEVICE_DEFAULT_ISO_CIS_RTN  # Number of C->P retransmissions
        rtn_p_to_c: int = DEVICE_DEFAULT_ISO_CIS_RTN  # Number of P->C retransmissions

    cig_id: int
    cis_parameters: list[CisParameters]
    sdu_interval_c_to_p: int  # C->P SDU interval, in microseconds
    sdu_interval_p_to_c: int  # P->C SDU interval, in microseconds
    worst_case_sca: WorstCaseSca = WorstCaseSca.SCA_251_TO_500_PPM
    packing: Packing = Packing.SEQUENTIAL
    framing: Framing = Framing.UNFRAMED
    max_transport_latency_c_to_p: int = (
        DEVICE_DEFAULT_ISO_CIS_MAX_TRANSPORT_LATENCY  # Max C->P transport latency, in milliseconds
    )
    max_transport_latency_p_to_c: int = (
        DEVICE_DEFAULT_ISO_CIS_MAX_TRANSPORT_LATENCY  # Max C->P transport latency, in milliseconds
    )


# -----------------------------------------------------------------------------
@dataclass
class CisLink(utils.EventEmitter, _IsoLink):
    class State(IntEnum):
        PENDING = 0
        ESTABLISHED = 1

    device: Device
    acl_connection: Connection  # Based ACL connection
    handle: int  # CIS handle assigned by Controller (in LE_Set_CIG_Parameters Complete or LE_CIS_Request events)
    cis_id: int  # CIS ID assigned by Central device
    cig_id: int  # CIG ID assigned by Central device
    cig_sync_delay: int = 0  # CIG sync delay, in microseconds
    cis_sync_delay: int = 0  # CIS sync delay, in microseconds
    transport_latency_c_to_p: int = 0  # C->P transport latency, in microseconds
    transport_latency_p_to_c: int = 0  # P->C transport latency, in microseconds
    phy_c_to_p: hci.Phy | None = None
    phy_p_to_c: hci.Phy | None = None
    nse: int = 0
    bn_c_to_p: int = 0
    bn_p_to_c: int = 0
    ft_c_to_p: int = 0
    ft_p_to_c: int = 0
    max_pdu_c_to_p: int = 0
    max_pdu_p_to_c: int = 0
    iso_interval: float = 0.0  # ISO interval, in milliseconds
    state: State = State.PENDING
    sink: Callable[[hci.HCI_IsoDataPacket], Any] | None = None

    EVENT_DISCONNECTION: ClassVar[str] = "disconnection"
    EVENT_DISCONNECTION_FAILURE: ClassVar[str] = "disconnection_failure"
    EVENT_ESTABLISHMENT: ClassVar[str] = "establishment"
    EVENT_ESTABLISHMENT_FAILURE: ClassVar[str] = "establishment_failure"

    def __post_init__(self) -> None:
        utils.EventEmitter.__init__(self)
        _IsoLink.__init__(self)

    async def disconnect(
        self, reason: int = hci.HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR
    ) -> None:
        await self.device.disconnect(self, reason)


# -----------------------------------------------------------------------------
@dataclass
class BisLink(_IsoLink):
    handle: int
    big: Big | BigSync
    sink: Callable[[hci.HCI_IsoDataPacket], Any] | None = None

    def __post_init__(self) -> None:
        super().__init__()
        self.device = self.big.device


# -----------------------------------------------------------------------------
class IsoPacketStream:
    """Async stream that can write SDUs to a CIS or BIS, with a maximum queue size."""

    iso_link: _IsoLink
    data_packet_queue: DataPacketQueue

    def __init__(self, iso_link: _IsoLink, max_queue_size: int) -> None:
        if iso_link.data_packet_queue is None:
            raise ValueError('link has no data packet queue')

        self.iso_link = iso_link
        self.data_packet_queue = iso_link.data_packet_queue
        self.data_packet_queue.on('flow', self._on_flow)
        self._thresholds: collections.deque[int] = collections.deque()
        self._semaphore = asyncio.Semaphore(max_queue_size)

    def _on_flow(self) -> None:
        # Release the semaphore once for each completed packet.
        while (
            self._thresholds and self.data_packet_queue.completed >= self._thresholds[0]
        ):
            self._thresholds.popleft()
            self._semaphore.release()

    async def write(self, sdu: bytes) -> None:
        """
        Write an SDU to the queue.

        This method blocks until there are fewer than max_queue_size packets queued
        but not yet completed.
        """

        # Wait until there's space in the queue.
        await self._semaphore.acquire()

        # Queue the packet.
        self.iso_link.write(sdu)

        # Remember the position of the packet so we can know when it is completed.
        self._thresholds.append(self.data_packet_queue.queued)


# -----------------------------------------------------------------------------
class Connection(utils.CompositeEventEmitter):
    device: Device
    handle: int
    transport: core.PhysicalTransport
    self_address: hci.Address
    self_resolvable_address: hci.Address | None
    peer_address: hci.Address
    peer_name: str | None
    peer_resolvable_address: hci.Address | None
    peer_le_features: hci.LeFeatureMask | None
    role: hci.Role
    parameters: Parameters
    encryption: int
    encryption_key_size: int
    authenticated: bool
    sc: bool
    gatt_client: gatt_client.Client
    pairing_peer_io_capability: int | None
    pairing_peer_authentication_requirements: int | None
    cs_configs: dict[int, ChannelSoundingConfig]  # Config ID to Configuration
    cs_procedures: dict[int, ChannelSoundingProcedure]  # Config ID to Procedures
    classic_mode: int = hci.HCI_Mode_Change_Event.Mode.ACTIVE
    classic_interval: int = 0

    EVENT_CONNECTION_ATT_MTU_UPDATE = "connection_att_mtu_update"
    EVENT_DISCONNECTION = "disconnection"
    EVENT_DISCONNECTION_FAILURE = "disconnection_failure"
    EVENT_CONNECTION_AUTHENTICATION = "connection_authentication"
    EVENT_CONNECTION_AUTHENTICATION_FAILURE = "connection_authentication_failure"
    EVENT_REMOTE_NAME = "remote_name"
    EVENT_REMOTE_NAME_FAILURE = "remote_name_failure"
    EVENT_CONNECTION_ENCRYPTION_CHANGE = "connection_encryption_change"
    EVENT_CONNECTION_ENCRYPTION_FAILURE = "connection_encryption_failure"
    EVENT_CONNECTION_ENCRYPTION_KEY_REFRESH = "connection_encryption_key_refresh"
    EVENT_CONNECTION_PARAMETERS_UPDATE = "connection_parameters_update"
    EVENT_CONNECTION_PARAMETERS_UPDATE_FAILURE = "connection_parameters_update_failure"
    EVENT_CONNECTION_PHY_UPDATE = "connection_phy_update"
    EVENT_CONNECTION_PHY_UPDATE_FAILURE = "connection_phy_update_failure"
    EVENT_CONNECTION_DATA_LENGTH_CHANGE = "connection_data_length_change"
    EVENT_CHANNEL_SOUNDING_CAPABILITIES_FAILURE = (
        "channel_sounding_capabilities_failure"
    )
    EVENT_CHANNEL_SOUNDING_CAPABILITIES = "channel_sounding_capabilities"
    EVENT_CHANNEL_SOUNDING_CONFIG_FAILURE = "channel_sounding_config_failure"
    EVENT_CHANNEL_SOUNDING_CONFIG = "channel_sounding_config"
    EVENT_CHANNEL_SOUNDING_CONFIG_REMOVED = "channel_sounding_config_removed"
    EVENT_CHANNEL_SOUNDING_PROCEDURE_FAILURE = "channel_sounding_procedure_failure"
    EVENT_CHANNEL_SOUNDING_PROCEDURE = "channel_sounding_procedure"
    EVENT_MODE_CHANGE = "mode_change"
    EVENT_MODE_CHANGE_FAILURE = "mode_change_failure"
    EVENT_ROLE_CHANGE = "role_change"
    EVENT_ROLE_CHANGE_FAILURE = "role_change_failure"
    EVENT_CLASSIC_PAIRING = "classic_pairing"
    EVENT_CLASSIC_PAIRING_FAILURE = "classic_pairing_failure"
    EVENT_PAIRING_START = "pairing_start"
    EVENT_PAIRING = "pairing"
    EVENT_PAIRING_FAILURE = "pairing_failure"
    EVENT_SECURITY_REQUEST = "security_request"
    EVENT_LINK_KEY = "link_key"
    EVENT_CIS_REQUEST = "cis_request"
    EVENT_CIS_ESTABLISHMENT = "cis_establishment"
    EVENT_CIS_ESTABLISHMENT_FAILURE = "cis_establishment_failure"
    EVENT_LE_SUBRATE_CHANGE = "le_subrate_change"
    EVENT_LE_SUBRATE_CHANGE_FAILURE = "le_subrate_change_failure"

    @utils.composite_listener
    class Listener:
        def on_disconnection(self, reason):
            pass

        def on_connection_parameters_update(self):
            pass

        def on_connection_parameters_update_failure(self, error):
            pass

        def on_connection_data_length_change(self):
            pass

        def on_connection_phy_update(self, phy):
            pass

        def on_connection_phy_update_failure(self, error):
            pass

        def on_connection_att_mtu_update(self):
            pass

        def on_connection_encryption_change(self):
            pass

        def on_connection_encryption_key_refresh(self):
            pass

    @dataclass
    class Parameters:
        """
        LE connection parameters.

        Attributes:
          connection_interval: Connection interval, in milliseconds.
          peripheral_latency: Peripheral latency, in number of intervals.
          supervision_timeout: Supervision timeout, in milliseconds.
          subrate_factor: See Bluetooth spec Vol 6, Part B - 4.5.1 Connection events
          continuation_number: See Bluetooth spec Vol 6, Part B - 4.5.1 Connection events
        """

        connection_interval: float
        peripheral_latency: int
        supervision_timeout: float
        subrate_factor: int = 1
        continuation_number: int = 0

    def __init__(
        self,
        device: Device,
        handle: int,
        transport: core.PhysicalTransport,
        self_address: hci.Address,
        self_resolvable_address: hci.Address | None,
        peer_address: hci.Address,
        peer_resolvable_address: hci.Address | None,
        role: hci.Role,
        parameters: Parameters,
    ):
        super().__init__()
        self.device = device
        self.handle = handle
        self.transport = transport
        self.self_address = self_address
        self.self_resolvable_address = self_resolvable_address
        self.peer_address = peer_address
        self.peer_resolvable_address = peer_resolvable_address
        self.peer_name = None  # Classic only
        self.role = role
        self.parameters = parameters
        self.encryption = 0
        self.encryption_key_size = 0
        self.authenticated = False
        self.sc = False
        self.att_mtu = att.ATT_DEFAULT_MTU
        self.data_length = DEVICE_DEFAULT_DATA_LENGTH
        self.gatt_client = gatt_client.Client(self)  # Per-connection client
        self.gatt_server = (
            device.gatt_server
        )  # By default, use the device's shared server
        self.pairing_peer_io_capability = None
        self.pairing_peer_authentication_requirements = None
        self.peer_le_features = None
        self.cs_configs = {}
        self.cs_procedures = {}

    @property
    def role_name(self):
        if self.role is None:
            return 'NOT-SET'
        if self.role == hci.Role.CENTRAL:
            return 'CENTRAL'
        if self.role == hci.Role.PERIPHERAL:
            return 'PERIPHERAL'
        return f'UNKNOWN[{self.role}]'

    @property
    def is_encrypted(self) -> bool:
        return self.encryption != 0

    @property
    def is_incomplete(self) -> bool:
        return self.handle is None

    def send_l2cap_pdu(self, cid: int, pdu: bytes) -> None:
        self.device.send_l2cap_pdu(self.handle, cid, pdu)

    @overload
    async def create_l2cap_channel(
        self, spec: l2cap.ClassicChannelSpec
    ) -> l2cap.ClassicChannel: ...

    @overload
    async def create_l2cap_channel(
        self, spec: l2cap.LeCreditBasedChannelSpec
    ) -> l2cap.LeCreditBasedChannel: ...

    async def create_l2cap_channel(
        self, spec: l2cap.ClassicChannelSpec | l2cap.LeCreditBasedChannelSpec
    ) -> l2cap.ClassicChannel | l2cap.LeCreditBasedChannel:
        return await self.device.create_l2cap_channel(connection=self, spec=spec)

    async def disconnect(
        self, reason: int = hci.HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR
    ) -> None:
        await self.device.disconnect(self, reason)

    async def pair(self) -> None:
        return await self.device.pair(self)

    def request_pairing(self) -> None:
        return self.device.request_pairing(self)

    # [Classic only]
    async def authenticate(self) -> None:
        return await self.device.authenticate(self)

    async def encrypt(self, enable: bool = True) -> None:
        return await self.device.encrypt(self, enable)

    async def switch_role(self, role: hci.Role) -> None:
        return await self.device.switch_role(self, role)

    async def sustain(self, timeout: float | None = None) -> None:
        """Idles the current task waiting for a disconnect or timeout"""

        abort = asyncio.get_running_loop().create_future()
        with closing(utils.EventWatcher()) as watcher:
            watcher.on(self, self.EVENT_DISCONNECTION, abort.set_result)
            watcher.on(self, self.EVENT_DISCONNECTION_FAILURE, abort.set_exception)

            await asyncio.wait_for(
                utils.cancel_on_event(self.device, Device.EVENT_FLUSH, abort), timeout
            )

    async def set_data_length(self, tx_octets: int, tx_time: int) -> None:
        return await self.device.set_data_length(self, tx_octets, tx_time)

    async def update_parameters(
        self,
        connection_interval_min: float,
        connection_interval_max: float,
        max_latency: int,
        supervision_timeout: float,
        use_l2cap=False,
    ) -> None:
        """
        Request an update of the connection parameters.

        Args:
          connection_interval_min: Minimum interval, in milliseconds.
          connection_interval_max: Maximum interval, in milliseconds.
          max_latency: Latency, in number of intervals.
          supervision_timeout: Timeout, in milliseconds.
          use_l2cap: Request the update via L2CAP.
        """
        return await self.device.update_connection_parameters(
            self,
            connection_interval_min,
            connection_interval_max,
            max_latency,
            supervision_timeout,
            use_l2cap=use_l2cap,
        )

    async def set_phy(
        self,
        tx_phys: Iterable[hci.Phy] | None = None,
        rx_phys: Iterable[hci.Phy] | None = None,
        phy_options: int = 0,
    ):
        return await self.device.set_connection_phy(self, tx_phys, rx_phys, phy_options)

    async def get_phy(self) -> ConnectionPHY:
        return await self.device.get_connection_phy(self)

    async def get_rssi(self):
        return await self.device.get_connection_rssi(self)

    async def transfer_periodic_sync(
        self, sync_handle: int, service_data: int = 0
    ) -> None:
        await self.device.transfer_periodic_sync(self, sync_handle, service_data)

    async def transfer_periodic_set_info(
        self, advertising_handle: int, service_data: int = 0
    ) -> None:
        await self.device.transfer_periodic_set_info(
            self, advertising_handle, service_data
        )

    # [Classic only]
    async def request_remote_name(self):
        return await self.device.request_remote_name(self)

    async def get_remote_le_features(self) -> hci.LeFeatureMask:
        """[LE Only] Reads remote LE supported features.

        Returns:
            LE features supported by the remote device.
        """
        self.peer_le_features = await self.device.get_remote_le_features(self)
        return self.peer_le_features

    def on_att_mtu_update(self, mtu: int):
        logger.debug(
            f'*** Connection ATT MTU Update: [0x{self.handle:04X}] '
            f'{self.peer_address} as {self.role_name}, '
            f'{mtu}'
        )
        self.att_mtu = mtu
        self.emit(self.EVENT_CONNECTION_ATT_MTU_UPDATE)

    @property
    def data_packet_queue(self) -> DataPacketQueue | None:
        return self.device.host.get_data_packet_queue(self.handle)

    def cancel_on_disconnection(self, awaitable: Awaitable[_T]) -> Awaitable[_T]:
        """
        Helper method to call `utils.cancel_on_event` for the 'disconnection' event
        """
        return utils.cancel_on_event(self, self.EVENT_DISCONNECTION, awaitable)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            try:
                await self.disconnect()
            except hci.HCI_StatusError as error:
                # Invalid parameter means the connection is no longer valid
                if error.error_code != hci.HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR:
                    raise

    def __str__(self):
        if self.transport == PhysicalTransport.LE:
            return (
                f'Connection(transport=LE, handle=0x{self.handle:04X}, '
                f'role={self.role_name}, '
                f'self_address={self.self_address}, '
                f'self_resolvable_address={self.self_resolvable_address}, '
                f'peer_address={self.peer_address}, '
                f'peer_resolvable_address={self.peer_resolvable_address})'
            )
        else:
            return (
                f'Connection(transport=BR/EDR, handle=0x{self.handle:04X}, '
                f'role={self.role_name}, '
                f'self_address={self.self_address}, '
                f'peer_address={self.peer_address})'
            )


# -----------------------------------------------------------------------------
@dataclass
class DeviceConfiguration:
    # Setup defaults
    name: str = DEVICE_DEFAULT_NAME
    address: hci.Address = hci.Address(DEVICE_DEFAULT_ADDRESS)
    class_of_device: int = DEVICE_DEFAULT_CLASS_OF_DEVICE
    scan_response_data: bytes = DEVICE_DEFAULT_SCAN_RESPONSE_DATA
    advertising_interval_min: float = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    advertising_interval_max: float = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    le_enabled: bool = True
    le_simultaneous_enabled: bool = False
    le_privacy_enabled: bool = False
    le_rpa_timeout: int = DEVICE_DEFAULT_LE_RPA_TIMEOUT
    le_subrate_enabled: bool = False
    classic_enabled: bool = False
    classic_sc_enabled: bool = True
    classic_ssp_enabled: bool = True
    classic_smp_enabled: bool = True
    classic_accept_any: bool = True
    classic_interlaced_scan_enabled: bool = True
    connectable: bool = True
    discoverable: bool = True
    advertising_data: bytes = bytes(
        AdvertisingData([data_types.CompleteLocalName(DEVICE_DEFAULT_NAME)])
    )
    irk: bytes = bytes(16)  # This really must be changed for any level of security
    keystore: str | None = None
    address_resolution_offload: bool = False
    address_generation_offload: bool = False
    cis_enabled: bool = False
    channel_sounding_enabled: bool = False
    identity_address_type: int | None = None
    io_capability: int = pairing.PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT
    gap_service_enabled: bool = True
    gatt_service_enabled: bool = True
    enhanced_retransmission_supported: bool = False
    l2cap_extended_features: Sequence[int] = (
        l2cap.L2CAP_Information_Request.ExtendedFeatures.FIXED_CHANNELS,
        l2cap.L2CAP_Information_Request.ExtendedFeatures.FCS_OPTION,
        l2cap.L2CAP_Information_Request.ExtendedFeatures.ENHANCED_RETRANSMISSION_MODE,
    )
    eatt_enabled: bool = False

    def __post_init__(self) -> None:
        self.gatt_services: list[dict[str, Any]] = []

    def load_from_dict(self, config: dict[str, Any]) -> None:
        config = copy.deepcopy(config)

        # Load simple properties
        if address := config.pop('address', None):
            self.address = hci.Address(address)

        # Load or synthesize an IRK
        if irk := config.pop('irk', None):
            self.irk = bytes.fromhex(irk)
        elif self.address != hci.Address(DEVICE_DEFAULT_ADDRESS):
            # Construct an IRK from the address bytes
            # NOTE: this is not secure, but will always give the same IRK for the same
            # address
            address_bytes = bytes(self.address)
            self.irk = (address_bytes * 3)[:16]
        else:
            # Fallback - when both IRK and address are not set, randomly generate an IRK.
            self.irk = secrets.token_bytes(16)

        if (name := config.pop('name', None)) is not None:
            self.name = name

        # Load advertising data
        if advertising_data := config.pop('advertising_data', None):
            self.advertising_data = bytes.fromhex(advertising_data)
        elif name is not None:
            self.advertising_data = bytes(
                AdvertisingData([data_types.CompleteLocalName(self.name)])
            )

        # Load scan response data
        if scan_response_data := config.pop('scan_response_data', None):
            self.scan_response_data = bytes.fromhex(scan_response_data)

        # Load advertising interval (for backward compatibility)
        if advertising_interval := config.pop('advertising_interval', None):
            self.advertising_interval_min = advertising_interval
            self.advertising_interval_max = advertising_interval
            if (
                'advertising_interval_max' in config
                or 'advertising_interval_min' in config
            ):
                logger.warning(
                    'Trying to set both advertising_interval and '
                    'advertising_interval_min/max, advertising_interval will be'
                    'ignored.'
                )

        # Load data in primitive types.
        for key, value in config.items():
            setattr(self, key, value)

    def load_from_file(self, filename: str) -> None:
        with open(filename, encoding='utf-8') as file:
            self.load_from_dict(json.load(file))

    @classmethod
    def from_file(cls: type[Self], filename: str) -> Self:
        config = cls()
        config.load_from_file(filename)
        return config

    @classmethod
    def from_dict(cls: type[Self], config: dict[str, Any]) -> Self:
        device_config = cls()
        device_config.load_from_dict(config)
        return device_config


# -----------------------------------------------------------------------------
# Decorators used with the following Device class
# (we define them outside of the Device class, because defining decorators
#  within a class requires unnecessarily complicated acrobatics)
# -----------------------------------------------------------------------------


# Decorator that converts the first argument from a connection handle to a connection
def with_connection_from_handle(function):
    @functools.wraps(function)
    def wrapper(self, connection_handle: int, *args, **kwargs):
        if (connection := self.lookup_connection(connection_handle)) is None:
            raise ObjectLookupError(
                f'no connection for handle: 0x{connection_handle:04x}'
            )
        return function(self, connection, *args, **kwargs)

    return wrapper


# Decorator that converts the first argument from a bluetooth address to a connection
def with_connection_from_address(function):
    @functools.wraps(function)
    def wrapper(device: Device, address: hci.Address, *args, **kwargs):
        if connection := device.pending_connections.get(address):
            return function(device, connection, *args, **kwargs)
        for connection in device.connections.values():
            if connection.peer_address == address:
                return function(device, connection, *args, **kwargs)
        raise ObjectLookupError('no connection for address')

    return wrapper


# Decorator that tries to convert the first argument from a bluetooth address to a
# connection
def try_with_connection_from_address(function):
    @functools.wraps(function)
    def wrapper(device: Device, address: hci.Address, *args, **kwargs):
        if connection := device.pending_connections.get(address):
            return function(device, connection, address, *args, **kwargs)
        for connection in device.connections.values():
            if connection.peer_address == address:
                return function(device, connection, address, *args, **kwargs)
        return function(device, None, address, *args, **kwargs)

    return wrapper


# Decorator that converts the first argument from a sync handle to a periodic
# advertising sync object
def with_periodic_advertising_sync_from_handle(function):
    @functools.wraps(function)
    def wrapper(self, sync_handle, *args, **kwargs):
        if (sync := self.lookup_periodic_advertising_sync(sync_handle)) is None:
            raise ValueError(
                f'no periodic advertising sync for handle: 0x{sync_handle:04x}'
            )
        return function(self, sync, *args, **kwargs)

    return wrapper


# Decorator that adds a method to the list of event handlers for host events.
# This assumes that the method name starts with `on_`
def host_event_handler(function):
    device_host_event_handlers.append(function.__name__[3:])
    return function


# List of host event handlers for the Device class.
# (we define this list outside the class, because referencing a class in method
#  decorators is not straightforward)
device_host_event_handlers: list[str] = []


# -----------------------------------------------------------------------------
class Device(utils.CompositeEventEmitter):
    # Incomplete list of fields.
    random_address: hci.Address  # Random private address that may change periodically
    public_address: (
        hci.Address
    )  # Public address that is globally unique (from controller)
    static_address: hci.Address  # Random static address that does not change once set
    classic_enabled: bool
    name: str
    class_of_device: int
    gatt_server: gatt_server.Server
    advertising_data: bytes
    scan_response_data: bytes
    cs_capabilities: ChannelSoundingCapabilities | None = None
    connections: dict[int, Connection]
    pending_connections: dict[hci.Address, Connection]
    classic_pending_accepts: dict[
        hci.Address,
        list[asyncio.Future[Connection | tuple[hci.Address, int, int]]],
    ]
    advertisement_accumulators: dict[hci.Address, AdvertisementDataAccumulator]
    periodic_advertising_syncs: list[PeriodicAdvertisingSync]
    config: DeviceConfiguration
    legacy_advertiser: LegacyAdvertiser | None
    sco_links: dict[int, ScoLink]
    cis_links: dict[int, CisLink]
    bigs: dict[int, Big]
    bis_links: dict[int, BisLink]
    big_syncs: dict[int, BigSync]
    _pending_cis: dict[int, tuple[int, int]]
    gatt_service: gatt_service.GenericAttributeProfileService | None = None

    EVENT_ADVERTISEMENT = "advertisement"
    EVENT_PERIODIC_ADVERTISING_SYNC_TRANSFER = "periodic_advertising_sync_transfer"
    EVENT_KEY_STORE_UPDATE = "key_store_update"
    EVENT_FLUSH = "flush"
    EVENT_CONNECTION = "connection"
    EVENT_CONNECTION_FAILURE = "connection_failure"
    EVENT_SCO_REQUEST = "sco_request"
    EVENT_INQUIRY_COMPLETE = "inquiry_complete"
    EVENT_SCO_CONNECTION = "sco_connection"
    EVENT_SCO_CONNECTION_FAILURE = "sco_connection_failure"
    EVENT_CIS_REQUEST = "cis_request"
    EVENT_CIS_ESTABLISHMENT = "cis_establishment"
    EVENT_CIS_ESTABLISHMENT_FAILURE = "cis_establishment_failure"
    EVENT_ROLE_CHANGE_FAILURE = "role_change_failure"
    EVENT_INQUIRY_RESULT = "inquiry_result"
    EVENT_REMOTE_NAME = "remote_name"
    EVENT_REMOTE_NAME_FAILURE = "remote_name_failure"

    @utils.composite_listener
    class Listener:
        def on_advertisement(self, advertisement):
            pass

        def on_inquiry_result(self, address, class_of_device, data, rssi):
            pass

        def on_connection(self, connection):
            pass

        def on_connection_failure(self, error):
            pass

        def on_connection_request(self, bd_addr, class_of_device, link_type):
            pass

        def on_characteristic_subscription(
            self, connection, characteristic, notify_enabled, indicate_enabled
        ):
            pass

    @classmethod
    def with_hci(
        cls,
        name: str,
        address: hci.Address,
        hci_source: TransportSource,
        hci_sink: TransportSink,
    ) -> Device:
        '''
        Create a Device instance with a Host configured to communicate with a controller
        through an HCI source/sink
        '''
        host = Host(controller_source=hci_source, controller_sink=hci_sink)
        return cls(name=name, address=address, host=host)

    @classmethod
    def from_config_file(cls, filename: str) -> Device:
        config = DeviceConfiguration.from_file(filename)
        return cls(config=config)

    @classmethod
    def from_config_with_hci(
        cls,
        config: DeviceConfiguration,
        hci_source: TransportSource,
        hci_sink: TransportSink,
    ) -> Device:
        host = Host(controller_source=hci_source, controller_sink=hci_sink)
        return cls(config=config, host=host)

    @classmethod
    def from_config_file_with_hci(
        cls, filename: str, hci_source: TransportSource, hci_sink: TransportSink
    ) -> Device:
        config = DeviceConfiguration.from_file(filename)
        return cls.from_config_with_hci(config, hci_source, hci_sink)

    def __init__(
        self,
        name: str | None = None,
        address: hci.Address | None = None,
        config: DeviceConfiguration | None = None,
        host: Host | None = None,
    ) -> None:
        super().__init__()

        # Use the initial config or a default
        config = config or DeviceConfiguration()
        self.config = config

        self._host = None
        self.powered_on = False
        self.auto_restart_inquiry = True
        self.command_timeout = 10  # seconds
        self.gatt_server = gatt_server.Server(self)
        self.sdp_server = sdp.Server(self)
        self.l2cap_channel_manager = l2cap.ChannelManager(
            config.l2cap_extended_features
        )
        self.advertisement_accumulators = {}  # Accumulators, by address
        self.periodic_advertising_syncs = []
        self.scanning = False
        self.scanning_is_passive = False
        self.discovering = False
        self.le_connecting = False
        self.disconnecting = False
        self.connections = {}  # Connections, by connection handle
        self.pending_connections = (
            {}
        )  # Pending connections, by BD address (BR/EDR only)
        self.sco_links = {}  # ScoLinks, by connection handle (BR/EDR only)
        self.cis_links = {}  # CisLinks, by connection handle (LE only)
        self._pending_cis = {}  # (CIS_ID, CIG_ID), by CIS_handle
        self.bigs = {}
        self.bis_links = {}
        self.big_syncs = {}
        self.classic_enabled = False
        self.inquiry_response = None
        self.address_resolver = None
        self.classic_pending_accepts = {
            hci.Address.ANY: []
        }  # Futures, by BD address OR [Futures] for hci.Address.ANY

        self._cis_lock = asyncio.Lock()

        # Own address type cache
        self.connect_own_address_type = None

        self.name = config.name
        self.public_address = hci.Address.ANY
        self.random_address = config.address
        self.static_address = config.address
        self.class_of_device = config.class_of_device
        self.keystore = None
        self.irk = config.irk
        self.le_enabled = config.le_enabled
        self.le_simultaneous_enabled = config.le_simultaneous_enabled
        self.le_privacy_enabled = config.le_privacy_enabled
        self.le_rpa_timeout = config.le_rpa_timeout
        self.le_rpa_periodic_update_task: asyncio.Task | None = None
        self.le_subrate_enabled = config.le_subrate_enabled
        self.classic_enabled = config.classic_enabled
        self.cis_enabled = config.cis_enabled
        self.classic_sc_enabled = config.classic_sc_enabled
        self.classic_ssp_enabled = config.classic_ssp_enabled
        self.classic_smp_enabled = config.classic_smp_enabled
        self.classic_interlaced_scan_enabled = config.classic_interlaced_scan_enabled
        self.discoverable = config.discoverable
        self.connectable = config.connectable
        self.classic_accept_any = config.classic_accept_any
        self.address_resolution_offload = config.address_resolution_offload
        self.address_generation_offload = config.address_generation_offload

        # Extended advertising.
        self.extended_advertising_sets: dict[int, AdvertisingSet] = {}
        self.connecting_extended_advertising_sets: dict[int, AdvertisingSet] = {}

        # Legacy advertising.
        # The advertising and scan response data, as well as the advertising interval
        # values are stored as properties of this object for convenience so that they
        # can be initialized from a config object, and for backward compatibility for
        # client code that may set those values directly before calling
        # start_advertising().
        self.legacy_advertising_set: AdvertisingSet | None = None
        self.legacy_advertiser: LegacyAdvertiser | None = None
        self.advertising_data = config.advertising_data
        self.scan_response_data = config.scan_response_data
        self.advertising_interval_min = config.advertising_interval_min
        self.advertising_interval_max = config.advertising_interval_max

        for service in config.gatt_services:
            characteristics = []
            for characteristic in service.get("characteristics", []):
                descriptors = []
                for descriptor in characteristic.get("descriptors", []):
                    # Leave this check until 5/25/2023
                    if descriptor.get("permission", False):
                        raise Exception(
                            "Error parsing Device Config's GATT Services. "
                            "The key 'permission' must be renamed to 'permissions'"
                        )
                    new_descriptor = Descriptor(
                        attribute_type=descriptor["descriptor_type"],
                        permissions=descriptor["permissions"],
                    )
                    descriptors.append(new_descriptor)
                new_characteristic: Characteristic[bytes] = Characteristic(
                    uuid=characteristic["uuid"],
                    properties=Characteristic.Properties.from_string(
                        characteristic["properties"]
                    ),
                    permissions=characteristic["permissions"],
                    descriptors=descriptors,
                )
                characteristics.append(new_characteristic)
            new_service = Service(uuid=service["uuid"], characteristics=characteristics)
            self.gatt_server.add_service(new_service)

        # If a name is passed, override the name from the config
        if name:
            self.name = name

        # If an address is passed, override the address from the config
        if address:
            if isinstance(address, str):
                address = hci.Address(address)
            self.random_address = address
            self.static_address = address

        # Setup SMP
        self.smp_manager = smp.Manager(
            self,
            pairing_config_factory=lambda connection: pairing.PairingConfig(
                identity_address_type=(
                    pairing.PairingConfig.AddressType(self.config.identity_address_type)
                    if self.config.identity_address_type
                    else None
                ),
                delegate=pairing.PairingDelegate(
                    io_capability=pairing.PairingDelegate.IoCapability(
                        self.config.io_capability
                    )
                ),
            ),
        )

        self.l2cap_channel_manager.register_fixed_channel(smp.SMP_CID, self.on_smp_pdu)

        # Register the SDP server with the L2CAP Channel Manager
        self.sdp_server.register(self.l2cap_channel_manager)

        self.add_default_services(
            add_gap_service=config.gap_service_enabled,
            add_gatt_service=config.gatt_service_enabled,
        )
        self.l2cap_channel_manager.register_fixed_channel(att.ATT_CID, self.on_gatt_pdu)

        if self.config.eatt_enabled:
            self.gatt_server.register_eatt()

        # Forward some events
        utils.setup_event_forwarding(
            self.gatt_server, self, 'characteristic_subscription'
        )

        # Set the initial host
        if host:
            self.host = host

    @property
    def host(self) -> Host:
        assert self._host
        return self._host

    @host.setter
    def host(self, host: Host) -> None:
        # Unsubscribe from events from the current host
        if self._host:
            for event_name in device_host_event_handlers:
                self._host.remove_listener(
                    event_name, getattr(self, f'on_{event_name}')
                )

        # Subscribe to events from the new host
        if host:
            for event_name in device_host_event_handlers:
                host.on(event_name, getattr(self, f'on_{event_name}'))

        # Update the references to the new host
        self._host = host
        self.l2cap_channel_manager.host = host

        # Set providers for the new host
        if host:
            host.long_term_key_provider = self.get_long_term_key
            host.link_key_provider = self.get_link_key

    @property
    def sdp_service_records(self):
        return self.sdp_server.service_records

    @sdp_service_records.setter
    def sdp_service_records(self, service_records):
        self.sdp_server.service_records = service_records

    def lookup_connection(self, connection_handle: int) -> Connection | None:
        if connection := self.connections.get(connection_handle):
            return connection

        return None

    def find_connection_by_bd_addr(
        self,
        bd_addr: hci.Address,
        transport: int | None = None,
        check_address_type: bool = False,
    ) -> Connection | None:
        for connection in self.connections.values():
            if bytes(connection.peer_address) == bytes(bd_addr):
                if (
                    check_address_type
                    and connection.peer_address.address_type != bd_addr.address_type
                ):
                    continue
                if transport is None or connection.transport == transport:
                    return connection

        return None

    def lookup_periodic_advertising_sync(
        self, sync_handle: int
    ) -> PeriodicAdvertisingSync | None:
        return next(
            (
                sync
                for sync in self.periodic_advertising_syncs
                if sync.sync_handle == sync_handle
            ),
            None,
        )

    def next_big_handle(self) -> int | None:
        return next(
            (
                handle
                for handle in range(DEVICE_MIN_BIG_HANDLE, DEVICE_MAX_BIG_HANDLE + 1)
                if handle
                not in itertools.chain(self.bigs.keys(), self.big_syncs.keys())
            ),
            None,
        )

    @overload
    async def create_l2cap_channel(
        self,
        connection: Connection,
        spec: l2cap.ClassicChannelSpec,
    ) -> l2cap.ClassicChannel: ...

    @overload
    async def create_l2cap_channel(
        self,
        connection: Connection,
        spec: l2cap.LeCreditBasedChannelSpec,
    ) -> l2cap.LeCreditBasedChannel: ...

    async def create_l2cap_channel(
        self,
        connection: Connection,
        spec: l2cap.ClassicChannelSpec | l2cap.LeCreditBasedChannelSpec,
    ) -> l2cap.ClassicChannel | l2cap.LeCreditBasedChannel:
        if isinstance(spec, l2cap.ClassicChannelSpec):
            return await self.l2cap_channel_manager.create_classic_channel(
                connection=connection, spec=spec
            )
        if isinstance(spec, l2cap.LeCreditBasedChannelSpec):
            return await self.l2cap_channel_manager.create_le_credit_based_channel(
                connection=connection, spec=spec
            )

    @overload
    def create_l2cap_server(
        self,
        spec: l2cap.ClassicChannelSpec,
        handler: Callable[[l2cap.ClassicChannel], Any] | None = None,
    ) -> l2cap.ClassicChannelServer: ...

    @overload
    def create_l2cap_server(
        self,
        spec: l2cap.LeCreditBasedChannelSpec,
        handler: Callable[[l2cap.LeCreditBasedChannel], Any] | None = None,
    ) -> l2cap.LeCreditBasedChannelServer: ...

    def create_l2cap_server(
        self,
        spec: l2cap.ClassicChannelSpec | l2cap.LeCreditBasedChannelSpec,
        handler: (
            Callable[[l2cap.ClassicChannel], Any]
            | Callable[[l2cap.LeCreditBasedChannel], Any]
            | None
        ) = None,
    ) -> l2cap.ClassicChannelServer | l2cap.LeCreditBasedChannelServer:
        if isinstance(spec, l2cap.ClassicChannelSpec):
            return self.l2cap_channel_manager.create_classic_server(
                spec=spec,
                handler=cast(Callable[[l2cap.ClassicChannel], Any], handler),
            )
        elif isinstance(spec, l2cap.LeCreditBasedChannelSpec):
            return self.l2cap_channel_manager.create_le_credit_based_server(
                handler=cast(Callable[[l2cap.LeCreditBasedChannel], Any], handler),
                spec=spec,
            )
        else:
            raise InvalidArgumentError(f'Unexpected mode {spec}')

    def send_l2cap_pdu(self, connection_handle: int, cid: int, pdu: bytes) -> None:
        self.host.send_l2cap_pdu(connection_handle, cid, pdu)

    async def send_command(self, command: hci.HCI_Command, check_result: bool = False):
        try:
            return await asyncio.wait_for(
                self.host.send_command(command, check_result), self.command_timeout
            )
        except asyncio.TimeoutError as error:
            logger.warning(f'!!! Command {command.name} timed out')
            raise CommandTimeoutError() from error

    async def power_on(self) -> None:
        # Reset the controller
        await self.host.reset()

        # Try to get the public address from the controller
        response = await self.send_command(hci.HCI_Read_BD_ADDR_Command())
        if response.return_parameters.status == hci.HCI_SUCCESS:
            logger.debug(
                color(f'BD_ADDR: {response.return_parameters.bd_addr}', 'yellow')
            )
            self.public_address = response.return_parameters.bd_addr

        # Instantiate the Key Store (we do this here rather than at __init__ time
        # because some Key Store implementations use the public address as a namespace)
        if self.keystore is None:
            self.keystore = KeyStore.create_for_device(self)

        # Finish setting up SMP based on post-init configurable options
        if self.classic_smp_enabled:
            self.l2cap_channel_manager.register_fixed_channel(
                smp.SMP_BR_CID, self.on_smp_pdu
            )

        if self.host.supports_command(hci.HCI_WRITE_LE_HOST_SUPPORT_COMMAND):
            await self.send_command(
                hci.HCI_Write_LE_Host_Support_Command(
                    le_supported_host=int(self.le_enabled),
                    simultaneous_le_host=int(self.le_simultaneous_enabled),
                ),
                check_result=True,
            )

        if self.le_enabled:
            # Generate a random address if not set.
            if self.static_address == hci.Address.ANY_RANDOM:
                self.static_address = hci.Address.generate_static_address()

            # If LE Privacy is enabled, generate an RPA
            if self.le_privacy_enabled:
                self.random_address = hci.Address.generate_private_address(self.irk)
                logger.info(f'Initial RPA: {self.random_address}')
                if self.le_rpa_timeout > 0:
                    # Start a task to periodically generate a new RPA
                    self.le_rpa_periodic_update_task = asyncio.create_task(
                        self._run_rpa_periodic_update()
                    )
            else:
                self.random_address = self.static_address

            if self.random_address != hci.Address.ANY_RANDOM:
                logger.debug(
                    color(
                        f'LE Random Address: {self.random_address}',
                        'yellow',
                    )
                )
                await self.send_command(
                    hci.HCI_LE_Set_Random_Address_Command(
                        random_address=self.random_address
                    ),
                    check_result=True,
                )

            # Load the address resolving list
            if self.keystore:
                await self.refresh_resolving_list()

            # Enable address resolution
            if self.address_resolution_offload:
                await self.send_command(
                    hci.HCI_LE_Set_Address_Resolution_Enable_Command(
                        address_resolution_enable=1
                    ),
                    check_result=True,
                )

            if self.cis_enabled:
                await self.send_command(
                    hci.HCI_LE_Set_Host_Feature_Command(
                        bit_number=hci.LeFeature.CONNECTED_ISOCHRONOUS_STREAM,
                        bit_value=1,
                    ),
                    check_result=True,
                )

            if self.le_subrate_enabled:
                await self.send_command(
                    hci.HCI_LE_Set_Host_Feature_Command(
                        bit_number=hci.LeFeature.CONNECTION_SUBRATING_HOST_SUPPORT,
                        bit_value=1,
                    ),
                    check_result=True,
                )

            if self.config.channel_sounding_enabled:
                await self.send_command(
                    hci.HCI_LE_Set_Host_Feature_Command(
                        bit_number=hci.LeFeature.CHANNEL_SOUNDING_HOST_SUPPORT,
                        bit_value=1,
                    ),
                    check_result=True,
                )
                result = await self.send_command(
                    hci.HCI_LE_CS_Read_Local_Supported_Capabilities_Command(),
                    check_result=True,
                )
                self.cs_capabilities = ChannelSoundingCapabilities(
                    num_config_supported=result.return_parameters.num_config_supported,
                    max_consecutive_procedures_supported=result.return_parameters.max_consecutive_procedures_supported,
                    num_antennas_supported=result.return_parameters.num_antennas_supported,
                    max_antenna_paths_supported=result.return_parameters.max_antenna_paths_supported,
                    roles_supported=result.return_parameters.roles_supported,
                    modes_supported=result.return_parameters.modes_supported,
                    rtt_capability=result.return_parameters.rtt_capability,
                    rtt_aa_only_n=result.return_parameters.rtt_aa_only_n,
                    rtt_sounding_n=result.return_parameters.rtt_sounding_n,
                    rtt_random_payload_n=result.return_parameters.rtt_random_payload_n,
                    nadm_sounding_capability=result.return_parameters.nadm_sounding_capability,
                    nadm_random_capability=result.return_parameters.nadm_random_capability,
                    cs_sync_phys_supported=result.return_parameters.cs_sync_phys_supported,
                    subfeatures_supported=result.return_parameters.subfeatures_supported,
                    t_ip1_times_supported=result.return_parameters.t_ip1_times_supported,
                    t_ip2_times_supported=result.return_parameters.t_ip2_times_supported,
                    t_fcs_times_supported=result.return_parameters.t_fcs_times_supported,
                    t_pm_times_supported=result.return_parameters.t_pm_times_supported,
                    t_sw_time_supported=result.return_parameters.t_sw_time_supported,
                    tx_snr_capability=result.return_parameters.tx_snr_capability,
                )

        if self.classic_enabled:
            await self.send_command(
                hci.HCI_Write_Local_Name_Command(local_name=self.name.encode('utf8'))
            )
            await self.send_command(
                hci.HCI_Write_Class_Of_Device_Command(
                    class_of_device=self.class_of_device
                )
            )
            await self.send_command(
                hci.HCI_Write_Simple_Pairing_Mode_Command(
                    simple_pairing_mode=int(self.classic_ssp_enabled)
                )
            )
            await self.send_command(
                hci.HCI_Write_Secure_Connections_Host_Support_Command(
                    secure_connections_host_support=int(self.classic_sc_enabled)
                )
            )
            await self.set_connectable(self.connectable)
            await self.set_discoverable(self.discoverable)

            if self.classic_interlaced_scan_enabled:
                if self.host.supports_lmp_features(
                    hci.LmpFeatureMask.INTERLACED_PAGE_SCAN
                ):
                    await self.send_command(
                        hci.HCI_Write_Page_Scan_Type_Command(page_scan_type=1),
                        check_result=True,
                    )

                if self.host.supports_lmp_features(
                    hci.LmpFeatureMask.INTERLACED_INQUIRY_SCAN
                ):
                    await self.send_command(
                        hci.HCI_Write_Inquiry_Scan_Type_Command(scan_type=1),
                        check_result=True,
                    )

        # Done
        self.powered_on = True

    async def reset(self) -> None:
        await self.host.reset()

    async def power_off(self) -> None:
        if self.powered_on:
            if self.le_rpa_periodic_update_task:
                self.le_rpa_periodic_update_task.cancel()

            await self.host.flush()

            self.powered_on = False

    async def update_rpa(self) -> bool:
        """
        Try to update the RPA.

        Returns:
          True if the RPA was updated, False if it could not be updated.
        """

        # Check if this is a good time to rotate the address
        if self.is_advertising or self.is_scanning or self.is_le_connecting:
            logger.debug('skipping RPA update')
            return False

        random_address = hci.Address.generate_private_address(self.irk)
        response = await self.send_command(
            hci.HCI_LE_Set_Random_Address_Command(random_address=self.random_address)
        )
        if response.return_parameters == hci.HCI_SUCCESS:
            logger.info(f'new RPA: {random_address}')
            self.random_address = random_address
            return True
        else:
            logger.warning(f'failed to set RPA: {response.return_parameters}')
            return False

    async def _run_rpa_periodic_update(self) -> None:
        """Update the RPA periodically"""
        while self.le_rpa_timeout != 0:
            await asyncio.sleep(self.le_rpa_timeout)
            if not await self.update_rpa():
                logger.debug("periodic RPA update failed")

    async def refresh_resolving_list(self) -> None:
        assert self.keystore is not None

        resolving_keys = await self.keystore.get_resolving_keys()
        # Create a host-side address resolver
        self.address_resolver = smp.AddressResolver(resolving_keys)

        if self.address_resolution_offload or self.address_generation_offload:
            await self.send_command(
                hci.HCI_LE_Clear_Resolving_List_Command(), check_result=True
            )

            # Add an empty entry for non-directed address generation.
            await self.send_command(
                hci.HCI_LE_Add_Device_To_Resolving_List_Command(
                    peer_identity_address_type=hci.Address.ANY.address_type,
                    peer_identity_address=hci.Address.ANY,
                    peer_irk=bytes(16),
                    local_irk=self.irk,
                ),
                check_result=True,
            )

            for irk, address in resolving_keys:
                await self.send_command(
                    hci.HCI_LE_Add_Device_To_Resolving_List_Command(
                        peer_identity_address_type=address.address_type,
                        peer_identity_address=address,
                        peer_irk=irk,
                        local_irk=self.irk,
                    ),
                    check_result=True,
                )

    def supports_le_features(self, feature: hci.LeFeatureMask) -> bool:
        return self.host.supports_le_features(feature)

    def supports_le_phy(self, phy: hci.Phy) -> bool:
        if phy == hci.Phy.LE_1M:
            return True

        feature_map: dict[hci.Phy, hci.LeFeatureMask] = {
            hci.Phy.LE_2M: hci.LeFeatureMask.LE_2M_PHY,
            hci.Phy.LE_CODED: hci.LeFeatureMask.LE_CODED_PHY,
        }
        if phy not in feature_map:
            raise InvalidArgumentError('invalid PHY')

        return self.supports_le_features(feature_map[phy])

    @property
    def supports_le_extended_advertising(self):
        return self.supports_le_features(hci.LeFeatureMask.LE_EXTENDED_ADVERTISING)

    @property
    def supports_le_periodic_advertising(self):
        return self.supports_le_features(hci.LeFeatureMask.LE_PERIODIC_ADVERTISING)

    async def start_advertising(
        self,
        advertising_type: AdvertisingType = AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE,
        target: hci.Address | None = None,
        own_address_type: hci.OwnAddressType = hci.OwnAddressType.RANDOM,
        auto_restart: bool = False,
        advertising_data: bytes | None = None,
        scan_response_data: bytes | None = None,
        advertising_interval_min: float | None = None,
        advertising_interval_max: float | None = None,
    ) -> None:
        """Start legacy advertising.

        If the controller supports it, extended advertising commands with legacy PDUs
        will be used to advertise. If not, legacy advertising commands will be used.

        Args:
          advertising_type:
            Type of advertising events.
          target:
            Peer address for directed advertising target.
            (Ignored if `advertising_type` is not directed)
          own_address_type:
            Own address type to use in the advertising.
          auto_restart:
            Whether the advertisement will be restarted after disconnection.
          advertising_data:
            Raw advertising data. If None, the value of the property
            self.advertising_data will be used.
          scan_response_data:
            Raw scan response. If None, the value of the property
            self.scan_response_data will be used.
          advertising_interval_min:
            Minimum advertising interval, in milliseconds. If None, the value of the
            property self.advertising_interval_min will be used.
          advertising_interval_max:
            Maximum advertising interval, in milliseconds. If None, the value of the
            property self.advertising_interval_max will be used.
        """
        # Update backing properties.
        if advertising_data is not None:
            self.advertising_data = advertising_data
        if scan_response_data is not None:
            self.scan_response_data = scan_response_data
        if advertising_interval_min is not None:
            self.advertising_interval_min = advertising_interval_min
        if advertising_interval_max is not None:
            self.advertising_interval_max = advertising_interval_max

        # Decide what peer address to use
        if advertising_type.is_directed:
            if target is None:
                raise InvalidArgumentError('directed advertising requires a target')
            peer_address = target
        else:
            peer_address = hci.Address.ANY

        # If we're already advertising, stop now because we'll be re-creating
        # a new advertiser or advertising set.
        await self.stop_advertising()
        assert self.legacy_advertiser is None
        assert self.legacy_advertising_set is None

        if self.supports_le_extended_advertising:
            # Use extended advertising commands with legacy PDUs.
            self.legacy_advertising_set = await self.create_advertising_set(
                auto_start=True,
                auto_restart=auto_restart,
                random_address=self.random_address,
                advertising_parameters=AdvertisingParameters(
                    advertising_event_properties=(
                        AdvertisingEventProperties.from_advertising_type(
                            advertising_type
                        )
                    ),
                    primary_advertising_interval_min=self.advertising_interval_min,
                    primary_advertising_interval_max=self.advertising_interval_max,
                    own_address_type=hci.OwnAddressType(own_address_type),
                    peer_address=peer_address,
                ),
                advertising_data=(
                    self.advertising_data if advertising_type.has_data else b''
                ),
                scan_response_data=(
                    self.scan_response_data if advertising_type.is_scannable else b''
                ),
            )
        else:
            # Use legacy commands.
            self.legacy_advertiser = LegacyAdvertiser(
                device=self,
                advertising_type=advertising_type,
                own_address_type=hci.OwnAddressType(own_address_type),
                peer_address=peer_address,
                auto_restart=auto_restart,
            )

            await self.legacy_advertiser.start()

    async def stop_advertising(self) -> None:
        """Stop legacy advertising."""
        # Disable advertising
        if self.legacy_advertising_set:
            if self.legacy_advertising_set.enabled:
                await self.legacy_advertising_set.stop()
            await self.legacy_advertising_set.remove()
            self.legacy_advertising_set = None
        elif self.legacy_advertiser:
            await self.legacy_advertiser.stop()
            self.legacy_advertiser = None

    async def create_advertising_set(
        self,
        advertising_parameters: AdvertisingParameters | None = None,
        random_address: hci.Address | None = None,
        advertising_data: bytes = b'',
        scan_response_data: bytes = b'',
        periodic_advertising_parameters: PeriodicAdvertisingParameters | None = None,
        periodic_advertising_data: bytes = b'',
        auto_start: bool = True,
        auto_restart: bool = False,
    ) -> AdvertisingSet:
        """
        Create an advertising set.

        This method allows the creation of advertising sets for controllers that
        support extended advertising.

        Args:
          advertising_parameters:
            The parameters to use for this set. If None, default parameters are used.
          random_address:
            The random address to use (only relevant when the parameters specify that
            own_address_type is random).
          advertising_data:
            Initial value for the set's advertising data.
          scan_response_data:
            Initial value for the set's scan response data.
          periodic_advertising_parameters:
            The parameters to use for periodic advertising (if needed).
          periodic_advertising_data:
            Initial value for the set's periodic advertising data.
          auto_start:
            True if the set should be automatically started upon creation.
          auto_restart:
            True if the set should be automatically restated after a disconnection.

        Returns:
          An AdvertisingSet instance.
        """
        # Instantiate default values
        if advertising_parameters is None:
            advertising_parameters = AdvertisingParameters()

        if periodic_advertising_data and periodic_advertising_parameters is None:
            periodic_advertising_parameters = PeriodicAdvertisingParameters()

        if (
            not advertising_parameters.advertising_event_properties.is_legacy
            and advertising_data
            and scan_response_data
        ):
            raise InvalidArgumentError(
                "Extended advertisements can't have both data and scan response data"
            )

        if periodic_advertising_parameters and (
            advertising_parameters.advertising_event_properties.is_connectable
            or advertising_parameters.advertising_event_properties.is_scannable
            or advertising_parameters.advertising_event_properties.is_anonymous
            or advertising_parameters.advertising_event_properties.is_legacy
        ):
            raise InvalidArgumentError(
                "Periodic advertising set cannot be connectable, scannable, anonymous,"
                "or legacy"
            )

        # Allocate a new handle
        try:
            advertising_handle = next(
                handle
                for handle in range(
                    DEVICE_MIN_EXTENDED_ADVERTISING_SET_HANDLE,
                    DEVICE_MAX_EXTENDED_ADVERTISING_SET_HANDLE + 1,
                )
                if handle not in self.extended_advertising_sets
            )
        except StopIteration as exc:
            raise OutOfResourcesError(
                "all valid advertising handles already in use"
            ) from exc

        # Use the device's random address if a random address is needed but none was
        # provided.
        if (
            advertising_parameters.own_address_type
            in (hci.OwnAddressType.RANDOM, hci.OwnAddressType.RESOLVABLE_OR_RANDOM)
            and random_address is None
        ):
            random_address = self.random_address

        # Create the object that represents the set.
        advertising_set = AdvertisingSet(
            device=self,
            advertising_handle=advertising_handle,
            auto_restart=auto_restart,
            random_address=random_address,
            advertising_parameters=advertising_parameters,
            advertising_data=advertising_data,
            scan_response_data=scan_response_data,
            periodic_advertising_parameters=periodic_advertising_parameters,
            periodic_advertising_data=periodic_advertising_data,
        )

        # Create the set in the controller.
        await advertising_set.set_advertising_parameters(advertising_parameters)

        # Update the set in the controller.
        try:
            if random_address:
                await advertising_set.set_random_address(random_address)

            if advertising_data:
                await advertising_set.set_advertising_data(advertising_data)

            if scan_response_data:
                await advertising_set.set_scan_response_data(scan_response_data)

            if periodic_advertising_parameters:
                await advertising_set.set_periodic_advertising_parameters(
                    periodic_advertising_parameters
                )

            if periodic_advertising_data:
                await advertising_set.set_periodic_advertising_data(
                    periodic_advertising_data
                )

        except hci.HCI_Error as error:
            # Remove the advertising set so that it doesn't stay dangling in the
            # controller.
            await self.send_command(
                hci.HCI_LE_Remove_Advertising_Set_Command(
                    advertising_handle=advertising_handle
                ),
                check_result=False,
            )
            raise error

        # Remember the set.
        self.extended_advertising_sets[advertising_handle] = advertising_set

        # Try to start the set if requested.
        if auto_start:
            try:
                # pylint: disable=line-too-long
                duration = (
                    DEVICE_MAX_HIGH_DUTY_CYCLE_CONNECTABLE_DIRECTED_ADVERTISING_DURATION
                    if advertising_parameters.advertising_event_properties.is_high_duty_cycle_directed_connectable
                    else 0
                )
                await advertising_set.start(duration=duration)
            except Exception:
                logger.exception('failed to start advertising set')
                await advertising_set.remove()
                raise

        return advertising_set

    @property
    def is_advertising(self):
        if self.legacy_advertiser:
            return True

        return any(
            advertising_set.enabled
            for advertising_set in self.extended_advertising_sets.values()
        )

    async def start_scanning(
        self,
        legacy: bool = False,
        active: bool = True,
        scan_interval: float = DEVICE_DEFAULT_SCAN_INTERVAL,  # Scan interval in ms
        scan_window: float = DEVICE_DEFAULT_SCAN_WINDOW,  # Scan window in ms
        own_address_type: hci.OwnAddressType = hci.OwnAddressType.RANDOM,
        filter_duplicates: bool = False,
        scanning_phys: Sequence[int] = (hci.HCI_LE_1M_PHY, hci.HCI_LE_CODED_PHY),
    ) -> None:
        # Check that the arguments are legal
        if scan_interval < scan_window:
            raise InvalidArgumentError('scan_interval must be >= scan_window')
        if (
            scan_interval < DEVICE_MIN_SCAN_INTERVAL
            or scan_interval > DEVICE_MAX_SCAN_INTERVAL
        ):
            raise InvalidArgumentError('scan_interval out of range')
        if scan_window < DEVICE_MIN_SCAN_WINDOW or scan_window > DEVICE_MAX_SCAN_WINDOW:
            raise InvalidArgumentError('scan_interval out of range')

        # Reset the accumulators
        self.advertisement_accumulators = {}

        # Enable scanning
        if not legacy and self.supports_le_extended_advertising:
            # Set the scanning parameters
            scan_type = (
                hci.HCI_LE_Set_Extended_Scan_Parameters_Command.ACTIVE_SCANNING
                if active
                else hci.HCI_LE_Set_Extended_Scan_Parameters_Command.PASSIVE_SCANNING
            )
            scanning_filter_policy = (
                hci.HCI_LE_Set_Extended_Scan_Parameters_Command.BASIC_UNFILTERED_POLICY
            )  # TODO: support other types

            scanning_phy_count = 0
            scanning_phys_bits = 0
            if hci.HCI_LE_1M_PHY in scanning_phys:
                scanning_phys_bits |= 1 << hci.HCI_LE_1M_PHY_BIT
                scanning_phy_count += 1
            if hci.HCI_LE_CODED_PHY in scanning_phys:
                if self.supports_le_features(hci.LeFeatureMask.LE_CODED_PHY):
                    scanning_phys_bits |= 1 << hci.HCI_LE_CODED_PHY_BIT
                    scanning_phy_count += 1

            if scanning_phy_count == 0:
                raise InvalidArgumentError('at least one scanning PHY must be enabled')

            await self.send_command(
                hci.HCI_LE_Set_Extended_Scan_Parameters_Command(
                    own_address_type=own_address_type,
                    scanning_filter_policy=scanning_filter_policy,
                    scanning_phys=scanning_phys_bits,
                    scan_types=[scan_type] * scanning_phy_count,
                    scan_intervals=[int(scan_interval / 0.625)] * scanning_phy_count,
                    scan_windows=[int(scan_window / 0.625)] * scanning_phy_count,
                ),
                check_result=True,
            )

            # Enable scanning
            await self.send_command(
                hci.HCI_LE_Set_Extended_Scan_Enable_Command(
                    enable=1,
                    filter_duplicates=1 if filter_duplicates else 0,
                    duration=0,  # TODO allow other values
                    period=0,  # TODO allow other values
                ),
                check_result=True,
            )
        else:
            # Set the scanning parameters
            scan_type = (
                hci.HCI_LE_Set_Scan_Parameters_Command.ACTIVE_SCANNING
                if active
                else hci.HCI_LE_Set_Scan_Parameters_Command.PASSIVE_SCANNING
            )
            await self.send_command(
                # pylint: disable=line-too-long
                hci.HCI_LE_Set_Scan_Parameters_Command(
                    le_scan_type=scan_type,
                    le_scan_interval=int(scan_interval / 0.625),
                    le_scan_window=int(scan_window / 0.625),
                    own_address_type=own_address_type,
                    scanning_filter_policy=hci.HCI_LE_Set_Scan_Parameters_Command.BASIC_UNFILTERED_POLICY,
                ),
                check_result=True,
            )

            # Enable scanning
            await self.send_command(
                hci.HCI_LE_Set_Scan_Enable_Command(
                    le_scan_enable=1, filter_duplicates=1 if filter_duplicates else 0
                ),
                check_result=True,
            )

        self.scanning_is_passive = not active
        self.scanning = True

    async def stop_scanning(self, legacy: bool = False) -> None:
        # Disable scanning
        if not legacy and self.supports_le_extended_advertising:
            await self.send_command(
                hci.HCI_LE_Set_Extended_Scan_Enable_Command(
                    enable=0, filter_duplicates=0, duration=0, period=0
                ),
                check_result=True,
            )
        else:
            await self.send_command(
                hci.HCI_LE_Set_Scan_Enable_Command(
                    le_scan_enable=0, filter_duplicates=0
                ),
                check_result=True,
            )

        self.scanning = False

    @property
    def is_scanning(self):
        return self.scanning

    @host_event_handler
    def on_advertising_report(
        self,
        report: (
            hci.HCI_LE_Advertising_Report_Event.Report
            | hci.HCI_LE_Extended_Advertising_Report_Event.Report
        ),
    ) -> None:
        if not (accumulator := self.advertisement_accumulators.get(report.address)):
            accumulator = AdvertisementDataAccumulator(passive=self.scanning_is_passive)
            self.advertisement_accumulators[report.address] = accumulator
        if advertisement := accumulator.update(report):
            self.emit(self.EVENT_ADVERTISEMENT, advertisement)

    async def create_periodic_advertising_sync(
        self,
        advertiser_address: hci.Address,
        sid: int,
        skip: int = DEVICE_DEFAULT_PERIODIC_ADVERTISING_SYNC_SKIP,
        sync_timeout: float = DEVICE_DEFAULT_PERIODIC_ADVERTISING_SYNC_TIMEOUT,
        filter_duplicates: bool = False,
    ) -> PeriodicAdvertisingSync:
        # Check that the controller supports the feature.
        if not self.supports_le_periodic_advertising:
            raise NotSupportedError()

        # Check that there isn't already an equivalent entry
        if any(
            sync.advertiser_address == advertiser_address and sync.sid == sid
            for sync in self.periodic_advertising_syncs
        ):
            raise ValueError("equivalent entry already created")

        # Create a new entry
        sync = PeriodicAdvertisingSync(
            device=self,
            advertiser_address=advertiser_address,
            sid=sid,
            skip=skip,
            sync_timeout=sync_timeout,
            filter_duplicates=filter_duplicates,
        )

        self.periodic_advertising_syncs.append(sync)

        # Check if any sync should be started
        await self._update_periodic_advertising_syncs()

        return sync

    async def _update_periodic_advertising_syncs(self) -> None:
        # Check if there's already a pending sync
        if any(
            sync.state == PeriodicAdvertisingSync.State.PENDING
            for sync in self.periodic_advertising_syncs
        ):
            logger.debug("at least one sync pending, nothing to update yet")
            return

        # Start the next sync that's waiting to be started
        if ready := next(
            (
                sync
                for sync in self.periodic_advertising_syncs
                if sync.state == PeriodicAdvertisingSync.State.INIT
            ),
            None,
        ):
            await ready.establish()
            return

    @host_event_handler
    def on_periodic_advertising_sync_establishment(
        self,
        status: int,
        sync_handle: int,
        advertising_sid: int,
        advertiser_address: hci.Address,
        advertiser_phy: int,
        periodic_advertising_interval: int,
        advertiser_clock_accuracy: int,
    ) -> None:
        for periodic_advertising_sync in self.periodic_advertising_syncs:
            if (
                periodic_advertising_sync.advertiser_address == advertiser_address
                and periodic_advertising_sync.sid == advertising_sid
            ):
                periodic_advertising_sync.on_establishment(
                    status,
                    sync_handle,
                    advertiser_phy,
                    periodic_advertising_interval,
                    advertiser_clock_accuracy,
                )

                utils.AsyncRunner.spawn(self._update_periodic_advertising_syncs())

                return

        logger.warning(
            "periodic advertising sync establishment for unknown address/sid"
        )

    @host_event_handler
    def on_periodic_advertising_sync_transfer(
        self,
        status: int,
        connection_handle: int,
        sync_handle: int,
        advertising_sid: int,
        advertiser_address: hci.Address,
        advertiser_phy: int,
        periodic_advertising_interval: int,
        advertiser_clock_accuracy: int,
    ) -> None:
        if not (connection := self.lookup_connection(connection_handle)):
            logger.error(
                "Receive PAST from unknown connection 0x%04X", connection_handle
            )

        pa_sync = PeriodicAdvertisingSync(
            device=self,
            advertiser_address=advertiser_address,
            sid=advertising_sid,
            skip=0,
            sync_timeout=0.0,
            filter_duplicates=False,
        )
        self.periodic_advertising_syncs.append(pa_sync)
        pa_sync.on_establishment(
            status=status,
            sync_handle=sync_handle,
            advertiser_phy=advertiser_phy,
            periodic_advertising_interval=periodic_advertising_interval,
            advertiser_clock_accuracy=advertiser_clock_accuracy,
        )
        self.emit(self.EVENT_PERIODIC_ADVERTISING_SYNC_TRANSFER, pa_sync, connection)

    @host_event_handler
    @with_periodic_advertising_sync_from_handle
    def on_periodic_advertising_sync_loss(
        self, periodic_advertising_sync: PeriodicAdvertisingSync
    ):
        periodic_advertising_sync.on_loss()

    @host_event_handler
    @with_periodic_advertising_sync_from_handle
    def on_periodic_advertising_report(
        self,
        periodic_advertising_sync: PeriodicAdvertisingSync,
        report: hci.HCI_LE_Periodic_Advertising_Report_Event,
    ):
        periodic_advertising_sync.on_periodic_advertising_report(report)

    @host_event_handler
    @with_periodic_advertising_sync_from_handle
    def on_biginfo_advertising_report(
        self,
        periodic_advertising_sync: PeriodicAdvertisingSync,
        report: hci.HCI_LE_BIGInfo_Advertising_Report_Event,
    ):
        periodic_advertising_sync.on_biginfo_advertising_report(report)

    async def start_discovery(self, auto_restart: bool = True) -> None:
        await self.send_command(
            hci.HCI_Write_Inquiry_Mode_Command(
                inquiry_mode=hci.HCI_EXTENDED_INQUIRY_MODE
            ),
            check_result=True,
        )

        self.discovering = False
        await self.send_command(
            hci.HCI_Inquiry_Command(
                lap=hci.HCI_GENERAL_INQUIRY_LAP,
                inquiry_length=DEVICE_DEFAULT_INQUIRY_LENGTH,
                num_responses=0,  # Unlimited number of responses.
            ),
            check_result=True,
        )

        self.auto_restart_inquiry = auto_restart
        self.discovering = True

    async def stop_discovery(self) -> None:
        if self.discovering:
            await self.send_command(hci.HCI_Inquiry_Cancel_Command(), check_result=True)
        self.auto_restart_inquiry = True
        self.discovering = False

    @host_event_handler
    def on_inquiry_result(
        self, address: hci.Address, class_of_device: int, data: bytes, rssi: int
    ):
        self.emit(
            self.EVENT_INQUIRY_RESULT,
            address,
            class_of_device,
            AdvertisingData.from_bytes(data),
            rssi,
        )

    async def set_scan_enable(
        self, inquiry_scan_enabled: bool, page_scan_enabled: bool
    ):
        if inquiry_scan_enabled and page_scan_enabled:
            scan_enable = 0x03
        elif page_scan_enabled:
            scan_enable = 0x02
        elif inquiry_scan_enabled:
            scan_enable = 0x01
        else:
            scan_enable = 0x00

        return await self.send_command(
            hci.HCI_Write_Scan_Enable_Command(scan_enable=scan_enable),
            check_result=True,
        )

    async def set_discoverable(self, discoverable: bool = True) -> None:
        self.discoverable = discoverable
        if self.classic_enabled:
            # Synthesize an inquiry response if none is set already
            if self.inquiry_response is None:
                self.inquiry_response = bytes(
                    AdvertisingData([data_types.CompleteLocalName(self.name)])
                )

            # Update the controller
            await self.send_command(
                hci.HCI_Write_Extended_Inquiry_Response_Command(
                    fec_required=0, extended_inquiry_response=self.inquiry_response
                ),
                check_result=True,
            )
            await self.set_scan_enable(
                inquiry_scan_enabled=self.discoverable,
                page_scan_enabled=self.connectable,
            )

    async def set_connectable(self, connectable: bool = True) -> None:
        self.connectable = connectable
        if self.classic_enabled:
            await self.set_scan_enable(
                inquiry_scan_enabled=self.discoverable,
                page_scan_enabled=self.connectable,
            )

    async def connect(
        self,
        peer_address: hci.Address | str,
        transport: core.PhysicalTransport = PhysicalTransport.LE,
        connection_parameters_preferences: (
            dict[hci.Phy, ConnectionParametersPreferences] | None
        ) = None,
        own_address_type: hci.OwnAddressType = hci.OwnAddressType.RANDOM,
        timeout: float | None = DEVICE_DEFAULT_CONNECT_TIMEOUT,
        always_resolve: bool = False,
    ) -> Connection:
        '''
        Request a connection to a peer.

        When the transport is BLE, this method cannot be called if there is already a
        pending connection.

        Args:
          peer_address:
            hci.Address or name of the device to connect to.
            If a string is passed:
              If the string is an address followed by a `@` suffix, the `always_resolve`
              argument is implicitly set to True, so the connection is made to the
              address after resolution.
              If the string is any other address, the connection is made to that
              address (with or without address resolution, depending on the
              `always_resolve` argument).
              For any other string, a scan for devices using that string as their name
              is initiated, and a connection to the first matching device's address
              is made. In that case, `always_resolve` is ignored.

          connection_parameters_preferences:
            (BLE only, ignored for BR/EDR)
            * None: use the 1M PHY with default parameters
            * map: each entry has a PHY as key and a ConnectionParametersPreferences
              object as value

          own_address_type:
            (BLE only, ignored for BR/EDR)
            hci.OwnAddressType.RANDOM to use this device's random address, or
            hci.OwnAddressType.PUBLIC to use this device's public address.

          timeout:
            Maximum time to wait for a connection to be established, in seconds.
            Pass None for an unlimited time.

          always_resolve:
            (BLE only, ignored for BR/EDR)
            If True, always initiate a scan, resolving addresses, and connect to the
            address that resolves to `peer_address`.
        '''

        # Check parameters
        if transport not in (PhysicalTransport.LE, PhysicalTransport.BR_EDR):
            raise InvalidArgumentError('invalid transport')
        transport = core.PhysicalTransport(transport)

        # Adjust the transport automatically if we need to
        if transport == PhysicalTransport.LE and not self.le_enabled:
            transport = PhysicalTransport.BR_EDR
        elif transport == PhysicalTransport.BR_EDR and not self.classic_enabled:
            transport = PhysicalTransport.LE

        # Check that there isn't already a pending connection
        if transport == PhysicalTransport.LE and self.is_le_connecting:
            raise InvalidStateError('connection already pending')

        if isinstance(peer_address, str):
            try:
                if transport == PhysicalTransport.LE and peer_address.endswith('@'):
                    peer_address = hci.Address.from_string_for_transport(
                        peer_address[:-1], transport
                    )
                    always_resolve = True
                    logger.debug('forcing address resolution')
                else:
                    peer_address = hci.Address.from_string_for_transport(
                        peer_address, transport
                    )
            except (InvalidArgumentError, ValueError):
                # If the address is not parsable, assume it is a name instead
                always_resolve = False
                logger.debug('looking for peer by name')
                assert isinstance(peer_address, str)
                peer_address = await self.find_peer_by_name(
                    peer_address, transport
                )  # TODO: timeout
        else:
            # All BR/EDR addresses should be public addresses
            if (
                transport == PhysicalTransport.BR_EDR
                and peer_address.address_type != hci.Address.PUBLIC_DEVICE_ADDRESS
            ):
                raise InvalidArgumentError('BR/EDR addresses must be PUBLIC')

        assert isinstance(peer_address, hci.Address)

        if transport == PhysicalTransport.LE and always_resolve:
            logger.debug('resolving address')
            peer_address = await self.find_peer_by_identity_address(
                peer_address
            )  # TODO: timeout

        def on_connection(connection):
            if transport == PhysicalTransport.LE or (
                # match BR/EDR connection event against peer address
                connection.transport == transport
                and connection.peer_address == peer_address
            ):
                pending_connection.set_result(connection)

        def on_connection_failure(error: core.ConnectionError):
            if transport == PhysicalTransport.LE or (
                # match BR/EDR connection failure event against peer address
                error.transport == transport
                and error.peer_address == peer_address
            ):
                pending_connection.set_exception(error)

        # Create a future so that we can wait for the connection's result
        pending_connection = asyncio.get_running_loop().create_future()
        self.on(self.EVENT_CONNECTION, on_connection)
        self.on(self.EVENT_CONNECTION_FAILURE, on_connection_failure)

        try:
            # Tell the controller to connect
            if transport == PhysicalTransport.LE:
                if connection_parameters_preferences is None:
                    if connection_parameters_preferences is None:
                        connection_parameters_preferences = {
                            hci.HCI_LE_1M_PHY: ConnectionParametersPreferences.default
                        }

                self.connect_own_address_type = own_address_type

                if self.host.supports_command(
                    hci.HCI_LE_EXTENDED_CREATE_CONNECTION_COMMAND
                ):
                    # Only keep supported PHYs
                    phys = sorted(
                        list(
                            set(
                                filter(
                                    self.supports_le_phy,
                                    connection_parameters_preferences.keys(),
                                )
                            )
                        )
                    )
                    if not phys:
                        raise InvalidArgumentError('at least one supported PHY needed')

                    phy_count = len(phys)
                    initiating_phys = hci.phy_list_to_bits(phys)

                    connection_interval_mins = [
                        int(
                            connection_parameters_preferences[
                                phy
                            ].connection_interval_min
                            / 1.25
                        )
                        for phy in phys
                    ]
                    connection_interval_maxs = [
                        int(
                            connection_parameters_preferences[
                                phy
                            ].connection_interval_max
                            / 1.25
                        )
                        for phy in phys
                    ]
                    max_latencies = [
                        connection_parameters_preferences[phy].max_latency
                        for phy in phys
                    ]
                    supervision_timeouts = [
                        int(
                            connection_parameters_preferences[phy].supervision_timeout
                            / 10
                        )
                        for phy in phys
                    ]
                    min_ce_lengths = [
                        int(
                            connection_parameters_preferences[phy].min_ce_length / 0.625
                        )
                        for phy in phys
                    ]
                    max_ce_lengths = [
                        int(
                            connection_parameters_preferences[phy].max_ce_length / 0.625
                        )
                        for phy in phys
                    ]

                    await self.send_command(
                        hci.HCI_LE_Extended_Create_Connection_Command(
                            initiator_filter_policy=0,
                            own_address_type=own_address_type,
                            peer_address_type=peer_address.address_type,
                            peer_address=peer_address,
                            initiating_phys=initiating_phys,
                            scan_intervals=(
                                int(DEVICE_DEFAULT_CONNECT_SCAN_INTERVAL / 0.625),
                            )
                            * phy_count,
                            scan_windows=(
                                int(DEVICE_DEFAULT_CONNECT_SCAN_WINDOW / 0.625),
                            )
                            * phy_count,
                            connection_interval_mins=connection_interval_mins,
                            connection_interval_maxs=connection_interval_maxs,
                            max_latencies=max_latencies,
                            supervision_timeouts=supervision_timeouts,
                            min_ce_lengths=min_ce_lengths,
                            max_ce_lengths=max_ce_lengths,
                        ),
                        check_result=True,
                    )
                else:
                    if hci.HCI_LE_1M_PHY not in connection_parameters_preferences:
                        raise InvalidArgumentError('1M PHY preferences required')

                    prefs = connection_parameters_preferences[hci.HCI_LE_1M_PHY]
                    await self.send_command(
                        hci.HCI_LE_Create_Connection_Command(
                            le_scan_interval=int(
                                DEVICE_DEFAULT_CONNECT_SCAN_INTERVAL / 0.625
                            ),
                            le_scan_window=int(
                                DEVICE_DEFAULT_CONNECT_SCAN_WINDOW / 0.625
                            ),
                            initiator_filter_policy=0,
                            peer_address_type=peer_address.address_type,
                            peer_address=peer_address,
                            own_address_type=own_address_type,
                            connection_interval_min=int(
                                prefs.connection_interval_min / 1.25
                            ),
                            connection_interval_max=int(
                                prefs.connection_interval_max / 1.25
                            ),
                            max_latency=prefs.max_latency,
                            supervision_timeout=int(prefs.supervision_timeout / 10),
                            min_ce_length=int(prefs.min_ce_length / 0.625),
                            max_ce_length=int(prefs.max_ce_length / 0.625),
                        ),
                        check_result=True,
                    )
            else:
                # Save pending connection
                self.pending_connections[peer_address] = Connection(
                    device=self,
                    handle=0,
                    transport=core.PhysicalTransport.BR_EDR,
                    self_address=self.public_address,
                    self_resolvable_address=None,
                    peer_address=peer_address,
                    peer_resolvable_address=None,
                    role=hci.Role.CENTRAL,
                    parameters=Connection.Parameters(0, 0, 0),
                )

                # TODO: allow passing other settings
                await self.send_command(
                    hci.HCI_Create_Connection_Command(
                        bd_addr=peer_address,
                        packet_type=0xCC18,  # FIXME: change
                        page_scan_repetition_mode=hci.HCI_R2_PAGE_SCAN_REPETITION_MODE,
                        clock_offset=0x0000,
                        allow_role_switch=0x01,
                        reserved=0,
                    ),
                    check_result=True,
                )

            # Wait for the connection process to complete
            if transport == PhysicalTransport.LE:
                self.le_connecting = True

            if timeout is None:
                return await utils.cancel_on_event(
                    self, Device.EVENT_FLUSH, pending_connection
                )

            try:
                return await asyncio.wait_for(
                    asyncio.shield(pending_connection), timeout
                )
            except asyncio.TimeoutError:
                if transport == PhysicalTransport.LE:
                    await self.send_command(
                        hci.HCI_LE_Create_Connection_Cancel_Command()
                    )
                else:
                    await self.send_command(
                        hci.HCI_Create_Connection_Cancel_Command(bd_addr=peer_address)
                    )

                try:
                    return await utils.cancel_on_event(
                        self, Device.EVENT_FLUSH, pending_connection
                    )
                except core.ConnectionError as error:
                    raise core.TimeoutError() from error
        finally:
            self.remove_listener(self.EVENT_CONNECTION, on_connection)
            self.remove_listener(self.EVENT_CONNECTION_FAILURE, on_connection_failure)
            if transport == PhysicalTransport.LE:
                self.le_connecting = False
                self.connect_own_address_type = None
            else:
                self.pending_connections.pop(peer_address, None)

    async def accept(
        self,
        peer_address: hci.Address | str = hci.Address.ANY,
        role: hci.Role = hci.Role.PERIPHERAL,
        timeout: float | None = DEVICE_DEFAULT_CONNECT_TIMEOUT,
    ) -> Connection:
        '''
        Wait and accept any incoming connection or a connection from `peer_address` when
        set.

        Notes:
          * A `connect` to the same peer will not complete this call.
          * The `timeout` parameter is only handled while waiting for the connection
            request, once received and accepted, the controller shall issue a connection
            complete event.
        '''

        if isinstance(peer_address, str):
            try:
                peer_address = hci.Address(peer_address)
            except InvalidArgumentError:
                # If the address is not parsable, assume it is a name instead
                logger.debug('looking for peer by name')
                assert isinstance(peer_address, str)
                peer_address = await self.find_peer_by_name(
                    peer_address, PhysicalTransport.BR_EDR
                )  # TODO: timeout

        assert isinstance(peer_address, hci.Address)

        if peer_address == hci.Address.NIL:
            raise InvalidArgumentError('accept on nil address')

        # Create a future so that we can wait for the request
        pending_request_fut = asyncio.get_running_loop().create_future()

        if peer_address == hci.Address.ANY:
            self.classic_pending_accepts[hci.Address.ANY].append(pending_request_fut)
        elif peer_address in self.classic_pending_accepts:
            raise InvalidStateError('accept connection already pending')
        else:
            self.classic_pending_accepts[peer_address] = [pending_request_fut]

        try:
            # Wait for a request or a completed connection
            pending_request = utils.cancel_on_event(
                self, Device.EVENT_FLUSH, pending_request_fut
            )
            result = await (
                asyncio.wait_for(pending_request, timeout)
                if timeout
                else pending_request
            )
        except Exception:
            # Remove future from device context
            if peer_address == hci.Address.ANY:
                self.classic_pending_accepts[hci.Address.ANY].remove(
                    pending_request_fut
                )
            else:
                self.classic_pending_accepts.pop(peer_address)
            raise

        # Result may already be a completed connection,
        # see `on_connection` for details
        if isinstance(result, Connection):
            return result

        # Otherwise, result came from `on_connection_request`
        peer_address, _class_of_device, _link_type = result
        assert isinstance(peer_address, hci.Address)

        # Create a future so that we can wait for the connection's result
        pending_connection = asyncio.get_running_loop().create_future()

        def on_connection(connection):
            if (
                connection.transport == PhysicalTransport.BR_EDR
                and connection.peer_address == peer_address
            ):
                pending_connection.set_result(connection)

        def on_connection_failure(error: core.ConnectionError):
            if (
                error.transport == PhysicalTransport.BR_EDR
                and error.peer_address == peer_address
            ):
                pending_connection.set_exception(error)

        self.on(self.EVENT_CONNECTION, on_connection)
        self.on(self.EVENT_CONNECTION_FAILURE, on_connection_failure)

        # Save Peripheral hci.role.
        # Even if we requested a role switch in the hci.HCI_Accept_Connection_Request
        # command, this connection is still considered Peripheral until an eventual
        # role change event.
        self.pending_connections[peer_address] = Connection(
            device=self,
            handle=0,
            transport=core.PhysicalTransport.BR_EDR,
            self_address=self.public_address,
            self_resolvable_address=None,
            peer_address=peer_address,
            peer_resolvable_address=None,
            role=hci.Role.PERIPHERAL,
            parameters=Connection.Parameters(0, 0, 0),
        )

        try:
            # Accept connection request
            await self.send_command(
                hci.HCI_Accept_Connection_Request_Command(
                    bd_addr=peer_address, role=role
                ),
                check_result=True,
            )

            # Wait for connection complete
            return await utils.cancel_on_event(
                self, Device.EVENT_FLUSH, pending_connection
            )

        finally:
            self.remove_listener(self.EVENT_CONNECTION, on_connection)
            self.remove_listener(self.EVENT_CONNECTION_FAILURE, on_connection_failure)
            self.pending_connections.pop(peer_address, None)

    @asynccontextmanager
    async def connect_as_gatt(self, peer_address: hci.Address | str):
        async with AsyncExitStack() as stack:
            connection = await stack.enter_async_context(
                await self.connect(peer_address)
            )
            peer = await stack.enter_async_context(Peer(connection))

            yield peer

    @property
    def is_le_connecting(self):
        return self.le_connecting

    @property
    def is_disconnecting(self):
        return self.disconnecting

    async def cancel_connection(self, peer_address=None):
        # Low-energy: cancel ongoing connection
        if peer_address is None:
            if not self.is_le_connecting:
                return
            await self.send_command(
                hci.HCI_LE_Create_Connection_Cancel_Command(), check_result=True
            )

        # BR/EDR: try to cancel to ongoing connection
        # NOTE: This API does not prevent from trying to cancel a connection which is
        # not currently being created
        else:
            if isinstance(peer_address, str):
                try:
                    peer_address = hci.Address(peer_address)
                except InvalidArgumentError:
                    # If the address is not parsable, assume it is a name instead
                    logger.debug('looking for peer by name')
                    assert isinstance(peer_address, str)
                    peer_address = await self.find_peer_by_name(
                        peer_address, PhysicalTransport.BR_EDR
                    )  # TODO: timeout

            await self.send_command(
                hci.HCI_Create_Connection_Cancel_Command(bd_addr=peer_address),
                check_result=True,
            )

    async def disconnect(
        self, connection: Connection | ScoLink | CisLink, reason: int
    ) -> None:
        # Create a future so that we can wait for the disconnection's result
        pending_disconnection = asyncio.get_running_loop().create_future()
        connection.on(connection.EVENT_DISCONNECTION, pending_disconnection.set_result)
        connection.on(
            connection.EVENT_DISCONNECTION_FAILURE, pending_disconnection.set_exception
        )

        try:
            # Wait for the disconnection process to complete
            self.disconnecting = True

            # Request a disconnection
            await self.send_command(
                hci.HCI_Disconnect_Command(
                    connection_handle=connection.handle, reason=reason
                ),
                check_result=True,
            )
            return await utils.cancel_on_event(
                self, Device.EVENT_FLUSH, pending_disconnection
            )
        finally:
            connection.remove_listener(
                connection.EVENT_DISCONNECTION, pending_disconnection.set_result
            )
            connection.remove_listener(
                connection.EVENT_DISCONNECTION_FAILURE,
                pending_disconnection.set_exception,
            )
            self.disconnecting = False

    async def set_data_length(
        self, connection: Connection, tx_octets: int, tx_time: int
    ) -> None:
        if tx_octets < 0x001B or tx_octets > 0x00FB:
            raise InvalidArgumentError('tx_octets must be between 0x001B and 0x00FB')

        if tx_time < 0x0148 or tx_time > 0x4290:
            raise InvalidArgumentError('tx_time must be between 0x0148 and 0x4290')

        return await self.send_command(
            hci.HCI_LE_Set_Data_Length_Command(
                connection_handle=connection.handle,
                tx_octets=tx_octets,
                tx_time=tx_time,
            ),
            check_result=True,
        )

    async def update_connection_parameters(
        self,
        connection: Connection,
        connection_interval_min: float,
        connection_interval_max: float,
        max_latency: int,
        supervision_timeout: float,
        min_ce_length: float = 0.0,
        max_ce_length: float = 0.0,
        use_l2cap: bool = False,
    ) -> None:
        '''
        Request an update of the connection parameters.

        Args:
          connection: The connection to update
          connection_interval_min: Minimum interval, in milliseconds.
          connection_interval_max: Maximum interval, in milliseconds.
          max_latency: Latency, in number of intervals.
          supervision_timeout: Timeout, in milliseconds.
          min_ce_length: Minimum connection event length, in milliseconds.
          max_ce_length: Maximum connection event length, in milliseconds.
          use_l2cap: Request the update via L2CAP.

        NOTE: the name of the parameters may look odd, but it just follows the names
        used in the Bluetooth spec.
        '''

        # Convert the input parameters
        connection_interval_min = int(connection_interval_min / 1.25)
        connection_interval_max = int(connection_interval_max / 1.25)
        supervision_timeout = int(supervision_timeout / 10)
        min_ce_length = int(min_ce_length / 0.625)
        max_ce_length = int(max_ce_length / 0.625)

        if use_l2cap:
            if connection.role != hci.Role.PERIPHERAL:
                raise InvalidStateError(
                    'only peripheral can update connection parameters with l2cap'
                )
            l2cap_result = (
                await self.l2cap_channel_manager.update_connection_parameters(
                    connection,
                    connection_interval_min,
                    connection_interval_max,
                    max_latency,
                    supervision_timeout,
                )
            )
            if l2cap_result != l2cap.L2CAP_CONNECTION_PARAMETERS_ACCEPTED_RESULT:
                raise ConnectionParameterUpdateError(l2cap_result)

            return

        await self.send_command(
            hci.HCI_LE_Connection_Update_Command(
                connection_handle=connection.handle,
                connection_interval_min=connection_interval_min,
                connection_interval_max=connection_interval_max,
                max_latency=max_latency,
                supervision_timeout=supervision_timeout,
                min_ce_length=min_ce_length,
                max_ce_length=max_ce_length,
            ),
            check_result=True,
        )

    async def get_connection_rssi(self, connection):
        result = await self.send_command(
            hci.HCI_Read_RSSI_Command(handle=connection.handle), check_result=True
        )
        return result.return_parameters.rssi

    async def get_connection_phy(self, connection: Connection) -> ConnectionPHY:
        if not self.host.supports_command(hci.HCI_LE_READ_PHY_COMMAND):
            return ConnectionPHY(hci.Phy.LE_1M, hci.Phy.LE_1M)

        result = await self.send_command(
            hci.HCI_LE_Read_PHY_Command(connection_handle=connection.handle),
            check_result=True,
        )
        return ConnectionPHY(
            result.return_parameters.tx_phy, result.return_parameters.rx_phy
        )

    async def set_connection_phy(
        self,
        connection: Connection,
        tx_phys: Iterable[hci.Phy] | None = None,
        rx_phys: Iterable[hci.Phy] | None = None,
        phy_options: int = 0,
    ):
        if not self.host.supports_command(hci.HCI_LE_SET_PHY_COMMAND):
            logger.warning('ignoring request, command not supported')
            return

        all_phys_bits = (1 if tx_phys is None else 0) | (
            (1 if rx_phys is None else 0) << 1
        )

        await self.send_command(
            hci.HCI_LE_Set_PHY_Command(
                connection_handle=connection.handle,
                all_phys=all_phys_bits,
                tx_phys=hci.phy_list_to_bits(tx_phys),
                rx_phys=hci.phy_list_to_bits(rx_phys),
                phy_options=phy_options,
            ),
            check_result=True,
        )

    async def set_default_phy(
        self,
        tx_phys: Iterable[hci.Phy] | None = None,
        rx_phys: Iterable[hci.Phy] | None = None,
    ):
        all_phys_bits = (1 if tx_phys is None else 0) | (
            (1 if rx_phys is None else 0) << 1
        )

        return await self.send_command(
            hci.HCI_LE_Set_Default_PHY_Command(
                all_phys=all_phys_bits,
                tx_phys=hci.phy_list_to_bits(tx_phys),
                rx_phys=hci.phy_list_to_bits(rx_phys),
            ),
            check_result=True,
        )

    async def transfer_periodic_sync(
        self, connection: Connection, sync_handle: int, service_data: int = 0
    ) -> None:
        return await self.send_command(
            hci.HCI_LE_Periodic_Advertising_Sync_Transfer_Command(
                connection_handle=connection.handle,
                service_data=service_data,
                sync_handle=sync_handle,
            ),
            check_result=True,
        )

    async def transfer_periodic_set_info(
        self, connection: Connection, advertising_handle: int, service_data: int = 0
    ) -> None:
        return await self.send_command(
            hci.HCI_LE_Periodic_Advertising_Set_Info_Transfer_Command(
                connection_handle=connection.handle,
                service_data=service_data,
                advertising_handle=advertising_handle,
            ),
            check_result=True,
        )

    async def find_peer_by_name(self, name: str, transport=PhysicalTransport.LE):
        """
        Scan for a peer with a given name and return its address.
        """

        # Create a future to wait for an address to be found
        peer_address = asyncio.get_running_loop().create_future()

        def on_peer_found(address: hci.Address, ad_data: AdvertisingData) -> None:
            local_name = ad_data.get(
                AdvertisingData.Type.COMPLETE_LOCAL_NAME
            ) or ad_data.get(AdvertisingData.Type.SHORTENED_LOCAL_NAME)
            if local_name == name:
                peer_address.set_result(address)

        listener: Callable[..., None] | None = None
        was_scanning = self.scanning
        was_discovering = self.discovering
        try:
            if transport == PhysicalTransport.LE:
                event_name = 'advertisement'
                listener = self.on(
                    event_name,
                    lambda advertisement: on_peer_found(
                        advertisement.address, advertisement.data
                    ),
                )

                if not self.scanning:
                    await self.start_scanning(filter_duplicates=True)

            elif transport == PhysicalTransport.BR_EDR:
                event_name = 'inquiry_result'
                listener = self.on(
                    event_name,
                    lambda address, class_of_device, eir_data, rssi: on_peer_found(
                        address, eir_data
                    ),
                )

                if not self.discovering:
                    await self.start_discovery()
            else:
                return None

            return await utils.cancel_on_event(self, Device.EVENT_FLUSH, peer_address)
        finally:
            if listener is not None:
                self.remove_listener(event_name, listener)

            if transport == PhysicalTransport.LE and not was_scanning:
                await self.stop_scanning()
            elif transport == PhysicalTransport.BR_EDR and not was_discovering:
                await self.stop_discovery()

    async def find_peer_by_identity_address(
        self, identity_address: hci.Address
    ) -> hci.Address:
        """
        Scan for a peer with a resolvable address that can be resolved to a given
        identity address.
        """

        # Create a future to wait for an address to be found
        peer_address = asyncio.get_running_loop().create_future()

        def on_peer_found(address, _):
            if address == identity_address:
                if not peer_address.done():
                    logger.debug(f'*** Matching public address found for {address}')
                    peer_address.set_result(address)
                return

            if address.is_resolvable:
                resolved_address = self.address_resolver.resolve(address)
                if resolved_address == identity_address:
                    if not peer_address.done():
                        logger.debug(f'*** Matching identity found for {address}')
                        peer_address.set_result(address)
                return

        was_scanning = self.scanning
        event_name = 'advertisement'
        listener = None
        try:
            listener = self.on(
                event_name,
                lambda advertisement: on_peer_found(
                    advertisement.address, advertisement.data
                ),
            )

            if not self.scanning:
                await self.start_scanning(filter_duplicates=True)

            return await utils.cancel_on_event(self, Device.EVENT_FLUSH, peer_address)
        finally:
            if listener is not None:
                self.remove_listener(event_name, listener)

            if not was_scanning:
                await self.stop_scanning()

    @property
    def pairing_config_factory(self) -> Callable[[Connection], pairing.PairingConfig]:
        return self.smp_manager.pairing_config_factory

    @pairing_config_factory.setter
    def pairing_config_factory(
        self, pairing_config_factory: Callable[[Connection], pairing.PairingConfig]
    ) -> None:
        self.smp_manager.pairing_config_factory = pairing_config_factory

    @property
    def smp_session_proxy(self) -> type[smp.Session]:
        return self.smp_manager.session_proxy

    @smp_session_proxy.setter
    def smp_session_proxy(self, session_proxy: type[smp.Session]) -> None:
        self.smp_manager.session_proxy = session_proxy

    async def pair(self, connection: Connection):
        return await self.smp_manager.pair(connection)

    def request_pairing(self, connection: Connection):
        return self.smp_manager.request_pairing(connection)

    async def get_long_term_key(
        self, connection_handle: int, rand: bytes, ediv: int
    ) -> bytes | None:
        if (connection := self.lookup_connection(connection_handle)) is None:
            return None

        # Start by looking for the key in an SMP session
        ltk = self.smp_manager.get_long_term_key(connection, rand, ediv)
        if ltk is not None:
            return ltk

        # Then look for the key in the keystore
        if self.keystore is not None:
            keys = await self.keystore.get(str(connection.peer_address))
            if keys is not None:
                logger.debug('found keys in the key store')
                if keys.ltk:
                    return keys.ltk.value

                if connection.role == hci.Role.CENTRAL and keys.ltk_central:
                    return keys.ltk_central.value

                if connection.role == hci.Role.PERIPHERAL and keys.ltk_peripheral:
                    return keys.ltk_peripheral.value
        return None

    async def get_link_key(self, address: hci.Address) -> bytes | None:
        if self.keystore is None:
            return None

        # Look for the key in the keystore
        keys = await self.keystore.get(str(address))
        if keys is None:
            logger.debug(f'no keys found for {address}')
            return None

        logger.debug('found keys in the key store')
        if keys.link_key is None:
            logger.warning('no link key')
            return None

        return keys.link_key.value

    # [Classic only]
    async def authenticate(self, connection: Connection) -> None:
        # Set up event handlers
        pending_authentication = asyncio.get_running_loop().create_future()
        with closing(utils.EventWatcher()) as watcher:

            @watcher.on(connection, connection.EVENT_CONNECTION_AUTHENTICATION)
            def on_authentication() -> None:
                pending_authentication.set_result(None)

            @watcher.on(connection, connection.EVENT_CONNECTION_AUTHENTICATION_FAILURE)
            def on_authentication_failure(error_code: int) -> None:
                pending_authentication.set_exception(hci.HCI_Error(error_code))

            # Request the authentication
            await self.send_command(
                hci.HCI_Authentication_Requested_Command(
                    connection_handle=connection.handle
                ),
                check_result=True,
            )

            # Wait for the authentication to complete
            await connection.cancel_on_disconnection(pending_authentication)

    async def encrypt(self, connection: Connection, enable: bool = True):
        if not enable and connection.transport == PhysicalTransport.LE:
            raise InvalidArgumentError('`enable` parameter is classic only.')

        # Set up event handlers
        pending_encryption = asyncio.get_running_loop().create_future()

        # Request the encryption
        with closing(utils.EventWatcher()) as watcher:

            @watcher.on(connection, connection.EVENT_CONNECTION_ENCRYPTION_CHANGE)
            def _() -> None:
                pending_encryption.set_result(None)

            @watcher.on(connection, connection.EVENT_CONNECTION_ENCRYPTION_FAILURE)
            def _(error_code: int):
                pending_encryption.set_exception(hci.HCI_Error(error_code))

            if connection.transport == PhysicalTransport.LE:
                # Look for a key in the key store
                if self.keystore is None:
                    raise InvalidOperationError('no key store')

                logger.debug(f'Looking up key for {connection.peer_address}')
                keys = await self.keystore.get(str(connection.peer_address))
                if keys is None:
                    raise InvalidOperationError('keys not found in key store')

                if keys.ltk is not None:
                    ltk = keys.ltk.value
                    rand = bytes(8)
                    ediv = 0
                elif keys.ltk_central is not None:
                    ltk = keys.ltk_central.value
                    rand = keys.ltk_central.rand
                    ediv = keys.ltk_central.ediv
                else:
                    raise InvalidOperationError('no LTK found for peer')

                if connection.role != hci.Role.CENTRAL:
                    raise InvalidStateError('only centrals can start encryption')

                await self.send_command(
                    hci.HCI_LE_Enable_Encryption_Command(
                        connection_handle=connection.handle,
                        random_number=rand,
                        encrypted_diversifier=ediv,
                        long_term_key=ltk,
                    ),
                    check_result=True,
                )
            else:
                await self.send_command(
                    hci.HCI_Set_Connection_Encryption_Command(
                        connection_handle=connection.handle,
                        encryption_enable=0x01 if enable else 0x00,
                    ),
                    check_result=True,
                )

            # Wait for the result
            await connection.cancel_on_disconnection(pending_encryption)

    async def update_keys(self, address: str, keys: PairingKeys) -> None:
        if self.keystore is None:
            return

        try:
            await self.keystore.update(address, keys)
            await self.refresh_resolving_list()
        except Exception:
            logger.exception('!!! error while storing keys')
        else:
            self.emit(self.EVENT_KEY_STORE_UPDATE)

    # [Classic only]
    async def switch_role(self, connection: Connection, role: hci.Role):
        pending_role_change = asyncio.get_running_loop().create_future()

        with closing(utils.EventWatcher()) as watcher:

            @watcher.on(connection, connection.EVENT_ROLE_CHANGE)
            def _(new_role: hci.Role):
                pending_role_change.set_result(new_role)

            @watcher.on(connection, connection.EVENT_ROLE_CHANGE_FAILURE)
            def _(error_code: int):
                pending_role_change.set_exception(hci.HCI_Error(error_code))

            await self.send_command(
                hci.HCI_Switch_Role_Command(bd_addr=connection.peer_address, role=role),
                check_result=True,
            )
            await connection.cancel_on_disconnection(pending_role_change)

    # [Classic only]
    async def request_remote_name(self, remote: hci.Address | Connection) -> str:
        # Set up event handlers
        pending_name: asyncio.Future[str] = asyncio.get_running_loop().create_future()

        peer_address = (
            remote if isinstance(remote, hci.Address) else remote.peer_address
        )

        with closing(utils.EventWatcher()) as watcher:

            @watcher.on(self, self.EVENT_REMOTE_NAME)
            def _(address: hci.Address, remote_name: str) -> None:
                if address == peer_address:
                    pending_name.set_result(remote_name)

            @watcher.on(self, self.EVENT_REMOTE_NAME_FAILURE)
            def _(address: hci.Address, error_code: int) -> None:
                if address == peer_address:
                    pending_name.set_exception(hci.HCI_Error(error_code))

            await self.send_command(
                hci.HCI_Remote_Name_Request_Command(
                    bd_addr=peer_address,
                    page_scan_repetition_mode=hci.HCI_Remote_Name_Request_Command.R2,
                    reserved=0,
                    clock_offset=0,  # TODO investigate non-0 values
                ),
                check_result=True,
            )

            # Wait for the result
            return await utils.cancel_on_event(self, Device.EVENT_FLUSH, pending_name)

    # [LE only]
    @utils.experimental('Only for testing.')
    async def setup_cig(
        self,
        parameters: CigParameters,
    ) -> list[int]:
        """Sends hci.HCI_LE_Set_CIG_Parameters_Command.

        Args:
            parameters: CIG parameters.

        Returns:
            List of created CIS handles corresponding to the same order of [cid_id].
        """
        response = await self.send_command(
            hci.HCI_LE_Set_CIG_Parameters_Command(
                cig_id=parameters.cig_id,
                sdu_interval_c_to_p=parameters.sdu_interval_c_to_p,
                sdu_interval_p_to_c=parameters.sdu_interval_p_to_c,
                worst_case_sca=parameters.worst_case_sca,
                packing=int(parameters.packing),
                framing=int(parameters.framing),
                max_transport_latency_c_to_p=parameters.max_transport_latency_c_to_p,
                max_transport_latency_p_to_c=parameters.max_transport_latency_p_to_c,
                cis_id=[cis.cis_id for cis in parameters.cis_parameters],
                max_sdu_c_to_p=[
                    cis.max_sdu_c_to_p for cis in parameters.cis_parameters
                ],
                max_sdu_p_to_c=[
                    cis.max_sdu_p_to_c for cis in parameters.cis_parameters
                ],
                phy_c_to_p=[cis.phy_c_to_p for cis in parameters.cis_parameters],
                phy_p_to_c=[cis.phy_p_to_c for cis in parameters.cis_parameters],
                rtn_c_to_p=[cis.rtn_c_to_p for cis in parameters.cis_parameters],
                rtn_p_to_c=[cis.rtn_p_to_c for cis in parameters.cis_parameters],
            ),
            check_result=True,
        )

        # Ideally, we should manage CIG lifecycle, but they are not useful for Unicast
        # Server, so here it only provides a basic functionality for testing.
        cis_handles = response.return_parameters.connection_handle[:]
        for cis, cis_handle in zip(parameters.cis_parameters, cis_handles):
            self._pending_cis[cis_handle] = (cis.cis_id, parameters.cig_id)

        return cis_handles

    # [LE only]
    @utils.experimental('Only for testing.')
    async def create_cis(
        self, cis_acl_pairs: Sequence[tuple[int, Connection]]
    ) -> list[CisLink]:
        for cis_handle, acl_connection in cis_acl_pairs:
            cis_id, cig_id = self._pending_cis[cis_handle]
            self.cis_links[cis_handle] = CisLink(
                device=self,
                acl_connection=acl_connection,
                handle=cis_handle,
                cis_id=cis_id,
                cig_id=cig_id,
            )

        with closing(utils.EventWatcher()) as watcher:
            pending_cis_establishments = {
                cis_handle: asyncio.get_running_loop().create_future()
                for cis_handle, _ in cis_acl_pairs
            }

            def on_cis_establishment(cis_link: CisLink) -> None:
                self._pending_cis.pop(cis_link.handle)
                if pending_future := pending_cis_establishments.get(cis_link.handle):
                    pending_future.set_result(cis_link)

            def on_cis_establishment_failure(cis_link: CisLink, status: int) -> None:
                if pending_future := pending_cis_establishments.get(cis_link.handle):
                    pending_future.set_exception(hci.HCI_Error(status))

            watcher.on(self, self.EVENT_CIS_ESTABLISHMENT, on_cis_establishment)
            watcher.on(
                self, self.EVENT_CIS_ESTABLISHMENT_FAILURE, on_cis_establishment_failure
            )
            await self.send_command(
                hci.HCI_LE_Create_CIS_Command(
                    cis_connection_handle=[p[0] for p in cis_acl_pairs],
                    acl_connection_handle=[p[1].handle for p in cis_acl_pairs],
                ),
                check_result=True,
            )

            return await asyncio.gather(*pending_cis_establishments.values())

    # [LE only]
    @utils.experimental('Only for testing.')
    async def accept_cis_request(self, cis_link: CisLink) -> None:
        """[LE Only] Accepts an incoming CIS request.

        This method returns when the CIS is established, or raises an exception if
        the CIS establishment fails.

        Args:
            handle: CIS handle to accept.
        """

        # There might be multiple ASE sharing a CIS channel.
        # If one of them has accepted the request, the others should just leverage it.
        async with self._cis_lock:
            if cis_link.state == CisLink.State.ESTABLISHED:
                return

            with closing(utils.EventWatcher()) as watcher:
                pending_establishment = asyncio.get_running_loop().create_future()

                def on_establishment() -> None:
                    pending_establishment.set_result(None)

                def on_establishment_failure(status: int) -> None:
                    pending_establishment.set_exception(hci.HCI_Error(status))

                watcher.on(cis_link, cis_link.EVENT_ESTABLISHMENT, on_establishment)
                watcher.on(
                    cis_link,
                    cis_link.EVENT_ESTABLISHMENT_FAILURE,
                    on_establishment_failure,
                )

                await self.send_command(
                    hci.HCI_LE_Accept_CIS_Request_Command(
                        connection_handle=cis_link.handle
                    ),
                    check_result=True,
                )

                await pending_establishment

    # [LE only]
    @utils.experimental('Only for testing.')
    async def reject_cis_request(
        self,
        cis_link: CisLink,
        reason: int = hci.HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
    ) -> None:
        await self.send_command(
            hci.HCI_LE_Reject_CIS_Request_Command(
                connection_handle=cis_link.handle, reason=reason
            ),
            check_result=True,
        )

    # [LE only]
    @utils.experimental('Only for testing.')
    async def create_big(
        self, advertising_set: AdvertisingSet, parameters: BigParameters
    ) -> Big:
        if (big_handle := self.next_big_handle()) is None:
            raise core.OutOfResourcesError("All valid BIG handles already in use")

        with closing(utils.EventWatcher()) as watcher:
            big = Big(
                big_handle=big_handle,
                parameters=parameters,
                advertising_set=advertising_set,
            )
            self.bigs[big_handle] = big
            established = asyncio.get_running_loop().create_future()
            watcher.once(
                big, big.Event.ESTABLISHMENT, lambda: established.set_result(None)
            )
            watcher.once(
                big,
                big.Event.ESTABLISHMENT_FAILURE,
                lambda status: established.set_exception(hci.HCI_Error(status)),
            )

            try:
                await self.send_command(
                    hci.HCI_LE_Create_BIG_Command(
                        big_handle=big_handle,
                        advertising_handle=advertising_set.advertising_handle,
                        num_bis=parameters.num_bis,
                        sdu_interval=parameters.sdu_interval,
                        max_sdu=parameters.max_sdu,
                        max_transport_latency=parameters.max_transport_latency,
                        rtn=parameters.rtn,
                        phy=parameters.phy,
                        packing=parameters.packing,
                        framing=parameters.framing,
                        encryption=1 if parameters.broadcast_code else 0,
                        broadcast_code=parameters.broadcast_code or bytes(16),
                    ),
                    check_result=True,
                )
                await established
            except hci.HCI_Error:
                del self.bigs[big_handle]
                raise

        return big

    # [LE only]
    @utils.experimental('Only for testing.')
    async def create_big_sync(
        self, pa_sync: PeriodicAdvertisingSync, parameters: BigSyncParameters
    ) -> BigSync:
        if (big_handle := self.next_big_handle()) is None:
            raise core.OutOfResourcesError("All valid BIG handles already in use")

        if (pa_sync_handle := pa_sync.sync_handle) is None:
            raise core.InvalidStateError("PA Sync is not established")

        with closing(utils.EventWatcher()) as watcher:
            big_sync = BigSync(
                big_handle=big_handle,
                parameters=parameters,
                pa_sync=pa_sync,
            )
            self.big_syncs[big_handle] = big_sync
            established = asyncio.get_running_loop().create_future()
            watcher.once(
                big_sync,
                big_sync.Event.ESTABLISHMENT,
                lambda: established.set_result(None),
            )
            watcher.once(
                big_sync,
                big_sync.Event.ESTABLISHMENT_FAILURE,
                lambda status: established.set_exception(hci.HCI_Error(status)),
            )

            try:
                await self.send_command(
                    hci.HCI_LE_BIG_Create_Sync_Command(
                        big_handle=big_handle,
                        sync_handle=pa_sync_handle,
                        encryption=1 if parameters.broadcast_code else 0,
                        broadcast_code=parameters.broadcast_code or bytes(16),
                        mse=parameters.mse,
                        big_sync_timeout=parameters.big_sync_timeout,
                        bis=parameters.bis,
                    ),
                    check_result=True,
                )
                await established
            except hci.HCI_Error:
                del self.big_syncs[big_handle]
                raise

        return big_sync

    async def get_remote_le_features(self, connection: Connection) -> hci.LeFeatureMask:
        """[LE Only] Reads remote LE supported features.

        Args:
            handle: connection handle to read LE features.

        Returns:
            LE features supported by the remote device.
        """
        with closing(utils.EventWatcher()) as watcher:
            read_feature_future: asyncio.Future[hci.LeFeatureMask] = (
                asyncio.get_running_loop().create_future()
            )

            def on_le_remote_features(handle: int, features: int):
                if handle == connection.handle:
                    read_feature_future.set_result(hci.LeFeatureMask(features))

            def on_failure(handle: int, status: int):
                if handle == connection.handle:
                    read_feature_future.set_exception(hci.HCI_Error(status))

            watcher.on(self.host, 'le_remote_features', on_le_remote_features)
            watcher.on(self.host, 'le_remote_features_failure', on_failure)
            await self.send_command(
                hci.HCI_LE_Read_Remote_Features_Command(
                    connection_handle=connection.handle
                ),
                check_result=True,
            )
            return await read_feature_future

    @utils.experimental('Only for testing.')
    async def get_remote_cs_capabilities(
        self, connection: Connection
    ) -> ChannelSoundingCapabilities:
        complete_future: asyncio.Future[ChannelSoundingCapabilities] = (
            asyncio.get_running_loop().create_future()
        )

        with closing(utils.EventWatcher()) as watcher:
            watcher.once(
                connection, 'channel_sounding_capabilities', complete_future.set_result
            )
            watcher.once(
                connection,
                'channel_sounding_capabilities_failure',
                lambda status: complete_future.set_exception(hci.HCI_Error(status)),
            )
            await self.send_command(
                hci.HCI_LE_CS_Read_Remote_Supported_Capabilities_Command(
                    connection_handle=connection.handle
                ),
                check_result=True,
            )
            return await complete_future

    @utils.experimental('Only for testing.')
    async def set_default_cs_settings(
        self,
        connection: Connection,
        role_enable: int = (
            hci.CsRoleMask.INITIATOR | hci.CsRoleMask.REFLECTOR
        ),  # Both role
        cs_sync_antenna_selection: int = 0xFF,  # No Preference
        max_tx_power: int = 0x04,  # 4 dB
    ) -> None:
        await self.send_command(
            hci.HCI_LE_CS_Set_Default_Settings_Command(
                connection_handle=connection.handle,
                role_enable=role_enable,
                cs_sync_antenna_selection=cs_sync_antenna_selection,
                max_tx_power=max_tx_power,
            ),
            check_result=True,
        )

    @utils.experimental('Only for testing.')
    async def create_cs_config(
        self,
        connection: Connection,
        config_id: int | None = None,
        create_context: int = 0x01,
        main_mode_type: int = 0x02,
        sub_mode_type: int = 0xFF,
        min_main_mode_steps: int = 0x02,
        max_main_mode_steps: int = 0x05,
        main_mode_repetition: int = 0x00,
        mode_0_steps: int = 0x03,
        role: int = hci.CsRole.INITIATOR,
        rtt_type: int = hci.RttType.AA_ONLY,
        cs_sync_phy: int = hci.CsSyncPhy.LE_1M,
        channel_map: bytes = b'\x54\x55\x55\x54\x55\x55\x55\x55\x55\x15',
        channel_map_repetition: int = 0x01,
        channel_selection_type: int = hci.HCI_LE_CS_Create_Config_Command.ChannelSelectionType.ALGO_3B,
        ch3c_shape: int = hci.HCI_LE_CS_Create_Config_Command.Ch3cShape.HAT,
        ch3c_jump: int = 0x03,
    ) -> ChannelSoundingConfig:
        complete_future: asyncio.Future[ChannelSoundingConfig] = (
            asyncio.get_running_loop().create_future()
        )
        if config_id is None:
            # Allocate an ID.
            config_id = next(
                (
                    i
                    for i in range(DEVICE_MIN_CS_CONFIG_ID, DEVICE_MAX_CS_CONFIG_ID + 1)
                    if i not in connection.cs_configs
                ),
                None,
            )
        if config_id is None:
            raise OutOfResourcesError("No available config ID on this connection!")

        with closing(utils.EventWatcher()) as watcher:
            watcher.once(
                connection, 'channel_sounding_config', complete_future.set_result
            )
            watcher.once(
                connection,
                'channel_sounding_config_failure',
                lambda status: complete_future.set_exception(hci.HCI_Error(status)),
            )
            await self.send_command(
                hci.HCI_LE_CS_Create_Config_Command(
                    connection_handle=connection.handle,
                    config_id=config_id,
                    create_context=create_context,
                    main_mode_type=main_mode_type,
                    sub_mode_type=sub_mode_type,
                    min_main_mode_steps=min_main_mode_steps,
                    max_main_mode_steps=max_main_mode_steps,
                    main_mode_repetition=main_mode_repetition,
                    mode_0_steps=mode_0_steps,
                    role=role,
                    rtt_type=rtt_type,
                    cs_sync_phy=cs_sync_phy,
                    channel_map=channel_map,
                    channel_map_repetition=channel_map_repetition,
                    channel_selection_type=channel_selection_type,
                    ch3c_shape=ch3c_shape,
                    ch3c_jump=ch3c_jump,
                    reserved=0x00,
                ),
                check_result=True,
            )
            return await complete_future

    @utils.experimental('Only for testing.')
    async def enable_cs_security(self, connection: Connection) -> None:
        complete_future: asyncio.Future[None] = (
            asyncio.get_running_loop().create_future()
        )
        with closing(utils.EventWatcher()) as watcher:

            def on_event(event: hci.HCI_LE_CS_Security_Enable_Complete_Event) -> None:
                if event.connection_handle != connection.handle:
                    return
                if event.status == hci.HCI_SUCCESS:
                    complete_future.set_result(None)
                else:
                    complete_future.set_exception(hci.HCI_Error(event.status))

            watcher.once(self.host, 'cs_security', on_event)
            await self.send_command(
                hci.HCI_LE_CS_Security_Enable_Command(
                    connection_handle=connection.handle
                ),
                check_result=True,
            )
            return await complete_future

    @utils.experimental('Only for testing.')
    async def set_cs_procedure_parameters(
        self,
        connection: Connection,
        config: ChannelSoundingConfig,
        tone_antenna_config_selection=0x00,
        preferred_peer_antenna=0x00,
        max_procedure_len=0x2710,  # 6.25s
        min_procedure_interval=0x01,
        max_procedure_interval=0xFF,
        max_procedure_count=0x01,
        min_subevent_len=0x0004E2,  # 1250us
        max_subevent_len=0x1E8480,  # 2s
        phy=hci.CsSyncPhy.LE_1M,
        tx_power_delta=0x00,
        snr_control_initiator=hci.CsSnr.NOT_APPLIED,
        snr_control_reflector=hci.CsSnr.NOT_APPLIED,
    ) -> None:
        await self.send_command(
            hci.HCI_LE_CS_Set_Procedure_Parameters_Command(
                connection_handle=connection.handle,
                config_id=config.config_id,
                max_procedure_len=max_procedure_len,
                min_procedure_interval=min_procedure_interval,
                max_procedure_interval=max_procedure_interval,
                max_procedure_count=max_procedure_count,
                min_subevent_len=min_subevent_len,
                max_subevent_len=max_subevent_len,
                tone_antenna_config_selection=tone_antenna_config_selection,
                phy=phy,
                tx_power_delta=tx_power_delta,
                preferred_peer_antenna=preferred_peer_antenna,
                snr_control_initiator=snr_control_initiator,
                snr_control_reflector=snr_control_reflector,
            ),
            check_result=True,
        )

    @utils.experimental('Only for testing.')
    async def enable_cs_procedure(
        self,
        connection: Connection,
        config: ChannelSoundingConfig,
        enabled: bool = True,
    ) -> ChannelSoundingProcedure:
        complete_future: asyncio.Future[ChannelSoundingProcedure] = (
            asyncio.get_running_loop().create_future()
        )
        with closing(utils.EventWatcher()) as watcher:
            watcher.once(
                connection, 'channel_sounding_procedure', complete_future.set_result
            )
            watcher.once(
                connection,
                'channel_sounding_procedure_failure',
                lambda x: complete_future.set_exception(hci.HCI_Error(x)),
            )
            await self.send_command(
                hci.HCI_LE_CS_Procedure_Enable_Command(
                    connection_handle=connection.handle,
                    config_id=config.config_id,
                    enable=enabled,
                ),
                check_result=True,
            )
            return await complete_future

    @host_event_handler
    def on_flush(self):
        self.emit(self.EVENT_FLUSH)
        for _, connection in self.connections.items():
            connection.emit(connection.EVENT_DISCONNECTION, 0)
        self.connections = {}

    # [Classic only]
    @host_event_handler
    def on_link_key(self, bd_addr: hci.Address, link_key: bytes, key_type: int) -> None:
        # Store the keys in the key store
        if self.keystore:
            authenticated = key_type in (
                hci.LinkKeyType.AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192,
                hci.LinkKeyType.AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256,
            )
            pairing_keys = PairingKeys(
                link_key=PairingKeys.Key(value=link_key, authenticated=authenticated),
                link_key_type=key_type,
            )

            utils.cancel_on_event(
                self, Device.EVENT_FLUSH, self.update_keys(str(bd_addr), pairing_keys)
            )

        if connection := self.find_connection_by_bd_addr(
            bd_addr, transport=PhysicalTransport.BR_EDR
        ):
            connection.emit(connection.EVENT_LINK_KEY)

    def add_service(self, service: gatt.Service):
        self.gatt_server.add_service(service)

    def add_services(self, services: Iterable[gatt.Service]):
        self.gatt_server.add_services(services)

    def add_default_services(
        self, add_gap_service: bool = True, add_gatt_service: bool = True
    ) -> None:
        # Add a GAP Service if requested
        if add_gap_service:
            self.gatt_server.add_service(GenericAccessService(self.name))
        if add_gatt_service:
            self.gatt_service = gatt_service.GenericAttributeProfileService(
                gatt.ServerSupportedFeatures.EATT_SUPPORTED
                if self.config.eatt_enabled
                else None
            )
            self.gatt_server.add_service(self.gatt_service)

    async def notify_subscriber(
        self,
        connection: Connection,
        attribute: Attribute,
        value: Any | None = None,
        force: bool = False,
    ) -> None:
        """
        Send a notification to an attribute subscriber.

        Args:
           connection:
             The connection of the subscriber.
           attribute:
             The attribute whose value is notified.
           value:
             The value of the attribute (if None, the value is read from the attribute)
            force:
              If True, send a notification even if there is no subscriber.
        """
        await self.gatt_server.notify_subscriber(connection, attribute, value, force)

    async def notify_subscribers(
        self, attribute: Attribute, value: Any | None = None, force: bool = False
    ) -> None:
        """
        Send a notification to all the subscribers of an attribute.

        Args:
           attribute:
             The attribute whose value is notified.
           value:
             The value of the attribute (if None, the value is read from the attribute)
            force:
              If True, send a notification for every connection even if there is no
              subscriber.
        """
        await self.gatt_server.notify_subscribers(attribute, value, force)

    async def indicate_subscriber(
        self,
        connection: Connection,
        attribute: Attribute,
        value: Any | None = None,
        force: bool = False,
    ):
        """
        Send an indication to an attribute subscriber.

        This method returns when the response to the indication has been received.

        Args:
           connection:
             The connection of the subscriber.
           attribute:
             The attribute whose value is indicated.
           value:
             The value of the attribute (if None, the value is read from the attribute)
            force:
              If True, send an indication even if there is no subscriber.
        """
        await self.gatt_server.indicate_subscriber(connection, attribute, value, force)

    async def indicate_subscribers(
        self, attribute: Attribute, value: Any | None = None, force: bool = False
    ):
        """
        Send an indication to all the subscribers of an attribute.

        Args:
           attribute:
             The attribute whose value is notified.
           value:
             The value of the attribute (if None, the value is read from the attribute)
            force:
              If True, send an indication for every connection even if there is no
              subscriber.
        """
        await self.gatt_server.indicate_subscribers(attribute, value, force)

    @host_event_handler
    def on_advertising_set_termination(
        self,
        status: int,
        advertising_handle: int,
        connection_handle: int,
        number_of_completed_extended_advertising_events: int,
    ):
        # Legacy advertising set is also one of extended advertising sets.
        if not (
            advertising_set := self.extended_advertising_sets.get(advertising_handle)
        ):
            logger.warning(f'advertising set {advertising_handle} not found')
            return

        advertising_set.on_termination(status)

        if status != hci.HCI_SUCCESS:
            logger.debug(
                f'advertising set {advertising_handle} terminated with status {status}'
            )
            return

        if connection := self.lookup_connection(connection_handle):
            # We have already received the connection complete event.
            self._complete_le_extended_advertising_connection(
                connection, advertising_set
            )
            return

        # Associate the connection handle with the advertising set, the connection
        # will complete later.
        logger.debug(
            f'the connection with handle {connection_handle:04X} will complete later'
        )
        self.connecting_extended_advertising_sets[connection_handle] = advertising_set

    @host_event_handler
    def on_big_establishment(
        self,
        status: int,
        big_handle: int,
        bis_handles: list[int],
        big_sync_delay: int,
        transport_latency_big: int,
        phy: int,
        nse: int,
        bn: int,
        pto: int,
        irc: int,
        max_pdu: int,
        iso_interval: int,
    ) -> None:
        if not (big := self.bigs.get(big_handle)):
            logger.warning('BIG %d not found', big_handle)
            return

        if status != hci.HCI_SUCCESS:
            del self.bigs[big_handle]
            logger.debug('Unable to create BIG %d', big_handle)
            big.state = Big.State.TERMINATED
            big.emit(Big.Event.ESTABLISHMENT_FAILURE, status)
            return

        big.bis_links = [BisLink(handle=handle, big=big) for handle in bis_handles]
        big.big_sync_delay = big_sync_delay
        big.transport_latency_big = transport_latency_big
        big.phy = hci.Phy(phy)
        big.nse = nse
        big.bn = bn
        big.pto = pto
        big.irc = irc
        big.max_pdu = max_pdu
        big.iso_interval = iso_interval * 1.25
        big.state = Big.State.ACTIVE

        for bis_link in big.bis_links:
            self.bis_links[bis_link.handle] = bis_link
        big.emit(Big.Event.ESTABLISHMENT)

    @host_event_handler
    def on_big_termination(self, reason: int, big_handle: int) -> None:
        if not (big := self.bigs.pop(big_handle, None)):
            logger.warning('BIG %d not found', big_handle)
            return

        big.state = Big.State.TERMINATED
        for bis_link in big.bis_links:
            self.bis_links.pop(bis_link.handle, None)
        big.emit(Big.Event.TERMINATION, reason)

    @host_event_handler
    def on_big_sync_establishment(
        self,
        status: int,
        big_handle: int,
        transport_latency_big: int,
        nse: int,
        bn: int,
        pto: int,
        irc: int,
        max_pdu: int,
        iso_interval: int,
        bis_handles: list[int],
    ) -> None:
        if not (big_sync := self.big_syncs.get(big_handle)):
            logger.warning('BIG Sync %d not found', big_handle)
            return

        if status != hci.HCI_SUCCESS:
            del self.big_syncs[big_handle]
            logger.debug('Unable to create BIG Sync %d', big_handle)
            big_sync.state = BigSync.State.TERMINATED
            big_sync.emit(BigSync.Event.ESTABLISHMENT_FAILURE, status)
            return

        big_sync.transport_latency_big = transport_latency_big
        big_sync.nse = nse
        big_sync.bn = bn
        big_sync.pto = pto
        big_sync.irc = irc
        big_sync.max_pdu = max_pdu
        big_sync.iso_interval = iso_interval * 1.25
        big_sync.bis_links = [
            BisLink(handle=handle, big=big_sync) for handle in bis_handles
        ]
        big_sync.state = BigSync.State.ACTIVE

        for bis_link in big_sync.bis_links:
            self.bis_links[bis_link.handle] = bis_link
        big_sync.emit(BigSync.Event.ESTABLISHMENT)

    @host_event_handler
    def on_big_sync_lost(self, big_handle: int, reason: int) -> None:
        if not (big_sync := self.big_syncs.pop(big_handle, None)):
            logger.warning('BIG %d not found', big_handle)
            return

        for bis_link in big_sync.bis_links:
            self.bis_links.pop(bis_link.handle, None)
        big_sync.state = BigSync.State.TERMINATED
        big_sync.emit(BigSync.Event.TERMINATION, reason)

    def _complete_le_extended_advertising_connection(
        self, connection: Connection, advertising_set: AdvertisingSet
    ) -> None:
        # Update the connection address.
        connection.self_address = (
            advertising_set.random_address
            if advertising_set.random_address is not None
            and advertising_set.advertising_parameters.own_address_type
            in (hci.OwnAddressType.RANDOM, hci.OwnAddressType.RESOLVABLE_OR_RANDOM)
            else self.public_address
        )

        if advertising_set.advertising_parameters.own_address_type in (
            hci.OwnAddressType.RANDOM,
            hci.OwnAddressType.PUBLIC,
        ):
            connection.self_resolvable_address = None

        # Setup auto-restart of the advertising set if needed.
        if advertising_set.auto_restart:
            connection.once(
                Connection.EVENT_DISCONNECTION,
                lambda _: utils.cancel_on_event(
                    self, Device.EVENT_FLUSH, advertising_set.start()
                ),
            )

        self.emit(self.EVENT_CONNECTION, connection)

    @host_event_handler
    def on_classic_connection(
        self,
        connection_handle: int,
        peer_address: hci.Address,
    ) -> None:
        if connection := self.pending_connections.pop(peer_address, None):
            connection.handle = connection_handle
        else:
            # Create a new connection
            connection = Connection(
                device=self,
                handle=connection_handle,
                transport=PhysicalTransport.BR_EDR,
                self_address=self.public_address,
                self_resolvable_address=None,
                peer_address=peer_address,
                peer_resolvable_address=None,
                role=hci.Role.PERIPHERAL,
                parameters=Connection.Parameters(0.0, 0, 0.0),
            )

        logger.debug('*** %s', connection)
        if connection_handle in self.connections:
            logger.warning(
                'new connection reuses the same handle as a previous connection'
            )
        self.connections[connection_handle] = connection

        self.emit(self.EVENT_CONNECTION, connection)

    @host_event_handler
    def on_le_connection(
        self,
        connection_handle: int,
        peer_address: hci.Address,
        self_resolvable_address: hci.Address | None,
        peer_resolvable_address: hci.Address | None,
        role: hci.Role,
        connection_interval: int,
        peripheral_latency: int,
        supervision_timeout: int,
    ) -> None:
        # Convert all-zeros addresses into None.
        if self_resolvable_address == hci.Address.ANY_RANDOM:
            self_resolvable_address = None
        if (
            peer_resolvable_address == hci.Address.ANY_RANDOM
            or not peer_address.is_resolved
        ):
            peer_resolvable_address = None

        logger.debug(
            f'*** Connection: [0x{connection_handle:04X}] '
            f'{peer_address} {"" if role is None else hci.HCI_Constant.role_name(role)}'
        )
        if connection_handle in self.connections:
            logger.warning(
                'new connection reuses the same handle as a previous connection'
            )

        if peer_resolvable_address is None:
            # Resolve the peer address if we can
            if self.address_resolver:
                if peer_address.is_resolvable:
                    resolved_address = self.address_resolver.resolve(peer_address)
                    if resolved_address is not None:
                        logger.debug(f'*** hci.Address resolved as {resolved_address}')
                        peer_resolvable_address = peer_address
                        peer_address = resolved_address

        self_address = None
        own_address_type: hci.OwnAddressType | None = None
        if role == hci.Role.CENTRAL:
            own_address_type = self.connect_own_address_type
            assert own_address_type is not None
        else:
            if self.supports_le_extended_advertising:
                # We'll know the address when the advertising set terminates,
                # Use a temporary placeholder value for self_address.
                self_address = hci.Address.ANY_RANDOM
            else:
                # We were connected via a legacy advertisement.
                if self.legacy_advertiser:
                    own_address_type = self.legacy_advertiser.own_address_type
                else:
                    # This should not happen, but just in case, pick a default.
                    logger.warning("connection without an advertiser")
                    self_address = self.random_address

        if self_address is None:
            self_address = (
                self.public_address
                if own_address_type
                in (
                    hci.OwnAddressType.PUBLIC,
                    hci.OwnAddressType.RESOLVABLE_OR_PUBLIC,
                )
                else self.random_address
            )

        # Some controllers may return local resolvable address even not using address
        # generation offloading. Ignore the value to prevent SMP failure.
        if own_address_type in (hci.OwnAddressType.RANDOM, hci.OwnAddressType.PUBLIC):
            self_resolvable_address = None

        # Create a connection.
        connection = Connection(
            self,
            connection_handle,
            PhysicalTransport.LE,
            self_address,
            self_resolvable_address,
            peer_address,
            peer_resolvable_address,
            role,
            Connection.Parameters(
                connection_interval * 1.25,
                peripheral_latency,
                supervision_timeout * 10.0,
            ),
        )
        self.connections[connection_handle] = connection

        if role == hci.Role.PERIPHERAL and self.legacy_advertiser:
            if self.legacy_advertiser.auto_restart:
                advertiser = self.legacy_advertiser
                connection.once(
                    Connection.EVENT_DISCONNECTION,
                    lambda _: utils.cancel_on_event(
                        self, Device.EVENT_FLUSH, advertiser.start()
                    ),
                )
            else:
                self.legacy_advertiser = None

        if role == hci.Role.CENTRAL or not self.supports_le_extended_advertising:
            # We can emit now, we have all the info we need
            self.emit(self.EVENT_CONNECTION, connection)
            return

        if role == hci.Role.PERIPHERAL and self.supports_le_extended_advertising:
            if advertising_set := self.connecting_extended_advertising_sets.pop(
                connection_handle, None
            ):
                # We have already received the advertising set termination event.
                self._complete_le_extended_advertising_connection(
                    connection, advertising_set
                )

    @host_event_handler
    def on_connection_failure(
        self,
        transport: hci.PhysicalTransport,
        peer_address: hci.Address,
        error_code: int,
    ):
        logger.debug(
            f'*** Connection failed: {hci.HCI_Constant.error_name(error_code)}'
        )

        # For directed advertising, this means a timeout
        if (
            transport == PhysicalTransport.LE
            and self.legacy_advertiser
            and self.legacy_advertiser.advertising_type.is_directed
        ):
            self.legacy_advertiser = None

        # Notify listeners
        error = core.ConnectionError(
            error_code,
            transport,
            peer_address,
            'hci',
            hci.HCI_Constant.error_name(error_code),
        )
        self.emit(self.EVENT_CONNECTION_FAILURE, error)

    # FIXME: Explore a delegate-model for BR/EDR wait connection #56.
    @host_event_handler
    def on_connection_request(
        self, bd_addr: hci.Address, class_of_device: int, link_type: int
    ):
        logger.debug(f'*** Connection request: {bd_addr}')

        # Handle SCO request.
        if link_type in (
            hci.HCI_Connection_Complete_Event.LinkType.SCO,
            hci.HCI_Connection_Complete_Event.LinkType.ESCO,
        ):
            if connection := self.find_connection_by_bd_addr(
                bd_addr, transport=PhysicalTransport.BR_EDR
            ):
                self.emit(self.EVENT_SCO_REQUEST, connection, link_type)
            else:
                logger.error(f'SCO request from a non-connected device {bd_addr}')
            return

        # match a pending future using `bd_addr`
        elif bd_addr in self.classic_pending_accepts:
            future, *_ = self.classic_pending_accepts.pop(bd_addr)
            future.set_result((bd_addr, class_of_device, link_type))

        # match first pending future for ANY address
        elif len(self.classic_pending_accepts[hci.Address.ANY]) > 0:
            future = self.classic_pending_accepts[hci.Address.ANY].pop(0)
            future.set_result((bd_addr, class_of_device, link_type))

        # device configuration is set to accept any incoming connection
        elif self.classic_accept_any:
            # Save pending connection
            self.pending_connections[bd_addr] = Connection(
                device=self,
                handle=0,
                transport=core.PhysicalTransport.BR_EDR,
                self_address=self.public_address,
                self_resolvable_address=None,
                peer_address=bd_addr,
                peer_resolvable_address=None,
                role=hci.Role.PERIPHERAL,
                parameters=Connection.Parameters(0, 0, 0),
            )

            self.host.send_command_sync(
                hci.HCI_Accept_Connection_Request_Command(
                    bd_addr=bd_addr,
                    role=0x01,  # Remain the peripheral
                )
            )

        # reject incoming connection
        else:
            self.host.send_command_sync(
                hci.HCI_Reject_Connection_Request_Command(
                    bd_addr=bd_addr,
                    reason=hci.HCI_CONNECTION_REJECTED_DUE_TO_LIMITED_RESOURCES_ERROR,
                )
            )

    @host_event_handler
    def on_disconnection(self, connection_handle: int, reason: int) -> None:
        if connection := self.connections.pop(connection_handle, None):
            logger.debug(
                f'*** Disconnection: [0x{connection.handle:04X}] '
                f'{connection.peer_address} as {connection.role_name}, reason={reason}'
            )
            connection.emit(connection.EVENT_DISCONNECTION, reason)

            # Cleanup subsystems that maintain per-connection state
            self.gatt_server.on_disconnection(connection)
        elif sco_link := self.sco_links.pop(connection_handle, None):
            sco_link.emit(sco_link.EVENT_DISCONNECTION, reason)
        elif cis_link := self.cis_links.pop(connection_handle, None):
            cis_link.emit(cis_link.EVENT_DISCONNECTION, reason)
        else:
            logger.error(
                f'*** Unknown disconnection handle=0x{connection_handle}, reason={reason} ***'
            )

    @host_event_handler
    @with_connection_from_handle
    def on_disconnection_failure(self, connection: Connection, error_code: int):
        logger.debug(f'*** Disconnection failed: {error_code}')
        error = core.ConnectionError(
            error_code,
            connection.transport,
            connection.peer_address,
            'hci',
            hci.HCI_Constant.error_name(error_code),
        )
        connection.emit(connection.EVENT_DISCONNECTION_FAILURE, error)

    @host_event_handler
    @utils.AsyncRunner.run_in_task()
    async def on_inquiry_complete(self):
        if self.auto_restart_inquiry:
            # Inquire again
            await self.start_discovery(auto_restart=True)
        else:
            self.auto_restart_inquiry = True
            self.discovering = False
            self.emit(self.EVENT_INQUIRY_COMPLETE)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_authentication(self, connection: Connection):
        logger.debug(
            f'*** Connection Authentication: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}'
        )
        connection.authenticated = True
        connection.emit(connection.EVENT_CONNECTION_AUTHENTICATION)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_authentication_failure(self, connection: Connection, error: int):
        logger.debug(
            f'*** Connection Authentication Failure: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, error={error}'
        )
        connection.emit(connection.EVENT_CONNECTION_AUTHENTICATION_FAILURE, error)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_io_capability_request(self, connection: Connection):
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)

        # Compute the authentication requirements
        authentication_requirements = (
            # No Bonding
            (
                hci.AuthenticationRequirements.MITM_NOT_REQUIRED_NO_BONDING,
                hci.AuthenticationRequirements.MITM_REQUIRED_NO_BONDING,
            ),
            # General Bonding
            (
                hci.AuthenticationRequirements.MITM_NOT_REQUIRED_GENERAL_BONDING,
                hci.AuthenticationRequirements.MITM_REQUIRED_GENERAL_BONDING,
            ),
        )[1 if pairing_config.bonding else 0][1 if pairing_config.mitm else 0]

        # Respond
        self.host.send_command_sync(
            hci.HCI_IO_Capability_Request_Reply_Command(
                bd_addr=connection.peer_address,
                io_capability=pairing_config.delegate.classic_io_capability,
                oob_data_present=0x00,  # Not present
                authentication_requirements=authentication_requirements,
            )
        )

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_io_capability_response(
        self,
        connection: Connection,
        io_capability: int,
        authentication_requirements: int,
    ):
        connection.pairing_peer_io_capability = io_capability
        connection.pairing_peer_authentication_requirements = (
            authentication_requirements
        )

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_user_confirmation_request(
        self, connection: Connection, code: int
    ) -> None:
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)
        io_capability = pairing_config.delegate.classic_io_capability
        peer_io_capability = connection.pairing_peer_io_capability
        if peer_io_capability is None:
            raise core.InvalidStateError("Unknown pairing_peer_io_capability")

        async def confirm() -> bool:
            # Ask the user to confirm the pairing, without display
            return await pairing_config.delegate.confirm()

        async def auto_confirm() -> bool:
            # Ask the user to auto-confirm the pairing, without display
            return await pairing_config.delegate.confirm(auto=True)

        async def display_confirm() -> bool:
            # Display the code and ask the user to compare
            return await pairing_config.delegate.compare_numbers(code, digits=6)

        async def display_auto_confirm() -> bool:
            # Display the code to the user and ask the delegate to auto-confirm
            await pairing_config.delegate.display_number(code, digits=6)
            return await pairing_config.delegate.confirm(auto=True)

        async def na() -> bool:
            raise UnreachableError()

        # See Bluetooth spec @ Vol 3, Part C 5.2.2.6
        methods: dict[int, dict[int, Callable[[], Awaitable[bool]]]] = {
            hci.IoCapability.DISPLAY_ONLY: {
                hci.IoCapability.DISPLAY_ONLY: display_auto_confirm,
                hci.IoCapability.DISPLAY_YES_NO: display_confirm,
                hci.IoCapability.KEYBOARD_ONLY: na,
                hci.IoCapability.NO_INPUT_NO_OUTPUT: auto_confirm,
            },
            hci.IoCapability.DISPLAY_YES_NO: {
                hci.IoCapability.DISPLAY_ONLY: display_auto_confirm,
                hci.IoCapability.DISPLAY_YES_NO: display_confirm,
                hci.IoCapability.KEYBOARD_ONLY: na,
                hci.IoCapability.NO_INPUT_NO_OUTPUT: auto_confirm,
            },
            hci.IoCapability.KEYBOARD_ONLY: {
                hci.IoCapability.DISPLAY_ONLY: na,
                hci.IoCapability.DISPLAY_YES_NO: na,
                hci.IoCapability.KEYBOARD_ONLY: na,
                hci.IoCapability.NO_INPUT_NO_OUTPUT: auto_confirm,
            },
            hci.IoCapability.NO_INPUT_NO_OUTPUT: {
                hci.IoCapability.DISPLAY_ONLY: confirm,
                hci.IoCapability.DISPLAY_YES_NO: confirm,
                hci.IoCapability.KEYBOARD_ONLY: auto_confirm,
                hci.IoCapability.NO_INPUT_NO_OUTPUT: auto_confirm,
            },
        }

        method = methods[peer_io_capability][io_capability]

        async def reply() -> None:
            try:
                if await connection.cancel_on_disconnection(method()):
                    await self.host.send_command(
                        hci.HCI_User_Confirmation_Request_Reply_Command(
                            bd_addr=connection.peer_address
                        )
                    )
                    return
            except Exception:
                logger.exception('exception while confirming')

            await self.host.send_command(
                hci.HCI_User_Confirmation_Request_Negative_Reply_Command(
                    bd_addr=connection.peer_address
                )
            )

        utils.AsyncRunner.spawn(reply())

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_user_passkey_request(self, connection: Connection) -> None:
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)

        async def reply() -> None:
            try:
                number = await connection.cancel_on_disconnection(
                    pairing_config.delegate.get_number()
                )
                if number is not None:
                    await self.host.send_command(
                        hci.HCI_User_Passkey_Request_Reply_Command(
                            bd_addr=connection.peer_address, numeric_value=number
                        )
                    )
                    return
            except Exception:
                logger.exception('exception while asking for pass-key')

            await self.host.send_command(
                hci.HCI_User_Passkey_Request_Negative_Reply_Command(
                    bd_addr=connection.peer_address
                )
            )

        utils.AsyncRunner.spawn(reply())

    # [Classic only]
    @host_event_handler
    @with_connection_from_handle
    def on_mode_change(
        self, connection: Connection, status: int, current_mode: int, interval: int
    ):
        if status == hci.HCI_SUCCESS:
            connection.classic_mode = current_mode
            connection.classic_interval = interval
            connection.emit(connection.EVENT_MODE_CHANGE)
        else:
            connection.emit(connection.EVENT_MODE_CHANGE_FAILURE, status)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_pin_code_request(self, connection: Connection):
        # Classic legacy pairing
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)
        io_capability = pairing_config.delegate.classic_io_capability

        # Respond
        if io_capability == hci.IoCapability.KEYBOARD_ONLY:
            # Ask the user to enter a string
            async def get_pin_code() -> None:
                pin_code_str = await connection.cancel_on_disconnection(
                    pairing_config.delegate.get_string(16)
                )

                if pin_code_str is not None:
                    pin_code = bytes(pin_code_str, encoding='utf-8')
                    pin_code_len = len(pin_code)
                    if not 1 <= pin_code_len <= 16:
                        raise core.InvalidArgumentError("pin_code should be 1-16 bytes")
                    await self.host.send_command(
                        hci.HCI_PIN_Code_Request_Reply_Command(
                            bd_addr=connection.peer_address,
                            pin_code_length=pin_code_len,
                            pin_code=pin_code,
                        )
                    )
                else:
                    logger.debug("delegate.get_string() returned None")
                    await self.host.send_command(
                        hci.HCI_PIN_Code_Request_Negative_Reply_Command(
                            bd_addr=connection.peer_address
                        )
                    )

            asyncio.create_task(get_pin_code())
        else:
            self.host.send_command_sync(
                hci.HCI_PIN_Code_Request_Negative_Reply_Command(
                    bd_addr=connection.peer_address
                )
            )

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_user_passkey_notification(
        self, connection: Connection, passkey: int
    ):
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)

        # Show the passkey to the user
        connection.cancel_on_disconnection(
            pairing_config.delegate.display_number(passkey, digits=6)
        )

    # [Classic only]
    @host_event_handler
    @try_with_connection_from_address
    def on_remote_name(
        self, connection: Connection | None, address: hci.Address, remote_name: bytes
    ):
        # Try to decode the name
        try:
            if connection:
                connection.peer_name = remote_name.decode('utf-8')
                connection.emit(connection.EVENT_REMOTE_NAME)
            self.emit(self.EVENT_REMOTE_NAME, address, remote_name.decode('utf-8'))
        except UnicodeDecodeError as error:
            logger.warning('peer name is not valid UTF-8')
            if connection:
                connection.emit(connection.EVENT_REMOTE_NAME_FAILURE, error)
            else:
                self.emit(self.EVENT_REMOTE_NAME_FAILURE, address, error)

    # [Classic only]
    @host_event_handler
    @try_with_connection_from_address
    def on_remote_name_failure(
        self, connection: Connection | None, address: hci.Address, error: int
    ):
        if connection:
            connection.emit(connection.EVENT_REMOTE_NAME_FAILURE, error)
        self.emit(self.EVENT_REMOTE_NAME_FAILURE, address, error)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    @utils.experimental('Only for testing.')
    def on_sco_connection(
        self, acl_connection: Connection, sco_handle: int, link_type: int
    ) -> None:
        logger.debug(
            f'*** SCO connected: {acl_connection.peer_address}, '
            f'sco_handle=[0x{sco_handle:04X}], '
            f'link_type=[0x{link_type:02X}] ***'
        )
        sco_link = self.sco_links[sco_handle] = ScoLink(
            device=self,
            acl_connection=acl_connection,
            handle=sco_handle,
            link_type=link_type,
        )
        self.emit(self.EVENT_SCO_CONNECTION, sco_link)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    @utils.experimental('Only for testing.')
    def on_sco_connection_failure(
        self, acl_connection: Connection, status: int
    ) -> None:
        logger.debug(f'*** SCO connection failure: {acl_connection.peer_address}***')
        self.emit(self.EVENT_SCO_CONNECTION_FAILURE)

    # [Classic only]
    @host_event_handler
    @utils.experimental('Only for testing')
    def on_sco_packet(
        self, sco_handle: int, packet: hci.HCI_SynchronousDataPacket
    ) -> None:
        if (sco_link := self.sco_links.get(sco_handle)) and sco_link.sink:
            sco_link.sink(packet)

    # [LE only]
    @host_event_handler
    @with_connection_from_handle
    @utils.experimental('Only for testing')
    def on_cis_request(
        self,
        acl_connection: Connection,
        cis_handle: int,
        cig_id: int,
        cis_id: int,
    ) -> None:
        logger.debug(
            f'*** CIS Request '
            f'acl_handle=[0x{acl_connection.handle:04X}]{acl_connection.peer_address}, '
            f'cis_handle=[0x{cis_handle:04X}], '
            f'cig_id=[0x{cig_id:02X}], '
            f'cis_id=[0x{cis_id:02X}] ***'
        )
        # LE_CIS_Established event doesn't provide info, so we must store them here.
        cis_link = CisLink(
            device=self,
            acl_connection=acl_connection,
            handle=cis_handle,
            cig_id=cig_id,
            cis_id=cis_id,
        )
        self.cis_links[cis_handle] = cis_link
        acl_connection.emit(acl_connection.EVENT_CIS_REQUEST, cis_link)
        self.emit(self.EVENT_CIS_REQUEST, cis_link)

    # [LE only]
    @host_event_handler
    @utils.experimental('Only for testing')
    def on_cis_establishment(
        self,
        cis_handle: int,
        cig_sync_delay: int,
        cis_sync_delay: int,
        transport_latency_c_to_p: int,
        transport_latency_p_to_c: int,
        phy_c_to_p: int,
        phy_p_to_c: int,
        nse: int,
        bn_c_to_p: int,
        bn_p_to_c: int,
        ft_c_to_p: int,
        ft_p_to_c: int,
        max_pdu_c_to_p: int,
        max_pdu_p_to_c: int,
        iso_interval: int,
    ) -> None:
        if cis_handle not in self.cis_links:
            logger.warning("CIS link not found")
            return

        cis_link = self.cis_links[cis_handle]
        cis_link.state = CisLink.State.ESTABLISHED

        assert cis_link.acl_connection

        # Update the CIS
        cis_link.cig_sync_delay = cig_sync_delay
        cis_link.cis_sync_delay = cis_sync_delay
        cis_link.transport_latency_c_to_p = transport_latency_c_to_p
        cis_link.transport_latency_p_to_c = transport_latency_p_to_c
        cis_link.phy_c_to_p = hci.Phy(phy_c_to_p)
        cis_link.phy_p_to_c = hci.Phy(phy_p_to_c)
        cis_link.nse = nse
        cis_link.bn_c_to_p = bn_c_to_p
        cis_link.bn_p_to_c = bn_p_to_c
        cis_link.ft_c_to_p = ft_c_to_p
        cis_link.ft_p_to_c = ft_p_to_c
        cis_link.max_pdu_c_to_p = max_pdu_c_to_p
        cis_link.max_pdu_p_to_c = max_pdu_p_to_c
        cis_link.iso_interval = iso_interval * 1.25

        logger.debug(
            f'*** CIS Establishment '
            f'{cis_link.acl_connection.peer_address}, '
            f'cis_handle=[0x{cis_handle:04X}], '
            f'cig_id=[0x{cis_link.cig_id:02X}], '
            f'cis_id=[0x{cis_link.cis_id:02X}] ***'
        )

        cis_link.emit(cis_link.EVENT_ESTABLISHMENT)
        cis_link.acl_connection.emit(
            cis_link.acl_connection.EVENT_CIS_ESTABLISHMENT, cis_link
        )
        self.emit(self.EVENT_CIS_ESTABLISHMENT, cis_link)

    # [LE only]
    @host_event_handler
    @utils.experimental('Only for testing')
    def on_cis_establishment_failure(self, cis_handle: int, status: int) -> None:
        if (cis_link := self.cis_links.pop(cis_handle, None)) is None:
            logger.warning("CIS link not found")
            return

        logger.debug(f'*** CIS Establishment Failure: cis=[0x{cis_handle:04X}] ***')
        cis_link.emit(cis_link.EVENT_ESTABLISHMENT_FAILURE, status)
        cis_link.acl_connection.emit(
            cis_link.acl_connection.EVENT_CIS_ESTABLISHMENT_FAILURE,
            cis_link,
            status,
        )
        self.emit(self.EVENT_CIS_ESTABLISHMENT_FAILURE, cis_link, status)

    # [LE only]
    @host_event_handler
    @utils.experimental('Only for testing')
    def on_iso_packet(self, handle: int, packet: hci.HCI_IsoDataPacket) -> None:
        if (cis_link := self.cis_links.get(handle)) and cis_link.sink:
            cis_link.sink(packet)
        elif (bis_link := self.bis_links.get(handle)) and bis_link.sink:
            bis_link.sink(packet)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_encryption_change(
        self, connection: Connection, encryption: int, encryption_key_size: int
    ):
        logger.debug(
            f'*** Connection Encryption Change: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'encryption={encryption}, '
            f'key_size={encryption_key_size}'
        )
        connection.encryption = encryption
        connection.encryption_key_size = encryption_key_size
        if (
            not connection.authenticated
            and connection.transport == PhysicalTransport.BR_EDR
            and encryption == hci.HCI_Encryption_Change_Event.Enabled.AES_CCM
        ):
            connection.authenticated = True
            connection.sc = True
        if (
            not connection.authenticated
            and connection.transport == PhysicalTransport.LE
            and encryption == hci.HCI_Encryption_Change_Event.Enabled.E0_OR_AES_CCM
        ):
            connection.authenticated = True
            connection.sc = True
        connection.emit(connection.EVENT_CONNECTION_ENCRYPTION_CHANGE)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_encryption_failure(self, connection, error):
        logger.debug(
            f'*** Connection Encryption Failure: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'error={error}'
        )
        connection.emit(connection.EVENT_CONNECTION_ENCRYPTION_FAILURE, error)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_encryption_key_refresh(self, connection: Connection):
        logger.debug(
            f'*** Connection Key Refresh: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}'
        )
        connection.emit(connection.EVENT_CONNECTION_ENCRYPTION_KEY_REFRESH)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_parameters_update(
        self,
        connection: Connection,
        connection_interval: int,
        peripheral_latency: int,
        supervision_timeout: int,
    ):
        logger.debug(
            f'*** Connection Parameters Update: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
        )
        if connection.parameters.connection_interval != connection_interval * 1.25:
            connection.parameters = Connection.Parameters(
                connection_interval * 1.25,
                peripheral_latency,
                supervision_timeout * 10.0,
            )
        else:
            connection.parameters = Connection.Parameters(
                connection_interval * 1.25,
                peripheral_latency,
                supervision_timeout * 10.0,
                connection.parameters.subrate_factor,
                connection.parameters.continuation_number,
            )
        connection.emit(connection.EVENT_CONNECTION_PARAMETERS_UPDATE)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_parameters_update_failure(
        self, connection: Connection, error: int
    ):
        logger.debug(
            f'*** Connection Parameters Update Failed: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'error={error}'
        )
        connection.emit(connection.EVENT_CONNECTION_PARAMETERS_UPDATE_FAILURE, error)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_phy_update(self, connection: Connection, phy: core.ConnectionPHY):
        logger.debug(
            f'*** Connection PHY Update: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'{phy}'
        )
        connection.emit(connection.EVENT_CONNECTION_PHY_UPDATE, phy)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_phy_update_failure(self, connection: Connection, error: int):
        logger.debug(
            f'*** Connection PHY Update Failed: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'error={error}'
        )
        connection.emit(connection.EVENT_CONNECTION_PHY_UPDATE_FAILURE, error)

    @host_event_handler
    @with_connection_from_handle
    def on_le_subrate_change(
        self,
        connection: Connection,
        subrate_factor: int,
        peripheral_latency: int,
        continuation_number: int,
        supervision_timeout: int,
    ):
        connection.parameters = Connection.Parameters(
            connection.parameters.connection_interval,
            peripheral_latency,
            supervision_timeout * 10.0,
            subrate_factor,
            continuation_number,
        )
        connection.emit(connection.EVENT_LE_SUBRATE_CHANGE)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_data_length_change(
        self,
        connection: Connection,
        max_tx_octets: int,
        max_tx_time: int,
        max_rx_octets: int,
        max_rx_time: int,
    ):
        logger.debug(
            f'*** Connection Data Length Change: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}'
        )
        connection.data_length = (
            max_tx_octets,
            max_tx_time,
            max_rx_octets,
            max_rx_time,
        )
        connection.emit(connection.EVENT_CONNECTION_DATA_LENGTH_CHANGE)

    @host_event_handler
    def on_cs_remote_supported_capabilities(
        self, event: hci.HCI_LE_CS_Read_Remote_Supported_Capabilities_Complete_Event
    ):
        if not (connection := self.lookup_connection(event.connection_handle)):
            return

        if event.status != hci.HCI_SUCCESS:
            connection.emit(
                connection.EVENT_CHANNEL_SOUNDING_CAPABILITIES_FAILURE, event.status
            )
            return

        capabilities = ChannelSoundingCapabilities(
            num_config_supported=event.num_config_supported,
            max_consecutive_procedures_supported=event.max_consecutive_procedures_supported,
            num_antennas_supported=event.num_antennas_supported,
            max_antenna_paths_supported=event.max_antenna_paths_supported,
            roles_supported=event.roles_supported,
            modes_supported=event.modes_supported,
            rtt_capability=event.rtt_capability,
            rtt_aa_only_n=event.rtt_aa_only_n,
            rtt_sounding_n=event.rtt_sounding_n,
            rtt_random_payload_n=event.rtt_random_payload_n,
            nadm_sounding_capability=event.nadm_sounding_capability,
            nadm_random_capability=event.nadm_random_capability,
            cs_sync_phys_supported=event.cs_sync_phys_supported,
            subfeatures_supported=event.subfeatures_supported,
            t_ip1_times_supported=event.t_ip1_times_supported,
            t_ip2_times_supported=event.t_ip2_times_supported,
            t_fcs_times_supported=event.t_fcs_times_supported,
            t_pm_times_supported=event.t_pm_times_supported,
            t_sw_time_supported=event.t_sw_time_supported,
            tx_snr_capability=event.tx_snr_capability,
        )
        connection.emit(connection.EVENT_CHANNEL_SOUNDING_CAPABILITIES, capabilities)

    @host_event_handler
    def on_cs_config(self, event: hci.HCI_LE_CS_Config_Complete_Event):
        if not (connection := self.lookup_connection(event.connection_handle)):
            return

        if event.status != hci.HCI_SUCCESS:
            connection.emit(
                connection.EVENT_CHANNEL_SOUNDING_CONFIG_FAILURE, event.status
            )
            return
        if event.action == hci.HCI_LE_CS_Config_Complete_Event.Action.CREATED:
            config = ChannelSoundingConfig(
                config_id=event.config_id,
                main_mode_type=event.main_mode_type,
                sub_mode_type=event.sub_mode_type,
                min_main_mode_steps=event.min_main_mode_steps,
                max_main_mode_steps=event.max_main_mode_steps,
                main_mode_repetition=event.main_mode_repetition,
                mode_0_steps=event.mode_0_steps,
                role=event.role,
                rtt_type=event.rtt_type,
                cs_sync_phy=event.cs_sync_phy,
                channel_map=event.channel_map,
                channel_map_repetition=event.channel_map_repetition,
                channel_selection_type=event.channel_selection_type,
                ch3c_shape=event.ch3c_shape,
                ch3c_jump=event.ch3c_jump,
                reserved=event.reserved,
                t_ip1_time=event.t_ip1_time,
                t_ip2_time=event.t_ip2_time,
                t_fcs_time=event.t_fcs_time,
                t_pm_time=event.t_pm_time,
            )
            connection.cs_configs[event.config_id] = config
            connection.emit(connection.EVENT_CHANNEL_SOUNDING_CONFIG, config)
        elif event.action == hci.HCI_LE_CS_Config_Complete_Event.Action.REMOVED:
            try:
                config = connection.cs_configs.pop(event.config_id)
                connection.emit(
                    connection.EVENT_CHANNEL_SOUNDING_CONFIG_REMOVED, config.config_id
                )
            except KeyError:
                logger.error('Removing unknown config %d', event.config_id)

    @host_event_handler
    def on_cs_procedure(self, event: hci.HCI_LE_CS_Procedure_Enable_Complete_Event):
        if not (connection := self.lookup_connection(event.connection_handle)):
            return

        if event.status != hci.HCI_SUCCESS:
            connection.emit(
                connection.EVENT_CHANNEL_SOUNDING_PROCEDURE_FAILURE, event.status
            )
            return

        procedure = ChannelSoundingProcedure(
            config_id=event.config_id,
            state=event.state,
            tone_antenna_config_selection=event.tone_antenna_config_selection,
            selected_tx_power=event.selected_tx_power,
            subevent_len=event.subevent_len,
            subevents_per_event=event.subevents_per_event,
            subevent_interval=event.subevent_interval,
            event_interval=event.event_interval,
            procedure_interval=event.procedure_interval,
            procedure_count=event.procedure_count,
            max_procedure_len=event.max_procedure_len,
        )
        connection.cs_procedures[procedure.config_id] = procedure
        connection.emit(connection.EVENT_CHANNEL_SOUNDING_PROCEDURE, procedure)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_role_change(
        self,
        connection: Connection,
        new_role: hci.Role,
    ):
        connection.role = new_role
        connection.emit(connection.EVENT_ROLE_CHANGE, new_role)

    # [Classic only]
    @host_event_handler
    @try_with_connection_from_address
    def on_role_change_failure(
        self, connection: Connection | None, address: hci.Address, error: int
    ):
        if connection:
            connection.emit(connection.EVENT_ROLE_CHANGE_FAILURE, error)
        self.emit(self.EVENT_ROLE_CHANGE_FAILURE, address, error)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_classic_pairing(self, connection: Connection) -> None:
        connection.emit(connection.EVENT_CLASSIC_PAIRING)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_classic_pairing_failure(self, connection: Connection, status: int) -> None:
        connection.emit(connection.EVENT_CLASSIC_PAIRING_FAILURE, status)

    def on_pairing_start(self, connection: Connection) -> None:
        connection.emit(connection.EVENT_PAIRING_START)

    def on_pairing(
        self,
        connection: Connection,
        identity_address: hci.Address | None,
        keys: PairingKeys,
        sc: bool,
    ) -> None:
        if identity_address is not None:
            connection.peer_resolvable_address = connection.peer_address
            connection.peer_address = identity_address
        connection.sc = sc
        connection.authenticated = True
        connection.emit(connection.EVENT_PAIRING, keys)

    def on_pairing_failure(self, connection: Connection, reason: int) -> None:
        connection.emit(connection.EVENT_PAIRING_FAILURE, reason)

    @with_connection_from_handle
    def on_gatt_pdu(self, connection: Connection, pdu: bytes):
        # Parse the L2CAP payload into an ATT PDU object
        att_pdu = att.ATT_PDU.from_bytes(pdu)

        # Conveniently, even-numbered op codes are client->server and
        # odd-numbered ones are server->client
        if att_pdu.op_code & 1:
            if connection.gatt_client is None:
                logger.warning(
                    'No GATT client for connection 0x%04X', connection.handle
                )
                return
            connection.gatt_client.on_gatt_pdu(att_pdu)
        else:
            if connection.gatt_server is None:
                logger.warning(
                    'No GATT server for connection 0x%04X', connection.handle
                )
                return
            connection.gatt_server.on_gatt_pdu(connection, att_pdu)

    @with_connection_from_handle
    def on_smp_pdu(self, connection: Connection, pdu: bytes):
        self.smp_manager.on_smp_pdu(connection, pdu)

    @host_event_handler
    @with_connection_from_handle
    def on_l2cap_pdu(self, connection: Connection, cid: int, pdu: bytes):
        self.l2cap_channel_manager.on_pdu(connection, cid, pdu)

    def __str__(self):
        return (
            f'Device(name="{self.name}", '
            f'random_address="{self.random_address}", '
            f'public_address="{self.public_address}", '
            f'static_address="{self.static_address}")'
        )
