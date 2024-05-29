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
from enum import IntEnum
import copy
import functools
import json
import asyncio
import logging
import secrets
import sys
from contextlib import (
    asynccontextmanager,
    AsyncExitStack,
    closing,
    AbstractAsyncContextManager,
)
from dataclasses import dataclass, field
from collections.abc import Iterable
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    overload,
    TYPE_CHECKING,
)
from typing_extensions import Self

from pyee import EventEmitter

from .colors import color
from .att import ATT_CID, ATT_DEFAULT_MTU, ATT_PDU
from .gatt import Characteristic, Descriptor, Service
from .hci import (
    HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE,
    HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE,
    HCI_CENTRAL_ROLE,
    HCI_PERIPHERAL_ROLE,
    HCI_COMMAND_STATUS_PENDING,
    HCI_CONNECTION_REJECTED_DUE_TO_LIMITED_RESOURCES_ERROR,
    HCI_DISPLAY_YES_NO_IO_CAPABILITY,
    HCI_DISPLAY_ONLY_IO_CAPABILITY,
    HCI_EXTENDED_INQUIRY_MODE,
    HCI_GENERAL_INQUIRY_LAP,
    HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR,
    HCI_KEYBOARD_ONLY_IO_CAPABILITY,
    HCI_LE_1M_PHY,
    HCI_LE_1M_PHY_BIT,
    HCI_LE_2M_PHY,
    HCI_LE_CODED_PHY,
    HCI_LE_CODED_PHY_BIT,
    HCI_LE_EXTENDED_CREATE_CONNECTION_COMMAND,
    HCI_LE_RAND_COMMAND,
    HCI_LE_READ_PHY_COMMAND,
    HCI_LE_SET_PHY_COMMAND,
    HCI_MITM_NOT_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS,
    HCI_MITM_NOT_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS,
    HCI_MITM_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS,
    HCI_MITM_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS,
    HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY,
    HCI_R2_PAGE_SCAN_REPETITION_MODE,
    HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
    HCI_SUCCESS,
    HCI_WRITE_LE_HOST_SUPPORT_COMMAND,
    HCI_Accept_Connection_Request_Command,
    HCI_Authentication_Requested_Command,
    HCI_Command_Status_Event,
    HCI_Constant,
    HCI_Create_Connection_Cancel_Command,
    HCI_Create_Connection_Command,
    HCI_Connection_Complete_Event,
    HCI_Disconnect_Command,
    HCI_Encryption_Change_Event,
    HCI_Error,
    HCI_IO_Capability_Request_Reply_Command,
    HCI_Inquiry_Cancel_Command,
    HCI_Inquiry_Command,
    HCI_IsoDataPacket,
    HCI_LE_Accept_CIS_Request_Command,
    HCI_LE_Add_Device_To_Resolving_List_Command,
    HCI_LE_Advertising_Report_Event,
    HCI_LE_Clear_Resolving_List_Command,
    HCI_LE_Connection_Update_Command,
    HCI_LE_Create_Connection_Cancel_Command,
    HCI_LE_Create_Connection_Command,
    HCI_LE_Create_CIS_Command,
    HCI_LE_Enable_Encryption_Command,
    HCI_LE_Extended_Advertising_Report_Event,
    HCI_LE_Extended_Create_Connection_Command,
    HCI_LE_Rand_Command,
    HCI_LE_Read_PHY_Command,
    HCI_LE_Read_Remote_Features_Command,
    HCI_LE_Reject_CIS_Request_Command,
    HCI_LE_Remove_Advertising_Set_Command,
    HCI_LE_Set_Address_Resolution_Enable_Command,
    HCI_LE_Set_Advertising_Data_Command,
    HCI_LE_Set_Advertising_Enable_Command,
    HCI_LE_Set_Advertising_Parameters_Command,
    HCI_LE_Set_Advertising_Set_Random_Address_Command,
    HCI_LE_Set_CIG_Parameters_Command,
    HCI_LE_Set_Data_Length_Command,
    HCI_LE_Set_Default_PHY_Command,
    HCI_LE_Set_Extended_Scan_Enable_Command,
    HCI_LE_Set_Extended_Scan_Parameters_Command,
    HCI_LE_Set_Extended_Scan_Response_Data_Command,
    HCI_LE_Set_Extended_Advertising_Data_Command,
    HCI_LE_Set_Extended_Advertising_Enable_Command,
    HCI_LE_Set_Extended_Advertising_Parameters_Command,
    HCI_LE_Set_Host_Feature_Command,
    HCI_LE_Set_Periodic_Advertising_Enable_Command,
    HCI_LE_Set_PHY_Command,
    HCI_LE_Set_Random_Address_Command,
    HCI_LE_Set_Scan_Enable_Command,
    HCI_LE_Set_Scan_Parameters_Command,
    HCI_LE_Set_Scan_Response_Data_Command,
    HCI_PIN_Code_Request_Reply_Command,
    HCI_PIN_Code_Request_Negative_Reply_Command,
    HCI_Read_BD_ADDR_Command,
    HCI_Read_RSSI_Command,
    HCI_Reject_Connection_Request_Command,
    HCI_Remote_Name_Request_Command,
    HCI_Switch_Role_Command,
    HCI_Set_Connection_Encryption_Command,
    HCI_StatusError,
    HCI_SynchronousDataPacket,
    HCI_User_Confirmation_Request_Negative_Reply_Command,
    HCI_User_Confirmation_Request_Reply_Command,
    HCI_User_Passkey_Request_Negative_Reply_Command,
    HCI_User_Passkey_Request_Reply_Command,
    HCI_Write_Class_Of_Device_Command,
    HCI_Write_Extended_Inquiry_Response_Command,
    HCI_Write_Inquiry_Mode_Command,
    HCI_Write_LE_Host_Support_Command,
    HCI_Write_Local_Name_Command,
    HCI_Write_Scan_Enable_Command,
    HCI_Write_Secure_Connections_Host_Support_Command,
    HCI_Write_Simple_Pairing_Mode_Command,
    Address,
    OwnAddressType,
    LeFeature,
    LeFeatureMask,
    Phy,
    phy_list_to_bits,
)
from .host import Host
from .gap import GenericAccessService
from .core import (
    BT_BR_EDR_TRANSPORT,
    BT_CENTRAL_ROLE,
    BT_LE_TRANSPORT,
    BT_PERIPHERAL_ROLE,
    AdvertisingData,
    ConnectionParameterUpdateError,
    CommandTimeoutError,
    ConnectionPHY,
    InvalidStateError,
)
from .utils import (
    AsyncRunner,
    CompositeEventEmitter,
    EventWatcher,
    setup_event_forwarding,
    composite_listener,
    deprecated,
    experimental,
)
from .keys import (
    KeyStore,
    PairingKeys,
)
from .pairing import PairingConfig
from . import gatt_client
from . import gatt_server
from . import smp
from . import sdp
from . import l2cap
from . import core

if TYPE_CHECKING:
    from .transport.common import TransportSource, TransportSink


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# fmt: off
# pylint: disable=line-too-long

DEVICE_MIN_SCAN_INTERVAL                      = 25
DEVICE_MAX_SCAN_INTERVAL                      = 10240
DEVICE_MIN_SCAN_WINDOW                        = 25
DEVICE_MAX_SCAN_WINDOW                        = 10240
DEVICE_MIN_LE_RSSI                            = -127
DEVICE_MAX_LE_RSSI                            = 20
DEVICE_MIN_EXTENDED_ADVERTISING_SET_HANDLE    = 0x00
DEVICE_MAX_EXTENDED_ADVERTISING_SET_HANDLE    = 0xEF

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
    HCI_LE_Set_Extended_Advertising_Parameters_Command.TX_POWER_NO_PREFERENCE
)

# fmt: on
# pylint: enable=line-too-long

# As specified in 7.8.56 LE Set Extended Advertising Enable command
DEVICE_MAX_HIGH_DUTY_CYCLE_CONNECTABLE_DIRECTED_ADVERTISING_DURATION = 1.28


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
@dataclass
class Advertisement:
    # Attributes
    address: Address
    rssi: int = HCI_LE_Extended_Advertising_Report_Event.RSSI_NOT_AVAILABLE
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
        HCI_LE_Extended_Advertising_Report_Event.TX_POWER_INFORMATION_NOT_AVAILABLE
    )
    sid: int = 0
    data_bytes: bytes = b''

    # Constants
    TX_POWER_NOT_AVAILABLE: ClassVar[int] = (
        HCI_LE_Extended_Advertising_Report_Event.TX_POWER_INFORMATION_NOT_AVAILABLE
    )
    RSSI_NOT_AVAILABLE: ClassVar[int] = (
        HCI_LE_Extended_Advertising_Report_Event.RSSI_NOT_AVAILABLE
    )

    def __post_init__(self) -> None:
        self.data = AdvertisingData.from_bytes(self.data_bytes)

    @classmethod
    def from_advertising_report(cls, report) -> Optional[Advertisement]:
        if isinstance(report, HCI_LE_Advertising_Report_Event.Report):
            return LegacyAdvertisement.from_advertising_report(report)

        if isinstance(report, HCI_LE_Extended_Advertising_Report_Event.Report):
            return ExtendedAdvertisement.from_advertising_report(report)

        return None


# -----------------------------------------------------------------------------
class LegacyAdvertisement(Advertisement):
    @classmethod
    def from_advertising_report(cls, report):
        return cls(
            address=report.address,
            rssi=report.rssi,
            is_legacy=True,
            is_connectable=report.event_type
            in (
                HCI_LE_Advertising_Report_Event.ADV_IND,
                HCI_LE_Advertising_Report_Event.ADV_DIRECT_IND,
            ),
            is_directed=report.event_type
            == HCI_LE_Advertising_Report_Event.ADV_DIRECT_IND,
            is_scannable=report.event_type
            in (
                HCI_LE_Advertising_Report_Event.ADV_IND,
                HCI_LE_Advertising_Report_Event.ADV_SCAN_IND,
            ),
            is_scan_response=report.event_type
            == HCI_LE_Advertising_Report_Event.SCAN_RSP,
            data_bytes=report.data,
        )


# -----------------------------------------------------------------------------
class ExtendedAdvertisement(Advertisement):
    @classmethod
    def from_advertising_report(cls, report):
        # fmt: off
        # pylint: disable=line-too-long
        return cls(
            address          = report.address,
            rssi             = report.rssi,
            is_legacy        = report.event_type & (1 << HCI_LE_Extended_Advertising_Report_Event.LEGACY_ADVERTISING_PDU_USED) != 0,
            is_anonymous     = report.address.address_type == HCI_LE_Extended_Advertising_Report_Event.ANONYMOUS_ADDRESS_TYPE,
            is_connectable   = report.event_type & (1 << HCI_LE_Extended_Advertising_Report_Event.CONNECTABLE_ADVERTISING) != 0,
            is_directed      = report.event_type & (1 << HCI_LE_Extended_Advertising_Report_Event.DIRECTED_ADVERTISING) != 0,
            is_scannable     = report.event_type & (1 << HCI_LE_Extended_Advertising_Report_Event.SCANNABLE_ADVERTISING) != 0,
            is_scan_response = report.event_type & (1 << HCI_LE_Extended_Advertising_Report_Event.SCAN_RESPONSE) != 0,
            is_complete      = (report.event_type >> 5 & 3)  == HCI_LE_Extended_Advertising_Report_Event.DATA_COMPLETE,
            is_truncated     = (report.event_type >> 5 & 3)  == HCI_LE_Extended_Advertising_Report_Event.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME,
            primary_phy      = report.primary_phy,
            secondary_phy    = report.secondary_phy,
            tx_power         = report.tx_power,
            sid              = report.advertising_sid,
            data_bytes       = report.data
        )
        # fmt: on


# -----------------------------------------------------------------------------
class AdvertisementDataAccumulator:
    def __init__(self, passive=False):
        self.passive = passive
        self.last_advertisement = None
        self.last_data = b''

    def update(self, report):
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
                result = Advertisement.from_advertising_report(report)
                result.is_connectable = self.last_advertisement.is_connectable
                result.is_scannable = True
                result.data = AdvertisingData.from_bytes(self.last_data + report.data)
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
    own_address_type: OwnAddressType
    peer_address: Address
    auto_restart: bool

    async def start(self) -> None:
        # Set/update the advertising data if the advertising type allows it
        if self.advertising_type.has_data:
            await self.device.send_command(
                HCI_LE_Set_Advertising_Data_Command(
                    advertising_data=self.device.advertising_data
                ),
                check_result=True,
            )

        # Set/update the scan response data if the advertising is scannable
        if self.advertising_type.is_scannable:
            await self.device.send_command(
                HCI_LE_Set_Scan_Response_Data_Command(
                    scan_response_data=self.device.scan_response_data
                ),
                check_result=True,
            )

        # Set the advertising parameters
        await self.device.send_command(
            HCI_LE_Set_Advertising_Parameters_Command(
                advertising_interval_min=self.device.advertising_interval_min,
                advertising_interval_max=self.device.advertising_interval_max,
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
            HCI_LE_Set_Advertising_Enable_Command(advertising_enable=1),
            check_result=True,
        )

    async def stop(self) -> None:
        # Disable advertising
        await self.device.send_command(
            HCI_LE_Set_Advertising_Enable_Command(advertising_enable=0),
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
        properties = (
            HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties(0)
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
        cls: Type[AdvertisingEventProperties],
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
# TODO: replace with typing.TypeAlias when the code base is all Python >= 3.10
AdvertisingChannelMap = HCI_LE_Set_Extended_Advertising_Parameters_Command.ChannelMap


# -----------------------------------------------------------------------------
@dataclass
class AdvertisingParameters:
    # pylint: disable=line-too-long
    advertising_event_properties: AdvertisingEventProperties = field(
        default_factory=AdvertisingEventProperties
    )
    primary_advertising_interval_min: int = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    primary_advertising_interval_max: int = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    primary_advertising_channel_map: (
        HCI_LE_Set_Extended_Advertising_Parameters_Command.ChannelMap
    ) = (
        AdvertisingChannelMap.CHANNEL_37
        | AdvertisingChannelMap.CHANNEL_38
        | AdvertisingChannelMap.CHANNEL_39
    )
    own_address_type: OwnAddressType = OwnAddressType.RANDOM
    peer_address: Address = Address.ANY
    advertising_filter_policy: int = 0
    advertising_tx_power: int = DEVICE_DEFAULT_ADVERTISING_TX_POWER
    primary_advertising_phy: Phy = Phy.LE_1M
    secondary_advertising_max_skip: int = 0
    secondary_advertising_phy: Phy = Phy.LE_1M
    advertising_sid: int = 0
    enable_scan_request_notifications: bool = False
    primary_advertising_phy_options: int = 0
    secondary_advertising_phy_options: int = 0


# -----------------------------------------------------------------------------
@dataclass
class PeriodicAdvertisingParameters:
    # TODO implement this class
    pass


# -----------------------------------------------------------------------------
@dataclass
class AdvertisingSet(EventEmitter):
    device: Device
    advertising_handle: int
    auto_restart: bool
    random_address: Optional[Address]
    advertising_parameters: AdvertisingParameters
    advertising_data: bytes
    scan_response_data: bytes
    periodic_advertising_parameters: Optional[PeriodicAdvertisingParameters]
    periodic_advertising_data: bytes
    selected_tx_power: int = 0
    enabled: bool = False

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
            HCI_LE_Set_Extended_Advertising_Parameters_Command(
                advertising_handle=self.advertising_handle,
                advertising_event_properties=int(
                    advertising_parameters.advertising_event_properties
                ),
                primary_advertising_interval_min=(
                    int(advertising_parameters.primary_advertising_interval_min / 0.625)
                ),
                primary_advertising_interval_max=(
                    int(advertising_parameters.primary_advertising_interval_min / 0.625)
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
            HCI_LE_Set_Extended_Advertising_Data_Command(
                advertising_handle=self.advertising_handle,
                operation=HCI_LE_Set_Extended_Advertising_Data_Command.Operation.COMPLETE_DATA,
                fragment_preference=HCI_LE_Set_Extended_Advertising_Parameters_Command.SHOULD_NOT_FRAGMENT,
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
            HCI_LE_Set_Extended_Scan_Response_Data_Command(
                advertising_handle=self.advertising_handle,
                operation=HCI_LE_Set_Extended_Advertising_Data_Command.Operation.COMPLETE_DATA,
                fragment_preference=HCI_LE_Set_Extended_Advertising_Parameters_Command.SHOULD_NOT_FRAGMENT,
                scan_response_data=scan_response_data,
            ),
            check_result=True,
        )
        self.scan_response_data = scan_response_data

    async def set_periodic_advertising_parameters(
        self, advertising_parameters: PeriodicAdvertisingParameters
    ) -> None:
        # TODO: send command
        self.periodic_advertising_parameters = advertising_parameters

    async def set_periodic_advertising_data(self, advertising_data: bytes) -> None:
        # TODO: send command
        self.periodic_advertising_data = advertising_data

    async def set_random_address(self, random_address: Address) -> None:
        await self.device.send_command(
            HCI_LE_Set_Advertising_Set_Random_Address_Command(
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
            HCI_LE_Set_Extended_Advertising_Enable_Command(
                enable=1,
                advertising_handles=[self.advertising_handle],
                durations=[round(duration * 100)],
                max_extended_advertising_events=[max_advertising_events],
            ),
            check_result=True,
        )
        self.enabled = True

        self.emit('start')

    async def start_periodic(self, include_adi: bool = False) -> None:
        await self.device.send_command(
            HCI_LE_Set_Periodic_Advertising_Enable_Command(
                enable=1 | (2 if include_adi else 0),
                advertising_handles=self.advertising_handle,
            ),
            check_result=True,
        )

        self.emit('start_periodic')

    async def stop(self) -> None:
        await self.device.send_command(
            HCI_LE_Set_Extended_Advertising_Enable_Command(
                enable=0,
                advertising_handles=[self.advertising_handle],
                durations=[0],
                max_extended_advertising_events=[0],
            ),
            check_result=True,
        )
        self.enabled = False

        self.emit('stop')

    async def stop_periodic(self) -> None:
        await self.device.send_command(
            HCI_LE_Set_Periodic_Advertising_Enable_Command(
                enable=0,
                advertising_handles=self.advertising_handle,
            ),
            check_result=True,
        )

        self.emit('stop_periodic')

    async def remove(self) -> None:
        await self.device.send_command(
            HCI_LE_Remove_Advertising_Set_Command(
                advertising_handle=self.advertising_handle
            ),
            check_result=True,
        )
        del self.device.extended_advertising_sets[self.advertising_handle]

    def on_termination(self, status: int) -> None:
        self.enabled = False
        self.emit('termination', status)


# -----------------------------------------------------------------------------
class LePhyOptions:
    # Coded PHY preference
    ANY_CODED_PHY = 0
    PREFER_S_2_CODED_PHY = 1
    PREFER_S_8_CODED_PHY = 2

    def __init__(self, coded_phy_preference=0):
        self.coded_phy_preference = coded_phy_preference

    def __int__(self):
        return self.coded_phy_preference & 3


# -----------------------------------------------------------------------------
_PROXY_CLASS = TypeVar('_PROXY_CLASS', bound=gatt_client.ProfileServiceProxy)


class Peer:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection

        # Create a GATT client for the connection
        self.gatt_client = gatt_client.Client(connection)
        connection.gatt_client = self.gatt_client

    @property
    def services(self) -> List[gatt_client.ServiceProxy]:
        return self.gatt_client.services

    async def request_mtu(self, mtu: int) -> int:
        mtu = await self.gatt_client.request_mtu(mtu)
        self.connection.emit('connection_att_mtu_update')
        return mtu

    async def discover_service(
        self, uuid: Union[core.UUID, str]
    ) -> List[gatt_client.ServiceProxy]:
        return await self.gatt_client.discover_service(uuid)

    async def discover_services(
        self, uuids: Iterable[core.UUID] = ()
    ) -> List[gatt_client.ServiceProxy]:
        return await self.gatt_client.discover_services(uuids)

    async def discover_included_services(
        self, service: gatt_client.ServiceProxy
    ) -> List[gatt_client.ServiceProxy]:
        return await self.gatt_client.discover_included_services(service)

    async def discover_characteristics(
        self,
        uuids: Iterable[Union[core.UUID, str]] = (),
        service: Optional[gatt_client.ServiceProxy] = None,
    ) -> List[gatt_client.CharacteristicProxy]:
        return await self.gatt_client.discover_characteristics(
            uuids=uuids, service=service
        )

    async def discover_descriptors(
        self,
        characteristic: Optional[gatt_client.CharacteristicProxy] = None,
        start_handle: Optional[int] = None,
        end_handle: Optional[int] = None,
    ):
        return await self.gatt_client.discover_descriptors(
            characteristic, start_handle, end_handle
        )

    async def discover_attributes(self) -> List[gatt_client.AttributeProxy]:
        return await self.gatt_client.discover_attributes()

    async def subscribe(
        self,
        characteristic: gatt_client.CharacteristicProxy,
        subscriber: Optional[Callable[[bytes], Any]] = None,
        prefer_notify: bool = True,
    ) -> None:
        return await self.gatt_client.subscribe(
            characteristic, subscriber, prefer_notify
        )

    async def unsubscribe(
        self,
        characteristic: gatt_client.CharacteristicProxy,
        subscriber: Optional[Callable[[bytes], Any]] = None,
    ) -> None:
        return await self.gatt_client.unsubscribe(characteristic, subscriber)

    async def read_value(
        self, attribute: Union[int, gatt_client.AttributeProxy]
    ) -> bytes:
        return await self.gatt_client.read_value(attribute)

    async def write_value(
        self,
        attribute: Union[int, gatt_client.AttributeProxy],
        value: bytes,
        with_response: bool = False,
    ) -> None:
        return await self.gatt_client.write_value(attribute, value, with_response)

    async def read_characteristics_by_uuid(
        self, uuid: core.UUID, service: Optional[gatt_client.ServiceProxy] = None
    ) -> List[bytes]:
        return await self.gatt_client.read_characteristics_by_uuid(uuid, service)

    def get_services_by_uuid(self, uuid: core.UUID) -> List[gatt_client.ServiceProxy]:
        return self.gatt_client.get_services_by_uuid(uuid)

    def get_characteristics_by_uuid(
        self, uuid: core.UUID, service: Optional[gatt_client.ServiceProxy] = None
    ) -> List[gatt_client.CharacteristicProxy]:
        return self.gatt_client.get_characteristics_by_uuid(uuid, service)

    def create_service_proxy(self, proxy_class: Type[_PROXY_CLASS]) -> _PROXY_CLASS:
        return cast(_PROXY_CLASS, proxy_class.from_client(self.gatt_client))

    async def discover_service_and_create_proxy(
        self, proxy_class: Type[_PROXY_CLASS]
    ) -> Optional[_PROXY_CLASS]:
        # Discover the first matching service and its characteristics
        services = await self.discover_service(proxy_class.SERVICE_CLASS.UUID)
        if services:
            service = services[0]
            await service.discover_characteristics()
            return self.create_service_proxy(proxy_class)
        return None

    async def sustain(self, timeout: Optional[float] = None) -> None:
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
    connection_interval_min: int = DEVICE_DEFAULT_CONNECTION_INTERVAL_MIN
    connection_interval_max: int = DEVICE_DEFAULT_CONNECTION_INTERVAL_MAX
    max_latency: int = DEVICE_DEFAULT_CONNECTION_MAX_LATENCY
    supervision_timeout: int = DEVICE_DEFAULT_CONNECTION_SUPERVISION_TIMEOUT
    min_ce_length: int = DEVICE_DEFAULT_CONNECTION_MIN_CE_LENGTH
    max_ce_length: int = DEVICE_DEFAULT_CONNECTION_MAX_CE_LENGTH


ConnectionParametersPreferences.default = ConnectionParametersPreferences()


# -----------------------------------------------------------------------------
@dataclass
class ScoLink(CompositeEventEmitter):
    device: Device
    acl_connection: Connection
    handle: int
    link_type: int
    sink: Optional[Callable[[HCI_SynchronousDataPacket], Any]] = None

    def __post_init__(self) -> None:
        super().__init__()

    async def disconnect(
        self, reason: int = HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR
    ) -> None:
        await self.device.disconnect(self, reason)


# -----------------------------------------------------------------------------
@dataclass
class CisLink(CompositeEventEmitter):
    class State(IntEnum):
        PENDING = 0
        ESTABLISHED = 1

    device: Device
    acl_connection: Connection  # Based ACL connection
    handle: int  # CIS handle assigned by Controller (in LE_Set_CIG_Parameters Complete or LE_CIS_Request events)
    cis_id: int  # CIS ID assigned by Central device
    cig_id: int  # CIG ID assigned by Central device
    state: State = State.PENDING
    sink: Optional[Callable[[HCI_IsoDataPacket], Any]] = None

    def __post_init__(self) -> None:
        super().__init__()

    async def disconnect(
        self, reason: int = HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR
    ) -> None:
        await self.device.disconnect(self, reason)


# -----------------------------------------------------------------------------
class Connection(CompositeEventEmitter):
    device: Device
    handle: int
    transport: int
    self_address: Address
    peer_address: Address
    peer_resolvable_address: Optional[Address]
    peer_le_features: Optional[LeFeatureMask]
    role: int
    encryption: int
    authenticated: bool
    sc: bool
    link_key_type: int
    gatt_client: gatt_client.Client
    pairing_peer_io_capability: Optional[int]
    pairing_peer_authentication_requirements: Optional[int]

    @composite_listener
    class Listener:
        def on_disconnection(self, reason):
            pass

        def on_connection_parameters_update(self):
            pass

        def on_connection_parameters_update_failure(self, error):
            pass

        def on_connection_data_length_change(self):
            pass

        def on_connection_phy_update(self):
            pass

        def on_connection_phy_update_failure(self, error):
            pass

        def on_connection_att_mtu_update(self):
            pass

        def on_connection_encryption_change(self):
            pass

        def on_connection_encryption_key_refresh(self):
            pass

    def __init__(
        self,
        device,
        handle,
        transport,
        self_address,
        peer_address,
        peer_resolvable_address,
        role,
        parameters,
        phy,
    ):
        super().__init__()
        self.device = device
        self.handle = handle
        self.transport = transport
        self.self_address = self_address
        self.peer_address = peer_address
        self.peer_resolvable_address = peer_resolvable_address
        self.peer_name = None  # Classic only
        self.role = role
        self.parameters = parameters
        self.encryption = 0
        self.authenticated = False
        self.sc = False
        self.link_key_type = None
        self.phy = phy
        self.att_mtu = ATT_DEFAULT_MTU
        self.data_length = DEVICE_DEFAULT_DATA_LENGTH
        self.gatt_client = None  # Per-connection client
        self.gatt_server = (
            device.gatt_server
        )  # By default, use the device's shared server
        self.pairing_peer_io_capability = None
        self.pairing_peer_authentication_requirements = None
        self.peer_le_features = None

    # [Classic only]
    @classmethod
    def incomplete(cls, device, peer_address, role):
        """
        Instantiate an incomplete connection (ie. one waiting for a HCI Connection
        Complete event).
        Once received it shall be completed using the `.complete` method.
        """
        return cls(
            device,
            None,
            BT_BR_EDR_TRANSPORT,
            device.public_address,
            peer_address,
            None,
            role,
            None,
            None,
        )

    # [Classic only]
    def complete(self, handle, parameters):
        """
        Finish an incomplete connection upon completion.
        """
        assert self.handle is None
        assert self.transport == BT_BR_EDR_TRANSPORT
        self.handle = handle
        self.parameters = parameters

    @property
    def role_name(self):
        if self.role is None:
            return 'NOT-SET'
        if self.role == BT_CENTRAL_ROLE:
            return 'CENTRAL'
        if self.role == BT_PERIPHERAL_ROLE:
            return 'PERIPHERAL'
        return f'UNKNOWN[{self.role}]'

    @property
    def is_encrypted(self):
        return self.encryption != 0

    @property
    def is_incomplete(self) -> bool:
        return self.handle is None

    def send_l2cap_pdu(self, cid: int, pdu: bytes) -> None:
        self.device.send_l2cap_pdu(self.handle, cid, pdu)

    @deprecated("Please use create_l2cap_channel()")
    async def open_l2cap_channel(
        self,
        psm,
        max_credits=DEVICE_DEFAULT_L2CAP_COC_MAX_CREDITS,
        mtu=DEVICE_DEFAULT_L2CAP_COC_MTU,
        mps=DEVICE_DEFAULT_L2CAP_COC_MPS,
    ):
        return await self.device.open_l2cap_channel(self, psm, max_credits, mtu, mps)

    @overload
    async def create_l2cap_channel(
        self, spec: l2cap.ClassicChannelSpec
    ) -> l2cap.ClassicChannel: ...

    @overload
    async def create_l2cap_channel(
        self, spec: l2cap.LeCreditBasedChannelSpec
    ) -> l2cap.LeCreditBasedChannel: ...

    async def create_l2cap_channel(
        self, spec: Union[l2cap.ClassicChannelSpec, l2cap.LeCreditBasedChannelSpec]
    ) -> Union[l2cap.ClassicChannel, l2cap.LeCreditBasedChannel]:
        return await self.device.create_l2cap_channel(connection=self, spec=spec)

    async def disconnect(
        self, reason: int = HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR
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

    async def switch_role(self, role: int) -> None:
        return await self.device.switch_role(self, role)

    async def sustain(self, timeout: Optional[float] = None) -> None:
        """Idles the current task waiting for a disconnect or timeout"""

        abort = asyncio.get_running_loop().create_future()
        self.on('disconnection', abort.set_result)
        self.on('disconnection_failure', abort.set_exception)

        try:
            await asyncio.wait_for(self.device.abort_on('flush', abort), timeout)
        except asyncio.TimeoutError:
            pass

        self.remove_listener('disconnection', abort.set_result)
        self.remove_listener('disconnection_failure', abort.set_exception)

    async def set_data_length(self, tx_octets, tx_time) -> None:
        return await self.device.set_data_length(self, tx_octets, tx_time)

    async def update_parameters(
        self,
        connection_interval_min,
        connection_interval_max,
        max_latency,
        supervision_timeout,
        use_l2cap=False,
    ):
        return await self.device.update_connection_parameters(
            self,
            connection_interval_min,
            connection_interval_max,
            max_latency,
            supervision_timeout,
            use_l2cap=use_l2cap,
        )

    async def set_phy(self, tx_phys=None, rx_phys=None, phy_options=None):
        return await self.device.set_connection_phy(self, tx_phys, rx_phys, phy_options)

    async def get_rssi(self):
        return await self.device.get_connection_rssi(self)

    async def get_phy(self):
        return await self.device.get_connection_phy(self)

    # [Classic only]
    async def request_remote_name(self):
        return await self.device.request_remote_name(self)

    async def get_remote_le_features(self) -> LeFeatureMask:
        """[LE Only] Reads remote LE supported features.

        Returns:
            LE features supported by the remote device.
        """
        self.peer_le_features = await self.device.get_remote_le_features(self)
        return self.peer_le_features

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            try:
                await self.disconnect()
            except HCI_StatusError as error:
                # Invalid parameter means the connection is no longer valid
                if error.error_code != HCI_INVALID_HCI_COMMAND_PARAMETERS_ERROR:
                    raise

    def __str__(self):
        return (
            f'Connection(handle=0x{self.handle:04X}, '
            f'role={self.role_name}, '
            f'self_address={self.self_address}, '
            f'peer_address={self.peer_address})'
        )


# -----------------------------------------------------------------------------
@dataclass
class DeviceConfiguration:
    # Setup defaults
    name: str = DEVICE_DEFAULT_NAME
    address: Address = Address(DEVICE_DEFAULT_ADDRESS)
    class_of_device: int = DEVICE_DEFAULT_CLASS_OF_DEVICE
    scan_response_data: bytes = DEVICE_DEFAULT_SCAN_RESPONSE_DATA
    advertising_interval_min: int = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    advertising_interval_max: int = DEVICE_DEFAULT_ADVERTISING_INTERVAL
    le_enabled: bool = True
    # LE host enable 2nd parameter
    le_simultaneous_enabled: bool = False
    classic_enabled: bool = False
    classic_sc_enabled: bool = True
    classic_ssp_enabled: bool = True
    classic_smp_enabled: bool = True
    classic_accept_any: bool = True
    connectable: bool = True
    discoverable: bool = True
    advertising_data: bytes = bytes(
        AdvertisingData(
            [(AdvertisingData.COMPLETE_LOCAL_NAME, bytes(DEVICE_DEFAULT_NAME, 'utf-8'))]
        )
    )
    irk: bytes = bytes(16)  # This really must be changed for any level of security
    keystore: Optional[str] = None
    address_resolution_offload: bool = False
    cis_enabled: bool = False

    def __post_init__(self) -> None:
        self.gatt_services: List[Dict[str, Any]] = []

    def load_from_dict(self, config: Dict[str, Any]) -> None:
        config = copy.deepcopy(config)

        # Load simple properties
        if address := config.pop('address', None):
            self.address = Address(address)

        # Load or synthesize an IRK
        if irk := config.pop('irk', None):
            self.irk = bytes.fromhex(irk)
        elif self.address != Address(DEVICE_DEFAULT_ADDRESS):
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
                AdvertisingData(
                    [(AdvertisingData.COMPLETE_LOCAL_NAME, bytes(self.name, 'utf-8'))]
                )
            )

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
        with open(filename, 'r', encoding='utf-8') as file:
            self.load_from_dict(json.load(file))

    @classmethod
    def from_file(cls: Type[Self], filename: str) -> Self:
        config = cls()
        config.load_from_file(filename)
        return config

    @classmethod
    def from_dict(cls: Type[Self], config: Dict[str, Any]) -> Self:
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
    def wrapper(self, connection_handle, *args, **kwargs):
        if (connection := self.lookup_connection(connection_handle)) is None:
            raise ValueError(f'no connection for handle: 0x{connection_handle:04x}')
        return function(self, connection, *args, **kwargs)

    return wrapper


# Decorator that converts the first argument from a bluetooth address to a connection
def with_connection_from_address(function):
    @functools.wraps(function)
    def wrapper(self, address, *args, **kwargs):
        if connection := self.pending_connections.get(address, False):
            return function(self, connection, *args, **kwargs)
        for connection in self.connections.values():
            if connection.peer_address == address:
                return function(self, connection, *args, **kwargs)
        raise ValueError('no connection for address')

    return wrapper


# Decorator that tries to convert the first argument from a bluetooth address to a
# connection
def try_with_connection_from_address(function):
    @functools.wraps(function)
    def wrapper(self, address, *args, **kwargs):
        if connection := self.pending_connections.get(address, False):
            return function(self, connection, address, *args, **kwargs)
        for connection in self.connections.values():
            if connection.peer_address == address:
                return function(self, connection, address, *args, **kwargs)
        return function(self, None, address, *args, **kwargs)

    return wrapper


# Decorator that adds a method to the list of event handlers for host events.
# This assumes that the method name starts with `on_`
def host_event_handler(function):
    device_host_event_handlers.append(function.__name__[3:])
    return function


# List of host event handlers for the Device class.
# (we define this list outside the class, because referencing a class in method
#  decorators is not straightforward)
device_host_event_handlers: List[str] = []


# -----------------------------------------------------------------------------
class Device(CompositeEventEmitter):
    # Incomplete list of fields.
    random_address: Address
    public_address: Address
    classic_enabled: bool
    name: str
    class_of_device: int
    gatt_server: gatt_server.Server
    advertising_data: bytes
    scan_response_data: bytes
    connections: Dict[int, Connection]
    pending_connections: Dict[Address, Connection]
    classic_pending_accepts: Dict[
        Address, List[asyncio.Future[Union[Connection, Tuple[Address, int, int]]]]
    ]
    advertisement_accumulators: Dict[Address, AdvertisementDataAccumulator]
    config: DeviceConfiguration
    legacy_advertiser: Optional[LegacyAdvertiser]
    sco_links: Dict[int, ScoLink]
    cis_links: Dict[int, CisLink]
    _pending_cis: Dict[int, Tuple[int, int]]

    @composite_listener
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
        address: Address,
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
        name: Optional[str] = None,
        address: Optional[Address] = None,
        config: Optional[DeviceConfiguration] = None,
        host: Optional[Host] = None,
        generic_access_service: bool = True,
    ) -> None:
        super().__init__()

        self._host = None
        self.powered_on = False
        self.auto_restart_inquiry = True
        self.command_timeout = 10  # seconds
        self.gatt_server = gatt_server.Server(self)
        self.sdp_server = sdp.Server(self)
        self.l2cap_channel_manager = l2cap.ChannelManager(
            [l2cap.L2CAP_Information_Request.EXTENDED_FEATURE_FIXED_CHANNELS]
        )
        self.advertisement_accumulators = {}  # Accumulators, by address
        self.scanning = False
        self.scanning_is_passive = False
        self.discovering = False
        self.le_connecting = False
        self.disconnecting = False
        self.connections = {}  # Connections, by connection handle
        self.pending_connections = {}  # Connections, by BD address (BR/EDR only)
        self.sco_links = {}  # ScoLinks, by connection handle (BR/EDR only)
        self.cis_links = {}  # CisLinks, by connection handle (LE only)
        self._pending_cis = {}  # (CIS_ID, CIG_ID), by CIS_handle
        self.classic_enabled = False
        self.inquiry_response = None
        self.address_resolver = None
        self.classic_pending_accepts = {
            Address.ANY: []
        }  # Futures, by BD address OR [Futures] for Address.ANY

        # In Python <= 3.9 + Rust Runtime, asyncio.Lock cannot be properly initiated.
        if sys.version_info >= (3, 10):
            self._cis_lock = asyncio.Lock()
        else:
            self._cis_lock = AsyncExitStack()

        # Own address type cache
        self.connect_own_address_type = None

        # Use the initial config or a default
        config = config or DeviceConfiguration()
        self.config = config

        self.public_address = Address('00:00:00:00:00:00')
        self.name = config.name
        self.random_address = config.address
        self.class_of_device = config.class_of_device
        self.keystore = None
        self.irk = config.irk
        self.le_enabled = config.le_enabled
        self.classic_enabled = config.classic_enabled
        self.le_simultaneous_enabled = config.le_simultaneous_enabled
        self.cis_enabled = config.cis_enabled
        self.classic_sc_enabled = config.classic_sc_enabled
        self.classic_ssp_enabled = config.classic_ssp_enabled
        self.classic_smp_enabled = config.classic_smp_enabled
        self.discoverable = config.discoverable
        self.connectable = config.connectable
        self.classic_accept_any = config.classic_accept_any
        self.address_resolution_offload = config.address_resolution_offload

        # Extended advertising.
        self.extended_advertising_sets: Dict[int, AdvertisingSet] = {}

        # Legacy advertising.
        # The advertising and scan response data, as well as the advertising interval
        # values are stored as properties of this object for convenience so that they
        # can be initialized from a config object, and for backward compatibility for
        # client code that may set those values directly before calling
        # start_advertising().
        self.legacy_advertising_set: Optional[AdvertisingSet] = None
        self.legacy_advertiser: Optional[LegacyAdvertiser] = None
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
                new_characteristic = Characteristic(
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
                address = Address(address)
            self.random_address = address

        # Setup SMP
        self.smp_manager = smp.Manager(
            self, pairing_config_factory=lambda connection: PairingConfig()
        )

        self.l2cap_channel_manager.register_fixed_channel(smp.SMP_CID, self.on_smp_pdu)

        # Register the SDP server with the L2CAP Channel Manager
        self.sdp_server.register(self.l2cap_channel_manager)

        self.add_default_services(generic_access_service)
        self.l2cap_channel_manager.register_fixed_channel(ATT_CID, self.on_gatt_pdu)

        # Forward some events
        setup_event_forwarding(self.gatt_server, self, 'characteristic_subscription')

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

    def lookup_connection(self, connection_handle: int) -> Optional[Connection]:
        if connection := self.connections.get(connection_handle):
            return connection

        return None

    def find_connection_by_bd_addr(
        self,
        bd_addr: Address,
        transport: Optional[int] = None,
        check_address_type: bool = False,
    ) -> Optional[Connection]:
        for connection in self.connections.values():
            if connection.peer_address.to_bytes() == bd_addr.to_bytes():
                if (
                    check_address_type
                    and connection.peer_address.address_type != bd_addr.address_type
                ):
                    continue
                if transport is None or connection.transport == transport:
                    return connection

        return None

    @deprecated("Please use create_l2cap_server()")
    def register_l2cap_server(self, psm, server) -> int:
        return self.l2cap_channel_manager.register_server(psm, server)

    @deprecated("Please use create_l2cap_server()")
    def register_l2cap_channel_server(
        self,
        psm,
        server,
        max_credits=DEVICE_DEFAULT_L2CAP_COC_MAX_CREDITS,
        mtu=DEVICE_DEFAULT_L2CAP_COC_MTU,
        mps=DEVICE_DEFAULT_L2CAP_COC_MPS,
    ):
        return self.l2cap_channel_manager.register_le_coc_server(
            psm, server, max_credits, mtu, mps
        )

    @deprecated("Please use create_l2cap_channel()")
    async def open_l2cap_channel(
        self,
        connection,
        psm,
        max_credits=DEVICE_DEFAULT_L2CAP_COC_MAX_CREDITS,
        mtu=DEVICE_DEFAULT_L2CAP_COC_MTU,
        mps=DEVICE_DEFAULT_L2CAP_COC_MPS,
    ):
        return await self.l2cap_channel_manager.open_le_coc(
            connection, psm, max_credits, mtu, mps
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
        spec: Union[l2cap.ClassicChannelSpec, l2cap.LeCreditBasedChannelSpec],
    ) -> Union[l2cap.ClassicChannel, l2cap.LeCreditBasedChannel]:
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
        handler: Optional[Callable[[l2cap.ClassicChannel], Any]] = None,
    ) -> l2cap.ClassicChannelServer: ...

    @overload
    def create_l2cap_server(
        self,
        spec: l2cap.LeCreditBasedChannelSpec,
        handler: Optional[Callable[[l2cap.LeCreditBasedChannel], Any]] = None,
    ) -> l2cap.LeCreditBasedChannelServer: ...

    def create_l2cap_server(
        self,
        spec: Union[l2cap.ClassicChannelSpec, l2cap.LeCreditBasedChannelSpec],
        handler: Union[
            Callable[[l2cap.ClassicChannel], Any],
            Callable[[l2cap.LeCreditBasedChannel], Any],
            None,
        ] = None,
    ) -> Union[l2cap.ClassicChannelServer, l2cap.LeCreditBasedChannelServer]:
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
            raise ValueError(f'Unexpected mode {spec}')

    def send_l2cap_pdu(self, connection_handle: int, cid: int, pdu: bytes) -> None:
        self.host.send_l2cap_pdu(connection_handle, cid, pdu)

    async def send_command(self, command, check_result=False):
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
        response = await self.send_command(HCI_Read_BD_ADDR_Command())
        if response.return_parameters.status == HCI_SUCCESS:
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

        if self.host.supports_command(HCI_WRITE_LE_HOST_SUPPORT_COMMAND):
            await self.send_command(
                HCI_Write_LE_Host_Support_Command(
                    le_supported_host=int(self.le_enabled),
                    simultaneous_le_host=int(self.le_simultaneous_enabled),
                )
            )

        if self.le_enabled:
            # Set the controller address
            if self.random_address == Address.ANY_RANDOM:
                # Try to use an address generated at random by the controller
                if self.host.supports_command(HCI_LE_RAND_COMMAND):
                    # Get 8 random bytes
                    response = await self.send_command(
                        HCI_LE_Rand_Command(), check_result=True
                    )

                    # Ensure the address bytes can be a static random address
                    address_bytes = response.return_parameters.random_number[
                        :5
                    ] + bytes([response.return_parameters.random_number[5] | 0xC0])

                    # Create a static random address from the random bytes
                    self.random_address = Address(address_bytes)

            if self.random_address != Address.ANY_RANDOM:
                logger.debug(
                    color(
                        f'LE Random Address: {self.random_address}',
                        'yellow',
                    )
                )
                await self.send_command(
                    HCI_LE_Set_Random_Address_Command(
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
                    HCI_LE_Set_Address_Resolution_Enable_Command(
                        address_resolution_enable=1
                    )
                )

            if self.cis_enabled:
                await self.send_command(
                    HCI_LE_Set_Host_Feature_Command(
                        bit_number=LeFeature.CONNECTED_ISOCHRONOUS_STREAM,
                        bit_value=1,
                    )
                )

        if self.classic_enabled:
            await self.send_command(
                HCI_Write_Local_Name_Command(local_name=self.name.encode('utf8'))
            )
            await self.send_command(
                HCI_Write_Class_Of_Device_Command(class_of_device=self.class_of_device)
            )
            await self.send_command(
                HCI_Write_Simple_Pairing_Mode_Command(
                    simple_pairing_mode=int(self.classic_ssp_enabled)
                )
            )
            await self.send_command(
                HCI_Write_Secure_Connections_Host_Support_Command(
                    secure_connections_host_support=int(self.classic_sc_enabled)
                )
            )
            await self.set_connectable(self.connectable)
            await self.set_discoverable(self.discoverable)

        # Done
        self.powered_on = True

    async def reset(self) -> None:
        await self.host.reset()

    async def power_off(self) -> None:
        if self.powered_on:
            await self.host.flush()
            self.powered_on = False

    async def refresh_resolving_list(self) -> None:
        assert self.keystore is not None

        resolving_keys = await self.keystore.get_resolving_keys()
        # Create a host-side address resolver
        self.address_resolver = smp.AddressResolver(resolving_keys)

        if self.address_resolution_offload:
            await self.send_command(HCI_LE_Clear_Resolving_List_Command())

            # Add an empty entry for non-directed address generation.
            await self.send_command(
                HCI_LE_Add_Device_To_Resolving_List_Command(
                    peer_identity_address_type=Address.ANY.address_type,
                    peer_identity_address=Address.ANY,
                    peer_irk=bytes(16),
                    local_irk=self.irk,
                )
            )

            for irk, address in resolving_keys:
                await self.send_command(
                    HCI_LE_Add_Device_To_Resolving_List_Command(
                        peer_identity_address_type=address.address_type,
                        peer_identity_address=address,
                        peer_irk=irk,
                        local_irk=self.irk,
                    )
                )

    def supports_le_features(self, feature: LeFeatureMask) -> bool:
        return self.host.supports_le_features(feature)

    def supports_le_phy(self, phy):
        if phy == HCI_LE_1M_PHY:
            return True

        feature_map = {
            HCI_LE_2M_PHY: LeFeatureMask.LE_2M_PHY,
            HCI_LE_CODED_PHY: LeFeatureMask.LE_CODED_PHY,
        }
        if phy not in feature_map:
            raise ValueError('invalid PHY')

        return self.supports_le_features(feature_map[phy])

    @property
    def supports_le_extended_advertising(self):
        return self.supports_le_features(LeFeatureMask.LE_EXTENDED_ADVERTISING)

    async def start_advertising(
        self,
        advertising_type: AdvertisingType = AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE,
        target: Optional[Address] = None,
        own_address_type: int = OwnAddressType.RANDOM,
        auto_restart: bool = False,
        advertising_data: Optional[bytes] = None,
        scan_response_data: Optional[bytes] = None,
        advertising_interval_min: Optional[int] = None,
        advertising_interval_max: Optional[int] = None,
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
                raise ValueError('directed advertising requires a target')
            peer_address = target
        else:
            peer_address = Address.ANY

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
                    own_address_type=OwnAddressType(own_address_type),
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
                own_address_type=OwnAddressType(own_address_type),
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
        advertising_parameters: Optional[AdvertisingParameters] = None,
        random_address: Optional[Address] = None,
        advertising_data: bytes = b'',
        scan_response_data: bytes = b'',
        periodic_advertising_parameters: Optional[PeriodicAdvertisingParameters] = None,
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

        if (
            not advertising_parameters.advertising_event_properties.is_legacy
            and advertising_data
            and scan_response_data
        ):
            raise ValueError(
                "Extended advertisements can't have both data and scan \
                              response data"
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
            raise RuntimeError("all valid advertising handles already in use") from exc

        # Use the device's random address if a random address is needed but none was
        # provided.
        if (
            advertising_parameters.own_address_type
            in (OwnAddressType.RANDOM, OwnAddressType.RESOLVABLE_OR_RANDOM)
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
                # TODO: call LE Set Periodic Advertising Parameters command
                raise NotImplementedError('periodic advertising not yet supported')

            if periodic_advertising_data:
                # TODO: call LE Set Periodic Advertising Data command
                raise NotImplementedError('periodic advertising not yet supported')

        except HCI_Error as error:
            # Remove the advertising set so that it doesn't stay dangling in the
            # controller.
            await self.send_command(
                HCI_LE_Remove_Advertising_Set_Command(
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
            except Exception as error:
                logger.exception(f'failed to start advertising set: {error}')
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
        scan_interval: int = DEVICE_DEFAULT_SCAN_INTERVAL,  # Scan interval in ms
        scan_window: int = DEVICE_DEFAULT_SCAN_WINDOW,  # Scan window in ms
        own_address_type: int = OwnAddressType.RANDOM,
        filter_duplicates: bool = False,
        scanning_phys: List[int] = [HCI_LE_1M_PHY, HCI_LE_CODED_PHY],
    ) -> None:
        # Check that the arguments are legal
        if scan_interval < scan_window:
            raise ValueError('scan_interval must be >= scan_window')
        if (
            scan_interval < DEVICE_MIN_SCAN_INTERVAL
            or scan_interval > DEVICE_MAX_SCAN_INTERVAL
        ):
            raise ValueError('scan_interval out of range')
        if scan_window < DEVICE_MIN_SCAN_WINDOW or scan_window > DEVICE_MAX_SCAN_WINDOW:
            raise ValueError('scan_interval out of range')

        # Reset the accumulators
        self.advertisement_accumulators = {}

        # Enable scanning
        if not legacy and self.supports_le_extended_advertising:
            # Set the scanning parameters
            scan_type = (
                HCI_LE_Set_Extended_Scan_Parameters_Command.ACTIVE_SCANNING
                if active
                else HCI_LE_Set_Extended_Scan_Parameters_Command.PASSIVE_SCANNING
            )
            scanning_filter_policy = (
                HCI_LE_Set_Extended_Scan_Parameters_Command.BASIC_UNFILTERED_POLICY
            )  # TODO: support other types

            scanning_phy_count = 0
            scanning_phys_bits = 0
            if HCI_LE_1M_PHY in scanning_phys:
                scanning_phys_bits |= 1 << HCI_LE_1M_PHY_BIT
                scanning_phy_count += 1
            if HCI_LE_CODED_PHY in scanning_phys:
                if self.supports_le_features(LeFeatureMask.LE_CODED_PHY):
                    scanning_phys_bits |= 1 << HCI_LE_CODED_PHY_BIT
                    scanning_phy_count += 1

            if scanning_phy_count == 0:
                raise ValueError('at least one scanning PHY must be enabled')

            await self.send_command(
                HCI_LE_Set_Extended_Scan_Parameters_Command(
                    own_address_type=own_address_type,
                    scanning_filter_policy=scanning_filter_policy,
                    scanning_phys=scanning_phys_bits,
                    scan_types=[scan_type] * scanning_phy_count,
                    scan_intervals=[int(scan_window / 0.625)] * scanning_phy_count,
                    scan_windows=[int(scan_window / 0.625)] * scanning_phy_count,
                ),
                check_result=True,
            )

            # Enable scanning
            await self.send_command(
                HCI_LE_Set_Extended_Scan_Enable_Command(
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
                HCI_LE_Set_Scan_Parameters_Command.ACTIVE_SCANNING
                if active
                else HCI_LE_Set_Scan_Parameters_Command.PASSIVE_SCANNING
            )
            await self.send_command(
                # pylint: disable=line-too-long
                HCI_LE_Set_Scan_Parameters_Command(
                    le_scan_type=scan_type,
                    le_scan_interval=int(scan_window / 0.625),
                    le_scan_window=int(scan_window / 0.625),
                    own_address_type=own_address_type,
                    scanning_filter_policy=HCI_LE_Set_Scan_Parameters_Command.BASIC_UNFILTERED_POLICY,
                ),
                check_result=True,
            )

            # Enable scanning
            await self.send_command(
                HCI_LE_Set_Scan_Enable_Command(
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
                HCI_LE_Set_Extended_Scan_Enable_Command(
                    enable=0, filter_duplicates=0, duration=0, period=0
                ),
                check_result=True,
            )
        else:
            await self.send_command(
                HCI_LE_Set_Scan_Enable_Command(le_scan_enable=0, filter_duplicates=0),
                check_result=True,
            )

        self.scanning = False

    @property
    def is_scanning(self):
        return self.scanning

    @host_event_handler
    def on_advertising_report(self, report):
        if not (accumulator := self.advertisement_accumulators.get(report.address)):
            accumulator = AdvertisementDataAccumulator(passive=self.scanning_is_passive)
            self.advertisement_accumulators[report.address] = accumulator
        if advertisement := accumulator.update(report):
            self.emit('advertisement', advertisement)

    async def start_discovery(self, auto_restart: bool = True) -> None:
        await self.send_command(
            HCI_Write_Inquiry_Mode_Command(inquiry_mode=HCI_EXTENDED_INQUIRY_MODE),
            check_result=True,
        )

        response = await self.send_command(
            HCI_Inquiry_Command(
                lap=HCI_GENERAL_INQUIRY_LAP,
                inquiry_length=DEVICE_DEFAULT_INQUIRY_LENGTH,
                num_responses=0,  # Unlimited number of responses.
            )
        )
        if response.status != HCI_Command_Status_Event.PENDING:
            self.discovering = False
            raise HCI_StatusError(response)

        self.auto_restart_inquiry = auto_restart
        self.discovering = True

    async def stop_discovery(self) -> None:
        if self.discovering:
            await self.send_command(HCI_Inquiry_Cancel_Command(), check_result=True)
        self.auto_restart_inquiry = True
        self.discovering = False

    @host_event_handler
    def on_inquiry_result(self, address, class_of_device, data, rssi):
        self.emit(
            'inquiry_result',
            address,
            class_of_device,
            AdvertisingData.from_bytes(data),
            rssi,
        )

    async def set_scan_enable(self, inquiry_scan_enabled, page_scan_enabled):
        if inquiry_scan_enabled and page_scan_enabled:
            scan_enable = 0x03
        elif page_scan_enabled:
            scan_enable = 0x02
        elif inquiry_scan_enabled:
            scan_enable = 0x01
        else:
            scan_enable = 0x00

        return await self.send_command(
            HCI_Write_Scan_Enable_Command(scan_enable=scan_enable)
        )

    async def set_discoverable(self, discoverable: bool = True) -> None:
        self.discoverable = discoverable
        if self.classic_enabled:
            # Synthesize an inquiry response if none is set already
            if self.inquiry_response is None:
                self.inquiry_response = bytes(
                    AdvertisingData(
                        [
                            (
                                AdvertisingData.COMPLETE_LOCAL_NAME,
                                bytes(self.name, 'utf-8'),
                            )
                        ]
                    )
                )

            # Update the controller
            await self.send_command(
                HCI_Write_Extended_Inquiry_Response_Command(
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
        peer_address: Union[Address, str],
        transport: int = BT_LE_TRANSPORT,
        connection_parameters_preferences: Optional[
            Dict[int, ConnectionParametersPreferences]
        ] = None,
        own_address_type: int = OwnAddressType.RANDOM,
        timeout: Optional[float] = DEVICE_DEFAULT_CONNECT_TIMEOUT,
    ) -> Connection:
        '''
        Request a connection to a peer.
        When transport is BLE, this method cannot be called if there is already a
        pending connection.

        connection_parameters_preferences: (BLE only, ignored for BR/EDR)
          * None: use the 1M PHY with default parameters
          * map: each entry has a PHY as key and a ConnectionParametersPreferences
            object as value

        own_address_type: (BLE only)
        '''

        # Check parameters
        if transport not in (BT_LE_TRANSPORT, BT_BR_EDR_TRANSPORT):
            raise ValueError('invalid transport')

        # Adjust the transport automatically if we need to
        if transport == BT_LE_TRANSPORT and not self.le_enabled:
            transport = BT_BR_EDR_TRANSPORT
        elif transport == BT_BR_EDR_TRANSPORT and not self.classic_enabled:
            transport = BT_LE_TRANSPORT

        # Check that there isn't already a pending connection
        if transport == BT_LE_TRANSPORT and self.is_le_connecting:
            raise InvalidStateError('connection already pending')

        if isinstance(peer_address, str):
            try:
                peer_address = Address.from_string_for_transport(
                    peer_address, transport
                )
            except ValueError:
                # If the address is not parsable, assume it is a name instead
                logger.debug('looking for peer by name')
                peer_address = await self.find_peer_by_name(
                    peer_address, transport
                )  # TODO: timeout
        else:
            # All BR/EDR addresses should be public addresses
            if (
                transport == BT_BR_EDR_TRANSPORT
                and peer_address.address_type != Address.PUBLIC_DEVICE_ADDRESS
            ):
                raise ValueError('BR/EDR addresses must be PUBLIC')

        assert isinstance(peer_address, Address)

        def on_connection(connection):
            if transport == BT_LE_TRANSPORT or (
                # match BR/EDR connection event against peer address
                connection.transport == transport
                and connection.peer_address == peer_address
            ):
                pending_connection.set_result(connection)

        def on_connection_failure(error):
            if transport == BT_LE_TRANSPORT or (
                # match BR/EDR connection failure event against peer address
                error.transport == transport
                and error.peer_address == peer_address
            ):
                pending_connection.set_exception(error)

        # Create a future so that we can wait for the connection's result
        pending_connection = asyncio.get_running_loop().create_future()
        self.on('connection', on_connection)
        self.on('connection_failure', on_connection_failure)

        try:
            # Tell the controller to connect
            if transport == BT_LE_TRANSPORT:
                if connection_parameters_preferences is None:
                    if connection_parameters_preferences is None:
                        connection_parameters_preferences = {
                            HCI_LE_1M_PHY: ConnectionParametersPreferences.default
                        }

                self.connect_own_address_type = own_address_type

                if self.host.supports_command(
                    HCI_LE_EXTENDED_CREATE_CONNECTION_COMMAND
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
                        raise ValueError('at least one supported PHY needed')

                    phy_count = len(phys)
                    initiating_phys = phy_list_to_bits(phys)

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

                    result = await self.send_command(
                        HCI_LE_Extended_Create_Connection_Command(
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
                        )
                    )
                else:
                    if HCI_LE_1M_PHY not in connection_parameters_preferences:
                        raise ValueError('1M PHY preferences required')

                    prefs = connection_parameters_preferences[HCI_LE_1M_PHY]
                    result = await self.send_command(
                        HCI_LE_Create_Connection_Command(
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
                        )
                    )
            else:
                # Save pending connection
                self.pending_connections[peer_address] = Connection.incomplete(
                    self, peer_address, BT_CENTRAL_ROLE
                )

                # TODO: allow passing other settings
                result = await self.send_command(
                    HCI_Create_Connection_Command(
                        bd_addr=peer_address,
                        packet_type=0xCC18,  # FIXME: change
                        page_scan_repetition_mode=HCI_R2_PAGE_SCAN_REPETITION_MODE,
                        clock_offset=0x0000,
                        allow_role_switch=0x01,
                        reserved=0,
                    )
                )

            if result.status != HCI_Command_Status_Event.PENDING:
                raise HCI_StatusError(result)

            # Wait for the connection process to complete
            if transport == BT_LE_TRANSPORT:
                self.le_connecting = True

            if timeout is None:
                return await self.abort_on('flush', pending_connection)

            try:
                return await asyncio.wait_for(
                    asyncio.shield(pending_connection), timeout
                )
            except asyncio.TimeoutError:
                if transport == BT_LE_TRANSPORT:
                    await self.send_command(HCI_LE_Create_Connection_Cancel_Command())
                else:
                    await self.send_command(
                        HCI_Create_Connection_Cancel_Command(bd_addr=peer_address)
                    )

                try:
                    return await self.abort_on('flush', pending_connection)
                except core.ConnectionError as error:
                    raise core.TimeoutError() from error
        finally:
            self.remove_listener('connection', on_connection)
            self.remove_listener('connection_failure', on_connection_failure)
            if transport == BT_LE_TRANSPORT:
                self.le_connecting = False
                self.connect_own_address_type = None
            else:
                self.pending_connections.pop(peer_address, None)

    async def accept(
        self,
        peer_address: Union[Address, str] = Address.ANY,
        role: int = BT_PERIPHERAL_ROLE,
        timeout: Optional[float] = DEVICE_DEFAULT_CONNECT_TIMEOUT,
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
                peer_address = Address(peer_address)
            except ValueError:
                # If the address is not parsable, assume it is a name instead
                logger.debug('looking for peer by name')
                peer_address = await self.find_peer_by_name(
                    peer_address, BT_BR_EDR_TRANSPORT
                )  # TODO: timeout

        assert isinstance(peer_address, Address)

        if peer_address == Address.NIL:
            raise ValueError('accept on nil address')

        # Create a future so that we can wait for the request
        pending_request_fut = asyncio.get_running_loop().create_future()

        if peer_address == Address.ANY:
            self.classic_pending_accepts[Address.ANY].append(pending_request_fut)
        elif peer_address in self.classic_pending_accepts:
            raise InvalidStateError('accept connection already pending')
        else:
            self.classic_pending_accepts[peer_address] = [pending_request_fut]

        try:
            # Wait for a request or a completed connection
            pending_request = self.abort_on('flush', pending_request_fut)
            result = await (
                asyncio.wait_for(pending_request, timeout)
                if timeout
                else pending_request
            )
        except Exception:
            # Remove future from device context
            if peer_address == Address.ANY:
                self.classic_pending_accepts[Address.ANY].remove(pending_request_fut)
            else:
                self.classic_pending_accepts.pop(peer_address)
            raise

        # Result may already be a completed connection,
        # see `on_connection` for details
        if isinstance(result, Connection):
            return result

        # Otherwise, result came from `on_connection_request`
        peer_address, _class_of_device, _link_type = result
        assert isinstance(peer_address, Address)

        # Create a future so that we can wait for the connection's result
        pending_connection = asyncio.get_running_loop().create_future()

        def on_connection(connection):
            if (
                connection.transport == BT_BR_EDR_TRANSPORT
                and connection.peer_address == peer_address
            ):
                pending_connection.set_result(connection)

        def on_connection_failure(error):
            if (
                error.transport == BT_BR_EDR_TRANSPORT
                and error.peer_address == peer_address
            ):
                pending_connection.set_exception(error)

        self.on('connection', on_connection)
        self.on('connection_failure', on_connection_failure)

        # Save pending connection, with the Peripheral role.
        # Even if we requested a role switch in the HCI_Accept_Connection_Request
        # command, this connection is still considered Peripheral until an eventual
        # role change event.
        self.pending_connections[peer_address] = Connection.incomplete(
            self, peer_address, BT_PERIPHERAL_ROLE
        )

        try:
            # Accept connection request
            await self.send_command(
                HCI_Accept_Connection_Request_Command(bd_addr=peer_address, role=role)
            )

            # Wait for connection complete
            return await self.abort_on('flush', pending_connection)

        finally:
            self.remove_listener('connection', on_connection)
            self.remove_listener('connection_failure', on_connection_failure)
            self.pending_connections.pop(peer_address, None)

    @asynccontextmanager
    async def connect_as_gatt(self, peer_address):
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
                HCI_LE_Create_Connection_Cancel_Command(), check_result=True
            )

        # BR/EDR: try to cancel to ongoing connection
        # NOTE: This API does not prevent from trying to cancel a connection which is
        # not currently being created
        else:
            if isinstance(peer_address, str):
                try:
                    peer_address = Address(peer_address)
                except ValueError:
                    # If the address is not parsable, assume it is a name instead
                    logger.debug('looking for peer by name')
                    peer_address = await self.find_peer_by_name(
                        peer_address, BT_BR_EDR_TRANSPORT
                    )  # TODO: timeout

            await self.send_command(
                HCI_Create_Connection_Cancel_Command(bd_addr=peer_address),
                check_result=True,
            )

    async def disconnect(
        self, connection: Union[Connection, ScoLink, CisLink], reason: int
    ) -> None:
        # Create a future so that we can wait for the disconnection's result
        pending_disconnection = asyncio.get_running_loop().create_future()
        connection.on('disconnection', pending_disconnection.set_result)
        connection.on('disconnection_failure', pending_disconnection.set_exception)

        # Request a disconnection
        result = await self.send_command(
            HCI_Disconnect_Command(connection_handle=connection.handle, reason=reason)
        )

        try:
            if result.status != HCI_Command_Status_Event.PENDING:
                raise HCI_StatusError(result)

            # Wait for the disconnection process to complete
            self.disconnecting = True
            return await self.abort_on('flush', pending_disconnection)
        finally:
            connection.remove_listener(
                'disconnection', pending_disconnection.set_result
            )
            connection.remove_listener(
                'disconnection_failure', pending_disconnection.set_exception
            )
            self.disconnecting = False

    async def set_data_length(self, connection, tx_octets, tx_time) -> None:
        if tx_octets < 0x001B or tx_octets > 0x00FB:
            raise ValueError('tx_octets must be between 0x001B and 0x00FB')

        if tx_time < 0x0148 or tx_time > 0x4290:
            raise ValueError('tx_time must be between 0x0148 and 0x4290')

        return await self.send_command(
            HCI_LE_Set_Data_Length_Command(
                connection_handle=connection.handle,
                tx_octets=tx_octets,
                tx_time=tx_time,
            ),
            check_result=True,
        )

    async def update_connection_parameters(
        self,
        connection,
        connection_interval_min,
        connection_interval_max,
        max_latency,
        supervision_timeout,
        min_ce_length=0,
        max_ce_length=0,
        use_l2cap=False,
    ) -> None:
        '''
        NOTE: the name of the parameters may look odd, but it just follows the names
        used in the Bluetooth spec.
        '''

        if use_l2cap:
            if connection.role != BT_PERIPHERAL_ROLE:
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

        result = await self.send_command(
            HCI_LE_Connection_Update_Command(
                connection_handle=connection.handle,
                connection_interval_min=connection_interval_min,
                connection_interval_max=connection_interval_max,
                max_latency=max_latency,
                supervision_timeout=supervision_timeout,
                min_ce_length=min_ce_length,
                max_ce_length=max_ce_length,
            )
        )
        if result.status != HCI_Command_Status_Event.PENDING:
            raise HCI_StatusError(result)

    async def get_connection_rssi(self, connection):
        result = await self.send_command(
            HCI_Read_RSSI_Command(handle=connection.handle), check_result=True
        )
        return result.return_parameters.rssi

    async def get_connection_phy(self, connection):
        result = await self.send_command(
            HCI_LE_Read_PHY_Command(connection_handle=connection.handle),
            check_result=True,
        )
        return (result.return_parameters.tx_phy, result.return_parameters.rx_phy)

    async def set_connection_phy(
        self, connection, tx_phys=None, rx_phys=None, phy_options=None
    ):
        if not self.host.supports_command(HCI_LE_SET_PHY_COMMAND):
            logger.warning('ignoring request, command not supported')
            return

        all_phys_bits = (1 if tx_phys is None else 0) | (
            (1 if rx_phys is None else 0) << 1
        )

        result = await self.send_command(
            HCI_LE_Set_PHY_Command(
                connection_handle=connection.handle,
                all_phys=all_phys_bits,
                tx_phys=phy_list_to_bits(tx_phys),
                rx_phys=phy_list_to_bits(rx_phys),
                phy_options=0 if phy_options is None else int(phy_options),
            )
        )

        if result.status != HCI_COMMAND_STATUS_PENDING:
            logger.warning(
                'HCI_LE_Set_PHY_Command failed: '
                f'{HCI_Constant.error_name(result.status)}'
            )
            raise HCI_StatusError(result)

    async def set_default_phy(self, tx_phys=None, rx_phys=None):
        all_phys_bits = (1 if tx_phys is None else 0) | (
            (1 if rx_phys is None else 0) << 1
        )

        return await self.send_command(
            HCI_LE_Set_Default_PHY_Command(
                all_phys=all_phys_bits,
                tx_phys=phy_list_to_bits(tx_phys),
                rx_phys=phy_list_to_bits(rx_phys),
            ),
            check_result=True,
        )

    async def find_peer_by_name(self, name, transport=BT_LE_TRANSPORT):
        """
        Scan for a peer with a give name and return its address and transport
        """

        # Create a future to wait for an address to be found
        peer_address = asyncio.get_running_loop().create_future()

        # Scan/inquire with event handlers to handle scan/inquiry results
        def on_peer_found(address, ad_data):
            local_name = ad_data.get(AdvertisingData.COMPLETE_LOCAL_NAME, raw=True)
            if local_name is None:
                local_name = ad_data.get(AdvertisingData.SHORTENED_LOCAL_NAME, raw=True)
            if local_name is not None:
                if local_name.decode('utf-8') == name:
                    peer_address.set_result(address)

        handler = None
        was_scanning = self.scanning
        was_discovering = self.discovering
        try:
            if transport == BT_LE_TRANSPORT:
                event_name = 'advertisement'
                handler = self.on(
                    event_name,
                    lambda advertisement: on_peer_found(
                        advertisement.address, advertisement.data
                    ),
                )

                if not self.scanning:
                    await self.start_scanning(filter_duplicates=True)

            elif transport == BT_BR_EDR_TRANSPORT:
                event_name = 'inquiry_result'
                handler = self.on(
                    event_name,
                    lambda address, class_of_device, eir_data, rssi: on_peer_found(
                        address, eir_data
                    ),
                )

                if not self.discovering:
                    await self.start_discovery()
            else:
                return None

            return await self.abort_on('flush', peer_address)
        finally:
            if handler is not None:
                self.remove_listener(event_name, handler)

            if transport == BT_LE_TRANSPORT and not was_scanning:
                await self.stop_scanning()
            elif transport == BT_BR_EDR_TRANSPORT and not was_discovering:
                await self.stop_discovery()

    @property
    def pairing_config_factory(self) -> Callable[[Connection], PairingConfig]:
        return self.smp_manager.pairing_config_factory

    @pairing_config_factory.setter
    def pairing_config_factory(
        self, pairing_config_factory: Callable[[Connection], PairingConfig]
    ) -> None:
        self.smp_manager.pairing_config_factory = pairing_config_factory

    @property
    def smp_session_proxy(self) -> Type[smp.Session]:
        return self.smp_manager.session_proxy

    @smp_session_proxy.setter
    def smp_session_proxy(self, session_proxy: Type[smp.Session]) -> None:
        self.smp_manager.session_proxy = session_proxy

    async def pair(self, connection):
        return await self.smp_manager.pair(connection)

    def request_pairing(self, connection):
        return self.smp_manager.request_pairing(connection)

    async def get_long_term_key(
        self, connection_handle: int, rand: bytes, ediv: int
    ) -> Optional[bytes]:
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

                if connection.role == BT_CENTRAL_ROLE and keys.ltk_central:
                    return keys.ltk_central.value

                if connection.role == BT_PERIPHERAL_ROLE and keys.ltk_peripheral:
                    return keys.ltk_peripheral.value
        return None

    async def get_link_key(self, address: Address) -> Optional[bytes]:
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
    async def authenticate(self, connection):
        # Set up event handlers
        pending_authentication = asyncio.get_running_loop().create_future()

        def on_authentication():
            pending_authentication.set_result(None)

        def on_authentication_failure(error_code):
            pending_authentication.set_exception(HCI_Error(error_code))

        connection.on('connection_authentication', on_authentication)
        connection.on('connection_authentication_failure', on_authentication_failure)

        # Request the authentication
        try:
            result = await self.send_command(
                HCI_Authentication_Requested_Command(
                    connection_handle=connection.handle
                )
            )
            if result.status != HCI_COMMAND_STATUS_PENDING:
                logger.warning(
                    'HCI_Authentication_Requested_Command failed: '
                    f'{HCI_Constant.error_name(result.status)}'
                )
                raise HCI_StatusError(result)

            # Wait for the authentication to complete
            await connection.abort_on('disconnection', pending_authentication)
        finally:
            connection.remove_listener('connection_authentication', on_authentication)
            connection.remove_listener(
                'connection_authentication_failure', on_authentication_failure
            )

    async def encrypt(self, connection, enable=True):
        if not enable and connection.transport == BT_LE_TRANSPORT:
            raise ValueError('`enable` parameter is classic only.')

        # Set up event handlers
        pending_encryption = asyncio.get_running_loop().create_future()

        def on_encryption_change():
            pending_encryption.set_result(None)

        def on_encryption_failure(error_code):
            pending_encryption.set_exception(HCI_Error(error_code))

        connection.on('connection_encryption_change', on_encryption_change)
        connection.on('connection_encryption_failure', on_encryption_failure)

        # Request the encryption
        try:
            if connection.transport == BT_LE_TRANSPORT:
                # Look for a key in the key store
                if self.keystore is None:
                    raise RuntimeError('no key store')

                keys = await self.keystore.get(str(connection.peer_address))
                if keys is None:
                    raise RuntimeError('keys not found in key store')

                if keys.ltk is not None:
                    ltk = keys.ltk.value
                    rand = bytes(8)
                    ediv = 0
                elif keys.ltk_central is not None:
                    ltk = keys.ltk_central.value
                    rand = keys.ltk_central.rand
                    ediv = keys.ltk_central.ediv
                else:
                    raise RuntimeError('no LTK found for peer')

                if connection.role != HCI_CENTRAL_ROLE:
                    raise InvalidStateError('only centrals can start encryption')

                result = await self.send_command(
                    HCI_LE_Enable_Encryption_Command(
                        connection_handle=connection.handle,
                        random_number=rand,
                        encrypted_diversifier=ediv,
                        long_term_key=ltk,
                    )
                )

                if result.status != HCI_COMMAND_STATUS_PENDING:
                    logger.warning(
                        'HCI_LE_Enable_Encryption_Command failed: '
                        f'{HCI_Constant.error_name(result.status)}'
                    )
                    raise HCI_StatusError(result)
            else:
                result = await self.send_command(
                    HCI_Set_Connection_Encryption_Command(
                        connection_handle=connection.handle,
                        encryption_enable=0x01 if enable else 0x00,
                    )
                )

                if result.status != HCI_COMMAND_STATUS_PENDING:
                    logger.warning(
                        'HCI_Set_Connection_Encryption_Command failed: '
                        f'{HCI_Constant.error_name(result.status)}'
                    )
                    raise HCI_StatusError(result)

            # Wait for the result
            await connection.abort_on('disconnection', pending_encryption)
        finally:
            connection.remove_listener(
                'connection_encryption_change', on_encryption_change
            )
            connection.remove_listener(
                'connection_encryption_failure', on_encryption_failure
            )

    async def update_keys(self, address: str, keys: PairingKeys) -> None:
        if self.keystore is None:
            return

        try:
            await self.keystore.update(address, keys)
            await self.refresh_resolving_list()
        except Exception as error:
            logger.warning(f'!!! error while storing keys: {error}')
        else:
            self.emit('key_store_update')

    # [Classic only]
    async def switch_role(self, connection: Connection, role: int):
        pending_role_change = asyncio.get_running_loop().create_future()

        def on_role_change(new_role):
            pending_role_change.set_result(new_role)

        def on_role_change_failure(error_code):
            pending_role_change.set_exception(HCI_Error(error_code))

        connection.on('role_change', on_role_change)
        connection.on('role_change_failure', on_role_change_failure)

        try:
            result = await self.send_command(
                HCI_Switch_Role_Command(bd_addr=connection.peer_address, role=role)
            )
            if result.status != HCI_COMMAND_STATUS_PENDING:
                logger.warning(
                    'HCI_Switch_Role_Command failed: '
                    f'{HCI_Constant.error_name(result.status)}'
                )
                raise HCI_StatusError(result)
            await connection.abort_on('disconnection', pending_role_change)
        finally:
            connection.remove_listener('role_change', on_role_change)
            connection.remove_listener('role_change_failure', on_role_change_failure)

    # [Classic only]
    async def request_remote_name(self, remote: Union[Address, Connection]) -> str:
        # Set up event handlers
        pending_name = asyncio.get_running_loop().create_future()

        peer_address = remote if isinstance(remote, Address) else remote.peer_address

        handler = self.on(
            'remote_name',
            lambda address, remote_name: (
                pending_name.set_result(remote_name)
                if address == peer_address
                else None
            ),
        )
        failure_handler = self.on(
            'remote_name_failure',
            lambda address, error_code: (
                pending_name.set_exception(HCI_Error(error_code))
                if address == peer_address
                else None
            ),
        )

        try:
            result = await self.send_command(
                HCI_Remote_Name_Request_Command(
                    bd_addr=peer_address,
                    page_scan_repetition_mode=HCI_Remote_Name_Request_Command.R2,
                    reserved=0,
                    clock_offset=0,  # TODO investigate non-0 values
                )
            )

            if result.status != HCI_COMMAND_STATUS_PENDING:
                logger.warning(
                    'HCI_Remote_Name_Request_Command failed: '
                    f'{HCI_Constant.error_name(result.status)}'
                )
                raise HCI_StatusError(result)

            # Wait for the result
            return await self.abort_on('flush', pending_name)
        finally:
            self.remove_listener('remote_name', handler)
            self.remove_listener('remote_name_failure', failure_handler)

    # [LE only]
    @experimental('Only for testing.')
    async def setup_cig(
        self,
        cig_id: int,
        cis_id: List[int],
        sdu_interval: Tuple[int, int],
        framing: int,
        max_sdu: Tuple[int, int],
        retransmission_number: int,
        max_transport_latency: Tuple[int, int],
    ) -> List[int]:
        """Sends HCI_LE_Set_CIG_Parameters_Command.

        Args:
            cig_id: CIG_ID.
            cis_id: CID ID list.
            sdu_interval: SDU intervals of (Central->Peripheral, Peripheral->Cental).
            framing: Un-framing(0) or Framing(1).
            max_sdu: Max SDU counts of (Central->Peripheral, Peripheral->Cental).
            retransmission_number: retransmission_number.
            max_transport_latency: Max transport latencies of
                                   (Central->Peripheral, Peripheral->Cental).

        Returns:
            List of created CIS handles corresponding to the same order of [cid_id].
        """
        num_cis = len(cis_id)

        response = await self.send_command(
            HCI_LE_Set_CIG_Parameters_Command(
                cig_id=cig_id,
                sdu_interval_c_to_p=sdu_interval[0],
                sdu_interval_p_to_c=sdu_interval[1],
                worst_case_sca=0x00,  # 251-500 ppm
                packing=0x00,  # Sequential
                framing=framing,
                max_transport_latency_c_to_p=max_transport_latency[0],
                max_transport_latency_p_to_c=max_transport_latency[1],
                cis_id=cis_id,
                max_sdu_c_to_p=[max_sdu[0]] * num_cis,
                max_sdu_p_to_c=[max_sdu[1]] * num_cis,
                phy_c_to_p=[HCI_LE_2M_PHY] * num_cis,
                phy_p_to_c=[HCI_LE_2M_PHY] * num_cis,
                rtn_c_to_p=[retransmission_number] * num_cis,
                rtn_p_to_c=[retransmission_number] * num_cis,
            ),
            check_result=True,
        )

        # Ideally, we should manage CIG lifecycle, but they are not useful for Unicast
        # Server, so here it only provides a basic functionality for testing.
        cis_handles = response.return_parameters.connection_handle[:]
        for id, cis_handle in zip(cis_id, cis_handles):
            self._pending_cis[cis_handle] = (id, cig_id)

        return cis_handles

    # [LE only]
    @experimental('Only for testing.')
    async def create_cis(self, cis_acl_pairs: List[Tuple[int, int]]) -> List[CisLink]:
        for cis_handle, acl_handle in cis_acl_pairs:
            acl_connection = self.lookup_connection(acl_handle)
            assert acl_connection
            cis_id, cig_id = self._pending_cis.pop(cis_handle)
            self.cis_links[cis_handle] = CisLink(
                device=self,
                acl_connection=acl_connection,
                handle=cis_handle,
                cis_id=cis_id,
                cig_id=cig_id,
            )

        with closing(EventWatcher()) as watcher:
            pending_cis_establishments = {
                cis_handle: asyncio.get_running_loop().create_future()
                for cis_handle, _ in cis_acl_pairs
            }

            def on_cis_establishment(cis_link: CisLink) -> None:
                if pending_future := pending_cis_establishments.get(cis_link.handle):
                    pending_future.set_result(cis_link)

            def on_cis_establishment_failure(cis_handle: int, status: int) -> None:
                if pending_future := pending_cis_establishments.get(cis_handle):
                    pending_future.set_exception(HCI_Error(status))

            watcher.on(self, 'cis_establishment', on_cis_establishment)
            watcher.on(self, 'cis_establishment_failure', on_cis_establishment_failure)
            await self.send_command(
                HCI_LE_Create_CIS_Command(
                    cis_connection_handle=[p[0] for p in cis_acl_pairs],
                    acl_connection_handle=[p[1] for p in cis_acl_pairs],
                ),
                check_result=True,
            )

            return await asyncio.gather(*pending_cis_establishments.values())

    # [LE only]
    @experimental('Only for testing.')
    async def accept_cis_request(self, handle: int) -> CisLink:
        """[LE Only] Accepts an incoming CIS request.

        When the specified CIS handle is already created, this method returns the
        existed CIS link object immediately.

        Args:
            handle: CIS handle to accept.

        Returns:
            CIS link object on the given handle.
        """
        if not (cis_link := self.cis_links.get(handle)):
            raise InvalidStateError(f'No pending CIS request of handle {handle}')

        # There might be multiple ASE sharing a CIS channel.
        # If one of them has accepted the request, the others should just leverage it.
        async with self._cis_lock:
            if cis_link.state == CisLink.State.ESTABLISHED:
                return cis_link

            with closing(EventWatcher()) as watcher:
                pending_establishment = asyncio.get_running_loop().create_future()

                def on_establishment() -> None:
                    pending_establishment.set_result(None)

                def on_establishment_failure(status: int) -> None:
                    pending_establishment.set_exception(HCI_Error(status))

                watcher.on(cis_link, 'establishment', on_establishment)
                watcher.on(cis_link, 'establishment_failure', on_establishment_failure)

                await self.send_command(
                    HCI_LE_Accept_CIS_Request_Command(connection_handle=handle),
                    check_result=True,
                )

                await pending_establishment
                return cis_link

        # Mypy believes this is reachable when context is an ExitStack.
        raise InvalidStateError('Unreachable')

    # [LE only]
    @experimental('Only for testing.')
    async def reject_cis_request(
        self,
        handle: int,
        reason: int = HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
    ) -> None:
        await self.send_command(
            HCI_LE_Reject_CIS_Request_Command(connection_handle=handle, reason=reason),
            check_result=True,
        )

    async def get_remote_le_features(self, connection: Connection) -> LeFeatureMask:
        """[LE Only] Reads remote LE supported features.

        Args:
            handle: connection handle to read LE features.

        Returns:
            LE features supported by the remote device.
        """
        with closing(EventWatcher()) as watcher:
            read_feature_future: asyncio.Future[LeFeatureMask] = (
                asyncio.get_running_loop().create_future()
            )

            def on_le_remote_features(handle: int, features: int):
                if handle == connection.handle:
                    read_feature_future.set_result(LeFeatureMask(features))

            def on_failure(handle: int, status: int):
                if handle == connection.handle:
                    read_feature_future.set_exception(HCI_Error(status))

            watcher.on(self.host, 'le_remote_features', on_le_remote_features)
            watcher.on(self.host, 'le_remote_features_failure', on_failure)
            await self.send_command(
                HCI_LE_Read_Remote_Features_Command(
                    connection_handle=connection.handle
                ),
                check_result=True,
            )
            return await read_feature_future

    @host_event_handler
    def on_flush(self):
        self.emit('flush')
        for _, connection in self.connections.items():
            connection.emit('disconnection', 0)
        self.connections = {}

    # [Classic only]
    @host_event_handler
    def on_link_key(self, bd_addr, link_key, key_type):
        # Store the keys in the key store
        if self.keystore:
            authenticated = key_type in (
                HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_192_TYPE,
                HCI_AUTHENTICATED_COMBINATION_KEY_GENERATED_FROM_P_256_TYPE,
            )
            pairing_keys = PairingKeys()
            pairing_keys.link_key = PairingKeys.Key(
                value=link_key, authenticated=authenticated
            )

            self.abort_on('flush', self.update_keys(str(bd_addr), pairing_keys))

        if connection := self.find_connection_by_bd_addr(
            bd_addr, transport=BT_BR_EDR_TRANSPORT
        ):
            connection.link_key_type = key_type

    def add_service(self, service):
        self.gatt_server.add_service(service)

    def add_services(self, services):
        self.gatt_server.add_services(services)

    def add_default_services(self, generic_access_service=True):
        # Add a GAP Service if requested
        if generic_access_service:
            self.gatt_server.add_service(GenericAccessService(self.name))

    async def notify_subscriber(self, connection, attribute, value=None, force=False):
        await self.gatt_server.notify_subscriber(connection, attribute, value, force)

    async def notify_subscribers(self, attribute, value=None, force=False):
        await self.gatt_server.notify_subscribers(attribute, value, force)

    async def indicate_subscriber(self, connection, attribute, value=None, force=False):
        await self.gatt_server.indicate_subscriber(connection, attribute, value, force)

    async def indicate_subscribers(self, attribute, value=None, force=False):
        await self.gatt_server.indicate_subscribers(attribute, value, force)

    @host_event_handler
    def on_advertising_set_termination(
        self,
        status,
        advertising_handle,
        connection_handle,
        number_of_completed_extended_advertising_events,
    ):
        # Legacy advertising set is also one of extended advertising sets.
        if not (
            advertising_set := self.extended_advertising_sets.get(advertising_handle)
        ):
            logger.warning(f'advertising set {advertising_handle} not found')
            return

        advertising_set.on_termination(status)

        if status != HCI_SUCCESS:
            logger.debug(
                f'advertising set {advertising_handle} '
                f'terminated with status {status}'
            )
            return

        if not (connection := self.lookup_connection(connection_handle)):
            logger.warning(f'no connection for handle 0x{connection_handle:04x}')
            return

        # Update the connection address.
        connection.self_address = (
            advertising_set.random_address
            if advertising_set.advertising_parameters.own_address_type
            in (OwnAddressType.RANDOM, OwnAddressType.RESOLVABLE_OR_RANDOM)
            else self.public_address
        )

        # Setup auto-restart of the advertising set if needed.
        if advertising_set.auto_restart:
            connection.once(
                'disconnection',
                lambda _: self.abort_on('flush', advertising_set.start()),
            )

        self._emit_le_connection(connection)

    def _emit_le_connection(self, connection: Connection) -> None:
        # If supported, read which PHY we're connected with before
        # notifying listeners of the new connection.
        if self.host.supports_command(HCI_LE_READ_PHY_COMMAND):

            async def read_phy():
                result = await self.send_command(
                    HCI_LE_Read_PHY_Command(connection_handle=connection.handle),
                    check_result=True,
                )
                connection.phy = ConnectionPHY(
                    result.return_parameters.tx_phy, result.return_parameters.rx_phy
                )
                # Emit an event to notify listeners of the new connection
                self.emit('connection', connection)

            # Do so asynchronously to not block the current event handler
            connection.abort_on('disconnection', read_phy())

            return

        self.emit('connection', connection)

    @host_event_handler
    def on_connection(
        self,
        connection_handle,
        transport,
        peer_address,
        role,
        connection_parameters,
    ):
        logger.debug(
            f'*** Connection: [0x{connection_handle:04X}] '
            f'{peer_address} {"" if role is None else HCI_Constant.role_name(role)}'
        )
        if connection_handle in self.connections:
            logger.warning(
                'new connection reuses the same handle as a previous connection'
            )

        if transport == BT_BR_EDR_TRANSPORT:
            # Create a new connection
            connection = self.pending_connections.pop(peer_address)
            connection.complete(connection_handle, connection_parameters)
            self.connections[connection_handle] = connection

            # Emit an event to notify listeners of the new connection
            self.emit('connection', connection)

            return

        # Resolve the peer address if we can
        peer_resolvable_address = None
        if self.address_resolver:
            if peer_address.is_resolvable:
                resolved_address = self.address_resolver.resolve(peer_address)
                if resolved_address is not None:
                    logger.debug(f'*** Address resolved as {resolved_address}')
                    peer_resolvable_address = peer_address
                    peer_address = resolved_address

        self_address = None
        if role == HCI_CENTRAL_ROLE:
            own_address_type = self.connect_own_address_type
            assert own_address_type is not None
        else:
            if self.supports_le_extended_advertising:
                # We'll know the address when the advertising set terminates,
                # Use a temporary placeholder value for self_address.
                self_address = Address.ANY_RANDOM
            else:
                # We were connected via a legacy advertisement.
                if self.legacy_advertiser:
                    own_address_type = self.legacy_advertiser.own_address_type
                    self.legacy_advertiser = None
                else:
                    # This should not happen, but just in case, pick a default.
                    logger.warning("connection without an advertiser")
                    self_address = self.random_address

        if self_address is None:
            self_address = (
                self.public_address
                if own_address_type
                in (
                    OwnAddressType.PUBLIC,
                    OwnAddressType.RESOLVABLE_OR_PUBLIC,
                )
                else self.random_address
            )

        # Create a connection.
        connection = Connection(
            self,
            connection_handle,
            transport,
            self_address,
            peer_address,
            peer_resolvable_address,
            role,
            connection_parameters,
            ConnectionPHY(HCI_LE_1M_PHY, HCI_LE_1M_PHY),
        )
        self.connections[connection_handle] = connection

        if (
            role == HCI_PERIPHERAL_ROLE
            and self.legacy_advertiser
            and self.legacy_advertiser.auto_restart
        ):
            connection.once(
                'disconnection',
                lambda _: self.abort_on('flush', self.legacy_advertiser.start()),
            )

        if role == HCI_CENTRAL_ROLE or not self.supports_le_extended_advertising:
            # We can emit now, we have all the info we need
            self._emit_le_connection(connection)

    @host_event_handler
    def on_connection_failure(self, transport, peer_address, error_code):
        logger.debug(f'*** Connection failed: {HCI_Constant.error_name(error_code)}')

        # For directed advertising, this means a timeout
        if (
            transport == BT_LE_TRANSPORT
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
            HCI_Constant.error_name(error_code),
        )
        self.emit('connection_failure', error)

    # FIXME: Explore a delegate-model for BR/EDR wait connection #56.
    @host_event_handler
    def on_connection_request(self, bd_addr, class_of_device, link_type):
        logger.debug(f'*** Connection request: {bd_addr}')

        # Handle SCO request.
        if link_type in (
            HCI_Connection_Complete_Event.SCO_LINK_TYPE,
            HCI_Connection_Complete_Event.ESCO_LINK_TYPE,
        ):
            if connection := self.find_connection_by_bd_addr(
                bd_addr, transport=BT_BR_EDR_TRANSPORT
            ):
                self.emit('sco_request', connection, link_type)
            else:
                logger.error(f'SCO request from a non-connected device {bd_addr}')
            return

        # match a pending future using `bd_addr`
        elif bd_addr in self.classic_pending_accepts:
            future, *_ = self.classic_pending_accepts.pop(bd_addr)
            future.set_result((bd_addr, class_of_device, link_type))

        # match first pending future for ANY address
        elif len(self.classic_pending_accepts[Address.ANY]) > 0:
            future = self.classic_pending_accepts[Address.ANY].pop(0)
            future.set_result((bd_addr, class_of_device, link_type))

        # device configuration is set to accept any incoming connection
        elif self.classic_accept_any:
            # Save pending connection
            self.pending_connections[bd_addr] = Connection.incomplete(
                self, bd_addr, BT_PERIPHERAL_ROLE
            )

            self.host.send_command_sync(
                HCI_Accept_Connection_Request_Command(
                    bd_addr=bd_addr, role=0x01  # Remain the peripheral
                )
            )

        # reject incoming connection
        else:
            self.host.send_command_sync(
                HCI_Reject_Connection_Request_Command(
                    bd_addr=bd_addr,
                    reason=HCI_CONNECTION_REJECTED_DUE_TO_LIMITED_RESOURCES_ERROR,
                )
            )

    @host_event_handler
    def on_disconnection(self, connection_handle: int, reason: int) -> None:
        if connection := self.connections.pop(connection_handle, None):
            logger.debug(
                f'*** Disconnection: [0x{connection.handle:04X}] '
                f'{connection.peer_address} as {connection.role_name}, reason={reason}'
            )
            connection.emit('disconnection', reason)

            # Cleanup subsystems that maintain per-connection state
            self.gatt_server.on_disconnection(connection)
        elif sco_link := self.sco_links.pop(connection_handle, None):
            sco_link.emit('disconnection', reason)
        elif cis_link := self.cis_links.pop(connection_handle, None):
            cis_link.emit('disconnection', reason)
        else:
            logger.error(
                f'*** Unknown disconnection handle=0x{connection_handle}, reason={reason} ***'
            )

    @host_event_handler
    @with_connection_from_handle
    def on_disconnection_failure(self, connection, error_code):
        logger.debug(f'*** Disconnection failed: {error_code}')
        error = core.ConnectionError(
            error_code,
            connection.transport,
            connection.peer_address,
            'hci',
            HCI_Constant.error_name(error_code),
        )
        connection.emit('disconnection_failure', error)

    @host_event_handler
    @AsyncRunner.run_in_task()
    async def on_inquiry_complete(self):
        if self.auto_restart_inquiry:
            # Inquire again
            await self.start_discovery(auto_restart=True)
        else:
            self.auto_restart_inquiry = True
            self.discovering = False
            self.emit('inquiry_complete')

    @host_event_handler
    @with_connection_from_handle
    def on_connection_authentication(self, connection):
        logger.debug(
            f'*** Connection Authentication: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}'
        )
        connection.authenticated = True
        connection.emit('connection_authentication')

    @host_event_handler
    @with_connection_from_handle
    def on_connection_authentication_failure(self, connection, error):
        logger.debug(
            f'*** Connection Authentication Failure: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, error={error}'
        )
        connection.emit('connection_authentication_failure', error)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_io_capability_request(self, connection):
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)

        # Compute the authentication requirements
        authentication_requirements = (
            # No Bonding
            (
                HCI_MITM_NOT_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS,
                HCI_MITM_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS,
            ),
            # General Bonding
            (
                HCI_MITM_NOT_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS,
                HCI_MITM_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS,
            ),
        )[1 if pairing_config.bonding else 0][1 if pairing_config.mitm else 0]

        # Respond
        self.host.send_command_sync(
            HCI_IO_Capability_Request_Reply_Command(
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
        self, connection, io_capability, authentication_requirements
    ):
        connection.peer_pairing_io_capability = io_capability
        connection.peer_pairing_authentication_requirements = (
            authentication_requirements
        )

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_user_confirmation_request(self, connection, code) -> None:
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)
        io_capability = pairing_config.delegate.classic_io_capability
        peer_io_capability = connection.peer_pairing_io_capability

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
            assert False, "N/A: unreachable"

        # See Bluetooth spec @ Vol 3, Part C 5.2.2.6
        methods = {
            HCI_DISPLAY_ONLY_IO_CAPABILITY: {
                HCI_DISPLAY_ONLY_IO_CAPABILITY: display_auto_confirm,
                HCI_DISPLAY_YES_NO_IO_CAPABILITY: display_confirm,
                HCI_KEYBOARD_ONLY_IO_CAPABILITY: na,
                HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: auto_confirm,
            },
            HCI_DISPLAY_YES_NO_IO_CAPABILITY: {
                HCI_DISPLAY_ONLY_IO_CAPABILITY: display_auto_confirm,
                HCI_DISPLAY_YES_NO_IO_CAPABILITY: display_confirm,
                HCI_KEYBOARD_ONLY_IO_CAPABILITY: na,
                HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: auto_confirm,
            },
            HCI_KEYBOARD_ONLY_IO_CAPABILITY: {
                HCI_DISPLAY_ONLY_IO_CAPABILITY: na,
                HCI_DISPLAY_YES_NO_IO_CAPABILITY: na,
                HCI_KEYBOARD_ONLY_IO_CAPABILITY: na,
                HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: auto_confirm,
            },
            HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: {
                HCI_DISPLAY_ONLY_IO_CAPABILITY: confirm,
                HCI_DISPLAY_YES_NO_IO_CAPABILITY: confirm,
                HCI_KEYBOARD_ONLY_IO_CAPABILITY: auto_confirm,
                HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY: auto_confirm,
            },
        }

        method = methods[peer_io_capability][io_capability]

        async def reply() -> None:
            try:
                if await connection.abort_on('disconnection', method()):
                    await self.host.send_command(
                        HCI_User_Confirmation_Request_Reply_Command(
                            bd_addr=connection.peer_address
                        )
                    )
                    return
            except Exception as error:
                logger.warning(f'exception while confirming: {error}')

            await self.host.send_command(
                HCI_User_Confirmation_Request_Negative_Reply_Command(
                    bd_addr=connection.peer_address
                )
            )

        AsyncRunner.spawn(reply())

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_user_passkey_request(self, connection) -> None:
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)

        async def reply() -> None:
            try:
                number = await connection.abort_on(
                    'disconnection', pairing_config.delegate.get_number()
                )
                if number is not None:
                    await self.host.send_command(
                        HCI_User_Passkey_Request_Reply_Command(
                            bd_addr=connection.peer_address, numeric_value=number
                        )
                    )
                    return
            except Exception as error:
                logger.warning(f'exception while asking for pass-key: {error}')

            await self.host.send_command(
                HCI_User_Passkey_Request_Negative_Reply_Command(
                    bd_addr=connection.peer_address
                )
            )

        AsyncRunner.spawn(reply())

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_pin_code_request(self, connection):
        # Classic legacy pairing
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)
        io_capability = pairing_config.delegate.classic_io_capability

        # Respond
        if io_capability == HCI_KEYBOARD_ONLY_IO_CAPABILITY:
            # Ask the user to enter a string
            async def get_pin_code():
                pin_code = await connection.abort_on(
                    'disconnection', pairing_config.delegate.get_string(16)
                )

                if pin_code is not None:
                    pin_code = bytes(pin_code, encoding='utf-8')
                    pin_code_len = len(pin_code)
                    assert 0 < pin_code_len <= 16, "pin_code should be 1-16 bytes"
                    await self.host.send_command(
                        HCI_PIN_Code_Request_Reply_Command(
                            bd_addr=connection.peer_address,
                            pin_code_length=pin_code_len,
                            pin_code=pin_code,
                        )
                    )
                else:
                    logger.debug("delegate.get_string() returned None")
                    await self.host.send_command(
                        HCI_PIN_Code_Request_Negative_Reply_Command(
                            bd_addr=connection.peer_address
                        )
                    )

            asyncio.create_task(get_pin_code())
        else:
            self.host.send_command_sync(
                HCI_PIN_Code_Request_Negative_Reply_Command(
                    bd_addr=connection.peer_address
                )
            )

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_authentication_user_passkey_notification(self, connection, passkey):
        # Ask what the pairing config should be for this connection
        pairing_config = self.pairing_config_factory(connection)

        # Show the passkey to the user
        connection.abort_on(
            'disconnection', pairing_config.delegate.display_number(passkey)
        )

    # [Classic only]
    @host_event_handler
    @try_with_connection_from_address
    def on_remote_name(self, connection: Connection, address, remote_name):
        # Try to decode the name
        try:
            remote_name = remote_name.decode('utf-8')
            if connection:
                connection.peer_name = remote_name
                connection.emit('remote_name')
            self.emit('remote_name', address, remote_name)
        except UnicodeDecodeError as error:
            logger.warning('peer name is not valid UTF-8')
            if connection:
                connection.emit('remote_name_failure', error)
            else:
                self.emit('remote_name_failure', address, error)

    # [Classic only]
    @host_event_handler
    @try_with_connection_from_address
    def on_remote_name_failure(self, connection: Connection, address, error):
        if connection:
            connection.emit('remote_name_failure', error)
        self.emit('remote_name_failure', address, error)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    @experimental('Only for testing.')
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
        self.emit('sco_connection', sco_link)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    @experimental('Only for testing.')
    def on_sco_connection_failure(
        self, acl_connection: Connection, status: int
    ) -> None:
        logger.debug(f'*** SCO connection failure: {acl_connection.peer_address}***')
        self.emit('sco_connection_failure')

    # [Classic only]
    @host_event_handler
    @experimental('Only for testing')
    def on_sco_packet(self, sco_handle: int, packet: HCI_SynchronousDataPacket) -> None:
        if (sco_link := self.sco_links.get(sco_handle)) and sco_link.sink:
            sco_link.sink(packet)

    # [LE only]
    @host_event_handler
    @with_connection_from_handle
    @experimental('Only for testing')
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
        self.cis_links[cis_handle] = CisLink(
            device=self,
            acl_connection=acl_connection,
            handle=cis_handle,
            cig_id=cig_id,
            cis_id=cis_id,
        )
        self.emit('cis_request', acl_connection, cis_handle, cig_id, cis_id)

    # [LE only]
    @host_event_handler
    @experimental('Only for testing')
    def on_cis_establishment(self, cis_handle: int) -> None:
        cis_link = self.cis_links[cis_handle]
        cis_link.state = CisLink.State.ESTABLISHED

        assert cis_link.acl_connection

        logger.debug(
            f'*** CIS Establishment '
            f'{cis_link.acl_connection.peer_address}, '
            f'cis_handle=[0x{cis_handle:04X}], '
            f'cig_id=[0x{cis_link.cig_id:02X}], '
            f'cis_id=[0x{cis_link.cis_id:02X}] ***'
        )

        cis_link.emit('establishment')
        self.emit('cis_establishment', cis_link)

    # [LE only]
    @host_event_handler
    @experimental('Only for testing')
    def on_cis_establishment_failure(self, cis_handle: int, status: int) -> None:
        logger.debug(f'*** CIS Establishment Failure: cis=[0x{cis_handle:04X}] ***')
        if cis_link := self.cis_links.pop(cis_handle):
            cis_link.emit('establishment_failure', status)
        self.emit('cis_establishment_failure', cis_handle, status)

    # [LE only]
    @host_event_handler
    @experimental('Only for testing')
    def on_iso_packet(self, handle: int, packet: HCI_IsoDataPacket) -> None:
        if (cis_link := self.cis_links.get(handle)) and cis_link.sink:
            cis_link.sink(packet)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_encryption_change(self, connection, encryption):
        logger.debug(
            f'*** Connection Encryption Change: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'encryption={encryption}'
        )
        connection.encryption = encryption
        if (
            not connection.authenticated
            and connection.transport == BT_BR_EDR_TRANSPORT
            and encryption == HCI_Encryption_Change_Event.AES_CCM
        ):
            connection.authenticated = True
            connection.sc = True
        if (
            not connection.authenticated
            and connection.transport == BT_LE_TRANSPORT
            and encryption == HCI_Encryption_Change_Event.E0_OR_AES_CCM
        ):
            connection.authenticated = True
            connection.sc = True
        connection.emit('connection_encryption_change')

    @host_event_handler
    @with_connection_from_handle
    def on_connection_encryption_failure(self, connection, error):
        logger.debug(
            f'*** Connection Encryption Failure: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'error={error}'
        )
        connection.emit('connection_encryption_failure', error)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_encryption_key_refresh(self, connection):
        logger.debug(
            f'*** Connection Key Refresh: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}'
        )
        connection.emit('connection_encryption_key_refresh')

    @host_event_handler
    @with_connection_from_handle
    def on_connection_parameters_update(self, connection, connection_parameters):
        logger.debug(
            f'*** Connection Parameters Update: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'{connection_parameters}'
        )
        connection.parameters = connection_parameters
        connection.emit('connection_parameters_update')

    @host_event_handler
    @with_connection_from_handle
    def on_connection_parameters_update_failure(self, connection, error):
        logger.debug(
            f'*** Connection Parameters Update Failed: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'error={error}'
        )
        connection.emit('connection_parameters_update_failure', error)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_phy_update(self, connection, connection_phy):
        logger.debug(
            f'*** Connection PHY Update: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'{connection_phy}'
        )
        connection.phy = connection_phy
        connection.emit('connection_phy_update')

    @host_event_handler
    @with_connection_from_handle
    def on_connection_phy_update_failure(self, connection, error):
        logger.debug(
            f'*** Connection PHY Update Failed: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'error={error}'
        )
        connection.emit('connection_phy_update_failure', error)

    @host_event_handler
    @with_connection_from_handle
    def on_connection_att_mtu_update(self, connection, att_mtu):
        logger.debug(
            f'*** Connection ATT MTU Update: [0x{connection.handle:04X}] '
            f'{connection.peer_address} as {connection.role_name}, '
            f'{att_mtu}'
        )
        connection.att_mtu = att_mtu
        connection.emit('connection_att_mtu_update')

    @host_event_handler
    @with_connection_from_handle
    def on_connection_data_length_change(
        self, connection, max_tx_octets, max_tx_time, max_rx_octets, max_rx_time
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
        connection.emit('connection_data_length_change')

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_role_change(self, connection, new_role):
        connection.role = new_role
        connection.emit('role_change', new_role)

    # [Classic only]
    @host_event_handler
    @try_with_connection_from_address
    def on_role_change_failure(self, connection, address, error):
        if connection:
            connection.emit('role_change_failure', error)
        self.emit('role_change_failure', address, error)

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_classic_pairing(self, connection: Connection) -> None:
        connection.emit('classic_pairing')

    # [Classic only]
    @host_event_handler
    @with_connection_from_address
    def on_classic_pairing_failure(self, connection: Connection, status) -> None:
        connection.emit('classic_pairing_failure', status)

    def on_pairing_start(self, connection: Connection) -> None:
        connection.emit('pairing_start')

    def on_pairing(
        self,
        connection: Connection,
        identity_address: Optional[Address],
        keys: PairingKeys,
        sc: bool,
    ) -> None:
        if identity_address is not None:
            connection.peer_resolvable_address = connection.peer_address
            connection.peer_address = identity_address
        connection.sc = sc
        connection.authenticated = True
        connection.emit('pairing', keys)

    def on_pairing_failure(self, connection: Connection, reason: int) -> None:
        connection.emit('pairing_failure', reason)

    @with_connection_from_handle
    def on_gatt_pdu(self, connection, pdu):
        # Parse the L2CAP payload into an ATT PDU object
        att_pdu = ATT_PDU.from_bytes(pdu)

        # Conveniently, even-numbered op codes are client->server and
        # odd-numbered ones are server->client
        if att_pdu.op_code & 1:
            if connection.gatt_client is None:
                logger.warning(
                    color('no GATT client for connection 0x{connection_handle:04X}')
                )
                return
            connection.gatt_client.on_gatt_pdu(att_pdu)
        else:
            if connection.gatt_server is None:
                logger.warning(
                    color('no GATT server for connection 0x{connection_handle:04X}')
                )
                return
            connection.gatt_server.on_gatt_pdu(connection, att_pdu)

    @with_connection_from_handle
    def on_smp_pdu(self, connection, pdu):
        self.smp_manager.on_smp_pdu(connection, pdu)

    @host_event_handler
    @with_connection_from_handle
    def on_l2cap_pdu(self, connection: Connection, cid: int, pdu: bytes):
        self.l2cap_channel_manager.on_pdu(connection, cid, pdu)

    def __str__(self):
        return (
            f'Device(name="{self.name}", '
            f'random_address="{self.random_address}", '
            f'public_address="{self.public_address}")'
        )
