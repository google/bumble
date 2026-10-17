# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Legacy, extended and periodic advertising HCI validation and data assembly."""

from dataclasses import replace

from bumble import hci
from bumble.hci import (
    HCI_LE_ADV_DATA_SIZE_MAX,
    HCI_LE_ADV_FILTER_CONNECT_MASK,
    HCI_LE_ADV_FILTER_POLICY_MASK,
    HCI_LE_ADV_FILTER_SCAN_MASK,
    HCI_LE_ADV_HANDLE_MAX,
    HCI_LE_ADV_INTERVAL_MAX,
    HCI_LE_ADV_INTERVAL_MIN,
    HCI_LE_ADV_INTERVAL_UNIT_US,
    HCI_LE_DURATION_UNIT_US,
    HCI_LE_EXT_ADV_INTERVAL_MAX,
)
from bumble.ll import (
    LL_ADV_DIRECT_HIGH_DUTY_TIMEOUT_US,
    LL_ADV_PRIMARY_CHANNEL_MAP_ALL,
    LL_MAFS_US,
    LL_PERIODIC_INTERVAL_MAX,
    LL_PERIODIC_INTERVAL_MIN,
    LL_PERIODIC_INTERVAL_UNIT_US,
    PDU_ADV_ADI_DID_MASK,
    PDU_ADV_ADI_SID_MAX,
    PDU_ADV_LEGACY_DATA_SIZE_MAX,
    AdvertisingMode,
    AdvertisingPduType,
)
from bumble.radio_controller.controller_le_context import (
    DISALLOWED,
    INVALID,
    SUCCESS,
    UNKNOWN_ADV,
    UNSUPPORTED,
    LeControllerContext,
)
from bumble.radio_controller.radio import (
    RADIO_ADVERTISING_SET_COUNT,
    RADIO_DIRECT_ADV_INTERVAL_US,
    RADIO_TX_POWER_MAX_DBM,
    RADIO_TX_POWER_MIN_DBM,
    Phy,
)
from bumble.radio_controller.radio_discovery import Advertising
from bumble.radio_controller.radio_extended import (
    advertising_time_us,
    auxiliary_pdu,
    periodic_time_us,
)

LegacyAdvertisingType = hci.HCI_LE_Set_Advertising_Parameters_Command.AdvertisingType

Properties = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.AdvertisingProperties
)

TX_POWER_NO_PREFERENCE = (
    hci.HCI_LE_Set_Extended_Advertising_Parameters_Command.TX_POWER_NO_PREFERENCE
)

DataOperation = hci.HCI_LE_Set_Extended_Advertising_Data_Command.Operation

SUPPORTED_ADVERTISING_PROPERTIES = int(
    Properties.CONNECTABLE_ADVERTISING
    | Properties.SCANNABLE_ADVERTISING
    | Properties.DIRECTED_ADVERTISING
    | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
    | Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.ANONYMOUS_ADVERTISING
    | Properties.INCLUDE_TX_POWER
)

# Periodic trains require extended, nonconnectable, nonscannable, nonanonymous sets.
PERIODIC_INCOMPATIBLE_ADVERTISING_PROPERTIES = (
    Properties.CONNECTABLE_ADVERTISING
    | Properties.SCANNABLE_ADVERTISING
    | Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.ANONYMOUS_ADVERTISING
)

LEGACY_PDU_TYPES: dict[int, AdvertisingPduType] = {
    LegacyAdvertisingType.ADV_IND: AdvertisingPduType.ADV_IND,
    LegacyAdvertisingType.ADV_DIRECT_IND: AdvertisingPduType.ADV_DIRECT_IND,
    LegacyAdvertisingType.ADV_SCAN_IND: AdvertisingPduType.ADV_SCAN_IND,
    LegacyAdvertisingType.ADV_NONCONN_IND: AdvertisingPduType.ADV_NONCONN_IND,
    LegacyAdvertisingType.ADV_DIRECT_IND_LOW_DUTY: AdvertisingPduType.ADV_DIRECT_IND,
}

LEGACY_ADVERTISING_PROPERTIES: dict[int, AdvertisingPduType] = {
    Properties.USE_LEGACY_ADVERTISING_PDUS: AdvertisingPduType.ADV_NONCONN_IND,
    Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.SCANNABLE_ADVERTISING: AdvertisingPduType.ADV_SCAN_IND,
    Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.CONNECTABLE_ADVERTISING
    | Properties.SCANNABLE_ADVERTISING: AdvertisingPduType.ADV_IND,
    Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.CONNECTABLE_ADVERTISING
    | Properties.DIRECTED_ADVERTISING: AdvertisingPduType.ADV_DIRECT_IND,
    Properties.USE_LEGACY_ADVERTISING_PDUS
    | Properties.CONNECTABLE_ADVERTISING
    | Properties.DIRECTED_ADVERTISING
    | Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING: (
        AdvertisingPduType.ADV_DIRECT_IND
    ),
}


class LeAdvertisingCommands(LeControllerContext):
    def _legacy(self) -> Advertising:
        advertiser = self.controller.le_legacy_advertiser
        item = self.link.advertisers.get(-1)
        if item is None:
            item = Advertising(
                self._address(advertiser.own_address_type),
                data=bytearray(advertiser.advertising_data),
                scan_response=bytearray(advertiser.scan_response_data),
            )
            self.link.advertisers[-1] = item
        item.address = self._address(advertiser.own_address_type)
        item.interval_us = (
            advertiser.advertising_interval_min * HCI_LE_ADV_INTERVAL_UNIT_US
        )
        item.channel_map = advertiser.advertising_channel_map
        item.pdu_type = LEGACY_PDU_TYPES[advertiser.advertising_type]
        item.target = (
            advertiser.peer_address
            if item.pdu_type == AdvertisingPduType.ADV_DIRECT_IND
            else None
        )
        item.high_duty = (
            advertiser.advertising_type == LegacyAdvertisingType.ADV_DIRECT_IND
        )
        if item.high_duty:
            item.interval_us = RADIO_DIRECT_ADV_INTERVAL_US
        item.filter_policy = advertiser.advertising_filter_policy
        return item

    def on_hci_le_set_advertising_parameters_command(self, command):
        if any(item.enabled for item in self.link.advertisers.values()):
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        if (
            command.advertising_type not in LEGACY_PDU_TYPES
            or command.own_address_type
            not in (hci.OwnAddressType.PUBLIC, hci.OwnAddressType.RANDOM)
        ):
            return hci.HCI_StatusReturnParameters(UNSUPPORTED)
        if (
            (
                command.advertising_type != LegacyAdvertisingType.ADV_DIRECT_IND
                and not HCI_LE_ADV_INTERVAL_MIN
                <= command.advertising_interval_min
                <= command.advertising_interval_max
                <= HCI_LE_ADV_INTERVAL_MAX
            )
            or not 1
            <= command.advertising_channel_map
            <= LL_ADV_PRIMARY_CHANNEL_MAP_ALL
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        if command.advertising_filter_policy not in (
            0,
            HCI_LE_ADV_FILTER_SCAN_MASK,
            HCI_LE_ADV_FILTER_CONNECT_MASK,
            HCI_LE_ADV_FILTER_POLICY_MASK,
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        if command.peer_address_type not in (
            hci.AddressType.PUBLIC_DEVICE,
            hci.AddressType.RANDOM_DEVICE,
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        return self.controller.on_hci_le_set_advertising_parameters_command(command)

    def on_hci_le_set_advertising_data_command(self, command):
        if len(command.advertising_data) > PDU_ADV_LEGACY_DATA_SIZE_MAX:
            return hci.HCI_StatusReturnParameters(INVALID)
        return self.controller.on_hci_le_set_advertising_data_command(command)

    def on_hci_le_set_scan_response_data_command(self, command):
        if len(command.scan_response_data) > PDU_ADV_LEGACY_DATA_SIZE_MAX:
            return hci.HCI_StatusReturnParameters(INVALID)
        return self.controller.on_hci_le_set_scan_response_data_command(command)

    def on_hci_le_set_advertising_enable_command(self, command):
        if command.advertising_enable not in (0, 1):
            return hci.HCI_StatusReturnParameters(INVALID)
        if command.advertising_enable and (
            any(key != -1 for key in self.link.advertisers)
        ):
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        item = self._legacy()
        item.enabled = bool(command.advertising_enable)
        item.next_us = self.now_us + 1
        item.events = 0
        item.deadline_us = (
            self.now_us + LL_ADV_DIRECT_HIGH_DUTY_TIMEOUT_US if item.high_duty else 0
        )
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def _extended_advertising_status(self, command):
        status = SUCCESS
        properties = command.advertising_event_properties
        item = self.link.advertisers.get(command.advertising_handle)
        if (
            item
            and item.periodic_enabled
            and properties & PERIODIC_INCOMPATIBLE_ADVERTISING_PROPERTIES
        ):
            status = INVALID
        elif item and (item.enabled or item.periodic_enabled):
            status = DISALLOWED
        elif item is None and len(self.link.advertisers) >= RADIO_ADVERTISING_SET_COUNT:
            status = hci.HCI_ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR
        elif (
            command.own_address_type
            not in (hci.OwnAddressType.PUBLIC, hci.OwnAddressType.RANDOM)
            or command.advertising_filter_policy
            not in (
                0,
                HCI_LE_ADV_FILTER_SCAN_MASK,
                HCI_LE_ADV_FILTER_CONNECT_MASK,
                HCI_LE_ADV_FILTER_POLICY_MASK,
            )
            or command.primary_advertising_phy not in (Phy.LE_1M, Phy.LE_CODED)
            or command.secondary_advertising_phy not in tuple(Phy)
        ):
            status = UNSUPPORTED
        elif (
            properties & ~SUPPORTED_ADVERTISING_PROPERTIES
            or (
                command.advertising_tx_power != TX_POWER_NO_PREFERENCE
                and not RADIO_TX_POWER_MIN_DBM
                <= command.advertising_tx_power
                <= RADIO_TX_POWER_MAX_DBM
            )
            or command.scan_request_notification_enable
            not in (
                0,
                1,
            )
            or properties & Properties.USE_LEGACY_ADVERTISING_PDUS
            and (
                properties not in LEGACY_ADVERTISING_PROPERTIES
                or command.primary_advertising_phy != Phy.LE_1M
            )
            or not properties & Properties.USE_LEGACY_ADVERTISING_PDUS
            and (
                properties
                & (
                    Properties.CONNECTABLE_ADVERTISING
                    | Properties.SCANNABLE_ADVERTISING
                )
                == (
                    Properties.CONNECTABLE_ADVERTISING
                    | Properties.SCANNABLE_ADVERTISING
                )
                or properties
                & Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
                or (
                    properties & Properties.ANONYMOUS_ADVERTISING
                    and properties
                    & (
                        Properties.CONNECTABLE_ADVERTISING
                        | Properties.SCANNABLE_ADVERTISING
                    )
                )
            )
            or (
                (
                    not properties
                    & Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
                    and not HCI_LE_ADV_INTERVAL_MIN
                    <= command.primary_advertising_interval_min
                    <= command.primary_advertising_interval_max
                    <= HCI_LE_EXT_ADV_INTERVAL_MAX
                )
                or not 1
                <= command.primary_advertising_channel_map
                <= LL_ADV_PRIMARY_CHANNEL_MAP_ALL
                or not 0 <= command.advertising_sid <= PDU_ADV_ADI_SID_MAX
                or not 0 <= command.advertising_handle <= HCI_LE_ADV_HANDLE_MAX
            )
        ):
            status = INVALID
        return status

    def _extended_advertiser(self, command):
        properties = command.advertising_event_properties
        item = self.link.advertisers.get(command.advertising_handle)
        item = (
            replace(item)
            if item
            else Advertising(self._address(command.own_address_type))
        )
        item.address = (
            (item.random_address or self.controller.random_address)
            if command.own_address_type == hci.OwnAddressType.RANDOM
            else self.controller.public_address
        )
        item.interval_us = (
            command.primary_advertising_interval_min * HCI_LE_ADV_INTERVAL_UNIT_US
        )
        item.interval_max_us = (
            command.primary_advertising_interval_max * HCI_LE_ADV_INTERVAL_UNIT_US
        )
        item.channel_map = command.primary_advertising_channel_map
        item.extended = not properties & Properties.USE_LEGACY_ADVERTISING_PDUS
        item.pdu_type = LEGACY_ADVERTISING_PROPERTIES.get(
            properties, AdvertisingPduType.ADV_NONCONN_IND
        )
        item.target = (
            command.peer_address
            if properties & Properties.DIRECTED_ADVERTISING
            else None
        )
        item.high_duty = bool(
            properties & Properties.HIGH_DUTY_CYCLE_DIRECTED_CONNECTABLE_ADVERTISING
        )
        if item.high_duty:
            item.interval_us = RADIO_DIRECT_ADV_INTERVAL_US
        item.mode = int(
            properties
            & (Properties.CONNECTABLE_ADVERTISING | Properties.SCANNABLE_ADVERTISING)
        )
        item.primary_phy = Phy(command.primary_advertising_phy)
        item.secondary_phy = Phy(command.secondary_advertising_phy)
        item.notify_scan_request = bool(command.scan_request_notification_enable)
        item.filter_policy = command.advertising_filter_policy
        item.anonymous = bool(properties & Properties.ANONYMOUS_ADVERTISING)
        item.tx_power_dbm = (
            0
            if command.advertising_tx_power == TX_POWER_NO_PREFERENCE
            else command.advertising_tx_power
        )
        item.include_tx_power = bool(properties & Properties.INCLUDE_TX_POWER)
        item.sid = command.advertising_sid
        return item

    @staticmethod
    def _advertising_data_status(item):
        if (
            (
                not item.extended
                and (
                    len(item.data) > PDU_ADV_LEGACY_DATA_SIZE_MAX
                    or len(item.scan_response) > PDU_ADV_LEGACY_DATA_SIZE_MAX
                )
            )
            or (item.target is not None and not item.extended and item.data)
            or (item.extended and item.mode == AdvertisingMode.SCANNABLE and item.data)
            or (
                item.extended
                and item.mode != AdvertisingMode.SCANNABLE
                and item.scan_response
            )
        ):
            return INVALID
        if (
            item.extended
            and item.mode == AdvertisingMode.CONNECTABLE
            and len(item.data) > auxiliary_pdu(item).data_capacity()
        ) or advertising_time_us(item) > item.interval_max_us:
            return hci.HCI_ErrorCode.PACKET_TOO_LONG_ERROR
        return SUCCESS

    def on_hci_le_set_extended_advertising_parameters_command(self, command):
        status = self._extended_advertising_status(command)
        if status != SUCCESS:
            return hci.HCI_LE_Set_Extended_Advertising_Parameters_ReturnParameters(
                status, 0
            )
        item = self._extended_advertiser(command)
        status = self._advertising_data_status(item)
        if status == SUCCESS:
            self.link.advertisers[command.advertising_handle] = item
            self.controller.on_hci_le_set_extended_advertising_parameters_command(
                command
            )
        return hci.HCI_LE_Set_Extended_Advertising_Parameters_ReturnParameters(
            status, item.tx_power_dbm if status == SUCCESS else 0
        )

    def on_hci_le_set_advertising_set_random_address_command(self, command):
        item = self.link.advertisers.get(command.advertising_handle)
        if item is None:
            return hci.HCI_StatusReturnParameters(UNKNOWN_ADV)
        if item.enabled:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        self.controller.on_hci_le_set_advertising_set_random_address_command(command)
        if item.address.is_random:
            item.address = command.random_address
        return hci.HCI_StatusReturnParameters(SUCCESS)

    @staticmethod
    def _store_data(item, field, value):
        setattr(item, field, bytearray(value))

    def _set_data(self, handle, operation, data, field):
        item = self.link.advertisers.get(handle)
        if item is None:
            return hci.HCI_StatusReturnParameters(UNKNOWN_ADV)
        key = (handle, field)
        maximum = (
            HCI_LE_ADV_DATA_SIZE_MAX if item.extended else PDU_ADV_LEGACY_DATA_SIZE_MAX
        )
        if item.extended and (
            (field == 'data' and item.mode == AdvertisingMode.SCANNABLE and data)
            or (
                field == 'scan_response'
                and item.mode != AdvertisingMode.SCANNABLE
                and data
            )
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        if item.target is not None and not item.extended and data:
            return hci.HCI_StatusReturnParameters(INVALID)
        if operation not in tuple(DataOperation):
            return hci.HCI_StatusReturnParameters(INVALID)
        if (
            field != 'periodic_data'
            and not item.extended
            and (
                operation != DataOperation.COMPLETE_DATA
                or len(data) > PDU_ADV_LEGACY_DATA_SIZE_MAX
            )
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        if (
            operation not in (DataOperation.COMPLETE_DATA, DataOperation.UNCHANGED_DATA)
            and not data
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        if (
            item.enabled or (field == 'periodic_data' and item.periodic_enabled)
        ) and operation not in (
            DataOperation.COMPLETE_DATA,
            DataOperation.UNCHANGED_DATA,
        ):
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        if field == 'periodic_data' and operation == DataOperation.UNCHANGED_DATA:
            return hci.HCI_StatusReturnParameters(INVALID)
        if operation == DataOperation.UNCHANGED_DATA:
            if data or not item.enabled or not getattr(item, field):
                return hci.HCI_StatusReturnParameters(INVALID)
            item.did = (item.did + 1) & PDU_ADV_ADI_DID_MASK
            return hci.HCI_StatusReturnParameters(SUCCESS)
        if (
            operation
            in (DataOperation.INTERMEDIATE_FRAGMENT, DataOperation.LAST_FRAGMENT)
            and key not in self.fragments
        ):
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        if operation in (DataOperation.FIRST_FRAGMENT, DataOperation.COMPLETE_DATA):
            self.fragments.pop(key, None)
            self._store_data(item, field, b'')
        value = (
            self.fragments.get(key, b'')
            if operation
            in (DataOperation.INTERMEDIATE_FRAGMENT, DataOperation.LAST_FRAGMENT)
            else b''
        ) + data
        if len(value) > maximum:
            self.fragments.pop(key, None)
            self._store_data(item, field, b'')
            return hci.HCI_StatusReturnParameters(
                hci.HCI_ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR
            )
        updated = replace(item, **{field: value})
        if (
            (
                item.extended
                and item.mode == AdvertisingMode.CONNECTABLE
                and field == 'data'
                and len(value) > auxiliary_pdu(item).data_capacity()
            )
            or (
                field == 'periodic_data'
                and item.periodic_interval
                and periodic_time_us(updated) + LL_MAFS_US
                >= item.periodic_interval * LL_PERIODIC_INTERVAL_UNIT_US
            )
            or advertising_time_us(updated)
            > (item.interval_us if item.enabled else item.interval_max_us)
        ):
            self.fragments.pop(key, None)
            self._store_data(item, field, b'')
            return hci.HCI_StatusReturnParameters(
                hci.HCI_ErrorCode.PACKET_TOO_LONG_ERROR
            )
        if operation in (DataOperation.LAST_FRAGMENT, DataOperation.COMPLETE_DATA):
            if item.periodic_enabled and (
                advertising_time_us(updated) + periodic_time_us(updated) + LL_MAFS_US
                >= item.periodic_interval * LL_PERIODIC_INTERVAL_UNIT_US
            ):
                self.fragments.pop(key, None)
                return hci.HCI_StatusReturnParameters(DISALLOWED)
            self._store_data(item, field, value)
            item.did = (item.did + 1) & PDU_ADV_ADI_DID_MASK
            self.fragments.pop(key, None)
        else:
            self.fragments[key] = value
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_set_extended_advertising_data_command(self, command):
        return self._set_data(
            command.advertising_handle,
            command.operation,
            command.advertising_data,
            'data',
        )

    def on_hci_le_set_extended_scan_response_data_command(self, command):
        return self._set_data(
            command.advertising_handle,
            command.operation,
            command.scan_response_data,
            'scan_response',
        )

    def on_hci_le_set_extended_advertising_enable_command(self, command):
        handles = command.advertising_handles
        if (
            command.enable not in (0, 1)
            or len(set(handles)) != len(handles)
            or (command.enable and not handles)
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        if any(handle not in self.link.advertisers for handle in handles):
            return hci.HCI_StatusReturnParameters(UNKNOWN_ADV)
        if command.enable:
            for handle in handles:
                item = self.link.advertisers[handle]
                if (
                    item.extended
                    and item.mode == AdvertisingMode.SCANNABLE
                    and not item.scan_response
                ):
                    return hci.HCI_StatusReturnParameters(DISALLOWED)
                duration = advertising_time_us(item)
                if duration > item.interval_max_us:
                    return hci.HCI_StatusReturnParameters(
                        hci.HCI_ErrorCode.PACKET_TOO_LONG_ERROR
                    )
        selected = handles or list(self.link.advertisers)
        for index, handle in enumerate(selected):
            item = self.link.advertisers[handle]
            if command.enable:
                duration_us = advertising_time_us(item)
                item.interval_us = max(
                    item.interval_us,
                    (duration_us + HCI_LE_ADV_INTERVAL_UNIT_US - 1)
                    // HCI_LE_ADV_INTERVAL_UNIT_US
                    * HCI_LE_ADV_INTERVAL_UNIT_US,
                )
            item.enabled = bool(command.enable)
            item.next_us = self.now_us + 1
            item.events = 0
            item.max_events = (
                command.max_extended_advertising_events[index] if handles else 0
            )
            duration = (
                command.durations[index] * HCI_LE_DURATION_UNIT_US if handles else 0
            )
            if item.high_duty:
                duration = min(
                    duration or LL_ADV_DIRECT_HIGH_DUTY_TIMEOUT_US,
                    LL_ADV_DIRECT_HIGH_DUTY_TIMEOUT_US,
                )
            item.deadline_us = self.now_us + duration if duration else 0
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_read_maximum_advertising_data_length_command(self, command):
        return hci.HCI_LE_Read_Maximum_Advertising_Data_Length_ReturnParameters(
            0, HCI_LE_ADV_DATA_SIZE_MAX
        )

    def on_hci_le_read_number_of_supported_advertising_sets_command(self, command):
        return hci.HCI_LE_Read_Number_Of_Supported_Advertising_Sets_ReturnParameters(
            SUCCESS, RADIO_ADVERTISING_SET_COUNT
        )

    def on_hci_le_remove_advertising_set_command(self, command):
        item = self.link.advertisers.get(command.advertising_handle)
        if item is None:
            return hci.HCI_StatusReturnParameters(UNKNOWN_ADV)
        if item.enabled or item.periodic_enabled:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        del self.link.advertisers[command.advertising_handle]
        self.controller.advertising_sets.pop(command.advertising_handle, None)
        self.fragments = {
            key: value
            for key, value in self.fragments.items()
            if key[0] != command.advertising_handle
        }
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_clear_advertising_sets_command(self, command):
        if any(
            item.enabled or item.periodic_enabled
            for item in self.link.advertisers.values()
        ):
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        self.link.advertisers.clear()
        self.controller.advertising_sets.clear()
        self.fragments.clear()
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_set_periodic_advertising_parameters_command(self, command):
        item = self.link.advertisers.get(command.advertising_handle)
        if item is None:
            return hci.HCI_StatusReturnParameters(UNKNOWN_ADV)
        if item.periodic_enabled:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        if not item.extended or item.mode or item.anonymous:
            return hci.HCI_StatusReturnParameters(INVALID)
        if command.periodic_advertising_properties:
            return hci.HCI_StatusReturnParameters(UNSUPPORTED)
        if (
            not LL_PERIODIC_INTERVAL_MIN
            <= command.periodic_advertising_interval_min
            <= command.periodic_advertising_interval_max
            <= LL_PERIODIC_INTERVAL_MAX
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        if (
            periodic_time_us(item) + LL_MAFS_US
            >= command.periodic_advertising_interval_max * LL_PERIODIC_INTERVAL_UNIT_US
        ):
            return hci.HCI_StatusReturnParameters(
                hci.HCI_ErrorCode.PACKET_TOO_LONG_ERROR
            )
        item.periodic_interval = command.periodic_advertising_interval_min
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_set_periodic_advertising_data_command(self, command):
        item = self.link.advertisers.get(command.advertising_handle)
        if item is None:
            return hci.HCI_StatusReturnParameters(UNKNOWN_ADV)
        if not item.periodic_interval:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        return self._set_data(
            command.advertising_handle,
            command.operation,
            command.advertising_data,
            'periodic_data',
        )

    def on_hci_le_set_periodic_advertising_enable_command(self, command):
        item = self.link.advertisers.get(command.advertising_handle)
        if item is None:
            return hci.HCI_StatusReturnParameters(UNKNOWN_ADV)
        if command.enable not in (0, 1):
            return hci.HCI_StatusReturnParameters(UNSUPPORTED)
        if (
            not item.extended
            or not item.periodic_interval
            or item.mode
            or item.anonymous
            or (
                command.enable
                and (command.advertising_handle, 'periodic_data') in self.fragments
            )
        ):
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        if (
            command.enable
            and periodic_time_us(item) + LL_MAFS_US
            >= item.periodic_interval * LL_PERIODIC_INTERVAL_UNIT_US
        ):
            return hci.HCI_StatusReturnParameters(
                hci.HCI_ErrorCode.PACKET_TOO_LONG_ERROR
            )
        if command.enable and (
            advertising_time_us(replace(item, periodic_enabled=True))
            + periodic_time_us(item)
            + LL_MAFS_US
            >= item.periodic_interval * LL_PERIODIC_INTERVAL_UNIT_US
        ):
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        self.link.set_periodic_enabled(item, bool(command.enable))
        return hci.HCI_StatusReturnParameters(SUCCESS)
