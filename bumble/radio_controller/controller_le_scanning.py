# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Scanning, filtering and periodic synchronization HCI commands."""

import asyncio

from bumble import hci
from bumble.hci import (
    HCI_LE_DURATION_UNIT_US,
    HCI_LE_EXT_SCAN_INTERVAL_MAX,
    HCI_LE_PERIODIC_SYNC_REPORTS_DISABLED_MASK,
    HCI_LE_PERIODIC_SYNC_SKIP_MAX,
    HCI_LE_PERIODIC_SYNC_TIMEOUT_MAX,
    HCI_LE_PERIODIC_SYNC_TIMEOUT_MIN,
    HCI_LE_SCAN_DUPLICATES_DISABLED,
    HCI_LE_SCAN_DUPLICATES_ENABLED,
    HCI_LE_SCAN_DUPLICATES_RESET_EACH_PERIOD,
    HCI_LE_SCAN_INTERVAL_MAX,
    HCI_LE_SCAN_INTERVAL_MIN,
    HCI_LE_SCAN_INTERVAL_UNIT_US,
    HCI_LE_SCAN_PERIOD_UNIT_US,
)
from bumble.ll import PDU_ADV_ADDRESS_SIZE, PDU_ADV_ADI_SID_MAX
from bumble.radio_controller.controller_le_context import (
    DISALLOWED,
    INVALID,
    SUCCESS,
    UNKNOWN_ADV,
    UNSUPPORTED,
    LeControllerContext,
)
from bumble.radio_controller.radio import (
    RADIO_PERIODIC_ADVERTISER_LIST_SIZE,
    RADIO_PERIODIC_SYNC_COUNT,
    RADIO_PRIMARY_SCAN_PHY_MASK,
    Phy,
)
from bumble.radio_controller.radio_discovery import (
    PeriodicSync,
    ScanBackoff,
    Scanning,
    ScanWindow,
)

SyncOptions = hci.HCI_LE_Periodic_Advertising_Create_Sync_Command.Options


class LeScanningCommands(LeControllerContext):
    def _scan_parameters(
        self,
        own,
        policy,
        scan_type,
        interval,
        window,
        maximum_interval=HCI_LE_SCAN_INTERVAL_MAX,
    ):
        if self.link.scan:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        if scan_type not in (0, 1):
            return hci.HCI_StatusReturnParameters(INVALID)
        if own not in (
            hci.OwnAddressType.PUBLIC,
            hci.OwnAddressType.RANDOM,
        ) or policy not in (0, 1):
            return hci.HCI_StatusReturnParameters(UNSUPPORTED)
        if not HCI_LE_SCAN_INTERVAL_MIN <= window <= interval <= maximum_interval:
            return hci.HCI_StatusReturnParameters(INVALID)
        self.scan_parameters = Scanning(
            self._address(own),
            interval * HCI_LE_SCAN_INTERVAL_UNIT_US,
            window * HCI_LE_SCAN_INTERVAL_UNIT_US,
            bool(scan_type),
        )
        self.scan_parameters.filter_policy = policy
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_set_scan_parameters_command(self, command):
        result = self._scan_parameters(
            command.own_address_type,
            command.scanning_filter_policy,
            command.le_scan_type,
            command.le_scan_interval,
            command.le_scan_window,
        )
        if result.status == SUCCESS:
            self.extended_scan = False
        return result

    def on_hci_le_set_extended_scan_parameters_command(self, command):
        if not command.scanning_phys:
            return hci.HCI_StatusReturnParameters(INVALID)
        if command.scanning_phys & ~RADIO_PRIMARY_SCAN_PHY_MASK:
            return hci.HCI_StatusReturnParameters(UNSUPPORTED)
        phys = [
            phy
            for phy, bit in (
                (Phy.LE_1M, hci.PhyBit.LE_1M),
                (Phy.LE_CODED, hci.PhyBit.LE_CODED),
            )
            if command.scanning_phys & bit
        ]
        if (
            not len(phys)
            == len(command.scan_types)
            == len(command.scan_intervals)
            == len(command.scan_windows)
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        if any(
            kind not in (0, 1)
            or not HCI_LE_SCAN_INTERVAL_MIN
            <= window
            <= interval
            <= HCI_LE_EXT_SCAN_INTERVAL_MAX
            for kind, interval, window in zip(
                command.scan_types, command.scan_intervals, command.scan_windows
            )
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        result = self._scan_parameters(
            command.own_address_type,
            command.scanning_filter_policy,
            command.scan_types[0],
            command.scan_intervals[0],
            command.scan_windows[0],
            maximum_interval=HCI_LE_EXT_SCAN_INTERVAL_MAX,
        )
        if result.status == SUCCESS:
            self.extended_scan = True
            self.scan_parameters.windows = tuple(
                ScanWindow(
                    phy,
                    interval * HCI_LE_SCAN_INTERVAL_UNIT_US,
                    window * HCI_LE_SCAN_INTERVAL_UNIT_US,
                    bool(kind),
                )
                for phy, kind, interval, window in zip(
                    phys,
                    command.scan_types,
                    command.scan_intervals,
                    command.scan_windows,
                )
            )
        return result

    def _scan_enable(self, enable, duplicates):
        if enable not in (0, 1) or duplicates not in (
            HCI_LE_SCAN_DUPLICATES_DISABLED,
            HCI_LE_SCAN_DUPLICATES_ENABLED,
            HCI_LE_SCAN_DUPLICATES_RESET_EACH_PERIOD,
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        self.filter_duplicates = bool(duplicates)
        self.seen.clear()
        self.scan_parameters.start_us = self.now_us
        self.scan_parameters.backoff = ScanBackoff()
        self.link.scan = self.scan_parameters if enable else None
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_set_scan_enable_command(self, command):
        if command.filter_duplicates not in (0, 1):
            return hci.HCI_StatusReturnParameters(INVALID)
        return self._scan_enable(command.le_scan_enable, command.filter_duplicates)

    def on_hci_le_set_extended_scan_enable_command(self, command):
        if (
            command.duration
            and command.period
            and command.duration * HCI_LE_DURATION_UNIT_US
            >= command.period * HCI_LE_SCAN_PERIOD_UNIT_US
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        result = self._scan_enable(command.enable, command.filter_duplicates)
        if result.status == SUCCESS:
            scan = self.scan_parameters
            scan.duration_us, scan.period_us = (
                command.duration * HCI_LE_DURATION_UNIT_US,
                command.period * HCI_LE_SCAN_PERIOD_UNIT_US,
            )
            scan.deadline_us = self.now_us + scan.duration_us if scan.duration_us else 0
            self.period_duplicate_reset = (
                command.filter_duplicates == HCI_LE_SCAN_DUPLICATES_RESET_EACH_PERIOD
            )
        return result

    def _filter_in_use(self):
        return (
            any(
                item.enabled and item.filter_policy
                for item in self.link.advertisers.values()
            )
            or bool(self.link.scan and self.link.scan.filter_policy)
            or bool(self.link.initiating and self.link.initiating.filter_policy)
        )

    def on_hci_le_read_filter_accept_list_size_command(self, command):
        return hci.HCI_LE_Read_Filter_Accept_List_Size_ReturnParameters(
            SUCCESS, self.controller.filter_accept_list_size
        )

    def on_hci_le_clear_filter_accept_list_command(self, command):
        if self._filter_in_use():
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        self.link.accept_list.clear()
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def _edit_filter(self, command, add):
        if self._filter_in_use():
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        if command.address_type not in (
            hci.AddressType.PUBLIC_DEVICE,
            hci.AddressType.RANDOM_DEVICE,
            hci.AddressType.ANONYMOUS,
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        address = hci.Address(
            (
                bytes(PDU_ADV_ADDRESS_SIZE)
                if command.address_type == hci.AddressType.ANONYMOUS
                else bytes(command.address)
            ),
            command.address_type,
        )
        if add:
            if (
                address not in self.link.accept_list
                and len(self.link.accept_list)
                >= self.controller.filter_accept_list_size
            ):
                return hci.HCI_StatusReturnParameters(
                    hci.HCI_ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR
                )
            self.link.accept_list.add(address)
        else:
            self.link.accept_list.discard(address)
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_add_device_to_filter_accept_list_command(self, command):
        return self._edit_filter(command, True)

    def on_hci_le_remove_device_from_filter_accept_list_command(self, command):
        return self._edit_filter(command, False)

    def on_hci_le_periodic_advertising_create_sync_command(self, command):
        if self.link.sync is not None:
            self.controller._send_hci_command_status(DISALLOWED, command.op_code)
            return
        use_list = bool(command.options & SyncOptions.USE_PERIODIC_ADVERTISER_LIST)
        if not use_list and any(
            active.address
            == hci.Address(
                bytes(command.advertiser_address), command.advertiser_address_type
            )
            and active.sid == command.advertising_sid
            for active in self.link.syncs.values()
        ):
            self.controller._send_hci_command_status(
                hci.HCI_ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR, command.op_code
            )
            return
        if len(self.link.syncs) >= RADIO_PERIODIC_SYNC_COUNT:
            self.controller._send_hci_command_status(
                hci.HCI_ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR, command.op_code
            )
            return
        if (
            command.options
            & ~(
                HCI_LE_PERIODIC_SYNC_REPORTS_DISABLED_MASK
                | SyncOptions.USE_PERIODIC_ADVERTISER_LIST
            )
            or command.sync_cte_type
        ):
            self.controller._send_hci_command_status(UNSUPPORTED, command.op_code)
            return
        if (
            not HCI_LE_PERIODIC_SYNC_TIMEOUT_MIN
            <= command.sync_timeout
            <= HCI_LE_PERIODIC_SYNC_TIMEOUT_MAX
            or not 0 <= command.skip <= HCI_LE_PERIODIC_SYNC_SKIP_MAX
            or (
                not command.options & SyncOptions.USE_PERIODIC_ADVERTISER_LIST
                and (
                    command.advertiser_address_type
                    not in (
                        hci.AddressType.PUBLIC_DEVICE,
                        hci.AddressType.RANDOM_DEVICE,
                    )
                    or not 0 <= command.advertising_sid <= PDU_ADV_ADI_SID_MAX
                )
            )
        ):
            self.controller._send_hci_command_status(INVALID, command.op_code)
            return
        self.link.sync = PeriodicSync(
            command.advertiser_address,
            command.advertising_sid,
            command.sync_timeout * hci.HCI_LE_PERIODIC_SYNC_TIMEOUT_UNIT_US,
            0,
            command.skip,
            not command.options & HCI_LE_PERIODIC_SYNC_REPORTS_DISABLED_MASK,
            use_list=use_list,
            handle=next(
                handle
                for handle in range(1, RADIO_PERIODIC_SYNC_COUNT + 1)
                if handle not in self.link.syncs
            ),
        )
        self.controller._send_hci_command_status(SUCCESS, command.op_code)

    def on_hci_le_read_periodic_advertiser_list_size_command(self, command):
        return hci.HCI_LE_Read_Periodic_Advertiser_List_Size_ReturnParameters(
            SUCCESS, RADIO_PERIODIC_ADVERTISER_LIST_SIZE
        )

    def _edit_periodic_list(self, command, add):
        if self.link.sync is not None:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        if (
            command.advertiser_address_type
            not in (hci.AddressType.PUBLIC_DEVICE, hci.AddressType.RANDOM_DEVICE)
            or not 0 <= command.advertising_sid <= PDU_ADV_ADI_SID_MAX
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        key = (
            hci.Address(
                bytes(command.advertiser_address), command.advertiser_address_type
            ),
            command.advertising_sid,
        )
        items = self.link.periodic_advertiser_list
        if add:
            if key in items:
                return hci.HCI_StatusReturnParameters(INVALID)
            if len(items) >= RADIO_PERIODIC_ADVERTISER_LIST_SIZE:
                return hci.HCI_StatusReturnParameters(
                    hci.HCI_ErrorCode.MEMORY_CAPACITY_EXCEEDED_ERROR
                )
            items.add(key)
        else:
            if key not in items:
                return hci.HCI_StatusReturnParameters(UNKNOWN_ADV)
            items.remove(key)
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_add_device_to_periodic_advertiser_list_command(self, command):
        return self._edit_periodic_list(command, True)

    def on_hci_le_remove_device_from_periodic_advertiser_list_command(self, command):
        return self._edit_periodic_list(command, False)

    def on_hci_le_clear_periodic_advertiser_list_command(self, command):
        if self.link.sync is not None:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        self.link.periodic_advertiser_list.clear()
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_periodic_advertising_create_sync_cancel_command(self, command):
        sync = self.link.sync
        if sync is None or sync.established:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        asyncio.get_running_loop().call_soon(
            self.on_sync_established,
            sync,
            hci.HCI_ErrorCode.OPERATION_CANCELLED_BY_HOST_ERROR,
        )
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_periodic_advertising_terminate_sync_command(self, command):
        if command.sync_handle not in self.link.syncs:
            return hci.HCI_StatusReturnParameters(
                hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
            )
        del self.link.syncs[command.sync_handle]
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_set_periodic_advertising_receive_enable_command(self, command):
        sync = self.link.syncs.get(command.sync_handle)
        if sync is None:
            return hci.HCI_StatusReturnParameters(
                hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
            )
        if command.enable not in (0, 1):
            return hci.HCI_StatusReturnParameters(UNSUPPORTED)
        sync.reports_enabled = bool(command.enable)
        return hci.HCI_StatusReturnParameters(SUCCESS)
