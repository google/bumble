# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""LE HCI entry point and reset/command-family boundaries."""


from bumble import hci
from bumble.hci import HCI_EVENT_MASK_DEFAULT, HCI_LE_EVENT_MASK_DEFAULT
from bumble.ll import LL_DATA_CHANNEL_MAP_ALL
from bumble.radio_controller.controller_le_advertising import LeAdvertisingCommands
from bumble.radio_controller.controller_le_connection import LeConnectionCommands
from bumble.radio_controller.controller_le_context import DISALLOWED, SUCCESS
from bumble.radio_controller.controller_le_scanning import LeScanningCommands
from bumble.radio_controller.radio import (
    RADIO_DEFAULT_SCAN_INTERVAL_US,
    RADIO_SUPPORTED_PHY_MASK,
)
from bumble.radio_controller.radio_discovery import Scanning

# Core Vol 4, Part E, 3.1.1: one advertising command family per reset.
LEGACY_ADVERTISING_COMMANDS = frozenset(
    (
        hci.HCI_LE_SET_ADVERTISING_PARAMETERS_COMMAND,
        hci.HCI_LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER_COMMAND,
        hci.HCI_LE_SET_ADVERTISING_DATA_COMMAND,
        hci.HCI_LE_SET_SCAN_RESPONSE_DATA_COMMAND,
        hci.HCI_LE_SET_ADVERTISING_ENABLE_COMMAND,
        hci.HCI_LE_SET_SCAN_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_SCAN_ENABLE_COMMAND,
        hci.HCI_LE_CREATE_CONNECTION_COMMAND,
    )
)

# The extended family includes scanning, initiating and periodic sync.
EXTENDED_ADVERTISING_COMMANDS = frozenset(
    (
        hci.HCI_LE_SET_ADVERTISING_SET_RANDOM_ADDRESS_COMMAND,
        hci.HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_EXTENDED_ADVERTISING_DATA_COMMAND,
        hci.HCI_LE_SET_EXTENDED_SCAN_RESPONSE_DATA_COMMAND,
        hci.HCI_LE_SET_EXTENDED_ADVERTISING_ENABLE_COMMAND,
        hci.HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND,
        hci.HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND,
        hci.HCI_LE_REMOVE_ADVERTISING_SET_COMMAND,
        hci.HCI_LE_CLEAR_ADVERTISING_SETS_COMMAND,
        hci.HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_PERIODIC_ADVERTISING_DATA_COMMAND,
        hci.HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE_COMMAND,
        hci.HCI_LE_SET_EXTENDED_SCAN_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_EXTENDED_SCAN_ENABLE_COMMAND,
        hci.HCI_LE_EXTENDED_CREATE_CONNECTION_COMMAND,
        hci.HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_COMMAND,
        hci.HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL_COMMAND,
        hci.HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC_COMMAND,
        hci.HCI_LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST_COMMAND,
        hci.HCI_LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST_COMMAND,
        hci.HCI_LE_CLEAR_PERIODIC_ADVERTISER_LIST_COMMAND,
        hci.HCI_LE_READ_PERIODIC_ADVERTISER_LIST_SIZE_COMMAND,
        hci.HCI_LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_COMMAND,
        hci.HCI_LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS_COMMAND,
    )
)


class LeControllerProcedures(
    LeAdvertisingCommands, LeScanningCommands, LeConnectionCommands
):
    """One command endpoint, grouped by the LE procedures each command configures."""

    def command_allowed(self, opcode: int) -> bool:
        if opcode in LEGACY_ADVERTISING_COMMANDS:
            extended = False
        elif opcode in EXTENDED_ADVERTISING_COMMANDS:
            extended = True
        else:
            return True
        if self.extended_commands is None:
            self.extended_commands = extended
        return self.extended_commands == extended

    def on_hci_reset_command(self, command):
        self.link.reset()
        self.controller.le_connections.clear()
        self.controller.advertising_sets.clear()
        self.fragments.clear()
        self.seen.clear()
        self.extended_scan = False
        self.scan_parameters = Scanning(
            self.controller.public_address,
            RADIO_DEFAULT_SCAN_INTERVAL_US,
            RADIO_DEFAULT_SCAN_INTERVAL_US,
        )
        self.controller.le_legacy_advertiser.advertising_data = b''
        self.controller.le_legacy_advertiser.scan_response_data = b''
        self.controller.le_legacy_advertiser.enabled = False
        self.controller.event_mask = HCI_EVENT_MASK_DEFAULT
        self.controller.event_mask_page_2 = 0
        self.controller.le_event_mask = HCI_LE_EVENT_MASK_DEFAULT
        self.host_channel_map = LL_DATA_CHANNEL_MAP_ALL
        self.default_tx_phys = self.default_rx_phys = RADIO_SUPPORTED_PHY_MASK
        self.period_duplicate_reset = False
        self.extended_commands = None
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_set_random_address_command(self, command):
        if self.link.initiating is not None:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        return self.controller.on_hci_le_set_random_address_command(command)
