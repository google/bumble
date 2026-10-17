# Copyright 2026 Xiaomi Corporation
# SPDX-License-Identifier: Apache-2.0

"""Initiating, ACL, encryption and connected Link Layer procedure HCI commands."""

import asyncio
import logging

from bumble import crypto, hci
from bumble.hci import (
    HCI_LE_ALL_PHYS_RX_MASK,
    HCI_LE_ALL_PHYS_TX_MASK,
    HCI_LE_EXT_SCAN_INTERVAL_MAX,
    HCI_LE_PHY_OPTIONS_NO_PREFERENCE,
    HCI_LE_PHY_OPTIONS_S2_PREFERRED,
    HCI_LE_PHY_OPTIONS_S8_PREFERRED,
    HCI_LE_SCAN_INTERVAL_MAX,
    HCI_LE_SCAN_INTERVAL_MIN,
    HCI_LE_SCAN_INTERVAL_UNIT_US,
)
from bumble.ll import (
    LL_CHANNEL_MAP_SIZE,
    LL_CONN_WINDOW_SIZE_MIN,
    LL_ENCRYPTION_RANDOM_SIZE,
    PDU_DATA_PAYLOAD_SIZE_MAX,
    PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
)
from bumble.radio_controller.controller_le_context import (
    DISALLOWED,
    INVALID,
    SUCCESS,
    UNSUPPORTED,
    LeControllerContext,
)
from bumble.radio_controller.radio import (
    PHY_CODED_S2_FACTOR,
    PHY_CODED_S8_FACTOR,
    RADIO_CONNECTION_COUNT,
    RADIO_PRIMARY_SCAN_PHY_MASK,
    RADIO_SUPPORTED_PHY_MASK,
    Phy,
)
from bumble.radio_controller.radio_data_length import valid_data_length
from bumble.radio_controller.radio_discovery import Initiating, ScanWindow
from bumble.radio_controller.radio_parameters import (
    Parameters,
    valid_channel_map,
    valid_timing,
)

logger = logging.getLogger(__name__)


class LeConnectionCommands(LeControllerContext):
    def _start_initiating(self, command, parameters, windows):
        """Commit one validated attempt; a rejected command leaves all state intact."""
        if not command.initiator_filter_policy and any(
            connection.peer == command.peer_address
            for connection in self.link.connections.values()
        ):
            self.controller._send_hci_command_status(
                hci.HCI_ErrorCode.CONNECTION_ALREADY_EXISTS_ERROR, command.op_code
            )
            return
        if self.link.initiating:
            self.controller._send_hci_command_status(DISALLOWED, command.op_code)
            return
        if len(self.link.connections) >= RADIO_CONNECTION_COUNT:
            self.controller._send_hci_command_status(
                hci.HCI_ErrorCode.CONNECTION_LIMIT_EXCEEDED_ERROR, command.op_code
            )
            return
        if (
            command.initiator_filter_policy not in (0, 1)
            or command.own_address_type
            not in (hci.OwnAddressType.PUBLIC, hci.OwnAddressType.RANDOM)
            or command.peer_address_type
            not in (hci.AddressType.PUBLIC_DEVICE, hci.AddressType.RANDOM_DEVICE)
        ):
            self.controller._send_hci_command_status(UNSUPPORTED, command.op_code)
            return
        window = windows[0]
        self.link.initiating = Initiating(
            self._address(command.own_address_type),
            command.peer_address,
            window.interval_us,
            window.window_us,
            next(iter(parameters.values())),
            self.now_us,
            windows=windows,
            phy_parameters=parameters,
            filter_policy=command.initiator_filter_policy,
        )
        self.controller._send_hci_command_status(SUCCESS, command.op_code)

    def on_hci_le_create_connection_command(self, command):
        if (
            command.min_ce_length > command.max_ce_length
            or not valid_timing(
                command.connection_interval_min,
                command.connection_interval_max,
                command.max_latency,
                command.supervision_timeout,
            )
            or not HCI_LE_SCAN_INTERVAL_MIN
            <= command.le_scan_window
            <= command.le_scan_interval
            <= HCI_LE_SCAN_INTERVAL_MAX
        ):
            self.controller._send_hci_command_status(INVALID, command.op_code)
            return
        # Wire identity and hop are allocated only before sending CONNECT_IND.
        parameters = Parameters(
            0,
            0,
            LL_CONN_WINDOW_SIZE_MIN,
            0,
            command.connection_interval_min,
            command.max_latency,
            command.supervision_timeout,
            self.host_channel_map,
            0,
        )
        self._start_initiating(
            command,
            {Phy.LE_1M: parameters},
            (
                ScanWindow(
                    Phy.LE_1M,
                    command.le_scan_interval * HCI_LE_SCAN_INTERVAL_UNIT_US,
                    command.le_scan_window * HCI_LE_SCAN_INTERVAL_UNIT_US,
                ),
            ),
        )

    def on_hci_le_extended_create_connection_command(self, command):
        if command.initiating_phys & ~RADIO_SUPPORTED_PHY_MASK:
            self.controller._send_hci_command_status(UNSUPPORTED, command.op_code)
            return
        if not command.initiating_phys & RADIO_PRIMARY_SCAN_PHY_MASK:
            self.controller._send_hci_command_status(INVALID, command.op_code)
            return
        phys = [phy for phy in Phy if command.initiating_phys & (1 << (phy - 1))]
        values = {}
        for index, phy in enumerate(phys):
            minimum, maximum, latency, timeout = (
                command.connection_interval_mins[index],
                command.connection_interval_maxs[index],
                command.max_latencies[index],
                command.supervision_timeouts[index],
            )
            if (
                not valid_timing(minimum, maximum, latency, timeout)
                or command.min_ce_lengths[index] > command.max_ce_lengths[index]
                or not HCI_LE_SCAN_INTERVAL_MIN
                <= command.scan_windows[index]
                <= command.scan_intervals[index]
                <= HCI_LE_EXT_SCAN_INTERVAL_MAX
            ):
                self.controller._send_hci_command_status(INVALID, command.op_code)
                return
            # The selected PHY receives its wire parameters at connection creation.
            values[phy] = Parameters(
                0,
                0,
                LL_CONN_WINDOW_SIZE_MIN,
                0,
                minimum,
                latency,
                timeout,
                self.host_channel_map,
                0,
            )
        self._start_initiating(
            command,
            values,
            tuple(
                ScanWindow(
                    phy,
                    command.scan_intervals[index] * HCI_LE_SCAN_INTERVAL_UNIT_US,
                    command.scan_windows[index] * HCI_LE_SCAN_INTERVAL_UNIT_US,
                )
                for index, phy in enumerate(phys)
                if phy != Phy.LE_2M
            ),
        )

    def on_hci_le_create_connection_cancel_command(self, command):
        item = self.link.initiating
        if item is None:
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        self.link.initiating = None
        asyncio.get_running_loop().call_soon(
            self._emit_hci_packet,
            self._connection_complete_event(
                status=hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR,
                connection_handle=0,
                role=0,
                peer_address_type=item.peer.address_type,
                peer_address=item.peer,
                connection_interval=0,
                peripheral_latency=0,
                supervision_timeout=0,
                central_clock_accuracy=0,
            ),
        )
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_disconnect_command(self, command):
        connection = self._connection(command.connection_handle)
        if connection is None:
            self.controller._send_hci_command_status(
                hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR, command.op_code
            )
            return
        connection.terminate(command.reason)
        self.controller._send_hci_command_status(SUCCESS, command.op_code)

    def _connection(self, handle):
        connection = self.link.connections.get(handle)
        return connection if connection and connection.reported else None

    def on_hci_read_rssi_command(self, command):
        connection = self._connection(command.handle)
        return hci.HCI_Read_RSSI_ReturnParameters(
            (
                SUCCESS
                if connection
                else hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
            ),
            command.handle,
            connection.rssi if connection else 0,
        )

    def on_hci_le_enable_encryption_command(self, command):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif connection.role != hci.Role.CENTRAL or connection.encryption.busy:
            status = DISALLOWED
        self.controller._send_hci_command_status(status, command.op_code)
        if status == SUCCESS:
            connection.encryption.start(
                command.random_number,
                command.encrypted_diversifier,
                command.long_term_key,
            )

    def on_hci_le_encrypt_command(self, command):
        return hci.HCI_LE_Encrypt_ReturnParameters(
            SUCCESS, crypto.e(command.key, command.plaintext_data)
        )

    def _supply_long_term_key(self, command, key):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        else:
            from bumble.radio_controller.radio_encryption import State

            if (
                connection.role != hci.Role.PERIPHERAL
                or connection.encryption.state != State.KEY
            ):
                status = DISALLOWED
            else:
                connection.encryption.supply_key(key)
        return hci.HCI_StatusAndConnectionHandleReturnParameters(
            status, command.connection_handle
        )

    def on_hci_le_long_term_key_request_reply_command(self, command):
        return self._supply_long_term_key(command, command.long_term_key)

    def on_hci_le_long_term_key_request_negative_reply_command(self, command):
        return self._supply_long_term_key(command, None)

    def on_hci_read_authenticated_payload_timeout_command(self, command):
        connection = self._connection(command.connection_handle)
        return hci.HCI_Read_Authenticated_Payload_Timeout_ReturnParameters(
            (
                SUCCESS
                if connection
                else hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
            ),
            command.connection_handle,
            connection.encryption.auth_timeout if connection else 0,
        )

    def on_hci_write_authenticated_payload_timeout_command(self, command):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif not command.authenticated_payload_timeout:
            status = INVALID
        else:
            connection.encryption.auth_timeout = command.authenticated_payload_timeout
        return hci.HCI_StatusAndConnectionHandleReturnParameters(
            status, command.connection_handle
        )

    def on_hci_le_rand_command(self, command):
        return hci.HCI_LE_Rand_ReturnParameters(
            SUCCESS, self.link.random.randbytes(LL_ENCRYPTION_RANDOM_SIZE)
        )

    def on_hci_le_read_remote_features_command(self, command):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif connection.controls.feature_request:
            status = DISALLOWED
        self.controller._send_hci_command_status(status, command.op_code)
        if status == SUCCESS:
            connection.controls.request_features()

    def on_hci_read_remote_version_information_command(self, command):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif connection.controls.version_request:
            status = DISALLOWED
        self.controller._send_hci_command_status(status, command.op_code)
        if status == SUCCESS:
            connection.controls.request_version()

    def on_hci_le_connection_update_command(self, command):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif connection.controls.busy:
            status = DISALLOWED
        elif (
            not valid_timing(
                command.connection_interval_min,
                command.connection_interval_max,
                command.max_latency,
                command.supervision_timeout,
            )
            or command.min_ce_length > command.max_ce_length
        ):
            status = INVALID
        elif (
            connection.role == hci.Role.PERIPHERAL
            and not connection.controls.supports_parameter_request
        ):
            status = hci.HCI_ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
        self.controller._send_hci_command_status(status, command.op_code)
        if status == SUCCESS:
            if (
                connection.role == hci.Role.CENTRAL
                and not connection.controls.supports_parameter_request
            ):
                connection.controls.request_update(
                    command.connection_interval_min,
                    command.max_latency,
                    command.supervision_timeout,
                )
            else:
                connection.controls.request_parameters(
                    command.connection_interval_min,
                    command.connection_interval_max,
                    command.max_latency,
                    command.supervision_timeout,
                )

    def on_hci_le_remote_connection_parameter_request_reply_command(self, command):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif connection.controls.remote_parameters is None:
            status = DISALLOWED
        elif not valid_timing(
            command.interval_min,
            command.interval_max,
            command.max_latency,
            command.timeout,
        ):
            status = INVALID
        else:
            connection.controls.reply_parameters(
                command.interval_min,
                command.interval_max,
                command.max_latency,
                command.timeout,
            )
        return hci.HCI_StatusAndConnectionHandleReturnParameters(
            status, command.connection_handle
        )

    def on_hci_le_remote_connection_parameter_request_negative_reply_command(
        self, command
    ):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif connection.controls.remote_parameters is None:
            status = DISALLOWED
        else:
            connection.controls.reject_remote_parameters(command.reason)
        return hci.HCI_StatusAndConnectionHandleReturnParameters(
            status, command.connection_handle
        )

    def on_hci_le_set_host_channel_classification_command(self, command):
        value = int.from_bytes(command.channel_map, 'little')
        if not valid_channel_map(value):
            return hci.HCI_StatusReturnParameters(INVALID)
        centrals = [
            connection
            for connection in self.link.connections.values()
            if connection.role == hci.Role.CENTRAL
        ]
        if any(connection.controls.busy for connection in centrals):
            return hci.HCI_StatusReturnParameters(DISALLOWED)
        for connection in centrals:
            connection.controls.request_channel_map(value)
        self.host_channel_map = value
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_read_channel_map_command(self, command):
        connection = self._connection(command.connection_handle)
        return hci.HCI_LE_Read_Channel_Map_ReturnParameters(
            (
                SUCCESS
                if connection
                else hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
            ),
            command.connection_handle,
            (connection.parameters.channel_map if connection else 0).to_bytes(
                LL_CHANNEL_MAP_SIZE, 'little'
            ),
        )

    @staticmethod
    def _phys(command):
        if (
            command.all_phys & ~(HCI_LE_ALL_PHYS_TX_MASK | HCI_LE_ALL_PHYS_RX_MASK)
            or (command.tx_phys | command.rx_phys) & ~RADIO_SUPPORTED_PHY_MASK
        ):
            return None
        tx = (
            RADIO_SUPPORTED_PHY_MASK
            if command.all_phys & HCI_LE_ALL_PHYS_TX_MASK
            else command.tx_phys
        )
        rx = (
            RADIO_SUPPORTED_PHY_MASK
            if command.all_phys & HCI_LE_ALL_PHYS_RX_MASK
            else command.rx_phys
        )
        return (tx, rx) if tx and rx else None

    def on_hci_le_read_phy_command(self, command):
        connection = self._connection(command.connection_handle)
        return hci.HCI_LE_Read_PHY_ReturnParameters(
            (
                SUCCESS
                if connection
                else hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
            ),
            command.connection_handle,
            connection.tx_phy if connection else Phy.LE_1M,
            connection.rx_phy if connection else Phy.LE_1M,
        )

    def on_hci_le_set_default_phy_command(self, command):
        phys = self._phys(command)
        if phys is None:
            return hci.HCI_StatusReturnParameters(INVALID)
        self.default_tx_phys, self.default_rx_phys = phys
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_set_phy_command(self, command):
        connection = self._connection(command.connection_handle)
        phys = self._phys(command)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif (command.tx_phys | command.rx_phys) & ~RADIO_SUPPORTED_PHY_MASK:
            status = UNSUPPORTED
        elif phys is None or command.phy_options not in (
            HCI_LE_PHY_OPTIONS_NO_PREFERENCE,
            HCI_LE_PHY_OPTIONS_S2_PREFERRED,
            HCI_LE_PHY_OPTIONS_S8_PREFERRED,
        ):
            status = INVALID
        elif connection.controls.busy:
            status = DISALLOWED
        self.controller._send_hci_command_status(status, command.op_code)
        if status == SUCCESS:
            connection.tx_coding = (
                PHY_CODED_S2_FACTOR
                if command.phy_options == HCI_LE_PHY_OPTIONS_S2_PREFERRED
                else PHY_CODED_S8_FACTOR
            )
            connection.controls.request_phy(*phys)

    def on_hci_acl_data_packet(self, packet):
        connection = self._connection(packet.connection_handle)
        if (
            connection is None
            or packet.bc_flag
            or packet.pb_flag
            not in (
                hci.HCI_ACL_PB_FIRST_NON_FLUSHABLE,
                hci.HCI_ACL_PB_CONTINUATION,
                hci.HCI_ACL_PB_FIRST_FLUSHABLE,
            )
        ):
            logger.warning('Invalid ACL handle or flags')
            return
        connection.enqueue_acl(
            packet.pb_flag == hci.HCI_ACL_PB_CONTINUATION, packet.data
        )

    def on_hci_le_set_data_length_command(self, command):
        connection = self._connection(command.connection_handle)
        status = SUCCESS
        if connection is None:
            status = hci.HCI_ErrorCode.UNKNOWN_CONNECTION_IDENTIFIER_ERROR
        elif not valid_data_length(command.tx_octets, command.tx_time):
            status = INVALID
        elif connection.controls.busy:
            status = DISALLOWED
        elif (
            connection.peer_features is not None
            and not connection.peer_features
            & hci.LeFeatureMask.LE_DATA_PACKET_LENGTH_EXTENSION
        ):
            status = hci.HCI_ErrorCode.UNSUPPORTED_REMOTE_FEATURE_ERROR
        else:
            connection.controls.data_length.request(command.tx_octets, command.tx_time)
        return hci.HCI_StatusAndConnectionHandleReturnParameters(
            status, command.connection_handle
        )

    def on_hci_le_read_suggested_default_data_length_command(self, command):
        return hci.HCI_LE_Read_Suggested_Default_Data_Length_ReturnParameters(
            SUCCESS, self.link.default_tx_octets, self.link.default_tx_time
        )

    def on_hci_le_write_suggested_default_data_length_command(self, command):
        if not valid_data_length(
            command.suggested_max_tx_octets, command.suggested_max_tx_time
        ):
            return hci.HCI_StatusReturnParameters(INVALID)
        self.link.default_tx_octets = command.suggested_max_tx_octets
        self.link.default_tx_time = command.suggested_max_tx_time
        return hci.HCI_StatusReturnParameters(SUCCESS)

    def on_hci_le_read_maximum_data_length_command(self, command):
        return hci.HCI_LE_Read_Maximum_Data_Length_ReturnParameters(
            SUCCESS,
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
            PDU_DATA_PAYLOAD_SIZE_MAX,
            PDU_DATA_PAYLOAD_TIME_CODED_MAX_US,
        )
