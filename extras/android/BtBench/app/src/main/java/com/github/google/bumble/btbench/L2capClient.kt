// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.github.google.bumble.btbench

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import java.util.logging.Logger

private val Log = Logger.getLogger("btbench.l2cap-client")

class L2capClient(
    private val viewModel: AppViewModel,
    private val bluetoothAdapter: BluetoothAdapter,
    private val context: Context
) {
    @SuppressLint("MissingPermission")
    fun run() {
        viewModel.running = true
        val addressIsPublic = viewModel.peerBluetoothAddress.endsWith("/P")
        val address = viewModel.peerBluetoothAddress.take(17)
        val remoteDevice = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            bluetoothAdapter.getRemoteLeDevice(
                address,
                if (addressIsPublic) {
                    BluetoothDevice.ADDRESS_TYPE_PUBLIC
                } else {
                    BluetoothDevice.ADDRESS_TYPE_RANDOM
                }
            )
        } else {
            bluetoothAdapter.getRemoteDevice(address)
        }

        val gatt = remoteDevice.connectGatt(
            context,
            false,
            object : BluetoothGattCallback() {
                override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                    Log.info("MTU update: mtu=$mtu status=$status")
                    viewModel.mtu = mtu
                }

                override fun onPhyUpdate(gatt: BluetoothGatt, txPhy: Int, rxPhy: Int, status: Int) {
                    Log.info("PHY update: tx=$txPhy, rx=$rxPhy, status=$status")
                    viewModel.txPhy = txPhy
                    viewModel.rxPhy = rxPhy
                }

                override fun onPhyRead(gatt: BluetoothGatt, txPhy: Int, rxPhy: Int, status: Int) {
                    Log.info("PHY: tx=$txPhy, rx=$rxPhy, status=$status")
                    viewModel.txPhy = txPhy
                    viewModel.rxPhy = rxPhy
                }

                override fun onConnectionStateChange(
                    gatt: BluetoothGatt?, status: Int, newState: Int
                ) {
                    if (gatt != null && newState == BluetoothProfile.STATE_CONNECTED) {
                        if (viewModel.use2mPhy) {
                            gatt.setPreferredPhy(
                                BluetoothDevice.PHY_LE_2M_MASK,
                                BluetoothDevice.PHY_LE_2M_MASK,
                                BluetoothDevice.PHY_OPTION_NO_PREFERRED
                            )
                        }
                        gatt.readPhy()

                        // Request an MTU update, even though we don't use GATT, because Android
                        // won't request a larger link layer maximum data length otherwise.
                        gatt.requestMtu(517)
                    }
                }
            },
            BluetoothDevice.TRANSPORT_LE,
            if (viewModel.use2mPhy) BluetoothDevice.PHY_LE_2M_MASK else BluetoothDevice.PHY_LE_1M_MASK
        )

        val socket = remoteDevice.createInsecureL2capChannel(viewModel.l2capPsm)

        val client = SocketClient(viewModel, socket)
        client.run()
    }
}