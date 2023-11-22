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
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY
import android.os.Build
import java.io.IOException
import java.util.logging.Logger
import kotlin.concurrent.thread

private val Log = Logger.getLogger("btbench.l2cap-server")

class L2capServer(private val viewModel: AppViewModel, private val bluetoothAdapter: BluetoothAdapter) {
    @SuppressLint("MissingPermission")
    fun run() {
        // Advertise to that the peer can find us and connect.
        val callback = object: AdvertiseCallback() {
            override fun onStartFailure(errorCode: Int) {
                Log.warning("failed to start advertising: $errorCode")
            }

            override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
                Log.info("advertising started: $settingsInEffect")
            }
        }
        val advertiseSettingsBuilder = AdvertiseSettings.Builder()
            .setAdvertiseMode(ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            advertiseSettingsBuilder.setDiscoverable(true)
        }
        val advertiseSettings = advertiseSettingsBuilder.build()
        val advertiseData = AdvertiseData.Builder().build()
        val scanData = AdvertiseData.Builder().setIncludeDeviceName(true).build()
        val advertiser = bluetoothAdapter.bluetoothLeAdvertiser
        advertiser.startAdvertising(advertiseSettings, advertiseData, scanData, callback)

        val serverSocket = bluetoothAdapter.listenUsingInsecureL2capChannel()
        viewModel.l2capPsm = serverSocket.psm
        Log.info("psm = $serverSocket.psm")

        val server = SocketServer(viewModel, serverSocket)
        server.run({ advertiser.stopAdvertising(callback) })
    }
}