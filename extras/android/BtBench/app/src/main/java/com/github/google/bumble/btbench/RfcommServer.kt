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
import java.io.IOException
import java.util.logging.Logger
import kotlin.concurrent.thread

private val Log = Logger.getLogger("btbench.rfcomm-server")

class RfcommServer(private val viewModel: AppViewModel, val bluetoothAdapter: BluetoothAdapter) {
    @SuppressLint("MissingPermission")
    fun run() {
        val serverSocket = bluetoothAdapter.listenUsingInsecureRfcommWithServiceRecord(
            "BumbleBench", DEFAULT_RFCOMM_UUID
        )

        val server = SocketServer(viewModel, serverSocket)
        server.run({})
    }
}