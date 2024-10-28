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
import java.util.logging.Logger

private val Log = Logger.getLogger("btbench.rfcomm-server")

class RfcommServer(
    private val viewModel: AppViewModel,
    private val bluetoothAdapter: BluetoothAdapter,
    private val createIoClient: (packetIo: PacketIO) -> IoClient
) : Mode {
    private var socketServer: SocketServer? = null

    @SuppressLint("MissingPermission")
    override fun run() {
        val serverSocket = bluetoothAdapter.listenUsingInsecureRfcommWithServiceRecord(
            "BumbleBench", DEFAULT_RFCOMM_UUID
        )
        socketServer = SocketServer(viewModel, serverSocket, createIoClient)
        socketServer!!.run({}, {})
    }

    override fun waitForCompletion() {
        socketServer?.waitForCompletion()
    }
}
