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
import android.content.Context
import java.util.logging.Logger

private val Log = Logger.getLogger("btbench.l2cap-client")

class L2capClient(
    private val viewModel: AppViewModel,
    bluetoothAdapter: BluetoothAdapter,
    context: Context,
    private val createIoClient: (packetIo: PacketIO) -> IoClient
) : Mode {
    private var connection: Connection = Connection(viewModel, bluetoothAdapter, context)
    private var socketClient: SocketClient? = null

    @SuppressLint("MissingPermission")
    override fun run() {
        viewModel.running = true
        connection.connect()
        val socket = connection.remoteDevice!!.createInsecureL2capChannel(viewModel.l2capPsm)
        socketClient = SocketClient(viewModel, socket, createIoClient)
        socketClient!!.run()
    }

    override fun waitForCompletion() {
        socketClient?.waitForCompletion()
    }
}
