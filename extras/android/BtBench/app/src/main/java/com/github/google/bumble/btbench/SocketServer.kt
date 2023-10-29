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

import android.bluetooth.BluetoothServerSocket
import java.io.IOException
import java.util.logging.Logger
import kotlin.concurrent.thread

private val Log = Logger.getLogger("btbench.socket-server")

class SocketServer(private val viewModel: AppViewModel, private val serverSocket: BluetoothServerSocket) {
    fun run(onTerminate: () -> Unit) {
        var aborted = false
        viewModel.running = true

        fun cleanup() {
            serverSocket.close()
            viewModel.running = false
            onTerminate()
        }

        thread(name = "SocketServer") {
            while (!aborted) {
                viewModel.aborter = {
                    serverSocket.close()
                }
                Log.info("waiting for connection...")
                val socket = try {
                    serverSocket.accept()
                } catch (error: IOException) {
                    Log.warning("server socket closed")
                    cleanup()
                    return@thread
                }
                Log.info("got connection")

                viewModel.aborter = {
                    aborted = true
                    socket.close()
                }
                viewModel.peerBluetoothAddress = socket.remoteDevice.address

                val socketDataSink = SocketDataSink(socket)
                val streamIO = StreamedPacketIO(socketDataSink)
                val socketDataSource = SocketDataSource(socket, streamIO::onData)
                val receiver = Receiver(viewModel, streamIO)
                socketDataSource.receive()
                socket.close()
            }
            cleanup()
        }
    }
}