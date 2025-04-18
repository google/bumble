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
import android.bluetooth.BluetoothSocket
import java.io.IOException
import java.util.logging.Logger
import kotlin.concurrent.thread

private val Log = Logger.getLogger("btbench.socket-client")

class SocketClient(
    private val viewModel: AppViewModel,
    private val socket: BluetoothSocket,
    private val createIoClient: (packetIo: PacketIO) -> IoClient
) {
    private var clientThread: Thread? = null

    @SuppressLint("MissingPermission")
    fun run() {
        viewModel.running = true
        val socketDataSink = SocketDataSink(socket)
        val streamIO = StreamedPacketIO(socketDataSink)
        val socketDataSource = SocketDataSource(socket, streamIO::onData)
        val ioClient = createIoClient(streamIO)

        fun cleanup() {
            socket.close()
            viewModel.aborter = {}
            viewModel.running = false
        }

        clientThread = thread(name = "SocketClient") {
            viewModel.aborter = {
                ioClient.abort()
                socket.close()
            }
            Log.info("connecting to remote")
            try {
                socket.connect()
            } catch (error: IOException) {
                Log.warning("connection failed")
                viewModel.status = "ABORTED"
                viewModel.lastError = "CONNECTION_FAILED"
                cleanup()
                return@thread
            }
            Log.info("connected")

            val sourceThread = thread {
                socketDataSource.receive()
                socket.close()
                ioClient.abort()
            }

            try {
                ioClient.run()
                socket.close()
                viewModel.status = "OK"
            } catch (error: IOException) {
                Log.info("run ended abruptly")
                viewModel.status = "ABORTED"
                viewModel.lastError = "IO_ERROR"
            }

            Log.info("waiting for source thread to finish")
            sourceThread.join()

            cleanup()
        }
    }

    fun waitForCompletion() {
        clientThread?.join()
    }
}
