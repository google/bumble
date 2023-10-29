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

import java.util.concurrent.Semaphore
import java.util.logging.Logger
import kotlin.time.DurationUnit
import kotlin.time.TimeSource

private val Log = Logger.getLogger("btbench.sender")

class Sender(private val viewModel: AppViewModel, private val packetIO: PacketIO) : PacketSink() {
    private var startTime: TimeSource.Monotonic.ValueTimeMark = TimeSource.Monotonic.markNow()
    private var bytesSent = 0
    private val done = Semaphore(0)

    init {
        packetIO.packetSink = this
    }

    fun run() {
        viewModel.packetsSent = 0
        viewModel.packetsReceived = 0
        viewModel.throughput = 0

        Log.info("sending reset")
        packetIO.sendPacket(ResetPacket())

        startTime = TimeSource.Monotonic.markNow()

        val packetCount = viewModel.senderPacketCount
        val packetSize = viewModel.senderPacketSize
        for (i in 0..<packetCount - 1) {
            packetIO.sendPacket(SequencePacket(0, i, ByteArray(packetSize - 6)))
            bytesSent += packetSize
            viewModel.packetsSent = i + 1
        }
        packetIO.sendPacket(
            SequencePacket(
                Packet.LAST_FLAG,
                packetCount - 1,
                ByteArray(packetSize - 6)
            )
        )
        bytesSent += packetSize
        viewModel.packetsSent = packetCount

        // Wait for the ACK
        Log.info("waiting for ACK")
        done.acquire()
        Log.info("got ACK")
    }

    fun abort() {
        done.release()
    }

    override fun onResetPacket() {
    }

    override fun onAckPacket() {
        Log.info("received ACK")
        val elapsed = TimeSource.Monotonic.markNow() - startTime
        val throughput = (bytesSent / elapsed.toDouble(DurationUnit.SECONDS)).toInt()
        Log.info("throughput: $throughput")
        viewModel.throughput = throughput
        done.release()
    }

    override fun onSequencePacket(packet: SequencePacket) {
    }
}