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
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.DurationUnit
import kotlin.time.TimeSource

private val Log = Logger.getLogger("btbench.sender")

class Sender(private val viewModel: AppViewModel, private val packetIO: PacketIO) : IoClient,
    PacketSink() {
    private var startTime: TimeSource.Monotonic.ValueTimeMark = TimeSource.Monotonic.markNow()
    private var bytesSent = 0
    private val done = Semaphore(0)

    init {
        packetIO.packetSink = this
    }

    override fun run() {
        viewModel.clear()

        Log.info("startup delay: ${viewModel.startupDelay}")
        Thread.sleep(viewModel.startupDelay.toLong());
        Log.info("running")

        Log.info("sending reset")
        packetIO.sendPacket(ResetPacket())

        startTime = TimeSource.Monotonic.markNow()

        val packetCount = viewModel.senderPacketCount
        val packetSize = viewModel.senderPacketSize
        for (i in 0..<packetCount) {
            var now = TimeSource.Monotonic.markNow()
            if (viewModel.senderPacketInterval > 0) {
                val targetTime = startTime + (i * viewModel.senderPacketInterval).milliseconds
                val delay = targetTime - now
                if (delay.isPositive()) {
                    Log.info("sleeping ${delay.inWholeMilliseconds} ms")
                    Thread.sleep(delay.inWholeMilliseconds)
                }
                now = TimeSource.Monotonic.markNow()
            }
            val flags = when (i) {
                packetCount - 1 -> Packet.LAST_FLAG
                else -> 0
            }
            packetIO.sendPacket(
                SequencePacket(
                    flags,
                    i,
                    (now - startTime).inWholeMicroseconds.toInt(),
                    ByteArray(packetSize - 10)
                )
            )
            bytesSent += packetSize
            viewModel.packetsSent = i + 1
        }

        // Wait for the ACK
        Log.info("waiting for ACK")
        done.acquire()
        Log.info("got ACK")
    }

    override fun abort() {
        done.release()
    }

    override fun onResetPacket() {
    }

    override fun onAckPacket(packet: AckPacket) {
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
