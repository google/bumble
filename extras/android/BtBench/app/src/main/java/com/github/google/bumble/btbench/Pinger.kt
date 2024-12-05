// Copyright 2024 Google LLC
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
import kotlin.time.TimeSource

private val Log = Logger.getLogger("btbench.pinger")

class Pinger(private val viewModel: AppViewModel, private val packetIO: PacketIO) : IoClient,
    PacketSink() {
    private val pingTimes: ArrayList<TimeSource.Monotonic.ValueTimeMark> = ArrayList()
    private val rtts: ArrayList<Long> = ArrayList()
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

        val packetCount = viewModel.senderPacketCount
        val packetSize = viewModel.senderPacketSize

        val startTime = TimeSource.Monotonic.markNow()
        for (i in 0..<packetCount) {
            var now = TimeSource.Monotonic.markNow()
            if (viewModel.senderPacketInterval > 0) {
                val targetTime = startTime + (i * viewModel.senderPacketInterval).milliseconds
                val delay = targetTime - now
                if (delay.isPositive()) {
                    Log.info("sleeping ${delay.inWholeMilliseconds} ms")
                    Thread.sleep(delay.inWholeMilliseconds)
                    now = TimeSource.Monotonic.markNow()
                }
            }
            pingTimes.add(TimeSource.Monotonic.markNow())
            packetIO.sendPacket(
                SequencePacket(
                    if (i < packetCount - 1) 0 else Packet.LAST_FLAG,
                    i,
                    (now - startTime).inWholeMicroseconds.toInt(),
                    ByteArray(packetSize - 10)
                )
            )
            viewModel.packetsSent = i + 1
        }

        // Wait for the last ACK
        Log.info("waiting for last ACK")
        done.acquire()
        Log.info("got last ACK")
    }

    override fun abort() {
        done.release()
    }

    override fun onResetPacket() {
    }

    override fun onAckPacket(packet: AckPacket) {
        val now = TimeSource.Monotonic.markNow()
        viewModel.packetsReceived += 1
        if (packet.sequenceNumber < pingTimes.size) {
            val rtt = (now - pingTimes[packet.sequenceNumber]).inWholeMilliseconds
            rtts.add(rtt)
            Log.info("received ACK ${packet.sequenceNumber}, RTT=$rtt")
        } else {
            Log.warning("received ACK with unexpected sequence ${packet.sequenceNumber}")
        }

        if (packet.flags and Packet.LAST_FLAG != 0) {
            Log.info("last packet received")
            val stats = "RTTs: min=${rtts.min()}, max=${rtts.max()}, avg=${rtts.sum() / rtts.size}"
            Log.info(stats)
            viewModel.stats = stats
            done.release()
        }
    }

    override fun onSequencePacket(packet: SequencePacket) {
    }
}
