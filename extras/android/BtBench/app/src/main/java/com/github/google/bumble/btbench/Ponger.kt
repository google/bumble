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

import java.util.concurrent.CountDownLatch
import java.util.logging.Logger
import kotlin.time.TimeSource

private val Log = Logger.getLogger("btbench.receiver")

class Ponger(private val viewModel: AppViewModel, private val packetIO: PacketIO) : IoClient, PacketSink() {
    private var startTime: TimeSource.Monotonic.ValueTimeMark = TimeSource.Monotonic.markNow()
    private var lastPacketTime: TimeSource.Monotonic.ValueTimeMark = TimeSource.Monotonic.markNow()
    private var expectedSequenceNumber: Int = 0
    private val done = CountDownLatch(1)

    init {
        packetIO.packetSink = this
    }

    override fun run() {
        viewModel.clear()
        done.await()
    }

    override fun abort() {}

    override fun onResetPacket() {
        startTime = TimeSource.Monotonic.markNow()
        lastPacketTime = startTime
        expectedSequenceNumber = 0
        viewModel.packetsSent = 0
        viewModel.packetsReceived = 0
        viewModel.stats = ""
    }

    override fun onAckPacket(packet: AckPacket) {
    }

    override fun onSequencePacket(packet: SequencePacket) {
        val now = TimeSource.Monotonic.markNow()
        lastPacketTime = now
        viewModel.packetsReceived += 1

        if (packet.sequenceNumber != expectedSequenceNumber) {
            Log.warning("unexpected packet sequence number (expected ${expectedSequenceNumber}, got ${packet.sequenceNumber})")
        }
        expectedSequenceNumber += 1

        packetIO.sendPacket(AckPacket(packet.flags, packet.sequenceNumber))
        viewModel.packetsSent += 1

        if (packet.flags and Packet.LAST_FLAG != 0) {
            Log.info("received last packet")
            done.countDown()
        }
    }
}
