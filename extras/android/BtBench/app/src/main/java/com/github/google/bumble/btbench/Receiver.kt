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

import java.util.logging.Logger
import kotlin.time.DurationUnit
import kotlin.time.TimeSource

private val Log = Logger.getLogger("btbench.receiver")

class Receiver(private val viewModel: AppViewModel, private val packetIO: PacketIO) : PacketSink() {
    private var startTime: TimeSource.Monotonic.ValueTimeMark = TimeSource.Monotonic.markNow()
    private var lastPacketTime: TimeSource.Monotonic.ValueTimeMark = TimeSource.Monotonic.markNow()
    private var bytesReceived = 0

    init {
        packetIO.packetSink = this
    }

    override fun onResetPacket() {
        startTime = TimeSource.Monotonic.markNow()
        lastPacketTime = startTime
        bytesReceived = 0
        viewModel.throughput = 0
        viewModel.packetsSent = 0
        viewModel.packetsReceived = 0
    }

    override fun onAckPacket() {

    }

    override fun onSequencePacket(packet: SequencePacket) {
        val received = packet.payload.size + 6
        bytesReceived += received
        val now = TimeSource.Monotonic.markNow()
        lastPacketTime = now
        viewModel.packetsReceived += 1
        if (packet.flags and Packet.LAST_FLAG != 0) {
            Log.info("received last packet")
            val elapsed = now - startTime
            val throughput = (bytesReceived / elapsed.toDouble(DurationUnit.SECONDS)).toInt()
            Log.info("throughput: $throughput")
            viewModel.throughput = throughput
            packetIO.sendPacket(AckPacket(packet.flags, packet.sequenceNumber))
        }
    }
}
