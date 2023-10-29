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

import android.bluetooth.BluetoothSocket
import java.io.IOException
import java.nio.ByteBuffer
import java.util.logging.Logger
import kotlin.math.min

private val Log = Logger.getLogger("btbench.packet")

fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

abstract class Packet(val type: Int, val payload: ByteArray = ByteArray(0)) {
    companion object {
        const val RESET = 0
        const val SEQUENCE = 1
        const val ACK = 2

        const val LAST_FLAG = 1

        fun from(data: ByteArray): Packet {
            return when (data[0].toInt()) {
                RESET -> ResetPacket()
                SEQUENCE -> SequencePacket(
                    data[1].toInt(),
                    ByteBuffer.wrap(data, 2, 4).getInt(),
                    data.sliceArray(6..<data.size)
                )

                ACK -> AckPacket(data[1].toInt(), ByteBuffer.wrap(data, 2, 4).getInt())
                else -> GenericPacket(data[0].toInt(), data.sliceArray(1..<data.size))
            }
        }
    }

    open fun toBytes(): ByteArray {
        return ByteBuffer.allocate(1 + payload.size).put(type.toByte()).put(payload).array()
    }
}

class GenericPacket(type: Int, payload: ByteArray) : Packet(type, payload)
class ResetPacket : Packet(RESET)

class AckPacket(val flags: Int, val sequenceNumber: Int) : Packet(ACK) {
    override fun toBytes(): ByteArray {
        return ByteBuffer.allocate(1 + 1 + 4).put(type.toByte()).put(flags.toByte())
            .putInt(sequenceNumber).array()
    }
}

class SequencePacket(val flags: Int, val sequenceNumber: Int, payload: ByteArray) :
    Packet(SEQUENCE, payload) {
    override fun toBytes(): ByteArray {
        return ByteBuffer.allocate(1 + 1 + 4 + payload.size).put(type.toByte()).put(flags.toByte())
            .putInt(sequenceNumber).put(payload).array()
    }
}

abstract class PacketSink {
    fun onPacket(packet: Packet) {
        when (packet) {
            is ResetPacket -> onResetPacket()
            is AckPacket -> onAckPacket()
            is SequencePacket -> onSequencePacket(packet)
        }
    }

    abstract fun onResetPacket()
    abstract fun onAckPacket()
    abstract fun onSequencePacket(packet: SequencePacket)
}

interface DataSink {
    fun onData(data: ByteArray)
}

interface PacketIO {
    var packetSink: PacketSink?
    fun sendPacket(packet: Packet)
}

class StreamedPacketIO(private val dataSink: DataSink) : PacketIO {
    private var bytesNeeded: Int = 0
    private var rxPacket: ByteBuffer? = null
    private var rxHeader = ByteBuffer.allocate(2)

    override var packetSink: PacketSink? = null

    fun onData(data: ByteArray) {
        var current = data
        while (current.isNotEmpty()) {
            if (bytesNeeded > 0) {
                val chunk = current.sliceArray(0..<min(bytesNeeded, current.size))
                rxPacket!!.put(chunk)
                current = current.sliceArray(chunk.size..<current.size)
                bytesNeeded -= chunk.size
                if (bytesNeeded == 0) {
                    // Packet completed.
                    //Log.fine("packet complete: ${current.toHex()}")
                    packetSink?.onPacket(Packet.from(rxPacket!!.array()))

                    // Reset.
                    reset()
                }
            } else {
                val headerBytesNeeded = 2 - rxHeader.position()
                val headerBytes = current.sliceArray(0..<min(headerBytesNeeded, current.size))
                current = current.sliceArray(headerBytes.size..<current.size)
                rxHeader.put(headerBytes)
                if (rxHeader.position() != 2) {
                    return
                }
                bytesNeeded = rxHeader.getShort(0).toInt()
                if (bytesNeeded == 0) {
                    Log.warning("found 0 size packet!")
                    reset()
                    return
                }
                rxPacket = ByteBuffer.allocate(bytesNeeded)
            }
        }
    }

    private fun reset() {
        rxPacket = null
        rxHeader.position(0)
    }

    override fun sendPacket(packet: Packet) {
        val packetBytes = packet.toBytes()
        val packetData =
            ByteBuffer.allocate(2 + packetBytes.size).putShort(packetBytes.size.toShort())
                .put(packetBytes).array()
        dataSink.onData(packetData)
    }
}

class SocketDataSink(private val socket: BluetoothSocket) : DataSink {
    override fun onData(data: ByteArray) {
        socket.outputStream.write(data)
    }
}

class SocketDataSource(
    private val socket: BluetoothSocket,
    private val onData: (data: ByteArray) -> Unit
) {
    fun receive() {
        val buffer = ByteArray(4096)
        do {
            try {
                val bytesRead = socket.inputStream.read(buffer)
                if (bytesRead <= 0) {
                    break
                }
                onData(buffer.sliceArray(0..<bytesRead))
            } catch (error: IOException) {
                Log.warning("IO Exception: $error")
                break
            }
        } while (true)
        Log.info("end of stream")
    }
}