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

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.content.Context
import java.io.IOException
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Semaphore
import java.util.logging.Logger
import kotlin.concurrent.thread

private val Log = Logger.getLogger("btbench.gatt-client")


class GattClientConnection(
    viewModel: AppViewModel,
    bluetoothAdapter: BluetoothAdapter,
    context: Context
) : Connection(viewModel, bluetoothAdapter, context), PacketIO {
    override var packetSink: PacketSink? = null
    private val discoveryDone: CountDownLatch = CountDownLatch(1)
    private val writeSemaphore: Semaphore = Semaphore(1)
    var rxCharacteristic: BluetoothGattCharacteristic? = null
    var txCharacteristic: BluetoothGattCharacteristic? = null

    override fun connect() {
        super.connect()

        // Check if we're already connected and have discovered the services
        if (gatt?.getService(BENCH_SERVICE_UUID) != null) {
            Log.fine("already connected")
            onServicesDiscovered(gatt, BluetoothGatt.GATT_SUCCESS)
        }
    }

    @SuppressLint("MissingPermission")
    override fun onConnectionStateChange(
        gatt: BluetoothGatt?, status: Int, newState: Int
    ) {
        super.onConnectionStateChange(gatt, status, newState)
        if (status != BluetoothGatt.GATT_SUCCESS) {
            Log.warning("onConnectionStateChange status=$status")
            discoveryDone.countDown()
            return
        }
        if (gatt != null && newState == BluetoothProfile.STATE_CONNECTED) {
            if (!gatt.discoverServices()) {
                Log.warning("discoverServices could not start")
                discoveryDone.countDown()
            }
        }
    }

    @SuppressLint("MissingPermission")
    override fun onServicesDiscovered(gatt: BluetoothGatt?, status: Int) {
        Log.fine("onServicesDiscovered")

        if (status != BluetoothGatt.GATT_SUCCESS) {
            Log.warning("failed to discover services: ${status}")
            discoveryDone.countDown()
            return
        }

        // Find the service
        val service = gatt!!.getService(BENCH_SERVICE_UUID)
        if (service == null) {
            Log.warning("GATT Service not found")
            discoveryDone.countDown()
            return
        }

        // Find the RX and TX characteristics
        rxCharacteristic = service.getCharacteristic(BENCH_RX_UUID)
        if (rxCharacteristic == null) {
            Log.warning("GATT RX Characteristics not found")
            discoveryDone.countDown()
            return
        }
        txCharacteristic = service.getCharacteristic(BENCH_TX_UUID)
        if (txCharacteristic == null) {
            Log.warning("GATT TX Characteristics not found")
            discoveryDone.countDown()
            return
        }

        // Subscribe to the RX characteristic
        Log.fine("subscribing to RX")
        gatt.setCharacteristicNotification(rxCharacteristic, true)
        val cccdDescriptor = rxCharacteristic!!.getDescriptor(CCCD_UUID)
        gatt.writeDescriptor(cccdDescriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);

        Log.info("GATT discovery complete")
        discoveryDone.countDown()
    }

    override fun onCharacteristicWrite(
        gatt: BluetoothGatt?,
        characteristic: BluetoothGattCharacteristic?,
        status: Int
    ) {
        // Now we can write again
        writeSemaphore.release()

        if (status != BluetoothGatt.GATT_SUCCESS) {
            Log.warning("onCharacteristicWrite failed: $status")
            return
        }
    }

    override fun onCharacteristicChanged(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray
    ) {
        if (characteristic.uuid == BENCH_RX_UUID && packetSink != null) {
            val packet = Packet.from(value)
            packetSink!!.onPacket(packet)
        }
    }

    @SuppressLint("MissingPermission")
    override fun sendPacket(packet: Packet) {
        if (txCharacteristic == null) {
            Log.warning("No TX characteristic, dropping")
            return
        }

        // Wait until we can write
        writeSemaphore.acquire()

        // Write the data
        val data = packet.toBytes()
        val clampedData = if (data.size > 512) {
            // Clamp the data to the maximum allowed characteristic data size
            data.copyOf(512)
        } else {
            data
        }
        gatt?.writeCharacteristic(
            txCharacteristic!!,
            clampedData,
            BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        )
    }

    override
    fun disconnect() {
        super.disconnect()
        discoveryDone.countDown()
    }

    fun waitForDiscoveryCompletion() {
        discoveryDone.await()
    }
}

class GattClient(
    private val viewModel: AppViewModel,
    bluetoothAdapter: BluetoothAdapter,
    context: Context,
    private val createIoClient: (packetIo: PacketIO) -> IoClient
) : Mode {
    private var connection: GattClientConnection =
        GattClientConnection(viewModel, bluetoothAdapter, context)
    private var clientThread: Thread? = null

    @SuppressLint("MissingPermission")
    override fun run() {
        viewModel.running = true

        clientThread = thread(name = "GattClient") {
            connection.connect()

            viewModel.aborter = {
                connection.disconnect()
            }

            // Discover the rx and tx characteristics
            connection.waitForDiscoveryCompletion()
            if (connection.rxCharacteristic == null || connection.txCharacteristic == null) {
                connection.disconnect()
                viewModel.running = false
                return@thread
            }

            val ioClient = createIoClient(connection)

            try {
                ioClient.run()
                viewModel.status = "OK"
            } catch (error: IOException) {
                Log.info("run ended abruptly")
                viewModel.status = "ABORTED"
                viewModel.lastError = "IO_ERROR"
            } finally {
                connection.disconnect()
                viewModel.running = false
            }
        }
    }

    override fun waitForCompletion() {
        clientThread?.join()
    }
}
