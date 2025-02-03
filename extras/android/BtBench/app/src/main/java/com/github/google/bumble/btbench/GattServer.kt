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
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import androidx.core.content.ContextCompat
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.Semaphore
import java.util.logging.Logger
import kotlin.concurrent.thread
import kotlin.experimental.and

private val Log = Logger.getLogger("btbench.gatt-server")

@SuppressLint("MissingPermission")
class GattServer(
    private val viewModel: AppViewModel,
    private val bluetoothAdapter: BluetoothAdapter,
    context: Context,
    private val createIoClient: (packetIo: PacketIO) -> IoClient
) : Mode, PacketIO, BluetoothGattServerCallback() {
    override var packetSink: PacketSink? = null
    private val gattServer: BluetoothGattServer
    private val rxCharacteristic: BluetoothGattCharacteristic?
    private val txCharacteristic: BluetoothGattCharacteristic?
    private val notifySemaphore: Semaphore = Semaphore(1)
    private val ready: CountDownLatch = CountDownLatch(1)
    private var peerDevice: BluetoothDevice? = null
    private var clientThread: Thread? = null
    private var sinkQueue: LinkedBlockingQueue<Packet>? = null

    init {
        val bluetoothManager = ContextCompat.getSystemService(context, BluetoothManager::class.java)
        gattServer = bluetoothManager!!.openGattServer(context, this)
        val benchService = gattServer.getService(BENCH_SERVICE_UUID)
        if (benchService == null) {
            rxCharacteristic = BluetoothGattCharacteristic(
                BENCH_RX_UUID,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
                0
            )
            txCharacteristic = BluetoothGattCharacteristic(
                BENCH_TX_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE
            )
            val rxCCCD = BluetoothGattDescriptor(
                CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
            )
            rxCharacteristic.addDescriptor(rxCCCD)

            val service =
                BluetoothGattService(BENCH_SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
            service.addCharacteristic(rxCharacteristic)
            service.addCharacteristic(txCharacteristic)

            gattServer.addService(service)
        } else {
            rxCharacteristic = benchService.getCharacteristic(BENCH_RX_UUID)
            txCharacteristic = benchService.getCharacteristic(BENCH_TX_UUID)
        }
    }

    override fun onCharacteristicWriteRequest(
        device: BluetoothDevice?,
        requestId: Int,
        characteristic: BluetoothGattCharacteristic?,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray?
    ) {
        Log.info("onCharacteristicWriteRequest")
        if (characteristic != null && characteristic.uuid == BENCH_TX_UUID) {
            if (packetSink == null) {
                Log.warning("no sink, dropping")
            } else if (offset != 0) {
                Log.warning("offset != 0")
            } else if (value == null) {
                Log.warning("no value")
            } else {
                // Deliver the packet in a separate thread so that we don't block this
                // callback.
                sinkQueue?.put(Packet.from(value))
            }
        }

        if (responseNeeded) {
            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
        }
    }

    override fun onNotificationSent(device: BluetoothDevice?, status: Int) {
        if (status == BluetoothGatt.GATT_SUCCESS) {
            notifySemaphore.release()
        }
    }

    override fun onDescriptorWriteRequest(
        device: BluetoothDevice?,
        requestId: Int,
        descriptor: BluetoothGattDescriptor?,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray?
    ) {
        if (descriptor?.uuid == CCCD_UUID && descriptor?.characteristic?.uuid == BENCH_RX_UUID) {
            if (offset == 0 && value?.size == 2) {
                if (value[0].and(1).toInt() != 0) {
                    // Subscription
                    Log.fine("peer subscribed to RX")
                    peerDevice = device
                    ready.countDown()
                }
            }
        }

        if (responseNeeded) {
            gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
        }
    }

    @SuppressLint("MissingPermission")
    override fun sendPacket(packet: Packet) {
        if (peerDevice == null) {
            Log.warning("no peer device, cannot send")
            return
        }
        if (rxCharacteristic == null) {
            Log.warning("no RX characteristic, cannot send")
            return
        }

        // Wait until we can notify
        notifySemaphore.acquire()

        // Send the packet via a notification
        val result = gattServer.notifyCharacteristicChanged(
            peerDevice!!,
            rxCharacteristic,
            false,
            packet.toBytes()
        )
        if (result != BluetoothStatusCodes.SUCCESS) {
            Log.warning("notifyCharacteristicChanged failed: $result")
            notifySemaphore.release()
        }
    }

    override fun run() {
        viewModel.running = true

        // Start advertising
        Log.fine("starting advertiser")
        val advertiser = Advertiser(bluetoothAdapter)
        advertiser.start()

        clientThread = thread(name = "GattServer") {
            // Wait for a subscriber
            Log.info("waiting for RX subscriber")
            viewModel.aborter = {
                ready.countDown()
            }
            ready.await()
            if (peerDevice == null) {
                Log.warning("server interrupted")
                viewModel.running = false
                gattServer.close()
                return@thread
            }
            Log.info("RX subscriber accepted")

            // Stop advertising
            Log.info("stopping advertiser")
            advertiser.stop()

            sinkQueue = LinkedBlockingQueue()
            val sinkWriterThread = thread(name = "SinkWriter") {
                while (true) {
                    try {
                        val packet = sinkQueue!!.take()
                        if (packetSink == null) {
                            Log.warning("no sink, dropping packet")
                            continue
                        }
                        packetSink!!.onPacket(packet)
                    } catch (error: InterruptedException) {
                        Log.warning("sink writer interrupted")
                        break
                    }
                }
            }

            val ioClient = createIoClient(this)

            try {
                ioClient.run()
                viewModel.status = "OK"
            } catch (error: IOException) {
                Log.info("run ended abruptly")
                viewModel.status = "ABORTED"
                viewModel.lastError = "IO_ERROR"
            } finally {
                sinkWriterThread.interrupt()
                sinkWriterThread.join()
                gattServer.close()
                viewModel.running = false
            }
        }
    }

    override fun waitForCompletion() {
        clientThread?.join()
        Log.info("server thread completed")
    }
}