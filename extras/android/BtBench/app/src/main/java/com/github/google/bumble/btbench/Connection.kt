package com.github.google.bumble.btbench

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import androidx.core.content.ContextCompat
import java.util.logging.Logger

private val Log = Logger.getLogger("btbench.connection")

open class Connection(
    private val viewModel: AppViewModel,
    private val bluetoothAdapter: BluetoothAdapter,
    private val context: Context
) : BluetoothGattCallback() {
    var remoteDevice: BluetoothDevice? = null
    var gatt: BluetoothGatt? = null

    @SuppressLint("MissingPermission")
    open fun connect() {
        val addressIsPublic = viewModel.peerBluetoothAddress.endsWith("/P")
        val address = viewModel.peerBluetoothAddress.take(17)
        remoteDevice = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            bluetoothAdapter.getRemoteLeDevice(
                address,
                if (addressIsPublic) {
                    BluetoothDevice.ADDRESS_TYPE_PUBLIC
                } else {
                    BluetoothDevice.ADDRESS_TYPE_RANDOM
                }
            )
        } else {
            bluetoothAdapter.getRemoteDevice(address)
        }

        gatt = remoteDevice?.connectGatt(
            context,
            false,
            this,
            BluetoothDevice.TRANSPORT_LE,
            if (viewModel.use2mPhy) BluetoothDevice.PHY_LE_2M_MASK else BluetoothDevice.PHY_LE_1M_MASK
        )
    }

    @SuppressLint("MissingPermission")
    open fun disconnect() {
        gatt?.disconnect()
    }

    override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
        Log.info("MTU update: mtu=$mtu status=$status")
        viewModel.mtu = mtu
    }

    override fun onPhyUpdate(gatt: BluetoothGatt, txPhy: Int, rxPhy: Int, status: Int) {
        Log.info("PHY update: tx=$txPhy, rx=$rxPhy, status=$status")
        viewModel.txPhy = txPhy
        viewModel.rxPhy = rxPhy
    }

    override fun onPhyRead(gatt: BluetoothGatt, txPhy: Int, rxPhy: Int, status: Int) {
        Log.info("PHY: tx=$txPhy, rx=$rxPhy, status=$status")
        viewModel.txPhy = txPhy
        viewModel.rxPhy = rxPhy
    }

    @SuppressLint("MissingPermission")
    override fun onConnectionStateChange(
        gatt: BluetoothGatt?, status: Int, newState: Int
    ) {
        if (status != BluetoothGatt.GATT_SUCCESS) {
            Log.warning("onConnectionStateChange status=$status")
        }

        if (gatt != null && newState == BluetoothProfile.STATE_CONNECTED) {
            if (viewModel.use2mPhy) {
                Log.info("requesting 2M PHY")
                gatt.setPreferredPhy(
                    BluetoothDevice.PHY_LE_2M_MASK,
                    BluetoothDevice.PHY_LE_2M_MASK,
                    BluetoothDevice.PHY_OPTION_NO_PREFERRED
                )
            }
            gatt.readPhy()

            // Request an MTU update, even though we don't use GATT, because Android
            // won't request a larger link layer maximum data length otherwise.
            gatt.requestMtu(517)

            // Request a specific connection priority
            val connectionPriority = when (viewModel.connectionPriority) {
                "BALANCED" -> BluetoothGatt.CONNECTION_PRIORITY_BALANCED
                "LOW_POWER" -> BluetoothGatt.CONNECTION_PRIORITY_LOW_POWER
                "HIGH" -> BluetoothGatt.CONNECTION_PRIORITY_HIGH
                "DCK" -> BluetoothGatt.CONNECTION_PRIORITY_DCK
                else -> 0
            }
            if (!gatt.requestConnectionPriority(connectionPriority)) {
                Log.warning("requestConnectionPriority failed")
            }
        }
    }
}