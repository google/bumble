package com.github.google.bumble.btbench

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import java.util.logging.Logger

private val Log = Logger.getLogger("btbench.scan")

class Scan(val bluetoothAdapter: BluetoothAdapter) {
    @SuppressLint("MissingPermission")
    fun run(startScan: Boolean) {
        var bluetoothLeScanner = bluetoothAdapter.bluetoothLeScanner

        val scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult?) {
                super.onScanResult(callbackType, result)
                val device: BluetoothDevice? = result?.device
                val deviceName = device?.name ?: "Unknown"
                val deviceAddress = device?.address ?: "Unknown"
                Log.info("Device found: $deviceName ($deviceAddress)")
            }

            override fun onScanFailed(errorCode: Int) {
                // Handle scan failure
                Log.warning("Scan failed with error code: $errorCode")
            }
        }

        if (startScan) {
            bluetoothLeScanner?.startScan(scanCallback)
        } else {
            bluetoothLeScanner?.stopScan(scanCallback)
        }
    }
}
