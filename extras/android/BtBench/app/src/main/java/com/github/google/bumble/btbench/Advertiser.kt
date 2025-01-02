package com.github.google.bumble.btbench

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY
import android.os.Build
import java.util.logging.Logger

private val Log = Logger.getLogger("btbench.advertiser")

class Advertiser(private val bluetoothAdapter: BluetoothAdapter) : AdvertiseCallback() {
    @SuppressLint("MissingPermission")
    fun start() {
        val advertiseSettingsBuilder = AdvertiseSettings.Builder()
            .setAdvertiseMode(ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
        advertiseSettingsBuilder.setDiscoverable(true)
        val advertiseSettings = advertiseSettingsBuilder.build()
        val advertiseData = AdvertiseData.Builder().build()
        val scanData = AdvertiseData.Builder().setIncludeDeviceName(true).build()
        bluetoothAdapter.bluetoothLeAdvertiser.startAdvertising(advertiseSettings, advertiseData, scanData, this)
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        bluetoothAdapter.bluetoothLeAdvertiser.stopAdvertising(this)
    }

    override fun onStartFailure(errorCode: Int) {
        Log.warning("failed to start advertising: $errorCode")
    }

    override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
        Log.info("advertising started: $settingsInEffect")
    }
}