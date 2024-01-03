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

import android.content.SharedPreferences
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import java.util.UUID

val DEFAULT_RFCOMM_UUID: UUID = UUID.fromString("E6D55659-C8B4-4B85-96BB-B1143AF6D3AE")
const val DEFAULT_PEER_BLUETOOTH_ADDRESS = "AA:BB:CC:DD:EE:FF"
const val DEFAULT_SENDER_PACKET_COUNT = 100
const val DEFAULT_SENDER_PACKET_SIZE = 1024
const val DEFAULT_PSM = 128

class AppViewModel : ViewModel() {
    private var preferences: SharedPreferences? = null
    var peerBluetoothAddress by mutableStateOf(DEFAULT_PEER_BLUETOOTH_ADDRESS)
    var l2capPsm by mutableIntStateOf(DEFAULT_PSM)
    var use2mPhy by mutableStateOf(true)
    var mtu by mutableIntStateOf(0)
    var rxPhy by mutableIntStateOf(0)
    var txPhy by mutableIntStateOf(0)
    var senderPacketCountSlider by mutableFloatStateOf(0.0F)
    var senderPacketSizeSlider by mutableFloatStateOf(0.0F)
    var senderPacketCount by mutableIntStateOf(DEFAULT_SENDER_PACKET_COUNT)
    var senderPacketSize by mutableIntStateOf(DEFAULT_SENDER_PACKET_SIZE)
    var packetsSent by mutableIntStateOf(0)
    var packetsReceived by mutableIntStateOf(0)
    var throughput by mutableIntStateOf(0)
    var running by mutableStateOf(false)
    var aborter: (() -> Unit)? = null

    fun loadPreferences(preferences: SharedPreferences) {
        this.preferences = preferences

        val savedPeerBluetoothAddress = preferences.getString(PEER_BLUETOOTH_ADDRESS_PREF_KEY, null)
        if (savedPeerBluetoothAddress != null) {
            peerBluetoothAddress = savedPeerBluetoothAddress
        }

        val savedSenderPacketCount = preferences.getInt(SENDER_PACKET_COUNT_PREF_KEY, 0)
        if (savedSenderPacketCount != 0) {
            senderPacketCount = savedSenderPacketCount
        }
        updateSenderPacketCountSlider()

        val savedSenderPacketSize = preferences.getInt(SENDER_PACKET_SIZE_PREF_KEY, 0)
        if (savedSenderPacketSize != 0) {
            senderPacketSize = savedSenderPacketSize
        }
        updateSenderPacketSizeSlider()
    }

    fun updatePeerBluetoothAddress(peerBluetoothAddress: String) {
        val address = peerBluetoothAddress.uppercase()
        this.peerBluetoothAddress = address

        // Save the address to the preferences
        with(preferences!!.edit()) {
            putString(PEER_BLUETOOTH_ADDRESS_PREF_KEY, address)
            apply()
        }
    }

    fun updateSenderPacketCountSlider() {
        senderPacketCountSlider = if (senderPacketCount <= 10) {
            0.0F
        } else if (senderPacketCount <= 50) {
            0.2F
        } else if (senderPacketCount <= 100) {
            0.4F
        } else if (senderPacketCount <= 500) {
            0.6F
        } else if (senderPacketCount <= 1000) {
            0.8F
        } else {
            1.0F
        }

        with(preferences!!.edit()) {
            putInt(SENDER_PACKET_COUNT_PREF_KEY, senderPacketCount)
            apply()
        }
    }

    fun updateSenderPacketCount() {
        senderPacketCount = if (senderPacketCountSlider < 0.1F) {
            10
        } else if (senderPacketCountSlider < 0.3F) {
            50
        } else if (senderPacketCountSlider < 0.5F) {
            100
        } else if (senderPacketCountSlider < 0.7F) {
            500
        } else if (senderPacketCountSlider < 0.9F) {
            1000
        } else {
            10000
        }

        with(preferences!!.edit()) {
            putInt(SENDER_PACKET_COUNT_PREF_KEY, senderPacketCount)
            apply()
        }
    }

    fun updateSenderPacketSizeSlider() {
        senderPacketSizeSlider = if (senderPacketSize <= 16) {
            0.0F
        } else if (senderPacketSize <= 256) {
            0.02F
        } else if (senderPacketSize <= 512) {
            0.4F
        } else if (senderPacketSize <= 1024) {
            0.6F
        } else if (senderPacketSize <= 2048) {
            0.8F
        } else {
            1.0F
        }

        with(preferences!!.edit()) {
            putInt(SENDER_PACKET_SIZE_PREF_KEY, senderPacketSize)
            apply()
        }
    }

    fun updateSenderPacketSize() {
        senderPacketSize = if (senderPacketSizeSlider < 0.1F) {
            16
        } else if (senderPacketSizeSlider < 0.3F) {
            256
        } else if (senderPacketSizeSlider < 0.5F) {
            512
        } else if (senderPacketSizeSlider < 0.7F) {
            1024
        } else if (senderPacketSizeSlider < 0.9F) {
            2048
        } else {
            4096
        }

        with(preferences!!.edit()) {
            putInt(SENDER_PACKET_SIZE_PREF_KEY, senderPacketSize)
            apply()
        }
    }

    fun abort() {
        aborter?.let { it() }
    }
}
