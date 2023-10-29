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

val DEFAULT_RFCOMM_UUID = UUID.fromString("0AF17D61-5DAE-4530-BE0D-6A8D54C3608B")
const val DEFAULT_PEER_BLUETOOTH_ADDRESS = "AA:BB:CC:DD:EE:FF"
const val DEFAULT_SENDER_PACKET_COUNT = 100
const val DEFAULT_SENDER_PACKET_SIZE = 1024

class AppViewModel : ViewModel() {
    private var preferences: SharedPreferences? = null
    var peerBluetoothAddress by mutableStateOf(DEFAULT_PEER_BLUETOOTH_ADDRESS)
    var l2capPsm by mutableStateOf(0)
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
        this.peerBluetoothAddress = peerBluetoothAddress

        // Save the address to the preferences
        with(preferences!!.edit()) {
            putString(PEER_BLUETOOTH_ADDRESS_PREF_KEY, peerBluetoothAddress)
            apply()
        }
    }

    fun updateSenderPacketCountSlider() {
        if (senderPacketCount <= 10) {
            senderPacketCountSlider = 0.0F
        } else if (senderPacketCount <= 50) {
            senderPacketCountSlider = 0.2F
        } else if (senderPacketCount <= 100) {
            senderPacketCountSlider = 0.4F
        } else if (senderPacketCount <= 500) {
            senderPacketCountSlider = 0.6F
        } else if (senderPacketCount <= 1000) {
            senderPacketCountSlider = 0.8F
        } else {
            senderPacketCountSlider = 1.0F
        }

        with(preferences!!.edit()) {
            putInt(SENDER_PACKET_COUNT_PREF_KEY, senderPacketCount)
            apply()
        }
    }

    fun updateSenderPacketCount() {
        if (senderPacketCountSlider < 0.2) {
            senderPacketCount = 10
        } else if (senderPacketCountSlider < 0.4) {
            senderPacketCount = 50
        } else if (senderPacketCountSlider < 0.6) {
            senderPacketCount = 100
        } else if (senderPacketCountSlider < 0.8) {
            senderPacketCount = 500
        } else if (senderPacketCountSlider < 1.0) {
            senderPacketCount = 1000
        } else {
            senderPacketCount = 10000
        }

        with(preferences!!.edit()) {
            putInt(SENDER_PACKET_COUNT_PREF_KEY, senderPacketCount)
            apply()
        }
    }

    fun updateSenderPacketSizeSlider() {
        if (senderPacketSize <= 1) {
            senderPacketSizeSlider = 0.0F
        } else if (senderPacketSize <= 256) {
            senderPacketSizeSlider = 0.02F
        } else if (senderPacketSize <= 512) {
            senderPacketSizeSlider = 0.4F
        } else if (senderPacketSize <= 1024) {
            senderPacketSizeSlider = 0.6F
        } else if (senderPacketSize <= 2048) {
            senderPacketSizeSlider = 0.8F
        } else {
            senderPacketSizeSlider = 1.0F
        }

        with(preferences!!.edit()) {
            putInt(SENDER_PACKET_SIZE_PREF_KEY, senderPacketSize)
            apply()
        }
    }

    fun updateSenderPacketSize() {
        if (senderPacketSizeSlider < 0.2) {
            senderPacketSize = 1
        } else if (senderPacketSizeSlider < 0.4) {
            senderPacketSize = 256
        } else if (senderPacketSizeSlider < 0.6) {
            senderPacketSize = 512
        } else if (senderPacketSizeSlider < 0.8) {
            senderPacketSize = 1024
        } else if (senderPacketSizeSlider < 1.0) {
            senderPacketSize = 2048
        } else {
            senderPacketSize = 4096
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
