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
const val DEFAULT_STARTUP_DELAY = 3000
const val DEFAULT_SENDER_PACKET_COUNT = 100
const val DEFAULT_SENDER_PACKET_SIZE = 1024
const val DEFAULT_SENDER_PACKET_INTERVAL = 100
const val DEFAULT_PSM = 128

const val L2CAP_CLIENT_MODE = "L2CAP Client"
const val L2CAP_SERVER_MODE = "L2CAP Server"
const val RFCOMM_CLIENT_MODE = "RFCOMM Client"
const val RFCOMM_SERVER_MODE = "RFCOMM Server"
const val GATT_CLIENT_MODE = "GATT Client"
const val GATT_SERVER_MODE = "GATT Server"

const val SEND_SCENARIO = "Send"
const val RECEIVE_SCENARIO = "Receive"
const val PING_SCENARIO = "Ping"
const val PONG_SCENARIO = "Pong"

class AppViewModel : ViewModel() {
    private var preferences: SharedPreferences? = null
    var status by mutableStateOf("")
    var lastError by mutableStateOf("")
    var mode by mutableStateOf(RFCOMM_SERVER_MODE)
    var scenario by mutableStateOf(RECEIVE_SCENARIO)
    var peerBluetoothAddress by mutableStateOf(DEFAULT_PEER_BLUETOOTH_ADDRESS)
    var startupDelay by mutableIntStateOf(DEFAULT_STARTUP_DELAY)
    var l2capPsm by mutableIntStateOf(DEFAULT_PSM)
    var use2mPhy by mutableStateOf(true)
    var connectionPriority by mutableStateOf("BALANCED")
    var mtu by mutableIntStateOf(0)
    var rxPhy by mutableIntStateOf(0)
    var txPhy by mutableIntStateOf(0)
    var senderPacketCountSlider by mutableFloatStateOf(0.0F)
    var senderPacketSizeSlider by mutableFloatStateOf(0.0F)
    var senderPacketCount by mutableIntStateOf(DEFAULT_SENDER_PACKET_COUNT)
    var senderPacketSize by mutableIntStateOf(DEFAULT_SENDER_PACKET_SIZE)
    var senderPacketInterval by mutableIntStateOf(DEFAULT_SENDER_PACKET_INTERVAL)
    var packetsSent by mutableIntStateOf(0)
    var packetsReceived by mutableIntStateOf(0)
    var throughput by mutableIntStateOf(0)
    var stats by mutableStateOf("")
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

        val savedSenderPacketInterval = preferences.getInt(SENDER_PACKET_INTERVAL_PREF_KEY, -1)
        if (savedSenderPacketInterval != -1) {
            senderPacketInterval = savedSenderPacketInterval
        }

        val savedMode = preferences.getString(MODE_PREF_KEY, null)
        if (savedMode != null) {
            mode = savedMode
        }

        val savedScenario = preferences.getString(SCENARIO_PREF_KEY, null)
        if (savedScenario != null) {
            scenario = savedScenario
        }

        val savedConnectionPriority = preferences.getString(CONNECTION_PRIORITY_PREF_KEY, null)
        if (savedConnectionPriority != null) {
            connectionPriority = savedConnectionPriority
        }
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
            // 970 is a value that works well on Android.
            970
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

    fun updateSenderPacketInterval(senderPacketInterval: Int) {
        this.senderPacketInterval = senderPacketInterval
        with(preferences!!.edit()) {
            putInt(SENDER_PACKET_INTERVAL_PREF_KEY, senderPacketInterval)
            apply()
        }
    }

    fun updateScenario(scenario: String) {
        this.scenario = scenario
        with(preferences!!.edit()) {
            putString(SCENARIO_PREF_KEY, scenario)
            apply()
        }
    }

    fun updateMode(mode: String) {
        this.mode = mode
        with(preferences!!.edit()) {
            putString(MODE_PREF_KEY, mode)
            apply()
        }
    }

    fun updateConnectionPriority(connectionPriority: String) {
        this.connectionPriority = connectionPriority
        with(preferences!!.edit()) {
            putString(CONNECTION_PRIORITY_PREF_KEY, connectionPriority)
            apply()
        }
    }

    fun clear() {
        status = ""
        lastError = ""
        mtu = 0
        rxPhy = 0
        txPhy = 0
        packetsSent = 0
        packetsReceived = 0
        throughput = 0
        stats = ""
    }

    fun abort() {
        aborter?.let { it() }
    }
}
