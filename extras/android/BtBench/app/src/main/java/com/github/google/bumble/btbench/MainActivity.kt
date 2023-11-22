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

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.github.google.bumble.btbench.ui.theme.BTBenchTheme
import java.util.logging.Logger

private val Log = Logger.getLogger("bumble.main-activity")

const val PEER_BLUETOOTH_ADDRESS_PREF_KEY = "peer_bluetooth_address"
const val SENDER_PACKET_COUNT_PREF_KEY = "sender_packet_count"
const val SENDER_PACKET_SIZE_PREF_KEY = "sender_packet_size"

class MainActivity : ComponentActivity() {
    private val appViewModel = AppViewModel()
    private var bluetoothAdapter: BluetoothAdapter? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        appViewModel.loadPreferences(getPreferences(Context.MODE_PRIVATE))
        checkPermissions()
    }

    private fun checkPermissions() {
        val neededPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT
            )
        } else {
            arrayOf(Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN)
        }
        val missingPermissions = neededPermissions.filter {
            ContextCompat.checkSelfPermission(baseContext, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isEmpty()) {
            start()
            return
        }

        val requestPermissionsLauncher = registerForActivityResult(
            ActivityResultContracts.RequestMultiplePermissions()
        ) { permissions ->
            permissions.entries.forEach {
                Log.info("permission: ${it.key} = ${it.value}")
            }
            val grantCount = permissions.count { it.value }
            if (grantCount == neededPermissions.size) {
                // We have all the permissions we need.
                start()
            } else {
                Log.warning("not all permissions granted")
            }
        }

        requestPermissionsLauncher.launch(missingPermissions.toTypedArray())
        return
    }

    @SuppressLint("MissingPermission")
    private fun initBluetooth() {
        val bluetoothManager = ContextCompat.getSystemService(this, BluetoothManager::class.java)
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null) {
            Log.warning("no bluetooth adapter")
            return
        }

        if (!bluetoothAdapter!!.isEnabled) {
            Log.warning("bluetooth not enabled")
            return
        }
    }

    private fun start() {
        initBluetooth()
        setContent {
            MainView(
                appViewModel,
                ::becomeDiscoverable,
                ::runRfcommClient,
                ::runRfcommServer,
                ::runL2capClient,
                ::runL2capServer
            )
        }

        // Process intent parameters, if any.
        intent.getStringExtra("peer-bluetooth-address")?.let {
            appViewModel.peerBluetoothAddress = it
        }
        val packetCount = intent.getIntExtra("packet-count", 0)
        if (packetCount > 0) {
            appViewModel.senderPacketCount = packetCount
        }
        appViewModel.updateSenderPacketCountSlider()
        val packetSize = intent.getIntExtra("packet-size", 0)
        if (packetSize > 0) {
            appViewModel.senderPacketSize = packetSize
        }
        appViewModel.updateSenderPacketSizeSlider()
        intent.getStringExtra("autostart")?.let {
            when (it) {
                "rfcomm-client" -> runRfcommClient()
                "rfcomm-server" -> runRfcommServer()
                "l2cap-client" -> runL2capClient()
                "l2cap-server" -> runL2capServer()
            }
        }
    }

    private fun runRfcommClient() {
        val rfcommClient = bluetoothAdapter?.let { RfcommClient(appViewModel, it) }
        rfcommClient?.run()
    }

    private fun runRfcommServer() {
        val rfcommServer = bluetoothAdapter?.let { RfcommServer(appViewModel, it) }
        rfcommServer?.run()
    }

    private fun runL2capClient() {
        val l2capClient = bluetoothAdapter?.let { L2capClient(appViewModel, it) }
        l2capClient?.run()
    }

    private fun runL2capServer() {
        val l2capServer = bluetoothAdapter?.let { L2capServer(appViewModel, it) }
        l2capServer?.run()
    }

    @SuppressLint("MissingPermission")
    fun becomeDiscoverable() {
        val discoverableIntent = Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE)
        discoverableIntent.putExtra(BluetoothAdapter.EXTRA_DISCOVERABLE_DURATION, 300)
        startActivity(discoverableIntent)
    }
}

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun MainView(
    appViewModel: AppViewModel,
    becomeDiscoverable: () -> Unit,
    runRfcommClient: () -> Unit,
    runRfcommServer: () -> Unit,
    runL2capClient: () -> Unit,
    runL2capServer: () -> Unit
) {
    BTBenchTheme {
        // A surface container using the 'background' color from the theme
        Surface(
            modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background
        ) {
            Column(modifier = Modifier.padding(horizontal = 16.dp)) {
                Text(
                    text = "Bumble Bench",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center
                )
                Divider()
                val keyboardController = LocalSoftwareKeyboardController.current
                TextField(label = {
                    Text(text = "Peer Bluetooth Address")
                },
                    value = appViewModel.peerBluetoothAddress,
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions.Default.copy(
                        keyboardType = KeyboardType.Ascii, imeAction = ImeAction.Done
                    ),
                    onValueChange = {
                        appViewModel.updatePeerBluetoothAddress(it)
                    },
                    keyboardActions = KeyboardActions(onDone = { keyboardController?.hide() })
                )
                Divider()
                TextField(label = {
                    Text(text = "L2CAP PSM")
                },
                    value = appViewModel.l2capPsm.toString(),
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions.Default.copy(
                        keyboardType = KeyboardType.Number,
                        imeAction = ImeAction.Done
                    ),
                    onValueChange = {
                        if (it.isNotEmpty()) {
                            val psm = it.toIntOrNull()
                            if (psm != null) {
                                appViewModel.l2capPsm = psm
                            }
                        }
                    },
                    keyboardActions = KeyboardActions(onDone = { keyboardController?.hide() }))
                Divider()
                Slider(
                    value = appViewModel.senderPacketCountSlider, onValueChange = {
                        appViewModel.senderPacketCountSlider = it
                        appViewModel.updateSenderPacketCount()
                    }, steps = 4
                )
                Text(text = "Packet Count: " + appViewModel.senderPacketCount.toString())
                Divider()
                Slider(
                    value = appViewModel.senderPacketSizeSlider, onValueChange = {
                        appViewModel.senderPacketSizeSlider = it
                        appViewModel.updateSenderPacketSize()
                    }, steps = 4
                )
                Text(text = "Packet Size: " + appViewModel.senderPacketSize.toString())
                Divider()
                ActionButton(
                    text = "Become Discoverable", onClick = becomeDiscoverable, true
                )
                Row() {
                    ActionButton(
                        text = "RFCOMM Client", onClick = runRfcommClient, !appViewModel.running
                    )
                    ActionButton(
                        text = "RFCOMM Server", onClick = runRfcommServer, !appViewModel.running
                    )
                }
                Row() {
                    ActionButton(
                        text = "L2CAP Client", onClick = runL2capClient, !appViewModel.running
                    )
                    ActionButton(
                        text = "L2CAP Server", onClick = runL2capServer, !appViewModel.running
                    )
                }
                Divider()
                Text(
                    text = "Packets Sent: ${appViewModel.packetsSent}"
                )
                Text(
                    text = "Packets Received: ${appViewModel.packetsReceived}"
                )
                Text(
                    text = "Throughput: ${appViewModel.throughput}"
                )
                Divider()
                ActionButton(
                    text = "Abort", onClick = appViewModel::abort, appViewModel.running
                )
            }
        }
    }
}

@Composable
fun ActionButton(text: String, onClick: () -> Unit, enabled: Boolean) {
    Button(onClick = onClick, enabled = enabled) {
        Text(text = text)
    }
}