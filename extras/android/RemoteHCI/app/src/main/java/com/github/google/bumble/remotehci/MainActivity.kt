package com.github.google.bumble.remotehci

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import com.github.google.bumble.remotehci.HciProxy.HalException
import com.github.google.bumble.remotehci.ui.theme.RemoteHCITheme
import java.io.IOException
import java.util.logging.Logger
import kotlin.concurrent.thread

const val DEFAULT_TCP_PORT = 9993
const val TCP_PORT_PREF_KEY = "tcp_port"

class AppViewModel : ViewModel(), HciProxy.Listener {
    private var preferences: SharedPreferences? = null
    var tcpPort by mutableStateOf(DEFAULT_TCP_PORT)
    var canStart by mutableStateOf(true)
    var message by mutableStateOf("")
    var hostConnected by mutableStateOf(false)
    var hciCommandPacketsReceived by mutableStateOf(0)
    var hciAclPacketsReceived by mutableStateOf(0)
    var hciScoPacketsReceived by mutableStateOf(0)
    var hciEventPacketsSent by mutableStateOf(0)
    var hciAclPacketsSent by mutableStateOf(0)
    var hciScoPacketsSent by mutableStateOf(0)

    fun loadPreferences(preferences: SharedPreferences) {
        this.preferences = preferences
        val savedTcpPortString = preferences.getString(TCP_PORT_PREF_KEY, null)
        if (savedTcpPortString != null) {
            val savedTcpPortInt = savedTcpPortString.toIntOrNull()
            if (savedTcpPortInt != null) {
                tcpPort = savedTcpPortInt
            }
        }
    }

    fun updateTcpPort(tcpPort: Int) {
        this.tcpPort = tcpPort

        // Save the port to the preferences
        with (preferences!!.edit()) {
            putString(TCP_PORT_PREF_KEY, tcpPort.toString())
            apply()
        }
    }

    override fun onHostConnectionState(connected: Boolean) {
        hostConnected = connected
    }

    override fun onHciPacketCountChange(
        commandPacketsReceived: Int,
        aclPacketsReceived: Int,
        scoPacketsReceived: Int,
        eventPacketsSent: Int,
        aclPacketsSent: Int,
        scoPacketsSent: Int
    ) {
        hciCommandPacketsReceived = commandPacketsReceived
        hciAclPacketsReceived = aclPacketsReceived
        hciScoPacketsReceived = scoPacketsReceived
        hciEventPacketsSent = eventPacketsSent
        hciAclPacketsSent = aclPacketsSent
        hciScoPacketsSent = scoPacketsSent

    }

    override fun onMessage(message: String) {
        this.message = message
    }
}

class MainActivity : ComponentActivity() {
    private val log = Logger.getLogger(MainActivity::class.java.name)
    private val appViewModel = AppViewModel()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        appViewModel.loadPreferences(getPreferences(Context.MODE_PRIVATE))

        val tcpPort = intent.getIntExtra("port", -1)
        if (tcpPort >= 0) {
            appViewModel.tcpPort = tcpPort
        }

        setContent {
            MainView(appViewModel, ::startProxy)
        }

        if (intent.getBooleanExtra("autostart", false)) {
            startProxy()
        }
    }

    private fun startProxy() {
        // Run the proxy in a thread.
        appViewModel.message = ""
        thread {
            log.info("HCI Proxy thread starting")
            appViewModel.canStart = false
            try {
                val hciProxy = HciProxy(appViewModel.tcpPort, appViewModel)
                hciProxy.run()
            } catch (error: IOException) {
                log.warning("Exception while running HCI Server: $error")
            } catch (error: HalException) {
                log.warning("HAL exception: ${error.message}")
                appViewModel.message = "Cannot bind to HAL (${error.message}). You may need to use the command 'setenforce 0' in a root adb shell."
            }
            log.info("HCI Proxy thread ended")
            appViewModel.canStart = true
        }
    }
}

@Composable
fun ActionButton(text: String, onClick: () -> Unit, enabled: Boolean) {
    Button(onClick = onClick, enabled = enabled) {
        Text(text = text)
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalComposeUiApi::class)
@Composable
fun MainView(appViewModel: AppViewModel, startProxy: () -> Unit) {
    RemoteHCITheme {
        // A surface container using the 'background' color from the theme
        Surface(
            modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background
        ) {
            Column(modifier = Modifier.padding(horizontal = 16.dp)) {
                Text(
                    text = "Bumble Remote HCI",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center
                )
                Divider()
                Text(
                    text = appViewModel.message
                )
                Divider()
                val keyboardController = LocalSoftwareKeyboardController.current
                TextField(
                    label = {
                        Text(text = "TCP Port")
                    },
                    value = appViewModel.tcpPort.toString(),
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions.Default.copy(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done),
                    onValueChange = {
                        if (it.isNotEmpty()) {
                            val tcpPort = it.toIntOrNull()
                            if (tcpPort != null) {
                                appViewModel.updateTcpPort(tcpPort)
                            }
                        }
                    },
                    keyboardActions = KeyboardActions(
                        onDone = {keyboardController?.hide()}
                    )
                )
                Divider()
                val connectState = if (appViewModel.hostConnected) "CONNECTED" else "DISCONNECTED"
                Text(
                    text = "HOST: $connectState",
                    modifier = Modifier.background(color = if (appViewModel.hostConnected) Color.Green else Color.Red),
                    color = Color.Black
                )
                Divider()
                Text(
                    text = "Command Packets Received: ${appViewModel.hciCommandPacketsReceived}"
                )
                Text(
                    text = "ACL Packets Received: ${appViewModel.hciAclPacketsReceived}"
                )
                Text(
                    text = "SCO Packets Received: ${appViewModel.hciScoPacketsReceived}"
                )
                Text(
                    text = "Event Packets Sent: ${appViewModel.hciEventPacketsSent}"
                )
                Text(
                    text = "ACL Packets Sent: ${appViewModel.hciAclPacketsSent}"
                )
                Text(
                    text = "SCO Packets Sent: ${appViewModel.hciScoPacketsSent}"
                )
                Divider()
                ActionButton(
                    text = "Start", onClick = startProxy, enabled = appViewModel.canStart
                )
            }
        }
    }
}