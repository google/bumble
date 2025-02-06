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

package com.github.google.bumble.btbench;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.Context;

import androidx.test.core.app.ApplicationProvider;

import com.google.android.mobly.snippet.Snippet;
import com.google.android.mobly.snippet.rpc.Rpc;
import com.google.android.mobly.snippet.rpc.RpcOptional;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.UUID;

class Runner {
    public UUID mId;
    private final Mode mMode;
    private final String mModeName;
    private final String mScenario;
    private final AppViewModel mModel;

    Runner(Mode mode, String modeName, String scenario, AppViewModel model) {
        this.mId = UUID.randomUUID();
        this.mMode = mode;
        this.mModeName = modeName;
        this.mScenario = scenario;
        this.mModel = model;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject result = new JSONObject();
        result.put("id", mId.toString());
        result.put("mode", mModeName);
        result.put("scenario", mScenario);
        result.put("model", AutomationSnippet.modelToJson(mModel));

        return result;
    }

    public void stop() {
        mModel.abort();
    }

    public void waitForCompletion() {
        mMode.waitForCompletion();
    }
}

public class AutomationSnippet implements Snippet {
    private static final String TAG = "btbench.snippet";
    private final BluetoothAdapter mBluetoothAdapter;
    private final Context mContext;
    private final ArrayList<Runner> mRunners = new ArrayList<>();

    public AutomationSnippet() throws IOException {
        mContext = ApplicationProvider.getApplicationContext();
        BluetoothManager bluetoothManager = mContext.getSystemService(BluetoothManager.class);
        mBluetoothAdapter = bluetoothManager.getAdapter();
        if (mBluetoothAdapter == null) {
            throw new IOException("bluetooth not supported");
        }
        if (!mBluetoothAdapter.isEnabled()) {
            throw new IOException("bluetooth not enabled");
        }
    }

    private Runner runScenario(AppViewModel model, String mode, String scenario) {
        Mode runnable;
        switch (mode) {
            case "rfcomm-client":
                runnable = new RfcommClient(model, mBluetoothAdapter,
                                            (PacketIO packetIO) -> createIoClient(model, scenario,
                                                                                  packetIO));
                break;

            case "rfcomm-server":
                runnable = new RfcommServer(model, mBluetoothAdapter,
                                            (PacketIO packetIO) -> createIoClient(model, scenario,
                                                                                  packetIO));
                break;

            case "l2cap-client":
                runnable = new L2capClient(model, mBluetoothAdapter, mContext,
                                           (PacketIO packetIO) -> createIoClient(model, scenario,
                                                                                 packetIO));
                break;

            case "l2cap-server":
                runnable = new L2capServer(model, mBluetoothAdapter,
                                           (PacketIO packetIO) -> createIoClient(model, scenario,
                                                                                 packetIO));
                break;

            case "gatt-client":
                runnable = new GattClient(model, mBluetoothAdapter, mContext,
                                          (PacketIO packetIO) -> createIoClient(model, scenario,
                                                                                packetIO));
                break;

            case "gatt-server":
                runnable = new GattServer(model, mBluetoothAdapter, mContext,
                                          (PacketIO packetIO) -> createIoClient(model, scenario,
                                                                                packetIO));
                break;

            default:
                return null;
        }

        model.setMode(mode);
        model.setScenario(scenario);
        runnable.run();
        Runner runner = new Runner(runnable, mode, scenario, model);
        mRunners.add(runner);
        return runner;
    }

    private IoClient createIoClient(AppViewModel model, String scenario, PacketIO packetIO) {
        switch (scenario) {
            case "send":
                return new Sender(model, packetIO);

            case "receive":
                return new Receiver(model, packetIO);

            case "ping":
                return new Pinger(model, packetIO);

            case "pong":
                return new Ponger(model, packetIO);

            default:
                return null;
        }
    }

    public static JSONObject modelToJson(AppViewModel model) throws JSONException {
        JSONObject result = new JSONObject();
        result.put("status", model.getStatus());
        result.put("running", model.getRunning());
        result.put("peer_bluetooth_address", model.getPeerBluetoothAddress());
        result.put("mode", model.getMode());
        result.put("scenario", model.getScenario());
        result.put("sender_packet_size", model.getSenderPacketSize());
        result.put("sender_packet_count", model.getSenderPacketCount());
        result.put("sender_packet_interval", model.getSenderPacketInterval());
        result.put("packets_sent", model.getPacketsSent());
        result.put("packets_received", model.getPacketsReceived());
        result.put("l2cap_psm", model.getL2capPsm());
        result.put("use_2m_phy", model.getUse2mPhy());
        result.put("connection_priority", model.getConnectionPriority());
        result.put("mtu", model.getMtu());
        result.put("rx_phy", model.getRxPhy());
        result.put("tx_phy", model.getTxPhy());
        result.put("startup_delay", model.getStartupDelay());
        if (model.getStatus().equals("OK")) {
            JSONObject stats = new JSONObject();
            result.put("stats", stats);
            stats.put("throughput", model.getThroughput());
            JSONObject rttStats = new JSONObject();
            stats.put("rtt", rttStats);
            rttStats.put("compound", model.getStats());
        } else {
            result.put("last_error", model.getLastError());
        }

        return result;
    }

    private Runner findRunner(String runnerId) {
        for (Runner runner : mRunners) {
            if (runner.mId.toString().equals(runnerId)) {
                return runner;
            }
        }

        return null;
    }

    @Rpc(description = "Run a scenario in RFComm Client mode")
    public JSONObject runRfcommClient(String scenario, String peerBluetoothAddress, int packetCount,
                                      int packetSize, int packetInterval,
                                      @RpcOptional Integer startupDelay) throws JSONException {
        // We only support "send" and "ping" for this mode for now
        if (!(scenario.equals("send") || scenario.equals("ping"))) {
            throw new InvalidParameterException(
                    "only 'send' and 'ping' are supported for this mode");
        }

        AppViewModel model = new AppViewModel();
        model.setPeerBluetoothAddress(peerBluetoothAddress);
        model.setSenderPacketCount(packetCount);
        model.setSenderPacketSize(packetSize);
        model.setSenderPacketInterval(packetInterval);
        if (startupDelay != null) {
            model.setStartupDelay(startupDelay);
        }

        Runner runner = runScenario(model, "rfcomm-client", scenario);
        assert runner != null;
        return runner.toJson();
    }

    @Rpc(description = "Run a scenario in RFComm Server mode")
    public JSONObject runRfcommServer(String scenario,
                                      @RpcOptional Integer startupDelay) throws JSONException {
        // We only support "receive" and "pong" for this mode for now
        if (!(scenario.equals("receive") || scenario.equals("pong"))) {
            throw new InvalidParameterException(
                    "only 'receive' and 'pong' are supported for this mode");
        }

        AppViewModel model = new AppViewModel();
        if (startupDelay != null) {
            model.setStartupDelay(startupDelay);
        }

        Runner runner = runScenario(model, "rfcomm-server", scenario);
        assert runner != null;
        return runner.toJson();
    }

    @Rpc(description = "Run a scenario in L2CAP Client mode")
    public JSONObject runL2capClient(String scenario, String peerBluetoothAddress, int psm,
                                     boolean use_2m_phy, int packetCount, int packetSize,
                                     int packetInterval, @RpcOptional String connectionPriority,
                                     @RpcOptional Integer startupDelay) throws JSONException {
        // We only support "send" and "ping" for this mode for now
        if (!(scenario.equals("send") || scenario.equals("ping"))) {
            throw new InvalidParameterException(
                    "only 'send' and 'ping' are supported for this mode");
        }

        AppViewModel model = new AppViewModel();
        model.setPeerBluetoothAddress(peerBluetoothAddress);
        model.setL2capPsm(psm);
        model.setUse2mPhy(use_2m_phy);
        model.setSenderPacketCount(packetCount);
        model.setSenderPacketSize(packetSize);
        model.setSenderPacketInterval(packetInterval);
        if (connectionPriority != null) {
            model.setConnectionPriority(connectionPriority);
        }
        if (startupDelay != null) {
            model.setStartupDelay(startupDelay);
        }
        Runner runner = runScenario(model, "l2cap-client", scenario);
        assert runner != null;
        return runner.toJson();
    }

    @Rpc(description = "Run a scenario in L2CAP Server mode")
    public JSONObject runL2capServer(String scenario,
                                     @RpcOptional Integer startupDelay) throws JSONException {
        // We only support "receive" and "pong" for this mode for now
        if (!(scenario.equals("receive") || scenario.equals("pong"))) {
            throw new InvalidParameterException(
                    "only 'receive' and 'pong' are supported for this mode");
        }

        AppViewModel model = new AppViewModel();
        if (startupDelay != null) {
            model.setStartupDelay(startupDelay);
        }

        Runner runner = runScenario(model, "l2cap-server", scenario);
        assert runner != null;
        return runner.toJson();
    }

    @Rpc(description = "Run a scenario in GATT Client mode")
    public JSONObject runGattClient(String scenario, String peerBluetoothAddress,
                                    boolean use_2m_phy, int packetCount, int packetSize,
                                    int packetInterval, @RpcOptional String connectionPriority,
                                    @RpcOptional Integer startupDelay) throws JSONException {
        // We only support "send" and "ping" for this mode for now
        if (!(scenario.equals("send") || scenario.equals("ping"))) {
            throw new InvalidParameterException(
                    "only 'send' and 'ping' are supported for this mode");
        }

        AppViewModel model = new AppViewModel();
        model.setPeerBluetoothAddress(peerBluetoothAddress);
        model.setUse2mPhy(use_2m_phy);
        model.setSenderPacketCount(packetCount);
        model.setSenderPacketSize(packetSize);
        model.setSenderPacketInterval(packetInterval);
        if (connectionPriority != null) {
            model.setConnectionPriority(connectionPriority);
        }
        if (startupDelay != null) {
            model.setStartupDelay(startupDelay);
        }
        Runner runner = runScenario(model, "gatt-client", scenario);
        assert runner != null;
        return runner.toJson();
    }

    @Rpc(description = "Run a scenario in GATT Server mode")
    public JSONObject runGattServer(String scenario,
                                    @RpcOptional Integer startupDelay) throws JSONException {
        // We only support "receive" and "pong" for this mode for now
        if (!(scenario.equals("receive") || scenario.equals("pong"))) {
            throw new InvalidParameterException(
                    "only 'receive' and 'pong' are supported for this mode");
        }

        AppViewModel model = new AppViewModel();
        if (startupDelay != null) {
            model.setStartupDelay(startupDelay);
        }

        Runner runner = runScenario(model, "gatt-server", scenario);
        assert runner != null;
        return runner.toJson();
    }

    @Rpc(description = "Stop a Runner")
    public JSONObject stopRunner(String runnerId) throws JSONException {
        Runner runner = findRunner(runnerId);
        if (runner == null) {
            return new JSONObject();
        }
        runner.stop();
        return runner.toJson();
    }

    @Rpc(description = "Wait for a Runner to complete")
    public JSONObject waitForRunnerCompletion(String runnerId) throws JSONException {
        Runner runner = findRunner(runnerId);
        if (runner == null) {
            return new JSONObject();
        }
        runner.waitForCompletion();
        return runner.toJson();
    }

    @Rpc(description = "Get a Runner by ID")
    public JSONObject getRunner(String runnerId) throws JSONException {
        Runner runner = findRunner(runnerId);
        if (runner == null) {
            return new JSONObject();
        }
        return runner.toJson();
    }

    @Rpc(description = "Get all Runners")
    public JSONObject getRunners() throws JSONException {
        JSONObject result = new JSONObject();
        JSONArray runners = new JSONArray();
        result.put("runners", runners);
        for (Runner runner : mRunners) {
            runners.put(runner.toJson());
        }

        return result;
    }

    @Override
    public void shutdown() {
    }
}
