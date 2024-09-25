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

import com.google.android.mobly.snippet.Snippet;
import com.google.android.mobly.snippet.rpc.Rpc;

import androidx.test.core.app.ApplicationProvider;

import org.json.JSONException;
import org.json.JSONObject;

public class AutomationSnippet implements Snippet {
    private static final String TAG = "btbench.snippet";
    private final BluetoothAdapter mBluetoothAdapter;
    private final Context mContext;

    public AutomationSnippet() {
        mContext = ApplicationProvider.getApplicationContext();
        BluetoothManager bluetoothManager = mContext.getSystemService(BluetoothManager.class);
        mBluetoothAdapter = bluetoothManager.getAdapter();
        if (mBluetoothAdapter == null) {
            throw new RuntimeException("bluetooth not supported");
        }
    }

    private void runScenario(AppViewModel model, String mode, String scenario) {
        Mode runner;
        switch (mode) {
            case "rfcomm-client":
                runner = new RfcommClient(model, mBluetoothAdapter, (PacketIO packetIO) -> createIoClient(model, scenario, packetIO));
                break;

            case "rfcomm-server":
                runner = new RfcommServer(model, mBluetoothAdapter, (PacketIO packetIO) -> createIoClient(model, scenario, packetIO));
                break;

            case "l2cap-client":
                runner = new L2capClient(model, mBluetoothAdapter, mContext, (PacketIO packetIO) -> createIoClient(model, scenario, packetIO));
                break;

            case "l2cap-server":
                runner = new L2capServer(model, mBluetoothAdapter, (PacketIO packetIO) -> createIoClient(model, scenario, packetIO));
                break;

            default:
                return;
        }

        runner.run(true);
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

    private static JSONObject resultFromModel(AppViewModel model) throws JSONException {
        JSONObject result = new JSONObject();
        JSONObject stats = new JSONObject();
        result.put("stats", stats);
        JSONObject throughputStats = new JSONObject();
        stats.put("throughput", throughputStats);
        throughputStats.put("average", model.getThroughput());
        JSONObject rttStats = new JSONObject();
        stats.put("rtt", rttStats);
        rttStats.put("compound", model.getStats());
        return result;
    }

    @Rpc(description = "Run a scenario in RFComm Client mode")
    public JSONObject runRfcommClient(String scenario, String peerBluetoothAddress, int packetCount, int packetSize, int packetInterval) throws JSONException {
        assert (mBluetoothAdapter != null);
        AppViewModel model = new AppViewModel();
        model.setPeerBluetoothAddress(peerBluetoothAddress);
        model.setSenderPacketCount(packetCount);
        model.setSenderPacketSize(packetSize);
        model.setSenderPacketInterval(packetInterval);

        runScenario(model, "rfcomm-client", scenario);
        return resultFromModel(model);
    }

    @Rpc(description = "Run a scenario in L2CAP Client mode")
    public JSONObject runL2capClient(String scenario, String peerBluetoothAddress, int psm, boolean use_2m_phy, int packetCount, int packetSize, int packetInterval) throws JSONException {
        assert (mBluetoothAdapter != null);
        AppViewModel model = new AppViewModel();
        model.setPeerBluetoothAddress(peerBluetoothAddress);
        model.setL2capPsm(psm);
        model.setUse2mPhy(use_2m_phy);
        model.setSenderPacketCount(packetCount);
        model.setSenderPacketSize(packetSize);
        model.setSenderPacketInterval(packetInterval);

        runScenario(model, "l2cap-client", scenario);
        return resultFromModel(model);
    }

    @Override
    public void shutdown() {
    }
}