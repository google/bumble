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
import android.renderscript.RSInvalidStateException;
import android.util.Log;

import com.google.android.mobly.snippet.Snippet;
import com.google.android.mobly.snippet.rpc.Rpc;
import androidx.test.core.app.ApplicationProvider;

import org.json.JSONException;
import org.json.JSONObject;


public class AutomationSnippet implements Snippet {
    private static final String TAG = "btbench.snippet";
    private final BluetoothAdapter mBluetoothAdapter;
    private AppViewModel rfcommServerModel;
    private RfcommServer rfcommServer;
    private AppViewModel l2capServerModel;
    private L2capServer l2capServer;

    public AutomationSnippet() {
        Context context = ApplicationProvider.getApplicationContext();
        BluetoothManager bluetoothManager = context.getSystemService(BluetoothManager.class);
        mBluetoothAdapter = bluetoothManager.getAdapter();
        if (mBluetoothAdapter == null) {
            throw new RuntimeException("bluetooth not supported");
        }
    }

    private static JSONObject throughputStats(AppViewModel model) throws JSONException {
        JSONObject result = new JSONObject();
        JSONObject stats = new JSONObject();
        result.put("stats", stats);
        JSONObject throughputStats = new JSONObject();
        stats.put("throughput", throughputStats);
        throughputStats.put("average", model.getThroughput());
        return result;
    }

    @Rpc(description = "Run an RFComm client throughput test")
    public JSONObject runRfcommClient(String peerBluetoothAddress, int packetCount, int packetSize) throws JSONException {
        assert(mBluetoothAdapter != null);
        AppViewModel model = new AppViewModel();
        model.setPeerBluetoothAddress(peerBluetoothAddress);
        model.setSenderPacketCount(packetCount);
        model.setSenderPacketSize(packetSize);

        //RfcommClient rfCommClient = new RfcommClient(model, mBluetoothAdapter);
        //rfCommClient.run(true);
        return throughputStats(model);
    }

    @Rpc(description = "Run an L2CAP client throughput test")
    public JSONObject runL2capClient(String peerBluetoothAddress, int psm, boolean use_2m_phy, int packetCount, int packetSize) throws JSONException {
        assert(mBluetoothAdapter != null);
        AppViewModel model = new AppViewModel();
        model.setPeerBluetoothAddress(peerBluetoothAddress);
        model.setL2capPsm(psm);
        model.setUse2mPhy(use_2m_phy);
        model.setSenderPacketCount(packetCount);
        model.setSenderPacketSize(packetSize);

        Context context = ApplicationProvider.getApplicationContext();
        //L2capClient l2capClient = new L2capClient(model, mBluetoothAdapter, context);
        //l2capClient.run(true);
        return throughputStats(model);
    }

    @Rpc(description = "Run an RFComm server")
    public JSONObject runRfcommServer() throws JSONException {
        assert(mBluetoothAdapter != null);
        if (rfcommServerModel != null) {
            rfcommServerModel.abort();
            rfcommServerModel = null;
            rfcommServer = null;
        }
        rfcommServerModel = new AppViewModel();
        //rfcommServer = new RfcommServer(rfcommServerModel, mBluetoothAdapter);
        //rfcommServer.run(true);

        return new JSONObject();
    }

    @Override
    public void shutdown() {
    }
}