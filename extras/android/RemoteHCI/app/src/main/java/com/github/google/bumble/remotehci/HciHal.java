package com.github.google.bumble.remotehci;

import android.hardware.bluetooth.V1_0.Status;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;

import java.util.ArrayList;
import java.util.NoSuchElementException;

public interface HciHal {
    public enum Status {
        SUCCESS("SUCCESS"),
        ALREADY_INITIALIZED("ALREADY_INITIALIZED"),
        UNABLE_TO_OPEN_INTERFACE("UNABLE_TO_OPEN_INTERFACE"),
        INITIALIZATION_ERROR("INITIALIZATION_ERROR"),
        TRANSPORT_ERROR("TRANSPORT_ERROR"),
        UNKNOWN("UNKNOWN");

        public final String label;

        private Status(String label) {
            this.label = label;
        }
    }
    static final String TAG = "HciHal";
    public static HciHal create(HciHalCallback hciCallbacks) {
        // First try HIDL
        HciHal hciHal = HciHidlHal.create(hciCallbacks);
        if (hciHal != null) {
            Log.d(TAG, "Found HIDL HAL");
            return hciHal;
        }

        // Then try AIDL
        hciHal = HciAidlHal.create(hciCallbacks);
        if (hciHal != null) {
            Log.d(TAG, "Found AIDL HAL");
            return hciHal;
        }

        Log.d(TAG, "No HAL found");
        return null;
    }

    public Status initialize() throws RemoteException, InterruptedException;
    public void sendPacket(HciPacket.Type type, byte[] packet);
}

class HciHidlHal extends android.hardware.bluetooth.V1_0.IBluetoothHciCallbacks.Stub implements HciHal {
    private static final String TAG = "HciHidlHal";
    private final android.hardware.bluetooth.V1_0.IBluetoothHci mHciService;
    private final HciHalCallback mHciCallbacks;
    private int mInitializationStatus = -1;


    public static HciHidlHal create(HciHalCallback hciCallbacks) {
        // Get the HAL service.
        android.hardware.bluetooth.V1_0.IBluetoothHci hciService;
        try {
            hciService = android.hardware.bluetooth.V1_0.IBluetoothHci.getService(true);
        } catch (NoSuchElementException e) {
            Log.d(TAG, "HIDL HAL V1.0 not found");
            return null;
        } catch (android.os.RemoteException e) {
            Log.w(TAG, "Exception from getService: " + e);
            return null;
        }
        Log.d(TAG, "Found HIDL HAL V1.0");
        return new HciHidlHal(hciService, hciCallbacks);
    }

    private HciHidlHal(android.hardware.bluetooth.V1_0.IBluetoothHci hciService, HciHalCallback hciCallbacks) {
        mHciService = hciService;
        mHciCallbacks = hciCallbacks;
    }

    public Status initialize() throws RemoteException, InterruptedException {
        // Trigger the initialization.
        mHciService.initialize(this);

        // Wait for the initialization to complete.
        Log.d(TAG, "Waiting for initialization status...");
        synchronized (this) {
            while (mInitializationStatus == -1) {
                wait();
            }
        }

        // Map the status code.
        switch (mInitializationStatus) {
            case android.hardware.bluetooth.V1_0.Status.SUCCESS:
                return Status.SUCCESS;

            case android.hardware.bluetooth.V1_0.Status.TRANSPORT_ERROR:
                return Status.TRANSPORT_ERROR;

            case android.hardware.bluetooth.V1_0.Status.INITIALIZATION_ERROR:
                return Status.INITIALIZATION_ERROR;

            default:
                return Status.UNKNOWN;
        }
    }

    @Override
    public void sendPacket(HciPacket.Type type, byte[] packet) {
        ArrayList<Byte> data = HciPacket.byteArrayToList(packet);

        try {
            switch (type) {
                case COMMAND:
                    mHciService.sendHciCommand(data);
                    break;

                case ACL_DATA:
                    mHciService.sendAclData(data);
                    break;

                case SCO_DATA:
                    mHciService.sendScoData(data);
                    break;
            }
        } catch (RemoteException error) {
            Log.w(TAG, "failed to forward packet: " + error);
        }
    }

    @Override
    public synchronized void initializationComplete(int status) throws RemoteException {
        mInitializationStatus = status;
        notifyAll();
    }

    @Override
    public void hciEventReceived(ArrayList<Byte> event) throws RemoteException {
        byte[] packet = HciPacket.listToByteArray(event);
        mHciCallbacks.onPacket(HciPacket.Type.EVENT, packet);
    }

    @Override
    public void aclDataReceived(ArrayList<Byte> data) throws RemoteException {
        byte[] packet = HciPacket.listToByteArray(data);
        mHciCallbacks.onPacket(HciPacket.Type.ACL_DATA, packet);
    }

    @Override
    public void scoDataReceived(ArrayList<Byte> data) throws RemoteException {
        byte[] packet = HciPacket.listToByteArray(data);
        mHciCallbacks.onPacket(HciPacket.Type.SCO_DATA, packet);
    }
}

class HciAidlHal extends android.hardware.bluetooth.IBluetoothHciCallbacks.Stub implements HciHal {
    private static final String TAG = "HciAidlHal";
    private final android.hardware.bluetooth.IBluetoothHci mHciService;
    private final HciHalCallback mHciCallbacks;
    private int mInitializationStatus = android.hardware.bluetooth.Status.SUCCESS;

    public static HciAidlHal create(HciHalCallback hciCallbacks) {
        IBinder binder = ServiceManager.getService("android.hardware.bluetooth.IBluetoothHci/default");
        if (binder == null) {
            Log.d(TAG, "AIDL HAL not found");
            return null;
        }
        android.hardware.bluetooth.IBluetoothHci hciService = android.hardware.bluetooth.IBluetoothHci.Stub.asInterface(binder);
        return new HciAidlHal(hciService, hciCallbacks);
    }

    private HciAidlHal(android.hardware.bluetooth.IBluetoothHci hciService, HciHalCallback hciCallbacks) {
        super();
        mHciService = hciService;
        mHciCallbacks = hciCallbacks;
    }

    public Status initialize() throws RemoteException, InterruptedException {
        // Trigger the initialization.
        mHciService.initialize(this);

        // Wait for the initialization to complete.
        Log.d(TAG, "Waiting for initialization status...");
        synchronized (this) {
            while (mInitializationStatus == -1) {
                wait();
            }
        }

        // Map the status code.
        switch (mInitializationStatus) {
            case android.hardware.bluetooth.Status.SUCCESS:
                return Status.SUCCESS;

            case android.hardware.bluetooth.Status.ALREADY_INITIALIZED:
                return Status.ALREADY_INITIALIZED;

            case android.hardware.bluetooth.Status.UNABLE_TO_OPEN_INTERFACE:
                return Status.UNABLE_TO_OPEN_INTERFACE;

            case android.hardware.bluetooth.Status.HARDWARE_INITIALIZATION_ERROR:
                return Status.INITIALIZATION_ERROR;

            default:
                return Status.UNKNOWN;
        }
    }

    // HciHal methods.
    @Override
    public void sendPacket(HciPacket.Type type, byte[] packet) {
        try {
            switch (type) {
                case COMMAND:
                    mHciService.sendHciCommand(packet);
                    break;

                case ACL_DATA:
                    mHciService.sendAclData(packet);
                    break;

                case SCO_DATA:
                    mHciService.sendScoData(packet);
                    break;

                case ISO_DATA:
                    mHciService.sendIsoData(packet);
                    break;
            }
        } catch (RemoteException error) {
            Log.w(TAG, "failed to forward packet: " + error);
        }
    }

    // IBluetoothHciCallbacks methods.
    @Override
    public synchronized void initializationComplete(int status) throws RemoteException {
        mInitializationStatus = status;
        notifyAll();
    }

    @Override
    public void hciEventReceived(byte[] event) throws RemoteException {
        mHciCallbacks.onPacket(HciPacket.Type.EVENT, event);
    }

    @Override
    public void aclDataReceived(byte[] data) throws RemoteException {
        mHciCallbacks.onPacket(HciPacket.Type.ACL_DATA, data);
    }

    @Override
    public void scoDataReceived(byte[] data) throws RemoteException {
        mHciCallbacks.onPacket(HciPacket.Type.SCO_DATA, data);
    }

    @Override
    public void isoDataReceived(byte[] data) throws RemoteException {
        mHciCallbacks.onPacket(HciPacket.Type.ISO_DATA, data);
    }
}