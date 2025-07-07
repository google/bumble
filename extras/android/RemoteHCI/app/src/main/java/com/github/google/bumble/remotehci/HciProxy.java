package com.github.google.bumble.remotehci;

import static com.github.google.bumble.remotehci.HciPacket.Type.COMMAND;

import android.os.RemoteException;
import android.util.Log;

import java.io.IOException;

public class HciProxy {
    private static final String TAG = "HciProxy";
    private final HciServer mServer;
    private final Listener mListener;
    private int mCommandPacketsReceived;
    private int mAclPacketsReceived;
    private int mScoPacketsReceived;
    private int mEventPacketsSent;
    private int mAclPacketsSent;
    private int mScoPacketsSent;

    private static final byte[] LOOPBACK_COMMAND_COMPLETE_EVENT = {
        0x0E, 0x04, 0x01, 0x77, (byte)0xFC, 0x00
    };

    HciProxy(int port, Listener listener) throws HalException {
        this.mListener = listener;

        // Instantiate a HAL to communicate with the hardware.
        HciHal hciHal = HciHal.create(new HciHalCallback() {
            @Override
            public void onPacket(HciPacket.Type type, byte[] packet) {
                Log.d(TAG, String.format("CONTROLLER->HOST: type=%s, size=%d", type, packet.length));
                mServer.sendPacket(type, packet);

                switch (type) {
                    case EVENT:
                        mEventPacketsSent += 1;
                        break;

                    case ACL_DATA:
                        mAclPacketsSent += 1;
                        break;

                    case SCO_DATA:
                        mScoPacketsSent += 1;
                        break;
                }
                updateHciPacketCount();
            }
        });
        if (hciHal == null) {
            String message = "Could not instantiate a HAL instance";
            Log.w(TAG, message);
            throw new HalException(message);
        }

        // Initialize the HAL.
        HciHal.Status status = null;
        try {
            status = hciHal.initialize();
        } catch (RemoteException | InterruptedException e) {
            throw new HalException("Exception while initializing");
        }
        if (status != HciHal.Status.SUCCESS) {
            String message = "HAL initialization failed: " + status.label;
            Log.w(TAG, message);
            throw new HalException(message);
        }

        // Create a server to accept clients.
        mServer = new HciServer(port, new HciServer.Listener() {
            @Override
            public void onHostConnectionState(boolean connected) {
                mListener.onHostConnectionState(connected);
                if (connected) {
                    mCommandPacketsReceived = 0;
                    mAclPacketsReceived = 0;
                    mScoPacketsReceived = 0;
                    mEventPacketsSent = 0;
                    mAclPacketsSent = 0;
                    mScoPacketsSent = 0;
                    updateHciPacketCount();
                }
            }

            @Override
            public void onMessage(String message) {
                listener.onMessage(message);
            }

            @Override
            public void onPacket(HciPacket.Type type, byte[] packet) {
                // Short-circuit a local response when a special latency-testing packet
                // is received.
                if (type == COMMAND && packet[0] == (byte)0x77 && packet[1] == (byte)0xFC) {
                    Log.d(TAG, "LOOPBACK");
                    mServer.sendPacket(HciPacket.Type.EVENT, LOOPBACK_COMMAND_COMPLETE_EVENT);
                    return;
                }

                Log.d(TAG, String.format("HOST->CONTROLLER: type=%s, size=%d", type, packet.length));
                hciHal.sendPacket(type, packet);

                switch (type) {
                    case COMMAND:
                        mCommandPacketsReceived += 1;
                        break;

                    case ACL_DATA:
                        mAclPacketsReceived += 1;
                        break;

                    case SCO_DATA:
                        mScoPacketsReceived += 1;
                        break;
                }
                updateHciPacketCount();
            }
        });
    }

    public void run() throws IOException {
        mServer.run();
    }

    private void updateHciPacketCount() {
        mListener.onHciPacketCountChange(
                mCommandPacketsReceived,
                mAclPacketsReceived,
                mScoPacketsReceived,
                mEventPacketsSent,
                mAclPacketsSent,
                mScoPacketsSent
        );
    }

    public interface Listener {
        void onHostConnectionState(boolean connected);

        void onHciPacketCountChange(
                int commandPacketsReceived,
                int aclPacketsReceived,
                int scoPacketsReceived,
                int eventPacketsSent,
                int aclPacketsSent,
                int scoPacketsSent
        );

        void onMessage(String message);
    }

    public static class HalException extends RuntimeException {
        public final String message;
        public HalException(String message) {
            this.message = message;
        }
    }
}
