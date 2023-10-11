package com.github.google.bumble.remotehci;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;


public class HciServer {
    private static final String TAG = "HciServer";
    private static final int BUFFER_SIZE = 1024;
    private final int mPort;
    private final Listener mListener;
    private OutputStream mOutputStream;

    public interface Listener extends HciParser.Sink {
        void onHostConnectionState(boolean connected);
        void onMessage(String message);
    }

    HciServer(int port, Listener listener) {
        this.mPort = port;
        this.mListener = listener;
    }

    public void run() throws IOException {
        for (;;) {
            try {
                loop();
            } catch (IOException error) {
                mListener.onMessage("Cannot listen on port " + mPort);
                return;
            }
        }
    }

    private void loop() throws IOException {
        mListener.onHostConnectionState(false);
        try (ServerSocket serverSocket = new ServerSocket(mPort)) {
            mListener.onMessage("Waiting for connection on port " + serverSocket.getLocalPort());
            try (Socket clientSocket = serverSocket.accept()) {
                mListener.onHostConnectionState(true);
                mListener.onMessage("Connected");
                HciParser parser = new HciParser(mListener);
                InputStream inputStream = clientSocket.getInputStream();
                synchronized (this) {
                    mOutputStream = clientSocket.getOutputStream();
                }
                byte[] buffer = new byte[BUFFER_SIZE];

                try {
                    for (; ; ) {
                        int bytesRead = inputStream.read(buffer);
                        if (bytesRead < 0) {
                            Log.d(TAG, "end of stream");
                            break;
                        }
                        parser.feedData(buffer, bytesRead);
                    }
                } catch (IOException error) {
                    Log.d(TAG, "exception in read loop: " + error);
                }
            }
        } finally {
            synchronized (this) {
                mOutputStream = null;
            }
        }
    }

    public void sendPacket(HciPacket.Type type, byte[] packet) {
        // Create a combined data buffer so we can write it out in a single call.
        byte[] data = new byte[packet.length + 1];
        data[0] = type.value;
        System.arraycopy(packet, 0, data, 1, packet.length);

        synchronized (this) {
            if (mOutputStream != null) {
                try {
                    mOutputStream.write(data);
                } catch (IOException error) {
                    Log.w(TAG, "failed to write packet: " + error);
                }
            } else {
                Log.d(TAG, "no client, dropping packet");
            }
        }
    }
}
