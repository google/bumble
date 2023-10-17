package com.github.google.bumble.remotehci;

import static java.lang.Integer.min;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;


class HciParser {
    Sink sink;
    State state;
    int bytesNeeded;
    ByteArrayOutputStream packet = new ByteArrayOutputStream();
    HciPacket.Type packetType;

    HciParser(Sink sink) {
        this.sink = sink;
        reset();
    }

    void feedData(byte[] data, int dataSize) {
        int dataOffset = 0;
        int dataLeft = dataSize;

        while (dataLeft > 0 && bytesNeeded > 0) {
            int consumed = min(dataLeft, bytesNeeded);
            if (state != State.NEED_TYPE) {
                packet.write(data, dataOffset, consumed);
            }
            bytesNeeded -= consumed;

            if (bytesNeeded == 0) {
                if (state == State.NEED_TYPE) {
                    packetType = HciPacket.Type.fromValue(data[dataOffset]);
                    if (packetType == null) {
                        throw new InvalidFormatException();
                    }
                    bytesNeeded = packetType.lengthOffset + packetType.lengthSize;
                    state = State.NEED_LENGTH;
                } else if (state == State.NEED_LENGTH) {
                    ByteBuffer lengthBuffer =
                            ByteBuffer.wrap(packet.toByteArray())
                                    .order(ByteOrder.LITTLE_ENDIAN);
                    bytesNeeded = packetType.lengthSize == 1 ?
                            lengthBuffer.get(packetType.lengthOffset) & 0xFF :
                            lengthBuffer.getShort(packetType.lengthOffset) & 0xFFFF;
                    state = State.NEED_BODY;
                }

                // Emit a packet if one is complete.
                if (state == State.NEED_BODY && bytesNeeded == 0) {
                    if (sink != null) {
                        sink.onPacket(packetType, packet.toByteArray());
                    }

                    reset();
                }
            }

            dataOffset += consumed;
            dataLeft -= consumed;
        }
    }

    void reset() {
        state = State.NEED_TYPE;
        bytesNeeded = 1;
        packet.reset();
        packetType = null;
    }

    enum State {
        NEED_TYPE, NEED_LENGTH, NEED_BODY
    }

    interface Sink {
        void onPacket(HciPacket.Type type, byte[] packet);
    }

    static class InvalidFormatException extends RuntimeException {
    }
}