package com.github.google.bumble.remotehci;

public interface HciHalCallback {
    public void onPacket(HciPacket.Type type, byte[] packet);
}
