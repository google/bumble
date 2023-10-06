package android.os;

public class HwBlob {
    public HwBlob(int size) {}
    public native final long handle();

    public native final int getInt32(long offset);
    public native final void putInt32(long offset, int x);
    public native final void putBool(long offset, boolean x);
    public native final void putInt8Array(long offset, byte[] x);
    public native final void putBlob(long offset, HwBlob blob);
    public native final void copyToInt8Array(long offset, byte[] array, int size);
}
