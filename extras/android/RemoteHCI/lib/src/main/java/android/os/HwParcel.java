package android.os;

import java.util.ArrayList;

public class HwParcel {
    public static final int STATUS_SUCCESS = 0;
    public native final void writeInterfaceToken(String interfaceName);
    public native final void writeBool(boolean val);
    public native final void writeInt8(byte val);
    public native final void writeInt16(short val);
    public native final void writeInt32(int val);
    public native final void writeInt64(long val);
    public native final void writeFloat(float val);
    public native final void writeDouble(double val);
    public native final void writeString(String val);
    public native final void writeNativeHandle(NativeHandle val);
    private native final void writeBoolVector(boolean[] val);
    private native final void writeInt8Vector(byte[] val);
    private native final void writeInt16Vector(short[] val);
    private native final void writeInt32Vector(int[] val);
    private native final void writeInt64Vector(long[] val);
    private native final void writeFloatVector(float[] val);
    private native final void writeDoubleVector(double[] val);
    private native final void writeStringVector(String[] val);
    private native final void writeNativeHandleVector(NativeHandle[] val);
    public final void writeBoolVector(ArrayList<Boolean> val) {
    }
    public final void writeInt8Vector(ArrayList<Byte> val) {
    }
    public final void writeInt16Vector(ArrayList<Short> val) {
    }
    public final void writeInt32Vector(ArrayList<Integer> val) {
    }
    public final void writeInt64Vector(ArrayList<Long> val) {
    }
    public final void writeFloatVector(ArrayList<Float> val) {
    }
    public final void writeDoubleVector(ArrayList<Double> val) {
    }
    public final void writeStringVector(ArrayList<String> val) {
    }
    public final void writeNativeHandleVector(ArrayList<NativeHandle> val) {
    }
    public native final void writeStrongBinder(IHwBinder binder);
    //public native final void writeHidlMemory(HidlMemory memory);
    public native final void enforceInterface(String interfaceName);
    public native final boolean readBool();
    public native final byte readInt8();
    public native final short readInt16();
    public native final int readInt32();
    public native final long readInt64();
    public native final float readFloat();
    public native final double readDouble();
    public native final String readString();
    public native final NativeHandle readNativeHandle();
    public native final NativeHandle readEmbeddedNativeHandle(
            long parentHandle, long offset);
    private native final boolean[] readBoolVectorAsArray();
    private native final byte[] readInt8VectorAsArray();
    private native final short[] readInt16VectorAsArray();
    private native final int[] readInt32VectorAsArray();
    private native final long[] readInt64VectorAsArray();
    private native final float[] readFloatVectorAsArray();
    private native final double[] readDoubleVectorAsArray();
    private native final String[] readStringVectorAsArray();
    private native final NativeHandle[] readNativeHandleAsArray();
    public final ArrayList<Boolean> readBoolVector() {
        return null;
    }
    public final ArrayList<Byte> readInt8Vector() {
        return null;
    }
    public final ArrayList<Short> readInt16Vector() {
        return null;
    }
    public final ArrayList<Integer> readInt32Vector() {
        return null;
    }
    public final ArrayList<Long> readInt64Vector() {
        return null;
    }
    public final ArrayList<Float> readFloatVector() {
        return null;
    }
    public final ArrayList<Double> readDoubleVector() {
        return null;
    }
    public final ArrayList<String> readStringVector() {
        return null;
    }
    public final ArrayList<NativeHandle> readNativeHandleVector() {
        return null;
    }
    public native final IHwBinder readStrongBinder();
//    public native final HidlMemory readHidlMemory();
//    public native final
//    HidlMemory readEmbeddedHidlMemory(long fieldHandle, long parentHandle, long offset);
    public native final HwBlob readBuffer(long expectedSize);
    public native final HwBlob readEmbeddedBuffer(
            long expectedSize, long parentHandle, long offset,
            boolean nullable);
    public native final void writeBuffer(HwBlob blob);
    public native final void writeStatus(int status);
    public native final void verifySuccess();
    public native final void releaseTemporaryStorage();
    public native final void release();
    public native final void send();}
