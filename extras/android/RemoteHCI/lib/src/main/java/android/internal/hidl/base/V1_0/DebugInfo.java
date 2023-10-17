package android.internal.hidl.base.V1_0;

import android.os.HwParcel;

public class DebugInfo {
    public static final class Architecture {
        public static final int UNKNOWN = 0;
    }

    public int pid = 0;
    public long ptr = 0L;
    public int arch = 0;
    public final void readFromParcel(HwParcel parcel) {
    }
    public final void writeToParcel(HwParcel parcel) {
    }
}