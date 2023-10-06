package android.hardware.bluetooth.V1_0;


public final class Status {
    public static final int SUCCESS = 0;
    public static final int TRANSPORT_ERROR = 1 /* ::android::hardware::bluetooth::V1_0::Status.SUCCESS implicitly + 1 */;
    public static final int INITIALIZATION_ERROR = 2 /* ::android::hardware::bluetooth::V1_0::Status.TRANSPORT_ERROR implicitly + 1 */;
    public static final int UNKNOWN = 3 /* ::android::hardware::bluetooth::V1_0::Status.INITIALIZATION_ERROR implicitly + 1 */;
    public static final String toString(int o) {
        if (o == SUCCESS) {
            return "SUCCESS";
        }
        if (o == TRANSPORT_ERROR) {
            return "TRANSPORT_ERROR";
        }
        if (o == INITIALIZATION_ERROR) {
            return "INITIALIZATION_ERROR";
        }
        if (o == UNKNOWN) {
            return "UNKNOWN";
        }
        return "0x" + Integer.toHexString(o);
    }

    public static final String dumpBitfield(int o) {
        java.util.ArrayList<String> list = new java.util.ArrayList<>();
        int flipped = 0;
        list.add("SUCCESS"); // SUCCESS == 0
        if ((o & TRANSPORT_ERROR) == TRANSPORT_ERROR) {
            list.add("TRANSPORT_ERROR");
            flipped |= TRANSPORT_ERROR;
        }
        if ((o & INITIALIZATION_ERROR) == INITIALIZATION_ERROR) {
            list.add("INITIALIZATION_ERROR");
            flipped |= INITIALIZATION_ERROR;
        }
        if ((o & UNKNOWN) == UNKNOWN) {
            list.add("UNKNOWN");
            flipped |= UNKNOWN;
        }
        if (o != flipped) {
            list.add("0x" + Integer.toHexString(o & (~flipped)));
        }
        return String.join(" | ", list);
    }

};

