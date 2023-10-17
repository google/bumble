package android.internal.hidl.base.V1_0;

import android.os.IHwBinder;
import android.os.IHwInterface;

public interface IBase extends IHwInterface {
    public static final String kInterfaceName = "android.hidl.base@1.0::IBase";

    public static abstract class Stub extends android.os.HwBinder implements IBase {
        public void onTransact(int _hidl_code, android.os.HwParcel _hidl_request, final android.os.HwParcel _hidl_reply, int _hidl_flags)
                throws android.os.RemoteException {}
    }

    public static final class Proxy implements IBase {
        @Override
        public IHwBinder asBinder() {
            return null;
        }
    }
}
