package android.os;

public class HwBinder implements IHwBinder {
    public native final void registerService(String serviceName);
    public static final IHwBinder getService(
            String iface,
            String serviceName) {
        return null; //STUB
    }

    public static final IHwBinder getService(
            String iface,
            String serviceName,
            boolean retry) {
        return null; // STUB
    }

    public static void enableInstrumentation() {

    }
    @Override
    public IHwInterface queryLocalInterface(String descriptor) {
        return null; // STUB
    }

    @Override
    public void transact(int code, HwParcel request, HwParcel reply, int flags) {

    }

    @Override
    public boolean linkToDeath(DeathRecipient recipient, long cookie) {
        return false;
    }

    @Override
    public boolean unlinkToDeath(DeathRecipient recipient) {
        return false;
    }
}
