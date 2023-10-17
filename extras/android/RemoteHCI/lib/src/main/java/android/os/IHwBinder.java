package android.os;

public interface IHwBinder {
    public interface DeathRecipient {
        public void serviceDied(long cookie);
    }
    public IHwInterface queryLocalInterface(String descriptor);
    public void transact(int code, HwParcel request, HwParcel reply, int flags);
    public boolean linkToDeath(DeathRecipient recipient, long cookie);
    public boolean unlinkToDeath(DeathRecipient recipient);
}
