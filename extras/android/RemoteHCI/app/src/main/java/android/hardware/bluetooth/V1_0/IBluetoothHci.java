package android.hardware.bluetooth.V1_0;

import android.os.HidlSupport;
import android.os.HwBinder;
import android.os.IHwBinder;
import android.os.HwBlob;
import android.os.HwParcel;
import android.os.IHwInterface;
import android.os.NativeHandle;

/**
 * The Host Controller Interface (HCI) is the layer defined by the Bluetooth
 * specification between the software that runs on the host and the Bluetooth
 * controller chip. This boundary is the natural choice for a Hardware
 * Abstraction Layer (HAL). Dealing only in HCI packets and events simplifies
 * the stack and abstracts away power management, initialization, and other
 * implementation-specific details related to the hardware.
 */
public interface IBluetoothHci extends android.internal.hidl.base.V1_0.IBase {
    /**
     * Fully-qualified interface name for this interface.
     */
    public static final String kInterfaceName = "android.hardware.bluetooth@1.0::IBluetoothHci";

    /**
     * Does a checked conversion from a binder to this class.
     */
    /* package private */ static IBluetoothHci asInterface(IHwBinder binder) {
        if (binder == null) {
            return null;
        }

        IHwInterface iface =
                binder.queryLocalInterface(kInterfaceName);

        if ((iface != null) && (iface instanceof IBluetoothHci)) {
            return (IBluetoothHci)iface;
        }

        IBluetoothHci proxy = new IBluetoothHci.Proxy(binder);

        try {
            for (String descriptor : proxy.interfaceChain()) {
                if (descriptor.equals(kInterfaceName)) {
                    return proxy;
                }
            }
        } catch (android.os.RemoteException e) {
        }

        return null;
    }

    /**
     * Does a checked conversion from any interface to this class.
     */
    public static IBluetoothHci castFrom(IHwInterface iface) {
        return (iface == null) ? null : IBluetoothHci.asInterface(iface.asBinder());
    }

    @Override
    public IHwBinder asBinder();

    /**
     * This will invoke the equivalent of the C++ getService(std::string) if retry is
     * true or tryGetService(std::string) if retry is false. If the service is
     * available on the device and retry is true, this will wait for the service to
     * start.
     *
     */
    public static IBluetoothHci getService(String serviceName, boolean retry) throws android.os.RemoteException {
        return IBluetoothHci.asInterface(HwBinder.getService("android.hardware.bluetooth@1.0::IBluetoothHci", serviceName, retry));
    }

    /**
     * Calls getService("default",retry).
     */
    public static IBluetoothHci getService(boolean retry) throws android.os.RemoteException {
        return getService("default", retry);
    }

    /**
     * @deprecated this will not wait for the interface to come up if it hasn't yet
     * started. See getService(String,boolean) instead.
     */
    @Deprecated
    public static IBluetoothHci getService(String serviceName) throws android.os.RemoteException {
        return IBluetoothHci.asInterface(HwBinder.getService("android.hardware.bluetooth@1.0::IBluetoothHci", serviceName));
    }

    /**
     * @deprecated this will not wait for the interface to come up if it hasn't yet
     * started. See getService(boolean) instead.
     */
    @Deprecated
    public static IBluetoothHci getService() throws android.os.RemoteException {
        return getService("default");
    }

    /**
     * Initialize the underlying HCI interface.
     *
     * This method should be used to initialize any hardware interfaces
     * required to communicate with the Bluetooth hardware in the
     * device.
     *
     * The |oninitializationComplete| callback must be invoked in response
     * to this function to indicate success before any other function
     * (sendHciCommand, sendAclData, * sendScoData) is invoked on this
     * interface.
     *
     * @param callback implements IBluetoothHciCallbacks which will
     *    receive callbacks when incoming HCI packets are received
     *    from the controller to be sent to the host.
     */
    void initialize(android.hardware.bluetooth.V1_0.IBluetoothHciCallbacks callback)
        throws android.os.RemoteException;
    /**
     * Send an HCI command (as specified in the Bluetooth Specification
     * V4.2, Vol 2, Part 5, Section 5.4.1) to the Bluetooth controller.
     * Commands must be executed in order.
     *
     * @param command is the HCI command to be sent
     */
    void sendHciCommand(java.util.ArrayList<Byte> command)
        throws android.os.RemoteException;
    /**
     * Send an HCI ACL data packet (as specified in the Bluetooth Specification
     * V4.2, Vol 2, Part 5, Section 5.4.2) to the Bluetooth controller.
     * Packets must be processed in order.
     * @param data HCI data packet to be sent
     */
    void sendAclData(java.util.ArrayList<Byte> data)
        throws android.os.RemoteException;
    /**
     * Send an SCO data packet (as specified in the Bluetooth Specification
     * V4.2, Vol 2, Part 5, Section 5.4.3) to the Bluetooth controller.
     * Packets must be processed in order.
     * @param data HCI data packet to be sent
     */
    void sendScoData(java.util.ArrayList<Byte> data)
        throws android.os.RemoteException;
    /**
     * Close the HCI interface
     */
    void close()
        throws android.os.RemoteException;
    /*
     * Provides run-time type information for this object.
     * For example, for the following interface definition:
     *     package android.hardware.foo@1.0;
     *     interface IParent {};
     *     interface IChild extends IParent {};
     * Calling interfaceChain on an IChild object must yield the following:
     *     ["android.hardware.foo@1.0::IChild",
     *      "android.hardware.foo@1.0::IParent"
     *      "android.internal.hidl.base@1.0::IBase"]
     *
     * @return descriptors a vector of descriptors of the run-time type of the
     *         object.
     */
    java.util.ArrayList<String> interfaceChain()
        throws android.os.RemoteException;
    /*
     * Emit diagnostic information to the given file.
     *
     * Optionally overriden.
     *
     * @param fd      File descriptor to dump data to.
     *                Must only be used for the duration of this call.
     * @param options Arguments for debugging.
     *                Must support empty for default debug information.
     */
    void debug(NativeHandle fd, java.util.ArrayList<String> options)
        throws android.os.RemoteException;
    /*
     * Provides run-time type information for this object.
     * For example, for the following interface definition:
     *     package android.hardware.foo@1.0;
     *     interface IParent {};
     *     interface IChild extends IParent {};
     * Calling interfaceDescriptor on an IChild object must yield
     *     "android.hardware.foo@1.0::IChild"
     *
     * @return descriptor a descriptor of the run-time type of the
     *         object (the first element of the vector returned by
     *         interfaceChain())
     */
    String interfaceDescriptor()
        throws android.os.RemoteException;
    /*
     * Returns hashes of the source HAL files that define the interfaces of the
     * runtime type information on the object.
     * For example, for the following interface definition:
     *     package android.hardware.foo@1.0;
     *     interface IParent {};
     *     interface IChild extends IParent {};
     * Calling interfaceChain on an IChild object must yield the following:
     *     [(hash of IChild.hal),
     *      (hash of IParent.hal)
     *      (hash of IBase.hal)].
     *
     * SHA-256 is used as the hashing algorithm. Each hash has 32 bytes
     * according to SHA-256 standard.
     *
     * @return hashchain a vector of SHA-1 digests
     */
    java.util.ArrayList<byte[/* 32 */]> getHashChain()
        throws android.os.RemoteException;
    /*
     * This method trigger the interface to enable/disable instrumentation based
     * on system property hal.instrumentation.enable.
     */
    void setHALInstrumentation()
        throws android.os.RemoteException;
    /*
     * Registers a death recipient, to be called when the process hosting this
     * interface dies.
     *
     * @param recipient a hidl_death_recipient callback object
     * @param cookie a cookie that must be returned with the callback
     * @return success whether the death recipient was registered successfully.
     */
    boolean linkToDeath(IHwBinder.DeathRecipient recipient, long cookie)
        throws android.os.RemoteException;
    /*
     * Provides way to determine if interface is running without requesting
     * any functionality.
     */
    void ping()
        throws android.os.RemoteException;
    /*
     * Get debug information on references on this interface.
     * @return info debugging information. See comments of DebugInfo.
     */
    android.internal.hidl.base.V1_0.DebugInfo getDebugInfo()
        throws android.os.RemoteException;
    /*
     * This method notifies the interface that one or more system properties
     * have changed. The default implementation calls
     * (C++)  report_sysprop_change() in libcutils or
     * (Java) android.os.SystemProperties.reportSyspropChanged,
     * which in turn calls a set of registered callbacks (eg to update trace
     * tags).
     */
    void notifySyspropsChanged()
        throws android.os.RemoteException;
    /*
     * Unregisters the registered death recipient. If this service was registered
     * multiple times with the same exact death recipient, this unlinks the most
     * recently registered one.
     *
     * @param recipient a previously registered hidl_death_recipient callback
     * @return success whether the death recipient was unregistered successfully.
     */
    boolean unlinkToDeath(IHwBinder.DeathRecipient recipient)
        throws android.os.RemoteException;

    public static final class Proxy implements IBluetoothHci {
        private IHwBinder mRemote;

        public Proxy(IHwBinder remote) {
            mRemote = java.util.Objects.requireNonNull(remote);
        }

        @Override
        public IHwBinder asBinder() {
            return mRemote;
        }

        @Override
        public String toString() {
            try {
                return this.interfaceDescriptor() + "@Proxy";
            } catch (android.os.RemoteException ex) {
                /* ignored; handled below. */
            }
            return "[class or subclass of " + IBluetoothHci.kInterfaceName + "]@Proxy";
        }

        @Override
        public final boolean equals(java.lang.Object other) {
            return HidlSupport.interfacesEqual(this, other);
        }

        @Override
        public final int hashCode() {
            return this.asBinder().hashCode();
        }

        // Methods from ::android::hardware::bluetooth::V1_0::IBluetoothHci follow.
        @Override
        public void initialize(android.hardware.bluetooth.V1_0.IBluetoothHciCallbacks callback)
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);
            _hidl_request.writeStrongBinder(callback == null ? null : callback.asBinder());

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(1 /* initialize */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public void sendHciCommand(java.util.ArrayList<Byte> command)
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);
            _hidl_request.writeInt8Vector(command);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(2 /* sendHciCommand */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public void sendAclData(java.util.ArrayList<Byte> data)
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);
            _hidl_request.writeInt8Vector(data);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(3 /* sendAclData */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public void sendScoData(java.util.ArrayList<Byte> data)
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);
            _hidl_request.writeInt8Vector(data);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(4 /* sendScoData */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public void close()
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(5 /* close */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        // Methods from ::android::hidl::base::V1_0::IBase follow.
        @Override
        public java.util.ArrayList<String> interfaceChain()
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(256067662 /* interfaceChain */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();

                java.util.ArrayList<String> _hidl_out_descriptors = _hidl_reply.readStringVector();
                return _hidl_out_descriptors;
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public void debug(NativeHandle fd, java.util.ArrayList<String> options)
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.internal.hidl.base.V1_0.IBase.kInterfaceName);
            _hidl_request.writeNativeHandle(fd);
            _hidl_request.writeStringVector(options);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(256131655 /* debug */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public String interfaceDescriptor()
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(256136003 /* interfaceDescriptor */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();

                String _hidl_out_descriptor = _hidl_reply.readString();
                return _hidl_out_descriptor;
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public java.util.ArrayList<byte[/* 32 */]> getHashChain()
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(256398152 /* getHashChain */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();

                java.util.ArrayList<byte[/* 32 */]> _hidl_out_hashchain =  new java.util.ArrayList<byte[/* 32 */]>();
                {
                    HwBlob _hidl_blob = _hidl_reply.readBuffer(16 /* size */);
                    {
                        int _hidl_vec_size = _hidl_blob.getInt32(0 /* offset */ + 8 /* offsetof(hidl_vec<T>, mSize) */);
                        HwBlob childBlob = _hidl_reply.readEmbeddedBuffer(
                                _hidl_vec_size * 32,_hidl_blob.handle(),
                                0 /* offset */ + 0 /* offsetof(hidl_vec<T>, mBuffer) */,true /* nullable */);

                        ((java.util.ArrayList<byte[/* 32 */]>) _hidl_out_hashchain).clear();
                        for (int _hidl_index_0 = 0; _hidl_index_0 < _hidl_vec_size; ++_hidl_index_0) {
                            byte[/* 32 */] _hidl_vec_element = new byte[32];
                            {
                                long _hidl_array_offset_1 = _hidl_index_0 * 32;
                                childBlob.copyToInt8Array(_hidl_array_offset_1, (byte[/* 32 */]) _hidl_vec_element, 32 /* size */);
                                _hidl_array_offset_1 += 32 * 1;
                            }
                            ((java.util.ArrayList<byte[/* 32 */]>) _hidl_out_hashchain).add(_hidl_vec_element);
                        }
                    }
                }
                return _hidl_out_hashchain;
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public void setHALInstrumentation()
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(256462420 /* setHALInstrumentation */, _hidl_request, _hidl_reply, 1 /* oneway */);
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public boolean linkToDeath(IHwBinder.DeathRecipient recipient, long cookie)
                throws android.os.RemoteException {
            return mRemote.linkToDeath(recipient, cookie);
        }
        @Override
        public void ping()
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(256921159 /* ping */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public android.internal.hidl.base.V1_0.DebugInfo getDebugInfo()
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(257049926 /* getDebugInfo */, _hidl_request, _hidl_reply, 0 /* flags */);
                _hidl_reply.verifySuccess();
                _hidl_request.releaseTemporaryStorage();

                android.internal.hidl.base.V1_0.DebugInfo _hidl_out_info = new android.internal.hidl.base.V1_0.DebugInfo();
                ((android.internal.hidl.base.V1_0.DebugInfo) _hidl_out_info).readFromParcel(_hidl_reply);
                return _hidl_out_info;
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public void notifySyspropsChanged()
                throws android.os.RemoteException {
            HwParcel _hidl_request = new HwParcel();
            _hidl_request.writeInterfaceToken(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

            HwParcel _hidl_reply = new HwParcel();
            try {
                mRemote.transact(257120595 /* notifySyspropsChanged */, _hidl_request, _hidl_reply, 1 /* oneway */);
                _hidl_request.releaseTemporaryStorage();
            } finally {
                _hidl_reply.release();
            }
        }

        @Override
        public boolean unlinkToDeath(IHwBinder.DeathRecipient recipient)
                throws android.os.RemoteException {
            return mRemote.unlinkToDeath(recipient);
        }
    }

    public static abstract class Stub extends HwBinder implements IBluetoothHci {
        @Override
        public IHwBinder asBinder() {
            return this;
        }

        @Override
        public final java.util.ArrayList<String> interfaceChain() {
            return new java.util.ArrayList<String>(java.util.Arrays.asList(
                    android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName,
                    android.internal.hidl.base.V1_0.IBase.kInterfaceName));

        }

        @Override
        public void debug(NativeHandle fd, java.util.ArrayList<String> options) {
            return;

        }

        @Override
        public final String interfaceDescriptor() {
            return android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName;

        }

        @Override
        public final java.util.ArrayList<byte[/* 32 */]> getHashChain() {
            return new java.util.ArrayList<byte[/* 32 */]>(java.util.Arrays.asList(
                    new byte[/* 32 */]{52,124,-25,70,-127,86,7,86,127,95,59,83,-28,-128,9,-104,-54,90,-71,53,81,65,-16,-120,15,-64,-49,12,31,-59,-61,85} /* 347ce746815607567f5f3b53e4800998ca5ab9355141f0880fc0cf0c1fc5c355 */,
                    new byte[/* 32 */]{-20,127,-41,-98,-48,45,-6,-123,-68,73,-108,38,-83,-82,62,-66,35,-17,5,36,-13,-51,105,87,19,-109,36,-72,59,24,-54,76} /* ec7fd79ed02dfa85bc499426adae3ebe23ef0524f3cd6957139324b83b18ca4c */));

        }

        @Override
        public final void setHALInstrumentation() {

        }

        @Override
        public final boolean linkToDeath(IHwBinder.DeathRecipient recipient, long cookie) {
            return true;

        }

        @Override
        public final void ping() {
            return;

        }

        @Override
        public final android.internal.hidl.base.V1_0.DebugInfo getDebugInfo() {
            android.internal.hidl.base.V1_0.DebugInfo info = new android.internal.hidl.base.V1_0.DebugInfo();
            info.pid = HidlSupport.getPidIfSharable();
            info.ptr = 0;
            info.arch = android.internal.hidl.base.V1_0.DebugInfo.Architecture.UNKNOWN;
            return info;

        }

        @Override
        public final void notifySyspropsChanged() {
            HwBinder.enableInstrumentation();

        }

        @Override
        public final boolean unlinkToDeath(IHwBinder.DeathRecipient recipient) {
            return true;

        }

        @Override
        public IHwInterface queryLocalInterface(String descriptor) {
            if (kInterfaceName.equals(descriptor)) {
                return this;
            }
            return null;
        }

        public void registerAsService(String serviceName) throws android.os.RemoteException {
            registerService(serviceName);
        }

        @Override
        public String toString() {
            return this.interfaceDescriptor() + "@Stub";
        }

        //@Override
        public void onTransact(int _hidl_code, HwParcel _hidl_request, final HwParcel _hidl_reply, int _hidl_flags)
                throws android.os.RemoteException {
            switch (_hidl_code) {
                case 1 /* initialize */:
                {
                    _hidl_request.enforceInterface(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);

                    android.hardware.bluetooth.V1_0.IBluetoothHciCallbacks callback = android.hardware.bluetooth.V1_0.IBluetoothHciCallbacks.asInterface(_hidl_request.readStrongBinder());
                    initialize(callback);
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.send();
                    break;
                }

                case 2 /* sendHciCommand */:
                {
                    _hidl_request.enforceInterface(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);

                    java.util.ArrayList<Byte> command = _hidl_request.readInt8Vector();
                    sendHciCommand(command);
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.send();
                    break;
                }

                case 3 /* sendAclData */:
                {
                    _hidl_request.enforceInterface(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);

                    java.util.ArrayList<Byte> data = _hidl_request.readInt8Vector();
                    sendAclData(data);
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.send();
                    break;
                }

                case 4 /* sendScoData */:
                {
                    _hidl_request.enforceInterface(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);

                    java.util.ArrayList<Byte> data = _hidl_request.readInt8Vector();
                    sendScoData(data);
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.send();
                    break;
                }

                case 5 /* close */:
                {
                    _hidl_request.enforceInterface(android.hardware.bluetooth.V1_0.IBluetoothHci.kInterfaceName);

                    close();
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.send();
                    break;
                }

                case 256067662 /* interfaceChain */:
                {
                    _hidl_request.enforceInterface(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

                    java.util.ArrayList<String> _hidl_out_descriptors = interfaceChain();
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.writeStringVector(_hidl_out_descriptors);
                    _hidl_reply.send();
                    break;
                }

                case 256131655 /* debug */:
                {
                    _hidl_request.enforceInterface(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

                    NativeHandle fd = _hidl_request.readNativeHandle();
                    java.util.ArrayList<String> options = _hidl_request.readStringVector();
                    debug(fd, options);
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.send();
                    break;
                }

                case 256136003 /* interfaceDescriptor */:
                {
                    _hidl_request.enforceInterface(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

                    String _hidl_out_descriptor = interfaceDescriptor();
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.writeString(_hidl_out_descriptor);
                    _hidl_reply.send();
                    break;
                }

                case 256398152 /* getHashChain */:
                {
                    _hidl_request.enforceInterface(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

                    java.util.ArrayList<byte[/* 32 */]> _hidl_out_hashchain = getHashChain();
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    {
                        HwBlob _hidl_blob = new HwBlob(16 /* size */);
                        {
                            int _hidl_vec_size = _hidl_out_hashchain.size();
                            _hidl_blob.putInt32(0 /* offset */ + 8 /* offsetof(hidl_vec<T>, mSize) */, _hidl_vec_size);
                            _hidl_blob.putBool(0 /* offset */ + 12 /* offsetof(hidl_vec<T>, mOwnsBuffer) */, false);
                            HwBlob childBlob = new HwBlob((int)(_hidl_vec_size * 32));
                            for (int _hidl_index_0 = 0; _hidl_index_0 < _hidl_vec_size; ++_hidl_index_0) {
                                {
                                    long _hidl_array_offset_1 = _hidl_index_0 * 32;
                                    byte[] _hidl_array_item_1 = (byte[/* 32 */]) _hidl_out_hashchain.get(_hidl_index_0);

                                    if (_hidl_array_item_1 == null || _hidl_array_item_1.length != 32) {
                                        throw new IllegalArgumentException("Array element is not of the expected length");
                                    }

                                    childBlob.putInt8Array(_hidl_array_offset_1, _hidl_array_item_1);
                                    _hidl_array_offset_1 += 32 * 1;
                                }
                            }
                            _hidl_blob.putBlob(0 /* offset */ + 0 /* offsetof(hidl_vec<T>, mBuffer) */, childBlob);
                        }
                        _hidl_reply.writeBuffer(_hidl_blob);
                    }
                    _hidl_reply.send();
                    break;
                }

                case 256462420 /* setHALInstrumentation */:
                {
                    _hidl_request.enforceInterface(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

                    setHALInstrumentation();
                    break;
                }

                case 256660548 /* linkToDeath */:
                {
                break;
                }

                case 256921159 /* ping */:
                {
                    _hidl_request.enforceInterface(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

                    ping();
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    _hidl_reply.send();
                    break;
                }

                case 257049926 /* getDebugInfo */:
                {
                    _hidl_request.enforceInterface(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

                    android.internal.hidl.base.V1_0.DebugInfo _hidl_out_info = getDebugInfo();
                    _hidl_reply.writeStatus(HwParcel.STATUS_SUCCESS);
                    ((android.internal.hidl.base.V1_0.DebugInfo) _hidl_out_info).writeToParcel(_hidl_reply);
                    _hidl_reply.send();
                    break;
                }

                case 257120595 /* notifySyspropsChanged */:
                {
                    _hidl_request.enforceInterface(android.internal.hidl.base.V1_0.IBase.kInterfaceName);

                    notifySyspropsChanged();
                    break;
                }

                case 257250372 /* unlinkToDeath */:
                {
                break;
                }

            }
        }
    }
}
