/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
package android.hardware.bluetooth;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public interface IBluetoothHciCallbacks extends android.os.IInterface
{
  /** Default implementation for IBluetoothHciCallbacks. */
  public static class Default implements android.hardware.bluetooth.IBluetoothHciCallbacks
  {
    @Override public void aclDataReceived(byte[] data) throws android.os.RemoteException
    {
    }
    @Override public void hciEventReceived(byte[] event) throws android.os.RemoteException
    {
    }
    @Override public void initializationComplete(int status) throws android.os.RemoteException
    {
    }
    @Override public void isoDataReceived(byte[] data) throws android.os.RemoteException
    {
    }
    @Override public void scoDataReceived(byte[] data) throws android.os.RemoteException
    {
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements android.hardware.bluetooth.IBluetoothHciCallbacks
  {
    /** Construct the stub at attach it to the interface. */
    public Stub()
    {
      //this.markVintfStability();
      try {
        Method method = this.getClass().getMethod("markVintfStability", (Class<?>[])null);
        method.invoke(this);
      } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
      this.attachInterface(this, DESCRIPTOR);
    }
    /**
     * Cast an IBinder object into an android.hardware.bluetooth.IBluetoothHciCallbacks interface,
     * generating a proxy if needed.
     */
    public static android.hardware.bluetooth.IBluetoothHciCallbacks asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof android.hardware.bluetooth.IBluetoothHciCallbacks))) {
        return ((android.hardware.bluetooth.IBluetoothHciCallbacks)iin);
      }
      return new android.hardware.bluetooth.IBluetoothHciCallbacks.Stub.Proxy(obj);
    }
    @Override public android.os.IBinder asBinder()
    {
      return this;
    }
    @Override public boolean onTransact(int code, android.os.Parcel data, android.os.Parcel reply, int flags) throws android.os.RemoteException
    {
      java.lang.String descriptor = DESCRIPTOR;
      if (code >= android.os.IBinder.FIRST_CALL_TRANSACTION && code <= android.os.IBinder.LAST_CALL_TRANSACTION) {
        data.enforceInterface(descriptor);
      }
      switch (code)
      {
        case INTERFACE_TRANSACTION:
        {
          reply.writeString(descriptor);
          return true;
        }
      }
      switch (code)
      {
        case TRANSACTION_aclDataReceived:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          this.aclDataReceived(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_hciEventReceived:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          this.hciEventReceived(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_initializationComplete:
        {
          int _arg0;
          _arg0 = data.readInt();
          this.initializationComplete(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_isoDataReceived:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          this.isoDataReceived(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_scoDataReceived:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          this.scoDataReceived(_arg0);
          reply.writeNoException();
          break;
        }
        default:
        {
          return super.onTransact(code, data, reply, flags);
        }
      }
      return true;
    }
    private static class Proxy implements android.hardware.bluetooth.IBluetoothHciCallbacks
    {
      private android.os.IBinder mRemote;
      Proxy(android.os.IBinder remote)
      {
        mRemote = remote;
      }
      @Override public android.os.IBinder asBinder()
      {
        return mRemote;
      }
      public java.lang.String getInterfaceDescriptor()
      {
        return DESCRIPTOR;
      }
      @Override public void aclDataReceived(byte[] data) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(data);
          boolean _status = mRemote.transact(Stub.TRANSACTION_aclDataReceived, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void hciEventReceived(byte[] event) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(event);
          boolean _status = mRemote.transact(Stub.TRANSACTION_hciEventReceived, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void initializationComplete(int status) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeInt(status);
          boolean _status = mRemote.transact(Stub.TRANSACTION_initializationComplete, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void isoDataReceived(byte[] data) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(data);
          boolean _status = mRemote.transact(Stub.TRANSACTION_isoDataReceived, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void scoDataReceived(byte[] data) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(data);
          boolean _status = mRemote.transact(Stub.TRANSACTION_scoDataReceived, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
    }
    static final int TRANSACTION_aclDataReceived = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_hciEventReceived = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_initializationComplete = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
    static final int TRANSACTION_isoDataReceived = (android.os.IBinder.FIRST_CALL_TRANSACTION + 3);
    static final int TRANSACTION_scoDataReceived = (android.os.IBinder.FIRST_CALL_TRANSACTION + 4);
  }
  public static final java.lang.String DESCRIPTOR = "android$hardware$bluetooth$IBluetoothHciCallbacks".replace('$', '.');
  public void aclDataReceived(byte[] data) throws android.os.RemoteException;
  public void hciEventReceived(byte[] event) throws android.os.RemoteException;
  public void initializationComplete(int status) throws android.os.RemoteException;
  public void isoDataReceived(byte[] data) throws android.os.RemoteException;
  public void scoDataReceived(byte[] data) throws android.os.RemoteException;
}
