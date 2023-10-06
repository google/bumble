/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
package android.hardware.bluetooth;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public interface IBluetoothHci extends android.os.IInterface
{
  /** Default implementation for IBluetoothHci. */
  public static class Default implements android.hardware.bluetooth.IBluetoothHci
  {
    @Override public void close() throws android.os.RemoteException
    {
    }
    @Override public void initialize(android.hardware.bluetooth.IBluetoothHciCallbacks callback) throws android.os.RemoteException
    {
    }
    @Override public void sendAclData(byte[] data) throws android.os.RemoteException
    {
    }
    @Override public void sendHciCommand(byte[] command) throws android.os.RemoteException
    {
    }
    @Override public void sendIsoData(byte[] data) throws android.os.RemoteException
    {
    }
    @Override public void sendScoData(byte[] data) throws android.os.RemoteException
    {
    }
    @Override
    public android.os.IBinder asBinder() {
      return null;
    }
  }
  /** Local-side IPC implementation stub class. */
  public static abstract class Stub extends android.os.Binder implements android.hardware.bluetooth.IBluetoothHci
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
     * Cast an IBinder object into an android.hardware.bluetooth.IBluetoothHci interface,
     * generating a proxy if needed.
     */
    public static android.hardware.bluetooth.IBluetoothHci asInterface(android.os.IBinder obj)
    {
      if ((obj==null)) {
        return null;
      }
      android.os.IInterface iin = obj.queryLocalInterface(DESCRIPTOR);
      if (((iin!=null)&&(iin instanceof android.hardware.bluetooth.IBluetoothHci))) {
        return ((android.hardware.bluetooth.IBluetoothHci)iin);
      }
      return new android.hardware.bluetooth.IBluetoothHci.Stub.Proxy(obj);
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
        case TRANSACTION_close:
        {
          this.close();
          reply.writeNoException();
          break;
        }
        case TRANSACTION_initialize:
        {
          android.hardware.bluetooth.IBluetoothHciCallbacks _arg0;
          _arg0 = android.hardware.bluetooth.IBluetoothHciCallbacks.Stub.asInterface(data.readStrongBinder());
          this.initialize(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_sendAclData:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          this.sendAclData(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_sendHciCommand:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          this.sendHciCommand(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_sendIsoData:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          this.sendIsoData(_arg0);
          reply.writeNoException();
          break;
        }
        case TRANSACTION_sendScoData:
        {
          byte[] _arg0;
          _arg0 = data.createByteArray();
          this.sendScoData(_arg0);
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
    private static class Proxy implements android.hardware.bluetooth.IBluetoothHci
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
      @Override public void close() throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          boolean _status = mRemote.transact(Stub.TRANSACTION_close, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void initialize(android.hardware.bluetooth.IBluetoothHciCallbacks callback) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeStrongInterface(callback);
          boolean _status = mRemote.transact(Stub.TRANSACTION_initialize, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void sendAclData(byte[] data) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(data);
          boolean _status = mRemote.transact(Stub.TRANSACTION_sendAclData, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void sendHciCommand(byte[] command) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(command);
          boolean _status = mRemote.transact(Stub.TRANSACTION_sendHciCommand, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void sendIsoData(byte[] data) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(data);
          boolean _status = mRemote.transact(Stub.TRANSACTION_sendIsoData, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
      @Override public void sendScoData(byte[] data) throws android.os.RemoteException
      {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try {
          _data.writeInterfaceToken(DESCRIPTOR);
          _data.writeByteArray(data);
          boolean _status = mRemote.transact(Stub.TRANSACTION_sendScoData, _data, _reply, 0);
          _reply.readException();
        }
        finally {
          _reply.recycle();
          _data.recycle();
        }
      }
    }
    static final int TRANSACTION_close = (android.os.IBinder.FIRST_CALL_TRANSACTION + 0);
    static final int TRANSACTION_initialize = (android.os.IBinder.FIRST_CALL_TRANSACTION + 1);
    static final int TRANSACTION_sendAclData = (android.os.IBinder.FIRST_CALL_TRANSACTION + 2);
    static final int TRANSACTION_sendHciCommand = (android.os.IBinder.FIRST_CALL_TRANSACTION + 3);
    static final int TRANSACTION_sendIsoData = (android.os.IBinder.FIRST_CALL_TRANSACTION + 4);
    static final int TRANSACTION_sendScoData = (android.os.IBinder.FIRST_CALL_TRANSACTION + 5);
  }
  public static final java.lang.String DESCRIPTOR = "android$hardware$bluetooth$IBluetoothHci".replace('$', '.');
  public void close() throws android.os.RemoteException;
  public void initialize(android.hardware.bluetooth.IBluetoothHciCallbacks callback) throws android.os.RemoteException;
  public void sendAclData(byte[] data) throws android.os.RemoteException;
  public void sendHciCommand(byte[] command) throws android.os.RemoteException;
  public void sendIsoData(byte[] data) throws android.os.RemoteException;
  public void sendScoData(byte[] data) throws android.os.RemoteException;
}
