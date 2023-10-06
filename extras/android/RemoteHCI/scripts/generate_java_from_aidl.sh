# Run this script to generate the .java files from the .aidl files
# then replace `this.markVintfStability()` with:
#   try {
#     Method method = this.getClass().getMethod("markVintfStability", null);
#     method.invoke(this);
#   } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
#     throw new RuntimeException(e);
#   }

AIDL=$ANDROID_SDK_ROOT/build-tools/34.0.0/aidl

$AIDL \
-oapp/src/main/java \
-Iapp/src/main/aidl \
--stability=vintf \
--structured \
app/src/main/aidl/android/hardware/bluetooth/IBluetoothHci.aidl

$AIDL \
-oapp/src/main/java \
-Iapp/src/main/aidl \
--stability=vintf \
--structured \
app/src/main/aidl/android/hardware/bluetooth/IBluetoothHciCallbacks.aidl

$AIDL \
-oapp/src/main/java \
-Iapp/src/main/aidl \
--stability=vintf \
--structured \
app/src/main/aidl/android/hardware/bluetooth/Status.aidl

