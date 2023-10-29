ANDROID BENCH APP
=================

This Android app that is compatible with the Bumble `bench` command line app.
This app can be used to test the throughput and latency between two Android
devices, or between an Android device and another device running the Bumble
`bench` app.
Only the RFComm Client, RFComm Server, L2CAP Client and L2CAP Server modes are
supported.

Building
--------

You can build the app by running `./gradlew build` (use `gradlew.bat` on Windows) from the `BtBench` top level directory.
You can also build with Android Studio: open the `BtBench` project. You can build and/or debug from there.

If the build succeeds, you can find the app APKs (debug and release) at:

  * [Release] ``app/build/outputs/apk/release/app-release-unsigned.apk``
  * [Debug] ``app/build/outputs/apk/debug/app-debug.apk``


Running
-------

### Starting the app
You can start the app from the Android launcher, from Android Studio, or with `adb`

#### Launching from the launcher
Just tap the app icon on the launcher, check the parameters, and tap
one of the benchmark action buttons.

#### Launching with `adb`
Using the `am` command, you can start the activity, and pass it arguments so that you can
automatically start the benchmark test, and/or set the parameters.

| Parameter Name         | Parameter Type | Description
|------------------------|----------------|------------
| autostart              | String         | Benchmark to start. (rfcomm-client, rfcomm-server, l2cap-client or l2cap-server)
| packet-count           | Integer        | Number of packets to send (rfcomm-client and l2cap-client only)
| packet-size            | Integer        | Number of bytes per packet (rfcomm-client and l2cap-client only)
| peer-bluetooth-address | Integer        | Peer Bluetooth address to connect to (rfcomm-client and l2cap-client | only)


!!! tip "Launching from adb with auto-start"
    In this example, we auto-start the Rfcomm Server bench action.
    ```bash
    $ adb shell am start -n com.github.google.bumble.btbench/.MainActivity --es autostart rfcomm-server
    ```

!!! tip "Launching from adb with auto-start and some parameters"
    In this example, we auto-start the Rfcomm Client bench action, set the packet count to 100,
    and the packet size to 1024, and connect to DA:4C:10:DE:17:02
    ```bash
    $ adb shell am start -n com.github.google.bumble.btbench/.MainActivity --es autostart rfcomm-client --ei packet-count 100 --ei packet-size 1024 --es peer-bluetooth-address DA:4C:10:DE:17:02
    ```

#### Selecting a Peer Bluetooth Address
The app's main activity has a "Peer Bluetooth Address" setting where you can change the address.

!!! note "Bluetooth Address for L2CAP vs RFComm"
    For BLE (L2CAP mode), the address of a device typically changes regularly (it is randomized for privacy), whereas the Bluetooth Classic addresses will remain the same (RFComm mode).
    If two devices are paired and bonded, then they will each "see" a non-changing address for each other even with BLE (Resolvable Private Address)

