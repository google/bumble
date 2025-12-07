:material-android: ANDROID PLATFORM
===================================

Using Bumble with Android is not about running the Bumble stack on the Android
OS itself, but rather using Bumble with the Bluetooth support of the Android
emulator.

The two main use cases are:

* Connecting the Bumble host stack to the Android emulator's virtual controller.
* Using Bumble as an HCI bridge to connect the Android emulator to a physical
    Bluetooth controller, such as a USB dongle, or other HCI transport.

!!! warning
    Bluetooth support in the Android emulator is a recent feature that may still
    be evolving. The information contained here be somewhat out of sync with the
    version of the emulator you are using.
    You will need version 33.1.4.0 or later.

The Android emulator supports Bluetooth in two ways: either by exposing virtual
Bluetooth controllers to which you can connect a virtual Bluetooth host stack, or
by exposing a way to connect your own virtual controller to the Android Bluetooth
stack via a virtual HCI interface.
Both ways are controlled via gRPC requests to the Android emulator controller and/or
from the Android emulator.

## Launching the Emulator

If the version of the emulator you are running does not yet support enabling
Bluetooth support by default or automatically, you must launch the emulator from
the command line.

!!! tip
    For details on how to launch the Android emulator from the command line,
    visit [this Android Studio user guide page](https://developer.android.com/studio/run/emulator-commandline)

The `-packet-streamer-endpoint <endpoint>` command line option may be used to enable
Bluetooth emulation and tell the emulator which virtual controller to connect to.

## Connecting to Netsim

If the emulator doesn't have Bluetooth emulation enabled by default, use the
`-packet-streamer-endpoint default` option to tell it to connect to Netsim.
If Netsim is not running, the emulator will start it automatically.

The Android emulator's virtual Bluetooth controller is called **Netsim**.
Netsim runs as a background process and allows multiple clients to connect to it,
each connecting to its own virtual controller instance hosted by Netsim. All the
clients connected to the same Netsim process can then "talk" to each other over a
virtual radio link layer.
Netsim supports other wireless protocols than Bluetooth, but the relevant part here
is Bluetooth. The virtual Bluetooth controller used by Netsim is sometimes referred to
as **Root Canal**.

Configuring a Bumble Device instance to use netsim as a virtual controller
allows that virtual device to communicate with the Android Bluetooth stack, and
through it with Android applications as well as system-managed profiles.
To connect a Bumble host stack to a netsim virtual controller instance, use
the Bumble `android-netsim` transport in `host` mode (the default).

!!! example "Run the example GATT server connected to the emulator via Netsim"
    ``` shell
    $ python3 run_gatt_server.py device1.json android-netsim
    ```

By default, the Bumble `android-netsim` transport will try to automatically discover
the port number on which the netsim process is exposing its gRPC server interface. If
that discovery process fails, or if you want to specify the interface manually, you
can pass a `hostname` and `port` as parameters to the transport, as: `android-netsim:<host>:<port>`.

!!! example "Run the example GATT server connected to the emulator via Netsim on a localhost, port 8877"
    ``` shell
    $ python3 run_gatt_server.py device1.json android-netsim:localhost:8877
    ```

### Multiple Instances

If you want to connect multiple Bumble devices to netsim, it may be useful to give each one
a netsim controller with a specific name. This can be done using the `name=<name>` transport option.
For example: `android-netsim:localhost:8877,name=bumble1`

## Connecting a Custom Virtual Controller

This is an advanced use case, which may not be officially supported, but should work in recent
versions of the emulator.

The first step is to run the Bumble HCI bridge, specifying netsim as the "host" end of the
bridge, and another controller (typically a USB Bluetooth dongle, but any other supported
transport can work as well) as the "controller" end of the bridge.

To connect a virtual controller to the Android Bluetooth stack, use the bumble `android-netsim` transport in `controller` mode. For example, with port number 8877, the transport name would be: `android-netsim:_:8877,mode=controller`.

!!! example "Connect the Android emulator to the first USB Bluetooth dongle, using the `hci_bridge` application"
    ```shell
    $ bumble-hci-bridge android-netsim:_:8877,mode=controller usb:0
    ```

Then, you can start the emulator and tell it to connect to this bridge, instead of netsim.
You will likely need to start the emulator from the command line, in order to specify the `-packet-streamer-endpoint <hostname>:<port>` option (unless the emulator offers a way to control that feature from a user/ui menu).

!!! example "Launch the emulator with a netsim replacement"
    In this example, we launch an emulator AVD named "Tiramisu", with a Bumble HCI bridge running
    on port 8877.
    ```shell
    $ emulator -packet-streamer-endpoint localhost:8877 -avd Tiramisu
    ```

!!! tip
    Attaching a virtual controller while the Android Bluetooth stack is running may not be well supported. So you may need to disable Bluetooth in your running Android guest
    before attaching the virtual controller, then re-enable it once attached.

## Other Tools

The `show` application that's included with Bumble can be used to parse and pretty-print the HCI packets
from an Android HCI "snoop log" (see [this page](https://source.android.com/devices/bluetooth/verifying_debugging)
for details on how to obtain HCI snoop logs from an Android device).
Use the `--format snoop` option to specify that the file is in that specific format.

!!! example "Analyze an Android HCI snoop log file"
    ```shell
    $ bumble-show --format snoop btsnoop_hci.log
    ```

## Application

Even though there are some sample Applications in this repo, Bumble doesn't have any support to build Bluetooth applications on Android. You may refer to the [Official Doc](https://developer.android.com/develop/connectivity/bluetooth) or other blog articles to learn more about Android and Bluetooth applications.

## Debugging

Note that the HCI Bridge just serves a bridge between the Android Emulator and physical controllers, so if you encounter issues such as `Android cannot scan / pair / connect my another device`, these are usually related to the Android or physical controllers, and not to the Bumble framework.

Setting the environment variable `BUMBLE_LOGLEVEL=DEBUG` when running hci_bridge may be a good first option.

!!! example "Run HCI Bridge with debugging log"
    ```shell
    $ BUMBLE_LOGLEVEL=DEBUG bumble-hci-bridge android-netsim:_:8877,mode=controller usb:0
    ```

Once you can see HCI logs output from bumble-hci-bridge, it means the bridge is properly working.

To further debug Android scenarios, you should get [snoop logs](https://source.android.com/docs/core/connect/bluetooth/verifying_debugging#debugging-with-logs) and [bug reports](https://developer.android.com/studio/debug/bug-report) from Android.

### Common issues

#### Cannot turn on Bluetooth

There might be some commands failures, or the controller may not support some capabilities necessary for Android. Particularly, LE-only controllers are not supported by Android Bluetooth stack.

#### Cannot scan / pair / connect my another device

1. Make sure the other device is in Pairing mode. For Android, it can usually be achieved by opening Settings > Bluetooth page.
2. For LE, make sure the other device has a name in its advertising data, or Android may filter out advertisements without names to avoid spamming.
3. There must be a connectable profile such as A2DP / HFP / HID for Android to connect over Settings page, or you need to have an App to connect GATT or Bluetooth sockets. If there isn't any active profile, the connection will usually be terminated automatically after pairing by Android.
4. Check other HCI event status in snoop logs.

#### Cannot use SCO or LE Audio

SCO and LE Audio are usually unavailable. This is often due to incomplete feature implementation in many common USB dongles.

Additionally, LE Audio is a very recent standard, and cross-controller compatibility is still maturing.
