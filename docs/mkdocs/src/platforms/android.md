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
    $ python run_gatt_server.py device1.json android-netsim
    ```

By default, the Bumble `android-netsim` transport will try to automatically discover
the port number on which the netsim process is exposing its gRPC server interface. If
that discovery process fails, or if you want to specify the interface manually, you 
can pass a `hostname` and `port` as parameters to the transport, as: `android-netsim:<host>:<port>`.

!!! example "Run the example GATT server connected to the emulator via Netsim on a localhost, port 8877"
    ``` shell
    $ python run_gatt_server.py device1.json android-netsim:localhost:8877
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
