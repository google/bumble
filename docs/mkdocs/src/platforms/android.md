:material-android: ANDROID PLATFORM
===================================

Using Bumble with Android is not about running the Bumble stack on the Android
OS itself, but rather using Bumble with the Bluetooth support of the Android
emulator.

The two main use cases are:

  * Connecting the Bumble host stack to the Android emulator's virtual controller.
  * Using Bumble as an HCI bridge to connect the Android emulator to a physical
    Bluetooth controller, such as a USB dongle

!!! warning
    Bluetooth support in the Android emulator is a recent feature that may still
    be evolving. The information contained here be somewhat out of sync with the
    version of the emulator you are using.
    You will need version 31.3.8.0 or later.

The Android emulator supports Bluetooth in two ways: either by exposing virtual
Bluetooth controllers to which you can connect a virtual Bluetooth host stack, or
by exposing an way to connect your own virtual controller to the Android Bluetooth
stack via a virtual HCI interface.
Both ways are controlled via gRPC requests to the Android emulator.

## Launching the Emulator

If the version of the emulator you are running does not yet support enabling
Bluetooth support by default or automatically, you must launch the emulator from
the command line.

!!! tip
    For details on how to launch the Android emulator from the command line,
    visit [this Android Studio user guide page](https://developer.android.com/studio/run/emulator-commandline)

The `-grpc <port>` command line option may be used to select a gRPC port other than the default.

## Connecting to Root Canal

The Android emulator's virtual Bluetooth controller is called **Root Canal**.
Multiple instances of Root Canal virtual controllers can be instantiated, they
communicate link layer packets between them, thus creating a virtual radio network.
Configuring a Bumble Device instance to use Root Canal as a virtual controller
allows that virtual device to communicate with the Android Bluetooth stack, and
through it with Android applications as well as system-managed profiles.
To connect a Bumble host stack to a Root Canal virtual controller instance, use
the bumble `android-emulator` transport in `host` mode (the default).

!!! example "Run the example GATT server connected to the emulator"
    ``` shell
    $ python run_gatt_server.py device1.json android-emulator
    ```

## Connecting a Custom Virtual Controller

This is an advanced use case, which may not be officially supported, but should work in recent
versions of the emulator.
You will likely need to start the emulator from the command line, in order to specify the `-forward-vhci` option (unless the emulator offers a way to control that feature from a user/ui menu).

!!! example "Launch the emulator with VHCI forwarding"
    In this example, we launch an emulator AVD named "Tiramisu"
    ```shell
    $ emulator -forward-vhci -avd Tiramisu
    ```

!!! tip
    Attaching a virtual controller use the VHCI forwarder while the Android Bluetooth stack
    is running isn't supported. So you need to disable Bluetooth in your running Android guest
    before attaching the virtual controller, then re-enable it once attached.

To connect a virtual controller to the Android Bluetooth stack, use the bumble `android-emulator` transport in `controller` mode. For example, using the default gRPC port, the transport name would be: `android-emulator:mode=controller`.

!!! example "Connect the Android emulator to the first USB Bluetooth dongle, using the `hci_bridge` application"
    ```shell
    $ bumble-hci-bridge android-emulator:mode=controller usb:0
    ```

## Other Tools

The `show` application that's included with Bumble can be used to parse and pretty-print the HCI packets
from an Android HCI "snoop log" (see [this page](https://source.android.com/devices/bluetooth/verifying_debugging)
for details on how to obtain HCI snoop logs from an Android device).
Use the `--format snoop` option to specify that the file is in that specific format.

!!! example "Analyze an Android HCI snoop log file"
    ```shell
    $ bumble-show --format snoop btsnoop_hci.log
    ```
