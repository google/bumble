ANDROID REMOTE HCI APP
======================

This application allows using an android phone's built-in Bluetooth controller with 
a Bumble host stack running outside the phone (typically a development laptop or desktop).
The app runs an HCI proxy between a TCP socket on the "outside" and the Bluetooth HCI HAL
on the "inside". (See [this page](https://source.android.com/docs/core/connect/bluetooth) for a high level 
description of the Android Bluetooth HCI HAL).
The HCI packets received on the TCP socket are forwarded to the phone's controller, and the 
packets coming from the controller are forwarded to the TCP socket.


Building
--------

You can build the app by running `./gradlew build` (use `gradlew.bat` on Windows) from the `RemoteHCI` top level directory.
You can also build with Android Studio: open the `RemoteHCI` project. You can build and/or debug from there.

If the build succeeds, you can find the app APKs (debug and release) at:

  * [Release] ``app/build/outputs/apk/release/app-release-unsigned.apk``
  * [Debug] ``app/build/outputs/apk/debug/app-debug.apk``


Running
-------

### Preconditions
When the proxy starts (tapping the "Start" button in the app's main activity), it will try to 
bind to the Bluetooth HAL. This requires disabling SELinux temporarily, and being the only HAL client.

#### Disabling SELinux
Binding to the Bluetooth HCI HAL requires certain SELinux permissions that can't simply be changed
on a device without rebuilding its system image. To bypass these restrictions, you will need
to disable SELinux on your phone (please be aware that this is global, not just for the proxy app,
so proceed with caution).
In order to disable SELinux, you need to root the phone (it may be advisable to do this on a
development phone).

!!! tip "Disabling SELinux Temporarily"
    Restart `adb` as root:
    ```bash
    $ adb root
    ```

    Then disable SELinux
    ```bash
    $ adb shell setenforce 0
    ```

    Once you're done using the proxy, you can restore SELinux, if you need to, with
    ```bash
    $ adb shell setenforce 1
    ```

    This state will also reset to the normal SELinux enforcement when you reboot.

#### Stopping the bluetooth process
Since the Bluetooth HAL service can only accept one client, and that in normal conditions 
that client is the Android's bluetooth stack, it is required to first shut down the 
Android bluetooth stack process.

!!! tip "Checking if the Bluetooth process is running"
    ```bash
    $ adb shell "ps -A | grep com.google.android.bluetooth"
    ```
    If the process is running, you will get a line like:
    ```
    bluetooth 10759 876 17455796 136620 do_epoll_wait 0 S com.google.android.bluetooth
    ```
    If you don't, it means that the process is not running and you are clear to proceed.

Simply turning Bluetooth off from the phone's settings does not ensure that the bluetooth process will exit.
If the bluetooth process is still running after toggling Bluetooth off from the settings, you may try enabling
Airplane Mode, then rebooting. The bluetooth process should, in theory, not restart after the reboot.

!!! tip "Stopping the bluetooth process with adb"
    ```bash
    $ adb shell cmd bluetooth_manager disable
    ```

### Starting the app
You can start the app from the Android launcher, from Android Studio, or with `adb`

#### Launching from the launcher
Just tap the app icon on the launcher, check the TCP port that is configured, and tap
the "Start" button.

#### Launching with `adb`
Using the `am` command, you can start the activity, and pass it arguments so that you can
automatically start the proxy, and/or set the port number.

!!! tip "Launching from adb with auto-start"
    ```bash
    $ adb shell am start -n com.github.google.bumble.remotehci/.MainActivity --ez autostart true
    ```

!!! tip "Launching from adb with auto-start and a port"
    In this example, we auto-start the proxy upon launch, with the port set to 9995
    ```bash
    $ adb shell am start -n com.github.google.bumble.remotehci/.MainActivity --ez autostart true --ei port 9995
    ```

#### Selecting a TCP port
The RemoteHCI app's main activity has a "TCP Port" setting where you can change the port on
which the proxy is accepting connections. If the default value isn't suitable, you can 
change it there (you can also use the special value 0 to let the OS assign a port number for you).

### Connecting to the proxy
To connect the Bumble stack to the proxy, you need to be able to reach the phone's network 
stack. This can be done over the phone's WiFi connection, or, alternatively, using an `adb`
TCP forward (which should be faster than over WiFi).

!!! tip "Forwarding TCP with `adb`"
    To connect to the proxy via an `adb` TCP forward, use:
    ```bash
    $ adb forward tcp:<outside-port> tcp:<inside-port>
    ```
    Where ``<outside-port>`` is the port number for a listening socket on your laptop or 
    desktop machine, and <inside-port> is the TCP port selected in the app's user interface.
    Those two ports may be the same, of course.
    For example, with the default TCP port 9993:
    ```bash
    $ adb forward tcp:9993 tcp:9993
    ```

Once you've ensured that you can reach the proxy's TCP port on the phone, either directly or
via an `adb` forward, you can then use it as a Bumble transport, using the transport name: 
``tcp-client:<host>:<port>`` syntax.

!!! example "Connecting a Bumble client"
    Connecting the `bumble-controller-info` app to the phone's controller.
    Assuming you have set up an `adb` forward on port 9993:
    ```bash
    $ bumble-controller-info tcp-client:localhost:9993
    ```

    Or over WiFi with, in this example, the IP address of the phone being ```192.168.86.27```
    ```bash
    $ bumble-controller-info tcp-client:192.168.86.27:9993
    ```
