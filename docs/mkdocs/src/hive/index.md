HIVE
====

Welcome to the Bumble Hive.
This is a collection of apps and virtual devices that can run entirely in a browser page.
The code for the apps and devices, as well as the Bumble runtime code, runs via [Pyodide](https://pyodide.org/).
Pyodide is a Python distribution for the browser and Node.js based on WebAssembly.

The Bumble stack uses a WebSocket to exchange HCI packets with a virtual or physical
Bluetooth controller.

The apps and devices in the hive can be accessed by following the links below. Each
page has a settings button that may be used to configure the WebSocket URL to use for
the virtual HCI connection. This will typically be the WebSocket URL for a `netsim`
daemon.
There is also a [TOML index](index.toml) that can be used by tools to know at which URL to access
each of the apps and devices, as well as their names and short descriptions.

!!! tip "Using `netsim`"
    When the `netsimd` daemon is running (for example when using the Android Emulator that
    is included in Android Studio), the daemon listens for connections on a TCP port.
    To find out what this TCP port is, you can read the `netsim.ini` file that `netsimd`
    creates, it includes a line with `web.port=<tcp-port>` (for example `web.port=7681`).
    The location of the `netsim.ini` file is platform-specific.

    === "macOS"
        On macOS, the directory where `netsim.ini` is stored is $TMPDIR
        ```bash
            $ cat $TMPDIR/netsim.ini
        ```

    === "Linux"
        On Linux, the directory where `netsim.ini` is stored is $XDG_RUNTIME_DIR
        ```bash
            $ cat $XDG_RUNTIME_DIR/netsim.ini
        ```


!!! tip "Using a local radio"
    You can connect the hive virtual apps and devices to a local Bluetooth radio, like,
    for example, a USB dongle.
    For that, you need to run a local HCI bridge to bridge a local HCI device to a WebSocket
    that a web page can connect to.
    Use the `bumble-hci-bridge` app, with the host transport set to a WebSocket server on an
    available port (ex: `ws-server:_:7682`) and the controller transport set to the transport
    name for the radio you want to use (ex: `usb:0` for the first USB dongle)


Applications
------------

  * [Scanner](web/scanner/scanner.html) - Scans for BLE devices.

Virtual Devices
---------------

  * [Speaker](web/speaker/speaker.html) - Virtual speaker that plays audio in a browser page.
  * [Heart Rate Monitor](web/heart_rate_monitor/heart_rate_monitor.html) - Virtual heart rate monitor.

