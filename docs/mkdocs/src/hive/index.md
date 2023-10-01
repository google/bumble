HIVE
====

Welcome to the Bumble Hive.
This is a collection of apps and virtual devices that can run entirely in a browser page.
The code for the apps and devices, as well as the Bumble runtime code, runs via [Pyiodide](https://pyodide.org/). 
Pyodide is a Python distribution for the browser and Node.js based on WebAssembly.

The Bumble stack uses a WebSocket to exchange HCI packets with a virtual or physical
Bluetooth controller.

The apps and devices in the hive can be accessed by following the links below. Each 
page has a settings button that may be used to configure the WebSocket URL to use for
the virutal HCI connection. This will typically be the WebSocket URL for a `netsim`
daemon.
There is also a [TOML index](index.toml) that can be used by tools to know at which URL to access 
each of the apps and devices, as well as their names and short desciptions.


Applications
------------

  * [Scanner](web/scanner/scanner.html) - Scans for BLE devices.

Virtual Devices
---------------

  * [Speaker](web/speaker/speaker.html) - Virtual speaker that plays audio in a browser page.
  * [Heart Rate Monitor](web/heart_rate_monitor/heart_rate_monitor.html) - Virtual heart rate monitor.

