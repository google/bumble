:material-linux: LINUX PLATFORM
===============================

In addition to all the standard functionality available from the project by running the python tools and/or writing your own apps by leveraging the API, it is also possible on Linux hosts to interface the Bumble stack with the native BlueZ stack, and with Bluetooth controllers.

Using Bumble With BlueZ
-----------------------

A Bumble virtual controller can be attached to the BlueZ stack.
Attaching a controller to BlueZ can be done by either simulating a UART HCI interface, or by using the VHCI driver interface if available.
In both cases, the controller can run locally on the Linux host, or remotely on a different host, with a bridge between the remote controller and the local BlueZ host, which may be useful when the BlueZ stack is running on an embedded system, or a host on which running the Bumble controller is not convenient.

### Using VHCI

With the [VHCI transport](../transports/vhci.md) you can attach a Bumble virtual controller to the BlueZ stack. Once attached, the controller will appear just like any other controller, and thus can be used with the standard BlueZ tools.

!!! example "Attaching a virtual controller"
    With the example app `run_controller.py`:
    ```
    PYTHONPATH=. python3 examples/run_controller.py F6:F7:F8:F9:FA:FB examples/device1.json vhci
    ```
    
    You should see a 'Virtual Bus' controller. For example:
    ```
    $ hciconfig
    hci0:	Type: Primary  Bus: Virtual
        BD Address: F6:F7:F8:F9:FA:FB  ACL MTU: 27:64  SCO MTU: 0:0
        UP RUNNING 
        RX bytes:0 acl:0 sco:0 events:43 errors:0
        TX bytes:274 acl:0 sco:0 commands:43 errors:0
    ```

    And scanning for devices should show the virtual 'Bumble' device that's running as part of the `run_controller.py` example app:
    ```
    pi@raspberrypi:~ $ sudo hcitool -i hci2 lescan
    LE Scan ...
    F0:F1:F2:F3:F4:F5 Bumble
    ```

### Using HCI Sockets

HCI sockets provide a way to send/receive HCI packets to/from a Bluetooth controller managed by the kernel.
The HCI device referenced by an `hci-socket` transport (`hciX`, where `X` is an integer, with `hci0` being the first controller device, and so on) must be in the `DOWN` state before it can be opened as a transport.
You can bring a HCI controller `UP` or `DOWN` with `hciconfig`.

!!! tip "List all available controllers"
    The command
    ```
    $ hciconfig
    ```
    lists all available HCI controllers and their state.

    Example:

    ```
    pi@raspberrypi:~ $ hciconfig
    hci1:	Type: Primary  Bus: USB
        BD Address: 00:16:A4:5A:40:F2  ACL MTU: 1021:8  SCO MTU: 64:1
        DOWN 
        RX bytes:84056 acl:0 sco:0 events:51 errors:0
        TX bytes:1980 acl:0 sco:0 commands:90 errors:0

    hci0:	Type: Primary  Bus: UART
        BD Address: DC:A6:32:75:2C:97  ACL MTU: 1021:8  SCO MTU: 64:1
        DOWN 
        RX bytes:68038 acl:0 sco:0 events:692 errors:0
        TX bytes:20105 acl:0 sco:0 commands:843 errors:0
    ```

!!! tip "Disabling `bluetoothd`"
    When the Bluetooth daemon, `bluetoothd`, is running, it will try to use any HCI controller attached to the BlueZ stack, automatically. This means that whenever an HCI socket transport is released, it is likely that `bluetoothd` will take it over, so you will get a "device busy" condition (ex: `OSError: [Errno 16] Device or resource busy`). If that happens, you can always use 
    ```
    $ hciconfig hci0 down
    ``` 
    (or `hciX` with `X` being the index of the controller device you want to use), but a simpler solution is to just stop the `bluetoothd` daemon, with a command like:
    ```
    $ sudo systemctl stop bluetooth.service
    ```
    You can always re-start the daemon with
    ```
    $ sudo systemctl start bluetooth.service
    ```

### Using a Simulated UART HCI

### Bridge to a Remote Controller


Using Bumble With Bluetooth Controllers
---------------------------------------

A Bumble application can interface with a local Bluetooth controller.
If your Bluetooth controller is a standard HCI USB controller, see the [USB Transport page](../transports/usb.md) for details on how to use HCI USB controllers.
If your Bluetooth controller is a standard HCI UART controller, see the [Serial Transport page](../transports/serial.md).
Alternatively, a Bumble Host object can communicate with one of the platform's controllers via an HCI Socket.

`<details to be filled in>`

### Raspberry Pi 4 :fontawesome-brands-raspberry-pi:

You can use the Bluetooth controller either via the kernel, or directly to the device.

#### Via The Kernel

Use an HCI Socket transport

#### Directly
In order to use the Bluetooth controller directly on a Raspberry Pi 4 board, you need to ensure that it isn't being used by the BlueZ stack (which it probably is by default).

```
$ sudo systemctl stop hciuart
```
should detach the controller from the stack, after which you can use the HCI UART with Bumble.

!!! tip "Check the device name for the UART and at what speed it should be opened"
    ```
    $ sudo systemctl status hciuart
    ```
    should show the speed at which the UART should be opened.
    For example:
    ```
    $ sudo systemctl status hciuart
     hciuart.service - Configure Bluetooth Modems connected by UART
      Loaded: loaded (/lib/systemd/system/hciuart.service; enabled; vendor preset: enabled)
      Active: active (running) since Fri 2021-06-18 02:17:28 BST; 1min 10s ago
     Process: 357 ExecStart=/usr/bin/btuart (code=exited, status=0/SUCCESS)
    Main PID: 586 (hciattach)
       Tasks: 1 (limit: 4915)
      CGroup: /system.slice/hciuart.service
              └─586 /usr/bin/hciattach /dev/serial1 bcm43xx 3000000 flow -
    ```
    When run before stopping the `hciuart` service, shows that on this board, the UART device is `/dev/serial` and the speed is `3000000`

!!! example "Example: scanning"
    ```
    python3 run_scanner.py serial:/dev/serial1,3000000
    ```

