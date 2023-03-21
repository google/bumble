BENCH TOOL
==========

The "bench" tool implements a number of different ways of measuring the
throughput and/or latency between two devices.

# General Usage

```
Usage: bench.py [OPTIONS] COMMAND [ARGS]...

Options:
  --device-config FILENAME        Device configuration file
  --role [sender|receiver|ping|pong]
  --mode [gatt-client|gatt-server|l2cap-client|l2cap-server|rfcomm-client|rfcomm-server]
  --att-mtu MTU                   GATT MTU (gatt-client mode)  [23<=x<=517]
  -s, --packet-size SIZE          Packet size (server role)  [8<=x<=4096]
  -c, --packet-count COUNT        Packet count (server role)
  -sd, --start-delay SECONDS      Start delay (server role)
  --help                          Show this message and exit.

Commands:
  central     Run as a central (initiates the connection)
  peripheral  Run as a peripheral (waits for a connection)
```

## Options for the ``central`` Command
```
Usage: bumble-bench central [OPTIONS] TRANSPORT

  Run as a central (initiates the connection)

Options:
  --peripheral ADDRESS_OR_NAME    Address or name to connect to
  --connection-interval, --ci CONNECTION_INTERVAL
                                  Connection interval (in ms)
  --phy [1m|2m|coded]             PHY to use
  --help                          Show this message and exit.
```


To test once device against another, one of the two devices must be running 
the ``peripheral`` command and the other the ``central`` command. The device
running the ``peripheral`` command will accept connections from the device
running the ``central`` command.
When using Bluetooth LE (all modes except for ``rfcomm-server`` and ``rfcomm-client``utils),
the default addresses configured in the tool should be sufficient. But when using 
Bluetooth Classic, the address of the Peripheral must be specified on the Central 
using the ``--peripheral`` option. The address will be printed by the Peripheral when
it starts.

Independently of whether the device is the Central or Peripheral, each device selects a
``mode`` and and ``role`` to run as. The ``mode`` and ``role`` of the Central and Peripheral
must be compatible.

Device 1 mode     | Device 2 mode
------------------|------------------
``gatt-client``   | ``gatt-server``
``l2cap-client``  | ``l2cap-server``
``rfcomm-client`` | ``rfcomm-server``

Device 1 role | Device 2 role
--------------|--------------
``sender``    | ``receiver``
``ping``      | ``pong``


# Examples

In the following examples, we have two USB Bluetooth controllers, one on `usb:0` and
the other on `usb:1`, and two consoles/terminals. We will run a command in each.

!!! example "GATT Throughput"
    Using the default mode and role for the Central and Peripheral.

    In the first console/terminal:
    ```
    $ bumble-bench peripheral usb:0
    ```

    In the second console/terminal:
    ```
    $ bumble-bench central usb:1
    ```

    In this default configuration, the Central runs a Sender, as a GATT client, 
    connecting to the Peripheral running a Receiver, as a GATT server.

!!! example "L2CAP Throughput"
    In the first console/terminal:
    ```
    $ bumble-bench --mode l2cap-server peripheral usb:0
    ```

    In the second console/terminal:
    ```
    $ bumble-bench --mode l2cap-client central usb:1
    ```

!!! example "RFComm Throughput"
    In the first console/terminal:
    ```
    $ bumble-bench --mode rfcomm-server peripheral usb:0
    ```

    NOTE: the BT address of the Peripheral will be printed out, use it with the
    ``--peripheral`` option for the Central.

    In this example, we use a larger packet size and packet count than the default.

    In the second console/terminal:
    ```
    $ bumble-bench --mode rfcomm-client --packet-size 2000 --packet-count 100 central --peripheral 00:16:A4:5A:40:F2 usb:1
    ```

!!! example "Ping/Pong Latency"
    In the first console/terminal:
    ```
    $ bumble-bench --role pong peripheral usb:0
    ```

    In the second console/terminal:
    ```
    $ bumble-bench --role ping central usb:1
    ```

!!! example "Reversed modes with GATT and custom connection interval"
    In the first console/terminal:
    ```
    $ bumble-bench --mode gatt-client peripheral usb:0
    ```

    In the second console/terminal:
    ```
    $ bumble-bench --mode gatt-server central --ci 10 usb:1
    ```

!!! example "Reversed modes with L2CAP and custom PHY"
    In the first console/terminal:
    ```
    $ bumble-bench --mode l2cap-client peripheral usb:0
    ```

    In the second console/terminal:
    ```
    $ bumble-bench --mode l2cap-server central --phy 2m usb:1
    ```

!!! example "Reversed roles with L2CAP"
    In the first console/terminal:
    ```
    $ bumble-bench --mode l2cap-client --role sender peripheral usb:0
    ```

    In the second console/terminal:
    ```
    $ bumble-bench --mode l2cap-server --role receiver central usb:1
    ```
