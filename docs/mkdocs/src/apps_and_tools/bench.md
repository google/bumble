BENCH TOOL
==========

The "bench" tool implements a number of different ways of measuring the
throughput and/or latency between two devices.

# General Usage

```
Usage: bumble-bench [OPTIONS] COMMAND [ARGS]...

Options:
  --device-config FILENAME        Device configuration file
  --scenario [send|receive|ping|pong]
  --mode [gatt-client|gatt-server|l2cap-client|l2cap-server|rfcomm-client|rfcomm-server]
  --att-mtu MTU                   GATT MTU (gatt-client mode)  [23<=x<=517]
  --extended-data-length TEXT     Request a data length upon connection,
                                  specified as tx_octets/tx_time
  --role-switch [central|peripheral]
                                  Request role switch upon connection (central
                                  or peripheral)
  --rfcomm-channel INTEGER        RFComm channel to use (specify 0 for channel
                                  discovery via SDP)
  --rfcomm-uuid TEXT              RFComm service UUID to use (ignored if
                                  --rfcomm-channel is not 0)
  --rfcomm-l2cap-mtu INTEGER      RFComm L2CAP MTU
  --rfcomm-max-frame-size INTEGER
                                  RFComm maximum frame size
  --rfcomm-initial-credits INTEGER
                                  RFComm initial credits
  --rfcomm-max-credits INTEGER    RFComm max credits
  --rfcomm-credits-threshold INTEGER
                                  RFComm credits threshold
  --l2cap-psm INTEGER             L2CAP PSM to use
  --l2cap-mtu INTEGER             L2CAP MTU to use
  --l2cap-mps INTEGER             L2CAP MPS to use
  --l2cap-max-credits INTEGER     L2CAP maximum number of credits allowed for
                                  the peer
  -s, --packet-size SIZE          Packet size (send or ping scenario)
                                  [8<=x<=8192]
  -c, --packet-count COUNT        Packet count (send or ping scenario)
  -sd, --start-delay SECONDS      Start delay (send or ping scenario)
  --repeat N                      Repeat the run N times (send and ping
                                  scenario)(0, which is the fault, to run just
                                  once)
  --repeat-delay SECONDS          Delay, in seconds, between repeats
  --pace MILLISECONDS             Wait N milliseconds between packets (0,
                                  which is the fault, to send as fast as
                                  possible)
  --linger                        Don't exit at the end of a run (receive and
                                  pong scenarios)
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
  --authenticate                  Authenticate (RFComm only)
  --encrypt                       Encrypt the connection (RFComm only)
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
``mode`` and and ``scenario`` to run as. The ``mode`` and ``scenario`` of the Central and Peripheral
must be compatible.

Device 1 scenario | Device 2 scenario
------------------|------------------
``gatt-client``   | ``gatt-server``
``l2cap-client``  | ``l2cap-server``
``rfcomm-client`` | ``rfcomm-server``

Device 1 scenario | Device 2 scenario
------------------|--------------
``send``          | ``receive``
``ping``          | ``pong``


# Examples

In the following examples, we have two USB Bluetooth controllers, one on `usb:0` and
the other on `usb:1`, and two consoles/terminals. We will run a command in each.

!!! example "GATT Throughput"
    Using the default mode and scenario for the Central and Peripheral.

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
    $ bumble-bench --scenario pong peripheral usb:0
    ```

    In the second console/terminal:
    ```
    $ bumble-bench --scenario ping central usb:1
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

!!! example "Reversed scenarios with L2CAP"
    In the first console/terminal:
    ```
    $ bumble-bench --mode l2cap-client --scenario send peripheral usb:0
    ```

    In the second console/terminal:
    ```
    $ bumble-bench --mode l2cap-server --scenario receive central usb:1
    ```
