Bumble Examples
===============

NOTE:
To run python scripts from this directory when the Bumble package isn't installed in your environment,
put .. in your PYTHONPATH: `export PYTHONPATH=..`

# `run_controller.py`
Run two virtual controllers, one connected to a soft device written in python with a simple GATT server, and the other connected to an external host.

## Running `run_controller.py` with a BlueZ host running on Linux.

In this configuration, a BlueZ stack running on a Linux host is connected to a Bumble virtual
controller, attached to a local link bus to a second, in-process, virtual controller, itself
used by a virtual device with a GATT server.

### Running with two separate hosts (ex: a mac laptop and a Linux VM)
In this setup, the virtual controllers and host run on a mac desktop, and the BlueZ stack on a Linux VM. A UDP socket communicates HCI packets between the macOS host and the Linux guest.

#### Linux setup
In a terminal, run `socat` to bridge a UDP socket to a local PTY.
The PTY is used a virtual HCI UART.
(in this example, the mac's IP address seen from the Linux VM is `172.16.104.1`, replace it with
the appropriate address for your environment. (you may also use a port number other than `22333` used here)
```
socat -d -d -x PTY,link=./hci_pty,rawer UDP-SENDTO:172.16.104.1:22333,bind=:22333
```

In the local directory, `socat` creates a symbolic link named `hci_pty` that points to the PTY.

In a second terminal, run
```
sudo btattach -P h4 -B hci_pty
```

This tells BlueZ to use the PTY as an HCI UART controller.

(optional) In a third terminal, run `sudo btmon`. This monitors the HCI traffic with BlueZ, which is great to see what's going on.

In a fourth terminal, run `sudo bluetoothctl` to interact with BlueZ as a client. From there, you can scan, advertise, connect, etc.

#### Mac setup
In a macOS terminal, run
```
python run_controller.py device1.json udp:0.0.0.0:22333,172.16.104.161:22333
```

This configures one of the virtual controllers to use a UDP socket as its HCI transport. In this example, the ip address of the Linux VM is `172.16.104.161`, replace it with the appropriate
address for your environment.

Once both the Linux and macOS processes are started, you should be able to interact with the
`bluetoothctl` tool on the Linux side and scan/connect/discover the virtual device running on
the macOS side. Relevant log output in each of the terminal consoles should show what it going on.

### Running with a single Linux host
In setup, both the BlueZ stack and tools as well as the Bumble virtual stack are running on the same
host.

In a terminal, run the example as
```
python run_controller.py device1.json pty:hci_pty
```

In the local directory, a symbolic link named `hci_pty` that points to the PTY is created.

From this point, run the same steps as in the previous example to attach the PTY to BlueZ and use
`bluetoothctl` to interact with the virtual controller.


# `run_gatt_client.py`
Run a host application connected to a 'real' BLE controller over a UART HCI to a dev board running Zephyr in HCI mode (could be any other UART BLE controller, or BlueZ over a virtual UART). The application connects to a Bluetooth peer specified as an argument.
Once connected, the application hosts a GATT client that discovers all services and all attributes of the peer and displays them.

# `run_gatt_server.py`
Run a host application connected to a 'real' BLE controller over a UART HCI to a dev board running Zephyr in HCI mode (could be any other UART BLE controller, or BlueZ over a virtual UART). The application connects to a Bluetooth peer specified as an argument.
The application hosts a simple GATT server with basic
services and characteristics.

# `run_gatt_client_and_server.py`

# `run_advertiser.py`

# `run_scanner.py`
Run a host application connected to a 'real' BLE controller over a UART HCI to a dev board running Zephyr in HCI mode (could be any other UART BLE controller, or BlueZ over a virtual UART), that starts scanning and prints out the scan results.
