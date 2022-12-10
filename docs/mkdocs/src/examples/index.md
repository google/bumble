EXAMPLES
========

The project includes a few simple example applications the illustrate some of the ways the library APIs can be used.
These examples include:

## `battery_service.py`
Run a simple device example with a GATT server that exposes a standard Battery Service.

## `get_peer_device_info.py`
An app that connects to a device, discovers its GATT services, and, if the Device Information Service is found, looks for a Manufacturer Name characteristics, reads and prints it.

## `keyboard.py`
An app that implements a virtual keyboard or mouse, or can connect to a real keyboard and receive key presses.

## `run_a2dp_info.py`
An app that connects to a device, phone or computer and inspects its A2DP (Advanced Audio Profile) capabilities

## `run_a2dp_source.py`
An app that can connect to a Bluetooth speaker and play audio.

## `run_a2dp_sink.py`
An app that implements a virtual Bluetooth speaker that can receive audio.

## `run_advertiser.py`
An app that runs a simple device that just advertises (BLE).

## `run_classic_connect.py`
An app that connects to a Bluetooth Classic device and prints its services.

## `run_classic_discoverable.py`
An app that implements a discoverable and connectable Bluetooth Classic device.

## `run_classic_discovery.py`
An app that discovers Bluetooth Classic devices and prints their information.

## `run_connect_and_encrypt.py`
An app that connected to a device (BLE) and encrypts the connection.

## `run_controller_with_scanner.py`

## `run_controller.py`
Creates two linked controllers, attaches one to a transport, and the other to a local host with a GATT server application. This can be used, for example, to attach a virtual controller to a native stack, like BlueZ on Linux, and use the native tools, like `bluetoothctl`, to scan and connect to the GATT server included in the example.

## `run_gatt_client_and_server.py`
Runs a local GATT server and GATT client, connected to each other. The GATT client discovers and logs all the services and characteristics exposed by the GATT server

## `run_gatt_client.py`
A simple GATT client that either connects to another BLE device or waits for a connection, then dumps its GATT database.

## `run_gatt_server.py`
A simple GATT server that either connects to another BLE device or waits for connections.

## `run_hfp_gateway.py`
A app that implements a Hands Free gateway. It can connect to a Hands Free headset.

## `run_hfp_handsfree.py`
A app that implements a Hands Free headset. It can simulate some of the events that a real headset would
emit, like picking up or hanging up a call, pressing a button, etc.

## `run_notifier.py`
An app that implements a GATT server with characteristics that can be subscribed to, and emits notifications
for those characteristics at regular intervals.

## `run_rfcomm_client.py`
An app that connects to an RFComm server and bridges the RFComm channel to a local TCP socket

## `run_rfcomm_server.py`
An app that implements an RFComm server and, when a connection is received, bridges the channel to a local TCP socket

## `run_scanner.py`
An app that scan for BLE devices and print the advertisements received.
