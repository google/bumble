HCI SOCKET TRANSPORT
====================

An HCI Socket can send/receive HCI packets to/from a Bluetooth HCI controller managed by the host OS. This is only supported on some platforms (currently only tested on Linux).

!!! note
    This type of transport can only be used for virtual hosts, not virtual controllers

## Moniker
The moniker for an HCI Socket transport is either just `hci-socket` (to use the default/first Bluetooth controller), or `hci-socket:<index>` where `<index>` is the 0-based index of a Bluetooth controller device.

!!! example
    `hci-socket`
    Use an HCI socket to the first Bluetooth controller (`hci0 on Linux`)

!!! tip "On Linux"
    See the [Linux Platform](../platforms/linux.md) page for details on how to use HCI sockets on Linux
