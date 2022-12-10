USE CASE 6
==========

# Connecting an emulated Bluetooth device to a physical controller

It can be useful to connect an emulated device (like a phone simulator, or an emulated embedded device) to a physical controller in order to connect to other Bluetooth devices. By doing this via a Bumble HCI bridge, it becomes easy to inspect the HCI packets exchanged with the controller, and possibly filter/change them if needed (for example to support vendor-specific HCI extensions).

```
+-----------+             +--------+             +------------+             +-----------+
| Emulated  |             | Bumble |             | Physical   |             | Bluetooth |
| Bluetooth |<--  HCI  -->| HCI    |<--  HCI  -->| Controller |{...radio...}| Device    |
| Device    |  Transport  | Bridge |  Transport  |            |             |           |
+-----------+             +--------+             +------------+             +-----------+
```
