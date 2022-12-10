USE CASE 1
==========

# Bumble python application connected to a device with a "real" Bluetooth controller

Write a python application (ex: a GATT client that will connect to a hear rate sensor, or a GATT server exposing a battery level) that can connect to or receive connections from a "real" Bluetooth device (like a sensor, or a mobile phone) using a Bluetooth controller (a USB dongle, or HCI-UART controller)

```
+--------++--------+             +------------+             +-----------+
| Bumble || Bumble |             | Physical   |             | Bluetooth |
| Python || Host   |<--  HCI  -->| Controller |{...radio...}| Device    |
| App    ||        |  Transport  |            |             |           |
+--------++--------+             +------------+             +-----------+
```
