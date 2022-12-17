USE CASE 4
==========

# Connecting two emulated Bluetooth devices

Connect two emulated Bluetooth device (ex: an Android emulator, or an embedded device emulator) to each other

```
+-----------+             +------------+                +------------+             +-----------+
| Emulated  |             | Bumble     |    Bumble      | Bumble     |             | Emulated  |
| Bluetooth |<--  HCI  -->| Virtual    |<== Local or ==>| Virtual    |<--  HCI  -->| Bluetooth |
| Device    |  Transport  | Controller |    Remote      | Controller |  Transport  | Device    |
+-----------+             +------------+    Link        +------------+             +-----------+
```
