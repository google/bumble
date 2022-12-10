USE CASE 3
==========

# Emulated Bluetooth device connected to a Bumble python application with virtual controller

Connect an emulated Bluetooth device (ex: an Android emulator, or an embedded device emulator) to a Bumble python application (ex: a GATT server or client).

```
+-----------+             +------------+                +------------++--------++--------+
| Emulated  |             | Bumble     |    Bumble      | Bumble     || Bumble || Bumble |
| Bluetooth |<--  HCI  -->| Virtual    |<== Local or ==>| Virtual    || Host   || Python |
| Device    |  Transport  | Controller |    Remote      | Controller ||        || App    |
+-----------+             +------------+    Link        +------------++--------++--------+
```
