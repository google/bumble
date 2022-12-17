USE CASE 2
==========

# Native Bluetooth application connected to a Bumble python application with virtual controller

Connect a native Bluetooth application, running on a host with Bluetooth stack to which we can attach a virtual controller (Linux for example), to a Bumble python application (ex: a GATT server or client).

```
+-----------+             +------------+                +------------++--------++--------+
| Native    |             | Bumble     |    Bumble      | Bumble     || Bumble || Bumble |
| Bluetooth |<--  HCI  -->| Virtual    |<== Local or ==>| Virtual    || Host   || Python |
| App       |  Transport  | Controller |    Remote      | Controller ||        || App    |
+-----------+             +------------+    Link        +------------++--------++--------+
```
