USE CASE 5
==========

# Connecting multiple Bumble python applications

Write several python applications (ex: a GATT client that will connect to a hear rate sensor, or a GATT server exposing a battery level) and connect them together

```
+--------++--------++------------+                        +------------++--------++--------+
| Bumble || Bumble || Bumble     |                        | Bumble     || Bumble || Bumble |
| Python || Host   || Controller |<--+                +-->| Controller || Host   || Python |
| App    ||        ||            |   |   +--------+   |   |            ||        || App    |
+--------++--------++------------+   +-->| Bumble |<--+   +------------++--------++--------+
                                         | Link   |
+--------++--------++------------+   +-->| Relay  |<--+   +------------++--------++--------+
| Bumble || Bumble || Bumble     |   |   +--------+   |   | Bumble     || Bumble || Bumble |
| Python || Host   || Controller |<--+                +-->| Controller || Host   || Python |
| App    ||        ||            |                        |            ||        || App    |
+--------++--------++------------+                        +------------++--------++--------+
```
