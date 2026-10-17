CONTROLLER
==========

`bumble.controller.Controller` implements the HCI-facing Controller interface.
By default it creates a `LocalLink`, which exchanges packets between Controllers
in memory. Passing `link=local_link` registers the Controller on that shared link.

An experimental `RadioBackend` instead executes Bluetooth LE radio procedures
through a physical-channel simulator. See [Radio-backed LE Controller](radio_controller.md)
for the backend architecture, supported procedures, BabbleSim setup and runnable examples.
