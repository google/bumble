DRIVERS
=======

Some Bluetooth controllers require a driver to function properly.
This may include, for instance, loading a Firmware image or patch,
loading a configuration.

By default, drivers will be automatically probed to determine if they should be
used with particular HCI controller.
When the transport for an HCI controller is instantiated from a transport name,
a driver may also be forced by specifying ``driver=<driver-name>`` in the optional
metadata portion of the transport name. For example,
``usb:[driver=-rtk]0`` indicates that the ``rtk`` driver should be used with the
first USB device, even if a normal probe would not have selected it based on the
USB vendor ID and product ID.

Drivers included in the module are:

  * [Realtek](realtek.md): Loading of Firmware and Config for Realtek USB dongles.