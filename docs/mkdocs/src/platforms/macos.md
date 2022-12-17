:material-apple: MACOS PLATFORM
===============================

USB HCI
-------

To use the experimental USB HCI support on macOS, you need to tell macOS not to use the USB Bluetooth
controller with its internal Bluetooth stack.
To do that, use the following command:
```
sudo nvram bluetoothHostControllerSwitchBehavior="never"
```
A reboot shouldn't be necessary after that. See [Tech Note 2295](https://developer.apple.com/library/archive/technotes/tn2295/_index.html)
