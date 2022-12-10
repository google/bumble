USB PROBE TOOL
==============

This tool lists all the USB devices, with details about each device.
For each device, the different possible Bumble transport strings that can
refer to it are listed.
If the device is known to be a Bluetooth HCI device, its identifier is printed
in reverse colors, and the transport names in cyan color.
For other devices, regardless of their type, the transport names are printed
in red. Whether that device is actually a Bluetooth device or not depends on
whether it is a Bluetooth device that uses a non-standard Class, or some other
type of device (there's no way to tell).

## Usage

This command line tool may be invoked with no arguments, or with `--verbose`
for extra details.
When installed from PyPI, run as
```
$ bumble-usb-probe
```

or, for extra details, with the `--verbose` argument
```
$ bumble-usb-probe --v
```

When running from the source distribution:
```
$ python3 apps/usb-probe.py
```

or

```
$ python3 apps/usb-probe.py --verbose
```

!!! example
    ```
    $ python3 apps/usb_probe.py

    ID 0A12:0001
    Bumble Transport Names: usb:0 or usb:0A12:0001
    Bus/Device:             020/034
    Class:                  Wireless Controller
    Subclass/Protocol:      1/1 [Bluetooth]
    Manufacturer:           None
    Product:                USB2.0-BT
    ```
