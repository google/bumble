USB TRANSPORT
=============

The USB transport interfaces with a local Bluetooth USB dongle.

## Moniker
The moniker for a USB transport is either:
  * `usb:<index>`
  * `usb:<vendor>:<product>`
  * `usb:<vendor>:<product>/<serial-number>`
  * `usb:<vendor>:<product>#<index>`

with `<index>` as a 0-based index (0 being the first one) to select amongst all the matching devices when there are more than one.
In the `usb:<index>` form, matching devices are the ones supporting Bluetooth HCI, as declared by their Class, Subclass and Protocol.
In the `usb:<vendor>:<product>#<index>` form, matching devices are the ones with the specified `<vendor>` and `<product>` identification.

`<vendor>` and `<product>` are a vendor ID and product ID in hexadecimal.

!!! examples
    `usb:04b4:f901`  
    The USB dongle with `<vendor>` equal to `04b4` and `<product>` equal to `f901`

    `usb:0`  
    The first Bluetooth HCI dongle that's declared as such by Class/Subclass/Protocol

    `usb:04b4:f901/0016A45B05D8`
    The USB dongle with `<vendor>` equal to `04b4`, `<product>` equal to `f901` and `<serial>` equal to `0016A45B05D8`

    `usb:04b4:f901/#1`
    The second USB dongle with `<vendor>` equal to `04b4` and `<product>` equal to `f901`

## Alternative
The library includes two different implementations of the USB transport, implemented using different python bindings for `libusb`.
Using the transport prefix `pyusb:` instead of `usb:` selects the implementation based on  [PyUSB](https://pypi.org/project/pyusb/), using the synchronous API of `libusb`, whereas the default implementation is based on [libusb1](https://pypi.org/project/libusb1/), using the asynchronous API of `libusb`. In order to use the alternative PyUSB-based implementation, you need to ensure that you have installed that python module, as it isn't installed by default as a dependency of Bumble.

## Listing Available USB Devices

### With `usb_probe`
You can use the [`usb_probe`](../apps_and_tools/usb_probe.md) tool to list all the USB devices attached to your host computer.
The tool will also show the `usb:XXX` transport name(s) you can use to reference each device.


### With `lsusb`
On Linux and macOS, the `lsusb` tool serves a similar purpose to Bumble's own `usb_probe` tool (without the Bumble specifics)

#### Installing lsusb

On Mac: `brew install lsusb`
On Linux: `sudo apt-get install usbutils`

#### Using lsusb

```
$ lsusb
Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 003 Device 014: ID 0b05:17cb ASUSTek Computer, Inc. Broadcom BCM20702A0 Bluetooth
```

The device id for the Bluetooth interface in this case is `0b05:17cb`.