USB TRANSPORT
=============

The USB transport interfaces with a local Bluetooth USB dongle.

## Moniker
The moniker for a USB transport is either `usb:<index>` or `usb:<vendor>:<product>`
with `<index>` as the 0-based index to select amongst all the devices that appear to be supporting Bluetooth HCI (0 being the first one), or where `<vendor>` and `<product>` are a vendor ID and product ID in hexadecimal.

!!! example
    `usb:04b4:f901`  
    Use the USB dongle with `vendor` equal to `04b4` and `product` equal to `f901`

    `usb:0`  
    Use the first Bluetooth dongle

## Alternative
The library includes two different implementations of the USB transport, implemented using different python bindings for `libusb`.
Using the transport prefix `pyusb:` instead of `usb:` selects the implementation based on  [PyUSB](https://pypi.org/project/pyusb/), using the synchronous API of `libusb`, whereas the default implementation is based on [libusb1](https://pypi.org/project/libusb1/), using the asynchronous API of `libusb`. In order to use the alternative PyUSB-based implementation, you need to ensure that you have installed that python module, as it isn't installed by default as a dependency of Bumble.
