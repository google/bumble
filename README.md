
     _                 _     _
    | |               | |   | |
    | |__  _   _ ____ | |__ | | _____
    |  _ \| | | |    \|  _ \| || ___ |
    | |_) ) |_| | | | | |_) ) || ____|
    |____/|____/|_|_|_|____/ \_)_____)

Bluetooth Stack for Apps, Emulation, Test and Experimentation
=============================================================

<img src="docs/mkdocs/src/images/logo_framed.png" alt="drawing" width="200" height="200"/>

Bumble is a full-featured Bluetooth stack written entirely in Python. It supports most of the common Bluetooth Low Energy (BLE) and Bluetooth Classic (BR/EDR) protocols and profiles, including GAP, L2CAP, ATT, GATT, SMP, SDP, RFCOMM, HFP, HID and A2DP. The stack can be used with physical radios via HCI over USB, UART, or the Linux VHCI, as well as virtual radios, including the virtual Bluetooth support of the Android emulator.

## Documentation

Browse the pre-built [Online Documentation](https://google.github.io/bumble/), 
or see the documentation source under `docs/mkdocs/src`, or build the static HTML site from the markdown text with:
```
mkdocs build -f docs/mkdocs/mkdocs.yml 
```

## Usage

### Getting Started

For a quick start to using Bumble, see the [Getting Started](docs/mkdocs/src/getting_started.md) guide.

### Dependencies

To install package dependencies needed to run the bumble examples execute the following commands:

```
python -m pip install --upgrade pip
python -m pip install ".[test,development,documentation]"
```

### Examples

Refer to the [Example Documentation](examples/README.md) for details on the included example scripts and how to run them.

The complete [list of Examples](/docs/mkdocs/src/examples/index.md), and what they are designed to do is here.

There are also a set of [Apps and Tools](docs/mkdocs/src/apps_and_tools/index.md) that show the utility of Bumble.

### Detecting Bluetooth Interfaces

Bumble is easiest to use with a dedicated USB dongle.
This is because internal Bluetooth interfaces tend to be locked down by the operating system.
To detect which Bluetooth dongles are connected, use `lsusb`.

#### Installing lsusb

On Mac: `brew install lsusb`
On Linux: `sudo apt-get install usbutils`

#### Using lsusb

```
$ lsusb
Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 003 Device 014: ID 0b05:17cb ASUSTek Computer, Inc. Broadcom BCM20702A0 Bluetooth
```

Note the device id for the Bluetooth interface in this case is `0b05:17cb`.

#### Passing usb:id to example

When running the examples, `usb:0` can be passed to use the first available Bluetooth interface.
Alternatively, the explicit interface identifier returned from `lsusb` may be used:

```
$ python3 ./apps/scan.py usb:0b05:17cb
<<< connecting to HCI...
<<< connected
>>> 0F:02:72:7B:1D:1A [RANDOM](non-resolvable):
  RSSI: -73 ████████████▊
  [Complete List of 16-bit Service Class UUIDs]: UUID-16:FD6F
  [Service Data]: service=UUID-16:FD6F, data=c43c0cc51d1b8a5c57dcf61069f8f50ba9f7302a

  ...
```

## License

Licensed under the [Apache 2.0](LICENSE) License.

## Disclaimer

This is not an official Google product.

This library is in alpha and will be going through a lot of breaking changes. While releases will be stable enough for prototyping, experimentation and research, we do not recommend using it in any production environment yet.
Expect bugs and sharp edges.
Please help by trying it out, reporting bugs, and letting us know what you think!
