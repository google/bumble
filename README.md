
     _                 _     _
    | |               | |   | |
    | |__  _   _ ____ | |__ | | _____
    |  _ \| | | |    \|  _ \| || ___ |
    | |_) ) |_| | | | | |_) ) || ____|
    |____/|____/|_|_|_|____/ \_)_____)

Bluetooth Stack for Apps, Emulation, Test and Experimentation
=============================================================

<img src="docs/mkdocs/src/images/logo_framed.png" alt="Logo" width="200" height="200"/>

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

To install package dependencies needed to run the bumble examples, execute the following commands:

```
python -m pip install --upgrade pip
python -m pip install ".[test,development,documentation]"
```

### Examples

Refer to the [Examples Documentation](examples/README.md) for details on the included example scripts and how to run them.

The complete [list of Examples](/docs/mkdocs/src/examples/index.md), and what they are designed to do is here.

There are also a set of [Apps and Tools](docs/mkdocs/src/apps_and_tools/index.md) that show the utility of Bumble.

### Using Bumble With a USB Dongle

Bumble is easiest to use with a dedicated USB dongle.
This is because internal Bluetooth interfaces tend to be locked down by the operating system.
You can use the [usb_probe](/docs/mkdocs/src/apps_and_tools/usb_probe.md) tool (all platforms) or `lsusb` (Linux or macOS) to list the available USB devices on your system.

See the [USB Transport](/docs/mkdocs/src/transports/usb.md) page for details on how to refer to USB devices. Also, if your are on a mac, see [these instructions](docs/mkdocs/src/platforms/macos.md).

## License

Licensed under the [Apache 2.0](LICENSE) License.

## Disclaimer

This is not an official Google product.

This library is in alpha and will be going through a lot of breaking changes. While releases will be stable enough for prototyping, experimentation and research, we do not recommend using it in any production environment yet.
Expect bugs and sharp edges.
Please help by trying it out, reporting bugs, and letting us know what you think!
