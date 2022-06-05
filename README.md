
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

## License

Licensed under the [Apache 2.0](LICENSE) License.

## Disclaimer

This is not an official Google product.

This library is in alpha and will be going through a lot of breaking changes. While releases will be stable enough for prototyping, experimentation and research, we do not recommend using it in any production environment yet.
Expect bugs and sharp edges.
Please help by trying it out, reporting bugs, and letting us know what you think!
