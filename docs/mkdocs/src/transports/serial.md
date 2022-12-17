SERIAL TRANSPORT
================

The serial transport implements sending/receiving HCI packets over a UART (a.k.a serial port).

## Moniker
The moniker syntax for a serial transport is: `serial:<device-path>[,<speed>]`
When `<speed>` is omitted, the default value of 1000000 is used

!!! example
    `serial:/dev/tty.usbmodem0006839912172,1000000`
    Opens the serial port `/dev/tty.usbmodem0006839912172` at `1000000`bps
