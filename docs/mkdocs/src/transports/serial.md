SERIAL TRANSPORT
================

The serial transport implements sending/receiving HCI packets over a UART (a.k.a serial port).

## Moniker
The moniker syntax for a serial transport is:  
    `<device-path>[,<speed>][,rtscts][,dsrdtr][,delay]`

When `<speed>` is omitted, the default value of 1000000 is used.  
When `rtscts` is specified, RTS/CTS hardware flow control is enabled.  
When `dsrdtr` is specified, DSR/DTR hardware flow control is enabled.  
When `delay` is specified, a short delay is added after opening the port.  

!!! example
    ```
    /dev/tty.usbmodem0006839912172
    /dev/tty.usbmodem0006839912172,1000000
    /dev/tty.usbmodem0006839912172,rtscts
    /dev/tty.usbmodem0006839912172,rtscts,delay
    ```