SERIAL TRANSPORT
================

The serial transport implements sending/receiving HCI packets over a UART (a.k.a serial port).

## Moniker
The moniker syntax for a serial transport is:  
    `<device-path>[,<speed>][,rtscts][,dsrdtr][,delay][,resync]`

When `<speed>` is omitted, the default value of 1000000 is used.  
When `rtscts` is specified, RTS/CTS hardware flow control is enabled.  
When `dsrdtr` is specified, DSR/DTR hardware flow control is enabled.  
When `delay` is specified, a short delay is added after opening the port.  
When `resync` is specified, a controller that was left in an unknown state (still sending data, or waiting for the rest of a packet) is brought back to a known one after opening the port: 258 zero bytes followed by an HCI_Reset command are sent, then, once a reset is complete, an HCI_Read_Local_Version_Information command, and everything received is discarded until that command is complete. The padding completes a partial command or SCO packet; a partial ACL or ISO packet can be longer and is not covered. If the commands are not answered within 2 seconds, the port is closed and opening the transport fails. Not all controllers accept the zero padding, so this is off by default.  

!!! example
    ```
    /dev/tty.usbmodem0006839912172
    /dev/tty.usbmodem0006839912172,1000000
    /dev/tty.usbmodem0006839912172,rtscts
    /dev/tty.usbmodem0006839912172,rtscts,delay
    /dev/tty.usbmodem0006839912172,resync
    ```