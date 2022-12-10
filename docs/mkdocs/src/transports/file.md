FILE TRANSPORT
==============

The File transport allows opening any named entry on a filesystem and use it for HCI transport I/O.
This is typically used to open a PTY, or unix driver, not for real files.

## Moniker
The moniker for a File transport is `file:<path>`

!!! example
    `file:/dev/ttys001`
    Opens the pseudo terminal `/dev/ttys001` as a transport
