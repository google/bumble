PTY TRANSPORT
=============

The PTY transport uses a Unix pseudo-terminal device to communicate with another process on the host, as if it were over a serial port.

## Moniker
The moniker syntax for a PTY transport is: `pty[:path]`.
Where `path`, is used, is the path name where a symbolic link to the PTY will be created for convenience (the link will be removed when the transport is closed or when the process exits).

!!! example
    `pty:virtual_hci`
    Creates a PTY entry and a symbolic link, named `virtual_hci`, linking to the PTY
