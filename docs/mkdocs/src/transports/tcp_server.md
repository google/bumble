TCP SERVER TRANSPORT
====================

The TCP Client transport uses an incoming TCP connection to a host:port address.

## Moniker
The moniker syntax for a TCP server transport is: `tcp-server:<local-host>:<local-port>`
where `<local-host>` may be the address of a local network interface, or `_` to accept
connections on all local network interfaces.

!!! example
    `tcp-server:_:9001`
    Waits for and accepts connections on port `9001`
