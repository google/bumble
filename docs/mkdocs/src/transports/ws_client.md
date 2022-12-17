UDP TRANSPORT
=============

The UDP transport is a UDP socket, receiving packets on a specified port number, and sending packets to a specified host and port number.

## Moniker
The moniker syntax for a UDP transport is: `udp:<local-host>:<local-port>,<remote-host>:<remote-port>`.

!!! example
    `udp:0.0.0.0:9000,127.0.0.1:9001`
    UDP transport where packets are received on port `9000` and sent to `127.0.0.1` on port `9001`
