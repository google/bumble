WEBSOCKET SERVER TRANSPORT
==========================

The WebSocket Server transport is WebSocket server that accepts connections from a WebSocket
client. HCI packets are sent and received over the connection.

## Moniker
The moniker syntax for a WebSocket Server transport is: `ws-server:<host>:<port>`,
where `<host>` may be the address of a local network interface, or `_`to accept connections on all local network interfaces. `<port>` is the TCP port number on which to accept connections.


!!! example
    `ws-server:_:9001`
