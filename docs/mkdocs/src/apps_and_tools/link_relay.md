LINK RELAY TOOL
===============

The Link Relay is a WebSocket relay, which acts like an online chat system, where each "chat room" can be joined by multiple virtual controllers, which can then communicate with each other, as if connected with radio communication.

```
usage: python link_relay.py [-h] [--log-level LOG_LEVEL] [--log-config LOG_CONFIG] [--port PORT]

optional arguments:
  -h, --help            show this help message and exit
  --log-level LOG_LEVEL
                        logger level
  --log-config LOG_CONFIG
                        logger config file (YAML)
  --port PORT           Port to listen on
```

(the default port is `10723`)

When running, the link relay waits for connections on its listening port.
The WebSocket path used by a connecting client indicates which virtual "chat room" to join.


!!! tip "Connecting to the relay as a controller"
    Most of the examples and tools that take a transport moniker as an argument also accept a link relay moniker, which is equivalent to a transport to a virtual controller that is connected to a relay.
    The moniker syntax is: `link-relay:ws://<hostname>/<room>` where `<hostname>` is the hostname to connect to and `<room>` is the virtual "chat room" in a relay.

    Example: `link-relay:ws://localhost:10723/test` will join the `test` "chat room"

!!! tip "Connecting to the relay as an observer"
    It is possible to connect to a "chat room" in a relay as an observer, rather than a virtual controller. In this case, a text-based console can be used to observe what is going on in the "chat room". Tools like [`wscat`](https://github.com/websockets/wscat#readme) or [`websocat`](https://github.com/vi/websocat) can be used for that.

    Example: `wscat --connect ws://localhost:10723/test`
