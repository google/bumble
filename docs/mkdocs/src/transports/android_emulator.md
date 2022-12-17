ANDROID EMULATOR TRANSPORT
==========================

The Android emulator transport either connects, as a host, to a "Root Canal" virtual controller
("host" mode), or attaches a virtual controller to the Android Bluetooth host stack ("controller" mode).

## Moniker
The moniker syntax for an Android Emulator transport is: `android-emulator:[mode=<host|controller>][<hostname>:<port>]`, where
the `mode` parameter can specify running as a host or a controller, and `<hostname>:<port>` can specify a host name (or IP address) and TCP port number on which to reach the gRPC server for the emulator.
Both the `mode=<host|controller>` and `<hostname>:<port>` parameters are optional (so the moniker `android-emulator` by itself is a valid moniker, which will create a transport in `host` mode, connected to `localhost` on the default gRPC port for the emulator).

!!! example Example
    `android-emulator`
    connect as a host to the emulator on localhost:8554

!!! example Example
    `android-emulator:mode=controller`
    connect as a controller to the emulator on localhost:8554

!!! example Example
    `android-emulator:localhost:8555`
    connect as a host to the emulator on localhost:8555
