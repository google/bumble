TRANSPORTS
==========

The Hosts and Controllers communicate over a transport, which is responsible for sending/receiving
HCI packets.
Several types of transports are supported:

  * In Process: HCI packets are passed via a function call
  * [Serial](serial.md): interface with a controller over a serial port (HCI UART, like a development board or serial Bluetooth dongle)
  * [USB](usb.md): interface with a controller over USB (HCI USB, like a Bluetooth USB dongle)
  * [UDP](udp.md): packets are sent to a specified host/port and received on a specified port over a UDP socket
  * [TCP Client](tcp_client.md): a connection to a TCP server is made, after which HCI packets are sent/received over a TCP socket
  * [TCP Server](tcp_server.md): listens for a TCP client on a specified port. When a client connection is made, HCI packets are sent/received over a TCP socket
  * [WebSocket Client](ws_client.md): a connection to a WebSocket server is made, after which HCI packets are sent/received over the socket.
  * [WebSocket Server](ws_server.md): listens for a WebSocket client on a specified port. When a client connection is made, HCI packets are sent/received over the socket.
  * [PTY](pty.md): a PTY (pseudo terminal) is used to send/receive HCI packets. This is convenient to expose a virtual controller as if it were an HCI UART
  * [VHCI](vhci.md): used to attach a virtual controller to a Bluetooth stack on platforms that support it.
  * [HCI Socket](hci_socket.md): an HCI socket, on platforms that support it, to send/receive HCI packets to/from an HCI controller managed by the OS.
  * [Android Emulator](android_emulator.md): a gRPC connection to the Android emulator's "netsim"
  virtual controller, or from the Android emulator, is used to setup either an HCI interface to the emulator's "netsim" virtual controller, or serve as a virtual controller for the Android Bluetooth host stack.
  * [File](file.md): HCI packets are read/written to a file-like node in the filesystem.
