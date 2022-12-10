HCI BRIDGE
==========

This tool acts as a simple bridge between two HCI transports, with a host on one side and
a controller on the other. All the HCI packets bridged between the two are printed on the console
for logging. This bridge also has the ability to short-circuit some HCI packets (respond to them
with a fixed response instead of bridging them to the other side), which may be useful when used with
a host that send custom HCI commands that the controller may not understand.


!!! info "Running the HCI bridge tool"
    ```
    python hci_bridge.py <host-transport-spec> <controller-transport-spec> [command-short-circuit-list]
    ```

!!! example "UDP to Serial"
    ```
    python hci_bridge.py udp:0.0.0.0:9000,127.0.0.1:9001 serial:/dev/tty.usbmodem0006839912171,1000000 0x3f:0x0070,0x3f:0x0074,0x3f:0x0077,0x3f:0x0078
    ```

!!! example "PTY to Link Relay"
    ```
    python hci_bridge.py serial:emulated_uart_pty,1000000 link-relay:ws://127.0.0.1:10723/test
    ```

    In this example, an emulator that exposes a PTY as an interface to its HCI UART is running as
    a Bluetooth host, and we are connecting it to a virtual controller attached to a link relay
    (through which the communication with other virtual controllers will be mediated).

    NOTE: this assumes you're running a Link Relay on port `10723`.
