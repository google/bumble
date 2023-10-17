HARDWARE
========

The Bumble Host connects to a controller over an [HCI Transport](../transports/index.md).
To use a hardware controller attached to the host on which the host application is running, the transport is typically either [HCI over UART](../transports/serial.md) or [HCI over USB](../transports/usb.md).
On Linux, the [VHCI Transport](../transports/vhci.md) can be used to communicate with any controller hardware managed by the operating system. Alternatively, a remote controller (a phyiscal controller attached to a remote host) can be used by connecting one of the networked transports (such as the [TCP Client transport](../transports/tcp_client.md), the [TCP Server transport](../transports/tcp_server.md) or the [UDP Transport](../transports/udp.md)) to an [HCI Bridge](../apps_and_tools/hci_bridge.md) bridging the network transport to a physical controller on a remote host.

In theory, any controller that is compliant with the HCI over UART or HCI over USB protocols can be used.

HCI over USB is very common, implemented by a number of commercial Bluetooth dongles.

It is also possible to use an embedded development board, running a specialized application, such as the [`HCI UART`](https://docs.zephyrproject.org/latest/samples/bluetooth/hci_uart/README.html) and [`HCI USB`](https://docs.zephyrproject.org/latest/samples/bluetooth/hci_usb/README.html) demo applications from the [Zephyr project](https://www.zephyrproject.org/), or the [`blehci`](https://mynewt.apache.org/latest/tutorials/ble/blehci_project.html) application from [mynewt/nimble](https://mynewt.apache.org/)

Some specific USB dongles and embedded boards that are known to work include:

  * [Nordic nRF52840 DK board](https://www.nordicsemi.com/Products/Development-hardware/nrf52840-dk) with the Zephyr `HCI UART` application
  * [Nordic nRF52840 DK board](https://www.nordicsemi.com/Products/Development-hardware/nrf52840-dk) with the mynewt `blehci` application
  * [Nordic nrf52840 dongle](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle) with the Zephyr `HCI USB` application
  * [BT820 USB Dongle](https://www.lairdconnect.com/wireless-modules/bluetooth-modules/bluetooth-42-and-40-modules/bt800-series-bluetooth-module)
