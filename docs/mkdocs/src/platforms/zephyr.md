:material-memory: ZEPHYR PLATFORM
=================================

Set TX Power on nRF52840
------------------------

The Nordic nRF52840 supports Zephyr's vendor specific HCI command for setting TX
power during advertising, connection, or scanning. With the example [HCI
USB](https://docs.zephyrproject.org/latest/samples/bluetooth/hci_usb/README.html)
application, an [nRF52840
dongle](https://www.nordicsemi.com/Products/Development-
hardware/nRF52840-Dongle) can be used as a Bumble controller.

To add dynamic TX power support to the HCI USB application, add the following to
`zephyr/samples/bluetooth/hci_usb/prj.conf` and build.

```
CONFIG_BT_CTLR_ADVANCED_FEATURES=y
CONFIG_BT_CTLR_CONN_RSSI=y
CONFIG_BT_CTLR_TX_PWR_DYNAMIC_CONTROL=y
```

Alternatively, a prebuilt firmware application can be downloaded here:
[hci_usb.zip](../downloads/zephyr/hci_usb.zip).

Put the nRF52840 dongle into bootloader mode by pressing the RESET button. The
LED should pulse red. Load the firmware application with the `nrfutil` tool:

```
nrfutil dfu usb-serial -pkg hci_usb.zip -p /dev/ttyACM0
```

The vendor specific HCI commands to read and write TX power are defined in
`bumble/vendor/zephyr/hci.py` and may be used as such:

```python
from bumble.vendor.zephyr.hci import HCI_Write_Tx_Power_Level_Command

# set advertising power to -4 dB
response = await host.send_command(
    HCI_Write_Tx_Power_Level_Command(
        handle_type=HCI_Write_Tx_Power_Level_Command.TX_POWER_HANDLE_TYPE_ADV,
        connection_handle=0,
        tx_power_level=-4,
    )
)

if response.return_parameters.status == HCI_SUCCESS:
    print(f"TX power set to {response.return_parameters.selected_tx_power_level}")

```
