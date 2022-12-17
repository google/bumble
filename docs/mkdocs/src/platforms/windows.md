:material-microsoft-windows: WINDOWS PLATFORM
=============================================

USB HCI
-------

To use a Bluetooth USB dongle on Windows, you need a USB dongle that does not require a vendor Windows driver (the dongle will be used directly through the [`WinUSB`](https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb) driver rather than through a vendor-supplied Windows driver).

In order to use the dongle, the `WinUSB` driver must be assigned to the USB device. It is likely that, by default, when you first plug in the dongle, it will be recognized by Windows as a Bluetooth USB device, and Windows will try to use it with its native Bluetooth stack. You will need to switch the driver, which can be done easily with the [Zadig tool](https://zadig.akeo.ie/).
In the Zadig tool, select your USB dongle device, and associate it with WinUSB.
Once the WinUSB driver is correctly assigned to your device, you can confirm that by checking the settings with the Windows Device Manager control panel. Your device should appear under "Universal Serial Bus Device" (not under "Bluetooth"), and inspecting the driver details, you should see `winusb.sys` in the list of driver files.

![USB Driver Details](winusb_driver.png)
