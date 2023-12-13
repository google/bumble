INTEL DRIVER
==============

This driver supports loading firmware images for dongles with an Intel chipset. At present, it is specifically designed for the Intel AX210 model.

The Intel AX210 relies solely on HCI Vendor Commands in bootloader mode, which limits the ability to programmatically identify the correct dongle when connected. To use Bumble with the Intel AX210, it's necessary to explicitly specify the intel driver in the transport command. For example:

```shell
python3 examples/<example>.py examples/classic1.json tcp-client:[driver=intel]127.0.0.1:6211
```

The driver uses particular Intel HCI vendor commands to ascertain the appropriate firmware image for the dongle in use. If a matching image is found, the driver proceeds to load it. The firmware files are sought in the following sequence:

  * The search begins in the directory specified by the `BUMBLE_INTEL_FIRMWARE_DIR` environment variable, if it has been set.
  * Next, the driver looks in the directory `<package-dir>/drivers/intel_fw`, where `<package-dir>` is the directory where the bumble package is installed.
  * On Linux, the system's firmware directory at `lib/firmware/intel/` is also checked.
  * Lastly, the driver searches in the current directory.


Obtaining Firmware Images and Config Data
-----------------------------------------

To determine the required firmware version for your dongle, you can utilize the utility scripts. Once you know the version needed, the firmware can be sourced directly from the Intel firmware repository in the Linux kernel. You can find the appropriate version at the following link: [Intel Firmware Repository](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/intel).

To aid in identifying the correct firmware version, the intel_util utility program can be used. This tool provides commands to retrieve firmware information and load firmware images into the Bluetooth dongle.

Usage of the intel_util program is as follows:

```
Usage: intel_util.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  info  Get the firmware info from a transport
  load  Load a firmware image into the Bluetooth dongle
```

An example command to get firmware info:

```shell
python3 tools/intel_util.py info tcp-client:[driver=intel]127.0.0.1:6211
```