REALTEK DRIVER
==============

This driver supports loading firmware images and optional config data to 
USB dongles with a Realtek chipset.
A number of USB dongles are supported, but likely not all.
When using a USB dongle, the USB product ID and manufacturer ID are used
to find whether a matching set of firmware image and config data
is needed for that specific model. If a match exists, the driver will try
load the firmware image and, if needed, config data.
The driver will look for those files by name, in order, in:

  * The directory specified by the environment variable `BUMBLE_RTK_FIRMWARE_DIR`
    if set.
  * The directory `<package-dir>/drivers/rtk_fw` where `<package-dir>` is the directory
    where the `bumble` package is installed.
  * The current directory.


Obtaining Firmware Images and Config Data
-----------------------------------------

Firmware images and config data may be obtained from a variety of online
sources.
To facilitate finding a downloading the, the utility program `bumble-rtk-fw-download`
may be used.

```
Usage: bumble-rtk-fw-download [OPTIONS]

  Download RTK firmware images and configs.

Options:
  --output-dir TEXT               Output directory where the files will be
                                  saved  [default: .]
  --source [linux-kernel|realtek-opensource|linux-from-scratch]
                                  [default: linux-kernel]
  --single TEXT                   Only download a single image set, by its
                                  base name
  --force                         Overwrite files if they already exist
  --parse                         Parse the FW image after saving
  --help                          Show this message and exit.
```

Utility
-------

The `bumble-rtk-util` utility may be used to interact with a Realtek USB dongle
and/or firmware images.

```
Usage: bumble-rtk-util [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  drop   Drop a firmware image from the USB dongle.
  info   Get the firmware info from a USB dongle.
  load   Load a firmware image into the USB dongle.
  parse  Parse a firmware image.
```