INTEL DRIVER
==============

This driver supports loading firmware images and optional config data to
Intel USB controllers.
A number of USB dongles are supported, but likely not all.
The initial implementation has been tested on BE200 and AX210 controllers.
When using a USB controller, the USB product ID and vendor ID are used
to find whether a matching set of firmware image and config data
is needed for that specific model. If a match exists, the driver will try
load the firmware image and, if needed, config data.
Alternatively, the metadata property ``driver=intel`` may be specified in a transport
name to force that driver to be used (ex: ``usb:[driver=intel]0`` instead of just
``usb:0`` for the first USB device).
The driver will look for the firmware and config files by name, in order, in:

  * The directory specified by the environment variable `BUMBLE_INTEL_FIRMWARE_DIR`
    if set.
  * The directory `<package-dir>/drivers/intel_fw` where `<package-dir>` is the directory
    where the `bumble` package is installed.
  * The current directory.

It is also possible to override or extend the config data with parameters passed via the
transport name. The driver name `intel` may be suffixed with `/<param:value>[+<param:value>]...`
The supported params are:
  * `ddc_addon`: configuration data to add to the data loaded from the config data file
  * `ddc_override`: configuration data to use instead of the data loaded from the config data file.

With both `dcc_addon` and `dcc_override`, the param value is a hex-encoded byte array containing
the config data (same format as the config file).
Example transport name:
`usb:[driver=intel/dcc_addon:03E40200]0`


Obtaining Firmware Images and Config Data
-----------------------------------------

Firmware images and config data may be obtained from a variety of online
sources.
To facilitate finding a downloading the, the utility program `bumble-intel-fw-download`
may be used.

```
Usage: bumble-intel-fw-download [OPTIONS]

  Download Intel firmware images and configs.

Options:
  --output-dir TEXT        Output directory where the files will be saved.
                           Defaults to the OS-specific app data dir, which the
                           driver will check when trying to find firmware
  --source [linux-kernel]  [default: linux-kernel]
  --single TEXT            Only download a single image set, by its base name
  --force                  Overwrite files if they already exist
  --help                   Show this message and exit.
```

Utility
-------

The `bumble-intel-util` utility may be used to interact with an Intel USB controller.

```
Usage: bumble-intel-util [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  bootloader  Reboot in bootloader mode.
  info        Get the firmware info.
  load        Load a firmware image.
```