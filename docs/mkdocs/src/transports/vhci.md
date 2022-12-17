VHCI TRANSPORT
==============

The VHCI transport allows attaching a virtual controller to the Bluetooth stack on operating systems that offer a VHCI driver (Linux, if enabled, maybe others).

!!! note
    This type of transport can only be used for virtual controllers, not virtual hosts

## Moniker
The moniker for a VHCI transport is either just `vhci` (to use the default VHCI device path at `/dev/vhci`), or `vhci:<path>` where `<path>` is the path of a VHCI device.

!!! example
    `vhci`
    Attaches a virtual controller transport to `/dev/vhci`
