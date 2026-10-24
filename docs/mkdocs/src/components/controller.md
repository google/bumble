CONTROLLER
==========

The Bumble Controller implements the lower layers of the Bluetooth stack and
exposes an HCI interface to a Host. Bumble applications can instead use an
external Controller by connecting the Host through a supported
[HCI transport](../transports/index.md).

External Controllers
--------------------

[BSWorld](https://github.com/XiaoMi/bsworld) runs Bumble Hosts against
independent external Controllers over Unix-socket HCI transports. It provides
deterministic BabbleSim radio and simulation time, including interference
injection, and archives HCI BTSnoop captures and over-the-air traces for
integration tests.

The BSWorld repository contains the setup instructions and Bumble test
scenarios for advertising, scanning, connections, and periodic advertising.
