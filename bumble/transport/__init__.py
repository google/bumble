# Copyright 2021-2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from contextlib import asynccontextmanager
import logging
import os

from .common import Transport, AsyncPipeSink, SnoopingTransport
from ..snoop import create_snooper

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def _wrap_transport(transport: Transport) -> Transport:
    """
    Automatically wrap a Transport instance when a wrapping class can be inferred
    from the environment.
    If no wrapping class is applicable, the transport argument is returned as-is.
    """

    # If BUMBLE_SNOOPER is set, try to automatically create a snooper.
    if snooper_spec := os.getenv('BUMBLE_SNOOPER'):
        try:
            return SnoopingTransport.create_with(
                transport, create_snooper(snooper_spec)
            )
        except Exception as exc:
            logger.warning(f'Exception while creating snooper: {exc}')

    return transport


# -----------------------------------------------------------------------------
async def open_transport(name: str) -> Transport:
    """
    Open a transport by name.
    The name must be <type>:<parameters>
    Where <parameters> depend on the type (and may be empty for some types).
    The supported types are:
      * serial
      * udp
      * tcp-client
      * tcp-server
      * ws-client
      * ws-server
      * pty
      * file
      * vhci
      * hci-socket
      * usb
      * pyusb
      * android-emulator
      * android-netsim
    """

    return _wrap_transport(await _open_transport(name))


# -----------------------------------------------------------------------------
async def _open_transport(name: str) -> Transport:
    # pylint: disable=import-outside-toplevel
    # pylint: disable=too-many-return-statements

    scheme, *spec = name.split(':', 1)
    if scheme == 'serial' and spec:
        from .serial import open_serial_transport

        return await open_serial_transport(spec[0])

    if scheme == 'udp' and spec:
        from .udp import open_udp_transport

        return await open_udp_transport(spec[0])

    if scheme == 'tcp-client' and spec:
        from .tcp_client import open_tcp_client_transport

        return await open_tcp_client_transport(spec[0])

    if scheme == 'tcp-server' and spec:
        from .tcp_server import open_tcp_server_transport

        return await open_tcp_server_transport(spec[0])

    if scheme == 'ws-client' and spec:
        from .ws_client import open_ws_client_transport

        return await open_ws_client_transport(spec[0])

    if scheme == 'ws-server' and spec:
        from .ws_server import open_ws_server_transport

        return await open_ws_server_transport(spec[0])

    if scheme == 'pty':
        from .pty import open_pty_transport

        return await open_pty_transport(spec[0] if spec else None)

    if scheme == 'file':
        from .file import open_file_transport

        assert spec is not None
        return await open_file_transport(spec[0])

    if scheme == 'vhci':
        from .vhci import open_vhci_transport

        return await open_vhci_transport(spec[0] if spec else None)

    if scheme == 'hci-socket':
        from .hci_socket import open_hci_socket_transport

        return await open_hci_socket_transport(spec[0] if spec else None)

    if scheme == 'usb':
        from .usb import open_usb_transport

        assert spec is not None
        return await open_usb_transport(spec[0])

    if scheme == 'pyusb':
        from .pyusb import open_pyusb_transport

        assert spec is not None
        return await open_pyusb_transport(spec[0])

    if scheme == 'android-emulator':
        from .android_emulator import open_android_emulator_transport

        return await open_android_emulator_transport(spec[0] if spec else None)

    if scheme == 'android-netsim':
        from .android_netsim import open_android_netsim_transport

        return await open_android_netsim_transport(spec[0] if spec else None)

    raise ValueError('unknown transport scheme')


# -----------------------------------------------------------------------------
async def open_transport_or_link(name: str) -> Transport:
    """
    Open a transport or a link relay.

    Args:
      name:
        Name of the transport or link relay to open.
        When the name starts with "link-relay:", open a link relay (see RemoteLink
        for details on what the arguments are).
        For other namespaces, see `open_transport`.

    """
    if name.startswith('link-relay:'):
        from ..controller import Controller
        from ..link import RemoteLink  # lazy import

        link = RemoteLink(name[11:])
        await link.wait_until_connected()
        controller = Controller('remote', link=link)

        class LinkTransport(Transport):
            async def close(self):
                link.close()

        return _wrap_transport(LinkTransport(controller, AsyncPipeSink(controller)))

    return await open_transport(name)
