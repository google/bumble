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
import logging
import os
import re
from typing import Optional

from bumble import utils
from bumble.snoop import create_snooper
from bumble.transport.common import SnoopingTransport, Transport, TransportSpecError

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
        except Exception:
            logger.exception('Exception while creating snooper')

    return transport


# -----------------------------------------------------------------------------
async def open_transport(name: str) -> Transport:
    """
    Open a transport by name.
    The name must be <type>:<metadata><parameters>
    Where <parameters> depend on the type (and may be empty for some types), and
    <metadata> is either omitted, or a ,-separated list of <key>=<value> pairs,
    enclosed in [].
    If there are not metadata or parameter, the : after the <type> may be omitted.
    Examples:
      * usb:0
      * usb:[driver=rtk]0
      * android-netsim

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

    scheme, *tail = name.split(':', 1)
    spec = tail[0] if tail else None
    metadata = None
    if spec and (m := re.search(r'\[(\w+=\w+(?:,\w+=\w+)*,?)\]', spec)):
        metadata_str = m.group(1)
        if m.start() == 0:
            # <metadata><spec>
            spec = spec[m.end() :]
        else:
            spec = spec[: m.start()]
        metadata = dict([entry.split('=') for entry in metadata_str.split(',')])

    transport = await _open_transport(scheme, spec)
    if metadata:
        transport.source.metadata = {  # type: ignore[attr-defined]
            **metadata,
            **getattr(transport.source, 'metadata', {}),
        }
        # pylint: disable=line-too-long
        logger.debug(f'HCI metadata: {transport.source.metadata}')  # type: ignore[attr-defined]

    return _wrap_transport(transport)


# -----------------------------------------------------------------------------
async def _open_transport(scheme: str, spec: Optional[str]) -> Transport:
    # pylint: disable=import-outside-toplevel
    # pylint: disable=too-many-return-statements

    if scheme == 'serial' and spec:
        from bumble.transport.serial import open_serial_transport

        return await open_serial_transport(spec)

    if scheme == 'udp' and spec:
        from bumble.transport.udp import open_udp_transport

        return await open_udp_transport(spec)

    if scheme == 'tcp-client' and spec:
        from bumble.transport.tcp_client import open_tcp_client_transport

        return await open_tcp_client_transport(spec)

    if scheme == 'tcp-server' and spec:
        from bumble.transport.tcp_server import open_tcp_server_transport

        return await open_tcp_server_transport(spec)

    if scheme == 'ws-client' and spec:
        from bumble.transport.ws_client import open_ws_client_transport

        return await open_ws_client_transport(spec)

    if scheme == 'ws-server' and spec:
        from bumble.transport.ws_server import open_ws_server_transport

        return await open_ws_server_transport(spec)

    if scheme == 'pty':
        from bumble.transport.pty import open_pty_transport

        return await open_pty_transport(spec)

    if scheme == 'file':
        from bumble.transport.file import open_file_transport

        assert spec is not None
        return await open_file_transport(spec)

    if scheme == 'vhci':
        from bumble.transport.vhci import open_vhci_transport

        return await open_vhci_transport(spec)

    if scheme == 'hci-socket':
        from bumble.transport.hci_socket import open_hci_socket_transport

        return await open_hci_socket_transport(spec)

    if scheme == 'usb':
        from bumble.transport.usb import open_usb_transport

        assert spec
        return await open_usb_transport(spec)

    if scheme == 'pyusb':
        from bumble.transport.pyusb import open_pyusb_transport

        assert spec
        return await open_pyusb_transport(spec)

    if scheme == 'android-emulator':
        from bumble.transport.android_emulator import open_android_emulator_transport

        return await open_android_emulator_transport(spec)

    if scheme == 'android-netsim':
        from bumble.transport.android_netsim import open_android_netsim_transport

        return await open_android_netsim_transport(spec)

    if scheme in ('unix', 'unix-client'):
        from bumble.transport.unix import open_unix_client_transport

        assert spec
        return await open_unix_client_transport(spec)

    if scheme == 'unix-server':
        from bumble.transport.unix import open_unix_server_transport

        assert spec
        return await open_unix_server_transport(spec)

    raise TransportSpecError('unknown transport scheme')


# -----------------------------------------------------------------------------
@utils.deprecated("RemoteLink has been removed. Use open_transport instead.")
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

    return await open_transport(name)
