# Copyright 2021-2022 Google LLC
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
import asyncio
import logging
import struct
import os
import socket
import ctypes
import collections

from typing import Optional

from .common import Transport, ParserSource


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
async def open_hci_socket_transport(spec: Optional[str]) -> Transport:
    '''
    Open an HCI Socket (only available on some platforms).
    The parameter string is either empty (to use the first/default Bluetooth adapter)
    or a 0-based integer to indicate the adapter number.
    '''

    HCI_CHANNEL_USER = 1  # pylint: disable=invalid-name

    # Create a raw HCI socket
    try:
        hci_socket = socket.socket(
            socket.AF_BLUETOOTH,  # type: ignore[attr-defined]
            socket.SOCK_RAW | socket.SOCK_NONBLOCK,  # type: ignore[attr-defined]
            socket.BTPROTO_HCI,  # type: ignore[attr-defined]
        )
    except AttributeError as error:
        # Not supported on this platform
        logger.info("HCI sockets not supported on this platform")
        raise Exception(
            'Bluetooth HCI sockets not supported on this platform'
        ) from error

    # Compute the adapter index
    if spec is None:
        adapter_index = 0
    else:
        adapter_index = int(spec)

    # Bind the socket
    # NOTE: since Python doesn't support binding with the required address format (yet),
    # we need to go directly to the C runtime...
    try:
        ctypes.cdll.LoadLibrary('libc.so.6')
        libc = ctypes.CDLL('libc.so.6', use_errno=True)
    except OSError as error:
        logger.info("HCI sockets not supported on this platform")
        raise Exception(
            'Bluetooth HCI sockets not supported on this platform'
        ) from error
    libc.bind.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_char), ctypes.c_int)
    libc.bind.restype = ctypes.c_int
    bind_address = struct.pack(
        # pylint: disable=no-member
        '<HHH',
        socket.AF_BLUETOOTH,  # type: ignore[attr-defined]
        adapter_index,
        HCI_CHANNEL_USER,
    )
    if (
        libc.bind(
            hci_socket.fileno(),
            ctypes.create_string_buffer(bind_address),
            len(bind_address),
        )
        != 0
    ):
        raise IOError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

    class HciSocketSource(ParserSource):
        def __init__(self, hci_socket):
            super().__init__()
            self.socket = hci_socket
            asyncio.get_running_loop().add_reader(
                self.socket.fileno(), self.recv_until_would_block
            )

        def recv_until_would_block(self):
            logger.debug('recv until would block +++')
            while True:
                try:
                    packet = self.socket.recv(4096)
                    logger.debug(f'received packet {len(packet)} bytes')
                    self.parser.feed_data(packet)
                except BlockingIOError:
                    logger.debug('recv would block')
                    break

        def close(self):
            asyncio.get_running_loop().remove_reader(self.socket.fileno())

    class HciSocketSink:
        def __init__(self, hci_socket):
            self.socket = hci_socket
            self.packets = collections.deque()
            self.writer_added = False

        def send_until_would_block(self):
            logger.debug('send until would block ---')
            while self.packets:
                packet = self.packets.pop()
                logger.debug('sending packet')
                try:
                    bytes_written = self.socket.send(packet)
                except BlockingIOError:
                    bytes_written = 0
                if bytes_written != len(packet):
                    # Note: we assume here that there are no partial writes
                    logger.debug('send would block')
                    break

            if self.packets:
                # There's still something to send, ensure that we are monitoring the
                # socket
                if not self.writer_added:
                    asyncio.get_running_loop().add_writer(
                        # pylint: disable=no-member
                        self.socket.fileno(),
                        self.send_until_would_block,
                    )
                    self.writer_added = True
            else:
                # Nothing left to send, stop monitoring the socket
                if self.writer_added:
                    asyncio.get_running_loop().remove_writer(self.socket.fileno())
                    self.writer_added = False

        def on_packet(self, packet):
            self.packets.appendleft(packet)
            self.send_until_would_block()

        def close(self):
            if self.writer_added:
                asyncio.get_running_loop().remove_writer(self.socket.fileno())

    class HciSocketTransport(Transport):
        def __init__(self, hci_socket, source, sink):
            super().__init__(source, sink)
            self.socket = hci_socket

        async def close(self):
            logger.debug('closing HCI socket transport')
            self.source.close()
            self.sink.close()
            self.socket.close()

    packet_source = HciSocketSource(hci_socket)
    packet_sink = HciSocketSink(hci_socket)
    return HciSocketTransport(hci_socket, packet_source, packet_sink)
