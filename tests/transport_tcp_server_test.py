# Copyright 2024 Google LLC
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

import asyncio
import os
import socket
from unittest import mock

import pytest

from bumble.transport.tcp_server import (
    open_tcp_server_transport,
    open_tcp_server_transport_with_socket,
)


async def test_open_with_spec():
    with mock.patch.object(asyncio.get_running_loop(), 'create_server') as m:
        await open_tcp_server_transport('localhost:32100')
        m.assert_awaited_once_with(mock.ANY, host='localhost', port=32100)


async def test_open_with_port_only_spec():
    with mock.patch.object(asyncio.get_running_loop(), 'create_server') as m:
        await open_tcp_server_transport('_:32100')
        m.assert_awaited_once_with(mock.ANY, host=None, port=32100)


async def test_open_with_socket():
    with mock.patch.object(asyncio.get_running_loop(), 'create_server') as m:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            await open_tcp_server_transport_with_socket(sock=sock)
        m.assert_awaited_once_with(mock.ANY, sock=sock)


@pytest.mark.skipif(
    not os.environ.get('PYTEST_NOSKIP', 0),
    reason='''\
Not hermetic. Should only run manually with
  $ PYTEST_NOSKIP=1 pytest tests
''',
)
def test_open_with_real_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('localhost', 0))
        port = sock.getsockname()[1]
        assert port != 0
        asyncio.run(open_tcp_server_transport_with_socket(sock=sock))
