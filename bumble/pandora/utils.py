# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations
import contextlib
import functools
import grpc
import inspect
import logging

from bumble.device import Device
from bumble.hci import Address
from google.protobuf.message import Message  # pytype: disable=pyi-error
from typing import Any, Dict, Generator, MutableMapping, Optional, Tuple

ADDRESS_TYPES: Dict[str, int] = {
    "public": Address.PUBLIC_DEVICE_ADDRESS,
    "random": Address.RANDOM_DEVICE_ADDRESS,
    "public_identity": Address.PUBLIC_IDENTITY_ADDRESS,
    "random_static_identity": Address.RANDOM_IDENTITY_ADDRESS,
}


def address_from_request(request: Message, field: Optional[str]) -> Address:
    if field is None:
        return Address.ANY
    return Address(bytes(reversed(getattr(request, field))), ADDRESS_TYPES[field])


class BumbleServerLoggerAdapter(logging.LoggerAdapter):  # type: ignore
    """Formats logs from the PandoraClient."""

    def process(
        self, msg: str, kwargs: MutableMapping[str, Any]
    ) -> Tuple[str, MutableMapping[str, Any]]:
        assert self.extra
        service_name = self.extra['service_name']
        assert isinstance(service_name, str)
        device = self.extra['device']
        assert isinstance(device, Device)
        addr_bytes = bytes(
            reversed(bytes(device.public_address))
        )  # pytype: disable=attribute-error
        addr = ':'.join([f'{x:02X}' for x in addr_bytes[4:]])
        return (f'[bumble.{service_name}:{addr}] {msg}', kwargs)


@contextlib.contextmanager
def exception_to_rpc_error(
    context: grpc.ServicerContext,
) -> Generator[None, None, None]:
    try:
        yield None
    except NotImplementedError as e:
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)  # type: ignore
        context.set_details(str(e))  # type: ignore
    except ValueError as e:
        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)  # type: ignore
        context.set_details(str(e))  # type: ignore
    except RuntimeError as e:
        context.set_code(grpc.StatusCode.ABORTED)  # type: ignore
        context.set_details(str(e))  # type: ignore


# Decorate an RPC servicer method with a wrapper that transform exceptions to gRPC errors.
def rpc(func: Any) -> Any:
    @functools.wraps(func)
    async def asyncgen_wrapper(
        self: Any, request: Any, context: grpc.ServicerContext
    ) -> Any:
        with exception_to_rpc_error(context):
            async for v in func(self, request, context):
                yield v

    @functools.wraps(func)
    async def async_wrapper(
        self: Any, request: Any, context: grpc.ServicerContext
    ) -> Any:
        with exception_to_rpc_error(context):
            return await func(self, request, context)

    @functools.wraps(func)
    def gen_wrapper(self: Any, request: Any, context: grpc.ServicerContext) -> Any:
        with exception_to_rpc_error(context):
            for v in func(self, request, context):
                yield v

    @functools.wraps(func)
    def wrapper(self: Any, request: Any, context: grpc.ServicerContext) -> Any:
        with exception_to_rpc_error(context):
            return func(self, request, context)

    if inspect.isasyncgenfunction(func):
        return asyncgen_wrapper

    if inspect.iscoroutinefunction(func):
        return async_wrapper

    if inspect.isgenerator(func):
        return gen_wrapper

    return wrapper
