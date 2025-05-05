# Copyright 2021-2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License")
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

from __future__ import annotations

import abc


class BaseEccKey(abc.ABC):
    """Base Elliptic Curve Cryptography Key class."""

    @classmethod
    @abc.abstractmethod
    def generate(cls) -> BaseEccKey:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_private_key_bytes(cls, d_bytes: bytes) -> BaseEccKey:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def x(self) -> bytes:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def y(self) -> bytes:
        raise NotImplementedError

    def dh(self, public_key_x: bytes, public_key_y: bytes) -> bytes:
        raise NotImplementedError
