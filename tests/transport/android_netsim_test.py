# Copyright 2021-2026 Google LLC
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
import pytest

pytest.importorskip('grpc')

from bumble.transport.android_netsim import (  # noqa: E402
    parse_android_netsim_spec,
)
from bumble.transport.common import TransportSpecError  # noqa: E402


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    'spec, expected',
    [
        (None, (None, 0, {})),
        ('', (None, 0, {})),
        ('localhost:8555', ('localhost', 8555, {})),
        ('localhost:8555,name=bumble1', ('localhost', 8555, {'name': 'bumble1'})),
        ('_:8877,mode=controller', ('_', 8877, {'mode': 'controller'})),
        ('name=bumble1', (None, 0, {'name': 'bumble1'})),
        (
            'address=F0:F1:F2:F3:F4:F5',
            (None, 0, {'address': 'F0:F1:F2:F3:F4:F5'}),
        ),
        (
            'localhost:8555,address=F0:F1:F2:F3:F4:F5',
            ('localhost', 8555, {'address': 'F0:F1:F2:F3:F4:F5'}),
        ),
    ],
)
def test_parse_android_netsim_spec(spec, expected):
    assert parse_android_netsim_spec(spec) == expected


# -----------------------------------------------------------------------------
def test_parse_android_netsim_spec_rejects_bare_parameter():
    with pytest.raises(TransportSpecError):
        parse_android_netsim_spec('localhost:8555,oops')
