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


# -----------------------------------------------------------------------------
def test_import():
    from bumble import (
        att,
        bridge,
        company_ids,
        controller,
        core,
        crypto,
        device,
        gap,
        hci,
        hfp,
        host,
        keys,
        l2cap,
        link,
        rfcomm,
        sdp,
        smp,
        transport,
        utils,
    )

    assert att
    assert bridge
    assert company_ids
    assert controller
    assert core
    assert crypto
    assert device
    assert gap
    assert hci
    assert hfp
    assert host
    assert keys
    assert l2cap
    assert link
    assert rfcomm
    assert sdp
    assert smp
    assert transport
    assert utils


# -----------------------------------------------------------------------------
def test_app_imports():
    from apps.console import main

    assert main

    from apps.controller_info import main

    assert main

    from apps.controllers import main

    assert main

    from apps.gatt_dump import main

    assert main

    from apps.gg_bridge import main

    assert main

    from apps.hci_bridge import main

    assert main

    from apps.pair import main

    assert main

    from apps.scan import main

    assert main

    from apps.show import main

    assert main

    from apps.unbond import main

    assert main

    from apps.usb_probe import main

    assert main


# -----------------------------------------------------------------------------
def test_profiles_imports():
    from bumble.profiles import (
        battery_service,
        device_information_service,
        heart_rate_service,
    )

    assert battery_service
    assert device_information_service
    assert heart_rate_service


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_import()
    test_app_imports()
    test_profiles_imports()
