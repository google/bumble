# Copyright 2021-2024 Google LLC
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
from bumble import hid
from . import test_utils


# -----------------------------------------------------------------------------
async def test_sdp_record():
    devices = test_utils.TwoDevices()
    await devices.setup_connection()

    devices[0].sdp_service_records = {
        1: hid.make_device_sdp_record(
            service_record_handle=1,
            hid_report_map=b'123',
            version_number=2,
            service_name=b'456',
            service_description=b'abc',
            provider_name=b'def',
            hid_parser_version=3,
            hid_device_subclass=4,
            hid_country_code=5,
            hid_virtual_cable=False,
            hid_reconnect_initiate=True,
            report_descriptor_type=6,
            hid_langid_base_language=7,
            hid_langid_base_bluetooth_string_offset=8,
            hid_battery_power=True,
            hid_remote_wake=False,
            hid_supervision_timeout=9,
            hid_normally_connectable=True,
            hid_boot_device=False,
            hid_ssr_host_max_latency=10,
            hid_ssr_host_min_timeout=11,
        )
    }
    found_record = await hid.find_device_sdp_record(devices.connections[1])
    assert found_record == hid.SdpInformation(
        service_record_handle=1,
        hid_report_map=b'123',
        version_number=2,
        service_name=b'456',
        service_description=b'abc',
        provider_name=b'def',
        hid_parser_version=3,
        hid_device_subclass=4,
        hid_country_code=5,
        hid_virtual_cable=False,
        hid_reconnect_initiate=True,
        report_descriptor_type=6,
        hid_langid_base_language=7,
        hid_langid_base_bluetooth_string_offset=8,
        hid_battery_power=True,
        hid_remote_wake=False,
        hid_supervision_timeout=9,
        hid_normally_connectable=True,
        hid_boot_device=False,
        hid_ssr_host_max_latency=10,
        hid_ssr_host_min_timeout=11,
    )
