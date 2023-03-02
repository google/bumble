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
from bumble.core import AdvertisingData, get_dict_key_by_value


# -----------------------------------------------------------------------------
def test_ad_data():
    data = bytes([2, AdvertisingData.TX_POWER_LEVEL, 123])
    ad = AdvertisingData.from_bytes(data)
    ad_bytes = bytes(ad)
    assert data == ad_bytes
    assert ad.get(AdvertisingData.COMPLETE_LOCAL_NAME, raw=True) is None
    assert ad.get(AdvertisingData.TX_POWER_LEVEL, raw=True) == bytes([123])
    assert ad.get_all(AdvertisingData.COMPLETE_LOCAL_NAME, raw=True) == []
    assert ad.get_all(AdvertisingData.TX_POWER_LEVEL, raw=True) == [bytes([123])]

    data2 = bytes([2, AdvertisingData.TX_POWER_LEVEL, 234])
    ad.append(data2)
    ad_bytes = bytes(ad)
    assert ad_bytes == data + data2
    assert ad.get(AdvertisingData.COMPLETE_LOCAL_NAME, raw=True) is None
    assert ad.get(AdvertisingData.TX_POWER_LEVEL, raw=True) == bytes([123])
    assert ad.get_all(AdvertisingData.COMPLETE_LOCAL_NAME, raw=True) == []
    assert ad.get_all(AdvertisingData.TX_POWER_LEVEL, raw=True) == [
        bytes([123]),
        bytes([234]),
    ]


# -----------------------------------------------------------------------------
def test_get_dict_key_by_value():
    dictionary = {"A": 1, "B": 2}
    assert get_dict_key_by_value(dictionary, 1) == "A"
    assert get_dict_key_by_value(dictionary, 2) == "B"
    assert get_dict_key_by_value(dictionary, 3) is None


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_ad_data()
