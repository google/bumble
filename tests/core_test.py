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
from bumble.core import AdvertisingData


# -----------------------------------------------------------------------------
def test_ad_data():
    data = bytes([2, AdvertisingData.TX_POWER_LEVEL, 123])
    ad = AdvertisingData.from_bytes(data)
    ad_bytes = bytes(ad)
    assert(data == ad_bytes)
    assert(ad.get(AdvertisingData.COMPLETE_LOCAL_NAME) is None)
    assert(ad.get(AdvertisingData.TX_POWER_LEVEL) == bytes([123]))
    assert(ad.get(AdvertisingData.COMPLETE_LOCAL_NAME, return_all=True) == [])
    assert(ad.get(AdvertisingData.TX_POWER_LEVEL, return_all=True) == [bytes([123])])

    data2 = bytes([2, AdvertisingData.TX_POWER_LEVEL, 234])
    ad.append(data2)
    ad_bytes = bytes(ad)
    assert(ad_bytes == data + data2)
    assert(ad.get(AdvertisingData.COMPLETE_LOCAL_NAME) is None)
    assert(ad.get(AdvertisingData.TX_POWER_LEVEL) == bytes([123]))
    assert(ad.get(AdvertisingData.COMPLETE_LOCAL_NAME, return_all=True) == [])
    assert(ad.get(AdvertisingData.TX_POWER_LEVEL, return_all=True) == [bytes([123]), bytes([234])])


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_ad_data()