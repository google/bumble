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
from enum import IntEnum

from bumble.core import AdvertisingData, Appearance, UUID, get_dict_key_by_value


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
def test_uuid_to_hex_str() -> None:
    assert UUID("b5ea").to_hex_str() == "B5EA"
    assert UUID("df5ce654").to_hex_str() == "DF5CE654"
    assert (
        UUID("df5ce654-e059-11ed-b5ea-0242ac120002").to_hex_str()
        == "DF5CE654E05911EDB5EA0242AC120002"
    )
    assert UUID("b5ea").to_hex_str('-') == "B5EA"
    assert UUID("df5ce654").to_hex_str('-') == "DF5CE654"
    assert (
        UUID("df5ce654-e059-11ed-b5ea-0242ac120002").to_hex_str('-')
        == "DF5CE654-E059-11ED-B5EA-0242AC120002"
    )


# -----------------------------------------------------------------------------
def test_appearance() -> None:
    a = Appearance(Appearance.Category.COMPUTER, Appearance.ComputerSubcategory.LAPTOP)
    assert str(a) == 'COMPUTER/LAPTOP'
    assert int(a) == 0x0083

    a = Appearance(Appearance.Category.HUMAN_INTERFACE_DEVICE, 0x77)
    assert str(a) == 'HUMAN_INTERFACE_DEVICE/HumanInterfaceDeviceSubcategory[119]'
    assert int(a) == 0x03C0 | 0x77

    a = Appearance.from_int(0x0381)
    assert a.category == Appearance.Category.BLOOD_PRESSURE
    assert a.subcategory == Appearance.BloodPressureSubcategory.ARM_BLOOD_PRESSURE
    assert int(a) == 0x381

    a = Appearance.from_int(0x038A)
    assert a.category == Appearance.Category.BLOOD_PRESSURE
    assert a.subcategory == 0x0A
    assert int(a) == 0x038A

    a = Appearance.from_int(0x3333)
    assert a.category == 0xCC
    assert a.subcategory == 0x33
    assert int(a) == 0x3333


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_ad_data()
    test_get_dict_key_by_value()
    test_uuid_to_hex_str()
    test_appearance()
