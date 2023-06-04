# Copyright 2021-2023 Google LLC
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
from bumble.codecs import AacAudioRtpPacket, BitReader


# -----------------------------------------------------------------------------
def test_reader():
    reader = BitReader(b'')
    with pytest.raises(ValueError):
        reader.read(1)

    reader = BitReader(b'hello')
    with pytest.raises(ValueError):
        reader.read(40)

    reader = BitReader(bytes([0xFF]))
    assert reader.read(1) == 1
    with pytest.raises(ValueError):
        reader.read(10)

    reader = BitReader(bytes([0x78]))
    value = 0
    for _ in range(8):
        value = (value << 1) | reader.read(1)
    assert value == 0x78

    data = bytes([x & 0xFF for x in range(66 * 100)])
    reader = BitReader(data)
    value = 0
    for _ in range(100):
        for bits in range(1, 33):
            value = value << bits | reader.read(bits)
    assert value == int.from_bytes(data, byteorder='big')


def test_aac_rtp():
    # pylint: disable=line-too-long
    packet_data = bytes.fromhex(
        '47fc0000b090800300202066000198000de120000000000000000000000000000000000000000000001c'
    )
    packet = AacAudioRtpPacket(packet_data)
    adts = packet.to_adts()
    assert adts == bytes.fromhex(
        'fff1508004fffc2066000198000de120000000000000000000000000000000000000000000001c'
    )


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_reader()
    test_aac_rtp()
