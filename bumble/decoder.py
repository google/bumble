# Copyright 2023 Google LLC
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
# Constants
# -----------------------------------------------------------------------------
# fmt: off

WL = [-60, -30, 58, 172, 334, 538, 1198, 3042]
RL42 = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0]
ILB = [
    2048,
    2093,
    2139,
    2186,
    2233,
    2282,
    2332,
    2383,
    2435,
    2489,
    2543,
    2599,
    2656,
    2714,
    2774,
    2834,
    2896,
    2960,
    3025,
    3091,
    3158,
    3228,
    3298,
    3371,
    3444,
    3520,
    3597,
    3676,
    3756,
    3838,
    3922,
    4008,
]
WH = [0, -214, 798]
RH2 = [2, 1, 2, 1]
# Values in QM2/QM4/QM6 left shift three bits than original g722 specification.
QM2 = [-7408, -1616, 7408, 1616]
QM4 = [
    0,
    -20456,
    -12896,
    -8968,
    -6288,
    -4240,
    -2584,
    -1200,
    20456,
    12896,
    8968,
    6288,
    4240,
    2584,
    1200,
    0,
]
QM6 = [
    -136,
    -136,
    -136,
    -136,
    -24808,
    -21904,
    -19008,
    -16704,
    -14984,
    -13512,
    -12280,
    -11192,
    -10232,
    -9360,
    -8576,
    -7856,
    -7192,
    -6576,
    -6000,
    -5456,
    -4944,
    -4464,
    -4008,
    -3576,
    -3168,
    -2776,
    -2400,
    -2032,
    -1688,
    -1360,
    -1040,
    -728,
    24808,
    21904,
    19008,
    16704,
    14984,
    13512,
    12280,
    11192,
    10232,
    9360,
    8576,
    7856,
    7192,
    6576,
    6000,
    5456,
    4944,
    4464,
    4008,
    3576,
    3168,
    2776,
    2400,
    2032,
    1688,
    1360,
    1040,
    728,
    432,
    136,
    -432,
    -136,
]
QMF_COEFFS = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11]

# fmt: on


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
class G722Decoder(object):
    """G.722 decoder with bitrate 64kbit/s.

    For the Blocks in the sub-band decoders, please refer to the G.722
    specification for the required information. G722 specification:
    https://www.itu.int/rec/T-REC-G.722-201209-I
    """

    def __init__(self):
        self._x = [0] * 24
        self._band = [Band(), Band()]
        # The initial value in BLOCK 3L
        self._band[0].det = 32
        # The initial value in BLOCK 3H
        self._band[1].det = 8

    def decode_frame(self, encoded_data) -> bytearray:
        result_array = bytearray(len(encoded_data) * 4)
        self.g722_decode(result_array, encoded_data)
        return result_array

    def g722_decode(self, result_array, encoded_data) -> int:
        """Decode the data frame using g722 decoder."""
        result_length = 0

        for code in encoded_data:
            higher_bits = (code >> 6) & 0x03
            lower_bits = code & 0x3F

            rlow = self.lower_sub_band_decoder(lower_bits)
            rhigh = self.higher_sub_band_decoder(higher_bits)

            # Apply the receive QMF
            self._x[:22] = self._x[2:]
            self._x[22] = rlow + rhigh
            self._x[23] = rlow - rhigh

            xout2 = sum(self._x[2 * i] * QMF_COEFFS[i] for i in range(12))
            xout1 = sum(self._x[2 * i + 1] * QMF_COEFFS[11 - i] for i in range(12))

            result_length = self.update_decoded_result(
                xout1, result_length, result_array
            )
            result_length = self.update_decoded_result(
                xout2, result_length, result_array
            )

        return result_length

    def update_decoded_result(self, xout, byte_length, byte_array) -> int:
        result = (int)(xout >> 11)
        bytes_result = result.to_bytes(2, 'little', signed=True)
        byte_array[byte_length] = bytes_result[0]
        byte_array[byte_length + 1] = bytes_result[1]
        return byte_length + 2

    def lower_sub_band_decoder(self, lower_bits) -> int:
        """Lower sub-band decoder for last six bits."""

        # Block 5L
        # INVQBL
        wd1 = lower_bits
        wd2 = QM6[wd1]
        wd1 >>= 2
        wd2 = (self._band[0].det * wd2) >> 15
        # RECONS
        rlow = self._band[0].s + wd2

        # Block 6L
        # LIMIT
        if rlow > 16383:
            rlow = 16383
        elif rlow < -16384:
            rlow = -16384

        # Block 2L
        # INVQAL
        wd2 = QM4[wd1]
        dlowt = (self._band[0].det * wd2) >> 15

        # Block 3L
        # LOGSCL
        wd2 = RL42[wd1]
        wd1 = (self._band[0].nb * 127) >> 7
        wd1 += WL[wd2]

        if wd1 < 0:
            wd1 = 0
        elif wd1 > 18432:
            wd1 = 18432

        self._band[0].nb = wd1

        # SCALEL
        wd1 = (self._band[0].nb >> 6) & 31
        wd2 = 8 - (self._band[0].nb >> 11)

        if wd2 < 0:
            wd3 = ILB[wd1] << -wd2
        else:
            wd3 = ILB[wd1] >> wd2

        self._band[0].det = wd3 << 2

        # Block 4L
        self._band[0].block4(dlowt)

        return rlow

    def higher_sub_band_decoder(self, higher_bits) -> int:
        """Higher sub-band decoder for first two bits."""

        # Block 2H
        # INVQAH
        wd2 = QM2[higher_bits]
        dhigh = (self._band[1].det * wd2) >> 15

        # Block 5H
        # RECONS
        rhigh = dhigh + self._band[1].s

        # Block 6H
        # LIMIT
        if rhigh > 16383:
            rhigh = 16383
        elif rhigh < -16384:
            rhigh = -16384

        # Block 3H
        # LOGSCH
        wd2 = RH2[higher_bits]
        wd1 = (self._band[1].nb * 127) >> 7
        wd1 += WH[wd2]

        if wd1 < 0:
            wd1 = 0
        elif wd1 > 22528:
            wd1 = 22528
        self._band[1].nb = wd1

        # SCALEH
        wd1 = (self._band[1].nb >> 6) & 31
        wd2 = 10 - (self._band[1].nb >> 11)

        if wd2 < 0:
            wd3 = ILB[wd1] << -wd2
        else:
            wd3 = ILB[wd1] >> wd2
        self._band[1].det = wd3 << 2

        # Block 4H
        self._band[1].block4(dhigh)

        return rhigh


# -----------------------------------------------------------------------------
class Band(object):
    """Structure for G722 decode proccessing."""

    s: int = 0
    nb: int = 0
    det: int = 0

    def __init__(self):
        self._sp = 0
        self._sz = 0
        self._r = [0] * 3
        self._a = [0] * 3
        self._ap = [0] * 3
        self._p = [0] * 3
        self._d = [0] * 7
        self._b = [0] * 7
        self._bp = [0] * 7
        self._sg = [0] * 7

    def saturate(self, amp: int) -> int:
        if amp > 32767:
            return 32767
        elif amp < -32768:
            return -32768
        else:
            return amp

    def block4(self, d: int) -> None:
        """Block4 for both lower and higher sub-band decoder."""
        wd1 = 0
        wd2 = 0
        wd3 = 0

        # RECONS
        self._d[0] = d
        self._r[0] = self.saturate(self.s + d)

        # PARREC
        self._p[0] = self.saturate(self._sz + d)

        # UPPOL2
        for i in range(3):
            self._sg[i] = (self._p[i]) >> 15
        wd1 = self.saturate((self._a[1]) << 2)
        wd2 = -wd1 if self._sg[0] == self._sg[1] else wd1

        if wd2 > 32767:
            wd2 = 32767

        wd3 = 128 if self._sg[0] == self._sg[2] else -128
        wd3 += wd2 >> 7
        wd3 += (self._a[2] * 32512) >> 15

        if wd3 > 12288:
            wd3 = 12288
        elif wd3 < -12288:
            wd3 = -12288
        self._ap[2] = wd3

        # UPPOL1
        self._sg[0] = (self._p[0]) >> 15
        self._sg[1] = (self._p[1]) >> 15
        wd1 = 192 if self._sg[0] == self._sg[1] else -192
        wd2 = (self._a[1] * 32640) >> 15

        self._ap[1] = self.saturate(wd1 + wd2)
        wd3 = self.saturate(15360 - self._ap[2])

        if self._ap[1] > wd3:
            self._ap[1] = wd3
        elif self._ap[1] < -wd3:
            self._ap[1] = -wd3

        # UPZERO
        wd1 = 0 if d == 0 else 128
        self._sg[0] = d >> 15
        for i in range(1, 7):
            self._sg[i] = (self._d[i]) >> 15
            wd2 = wd1 if self._sg[i] == self._sg[0] else -wd1
            wd3 = (self._b[i] * 32640) >> 15
            self._bp[i] = self.saturate(wd2 + wd3)

        # DELAYA
        for i in range(6, 0, -1):
            self._d[i] = self._d[i - 1]
            self._b[i] = self._bp[i]

        for i in range(2, 0, -1):
            self._r[i] = self._r[i - 1]
            self._p[i] = self._p[i - 1]
            self._a[i] = self._ap[i]

        # FILTEP
        self._sp = 0
        for i in range(1, 3):
            wd1 = self.saturate(self._r[i] + self._r[i])
            self._sp += (self._a[i] * wd1) >> 15
        self._sp = self.saturate(self._sp)

        # FILTEZ
        self._sz = 0
        for i in range(6, 0, -1):
            wd1 = self.saturate(self._d[i] + self._d[i])
            self._sz += (self._b[i] * wd1) >> 15
        self._sz = self.saturate(self._sz)

        # PREDIC
        self.s = self.saturate(self._sp + self._sz)
