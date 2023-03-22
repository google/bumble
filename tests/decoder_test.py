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
# Imports
# -----------------------------------------------------------------------------
import hashlib
import os
from bumble.decoder import G722Decoder


# -----------------------------------------------------------------------------
def test_decode_file():
    decoder = G722Decoder()
    output_bytes = bytearray()

    with open(
        os.path.join(os.path.dirname(__file__), 'g722_sample.g722'), 'rb'
    ) as file:
        file_content = file.read()
        frame_length = 80
        data_length = int(len(file_content) / frame_length)

        for i in range(0, data_length):
            decoded_data = decoder.decode_frame(
                file_content[i * frame_length : i * frame_length + frame_length]
            )
            output_bytes.extend(decoded_data)

        result = hashlib.md5(output_bytes).hexdigest()
        assert result == 'b58e0cdd012d12f5633fc796c3b0fbd4'


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_decode_file()
