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
from bumble.profiles import le_audio


def test_parse_metadata():
    metadata = le_audio.Metadata(
        entries=[
            le_audio.Metadata.Entry(
                tag=le_audio.Metadata.Tag.PROGRAM_INFO,
                data=b'',
            ),
            le_audio.Metadata.Entry(
                tag=le_audio.Metadata.Tag.STREAMING_AUDIO_CONTEXTS,
                data=bytes([0, 0]),
            ),
            le_audio.Metadata.Entry(
                tag=le_audio.Metadata.Tag.PREFERRED_AUDIO_CONTEXTS,
                data=bytes([1, 2]),
            ),
        ]
    )

    assert le_audio.Metadata.from_bytes(bytes(metadata)) == metadata
