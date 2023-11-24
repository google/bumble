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
from bumble.profiles import pacs


# -----------------------------------------------------------------------------
def test_codec_specific_capabilities() -> None:
    SAMPLE_FREQUENCY = pacs.SupportedSamplingFrequency.FREQ_16000
    FRAME_SURATION = pacs.SupportedFrameDuration.DURATION_10000_US_SUPPORTED
    AUDIO_CHANNEL_COUNTS = [1]
    cap = pacs.CodecSpecificCapabilities(
        supported_sampling_frequencies=SAMPLE_FREQUENCY,
        supported_frame_durations=FRAME_SURATION,
        supported_audio_channel_counts=AUDIO_CHANNEL_COUNTS,
        min_octets_per_sample=40,
        max_octets_per_sample=40,
        supported_max_codec_frames_per_sdu=1,
    )
    assert pacs.CodecSpecificCapabilities.from_bytes(bytes(cap)) == cap


# -----------------------------------------------------------------------------
def test_pac_record() -> None:
    SAMPLE_FREQUENCY = pacs.SupportedSamplingFrequency.FREQ_16000
    FRAME_SURATION = pacs.SupportedFrameDuration.DURATION_10000_US_SUPPORTED
    AUDIO_CHANNEL_COUNTS = [1]
    cap = pacs.CodecSpecificCapabilities(
        supported_sampling_frequencies=SAMPLE_FREQUENCY,
        supported_frame_durations=FRAME_SURATION,
        supported_audio_channel_counts=AUDIO_CHANNEL_COUNTS,
        min_octets_per_sample=40,
        max_octets_per_sample=40,
        supported_max_codec_frames_per_sdu=1,
    )

    pac_record = pacs.PacRecord(
        codec_id=b'12345', codec_specific_capabilities=cap, metadata=b''
    )
    assert pacs.PacRecord.from_bytes(bytes(pac_record)) == pac_record


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_codec_specific_capabilities()
