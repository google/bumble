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
import asyncio
import os
import pytest
import logging

from bumble import device
from bumble.hci import CodecID, CodingFormat
from bumble.profiles.bap import (
    AudioLocation,
    SupportedFrameDuration,
    SupportedSamplingFrequency,
    CodecSpecificCapabilities,
    ContextType,
    PacRecord,
    PublishedAudioCapabilitiesService,
    PublishedAudioCapabilitiesServiceProxy,
)
from .test_utils import TwoDevices

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def test_codec_specific_capabilities() -> None:
    SAMPLE_FREQUENCY = SupportedSamplingFrequency.FREQ_16000
    FRAME_SURATION = SupportedFrameDuration.DURATION_10000_US_SUPPORTED
    AUDIO_CHANNEL_COUNTS = [1]
    cap = CodecSpecificCapabilities(
        supported_sampling_frequencies=SAMPLE_FREQUENCY,
        supported_frame_durations=FRAME_SURATION,
        supported_audio_channel_counts=AUDIO_CHANNEL_COUNTS,
        min_octets_per_codec_frame=40,
        max_octets_per_codec_frame=40,
        supported_max_codec_frames_per_sdu=1,
    )
    assert CodecSpecificCapabilities.from_bytes(bytes(cap)) == cap


# -----------------------------------------------------------------------------
def test_pac_record() -> None:
    SAMPLE_FREQUENCY = SupportedSamplingFrequency.FREQ_16000
    FRAME_SURATION = SupportedFrameDuration.DURATION_10000_US_SUPPORTED
    AUDIO_CHANNEL_COUNTS = [1]
    cap = CodecSpecificCapabilities(
        supported_sampling_frequencies=SAMPLE_FREQUENCY,
        supported_frame_durations=FRAME_SURATION,
        supported_audio_channel_counts=AUDIO_CHANNEL_COUNTS,
        min_octets_per_codec_frame=40,
        max_octets_per_codec_frame=40,
        supported_max_codec_frames_per_sdu=1,
    )

    pac_record = PacRecord(
        coding_format=CodingFormat(CodecID.LC3),
        codec_specific_capabilities=cap,
        metadata=b'',
    )
    assert PacRecord.from_bytes(bytes(pac_record)) == pac_record


# -----------------------------------------------------------------------------
def test_vendor_specific_pac_record() -> None:
    # Vendor-Specific codec, Google, ID=0xFFFF. No capabilities and metadata.
    RAW_DATA = bytes.fromhex('ffe000ffff0000')
    assert bytes(PacRecord.from_bytes(RAW_DATA)) == RAW_DATA


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_pacs():
    devices = TwoDevices()
    devices[0].add_service(
        PublishedAudioCapabilitiesService(
            supported_sink_context=ContextType.MEDIA,
            available_sink_context=ContextType.MEDIA,
            supported_source_context=0,
            available_source_context=0,
            sink_pac=[
                # Codec Capability Setting 16_2
                PacRecord(
                    coding_format=CodingFormat(CodecID.LC3),
                    codec_specific_capabilities=CodecSpecificCapabilities(
                        supported_sampling_frequencies=(
                            SupportedSamplingFrequency.FREQ_16000
                        ),
                        supported_frame_durations=(
                            SupportedFrameDuration.DURATION_10000_US_SUPPORTED
                        ),
                        supported_audio_channel_counts=[1],
                        min_octets_per_codec_frame=40,
                        max_octets_per_codec_frame=40,
                        supported_max_codec_frames_per_sdu=1,
                    ),
                ),
                # Codec Capability Setting 24_2
                PacRecord(
                    coding_format=CodingFormat(CodecID.LC3),
                    codec_specific_capabilities=CodecSpecificCapabilities(
                        supported_sampling_frequencies=(
                            SupportedSamplingFrequency.FREQ_24000
                        ),
                        supported_frame_durations=(
                            SupportedFrameDuration.DURATION_10000_US_SUPPORTED
                        ),
                        supported_audio_channel_counts=[1],
                        min_octets_per_codec_frame=60,
                        max_octets_per_codec_frame=60,
                        supported_max_codec_frames_per_sdu=1,
                    ),
                ),
            ],
            sink_audio_locations=AudioLocation.FRONT_LEFT | AudioLocation.FRONT_RIGHT,
        )
    )

    await devices.setup_connection()
    peer = device.Peer(devices.connections[1])
    pacs_client = await peer.discover_service_and_create_proxy(
        PublishedAudioCapabilitiesServiceProxy
    )


# -----------------------------------------------------------------------------
async def run():
    await test_pacs()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
