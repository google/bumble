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
import functools
import pytest
import logging

from bumble import device
from bumble.hci import CodecID, CodingFormat
from bumble.profiles.bap import (
    AudioLocation,
    AseStateMachine,
    ASE_Operation,
    ASE_Config_Codec,
    ASE_Config_QOS,
    ASE_Disable,
    ASE_Enable,
    ASE_Receiver_Start_Ready,
    ASE_Receiver_Stop_Ready,
    ASE_Release,
    ASE_Update_Metadata,
    SupportedFrameDuration,
    SupportedSamplingFrequency,
    SamplingFrequency,
    FrameDuration,
    CodecSpecificCapabilities,
    CodecSpecificConfiguration,
    ContextType,
    PacRecord,
    AudioStreamControlService,
    AudioStreamControlServiceProxy,
    PublishedAudioCapabilitiesService,
    PublishedAudioCapabilitiesServiceProxy,
)
from tests.test_utils import TwoDevices


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def basic_check(operation: ASE_Operation):
    serialized = bytes(operation)
    parsed = ASE_Operation.from_bytes(serialized)
    assert bytes(parsed) == serialized


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
def test_ASE_Config_Codec() -> None:
    operation = ASE_Config_Codec(
        ase_id=[1, 2],
        target_latency=[3, 4],
        target_phy=[5, 6],
        codec_id=[CodingFormat(CodecID.LC3), CodingFormat(CodecID.LC3)],
        codec_specific_configuration=[b'foo', b'bar'],
    )
    basic_check(operation)


# -----------------------------------------------------------------------------
def test_ASE_Config_QOS() -> None:
    operation = ASE_Config_QOS(
        ase_id=[1, 2],
        cig_id=[1, 2],
        cis_id=[3, 4],
        sdu_interval=[5, 6],
        framing=[0, 1],
        phy=[2, 3],
        max_sdu=[4, 5],
        retransmission_number=[6, 7],
        max_transport_latency=[8, 9],
        presentation_delay=[10, 11],
    )
    basic_check(operation)


# -----------------------------------------------------------------------------
def test_ASE_Enable() -> None:
    operation = ASE_Enable(
        ase_id=[1, 2],
        metadata=[b'foo', b'bar'],
    )
    basic_check(operation)


# -----------------------------------------------------------------------------
def test_ASE_Update_Metadata() -> None:
    operation = ASE_Update_Metadata(
        ase_id=[1, 2],
        metadata=[b'foo', b'bar'],
    )
    basic_check(operation)


# -----------------------------------------------------------------------------
def test_ASE_Disable() -> None:
    operation = ASE_Disable(ase_id=[1, 2])
    basic_check(operation)


# -----------------------------------------------------------------------------
def test_ASE_Release() -> None:
    operation = ASE_Release(ase_id=[1, 2])
    basic_check(operation)


# -----------------------------------------------------------------------------
def test_ASE_Receiver_Start_Ready() -> None:
    operation = ASE_Receiver_Start_Ready(ase_id=[1, 2])
    basic_check(operation)


# -----------------------------------------------------------------------------
def test_ASE_Receiver_Stop_Ready() -> None:
    operation = ASE_Receiver_Stop_Ready(ase_id=[1, 2])
    basic_check(operation)


# -----------------------------------------------------------------------------
def test_codec_specific_configuration() -> None:
    SAMPLE_FREQUENCY = SamplingFrequency.FREQ_16000
    FRAME_SURATION = FrameDuration.DURATION_10000_US
    AUDIO_LOCATION = AudioLocation.FRONT_LEFT
    config = CodecSpecificConfiguration(
        sampling_frequency=SAMPLE_FREQUENCY,
        frame_duration=FRAME_SURATION,
        audio_channel_allocation=AUDIO_LOCATION,
        octets_per_codec_frame=60,
        codec_frames_per_sdu=1,
    )
    assert CodecSpecificConfiguration.from_bytes(bytes(config)) == config


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
@pytest.mark.asyncio
async def test_ascs():
    devices = TwoDevices()
    devices[0].add_service(
        AudioStreamControlService(device=devices[0], sink_ase_id=[1, 2])
    )

    await devices.setup_connection()
    peer = device.Peer(devices.connections[1])
    ascs_client = await peer.discover_service_and_create_proxy(
        AudioStreamControlServiceProxy
    )

    notifications = {1: asyncio.Queue(), 2: asyncio.Queue()}

    def on_notification(data: bytes, ase_id: int):
        notifications[ase_id].put_nowait(data)

    # Should be idle
    assert await ascs_client.sink_ase[0].read_value() == bytes(
        [1, AseStateMachine.State.IDLE]
    )
    assert await ascs_client.sink_ase[1].read_value() == bytes(
        [2, AseStateMachine.State.IDLE]
    )

    # Subscribe
    await ascs_client.sink_ase[0].subscribe(
        functools.partial(on_notification, ase_id=1)
    )
    await ascs_client.sink_ase[1].subscribe(
        functools.partial(on_notification, ase_id=2)
    )

    # Config Codec
    config = CodecSpecificConfiguration(
        sampling_frequency=SamplingFrequency.FREQ_48000,
        frame_duration=FrameDuration.DURATION_10000_US,
        audio_channel_allocation=AudioLocation.FRONT_LEFT,
        octets_per_codec_frame=120,
        codec_frames_per_sdu=1,
    )
    await ascs_client.ase_control_point.write_value(
        ASE_Config_Codec(
            ase_id=[1, 2],
            target_latency=[3, 4],
            target_phy=[5, 6],
            codec_id=[CodingFormat(CodecID.LC3), CodingFormat(CodecID.LC3)],
            codec_specific_configuration=[config, config],
        )
    )
    assert (await notifications[1].get())[:2] == bytes(
        [1, AseStateMachine.State.CODEC_CONFIGURED]
    )
    assert (await notifications[2].get())[:2] == bytes(
        [2, AseStateMachine.State.CODEC_CONFIGURED]
    )

    # Config QOS
    await ascs_client.ase_control_point.write_value(
        ASE_Config_QOS(
            ase_id=[1, 2],
            cig_id=[1, 2],
            cis_id=[3, 4],
            sdu_interval=[5, 6],
            framing=[0, 1],
            phy=[2, 3],
            max_sdu=[4, 5],
            retransmission_number=[6, 7],
            max_transport_latency=[8, 9],
            presentation_delay=[10, 11],
        )
    )
    assert (await notifications[1].get())[:2] == bytes(
        [1, AseStateMachine.State.QOS_CONFIGURED]
    )
    assert (await notifications[2].get())[:2] == bytes(
        [2, AseStateMachine.State.QOS_CONFIGURED]
    )

    # Enable
    await ascs_client.ase_control_point.write_value(
        ASE_Enable(
            ase_id=[1, 2],
            metadata=[b'foo', b'bar'],
        )
    )
    assert (await notifications[1].get())[:2] == bytes(
        [1, AseStateMachine.State.ENABLING]
    )
    assert (await notifications[2].get())[:2] == bytes(
        [2, AseStateMachine.State.ENABLING]
    )

    # CIS establishment
    devices[0].emit(
        'cis_establishment',
        device.CisLink(
            device=devices[0],
            acl_connection=devices.connections[0],
            handle=5,
            cis_id=3,
            cig_id=1,
        ),
    )
    devices[0].emit(
        'cis_establishment',
        device.CisLink(
            device=devices[0],
            acl_connection=devices.connections[0],
            handle=6,
            cis_id=4,
            cig_id=2,
        ),
    )
    assert (await notifications[1].get())[:2] == bytes(
        [1, AseStateMachine.State.STREAMING]
    )
    assert (await notifications[2].get())[:2] == bytes(
        [2, AseStateMachine.State.STREAMING]
    )

    # Release
    await ascs_client.ase_control_point.write_value(
        ASE_Release(
            ase_id=[1, 2],
            metadata=[b'foo', b'bar'],
        )
    )
    assert (await notifications[1].get())[:2] == bytes(
        [1, AseStateMachine.State.RELEASING]
    )
    assert (await notifications[2].get())[:2] == bytes(
        [2, AseStateMachine.State.RELEASING]
    )
    assert (await notifications[1].get())[:2] == bytes([1, AseStateMachine.State.IDLE])
    assert (await notifications[2].get())[:2] == bytes([2, AseStateMachine.State.IDLE])

    await asyncio.sleep(0.001)


# -----------------------------------------------------------------------------
async def run():
    await test_pacs()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
