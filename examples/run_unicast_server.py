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
import logging
import sys
import os
import struct
import secrets
from bumble.core import AdvertisingData
from bumble.device import Device, CisLink
from bumble.hci import (
    CodecID,
    CodingFormat,
    HCI_IsoDataPacket,
)
from bumble.profiles.bap import (
    UnicastServerAdvertisingData,
    CodecSpecificCapabilities,
    ContextType,
    AudioLocation,
    SupportedSamplingFrequency,
    SupportedFrameDuration,
    PacRecord,
    PublishedAudioCapabilitiesService,
    AudioStreamControlService,
)
from bumble.profiles.cap import CommonAudioServiceService
from bumble.profiles.csip import CoordinatedSetIdentificationService, SirkType

from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print('Usage: run_cig_setup.py <config-file>' '<transport-spec-for-device>')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.cis_enabled = True

        await device.power_on()

        csis = CoordinatedSetIdentificationService(
            set_identity_resolving_key=secrets.token_bytes(16),
            set_identity_resolving_key_type=SirkType.PLAINTEXT,
        )
        device.add_service(CommonAudioServiceService(csis))
        device.add_service(
            PublishedAudioCapabilitiesService(
                supported_source_context=ContextType.PROHIBITED,
                available_source_context=ContextType.PROHIBITED,
                supported_sink_context=ContextType.MEDIA,
                available_sink_context=ContextType.MEDIA,
                sink_audio_locations=(
                    AudioLocation.FRONT_LEFT | AudioLocation.FRONT_RIGHT
                ),
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
                                SupportedSamplingFrequency.FREQ_48000
                            ),
                            supported_frame_durations=(
                                SupportedFrameDuration.DURATION_10000_US_SUPPORTED
                            ),
                            supported_audio_channel_counts=[1],
                            min_octets_per_codec_frame=120,
                            max_octets_per_codec_frame=120,
                            supported_max_codec_frames_per_sdu=1,
                        ),
                    ),
                ],
            )
        )

        device.add_service(AudioStreamControlService(device, sink_ase_id=[1, 2]))

        advertising_data = (
            bytes(
                AdvertisingData(
                    [
                        (
                            AdvertisingData.COMPLETE_LOCAL_NAME,
                            bytes('Bumble LE Audio', 'utf-8'),
                        ),
                        (
                            AdvertisingData.FLAGS,
                            bytes(
                                [
                                    AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG
                                    | AdvertisingData.BR_EDR_HOST_FLAG
                                    | AdvertisingData.BR_EDR_CONTROLLER_FLAG
                                ]
                            ),
                        ),
                        (
                            AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
                            bytes(PublishedAudioCapabilitiesService.UUID),
                        ),
                    ]
                )
            )
            + csis.get_advertising_data()
            + bytes(UnicastServerAdvertisingData())
        )
        subprocess = await asyncio.create_subprocess_shell(
            f'dlc3 | ffplay pipe:0',
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdin = subprocess.stdin
        assert stdin

        # Write a fake LC3 header to dlc3.
        stdin.write(
            bytes([0x1C, 0xCC])  # Header.
            + struct.pack(
                '<HHHHHHI',
                18,  # Header length.
                48000 // 100,  # Sampling Rate(/100Hz).
                0,  # Bitrate(unused).
                1,  # Channels.
                10000 // 10,  # Frame duration(/10us).
                0,  # RFU.
                0x0FFFFFFF,  # Frame counts.
            )
        )

        def on_pdu(pdu: HCI_IsoDataPacket):
            # LC3 format: |frame_length(2)| + |frame(length)|.
            if pdu.iso_sdu_length:
                stdin.write(struct.pack('<H', pdu.iso_sdu_length))
            stdin.write(pdu.iso_sdu_fragment)

        def on_cis(cis_link: CisLink):
            cis_link.on('pdu', on_pdu)

        device.once('cis_establishment', on_cis)

        await device.create_advertising_set(
            advertising_data=advertising_data,
        )

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
