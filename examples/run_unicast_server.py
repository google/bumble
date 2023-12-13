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
import datetime
import functools
import logging
import sys
import os
import io
import struct
import secrets

from typing import Dict

from bumble.core import AdvertisingData
from bumble.device import Device
from bumble.hci import (
    CodecID,
    CodingFormat,
    HCI_IsoDataPacket,
)
from bumble.profiles.bap import (
    AseStateMachine,
    UnicastServerAdvertisingData,
    CodecSpecificConfiguration,
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


def _sink_pac_record() -> PacRecord:
    return PacRecord(
        coding_format=CodingFormat(CodecID.LC3),
        codec_specific_capabilities=CodecSpecificCapabilities(
            supported_sampling_frequencies=(
                SupportedSamplingFrequency.FREQ_8000
                | SupportedSamplingFrequency.FREQ_16000
                | SupportedSamplingFrequency.FREQ_24000
                | SupportedSamplingFrequency.FREQ_32000
                | SupportedSamplingFrequency.FREQ_48000
            ),
            supported_frame_durations=(
                SupportedFrameDuration.DURATION_7500_US_SUPPORTED
                | SupportedFrameDuration.DURATION_10000_US_SUPPORTED
            ),
            supported_audio_channel_count=[1, 2],
            min_octets_per_codec_frame=26,
            max_octets_per_codec_frame=240,
            supported_max_codec_frames_per_sdu=2,
        ),
    )


file_outputs: Dict[AseStateMachine, io.BufferedWriter] = {}


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
                supported_sink_context=ContextType(0xFF),  # All context types
                available_sink_context=ContextType(0xFF),  # All context types
                sink_audio_locations=(
                    AudioLocation.FRONT_LEFT | AudioLocation.FRONT_RIGHT
                ),
                sink_pac=[_sink_pac_record()],
            )
        )

        ascs = AudioStreamControlService(device, sink_ase_id=[1], source_ase_id=[2])
        device.add_service(ascs)

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

        def on_pdu(ase: AseStateMachine, pdu: HCI_IsoDataPacket):
            # LC3 format: |frame_length(2)| + |frame(length)|.
            sdu = b''
            if pdu.iso_sdu_length:
                sdu = struct.pack('<H', pdu.iso_sdu_length)
            sdu += pdu.iso_sdu_fragment
            file_outputs[ase].write(sdu)

        def on_ase_state_change(
            state: AseStateMachine.State,
            ase: AseStateMachine,
        ) -> None:
            if state != AseStateMachine.State.STREAMING:
                if file_output := file_outputs.pop(ase):
                    file_output.close()
            else:
                file_output = open(f'{datetime.datetime.now().isoformat()}.lc3', 'wb')
                codec_configuration = ase.codec_specific_configuration
                assert isinstance(codec_configuration, CodecSpecificConfiguration)
                # Write a LC3 header.
                file_output.write(
                    bytes([0x1C, 0xCC])  # Header.
                    + struct.pack(
                        '<HHHHHHI',
                        18,  # Header length.
                        codec_configuration.sampling_frequency.hz
                        // 100,  # Sampling Rate(/100Hz).
                        0,  # Bitrate(unused).
                        bin(codec_configuration.audio_channel_allocation).count(
                            '1'
                        ),  # Channels.
                        codec_configuration.frame_duration.us
                        // 10,  # Frame duration(/10us).
                        0,  # RFU.
                        0x0FFFFFFF,  # Frame counts.
                    )
                )
                file_outputs[ase] = file_output
                assert ase.cis_link
                ase.cis_link.sink = functools.partial(on_pdu, ase)

        for ase in ascs.ase_state_machines.values():
            ase.on(
                'state_change',
                functools.partial(on_ase_state_change, ase=ase),
            )

        await device.create_advertising_set(
            advertising_data=advertising_data,
            auto_restart=True,
        )

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
