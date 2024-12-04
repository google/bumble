# Copyright 2024 Google LLC
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
import logging
import sys
import os
import random

from bumble import core
from bumble import hci
from bumble import device as bumble_device
from bumble.profiles import bap
from bumble.profiles import le_audio
from bumble.transport import open_transport_or_link


# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_auracast_source.py <config-file> <transport-spec-for-device> '
            '<lc3_file_path>'
        )
        print('example: run_auracast_source.py device1.json usb:0 sample.lc3')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        device = bumble_device.Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )

        await device.power_on()

        broadcast_id = random.randint(0, 0xFFFFFF)
        basic_audio_announcement = bap.BasicAudioAnnouncement(
            presentation_delay=40000,
            subgroups=[
                bap.BasicAudioAnnouncement.Subgroup(
                    codec_id=hci.CodingFormat(codec_id=hci.CodecID.LC3),
                    codec_specific_configuration=bap.CodecSpecificConfiguration(
                        sampling_frequency=bap.SamplingFrequency.FREQ_48000,
                        frame_duration=bap.FrameDuration.DURATION_10000_US,
                        octets_per_codec_frame=100,
                    ),
                    metadata=le_audio.Metadata(
                        [
                            le_audio.Metadata.Entry(
                                tag=le_audio.Metadata.Tag.LANGUAGE, data=b'eng'
                            ),
                            le_audio.Metadata.Entry(
                                tag=le_audio.Metadata.Tag.PROGRAM_INFO, data=b'Disco'
                            ),
                        ]
                    ),
                    bis=[
                        bap.BasicAudioAnnouncement.BIS(
                            index=0,
                            codec_specific_configuration=bap.CodecSpecificConfiguration(
                                audio_channel_allocation=bap.AudioLocation.FRONT_LEFT
                            ),
                        ),
                        bap.BasicAudioAnnouncement.BIS(
                            index=1,
                            codec_specific_configuration=bap.CodecSpecificConfiguration(
                                audio_channel_allocation=bap.AudioLocation.FRONT_RIGHT
                            ),
                        ),
                    ],
                )
            ],
        )
        broadcast_audio_announcement = bap.BroadcastAudioAnnouncement(broadcast_id)
        advertising_set = await device.create_advertising_set(
            advertising_parameters=bumble_device.AdvertisingParameters(
                advertising_event_properties=bumble_device.AdvertisingEventProperties(
                    is_connectable=False
                ),
                primary_advertising_interval_min=100,
                primary_advertising_interval_max=200,
            ),
            advertising_data=(
                broadcast_audio_announcement.get_advertising_data()
                + bytes(
                    core.AdvertisingData(
                        [(core.AdvertisingData.BROADCAST_NAME, b'Bumble Auracast')]
                    )
                )
            ),
            periodic_advertising_parameters=bumble_device.PeriodicAdvertisingParameters(
                periodic_advertising_interval_min=80,
                periodic_advertising_interval_max=160,
            ),
            periodic_advertising_data=basic_audio_announcement.get_advertising_data(),
            auto_restart=True,
            auto_start=True,
        )
        await advertising_set.start_periodic()
        big = await device.create_big(
            advertising_set,
            parameters=bumble_device.BigParameters(
                num_bis=2,
                sdu_interval=10000,
                max_sdu=100,
                max_transport_latency=65,
                rtn=4,
            ),
        )
        for bis_link in big.bis_links:
            await device.send_command(
                hci.HCI_LE_Setup_ISO_Data_Path_Command(
                    connection_handle=bis_link.handle,
                    data_path_direction=hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.HOST_TO_CONTROLLER,
                    data_path_id=0,
                    codec_id=hci.CodingFormat(hci.CodecID.TRANSPARENT),
                    controller_delay=0,
                    codec_configuration=b'',
                ),
                check_result=True,
            )

        await hci_transport.source.terminated


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
asyncio.run(main())
