# Copyright 2021-2026 Google LLC
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
from __future__ import annotations

import pytest

from bumble import device, hci
from bumble.profiles import rap


# -----------------------------------------------------------------------------
def _make_config(role: hci.CsRole, rtt_type: hci.RttType = hci.RttType.AA_ONLY):
    return device.ChannelSoundingConfig(
        config_id=0,
        main_mode_type=0,
        sub_mode_type=0,
        min_main_mode_steps=0,
        max_main_mode_steps=0,
        main_mode_repetition=0,
        mode_0_steps=0,
        role=role,
        rtt_type=rtt_type,
        cs_sync_phy=0,
        channel_map=b"",
        channel_map_repetition=0,
        channel_selection_type=0,
        ch3c_shape=0,
        ch3c_jump=0,
        reserved=0,
        t_ip1_time=0,
        t_ip2_time=0,
        t_fcs_time=0,
        t_pm_time=0,
    )


# -----------------------------------------------------------------------------
def test_parse_ranging_data_initiator_without_sounding_sequence() -> None:
    config = _make_config(role=hci.CsRole.INITIATOR)
    expected_ranging_data = rap.RangingData(
        ranging_header=rap.RangingHeader(
            configuration_id=0,
            selected_tx_power=-1,
            antenna_paths_mask=0x0F,
            ranging_counter=2,
        ),
        subevents=[
            rap.Subevent(
                start_acl_connection_event=0,
                frequency_compensation=1,
                ranging_done_status=2,
                ranging_abort_reason=3,
                subevent_abort_reason=4,
                subevent_done_status=5,
                reference_power_level=-2,
                steps=[
                    rap.Step(mode=0, data=bytes(5)),
                    rap.Step(mode=1, data=bytes(6)),
                    rap.Step(mode=2, data=bytes(21)),
                    rap.Step(mode=3, data=bytes(27)),
                ],
            )
        ],
    )

    assert (
        rap.RangingData.from_bytes(bytes(expected_ranging_data), config)
        == expected_ranging_data
    )


# -----------------------------------------------------------------------------
def test_parse_ranging_data_reflector_without_sounding_sequence() -> None:
    config = _make_config(role=hci.CsRole.REFLECTOR)
    expected_ranging_data = rap.RangingData(
        ranging_header=rap.RangingHeader(
            configuration_id=0,
            selected_tx_power=-1,
            antenna_paths_mask=0x0F,
            ranging_counter=2,
        ),
        subevents=[
            rap.Subevent(
                start_acl_connection_event=0,
                frequency_compensation=1,
                ranging_done_status=2,
                ranging_abort_reason=3,
                subevent_abort_reason=4,
                subevent_done_status=5,
                reference_power_level=-2,
                steps=[
                    rap.Step(mode=0, data=bytes(3)),
                    rap.Step(mode=1, data=bytes(6)),
                    rap.Step(mode=2, data=bytes(21)),
                    rap.Step(mode=3, data=bytes(27)),
                ],
            )
        ],
    )

    assert (
        rap.RangingData.from_bytes(bytes(expected_ranging_data), config)
        == expected_ranging_data
    )


# -----------------------------------------------------------------------------
def test_parse_ranging_data_initiator_with_sounding_sequence() -> None:
    config = _make_config(
        role=hci.CsRole.INITIATOR, rtt_type=hci.RttType.SOUNDING_SEQUENCE_32_BIT
    )
    expected_ranging_data = rap.RangingData(
        ranging_header=rap.RangingHeader(
            configuration_id=0,
            selected_tx_power=-1,
            antenna_paths_mask=0x0F,
            ranging_counter=2,
        ),
        subevents=[
            rap.Subevent(
                start_acl_connection_event=0,
                frequency_compensation=1,
                ranging_done_status=2,
                ranging_abort_reason=3,
                subevent_abort_reason=4,
                subevent_done_status=5,
                reference_power_level=-2,
                steps=[
                    rap.Step(mode=0, data=bytes(5)),
                    rap.Step(mode=1, data=bytes(12)),
                    rap.Step(mode=2, data=bytes(21)),
                    rap.Step(mode=3, data=bytes(33)),
                ],
            )
        ],
    )

    assert (
        rap.RangingData.from_bytes(bytes(expected_ranging_data), config)
        == expected_ranging_data
    )


# -----------------------------------------------------------------------------
def test_parse_ranging_data_reflector_with_sounding_sequence() -> None:
    config = _make_config(
        role=hci.CsRole.REFLECTOR,
        rtt_type=hci.RttType.SOUNDING_SEQUENCE_96_BIT,
    )
    expected_ranging_data = rap.RangingData(
        ranging_header=rap.RangingHeader(
            configuration_id=0,
            selected_tx_power=-1,
            antenna_paths_mask=0x0F,
            ranging_counter=2,
        ),
        subevents=[
            rap.Subevent(
                start_acl_connection_event=0,
                frequency_compensation=1,
                ranging_done_status=2,
                ranging_abort_reason=3,
                subevent_abort_reason=4,
                subevent_done_status=5,
                reference_power_level=-2,
                steps=[
                    rap.Step(mode=0, data=bytes(3)),
                    rap.Step(mode=1, data=bytes(12)),
                    rap.Step(mode=2, data=bytes(21)),
                    rap.Step(mode=3, data=bytes(33)),
                ],
            )
        ]
        * 2,
    )

    assert (
        rap.RangingData.from_bytes(bytes(expected_ranging_data), config)
        == expected_ranging_data
    )


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "operation",
    [
        rap.GetRangingDataOperation(ranging_counter=1),
        rap.AckRangingDataOperation(ranging_counter=1),
        rap.RetrieveLostRangingDataSegmentsOperation(
            ranging_counter=1,
            first_segment_index=2,
            last_segment_index=3,
        ),
        rap.AbortOperationOperation(),
        rap.SetFilterOperation(filter_configuration=0x01),
    ],
)
def test_parse_control_point_operation(operation: rap.RasControlPointOperation) -> None:
    assert rap.RasControlPointOperation.from_bytes(bytes(operation)) == operation


# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "response",
    [
        rap.CompleteRangingDataResponse(ranging_counter=1),
        rap.CompleteLostRangingDataResponse(
            ranging_counter=1,
            first_segment_index=2,
            last_segment_index=3,
        ),
        rap.CodeResponse(value=rap.RasControlPointResponseCode.SUCCESS),
    ],
)
def test_parse_control_point_operation_response(
    response: rap.ControlPointOperationResponse,
) -> None:
    assert rap.ControlPointOperationResponse.from_bytes(bytes(response)) == response
