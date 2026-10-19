# Copyright 2021-2022 Google LLC
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
import dataclasses
import logging
import os
from unittest import mock

import pytest
import pytest_asyncio

from bumble import core, hci, hfp, rfcomm
from bumble.host import Host
from bumble.testing.test_utils import TwoDevices

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def _default_hf_configuration() -> hfp.HfConfiguration:
    return hfp.HfConfiguration(
        supported_hf_features=[
            hfp.HfFeature.CODEC_NEGOTIATION,
            hfp.HfFeature.ESCO_S4_SETTINGS_SUPPORTED,
            hfp.HfFeature.HF_INDICATORS,
            hfp.HfFeature.ENHANCED_CALL_STATUS,
            hfp.HfFeature.THREE_WAY_CALLING,
            hfp.HfFeature.CLI_PRESENTATION_CAPABILITY,
        ],
        supported_hf_indicators=[
            hfp.HfIndicator.ENHANCED_SAFETY,
            hfp.HfIndicator.BATTERY_LEVEL,
        ],
        supported_audio_codecs=[
            hfp.AudioCodec.CVSD,
            hfp.AudioCodec.MSBC,
        ],
    )


# -----------------------------------------------------------------------------
def _default_hf_sdp_features() -> hfp.HfSdpFeature:
    return (
        hfp.HfSdpFeature.WIDE_BAND_SPEECH
        | hfp.HfSdpFeature.THREE_WAY_CALLING
        | hfp.HfSdpFeature.CLI_PRESENTATION_CAPABILITY
    )


# -----------------------------------------------------------------------------
def _default_ag_configuration() -> hfp.AgConfiguration:
    return hfp.AgConfiguration(
        supported_ag_features=[
            hfp.AgFeature.HF_INDICATORS,
            hfp.AgFeature.IN_BAND_RING_TONE_CAPABILITY,
            hfp.AgFeature.REJECT_CALL,
            hfp.AgFeature.CODEC_NEGOTIATION,
            hfp.AgFeature.ESCO_S4_SETTINGS_SUPPORTED,
            hfp.AgFeature.ENHANCED_CALL_STATUS,
            hfp.AgFeature.THREE_WAY_CALLING,
        ],
        supported_ag_indicators=[
            hfp.AgIndicatorState.call(),
            hfp.AgIndicatorState.service(),
            hfp.AgIndicatorState.callsetup(),
            hfp.AgIndicatorState.callsetup(),
            hfp.AgIndicatorState.signal(),
            hfp.AgIndicatorState.roam(),
            hfp.AgIndicatorState.battchg(),
        ],
        supported_hf_indicators=[
            hfp.HfIndicator.ENHANCED_SAFETY,
            hfp.HfIndicator.BATTERY_LEVEL,
        ],
        supported_ag_call_hold_operations=[
            hfp.CallHoldOperation.ADD_HELD_CALL,
            hfp.CallHoldOperation.HOLD_ALL_ACTIVE_CALLS,
            hfp.CallHoldOperation.HOLD_ALL_CALLS_EXCEPT,
            hfp.CallHoldOperation.RELEASE_ALL_ACTIVE_CALLS,
            hfp.CallHoldOperation.RELEASE_ALL_HELD_CALLS,
            hfp.CallHoldOperation.RELEASE_SPECIFIC_CALL,
            hfp.CallHoldOperation.CONNECT_TWO_CALLS,
        ],
        supported_audio_codecs=[hfp.AudioCodec.CVSD, hfp.AudioCodec.MSBC],
    )


# -----------------------------------------------------------------------------
def _default_ag_sdp_features() -> hfp.AgSdpFeature:
    return (
        hfp.AgSdpFeature.WIDE_BAND_SPEECH
        | hfp.AgSdpFeature.IN_BAND_RING_TONE_CAPABILITY
        | hfp.AgSdpFeature.THREE_WAY_CALLING
    )


# -----------------------------------------------------------------------------
async def make_hfp_connections(
    hf_config: hfp.HfConfiguration | None = None,
    ag_config: hfp.AgConfiguration | None = None,
):
    if not hf_config:
        hf_config = _default_hf_configuration()
    if not ag_config:
        ag_config = _default_ag_configuration()

    # Setup devices
    devices = TwoDevices()
    await devices.setup_connection()

    # Setup RFCOMM channel
    wait_dlc = asyncio.get_running_loop().create_future()
    rfcomm_channel = rfcomm.Server(devices.devices[0]).listen(wait_dlc.set_result)
    assert devices.connections[0]
    assert devices.connections[1]
    client_mux = await rfcomm.Client(devices.connections[1]).start()

    client_dlc = await client_mux.open_dlc(rfcomm_channel)
    server_dlc = await wait_dlc

    # Setup HFP connection
    hf = hfp.HfProtocol(client_dlc, hf_config)
    ag = hfp.AgProtocol(server_dlc, ag_config)

    await hf.initiate_slc()
    return (hf, ag)


# -----------------------------------------------------------------------------
@pytest_asyncio.fixture
async def hfp_connections():
    hf, ag = await make_hfp_connections()
    hf_loop_task = asyncio.create_task(hf.run())

    try:
        yield (hf, ag)
    finally:
        # Close the coroutine.
        hf.unsolicited_queue.put_nowait(None)
        await hf_loop_task


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_slc_with_minimal_features():
    hf, ag = await make_hfp_connections(
        hfp.HfConfiguration(
            supported_audio_codecs=[],
            supported_hf_features=[],
            supported_hf_indicators=[],
        ),
        hfp.AgConfiguration(
            supported_ag_call_hold_operations=[],
            supported_ag_features=[],
            supported_ag_indicators=[
                hfp.AgIndicatorState(
                    indicator=hfp.AgIndicator.CALL,
                    supported_values={0, 1},
                    current_status=0,
                )
            ],
            supported_hf_indicators=[],
            supported_audio_codecs=[],
        ),
    )

    assert hf.supported_ag_features == ag.supported_ag_features
    assert hf.supported_hf_features == ag.supported_hf_features
    assert hf.supported_ag_call_hold_operations == ag.supported_ag_call_hold_operations
    for a, b in zip(hf.ag_indicators, ag.ag_indicators):
        assert a.indicator == b.indicator
        assert a.current_status == b.current_status


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_slc(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections

    assert hf.supported_ag_features == ag.supported_ag_features
    assert hf.supported_hf_features == ag.supported_hf_features
    assert hf.supported_ag_call_hold_operations == ag.supported_ag_call_hold_operations
    for a, b in zip(hf.ag_indicators, ag.ag_indicators):
        assert a.indicator == b.indicator
        assert a.current_status == b.current_status


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ag_indicator(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections

    future = asyncio.get_running_loop().create_future()
    hf.on('ag_indicator', future.set_result)

    ag.update_ag_indicator(hfp.AgIndicator.CALL, 1)

    indicator: hfp.AgIndicatorState = await future
    assert indicator.current_status == 1
    assert indicator.indicator == hfp.AgIndicator.CALL


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_hf_indicator(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections

    future = asyncio.get_running_loop().create_future()
    ag.on('hf_indicator', future.set_result)

    await hf.execute_command('AT+BIEV=2,100')

    indicator: hfp.HfIndicatorState = await future
    assert indicator.current_status == 100


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_codec_negotiation(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections

    futures = [
        asyncio.get_running_loop().create_future(),
        asyncio.get_running_loop().create_future(),
    ]
    hf.on('codec_negotiation', futures[0].set_result)
    ag.on('codec_negotiation', futures[1].set_result)
    await ag.negotiate_codec(hfp.AudioCodec.MSBC)

    assert await futures[0] == await futures[1]


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_dial(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections
    NUMBER = 'ATD123456789'

    future = asyncio.get_running_loop().create_future()
    ag.on('dial', future.set_result)
    await hf.execute_command(f'ATD{NUMBER}')

    number: str = await future
    assert number == NUMBER


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_answer(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections

    future = asyncio.get_running_loop().create_future()
    ag.on('answer', lambda: future.set_result(None))
    await hf.answer_incoming_call()

    await future


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reject_incoming_call(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections

    future = asyncio.get_running_loop().create_future()
    ag.on('hang_up', lambda: future.set_result(None))
    await hf.reject_incoming_call()

    await future


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_terminate_call(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections

    future = asyncio.get_running_loop().create_future()
    ag.on('hang_up', lambda: future.set_result(None))
    await hf.terminate_call()

    await future


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_query_calls_without_calls(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections

    assert await hf.query_current_calls() == []


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_query_calls_with_calls(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections
    ag.calls.append(
        hfp.CallInfo(
            index=1,
            direction=hfp.CallInfoDirection.MOBILE_ORIGINATED_CALL,
            status=hfp.CallInfoStatus.ACTIVE,
            mode=hfp.CallInfoMode.VOICE,
            multi_party=hfp.CallInfoMultiParty.NOT_IN_CONFERENCE,
            number='123456789',
        )
    )

    assert await hf.query_current_calls() == ag.calls


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    (
        hfp.CallHoldOperation.RELEASE_ALL_HELD_CALLS,
        hfp.CallHoldOperation.RELEASE_ALL_ACTIVE_CALLS,
        hfp.CallHoldOperation.HOLD_ALL_ACTIVE_CALLS,
        hfp.CallHoldOperation.ADD_HELD_CALL,
        hfp.CallHoldOperation.CONNECT_TWO_CALLS,
    ),
)
async def test_hold_call_without_call_index(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
    operation: hfp.CallHoldOperation,
):
    hf, ag = hfp_connections
    call_hold_future = asyncio.get_running_loop().create_future()
    ag.on("call_hold", lambda op, index: call_hold_future.set_result((op, index)))

    await hf.execute_command(f"AT+CHLD={operation.value}")

    assert (await call_hold_future) == (operation, None)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation",
    (
        hfp.CallHoldOperation.RELEASE_SPECIFIC_CALL,
        hfp.CallHoldOperation.HOLD_ALL_CALLS_EXCEPT,
    ),
)
async def test_hold_call_with_call_index(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
    operation: hfp.CallHoldOperation,
):
    hf, ag = hfp_connections
    call_hold_future = asyncio.get_running_loop().create_future()
    ag.on("call_hold", lambda op, index: call_hold_future.set_result((op, index)))
    ag.calls.append(
        hfp.CallInfo(
            index=1,
            direction=hfp.CallInfoDirection.MOBILE_ORIGINATED_CALL,
            status=hfp.CallInfoStatus.ACTIVE,
            mode=hfp.CallInfoMode.VOICE,
            multi_party=hfp.CallInfoMultiParty.NOT_IN_CONFERENCE,
            number='123456789',
        )
    )

    await hf.execute_command(f"AT+CHLD={operation.value.replace('x', '1')}")

    assert (await call_hold_future) == (operation, 1)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ring(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections
    ring_future = asyncio.get_running_loop().create_future()
    hf.on("ring", lambda: ring_future.set_result(None))

    ag.send_ring()

    await ring_future


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_speaker_volume(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections
    speaker_volume_future = asyncio.get_running_loop().create_future()
    hf.on("speaker_volume", speaker_volume_future.set_result)

    ag.set_speaker_volume(10)

    assert await speaker_volume_future == 10


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_microphone_volume(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections
    microphone_volume_future = asyncio.get_running_loop().create_future()
    hf.on("microphone_volume", microphone_volume_future.set_result)

    ag.set_microphone_volume(10)

    assert await microphone_volume_future == 10


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cli_notification(hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol]):
    hf, ag = hfp_connections
    cli_notification_future = asyncio.get_running_loop().create_future()
    hf.on("cli_notification", cli_notification_future.set_result)

    ag.send_cli_notification(
        hfp.CallLineIdentification(number="\"123456789\"", type=129, alpha="\"Bumble\"")
    )

    assert await cli_notification_future == hfp.CallLineIdentification(
        number="123456789", type=129, alpha="Bumble", subaddr="", satype=None
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_voice_recognition_from_hf(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections
    voice_recognition_future = asyncio.get_running_loop().create_future()
    ag.on("voice_recognition", voice_recognition_future.set_result)

    await hf.execute_command("AT+BVRA=1")

    assert await voice_recognition_future == hfp.VoiceRecognitionState.ENABLE


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_voice_recognition_from_ag(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections
    voice_recognition_future = asyncio.get_running_loop().create_future()
    hf.on("voice_recognition", voice_recognition_future.set_result)

    ag.send_response("+BVRA: 1")

    assert await voice_recognition_future == hfp.VoiceRecognitionState.ENABLE


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_hf_sdp_record():
    devices = TwoDevices()
    await devices.setup_connection()

    devices[0].sdp_service_records[1] = hfp.make_hf_sdp_records(
        1, 2, _default_hf_configuration(), hfp.ProfileVersion.V1_8
    )

    assert await hfp.find_hf_sdp_record(devices.connections[1]) == (
        2,
        hfp.ProfileVersion.V1_8,
        _default_hf_sdp_features(),
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ag_sdp_record():
    devices = TwoDevices()
    await devices.setup_connection()

    devices[0].sdp_service_records[1] = hfp.make_ag_sdp_records(
        1, 2, _default_ag_configuration(), hfp.ProfileVersion.V1_8
    )

    assert await hfp.find_ag_sdp_record(devices.connections[1]) == (
        2,
        hfp.ProfileVersion.V1_8,
        _default_ag_sdp_features(),
    )


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        'codec_parameters',
        'enhanced_commands',
        'expected_link_type',
        'expected_air_mode',
    ),
    [
        # eSCO link with the enhanced commands
        (
            hfp.DefaultCodecParameters.ESCO_CVSD_S1,
            True,
            hci.HCI_Connection_Complete_Event.LinkType.ESCO,
            hci.CodecID.CVSD,
        ),
        # Transparent (mSBC) eSCO link with the enhanced commands
        (
            hfp.DefaultCodecParameters.ESCO_MSBC_T2,
            True,
            hci.HCI_Connection_Complete_Event.LinkType.ESCO,
            hci.CodecID.TRANSPARENT,
        ),
        # eSCO link with the non-enhanced commands
        (
            hfp.DefaultCodecParameters.ESCO_CVSD_S1,
            False,
            hci.HCI_Connection_Complete_Event.LinkType.ESCO,
            hci.CodecID.CVSD,
        ),
        # SCO link with the non-enhanced commands
        (
            hfp.DefaultCodecParameters.SCO_CVSD_D1,
            False,
            hci.HCI_Connection_Complete_Event.LinkType.SCO,
            hci.CodecID.CVSD,
        ),
    ],
)
async def test_sco_setup(
    codec_parameters: hfp.DefaultCodecParameters,
    enhanced_commands: bool,
    expected_link_type: int,
    expected_air_mode: int,
):
    devices = TwoDevices()

    # Enable Classic connections
    devices[0].classic_enabled = True
    devices[1].classic_enabled = True

    # Start
    await devices[0].power_on()
    await devices[1].power_on()

    connections = await asyncio.gather(
        devices[0].connect(
            devices[1].public_address, transport=core.PhysicalTransport.BR_EDR
        ),
        devices[1].accept(devices[0].public_address),
    )

    parameters = hfp.ESCO_PARAMETERS[codec_parameters]

    def on_sco_request(_connection, _link_type: int):
        connections[1].abort_on(
            'disconnection',
            devices[1].send_command(
                hfp.accept_synchronous_connection_request_command(
                    devices[1].host, connections[1].peer_address, parameters
                )
            ),
        )

    devices[1].on('sco_request', on_sco_request)

    sco_connection_futures = [
        asyncio.get_running_loop().create_future(),
        asyncio.get_running_loop().create_future(),
    ]

    for index, future in enumerate(sco_connection_futures):
        devices[index].on('sco_connection', future.set_result)

    # Pretend the controllers only implement either the enhanced or the non-enhanced
    # commands, so that both ways of setting up a link are covered.
    with mock.patch.object(
        Host,
        'supports_command',
        lambda _self, op_code: enhanced_commands
        and op_code
        in (
            hci.HCI_ENHANCED_SETUP_SYNCHRONOUS_CONNECTION_COMMAND,
            hci.HCI_ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST_COMMAND,
        ),
    ):
        await devices[0].send_command(
            hfp.setup_synchronous_connection_command(
                devices[0].host, connections[0].handle, parameters
            )
        )
        sco_connections = await asyncio.gather(*sco_connection_futures)

    for sco_connection in sco_connections:
        assert sco_connection.link_type == expected_link_type
        assert sco_connection.air_mode == expected_air_mode

    sco_disconnection_futures = [
        asyncio.get_running_loop().create_future(),
        asyncio.get_running_loop().create_future(),
    ]
    for future, sco_connection in zip(sco_disconnection_futures, sco_connections):
        sco_connection.on('disconnection', future.set_result)

    await sco_connections[0].disconnect()
    await asyncio.gather(*sco_disconnection_futures)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sco_setup_rejected():
    devices = TwoDevices()

    # Enable Classic connections
    devices[0].classic_enabled = True
    devices[1].classic_enabled = True

    # Start
    await devices[0].power_on()
    await devices[1].power_on()

    connections = await asyncio.gather(
        devices[0].connect(
            devices[1].public_address, transport=core.PhysicalTransport.BR_EDR
        ),
        devices[1].accept(devices[0].public_address),
    )

    def on_sco_request(_connection, _link_type: int):
        connections[1].abort_on(
            'disconnection',
            devices[1].send_command(
                hci.HCI_Reject_Synchronous_Connection_Request_Command(
                    bd_addr=connections[1].peer_address,
                    reason=hci.HCI_ErrorCode.CONNECTION_REJECTED_DUE_TO_LIMITED_RESOURCES_ERROR,
                )
            ),
        )

    devices[1].on('sco_request', on_sco_request)

    failure_future = asyncio.get_running_loop().create_future()
    devices[0].on('sco_connection_failure', failure_future.set_result)

    # The non-enhanced Reject Synchronous Connection Request command
    with mock.patch.object(Host, 'supports_command', return_value=False):
        await devices[0].send_command(
            hfp.setup_synchronous_connection_command(
                devices[0].host,
                connections[0].handle,
                hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.ESCO_CVSD_S1],
            )
        )
        assert (
            await asyncio.wait_for(failure_future, timeout=5)
            == hci.HCI_ErrorCode.CONNECTION_REJECTED_DUE_TO_LIMITED_RESOURCES_ERROR
        )


# -----------------------------------------------------------------------------
def test_esco_parameters_as_legacy_dict():
    # CVSD: the air coding format is CVSD, the PCM data is 16-bit two's complement
    # (which is also the default voice setting of most controllers).
    parameters = hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.ESCO_CVSD_S1]
    legacy = parameters.as_legacy_dict()
    assert legacy['voice_setting'] == 0x0060
    assert legacy['transmit_bandwidth'] == parameters.transmit_bandwidth
    assert legacy['receive_bandwidth'] == parameters.receive_bandwidth
    assert legacy['max_latency'] == parameters.max_latency
    assert legacy['retransmission_effort'] == parameters.retransmission_effort
    assert legacy['packet_type'] == parameters.packet_type

    # mSBC is coded by the host: it goes over the air as transparent data
    parameters = hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.ESCO_MSBC_T2]
    assert parameters.as_legacy_dict()['voice_setting'] == 0x0063

    # 8-bit PCM samples, sign and magnitude
    parameters = dataclasses.replace(
        hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.ESCO_CVSD_S1],
        input_coded_data_size=8,
        input_pcm_data_format=hci.PcmDataFormat.SIGN_MAGNITUDE,
    )
    assert parameters.as_legacy_dict()['voice_setting'] == 0x0080


# -----------------------------------------------------------------------------
def test_synchronous_connection_commands():
    parameters = hfp.ESCO_PARAMETERS[hfp.DefaultCodecParameters.ESCO_CVSD_S1]
    address = hci.Address('F0:F1:F2:F3:F4:F5')
    host = mock.Mock()

    host.supports_command.return_value = True
    assert isinstance(
        hfp.setup_synchronous_connection_command(host, 0x0040, parameters),
        hci.HCI_Enhanced_Setup_Synchronous_Connection_Command,
    )
    assert isinstance(
        hfp.accept_synchronous_connection_request_command(host, address, parameters),
        hci.HCI_Enhanced_Accept_Synchronous_Connection_Request_Command,
    )

    host.supports_command.return_value = False
    legacy_setup = hfp.setup_synchronous_connection_command(host, 0x0040, parameters)
    assert isinstance(legacy_setup, hci.HCI_Setup_Synchronous_Connection_Command)
    assert legacy_setup.connection_handle == 0x0040
    assert legacy_setup.voice_setting == 0x0060
    legacy_accept = hfp.accept_synchronous_connection_request_command(
        host, address, parameters
    )
    assert isinstance(
        legacy_accept, hci.HCI_Accept_Synchronous_Connection_Request_Command
    )
    assert legacy_accept.bd_addr == address
    assert legacy_accept.voice_setting == 0x0060


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_hf_batched_response(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections

    ag.dlc.write(b'\r\n+BIND: (1,2)\r\n\r\nOK\r\n')

    await hf.execute_command("AT+BIND=?", response_type=hfp.AtResponseType.SINGLE)


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ag_batched_commands(
    hfp_connections: tuple[hfp.HfProtocol, hfp.AgProtocol],
):
    hf, ag = hfp_connections

    answer_future = asyncio.get_running_loop().create_future()
    ag.on('answer', lambda: answer_future.set_result(None))

    hang_up_future = asyncio.get_running_loop().create_future()
    ag.on('hang_up', lambda: hang_up_future.set_result(None))

    hf.dlc.write(b'ATA\rAT+CHUP\r')

    await answer_future
    await hang_up_future


# -----------------------------------------------------------------------------
async def run():
    await test_slc()


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
    asyncio.run(run())
