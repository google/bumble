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
from __future__ import annotations

import struct
from collections.abc import Sequence

import pytest

from bumble import avc, avctp, avrcp

from . import test_utils


# -----------------------------------------------------------------------------
class TwoDevices(test_utils.TwoDevices):
    protocols: Sequence[avrcp.Protocol] = ()

    async def setup_avdtp_connections(self):
        self.protocols = [avrcp.Protocol(), avrcp.Protocol()]
        self.protocols[0].listen(self.devices[1])
        await self.protocols[1].connect(self.connections[0])

    @classmethod
    async def create_with_avdtp(cls) -> TwoDevices:
        devices = await cls.create_with_connection()
        await devices.setup_avdtp_connections()
        return devices


# -----------------------------------------------------------------------------
def test_GetPlayStatusCommand():
    command = avrcp.GetPlayStatusCommand()
    assert avrcp.Command.from_bytes(command.pdu_id, bytes(command)) == command


# -----------------------------------------------------------------------------
def test_GetCapabilitiesCommand():
    command = avrcp.GetCapabilitiesCommand(
        capability_id=avrcp.GetCapabilitiesCommand.CapabilityId.COMPANY_ID
    )
    assert avrcp.Command.from_bytes(command.pdu_id, bytes(command)) == command


# -----------------------------------------------------------------------------
def test_SetAbsoluteVolumeCommand():
    command = avrcp.SetAbsoluteVolumeCommand(volume=5)
    assert avrcp.Command.from_bytes(command.pdu_id, bytes(command)) == command


# -----------------------------------------------------------------------------
def test_GetElementAttributesCommand():
    command = avrcp.GetElementAttributesCommand(
        identifier=999,
        attribute_ids=[
            avrcp.MediaAttributeId.ALBUM_NAME,
            avrcp.MediaAttributeId.ARTIST_NAME,
        ],
    )
    assert avrcp.Command.from_bytes(command.pdu_id, bytes(command)) == command


# -----------------------------------------------------------------------------
def test_RegisterNotificationCommand():
    command = avrcp.RegisterNotificationCommand(
        event_id=avrcp.EventId.ADDRESSED_PLAYER_CHANGED, playback_interval=123
    )
    assert avrcp.Command.from_bytes(command.pdu_id, bytes(command)) == command


# -----------------------------------------------------------------------------
def test_UidsChangedEvent():
    event = avrcp.UidsChangedEvent(uid_counter=7)
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_TrackChangedEvent():
    event = avrcp.TrackChangedEvent(identifier=b'12356')
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_VolumeChangedEvent():
    event = avrcp.VolumeChangedEvent(volume=9)
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_PlaybackStatusChangedEvent():
    event = avrcp.PlaybackStatusChangedEvent(play_status=avrcp.PlayStatus.PLAYING)
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_AddressedPlayerChangedEvent():
    event = avrcp.AddressedPlayerChangedEvent(
        player=avrcp.AddressedPlayerChangedEvent.Player(player_id=9, uid_counter=10)
    )
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_AvailablePlayersChangedEvent():
    event = avrcp.AvailablePlayersChangedEvent()
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_PlaybackPositionChangedEvent():
    event = avrcp.PlaybackPositionChangedEvent(playback_position=1314)
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_NowPlayingContentChangedEvent():
    event = avrcp.NowPlayingContentChangedEvent()
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_PlayerApplicationSettingChangedEvent():
    event = avrcp.PlayerApplicationSettingChangedEvent(
        player_application_settings=[
            avrcp.PlayerApplicationSettingChangedEvent.Setting(
                avrcp.ApplicationSetting.AttributeId.REPEAT_MODE,
                avrcp.ApplicationSetting.RepeatModeStatus.ALL_TRACK_REPEAT,
            )
        ]
    )
    assert avrcp.Event.from_bytes(bytes(event)) == event


# -----------------------------------------------------------------------------
def test_RejectedResponse():
    pdu_id = avrcp.PduId.GET_ELEMENT_ATTRIBUTES
    response = avrcp.RejectedResponse(
        pdu_id=pdu_id,
        status_code=avrcp.StatusCode.DOES_NOT_EXIST,
    )
    assert (
        avrcp.RejectedResponse.from_bytes(pdu=bytes(response), pdu_id=pdu_id)
        == response
    )


# -----------------------------------------------------------------------------
def test_GetPlayStatusResponse():
    response = avrcp.GetPlayStatusResponse(
        song_length=1010, song_position=13, play_status=avrcp.PlayStatus.PAUSED
    )
    assert avrcp.GetPlayStatusResponse.from_bytes(bytes(response)) == response


# -----------------------------------------------------------------------------
def test_NotImplementedResponse():
    pdu_id = avrcp.PduId.GET_ELEMENT_ATTRIBUTES
    response = avrcp.NotImplementedResponse(pdu_id=pdu_id, parameters=b'koasd')
    assert (
        avrcp.NotImplementedResponse.from_bytes(bytes(response), pdu_id=pdu_id)
        == response
    )


# -----------------------------------------------------------------------------
def test_GetCapabilitiesResponse():
    response = avrcp.GetCapabilitiesResponse(
        capability_id=avrcp.GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED,
        capabilities=[
            avrcp.EventId.ADDRESSED_PLAYER_CHANGED,
            avrcp.EventId.BATT_STATUS_CHANGED,
        ],
    )
    assert avrcp.GetCapabilitiesResponse.from_bytes(bytes(response)) == response


# -----------------------------------------------------------------------------
def test_RegisterNotificationResponse():
    response = avrcp.RegisterNotificationResponse(
        event=avrcp.PlaybackPositionChangedEvent(playback_position=38)
    )
    assert avrcp.RegisterNotificationResponse.from_bytes(bytes(response)) == response


# -----------------------------------------------------------------------------
def test_SetAbsoluteVolumeResponse():
    response = avrcp.SetAbsoluteVolumeResponse(volume=99)
    assert avrcp.SetAbsoluteVolumeResponse.from_bytes(bytes(response)) == response


# -----------------------------------------------------------------------------
def test_GetElementAttributesResponse():
    response = avrcp.GetElementAttributesResponse(
        attributes=[
            avrcp.MediaAttribute(
                attribute_id=avrcp.MediaAttributeId.ALBUM_NAME,
                attribute_value="White Album",
            )
        ]
    )
    assert avrcp.GetElementAttributesResponse.from_bytes(bytes(response)) == response


# -----------------------------------------------------------------------------
def test_frame_parser():
    with pytest.raises(ValueError):
        avc.Frame.from_bytes(bytes.fromhex("11480000"))

    x = bytes.fromhex("014D0208")
    frame = avc.Frame.from_bytes(x)
    assert frame.subunit_type == avc.Frame.SubunitType.PANEL
    assert frame.subunit_id == 7
    assert frame.opcode == 8

    x = bytes.fromhex("014DFF0108")
    frame = avc.Frame.from_bytes(x)
    assert frame.subunit_type == avc.Frame.SubunitType.PANEL
    assert frame.subunit_id == 260
    assert frame.opcode == 8

    x = bytes.fromhex("0148000019581000000103")

    frame = avc.Frame.from_bytes(x)

    assert isinstance(frame, avc.CommandFrame)
    assert frame.ctype == avc.CommandFrame.CommandType.STATUS
    assert frame.subunit_type == avc.Frame.SubunitType.PANEL
    assert frame.subunit_id == 0
    assert frame.opcode == 0


# -----------------------------------------------------------------------------
def test_vendor_dependent_command():
    x = bytes.fromhex("0148000019581000000103")
    frame = avc.Frame.from_bytes(x)
    assert isinstance(frame, avc.VendorDependentCommandFrame)
    assert frame.company_id == 0x1958
    assert frame.vendor_dependent_data == bytes.fromhex("1000000103")

    frame = avc.VendorDependentCommandFrame(
        avc.CommandFrame.CommandType.STATUS,
        avc.Frame.SubunitType.PANEL,
        0,
        0x1958,
        bytes.fromhex("1000000103"),
    )
    assert bytes(frame) == x


# -----------------------------------------------------------------------------
def test_avctp_message_assembler():
    received_message = []

    def on_message(transaction_label, is_response, ipid, pid, payload):
        received_message.append((transaction_label, is_response, ipid, pid, payload))

    assembler = avctp.MessageAssembler(on_message)

    payload = bytes.fromhex("01")
    assembler.on_pdu(bytes([1 << 4 | 0b00 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload)
    assert received_message
    assert received_message[0] == (1, False, False, 0x1122, payload)

    received_message = []
    payload = bytes.fromhex("010203")
    assembler.on_pdu(bytes([1 << 4 | 0b01 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload)
    assert len(received_message) == 0
    assembler.on_pdu(bytes([1 << 4 | 0b00 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload)
    assert received_message
    assert received_message[0] == (1, False, False, 0x1122, payload)

    received_message = []
    payload = bytes.fromhex("010203")
    assembler.on_pdu(
        bytes([1 << 4 | 0b01 << 2 | 1 << 1 | 0, 3, 0x11, 0x22]) + payload[0:1]
    )
    assembler.on_pdu(
        bytes([1 << 4 | 0b10 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload[1:2]
    )
    assembler.on_pdu(
        bytes([1 << 4 | 0b11 << 2 | 1 << 1 | 0, 0x11, 0x22]) + payload[2:3]
    )
    assert received_message
    assert received_message[0] == (1, False, False, 0x1122, payload)

    # received_message = []
    # parameter = bytes.fromhex("010203")
    # assembler.on_pdu(struct.pack(">BBH", 0x10, 0b11, len(parameter)) + parameter)
    # assert len(received_message) == 0


# -----------------------------------------------------------------------------
def test_avrcp_pdu_assembler():
    received_pdus = []

    def on_pdu(pdu_id, parameter):
        received_pdus.append((pdu_id, parameter))

    assembler = avrcp.PduAssembler(on_pdu)

    parameter = bytes.fromhex("01")
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b00, len(parameter)) + parameter)
    assert received_pdus
    assert received_pdus[0] == (0x10, parameter)

    received_pdus = []
    parameter = bytes.fromhex("010203")
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b01, len(parameter)) + parameter)
    assert len(received_pdus) == 0
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b00, len(parameter)) + parameter)
    assert received_pdus
    assert received_pdus[0] == (0x10, parameter)

    received_pdus = []
    parameter = bytes.fromhex("010203")
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b01, 1) + parameter[0:1])
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b10, 1) + parameter[1:2])
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b11, 1) + parameter[2:3])
    assert received_pdus
    assert received_pdus[0] == (0x10, parameter)

    received_pdus = []
    parameter = bytes.fromhex("010203")
    assembler.on_pdu(struct.pack(">BBH", 0x10, 0b11, len(parameter)) + parameter)
    assert len(received_pdus) == 0


def test_passthrough_commands():
    play_pressed = avc.PassThroughCommandFrame(
        avc.CommandFrame.CommandType.CONTROL,
        avc.CommandFrame.SubunitType.PANEL,
        0,
        avc.PassThroughCommandFrame.StateFlag.PRESSED,
        avc.PassThroughCommandFrame.OperationId.PLAY,
        b'',
    )

    play_pressed_bytes = bytes(play_pressed)
    parsed = avc.Frame.from_bytes(play_pressed_bytes)
    assert isinstance(parsed, avc.PassThroughCommandFrame)
    assert parsed.operation_id == avc.PassThroughCommandFrame.OperationId.PLAY
    assert bytes(parsed) == play_pressed_bytes


# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_get_supported_events():
    two_devices = await TwoDevices.create_with_avdtp()

    supported_events = await two_devices.protocols[0].get_supported_events()
    assert supported_events == []

    delegate1 = avrcp.Delegate([avrcp.EventId.VOLUME_CHANGED])
    two_devices.protocols[0].delegate = delegate1
    supported_events = await two_devices.protocols[1].get_supported_events()
    assert supported_events == [avrcp.EventId.VOLUME_CHANGED]


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_frame_parser()
    test_vendor_dependent_command()
    test_avctp_message_assembler()
    test_avrcp_pdu_assembler()
    test_passthrough_commands()
    test_get_supported_events()
