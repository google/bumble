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


@pytest.mark.parametrize(
    "command,",
    [
        avrcp.GetPlayStatusCommand(),
        avrcp.GetCapabilitiesCommand(
            capability_id=avrcp.GetCapabilitiesCommand.CapabilityId.COMPANY_ID
        ),
        avrcp.SetAbsoluteVolumeCommand(volume=5),
        avrcp.GetElementAttributesCommand(
            identifier=999,
            attribute_ids=[
                avrcp.MediaAttributeId.ALBUM_NAME,
                avrcp.MediaAttributeId.ARTIST_NAME,
            ],
        ),
        avrcp.RegisterNotificationCommand(
            event_id=avrcp.EventId.ADDRESSED_PLAYER_CHANGED, playback_interval=123
        ),
        avrcp.SearchCommand(
            character_set_id=avrcp.CharacterSetId.UTF_8, search_string="Bumble!"
        ),
        avrcp.PlayItemCommand(
            scope=avrcp.Scope.MEDIA_PLAYER_LIST, uid=0, uid_counter=1
        ),
        avrcp.ListPlayerApplicationSettingAttributesCommand(),
        avrcp.ListPlayerApplicationSettingValuesCommand(
            attribute=avrcp.ApplicationSetting.AttributeId.REPEAT_MODE
        ),
        avrcp.GetCurrentPlayerApplicationSettingValueCommand(
            attribute=[
                avrcp.ApplicationSetting.AttributeId.REPEAT_MODE,
                avrcp.ApplicationSetting.AttributeId.SHUFFLE_ON_OFF,
            ]
        ),
        avrcp.SetPlayerApplicationSettingValueCommand(
            attribute=[avrcp.ApplicationSetting.AttributeId.REPEAT_MODE],
            value=[avrcp.ApplicationSetting.RepeatModeStatus.ALL_TRACK_REPEAT],
        ),
        avrcp.GetPlayerApplicationSettingAttributeTextCommand(
            attribute=[
                avrcp.ApplicationSetting.AttributeId.REPEAT_MODE,
                avrcp.ApplicationSetting.AttributeId.SHUFFLE_ON_OFF,
            ]
        ),
        avrcp.GetPlayerApplicationSettingValueTextCommand(
            attribute=avrcp.ApplicationSetting.AttributeId.REPEAT_MODE,
            value=[
                avrcp.ApplicationSetting.RepeatModeStatus.ALL_TRACK_REPEAT,
                avrcp.ApplicationSetting.RepeatModeStatus.GROUP_REPEAT,
            ],
        ),
        avrcp.InformDisplayableCharacterSetCommand(
            character_set_id=[avrcp.CharacterSetId.UTF_8]
        ),
        avrcp.InformBatteryStatusOfCtCommand(
            battery_status=avrcp.InformBatteryStatusOfCtCommand.BatteryStatus.NORMAL
        ),
        avrcp.SetAddressedPlayerCommand(player_id=1),
        avrcp.SetBrowsedPlayerCommand(player_id=1),
        avrcp.GetFolderItemsCommand(
            scope=avrcp.Scope.NOW_PLAYING,
            start_item=0,
            end_item=1,
            attributes=[avrcp.MediaAttributeId.ARTIST_NAME],
        ),
        avrcp.ChangePathCommand(
            uid_counter=1,
            direction=avrcp.ChangePathCommand.Direction.DOWN,
            folder_uid=2,
        ),
        avrcp.GetItemAttributesCommand(
            scope=avrcp.Scope.NOW_PLAYING,
            uid=0,
            uid_counter=1,
            start_item=0,
            end_item=0,
            attributes=[avrcp.MediaAttributeId.DEFAULT_COVER_ART],
        ),
        avrcp.GetTotalNumberOfItemsCommand(scope=avrcp.Scope.NOW_PLAYING),
        avrcp.AddToNowPlayingCommand(
            scope=avrcp.Scope.NOW_PLAYING, uid=0, uid_counter=1
        ),
    ],
)
def test_command(command: avrcp.Command):
    assert avrcp.Command.from_bytes(command.pdu_id, bytes(command)) == command


@pytest.mark.parametrize(
    "event,",
    [
        avrcp.UidsChangedEvent(uid_counter=7),
        avrcp.TrackChangedEvent(identifier=b'12356'),
        avrcp.VolumeChangedEvent(volume=9),
        avrcp.PlaybackStatusChangedEvent(play_status=avrcp.PlayStatus.PLAYING),
        avrcp.AddressedPlayerChangedEvent(
            player=avrcp.AddressedPlayerChangedEvent.Player(player_id=9, uid_counter=10)
        ),
        avrcp.AvailablePlayersChangedEvent(),
        avrcp.PlaybackPositionChangedEvent(playback_position=1314),
        avrcp.NowPlayingContentChangedEvent(),
        avrcp.PlayerApplicationSettingChangedEvent(
            player_application_settings=[
                avrcp.PlayerApplicationSettingChangedEvent.Setting(
                    avrcp.ApplicationSetting.AttributeId.REPEAT_MODE,
                    avrcp.ApplicationSetting.RepeatModeStatus.ALL_TRACK_REPEAT,
                )
            ]
        ),
    ],
)
def test_event(event: avrcp.Event):
    assert avrcp.Event.from_bytes(bytes(event)) == event


@pytest.mark.parametrize(
    "response,",
    [
        avrcp.GetPlayStatusResponse(
            song_length=1010, song_position=13, play_status=avrcp.PlayStatus.PAUSED
        ),
        avrcp.GetCapabilitiesResponse(
            capability_id=avrcp.GetCapabilitiesCommand.CapabilityId.EVENTS_SUPPORTED,
            capabilities=[
                avrcp.EventId.ADDRESSED_PLAYER_CHANGED,
                avrcp.EventId.BATT_STATUS_CHANGED,
            ],
        ),
        avrcp.RegisterNotificationResponse(
            event=avrcp.PlaybackPositionChangedEvent(playback_position=38)
        ),
        avrcp.SetAbsoluteVolumeResponse(volume=99),
        avrcp.GetElementAttributesResponse(
            attributes=[
                avrcp.MediaAttribute(
                    attribute_id=avrcp.MediaAttributeId.ALBUM_NAME,
                    attribute_value="White Album",
                    character_set_id=avrcp.CharacterSetId.UTF_8,
                )
            ]
        ),
        avrcp.ListPlayerApplicationSettingAttributesResponse(
            attribute=[
                avrcp.ApplicationSetting.AttributeId.REPEAT_MODE,
                avrcp.ApplicationSetting.AttributeId.SHUFFLE_ON_OFF,
            ]
        ),
        avrcp.ListPlayerApplicationSettingValuesResponse(
            value=[
                avrcp.ApplicationSetting.RepeatModeStatus.ALL_TRACK_REPEAT,
                avrcp.ApplicationSetting.RepeatModeStatus.GROUP_REPEAT,
            ]
        ),
        avrcp.GetCurrentPlayerApplicationSettingValueResponse(
            attribute=[avrcp.ApplicationSetting.AttributeId.REPEAT_MODE],
            value=[avrcp.ApplicationSetting.RepeatModeStatus.ALL_TRACK_REPEAT],
        ),
        avrcp.SetPlayerApplicationSettingValueResponse(),
        avrcp.GetPlayerApplicationSettingAttributeTextResponse(
            attribute=[avrcp.ApplicationSetting.AttributeId.REPEAT_MODE],
            character_set_id=[avrcp.CharacterSetId.UTF_8],
            attribute_string=["Repeat"],
        ),
        avrcp.GetPlayerApplicationSettingValueTextResponse(
            value=[avrcp.ApplicationSetting.RepeatModeStatus.ALL_TRACK_REPEAT],
            character_set_id=[avrcp.CharacterSetId.UTF_8],
            attribute_string=["All track repeat"],
        ),
        avrcp.InformDisplayableCharacterSetResponse(),
        avrcp.InformBatteryStatusOfCtResponse(),
        avrcp.SetAddressedPlayerResponse(status=avrcp.StatusCode.OPERATION_COMPLETED),
        avrcp.SetBrowsedPlayerResponse(
            status=avrcp.StatusCode.OPERATION_COMPLETED,
            uid_counter=1,
            numbers_of_items=2,
            character_set_id=avrcp.CharacterSetId.UTF_8,
            folder_names=["folder1", "folder2"],
        ),
        avrcp.GetFolderItemsResponse(
            status=avrcp.StatusCode.OPERATION_COMPLETED,
            uid_counter=1,
            items=[
                avrcp.MediaPlayerItem(
                    player_id=1,
                    major_player_type=avrcp.MediaPlayerItem.MajorPlayerType.AUDIO,
                    player_sub_type=avrcp.MediaPlayerItem.PlayerSubType.AUDIO_BOOK,
                    play_status=avrcp.PlayStatus.FWD_SEEK,
                    feature_bitmask=avrcp.MediaPlayerItem.Features.ADD_TO_NOW_PLAYING,
                    character_set_id=avrcp.CharacterSetId.UTF_8,
                    displayable_name="Woo",
                )
            ],
        ),
        avrcp.ChangePathResponse(
            status=avrcp.StatusCode.OPERATION_COMPLETED, number_of_items=2
        ),
        avrcp.GetItemAttributesResponse(
            status=avrcp.StatusCode.OPERATION_COMPLETED,
            attribute_value_entry_list=[
                avrcp.AttributeValueEntry(
                    attribute_id=avrcp.MediaAttributeId.GENRE,
                    character_set_id=avrcp.CharacterSetId.UTF_8,
                    attribute_value="uuddlrlrabab",
                )
            ],
        ),
        avrcp.GetTotalNumberOfItemsResponse(
            status=avrcp.StatusCode.OPERATION_COMPLETED,
            uid_counter=1,
            number_of_items=2,
        ),
        avrcp.SearchResponse(
            status=avrcp.StatusCode.OPERATION_COMPLETED,
            uid_counter=1,
            number_of_items=2,
        ),
        avrcp.PlayItemResponse(status=avrcp.StatusCode.OPERATION_COMPLETED),
        avrcp.AddToNowPlayingResponse(status=avrcp.StatusCode.OPERATION_COMPLETED),
    ],
)
def test_response(response: avrcp.Response):
    assert avrcp.Response.from_bytes(bytes(response), response.pdu_id) == response


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
