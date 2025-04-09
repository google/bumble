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
from __future__ import annotations
import asyncio
import asyncio.subprocess
import os
import logging
from typing import Optional, Union

import click

from bumble.a2dp import (
    make_audio_source_service_sdp_records,
    A2DP_SBC_CODEC_TYPE,
    A2DP_MPEG_2_4_AAC_CODEC_TYPE,
    A2DP_NON_A2DP_CODEC_TYPE,
    AacFrame,
    AacParser,
    AacPacketSource,
    AacMediaCodecInformation,
    SbcFrame,
    SbcParser,
    SbcPacketSource,
    SbcMediaCodecInformation,
    OpusPacket,
    OpusParser,
    OpusPacketSource,
    OpusMediaCodecInformation,
)
from bumble.avrcp import Protocol as AvrcpProtocol
from bumble.avdtp import (
    find_avdtp_service_with_connection,
    AVDTP_AUDIO_MEDIA_TYPE,
    AVDTP_DELAY_REPORTING_SERVICE_CATEGORY,
    MediaCodecCapabilities,
    MediaPacketPump,
    Protocol as AvdtpProtocol,
)
from bumble.colors import color
from bumble.core import (
    AdvertisingData,
    ConnectionError as BumbleConnectionError,
    DeviceClass,
    PhysicalTransport,
)
from bumble.device import Connection, Device, DeviceConfiguration
from bumble.hci import Address, HCI_CONNECTION_ALREADY_EXISTS_ERROR, HCI_Constant
from bumble.pairing import PairingConfig
from bumble.transport import open_transport
from bumble.utils import AsyncRunner


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
def a2dp_source_sdp_records():
    service_record_handle = 0x00010001
    return {
        service_record_handle: make_audio_source_service_sdp_records(
            service_record_handle
        )
    }


# -----------------------------------------------------------------------------
async def sbc_codec_capabilities(read_function) -> MediaCodecCapabilities:
    sbc_parser = SbcParser(read_function)
    sbc_frame: SbcFrame
    async for sbc_frame in sbc_parser.frames:
        # We only need the first frame
        print(color(f"SBC format: {sbc_frame}", "cyan"))
        break

    channel_mode = [
        SbcMediaCodecInformation.ChannelMode.MONO,
        SbcMediaCodecInformation.ChannelMode.DUAL_CHANNEL,
        SbcMediaCodecInformation.ChannelMode.STEREO,
        SbcMediaCodecInformation.ChannelMode.JOINT_STEREO,
    ][sbc_frame.channel_mode]
    block_length = {
        4: SbcMediaCodecInformation.BlockLength.BL_4,
        8: SbcMediaCodecInformation.BlockLength.BL_8,
        12: SbcMediaCodecInformation.BlockLength.BL_12,
        16: SbcMediaCodecInformation.BlockLength.BL_16,
    }[sbc_frame.block_count]
    subbands = {
        4: SbcMediaCodecInformation.Subbands.S_4,
        8: SbcMediaCodecInformation.Subbands.S_8,
    }[sbc_frame.subband_count]
    allocation_method = [
        SbcMediaCodecInformation.AllocationMethod.LOUDNESS,
        SbcMediaCodecInformation.AllocationMethod.SNR,
    ][sbc_frame.allocation_method]
    return MediaCodecCapabilities(
        media_type=AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=A2DP_SBC_CODEC_TYPE,
        media_codec_information=SbcMediaCodecInformation(
            sampling_frequency=SbcMediaCodecInformation.SamplingFrequency.from_int(
                sbc_frame.sampling_frequency
            ),
            channel_mode=channel_mode,
            block_length=block_length,
            subbands=subbands,
            allocation_method=allocation_method,
            minimum_bitpool_value=2,
            maximum_bitpool_value=40,
        ),
    )


# -----------------------------------------------------------------------------
async def aac_codec_capabilities(read_function) -> MediaCodecCapabilities:
    aac_parser = AacParser(read_function)
    aac_frame: AacFrame
    async for aac_frame in aac_parser.frames:
        # We only need the first frame
        print(color(f"AAC format: {aac_frame}", "cyan"))
        break

    sampling_frequency = AacMediaCodecInformation.SamplingFrequency.from_int(
        aac_frame.sampling_frequency
    )
    channels = (
        AacMediaCodecInformation.Channels.MONO
        if aac_frame.channel_configuration == 1
        else AacMediaCodecInformation.Channels.STEREO
    )

    return MediaCodecCapabilities(
        media_type=AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=A2DP_MPEG_2_4_AAC_CODEC_TYPE,
        media_codec_information=AacMediaCodecInformation(
            object_type=AacMediaCodecInformation.ObjectType.MPEG_2_AAC_LC,
            sampling_frequency=sampling_frequency,
            channels=channels,
            vbr=1,
            bitrate=128000,
        ),
    )


# -----------------------------------------------------------------------------
async def opus_codec_capabilities(read_function) -> MediaCodecCapabilities:
    opus_parser = OpusParser(read_function)
    opus_packet: OpusPacket
    async for opus_packet in opus_parser.packets:
        # We only need the first packet
        print(color(f"Opus format: {opus_packet}", "cyan"))
        break

    if opus_packet.channel_mode == OpusPacket.ChannelMode.MONO:
        channel_mode = OpusMediaCodecInformation.ChannelMode.MONO
    elif opus_packet.channel_mode == OpusPacket.ChannelMode.STEREO:
        channel_mode = OpusMediaCodecInformation.ChannelMode.STEREO
    else:
        channel_mode = OpusMediaCodecInformation.ChannelMode.DUAL_MONO

    if opus_packet.duration == 10:
        frame_size = OpusMediaCodecInformation.FrameSize.FS_10MS
    else:
        frame_size = OpusMediaCodecInformation.FrameSize.FS_20MS

    return MediaCodecCapabilities(
        media_type=AVDTP_AUDIO_MEDIA_TYPE,
        media_codec_type=A2DP_NON_A2DP_CODEC_TYPE,
        media_codec_information=OpusMediaCodecInformation(
            channel_mode=channel_mode,
            sampling_frequency=OpusMediaCodecInformation.SamplingFrequency.SF_48000,
            frame_size=frame_size,
        ),
    )


# -----------------------------------------------------------------------------
class Player:
    def __init__(
        self,
        transport: str,
        device_config: Optional[str],
        authenticate: bool,
        encrypt: bool,
    ) -> None:
        self.transport = transport
        self.device_config = device_config
        self.authenticate = authenticate
        self.encrypt = encrypt
        self.avrcp_protocol: Optional[AvrcpProtocol] = None
        self.done: Optional[asyncio.Event]

    async def run(self, workload) -> None:
        self.done = asyncio.Event()
        try:
            await self._run(workload)
        except Exception as error:
            print(color(f"!!! ERROR: {error}", "red"))

    async def _run(self, workload) -> None:
        async with await open_transport(self.transport) as (hci_source, hci_sink):
            # Create a device
            device_config = DeviceConfiguration()
            if self.device_config:
                device_config.load_from_file(self.device_config)
            else:
                device_config.name = "Bumble Player"
                device_config.class_of_device = DeviceClass.pack_class_of_device(
                    DeviceClass.AUDIO_SERVICE_CLASS,
                    DeviceClass.AUDIO_VIDEO_MAJOR_DEVICE_CLASS,
                    DeviceClass.AUDIO_VIDEO_UNCATEGORIZED_MINOR_DEVICE_CLASS,
                )
                device_config.keystore = "JsonKeyStore"

            device_config.classic_enabled = True
            device_config.le_enabled = False
            device_config.le_simultaneous_enabled = False
            device_config.classic_sc_enabled = False
            device_config.classic_smp_enabled = False
            device = Device.from_config_with_hci(device_config, hci_source, hci_sink)

            # Setup the SDP records to expose the SRC service
            device.sdp_service_records = a2dp_source_sdp_records()

            # Setup AVRCP
            self.avrcp_protocol = AvrcpProtocol()
            self.avrcp_protocol.listen(device)

            # Don't require MITM when pairing.
            device.pairing_config_factory = lambda connection: PairingConfig(mitm=False)

            # Start the controller
            await device.power_on()

            # Print some of the config/properties
            print(
                "Player Bluetooth Address:",
                color(
                    device.public_address.to_string(with_type_qualifier=False),
                    "yellow",
                ),
            )

            # Listen for connections
            device.on("connection", self.on_bluetooth_connection)

            # Run the workload
            try:
                await workload(device)
            except BumbleConnectionError as error:
                if error.error_code == HCI_CONNECTION_ALREADY_EXISTS_ERROR:
                    print(color("Connection already established", "blue"))
                else:
                    print(color(f"Failed to connect: {error}", "red"))

            # Wait until it is time to exit
            assert self.done is not None
            await asyncio.wait(
                [hci_source.terminated, asyncio.ensure_future(self.done.wait())],
                return_when=asyncio.FIRST_COMPLETED,
            )

    def on_bluetooth_connection(self, connection: Connection) -> None:
        print(color(f"--- Connected: {connection}", "cyan"))
        connection.on("disconnection", self.on_bluetooth_disconnection)

    def on_bluetooth_disconnection(self, reason) -> None:
        print(color(f"--- Disconnected: {HCI_Constant.error_name(reason)}", "cyan"))
        self.set_done()

    async def connect(self, device: Device, address: str) -> Connection:
        print(color(f"Connecting to {address}...", "green"))
        connection = await device.connect(address, transport=PhysicalTransport.BR_EDR)

        # Request authentication
        if self.authenticate:
            print(color("*** Authenticating...", "blue"))
            await connection.authenticate()
            print(color("*** Authenticated", "blue"))

        # Enable encryption
        if self.encrypt:
            print(color("*** Enabling encryption...", "blue"))
            await connection.encrypt()
            print(color("*** Encryption on", "blue"))

        return connection

    async def create_avdtp_protocol(self, connection: Connection) -> AvdtpProtocol:
        # Look for an A2DP service
        avdtp_version = await find_avdtp_service_with_connection(connection)
        if not avdtp_version:
            raise RuntimeError("no A2DP service found")

        print(color(f"AVDTP Version: {avdtp_version}"))

        # Create a client to interact with the remote device
        return await AvdtpProtocol.connect(connection, avdtp_version)

    async def stream_packets(
        self,
        protocol: AvdtpProtocol,
        codec_type: int,
        vendor_id: int,
        codec_id: int,
        packet_source: Union[SbcPacketSource, AacPacketSource, OpusPacketSource],
        codec_capabilities: MediaCodecCapabilities,
    ):
        # Discover all endpoints on the remote device
        endpoints = await protocol.discover_remote_endpoints()
        for endpoint in endpoints:
            print('@@@', endpoint)

        # Select a sink
        sink = protocol.find_remote_sink_by_codec(
            AVDTP_AUDIO_MEDIA_TYPE, codec_type, vendor_id, codec_id
        )
        if sink is None:
            print(color('!!! no compatible sink found', 'red'))
            return
        print(f'### Selected sink: {sink.seid}')

        # Check if the sink supports delay reporting
        delay_reporting = False
        for capability in sink.capabilities:
            if capability.service_category == AVDTP_DELAY_REPORTING_SERVICE_CATEGORY:
                delay_reporting = True
                break

        def on_delay_report(delay: int):
            print(color(f"*** DELAY REPORT: {delay}", "blue"))

        # Adjust the codec capabilities for certain codecs
        for capability in sink.capabilities:
            if isinstance(capability, MediaCodecCapabilities):
                if isinstance(
                    codec_capabilities.media_codec_information, SbcMediaCodecInformation
                ) and isinstance(
                    capability.media_codec_information, SbcMediaCodecInformation
                ):
                    codec_capabilities.media_codec_information.minimum_bitpool_value = (
                        capability.media_codec_information.minimum_bitpool_value
                    )
                    codec_capabilities.media_codec_information.maximum_bitpool_value = (
                        capability.media_codec_information.maximum_bitpool_value
                    )
                    print(color("Source media codec:", "green"), codec_capabilities)

        # Stream the packets
        packet_pump = MediaPacketPump(packet_source.packets)
        source = protocol.add_source(codec_capabilities, packet_pump, delay_reporting)
        source.on("delay_report", on_delay_report)
        stream = await protocol.create_stream(source, sink)
        await stream.start()

        await packet_pump.wait_for_completion()

    async def discover(self, device: Device) -> None:
        @device.listens_to("inquiry_result")
        def on_inquiry_result(
            address: Address, class_of_device: int, data: AdvertisingData, rssi: int
        ) -> None:
            (
                service_classes,
                major_device_class,
                minor_device_class,
            ) = DeviceClass.split_class_of_device(class_of_device)
            separator = "\n  "
            print(f">>> {color(address.to_string(False), 'yellow')}:")
            print(f"  Device Class (raw): {class_of_device:06X}")
            major_class_name = DeviceClass.major_device_class_name(major_device_class)
            print("  Device Major Class: " f"{major_class_name}")
            minor_class_name = DeviceClass.minor_device_class_name(
                major_device_class, minor_device_class
            )
            print("  Device Minor Class: " f"{minor_class_name}")
            print(
                "  Device Services: "
                f"{', '.join(DeviceClass.service_class_labels(service_classes))}"
            )
            print(f"  RSSI: {rssi}")
            if data.ad_structures:
                print(f"  {data.to_string(separator)}")

        await device.start_discovery()

    async def pair(self, device: Device, address: str) -> None:
        print(color(f"Connecting to {address}...", "green"))
        connection = await device.connect(address, transport=PhysicalTransport.BR_EDR)

        print(color("Pairing...", "magenta"))
        await connection.authenticate()
        print(color("Pairing completed", "magenta"))
        self.set_done()

    async def inquire(self, device: Device, address: str) -> None:
        connection = await self.connect(device, address)
        avdtp_protocol = await self.create_avdtp_protocol(connection)

        # Discover the remote endpoints
        endpoints = await avdtp_protocol.discover_remote_endpoints()
        print(f'@@@ Found {len(list(endpoints))} endpoints')
        for endpoint in endpoints:
            print('@@@', endpoint)

        self.set_done()

    async def play(
        self,
        device: Device,
        address: Optional[str],
        audio_format: str,
        audio_file: str,
    ) -> None:
        if audio_format == "auto":
            if audio_file.endswith(".sbc"):
                audio_format = "sbc"
            elif audio_file.endswith(".aac") or audio_file.endswith(".adts"):
                audio_format = "aac"
            elif audio_file.endswith(".ogg"):
                audio_format = "opus"
            else:
                raise ValueError("Unable to determine audio format from file extension")

        device.on(
            "connection",
            lambda connection: AsyncRunner.spawn(on_connection(connection)),
        )

        async def on_connection(connection: Connection):
            avdtp_protocol = await self.create_avdtp_protocol(connection)

            with open(audio_file, 'rb') as input_file:
                # NOTE: this should be using asyncio file reading, but blocking reads
                # are good enough for this command line app.
                async def read_audio_data(byte_count):
                    return input_file.read(byte_count)

                # Obtain the codec capabilities from the stream
                packet_source: Union[SbcPacketSource, AacPacketSource, OpusPacketSource]
                vendor_id = 0
                codec_id = 0
                if audio_format == "sbc":
                    codec_type = A2DP_SBC_CODEC_TYPE
                    codec_capabilities = await sbc_codec_capabilities(read_audio_data)
                    packet_source = SbcPacketSource(
                        read_audio_data,
                        avdtp_protocol.l2cap_channel.peer_mtu,
                    )
                elif audio_format == "aac":
                    codec_type = A2DP_MPEG_2_4_AAC_CODEC_TYPE
                    codec_capabilities = await aac_codec_capabilities(read_audio_data)
                    packet_source = AacPacketSource(
                        read_audio_data,
                        avdtp_protocol.l2cap_channel.peer_mtu,
                    )
                else:
                    codec_type = A2DP_NON_A2DP_CODEC_TYPE
                    vendor_id = OpusMediaCodecInformation.VENDOR_ID
                    codec_id = OpusMediaCodecInformation.CODEC_ID
                    codec_capabilities = await opus_codec_capabilities(read_audio_data)
                    packet_source = OpusPacketSource(
                        read_audio_data,
                        avdtp_protocol.l2cap_channel.peer_mtu,
                    )

                # Rewind to the start
                input_file.seek(0)

                try:
                    await self.stream_packets(
                        avdtp_protocol,
                        codec_type,
                        vendor_id,
                        codec_id,
                        packet_source,
                        codec_capabilities,
                    )
                except Exception as error:
                    print(color(f"!!! Error while streaming: {error}", "red"))

            self.set_done()

        if address:
            await self.connect(device, address)
        else:
            print(color("Waiting for an incoming connection...", "magenta"))

    def set_done(self) -> None:
        if self.done:
            self.done.set()


# -----------------------------------------------------------------------------
def create_player(context) -> Player:
    return Player(
        transport=context.obj["hci_transport"],
        device_config=context.obj["device_config"],
        authenticate=context.obj["authenticate"],
        encrypt=context.obj["encrypt"],
    )


# -----------------------------------------------------------------------------
@click.group()
@click.pass_context
@click.option("--hci-transport", metavar="TRANSPORT", required=True)
@click.option("--device-config", metavar="FILENAME", help="Device configuration file")
@click.option(
    "--authenticate",
    is_flag=True,
    help="Request authentication when connecting",
    default=False,
)
@click.option(
    "--encrypt", is_flag=True, help="Request encryption when connecting", default=True
)
def player_cli(ctx, hci_transport, device_config, authenticate, encrypt):
    ctx.ensure_object(dict)
    ctx.obj["hci_transport"] = hci_transport
    ctx.obj["device_config"] = device_config
    ctx.obj["authenticate"] = authenticate
    ctx.obj["encrypt"] = encrypt


@player_cli.command("discover")
@click.pass_context
def discover(context):
    """Discover speakers or headphones"""
    player = create_player(context)
    asyncio.run(player.run(player.discover))


@player_cli.command("inquire")
@click.pass_context
@click.argument(
    "address",
    metavar="ADDRESS",
)
def inquire(context, address):
    """Connect to a speaker or headphone and inquire about their capabilities"""
    player = create_player(context)
    asyncio.run(player.run(lambda device: player.inquire(device, address)))


@player_cli.command("pair")
@click.pass_context
@click.argument(
    "address",
    metavar="ADDRESS",
)
def pair(context, address):
    """Pair with a speaker or headphone"""
    player = create_player(context)
    asyncio.run(player.run(lambda device: player.pair(device, address)))


@player_cli.command("play")
@click.pass_context
@click.option(
    "--connect",
    "address",
    metavar="ADDRESS",
    help="Address or name to connect to",
)
@click.option(
    "-f",
    "--audio-format",
    type=click.Choice(["auto", "sbc", "aac", "opus"]),
    help="Audio file format (use 'auto' to infer the format from the file extension)",
    default="auto",
)
@click.argument("audio_file")
def play(context, address, audio_format, audio_file):
    """Play and audio file"""
    player = create_player(context)
    asyncio.run(
        player.run(
            lambda device: player.play(device, address, audio_format, audio_file)
        )
    )


# -----------------------------------------------------------------------------
def main():
    logging.basicConfig(level=os.environ.get("BUMBLE_LOGLEVEL", "WARNING").upper())
    player_cli()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
