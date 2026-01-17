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
import time

import click

import bumble.logging
from bumble.colors import color
from bumble.company_ids import COMPANY_IDENTIFIERS
from bumble.core import name_or_number
from bumble.hci import (
    HCI_LE_READ_BUFFER_SIZE_COMMAND,
    HCI_LE_READ_BUFFER_SIZE_V2_COMMAND,
    HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND,
    HCI_LE_READ_MAXIMUM_DATA_LENGTH_COMMAND,
    HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND,
    HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
    HCI_READ_BD_ADDR_COMMAND,
    HCI_READ_BUFFER_SIZE_COMMAND,
    HCI_READ_LOCAL_NAME_COMMAND,
    HCI_Command,
    HCI_LE_Read_Buffer_Size_Command,
    HCI_LE_Read_Buffer_Size_V2_Command,
    HCI_LE_Read_Maximum_Advertising_Data_Length_Command,
    HCI_LE_Read_Maximum_Data_Length_Command,
    HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command,
    HCI_LE_Read_Suggested_Default_Data_Length_Command,
    HCI_Read_BD_ADDR_Command,
    HCI_Read_Buffer_Size_Command,
    HCI_Read_Local_Name_Command,
    HCI_Read_Local_Supported_Codecs_Command,
    HCI_Read_Local_Supported_Codecs_V2_Command,
    HCI_Read_Local_Version_Information_Command,
    LeFeature,
    SpecificationVersion,
    map_null_terminated_utf8_string,
)
from bumble.host import Host
from bumble.transport import open_transport


# -----------------------------------------------------------------------------
async def get_classic_info(host: Host) -> None:
    if host.supports_command(HCI_READ_BD_ADDR_COMMAND):
        response1 = await host.send_sync_command(HCI_Read_BD_ADDR_Command())
        print()
        print(
            color('Public Address:', 'yellow'),
            response1.bd_addr.to_string(False),
        )

    if host.supports_command(HCI_READ_LOCAL_NAME_COMMAND):
        response2 = await host.send_sync_command(HCI_Read_Local_Name_Command())
        print()
        print(
            color('Local Name:', 'yellow'),
            map_null_terminated_utf8_string(response2.local_name),
        )


# -----------------------------------------------------------------------------
async def get_le_info(host: Host) -> None:
    print()

    if host.supports_command(HCI_LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS_COMMAND):
        response1 = await host.send_sync_command(
            HCI_LE_Read_Number_Of_Supported_Advertising_Sets_Command()
        )
        print(
            color('LE Number Of Supported Advertising Sets:', 'yellow'),
            response1.num_supported_advertising_sets,
            '\n',
        )

    if host.supports_command(HCI_LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH_COMMAND):
        response2 = await host.send_sync_command(
            HCI_LE_Read_Maximum_Advertising_Data_Length_Command()
        )
        print(
            color('LE Maximum Advertising Data Length:', 'yellow'),
            response2.max_advertising_data_length,
            '\n',
        )

    if host.supports_command(HCI_LE_READ_MAXIMUM_DATA_LENGTH_COMMAND):
        response3 = await host.send_sync_command(
            HCI_LE_Read_Maximum_Data_Length_Command()
        )
        print(
            color('Maximum Data Length:', 'yellow'),
            (
                f'tx:{response3.supported_max_tx_octets}/'
                f'{response3.supported_max_tx_time}, '
                f'rx:{response3.supported_max_rx_octets}/'
                f'{response3.supported_max_rx_time}'
            ),
            '\n',
        )

    if host.supports_command(HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND):
        response4 = await host.send_sync_command(
            HCI_LE_Read_Suggested_Default_Data_Length_Command()
        )
        print(
            color('Suggested Default Data Length:', 'yellow'),
            f'{response4.suggested_max_tx_octets}/'
            f'{response4.suggested_max_tx_time}',
            '\n',
        )

    print(color('LE Features:', 'yellow'))
    for feature in host.supported_le_features:
        print(f'  {LeFeature(feature).name}')


# -----------------------------------------------------------------------------
async def get_flow_control_info(host: Host) -> None:
    print()

    if host.supports_command(HCI_READ_BUFFER_SIZE_COMMAND):
        response1 = await host.send_sync_command(HCI_Read_Buffer_Size_Command())
        print(
            color('ACL Flow Control:', 'yellow'),
            f'{response1.hc_total_num_acl_data_packets} '
            f'packets of size {response1.hc_acl_data_packet_length}',
        )

    if host.supports_command(HCI_LE_READ_BUFFER_SIZE_V2_COMMAND):
        response2 = await host.send_sync_command(HCI_LE_Read_Buffer_Size_V2_Command())
        print(
            color('LE ACL Flow Control:', 'yellow'),
            f'{response2.total_num_le_acl_data_packets} '
            f'packets of size {response2.le_acl_data_packet_length}',
        )
        print(
            color('LE ISO Flow Control:', 'yellow'),
            f'{response2.total_num_iso_data_packets} '
            f'packets of size {response2.iso_data_packet_length}',
        )
    elif host.supports_command(HCI_LE_READ_BUFFER_SIZE_COMMAND):
        response3 = await host.send_sync_command(HCI_LE_Read_Buffer_Size_Command())
        print(
            color('LE ACL Flow Control:', 'yellow'),
            f'{response3.total_num_le_acl_data_packets} '
            f'packets of size {response3.le_acl_data_packet_length}',
        )


# -----------------------------------------------------------------------------
async def get_codecs_info(host: Host) -> None:
    print()

    if host.supports_command(HCI_Read_Local_Supported_Codecs_V2_Command.op_code):
        response1 = await host.send_sync_command(
            HCI_Read_Local_Supported_Codecs_V2_Command()
        )
        print(color('Codecs:', 'yellow'))

        for codec_id, transport in zip(
            response1.standard_codec_ids,
            response1.standard_codec_transports,
        ):
            print(f'  {codec_id.name} - {transport.name}')

        for vendor_codec_id, vendor_transport in zip(
            response1.vendor_specific_codec_ids,
            response1.vendor_specific_codec_transports,
        ):
            company = name_or_number(COMPANY_IDENTIFIERS, vendor_codec_id >> 16)
            print(f'  {company} / {vendor_codec_id & 0xFFFF} - {vendor_transport.name}')

        if not response1.standard_codec_ids:
            print('  No standard codecs')
        if not response1.vendor_specific_codec_ids:
            print('  No Vendor-specific codecs')

    if host.supports_command(HCI_Read_Local_Supported_Codecs_Command.op_code):
        response2 = await host.send_sync_command(
            HCI_Read_Local_Supported_Codecs_Command()
        )
        print(color('Codecs (BR/EDR):', 'yellow'))
        for codec_id in response2.standard_codec_ids:
            print(f'  {codec_id.name}')

        for vendor_codec_id in response2.vendor_specific_codec_ids:
            company = name_or_number(COMPANY_IDENTIFIERS, vendor_codec_id >> 16)
            print(f'  {company} / {vendor_codec_id & 0xFFFF}')

        if not response2.standard_codec_ids:
            print('  No standard codecs')
        if not response2.vendor_specific_codec_ids:
            print('  No Vendor-specific codecs')


# -----------------------------------------------------------------------------
async def async_main(
    latency_probes, latency_probe_interval, latency_probe_command, transport
):
    print('<<< connecting to HCI...')
    async with await open_transport(transport) as (hci_source, hci_sink):
        print('<<< connected')

        host = Host(hci_source, hci_sink)
        await host.reset()

        # Measure the latency if requested
        # (we add an extra probe at the start, that we ignore, just to ensure that
        # the transport is primed)
        latencies = []
        if latency_probes:
            if latency_probe_command:
                probe_hci_command = HCI_Command.from_bytes(
                    bytes.fromhex(latency_probe_command)
                )
            else:
                probe_hci_command = HCI_Read_Local_Version_Information_Command()

            for iteration in range(1 + latency_probes):
                if latency_probe_interval:
                    await asyncio.sleep(latency_probe_interval / 1000)
                start = time.time()
                await host.send_command(probe_hci_command)
                if iteration:
                    latencies.append(1000 * (time.time() - start))
            print(
                color('HCI Command Latency:', 'yellow'),
                (
                    f'min={min(latencies):.2f}, '
                    f'max={max(latencies):.2f}, '
                    f'average={sum(latencies) / len(latencies):.2f},'
                ),
                [f'{latency:.4}' for latency in latencies],
                '\n',
            )

        # Print version
        print(color('Version:', 'yellow'))
        print(
            color('  Manufacturer:  ', 'green'),
            name_or_number(COMPANY_IDENTIFIERS, host.local_version.company_identifier),
        )
        print(
            color('  HCI Version:   ', 'green'),
            SpecificationVersion(host.local_version.hci_version).name,
        )
        print(
            color('  HCI Subversion:', 'green'),
            f'0x{host.local_version.hci_subversion:04x}',
        )
        print(
            color('  LMP Version:   ', 'green'),
            SpecificationVersion(host.local_version.lmp_version).name,
        )
        print(
            color('  LMP Subversion:', 'green'),
            f'0x{host.local_version.lmp_subversion:04x}',
        )

        # Get the Classic info
        await get_classic_info(host)

        # Get the LE info
        await get_le_info(host)

        # Print the flow control info
        await get_flow_control_info(host)

        # Get codec info
        await get_codecs_info(host)

        # Print the list of commands supported by the controller
        print()
        print(color('Supported Commands:', 'yellow'))
        for command in host.supported_commands:
            print(f'  {HCI_Command.command_name(command)}')


# -----------------------------------------------------------------------------
@click.command()
@click.option(
    '--latency-probes',
    metavar='N',
    type=int,
    help='Send N commands to measure HCI transport latency statistics',
)
@click.option(
    '--latency-probe-interval',
    metavar='INTERVAL',
    type=int,
    help='Interval between latency probes (milliseconds)',
)
@click.option(
    '--latency-probe-command',
    metavar='COMMAND_HEX',
    help=(
        'Probe command (HCI Command packet bytes, in hex. Use 0177FC00 for'
        ' a loopback test with the HCI remote proxy app)'
    ),
)
@click.argument('transport')
def main(latency_probes, latency_probe_interval, latency_probe_command, transport):
    bumble.logging.setup_basic_logging()
    asyncio.run(
        async_main(
            latency_probes, latency_probe_interval, latency_probe_command, transport
        )
    )


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
