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
# Bumble Tool
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import asyncio
import logging
import os
import random
import re
import humanize
from typing import Optional, Union
from collections import OrderedDict

import click
from prettytable import PrettyTable

from prompt_toolkit import Application
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import Completer, Completion, NestedCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.styles import Style
from prompt_toolkit.filters import Condition
from prompt_toolkit.widgets import TextArea, Frame
from prompt_toolkit.widgets.toolbars import FormattedTextToolbar
from prompt_toolkit.data_structures import Point
from prompt_toolkit.layout import (
    Layout,
    HSplit,
    Window,
    CompletionsMenu,
    Float,
    FormattedTextControl,
    FloatContainer,
    ConditionalContainer,
    Dimension,
)

from bumble import __version__
import bumble.core
from bumble import colors
from bumble.core import UUID, AdvertisingData, BT_LE_TRANSPORT
from bumble.device import ConnectionParametersPreferences, Device, Connection, Peer
from bumble.utils import AsyncRunner
from bumble.transport import open_transport_or_link
from bumble.gatt import Characteristic, Service, CharacteristicDeclaration, Descriptor
from bumble.gatt_client import CharacteristicProxy
from bumble.hci import (
    HCI_Constant,
    HCI_LE_1M_PHY,
    HCI_LE_2M_PHY,
    HCI_LE_CODED_PHY,
)


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
BUMBLE_USER_DIR = os.path.expanduser('~/.bumble')
DEFAULT_RSSI_BAR_WIDTH = 20
DEFAULT_CONNECTION_TIMEOUT = 30.0
DISPLAY_MIN_RSSI = -100
DISPLAY_MAX_RSSI = -30
RSSI_MONITOR_INTERVAL = 5.0  # Seconds


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------


def le_phy_name(phy_id):
    return {HCI_LE_1M_PHY: '1M', HCI_LE_2M_PHY: '2M', HCI_LE_CODED_PHY: 'CODED'}.get(
        phy_id, HCI_Constant.le_phy_name(phy_id)
    )


def rssi_bar(rssi):
    blocks = ['', '▏', '▎', '▍', '▌', '▋', '▊', '▉']
    bar_width = (rssi - DISPLAY_MIN_RSSI) / (DISPLAY_MAX_RSSI - DISPLAY_MIN_RSSI)
    bar_width = min(max(bar_width, 0), 1)
    bar_ticks = int(bar_width * DEFAULT_RSSI_BAR_WIDTH * 8)
    bar_blocks = ('█' * int(bar_ticks / 8)) + blocks[bar_ticks % 8]
    return f'{rssi:4} {bar_blocks}'


def parse_phys(phys):
    if phys.lower() == '*':
        return None

    phy_list = []
    elements = phys.lower().split(',')
    for element in elements:
        if element == '1m':
            phy_list.append(HCI_LE_1M_PHY)
        elif element == '2m':
            phy_list.append(HCI_LE_2M_PHY)
        elif element == 'coded':
            phy_list.append(HCI_LE_CODED_PHY)
        else:
            raise ValueError('invalid PHY name')
    return phy_list


# -----------------------------------------------------------------------------
# Console App
# -----------------------------------------------------------------------------
class ConsoleApp:
    connected_peer: Optional[Peer]

    def __init__(self):
        self.known_addresses = set()
        self.known_remote_attributes = []
        self.known_local_attributes = []
        self.device = None
        self.connected_peer = None
        self.top_tab = 'device'
        self.monitor_rssi = False
        self.connection_rssi = None

        style = Style.from_dict(
            {
                'output-field': 'bg:#000044 #ffffff',
                'input-field': 'bg:#000000 #ffffff',
                'line': '#004400',
                'error': 'fg:ansired',
            }
        )

        class LiveCompleter(Completer):
            def __init__(self, words):
                self.words = words

            def get_completions(self, document, complete_event):
                prefix = document.text_before_cursor.upper()
                for word in [x for x in self.words if x.upper().startswith(prefix)]:
                    yield Completion(word, start_position=-len(prefix))

        def make_completer():
            return NestedCompleter.from_nested_dict(
                {
                    'scan': {'on': None, 'off': None, 'clear': None},
                    'advertise': {'on': None, 'off': None},
                    'rssi': {'on': None, 'off': None},
                    'show': {
                        'scan': None,
                        'log': None,
                        'device': None,
                        'local-services': None,
                        'remote-services': None,
                        'local-values': None,
                        'remote-values': None,
                    },
                    'filter': {
                        'address': None,
                    },
                    'connect': LiveCompleter(self.known_addresses),
                    'update-parameters': None,
                    'encrypt': None,
                    'disconnect': None,
                    'discover': {'services': None, 'attributes': None},
                    'request-mtu': None,
                    'read': LiveCompleter(self.known_remote_attributes),
                    'write': LiveCompleter(self.known_remote_attributes),
                    'local-write': LiveCompleter(self.known_local_attributes),
                    'subscribe': LiveCompleter(self.known_remote_attributes),
                    'unsubscribe': LiveCompleter(self.known_remote_attributes),
                    'set-phy': {'1m': None, '2m': None, 'coded': None},
                    'set-default-phy': None,
                    'quit': None,
                    'exit': None,
                }
            )

        self.input_field = TextArea(
            height=1,
            prompt="> ",
            multiline=False,
            wrap_lines=False,
            completer=make_completer(),
            history=FileHistory(os.path.join(BUMBLE_USER_DIR, 'history')),
        )

        self.input_field.accept_handler = self.accept_input

        self.output_height = Dimension(min=7, max=7, weight=1)
        self.output_lines = []
        self.output = FormattedTextControl(
            get_cursor_position=lambda: Point(0, max(0, len(self.output_lines) - 1))
        )
        self.output_max_lines = 20
        self.scan_results_text = FormattedTextControl()
        self.local_services_text = FormattedTextControl()
        self.remote_services_text = FormattedTextControl()
        self.device_text = FormattedTextControl()
        self.log_text = FormattedTextControl(
            get_cursor_position=lambda: Point(0, max(0, len(self.log_lines) - 1))
        )
        self.local_values_text = FormattedTextControl()
        self.remote_values_text = FormattedTextControl()
        self.log_height = Dimension(min=7, weight=4)
        self.log_max_lines = 100
        self.log_lines = []

        container = HSplit(
            [
                ConditionalContainer(
                    Frame(Window(self.scan_results_text), title='Scan Results'),
                    filter=Condition(lambda: self.top_tab == 'scan'),
                ),
                ConditionalContainer(
                    Frame(Window(self.local_services_text), title='Local Services'),
                    filter=Condition(lambda: self.top_tab == 'local-services'),
                ),
                ConditionalContainer(
                    Frame(Window(self.local_values_text), title='Local Values'),
                    filter=Condition(lambda: self.top_tab == 'local-values'),
                ),
                ConditionalContainer(
                    Frame(Window(self.remote_services_text), title='Remote Services'),
                    filter=Condition(lambda: self.top_tab == 'remote-services'),
                ),
                ConditionalContainer(
                    Frame(Window(self.remote_values_text), title='Remote Values'),
                    filter=Condition(lambda: self.top_tab == 'remote-values'),
                ),
                ConditionalContainer(
                    Frame(Window(self.log_text, height=self.log_height), title='Log'),
                    filter=Condition(lambda: self.top_tab == 'log'),
                ),
                ConditionalContainer(
                    Frame(Window(self.device_text), title='Device'),
                    filter=Condition(lambda: self.top_tab == 'device'),
                ),
                Frame(Window(self.output, height=self.output_height)),
                FormattedTextToolbar(text=self.get_status_bar_text, style='reverse'),
                self.input_field,
            ]
        )

        container = FloatContainer(
            container,
            floats=[
                Float(
                    xcursor=True,
                    ycursor=True,
                    content=CompletionsMenu(max_height=16, scroll_offset=1),
                ),
            ],
        )

        layout = Layout(container, focused_element=self.input_field)

        key_bindings = KeyBindings()

        @key_bindings.add("c-c")
        @key_bindings.add("c-q")
        def _(event):
            event.app.exit()

        # pylint: disable=invalid-name
        self.ui = Application(
            layout=layout, style=style, key_bindings=key_bindings, full_screen=True
        )

    async def run_async(self, device_config, transport):
        rssi_monitoring_task = asyncio.create_task(self.rssi_monitor_loop())

        async with await open_transport_or_link(transport) as (hci_source, hci_sink):
            if device_config:
                self.device = Device.from_config_file_with_hci(
                    device_config, hci_source, hci_sink
                )
            else:
                random_address = (
                    f"{random.randint(192,255):02X}"  # address is static random
                )
                for random_byte in random.sample(range(255), 5):
                    random_address += f":{random_byte:02X}"
                self.append_to_log(f"Setting random address: {random_address}")
                self.device = Device.with_hci(
                    'Bumble', random_address, hci_source, hci_sink
                )
            self.device.listener = DeviceListener(self)
            await self.device.power_on()
            self.show_device(self.device)
            self.show_local_services(self.device.gatt_server.attributes)

            # Run the UI
            await self.ui.run_async()

        rssi_monitoring_task.cancel()

    def add_known_address(self, address):
        self.known_addresses.add(address)

    def accept_input(self, _):
        if len(self.input_field.text) == 0:
            return
        self.append_to_output([('', '* '), ('ansicyan', self.input_field.text)], False)
        self.ui.create_background_task(self.command(self.input_field.text))

    def get_status_bar_text(self):
        scanning = "ON" if self.device and self.device.is_scanning else "OFF"

        connection_state = 'NONE'
        encryption_state = ''
        att_mtu = ''
        rssi = '' if self.connection_rssi is None else rssi_bar(self.connection_rssi)

        if self.device:
            if self.device.is_le_connecting:
                connection_state = 'CONNECTING'
            elif self.connected_peer:
                connection = self.connected_peer.connection
                connection_parameters = (
                    f'{connection.parameters.connection_interval}/'
                    f'{connection.parameters.peripheral_latency}/'
                    f'{connection.parameters.supervision_timeout}'
                )
                if connection.transport == BT_LE_TRANSPORT:
                    phy_state = (
                        f' RX={le_phy_name(connection.phy.rx_phy)}/'
                        f'TX={le_phy_name(connection.phy.tx_phy)}'
                    )
                else:
                    phy_state = ''
                connection_state = (
                    f'{connection.peer_address} '
                    f'{connection_parameters} '
                    f'{connection.data_length}'
                    f'{phy_state}'
                )
                encryption_state = (
                    'ENCRYPTED' if connection.is_encrypted else 'NOT ENCRYPTED'
                )
                att_mtu = f'ATT_MTU: {connection.att_mtu}'

        return [
            ('ansigreen', f' SCAN: {scanning} '),
            ('', '  '),
            ('ansiblue', f' CONNECTION: {connection_state} '),
            ('', '  '),
            ('ansimagenta', f' {encryption_state} '),
            ('', '  '),
            ('ansicyan', f' {att_mtu} '),
            ('', '  '),
            ('ansiyellow', f' {rssi} '),
        ]

    def show_error(self, title, details=None):
        appended = [('class:error', title)]
        if details:
            appended.append(('', f' {details}'))
        self.append_to_output(appended)

    def show_scan_results(self, scan_results):
        max_lines = 40  # TEMP
        lines = []
        keys = list(scan_results.keys())[:max_lines]
        for key in keys:
            lines.append(scan_results[key].to_display_string())
        self.scan_results_text.text = ANSI('\n'.join(lines))
        self.ui.invalidate()

    def show_remote_services(self, services):
        lines = []
        del self.known_remote_attributes[:]
        for service in services:
            lines.append(("ansicyan", f"{service}\n"))

            for characteristic in service.characteristics:
                lines.append(('ansimagenta', f'  {characteristic} + \n'))
                self.known_remote_attributes.append(
                    f'{service.uuid.to_hex_str()}.{characteristic.uuid.to_hex_str()}'
                )
                self.known_remote_attributes.append(
                    f'*.{characteristic.uuid.to_hex_str()}'
                )
                self.known_remote_attributes.append(f'#{characteristic.handle:X}')
                for descriptor in characteristic.descriptors:
                    lines.append(("ansigreen", f"    {descriptor}\n"))

        self.remote_services_text.text = lines
        self.ui.invalidate()

    def show_local_services(self, attributes):
        lines = []
        del self.known_local_attributes[:]
        for attribute in attributes:
            if isinstance(attribute, Service):
                # Save the most recent service for use later
                service = attribute
                lines.append(("ansicyan", f"{attribute}\n"))
            elif isinstance(attribute, Characteristic):
                # CharacteristicDeclaration includes all info from Characteristic
                # no need to print it twice
                continue
            elif isinstance(attribute, CharacteristicDeclaration):
                # Save the most recent characteristic declaration for use later
                characteristic_declaration = attribute
                self.known_local_attributes.append(
                    f'{service.uuid.to_hex_str()}.{attribute.characteristic.uuid.to_hex_str()}'
                )
                self.known_local_attributes.append(
                    f'#{attribute.characteristic.handle:X}'
                )
                lines.append(("ansimagenta", f"  {attribute}\n"))
            elif isinstance(attribute, Descriptor):
                self.known_local_attributes.append(
                    f'{service.uuid.to_hex_str()}.{characteristic_declaration.characteristic.uuid.to_hex_str()}.{attribute.type.to_hex_str()}'
                )
                self.known_local_attributes.append(f'#{attribute.handle:X}')
                lines.append(("ansigreen", f"    {attribute}\n"))
            else:
                lines.append(("ansiyellow", f"{attribute}\n"))

        self.local_services_text.text = lines
        self.ui.invalidate()

    def show_device(self, device):
        lines = []

        lines.append(('ansicyan', 'Bumble Version:       '))
        lines.append(('', f'{__version__}\n'))
        lines.append(('ansicyan', 'Name:                 '))
        lines.append(('', f'{device.name}\n'))
        lines.append(('ansicyan', 'Public Address:       '))
        lines.append(('', f'{device.public_address}\n'))
        lines.append(('ansicyan', 'Random Address:       '))
        lines.append(('', f'{device.random_address}\n'))
        lines.append(('ansicyan', 'LE Enabled:           '))
        lines.append(('', f'{device.le_enabled}\n'))
        lines.append(('ansicyan', 'Classic Enabled:      '))
        lines.append(('', f'{device.classic_enabled}\n'))
        lines.append(('ansicyan', 'Classic SC Enabled:   '))
        lines.append(('', f'{device.classic_sc_enabled}\n'))
        lines.append(('ansicyan', 'Classic SSP Enabled:  '))
        lines.append(('', f'{device.classic_ssp_enabled}\n'))
        lines.append(('ansicyan', 'Classic Class:        '))
        lines.append(('', f'{device.class_of_device}\n'))
        lines.append(('ansicyan', 'Discoverable:         '))
        lines.append(('', f'{device.discoverable}\n'))
        lines.append(('ansicyan', 'Connectable:          '))
        lines.append(('', f'{device.connectable}\n'))
        lines.append(('ansicyan', 'Advertising Data:     '))
        lines.append(('', f'{device.advertising_data}\n'))
        lines.append(('ansicyan', 'Scan Response Data:   '))
        lines.append(('', f'{device.scan_response_data}\n'))
        advertising_interval = (
            device.advertising_interval_min
            if device.advertising_interval_min == device.advertising_interval_max
            else (
                f'{device.advertising_interval_min} to '
                f'{device.advertising_interval_max}'
            )
        )
        lines.append(('ansicyan', 'Advertising Interval: '))
        lines.append(('', f'{advertising_interval}\n'))

        self.device_text.text = lines
        self.ui.invalidate()

    def append_to_output(self, line, invalidate=True):
        if isinstance(line, str):
            line = [('', line)]
        self.output_lines = self.output_lines[-self.output_max_lines :]
        self.output_lines.append(line)
        formatted_text = []
        for line in self.output_lines:
            formatted_text += line
            formatted_text.append(('', '\n'))
        self.output.text = formatted_text
        if invalidate:
            self.ui.invalidate()

    def append_to_log(self, lines, invalidate=True):
        self.log_lines.extend(lines.split('\n'))
        self.log_lines = self.log_lines[-self.log_max_lines :]
        self.log_text.text = ANSI('\n'.join(self.log_lines))
        if invalidate:
            self.ui.invalidate()

    async def discover_services(self):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        # Discover all services, characteristics and descriptors
        self.append_to_output('discovering services...')
        await self.connected_peer.discover_services()
        self.append_to_output(
            f'found {len(self.connected_peer.services)} services,'
            ' discovering characteristics...'
        )
        await self.connected_peer.discover_characteristics()
        self.append_to_output('found characteristics, discovering descriptors...')
        for service in self.connected_peer.services:
            for characteristic in service.characteristics:
                await self.connected_peer.discover_descriptors(characteristic)
        self.append_to_output('discovery completed')

        self.show_remote_services(self.connected_peer.services)

    async def discover_attributes(self):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        # Discover all attributes
        self.append_to_output('discovering attributes...')
        attributes = await self.connected_peer.discover_attributes()
        self.append_to_output(f'discovered {len(attributes)} attributes...')

        self.show_attributes(attributes)

    def find_remote_characteristic(self, param) -> Optional[CharacteristicProxy]:
        if not self.connected_peer:
            return None
        parts = param.split('.')
        if len(parts) == 2:
            service_uuid = UUID(parts[0]) if parts[0] != '*' else None
            characteristic_uuid = UUID(parts[1])
            for service in self.connected_peer.services:
                if service_uuid is None or service.uuid == service_uuid:
                    for characteristic in service.characteristics:
                        if characteristic.uuid == characteristic_uuid:
                            return characteristic
        elif len(parts) == 1:
            if parts[0].startswith('#'):
                attribute_handle = int(f'{parts[0][1:]}', 16)
                for service in self.connected_peer.services:
                    for characteristic in service.characteristics:
                        if characteristic.handle == attribute_handle:
                            return characteristic

        return None

    def find_local_attribute(
        self, param
    ) -> Optional[Union[Characteristic, Descriptor]]:
        parts = param.split('.')
        if len(parts) == 3:
            service_uuid = UUID(parts[0])
            characteristic_uuid = UUID(parts[1])
            descriptor_uuid = UUID(parts[2])
            return self.device.gatt_server.get_descriptor_attribute(
                service_uuid, characteristic_uuid, descriptor_uuid
            )
        if len(parts) == 2:
            service_uuid = UUID(parts[0])
            characteristic_uuid = UUID(parts[1])
            characteristic_attributes = (
                self.device.gatt_server.get_characteristic_attributes(
                    service_uuid, characteristic_uuid
                )
            )
            if characteristic_attributes:
                return characteristic_attributes[1]
            return None
        elif len(parts) == 1:
            if parts[0].startswith('#'):
                attribute_handle = int(f'{parts[0][1:]}', 16)
                attribute = self.device.gatt_server.get_attribute(attribute_handle)
                if isinstance(attribute, (Characteristic, Descriptor)):
                    return attribute
                return None

        return None

    async def rssi_monitor_loop(self):
        while True:
            if self.monitor_rssi and self.connected_peer:
                self.connection_rssi = await self.connected_peer.connection.get_rssi()
            await asyncio.sleep(RSSI_MONITOR_INTERVAL)

    async def command(self, command):
        try:
            (keyword, *params) = command.strip().split(' ')
            keyword = keyword.replace('-', '_').lower()
            handler = getattr(self, f'do_{keyword}', None)
            if handler:
                await handler(params)
                self.ui.invalidate()
            else:
                self.show_error('unknown command', keyword)
        except Exception as error:
            self.show_error(str(error))

    async def do_scan(self, params):
        if len(params) == 0:
            # Toggle scanning
            if self.device.is_scanning:
                await self.device.stop_scanning()
            else:
                await self.device.start_scanning()
        elif params[0] == 'on':
            if len(params) == 2:
                if not params[1].startswith("filter="):
                    self.show_error(
                        'invalid syntax',
                        'expected address filter=key1:value1,key2:value,... '
                        'available filters: address',
                    )
                # regex: (word):(any char except ,)
                matches = re.findall(r"(\w+):([^,]+)", params[1])
                for match in matches:
                    if match[0] == "address":
                        self.device.listener.address_filter = match[1]

            await self.device.start_scanning()
            self.top_tab = 'scan'
        elif params[0] == 'off':
            await self.device.stop_scanning()
        elif params[0] == 'clear':
            self.device.listener.scan_results.clear()
            self.known_addresses.clear()
            self.show_scan_results(self.device.listener.scan_results)
        else:
            self.show_error('unsupported arguments for scan command')

    async def do_rssi(self, params):
        if len(params) == 0:
            # Toggle monitoring
            self.monitor_rssi = not self.monitor_rssi
        elif params[0] == 'on':
            self.monitor_rssi = True
        elif params[0] == 'off':
            self.monitor_rssi = False
        else:
            self.show_error('unsupported arguments for rssi command')

    async def do_connect(self, params):
        if len(params) != 1 and len(params) != 2:
            self.show_error('invalid syntax', 'expected connect <address> [phys]')
            return

        if len(params) == 1:
            phys = None
        else:
            phys = parse_phys(params[1])
        if phys is None:
            connection_parameters_preferences = None
        else:
            connection_parameters_preferences = {
                phy: ConnectionParametersPreferences() for phy in phys
            }

        if self.device.is_scanning:
            await self.device.stop_scanning()

        self.append_to_output('connecting...')

        try:
            await self.device.connect(
                params[0],
                connection_parameters_preferences=connection_parameters_preferences,
                timeout=DEFAULT_CONNECTION_TIMEOUT,
            )
            self.top_tab = 'services'
        except bumble.core.TimeoutError:
            self.show_error('connection timed out')

    async def do_disconnect(self, _):
        if self.device.is_le_connecting:
            await self.device.cancel_connection()
        else:
            if not self.connected_peer:
                self.show_error('not connected')
                return

            await self.connected_peer.connection.disconnect()

    async def do_update_parameters(self, params):
        if len(params) != 1 or len(params[0].split('/')) != 3:
            self.show_error(
                'invalid syntax',
                'expected update-parameters <interval-min>-<interval-max>'
                '/<max-latency>/<supervision>',
            )
            return

        if not self.connected_peer:
            self.show_error('not connected')
            return

        connection_intervals, max_latency, supervision_timeout = params[0].split('/')
        connection_interval_min, connection_interval_max = [
            int(x) for x in connection_intervals.split('-')
        ]
        max_latency = int(max_latency)
        supervision_timeout = int(supervision_timeout)
        await self.connected_peer.connection.update_parameters(
            connection_interval_min,
            connection_interval_max,
            max_latency,
            supervision_timeout,
        )

    async def do_encrypt(self, _):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        await self.connected_peer.connection.encrypt()

    async def do_advertise(self, params):
        if len(params) == 0:
            # Toggle advertising
            if self.device.is_advertising:
                await self.device.stop_advertising()
            else:
                await self.device.start_advertising()
        elif params[0] == 'on':
            await self.device.start_advertising()
        elif params[0] == 'off':
            await self.device.stop_advertising()
        else:
            self.show_error('unsupported arguments for advertise command')

    async def do_show(self, params):
        if params:
            if params[0] in {
                'scan',
                'log',
                'device',
                'local-services',
                'remote-services',
                'local-values',
                'remote-values',
            }:
                self.top_tab = params[0]
                self.ui.invalidate()

        while self.top_tab == 'local-values':
            await self.do_show_local_values()
            await asyncio.sleep(1)

        while self.top_tab == 'remote-values':
            await self.do_show_remote_values()
            await asyncio.sleep(1)

    async def do_show_local_values(self):
        prettytable = PrettyTable()
        field_names = ["Service", "Characteristic", "Descriptor"]

        # if there's no connections, add a column just for value
        if not self.device.connections:
            field_names.append("Value")

        # if there are connections, add a column for each connection's value
        for connection in self.device.connections.values():
            field_names.append(f"Connection {connection.handle}")

        for attribute in self.device.gatt_server.attributes:
            if isinstance(attribute, Characteristic):
                service = self.device.gatt_server.get_attribute_group(
                    attribute.handle, Service
                )
                if not service:
                    continue
                values = [
                    attribute.read_value(connection)
                    for connection in self.device.connections.values()
                ]
                if not values:
                    values = [attribute.read_value(None)]
                prettytable.add_row([f"{service.uuid}", attribute.uuid, ""] + values)

            elif isinstance(attribute, Descriptor):
                service = self.device.gatt_server.get_attribute_group(
                    attribute.handle, Service
                )
                if not service:
                    continue
                characteristic = self.device.gatt_server.get_attribute_group(
                    attribute.handle, Characteristic
                )
                if not characteristic:
                    continue
                values = [
                    attribute.read_value(connection)
                    for connection in self.device.connections.values()
                ]
                if not values:
                    values = [attribute.read_value(None)]

                # TODO: future optimization: convert CCCD value to human readable string

                prettytable.add_row(
                    [service.uuid, characteristic.uuid, attribute.type] + values
                )

        prettytable.field_names = field_names
        self.local_values_text.text = prettytable.get_string()
        self.ui.invalidate()

    async def do_show_remote_values(self):
        prettytable = PrettyTable(
            field_names=[
                "Connection",
                "Service",
                "Characteristic",
                "Descriptor",
                "Time",
                "Value",
            ]
        )
        for connection in self.device.connections.values():
            for handle, (time, value) in connection.gatt_client.cached_values.items():
                row = [connection.handle]
                attribute = connection.gatt_client.get_attributes(handle)
                if not attribute:
                    continue
                if len(attribute) == 3:
                    row.extend(
                        [attribute[0].uuid, attribute[1].uuid, attribute[2].type]
                    )
                elif len(attribute) == 2:
                    row.extend([attribute[0].uuid, attribute[1].uuid, ""])
                elif len(attribute) == 1:
                    row.extend([attribute[0].uuid, "", ""])
                else:
                    continue

                row.extend([humanize.naturaltime(time), value])
                prettytable.add_row(row)

        self.remote_values_text.text = prettytable.get_string()
        self.ui.invalidate()

    async def do_get_phy(self, _):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        phy = await self.connected_peer.connection.get_phy()
        self.append_to_output(
            f'PHY: RX={HCI_Constant.le_phy_name(phy[0])}, '
            f'TX={HCI_Constant.le_phy_name(phy[1])}'
        )

    async def do_request_mtu(self, params):
        if len(params) != 1:
            self.show_error('invalid syntax', 'expected request-mtu <mtu>')
            return

        if not self.connected_peer:
            self.show_error('not connected')
            return

        await self.connected_peer.request_mtu(int(params[0]))

    async def do_discover(self, params):
        if not params:
            self.show_error('invalid syntax', 'expected discover services|attributes')
            return

        discovery_type = params[0]
        if discovery_type == 'services':
            await self.discover_services()
        elif discovery_type == 'attributes':
            await self.discover_attributes()

    async def do_read(self, params):
        if len(params) != 1:
            self.show_error('invalid syntax', 'expected read <attribute>')
            return

        if not self.connected_peer:
            self.show_error('not connected')
            return

        characteristic = self.find_remote_characteristic(params[0])
        if characteristic is None:
            self.show_error('no such characteristic')
            return

        value = await characteristic.read_value()
        self.append_to_output(f'VALUE: 0x{value.hex()}')

    async def do_write(self, params):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        if len(params) != 2:
            self.show_error('invalid syntax', 'expected write <attribute> <value>')
            return

        if params[1].upper().startswith("0X"):
            value = bytes.fromhex(params[1][2:])  # parse as hex string
        else:
            try:
                value = int(params[1])  # try as integer
            except ValueError:
                value = str.encode(params[1])  # must be a string

        characteristic = self.find_remote_characteristic(params[0])
        if characteristic is None:
            self.show_error('no such characteristic')
            return

        # use write with response if supported
        with_response = characteristic.properties & Characteristic.Properties.WRITE
        await characteristic.write_value(value, with_response=with_response)

    async def do_local_write(self, params):
        if len(params) != 2:
            self.show_error(
                'invalid syntax', 'expected local-write <attribute> <value>'
            )
            return

        if params[1].upper().startswith("0X"):
            value = bytes.fromhex(params[1][2:])  # parse as hex string
        else:
            try:
                value = int(params[1]).to_bytes(2, "little")  # try as 2 byte integer
            except ValueError:
                value = str.encode(params[1])  # must be a string

        attribute = self.find_local_attribute(params[0])
        if not attribute:
            self.show_error('invalid syntax', 'unable to find attribute')
            return

        # send data to any subscribers
        if isinstance(attribute, Characteristic):
            attribute.write_value(None, value)
            if attribute.has_properties(Characteristic.NOTIFY):
                await self.device.gatt_server.notify_subscribers(attribute)
            if attribute.has_properties(Characteristic.INDICATE):
                await self.device.gatt_server.indicate_subscribers(attribute)

    async def do_subscribe(self, params):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        if len(params) != 1:
            self.show_error('invalid syntax', 'expected subscribe <attribute>')
            return

        characteristic = self.find_remote_characteristic(params[0])
        if characteristic is None:
            self.show_error('no such characteristic')
            return

        await characteristic.subscribe(
            lambda value: self.append_to_output(
                f"{characteristic} VALUE: 0x{value.hex()}"
            ),
        )

    async def do_unsubscribe(self, params):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        if len(params) != 1:
            self.show_error('invalid syntax', 'expected subscribe <attribute>')
            return

        characteristic = self.find_remote_characteristic(params[0])
        if characteristic is None:
            self.show_error('no such characteristic')
            return

        await characteristic.unsubscribe()

    async def do_set_phy(self, params):
        if len(params) != 1:
            self.show_error(
                'invalid syntax', 'expected set-phy <tx_rx_phys>|<tx_phys>/<rx_phys>'
            )
            return

        if not self.connected_peer:
            self.show_error('not connected')
            return

        if '/' in params[0]:
            tx_phys, rx_phys = params[0].split('/')
        else:
            tx_phys = params[0]
            rx_phys = tx_phys

        await self.connected_peer.connection.set_phy(
            tx_phys=parse_phys(tx_phys), rx_phys=parse_phys(rx_phys)
        )

    async def do_set_default_phy(self, params):
        if len(params) != 1:
            self.show_error(
                'invalid syntax',
                'expected set-default-phy <tx_rx_phys>|<tx_phys>/<rx_phys>',
            )
            return

        if '/' in params[0]:
            tx_phys, rx_phys = params[0].split('/')
        else:
            tx_phys = params[0]
            rx_phys = tx_phys

        await self.device.set_default_phy(
            tx_phys=parse_phys(tx_phys), rx_phys=parse_phys(rx_phys)
        )

    async def do_exit(self, _):
        self.ui.exit()

    async def do_quit(self, _):
        self.ui.exit()

    async def do_filter(self, params):
        if params[0] == "address":
            if len(params) != 2:
                self.show_error('invalid syntax', 'expected filter address <pattern>')
                return
            self.device.listener.address_filter = params[1]


# -----------------------------------------------------------------------------
# Device and Connection Listener
# -----------------------------------------------------------------------------
class DeviceListener(Device.Listener, Connection.Listener):
    def __init__(self, app):
        self.app = app
        self.scan_results = OrderedDict()
        self.address_filter = None

    @property
    def address_filter(self):
        return self._address_filter

    @address_filter.setter
    def address_filter(self, filter_addr):
        if filter_addr is None:
            self._address_filter = re.compile(r".*")
        else:
            self._address_filter = re.compile(filter_addr)
        self.scan_results = OrderedDict(
            filter(self.filter_address_match, self.scan_results)
        )
        self.app.show_scan_results(self.scan_results)

    def filter_address_match(self, address):
        """
        Returns true if an address matches the filter
        """
        return bool(self.address_filter.match(address))

    @AsyncRunner.run_in_task()
    # pylint: disable=invalid-overridden-method
    async def on_connection(self, connection):
        self.app.connected_peer = Peer(connection)
        self.app.connection_rssi = None
        self.app.append_to_output(f'connected to {self.app.connected_peer}')
        connection.listener = self

    def on_disconnection(self, reason):
        self.app.append_to_output(
            f'disconnected from {self.app.connected_peer}, '
            f'reason: {HCI_Constant.error_name(reason)}'
        )
        self.app.connected_peer = None
        self.app.connection_rssi = None

    def on_connection_parameters_update(self):
        self.app.append_to_output(
            f'connection parameters update: '
            f'{self.app.connected_peer.connection.parameters}'
        )

    def on_connection_phy_update(self):
        self.app.append_to_output(
            f'connection phy update: {self.app.connected_peer.connection.phy}'
        )

    def on_connection_att_mtu_update(self):
        self.app.append_to_output(
            f'connection att mtu update: {self.app.connected_peer.connection.att_mtu}'
        )

    def on_connection_encryption_change(self):
        encryption_state = (
            'encrypted'
            if self.app.connected_peer.connection.is_encrypted
            else 'not encrypted'
        )
        self.app.append_to_output(
            'connection encryption change: ' f'{encryption_state}'
        )

    def on_connection_data_length_change(self):
        self.app.append_to_output(
            'connection data length change: '
            f'{self.app.connected_peer.connection.data_length}'
        )

    def on_advertisement(self, advertisement):
        if not self.filter_address_match(str(advertisement.address)):
            return

        entry_key = f'{advertisement.address}/{advertisement.address.address_type}'
        entry = self.scan_results.get(entry_key)
        if entry:
            entry.ad_data = advertisement.data
            entry.rssi = advertisement.rssi
            entry.connectable = advertisement.is_connectable
        else:
            self.app.add_known_address(str(advertisement.address))
            self.scan_results[entry_key] = ScanResult(
                advertisement.address,
                advertisement.address.address_type,
                advertisement.data,
                advertisement.rssi,
                advertisement.is_connectable,
            )

        self.app.show_scan_results(self.scan_results)


# -----------------------------------------------------------------------------
# Scanning
# -----------------------------------------------------------------------------
class ScanResult:
    def __init__(self, address, address_type, ad_data, rssi, connectable):
        self.address = address
        self.address_type = address_type
        self.ad_data = ad_data
        self.rssi = rssi
        self.connectable = connectable

    def to_display_string(self):
        address_type_string = ('P', 'R', 'PI', 'RI')[self.address_type]
        address_color = colors.yellow if self.connectable else colors.red
        if address_type_string.startswith('P'):
            type_color = colors.green
        else:
            type_color = colors.cyan

        name = self.ad_data.get(AdvertisingData.COMPLETE_LOCAL_NAME, raw=True)
        if name is None:
            name = self.ad_data.get(AdvertisingData.SHORTENED_LOCAL_NAME, raw=True)
        if name:
            # Convert to string
            try:
                name = name.decode()
            except UnicodeDecodeError:
                name = name.hex()
        else:
            name = ''

        # Remove any '/P' qualifier suffix from the address string
        address_str = self.address.to_string(with_type_qualifier=False)

        # RSSI bar
        bar_string = rssi_bar(self.rssi)
        bar_padding = ' ' * (DEFAULT_RSSI_BAR_WIDTH + 5 - len(bar_string))
        return (
            f'{address_color(address_str)} [{type_color(address_type_string)}] '
            f'{bar_string} {bar_padding} {name}'
        )


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
class LogHandler(logging.Handler):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setFormatter(logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s'))

    def emit(self, record):
        message = self.format(record)
        self.app.append_to_log(message)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
@click.command()
@click.option('--device-config', help='Device configuration file')
@click.argument('transport')
def main(device_config, transport):
    # Ensure that the BUMBLE_USER_DIR directory exists
    if not os.path.isdir(BUMBLE_USER_DIR):
        os.mkdir(BUMBLE_USER_DIR)

    # Create an instance of the app
    app = ConsoleApp()

    # Setup logging
    # logging.basicConfig(level = 'FATAL')
    # logging.basicConfig(level = 'DEBUG')
    root_logger = logging.getLogger()

    root_logger.addHandler(LogHandler(app))
    root_logger.setLevel(logging.DEBUG)

    # Run until the user exits
    asyncio.run(app.run_async(device_config, transport))


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
