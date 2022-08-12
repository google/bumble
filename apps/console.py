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
from bumble.hci import HCI_Constant
import os
import os.path
import logging
import click
from collections import OrderedDict
import colors

from bumble.core import UUID, AdvertisingData
from bumble.device import Device, Connection, Peer
from bumble.utils import AsyncRunner
from bumble.transport import open_transport_or_link
from bumble.gatt import Characteristic

from prompt_toolkit import Application
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import Completer, Completion, NestedCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.styles import Style
from prompt_toolkit.filters import Condition
from prompt_toolkit.widgets import TextArea, Frame
from prompt_toolkit.widgets.toolbars import FormattedTextToolbar
from prompt_toolkit.layout import (
    Layout,
    HSplit,
    Window,
    CompletionsMenu,
    Float,
    FormattedTextControl,
    FloatContainer,
    ConditionalContainer
)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
BUMBLE_USER_DIR        = os.path.expanduser('~/.bumble')
DEFAULT_PROMPT_HEIGHT  = 20
DEFAULT_RSSI_BAR_WIDTH = 20
DISPLAY_MIN_RSSI       = -100
DISPLAY_MAX_RSSI       = -30

# -----------------------------------------------------------------------------
# Globals
# -----------------------------------------------------------------------------
App = None


# -----------------------------------------------------------------------------
# Console App
# -----------------------------------------------------------------------------
class ConsoleApp:
    def __init__(self):
        self.known_addresses = set()
        self.known_attributes = []
        self.device = None
        self.connected_peer = None
        self.top_tab = 'scan'

        style = Style.from_dict({
            'output-field': 'bg:#000044 #ffffff',
            'input-field':  'bg:#000000 #ffffff',
            'line':         '#004400',
            'error':        'fg:ansired'
        })

        class LiveCompleter(Completer):
            def __init__(self, words):
                self.words = words

            def get_completions(self, document, complete_event):
                prefix = document.text_before_cursor.upper()
                for word in [x for x in self.words if x.upper().startswith(prefix)]:
                    yield Completion(word, start_position=-len(prefix))

        def make_completer():
            return NestedCompleter.from_nested_dict({
                'scan': {
                    'on': None,
                    'off': None
                },
                'advertise': {
                    'on': None,
                    'off': None
                },
                'show': {
                    'scan': None,
                    'services': None,
                    'attributes': None,
                    'log': None
                },
                'connect': LiveCompleter(self.known_addresses),
                'update-parameters': None,
                'encrypt': None,
                'disconnect': None,
                'discover': {
                    'services': None,
                    'attributes': None
                },
                'read': LiveCompleter(self.known_attributes),
                'write': LiveCompleter(self.known_attributes),
                'subscribe': LiveCompleter(self.known_attributes),
                'unsubscribe': LiveCompleter(self.known_attributes),
                'quit': None,
                'exit': None
            })

        self.input_field = TextArea(
            height=1,
            prompt="> ",
            multiline=False,
            wrap_lines=False,
            completer=make_completer(),
            history=FileHistory(os.path.join(BUMBLE_USER_DIR, 'history'))
        )

        self.input_field.accept_handler = self.accept_input

        self.output_height = 7
        self.output_lines = []
        self.output = FormattedTextControl()
        self.scan_results_text = FormattedTextControl()
        self.services_text = FormattedTextControl()
        self.attributes_text = FormattedTextControl()
        self.log_text = FormattedTextControl()
        self.log_height = 20
        self.log_lines = []

        container = HSplit([
            ConditionalContainer(
                Frame(Window(self.scan_results_text), title='Scan Results'),
                filter=Condition(lambda: self.top_tab == 'scan')
            ),
            ConditionalContainer(
                Frame(Window(self.services_text), title='Services'),
                filter=Condition(lambda: self.top_tab == 'services')
            ),
            ConditionalContainer(
                Frame(Window(self.attributes_text), title='Attributes'),
                filter=Condition(lambda: self.top_tab == 'attributes')
            ),
            ConditionalContainer(
                Frame(Window(self.log_text), title='Log'),
                filter=Condition(lambda: self.top_tab == 'log')
            ),
            Frame(Window(self.output), height=self.output_height),
            # HorizontalLine(),
            FormattedTextToolbar(text=self.get_status_bar_text, style='reverse'),
            self.input_field
        ])

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

        kb = KeyBindings()
        @kb.add("c-c")
        @kb.add("c-q")
        def _(event):
            event.app.exit()

        self.ui = Application(
            layout=layout,
            style=style,
            key_bindings=kb,
            full_screen=True
        )

    async def run_async(self, device_config, transport):
        async with await open_transport_or_link(transport) as (hci_source, hci_sink):
            if device_config:
                self.device = Device.from_config_file_with_hci(device_config, hci_source, hci_sink)
            else:
                self.device = Device.with_hci('Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
            self.device.listener = DeviceListener(self)
            await self.device.power_on()

            # Run the UI
            await self.ui.run_async()

    def add_known_address(self, address):
        self.known_addresses.add(address)

    def accept_input(self, buff):
        if len(self.input_field.text) == 0:
            return
        self.append_to_output([('', '* '), ('ansicyan', self.input_field.text)], False)
        self.ui.create_background_task(self.command(self.input_field.text))

    def get_status_bar_text(self):
        scanning = "ON" if self.device and self.device.is_scanning else "OFF"

        connection_state = 'NONE'
        encryption_state = ''

        if self.device:
            if self.device.is_connecting:
                connection_state = 'CONNECTING'
            elif self.connected_peer:
                connection = self.connected_peer.connection
                connection_parameters = f'{connection.parameters.connection_interval}/{connection.parameters.connection_latency}/{connection.parameters.supervision_timeout}'
                connection_state = f'{connection.peer_address} {connection_parameters} {connection.data_length}'
                encryption_state = 'ENCRYPTED' if connection.is_encrypted else 'NOT ENCRYPTED'

        return [
            ('ansigreen', f' SCAN: {scanning} '),
            ('', '  '),
            ('ansiblue', f' CONNECTION: {connection_state} '),
            ('', '  '),
            ('ansimagenta', f' {encryption_state} ')
        ]

    def show_error(self, title, details = None):
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

    def show_services(self, services):
        lines = []
        del self.known_attributes[:]
        for service in services:
            lines.append(('ansicyan', str(service) + '\n'))

            for characteristic in service.characteristics:
                lines.append(('ansimagenta', '  ' + str(characteristic) + '\n'))
                self.known_attributes.append(f'{service.uuid.to_hex_str()}.{characteristic.uuid.to_hex_str()}')
                self.known_attributes.append(f'*.{characteristic.uuid.to_hex_str()}')
                self.known_attributes.append(f'#{characteristic.handle:X}')
                for descriptor in characteristic.descriptors:
                    lines.append(('ansigreen', '    ' + str(descriptor) + '\n'))

        self.services_text.text = lines
        self.ui.invalidate()

    async def show_attributes(self, attributes):
        lines = []

        for attribute in attributes:
            lines.append(('ansicyan', f'{attribute}\n'))

        self.attributes_text.text = lines
        self.ui.invalidate()

    def append_to_output(self, line, invalidate=True):
        if type(line) is str:
            line = [('', line)]
        self.output_lines = self.output_lines[-(self.output_height - 3):]
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
        self.log_lines = self.log_lines[-(self.log_height - 3):]
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
        self.append_to_output(f'found {len(self.connected_peer.services)} services, discovering charateristics...')
        await self.connected_peer.discover_characteristics()
        self.append_to_output('found characteristics, discovering descriptors...')
        for service in self.connected_peer.services:
            for characteristic in service.characteristics:
                await self.connected_peer.discover_descriptors(characteristic)
        self.append_to_output('discovery completed')

        self.show_services(self.connected_peer.services)

    async def discover_attributes(self):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        # Discover all attributes
        self.append_to_output('discovering attributes...')
        attributes = await self.connected_peer.discover_attributes()
        self.append_to_output(f'discovered {len(attributes)} attributes...')

        await self.show_attributes(attributes)

    def find_characteristic(self, param):
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
            await self.device.start_scanning()
            self.top_tab = 'scan'
        elif params[0] == 'off':
            await self.device.stop_scanning()
        else:
            self.show_error('unsupported arguments for scan command')

    async def do_connect(self, params):
        if len(params) != 1:
            self.show_error('invalid syntax', 'expected connect <address>')
            return

        self.append_to_output('connecting...')
        await self.device.connect(params[0])
        self.top_tab = 'services'

    async def do_disconnect(self, params):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        await self.connected_peer.connection.disconnect()

    async def do_update_parameters(self, params):
        if len(params) != 1 or len(params[0].split('/')) != 3:
            self.show_error('invalid syntax', 'expected update-parameters <interval-min>-<interval-max>/<latency>/<supervision>')
            return

        if not self.connected_peer:
            self.show_error('not connected')
            return

        connection_intervals, connection_latency, supervision_timeout = params[0].split('/')
        connection_interval_min, connection_interval_max = [int(x) for x in connection_intervals.split('-')]
        connection_latency = int(connection_latency)
        supervision_timeout = int(supervision_timeout)
        await self.connected_peer.connection.update_parameters(
            connection_interval_min,
            connection_interval_max,
            connection_latency,
            supervision_timeout
        )

    async def do_encrypt(self, params):
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
            if params[0] in {'scan', 'services', 'attributes', 'log'}:
                self.top_tab = params[0]
                self.ui.invalidate()

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
        if not self.connected_peer:
            self.show_error('not connected')
            return

        if len(params) != 1:
            self.show_error('invalid syntax', 'expected read <attribute>')
            return

        characteristic = self.find_characteristic(params[0])
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

        characteristic = self.find_characteristic(params[0])
        if characteristic is None:
            self.show_error('no such characteristic')
            return

        # use write with response if supported
        with_response = characteristic.properties & Characteristic.WRITE
        await characteristic.write_value(value, with_response=with_response)

    async def do_subscribe(self, params):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        if len(params) != 1:
            self.show_error('invalid syntax', 'expected subscribe <attribute>')
            return

        characteristic = self.find_characteristic(params[0])
        if characteristic is None:
            self.show_error('no such characteristic')
            return

        await characteristic.subscribe(
            lambda value: self.append_to_output(f"{characteristic} VALUE: 0x{value.hex()}"),
        )

    async def do_unsubscribe(self, params):
        if not self.connected_peer:
            self.show_error('not connected')
            return

        if len(params) != 1:
            self.show_error('invalid syntax', 'expected subscribe <attribute>')
            return

        characteristic = self.find_characteristic(params[0])
        if characteristic is None:
            self.show_error('no such characteristic')
            return

        await characteristic.unsubscribe()

    async def do_exit(self, params):
        self.ui.exit()

    async def do_quit(self, params):
        self.ui.exit()


# -----------------------------------------------------------------------------
# Device and Connection Listener
# -----------------------------------------------------------------------------
class DeviceListener(Device.Listener, Connection.Listener):
    def __init__(self, app):
        self.app = app
        self.scan_results = OrderedDict()

    @AsyncRunner.run_in_task()
    async def on_connection(self, connection):
        self.app.connected_peer = Peer(connection)
        self.app.append_to_output(f'connected to {self.app.connected_peer}')
        connection.listener = self

    def on_disconnection(self, reason):
        self.app.append_to_output(f'disconnected from {self.app.connected_peer}, reason: {HCI_Constant.error_name(reason)}')
        self.app.connected_peer = None

    def on_connection_parameters_update(self):
        self.app.append_to_output(f'connection parameters update: {self.app.connected_peer.connection.parameters}')

    def on_connection_phy_update(self):
        self.app.append_to_output(f'connection phy update: {self.app.connected_peer.connection.phy}')

    def on_connection_att_mtu_update(self):
        self.app.append_to_output(f'connection att mtu update: {self.app.connected_peer.connection.att_mtu}')

    def on_connection_encryption_change(self):
        self.app.append_to_output(f'connection encryption change: {"encrypted" if self.app.connected_peer.connection.is_encrypted else "not encrypted"}')

    def on_connection_data_length_change(self):
        self.app.append_to_output(f'connection data length change: {self.app.connected_peer.connection.data_length}')

    def on_advertisement(self, address, ad_data, rssi, connectable):
        entry_key = f'{address}/{address.address_type}'
        entry = self.scan_results.get(entry_key)
        if entry:
            entry.ad_data     = ad_data
            entry.rssi        = rssi
            entry.connectable = connectable
        else:
            self.app.add_known_address(str(address))
            self.scan_results[entry_key] = ScanResult(address, address.address_type, ad_data, rssi, connectable)

        self.app.show_scan_results(self.scan_results)


# -----------------------------------------------------------------------------
# Scanning
# -----------------------------------------------------------------------------
class ScanResult:
    def __init__(self, address, address_type, ad_data, rssi, connectable):
        self.address      = address
        self.address_type = address_type
        self.ad_data      = ad_data
        self.rssi         = rssi
        self.connectable  = connectable

    def to_display_string(self):
        address_type_string = ('P', 'R', 'PI', 'RI')[self.address_type]
        address_color = colors.yellow if self.connectable else colors.red
        if address_type_string.startswith('P'):
            type_color = colors.green
        else:
            type_color = colors.cyan

        name = self.ad_data.get(AdvertisingData.COMPLETE_LOCAL_NAME)
        if name is None:
            name = self.ad_data.get(AdvertisingData.SHORTENED_LOCAL_NAME)
        if name:
            # Convert to string
            try:
                name = name.decode()
            except UnicodeDecodeError:
                name = name.hex()
        else:
            name = ''

        # RSSI bar
        blocks = ['', '▏', '▎', '▍', '▌', '▋', '▊', '▉']
        bar_width = (self.rssi - DISPLAY_MIN_RSSI) / (DISPLAY_MAX_RSSI - DISPLAY_MIN_RSSI)
        bar_width = min(max(bar_width, 0), 1)
        bar_ticks = int(bar_width * DEFAULT_RSSI_BAR_WIDTH * 8)
        bar_blocks = ('█' * int(bar_ticks / 8)) + blocks[bar_ticks % 8]
        bar_string = f'{self.rssi} {bar_blocks}'
        bar_padding = ' ' * (DEFAULT_RSSI_BAR_WIDTH + 5 - len(bar_string))
        return f'{address_color(str(self.address))} [{type_color(address_type_string)}] {bar_string} {bar_padding} {name}'


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
class LogHandler(logging.Handler):
    def __init__(self, app):
        super().__init__()
        self.app = app

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

    # Create an instane of the app
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
    main()
