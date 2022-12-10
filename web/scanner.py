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
from bumble.device import Device
from bumble.transport import PacketParser


# -----------------------------------------------------------------------------
class ScannerListener(Device.Listener):
    def on_advertisement(self, advertisement):
        address_type_string = ('P', 'R', 'PI', 'RI')[advertisement.address.address_type]
        print(
            f'>>> {advertisement.address} [{address_type_string}]: RSSI={advertisement.rssi}, {advertisement.ad_data}'
        )


class HciSource:
    def __init__(self, host_source):
        self.parser = PacketParser()
        host_source.delegate = self

    def set_packet_sink(self, sink):
        self.parser.set_packet_sink(sink)

    # host source delegation
    def data_received(self, data):
        print('*** DATA from JS:', data)
        buffer = bytes(data.to_py())
        self.parser.feed_data(buffer)


# class HciSink:
#     def __init__(self, host_sink):
#         self.host_sink = host_sink

#     def on_packet(self, packet):
#         print(f'>>> PACKET from Python: {packet}')
#         self.host_sink.on_packet(packet)


# -----------------------------------------------------------------------------
async def main(host_source, host_sink):
    print('### Starting Scanner')
    hci_source = HciSource(host_source)
    hci_sink = host_sink
    device = Device.with_hci('Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
    device.listener = ScannerListener()
    await device.power_on()
    await device.start_scanning()

    print('### Scanner started')
